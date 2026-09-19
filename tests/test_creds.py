"""Pins the credential contract shared with the Node circuit breakers.

These assertions encode ``@vaibot/guard``'s ``scripts/lib/creds.mjs``. If they
drift, the Hermes plugin and the guard sharing a machine can resolve *different*
environments — talking to different control planes while appearing to agree.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vaibot import creds  # noqa: E402


def _store(active="production", envs=None):
    return {"version": 3, "active_env": active, "environments": envs or {}}


class TempStore:
    """Write a credentials.json into a temp dir and yield an env mapping for it."""

    def __init__(self, payload, **extra_env):
        self.payload = payload
        self.extra_env = extra_env

    def __enter__(self):
        self.dir = tempfile.TemporaryDirectory()
        path = Path(self.dir.name) / "credentials.json"
        if self.payload is not None:
            path.write_text(
                self.payload if isinstance(self.payload, str) else json.dumps(self.payload),
                encoding="utf-8",
            )
        return {"VAIBOT_CREDS_DIR": self.dir.name, **self.extra_env}

    def __exit__(self, *exc):
        self.dir.cleanup()
        return False


class EnvPrefixTests(unittest.TestCase):
    def test_recognised_prefixes_map_to_envs(self):
        self.assertEqual(creds.env_for_key("vb_live_abc"), "production")
        self.assertEqual(creds.env_for_key("vb_stg_abc"), "staging")

    def test_unrecognised_prefix_is_none(self):
        self.assertIsNone(creds.env_for_key("sk_whatever"))
        self.assertIsNone(creds.env_for_key(""))
        self.assertIsNone(creds.env_for_key(None))

    def test_prefix_guard_is_lenient(self):
        # An unrecognised prefix PASSES. A false denial here locks a user out of
        # their own governance, which is worse than the mismatch it would guard.
        self.assertTrue(creds.key_prefix_matches_env("sk_unknown", "production"))
        # A recognised prefix must match.
        self.assertTrue(creds.key_prefix_matches_env("vb_live_x", "production"))
        self.assertFalse(creds.key_prefix_matches_env("vb_stg_x", "production"))


class ResolveEnvTests(unittest.TestCase):
    """Precedence: VAIBOT_ENV → VAIBOT_API_URL → VAIBOT_API_KEY prefix →
    stored active key prefix → stored active_env → default."""

    def test_explicit_env_wins_over_everything(self):
        with TempStore(_store("production", {"production": {"api_key": "vb_live_x"}}),
                       VAIBOT_ENV="staging", VAIBOT_API_KEY="vb_live_x") as env:
            self.assertEqual(creds.resolve_env(env), "staging")

    def test_api_url_beats_key_prefix(self):
        with TempStore(_store(), VAIBOT_API_URL="https://staging-api.vaibot.io",
                       VAIBOT_API_KEY="vb_live_x") as env:
            self.assertEqual(creds.resolve_env(env), "staging")

    def test_env_key_prefix_beats_store(self):
        with TempStore(_store("production", {"production": {"api_key": "vb_live_x"}}),
                       VAIBOT_API_KEY="vb_stg_x") as env:
            self.assertEqual(creds.resolve_env(env), "staging")

    def test_stored_key_prefix_used_when_no_env(self):
        with TempStore(_store("production", {"production": {"api_key": "vb_stg_x"}})) as env:
            # The stored key's prefix outranks the stored active_env label.
            self.assertEqual(creds.resolve_env(env), "staging")

    def test_falls_back_to_active_env_then_default(self):
        with TempStore(_store("staging", {"staging": {"api_key": "sk_unknown"}})) as env:
            self.assertEqual(creds.resolve_env(env), "staging")
        with TempStore(_store("production")) as env:
            self.assertEqual(creds.resolve_env(env), "production")


class StoreRobustnessTests(unittest.TestCase):
    def test_missing_file_yields_empty_store(self):
        with TempStore(None) as env:
            self.assertEqual(creds.load_store(env)["environments"], {})

    def test_corrupt_file_does_not_raise(self):
        # A broken store must degrade to "no key", never crash the host agent.
        with TempStore("{not json") as env:
            self.assertEqual(creds.load_store(env)["environments"], {})
            self.assertIsNone(creds.resolve_credentials(env).api_key)

    def test_non_object_file_does_not_raise(self):
        with TempStore('"a string"') as env:
            self.assertEqual(creds.load_store(env)["environments"], {})

    def test_invalid_active_env_falls_back(self):
        with TempStore({"version": 3, "active_env": "banana", "environments": {}}) as env:
            self.assertEqual(creds.load_store(env)["active_env"], "production")


class ResolveCredentialsTests(unittest.TestCase):
    def test_resolves_key_and_canonical_base(self):
        with TempStore(_store("production", {"production": {"api_key": "vb_live_abc"}})) as env:
            r = creds.resolve_credentials(env)
            self.assertEqual(r.env, "production")
            self.assertEqual(r.api_key, "vb_live_abc")
            self.assertEqual(r.api_base_url, "https://api.vaibot.io")
            self.assertFalse(r.key_mismatch)

    def test_staging_base(self):
        with TempStore(_store("staging", {"staging": {"api_key": "vb_stg_abc"}})) as env:
            self.assertEqual(creds.resolve_credentials(env).api_base_url,
                             "https://staging-api.vaibot.io")

    def test_mismatched_key_is_withheld_not_used(self):
        # A staging key while resolving production: flag it AND withhold it, so
        # we never talk to the wrong control plane with a valid-looking key.
        with TempStore(_store("production", {"production": {"api_key": "vb_stg_wrong"}}),
                       VAIBOT_ENV="production") as env:
            r = creds.resolve_credentials(env)
            self.assertTrue(r.key_mismatch)
            self.assertIsNone(r.api_key)

    def test_unrecognised_prefix_is_kept(self):
        with TempStore(_store("production", {"production": {"api_key": "sk_custom"}})) as env:
            r = creds.resolve_credentials(env)
            self.assertFalse(r.key_mismatch)
            self.assertEqual(r.api_key, "sk_custom")

    def test_url_override_wins(self):
        with TempStore(_store(), VAIBOT_GOVERNANCE_URL="http://127.0.0.1:8080/") as env:
            # Trailing slash is stripped, matching the Node implementation.
            self.assertEqual(creds.resolve_credentials(env).api_base_url, "http://127.0.0.1:8080")


if __name__ == "__main__":
    unittest.main()
