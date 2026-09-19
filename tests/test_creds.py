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

    def test_staging_url_override_is_honoured(self):
        with TempStore(_store(), VAIBOT_ENV="staging",
                       VAIBOT_GOVERNANCE_URL="http://127.0.0.1:8080/") as env:
            # Trailing slash is stripped, matching the Node implementation.
            self.assertEqual(creds.resolve_credentials(env).api_base_url, "http://127.0.0.1:8080")

    def test_production_url_override_needs_the_flag(self):
        # §5: without VAIBOT_ALLOW_URL_OVERRIDE an env var alone must not send a
        # production key to a host of its choosing.
        seeded = _store("production", {"production": {"api_key": "vb_live_abc"}})
        with TempStore(seeded, VAIBOT_GOVERNANCE_URL="https://attacker.invalid") as env:
            self.assertEqual(creds.resolve_credentials(env).api_base_url, "https://api.vaibot.io")
        with TempStore(seeded, VAIBOT_GOVERNANCE_URL="https://attacker.invalid",
                       VAIBOT_ALLOW_URL_OVERRIDE="1") as env:
            self.assertEqual(creds.resolve_credentials(env).api_base_url, "https://attacker.invalid")

    def test_api_url_infers_env_but_is_never_a_base(self):
        with TempStore(_store(), VAIBOT_API_URL="https://staging-api.vaibot.io/v2") as env:
            r = creds.resolve_credentials(env)
            self.assertEqual(r.env, "staging")
            self.assertEqual(r.api_base_url, "https://staging-api.vaibot.io")
        with TempStore(_store(), VAIBOT_ENV="staging", VAIBOT_API_URL="http://127.0.0.1:9") as env:
            self.assertEqual(creds.resolve_credentials(env).api_base_url, "https://staging-api.vaibot.io")

    def test_stored_governance_slot_url_is_used(self):
        seeded = _store("staging", {"staging": {"api_key": "vb_stg_x",
                                                "governance": {"url": "http://127.0.0.1:7000/"}}})
        with TempStore(seeded) as env:
            self.assertEqual(creds.resolve_credentials(env).api_base_url, "http://127.0.0.1:7000")


class EnvForApiUrlTests(unittest.TestCase):
    def test_matches_on_host_only(self):
        self.assertEqual(creds.env_for_api_url("https://api.vaibot.io"), "production")
        self.assertEqual(creds.env_for_api_url("https://api.vaibot.io:443/v2"), "production")
        self.assertEqual(creds.env_for_api_url("https://staging-api.vaibot.io"), "staging")
        self.assertEqual(creds.env_for_api_url("http://my-staging-box:8080"), "staging")

    def test_substrings_outside_the_host_do_not_count(self):
        self.assertIsNone(creds.env_for_api_url("https://evil.invalid/?x=api.vaibot.io"))
        self.assertIsNone(creds.env_for_api_url("https://evil.invalid/staging"))
        self.assertIsNone(creds.env_for_api_url("https://api.vaibot.io.evil.invalid"))
        self.assertIsNone(creds.env_for_api_url("not a url"))
        self.assertIsNone(creds.env_for_api_url(""))


class MigrationTests(unittest.TestCase):
    def test_v1_flat_file_is_lifted_into_its_env(self):
        with TempStore({"api_key": "vb_stg_legacy", "api_url": "https://staging-api.vaibot.io"}) as env:
            r = creds.resolve_credentials(env)
            self.assertEqual((r.env, r.api_key), ("staging", "vb_stg_legacy"))

    def test_v1_flat_file_without_url_uses_the_key_prefix(self):
        with TempStore({"api_key": "vb_live_legacy"}) as env:
            self.assertEqual(creds.resolve_credentials(env).api_key, "vb_live_legacy")

    def test_keyless_records_are_dropped(self):
        store = creds.migrate_store({"version": 3, "active_env": "staging",
                                     "environments": {"staging": {"wallet_address": "0x1"}}})
        self.assertEqual(store["environments"], {})


# Fixtures resolved by BOTH implementations. Each is (env vars, store payload).
_PARITY_FIXTURES = [
    ({}, _store("production", {"production": {"api_key": "vb_live_a"}})),
    ({}, _store("production", {"production": {"api_key": "vb_stg_mismatch"}})),
    ({"VAIBOT_ENV": "production"}, _store("production", {"production": {"api_key": "vb_stg_mismatch"}})),
    ({"VAIBOT_ENV": "staging"}, _store("production", {"production": {"api_key": "vb_live_a"}})),
    ({"VAIBOT_API_KEY": "vb_stg_env"}, _store("production", {"production": {"api_key": "vb_live_a"}})),
    ({"VAIBOT_API_URL": "https://staging-api.vaibot.io"}, _store()),
    ({"VAIBOT_API_URL": "https://evil.invalid/?x=api.vaibot.io"}, _store("staging")),
    ({"VAIBOT_GOVERNANCE_URL": "https://attacker.invalid"}, _store("production", {"production": {"api_key": "vb_live_a"}})),
    ({"VAIBOT_GOVERNANCE_URL": "https://ok.invalid/", "VAIBOT_ALLOW_URL_OVERRIDE": "yes"}, _store()),
    ({"VAIBOT_ENV": "staging", "VAIBOT_GOVERNANCE_URL": "http://127.0.0.1:1/"}, _store()),
    ({}, _store("staging", {"staging": {"api_key": "sk_custom", "governance": {"url": "http://127.0.0.1:2/"}}})),
    ({}, {"api_key": "vb_stg_legacy", "api_url": "https://staging-api.vaibot.io"}),
    ({}, {"api_key": "vb_live_legacy"}),
    ({}, "{not json"),
    ({}, None),
]

_NODE_RESOLVER = r"""
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
const { resolveCredentials } = await import(process.argv[2])
let raw = ''
for await (const c of process.stdin) raw += c
const out = []
for (const [envVars, payload] of JSON.parse(raw)) {
  const dir = mkdtempSync(join(tmpdir(), 'vaibot-creds-parity-'))
  if (payload !== null) writeFileSync(join(dir, 'credentials.json'), typeof payload === 'string' ? payload : JSON.stringify(payload))
  const r = resolveCredentials({ env: { ...envVars, VAIBOT_CREDS_DIR: dir } })
  out.push({ env: r.env, api_base_url: r.apiBaseUrl, api_key: r.apiKey ?? null, key_mismatch: r.keyMismatch })
}
process.stdout.write(JSON.stringify(out))
"""


def _node_creds_module():
    """The guard's creds.mjs from this checkout, or None when unavailable."""
    import shutil

    override = os.environ.get("VAIBOT_GUARD_SRC")
    root = Path(override) if override else Path(__file__).resolve().parents[2] / "vaibot-guard"
    module = root / "scripts" / "lib" / "creds.mjs"
    node = shutil.which("node")
    return (node, module) if node and module.is_file() else None


class NodeParityTests(unittest.TestCase):
    """The Python port and the Node original must resolve identically.

    This is the test that would have caught S1 shipping without the §5 gate.
    Skipped only where node or the guard source isn't available.
    """

    def test_python_and_node_resolve_identically(self):
        found = _node_creds_module()
        if not found:
            self.skipTest("node or the guard's creds.mjs is not available")
        node, module = found

        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "resolve.mjs"
            script.write_text(_NODE_RESOLVER, encoding="utf-8")
            proc = subprocess.run(
                [node, str(script), module.as_uri()],
                input=json.dumps(_PARITY_FIXTURES), capture_output=True, text=True, timeout=30,
                env={"PATH": os.environ.get("PATH", "")},
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        node_results = json.loads(proc.stdout)

        for (env_vars, payload), expected in zip(_PARITY_FIXTURES, node_results):
            with TempStore(payload, **env_vars) as env:
                r = creds.resolve_credentials(env)
                got = {"env": r.env, "api_base_url": r.api_base_url,
                       "api_key": r.api_key, "key_mismatch": r.key_mismatch}
            self.assertEqual(got, expected, f"fixture env={env_vars} store={payload!r}")


if __name__ == "__main__":
    unittest.main()
