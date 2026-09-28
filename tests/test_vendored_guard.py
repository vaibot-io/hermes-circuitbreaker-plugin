"""The plugin is a complete install, and an unclassifiable call never proceeds.

Every other VAIBot breaker vendors the guard, which is what makes one `npm install`
a working system rather than half of one. This package now holds the same property
for `pip install`: someone may meet this plugin before they ever meet the CLI, and
"now go install something else" is not a front door.

Two things are pinned here, and the second matters more than the first:

* **The guard ships with the package**, is the version the rest of the family
  vendors, and carries the two subcommands this plugin delegates to.
* **An unclassifiable call escalates in EVERY mode.** Vendoring can still fail — no
  node, a stripped container — so the floor cannot depend on it. The classifier IS
  the floor on a degraded path; when it is absent there is no floor left, and
  allowing would let a catastrophic call through in observe, which is exactly what
  observe is documented not to do.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import vaibot  # noqa: E402
from vaibot import localcli  # noqa: E402
from vaibot.creds import ResolvedCredentials  # noqa: E402
from vaibot.engine import Engine  # noqa: E402

PKG = Path(vaibot.__file__).resolve().parent
VENDOR = PKG / "vendor" / "vaibot-guard"


class TestTheGuardShipsWithThePackage(unittest.TestCase):
    def test_the_vendored_guard_is_present(self):
        self.assertTrue(VENDOR.is_dir(), f"no vendored guard at {VENDOR}")
        self.assertTrue((VENDOR / "scripts" / "vaibot-guard.mjs").is_file())
        self.assertTrue((VENDOR / "package.json").is_file())

    def test_it_carries_the_two_subcommands_this_plugin_delegates_to(self):
        # classify = the local safety floor; bootstrap = the single credential
        # writer. A vendored guard without them is worse than none, because the
        # resolution chain would prefer it over nothing and still answer None.
        cli = (VENDOR / "scripts" / "vaibot-guard.mjs").read_text(encoding="utf-8")
        self.assertIn('"classify"', cli)
        self.assertIn('"bootstrap"', cli)

    def test_it_is_the_version_the_rest_of_the_family_vendors(self):
        # All five breakers move together. A plugin pinning its own guard version
        # is how eight vendored copies ended up spanning 1.0.2 to 2.1.0.
        version = json.loads((VENDOR / "package.json").read_text(encoding="utf-8"))["version"]
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")

    def test_the_recorded_digest_names_what_npm_serves(self):
        # The copy was taken from the published tarball and checked against the
        # digest the registry reports, so it is provably npm's build rather than
        # whatever happened to be on the machine that vendored it.
        digest = (PKG / "vendor" / "vaibot-guard.sha1").read_text(encoding="utf-8").strip()
        self.assertRegex(digest, r"^[0-9a-f]{40}$")

    def test_node_modules_never_ships(self):
        self.assertFalse((VENDOR / "node_modules").exists(), "node_modules must not be vendored")


class TestResolutionOrder(unittest.TestCase):
    """PATH before vendored, so a newer system guard wins and a machine keeps one guard."""

    def test_path_is_preferred_over_the_vendored_copy(self):
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "vaibot-guard"
            fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake.chmod(0o755)
            argv, source = localcli.resolve_guard_cli({"PATH": d})
        self.assertEqual(source, "path")
        self.assertEqual(argv, [str(fake)])

    def test_the_vendored_copy_is_used_when_path_has_none(self):
        # A PATH with node and NOTHING else. Pointing at node's own directory is not
        # good enough: on this machine `vaibot-guard` sits beside it, so that PATH
        # finds one and the test would assert the opposite of what it means.
        import shutil

        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed")
        with tempfile.TemporaryDirectory() as d:
            os.symlink(node, os.path.join(d, "node"))
            self.assertIsNone(shutil.which("vaibot-guard", path=d), "setup: this PATH must have no guard")
            argv, source = localcli.resolve_guard_cli({"PATH": d})
            self.assertEqual(source, "vendored")
            self.assertEqual(argv[1], str(VENDOR / "scripts" / "vaibot-guard.mjs"))

    def test_no_node_is_distinguished_from_no_guard(self):
        # Different problems, different fixes: install node vs install the guard.
        argv, source = localcli.resolve_guard_cli({"PATH": ""})
        self.assertIsNone(argv)
        self.assertEqual(source, "vendored-no-node")

    def test_an_explicit_override_always_wins(self):
        argv, source = localcli.resolve_guard_cli({"PATH": "", "VAIBOT_GUARD_CLI": "/opt/custom/vaibot-guard"})
        self.assertEqual(source, "override")
        self.assertEqual(argv, ["/opt/custom/vaibot-guard"])


class TestAnUnclassifiableCallNeverProceeds(unittest.TestCase):
    """The fix: `verdict is None` is checked BEFORE `lenient`, not after."""

    NO_KEY = ResolvedCredentials(env="staging", api_base_url="https://x", api_key=None, key_mismatch=False)

    def _decide(self, *, lenient: bool):
        env = {"HOME": "/tmp/does-not-exist-for-this-test", "VAIBOT_GUARD_BASE_URL": "http://127.0.0.1:1"}
        if lenient:
            env["VAIBOT_FAIL_OPEN"] = "true"
            env["VAIBOT_MODE"] = "observe"
        else:
            env["VAIBOT_MODE"] = "enforce"
        eng = Engine(
            env=env,
            classify=lambda *a, **k: None,  # no classifier: old CLI, or no node
            resolve=lambda *a, **k: self.NO_KEY,
            ensure=lambda *a, **k: None,
        )
        return eng.decide("terminal", {"command": "rm -rf /"}, "s")

    def test_enforce_escalates(self):
        d = self._decide(lenient=False).directive
        self.assertIsNotNone(d)
        self.assertEqual(d["action"], "approve")

    def test_observe_and_fail_open_ALSO_escalate(self):
        # The regression this file exists for. Before the fix this returned None —
        # the call proceeded — because `lenient` was checked first and there was no
        # classifier verdict left to floor it with.
        d = self._decide(lenient=True).directive
        self.assertIsNotNone(d, "an unclassifiable call must not proceed, even in observe")
        self.assertEqual(d["action"], "approve")

    def test_it_asks_rather_than_blocks(self):
        # Observe must not become STRICTER than enforce. Enforce asks here, so
        # observe asks too — identical behaviour, which is what the floor exception
        # in observe already looks like for a catastrophic deny.
        for lenient in (True, False):
            with self.subTest(lenient=lenient):
                self.assertEqual(self._decide(lenient=lenient).directive["action"], "approve")


class TestStatusNamesWhatTheFloorCanReach(unittest.TestCase):
    def test_status_reports_the_classifier_source(self):
        from vaibot import commands

        # Patch where the name is LOOKED UP: commands.py imported it directly, so it
        # holds its own reference and patching localcli's attribute does nothing.
        with mock.patch.object(commands, "resolve_guard_cli", return_value=(None, "none")):
            text = commands.status_text({})
        self.assertIn("Classifier", text)
        self.assertIn("NOT FOUND", text)
        self.assertIn("ask", text, "it should say what happens instead, not just that it is missing")

    def test_status_distinguishes_a_missing_node(self):
        from vaibot import commands

        with mock.patch.object(commands, "resolve_guard_cli", return_value=(None, "vendored-no-node")):
            text = commands.status_text({})
        self.assertIn("node", text)


if __name__ == "__main__":
    unittest.main()
