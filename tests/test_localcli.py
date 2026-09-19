"""Pins the guard-CLI bridge: exit 0 + one JSON line, or it didn't answer.

Fake CLIs (tiny Python executables) cover every way the real one can fail. A
separate integration test runs the real guard CLI when one that has the
``classify`` subcommand is available (``VAIBOT_GUARD_SRC`` or the sibling
checkout).
"""

import json
import os
import shutil
import stat
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vaibot import localcli  # noqa: E402


class FakeCli:
    """Writes an executable that records its argv + stdin and runs `body`."""

    def __init__(self, body: str):
        self.body = body

    def __enter__(self):
        self.dir = tempfile.TemporaryDirectory()
        d = Path(self.dir.name)
        self.record = d / "record.json"
        self.path = d / "fake-guard"
        self.path.write_text(
            f"#!{sys.executable}\n"
            "import json, sys\n"
            f"RECORD = {str(self.record)!r}\n"
            "stdin = sys.stdin.read()\n"
            "json.dump({'argv': sys.argv[1:], 'stdin': stdin}, open(RECORD, 'w'))\n"
            + textwrap.dedent(self.body)
        )
        self.path.chmod(self.path.stat().st_mode | stat.S_IXUSR)
        self.env = {"PATH": os.environ.get("PATH", ""), "VAIBOT_GUARD_CLI": str(self.path)}
        return self

    def seen(self):
        return json.loads(self.record.read_text())

    def __exit__(self, *exc):
        self.dir.cleanup()
        return False


VERDICT = 'print(json.dumps({"verdictHint": "deny", "risk": "dangerous", "reasons": ["rm -rf on a protected target"]}))'


class ResolutionTests(unittest.TestCase):
    def test_no_cli_anywhere_is_none(self):
        self.assertIsNone(localcli.guard_cli({"PATH": ""}))
        self.assertIsNone(localcli.classify("terminal", {"command": "ls"}, env={"PATH": ""}))
        self.assertIsNone(localcli.bootstrap(env={"PATH": ""}))

    def test_mjs_override_runs_under_node_or_not_at_all(self):
        self.assertIsNone(localcli.guard_cli({"PATH": "", "VAIBOT_GUARD_CLI": "/x/vaibot-guard.mjs"}))
        node = shutil.which("node")
        if node:
            argv = localcli.guard_cli({"PATH": os.path.dirname(node), "VAIBOT_GUARD_CLI": "/x/vaibot-guard.mjs"})
            self.assertEqual(argv[1:], ["/x/vaibot-guard.mjs"])


class ClassifyTests(unittest.TestCase):
    def test_parses_a_verdict_and_sends_the_renamed_tool(self):
        with FakeCli(VERDICT) as cli:
            v = localcli.classify("terminal", {"command": "x"}, env=cli.env)
            self.assertEqual((v.verdict_hint, v.risk, v.reason), ("deny", "dangerous", "rm -rf on a protected target"))
            seen = cli.seen()
            self.assertEqual(seen["argv"], ["classify"])
            self.assertEqual(json.loads(seen["stdin"]), {"toolName": "shell", "params": {"command": "x"}})

    def test_every_failure_is_none(self):
        cases = {
            "non-zero exit": "sys.exit(2)",
            "exit 0 but empty": "pass",
            "exit 0 but garbage": "print('help text, not json')",
            "no verdictHint": 'print(json.dumps({"risk": "low"}))',
            "unknown verdictHint": 'print(json.dumps({"verdictHint": "maybe"}))',
            "a JSON list": "print('[1, 2]')",
        }
        for name, body in cases.items():
            with FakeCli(body) as cli:
                self.assertIsNone(localcli.classify("terminal", {}, env=cli.env), name)

    def test_a_hung_cli_times_out_to_none(self):
        with FakeCli("import time; time.sleep(5)") as cli:
            self.assertIsNone(localcli.classify("terminal", {}, env=cli.env, timeout_s=0.5))


class BootstrapTests(unittest.TestCase):
    def test_provisioned(self):
        body = 'print(json.dumps({"ok": True, "env": "staging", "provisioned": True, "wallet_address": "0xabc"}))'
        with FakeCli(body) as cli:
            r = localcli.bootstrap(env=cli.env, timeout_s=10)
            self.assertEqual((r.provisioned, r.reason, r.env, r.wallet_address), (True, None, "staging", "0xabc"))
            self.assertEqual(cli.seen()["argv"], ["bootstrap", "--agent", "hermes", "--timeout-ms", "7000"])

    def test_not_provisioned_carries_the_reason(self):
        for reason in ("key-present", "account-exists"):
            body = f'print(json.dumps({{"ok": True, "env": "production", "provisioned": False, "reason": "{reason}"}}))'
            with FakeCli(body) as cli:
                r = localcli.bootstrap(env=cli.env)
                self.assertEqual((r.provisioned, r.reason), (False, reason))

    def test_malformed_answers_are_none(self):
        for body in ("sys.exit(2)", 'print(json.dumps({"ok": False, "provisioned": True}))',
                     'print(json.dumps({"ok": True}))', "print('nope')"):
            with FakeCli(body) as cli:
                self.assertIsNone(localcli.bootstrap(env=cli.env), body)


def _real_cli():
    root = Path(os.environ.get("VAIBOT_GUARD_SRC") or Path(__file__).resolve().parents[2] / "vaibot-guard")
    script = root / "scripts" / "vaibot-guard.mjs"
    if not (shutil.which("node") and script.is_file()):
        return None
    # Only a guard that has the subcommand: older checkouts don't.
    return script if '"classify"' in script.read_text(encoding="utf-8") else None


class RealGuardCliTests(unittest.TestCase):
    """End-to-end against the guard's own classifier — the floor itself."""

    def setUp(self):
        script = _real_cli()
        if not script:
            self.skipTest("no guard checkout with the classify subcommand")
        # A bare env: classify must need no credentials and no daemon.
        self.env = {"PATH": os.environ.get("PATH", ""), "VAIBOT_GUARD_CLI": str(script),
                    "HOME": tempfile.mkdtemp()}

    def test_floor_denies_through_the_hermes_shell_tool(self):
        destructive = "".join(("rm", " -rf", " /"))
        v = localcli.classify("terminal", {"command": destructive}, env=self.env, timeout_s=20)
        self.assertEqual(v.verdict_hint, "deny")

    def test_safe_work_is_allowed(self):
        self.assertEqual(localcli.classify("terminal", {"command": "ls -la"}, env=self.env, timeout_s=20).verdict_hint, "allow")
        self.assertEqual(localcli.classify("read_file", {"path": "src/x.py"}, env=self.env, timeout_s=20).verdict_hint, "allow")

    def test_python_execution_escalates(self):
        v = localcli.classify("execute_code", {"code": "cat = open('/tmp/x').read()"}, env=self.env, timeout_s=20)
        self.assertEqual(v.verdict_hint, "ask")


if __name__ == "__main__":
    unittest.main()
