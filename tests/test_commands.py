"""``/vaibot`` — the status readout, and what it must never print.

Registered through Hermes' documented slash-command API:
``ctx.register_command(name, handler, description="", args_hint="")``, where the
handler takes the raw argument string and returns text. The same output goes to a
CLI session, Telegram and Discord, which is why the credential assertions here
matter as much as the content ones.
"""

import json
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vaibot import commands  # noqa: E402
from vaibot import guard as guard_client  # noqa: E402
from vaibot.containment import containment_file  # noqa: E402

logging.getLogger("vaibot").addHandler(logging.NullHandler())

SECRET_KEY = "vb_stg_supersecretkeyvalue"
GUARD_TOKEN = "deadbeefcafebabedeadbeefcafebabe"


class Sandbox(unittest.TestCase):
    """HOME redirected so containment, creds and breaker state are this test's."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._real_home = os.environ.get("HOME")
        os.environ["HOME"] = self._tmp.name
        self.addCleanup(self._restore)
        self.env = {}
        # No guard by default; individual tests opt into one.
        self._real_read_lock = guard_client.read_lock
        self._real_probe = guard_client.probe
        guard_client.read_lock = lambda env=None: None
        self.addCleanup(self._restore_guard)

    def _restore(self):
        if self._real_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._real_home
        self._tmp.cleanup()

    def _restore_guard(self):
        guard_client.read_lock = self._real_read_lock
        guard_client.probe = self._real_probe

    def contain(self, reason="laptop looks compromised", at=None):
        path = containment_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        body = {"contained": True, "reason": reason}
        if at:
            body["at"] = at
        path.write_text(json.dumps(body), encoding="utf-8")

    def seed_creds(self, api_key=SECRET_KEY, env="staging"):
        d = Path(self._tmp.name) / ".vaibot"
        d.mkdir(parents=True, exist_ok=True)
        store = {"version": 3, "active_env": env,
                 "environments": {env: {"api_key": api_key} if api_key else {}}}
        (d / "credentials.json").write_text(json.dumps(store), encoding="utf-8")

    def with_guard(self, health):
        guard_client.read_lock = lambda env=None: guard_client.GuardLock(
            host="127.0.0.1", port=39111, token=GUARD_TOKEN)
        guard_client.probe = lambda lock, timeout_s=2.0: health


class TestDispatch(Sandbox):
    def test_bare_and_help_both_show_usage(self):
        for args in ["", "   ", "help", "--help", "-h"]:
            with self.subTest(args=args):
                self.assertIn("/vaibot status", commands.handle(args, self.env))

    def test_an_unknown_subcommand_says_so_and_shows_usage(self):
        out = commands.handle("frobnicate", self.env)
        self.assertIn("Unknown subcommand", out)
        self.assertIn("/vaibot status", out)

    def test_it_never_raises(self):
        # A command that throws inside the agent's own chat is a worse failure
        # than one that says it could not answer.
        guard_client.read_lock = lambda env=None: (_ for _ in ()).throw(RuntimeError("boom"))
        self.assertIsInstance(commands.handle("status", self.env), str)


def parse_grid(out: str) -> dict:
    """Grid rows as {label: value}.

    Parsing rather than matching whole rendered lines, so a column-width or
    separator change doesn't fail every assertion in this file.
    """
    rows = {}
    for line in out.splitlines():
        if not line.startswith("  ") or line.strip() == "":
            continue
        parts = line.strip().split("   ", 1)
        if len(parts) == 2:
            rows[parts[0].strip()] = parts[1].strip()
    return rows


def grid_order(out: str) -> list:
    return list(parse_grid(out).keys())


class TestStatusContent(Sandbox):
    def test_containment_leads_when_engaged(self):
        self.contain()
        out = commands.handle("status", self.env)
        grid = parse_grid(out)
        self.assertIn("CONTAINED", grid["Containment"])
        self.assertIn("laptop looks compromised", grid["Containment"])
        self.assertIn("vaibot release", out, "it should say how to lift it")
        # Containment answers "why did my agent stop", so it is the first row.
        self.assertEqual(grid_order(out)[0], "Containment")

    def test_says_not_engaged_when_clear(self):
        grid = parse_grid(commands.handle("status", self.env))
        self.assertEqual(grid["Containment"], "not engaged")

    def test_reports_containment_with_no_guard_and_no_network(self):
        # The point of reading local state: this is exactly when a daemon is gone.
        self.contain(reason=None)
        grid = parse_grid(commands.handle("status", self.env))
        self.assertIn("CONTAINED", grid["Containment"])
        self.assertIn("none found", grid["Guard"])

    def test_names_the_guard_and_its_capabilities(self):
        self.with_guard(guard_client.Health(capabilities=frozenset({"rule-id", "host-bypass"}), version="2.2.0"))
        grid = parse_grid(commands.handle("status", self.env))
        self.assertIn("answering", grid["Guard"])
        self.assertIn("2.2.0", grid["Guard"])
        self.assertIn("host-bypass", grid["Understands"])
        self.assertIn("rule-id", grid["Understands"])

    def test_a_stale_lock_reads_as_flagged_not_healthy(self):
        self.with_guard(None)  # lock present, nothing answers
        self.assertIn("nothing answers", parse_grid(commands.handle("status", self.env))["Guard"])

    def test_reports_the_account_environment_without_the_key(self):
        self.seed_creds()
        self.assertEqual(parse_grid(commands.handle("status", self.env))["Account"], "key resolves · staging")

    def test_says_when_there_is_no_key_yet(self):
        self.seed_creds(api_key=None)
        self.assertIn("no key yet", parse_grid(commands.handle("status", self.env))["Account"])

    def test_every_row_is_a_label_and_a_value(self):
        # Guards the grid shape itself: a row that lost its value would read as a
        # stray sentence in the middle of the table.
        self.with_guard(guard_client.Health(capabilities=frozenset({"rule-id"}), version="2.2.0"))
        self.seed_creds()
        grid = parse_grid(commands.handle("status", self.env))
        self.assertEqual(set(grid), {"Containment", "Guard", "Understands", "Classifier", "Account", "Breaker"})
        for label, value in grid.items():
            self.assertTrue(value, f"{label} has no value")


class TestNeverLeaksCredentials(Sandbox):
    """Output can land in a Telegram or Discord channel. Treat it as public."""

    def test_the_api_key_never_appears(self):
        self.seed_creds()
        self.with_guard(guard_client.Health(capabilities=frozenset({"rule-id"}), version="2.2.0"))
        out = commands.handle("status", self.env)
        self.assertNotIn(SECRET_KEY, out)
        self.assertNotIn(SECRET_KEY[6:], out, "not even a suffix of the key")

    def test_the_guard_token_never_appears(self):
        self.with_guard(guard_client.Health(version="2.2.0"))
        out = commands.handle("status", self.env)
        self.assertNotIn(GUARD_TOKEN, out)
        self.assertNotIn(GUARD_TOKEN[:8], out)


class TestRegistration(unittest.TestCase):
    def test_registers_through_the_documented_api(self):
        seen = {}

        class Ctx:
            def register_command(self, name, handler, description="", args_hint=""):
                seen.update(name=name, handler=handler, description=description, args_hint=args_hint)

        commands.register(Ctx())
        self.assertEqual(seen["name"], "vaibot", "registered without the slash, per the docs")
        self.assertTrue(callable(seen["handler"]))
        self.assertTrue(seen["description"])
        # The handler takes the raw argument string and returns text.
        self.assertIsInstance(seen["handler"]("help"), str)

    def test_a_hermes_without_slash_commands_still_loads_the_plugin(self):
        class Ctx:
            pass  # no register_command

        commands.register(Ctx())  # must not raise — governance outranks a readout

    def test_a_failing_registration_does_not_break_loading(self):
        class Ctx:
            def register_command(self, *a, **k):
                raise RuntimeError("no room")

        commands.register(Ctx())  # swallowed


if __name__ == "__main__":
    unittest.main()
