"""``hermes vaibot ...`` — the documented CLI-command API, and what it prints.

Registered through ``ctx.register_cli_command(name, help, setup_fn, handler_fn)``,
where ``setup_fn`` is handed an argparse subparser and ``handler_fn`` the parsed
namespace. The parser is built here with real argparse, so a wrong ``dest`` or a
missing subcommand fails in this file rather than in someone's terminal.

The exit code carries meaning: ``hermes vaibot guard`` is the thing a person runs
when they want to know whether governance came up, so "nothing is governing" must
not exit 0.
"""

import argparse
import io
import contextlib
import logging
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vaibot import cli, commands, launch  # noqa: E402

logging.getLogger("vaibot").addHandler(logging.NullHandler())


def parse(argv):
    parser = argparse.ArgumentParser(prog="hermes vaibot")
    cli.setup(parser)
    return parser.parse_args(argv)


def run(args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.handle(args)
    return code, out.getvalue()


class TestParser(unittest.TestCase):
    def test_every_subcommand_parses(self):
        for name in cli.SUBCOMMANDS:
            self.assertEqual(getattr(parse([name]), "vaibot_subcommand"), name)

    def test_no_subcommand_is_allowed(self):
        # `hermes vaibot` on its own must not be an argparse error; it reads as
        # "tell me what is going on", which is the status readout.
        self.assertIsNone(getattr(parse([]), "vaibot_subcommand"))

    def test_an_unknown_subcommand_is_rejected_by_argparse(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                parse(["frobnicate"])


class TestStatus(unittest.TestCase):
    def test_it_prints_the_same_readout_as_the_slash_command(self):
        with mock.patch.object(commands, "status_text", return_value="VAIBot status\n\n  x") as text:
            code, out = run(parse(["status"]))
        self.assertEqual(code, 0)
        self.assertIn("VAIBot status", out)
        text.assert_called_once()

    def test_no_subcommand_falls_back_to_status(self):
        with mock.patch.object(commands, "status_text", return_value="readout"):
            code, out = run(parse([]))
        self.assertEqual((code, out.strip()), (0, "readout"))

    def test_it_runs_against_the_real_readout_too(self):
        # A smoke test through the actual status path: no daemon, no network.
        code, out = run(parse(["status"]))
        self.assertEqual(code, 0)
        self.assertIn("Containment", out)


class TestGuard(unittest.TestCase):
    def guard(self, result):
        with mock.patch.object(launch, "ensure_guard", return_value=result) as ensure:
            code, out = run(parse(["guard"]))
        ensure.assert_called_once()
        return code, out

    def test_adopting_a_running_guard_is_a_success(self):
        code, out = self.guard(launch.Launch("reused", "guard 2.2.0 on port 39111", 39111))
        self.assertEqual(code, 0)
        self.assertIn("already running", out)
        self.assertIn("39111", out)

    def test_starting_one_is_a_success(self):
        code, out = self.guard(launch.Launch("launched", "", 39112))
        self.assertEqual(code, 0)
        self.assertIn("Started the local guard", out)

    def test_a_failure_exits_non_zero_and_says_where_to_look(self):
        code, out = self.guard(launch.Launch("failed", "no candidate port yielded a healthy guard"))
        self.assertEqual(code, 1, "an operator asking whether governance came up must be told")
        self.assertIn("no candidate port", out)
        self.assertIn("launch.log", out)
        self.assertIn("classifier floor", out, "say what is governing in the meantime")

    def test_an_external_or_disabled_guard_is_not_a_failure(self):
        for status in ("external", "disabled"):
            code, out = self.guard(launch.Launch(status, "because you said so"))
            self.assertEqual(code, 0, status)
            self.assertNotIn("launch.log", out, status)

    def test_every_status_has_a_sentence(self):
        # A status with no headline would print the raw word to an operator.
        for status in ("reused", "launched", "external", "disabled", "in-flight",
                       "cooling", "no-node", "no-launcher", "failed"):
            lines = cli._guard_lines(launch.Launch(status))
            self.assertTrue(lines[2].strip().endswith("."), f"{status}: {lines[2]!r}")


class TestNeverRaises(unittest.TestCase):
    def test_an_error_becomes_a_message_and_a_non_zero_code(self):
        with mock.patch.object(commands, "status_text", side_effect=RuntimeError("boom")):
            code, out = run(parse(["status"]))
        self.assertEqual(code, 1)
        self.assertIn("couldn't run", out)

    def test_an_unknown_subcommand_reaching_the_handler_is_survivable(self):
        # argparse normally prevents this; the handler is defensive anyway,
        # because Hermes owns the parser and could hand over anything.
        code, out = run(argparse.Namespace(vaibot_subcommand="nope"))
        self.assertEqual(code, 2)
        self.assertIn("Unknown command", out)


class TestRegistration(unittest.TestCase):
    def test_registers_through_the_documented_api(self):
        seen = {}

        class Ctx:
            def register_cli_command(self, name, help, setup_fn, handler_fn=None):
                seen.update(name=name, help=help, setup_fn=setup_fn, handler_fn=handler_fn)

        cli.register(Ctx())
        self.assertEqual(seen["name"], "vaibot", "registered without the `hermes` prefix, per the docs")
        self.assertTrue(seen["help"])
        self.assertIs(seen["setup_fn"], cli.setup)
        self.assertIs(seen["handler_fn"], cli.handle)

    def test_a_hermes_without_cli_commands_still_loads_the_plugin(self):
        class Ctx:
            pass

        cli.register(Ctx())  # must not raise — governance outranks a terminal command

    def test_a_failing_registration_does_not_break_loading(self):
        class Ctx:
            def register_cli_command(self, *a, **k):
                raise RuntimeError("name taken")

        cli.register(Ctx())


if __name__ == "__main__":
    unittest.main()
