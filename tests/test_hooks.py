"""The hook layer: what Hermes actually calls.

Pins the two postures that matter most: the decision fails closed (Hermes runs
a call whose hook raised, so the hook must not raise), and a declined
escalation lands on the receipt chain as denied, not approved.
"""

import logging
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import vaibot  # noqa: E402
from vaibot import guard as guard_client  # noqa: E402
from vaibot.engine import Outcome  # noqa: E402

logging.getLogger("vaibot").addHandler(logging.NullHandler())

LOCK = guard_client.GuardLock(host="127.0.0.1", port=1, token="t")


class FakeEngine:
    def __init__(self, outcome=None, error=None):
        self.outcome = outcome or Outcome(None, "guard", "run_1")
        self.error = error
        self.calls = []

    def decide(self, tool_name, args, session_id=""):
        self.calls.append((tool_name, args, session_id))
        if self.error:
            raise self.error
        return self.outcome


class HookCase(unittest.TestCase):
    def setUp(self):
        vaibot._runs.clear()
        self._saved_engine = vaibot._engine

    def tearDown(self):
        vaibot._engine = self._saved_engine
        vaibot._runs.clear()

    def use(self, engine):
        vaibot._engine = engine
        return engine


class PreToolCallTests(HookCase):
    def test_returns_the_directive_and_remembers_the_run(self):
        directive = {"action": "approve", "message": "m", "rule_key": "k"}
        self.use(FakeEngine(Outcome(directive, "guard", "run_9", escalated=True)))
        out = vaibot._on_pre_tool_call(tool_name="terminal", args={"command": "x"}, tool_call_id="tc1", session_id="s")
        self.assertEqual(out, directive)
        self.assertEqual(vaibot._runs["tc1"], {"run_id": "run_9", "escalated": True})

    def test_governance_tools_are_never_governed(self):
        engine = self.use(FakeEngine())
        self.assertIsNone(vaibot._on_pre_tool_call(tool_name="mcp__vaibot__status", args={}))
        self.assertEqual(engine.calls, [])

    def test_non_dict_args_are_treated_as_empty(self):
        engine = self.use(FakeEngine())
        vaibot._on_pre_tool_call(tool_name="terminal", args="rm", tool_call_id="t")
        self.assertEqual(engine.calls[0][1], {})

    def test_an_internal_error_blocks_in_enforce(self):
        # Hermes treats a raising hook as "no directive" and would RUN the call.
        self.use(FakeEngine(error=RuntimeError("boom")))
        with mock.patch.dict(os.environ, {"VAIBOT_MODE": "enforce"}, clear=False):
            os.environ.pop("VAIBOT_FAIL_OPEN", None)
            with self.assertLogs("vaibot", level="ERROR"):
                out = vaibot._on_pre_tool_call(tool_name="terminal", args={}, tool_call_id="t")
        self.assertEqual(out["action"], "block")
        self.assertIn("fail-closed", out["message"])

    def test_an_internal_error_proceeds_in_observe_or_fail_open(self):
        self.use(FakeEngine(error=RuntimeError("boom")))
        for env in ({"VAIBOT_MODE": "observe"}, {"VAIBOT_FAIL_OPEN": "true"}):
            with mock.patch.dict(os.environ, env, clear=False), self.assertLogs("vaibot", level="ERROR"):
                self.assertIsNone(vaibot._on_pre_tool_call(tool_name="terminal", args={}))

    def test_a_degraded_decision_with_no_run_is_not_tracked(self):
        self.use(FakeEngine(Outcome(None, "guard-down", None)))
        vaibot._on_pre_tool_call(tool_name="terminal", args={}, tool_call_id="t")
        self.assertEqual(vaibot._runs, {})


class FinalizeMappingTests(unittest.TestCase):
    def test_declined_escalation_is_recorded_as_denied(self):
        self.assertEqual(vaibot._finalize_fields({"escalated": True}, "blocked"), ("denied_by_reviewer", "denied"))

    def test_granted_escalation_is_recorded_as_run(self):
        self.assertEqual(vaibot._finalize_fields({"escalated": True}, "ok"), ("allowed", None))
        # Approved, ran, and failed: it ran, so no denial.
        self.assertEqual(vaibot._finalize_fields({"escalated": True}, "error"), ("blocked", None))

    def test_ordinary_calls(self):
        self.assertEqual(vaibot._finalize_fields({"escalated": False}, "ok"), ("allowed", None))
        self.assertEqual(vaibot._finalize_fields({"escalated": False}, "blocked"), ("blocked", None))
        self.assertEqual(vaibot._finalize_fields({}, "error"), ("blocked", None))


class PostToolCallTests(HookCase):
    def test_finalizes_the_remembered_run(self):
        vaibot._runs["tc1"] = {"run_id": "run_1", "escalated": True}
        with mock.patch.object(guard_client, "read_lock", return_value=LOCK), \
             mock.patch.object(guard_client, "finalize_tool",
                               return_value=guard_client.GuardResponse(ok=True)) as fin:
            vaibot._on_post_tool_call(tool_name="terminal", tool_call_id="tc1", session_id="s",
                                      status="blocked", error_message="BLOCKED: denied by user", duration_ms=3)
        kwargs = fin.call_args.kwargs
        self.assertEqual((kwargs["run_id"], kwargs["outcome"], kwargs["approval"]),
                         ("run_1", "denied_by_reviewer", "denied"))
        self.assertEqual(kwargs["error"], "BLOCKED: denied by user")
        self.assertEqual(vaibot._runs, {}, "the entry is consumed")

    def test_nothing_to_finalize_without_a_run(self):
        with mock.patch.object(guard_client, "finalize_tool") as fin:
            vaibot._on_post_tool_call(tool_name="terminal", tool_call_id="unknown", status="ok")
        fin.assert_not_called()

    def test_bookkeeping_failures_never_raise(self):
        vaibot._runs["tc1"] = {"run_id": "run_1"}
        with mock.patch.object(guard_client, "read_lock", side_effect=RuntimeError("disk")), \
             self.assertLogs("vaibot", level="WARNING"):
            self.assertIsNone(vaibot._on_post_tool_call(tool_name="terminal", tool_call_id="tc1", status="ok"))

    def test_a_vanished_guard_is_logged_not_raised(self):
        vaibot._runs["tc1"] = {"run_id": "run_1"}
        with mock.patch.object(guard_client, "read_lock", return_value=None), \
             self.assertLogs("vaibot", level="WARNING") as logs:
            vaibot._on_post_tool_call(tool_name="terminal", tool_call_id="tc1", status="ok")
        self.assertTrue(any("unfinalized" in m for m in logs.output))


class RegisterTests(unittest.TestCase):
    def test_registers_both_hooks(self):
        ctx = mock.Mock()
        with mock.patch.object(vaibot, "resolve_credentials") as rc, \
             mock.patch.object(guard_client, "read_lock", return_value=LOCK):
            rc.return_value.key_mismatch = False
            vaibot.register(ctx)
        registered = {c.args[0]: c.args[1] for c in ctx.register_hook.call_args_list}
        self.assertIs(registered["pre_tool_call"], vaibot._on_pre_tool_call)
        self.assertIs(registered["post_tool_call"], vaibot._on_post_tool_call)


if __name__ == "__main__":
    unittest.main()
