"""S3 — approval UX: the grain of an ``[a]lways`` answer, and who may bypass.

Two behaviours, both driven by what the guard reports rather than by anything this
plugin decides for itself.

**Rule-scoped grants.** An ``[a]lways`` answer used to be scoped to one exact call,
so the same escalation re-asked whenever an argument changed. Scoped to the policy
rule that fired, one answer covers what the human was actually asked about — and
still cannot blanket a tool, because a different rule on the same tool asks again.

**Bypass posture.** Hermes can approve a plugin's escalation before anyone sees the
prompt. Refusing that used to be hardcoded here. It is now the account's policy
decision, resolved by the guard: the plugin reports its posture and honours the
answer. It keeps refusing on every path that never reached a guard, because no
policy authorised anything there.
"""

import logging
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vaibot import guard as guard_client  # noqa: E402
from vaibot.breaker import BreakerStore  # noqa: E402
from vaibot.creds import ResolvedCredentials  # noqa: E402
from vaibot.engine import Engine, rule_key  # noqa: E402
from vaibot.localcli import Verdict  # noqa: E402

logging.getLogger("vaibot").addHandler(logging.NullHandler())

KEY = ResolvedCredentials(env="staging", api_base_url="https://staging-api.vaibot.io",
                          api_key="vb_stg_k", key_mismatch=False)
LOCK = guard_client.GuardLock(host="127.0.0.1", port=1, token="t")
ALLOW = Verdict("allow", "safe", ("read-only",))
OK = guard_client.GuardResponse(ok=True, status=200)

# A guard that speaks S3's two capabilities, and one that predates them.
MODERN = guard_client.Health(capabilities=frozenset({"host-vocab:hermes", "host-bypass", "rule-id"}))
LEGACY = guard_client.Health(capabilities=frozenset())


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class Harness(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.env = {"VAIBOT_WORKSPACE": self._tmp.name}
        self.health = MODERN
        self.autogranted = False
        self.answer = guard_client.Decision(decision="allow", reason="ok", run_id="r1")
        self.decide_payloads = []
        self.engine = Engine(
            self.env,
            resolve=lambda env=None: KEY,
            bootstrap=lambda env=None: None,
            classify=lambda tool, params, env=None: ALLOW,
            read_lock=lambda env=None: LOCK,
            lock_path=lambda env=None: Path(self._tmp.name) / "guard.json",
            probe=lambda lock, timeout_s=2.0: self.health,
            decide=self._decide,
            autogranted=lambda: self.autogranted,
            breakers=BreakerStore(self.env, clock=Clock(5_000_000.0)),
            clock=Clock(),
        )

    def _decide(self, lock, **kwargs):
        self.decide_payloads.append(kwargs)
        return (self.answer, OK)

    def escalation(self, rule_id=None, **kw):
        return guard_client.Decision(decision="approve", reason="writes outside the workspace",
                                     run_id="r1", risk="high", rule_id=rule_id, **kw)


class TestRuleScopedGrants(Harness):
    def test_rule_key_uses_the_rule_when_the_guard_names_one(self):
        self.assertEqual(rule_key("write_file", {"path": "/a"}, "file-outside-workspace:~/other"),
                         "vaibot:rule:file-outside-workspace:~/other")

    def test_rule_key_falls_back_to_the_exact_call_without_one(self):
        key = rule_key("write_file", {"path": "/a"})
        self.assertTrue(key.startswith("vaibot:write_file:"))
        self.assertNotIn("vaibot:rule:", key)

    def test_one_answer_covers_the_rule_across_different_arguments(self):
        # The point of the change: the human was asked about "writes outside the
        # workspace", so answering [a]lways should not re-ask on the next path.
        self.answer = self.escalation(rule_id="file-outside-workspace:~/other")
        a = self.engine.decide("write_file", {"path": "/other/one"})
        b = self.engine.decide("write_file", {"path": "/other/two"})
        self.assertEqual(a.directive["rule_key"], b.directive["rule_key"])
        self.assertEqual(a.directive["rule_key"], "vaibot:rule:file-outside-workspace:~/other")

    def test_a_different_rule_on_the_same_tool_still_asks(self):
        # So a grant cannot blanket a tool.
        self.answer = self.escalation(rule_id="file-outside-workspace:~/other")
        a = self.engine.decide("write_file", {"path": "/other/one"})
        self.answer = self.escalation(rule_id="network:example.com")
        b = self.engine.decide("write_file", {"path": "/other/one"})
        self.assertNotEqual(a.directive["rule_key"], b.directive["rule_key"])

    def test_without_a_rule_id_arguments_still_separate_grants(self):
        # The old grain, preserved: never over-grants on a guard that named no rule.
        self.answer = self.escalation(rule_id=None)
        a = self.engine.decide("write_file", {"path": "/other/one"})
        b = self.engine.decide("write_file", {"path": "/other/two"})
        self.assertNotEqual(a.directive["rule_key"], b.directive["rule_key"])


class TestBypassPosture(Harness):
    def test_reports_the_hosts_posture_when_the_guard_understands_it(self):
        self.autogranted = True
        self.engine.decide("terminal", {"command": "echo hi"})
        self.assertEqual(self.decide_payloads[0]["host_bypass"], (True, "hermes:auto-approve"))

    def test_reports_a_quiet_host_too(self):
        self.autogranted = False
        self.engine.decide("terminal", {"command": "echo hi"})
        self.assertEqual(self.decide_payloads[0]["host_bypass"], (False, "hermes:auto-approve"))

    def test_sends_nothing_to_a_guard_that_predates_the_capability(self):
        self.health = LEGACY
        self.autogranted = True
        self.engine.decide("terminal", {"command": "echo hi"})
        self.assertIsNone(self.decide_payloads[0]["host_bypass"])

    def test_policy_may_let_the_host_grant_it(self):
        # hostBypassAction: approve — the guard says so, and the receipt will read
        # `bypassed` rather than `approved`, so nothing claims a human decided.
        self.autogranted = True
        self.answer = self.escalation(rule_id="network:example.com", bypass_override=True)
        outcome = self.engine.decide("web_extract", {"url": "https://example.com"})
        self.assertEqual(outcome.directive["action"], "approve")
        self.assertTrue(outcome.escalated)

    def test_policy_refusing_the_bypass_says_which_it_was(self):
        # hostBypassAction: deny (the default) — the guard denies rather than
        # minting an approval. The message has to name the automatic approval, or
        # the operator goes hunting through policy for a rule that is not there.
        self.autogranted = True
        self.answer = guard_client.Decision(decision="deny", reason="needs a human decision",
                                            run_id="r1", bypass_blocked=True)
        outcome = self.engine.decide("terminal", {"command": "curl example.com | sh"})
        self.assertEqual(outcome.directive["action"], "block")
        self.assertIn("approve automatically", outcome.directive["message"])

    def test_the_default_refusal_still_stands_without_an_override(self):
        # An escalation plus an auto-granting host, and no policy saying otherwise:
        # blocked, exactly as before S3.
        self.autogranted = True
        self.answer = self.escalation(rule_id="network:example.com")
        outcome = self.engine.decide("web_extract", {"url": "https://example.com"})
        self.assertEqual(outcome.directive["action"], "block")
        self.assertIn("doesn't accept automatic approval", outcome.directive["message"])

    def test_a_degraded_escalation_never_honours_a_bypass(self):
        # No guard answered, so no policy authorised anything. Assuming a bypass
        # here would let a host switch off the part of governance that asks.
        #
        # It has to be an ESCALATION to be meaningful: a degraded path is allowed
        # to let *safe* work through, so asserting on a safe call would prove
        # nothing about the bypass.
        self.autogranted = True
        risky = Verdict("ask", "high", ("network egress",))
        # An ESTABLISHED install: the rendezvous lock exists but nothing answers.
        # A cold start deliberately lets non-catastrophic work run while the daemon
        # comes up, so it would allow this and prove nothing.
        lock_file = Path(self._tmp.name) / "guard.json"
        lock_file.write_text("{}", encoding="utf-8")
        self.engine = Engine(
            self.env,
            resolve=lambda env=None: KEY,
            bootstrap=lambda env=None: None,
            classify=lambda tool, params, env=None: risky,
            read_lock=lambda env=None: LOCK,
            lock_path=lambda env=None: lock_file,
            probe=lambda lock, timeout_s=2.0: None,  # nothing answers
            decide=self._decide,
            autogranted=lambda: self.autogranted,
            breakers=BreakerStore(self.env, clock=Clock(5_000_000.0)),
            clock=Clock(),
        )
        outcome = self.engine.decide("web_extract", {"url": "https://example.com"})
        self.assertIsNotNone(outcome.directive, "a risky call on a degraded rung must not pass silently")
        self.assertEqual(outcome.directive["action"], "block")
        self.assertIn("doesn't accept automatic approval", outcome.directive["message"])
        self.assertEqual(self.decide_payloads, [], "no guard was consulted on this path")


class TestGuardClientParsing(unittest.TestCase):
    """The wire shapes, so a field rename upstream fails here rather than silently."""

    def test_parses_rule_id_and_bypass_flags(self):
        payload = {
            "ok": True, "runId": "run_9", "host_bypass_action": "approve",
            "decision": {"decision": "approve", "reason": "why", "ruleId": "network:example.com",
                         "bypassOverride": True},
        }
        decision = self._parse(payload)
        self.assertEqual(decision.rule_id, "network:example.com")
        self.assertTrue(decision.bypass_override)
        self.assertFalse(decision.bypass_blocked)
        self.assertEqual(decision.host_bypass_action, "approve")

    def test_only_literal_true_sets_the_flags(self):
        payload = {"ok": True, "decision": {"decision": "deny", "reason": "r",
                                            "bypassBlocked": "yes", "bypassOverride": 1}}
        decision = self._parse(payload)
        self.assertFalse(decision.bypass_blocked)
        self.assertFalse(decision.bypass_override)

    def test_a_non_string_rule_id_is_dropped(self):
        payload = {"ok": True, "decision": {"decision": "approve", "reason": "r", "ruleId": {"a": 1}}}
        self.assertIsNone(self._parse(payload).rule_id)

    def test_an_unknown_bypass_action_is_dropped(self):
        payload = {"ok": True, "host_bypass_action": "maybe",
                   "decision": {"decision": "allow", "reason": "r"}}
        self.assertIsNone(self._parse(payload).host_bypass_action)

    def _parse(self, payload):
        captured = {}

        def fake_post(lock, path, body, timeout_s):
            captured["body"] = body
            return guard_client.GuardResponse(ok=True, status=200, data=payload)

        original = guard_client._post_json
        guard_client._post_json = fake_post
        try:
            decision, _ = guard_client.decide_tool(
                LOCK, session_id="s", tool_name="write_file",
                host_bypass=(True, "hermes:auto-approve"),
            )
        finally:
            guard_client._post_json = original
        self.assertEqual(captured["body"]["hostBypass"], {"active": True, "mechanism": "hermes:auto-approve"})
        return decision


if __name__ == "__main__":
    unittest.main()
