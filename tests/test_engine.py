"""The decision pipeline, rung by rung.

Every dependency is a fake, so each rung of the degrade ladder is exercised
without a daemon, node, or Hermes: no key, breaker tripped, guard down (cold
start vs. established install), and the guard's own verdict in observe and
enforce.
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
from vaibot.engine import ACCOUNT_EXISTS_RETRY_S, BOOTSTRAP_RETRY_S, Engine, rule_key  # noqa: E402
from vaibot.localcli import BootstrapResult, Verdict  # noqa: E402

# Expected warnings are asserted where they matter; keep the rest out of the run.
logging.getLogger("vaibot").addHandler(logging.NullHandler())

KEY = ResolvedCredentials(env="staging", api_base_url="https://staging-api.vaibot.io", api_key="vb_stg_k", key_mismatch=False)
NO_KEY = ResolvedCredentials(env="staging", api_base_url="https://staging-api.vaibot.io", api_key=None, key_mismatch=False)
LOCK = guard_client.GuardLock(host="127.0.0.1", port=1, token="t")

ALLOW = Verdict("allow", "safe", ("read-only",))
ASK = Verdict("ask", "high", ("network egress",))
DENY = Verdict("deny", "dangerous", ("rm -rf on a protected target",))


def decision(verdict="allow", reason="because", floor=False, mode=None, risk=None, run_id="run_1"):
    return guard_client.Decision(decision=verdict, reason=reason, run_id=run_id, floor=floor,
                                 risk=risk, effective_mode=mode)


OK = guard_client.GuardResponse(ok=True, status=200)


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class Rig:
    """An Engine wired to fakes. Tweak the attributes, then call decide()."""

    def __init__(self, **env):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = {"VAIBOT_CREDS_DIR": self.tmp.name, "VAIBOT_WORKSPACE": "/work", **env}
        self.creds = KEY
        self.after_bootstrap = None       # creds to resolve once bootstrap succeeds
        self.bootstrap_result = None
        self.bootstrap_calls = 0
        self.verdict = ALLOW              # classifier answer (None = unavailable)
        self.classified = []
        self.lock = LOCK
        self.lock_file_exists = True      # False = cold start
        self.health = guard_client.Health()
        self.answer = (decision(), OK)
        self.decide_calls = []
        self.autogranted = False
        self.clock = Clock()
        self.breaker_clock = Clock(5_000_000.0)
        self.breakers = BreakerStore(self.env, clock=self.breaker_clock)
        self.engine = Engine(
            self.env,
            resolve=self._resolve,
            bootstrap=self._bootstrap,
            classify=self._classify,
            read_lock=lambda env=None: self.lock,
            lock_path=self._lock_path,
            probe=lambda lock, timeout_s=2.0: self.health,
            decide=self._decide,
            autogranted=lambda: self.autogranted,
            breakers=self.breakers,
            clock=self.clock,
        )

    def _resolve(self, env=None):
        return self.creds

    def _bootstrap(self, env=None):
        self.bootstrap_calls += 1
        if self.bootstrap_result is not None and self.after_bootstrap is not None:
            self.creds = self.after_bootstrap
        return self.bootstrap_result

    def _classify(self, tool_name, params, env=None):
        self.classified.append(tool_name)
        return self.verdict

    def _lock_path(self, env=None):
        p = Path(self.tmp.name) / "guard" / "guard.json"
        if self.lock_file_exists:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("{}")
        elif p.exists():
            p.unlink()
        return p

    def _decide(self, lock, **kwargs):
        self.decide_calls.append(kwargs)
        return self.answer

    def decide(self, tool="terminal", args=None):
        return self.engine.decide(tool, args if args is not None else {"command": "ls"}, "sess")

    def trip(self):
        b = self.breakers.load()
        for _ in range(3):
            b.record_failure("down")
        self.breakers.save(b)

    def close(self):
        self.tmp.cleanup()


class RigCase(unittest.TestCase):
    def rig(self, **env):
        r = Rig(**env)
        self.addCleanup(r.close)
        return r


# ── rung 4: the guard answers ─────────────────────────────────────────────────


class GuardVerdictTests(RigCase):
    def test_allow_proceeds_and_keeps_the_run(self):
        out = self.rig().decide()
        self.assertIsNone(out.directive)
        self.assertEqual((out.rung, out.run_id, out.escalated), ("guard", "run_1", False))

    def test_deny_blocks_with_the_reason(self):
        r = self.rig()
        r.answer = (decision("deny", "File mutation touches denied path"), OK)
        out = r.decide("write_file", {"path": "/etc/hosts"})
        self.assertEqual(out.directive["action"], "block")
        self.assertIn("File mutation touches denied path", out.directive["message"])
        self.assertIn("write_file", out.directive["message"])

    def test_approve_escalates_to_the_native_prompt(self):
        r = self.rig()
        r.answer = (decision("approve", "Network destination not allowlisted", risk={"risk": "high"}), OK)
        args = {"urls": ["https://example.invalid"]}
        out = r.decide("web_extract", args)
        self.assertEqual(out.directive["action"], "approve")
        self.assertIn("high risk", out.directive["message"])
        self.assertIn("Network destination not allowlisted", out.directive["message"])
        self.assertEqual(out.directive["rule_key"], rule_key("web_extract", args))
        self.assertTrue(out.escalated)
        self.assertEqual(out.run_id, "run_1")

    def test_an_escalation_hermes_would_auto_grant_is_blocked(self):
        r = self.rig()
        r.autogranted = True
        r.answer = (decision("approve", "needs a human"), OK)
        out = r.decide()
        self.assertEqual(out.directive["action"], "block")
        self.assertIn("approve automatically", out.directive["message"])
        # Still an escalated run, so the receipt records it as not granted.
        self.assertTrue(out.escalated)

    def test_unknown_verdict_fails_closed_unless_fail_open(self):
        r = self.rig()
        r.answer = (decision("frobnicate"), OK)
        self.assertEqual(r.decide().directive["action"], "block")
        r2 = self.rig(VAIBOT_FAIL_OPEN="true")
        r2.answer = (decision("frobnicate"), OK)
        self.assertIsNone(r2.decide().directive)

    def test_observe_allows_everything_but_the_floor(self):
        r = self.rig()
        for verdict in ("approve", "deny"):
            r.answer = (decision(verdict, mode="observe"), OK)
            self.assertIsNone(r.decide().directive, verdict)
        r.answer = (decision("deny", "Classifier: dangerous", floor=True, mode="observe"), OK)
        out = r.decide()
        self.assertEqual(out.directive["action"], "block")
        self.assertIn("catastrophic floor", out.directive["message"])

    def test_the_guards_mode_beats_the_local_one(self):
        r = self.rig(VAIBOT_MODE="observe")
        r.answer = (decision("deny", mode="enforce"), OK)
        self.assertEqual(r.decide().directive["action"], "block")
        r2 = self.rig(VAIBOT_MODE="enforce")
        r2.answer = (decision("deny", mode="observe"), OK)
        self.assertIsNone(r2.decide().directive)

    def test_local_mode_applies_when_the_guard_is_silent_on_it(self):
        r = self.rig(VAIBOT_MODE="observe")
        r.answer = (decision("deny", mode=None), OK)
        self.assertIsNone(r.decide().directive)

    def test_decide_payload(self):
        r = self.rig()
        r.decide("terminal", {"command": "ls", "workdir": "/w"})
        call = r.decide_calls[0]
        self.assertEqual(call["params"], {"command": "ls", "workdir": "/w"})
        self.assertEqual(call["workspace_dir"], "/work")
        self.assertEqual(call["session_id"], "sess")

    def test_old_guards_get_renamed_tools_new_ones_native(self):
        r = self.rig()
        r.decide("terminal")
        self.assertEqual(r.decide_calls[-1]["tool_name"], "shell")
        r.health = guard_client.Health(capabilities=frozenset({"host-vocab:hermes"}))
        r.decide("terminal")
        self.assertEqual(r.decide_calls[-1]["tool_name"], "terminal")

    def test_success_resets_the_breaker(self):
        r = self.rig()
        b = r.breakers.load()
        b.record_failure("x")
        r.breakers.save(b)
        r.decide()
        self.assertEqual(r.breakers.load().failures, [])


class GuardErrorTests(RigCase):
    def test_transport_failure_blocks_and_counts(self):
        r = self.rig()
        r.answer = (None, guard_client.GuardResponse(ok=False, unreachable=True, error="timed out"))
        out = r.decide()
        self.assertEqual(out.directive["action"], "block")
        self.assertIn("didn't answer", out.directive["message"])
        self.assertEqual(len(r.breakers.load().failures), 1)

    def test_a_4xx_blocks_but_is_not_an_outage(self):
        r = self.rig()
        r.answer = (None, guard_client.GuardResponse(ok=False, unreachable=False, status=401))
        out = r.decide()
        self.assertEqual(out.directive["action"], "block")
        self.assertIn("401", out.directive["message"])
        self.assertEqual(r.breakers.load().failures, [])

    def test_lenient_modes_still_hold_the_floor_on_failure(self):
        for env in ({"VAIBOT_MODE": "observe"}, {"VAIBOT_FAIL_OPEN": "true"}):
            r = self.rig(**env)
            r.answer = (None, guard_client.GuardResponse(ok=False, unreachable=True))
            r.verdict = ASK
            self.assertIsNone(r.decide().directive, env)
            r.verdict = DENY
            self.assertEqual(r.decide().directive["action"], "block", env)


# ── rung 3: guard down ────────────────────────────────────────────────────────


class GuardDownTests(RigCase):
    def rig(self, **env):
        # Keep the breaker out of the way: these tests are about rung 3 alone.
        return super().rig(VAIBOT_BREAKER_FAILURE_THRESHOLD="100", **env)

    def test_cold_start_lets_non_catastrophic_work_run(self):
        r = self.rig()
        r.lock, r.health, r.lock_file_exists = None, None, False
        for verdict in (ALLOW, ASK):
            r.verdict = verdict
            self.assertIsNone(r.decide().directive)
        r.verdict = DENY
        self.assertEqual(r.decide().directive["action"], "block")
        self.assertEqual(r.decide_calls, [])

    def test_cold_start_without_a_classifier_asks_a_human(self):
        r = self.rig()
        r.lock, r.health, r.lock_file_exists, r.verdict = None, None, False, None
        self.assertEqual(r.decide().directive["action"], "approve")

    def test_established_install_governs_locally_and_says_so(self):
        r = self.rig()
        r.health = None  # lock present, nothing answering
        r.verdict = ASK
        with self.assertLogs("vaibot", level="WARNING") as logs:
            out = r.decide()
        self.assertEqual(out.directive["action"], "approve")
        self.assertIn("unreachable", out.directive["message"])
        self.assertTrue(any("possible tampering" in m for m in logs.output))
        r.verdict = ALLOW
        self.assertIsNone(r.decide().directive)
        r.verdict = DENY
        self.assertEqual(r.decide().directive["action"], "block")

    def test_observe_account_override_is_made_visible(self):
        r = self.rig()
        r.lock = guard_client.GuardLock(host="127.0.0.1", port=1, token="t", effective_mode="observe")
        r.health = None
        with self.assertLogs("vaibot", level="WARNING") as logs:
            r.decide()
        self.assertTrue(any("failing closed" in m for m in logs.output))

    def test_explicit_guard_url_is_never_a_cold_start(self):
        r = self.rig(VAIBOT_GUARD_BASE_URL="http://127.0.0.1:1")
        r.health, r.lock_file_exists, r.verdict = None, False, ASK
        # Cold start would have allowed an ASK; established governance escalates it.
        self.assertEqual(r.decide().directive["action"], "approve")

    def test_guard_down_counts_toward_the_breaker(self):
        r = self.rig()
        r.health = None
        r.decide()
        self.assertEqual(len(r.breakers.load().failures), 1)


# ── rung 2: breaker ───────────────────────────────────────────────────────────


class BreakerTests(RigCase):
    def test_tripped_breaker_never_calls_the_guard(self):
        r = self.rig()
        r.trip()
        r.decide()
        self.assertEqual(r.decide_calls, [])

    def test_tripped_decisions(self):
        r = self.rig(VAIBOT_BREAKER_DENYLIST="terminal")
        r.trip()
        out = r.decide("terminal")
        self.assertIn("denylist", out.directive["message"])
        self.assertEqual(r.classified, [], "the denylist is checked before the classifier")
        r.verdict = ALLOW
        self.assertIsNone(r.decide("read_file", {"path": "x"}).directive)
        for verdict in (ASK, DENY, None):
            r.verdict = verdict
            out = r.decide("write_file", {"path": "x"})
            self.assertEqual(out.directive["action"], "block", verdict)
            self.assertIn("circuit breaker tripped", out.directive["message"])

    def test_tripped_in_observe_still_holds_the_floor(self):
        r = self.rig(VAIBOT_MODE="observe")
        r.trip()
        r.verdict = ASK
        self.assertIsNone(r.decide().directive)
        r.verdict = DENY
        self.assertEqual(r.decide().directive["action"], "block")

    def test_three_outages_trip_it_and_the_third_is_decided_by_the_breaker(self):
        r = self.rig()
        r.health = None
        r.verdict = ASK
        self.assertEqual(r.decide().rung, "guard-down")
        self.assertEqual(r.decide().rung, "guard-down")
        out = r.decide()
        self.assertEqual(out.rung, "breaker")
        self.assertEqual(out.directive["action"], "block")

    def test_cooldown_hands_back_to_the_guard(self):
        r = self.rig()
        r.trip()
        self.assertEqual(r.decide().rung, "breaker")
        r.breaker_clock.t += 60_001
        out = r.decide()
        self.assertEqual(out.rung, "guard")
        self.assertEqual(len(r.decide_calls), 1)


# ── rung 1: no key ────────────────────────────────────────────────────────────


class NoKeyTests(RigCase):
    def test_provisioning_success_continues_to_the_guard(self):
        r = self.rig()
        r.creds, r.after_bootstrap = NO_KEY, KEY
        r.bootstrap_result = BootstrapResult(provisioned=True, reason=None, env="staging")
        with self.assertLogs("vaibot", level="WARNING"):
            out = r.decide()
        self.assertEqual(out.rung, "guard")
        self.assertEqual(r.bootstrap_calls, 1)

    def test_keyless_local_governance(self):
        r = self.rig()
        r.creds = NO_KEY
        r.verdict = DENY
        out = r.decide()
        self.assertEqual(out.directive["action"], "block")
        self.assertIn("floor", out.directive["message"])
        r.verdict = ASK
        out = r.decide()
        self.assertEqual(out.directive["action"], "approve")
        self.assertIn("vaibot login", out.directive["message"])
        r.verdict = ALLOW
        self.assertIsNone(r.decide().directive)
        r.verdict = None
        self.assertEqual(r.decide().directive["action"], "approve")
        self.assertEqual(r.decide_calls, [])

    def test_keyless_observe_still_holds_the_floor(self):
        r = self.rig(VAIBOT_MODE="observe")
        r.creds = NO_KEY
        r.verdict = ASK
        self.assertIsNone(r.decide().directive)
        r.verdict = DENY
        self.assertEqual(r.decide().directive["action"], "block")

    def test_a_failed_attempt_backs_off(self):
        r = self.rig()
        r.creds = NO_KEY
        r.decide()
        r.decide()
        self.assertEqual(r.bootstrap_calls, 1)
        r.clock.t += BOOTSTRAP_RETRY_S + 1
        r.decide()
        self.assertEqual(r.bootstrap_calls, 2)

    def test_an_existing_account_backs_off_longer(self):
        r = self.rig()
        r.creds = NO_KEY
        r.bootstrap_result = BootstrapResult(provisioned=False, reason="account-exists", env="staging")
        with self.assertLogs("vaibot", level="WARNING") as logs:
            r.decide()
        self.assertTrue(any("vaibot login" in m for m in logs.output))
        r.clock.t += BOOTSTRAP_RETRY_S + 1
        r.decide()
        self.assertEqual(r.bootstrap_calls, 1)
        r.clock.t += ACCOUNT_EXISTS_RETRY_S
        r.decide()
        self.assertEqual(r.bootstrap_calls, 2)


class RuleKeyTests(unittest.TestCase):
    def test_scoped_to_the_exact_call(self):
        a = rule_key("terminal", {"command": "curl https://a", "workdir": "/w"})
        self.assertEqual(a, rule_key("terminal", {"workdir": "/w", "command": "curl https://a"}))
        self.assertNotEqual(a, rule_key("terminal", {"command": "curl https://b", "workdir": "/w"}))
        self.assertNotEqual(a, rule_key("web_extract", {"command": "curl https://a", "workdir": "/w"}))
        self.assertTrue(a.startswith("vaibot:terminal:"))

    def test_tolerates_unserialisable_args(self):
        self.assertTrue(rule_key("x", {"o": object()}).startswith("vaibot:x:"))


if __name__ == "__main__":
    unittest.main()
