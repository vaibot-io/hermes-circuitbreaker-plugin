"""Cross-breaker parity: the three invariants every VAIBot circuit breaker owes.

The five breakers (Claude Code, Codex, OpenClaw, Cursor, and this one) share a
guard, a credential store and a signed policy, so they have to agree about what
happens when governance is *not* available. Those agreements were previously held
by inspection — each plugin tests its own rungs, nobody tests the shape. This file
states them as tables over every rung and every mode, so a new rung has to be
added to the table before it can quietly break one of them.

1. **Containment is rung 0.** Engaged, everything blocks: on every rung, in every
   mode, before any guard call, any classification, any grant, and any hash of the
   call. It is the one thing that survives observe and ``FAIL_OPEN``, and a corrupt
   or absent record must never read as engaged.
2. **The catastrophic floor holds on every degraded path.** Whenever the guard
   could not give a usable verdict, the guard's own classifier decides, and a
   classifier ``deny`` blocks — in observe and under ``FAIL_OPEN`` too. Those
   settings change whether you are *asked*, never whether a catastrophic action
   can run.
3. **A host that approves by itself never satisfies an escalation.** Only the
   account's policy, resolved by a guard that actually answered, can allow that.
   Every degraded rung refuses, because no guard answered there.

**What this file cannot prove.** Parity *between* the breakers needs their code:
the same containment record read the same way, the same launch lock, the same
finalize vocabulary. Those assertions belong in one shared conformance suite in
the monorepo (``packages/shared``), run against all five, with each plugin's
adapter reduced to "given this rung, what directive". This file is the Hermes half
of that, in the shape it would take. Two specifics worth carrying over: the
OpenClaw plugin is the only one that asserts an already-approved call cannot be
replayed through containment (the analogue here is
:meth:`TestContainmentIsRungZero.test_a_granted_rule_cannot_carry_a_contained_call`),
and every breaker exempts its own governance tools by name prefix, which is only
safe if the prefix match is exact (see
:meth:`TestContainmentIsRungZero.test_the_governance_exemption_is_not_a_prefix_free_for_all`).
"""

import json
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import vaibot  # noqa: E402
from vaibot import guard as guard_client  # noqa: E402
from vaibot import launch  # noqa: E402
from vaibot.breaker import BreakerStore  # noqa: E402
from vaibot.containment import containment_file  # noqa: E402
from vaibot.creds import ResolvedCredentials  # noqa: E402
from vaibot.engine import Engine  # noqa: E402
from vaibot.localcli import Verdict  # noqa: E402

logging.getLogger("vaibot").addHandler(logging.NullHandler())

KEY = ResolvedCredentials(env="staging", api_base_url="https://staging-api.vaibot.io",
                          api_key="vb_stg_k", key_mismatch=False)
NO_KEY = ResolvedCredentials(env="staging", api_base_url="https://staging-api.vaibot.io",
                             api_key=None, key_mismatch=False)
LOCK = guard_client.GuardLock(host="127.0.0.1", port=1, token="t")
HEALTH = guard_client.Health()
OK = guard_client.GuardResponse(ok=True, status=200)

ALLOW = Verdict("allow", "safe", ("read-only",))
ASK = Verdict("ask", "high", ("network egress",))
DENY = Verdict("deny", "dangerous", ("rm -rf on a protected target",))

#: Every posture that changes whether the plugin blocks.
MODES = {
    "enforce": {},
    "observe": {"VAIBOT_MODE": "observe"},
    "fail-open": {"VAIBOT_FAIL_OPEN": "true"},
}

#: Every way the guard can fail to give a usable verdict, plus the healthy case.
#: Adding a rung to the engine means adding it here.
DEGRADED_RUNGS = (
    "no key",
    "breaker tripped",
    "guard down (fresh install)",
    "guard down (established install)",
    "guard unreachable mid-call",
    "guard refuses (4xx)",
    "guard answers nonsense",
)
ALL_RUNGS = DEGRADED_RUNGS + ("guard answers",)

#: Degraded rungs where *nothing* answered, so the plugin governs locally: the
#: classifier decides, and safe work runs in every mode rather than the agent
#: being bricked because governance is away.
LOCALLY_GOVERNED = (
    "no key",
    "breaker tripped",
    "guard down (fresh install)",
    "guard down (established install)",
)
#: Degraded rungs where a guard WAS reachable and still produced no usable
#: verdict. In enforce those fail closed — something is there and it is not
#: answering, which is not the same as nothing being there — and only observe or
#: FAIL_OPEN let even safe work through. The distinction is deliberate, so it is
#: stated rather than left to whichever assertion happened to be written first.
FAIL_CLOSED_RUNGS = (
    "guard unreachable mid-call",
    "guard refuses (4xx)",
    "guard answers nonsense",
)


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class Rig:
    """An engine pinned to one rung and one mode, with everything else faked."""

    def __init__(self, home: Path, rung: str, mode: dict, verdict=ALLOW, autogranted=False):
        self.home = home
        self.creds = KEY
        self.verdict = verdict
        self.lock = LOCK
        self.health = HEALTH
        self.answer = (guard_client.Decision(decision="allow", reason="ok", run_id="run_1"), OK)
        # A private state directory per rig: breaker state is persisted, and a rig
        # for one rung must not inherit the tripped breaker of the rung before it.
        self.state = Path(tempfile.mkdtemp(dir=home))
        self.lock_file = self.state / "lock-exists.json"
        self.lock_file.write_text("{}", encoding="utf-8")
        self.decide_calls = []
        self.classified = []
        self.ensured = []
        # A high threshold so only the breaker rung trips, never a side effect.
        self.env = {
            "VAIBOT_CREDS_DIR": str(self.state / "creds"),
            "VAIBOT_WORKSPACE": str(home),
            "VAIBOT_BREAKER_FAILURE_THRESHOLD": "100",
            **mode,
        }
        self.breakers = BreakerStore(self.env, clock=Clock(5_000_000.0))
        self._apply(rung)
        self.engine = Engine(
            self.env,
            resolve=lambda env=None: self.creds,
            bootstrap=lambda env=None: None,
            classify=self._classify,
            read_lock=lambda env=None: self.lock,
            lock_path=lambda env=None: self.lock_file,
            probe=lambda lock, timeout_s=2.0: self.health,
            decide=self._decide,
            autogranted=lambda: autogranted,
            breakers=self.breakers,
            clock=Clock(),
            ensure=lambda env=None: self.ensured.append(env),
        )

    def _apply(self, rung: str) -> None:
        if rung == "no key":
            self.creds = NO_KEY
        elif rung == "breaker tripped":
            breaker = self.breakers.load()
            for _ in range(150):
                breaker.record_failure("guard unavailable")
            self.breakers.save(breaker)
        elif rung == "guard down (fresh install)":
            self.lock, self.health = None, None
            self.lock_file = self.state / "no-lock-here.json"
        elif rung == "guard down (established install)":
            self.health = None
        elif rung == "guard unreachable mid-call":
            self.answer = (None, guard_client.GuardResponse(ok=False, unreachable=True, error="timed out"))
        elif rung == "guard refuses (4xx)":
            self.answer = (None, guard_client.GuardResponse(ok=False, unreachable=False, status=401))
        elif rung == "guard answers nonsense":
            self.answer = (guard_client.Decision(decision="frobnicate", reason="?", run_id="run_1"), OK)
        elif rung not in ("guard answers",):
            raise AssertionError(f"unknown rung {rung!r}")

    def _classify(self, tool_name, params, env=None):
        self.classified.append(tool_name)
        return self.verdict

    def _decide(self, lock, **kwargs):
        self.decide_calls.append(kwargs)
        return self.answer

    def decide(self, tool="terminal", args=None):
        return self.engine.decide(tool, args if args is not None else {"command": "ls"}, "sess")


class ParityCase(unittest.TestCase):
    """HOME redirected: containment is read from the guard's own rendezvous dir,
    which is resolved from the home directory and nothing else."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self._real_home = os.environ.get("HOME")
        os.environ["HOME"] = str(self.home)
        self.addCleanup(self._restore)

    def _restore(self):
        if self._real_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._real_home
        self._tmp.cleanup()

    def contain(self, payload=None):
        path = containment_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        body = {"contained": True, "reason": "laptop looks compromised"} if payload is None else payload
        path.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")

    def rig(self, rung, mode, **kw):
        return Rig(self.home, rung, MODES[mode], **kw)


class TestContainmentIsRungZero(ParityCase):
    def test_it_blocks_on_every_rung_in_every_mode(self):
        self.contain()
        for rung in ALL_RUNGS:
            for mode in MODES:
                with self.subTest(rung=rung, mode=mode):
                    rig = self.rig(rung, mode, verdict=ALLOW)
                    outcome = rig.decide()
                    self.assertEqual(outcome.rung, "containment")
                    self.assertEqual(outcome.directive["action"], "block")
                    self.assertIn("containment engaged", outcome.directive["message"])
                    self.assertIn("laptop looks compromised", outcome.directive["message"])
                    self.assertEqual(rig.decide_calls, [], "containment must not need the guard")
                    self.assertEqual(rig.classified, [], "containment must not need the classifier")

    def test_it_needs_no_key_no_daemon_and_no_network(self):
        # The paths it has to survive are exactly the ones that reach nothing.
        self.contain()
        rig = self.rig("guard down (fresh install)", "fail-open")
        rig.creds = NO_KEY
        self.assertEqual(rig.decide().rung, "containment")

    def test_a_credential_directory_override_does_not_move_the_record(self):
        # The guard resolves this file from the home directory alone. A breaker
        # that followed VAIBOT_CREDS_DIR would read a file the guard never writes.
        self.contain()
        rig = self.rig("guard answers", "enforce")
        rig.env["VAIBOT_CREDS_DIR"] = str(self.home / "somewhere-else")
        self.assertEqual(rig.decide().rung, "containment")

    def test_a_corrupt_or_absent_record_lets_governance_proceed(self):
        # The other direction, and it matters as much: failing *into* containment
        # would take an account's agents down with nothing to explain why.
        for payload in [None, "", "{", "null", "[]", '"a string"', {"contained": "true"},
                        {"contained": 1}, {}]:
            with self.subTest(payload=payload):
                if payload is not None:
                    self.contain(payload)
                rig = self.rig("guard answers", "enforce")
                outcome = rig.decide()
                self.assertNotEqual(outcome.rung, "containment")
                self.assertEqual(len(rig.decide_calls), 1)

    def test_a_granted_rule_cannot_carry_a_contained_call(self):
        # The Hermes analogue of OpenClaw's replay pointer. An `[a]lways` answer
        # lives in Hermes and is satisfied when this plugin returns an `approve`
        # directive carrying that rule_key — so the guarantee is that containment
        # is read before any directive with a rule_key can be produced. Line order
        # in decide() is what makes that true; this fails if it moves.
        escalation = guard_client.Decision(
            decision="approve", reason="writes outside the workspace", run_id="run_1",
            risk="high", rule_id="file-outside-workspace:~/other",
        )
        rig = self.rig("guard answers", "enforce")
        rig.answer = (escalation, OK)
        granted = rig.decide("write_file", {"path": "/other/one"})
        self.assertEqual(granted.directive["action"], "approve")
        self.assertIn("rule_key", granted.directive, "a grant key must exist for this to be meaningful")

        self.contain()
        contained = self.rig("guard answers", "enforce")
        contained.answer = (escalation, OK)
        outcome = contained.decide("write_file", {"path": "/other/one"})
        self.assertEqual(outcome.rung, "containment")
        self.assertNotIn("rule_key", outcome.directive, "no grant key may be minted while contained")

    def test_the_governance_exemption_is_not_a_prefix_free_for_all(self):
        # Governance tools are exempt so an operator can still lift containment.
        # Hermes namespaces MCP tools as mcp__<server>__<tool>, so the exemption
        # has to end at a namespace boundary: a server called `vaibotage` is
        # somebody else's, and must not inherit the exemption.
        self.assertTrue(vaibot._should_skip("mcp__vaibot__status"))
        self.assertTrue(vaibot._should_skip("mcp__vaibot"))
        for impostor in ("mcp__vaibotage__run", "mcp__vaibot-evil__run", "mcp__vaibotx"):
            with self.subTest(tool=impostor):
                self.assertFalse(vaibot._should_skip(impostor))

    def test_an_internal_error_does_not_lift_it(self):
        # An unexpected failure while governing is a path that never reached the
        # guard, which is exactly what containment exists for. Under observe or
        # FAIL_OPEN the hook otherwise lets the call run.
        self.contain()
        broken = mock.Mock()
        broken.decide.side_effect = RuntimeError("boom")
        for mode in ({"VAIBOT_MODE": "observe"}, {"VAIBOT_FAIL_OPEN": "true"}, {}):
            with self.subTest(mode=mode or "enforce"):
                with mock.patch.object(vaibot, "_engine", broken), \
                     mock.patch.dict(os.environ, mode, clear=False), \
                     self.assertLogs("vaibot", level="ERROR"):
                    os.environ.pop("VAIBOT_MODE", None) if "VAIBOT_MODE" not in mode else None
                    os.environ.pop("VAIBOT_FAIL_OPEN", None) if "VAIBOT_FAIL_OPEN" not in mode else None
                    directive = vaibot._on_pre_tool_call(tool_name="terminal", args={}, tool_call_id="t")
                self.assertIsNotNone(directive, "a contained account must not run the call")
                self.assertEqual(directive["action"], "block")
                self.assertIn("containment engaged", directive["message"])

    def test_it_is_read_before_anything_that_could_fail(self):
        # Rung 0 must not sit behind settings resolution: a broken settings source
        # would otherwise raise past it, and the hook's lenient posture would run
        # the call.
        self.contain()

        class Hostile(dict):
            def get(self, *args, **kwargs):
                raise RuntimeError("settings backend is down")

        rig = self.rig("guard answers", "enforce")
        rig.engine._env = Hostile(rig.env)
        self.assertEqual(rig.decide().rung, "containment")

    def test_lifting_it_restores_normal_governance(self):
        self.contain()
        rig = self.rig("guard answers", "enforce")
        self.assertEqual(rig.decide().rung, "containment")
        self.contain({"contained": False})
        rig = self.rig("guard answers", "enforce")
        self.assertEqual(len(rig.decide().run_id or ""), len("run_1"))
        self.assertEqual(rig.decide_calls and rig.decide_calls[0]["session_id"], "sess")


class TestTheFloorHoldsOnEveryDegradedPath(ParityCase):
    def test_a_classifier_deny_blocks_on_every_degraded_rung_in_every_mode(self):
        for rung in DEGRADED_RUNGS:
            for mode in MODES:
                with self.subTest(rung=rung, mode=mode):
                    rig = self.rig(rung, mode, verdict=DENY)
                    outcome = rig.decide("terminal", {"command": "rm -rf /"})
                    self.assertIsNotNone(outcome.directive, "a catastrophic call must never pass")
                    self.assertEqual(outcome.directive["action"], "block")

    def test_the_two_kinds_of_degraded_rung_are_the_whole_set(self):
        # So a new rung has to be classified as one or the other, rather than
        # inheriting whichever posture its branch happens to fall into.
        self.assertEqual(sorted(LOCALLY_GOVERNED + FAIL_CLOSED_RUNGS), sorted(DEGRADED_RUNGS))

    def test_safe_work_runs_wherever_the_plugin_governs_locally(self):
        # The floor is not "block everything": a breaker that bricks the agent
        # whenever the guard is away gets switched off, and then nothing is
        # governed at all.
        for rung in LOCALLY_GOVERNED:
            for mode in MODES:
                with self.subTest(rung=rung, mode=mode):
                    rig = self.rig(rung, mode, verdict=ALLOW)
                    outcome = rig.decide("read_file", {"path": "src/x.py"})
                    self.assertIsNone(outcome.directive, f"{rung}/{mode} should let safe work run")

    def test_a_reachable_guard_that_will_not_answer_fails_closed_in_enforce(self):
        # The other posture, and it is the stricter one: a guard that is there and
        # produces no verdict blocks even a read, because the plugin cannot tell an
        # outage from something interfering with the decision.
        for rung in FAIL_CLOSED_RUNGS:
            with self.subTest(rung=rung):
                rig = self.rig(rung, "enforce", verdict=ALLOW)
                outcome = rig.decide("read_file", {"path": "src/x.py"})
                self.assertIsNotNone(outcome.directive, f"{rung} must fail closed in enforce")
                self.assertEqual(outcome.directive["action"], "block")
            for mode in ("observe", "fail-open"):
                with self.subTest(rung=rung, mode=mode):
                    # The operator asked for that, and the floor still holds (above).
                    rig = self.rig(rung, mode, verdict=ALLOW)
                    self.assertIsNone(rig.decide("read_file", {"path": "src/x.py"}).directive)

    def test_a_risky_call_is_asked_about_rather_than_waved_through(self):
        # In enforce, an unclassifiable-as-safe call on a degraded path goes to a
        # human. The exception is a cold start, which deliberately lets
        # non-catastrophic work run while the daemon comes up.
        cold = "guard down (fresh install)"
        for rung in DEGRADED_RUNGS:
            with self.subTest(rung=rung):
                outcome = self.rig(rung, "enforce", verdict=ASK).decide()
                if rung == cold:
                    self.assertIsNone(outcome.directive, "a cold start lets non-catastrophic work run")
                else:
                    self.assertIsNotNone(outcome.directive)
                    self.assertIn(outcome.directive["action"], ("approve", "block"))

    def test_an_unusable_verdict_is_a_degraded_path_not_a_decision(self):
        # A reachable guard that answers garbage has not decided anything. In
        # enforce that blocks; in observe and fail-open the classifier floor
        # speaks, exactly as on every other degraded rung — rather than the
        # garbage reading as "nothing to see here".
        self.assertEqual(self.rig("guard answers nonsense", "enforce", verdict=ALLOW)
                         .decide().directive["action"], "block")
        for mode in ("observe", "fail-open"):
            with self.subTest(mode=mode):
                rig = self.rig("guard answers nonsense", mode, verdict=DENY)
                self.assertEqual(rig.decide().directive["action"], "block")
                self.assertEqual(rig.classified, ["terminal"], "the floor must be consulted")

    def test_the_guards_own_floor_deny_blocks_in_observe(self):
        rig = self.rig("guard answers", "observe")
        rig.answer = (guard_client.Decision(decision="deny", reason="Classifier: dangerous",
                                            run_id="run_1", floor=True, effective_mode="observe"), OK)
        outcome = rig.decide()
        self.assertEqual(outcome.directive["action"], "block")
        self.assertIn("catastrophic floor", outcome.directive["message"])


class TestNoHostMayApproveForItself(ParityCase):
    """An escalation is a demand for a human decision. Only the account's policy,
    resolved by a guard that answered, can let the host satisfy it itself."""

    def test_no_degraded_rung_hands_an_auto_granting_host_an_approval(self):
        # Enforce only: observe and fail-open let a risky call run because the
        # operator asked for that, which is not a bypass.
        for rung in DEGRADED_RUNGS:
            with self.subTest(rung=rung):
                rig = self.rig(rung, "enforce", verdict=ASK, autogranted=True)
                outcome = rig.decide()
                if rung == "guard down (fresh install)":
                    # Documented exception: a cold start lets non-catastrophic
                    # work run, so there is no escalation to satisfy.
                    self.assertIsNone(outcome.directive)
                    continue
                self.assertIsNotNone(outcome.directive)
                self.assertEqual(outcome.directive["action"], "block",
                                 f"{rung} must not open a gate an auto-granting host would satisfy")

    def test_the_floor_still_blocks_a_bypassing_host(self):
        for rung in DEGRADED_RUNGS:
            with self.subTest(rung=rung):
                rig = self.rig(rung, "enforce", verdict=DENY, autogranted=True)
                self.assertEqual(rig.decide().directive["action"], "block")

    def test_only_a_guard_resolved_policy_may_allow_it(self):
        escalation = guard_client.Decision(decision="approve", reason="needs review", run_id="run_1",
                                           risk="high", rule_id="network:example.com")
        refused = self.rig("guard answers", "enforce", autogranted=True)
        refused.answer = (escalation, OK)
        self.assertEqual(refused.decide().directive["action"], "block")

        permitted = self.rig("guard answers", "enforce", autogranted=True)
        permitted.answer = (
            guard_client.Decision(decision="approve", reason="needs review", run_id="run_1",
                                  risk="high", rule_id="network:example.com", bypass_override=True),
            OK,
        )
        outcome = permitted.decide()
        self.assertEqual(outcome.directive["action"], "approve")
        self.assertTrue(outcome.escalated, "the receipt must still record that it was escalated")

    def test_the_hosts_posture_is_reported_to_a_guard_that_understands_it(self):
        for autogranted in (True, False):
            with self.subTest(autogranted=autogranted):
                rig = self.rig("guard answers", "enforce", autogranted=autogranted)
                rig.health = guard_client.Health(capabilities=frozenset({"host-bypass"}))
                rig.decide()
                self.assertEqual(rig.decide_calls[0]["host_bypass"], (autogranted, "hermes:auto-approve"))

    def test_nothing_is_reported_to_a_guard_that_predates_it(self):
        rig = self.rig("guard answers", "enforce", autogranted=True)
        rig.decide()
        self.assertIsNone(rig.decide_calls[0]["host_bypass"])


class TestTheTableCoversTheEngine(ParityCase):
    """The tables are only worth something if they cover every rung the engine has."""

    def test_every_rung_the_engine_reports_appears_in_the_table(self):
        seen = set()
        for rung in ALL_RUNGS:
            for verdict in (ALLOW, ASK, DENY):
                seen.add(self.rig(rung, "enforce", verdict=verdict).decide().rung)
                seen.add(self.rig(rung, "observe", verdict=verdict).decide().rung)
        self.contain()
        seen.add(self.rig("guard answers", "enforce").decide().rung)
        # Every rung name the engine can attribute a decision to. A new one means
        # a new row in the tables above, not just a new branch.
        self.assertEqual(seen, {"containment", "no-key", "breaker", "guard-down", "guard-error", "guard", "observe"})


if __name__ == "__main__":
    unittest.main()
