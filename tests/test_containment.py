"""Account-wide containment — the record, and rung 0 of the ladder.

Two halves. First the reader, which runs on every tool call and must never raise
and never fail *into* containment. Then the engine, where the point is ordering:
every rung below rung 0 can let a call through — no key governs locally, a tripped
breaker decides locally, guard-down degrades, observe and FAIL_OPEN allow outright
— so containment is only meaningful if it is checked before all of them.

HOME is redirected rather than injecting a path, because that is what the guard
itself resolves this file from. A test that injected a path would pass while the
plugin read a file the guard never writes.
"""

import json
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vaibot import guard as guard_client  # noqa: E402
from vaibot.breaker import BreakerStore  # noqa: E402
from vaibot.containment import Containment, containment_file, read_containment  # noqa: E402
from vaibot.creds import ResolvedCredentials  # noqa: E402
from vaibot.engine import Engine  # noqa: E402
from vaibot.localcli import Verdict  # noqa: E402

logging.getLogger("vaibot").addHandler(logging.NullHandler())

KEY = ResolvedCredentials(env="staging", api_base_url="https://staging-api.vaibot.io",
                          api_key="vb_stg_k", key_mismatch=False)
NO_KEY = ResolvedCredentials(env="staging", api_base_url="https://staging-api.vaibot.io",
                             api_key=None, key_mismatch=False)
LOCK = guard_client.GuardLock(host="127.0.0.1", port=1, token="t")
ALLOW = Verdict("allow", "safe", ("read-only",))
OK = guard_client.GuardResponse(ok=True, status=200)


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class HomeSandbox(unittest.TestCase):
    """Redirects HOME so the record read is this test's, never the developer's."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._real_home = os.environ.get("HOME")
        os.environ["HOME"] = self._tmp.name
        self.addCleanup(self._restore)

    def _restore(self):
        if self._real_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._real_home
        self._tmp.cleanup()

    def write_record(self, payload):
        """Write the record as the guard writes it; a str is written verbatim."""
        path = containment_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload if isinstance(payload, str) else json.dumps(payload),
                        encoding="utf-8")
        return path


class TestReadContainment(HomeSandbox):
    def test_path_is_the_guards_rendezvous_dir(self):
        # A workspace-local file cannot be found by a breaker running elsewhere on
        # the machine, which is most of them.
        self.assertEqual(containment_file().name, "containment.json")
        self.assertEqual(containment_file().parent.name, "guard")
        self.assertEqual(containment_file().parent.parent.name, ".vaibot")

    def test_absent_means_not_engaged(self):
        self.assertEqual(read_containment(), Containment(contained=False, reason=None, at=None))

    def test_round_trips_state_reason_and_time(self):
        self.write_record({"contained": True, "reason": "laptop looks compromised", "at": "2026-09-27T00:00:00Z"})
        got = read_containment()
        self.assertTrue(got.contained)
        self.assertEqual(got.reason, "laptop looks compromised")
        self.assertEqual(got.at, "2026-09-27T00:00:00Z")

    def test_corrupt_records_never_raise_and_never_claim_containment(self):
        for junk in ["", "{", "null", "[]", "not json", "\x00", '"a string"', "[1,2,3]"]:
            with self.subTest(junk=junk):
                self.write_record(junk)
                self.assertFalse(read_containment().contained)

    def test_only_a_literal_true_engages_it(self):
        for value in [1, "true", "1", "yes", {}, [], None]:
            with self.subTest(value=value):
                self.write_record({"contained": value})
                self.assertFalse(read_containment().contained)
        self.write_record({"contained": True})
        self.assertTrue(read_containment().contained)

    def test_non_string_reason_is_dropped_rather_than_rendered(self):
        self.write_record({"contained": True, "reason": {"nested": "object"}, "at": 12345})
        got = read_containment()
        self.assertTrue(got.contained)
        self.assertIsNone(got.reason)
        self.assertIsNone(got.at)

    def test_an_explicit_path_is_honoured(self):
        other = Path(self._tmp.name) / "elsewhere.json"
        other.write_text(json.dumps({"contained": True}), encoding="utf-8")
        self.assertTrue(read_containment(other).contained)

    def test_an_unreadable_path_does_not_raise(self):
        # A directory where a file is expected: reading it raises, and that must
        # be swallowed — this runs on every tool call.
        d = Path(self._tmp.name) / "a-directory.json"
        d.mkdir()
        self.assertFalse(read_containment(d).contained)


class TestContainmentRung(HomeSandbox):
    """Rung 0 — ahead of every rung that could let a call through."""

    def setUp(self):
        super().setUp()
        self.env = {"VAIBOT_WORKSPACE": self._tmp.name}
        self.creds = KEY
        self.classified = []
        self.decide_calls = []
        self.breakers = BreakerStore(self.env, clock=Clock(5_000_000.0))
        self.engine = Engine(
            self.env,
            resolve=lambda env=None: self.creds,
            bootstrap=lambda env=None: None,
            classify=self._classify,
            read_lock=lambda env=None: LOCK,
            lock_path=lambda env=None: Path(self._tmp.name) / "guard.json",
            probe=lambda lock, timeout_s=2.0: guard_client.Health(),
            decide=self._decide,
            autogranted=lambda: False,
            breakers=self.breakers,
            clock=Clock(),
        )
        self.write_record({"contained": True, "reason": "laptop looks compromised"})

    def _classify(self, tool_name, params):
        self.classified.append(tool_name)
        return ALLOW

    def _decide(self, *a, **k):
        self.decide_calls.append((a, k))
        return (guard_client.Decision(decision="allow", reason="ok", run_id="r1"), OK)

    def assert_contained(self, outcome):
        self.assertEqual(outcome.rung, "containment")
        self.assertIsNotNone(outcome.directive)
        self.assertEqual(outcome.directive["action"], "block")
        self.assertIn("containment engaged", outcome.directive["message"])
        self.assertIn("laptop looks compromised", outcome.directive["message"],
                      "the reason given when engaging should reach the agent")

    def test_blocks_a_benign_call(self):
        self.assert_contained(self.engine.decide("read_file", {"path": "/tmp/a"}))

    def test_consults_neither_the_guard_nor_the_classifier(self):
        # Proves it is ahead of the ladder rather than folded into it: no network,
        # and not even a local classification.
        self.engine.decide("terminal", {"command": "echo hi"})
        self.assertEqual(self.decide_calls, [], "containment must not need the guard")
        self.assertEqual(self.classified, [], "containment must not need the classifier")

    def test_observe_mode_does_not_lift_it(self):
        # Nothing else in this plugin blocks under observe. Containment does.
        self.env["VAIBOT_MODE"] = "observe"
        self.assert_contained(self.engine.decide("read_file", {"path": "/tmp/a"}))

    def test_fail_open_does_not_lift_it(self):
        self.env["VAIBOT_FAIL_OPEN"] = "true"
        self.assert_contained(self.engine.decide("read_file", {"path": "/tmp/a"}))

    def test_a_missing_key_does_not_reach_local_governance(self):
        # Rung 1 would govern locally via the classifier and allow safe work.
        self.creds = NO_KEY
        self.assert_contained(self.engine.decide("read_file", {"path": "/tmp/a"}))
        self.assertEqual(self.classified, [])

    def test_a_tripped_breaker_does_not_decide_locally(self):
        # Rung 2 would decide locally without calling the guard.
        breaker = self.breakers.load()
        for _ in range(50):
            breaker.record_failure("x")
        self.breakers.save(breaker)
        self.assert_contained(self.engine.decide("read_file", {"path": "/tmp/a"}))

    def test_lifting_it_restores_normal_governance(self):
        self.write_record({"contained": False})
        outcome = self.engine.decide("read_file", {"path": "/tmp/a"})
        self.assertNotEqual(outcome.rung, "containment")
        self.assertEqual(len(self.decide_calls), 1, "the guard should be consulted again once lifted")


if __name__ == "__main__":
    unittest.main()
