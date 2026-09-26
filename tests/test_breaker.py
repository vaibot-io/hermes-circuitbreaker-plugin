"""Pins the circuit breaker to @vaibot/guard's circuit-breaker.mjs semantics.

The clock is injected, so window and cooldown behaviour is exact rather than
timing-dependent.
"""

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vaibot.breaker import (  # noqa: E402
    DEFAULT_COOLDOWN_MS,
    DEFAULT_FAILURE_THRESHOLD,
    DEFAULT_WINDOW_MS,
    BreakerConfig,
    BreakerStore,
    CircuitBreaker,
)


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def make(clock=None, **cfg):
    return CircuitBreaker(cfg=BreakerConfig(**cfg), clock=clock or Clock())


class TripTests(unittest.TestCase):
    def test_trips_at_the_threshold_inside_the_window(self):
        b = make()
        b.record_failure("a")
        b.record_failure("b")
        self.assertFalse(b.is_tripped())
        b.record_failure("c")
        self.assertTrue(b.is_tripped())
        self.assertEqual(b.last_error, "c")

    def test_failures_outside_the_window_fall_off(self):
        clock = Clock()
        b = make(clock)
        b.record_failure()
        b.record_failure()
        clock.t += DEFAULT_WINDOW_MS + 1
        b.record_failure()
        self.assertFalse(b.is_tripped())
        self.assertEqual(len(b.failures), 1)

    def test_cooldown_auto_resets(self):
        clock = Clock()
        b = make(clock)
        for _ in range(3):
            b.record_failure("x")
        clock.t += DEFAULT_COOLDOWN_MS  # exactly at the boundary: still tripped
        self.assertTrue(b.is_tripped())
        clock.t += 1
        self.assertFalse(b.is_tripped())
        self.assertEqual((b.failures, b.tripped_at, b.last_error), ([], None, None))

    def test_success_clears_everything(self):
        b = make()
        for _ in range(3):
            b.record_failure("x")
        b.record_success()
        self.assertFalse(b.is_tripped())
        self.assertEqual(b.failures, [])

    def test_denylist_is_exact_and_independent_of_trip_state(self):
        b = make(denylist=("terminal",))
        self.assertTrue(b.is_denied("terminal"))
        self.assertFalse(b.is_denied("Terminal"))
        self.assertFalse(b.is_denied("write_file"))


class SnapshotTests(unittest.TestCase):
    def test_round_trip_uses_the_node_keys(self):
        b = make()
        b.record_failure("boom")
        snap = b.snapshot()
        self.assertEqual(set(snap), {"failures", "trippedAt", "lastError"})
        c = make()
        c.load(snap)
        self.assertEqual(c.snapshot(), snap)

    def test_load_tolerates_garbage(self):
        b = make()
        for junk in (None, "x", 7, {"failures": "no", "trippedAt": "no", "lastError": 3},
                     {"failures": [1, "a", None, 2.5], "trippedAt": True}):
            b.load(junk)
            self.assertIsNone(b.tripped_at)
            self.assertTrue(all(isinstance(t, float) for t in b.failures))


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = BreakerConfig.from_env({})
        self.assertEqual(
            (cfg.failure_threshold, cfg.window_ms, cfg.cooldown_ms, cfg.denylist),
            (DEFAULT_FAILURE_THRESHOLD, DEFAULT_WINDOW_MS, DEFAULT_COOLDOWN_MS, ()),
        )

    def test_env_overrides_and_denylist_parsing(self):
        cfg = BreakerConfig.from_env({
            "VAIBOT_BREAKER_FAILURE_THRESHOLD": "5",
            "VAIBOT_BREAKER_WINDOW_MS": "2000",
            "VAIBOT_BREAKER_COOLDOWN_MS": "30000",
            "VAIBOT_BREAKER_DENYLIST": " terminal, ,write_file ",
        })
        self.assertEqual((cfg.failure_threshold, cfg.window_ms, cfg.cooldown_ms), (5, 2000, 30000))
        self.assertEqual(cfg.denylist, ("terminal", "write_file"))

    def test_nonsense_falls_back_to_defaults(self):
        # Node: Number(x) || default, then finite and > 0.
        for bad in ("0", "-3", "abc", "", "inf", "nan"):
            cfg = BreakerConfig.from_env({"VAIBOT_BREAKER_FAILURE_THRESHOLD": bad})
            self.assertEqual(cfg.failure_threshold, DEFAULT_FAILURE_THRESHOLD, bad)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = {"VAIBOT_CREDS_DIR": self.tmp.name}
        self.clock = Clock()
        self.store = BreakerStore(self.env, clock=self.clock)

    def tearDown(self):
        self.tmp.cleanup()

    def test_trip_state_survives_a_reload(self):
        b = self.store.load()
        for _ in range(3):
            b.record_failure("down")
        self.store.save(b)
        again = self.store.load()
        self.assertTrue(again.is_tripped())
        self.assertEqual(again.last_error, "down")

    def test_file_is_private_and_in_the_node_shape(self):
        b = self.store.load()
        b.record_failure("x")
        self.store.save(b)
        path = self.store.path
        self.assertEqual(path.name, "hermes.json")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(path.parent).st_mode), 0o700)
        raw = json.loads(path.read_text())
        self.assertEqual(raw["version"], 1)
        self.assertEqual(set(raw["breaker"]), {"failures", "trippedAt", "lastError"})
        # No temp files left behind by the atomic write.
        self.assertEqual([p.name for p in path.parent.iterdir()], ["hermes.json"])

    def test_corrupt_state_loads_fresh(self):
        self.store.path.parent.mkdir(parents=True)
        self.store.path.write_text("{nope")
        self.assertFalse(self.store.load().is_tripped())

    def test_unwritable_location_does_not_raise(self):
        blocker = Path(self.tmp.name) / "breaker-state"
        blocker.write_text("a file where the directory should be")
        self.store.save(self.store.load())  # best-effort: swallowed


if __name__ == "__main__":
    unittest.main()
