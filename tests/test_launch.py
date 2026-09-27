"""Discover-or-launch: adopt the running guard, and never start a second.

One guard per machine is the invariant, so the assertions that matter most are the
ones about *not* launching: a healthy guard is adopted without spawning anything,
a burst of callers produces exactly one attempt, a failed attempt backs off, and a
launch nobody can confirm is reported as a failure rather than as success.

**No test here starts a real daemon.** The node bridge is exercised for real, but
against a fixture ``guard-launch.mjs`` that returns an answer instead of spawning
anything — so the contract with the guard's own launcher is tested without putting
a guard on the machine running the tests.
"""

import json
import logging
import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import vaibot  # noqa: E402
from vaibot import config, engine, launch  # noqa: E402
from vaibot import guard as guard_client  # noqa: E402

logging.getLogger("vaibot").addHandler(logging.NullHandler())

LOCK = guard_client.GuardLock(host="127.0.0.1", port=39117, token="t")
HEALTHY = guard_client.Health(version="2.2.0")


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class LaunchCase(unittest.TestCase):
    def setUp(self):
        launch.reset()
        config.clear_provider()
        self.addCleanup(launch.reset)
        self.addCleanup(config.clear_provider)
        self.runs = []
        self.answer = {"ok": True, "status": "launched", "port": 39117}
        self.lock = None
        self.health = HEALTHY
        self.clock = Clock()

    # deps
    def read_lock(self, env=None):
        return self.lock

    def probe(self, lock, timeout_s=2.0):
        return self.health

    def run_launcher(self, launcher, daemon, workspace, env, timeout_s):
        self.runs.append({"launcher": launcher, "daemon": daemon, "workspace": workspace})
        return self.answer

    def ensure(self, env=None, **kw):
        return launch.ensure_guard(
            env if env is not None else {},
            read_lock=kw.pop("read_lock", self.read_lock),
            probe=kw.pop("probe", self.probe),
            run=kw.pop("run", self.run_launcher),
            clock=kw.pop("clock", self.clock),
            **kw,
        )


class TestAdoptRatherThanLaunch(LaunchCase):
    def test_a_healthy_guard_is_adopted_and_nothing_is_spawned(self):
        self.lock = LOCK
        result = self.ensure()
        self.assertEqual(result.status, "reused")
        self.assertEqual(result.port, 39117)
        self.assertEqual(self.runs, [], "a running guard must never be duplicated")

    def test_repeated_calls_stay_idempotent(self):
        self.lock = LOCK
        for _ in range(5):
            self.assertEqual(self.ensure().status, "reused")
        self.assertEqual(self.runs, [])

    def test_a_healthy_guard_is_adopted_without_taking_the_launch_lock(self):
        # The common path: a guard is up and tool calls keep arriving. If that went
        # through the single-flight lock, a call would either queue behind an
        # attempt or be told one is in flight — for a guard that is already there.
        self.lock = LOCK
        self.assertTrue(launch._flight.acquire(blocking=False))
        self.addCleanup(launch._flight.release)
        result = self.ensure()
        self.assertEqual(result.status, "reused")
        self.assertEqual(self.runs, [])

    def test_a_stale_lock_is_not_adopted(self):
        # The lock outlives the process that wrote it, so "a lock exists" is not
        # "a guard is running" — that is exactly when one must be started.
        self.lock, self.health = LOCK, None
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self._with_tree(tmp).status, "launched")

    def test_it_launches_when_there_is_no_lock_at_all(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._with_tree(tmp)
        self.assertEqual(result.status, "launched")
        self.assertEqual(len(self.runs), 1)

    def _with_tree(self, tmp):
        """Launch with a real-looking guard install, adopting once it is up."""
        cli = make_guard_tree(Path(tmp))
        calls = {"n": 0}

        def read_lock(env=None):
            # Nothing before the launch; the daemon's own lock afterwards.
            return LOCK if calls["n"] else self.lock

        def run(*args):
            calls["n"] += 1
            self.health = HEALTHY
            return self.run_launcher(*args)

        return launch.ensure_guard(
            {"VAIBOT_GUARD_CLI": str(cli), "PATH": os.environ.get("PATH", "")},
            read_lock=read_lock, probe=self.probe, run=run, clock=self.clock,
        )


class TestGates(LaunchCase):
    def test_an_external_guard_is_never_launched_over(self):
        result = self.ensure({"VAIBOT_GUARD_BASE_URL": "http://10.0.0.5:39111"})
        self.assertEqual(result.status, "external")
        self.assertEqual(self.runs, [])

    def test_auto_launch_can_be_switched_off(self):
        result = self.ensure({"VAIBOT_AUTO_LAUNCH": "0"})
        self.assertEqual(result.status, "disabled")
        self.assertEqual(self.runs, [])

    def test_a_guard_install_without_a_launcher_is_reported_not_guessed(self):
        with tempfile.TemporaryDirectory() as tmp:
            cli = make_guard_tree(Path(tmp), launcher=False)
            result = self.ensure({"VAIBOT_GUARD_CLI": str(cli), "PATH": os.environ.get("PATH", "")})
        self.assertEqual(result.status, "no-launcher")
        self.assertEqual(self.runs, [])


class TestSingleFlight(LaunchCase):
    def test_a_burst_of_callers_produces_exactly_one_attempt(self):
        started = threading.Event()
        release = threading.Event()

        def slow_run(*args):
            self.runs.append(args)
            started.set()
            release.wait(5)
            return self.answer

        with tempfile.TemporaryDirectory() as tmp:
            env = {"VAIBOT_GUARD_CLI": str(make_guard_tree(Path(tmp))), "PATH": os.environ.get("PATH", "")}
            results = []

            def attempt():
                results.append(launch.ensure_guard(
                    env, read_lock=self.read_lock, probe=self.probe, run=slow_run, clock=self.clock,
                ))

            threads = [threading.Thread(target=attempt) for _ in range(8)]
            threads[0].start()
            self.assertTrue(started.wait(5), "the first attempt should have begun")
            for t in threads[1:]:
                t.start()
            for t in threads[1:]:
                t.join(5)
            release.set()
            threads[0].join(5)

        self.assertEqual(len(self.runs), 1, "only one launcher may run at a time")
        self.assertEqual(sum(1 for r in results if r.status == "in-flight"), 7)

    def test_an_in_flight_launch_is_reported_not_queued(self):
        # A caller that waited here would put a daemon boot inside a tool call.
        self.assertTrue(launch._flight.acquire(blocking=False))
        self.addCleanup(launch._flight.release)
        self.assertEqual(self.ensure().status, "in-flight")
        self.assertEqual(self.runs, [])


class TestBackOff(LaunchCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = {
            "VAIBOT_GUARD_CLI": str(make_guard_tree(Path(self.tmp.name))),
            "PATH": os.environ.get("PATH", ""),
        }

    def attempt(self):
        return launch.ensure_guard(
            self.env, read_lock=self.read_lock, probe=self.probe, run=self.run_launcher, clock=self.clock,
        )

    def test_a_failed_attempt_is_not_retried_on_every_call(self):
        self.answer = {"ok": False, "status": "launch-failed", "reason": "no candidate port"}
        self.assertEqual(self.attempt().status, "failed")
        self.assertEqual(self.attempt().status, "cooling")
        self.assertEqual(len(self.runs), 1)
        self.clock.t += launch.RETRY_AFTER_S + 1
        self.attempt()
        self.assertEqual(len(self.runs), 2)

    def test_a_launcher_that_did_not_answer_is_a_failure(self):
        self.answer = None  # no node, a crash, unparseable output
        self.assertEqual(self.attempt().status, "failed")

    def test_success_that_cannot_be_confirmed_is_not_reported_as_success(self):
        # The daemon writes the rendezvous lock; if nothing answers on it, then
        # whatever the launcher said, no guard is governing.
        self.answer = {"ok": True, "status": "launched", "port": 39117}
        self.health = None
        result = self.attempt()
        self.assertEqual(result.status, "failed")
        self.assertIn("no guard answers", result.detail)

    def test_a_launcher_that_adopted_someone_elses_guard_says_reused(self):
        self.answer = {"ok": True, "status": "reused", "port": 39117}
        self.lock = LOCK
        # Nothing to adopt up front (the probe fails), but the launcher found the
        # port already held by a compatible guard.
        self.health = None

        def probe(lock, timeout_s=2.0):
            return None if not self.runs else HEALTHY

        result = launch.ensure_guard(
            self.env, read_lock=self.read_lock, probe=probe, run=self.run_launcher, clock=self.clock,
        )
        self.assertEqual(result.status, "reused")


class TestScriptResolution(unittest.TestCase):
    def test_both_scripts_are_resolved_from_the_guard_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            cli = make_guard_tree(Path(tmp))
            scripts = launch.guard_scripts({"VAIBOT_GUARD_CLI": str(cli), "PATH": ""})
            self.assertIsNotNone(scripts)
            launcher, daemon = scripts
            self.assertEqual(launcher.name, "guard-launch.mjs")
            self.assertEqual(daemon.name, launch.GUARD_SERVICE_SCRIPT)

    def test_the_launcher_comes_from_the_same_install_as_the_cli(self):
        # `vaibot-guard` on PATH is a symlink into the package, and the launcher
        # that runs must belong to the same guard as the classifier — not to
        # whatever other copy happens to be installed somewhere else.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cli = make_guard_tree(root)
            launcher, daemon = launch.guard_scripts({"VAIBOT_GUARD_CLI": str(cli), "PATH": ""})
            scripts_dir = str((root / "scripts").resolve())
            self.assertTrue(str(launcher).startswith(scripts_dir))
            self.assertTrue(str(daemon).startswith(scripts_dir))

    @unittest.skipUnless(shutil.which("node"), "node is not available")
    def test_a_direct_mjs_override_resolves_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_guard_tree(Path(tmp))
            entry = Path(tmp) / "scripts" / "vaibot-guard.mjs"
            self.assertIsNotNone(
                launch.guard_scripts({"VAIBOT_GUARD_CLI": str(entry), "PATH": os.environ.get("PATH", "")})
            )

    def test_no_guard_cli_means_no_launcher(self):
        self.assertIsNone(launch.guard_scripts({"PATH": ""}))


def make_guard_tree(root: Path, launcher: bool = True, launcher_body: str = None) -> Path:
    """A minimal ``@vaibot/guard`` install; returns the CLI as PATH would find it.

    Shaped like the real package: the executable on PATH is a symlink into
    ``scripts/``, which is where the daemon script and the launcher live.
    """
    scripts = root / "scripts"
    (scripts / "lib").mkdir(parents=True, exist_ok=True)
    entry = scripts / "vaibot-guard.mjs"
    entry.write_text("// cli\n", encoding="utf-8")
    (scripts / launch.GUARD_SERVICE_SCRIPT).write_text("// daemon\n", encoding="utf-8")
    if launcher:
        (scripts / "lib" / "guard-launch.mjs").write_text(
            launcher_body or "export async function ensureGuardDefault() { return { ok: false } }\n",
            encoding="utf-8",
        )
    bin_dir = root / "bin"
    bin_dir.mkdir(exist_ok=True)
    cli = bin_dir / "vaibot-guard"
    if not cli.exists():
        cli.symlink_to(entry)
    return cli


@unittest.skipUnless(shutil.which("node"), "node is not available")
class TestNodeBridge(unittest.TestCase):
    """The real bridge, against a launcher that answers instead of spawning.

    This is the contract with ``@vaibot/guard``: its own ``ensureGuardDefault`` is
    handed the daemon script and the workspace, and its answer comes back as one
    JSON line. Everything the guard would actually do — the launch lock, the port
    walk, writing the rendezvous file — stays on its side of that call.
    """

    def test_the_guards_launcher_receives_the_daemon_script_and_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = root / "seen.json"
            body = (
                "import { writeFileSync } from 'node:fs'\n"
                "export async function ensureGuardDefault(opts = {}) {\n"
                f"  writeFileSync({json.dumps(str(record))}, JSON.stringify(opts))\n"
                "  return { ok: true, status: 'launched', port: 39118, host: '127.0.0.1' }\n"
                "}\n"
            )
            cli = make_guard_tree(root, launcher_body=body)
            scripts = launch.guard_scripts({"VAIBOT_GUARD_CLI": str(cli), "PATH": os.environ.get("PATH", "")})
            answer = launch._ensure_via_node(
                scripts[0], scripts[1], "/work", {"PATH": os.environ.get("PATH", "")}, 30.0,
            )
            self.assertEqual(answer, {"ok": True, "status": "launched", "port": 39118, "reason": None})
            seen = json.loads(record.read_text())
        self.assertEqual(seen.get("guardScript"), str(scripts[1]))
        self.assertEqual(seen.get("guardEnv"), {"VAIBOT_WORKSPACE": "/work"})

    def test_a_launcher_that_throws_did_not_answer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cli = make_guard_tree(
                root, launcher_body="export async function ensureGuardDefault() { throw new Error('boom') }\n"
            )
            scripts = launch.guard_scripts({"VAIBOT_GUARD_CLI": str(cli), "PATH": os.environ.get("PATH", "")})
            self.assertIsNone(
                launch._ensure_via_node(scripts[0], scripts[1], "", {"PATH": os.environ.get("PATH", "")}, 30.0)
            )

    def test_the_arguments_never_appear_in_the_process_table(self):
        # The bridge reads its inputs on stdin. argv is world-readable, and the
        # guard's own env can carry credentials.
        self.assertNotIn("guardScript", " ".join(["--input-type=module", "-e", launch._BRIDGE]).split("opts")[0])
        self.assertIn("process.stdin", launch._BRIDGE)


class TestBackgroundAndWiring(LaunchCase):
    def test_the_background_thread_never_raises(self):
        # This one calls the real ensure_guard, so it is belted twice: auto-launch
        # off, and an empty PATH so no guard install can be resolved even if that
        # gate were removed. A test must not be able to put a daemon on the machine
        # running it.
        launch.ensure_in_background({"VAIBOT_AUTO_LAUNCH": "0", "PATH": ""})
        for thread in threading.enumerate():
            if thread.name == "vaibot-ensure-guard":
                thread.join(5)
                self.assertFalse(thread.is_alive())

    def test_one_background_attempt_at_a_time(self):
        release = threading.Event()
        calls = []
        original = launch.ensure_guard

        def blocking(env=None, **kw):
            calls.append(env)
            release.wait(5)
            return launch.Launch("failed")

        launch.ensure_guard = blocking
        self.addCleanup(setattr, launch, "ensure_guard", original)
        try:
            launch.ensure_in_background({})
            launch.ensure_in_background({})
            launch.ensure_in_background({})
        finally:
            release.set()
        for thread in threading.enumerate():
            if thread.name == "vaibot-ensure-guard":
                thread.join(5)
        self.assertEqual(len(calls), 1)

    def test_an_engine_cannot_start_a_daemon_by_omission(self):
        # Every test in this suite builds an Engine without an `ensure`; the
        # default must be inert, or one forgotten argument spawns a daemon.
        self.assertIs(engine.Engine(env={})._ensure, engine._no_ensure)

    def test_the_plugins_own_engine_carries_the_real_launcher(self):
        saved = vaibot._engine
        vaibot._engine = None
        try:
            self.assertIs(vaibot._get_engine()._ensure, launch.ensure_in_background)
        finally:
            vaibot._engine = saved

    def test_the_ladder_asks_for_a_guard_when_none_answers(self):
        asked = []
        with tempfile.TemporaryDirectory() as tmp:
            env = {"VAIBOT_CREDS_DIR": tmp, "VAIBOT_BREAKER_FAILURE_THRESHOLD": "100"}
            from vaibot.creds import ResolvedCredentials
            from vaibot.localcli import Verdict

            def build(health):
                return engine.Engine(
                    env,
                    resolve=lambda e=None: ResolvedCredentials(
                        env="staging", api_base_url="x", api_key="vb_stg_k", key_mismatch=False),
                    bootstrap=lambda e=None: None,
                    classify=lambda tool, params, env=None: Verdict("allow", "safe", ("ok",)),
                    read_lock=lambda e=None: LOCK,
                    lock_path=lambda e=None: Path(tmp) / "guard.json",
                    probe=lambda lock, timeout_s=2.0: health,
                    decide=lambda lock, **kw: (
                        guard_client.Decision(decision="allow", reason="ok", run_id="r"),
                        guard_client.GuardResponse(ok=True, status=200),
                    ),
                    autogranted=lambda: False,
                    clock=Clock(),
                    ensure=lambda e=None: asked.append(e),
                )

            build(None).decide("read_file", {"path": "/tmp/a"})
            self.assertEqual(asked, [env], "nothing answered, so ask for a guard")

            asked.clear()
            build(HEALTHY).decide("read_file", {"path": "/tmp/a"})
            self.assertEqual(asked, [], "a guard answered; there is nothing to launch")


if __name__ == "__main__":
    unittest.main()
