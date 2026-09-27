"""Discover-or-launch the one local guard.

A machine has exactly **one** guard. That invariant is held by two things the
daemon owns: the rendezvous lock it writes at ``~/.vaibot/guard/guard.json``, and
the port it binds, which acts as a mutex. So the job here is not "start a
daemon" — it is *adopt* the running one, and only start one when there is
genuinely none.

**This module does not implement the launch.** ``@vaibot/guard`` already ships
the launcher every other breaker uses (``scripts/lib/guard-launch.mjs``,
``ensureGuardDefault``): single-flight through an ``O_EXCL`` lock file with a
stale-holder steal, a candidate-port walk that identity-checks whatever is
already bound, the daemon spawned detached with its boot output tee'd to
``~/.vaibot/guard/launch.log``, and the rendezvous lock written atomically at
0600. A Python copy of that would be a second implementation of a
single-instance rule, and — worse — a second writer of the rendezvous file. This
plugin already refuses to reimplement the classifier and the credential writer
for the same reason; the launcher is the third such thing. So it shells out, in
the same shape as :mod:`vaibot.localcli`: one short-lived node process, exit 0
plus one JSON line, and anything else means "it didn't answer".

What this module *does* own is everything on the Python side of that call:

* **Adopt before launching.** Probe the lock first; a healthy guard is reused and
  nothing is spawned.
* **Single-flight in this process.** A non-blocking lock, so a burst of tool
  calls cannot start a second node bridge, plus a cooldown so a machine that
  cannot run a guard is not re-tried on every call. Cross-process single-flight
  is the guard's own launch lock — the one file every breaker agrees on.
* **Never block a decision.** :func:`ensure_in_background` runs on a daemon
  thread. A cold start pays a bounded wait for the daemon to report healthy, and
  a tool call must not wait for it: the degrade ladder already governs that call
  locally, and the next one finds the guard. ``hermes vaibot guard`` runs the
  same thing in the foreground, where waiting is the point.
* **Stay out of the way when told.** An explicit ``VAIBOT_GUARD_BASE_URL`` names
  someone else's guard, and ``auto_launch: false`` (or ``VAIBOT_AUTO_LAUNCH=0``)
  switches this off. Neither ever spawns anything.

Nothing here raises. A guard that cannot be started is an outage, and the ladder
in :mod:`vaibot.engine` already knows what to do about one.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from . import config
from . import guard as guard_client
from . import localcli

logger = logging.getLogger("vaibot")

#: The daemon script the launcher spawns, and the launcher itself — both siblings
#: of the guard CLI inside the installed ``@vaibot/guard`` package.
GUARD_SERVICE_SCRIPT = "vaibot-guard-service.mjs"
LAUNCHER_SCRIPT = ("lib", "guard-launch.mjs")

#: Longer than the launcher's own budget (up to ~3s waiting for its lock plus a
#: 10s wait for the daemon to report healthy), so a slow cold start is reported
#: as what it is rather than cut off mid-spawn and read as a failure.
ENSURE_TIMEOUT_S = 30.0

#: After an attempt that produced no healthy guard, how long before trying again.
#: A machine with no node, no guard package, or a crash-looping daemon must not
#: pay a subprocess per tool call.
RETRY_AFTER_S = 60.0

#: Runs inside node. Reads its arguments as JSON on stdin — never argv, which is
#: world-readable in ``ps`` — and prints one JSON line.
_BRIDGE = """
let raw = ''
for await (const chunk of process.stdin) raw += chunk
const opts = JSON.parse(raw || '{}')
const { ensureGuardDefault } = await import(opts.launcher)
const r = await ensureGuardDefault({ guardScript: opts.guardScript, guardEnv: opts.guardEnv || {} })
const ok = !!(r && r.ok)
process.stdout.write(JSON.stringify({
  ok,
  status: (r && r.status) || (ok ? 'launched' : 'failed'),
  port: r && Number.isInteger(r.port) ? r.port : null,
  reason: (r && r.reason) || null,
}))
"""


@dataclass(frozen=True)
class Launch:
    """What happened, in one word plus a sentence for a human."""

    #: reused | launched | external | disabled | no-node | no-launcher |
    #: failed | in-flight | cooling
    status: str
    detail: str = ""
    port: Optional[int] = None

    @property
    def running(self) -> bool:
        """Is a guard known to be up as a result of this call?"""
        return self.status in ("reused", "launched")


def _node(env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    import shutil

    e = config.layered(env)
    return shutil.which("node", path=e.get("PATH"))


def guard_scripts(env: Optional[Mapping[str, str]] = None) -> Optional[Tuple[Path, Path]]:
    """``(launcher, daemon)`` inside the installed guard package, or None.

    Both are resolved from whatever ``localcli`` resolved the guard CLI to —
    ``VAIBOT_GUARD_CLI`` or ``vaibot-guard`` on PATH, which is normally a symlink
    into the package — so the launcher that runs always belongs to the same guard
    install the classifier and ``bootstrap`` come from. A guard too old to ship
    the launcher, or a CLI that is a wrapper somewhere else entirely, yields None,
    and the caller reports that it has no launcher rather than guessing a path.
    """
    cli = localcli.guard_cli(env)
    if not cli:
        return None
    try:
        scripts_dir = Path(cli[-1]).resolve().parent
        launcher = scripts_dir.joinpath(*LAUNCHER_SCRIPT)
        daemon = scripts_dir / GUARD_SERVICE_SCRIPT
        if launcher.is_file() and daemon.is_file():
            return launcher, daemon
    except OSError:
        return None
    return None


def _workspace(env: Optional[Mapping[str, str]] = None) -> str:
    """The workspace to pin on the daemon we start.

    Handing it over explicitly is the one thing worth saying at launch: a guard
    left to infer its workspace takes the current directory of whatever happened
    to start it, and then every edit outside that directory is an escalation.
    """
    return config.layered(env).get("VAIBOT_WORKSPACE") or os.getcwd()


def _ensure_via_node(
    launcher: Path,
    daemon: Path,
    workspace: str,
    env: Optional[Mapping[str, str]],
    timeout_s: float,
) -> Optional[Dict[str, Any]]:
    """Run the guard's own ``ensureGuardDefault``. None means it didn't answer."""
    import json

    node = _node(env)
    if not node:
        return None
    payload = json.dumps(
        {
            "launcher": launcher.as_uri(),
            "guardScript": str(daemon),
            "guardEnv": {"VAIBOT_WORKSPACE": workspace} if workspace else {},
        }
    )
    return localcli.run_json([node, "--input-type=module", "-e", _BRIDGE], payload, timeout_s, env)


# ── single-flight state ─────────────────────────────────────────────────────

_flight = threading.Lock()
_state_lock = threading.Lock()
_next_attempt_at = 0.0
_thread: Optional[threading.Thread] = None


def reset() -> None:
    """Forget the cooldown and any in-flight marker (tests)."""
    global _next_attempt_at, _thread
    with _state_lock:
        _next_attempt_at = 0.0
        _thread = None


def _cooling(clock: Callable[[], float]) -> bool:
    with _state_lock:
        return clock() < _next_attempt_at


def _back_off(clock: Callable[[], float]) -> None:
    global _next_attempt_at
    with _state_lock:
        _next_attempt_at = clock() + RETRY_AFTER_S


def ensure_guard(
    env: Optional[Mapping[str, str]] = None,
    *,
    read_lock: Callable[..., Optional[guard_client.GuardLock]] = guard_client.read_lock,
    probe: Callable[..., Optional[guard_client.Health]] = guard_client.probe,
    run: Callable[..., Optional[Dict[str, Any]]] = _ensure_via_node,
    clock: Callable[[], float] = time.monotonic,
    timeout_s: float = ENSURE_TIMEOUT_S,
) -> Launch:
    """Adopt the running guard, or start one. Idempotent; never spawns a second."""
    e = config.layered(env)
    if e.get("VAIBOT_GUARD_BASE_URL"):
        return Launch("external", "VAIBOT_GUARD_BASE_URL names a guard; not starting one")
    if not config.auto_launch_enabled(env):
        return Launch("disabled", "auto-launch is switched off")

    # Adopt first, and cheaply: the overwhelmingly common case is a guard that is
    # already up, and it must cost one probe and no lock.
    adopted = _adopt(env, read_lock, probe)
    if adopted is not None:
        return adopted

    if not _flight.acquire(blocking=False):
        # Another thread in this process is already dealing with it.
        return Launch("in-flight", "a launch is already under way")
    try:
        if _cooling(clock):
            return Launch("cooling", f"a recent attempt failed; not retrying for {int(RETRY_AFTER_S)}s")
        # Re-check under the flight lock: the guard may have come up while we
        # were waiting, and adopting beats launching every time.
        adopted = _adopt(env, read_lock, probe)
        if adopted is not None:
            return adopted

        scripts = guard_scripts(env)
        if scripts is None:
            _back_off(clock)
            return Launch(
                "no-launcher",
                "no @vaibot/guard install with a launcher was found — set VAIBOT_GUARD_CLI, or "
                "start the guard yourself",
            )
        if not _node(env):
            _back_off(clock)
            return Launch("no-node", "node is not on PATH, so the guard cannot be started here")

        launcher, daemon = scripts
        answer = run(launcher, daemon, _workspace(env), env, timeout_s)
        if not answer or answer.get("ok") is not True:
            _back_off(clock)
            reason = (answer or {}).get("reason") or "the launcher did not report a healthy guard"
            logger.warning(
                "vaibot: could not start the local guard (%s) — governing locally until one is "
                "running; see ~/.vaibot/guard/launch.log",
                reason,
            )
            return Launch("failed", str(reason))

        # Trust the rendezvous lock, not the answer: the daemon is what writes it,
        # and a launch that cannot be verified is not a launch.
        confirmed = _adopt(env, read_lock, probe)
        if confirmed is None:
            _back_off(clock)
            return Launch("failed", "the launcher reported success but no guard answers")
        status = "launched" if answer.get("status") != "reused" else "reused"
        if status == "launched":
            logger.info("vaibot: started the local guard on port %s", confirmed.port)
        return Launch(status, "", confirmed.port)
    finally:
        _flight.release()


def _adopt(
    env: Optional[Mapping[str, str]],
    read_lock: Callable[..., Optional[guard_client.GuardLock]],
    probe: Callable[..., Optional[guard_client.Health]],
) -> Optional[Launch]:
    """A healthy guard from the rendezvous lock, or None."""
    try:
        lock = read_lock(env)
    except Exception:
        return None
    if lock is None:
        return None
    try:
        health = probe(lock)
    except Exception:
        return None
    if health is None:
        return None
    return Launch("reused", f"guard {health.version or 'unknown version'} on port {lock.port}", lock.port)


def ensure_in_background(env: Optional[Mapping[str, str]] = None) -> None:
    """Kick :func:`ensure_guard` off on a daemon thread and return immediately.

    Governance never waits on this. Every caller is on a path that has already
    decided what to do without a guard, so the only thing a thread can do here is
    make the *next* call better.
    """
    global _thread
    with _state_lock:
        if _thread is not None and _thread.is_alive():
            return
        thread = threading.Thread(target=_ensure_quietly, args=(env,), name="vaibot-ensure-guard", daemon=True)
        _thread = thread
    thread.start()


def _ensure_quietly(env: Optional[Mapping[str, str]]) -> None:
    try:
        result = ensure_guard(env)
        logger.debug("vaibot: ensure-guard → %s %s", result.status, result.detail)
    except Exception as exc:  # a background thread must never take the agent down
        logger.warning("vaibot: ensure-guard failed unexpectedly: %s", exc)
