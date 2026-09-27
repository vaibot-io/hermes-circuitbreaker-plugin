"""VAIBot governance plugin for Hermes — the hook layer.

Routes every tool call through the local ``@vaibot/guard``, turns its verdict
into a Hermes directive, and closes a signed, tamper-evident receipt for it:

    guard allow    → None                  (the call proceeds)
    guard approve  → {"action": "approve"} (Hermes' native [o]nce/[s]ession/[a]lways/[d]eny)
    guard deny     → {"action": "block"}   (the message becomes the tool result)

When the guard can't answer, the degrade ladder in ``engine`` decides locally,
with the guard's own classifier as the floor. See ``engine`` for each rung.

Two things are structurally better here than in the Claude Code plugin, and the
design leans on both rather than porting its workarounds:

* **Hooks run in-process.** Run state is a dict. The Claude Code plugin has to
  persist run state to ``/tmp``, claim entries by unlinking them to survive
  races between concurrent hook subprocesses, and expire stale files. None of
  that applies here.
* **``post_tool_call`` fires even when a call is blocked** (``status="blocked"``),
  including when a human declines the approval prompt. Every decision therefore
  closes its own receipt synchronously. There is no ask-in-flight orphan class,
  so there is no sweep, no ``Stop`` hook, and no pending-pointer files.

Failure posture: the *decision* fails closed — an unexpected error while
governing a call blocks it (unless the operator chose observe or FAIL_OPEN),
because Hermes treats a raising hook as "no directive" and would run the call.
The *bookkeeping* never fails closed: a receipt that can't be written is logged
and dropped, never allowed to reach tool dispatch.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, Optional

from . import cli, commands, config, launch
from . import guard as guard_client
from .containment import block_message as containment_block_message, read_containment
from .creds import resolve_credentials
from .engine import Engine, Settings

logger = logging.getLogger("vaibot")

#: Kept in step with ``plugin.yaml`` and read by the build as the package version,
#: so the three can't drift (there is a test).
__version__ = "0.2.0"

#: Governance tools are exempt so a governance call can't recurse into governing
#: itself, and so an operator can still lift containment from inside the agent.
#: Hermes namespaces MCP tools as ``mcp__<server>__<tool>`` — the same convention
#: Claude Code uses, so this check ports verbatim.
#:
#: Matched at the namespace boundary rather than as a bare prefix: an exemption
#: that any name *beginning* with this satisfied would hand a server called
#: ``vaibotage`` a tool namespace that is never governed at all.
_SELF_PREFIX = "mcp__vaibot"
_SELF_NAMESPACE = _SELF_PREFIX + "__"

#: tool_call_id → run bookkeeping, consumed by post_tool_call. In-process and
#: mutated from the agent's tool threads, so it takes a lock; a dict here
#: replaces the entire /tmp state-file mechanism the subprocess plugins need.
_runs: Dict[str, Dict[str, Any]] = {}
_runs_lock = threading.Lock()

#: Bounded so a pathological session can't grow this without limit. post_tool_call
#: fires for every pre_tool_call (including blocked calls), so entries are
#: normally consumed immediately and this ceiling is never approached.
_MAX_TRACKED_RUNS = 512

_engine: Optional[Engine] = None
_engine_lock = threading.Lock()


def _get_engine() -> Engine:
    global _engine
    with _engine_lock:
        if _engine is None:
            # The real launcher is passed in here and nowhere else: an Engine
            # built any other way (every test) cannot start a daemon by omission.
            _engine = Engine(ensure=launch.ensure_in_background)
        return _engine


def _remember(tool_call_id: str, entry: Dict[str, Any]) -> None:
    with _runs_lock:
        if len(_runs) >= _MAX_TRACKED_RUNS:
            # Drop the oldest rather than refusing to track the newest: a stuck
            # entry is a lost receipt, but refusing new ones loses all of them.
            try:
                _runs.pop(next(iter(_runs)))
            except StopIteration:
                pass
        _runs[tool_call_id] = entry


def _take(tool_call_id: str) -> Optional[Dict[str, Any]]:
    with _runs_lock:
        return _runs.pop(tool_call_id, None)


def _should_skip(tool_name: str) -> bool:
    return not tool_name or tool_name == _SELF_PREFIX or tool_name.startswith(_SELF_NAMESPACE)


def _on_pre_tool_call(**kwargs: Any) -> Optional[Dict[str, Any]]:
    """Decide, open a receipt, and return Hermes' directive (None = proceed)."""
    tool_name = str(kwargs.get("tool_name") or "")
    if _should_skip(tool_name):
        return None
    args = kwargs.get("args")
    args = args if isinstance(args, dict) else {}

    try:
        outcome = _get_engine().decide(tool_name, args, str(kwargs.get("session_id") or ""))
    except Exception:
        logger.exception("vaibot: governing %s failed", tool_name)
        # An unexpected failure is one more path that never reached the guard, and
        # this is the only branch where observe or FAIL_OPEN would run the call
        # anyway — so the account-wide stop is checked here too. read_containment
        # never raises and needs no daemon, network or credentials, which is what
        # makes it safe to trust from inside an error handler.
        contained = read_containment()
        if contained.contained:
            return {"action": "block", "message": containment_block_message(contained)}
        if Settings.from_env().lenient:
            return None
        return {
            "action": "block",
            "message": f"VAIBot: internal error while governing {tool_name} — blocked (fail-closed).",
        }

    tool_call_id = str(kwargs.get("tool_call_id") or "")
    if outcome.run_id and tool_call_id:
        # `gate_asked` — did we hand this to Hermes' approval gate, or block it
        # ourselves? `escalated` alone conflates the two: refusing an auto-granted
        # escalation is also an escalated run, but it returns a block directive, so
        # no prompt ever opens. Only the directive distinguishes them.
        directive = outcome.directive or {}
        _remember(tool_call_id, {
            "run_id": outcome.run_id,
            "escalated": outcome.escalated,
            "gate_asked": outcome.escalated and directive.get("action") == "approve",
        })
    return outcome.directive


def _finalize_fields(entry: Dict[str, Any], status: str) -> tuple:
    """(outcome, approval, approval_scope) for the guard's finalize.

    A call we handed to Hermes' approval gate and that came back ``blocked`` was
    not granted: the human chose ``[d]eny``, the prompt timed out, or the gate
    errored — all three fail closed upstream. The guard reads an escalated run as
    *approved* unless told otherwise, so say so explicitly, and mark the scope
    ``prompt`` to record that someone was actually asked.

    A call VAIBot blocked ITSELF is different and must not be recorded as a
    reviewer denial. Refusing an auto-granted escalation returns a ``block``
    directive, so Hermes never opens the gate and no human ever sees it. That is a
    policy deny, and writing it as ``denied_by_reviewer`` would put a decision in
    a person's mouth that they were never offered.

    What still cannot be told apart from here is *which* of deny, timeout or gate
    error ended a real prompt. Hermes reports all three as a blocked tool call, and
    the guard's receipt vocabulary has one state for "not granted" — so nothing
    honest distinguishes them yet. Claiming ``choice: deny`` for a timeout would be
    the same error in miniature.
    """
    if entry.get("gate_asked") and status == "blocked":
        return "denied_by_reviewer", "denied", "prompt"
    return ("allowed" if status == "ok" else "blocked"), None, None


def _on_post_tool_call(**kwargs: Any) -> None:
    """Close the receipt opened by pre_tool_call."""
    try:
        tool_name = str(kwargs.get("tool_name") or "")
        if _should_skip(tool_name):
            return None

        tool_call_id = str(kwargs.get("tool_call_id") or "")
        entry = _take(tool_call_id) if tool_call_id else None
        if not entry or not entry.get("run_id"):
            return None

        lock = guard_client.read_lock()
        if lock is None:
            logger.warning("vaibot: guard gone; run %s left unfinalized", entry["run_id"])
            return None

        outcome, approval, approval_scope = _finalize_fields(entry, str(kwargs.get("status") or "ok"))
        error_message = kwargs.get("error_message")
        resp = guard_client.finalize_tool(
            lock,
            session_id=str(kwargs.get("session_id") or "hermes"),
            run_id=str(entry["run_id"]),
            outcome=outcome,
            duration_ms=kwargs.get("duration_ms"),
            error=str(error_message) if error_message else None,
            approval=approval,
            approval_scope=approval_scope,
        )
        if not resp.ok:
            logger.warning("vaibot: finalize failed for run %s (%s)", entry["run_id"], resp.error or resp.status)
        return None
    except Exception as exc:  # bookkeeping never reaches tool dispatch
        logger.warning("vaibot: post_tool_call error: %s", exc)
        return None


def register(ctx: Any) -> None:
    """Entry point Hermes calls to load the plugin."""
    # Settings first: everything below, and every decision after, reads them.
    # A Hermes without the plugin-config API leaves the plugin on the environment
    # alone, which is how it has always run.
    config.from_ctx(ctx)

    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("post_tool_call", _on_post_tool_call)
    # /vaibot — a status readout for the moment an agent has just been stopped.
    # Registered defensively: a Hermes without the slash-command API must still
    # load the plugin, because governance matters more than a readout.
    commands.register(ctx)
    # `hermes vaibot status|guard` — the same answers from a terminal, for when
    # there is no session to type into. Registered just as defensively.
    cli.register(ctx)

    creds = resolve_credentials()
    if creds.key_mismatch:
        logger.warning(
            "vaibot: ignoring a stored API key whose prefix doesn't match env=%r — will re-provision", creds.env
        )
    if guard_client.read_lock() is None:
        logger.info("vaibot: no local guard found yet — governing locally until one is running")
    # Adopt the running guard, or bring one up, without holding up the session:
    # a cold start pays a daemon boot, and plugin load is not the place to wait
    # for it. Idempotent, so it costs one health probe when a guard is already up.
    launch.ensure_in_background()
