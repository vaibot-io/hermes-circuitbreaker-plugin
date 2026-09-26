"""VAIBot governance plugin for Hermes — S2: enforcement + degrade ladder.

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

from . import guard as guard_client
from .creds import resolve_credentials
from .engine import Engine, Settings

logger = logging.getLogger("vaibot")

#: Governance tools are exempt so a governance call can't recurse into governing
#: itself. Hermes namespaces MCP tools as ``mcp__<server>__<tool>`` — the same
#: convention Claude Code uses, so this check ports verbatim.
_SELF_PREFIX = "mcp__vaibot"

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
            _engine = Engine()
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
    return not tool_name or tool_name.startswith(_SELF_PREFIX)


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
        if Settings.from_env().lenient:
            return None
        return {
            "action": "block",
            "message": f"VAIBot: internal error while governing {tool_name} — blocked (fail-closed).",
        }

    tool_call_id = str(kwargs.get("tool_call_id") or "")
    if outcome.run_id and tool_call_id:
        _remember(tool_call_id, {"run_id": outcome.run_id, "escalated": outcome.escalated})
    return outcome.directive


def _finalize_fields(entry: Dict[str, Any], status: str) -> tuple:
    """(outcome, approval) for the guard's finalize.

    An escalated call that ended ``blocked`` was not granted — the human chose
    ``[d]eny``, the prompt timed out, no human was present, or VAIBot refused an
    automatic grant. The guard reads an escalated run as *approved* unless told
    otherwise, so say so explicitly.
    """
    if entry.get("escalated") and status == "blocked":
        return "denied_by_reviewer", "denied"
    return ("allowed" if status == "ok" else "blocked"), None


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

        outcome, approval = _finalize_fields(entry, str(kwargs.get("status") or "ok"))
        error_message = kwargs.get("error_message")
        resp = guard_client.finalize_tool(
            lock,
            session_id=str(kwargs.get("session_id") or "hermes"),
            run_id=str(entry["run_id"]),
            outcome=outcome,
            duration_ms=kwargs.get("duration_ms"),
            error=str(error_message) if error_message else None,
            approval=approval,
        )
        if not resp.ok:
            logger.warning("vaibot: finalize failed for run %s (%s)", entry["run_id"], resp.error or resp.status)
        return None
    except Exception as exc:  # bookkeeping never reaches tool dispatch
        logger.warning("vaibot: post_tool_call error: %s", exc)
        return None


def register(ctx: Any) -> None:
    """Entry point Hermes calls to load the plugin."""
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("post_tool_call", _on_post_tool_call)

    creds = resolve_credentials()
    if creds.key_mismatch:
        logger.warning(
            "vaibot: ignoring a stored API key whose prefix doesn't match env=%r — will re-provision", creds.env
        )
    if guard_client.read_lock() is None:
        logger.info("vaibot: no local guard found yet — governing locally until one is running")
