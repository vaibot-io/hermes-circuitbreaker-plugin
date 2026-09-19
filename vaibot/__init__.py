"""VAIBot governance plugin for Hermes — S1: skeleton + provenance.

Routes every tool call through the local ``@vaibot/guard`` and closes a signed,
tamper-evident receipt for it.

**This sprint does not enforce.** ``pre_tool_call`` always returns None, so no
call is ever blocked or escalated yet — S1 proves the receipt path end-to-end
against a real Hermes install. Enforcement (mapping the guard verdict onto
``block`` / ``approve``, the degrade ladder, observe-vs-enforce) is S2/S3, and
the seams for it are marked below.

Two things are structurally better here than in the Claude Code plugin, and the
design leans on both rather than porting its workarounds:

* **Hooks run in-process.** Run state is a dict. The Claude Code plugin has to
  persist run state to ``/tmp``, claim entries by unlinking them to survive
  races between concurrent hook subprocesses, and expire stale files. None of
  that applies here.
* **``post_tool_call`` fires even when a call is blocked** (``status="blocked"``,
  ``error_type="plugin_block"``). Every decision therefore closes its own
  receipt synchronously. There is no ask-in-flight orphan class, so there is no
  sweep, no ``Stop`` hook, and no pending-pointer files.

Failure posture for S1: this plugin must never take the agent down. Every hook
body is wrapped, and any internal error degrades to "no receipt" rather than an
exception escaping into the tool-dispatch path. When enforcement lands in S2
that posture inverts for the *decision* (fail closed), but never for the
*bookkeeping*.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional

from . import guard as guard_client
from .creds import resolve_credentials

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


def _workspace_dir() -> str:
    return os.environ.get("VAIBOT_WORKSPACE") or os.getcwd()


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


def _on_pre_tool_call(**kwargs: Any) -> None:
    """Decide + open a receipt. Returns None always in S1 (observe only).

    S2 seam: map the verdict onto Hermes' directives here —
      allow  → None
      deny   → {"action": "block",   "message": reason}
      approve→ {"action": "approve", "message": reason, "rule_key": ...}
    plus the degrade ladder when the guard is unreachable.
    """
    try:
        tool_name = str(kwargs.get("tool_name") or "")
        if _should_skip(tool_name):
            return None

        lock = guard_client.read_lock()
        if lock is None:
            # Cold start — the guard has never run here. S2 distinguishes this
            # from "ran and vanished" (possible tampering) and degrades
            # differently for each. For now: no guard, no receipt.
            logger.debug("vaibot: no guard lock; skipping %s", tool_name)
            return None

        decision, resp = guard_client.decide_tool(
            lock,
            session_id=str(kwargs.get("session_id") or "hermes"),
            tool_name=tool_name,
            params=kwargs.get("args") if isinstance(kwargs.get("args"), dict) else {},
            workspace_dir=_workspace_dir(),
        )

        if decision is None:
            logger.debug("vaibot: guard unreachable for %s (%s)", tool_name, resp.error)
            return None

        tool_call_id = str(kwargs.get("tool_call_id") or "")
        if decision.run_id and tool_call_id:
            _remember(tool_call_id, {"run_id": decision.run_id, "tool_name": tool_name})

        # S1 is observe-only: record what WOULD have happened without acting on
        # it. Logged rather than silent so the path is verifiable on a real
        # install before enforcement is switched on.
        if decision.decision != "allow":
            logger.info(
                "vaibot [observe]: %s would be %s — %s",
                tool_name, decision.decision, decision.reason,
            )
        return None
    except Exception as exc:  # never break tool dispatch
        logger.debug("vaibot pre_tool_call error: %s", exc)
        return None


def _on_post_tool_call(**kwargs: Any) -> None:
    """Close the receipt opened by pre_tool_call.

    Fires for blocked calls too, so `status` distinguishes a real failure from a
    governance block — that is what makes every receipt resolve synchronously.
    """
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
            logger.debug("vaibot: guard gone; run %s left open", entry["run_id"])
            return None

        status = str(kwargs.get("status") or "")
        error_message = kwargs.get("error_message")
        outcome = "blocked" if (status and status != "ok") else "allowed"

        guard_client.finalize_tool(
            lock,
            session_id=str(kwargs.get("session_id") or "hermes"),
            run_id=str(entry["run_id"]),
            outcome=outcome,
            duration_ms=kwargs.get("duration_ms"),
            error=str(error_message) if error_message else None,
        )
        return None
    except Exception as exc:
        logger.debug("vaibot post_tool_call error: %s", exc)
        return None


def register(ctx: Any) -> None:
    """Entry point Hermes calls to load the plugin."""
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("post_tool_call", _on_post_tool_call)

    creds = resolve_credentials()
    if creds.key_mismatch:
        logger.warning(
            "vaibot: ignoring a stored API key whose prefix doesn't match env=%r", creds.env
        )
    if guard_client.read_lock() is None:
        # Not fatal: the guard may come up later, and S1 simply records nothing
        # until it does. S4 adds probe-and-launch.
        logger.info("vaibot: no local guard found — receipts will start once it is running")
