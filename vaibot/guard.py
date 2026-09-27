"""Client for the local ``@vaibot/guard`` daemon.

The guard is the decision engine and the thing that signs receipts; this module
is a thin, dependency-free client for it. Everything here uses the standard
library — a component sitting on a security path inside someone else's agent
should add as little surface as possible, and the calls are localhost JSON.

**Discovery is via the rendezvous lock, never a hardcoded port.** The daemon
writes ``~/.vaibot/guard/guard.json`` with the host/port/token it actually bound,
which is often not the default when another guard already holds that port.
Assuming the default is a silent way to govern nothing.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

DEFAULT_TIMEOUT_S = 10.0


def guard_lock_path(env: Optional[Mapping[str, str]] = None) -> Path:
    e = os.environ if env is None else env
    override = e.get("VAIBOT_CREDS_DIR")
    base = Path(override) if override else Path.home() / ".vaibot"
    return base / "guard" / "guard.json"


@dataclass(frozen=True)
class GuardLock:
    host: str
    port: int
    token: str
    #: Account posture the guard last published. Authoritative over any local
    #: VAIBOT_MODE when present — the guard polls the control plane for it.
    effective_mode: Optional[str] = None


def read_lock(env: Optional[Mapping[str, str]] = None) -> Optional[GuardLock]:
    """Read the rendezvous lock, or None when absent/unreadable/malformed.

    None is meaningful: it is the "cold start" signal the degrade ladder keys off
    (a machine where the guard has never run) as distinct from a guard that ran
    and has since gone away. Callers must preserve that distinction.
    """
    e = os.environ if env is None else env

    base_url = e.get("VAIBOT_GUARD_BASE_URL")
    if base_url:
        # Explicit override: external guard, or a test seam.
        try:
            from urllib.parse import urlparse

            u = urlparse(base_url)
            if u.hostname:
                return GuardLock(
                    host=u.hostname,
                    port=int(u.port or 39111),
                    token=e.get("VAIBOT_GUARD_TOKEN", ""),
                )
        except (ValueError, TypeError):
            pass  # fall through to the lock

    try:
        raw = json.loads(guard_lock_path(e).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None

    port = raw.get("port")
    if not isinstance(port, int) or port <= 0:
        return None

    mode = raw.get("effective_mode")
    return GuardLock(
        host=str(raw.get("host") or "127.0.0.1"),
        port=port,
        token=str(raw.get("token") or ""),
        effective_mode=mode if mode in ("observe", "enforce") else None,
    )


@dataclass(frozen=True)
class GuardResponse:
    ok: bool
    #: True only for transport-level failures (connection refused, timeout, 5xx).
    #: A 4xx is a real answer from a reachable guard, NOT an outage — conflating
    #: them would trip the circuit breaker on an auth problem.
    unreachable: bool = False
    status: Optional[int] = None
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


def _post_json(
    lock: GuardLock, path: str, payload: Dict[str, Any], timeout_s: float
) -> GuardResponse:
    url = f"http://{lock.host}:{lock.port}{path}"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("content-type", "application/json")
    if lock.token:
        req.add_header("authorization", f"Bearer {lock.token}")

    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            try:
                return GuardResponse(ok=True, status=resp.status, data=json.loads(text or "{}"))
            except ValueError:
                # Reachable but unparseable — treat as an outage so the caller
                # falls back rather than reading a missing decision as allow.
                return GuardResponse(ok=False, unreachable=True, status=resp.status,
                                     error="malformed guard response")
    except urllib.error.HTTPError as exc:
        return GuardResponse(ok=False, unreachable=exc.code >= 500, status=exc.code,
                             error=f"http {exc.code}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return GuardResponse(ok=False, unreachable=True, error=str(exc))


@dataclass(frozen=True)
class Health:
    #: What the live daemon's decisions understand (e.g. "host-vocab:hermes").
    #: Empty for a guard that predates the field.
    capabilities: frozenset = frozenset()
    version: Optional[str] = None


def probe(lock: GuardLock, timeout_s: float = 2.0) -> Optional[Health]:
    """GET /health on the live daemon, or None when nothing healthy answers.

    Tells a live guard from a stale lock, and reports its capabilities. Read
    from the daemon itself rather than the lock, which can outlive the process
    that wrote it.
    """
    try:
        req = urllib.request.Request(f"http://{lock.host}:{lock.port}/health", method="GET")
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            if not 200 <= resp.status < 300:
                return None
            text = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None
    try:
        data = json.loads(text or "{}")
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    caps = data.get("capabilities")
    version = data.get("version")
    return Health(
        capabilities=frozenset(c for c in caps if isinstance(c, str)) if isinstance(caps, list) else frozenset(),
        version=version if isinstance(version, str) else None,
    )


def health(lock: GuardLock, timeout_s: float = 2.0) -> bool:
    """Probe /health. Used to tell a live guard from a stale lock."""
    return probe(lock, timeout_s) is not None


@dataclass(frozen=True)
class Decision:
    #: "allow" | "deny" | "approve". Defaults to deny on a malformed answer.
    decision: str
    reason: str
    run_id: Optional[str] = None
    approval_id: Optional[str] = None
    #: True marks the un-overridable catastrophic floor (Tier-0), which denies
    #: even in observe mode.
    floor: bool = False
    risk: Any = None
    effective_mode: Optional[str] = None
    #: The policy rule that fired, and its subject where one applies — e.g.
    #: ``file-outside-workspace:~/other/dir``, ``network:example.com``,
    #: ``token-approve:curl``. Present on escalations and denials from a guard
    #: advertising ``rule-id``; None from one that predates it. This is the grain
    #: an ``[a]lways`` answer is scoped to, so a session grant covers the rule
    #: rather than one exact call or a whole tool.
    rule_id: Optional[str] = None
    #: The guard refused an escalation because the host's own approvals are
    #: switched off — policy ``hostBypassAction: deny``. The call is denied and
    #: no approval record is minted.
    bypass_blocked: bool = False
    #: Policy allows the host to grant this escalation itself
    #: (``hostBypassAction: approve``). The receipt records ``bypassed``, never
    #: ``approved``, so provenance never claims a human decided.
    bypass_override: bool = False
    #: What the guard resolved the policy's bypass posture to: "deny" | "approve".
    host_bypass_action: Optional[str] = None


def decide_tool(
    lock: GuardLock,
    *,
    session_id: str,
    tool_name: str,
    params: Optional[Dict[str, Any]] = None,
    workspace_dir: str = "",
    approval_id: Optional[str] = None,
    host_bypass: Optional[tuple[bool, str]] = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> tuple[Optional[Decision], GuardResponse]:
    """POST /v1/decide/tool.

    Returns ``(decision, response)``. ``decision`` is None only when the guard
    could not be reached or answered; a reachable guard that returns something
    unusable yields a **deny**, never a silent allow.
    """
    payload: Dict[str, Any] = {
        "sessionId": session_id or "hermes",
        "toolName": tool_name,
        "params": params or {},
        "workspaceDir": workspace_dir or "",
    }
    if approval_id:
        payload["approval"] = {"approvalId": approval_id}
    if host_bypass is not None:
        # Report the host's posture; the guard applies the policy's
        # hostBypassAction itself. Reporting rather than enforcing is the point:
        # loosening a bypass to "approve" takes a verified signed bundle, which a
        # plugin cannot mint. The mechanism is a short label for the receipt.
        active, mechanism = host_bypass
        payload["hostBypass"] = {"active": bool(active), "mechanism": mechanism or ""}

    resp = _post_json(lock, "/v1/decide/tool", payload, timeout_s)
    if not resp.ok or not isinstance(resp.data, dict):
        return None, resp

    data = resp.data
    inner = data.get("decision")
    inner = inner if isinstance(inner, dict) else {}
    raw_decision = inner.get("decision")

    mode = data.get("effective_mode")
    return (
        Decision(
            # Fail-closed: a 200 with no usable verdict is a reachable guard
            # returning garbage. Deny, never allow.
            decision=raw_decision if isinstance(raw_decision, str) else "deny",
            reason=str(inner.get("reason") or "malformed guard decision"),
            run_id=data.get("runId"),
            approval_id=inner.get("approvalId"),
            floor=inner.get("floor") is True,
            risk=data.get("risk"),
            effective_mode=mode if mode in ("observe", "enforce") else None,
            rule_id=inner["ruleId"] if isinstance(inner.get("ruleId"), str) else None,
            bypass_blocked=inner.get("bypassBlocked") is True,
            bypass_override=inner.get("bypassOverride") is True,
            host_bypass_action=(
                data["host_bypass_action"]
                if data.get("host_bypass_action") in ("deny", "approve")
                else None
            ),
        ),
        resp,
    )


def finalize_tool(
    lock: GuardLock,
    *,
    session_id: str,
    run_id: str,
    outcome: str,
    duration_ms: Optional[float] = None,
    error: Optional[str] = None,
    approval: Optional[str] = None,
    approval_scope: Optional[str] = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> GuardResponse:
    """POST /v1/finalize/tool — closes the run and proves the finalize receipt.

    ``approval="denied"`` records that the gate refused an escalated call. The
    guard derives the receipt's approval status from the finalize, so an escalated
    run finalized without it is written as approved.

    ``approval_scope="prompt"`` records that a prompt actually fired, which is
    what separates "the gate refused" from "VAIBot refused before anyone was
    asked". The guard's vocabulary is ``prompt`` | ``session-grant``.
    """
    result: Dict[str, Any] = {"outcome": outcome}
    if approval:
        result["approval"] = approval
    if approval_scope:
        result["approvalScope"] = approval_scope
    if isinstance(duration_ms, (int, float)):
        result["duration_ms"] = duration_ms
    if error:
        result["error"] = str(error)[:2000]

    return _post_json(
        lock,
        "/v1/finalize/tool",
        {"sessionId": session_id or "hermes", "runId": run_id, "result": result},
        timeout_s,
    )
