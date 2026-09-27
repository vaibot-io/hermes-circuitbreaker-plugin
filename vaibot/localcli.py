"""Bridge to the guard's one-shot CLI subcommands.

Two things the plugin must not reimplement, so it runs the guard's own code:

* ``classify`` — the local safety floor, used only on degraded paths (no key,
  guard down, breaker tripped). A Python copy would be a second floor drifting
  from the first.
* ``bootstrap`` — first-run provisioning. The credential store is shared by
  every breaker on the machine and has exactly one writer; this keeps it that
  way.

Both are contracts of the form "exit 0 + one JSON line, or it didn't answer".
Anything else — no CLI, an old CLI without the subcommand, a timeout, a non-zero
exit, unparseable output — comes back as ``None``, and the caller falls back to
its own fail-closed posture. Nothing here raises.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

from . import config
from .vocab import classifier_tool_name

CLASSIFY_TIMEOUT_S = 5.0
BOOTSTRAP_TIMEOUT_S = 15.0


def guard_cli(env: Optional[Mapping[str, str]] = None) -> Optional[List[str]]:
    """argv prefix for the guard CLI, or None when there isn't one.

    ``VAIBOT_GUARD_CLI`` names it explicitly (a ``.mjs``/``.js`` path runs under
    node); otherwise ``vaibot-guard`` on PATH.
    """
    # Layered so ``guard_cli`` can also come from Hermes plugin config; PATH and
    # every other name reads straight through.
    e = config.layered(env)
    search_path = e.get("PATH")
    override = (e.get("VAIBOT_GUARD_CLI") or "").strip()
    if override:
        if override.endswith((".mjs", ".js")):
            node = shutil.which("node", path=search_path)
            return [node, override] if node else None
        return [override]
    found = shutil.which("vaibot-guard", path=search_path)
    return [found] if found else None


def run_json(
    argv: Sequence[str],
    stdin: Optional[str],
    timeout_s: float,
    env: Optional[Mapping[str, str]],
) -> Optional[Dict[str, Any]]:
    try:
        proc = subprocess.run(
            list(argv),
            input=stdin if stdin is not None else "",
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=dict(os.environ if env is None else env),
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout.strip() or "null")
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


@dataclass(frozen=True)
class Verdict:
    #: "allow" | "ask" | "deny"
    verdict_hint: str
    risk: str
    reasons: tuple

    @property
    def reason(self) -> str:
        return self.reasons[0] if self.reasons else self.risk


def classify(
    tool_name: str,
    params: Optional[Mapping[str, Any]],
    *,
    env: Optional[Mapping[str, str]] = None,
    timeout_s: float = CLASSIFY_TIMEOUT_S,
) -> Optional[Verdict]:
    """The guard's offline verdict for one call, or None if it didn't answer."""
    cli = guard_cli(env)
    if not cli:
        return None
    try:
        payload = json.dumps({"toolName": classifier_tool_name(tool_name), "params": dict(params or {})})
    except (TypeError, ValueError):
        return None
    data = run_json([*cli, "classify"], payload, timeout_s, env)
    if not data:
        return None
    hint = data.get("verdictHint")
    if hint not in ("allow", "ask", "deny"):
        # A verdict without a usable hint is a failure to answer, never an allow.
        return None
    reasons = data.get("reasons")
    return Verdict(
        verdict_hint=hint,
        risk=str(data.get("risk") or "unknown"),
        reasons=tuple(str(r) for r in reasons) if isinstance(reasons, list) else (),
    )


@dataclass(frozen=True)
class BootstrapResult:
    provisioned: bool
    #: "key-present" | "account-exists" | None (when provisioned)
    reason: Optional[str]
    env: Optional[str]
    wallet_address: Optional[str] = None


def bootstrap(
    agent: str = "hermes",
    *,
    env: Optional[Mapping[str, str]] = None,
    timeout_s: float = BOOTSTRAP_TIMEOUT_S,
) -> Optional[BootstrapResult]:
    """Provision an account through the guard CLI, or None if it didn't answer.

    The key never comes back through here — the CLI writes it to the shared
    store and the caller re-reads it — so it can't leak into a log line.
    """
    cli = guard_cli(env)
    if not cli:
        return None
    # Leave the CLI's own network timeout inside ours, so it reports a failure
    # rather than being cut off mid-write.
    inner_ms = max(1000, int((timeout_s - 3) * 1000))
    data = run_json([*cli, "bootstrap", "--agent", agent, "--timeout-ms", str(inner_ms)], None, timeout_s, env)
    if not data or data.get("ok") is not True or not isinstance(data.get("provisioned"), bool):
        return None
    reason = data.get("reason")
    wallet = data.get("wallet_address")
    return BootstrapResult(
        provisioned=data["provisioned"],
        reason=reason if isinstance(reason, str) else None,
        env=data.get("env") if isinstance(data.get("env"), str) else None,
        wallet_address=wallet if isinstance(wallet, str) else None,
    )
