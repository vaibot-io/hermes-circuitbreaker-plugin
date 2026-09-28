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
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from . import config
from .vocab import classifier_tool_name

CLASSIFY_TIMEOUT_S = 5.0
BOOTSTRAP_TIMEOUT_S = 15.0


#: The guard shipped inside this package. Every other breaker vendors the guard
#: too, which is what makes a single `npm install` a complete install; this is the
#: same property for `pip install`. Someone may meet this plugin before they ever
#: meet the CLI, and "now go install something else" is not a front door.
#:
#: Vendored from the published tarball and verified against the digest the registry
#: reports (see vendor/vaibot-guard.sha1), so the committed copy is provably what
#: npm serves rather than whatever happened to be on the build machine.
VENDORED_GUARD = ("vendor", "vaibot-guard", "scripts", "vaibot-guard.mjs")


def vendored_guard_path() -> Optional[str]:
    """Absolute path to the guard CLI shipped with this package, if present."""
    p = Path(__file__).resolve().parent.joinpath(*VENDORED_GUARD)
    return str(p) if p.is_file() else None


def resolve_guard_cli(env: Optional[Mapping[str, str]] = None) -> tuple:
    """``(argv, source)`` for the guard CLI. ``source`` is for diagnostics only.

    Resolution order, and the reason for it:

    1. ``VAIBOT_GUARD_CLI`` — an explicit choice always wins.
    2. ``vaibot-guard`` on PATH — a system install is preferred over the vendored
       copy so a NEWER guard is used when one exists, and so a machine with the
       full VAIBot stack keeps one guard rather than quietly running the one that
       happens to sit inside a plugin.
    3. The vendored copy — the floor still applies on a machine that has only this
       plugin. It needs node, which this plugin already required.
    4. ``(None, "none")`` — no guard. The caller must treat that as "cannot
       classify", never as "safe"; see :func:`Engine._degraded`.
    """
    e = config.layered(env)
    search_path = e.get("PATH")
    override = (e.get("VAIBOT_GUARD_CLI") or "").strip()
    if override:
        if override.endswith((".mjs", ".js")):
            node = shutil.which("node", path=search_path)
            return ([node, override], "override") if node else (None, "override-no-node")
        return ([override], "override")

    found = shutil.which("vaibot-guard", path=search_path)
    if found:
        return ([found], "path")

    vendored = vendored_guard_path()
    if vendored:
        node = shutil.which("node", path=search_path)
        if node:
            return ([node, vendored], "vendored")
        # The files are here but nothing can run them. Worth distinguishing from
        # "no guard at all", because the fix is different: install node.
        return (None, "vendored-no-node")

    return (None, "none")


def guard_cli(env: Optional[Mapping[str, str]] = None) -> Optional[List[str]]:
    """argv prefix for the guard CLI, or None when there isn't one."""
    return resolve_guard_cli(env)[0]


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
