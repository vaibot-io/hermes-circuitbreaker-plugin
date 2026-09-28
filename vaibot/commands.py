"""The ``/vaibot`` slash command — what is governing this session, right now.

Registered through ``ctx.register_command(name, handler, description, args_hint)``.
The handler takes the raw argument string and returns text, so the same command
works in a CLI session and through the Telegram and Discord gateways.

This exists for one moment in particular: an agent has just been stopped and the
operator needs to know why. The answer has to be readable without a dashboard, and
it has to work when the daemon is down — so containment and the breaker are read
from local state, and the guard is probed rather than assumed.

**Never prints a credential.** It says whether a key resolves and for which
environment, never the key, and never the guard token. A slash command's output
can land in a Telegram or Discord channel, so treating it as public is the only
safe assumption.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from . import guard as guard_client
from . import localcli
from .localcli import resolve_guard_cli
from .breaker import BreakerStore
from .containment import read_containment
from .creds import resolve_credentials

logger = logging.getLogger("vaibot")

USAGE = "\n".join(
    [
        "VAIBot — governance for this session.",
        "",
        "  /vaibot status   what is governing this session right now",
        "  /vaibot help     this message",
    ]
)


def _ago(iso: Optional[str]) -> str:
    """"3m ago" from an ISO timestamp, or "" when it can't be read."""
    if not iso:
        return ""
    try:
        stamp = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return ""
    seconds = (datetime.now(timezone.utc) - stamp).total_seconds()
    if seconds < 0:
        return ""
    if seconds < 90:
        return f"{int(seconds)}s ago"
    if seconds < 5400:
        return f"{int(seconds // 60)}m ago"
    return f"{int(seconds // 3600)}h ago"


def _grid(rows: list[tuple[str, str]]) -> list[str]:
    """Label/value rows on an aligned column.

    Alignment assumes a monospace surface, which the CLI is. A proportional
    gateway (Telegram, Discord) loses the column but keeps every label and value
    on its own line, so the readout degrades to a plain list rather than to
    nonsense.
    """
    width = max((len(label) for label, _ in rows), default=0)
    return [f"  {label.ljust(width)}   {value}" for label, value in rows]


def _classifier_row(argv, source: str) -> str:
    """What the degraded paths can actually reach, and what to do if that is nothing.

    Says which guard would answer AND whether it is new enough, because "a guard is
    installed" and "the floor works" are different facts.
    """
    if source == "none":
        return "NOT FOUND · degraded paths cannot reach the floor, so they ask instead"
    if source == "vendored-no-node":
        return "vendored copy present but node is missing · install node to use the floor"
    if source == "override-no-node":
        return "VAIBOT_GUARD_CLI names a .mjs but node is missing"

    where = {"path": "from PATH", "vendored": "vendored with this plugin", "override": "VAIBOT_GUARD_CLI"}.get(source, source)
    probe = localcli.classify("terminal", {"command": "true"}, env=None)
    if probe is None:
        return f"{where} · too old for `classify` · degraded paths ask instead of applying the floor"
    return f"{where} · `classify` answers"


def status_text(env: Optional[Mapping[str, str]] = None) -> str:
    rows: list[tuple[str, str]] = []
    footer: list[str] = []

    # Containment first: when it is engaged it is the only thing that matters,
    # and it is readable with no daemon and no network.
    containment = read_containment()
    if containment.contained:
        parts = ["CONTAINED"]
        if containment.reason:
            parts.append(containment.reason)
        since = _ago(containment.at)
        if since:
            parts.append(since)
        rows.append(("Containment", " · ".join(parts)))
        # The instruction goes below the grid: it is a sentence, not a field, and
        # it is the one thing the reader has to act on.
        footer = [
            "",
            "  Every action on this account is blocked, on every machine.",
            "  Lift it from the dashboard or with `vaibot release`.",
        ]
    else:
        rows.append(("Containment", "not engaged"))

    # The guard: probe it rather than trusting the rendezvous lock, which can
    # outlive the process that wrote it.
    lock = guard_client.read_lock(env)
    if lock is None:
        rows.append(("Guard", "none found · governing locally from the classifier floor"))
    else:
        health = guard_client.probe(lock)
        if health is None:
            rows.append(("Guard", "lock present, nothing answers · governing locally, flagged"))
        else:
            rows.append(("Guard", f"answering · {health.version or 'unknown version'}"))
            if health.capabilities:
                rows.append(("Understands", ", ".join(sorted(health.capabilities))))

    # WHICH guard CLI the degraded paths would reach, which is not the same
    # question as whether a daemon is answering. A machine can have a healthy
    # daemon and still have no usable `classify`, and that combination is exactly
    # what went unnoticed here for weeks: a 2.1.1 on PATH, predating the
    # subcommand, so every degraded path silently had no floor to consult.
    argv, source = resolve_guard_cli(env)
    rows.append(("Classifier", _classifier_row(argv, source)))

    # Identity, never the secret.
    try:
        creds = resolve_credentials(env)
        if creds.api_key:
            rows.append(("Account", f"key resolves · {creds.env}"))
        else:
            rows.append(("Account", f"no key yet · {creds.env} · run `vaibot login`"))
        if creds.key_mismatch:
            rows.append(("Warning", "the stored key's prefix names another environment, so it is ignored"))
    except Exception:  # a readout must never be the thing that fails
        rows.append(("Account", "could not read the credential store"))

    # The local breaker, which governs while the guard is unreachable.
    try:
        breaker = BreakerStore(env).load()
        if breaker.is_tripped():
            rows.append(("Breaker", "TRIPPED · deciding locally until it cools down"))
        elif breaker.failures:
            rows.append(("Breaker", f"{len(breaker.failures)} recent guard failure(s)"))
        else:
            rows.append(("Breaker", "healthy"))
    except Exception:
        pass

    return "\n".join(["VAIBot status", ""] + _grid(rows) + footer)


def handle(raw_args: str, env: Optional[Mapping[str, str]] = None) -> str:
    """Dispatch ``/vaibot <sub>``. Never raises: a command that throws inside the
    agent's own chat is a worse failure than one that says it could not answer."""
    try:
        sub = (raw_args or "").strip().split()
        if not sub or sub[0] in ("help", "-h", "--help"):
            return USAGE
        if sub[0] == "status":
            return status_text(env)
        return f"Unknown subcommand {sub[0]!r}.\n\n{USAGE}"
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("vaibot: /vaibot failed: %s", exc)
        return "VAIBot: couldn't read status just now."


def register(ctx: Any) -> None:
    """Attach the command, if this Hermes exposes slash commands.

    Guarded by a capability check rather than assumed: a Hermes without
    ``register_command`` must still load the plugin, because governance matters
    more than a status readout.
    """
    register_command = getattr(ctx, "register_command", None)
    if not callable(register_command):
        logger.info("vaibot: this Hermes has no slash-command API — /vaibot not registered")
        return
    try:
        register_command(
            "vaibot",
            lambda raw_args: handle(raw_args),
            description="VAIBot governance status",
            args_hint="[status|help]",
        )
    except Exception as exc:
        logger.warning("vaibot: could not register /vaibot: %s", exc)
