"""``hermes vaibot ...`` — the same answers, from a terminal.

Registered through ``ctx.register_cli_command(name, help, setup_fn, handler_fn)``:
``setup_fn`` is handed an argparse subparser, ``handler_fn`` the parsed namespace.

Two subcommands, and both exist because of when they are needed:

``hermes vaibot status``
    The readout ``/vaibot status`` gives, for the times you are not in a session
    — a cron run that stopped, a gateway that is quiet, a machine you have just
    walked up to. Same text, same rule about never printing a credential.

``hermes vaibot guard``
    Make sure the local guard is running, and say what happened. Auto-launch is
    otherwise silent and runs on a background thread, so this is where an
    operator can watch it, wait for it, and read the reason when it fails. Safe
    to run repeatedly: it adopts a running guard rather than starting another.

A Hermes without the CLI-command API still loads the plugin. Governance outranks
a terminal command, exactly as it outranks the slash command.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from . import commands, launch

logger = logging.getLogger("vaibot")

SUBCOMMANDS = ("status", "guard")


def setup(parser: Any) -> None:
    """Build ``hermes vaibot <command>``. Called by Hermes with a subparser."""
    sub = parser.add_subparsers(dest="vaibot_subcommand", metavar="<command>")
    sub.add_parser("status", help="what is governing this machine right now")
    sub.add_parser(
        "guard",
        help="make sure the local guard is running (adopts a running one; never starts a second)",
    )


def _guard_lines(result: launch.Launch) -> list:
    headline = {
        "reused": "A guard is already running — adopted it.",
        "launched": "Started the local guard.",
        "external": "Using the guard named by VAIBOT_GUARD_BASE_URL.",
        "disabled": "Auto-launch is switched off, so nothing was started.",
        "in-flight": "Another launch is already under way.",
        "cooling": "A recent attempt failed, so this one backed off.",
        "no-node": "Could not start a guard: node is not available.",
        "no-launcher": "Could not start a guard: no @vaibot/guard install was found.",
        "failed": "Could not start a guard.",
    }.get(result.status, f"Guard: {result.status}")
    lines = ["VAIBot guard", "", f"  {headline}"]
    if result.port:
        lines.append(f"  Port {result.port}")
    if result.detail:
        lines.append(f"  {result.detail}")
    if not result.running and result.status not in ("external", "disabled"):
        lines += [
            "",
            "  VAIBot keeps governing from the classifier floor until a guard is up.",
            "  The daemon's own boot output is in ~/.vaibot/guard/launch.log.",
        ]
    return lines


def handle(args: Optional[Any] = None) -> int:
    """Dispatch. Returns a process exit code: 0 fine, 1 nothing is governing."""
    sub = getattr(args, "vaibot_subcommand", None) or "status"
    try:
        if sub == "guard":
            result = launch.ensure_guard()
            print("\n".join(_guard_lines(result)))
            return 0 if result.running or result.status in ("external", "disabled") else 1
        if sub == "status":
            print(commands.status_text())
            return 0
        print(f"Unknown command {sub!r}. Try: {', '.join(SUBCOMMANDS)}")
        return 2
    except Exception as exc:  # a readout must never be the thing that fails
        logger.warning("vaibot: `hermes vaibot %s` failed: %s", sub, exc)
        print(f"VAIBot: couldn't run {sub!r} just now ({exc}).")
        return 1


def register(ctx: Any) -> None:
    """Attach ``hermes vaibot``, if this Hermes exposes CLI commands."""
    register_cli_command = getattr(ctx, "register_cli_command", None)
    if not callable(register_cli_command):
        logger.info("vaibot: this Hermes has no CLI-command API — `hermes vaibot` not registered")
        return
    try:
        register_cli_command(
            "vaibot",
            "VAIBot governance status, and the local guard",
            setup,
            handle,
        )
    except Exception as exc:
        logger.warning("vaibot: could not register `hermes vaibot`: %s", exc)
