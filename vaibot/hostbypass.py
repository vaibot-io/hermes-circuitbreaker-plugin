"""Would Hermes grant an ``approve`` directive without asking anyone?

Hermes' approval gate short-circuits to "approved" in two situations, before any
human sees the prompt:

* yolo — ``--yolo`` / ``HERMES_YOLO_MODE`` (process-wide, frozen at import) or
  the gateway's ``/yolo`` toggle (per session);
* a cron session with ``approvals.cron_mode: approve``, when no interactive user
  or gateway is present.

(``approvals.mode: off`` does NOT reach the plugin gate — only Hermes' own
dangerous-command check honours it — so it isn't counted here.)

A VAIBot escalation is a demand for a human decision; an auto-grant would
silently satisfy it. The decided posture is that the floor never honours a host
bypass and, above it, the default is to refuse one — so the engine turns an
escalation into a block while this returns True. Making that configurable per
policy is S3.

These are Hermes internals, read defensively. If they can't be read inside a
Hermes process, the answer is True: failing to detect a bypass must cost a
prompt, never an ungoverned action.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("vaibot")

_warned = False


def approval_autogranted() -> bool:
    global _warned
    try:
        from tools import approval as gate  # Hermes' own module
    except Exception:
        # Not running inside Hermes (tests, a bare import): nothing can auto-grant.
        return False

    try:
        if bool(getattr(gate, "_YOLO_MODE_FROZEN")) or bool(gate.is_current_session_yolo_enabled()):
            return True
        # Mirrors _run_approval_gate: with neither an interactive CLI nor a
        # gateway, a cron session auto-approves unless cron_mode is "deny".
        if not gate._is_interactive_cli() and not gate._is_gateway_approval_context():
            if gate.env_var_enabled("HERMES_CRON_SESSION") and gate._get_cron_approval_mode() != "deny":
                return True
        return False
    except Exception as exc:
        if not _warned:
            _warned = True
            logger.warning(
                "vaibot: can't read Hermes' approval state (%s); treating approvals as "
                "auto-granted, so VAIBot escalations will block instead of prompting",
                exc,
            )
        return True
