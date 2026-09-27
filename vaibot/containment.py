"""Account-wide containment, read from the machine-wide record.

A Python port of the half of ``@vaibot/guard``'s ``scripts/lib/guard-bootstrap.mjs``
that reads containment state. The guard writes one record per machine, in the
shared rendezvous directory, and every breaker on the machine reads that same
file — with **no daemon, no network and no credentials**.

That last part is the whole point. Containment has to hold on exactly the paths
where a breaker degrades: no API key, breaker tripped, guard unreachable,
fail-open, observe mode. Those are the paths that never reach the daemon, and a
file is the one thing all of them can still read.

Deliberately NOT honouring ``VAIBOT_CREDS_DIR``: the guard resolves this path
from the home directory alone, so following a creds override here would have the
breaker read a record the guard never writes. Tests redirect ``HOME`` instead,
which is what the guard itself responds to.

Unlike the Node original, the path is resolved per call rather than at import, so
a changed ``HOME`` is picked up. Nothing depends on the import-time behaviour.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union


@dataclass(frozen=True)
class Containment:
    """What the machine-wide record says."""

    #: True ONLY for a literal ``true`` in the record. Anything else is "not engaged".
    contained: bool = False
    #: Why it was engaged, when the control plane sent a reason.
    reason: Optional[str] = None
    #: When it was engaged, ISO-8601, as the guard wrote it.
    at: Optional[str] = None


def guard_dir() -> Path:
    """The shared rendezvous directory the guard owns."""
    return Path.home() / ".vaibot" / "guard"


def containment_file() -> Path:
    return guard_dir() / "containment.json"


def read_containment(file: Optional[Union[str, Path]] = None) -> Containment:
    """Read the record. Absent or unreadable means NOT engaged.

    This runs on every single tool call, so it must never raise: a breaker that
    crashes reading this file is worse than one that cannot read it. It must also
    never fail *into* containment — a corrupt record that read as engaged would
    take an account's agents down with no way to tell why.
    """
    path = Path(file) if file is not None else containment_file()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return Containment()
    if not isinstance(raw, dict):
        return Containment()
    return Containment(
        # Identity against True, not truthiness: 1, "true" and "yes" are not
        # containment. Only the guard's own literal boolean engages it.
        contained=raw.get("contained") is True,
        reason=raw["reason"] if isinstance(raw.get("reason"), str) else None,
        at=raw["at"] if isinstance(raw.get("at"), str) else None,
    )
