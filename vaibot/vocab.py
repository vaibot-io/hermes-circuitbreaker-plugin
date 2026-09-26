"""Which tool name to send the guard.

The guard classifies tools by name. Guards that advertise ``host-vocab:hermes``
on ``/health`` understand Hermes' own names, so those get the native name and
receipts say ``terminal``, not ``shell``. Every released guard before that knows
only the Claude Code / Codex vocabulary, and would treat ``terminal`` as an
unknown tool: no catastrophic floor, no workspace-boundary check. For those,
the call is renamed to a tool the guard already understands, with the same
argument shape.

Why this second copy of the vocabulary can't drift: it only ever targets
**released** guards, whose tables are frozen. A guard new enough to change its
tables also advertises the capability and never sees this map. Delete it once
the plugin's minimum supported guard advertises ``host-vocab:hermes``.

When unsure, rename. Renaming is safe against every guard, old or new; only
receipt labels depend on getting the capability right, never the floor.
"""

from __future__ import annotations

from typing import Iterable, Mapping

NATIVE_VOCAB_CAPABILITY = "host-vocab:hermes"

#: Hermes name → the name a pre-capability guard classifies the same way.
#: Argument shapes already line up: ``command`` for exec, ``path`` for files.
#: ``execute_code`` is deliberately absent — Python is not a shell command, and
#: an unknown tool escalates to approval, which is the safe reading.
LEGACY_NAMES: Mapping[str, str] = {
    "terminal": "shell",
    "write_file": "write",
    "patch": "edit",
    "read_file": "read",
    "search_files": "grep",
    "web_extract": "web_fetch",
}


def guard_tool_name(tool_name: str, capabilities: Iterable[str] = ()) -> str:
    """The name to put in a decide request for this guard."""
    if NATIVE_VOCAB_CAPABILITY in set(capabilities or ()):
        return tool_name
    return LEGACY_NAMES.get(tool_name, tool_name)


def classifier_tool_name(tool_name: str) -> str:
    """The name for an offline ``classify`` call.

    Always renamed: there is no live daemon to ask what the CLI understands, and
    the renamed form classifies correctly on every guard.
    """
    return LEGACY_NAMES.get(tool_name, tool_name)
