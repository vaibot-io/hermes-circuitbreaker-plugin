"""Test-suite safety net: a test process never starts a guard daemon.

The plugin starts a guard when none is running, which is right in an agent and
wrong in a test run — the daemon is machine-wide, detaches from the process that
spawned it, and outlives the suite. So auto-launch is switched off here for every
path that reads the *real* process environment.

Tests that pass their own environment mapping are unaffected (a layered mapping
consults what it was given, not ``os.environ``), which is how the launch tests
still exercise auto-launch end to end. ``setdefault`` so an operator who really
wants the live behaviour can still ask for it.

This is a second line of defence, not the first: a test that calls
``vaibot.register()`` patches the launcher itself. Both are here because the first
version of this suite did spawn a real daemon on a developer's machine.
"""

import os

os.environ.setdefault("VAIBOT_AUTO_LAUNCH", "0")
