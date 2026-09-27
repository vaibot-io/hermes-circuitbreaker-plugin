"""Would Hermes approve a VAIBot escalation before anyone saw the prompt?

This is the one place the plugin reads Hermes' internals, and the whole
bypass-posture story rests on it: the guard applies the account's
``hostBypassAction`` to whatever this reports, and every degraded rung refuses an
escalation while it says True. Reading it wrong in the safe direction costs a
prompt; reading it wrong in the other direction is an ungoverned action.

Hermes' approval module is faked here rather than imported, so the fake is the
contract: ``_YOLO_MODE_FROZEN``, ``is_current_session_yolo_enabled()``,
``_is_interactive_cli()``, ``_is_gateway_approval_context()``,
``env_var_enabled()`` and ``_get_cron_approval_mode()``. If a Hermes release
renames one of those, this plugin falls into "assume a bypass", which is the
posture the last test pins.
"""

import logging
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vaibot import hostbypass  # noqa: E402

logging.getLogger("vaibot").addHandler(logging.NullHandler())

_MISSING = object()

#: A quiet Hermes: an interactive session, no yolo, no cron.
QUIET = dict(
    _YOLO_MODE_FROZEN=False,
    is_current_session_yolo_enabled=lambda: False,
    _is_interactive_cli=lambda: True,
    _is_gateway_approval_context=lambda: False,
    env_var_enabled=lambda name: False,
    _get_cron_approval_mode=lambda: "deny",
)


class HostBypassCase(unittest.TestCase):
    def setUp(self):
        hostbypass._warned = False
        self.addCleanup(setattr, hostbypass, "_warned", False)

    def install(self, **attrs):
        """Put a fake ``tools.approval`` where the plugin looks for Hermes'."""
        approval = types.ModuleType("tools.approval")
        for name, value in {**QUIET, **attrs}.items():
            setattr(approval, name, value)
        tools = types.ModuleType("tools")
        tools.approval = approval
        for name, module in (("tools", tools), ("tools.approval", approval)):
            previous = sys.modules.get(name, _MISSING)
            sys.modules[name] = module
            self.addCleanup(self._restore, name, previous)
        return approval

    def _restore(self, name, previous):
        if previous is _MISSING:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous


class TestOutsideHermes(HostBypassCase):
    def test_nothing_can_auto_grant_when_there_is_no_hermes(self):
        # Tests, a bare import, `hermes vaibot` before a session: no gate exists,
        # so nothing is granting anything.
        previous = sys.modules.get("tools", _MISSING)
        sys.modules["tools"] = None  # makes `from tools import ...` raise
        self.addCleanup(self._restore, "tools", previous)
        self.assertFalse(hostbypass.approval_autogranted())


class TestAQuietHost(HostBypassCase):
    def test_an_interactive_session_asks_a_human(self):
        self.install()
        self.assertFalse(hostbypass.approval_autogranted())

    def test_a_cron_session_that_denies_is_not_a_bypass(self):
        # approvals.cron_mode: deny — the escalation is refused, not granted, so
        # the human decision was not skipped.
        self.install(
            _is_interactive_cli=lambda: False,
            env_var_enabled=lambda name: name == "HERMES_CRON_SESSION",
            _get_cron_approval_mode=lambda: "deny",
        )
        self.assertFalse(hostbypass.approval_autogranted())

    def test_a_non_interactive_session_that_is_not_cron_is_not_a_bypass(self):
        self.install(_is_interactive_cli=lambda: False, _is_gateway_approval_context=lambda: False)
        self.assertFalse(hostbypass.approval_autogranted())


class TestEveryWayHermesGrantsItself(HostBypassCase):
    def test_process_wide_yolo(self):
        # --yolo / HERMES_YOLO_MODE, frozen at import.
        self.install(_YOLO_MODE_FROZEN=True)
        self.assertTrue(hostbypass.approval_autogranted())

    def test_the_gateways_per_session_yolo_toggle(self):
        self.install(is_current_session_yolo_enabled=lambda: True)
        self.assertTrue(hostbypass.approval_autogranted())

    def test_a_cron_session_that_approves(self):
        self.install(
            _is_interactive_cli=lambda: False,
            _is_gateway_approval_context=lambda: False,
            env_var_enabled=lambda name: name == "HERMES_CRON_SESSION",
            _get_cron_approval_mode=lambda: "approve",
        )
        self.assertTrue(hostbypass.approval_autogranted())

    def test_a_cron_mode_nobody_recognises_still_counts_as_granting(self):
        # The gate auto-approves unless cron_mode is exactly "deny", so anything
        # else — including a new value — has to read as a bypass here.
        self.install(
            _is_interactive_cli=lambda: False,
            env_var_enabled=lambda name: name == "HERMES_CRON_SESSION",
            _get_cron_approval_mode=lambda: "whatever-comes-next",
        )
        self.assertTrue(hostbypass.approval_autogranted())

    def test_an_interactive_cron_session_still_asks(self):
        # A person is there, so the gate prompts rather than auto-approving.
        self.install(
            _is_interactive_cli=lambda: True,
            env_var_enabled=lambda name: name == "HERMES_CRON_SESSION",
            _get_cron_approval_mode=lambda: "approve",
        )
        self.assertFalse(hostbypass.approval_autogranted())

    def test_a_gateway_session_is_asked_not_auto_granted(self):
        self.install(
            _is_interactive_cli=lambda: False,
            _is_gateway_approval_context=lambda: True,
            env_var_enabled=lambda name: name == "HERMES_CRON_SESSION",
            _get_cron_approval_mode=lambda: "approve",
        )
        self.assertFalse(hostbypass.approval_autogranted())


class TestUnreadableInternals(HostBypassCase):
    """The direction this has to fail in: a prompt, never an ungoverned action."""

    def test_an_internal_that_raises_is_read_as_a_bypass(self):
        def explode():
            raise AttributeError("Hermes renamed this")

        self.install(is_current_session_yolo_enabled=explode)
        with self.assertLogs("vaibot", level="WARNING") as logs:
            self.assertTrue(hostbypass.approval_autogranted())
        self.assertTrue(any("auto-granted" in m for m in logs.output))

    def test_a_missing_internal_is_read_as_a_bypass(self):
        approval = self.install()
        del approval.is_current_session_yolo_enabled
        with self.assertLogs("vaibot", level="WARNING"):
            self.assertTrue(hostbypass.approval_autogranted())

    def test_it_complains_once_not_once_per_tool_call(self):
        def explode():
            raise AttributeError("Hermes renamed this")

        self.install(is_current_session_yolo_enabled=explode)
        with self.assertLogs("vaibot", level="WARNING") as logs:
            for _ in range(5):
                self.assertTrue(hostbypass.approval_autogranted())
        self.assertEqual(len(logs.output), 1)


if __name__ == "__main__":
    unittest.main()
