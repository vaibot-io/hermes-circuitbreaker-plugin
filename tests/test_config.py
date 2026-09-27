"""Settings: where they come from, and which source wins.

The rule under test is in ``vaibot.config``: the environment beats the plugin
config, **except** for the two settings that can only loosen governance — ``mode``
and ``fail_open`` — where the stricter source wins instead, so a posture pinned in
the config cannot be undone by a variable in the environment the agent itself runs
in. Everything else is plain precedence.

Two properties matter as much as the precedence itself:

* with no plugin config in play, every setting behaves exactly as it did when
  environment variables were the only source;
* a host whose ``get_config`` is missing, or raises, is "no opinion" — never an
  error. A governance decision must not fail because a settings lookup did.
"""

import logging
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vaibot import config, localcli  # noqa: E402
from vaibot.breaker import BreakerConfig  # noqa: E402
from vaibot.engine import Settings  # noqa: E402

logging.getLogger("vaibot").addHandler(logging.NullHandler())

PLUGIN_YAML = Path(__file__).resolve().parents[1] / "vaibot" / "plugin.yaml"


class ConfigCase(unittest.TestCase):
    """Installs a fake ``ctx.get_config`` and always removes it again.

    The provider is process-wide, exactly as it is once Hermes has loaded the
    plugin, so leaving one behind would leak into every other test.
    """

    def setUp(self):
        config.clear_provider()
        config._warned.clear()
        self.addCleanup(config.clear_provider)
        self.addCleanup(config._warned.clear)

    def with_config(self, values=None, raises=False):
        def get_config(key, default=None):
            if raises:
                raise RuntimeError("config backend is down")
            return (values or {}).get(key, default)

        config.set_provider(get_config)


class TestPrecedence(ConfigCase):
    def test_env_only_behaves_as_it_always_has(self):
        settings = Settings.from_env({"VAIBOT_TIMEOUT_MS": "2500", "VAIBOT_WORKSPACE": "/w"})
        self.assertEqual((settings.mode, settings.fail_open), ("enforce", False))
        self.assertEqual((settings.timeout_s, settings.workspace_dir), (2.5, "/w"))

    def test_config_applies_when_the_environment_is_silent(self):
        self.with_config({"timeout_ms": 2000, "workspace": "/from-config"})
        settings = Settings.from_env({})
        self.assertEqual(settings.timeout_s, 2.0)
        self.assertEqual(settings.workspace_dir, "/from-config")

    def test_the_environment_wins(self):
        self.with_config({"timeout_ms": 2000, "workspace": "/from-config"})
        settings = Settings.from_env({"VAIBOT_TIMEOUT_MS": "7000", "VAIBOT_WORKSPACE": "/from-env"})
        self.assertEqual(settings.timeout_s, 7.0)
        self.assertEqual(settings.workspace_dir, "/from-env")

    def test_an_empty_variable_is_not_an_opinion(self):
        # An exported-but-empty variable is how a shell says "unset", so it must
        # not shadow a configured value with the built-in default.
        self.with_config({"timeout_ms": 2000})
        self.assertEqual(Settings.from_env({"VAIBOT_TIMEOUT_MS": ""}).timeout_s, 2.0)

    def test_breaker_knobs_come_from_either_source(self):
        self.with_config({"breaker_failure_threshold": 9, "breaker_denylist": ["terminal", "patch"]})
        cfg = BreakerConfig.from_env({})
        self.assertEqual(cfg.failure_threshold, 9)
        self.assertEqual(cfg.denylist, ("terminal", "patch"))
        # And the variable still wins over the config.
        cfg = BreakerConfig.from_env({"VAIBOT_BREAKER_FAILURE_THRESHOLD": "2"})
        self.assertEqual(cfg.failure_threshold, 2)

    def test_the_guard_cli_can_be_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "vaibot-guard"
            fake.write_text("#!/bin/sh\n", encoding="utf-8")
            self.with_config({"guard_cli": str(fake)})
            self.assertEqual(localcli.guard_cli({"PATH": ""}), [str(fake)])


class TestLooseningNeedsBothSources(ConfigCase):
    """``mode`` and ``fail_open`` change whether you are asked. Stricter wins."""

    def test_a_pinned_enforce_cannot_be_loosened_from_the_environment(self):
        self.with_config({"mode": "enforce"})
        with self.assertLogs("vaibot", level="WARNING") as logs:
            settings = Settings.from_env({"VAIBOT_MODE": "observe"})
        self.assertEqual(settings.mode, "enforce")
        self.assertTrue(any("never loosened" in m for m in logs.output))

    def test_a_pinned_no_fail_open_cannot_be_loosened_from_the_environment(self):
        self.with_config({"fail_open": False})
        with self.assertLogs("vaibot", level="WARNING"):
            self.assertFalse(Settings.from_env({"VAIBOT_FAIL_OPEN": "true"}).fail_open)

    def test_the_environment_may_still_tighten_a_loose_config(self):
        self.with_config({"mode": "observe", "fail_open": True})
        settings = Settings.from_env({"VAIBOT_MODE": "enforce", "VAIBOT_FAIL_OPEN": "false"})
        self.assertEqual((settings.mode, settings.fail_open), ("enforce", False))

    def test_either_source_alone_still_loosens(self):
        # The point of keeping this usable: one source with an opinion and no
        # contradiction works exactly as it always did.
        self.with_config({"mode": "observe", "fail_open": True})
        settings = Settings.from_env({})
        self.assertEqual((settings.mode, settings.fail_open), ("observe", True))

        config.clear_provider()
        settings = Settings.from_env({"VAIBOT_MODE": "observe", "VAIBOT_FAIL_OPEN": "true"})
        self.assertEqual((settings.mode, settings.fail_open), ("observe", True))

    def test_a_typo_reads_as_enforce_and_beats_a_configured_observe(self):
        # VAIBOT_MODE has always meant "observe, or else enforce". A misspelling
        # must not silently stop enforcing, and it is still an opinion.
        self.with_config({"mode": "observe"})
        self.assertEqual(Settings.from_env({"VAIBOT_MODE": "observer"}).mode, "enforce")

    def test_warns_once_not_once_per_call(self):
        self.with_config({"mode": "enforce"})
        with self.assertLogs("vaibot", level="WARNING") as logs:
            for _ in range(5):
                Settings.from_env({"VAIBOT_MODE": "observe"})
        self.assertEqual(len(logs.output), 1)


class TestHostFailures(ConfigCase):
    def test_a_missing_get_config_is_env_only(self):
        class Ctx:
            pass

        self.assertFalse(config.from_ctx(Ctx()))
        self.assertIsNone(config.get("mode"))

    def test_a_raising_get_config_is_no_opinion(self):
        self.with_config(raises=True)
        with self.assertLogs("vaibot", level="WARNING") as logs:
            settings = Settings.from_env({"VAIBOT_TIMEOUT_MS": "3000"})
        self.assertEqual(settings.timeout_s, 3.0)
        self.assertEqual(settings.mode, "enforce")
        self.assertTrue(any("could not read plugin config" in m for m in logs.output))

    def test_from_ctx_installs_a_present_get_config(self):
        class Ctx:
            def get_config(self, key, default=None):
                return "observe" if key == "mode" else default

        self.assertTrue(config.from_ctx(Ctx()))
        self.assertEqual(config.get("mode"), "observe")


class TestNormalisation(ConfigCase):
    def test_yaml_scalars_render_the_way_the_variable_is_written(self):
        self.assertEqual(config.normalise(True), "true")
        self.assertEqual(config.normalise(False), "false")
        self.assertEqual(config.normalise(10000), "10000")
        self.assertEqual(config.normalise(2.5), "2.5")
        self.assertEqual(config.normalise(["a", " b ", ""]), "a,b")

    def test_values_with_no_sensible_rendering_are_dropped(self):
        # Stringifying a dict would hand the parser downstream a setting nobody
        # wrote; "" and None are simply no opinion.
        for value in ({"a": 1}, object(), None, "", []):
            self.assertIsNone(config.normalise(value), value)


class TestSealedSettings(ConfigCase):
    def test_credentials_and_endpoints_have_no_config_key(self):
        for name in config.SEALED_ENV:
            self.assertNotIn(name, config.ENV_TO_KEY, name)

    def test_an_undeclared_key_is_never_even_asked_about(self):
        # The other half of sealing: `get` answers only for keys in the schema, so
        # a future caller cannot smuggle a setting past it by naming one.
        asked = []

        def get_config(key, default=None):
            asked.append(key)
            return "yes"

        config.set_provider(get_config)
        self.assertIsNone(config.get("api_key"))
        self.assertIsNone(config.get("VAIBOT_API_KEY"))
        self.assertEqual(asked, [], "the host is not consulted about an undeclared key")
        self.assertEqual(config.get("mode"), "yes")

    def test_a_provider_cannot_introduce_one(self):
        # One machine has one VAIBot identity, and the production URL-override
        # gate lives in `creds`. A plugin setting must not be a second way round
        # either, even if the host happily answers for the key.
        config.set_provider(lambda key, default=None: "https://evil.example")
        layered = config.layered({})
        for name in config.SEALED_ENV:
            self.assertIsNone(layered.get(name), name)


class TestLayeredMapping(ConfigCase):
    def test_unrelated_names_read_straight_through(self):
        self.with_config({"mode": "observe"})
        layered = config.layered({"PATH": "/bin", "HOME": "/h"})
        self.assertEqual(layered["PATH"], "/bin")
        self.assertIsNone(layered.get("NOT_SET"))
        with self.assertRaises(KeyError):
            layered["NOT_SET"]

    def test_it_is_a_real_mapping_including_config_only_names(self):
        self.with_config({"mode": "observe"})
        as_dict = dict(config.layered({"PATH": "/bin"}))
        self.assertEqual(as_dict["PATH"], "/bin")
        self.assertEqual(as_dict["VAIBOT_MODE"], "observe")
        self.assertEqual(len(config.layered({"PATH": "/bin"})), 2)

    def test_it_defaults_to_the_process_environment(self):
        os.environ["VAIBOT_TEST_ONLY_MARKER"] = "1"
        self.addCleanup(os.environ.pop, "VAIBOT_TEST_ONLY_MARKER", None)
        self.assertEqual(config.layered().get("VAIBOT_TEST_ONLY_MARKER"), "1")


class TestAutoLaunchFlag(ConfigCase):
    def test_on_by_default(self):
        self.assertTrue(config.auto_launch_enabled({}))

    def test_switched_off_from_either_source(self):
        for value in ("0", "false", "no", "off", "FALSE"):
            self.assertFalse(config.auto_launch_enabled({"VAIBOT_AUTO_LAUNCH": value}), value)
        self.with_config({"auto_launch": False})
        self.assertFalse(config.auto_launch_enabled({}))

    def test_the_environment_wins(self):
        # Not a loosening setting: a running guard governs more than an absent
        # one, so this is ordinary precedence.
        self.with_config({"auto_launch": False})
        self.assertTrue(config.auto_launch_enabled({"VAIBOT_AUTO_LAUNCH": "true"}))


def declared_schema(text: str) -> dict:
    """``{config key: env var}`` from plugin.yaml's ``config_schema`` block.

    Parsed by hand rather than with PyYAML: the plugin has no dependencies, and
    neither does its test suite. The shape being read is fixed and two levels
    deep, which is why a few lines of matching is honest here.
    """
    keys, current = {}, None
    inside = False
    for line in text.splitlines():
        if re.match(r"^config_schema:\s*$", line):
            inside = True
            continue
        if inside and line and not line.startswith(" ") and not line.startswith("#"):
            break  # a new top-level key ends the block
        if not inside:
            continue
        key = re.match(r"^  (\w+):\s*$", line)
        if key:
            current = key.group(1)
            keys[current] = None
            continue
        env = re.match(r"^    env:\s*(\S+)\s*$", line)
        if env and current:
            keys[current] = env.group(1)
    return keys


class TestSchemaIsDeclaredToHermes(unittest.TestCase):
    """plugin.yaml is what Hermes renders; CONFIG_KEYS is what the code reads."""

    def test_every_key_is_declared_with_the_same_variable(self):
        declared = declared_schema(PLUGIN_YAML.read_text(encoding="utf-8"))
        self.assertEqual(declared, dict(config.CONFIG_KEYS))


if __name__ == "__main__":
    unittest.main()
