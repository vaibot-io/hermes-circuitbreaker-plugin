"""Plugin-scoped settings, layered over the environment.

Every setting this plugin has ever had is an environment variable. Hermes also
offers plugin-scoped settings — ``ctx.get_config(key, default)``, backed by
``plugins.entries.vaibot.<key>`` in ``config.yaml`` and declared as
``config_schema`` in ``plugin.yaml`` — which is where an operator would rather
pin a posture than export a variable into every shell that starts an agent.
Both work. This module is the one place that decides which wins.

**Precedence**

1. The guard's published ``effective_mode`` — not part of this ladder at all.
   Whenever a guard answers, the account's resolved posture beats anything local,
   and nothing here changes that.
2. The environment variable, when it is set to a non-empty value.
3. The plugin config value.
4. The built-in default.

Environment first is the ordinary reading: a variable is the narrower, more
deliberate scope — one process, one CI job, one debugging session — while the
config file is the persistent machine-wide preference. It is also what every
other VAIBot breaker does, all of which are environment-only, so a variable must
not become *less* effective here than it is there. Hermes' own ``config_schema``
binds a key to an ``env:`` variable for the same reason.

**One exception, and it only ever tightens.** ``mode`` and ``fail_open`` are the
two settings that can only *loosen* governance: they change whether you are
asked, never whether a catastrophic action can run. For those two, a source that
has an opinion is compared with the other, and the **stricter** one wins —
``enforce`` beats ``observe``, and ``fail_open: false`` beats ``fail_open:
true``. So an operator who pins ``enforce`` in the config cannot have it undone
by a variable in the environment the agent itself runs in, while a variable can
still tighten a loose config, and a variable on its own still works exactly as
before. A source that says nothing has no opinion; an empty value says nothing.

**Deliberately not configurable: credentials and endpoints.** ``VAIBOT_API_KEY``,
``VAIBOT_ENV``, ``VAIBOT_API_URL``, ``VAIBOT_GOVERNANCE_URL``,
``VAIBOT_ALLOW_URL_OVERRIDE``, ``VAIBOT_CREDS_DIR``, ``VAIBOT_GUARD_BASE_URL``
and ``VAIBOT_GUARD_TOKEN`` have no config key. One machine has one VAIBot
identity, resolved by the store's own precedence so every breaker on it agrees;
a per-plugin setting that redirected the environment or the governance base would
fork that identity, and would be a second way around the production URL-override
gate that ``creds`` exists to enforce. Those stay where the guard can see them.

Reads are defensive. ``get_config`` belongs to the host: a Hermes that does not
implement it (the API is documented, but not present in every build) or one whose
implementation raises is treated as "no opinion", never as an error — a
governance decision must not fail because a settings lookup did.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Callable, Dict, Iterator, Mapping, Optional

logger = logging.getLogger("vaibot")

#: Plugin config key → the environment variable that means the same thing.
#: This mapping IS the schema; ``plugin.yaml``'s ``config_schema`` declares the
#: same pairs for Hermes to render, and a test holds the two together.
CONFIG_KEYS: Mapping[str, str] = {
    "mode": "VAIBOT_MODE",
    "fail_open": "VAIBOT_FAIL_OPEN",
    "timeout_ms": "VAIBOT_TIMEOUT_MS",
    "workspace": "VAIBOT_WORKSPACE",
    "guard_cli": "VAIBOT_GUARD_CLI",
    "auto_launch": "VAIBOT_AUTO_LAUNCH",
    "breaker_failure_threshold": "VAIBOT_BREAKER_FAILURE_THRESHOLD",
    "breaker_window_ms": "VAIBOT_BREAKER_WINDOW_MS",
    "breaker_cooldown_ms": "VAIBOT_BREAKER_COOLDOWN_MS",
    "breaker_denylist": "VAIBOT_BREAKER_DENYLIST",
}

ENV_TO_KEY: Mapping[str, str] = {env_name: key for key, env_name in CONFIG_KEYS.items()}

#: Settings that deliberately have no config key — see the module docstring.
SEALED_ENV = (
    "VAIBOT_API_KEY",
    "VAIBOT_ENV",
    "VAIBOT_API_URL",
    "VAIBOT_GOVERNANCE_URL",
    "VAIBOT_ALLOW_URL_OVERRIDE",
    "VAIBOT_CREDS_DIR",
    "VAIBOT_GUARD_BASE_URL",
    "VAIBOT_GUARD_TOKEN",
)

#: The two settings that can only loosen governance, so the stricter source wins.
TIGHTENING_ONLY = ("mode", "fail_open")

_provider: Optional[Callable[..., Any]] = None
_provider_lock = threading.Lock()

#: One warning per refused loosening, not one per tool call.
_warned: set = set()


def set_provider(getter: Optional[Callable[..., Any]]) -> None:
    """Install the host's config reader — ``ctx.get_config``, or a fake in tests."""
    global _provider
    with _provider_lock:
        _provider = getter if callable(getter) else None


def clear_provider() -> None:
    set_provider(None)


def provider() -> Optional[Callable[..., Any]]:
    with _provider_lock:
        return _provider


def from_ctx(ctx: Any) -> bool:
    """Wire up Hermes' plugin config, if this Hermes has it.

    Returns whether a reader was installed. A Hermes without ``get_config`` is
    not an error: the plugin then behaves exactly as it always has, on the
    environment alone.
    """
    getter = getattr(ctx, "get_config", None)
    if not callable(getter):
        logger.info("vaibot: this Hermes has no plugin-config API — settings come from the environment")
        set_provider(None)
        return False
    set_provider(getter)
    return True


def normalise(value: Any) -> Optional[str]:
    """A config value as the string an environment variable would have held.

    Config comes from YAML, so ``fail_open: true`` is a real boolean and
    ``breaker_denylist: [terminal]`` a real list. The parsers downstream are the
    same ones that read the environment, so everything is rendered the way that
    variable would be written. A value with no sensible rendering — a dict, an
    object — is dropped rather than stringified into something that parses as a
    setting nobody wrote. An empty value is "no opinion".
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value or None
    if isinstance(value, (list, tuple)):
        items = [str(v).strip() for v in value if str(v).strip()]
        return ",".join(items) or None
    return None


def get(key: str) -> Optional[str]:
    """This plugin's config value for ``key``, or None when there is no opinion."""
    getter = provider()
    if getter is None or key not in CONFIG_KEYS:
        return None
    try:
        raw = getter(key, None)
    except Exception as exc:  # the host's problem, never a governance failure
        if key not in _warned:
            _warned.add(key)
            logger.warning("vaibot: could not read plugin config %r (%s) — using the environment", key, exc)
        return None
    return normalise(raw)


def refused_loosening(setting: str, wanted: str, kept: str) -> None:
    """Say once that a loosening value lost to a stricter source."""
    token = f"{setting}:{wanted}->{kept}"
    if token in _warned:
        return
    _warned.add(token)
    logger.warning(
        "vaibot: ignoring %s=%r because another source pins the stricter %r — a setting that only "
        "loosens governance can be tightened from either place, never loosened.",
        setting, wanted, kept,
    )


class Layered(Mapping):
    """The environment, with this plugin's config underneath it.

    A full mapping rather than a helper function so the existing ``from_env``
    readers keep taking a mapping and nothing downstream has to learn about
    config. Only the names in :data:`CONFIG_KEYS` are layered; every other name
    (``PATH``, and every sealed credential variable) reads straight through.
    """

    __slots__ = ("_env",)

    def __init__(self, env: Optional[Mapping[str, str]] = None):
        self._env = os.environ if env is None else env

    def __getitem__(self, name: str) -> str:
        raw = self._env.get(name)
        if raw is not None and raw != "":
            return raw
        key = ENV_TO_KEY.get(name)
        if key is not None:
            value = get(key)
            if value is not None:
                return value
        if raw is None:
            raise KeyError(name)
        return raw

    def __iter__(self) -> Iterator[str]:
        seen = set()
        for name in self._env:
            seen.add(name)
            yield name
        for name, key in ENV_TO_KEY.items():
            if name not in seen and get(key) is not None:
                yield name

    def __len__(self) -> int:
        return sum(1 for _ in self.__iter__())

    def as_dict(self) -> Dict[str, str]:
        return {name: self[name] for name in self}


def layered(env: Optional[Mapping[str, str]] = None) -> Mapping[str, str]:
    """``env`` (or the process environment) with the plugin config underneath."""
    return Layered(env)


# ── the two settings where the stricter source wins ─────────────────────────


def _mode_opinion(value: Any) -> Optional[str]:
    """``observe`` | ``enforce`` | None (no opinion).

    Anything set that is not exactly ``observe`` reads as ``enforce``, which is
    how the environment variable has always behaved: a typo must not silently
    stop enforcing. An empty value is not an opinion.
    """
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    if not text:
        return None
    return "observe" if text == "observe" else "enforce"


def resolve_mode(env_value: Any) -> str:
    """Posture for when no guard answers. ``enforce`` unless both sources agree
    otherwise; see the module docstring for why loosening cannot come from the
    environment alone once a config pins it."""
    env_opinion = _mode_opinion(env_value)
    config_opinion = _mode_opinion(get("mode"))
    if env_opinion == "observe" and config_opinion == "enforce":
        refused_loosening("mode", "observe", "enforce")
        return "enforce"
    if env_opinion is not None:
        return env_opinion
    return config_opinion or "enforce"


def _fail_open_opinion(value: Any) -> Optional[bool]:
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    if not text:
        return None
    return text == "true"


def resolve_fail_open(env_value: Any) -> bool:
    env_opinion = _fail_open_opinion(env_value)
    config_opinion = _fail_open_opinion(get("fail_open"))
    if env_opinion is True and config_opinion is False:
        refused_loosening("fail_open", "true", "false")
        return False
    if env_opinion is not None:
        return env_opinion
    return bool(config_opinion)


#: Values that switch a default-on flag off, spelled the ways people spell them.
_OFF = ("0", "false", "no", "off")


def auto_launch_enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    """May this plugin start a guard when none is running? On by default.

    Ordinary precedence: this one cannot loosen governance — a guard that is
    running governs more than one that is absent, so switching it off is the
    restrictive choice and either source may make it.
    """
    value = layered(env).get(CONFIG_KEYS["auto_launch"])
    return str(value).strip().lower() not in _OFF if value is not None else True
