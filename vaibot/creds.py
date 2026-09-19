"""Credential + endpoint resolution.

A Python port of ``@vaibot/guard``'s ``scripts/lib/creds.mjs``. It reads the SAME
``~/.vaibot/credentials.json`` every Node circuit breaker reads (store version 3,
environment-namespaced), so one machine has one VAIBot identity across all five
plugins rather than a per-runtime account.

Two behaviours are ported deliberately and should not be "improved":

* **Precedence** — ``VAIBOT_ENV`` → ``VAIBOT_API_URL`` → ``VAIBOT_API_KEY`` prefix
  → stored active key prefix → stored ``active_env`` → default. Diverging here
  would let the Hermes plugin talk to a different environment than the guard it
  shares a machine with.
* **The lenient prefix guard** — a key whose prefix is *recognised* must match the
  resolved environment, but an *unrecognised* prefix is allowed through rather
  than rejected. A false denial here locks a user out of their own governance,
  which is worse than the mismatch it would be guarding against.

This module performs no I/O beyond reading the credentials file, and never
writes: provisioning stays with the CLI and the Node bootstrap path.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

STORE_VERSION = 3
ENVS = ("production", "staging")
DEFAULT_ENV = "production"

# V2 governance bases per environment.
API_BASE: Dict[str, str] = {
    "production": "https://api.vaibot.io",
    "staging": "https://staging-api.vaibot.io",
}

# Server-enforced key prefixes (apps/api): vb_live_* on prod, vb_stg_* on staging.
KEY_PREFIX: Dict[str, str] = {
    "production": "vb_live_",
    "staging": "vb_stg_",
}


def is_env(value: Any) -> bool:
    return value in ENVS


def env_for_key(api_key: Optional[str]) -> Optional[str]:
    """Environment named by a key's prefix, or None when unrecognised."""
    if not api_key or not isinstance(api_key, str):
        return None
    for env_name, prefix in KEY_PREFIX.items():
        if api_key.startswith(prefix):
            return env_name
    return None


def key_prefix_matches_env(api_key: Optional[str], env_name: str) -> bool:
    """Lenient guard: unrecognised prefixes pass, recognised ones must match."""
    found = env_for_key(api_key)
    return True if found is None else found == env_name


def env_for_api_url(url: Optional[str]) -> Optional[str]:
    if not url or not isinstance(url, str):
        return None
    lowered = url.lower()
    if "staging" in lowered:
        return "staging"
    if "api.vaibot.io" in lowered:
        return "production"
    return None


def creds_dir(env: Optional[Mapping[str, str]] = None) -> Path:
    e = os.environ if env is None else env
    override = e.get("VAIBOT_CREDS_DIR")
    return Path(override) if override else Path.home() / ".vaibot"


def creds_path(env: Optional[Mapping[str, str]] = None) -> Path:
    return creds_dir(env) / "credentials.json"


def load_store(env: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """Read the credential store. A missing or corrupt file yields an empty store
    rather than raising — a broken store must degrade to "no key", never crash
    the agent this plugin is running inside."""
    try:
        raw = json.loads(creds_path(env).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"version": STORE_VERSION, "active_env": DEFAULT_ENV, "environments": {}}
    if not isinstance(raw, dict):
        return {"version": STORE_VERSION, "active_env": DEFAULT_ENV, "environments": {}}
    envs = raw.get("environments")
    return {
        "version": raw.get("version", STORE_VERSION),
        "active_env": raw.get("active_env") if is_env(raw.get("active_env")) else DEFAULT_ENV,
        "environments": envs if isinstance(envs, dict) else {},
    }


def resolve_env(
    env: Optional[Mapping[str, str]] = None,
    store: Optional[Dict[str, Any]] = None,
) -> str:
    e = os.environ if env is None else env

    if is_env(e.get("VAIBOT_ENV")):
        return str(e["VAIBOT_ENV"])

    from_url = env_for_api_url(e.get("VAIBOT_API_URL"))
    if from_url:
        return from_url

    from_env_key = env_for_key(e.get("VAIBOT_API_KEY"))
    if from_env_key:
        return from_env_key

    s = load_store(e) if store is None else store
    active = s.get("active_env")
    slot = s.get("environments", {}).get(active) or {}
    from_store_key = env_for_key(slot.get("api_key"))
    if from_store_key:
        return from_store_key
    if is_env(active):
        return str(active)

    return DEFAULT_ENV


def api_base_for_env(env_name: str, override: Optional[str] = None) -> str:
    if override:
        return override.rstrip("/")
    return API_BASE.get(env_name, API_BASE[DEFAULT_ENV])


@dataclass(frozen=True)
class ResolvedCredentials:
    env: str
    api_base_url: str
    api_key: Optional[str]
    #: True when a candidate key's prefix names a *different* environment. The key
    #: is withheld in that case; callers should warn and re-bootstrap rather than
    #: silently talking to the wrong control plane.
    key_mismatch: bool


def resolve_credentials(env: Optional[Mapping[str, str]] = None) -> ResolvedCredentials:
    e = os.environ if env is None else env
    store = load_store(e)
    env_name = resolve_env(e, store)

    # Stored slot url overrides the canonical base, matching governanceBaseForEnv.
    slot = store.get("environments", {}).get(env_name) or {}
    slot_url = slot.get("governance_url") if isinstance(slot, dict) else None
    api_base_url = api_base_for_env(
        env_name, e.get("VAIBOT_GOVERNANCE_URL") or slot_url or e.get("VAIBOT_API_URL")
    )

    candidate = e.get("VAIBOT_API_KEY") or (slot.get("api_key") if isinstance(slot, dict) else None)
    key_mismatch = bool(candidate) and not key_prefix_matches_env(candidate, env_name)

    return ResolvedCredentials(
        env=env_name,
        api_base_url=api_base_url,
        api_key=None if key_mismatch else (candidate or None),
        key_mismatch=key_mismatch,
    )
