"""Credential + endpoint resolution.

A Python port of ``@vaibot/guard``'s ``scripts/lib/creds.mjs``. It reads the SAME
``~/.vaibot/credentials.json`` every Node circuit breaker reads (store version 3,
environment-namespaced), so one machine has one VAIBot identity across all five
plugins rather than a per-runtime account.

Behaviours ported deliberately, which should not be "improved":

* **Precedence** — ``VAIBOT_ENV`` → ``VAIBOT_API_URL`` → ``VAIBOT_API_KEY`` prefix
  → stored active key prefix → stored ``active_env`` → default. Diverging here
  would let the Hermes plugin talk to a different environment than the guard it
  shares a machine with.
* **The lenient prefix guard** — a key whose prefix is *recognised* must match the
  resolved environment, but an *unrecognised* prefix is allowed through rather
  than rejected. A false denial here locks a user out of their own governance,
  which is worse than the mismatch it would be guarding against.
* **The production URL-override gate (§5)** — ``VAIBOT_GOVERNANCE_URL`` is honoured
  for staging, but for production only when ``VAIBOT_ALLOW_URL_OVERRIDE`` is set.
  Without it an env var alone could send a production key to a host of its
  choosing. ``VAIBOT_API_URL`` only ever infers the environment; it is too
  overloaded to alias as a base.

This module reads; it never writes. Provisioning goes through
``vaibot-guard bootstrap`` so the shared store keeps a single writer.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlparse

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
    if not isinstance(api_key, str):
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
    """Environment named by an API URL's HOST, or None for any other host.

    Matches on the host only: a substring test would let ``staging`` in a path
    or query string (or ``api.vaibot.io`` inside someone else's URL) decide the
    environment.
    """
    if not isinstance(url, str) or not url:
        return None
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return None
    # Node compares URL.host, which keeps a port only when it isn't the
    # scheme's default (https://api.vaibot.io:443 is still api.vaibot.io).
    default_port = {"http": 80, "https": 443}.get(parsed.scheme)
    netloc = f"{host}:{port}" if port and port != default_port else host
    if netloc == "api.vaibot.io":
        return "production"
    if netloc == "staging-api.vaibot.io" or "staging" in netloc:
        return "staging"
    return None


def creds_dir(env: Optional[Mapping[str, str]] = None) -> Path:
    e = os.environ if env is None else env
    override = e.get("VAIBOT_CREDS_DIR")
    return Path(override) if override else Path.home() / ".vaibot"


def creds_path(env: Optional[Mapping[str, str]] = None) -> Path:
    return creds_dir(env) / "credentials.json"


def _empty_store() -> Dict[str, Any]:
    return {"version": STORE_VERSION, "active_env": DEFAULT_ENV, "environments": {}}


def _slim_record(rec: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"api_key": rec["api_key"]}
    wallet = rec.get("wallet_address")
    if isinstance(wallet, str) and wallet:
        out["wallet_address"] = wallet
    for slot in ("governance", "provenance"):
        value = rec.get(slot)
        url = value.get("url") if isinstance(value, dict) else None
        if isinstance(url, str) and url:
            out[slot] = {"url": url}
    return out


def migrate_store(raw: Any) -> Dict[str, Any]:
    """Normalise any parsed JSON into a v3 store, in memory. Never raises.

    Mirrors ``migrateStore``: v2 and v3 both nest under ``environments`` (a v2
    file just has no URL slots), and a v1 flat file ``{api_key, api_url?}`` is
    lifted into the env its URL or key names. Records without a key are dropped.
    """
    if not isinstance(raw, dict):
        return _empty_store()

    envs = raw.get("environments")
    if isinstance(envs, dict):
        out = _empty_store()
        out["active_env"] = raw.get("active_env") if is_env(raw.get("active_env")) else DEFAULT_ENV
        for env_name in ENVS:
            rec = envs.get(env_name)
            if isinstance(rec, dict) and isinstance(rec.get("api_key"), str) and rec["api_key"]:
                out["environments"][env_name] = _slim_record(rec)
        return out

    api_key = raw.get("api_key")
    if isinstance(api_key, str) and api_key:
        env_name = env_for_api_url(raw.get("api_url")) or env_for_key(api_key) or DEFAULT_ENV
        out = _empty_store()
        out["active_env"] = env_name
        out["environments"][env_name] = _slim_record(raw)
        return out

    return _empty_store()


def load_store(env: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """Read + migrate the store in memory. A missing or corrupt file yields an
    empty store rather than raising — a broken store must degrade to "no key",
    never crash the agent this plugin is running inside."""
    try:
        raw = json.loads(creds_path(env).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _empty_store()
    return migrate_store(raw)


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


def url_override_allowed(env: Optional[Mapping[str, str]] = None) -> bool:
    """The deliberate-act flag for redirecting a production base."""
    e = os.environ if env is None else env
    value = str(e.get("VAIBOT_ALLOW_URL_OVERRIDE") or "").strip()
    return value in ("1", "true", "yes", "TRUE")


def gate_url_override(env_name: str, requested: Optional[str], allow: bool) -> Optional[str]:
    """§5: a production override is honoured only with the flag; else ignored."""
    if not requested:
        return None
    if env_name == "production" and not allow:
        return None
    return requested


def governance_base_for_env(
    store: Mapping[str, Any], env_name: str, override: Optional[str] = None
) -> str:
    """V2 governance base: override → stored slot URL → canonical."""
    canonical = API_BASE.get(env_name, API_BASE[DEFAULT_ENV])
    if override:
        return override.rstrip("/")
    slot = (store.get("environments") or {}).get(env_name) or {}
    stored = slot.get("governance", {}).get("url") if isinstance(slot.get("governance"), dict) else None
    if isinstance(stored, str) and stored:
        return stored.rstrip("/")
    return canonical


@dataclass(frozen=True)
class ResolvedCredentials:
    env: str
    api_base_url: str
    api_key: Optional[str]
    #: True when a candidate key's prefix names a *different* environment. The key
    #: is withheld in that case; callers should re-bootstrap rather than silently
    #: talking to the wrong control plane.
    key_mismatch: bool


def resolve_credentials(env: Optional[Mapping[str, str]] = None) -> ResolvedCredentials:
    e = os.environ if env is None else env
    store = load_store(e)
    env_name = resolve_env(e, store)

    override = gate_url_override(env_name, e.get("VAIBOT_GOVERNANCE_URL"), url_override_allowed(e))
    api_base_url = governance_base_for_env(store, env_name, override)

    slot = store.get("environments", {}).get(env_name) or {}
    candidate = e.get("VAIBOT_API_KEY") or slot.get("api_key") or None
    key_mismatch = bool(candidate) and not key_prefix_matches_env(candidate, env_name)

    return ResolvedCredentials(
        env=env_name,
        api_base_url=api_base_url,
        api_key=None if key_mismatch else candidate,
        key_mismatch=key_mismatch,
    )
