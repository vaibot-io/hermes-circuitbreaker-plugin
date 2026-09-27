"""Local circuit breaker.

A port of ``@vaibot/guard``'s ``scripts/lib/circuit-breaker.mjs`` (sliding-window
failure counter with cooldown auto-reset), persisted the way the Claude Code
plugin persists it, so trip state survives a Hermes restart.

Semantics, unchanged from the original:

* ``record_failure`` appends now; failures older than ``window_ms`` fall off.
  ``failure_threshold`` failures inside the window trip the breaker.
* ``is_tripped`` auto-resets once ``cooldown_ms`` has passed since the trip.
* ``record_success`` clears everything.
* ``is_denied`` is a static denylist — the one thing no classifier verdict can
  pass while tripped. There is deliberately no allowlist: whether a tool may pass
  a tripped breaker is computed by the classifier on every call, never granted
  and remembered.

Only transport failures count (network, timeout, 5xx). A 4xx is a real answer
from a reachable guard; counting it would trip the breaker on a misconfiguration.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from . import config
from .creds import creds_dir

DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_WINDOW_MS = 10_000
DEFAULT_COOLDOWN_MS = 60_000

STATE_FILE_NAME = "hermes.json"


def _now_ms() -> float:
    return time.time() * 1000.0


def _positive(value: Any, default: float) -> float:
    """Node's ``Number(x) || default`` then ``isFinite(x) && x > 0``."""
    try:
        n = float(value)
    except (TypeError, ValueError):
        return default
    return n if n > 0 and n != float("inf") else default


@dataclass(frozen=True)
class BreakerConfig:
    failure_threshold: float = DEFAULT_FAILURE_THRESHOLD
    window_ms: float = DEFAULT_WINDOW_MS
    cooldown_ms: float = DEFAULT_COOLDOWN_MS
    denylist: Tuple[str, ...] = ()

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "BreakerConfig":
        # Layered so the same four knobs can be set as Hermes plugin config;
        # the environment still wins. See ``config`` for the precedence.
        e = config.layered(env)
        raw_deny = e.get("VAIBOT_BREAKER_DENYLIST") or ""
        return cls(
            failure_threshold=_positive(e.get("VAIBOT_BREAKER_FAILURE_THRESHOLD"), DEFAULT_FAILURE_THRESHOLD),
            window_ms=_positive(e.get("VAIBOT_BREAKER_WINDOW_MS"), DEFAULT_WINDOW_MS),
            cooldown_ms=_positive(e.get("VAIBOT_BREAKER_COOLDOWN_MS"), DEFAULT_COOLDOWN_MS),
            denylist=tuple(s.strip() for s in raw_deny.split(",") if s.strip()),
        )


@dataclass
class CircuitBreaker:
    cfg: BreakerConfig = field(default_factory=BreakerConfig)
    clock: Callable[[], float] = _now_ms
    failures: List[float] = field(default_factory=list)
    tripped_at: Optional[float] = None
    last_error: Optional[str] = None

    def load(self, snapshot: Optional[Mapping[str, Any]]) -> None:
        snap = snapshot if isinstance(snapshot, Mapping) else {}
        failures = snap.get("failures")
        self.failures = [float(t) for t in failures if isinstance(t, (int, float))] if isinstance(failures, list) else []
        tripped = snap.get("trippedAt")
        self.tripped_at = float(tripped) if isinstance(tripped, (int, float)) and not isinstance(tripped, bool) else None
        err = snap.get("lastError")
        self.last_error = err if isinstance(err, str) else None

    def snapshot(self) -> Dict[str, Any]:
        # Same keys as the Node snapshot, so the file reads the same either way.
        return {"failures": list(self.failures), "trippedAt": self.tripped_at, "lastError": self.last_error}

    def record_failure(self, err: Optional[str] = None) -> None:
        now = self.clock()
        self.failures.append(now)
        self.failures = [t for t in self.failures if now - t <= self.cfg.window_ms]
        if isinstance(err, str) and err:
            self.last_error = err
        if len(self.failures) >= self.cfg.failure_threshold:
            self.tripped_at = now

    def record_success(self) -> None:
        self.failures = []
        self.tripped_at = None
        self.last_error = None

    def is_tripped(self) -> bool:
        if self.tripped_at is None:
            return False
        if self.clock() - self.tripped_at > self.cfg.cooldown_ms:
            self.record_success()
            return False
        return True

    def is_denied(self, tool_name: str) -> bool:
        return tool_name in self.cfg.denylist


def state_path(env: Optional[Mapping[str, str]] = None) -> Path:
    return creds_dir(env) / "breaker-state" / STATE_FILE_NAME


class BreakerStore:
    """Load/save the breaker snapshot. Best-effort: state is an optimisation,
    never a correctness dependency, so every I/O failure degrades to "fresh"."""

    def __init__(self, env: Optional[Mapping[str, str]] = None, clock: Callable[[], float] = _now_ms):
        self._env = env
        self._clock = clock
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return state_path(self._env)

    def load(self) -> CircuitBreaker:
        breaker = CircuitBreaker(cfg=BreakerConfig.from_env(self._env), clock=self._clock)
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            breaker.load(raw.get("breaker") if isinstance(raw, dict) else None)
        except (OSError, ValueError):
            pass
        return breaker

    def save(self, breaker: CircuitBreaker) -> None:
        with self._lock:
            try:
                directory = self.path.parent
                directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(directory, 0o700)
                payload = json.dumps(
                    {"version": 1, "breaker": breaker.snapshot(), "updated_at": int(self._clock())}
                ) + "\n"
                # Write-then-rename so a crash can't leave a truncated file.
                fd, tmp = tempfile.mkstemp(prefix=f"{STATE_FILE_NAME}.tmp-", dir=directory)
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as fh:
                        fh.write(payload)
                    os.chmod(tmp, 0o600)
                    os.replace(tmp, self.path)
                except BaseException:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
                    raise
            except OSError:
                pass
