"""The decision pipeline: guard verdict → Hermes directive, plus the degrade ladder.

Ported from the Claude Code plugin's PreToolUse hook, rung for rung:

1. **No API key** → try to provision one (through the guard CLI). If that can't
   yield a key, govern locally: the classifier's floor denies, risky calls go to
   Hermes' native approval prompt, safe work runs. No receipts until a key exists.
2. **Breaker tripped** (the guard failed N times inside the window) → decide
   locally without calling the guard again: denylist blocks, classifier-safe
   passes, anything else blocks until the cooldown ends.
3. **Guard unreachable** → a fresh install (no rendezvous lock yet) lets
   non-catastrophic work run so the daemon can come up; an established install
   whose guard has vanished is treated as possible tampering and governed
   locally, loudly.
4. **Guard answers** → its ``effective_mode`` is authoritative. Observe allows
   everything except the catastrophic floor; enforce maps allow / approve / deny
   onto None / ``approve`` / ``block``. An unrecognised verdict blocks.

Two deliberate departures from the Claude Code original, both toward safety:

* **The floor holds in every mode on the degraded paths too.** The original lets
  a keyless or guard-down call through untouched under observe or FAIL_OPEN; here
  a classifier ``deny`` still blocks, matching what the online path already does.
* **An escalation Hermes would auto-grant becomes a block** (see hostbypass).

The pipeline never raises for an expected failure; the hook wrapper turns an
unexpected one into a fail-closed block.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional

from . import config
from . import guard as guard_client
from . import localcli
from .breaker import BreakerStore, CircuitBreaker
from .containment import read_containment
from .creds import ResolvedCredentials, creds_path, resolve_credentials
from .hostbypass import approval_autogranted
from .vocab import guard_tool_name

logger = logging.getLogger("vaibot")

#: After a provisioning attempt that couldn't produce a key, how long to govern
#: locally before trying again — so a dead endpoint isn't hit on every call.
BOOTSTRAP_RETRY_S = 300.0
#: The account exists and only `vaibot login` can restore its key; asking the
#: server again soon won't change the answer.
ACCOUNT_EXISTS_RETRY_S = 3600.0


@dataclass(frozen=True)
class Settings:
    #: Posture when no guard answers. The guard's published effective_mode wins
    #: whenever it does answer.
    mode: str
    fail_open: bool
    timeout_s: float
    workspace_dir: str

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Settings":
        """Environment first, then Hermes' plugin config, then the defaults.

        ``mode`` and ``fail_open`` are the two settings that can only loosen
        governance, so the stricter source wins rather than the nearer one; see
        ``config`` for the whole rule. Everything else is plain precedence, which
        is why it can read straight off the layered mapping.
        """
        raw = os.environ if env is None else env
        e = config.layered(env)
        try:
            timeout_ms = float(e.get("VAIBOT_TIMEOUT_MS") or 0)
        except (TypeError, ValueError):
            timeout_ms = 0
        return cls(
            mode=config.resolve_mode(raw.get("VAIBOT_MODE")),
            fail_open=config.resolve_fail_open(raw.get("VAIBOT_FAIL_OPEN")),
            timeout_s=timeout_ms / 1000.0 if timeout_ms > 0 else 10.0,
            workspace_dir=e.get("VAIBOT_WORKSPACE") or os.getcwd(),
        )

    @property
    def lenient(self) -> bool:
        """Observe or FAIL_OPEN: only the floor blocks on a degraded path."""
        return self.mode == "observe" or self.fail_open


@dataclass(frozen=True)
class Outcome:
    #: What pre_tool_call returns: None (proceed) or a block/approve directive.
    directive: Optional[Dict[str, Any]]
    #: Which rung decided — for logs and tests.
    rung: str
    #: The guard run to finalize in post_tool_call, when the guard was consulted.
    run_id: Optional[str] = None
    #: The guard escalated this call for a human decision (enforce mode). The
    #: receipt must then say whether it was granted — see post_tool_call.
    escalated: bool = False


def _allow(rung: str, run_id: Optional[str] = None) -> Outcome:
    return Outcome(None, rung, run_id)


def _block(message: str, rung: str, run_id: Optional[str] = None, escalated: bool = False) -> Outcome:
    return Outcome({"action": "block", "message": message}, rung, run_id, escalated)


def rule_key(tool_name: str, args: Mapping[str, Any], rule_id: Optional[str] = None) -> str:
    """Allowlist grain for Hermes' ``[s]ession`` / ``[a]lways`` answers.

    With a ``rule_id`` — the policy rule the guard says fired — the grain is that
    rule, so answering ``[a]lways`` covers the thing the human was actually asked
    about: "writes outside the workspace", not "this one file". That is both more
    useful and narrower than the alternatives, because it still cannot blanket a
    whole tool: a different rule on the same tool asks again.

    Without one — a guard predating ``rule-id``, or a verdict carrying no rule —
    it falls back to this exact call (tool + arguments). That never over-grants,
    but it does under-grant: the same escalation re-asks on any argument change.
    Falling back is deliberate; inventing a broader key from a guard that did not
    name a rule would widen a grant on a guess.
    """
    if rule_id:
        return f"vaibot:rule:{rule_id}"
    try:
        canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        canonical = repr(sorted(args.items(), key=lambda kv: str(kv[0])))
    digest = hashlib.sha256(f"{tool_name}\n{canonical}".encode("utf-8")).hexdigest()[:16]
    return f"vaibot:{tool_name}:{digest}"


def _jsonable(args: Mapping[str, Any]) -> Dict[str, Any]:
    """Tool args as plain JSON. Hermes args come from model JSON, but a hook
    must not fail closed on an exotic value it could have stringified."""
    try:
        return json.loads(json.dumps(dict(args), default=str))
    except (TypeError, ValueError):
        return {}


def _no_ensure(*_args: Any, **_kwargs: Any) -> None:
    """The default auto-launch dependency: do nothing.

    Starting a machine-wide daemon is not something an ``Engine`` built in a test
    should ever be able to do by omission, so the plugin's own wiring passes the
    real launcher in explicitly (see ``vaibot.register``) and everything else gets
    this. A footgun that defaults to "spawn a guard" would be one bad constructor
    call away from a daemon on a developer's machine.
    """
    return None


def _risk_label(risk: Any) -> str:
    if isinstance(risk, dict):
        return str(risk.get("risk") or "elevated")
    return str(risk) if risk else "elevated"


class Engine:
    """One per plugin load. Dependencies are injectable so each rung is testable
    without a daemon, a node runtime, or a Hermes process."""

    def __init__(
        self,
        env: Optional[Mapping[str, str]] = None,
        *,
        resolve: Callable[..., ResolvedCredentials] = resolve_credentials,
        bootstrap: Callable[..., Optional[localcli.BootstrapResult]] = localcli.bootstrap,
        classify: Callable[..., Optional[localcli.Verdict]] = localcli.classify,
        read_lock: Callable[..., Optional[guard_client.GuardLock]] = guard_client.read_lock,
        lock_path: Callable[..., Any] = guard_client.guard_lock_path,
        probe: Callable[..., Optional[guard_client.Health]] = guard_client.probe,
        decide: Callable[..., Any] = guard_client.decide_tool,
        autogranted: Callable[[], bool] = approval_autogranted,
        breakers: Optional[BreakerStore] = None,
        clock: Callable[[], float] = time.monotonic,
        ensure: Callable[..., Any] = _no_ensure,
    ):
        self._env = env
        self._resolve = resolve
        self._bootstrap = bootstrap
        self._classify_fn = classify
        self._read_lock = read_lock
        self._lock_path = lock_path
        self._probe = probe
        self._decide = decide
        self._autogranted = autogranted
        self._breakers = breakers or BreakerStore(env)
        self._clock = clock
        self._ensure = ensure
        self._bootstrap_lock = threading.Lock()
        self._bootstrap_retry_at = 0.0

    @property
    def env(self) -> Mapping[str, str]:
        return os.environ if self._env is None else self._env

    # ── entry point ─────────────────────────────────────────────────────────

    def decide(self, tool_name: str, args: Mapping[str, Any], session_id: str = "") -> Outcome:
        settings = Settings.from_env(self._env)
        params = _jsonable(args)

        # Rung 0 — containment: the account-wide stop, ahead of every rung below.
        #
        # Each rung underneath can let a call through: no key governs locally,
        # a tripped breaker decides locally, guard-down degrades, and observe or
        # FAIL_OPEN allow outright. Those are precisely the paths containment has
        # to survive, so it cannot sit anywhere but first. It also ignores
        # `settings.lenient` — observe does not lift containment, which is the one
        # place this plugin overrides observe mode's "never block" rule.
        #
        # Governance tools are already exempt before decide() is reached (see
        # _should_skip), so an operator can still look at the account and lift it.
        containment = read_containment()
        if containment.contained:
            why = f" ({containment.reason})" if containment.reason else ""
            return _block(
                f"VAIBot containment engaged{why} — every action on this account is blocked, on "
                "every machine. Lift it from the dashboard or with `vaibot release`.",
                "containment",
            )

        # Rung 1 — no key.
        creds = self._resolve(self._env)
        if not creds.api_key:
            creds = self._try_bootstrap(creds)
            if not creds.api_key:
                return self._local(tool_name, params, settings, self._classify(tool_name, params), "no-key",
                                   note=" No API key yet, so this won't reach your audit chain — run "
                                        "`vaibot login` to restore full governance.")

        # Rung 2 — breaker already tripped: don't call the guard again.
        breaker = self._breakers.load()
        if breaker.is_tripped():
            return self._tripped(breaker, tool_name, params, settings)

        # Rung 3 — is a guard actually answering?
        lock = self._read_lock(self._env)
        health = self._probe(lock) if lock is not None else None
        if health is None:
            # Nothing is answering: ask for a guard to be brought up, on a
            # background thread. This call is still decided by the ladder below —
            # waiting on a cold start would put a daemon boot inside a tool call
            # — but the next one finds a guard instead of the same outage.
            self._ensure(self._env)
            self._record_failure(breaker, "guard unavailable")
            if breaker.is_tripped():
                return self._tripped(breaker, tool_name, params, settings)
            if settings.lenient:
                return self._local(tool_name, params, settings, self._classify(tool_name, params), "guard-down")
            return self._guard_down(tool_name, params, settings, lock)

        # Rung 4 — ask the guard.
        #
        # Report the host's approval-bypass posture when the guard understands it,
        # and let the guard apply the policy's hostBypassAction. Reporting beats
        # enforcing: loosening a bypass to "approve" requires a verified signed
        # bundle, which this plugin cannot mint, so the decision belongs there. A
        # guard without the capability gets no field and keeps the old behaviour,
        # where this plugin refuses an auto-granted escalation itself.
        speaks_bypass = "host-bypass" in health.capabilities
        decision, resp = self._decide(
            lock,
            session_id=session_id or "hermes",
            tool_name=guard_tool_name(tool_name, health.capabilities),
            params=params,
            workspace_dir=settings.workspace_dir,
            host_bypass=(self._autogranted(), "hermes:auto-approve") if speaks_bypass else None,
            timeout_s=settings.timeout_s,
        )
        if decision is None:
            if resp.unreachable:
                self._record_failure(breaker, f"guard {resp.status or 'unreachable'}")
                if breaker.is_tripped():
                    return self._tripped(breaker, tool_name, params, settings)
                if settings.lenient:
                    return self._local(tool_name, params, settings, self._classify(tool_name, params), "guard-down")
                return _block(
                    f"VAIBot: the guard didn't answer ({resp.error or resp.status}) — {tool_name} blocked (fail-closed).",
                    "guard-error",
                )
            # A 4xx is a real answer from a reachable guard, not an outage.
            if settings.lenient:
                return self._local(tool_name, params, settings, self._classify(tool_name, params), "guard-error")
            return _block(
                f"VAIBot: the guard refused the request (HTTP {resp.status}) — {tool_name} blocked (fail-closed).",
                "guard-error",
            )

        # Reset the failure window — but only touch disk when there was something
        # to clear, rather than rewriting the state file on every governed call.
        if breaker.failures or breaker.tripped_at is not None:
            breaker.record_success()
            self._breakers.save(breaker)
        return self._map_verdict(tool_name, params, settings, decision)

    # ── rung 4: the guard answered ──────────────────────────────────────────

    def _map_verdict(self, tool_name: str, params: Dict[str, Any], settings: Settings, decision: Any) -> Outcome:
        run_id = decision.run_id
        verdict = decision.decision
        reason = decision.reason
        # The guard publishes the account's resolved mode; on this path it wins
        # over the local VAIBOT_MODE, which only governs when no guard answers.
        mode = decision.effective_mode or settings.mode

        if mode == "observe":
            if verdict != "allow":
                logger.info("vaibot [observe]: %s would be %s — %s", tool_name, verdict, reason)
            if verdict == "deny" and decision.floor:
                return _block(f"VAIBot blocked (catastrophic floor, enforced even in observe) — {reason}", "observe", run_id)
            return _allow("observe", run_id)

        if verdict == "allow":
            return _allow("guard", run_id)
        if verdict == "approve":
            # Policy said the host may grant this itself (hostBypassAction:
            # approve). Hand it to Hermes' prompt, which its bypass will satisfy
            # without asking. The receipt records `bypassed`, never `approved`, so
            # provenance never claims a human decided — which is why this is safe
            # to honour and why the guard, not this plugin, gets to say so.
            if decision.bypass_override:
                return self._escalate(
                    tool_name, params, reason, _risk_label(decision.risk), "guard", run_id,
                    escalated=True, rule_id=decision.rule_id, allow_autogrant=True,
                )
            return self._escalate(
                tool_name, params, reason, _risk_label(decision.risk), "guard", run_id,
                escalated=True, rule_id=decision.rule_id,
            )
        if verdict == "deny":
            # Policy refused the escalation because the host's approvals are off
            # (hostBypassAction: deny, the default). Say which it was, so the
            # operator knows to turn the bypass off rather than hunting a policy.
            if decision.bypass_blocked:
                return _block(
                    f"VAIBot blocked {tool_name} — {reason}. Hermes is set to approve automatically "
                    "(--yolo, /yolo, or approvals.cron_mode: approve), and this account's policy does not "
                    "accept an automatic approval for an escalated action. Turn automatic approval off to "
                    "be asked instead.",
                    "guard", run_id,
                )
            return _block(f"VAIBot blocked {tool_name} — {reason}", "guard", run_id)
        if settings.fail_open:
            return _allow("fail-open", run_id)
        return _block(f"VAIBot: unrecognised guard decision {verdict!r} — {tool_name} blocked (fail-closed).", "guard", run_id)

    # ── escalation ──────────────────────────────────────────────────────────

    def _escalate(
        self,
        tool_name: str,
        params: Dict[str, Any],
        reason: str,
        risk: str,
        rung: str,
        run_id: Optional[str] = None,
        *,
        escalated: bool = False,
        note: str = "",
        rule_id: Optional[str] = None,
        allow_autogrant: bool = False,
    ) -> Outcome:
        # `allow_autogrant` is set only when the guard resolved the account's
        # policy to hostBypassAction: approve for this call. Everywhere else the
        # refusal stands, including every degraded rung — those never reached a
        # guard, so no policy authorised a bypass and assuming one would let a
        # host switch off the part of governance that asks a human.
        if self._autogranted() and not allow_autogrant:
            return _block(
                f"VAIBot: this {tool_name} call needs a human decision ({reason}), but Hermes is set to approve "
                "automatically (--yolo, /yolo, or approvals.cron_mode: approve). VAIBot doesn't accept automatic "
                "approval for actions it escalates, so it was blocked. Turn automatic approval off to be asked instead.",
                rung, run_id, escalated,
            )
        return Outcome(
            {
                "action": "approve",
                "message": f"VAIBot flagged this {tool_name} call as {risk} risk — {reason}.{note}",
                "rule_key": rule_key(tool_name, params, rule_id),
            },
            rung,
            run_id,
            escalated,
        )

    # ── local governance (no key / guard down / lenient degraded) ────────────

    def _classify(self, tool_name: str, params: Dict[str, Any]) -> Optional[localcli.Verdict]:
        return self._classify_fn(tool_name, params, env=self._env)

    def _local(
        self,
        tool_name: str,
        params: Dict[str, Any],
        settings: Settings,
        verdict: Optional[localcli.Verdict],
        rung: str,
        note: str = "",
    ) -> Outcome:
        if verdict is not None and verdict.verdict_hint == "deny":
            return _block(
                f"VAIBot floor — {tool_name} blocked ({verdict.reason}), enforced even while governance is degraded.",
                rung,
            )
        if settings.lenient:
            return _allow(rung)
        if verdict is None:
            # No classifier to consult (no node, or a guard CLI too old to have
            # `classify`). Put a human in the loop rather than guess.
            return self._escalate(tool_name, params, "VAIBot can't classify this call locally", "unknown", rung, note=note)
        if verdict.verdict_hint == "ask":
            return self._escalate(tool_name, params, verdict.reason, verdict.risk, rung, note=note)
        return _allow(rung)

    def _is_cold_start(self) -> bool:
        """No rendezvous lock has ever been written here. An explicit guard URL
        is never a cold start; an unreadable path fails toward closed."""
        if self.env.get("VAIBOT_GUARD_BASE_URL"):
            return False
        try:
            return not self._lock_path(self._env).exists()
        except OSError:
            return False

    def _guard_down(
        self,
        tool_name: str,
        params: Dict[str, Any],
        settings: Settings,
        lock: Optional[guard_client.GuardLock],
    ) -> Outcome:
        verdict = self._classify(tool_name, params)
        cold = self._is_cold_start()

        if cold and verdict is not None and verdict.verdict_hint != "deny":
            logger.warning(
                "vaibot [degraded]: the guard isn't up yet (fresh install) — %s allowed without a receipt; "
                "the catastrophic floor is still enforced. See ~/.vaibot/guard/launch.log if it never comes up.",
                tool_name,
            )
            return _allow("guard-down")

        if not cold:
            # The lock says a guard ran here, and it's gone. A crash or reboot
            # looks the same as tampering, so don't brick the agent — govern
            # locally — but say so loudly. §9: when the account was deliberately
            # in observe, make the fail-closed override visible.
            observe_override = lock is not None and lock.effective_mode == "observe" and settings.mode != "observe"
            logger.warning(
                "vaibot [degraded]: the guard ran here but is now unreachable — governing %s locally "
                "(possible tampering; recorded).%s",
                tool_name,
                " NOTE: this account's posture was 'observe', but with the guard down VAIBot is failing "
                "closed to enforce locally until it recovers." if observe_override else "",
            )
        return self._local(
            tool_name, params, settings, verdict, "guard-down",
            note=" The guard is unreachable, so this won't reach your audit chain until it's back.",
        )

    # ── rung 2: breaker ─────────────────────────────────────────────────────

    def _record_failure(self, breaker: CircuitBreaker, err: str) -> None:
        breaker.record_failure(err)
        self._breakers.save(breaker)

    def _tripped(self, breaker: CircuitBreaker, tool_name: str, params: Dict[str, Any], settings: Settings) -> Outcome:
        self._breakers.save(breaker)
        cfg = breaker.cfg

        if settings.mode == "observe":
            logger.info("vaibot [breaker observe]: tripped — %s re-decided locally, observe allows", tool_name)
            return self._local(tool_name, params, settings, self._classify(tool_name, params), "breaker")

        if breaker.is_denied(tool_name):
            return _block(f"VAIBot circuit breaker tripped — {tool_name} is in the breaker denylist.", "breaker")

        verdict = self._classify(tool_name, params)
        if verdict is not None and verdict.verdict_hint == "allow":
            logger.info("vaibot [breaker]: tripped — classifier pass-through (%s) for %s", verdict.risk, tool_name)
            return _allow("breaker")

        described = (
            f"classified {verdict.risk} ({verdict.reason})" if verdict is not None else "couldn't be classified locally"
        )
        return _block(
            f"VAIBot circuit breaker tripped — the guard failed {int(cfg.failure_threshold)}+ times within "
            f"{round(cfg.window_ms / 1000)}s. {tool_name} {described}, and can't be passed automatically while "
            f"governance is offline, so it's blocked until the cooldown ({round(cfg.cooldown_ms / 1000)}s) ends "
            "or the guard recovers.",
            "breaker",
        )

    # ── rung 1: provisioning ────────────────────────────────────────────────

    def _try_bootstrap(self, creds: ResolvedCredentials) -> ResolvedCredentials:
        now = self._clock()
        if now < self._bootstrap_retry_at:
            return creds
        # One provisioning attempt at a time; a concurrent call governs locally
        # instead of waiting on the network.
        if not self._bootstrap_lock.acquire(blocking=False):
            return creds
        try:
            result = self._bootstrap(env=self._env)
            if result is not None and (result.provisioned or result.reason == "key-present"):
                fresh = self._resolve(self._env)
                if fresh.api_key:
                    if result.provisioned:
                        logger.warning(
                            "vaibot: provisioned a free VAIBot account for this machine; credentials saved to %s",
                            creds_path(self._env),
                        )
                    return fresh
            if result is not None and result.reason == "account-exists":
                logger.warning(
                    "vaibot: this machine already has a VAIBot account, but its key isn't stored locally — "
                    "run `vaibot login` to restore it. Governing locally until then (floor enforced)."
                )
                self._bootstrap_retry_at = now + ACCOUNT_EXISTS_RETRY_S
            else:
                logger.warning(
                    "vaibot: no API key, and provisioning didn't answer — governing locally (floor enforced). "
                    "Retrying in %d minutes.",
                    int(BOOTSTRAP_RETRY_S // 60),
                )
                self._bootstrap_retry_at = now + BOOTSTRAP_RETRY_S
            return creds
        finally:
            self._bootstrap_lock.release()
