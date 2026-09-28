# VAIBot Guard — Threat Model (no-allowlist governance)

_Last updated: 2026-09-26. Scope: the universal `@vaibot/guard` daemon and the
no-allowlist decision engine it hosts for the per-host circuit-breaker plugins._

## 1. Model in one paragraph

There is **no allowlist**. "Safe" is *computed* on every call from the intrinsic
properties of the action — never granted once and remembered — so there is no
mutable, poisonable grant store to attack. Enforcement is the composition of
four layers, each of which can only *add* denials:

1. a **signed denylist** (the un-overridable safety floor) carried in an
   Ed25519-signed, versioned policy bundle;
2. a **stateless risk classifier** with a hard-coded destructive floor
   (`rm -rf /`, `curl|sh`, fork bombs, `mkfs`, …) that is **not** table-driven;
3. **ephemeral session approvals** — in-memory, session-scoped, never persisted;
4. **fail-closed verification** — a missing / malformed / expired / unsigned
   bundle falls back to the conservative built-in defaults, never below them.

The only **durable** policy is the server-signed bundle. Everything else
(approvals, classifier verdicts) is recomputed per call or per session.

## 2. Assets

| Asset | Why it matters |
|---|---|
| Integrity of the deny decision | A bypass executes attacker-chosen actions on the developer's machine. |
| Provenance / audit chain | Tier-1 Merkle ledger + tier-2 signed receipts are the verifiable record; a downgrade weakens accountability. |
| The bundle **signing key** (server-held) | Compromise lets an attacker mint policy. Out of scope for the client; mitigated by expiry, anchoring, and revocation. |
| Developer secrets / workspace | The actions the guard gates touch real files, networks, and credentials. |

## 3. Trust boundaries

```
 [ AI agent ]            untrusted — may be prompt-injected
     │  hook (thin client, holds guard token)
     ▼
 [ @vaibot/guard daemon ]   trusted; binds 127.0.0.1 only; token auth; state owner-only
     │  POST /api/prove, receipts
     ▼
 [ V2 governance API ]      trusted server; holds the signing key
     │
     ▼
 [ Base chain ]             public anchor of Merkle roots + bundle hashes
```

The agent is **untrusted**. The hook is a thin client that forwards tool calls;
it cannot make policy. The daemon is the trust anchor on the local machine. The
issuer public key is **pinned by the client**, never read from the bundle.

## 4. Adversaries, attacks, and controls

| # | Adversary / attack | Control |
|---|---|---|
| A1 | Prompt-injected agent tries to **self-grant** a denied action | Deny is un-overridable: the redemption path re-evaluates current policy; a valid approval may only upgrade an *ask* to *allow*, never resurrect a *deny*. Approvals are param-bound (`paramsHash`) and session-bound. |
| A2 | Agent tries to **mutate the signed policy** at runtime | No policy-write endpoint exists; the bundle is signature-verified and loaded once at startup. |
| A3 | **Hostile-but-signed bundle** relaxes a dangerous verb to "safe" | The destructive floor is hard-coded in the classifier (not table-driven). Bundle `classifierTables` that move a protected verb (`curl`, `rm`, `ssh`, …) into `safeCmds` are rejected wholesale → built-in defaults (fail-closed), so network egress keeps earning a receipt. |
| A4 | **Tampered / missing / expired** bundle | Fail-closed verification: any verification failure falls back to the safe built-in baseline (empty denylist + conservative classifier), never relaxing enforcement. |
| A5 | **Offline abuse** — mint a durable grant while the API is unreachable | Approvals are ephemeral and in-memory; the only durable policy is the signed bundle, which can't be created locally. Offline activity mints no durable grant and doesn't weaken policy across a restart. |
| A6 | **Replay** an approval into a later session | Approvals live in memory scoped to the daemon lifetime and are never written to disk; a restart drops them. Redemption is bound to `sessionId` and `paramsHash`. |
| A7 | **Symlink / path traversal** to escape the workspace boundary | Path boundaries resolve via `realpath()`; mutation outside the workspace or into denied paths is denied outright, not merely flagged high-risk. |
| A8 | **Foreign daemon** squats the guard port | Identity-validated `/health` (version + instanceId); token auth; localhost-only bind. |

Each control above carries regression coverage in the guard's test suite.

## 5. Residual risks & known gaps

- **Coverage is shell-first.** Governance is strongest on shell/exec and file
  tools. Not every non-shell tool surface on every host is interceptable, so
  hook-based governance is strong rather than universal — stated here rather
  than implied.
- **Provenance tier.** The tier-1 Merkle ledger and tier-2 signed receipts are
  in force today. On-chain anchoring of the bundle hash with per-action coverage
  is a further tier and is still being verified; until then, treat provenance as
  tier-1/tier-2.
- **Operator-in-the-loop.** An agent holding the guard token can mint and
  resolve its own approval, but cannot escalate it onto a denied action (A1).
  Genuine human approval (dashboard / `vaibot approve` CLI) is the operator's
  responsibility: the guard guarantees the *deny floor*, not that a human, and
  not the agent, clicked approve.
- **Signing-key compromise** is out of scope for the client. Mitigations are
  bundle expiry, on-chain anchoring of the bundle hash, and revocation.
- **Revocation channel integrity.** The guard refreshes the active bundle from
  `GET /v2/policy` on a timer, and applies a bundle only if it verifies against
  the pinned key, so a forged *bundle* cannot be installed. An authoritative
  "no active policy" response carries no signature of its own, so the
  revocation channel's integrity rests on TLS to the control plane. The blast
  radius is bounded: the hard-coded destructive floor still applies, so the
  effect is limited to user-added denials and can never relax the safety net. A
  signed revocation list is a future hardening.
- **Operator friction is a real cost.** Because decisions are content-aware, an
  operator working under enforce can be stopped on legitimate work whose
  *content* merely refers to a protected term — editing policy, or writing
  security documentation. This is a usability defect in the control, not a
  safety one, and narrowing the matcher is active work.

## 6. Invariants (must always hold)

1. No input — with or without an approval — yields `allow` for a denylisted tool
   or a destructive-pattern command.
2. A signed bundle can only **add** denials or **raise** receipt tiers; it can
   never relax the built-in destructive floor or downgrade a protected verb.
3. Approvals never touch disk and never survive the session.
4. A verification failure never relaxes enforcement below the built-in baseline.

## 7. What a hook-based deployment can and cannot promise

The guard daemon runs as the **same OS user** as the agent's tool execution, and
enforcement is an in-process decision about an action described to it. That makes
it **tamper-evident, not tamper-proof**. An adversary already operating with the
user's own privileges is inside the same trust domain as the control, and no
same-privilege mechanism is a hard boundary against it. This is a property of
where the control sits, not a defect to be patched.

What follows, stated plainly:

- Casual and accidental disablement is blocked and recorded.
- The destructive floor keeps applying on degraded paths, including with no
  daemon, no network and no credentials.
- Loss of governance is **visible**: guard-down and denials alert, so
  tamper-evidence is an active signal rather than a silent gap.
- Preventing a **determined same-user adversary** from disabling governance is
  **out of scope** for a hook-only deployment.

That last boundary is addressed by moving the control out of the agent's trust
domain — a host or network chokepoint the agent cannot unregister, or a
privilege-separated daemon — which is the direction of the product. Treat the
hook plus daemon as tamper-evident telemetry and best-effort prevention of
casual disablement.

### Defensible claims

- ✅ "Governed actions are gated and recorded; casual or accidental disablement
  is blocked and logged."
- ✅ "Tamper-evident audit chain; guard-down and denials alert."
- ❌ "Prevents a compromised agent from switching off governance." Not
  defensible for a hook-only deployment — only with an out-of-band chokepoint
  or a privilege-separated daemon.
