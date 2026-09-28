# @vaibot/guard

**VAIBot Guard** — a local policy-decision + enforcement daemon with a tamper-evident audit log. It is the **universal decision authority** that the per-host circuit-breaker plugins (Claude Code, Codex, OpenClaw) route every tool call through, so enforcement is **agent-agnostic**: one guard, many hosts.

## Installation

**The guard is generally installed and managed by the [VAIBot CLI](https://github.com/vaibot-io/command-cli)** — you don't normally install this package by hand. One command installs the `vaibot` CLI (macOS + Linux) and runs `vaibot init`, which installs and starts the guard as part of setup:

```bash
curl -fsSL https://raw.githubusercontent.com/vaibot-io/command-cli/main/install.sh | sh
```

Once the CLI is present you can also drive the guard directly:

```bash
vaibot init            # onboard + install the guard as part of setup
vaibot guard install   # install / manage the guard directly
```

Manual install (what the CLI does for you):

```bash
npm install -g @vaibot/guard
```

That provides two binaries: `vaibot-guard` (operator CLI) and `vaibot-guard-service` (the daemon).

## What it does

A local HTTP service that gates agent tool calls and writes a **tamper-evident audit log** (incremental Merkle accumulator, JSONL) inside the workspace. Decisions are driven by a signed policy bundle; receipts can be anchored to the VAIBot provenance chain.

## Credentials (treat as secrets)
- `VAIBOT_GUARD_TOKEN` — bearer token for guard endpoints (recommended)
- `VAIBOT_API_KEY` — optional: anchor receipts to VAIBot `/prove`

## HTTP API
- `GET  /health`                                             — identity, capabilities, `effective_mode`, `contained`
- `POST /v1/decide/exec`   + `POST /v1/finalize`            — shell exec flows
- `POST /v1/decide/tool`   + `POST /v1/finalize/tool`       — tool-call gating
- `POST /v1/approvals/list` + `POST /v1/approvals/resolve`  — approve / deny
- `POST /v1/flush`         — checkpoint flush
- `POST /api/proof`        — Merkle inclusion proofs

When `VAIBOT_GUARD_TOKEN` is set, protected endpoints require `Authorization: Bearer <token>`.

`/health` also returns `capabilities`, a list of what this daemon's decisions understand, so a client can adapt without comparing versions. Read it from the live daemon, never from a cached copy, which can outlive the process that wrote it.

| Capability | Meaning |
|---|---|
| `host-vocab:<host>` | That host's native tool names are classified directly, so a client may send them as-is instead of remapping to a generic vocabulary. |
| `host-bypass` | Decide accepts `hostBypass` and applies the policy's `hostBypassAction` itself (below). A client should report its host's bypass state rather than enforce its own default. |
| `rule-id` | Escalations and denials carry `decision.ruleId`, the policy rule that fired and its subject. |

## Containment — the account-wide halt

Containment halts **every agent on the account, on every machine**. It is evaluated *before* policy and the classifier, so it holds when policy is stale, unfetchable or fails signature verification — and it holds in **observe mode**, which nothing else does.

Requires guard **2.2.0+** and a control plane serving `/v2/enforcement/*`.

### Engage it

```bash
vaibot contain --reason "laptop looks compromised"
```

Or the **Containment** card on `/dashboard`. Any credential on the account can engage it — session or API key — and it is idempotent, so pulling it twice is not an error. That is deliberate: a false engage costs a stalled agent for a minute, while hesitating in a real incident costs more.

Connected guards pick it up in **about a second**. A guard that is offline picks it up the moment it reconnects.

### Release it

```bash
vaibot release
```

Releasing re-enables every agent, so it is deliberately harder than engaging:

- a **signed-in session** — an API key is refused (`session_required`). An API key is what agent-adjacent code holds, and containment exists to constrain a misbehaving agent, so an agent able to both engage and release would make it pointless.
- **plus a second factor** — an emailed code, or a recovery code.

`vaibot release` walks the emailed step-up for you. It attempts the release first, so "nothing to release" never sends mail.

### Recovery codes — generate these BEFORE you need them

The emailed factor assumes you can reach your mail. When you cannot, every agent stays halted. Recovery codes are the way back:

```bash
curl -sX POST https://api.vaibot.io/v2/enforcement/recovery-codes \
  -H "authorization: Bearer <session token>"
```

Eight codes, shown **once**, stored only as a hash. Redeem one in place of the emailed code:

```bash
curl -sX POST https://api.vaibot.io/v2/enforcement/release \
  -H "authorization: Bearer <session token>" \
  -H 'content-type: application/json' \
  -d '{"recovery_code":"ABCD-EFGH-JKMN"}'
```

Two rules worth knowing:

- **Keep them off the machine.** A copy on a halted machine is no use.
- **They cannot be issued while contained** (`409`). Issuing a code is issuing a release factor, so minting one mid-incident would be a way around containment. Generate a set now, while nothing is wrong.

Case, spacing and dashes are forgiving, and `0/O` and `1/I/L` are interchangeable — these get read off paper on a bad day.

### How the guard learns about it

- **Pushed** over `GET /v2/enforcement/stream` (SSE), so a change lands in about a second rather than at the next poll. Current state arrives on connect, so a reconnect resynchronises by itself.
- A periodic `/v2/accounts/me` poll remains underneath as a reconciliation floor, not the latency path.
- **A dropped stream never releases containment.** Only an explicit value from the control plane moves the flag.
- **It survives a restart.** The engaged state is persisted locally and re-applied before the first decision, so a contained machine does not come back permissive.
- The stream talks to the **canonical** governance base, never an overridable one, so a `VAIBOT_GOVERNANCE_URL` override cannot point a guard at a control plane that simply never reports a change.

### Observing it

- `GET /health` reports `contained`
- `/v1/decide/*` responses carry `contained`
- A containment denial writes a **governance receipt** as well as the local ledger, so an incident is not invisible in the dashboard

### What it does not cover

Containment constrains a misbehaving **agent**, not a compromised **host**. It is an application-level control, so it cannot outrank whoever administers the control plane itself. The practical mitigation is credential hygiene: an agent's environment should not hold operator credentials to the control plane that governs it.

## Offline classification (`vaibot-guard classify`)

A one-shot risk classification with **no daemon, no network and no credentials** — the same classifier the daemon uses, exposed for callers that need the safety floor while the daemon is unreachable.

```bash
echo '{"toolName":"Bash","params":{"command":"…"}}' | vaibot-guard classify
vaibot-guard classify --intent '{"tool":"Write","input":{"file_path":"/etc/hosts"}}'
vaibot-guard classify --escalate-at high --intent '…'   # apply a preset's ask threshold
```

Accepts either the classifier's native `{tool, input}` or the `{toolName, params}` wire shape `/v1/decide/tool` already speaks. Writes the verdict to stdout; callers read **`verdictHint`** (`allow` | `ask` | `deny`).

**Exit 0** means classified. **Any non-zero exit prints no verdict at all** — treat it as a failure to answer and fall back to your own fail-closed posture, never as an allow.

This exists so non-Node hosts (e.g. a Python plugin) reach the *real* floor instead of reimplementing the classifier and drifting from it. "Daemon down" does not imply "node missing", so this still answers on the degraded path.

## Account bootstrap (`vaibot-guard bootstrap`)

Provisions a free-tier account for a machine with no API key and saves it to the shared credential store every breaker on the machine reads. It exists so non-Node hosts don't grow a second writer for that store.

```bash
vaibot-guard bootstrap --agent <host> [--timeout-ms 10000]
```

stdout is one JSON line, and **never contains the key**; the caller re-reads it from the store:

| Output | Meaning |
|---|---|
| `{"ok":true,"env":"…","provisioned":true,"wallet_address":"0x…","wallet_network":"…"}` | New account; key saved |
| `{"ok":true,"env":"…","provisioned":false,"reason":"key-present"}` | A key already resolves; no network call was made |
| `{"ok":true,"env":"…","provisioned":false,"reason":"account-exists"}` | This machine already has an account but the local key is gone; recover with `vaibot login` |

**Any non-zero exit prints nothing on stdout.** Treat it as a failure to answer and fall back to your keyless posture.

Every breaker derives the same machine fingerprint, so a machine keeps one identity whichever breaker provisions it first. Credential resolution applies the production URL-override gate, so an injected `VAIBOT_GOVERNANCE_URL` can't redirect provisioning without `VAIBOT_ALLOW_URL_OVERRIDE`. A key issued for a different environment than the one being provisioned is refused rather than saved.

## Per-host enforcement (circuit-breaker plugins)

The guard makes the decisions; a per-host **circuit-breaker plugin** intercepts tool calls and routes them to the guard, so enforcement happens at the host boundary rather than relying on the model to behave. Wire the plugin for your agent with:

```bash
vaibot plugin add <host>   # claudecode | codex | openclaw
```

Each plugin **ensures the guard is present, installing it only if it's missing** — the CLI is the first-class installer; the plugins are the fallback.

### Approval bypass (`hostBypassAction`)

Every agent host has a switch that turns its own approval prompts off, such as Claude Code's `--dangerously-skip-permissions`. While it's on, a plugin's request for a human decision is granted before any human sees it. The signed policy's `hostBypassAction` decides what happens instead:

| Value | An escalation while the host's bypass is active |
|---|---|
| `deny` (default) | Becomes a `deny` with `decision.bypassBlocked: true`, and no approval record is minted |
| `approve` | Stays an `approve` with `decision.bypassOverride: true`; the host grants it, and the receipt records `approval.status: "bypassed"`, never `"approved"` |

Plugins report the host's state on each decide: `"hostBypass": {"active": true, "mechanism": "<host>:<switch>"}`. Only a literal `true` counts, and the mechanism is a short label for the receipt. Only escalations change: a deny, the catastrophic floor included, and an allow pass through untouched. Loosening to `approve` takes a verified signed bundle; a local policy file can only set `deny`. The resolved value is on `GET /v1/policy` and in each decide response as `host_bypass_action`.

### Rule ids

`decision.ruleId` names the rule and, where it matters, its subject, so a host can scope "approve for this session" to one rule rather than to a whole tool: `file-outside-workspace:~/other/dir`, `network:example.com`, `token-approve:curl`, `classifier:medium-unknown-tool-execute_code`, `floor:…`.

### Receipt fields

Every governance receipt records the bypass posture and never folds it into the decision: `host_bypass_active`, `bypass_override`, and `host_bypass_mechanism` when active. It also carries `policy.rule_id`. A finalize may add how the approval was given (`approvalScope`: `prompt` | `session-grant`; `approvalChoice`: `once` | `session` | `always` | `deny` | `timeout`), which becomes `approval.scope` / `approval.choice`. It may also add the host's own prompt, when one fired on a call the guard allowed (`hostApproval`: `{choice, surface}`), which becomes `host_approval`. Values outside those vocabularies are dropped.

## Manual quick start (foreground, no persistence)

```bash
export VAIBOT_GUARD_HOST=127.0.0.1
export VAIBOT_GUARD_PORT=39111
export VAIBOT_WORKSPACE="$(pwd)"
export VAIBOT_GUARD_TOKEN="<random-token>"

vaibot-guard-service
curl -s http://127.0.0.1:39111/health
```

## systemd user service

```bash
vaibot-guard install-local
```

Installs and starts a user-level service with its own environment file. The unit adds OpenClaw-gateway ordering **only on OpenClaw hosts**; otherwise it runs standalone.

## Policy + schemas

See `references/`: `policy.md`, `policy.default.json`, `receipt-schema.md`, `checkpoint-schema.md`, `inclusion-proofs.md`, `required-mode.md`.

## Threat model

See `THREAT-MODEL.md`.
