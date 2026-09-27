# @vaibot/hermes-circuitbreaker-plugin

VAIBot governance for [Hermes](https://github.com/NousResearch/hermes-agent). Routes every tool call through the local `@vaibot/guard`, blocks or escalates it per policy, and writes signed, tamper-evident receipts.

The fifth circuit breaker, alongside the Claude Code, Codex, OpenClaw and Cursor plugins. They share one guard, one credential store and one signed policy.

## Status — S2 (enforcement + degrade ladder)

| Sprint | Scope | State |
|---|---|---|
| S0 | `vaibot-guard classify` — offline floor for non-Node hosts | ✅ done |
| S1 | Skeleton + provenance: hooks → guard → signed receipts | ✅ done |
| **S2** | **Enforcement: verdict → directive, degrade ladder, breaker, provisioning** | ✅ **this build** |
| S3 | Approval UX: rule-scoped `[a]lways`, configurable bypass posture, `/vaibot` commands, approval observers | 🟡 first two done |
| S4 | Packaging, config schema, guard auto-launch | |
| S5 | Hardening + cross-plugin parity tests | |

Containment arrived outside this plan, with guard 2.2.0: it is honoured here as rung 0 of the ladder below, bringing Hermes to parity with the four published breakers.

## What it does

| Guard verdict | Hermes directive |
|---|---|
| `allow` | `None` — the call proceeds |
| `approve` | `{"action": "approve"}` — Hermes' native `[o]nce / [s]ession / [a]lways / [d]eny` prompt |
| `deny` | `{"action": "block"}` — the reason becomes the tool result the model sees |
| anything else | `block` (fail-closed) |

The guard's published `effective_mode` is authoritative. In **observe**, everything proceeds except the catastrophic floor, which blocks in every mode.

When the guard can't answer, the plugin degrades rather than bricking the agent. The guard's own classifier is the floor on every degraded path:

| Rung | Behaviour |
|---|---|
| **Containment engaged** | The account-wide stop. Checked before every rung below, and it is the one thing that holds in observe and under `VAIBOT_FAIL_OPEN`. Read from machine-wide state with no daemon, no network and no credentials, so it survives exactly the paths that never reach the guard. Governance tools stay exempt, so an operator can still lift it. |
| **No API key** | Provision one via `vaibot-guard bootstrap`. If that can't, govern locally: floor blocks, risky calls prompt, safe work runs. Retries after 5 min (1 h if the account exists and only `vaibot login` can help). |
| **Breaker tripped** | 3 guard failures inside 10 s. Decide locally for 60 s without calling the guard: denylist blocks, classifier-safe passes, the rest blocks. State persists in `~/.vaibot/breaker-state/hermes.json`. |
| **Guard down, fresh install** | No rendezvous lock yet, so non-catastrophic work runs while the daemon comes up. |
| **Guard down, established install** | The lock exists but nothing answers. That looks the same as tampering, so the call is governed locally and flagged loudly. |

### Deliberate departures from the Claude Code plugin

- **The floor holds in every mode on degraded paths.** Claude Code lets a keyless or guard-down call through untouched under observe or `VAIBOT_FAIL_OPEN`; here a classifier `deny` still blocks, as it already does online.
- **An escalation Hermes would grant automatically is refused unless policy says otherwise.** Under `--yolo`, `/yolo`, or `approvals.cron_mode: approve`, Hermes approves plugin escalations before anyone sees a prompt. The plugin reports that posture on each decision and the guard applies the account's `hostBypassAction`: `deny` (the default) blocks and mints no approval, `approve` hands it to Hermes' prompt and records the receipt as `bypassed`, never `approved`. Reporting rather than deciding is deliberate — loosening a bypass takes a verified signed bundle, which a plugin cannot mint. Every degraded rung keeps refusing, because no guard answered there and so no policy authorised anything. If Hermes' approval internals can't be read, the plugin assumes a bypass is active: failing to detect one must cost a prompt, never an ungoverned action.
- **`[a]lways` is scoped to the policy rule that fired**, so one answer covers what the human was asked about ("writes outside the workspace") rather than one exact path — and still can't blanket a tool, since a different rule on the same tool asks again. Against a guard that names no rule it falls back to the exact call (tool + arguments), which under-grants rather than over-grants.

## Install

```bash
# directory install
cp -r vaibot ~/.hermes/plugins/vaibot
hermes plugins enable vaibot

# or via pip entry point
pip install vaibot-hermes-circuitbreaker
hermes plugins enable vaibot
```

Needs a running `@vaibot/guard`, and `vaibot-guard` on `PATH` (or `VAIBOT_GUARD_CLI`) for the degraded paths and first-run provisioning.

| Variable | Default | Meaning |
|---|---|---|
| `VAIBOT_MODE` | `enforce` | Posture when **no** guard answers; the guard's `effective_mode` wins whenever one does |
| `VAIBOT_FAIL_OPEN` | unset | `true` lets guard errors through (the floor still blocks) |
| `VAIBOT_TIMEOUT_MS` | `10000` | Guard decide timeout |
| `VAIBOT_BREAKER_FAILURE_THRESHOLD` / `_WINDOW_MS` / `_COOLDOWN_MS` | `3` / `10000` / `60000` | Breaker tuning |
| `VAIBOT_BREAKER_DENYLIST` | empty | Comma-separated tool names always blocked while tripped |
| `VAIBOT_GUARD_CLI` | `vaibot-guard` on `PATH` | Guard CLI for `classify` / `bootstrap`; a `.mjs` path runs under node |
| `VAIBOT_WORKSPACE` | cwd | Workspace sent with each decision |

## Design notes

**Zero dependencies.** Standard library only. This runs in-process inside your agent on a security path; HTTP is `urllib` and the daemon is loopback. Two things are deliberately *not* reimplemented, because a Python copy would drift from the original: risk classification (`vaibot-guard classify`) and credential writes (`vaibot-guard bootstrap`). One safety floor, one writer for the shared credential store.

**Tool names.** Guards that advertise `host-vocab:hermes` on `/health` understand Hermes' names natively, so receipts say `terminal`. Released guards before that would treat `terminal` as an unknown tool, skipping both the catastrophic floor and the workspace-boundary check. For those, the plugin renames each call to a tool they already understand (`terminal` → `shell`, `write_file` → `write`, …). The rename is safe against every guard, so a capability-detection mistake can only mislabel a receipt, never open the floor. `execute_code` is deliberately never renamed to a shell: Python read as a shell command would pass `cat = open(...)` as `cat`.

**Discovery via the rendezvous lock**, never a hardcoded port. The daemon writes its real host/port/token to `~/.vaibot/guard/guard.json`, and it often doesn't bind the default.

**Shared identity.** Reads the same `~/.vaibot/credentials.json` (v3, env-namespaced) as the Node plugins, with the same resolution precedence, the same *lenient* key-prefix guard, and the same production URL-override gate: `VAIBOT_GOVERNANCE_URL` is ignored for production unless `VAIBOT_ALLOW_URL_OVERRIDE` is set. A cross-language test resolves the same fixtures through the Node original and this port and requires identical answers.

**Receipts close synchronously.** Hermes hooks run in-process, so run state is a dict rather than `/tmp` files claimed by unlinking. And `post_tool_call` fires even for blocked calls, including a declined approval prompt, so every decision closes its own receipt. A declined escalation is finalized with `approval: "denied"`; without it the guard would record the run as approved.

**Fail-closed where it counts.** Hermes runs a call whose hook raised, so an unexpected error while governing blocks the call (unless you chose observe or fail-open). A reachable guard returning an unusable verdict yields `deny`. A 4xx is a real answer, not an outage, so it never trips the breaker. Bookkeeping failures degrade to "no receipt" and never reach tool dispatch.

## Tests

```bash
python3 -m unittest discover -s tests
VAIBOT_GUARD_SRC=/path/to/vaibot-guard python3 -m unittest discover -s tests   # + real-CLI floor tests
```

156 tests, no dependencies. Some are cross-language and run only when node and a guard checkout are available; each skips cleanly otherwise:

- credential resolution against the Node `creds.mjs`
- every rename target against the guard's released classifier
- the floor through the real `classify` CLI (needs a guard that has the subcommand)

## License

MIT
