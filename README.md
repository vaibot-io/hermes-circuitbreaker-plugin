# VAIBot Governance Plugin for Hermes

VAIBot governance for [Hermes](https://github.com/NousResearch/hermes-agent). Routes every tool call through the local `@vaibot/guard`, blocks or escalates it per policy, and writes signed, tamper-evident receipts.

One of the VAIBot circuit breakers, alongside the Claude Code, Codex, OpenClaw and Cursor plugins. They share one guard, one credential store and one signed policy, so an account's rules apply the same way whichever agent you run.

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

### Approvals, and what still blocks

- **The floor holds in every mode.** On a degraded path a classifier `deny` still blocks, even under observe or `VAIBOT_FAIL_OPEN`. Those settings change whether you are asked, never whether a catastrophic action can run.
- **An escalation Hermes would grant automatically is refused unless policy says otherwise.** Under `--yolo`, `/yolo`, or `approvals.cron_mode: approve`, Hermes approves plugin escalations before anyone sees a prompt. The plugin reports that posture on each decision and the guard applies the account's `hostBypassAction`: `deny` (the default) blocks and mints no approval, `approve` hands it to Hermes' prompt and records the receipt as `bypassed`, never `approved`. Reporting rather than deciding is deliberate — loosening a bypass takes a verified signed bundle, which a plugin cannot mint. Every degraded rung keeps refusing, because no guard answered there and so no policy authorised anything. If Hermes' approval internals can't be read, the plugin assumes a bypass is active: failing to detect one must cost a prompt, never an ungoverned action.
- **`[a]lways` is scoped to the policy rule that fired**, so one answer covers what the human was asked about ("writes outside the workspace") rather than one exact path — and still can't blanket a tool, since a different rule on the same tool asks again. Against a guard that names no rule it falls back to the exact call (tool + arguments), which under-grants rather than over-grants.

## Install

Two ways in, and the same `vaibot/` tree serves both.

```bash
# directory install — no build step
cp -r vaibot ~/.hermes/plugins/vaibot
hermes plugins enable vaibot

# or as a package, from a checkout of this repo
pip install .
hermes plugins enable vaibot
```

Not on PyPI, so install the package from a checkout or a git URL rather than by
name. It has no dependencies, so there is nothing else to fetch.

Wants `vaibot-guard` on `PATH` (or `VAIBOT_GUARD_CLI`) — that is where the
classifier floor, first-run provisioning and the guard's launcher come from. If no
guard is running, one is started for you; see [the local guard](#the-local-guard).

## Settings

Every setting is an environment variable, and every one is also a Hermes plugin
setting — `plugins.entries.vaibot.<key>` in `config.yaml`, declared in the
plugin's own `config_schema`, so `hermes` can show it.

| Setting | Variable | Default | Meaning |
|---|---|---|---|
| `mode` | `VAIBOT_MODE` | `enforce` | Posture when **no** guard answers; the guard's `effective_mode` wins whenever one does |
| `fail_open` | `VAIBOT_FAIL_OPEN` | `false` | `true` lets guard errors through (the floor still blocks) |
| `timeout_ms` | `VAIBOT_TIMEOUT_MS` | `10000` | Guard decide timeout |
| `workspace` | `VAIBOT_WORKSPACE` | cwd | Workspace sent with each decision, and pinned on a guard VAIBot starts |
| `guard_cli` | `VAIBOT_GUARD_CLI` | `vaibot-guard` on `PATH` | Guard CLI for `classify` / `bootstrap`; a `.mjs` path runs under node |
| `auto_launch` | `VAIBOT_AUTO_LAUNCH` | `true` | Start a local guard when none is running |
| `breaker_failure_threshold` | `VAIBOT_BREAKER_FAILURE_THRESHOLD` | `3` | Guard failures inside the window that trip the breaker |
| `breaker_window_ms` | `VAIBOT_BREAKER_WINDOW_MS` | `10000` | Breaker failure window |
| `breaker_cooldown_ms` | `VAIBOT_BREAKER_COOLDOWN_MS` | `60000` | How long the breaker decides locally before handing back |
| `breaker_denylist` | `VAIBOT_BREAKER_DENYLIST` | empty | Tools always blocked while tripped (a list, or a comma-separated variable) |

**Which source wins.** The guard's published `effective_mode` beats everything
local whenever a guard answers. Below that: the variable, then the plugin setting,
then the default. The variable comes first because it is the narrower, more
deliberate scope — one process, one job, one debugging session — and because it is
the only source the other VAIBot breakers have.

**`mode` and `fail_open` are the exception**, and it only ever tightens. They are
the two settings that can *only loosen* governance, so the **stricter** source
wins rather than the nearer one: `enforce` pinned in `config.yaml` is not undone
by `VAIBOT_MODE=observe` in the environment the agent itself runs in. A variable
can still tighten a loose setting, and a variable on its own behaves exactly as it
always has.

**Credentials and endpoints have no plugin setting** — `VAIBOT_API_KEY`,
`VAIBOT_ENV`, `VAIBOT_API_URL`, `VAIBOT_GOVERNANCE_URL`,
`VAIBOT_ALLOW_URL_OVERRIDE`, `VAIBOT_CREDS_DIR`, `VAIBOT_GUARD_BASE_URL` and
`VAIBOT_GUARD_TOKEN` stay where the guard can see them. One machine has one VAIBot
identity, resolved by the shared credential store so every breaker on it agrees; a
per-plugin override would fork that identity, and would be a second way around the
production URL-override gate.

## The local guard

When no guard is running — at load, or when a decision finds none — VAIBot starts
one. When one is already running it is adopted, not duplicated.

A machine has exactly **one** guard, and that invariant belongs to the daemon: the
rendezvous lock it writes at `~/.vaibot/guard/guard.json` and the port it binds,
which acts as a mutex. So the plugin probes before it launches, and the launch
itself is the guard's own launcher rather than a second copy of it — one
implementation of the single-instance rule, one writer of the rendezvous file, the
same way the classifier and the credential writer are the guard's and not this
plugin's.

It never holds up a tool call. The launch runs in the background and the call in
flight is governed by the ladder above; the next call finds a guard. Concurrent
callers produce one attempt, and an attempt that fails backs off rather than
paying a subprocess per tool call.

```
hermes vaibot guard     make sure the guard is up, in the foreground, and say what happened
hermes vaibot status    the readout below, from a terminal
```

`auto_launch: false` (or `VAIBOT_AUTO_LAUNCH=0`) switches it off, and an explicit
`VAIBOT_GUARD_BASE_URL` — someone else's guard — is always left alone.

## `/vaibot`

```
/vaibot status   what is governing this session right now
/vaibot help
```

Registered through Hermes' slash-command API, so it works in a CLI session and through the Telegram and Discord gateways alike — and as `hermes vaibot status` outside a session altogether. It exists for one moment in particular — an agent has just stopped and you need to know why — so containment and breaker state are read from local state and the guard is probed rather than assumed. It answers with no daemon and no network.

```
VAIBot status

  Containment   CONTAINED · laptop looks compromised · 4m ago
  Guard         none found · governing locally from the classifier floor
  Account       no key yet · production · run `vaibot login`
  Breaker       healthy

  Every action on this account is blocked, on every machine.
  Lift it from the dashboard or with `vaibot release`.
```

It never prints a credential: it says whether a key resolves and for which environment, never the key, and never the guard token. The output can land in a Telegram or Discord channel, so it is written to be public. A Hermes without the slash-command API still loads the plugin — governance outranks a readout.

## Design notes

**Zero dependencies.** Standard library only, and the imports are tested, not just declared. This runs in-process inside your agent on a security path; HTTP is `urllib` and the daemon is loopback. Three things are deliberately *not* reimplemented, because a Python copy would drift from the original: risk classification (`vaibot-guard classify`), credential writes (`vaibot-guard bootstrap`) and starting the daemon (the guard's own `ensureGuardDefault`). One safety floor, one writer for the shared credential store, one launcher.

**Tool names.** Guards that advertise `host-vocab:hermes` on `/health` understand Hermes' names natively, so receipts say `terminal`. Released guards before that would treat `terminal` as an unknown tool, skipping both the catastrophic floor and the workspace-boundary check. For those, the plugin renames each call to a tool they already understand (`terminal` → `shell`, `write_file` → `write`, …). The rename is safe against every guard, so a capability-detection mistake can only mislabel a receipt, never open the floor. `execute_code` is deliberately never renamed to a shell: Python read as a shell command would pass `cat = open(...)` as `cat`.

**Discovery via the rendezvous lock**, never a hardcoded port. The daemon writes its real host/port/token to `~/.vaibot/guard/guard.json`, and it often doesn't bind the default.

**Shared identity.** Reads the same `~/.vaibot/credentials.json` (v3, env-namespaced) as the Node plugins, with the same resolution precedence, the same *lenient* key-prefix guard, and the same production URL-override gate: `VAIBOT_GOVERNANCE_URL` is ignored for production unless `VAIBOT_ALLOW_URL_OVERRIDE` is set. A cross-language test resolves the same fixtures through the Node original and this port and requires identical answers.

**Receipts close synchronously.** Hermes hooks run in-process, so run state is a dict rather than `/tmp` files claimed by unlinking. And `post_tool_call` fires even for blocked calls, including a declined approval prompt, so every decision closes its own receipt.

**A receipt never claims a person decided something they were never asked.** A call handed to Hermes' gate that comes back blocked is finalized `approval: "denied"`, `approvalScope: "prompt"` — without it the guard records an escalated run as approved. A call VAIBot refused *itself*, such as declining an auto-granted escalation, returns a `block` directive, so the gate never opens and no prompt fires: that finalizes as a plain policy deny. What still cannot be told apart is *which* of deny, timeout or gate error ended a real prompt — Hermes reports all three as a blocked tool call, and the receipt vocabulary has one state for "not granted", so nothing honest separates them yet.

**Fail-closed where it counts.** Hermes runs a call whose hook raised, so an unexpected error while governing blocks the call (unless you chose observe or fail-open). A reachable guard returning an unusable verdict yields `deny`. A 4xx is a real answer, not an outage, so it never trips the breaker. Bookkeeping failures degrade to "no receipt" and never reach tool dispatch.

## Tests

```bash
python3 -m unittest discover -s tests
VAIBOT_GUARD_SRC=/path/to/vaibot-guard python3 -m unittest discover -s tests   # + real-CLI floor tests
```

No dependencies to install. Some tests are cross-language and run only when node and a guard checkout are available; each skips cleanly otherwise:

- credential resolution against the Node `creds.mjs`
- every rename target against the guard's released classifier
- the floor through the real `classify` CLI (needs a guard that has the subcommand)

## License

MIT
