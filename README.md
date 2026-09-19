# @vaibot/hermes-circuitbreaker-plugin

VAIBot governance for [Hermes](https://github.com/NousResearch/hermes-agent). Routes every tool call through the local `@vaibot/guard` and writes signed, tamper-evident receipts.

The fifth circuit breaker, alongside the Claude Code, Codex, OpenClaw and Cursor plugins. They share one guard, one credential store and one signed policy.

## Status — S1 (provenance only)

**This build does not block or escalate anything.** `pre_tool_call` always returns `None`; the sprint exists to prove the receipt path end-to-end against a real Hermes install.

| Sprint | Scope | State |
|---|---|---|
| S0 | `vaibot-guard classify` — offline floor for non-Node hosts | ✅ done |
| **S1** | **Skeleton + provenance: hooks → guard → signed receipts** | ✅ **this build** |
| S2 | Enforcement: verdict → `block`, decision chain, degrade ladder | next |
| S3 | Approval UX: `approve` → native gate, `/vaibot` commands, bypass posture | |
| S4 | Packaging, config schema, guard auto-launch | |
| S5 | Hardening + cross-plugin parity tests | |

## Install

```bash
# directory install
cp -r vaibot ~/.hermes/plugins/vaibot
hermes plugins enable vaibot

# or via pip entry point
pip install vaibot-hermes-circuitbreaker
hermes plugins enable vaibot
```

Requires a running `@vaibot/guard`. Until one exists the plugin records nothing and logs once — it never fails the agent.

## Design notes

**Zero dependencies.** Standard library only. This runs in-process inside your agent on a security path; HTTP is `urllib`, the daemon is loopback, and risk classification is delegated to the guard's own `vaibot-guard classify` rather than reimplemented — one safety floor, not two that drift.

**Discovery via the rendezvous lock**, never a hardcoded port. The daemon writes its real host/port/token to `~/.vaibot/guard/guard.json`; it does not always bind 39111, and assuming the default is a silent way to govern nothing.

**Shared identity.** Reads the same `~/.vaibot/credentials.json` (v3, env-namespaced) as the Node plugins, with the same resolution precedence and the same deliberately *lenient* key-prefix guard — a false denial there would lock you out of your own governance.

**Two structural wins over the subprocess plugins.** Hermes hooks run in-process, so run state is a dict rather than `/tmp` files claimed by unlinking to survive races. And `post_tool_call` fires even for blocked calls, so every decision closes its own receipt synchronously — there is no ask-in-flight orphan class, and therefore no sweep, no `Stop` hook, and no pending-pointer files.

**Fail-closed where it counts.** A reachable guard that returns an unusable verdict yields `deny`, never a silent allow. A 4xx is a real answer, not an outage — conflating them would trip the breaker on a misconfiguration and mask it as a network blip. Bookkeeping failures, by contrast, degrade to "no receipt" and never propagate into tool dispatch.

## Tests

```bash
python3 -m unittest discover -s tests
```

35 tests, no dependencies. They pin the contracts shared with the Node side — credential precedence, the lenient prefix guard, lock parsing, and the fail-closed decision paths — so drift fails here rather than in production.

## License

MIT
