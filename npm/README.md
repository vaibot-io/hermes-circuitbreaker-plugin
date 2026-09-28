# VAIBot circuit breaker for Hermes

Installer for the [VAIBot](https://www.vaibot.io) governance plugin for [Hermes](https://github.com/NousResearch/hermes-agent). Every tool call is routed through the local VAIBot guard, blocked or escalated per your account's policy, and recorded in a signed, tamper-evident receipt.

```bash
npx @vaibot/hermes-circuitbreaker-plugin install
hermes plugins enable vaibot
```

One of the five VAIBot circuit breakers, alongside the Claude Code, Codex, OpenClaw and Cursor plugins. All five share one guard, one credential store and one signed policy, so an account's rules apply the same way whichever agent you run.

## What this package is, and is not

**The plugin itself is Python**, published to PyPI as [`vaibot-hermes-circuitbreaker`](https://pypi.org/project/vaibot-hermes-circuitbreaker/). Most people find VAIBot through npm, so this package exists to make that route work — it is an **installer**, not a copy.

It fetches the published wheel from PyPI, verifies it against a SHA-256 pinned at publish time, and unpacks it where Hermes looks for plugins. A wheel is a zip, so:

- **no `pip`** and no Python needed to install
- **no PEP 668 failure** on distros that mark the system Python externally-managed
- **no virtualenv guessing** about which interpreter Hermes actually runs under
- **PyPI stays the single source of truth** — this package carries the coordinates and the hash, never a second copy of the plugin

If the digest doesn't match, the install **stops**. It is not a warning.

## It does not run on `postinstall`

Deliberately. Installing a governance plugin into an agent's configuration directory is something a person should ask for, so it happens only when you invoke it. That also means it can't silently fail under `npm ci --ignore-scripts`, pnpm's allowlist, or Bun's defaults — you'd notice.

## Usage

```
npx @vaibot/hermes-circuitbreaker-plugin install [options]

  --dir <path>    Install into <path> instead of ~/.hermes/plugins
  --force         Replace an existing install (the old copy is kept as a .bak)
  --dry-run       Fetch and verify, then stop without writing
  -h, --help
```

## Requirements

- **Node 18+** to run this installer
- **Node on PATH** afterwards, because the guard is a Node program
- **Python 3.10+**, which Hermes already needs

Zero dependencies — this package installs a security plugin, so adding a transitive tree to do it would be the wrong trade. The zip reader is about a hundred lines over `node:zlib`.

## The guard ships with the plugin

There is no second component to install. The wheel contains `@vaibot/guard`, so the classifier floor, first-run provisioning and the guard launcher are all present after one command.

If you already have `vaibot-guard` on `PATH`, **that** one is used in preference to the bundled copy — so a machine with the full VAIBot stack keeps a single guard rather than quietly running the one inside a plugin. `VAIBOT_GUARD_CLI` overrides both.

Inside Hermes, `/vaibot status` tells you which one answered:

```
Classifier    from PATH · `classify` answers
Classifier    vendored with this plugin · `classify` answers
Classifier    NOT FOUND · degraded paths cannot reach the floor, so they ask instead
```

## Installing without npm

The npm route is for discovery and convenience. Either of these is equally supported:

```bash
pip install vaibot-hermes-circuitbreaker        # PyPI directly
vaibot plugin add hermes                        # the VAIBot CLI
```

## Links

- [Plugin source and full documentation](https://github.com/vaibot-io/hermes-circuitbreaker-plugin#readme)
- [PyPI package](https://pypi.org/project/vaibot-hermes-circuitbreaker/)
- [vaibot.io](https://www.vaibot.io)

MIT © Campbell Labs LLC
