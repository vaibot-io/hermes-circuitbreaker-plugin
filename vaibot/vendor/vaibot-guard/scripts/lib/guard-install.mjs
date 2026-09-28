// @vaibot/shared — platform-aware guard service install (the `vaibot guard install`
// ladder). Composes serviceTiers() detection + systemdUnit()/launchdPlist() generation:
// walk the root-preferred ladder, write the unit for the best available tier, enable +
// start it, and report which tier won. Best-effort per tier with fallback to 'self'
// (self-spawn — the universal path). fs + exec are injectable so the ladder logic is
// fully unit-testable without a real supervisor; the actual systemctl/launchctl calls
// are exercised on real hardware.

import { mkdirSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, dirname } from 'node:path'
import { promisify } from 'node:util'
import { execFile as _execFile } from 'node:child_process'
import { serviceTiers } from './guard-supervisor.mjs'
import { systemdUnit, launchdPlist } from './guard-units.mjs'

export const GUARD_UNIT = 'vaibot-guard'
export const GUARD_LABEL = 'io.vaibot.guard'

// Where each platform/scope writes its unit file.
export function unitPath(platform, scope, home = homedir()) {
  if (platform === 'linux') {
    return scope === 'system'
      ? `/etc/systemd/system/${GUARD_UNIT}.service`
      : join(home, '.config', 'systemd', 'user', `${GUARD_UNIT}.service`)
  }
  if (platform === 'darwin') {
    return scope === 'system'
      ? `/Library/LaunchDaemons/${GUARD_LABEL}.plist`
      : join(home, 'Library', 'LaunchAgents', `${GUARD_LABEL}.plist`)
  }
  return null // windows / unknown → self-spawn, no unit
}

// The ordered enable/start commands for (platform, scope), as [cmd, args] pairs. System
// scope is sudo-prefixed (non-interactive `-n`, so it fails cleanly if sudo needs a
// password rather than hanging). Pure — returns commands, runs nothing.
export function startCommands(platform, scope, uid) {
  const sudo = scope === 'system'
  const wrap = (cmd, args) => (sudo ? ['sudo', ['-n', cmd, ...args]] : [cmd, args])
  if (platform === 'linux') {
    const scopeFlag = scope === 'system' ? [] : ['--user']
    return [
      wrap('systemctl', [...scopeFlag, 'daemon-reload']),
      wrap('systemctl', [...scopeFlag, 'enable', '--now', GUARD_UNIT]),
    ]
  }
  if (platform === 'darwin') {
    const domain = scope === 'system' ? 'system' : `gui/${uid ?? ''}`
    const plist = unitPath(platform, scope)
    return [
      wrap('launchctl', ['bootstrap', domain, plist]),
      wrap('launchctl', ['kickstart', '-k', `${domain}/${GUARD_LABEL}`]),
    ]
  }
  return []
}

// Best-effort idempotency cleanup run BEFORE the start commands: remove a prior
// registration so `launchctl bootstrap` (and a failed systemd unit) don't error on
// re-install. Failures are ignored — nothing to clean is the normal first-run case.
export function preCleanCommands(platform, scope, uid) {
  const sudo = scope === 'system'
  const wrap = (cmd, args) => (sudo ? ['sudo', ['-n', cmd, ...args]] : [cmd, args])
  if (platform === 'darwin') {
    const domain = scope === 'system' ? 'system' : `gui/${uid ?? ''}`
    return [wrap('launchctl', ['bootout', `${domain}/${GUARD_LABEL}`])]
  }
  if (platform === 'linux') {
    const scopeFlag = scope === 'system' ? [] : ['--user']
    return [wrap('systemctl', [...scopeFlag, 'reset-failed', GUARD_UNIT])]
  }
  return []
}

// Generate + write the unit for one tier, then run its enable/start commands in order.
// Returns { ok, ran:[...], error? }. Injectable { write, mkdir, run } for tests.
export async function installTier(opts, deps = {}) {
  const { platform, scope, execStart, programArgs, envFile, envVars, uid, workingDir, stdout, stderr, home = homedir() } = opts
  const { write = writeFileSync, mkdir = mkdirSync, run } = deps
  const runCmd = run ?? (async (cmd, args) => { await promisify(_execFile)(cmd, args); return true })

  const path = unitPath(platform, scope, home)
  if (!path) return { ok: false, error: `no unit path for ${platform}/${scope}` }
  try {
    mkdir(dirname(path), { recursive: true })
    const content =
      platform === 'linux'
        ? systemdUnit({ execStart, envFile, scope })
        : launchdPlist({ label: GUARD_LABEL, programArgs, envVars, workingDir, stdout, stderr })
    write(path, content, { mode: 0o644 })
  } catch (e) {
    return { ok: false, error: `write unit: ${e?.message ?? e}` }
  }

  // Idempotency: best-effort removal of any prior registration (failures ignored).
  for (const [cmd, args] of preCleanCommands(platform, scope, uid)) {
    try { await runCmd(cmd, args) } catch { /* nothing to clean — expected on first install */ }
  }

  const ran = []
  for (const [cmd, args] of startCommands(platform, scope, uid)) {
    try {
      await runCmd(cmd, args)
      ran.push(`${cmd} ${args.join(' ')}`)
    } catch (e) {
      return { ok: false, ran, error: `${cmd}: ${e?.message ?? e}` }
    }
  }
  return { ok: true, ran }
}

// Walk the root-preferred ladder: install the first tier that succeeds. 'self' means no
// usable supervisor — the caller self-spawns. Returns { tier, ok, selfSpawn?, ran?, error? }.
export async function installGuardService(opts = {}, deps = {}) {
  const tiers = opts.tiers ?? serviceTiers(opts)
  let lastError
  for (const tier of tiers) {
    if (tier === 'self') return { tier: 'self', ok: true, selfSpawn: true }
    const res = await installTier({ ...opts, scope: tier }, deps)
    if (res.ok) return { tier, ...res }
    lastError = res.error
  }
  return { tier: 'self', ok: true, selfSpawn: true, error: lastError }
}
