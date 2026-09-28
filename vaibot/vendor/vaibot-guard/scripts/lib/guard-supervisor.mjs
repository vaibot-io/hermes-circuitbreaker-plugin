// @vaibot/shared — platform + service-supervisor detection for the guard's
// adopt → service → self-spawn → degrade chain.
//
// Pure logic; every side-effecting probe (filesystem, PATH lookup, uid, sudo) is
// injected, so this is fully unit-testable without a real OS. The output is the
// ordered *preference* — the caller (ensureGuard wiring / the CLI installer) then
// tries each tier in turn and falls through on failure. 'self' (self-spawn) is the
// universal fallback and always terminates the list.

import { existsSync, readFileSync } from 'node:fs'
import { join, delimiter } from 'node:path'

// Inside a container? Containers rarely have a usable per-user service supervisor,
// so the guard self-spawns there.
export function detectContainer({ env = process.env, exists = existsSync, read = readFileSync } = {}) {
  if (env.container) return true
  try {
    if (exists('/.dockerenv') || exists('/run/.containerenv')) return true
  } catch { /* ignore */ }
  try {
    if (/\b(docker|kubepods|containerd|libpod|podman|lxc)\b/i.test(read('/proc/1/cgroup', 'utf-8'))) return true
  } catch { /* ignore */ }
  return false
}

// A CI runner? Ephemeral, no persistent supervisor — self-spawn per job.
export function detectCI({ env = process.env } = {}) {
  return !!(
    env.CI || env.CONTINUOUS_INTEGRATION || env.GITHUB_ACTIONS || env.GITLAB_CI ||
    env.BUILDKITE || env.CIRCLECI || env.TRAVIS || env.JENKINS_URL || env.TEAMCITY_VERSION
  )
}

// Real PATH lookup: is `name` an executable on PATH? This is the DEFAULT hasCmd
// probe for serviceTiers in production (tests inject a fake). Without it, detection
// defaulted to "command absent" and every platform fell through to self-spawn.
export function commandExists(name, env = process.env) {
  const dirs = String(env.PATH || '').split(delimiter).filter(Boolean)
  const exts = process.platform === 'win32'
    ? String(env.PATHEXT || '.EXE;.CMD;.BAT').split(';').map((e) => e.trim()).filter(Boolean)
    : ['']
  for (const dir of dirs) {
    for (const ext of exts) {
      try {
        if (existsSync(join(dir, name + ext))) return true
      } catch { /* ignore unreadable PATH entries */ }
    }
  }
  return false
}

/**
 * Ordered service-tier preference for the ROOT-PREFERRED ladder. Returns a subset
 * of ['system','user','self'] — always ending in 'self' (the universal fallback),
 * so it is never root-required.
 *
 *   system : root/system-supervised unit — the real tamper boundary (a non-root
 *            agent cannot stop it). Offered only when we're root OR sudo works.
 *   user   : per-user supervised unit (systemd --user / launchd LaunchAgent) —
 *            single-instance + auto-restart, but NOT a tamper boundary (same user).
 *   self   : detached self-spawn — works everywhere (containers/CI/Windows/first run).
 *
 * @param {{platform?, env?, uid?, isContainer?, isCI?, hasCmd?, canSudo?}} opts
 *   hasCmd(name) → boolean : is `name` on PATH? (inject a `command -v` probe)
 *   canSudo               : does non-interactive `sudo -n true` succeed?
 */
export function serviceTiers(opts = {}) {
  const {
    platform = process.platform,
    env = process.env,
    uid = typeof process.getuid === 'function' ? process.getuid() : null,
    isContainer = detectContainer({ env }),
    isCI = detectCI({ env }),
    hasCmd = commandExists,
    canSudo = false,
  } = opts

  // No usable supervisor in containers / CI — self-spawn only.
  if (isContainer || isCI) return ['self']

  const root = uid === 0
  const tiers = []

  if (platform === 'linux' && hasCmd('systemctl')) {
    if (root || canSudo) tiers.push('system')          // system unit = tamper boundary
    if (!root && env.XDG_RUNTIME_DIR) tiers.push('user') // user unit needs a user bus
  } else if (platform === 'darwin' && hasCmd('launchctl')) {
    if (root || canSudo) tiers.push('system')          // LaunchDaemon = tamper boundary
    if (!root) tiers.push('user')                      // LaunchAgent
  }
  // Windows + anything unrecognized: self-spawn for v1.

  tiers.push('self')
  return tiers
}
