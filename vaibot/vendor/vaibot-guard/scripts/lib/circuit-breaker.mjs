// @vaibot/shared — circuit breaker for local fallback.
//
// Sliding-window failure counter with cool-down auto-reset. Lifted from the
// openclaw-circuitbreaker-plugin (packages/openclaw-circuitbreaker-plugin/
// src/plugin.ts) so the codex and claudecode plugins can vendor a verbatim
// copy under scripts/lib/circuit-breaker.mjs without each forking the
// algorithm. Authored as plain ESM (.mjs) on purpose — same constraint as
// creds.mjs: the hook plugins run as standalone node scripts and cannot
// import a workspace package at runtime.
//
// Semantics (defaults match openclaw):
//   - recordFailure() appends Date.now(); the window is sliding so old
//     failures fall off automatically.
//   - When N failures (failureThreshold) accumulate inside windowMs, the
//     breaker trips: trippedAt = now.
//   - isTripped() auto-resets after cooldownMs from trippedAt — first
//     read past the cooldown clears state and returns false.
//   - recordSuccess() clears all state (failures, tripped, last error).
//   - isDenied(toolName) is a static denylist check — the un-overridable
//     safety floor. There is deliberately NO allowlist: whether a tool may
//     pass through a tripped breaker is decided by the risk classifier
//     (@vaibot/shared/classifier), never by a mutable/learned list.
//
// State serialization:
//   snapshot() / load() round-trip { failures, trippedAt, lastError }.
//   The state is JSON-safe (plain arrays + scalars). State is OWNED by
//   the caller — this class is in-memory only; the caller is responsible
//   for persisting the snapshot to disk and reloading on next invocation.

export const DEFAULT_FAILURE_THRESHOLD = 3
export const DEFAULT_WINDOW_MS = 10_000
export const DEFAULT_COOLDOWN_MS = 60_000

/**
 * @typedef {Object} CircuitBreakerConfig
 * @property {number} [failureThreshold] — failures within windowMs that trip the breaker (default 3)
 * @property {number} [windowMs]         — sliding window for failure counting (default 10000 ms)
 * @property {number} [cooldownMs]       — auto-reset window after tripping (default 60000 ms)
 * @property {string[]} [denylist]       — tool names blocked when tripped (the un-overridable safety floor)
 */

/**
 * @typedef {Object} CircuitBreakerSnapshot
 * @property {number[]} failures
 * @property {number|null} trippedAt
 * @property {string|null} lastError
 */

function normalizeConfig(cfg) {
  cfg = cfg ?? {}
  return {
    failureThreshold:
      Number.isFinite(cfg.failureThreshold) && cfg.failureThreshold > 0
        ? Number(cfg.failureThreshold)
        : DEFAULT_FAILURE_THRESHOLD,
    windowMs:
      Number.isFinite(cfg.windowMs) && cfg.windowMs > 0
        ? Number(cfg.windowMs)
        : DEFAULT_WINDOW_MS,
    cooldownMs:
      Number.isFinite(cfg.cooldownMs) && cfg.cooldownMs > 0
        ? Number(cfg.cooldownMs)
        : DEFAULT_COOLDOWN_MS,
    denylist: Array.isArray(cfg.denylist) ? cfg.denylist.slice() : [],
  }
}

export class CircuitBreaker {
  /** @param {CircuitBreakerConfig} [cfg] */
  constructor(cfg) {
    this.cfg = normalizeConfig(cfg)
    this.failures = []
    this.trippedAt = null
    this.lastError = null
  }

  /** @param {Partial<CircuitBreakerSnapshot>} [state] */
  load(state) {
    state = state ?? {}
    this.failures = Array.isArray(state.failures) ? state.failures.slice() : []
    this.trippedAt = typeof state.trippedAt === 'number' ? state.trippedAt : null
    this.lastError = typeof state.lastError === 'string' ? state.lastError : null
  }

  /** @returns {CircuitBreakerSnapshot} */
  snapshot() {
    return {
      failures: this.failures.slice(),
      trippedAt: this.trippedAt,
      lastError: this.lastError,
    }
  }

  /** @param {string} [err] */
  recordFailure(err) {
    const now = Date.now()
    this.failures.push(now)
    this.failures = this.failures.filter((t) => now - t <= this.cfg.windowMs)
    if (typeof err === 'string' && err) this.lastError = err
    if (this.failures.length >= this.cfg.failureThreshold) {
      this.trippedAt = now
    }
  }

  recordSuccess() {
    this.failures = []
    this.trippedAt = null
    this.lastError = null
  }

  isTripped() {
    if (this.trippedAt == null) return false
    const now = Date.now()
    if (now - this.trippedAt > this.cfg.cooldownMs) {
      this.trippedAt = null
      this.failures = []
      this.lastError = null
      return false
    }
    return true
  }

  /**
   * Static denylist check, independent of trip state — the un-overridable
   * safety floor. Whether a non-denied tool may pass through a tripped
   * breaker is decided by the risk classifier, not by this class.
   *
   * @param {string} toolName — true iff in denylist
   */
  isDenied(toolName) {
    return this.cfg.denylist.includes(toolName)
  }
}
