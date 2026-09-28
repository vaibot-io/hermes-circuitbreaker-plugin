// Type declarations for circuit-breaker.mjs — sliding-window failure
// counter with cool-down auto-reset. Hand-written to pair with the
// plain-ESM source.

export const DEFAULT_FAILURE_THRESHOLD: 3
export const DEFAULT_WINDOW_MS: 10000
export const DEFAULT_COOLDOWN_MS: 60000

export interface CircuitBreakerConfig {
  /** Failures within `windowMs` that trip the breaker. Default 3. */
  failureThreshold?: number
  /** Sliding window for failure counting, in ms. Default 10000. */
  windowMs?: number
  /** Auto-reset window after tripping, in ms. Default 60000. */
  cooldownMs?: number
  /** Tool names blocked when tripped — the un-overridable safety floor. */
  denylist?: string[]
}

export interface CircuitBreakerSnapshot {
  failures: number[]
  trippedAt: number | null
  lastError: string | null
}

export class CircuitBreaker {
  constructor(cfg?: CircuitBreakerConfig)
  load(state?: Partial<CircuitBreakerSnapshot>): void
  snapshot(): CircuitBreakerSnapshot
  recordFailure(err?: string): void
  recordSuccess(): void
  isTripped(): boolean
  isDenied(toolName: string): boolean
}
