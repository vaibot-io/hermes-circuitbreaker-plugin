// Type declarations for guard-launch.mjs — real launch dep + default wiring
// for ensureGuard. Hand-written to pair with the plain-ESM source.

import type { EnsureGuardOpts, EnsureGuardResult, LaunchResult } from './guard-bootstrap.mjs'

export function tcpProbe(host: string, port: number, opts?: { timeoutMs?: number }): Promise<boolean>

export function makeLauncher(cfg: {
  guardScript: string
  baseEnv?: Record<string, string>
  healthTimeoutMs?: number
  pollMs?: number
}): (host: string, port: number, token: string) => Promise<LaunchResult>

export function ensureGuardDefault(
  opts: EnsureGuardOpts & {
    guardScript: string
    guardEnv?: Record<string, string>
    healthTimeoutMs?: number
    pollMs?: number
  },
): Promise<EnsureGuardResult>
