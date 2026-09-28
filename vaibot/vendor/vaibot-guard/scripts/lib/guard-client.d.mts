// Type declarations for guard-client.mjs — route a tool-call decision through
// the local guard. Hand-written to pair with the plain-ESM source.

export interface GuardTarget {
  host: string
  port: number
  token: string
}

export interface DecideRequest {
  sessionId?: string
  toolName: string
  params?: Record<string, unknown>
  workspaceDir?: string
  cwd?: string
  approvalId?: string
}

export interface DecideResult {
  ok: boolean
  unreachable?: boolean
  status?: number
  error?: unknown
  decision?: 'allow' | 'deny' | 'approve'
  reason?: string
  approvalId?: string | null
  runId?: string | null
  risk?: unknown
  raw?: unknown
}

export interface GuardVerdict {
  permission: 'allow' | 'deny' | 'ask'
  reason: string
  approvalId?: string | null
}

export function decideViaGuard(
  guard: GuardTarget,
  request: DecideRequest,
  opts?: { fetchImpl?: typeof fetch; timeoutMs?: number },
): Promise<DecideResult>

export function guardDecisionToVerdict(result: DecideResult | null): GuardVerdict | null
