// @vaibot/shared — guard client (Direction A).
//
// Routes a tool-call decision through the local guard's POST /v1/decide/tool so
// codex/claudecode decide via the guard's engine (which also proves/anchors the
// receipt). On guard-unreachable the caller falls back to the local classifier
// breaker — decideViaGuard reports `unreachable` so the caller knows whether to
// count a breaker failure (5xx / network) vs. honour a real verdict (4xx/401).
//
// Plain ESM so the vendored hook copies can use it at runtime.

/**
 * POST a tool call to the guard's /v1/decide/tool.
 * @param {{host:string, port:number, token:string}} guard
 * @param {{sessionId?:string, toolName:string, params?:object, workspaceDir?:string, cwd?:string, approvalId?:string}} request
 * @param {{fetchImpl?:typeof fetch, timeoutMs?:number}} [opts]
 * @returns {Promise<{ok:boolean, unreachable?:boolean, status?:number, error?:unknown,
 *   decision?:'allow'|'deny'|'approve', reason?:string, approvalId?:string|null, floor?:boolean,
 *   effective_mode?:'observe'|'enforce'|null, runId?:string|null, risk?:any, raw?:any}>}
 */
export async function decideViaGuard(guard, request, opts = {}) {
  const { fetchImpl = fetch, timeoutMs = 10000 } = opts
  const url = `http://${guard.host}:${guard.port}/v1/decide/tool`
  const body = {
    sessionId: request.sessionId ?? 'unknown-session',
    toolName: request.toolName,
    params: request.params ?? {},
    workspaceDir: request.workspaceDir ?? request.cwd ?? '',
  }
  if (request.approvalId) body.approval = { approvalId: request.approvalId }

  let res
  try {
    res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${guard.token}` },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (error) {
    return { ok: false, unreachable: true, error }
  }

  if (!res.ok) {
    // 5xx → transient (breaker should count it). 4xx (incl. 401/403) are real
    // verdicts / config problems, NOT transient outages.
    return { ok: false, unreachable: res.status >= 500, status: res.status }
  }

  let data
  try {
    data = await res.json()
  } catch (error) {
    return { ok: false, unreachable: true, error }
  }

  const inner = data && typeof data.decision === 'object' ? data.decision : null
  return {
    ok: true,
    // Fail-closed: a 200 response with no usable decision is the guard reachable
    // but returning garbage — treat it as DENY, never silently allow.
    decision: typeof inner?.decision === 'string' ? inner.decision : 'deny',
    reason: inner?.reason ?? 'malformed guard decision',
    approvalId: inner?.approvalId ?? null,
    floor: inner?.floor === true, // un-overridable catastrophic floor (Tier-0)
    // Guard-published account mode (single source of truth). null when the guard
    // is older / silent → caller falls back to its local VAIBOT_MODE / cfg.mode.
    effective_mode: data?.effective_mode === 'observe' || data?.effective_mode === 'enforce' ? data.effective_mode : null,
    runId: data?.runId ?? null,
    risk: data?.risk ?? null,
    raw: data,
  }
}

/**
 * Map a decideViaGuard result to a hook permission verdict. Returns null when
 * the caller should fall back (guard not reachable / errored).
 * @returns {{permission:'allow'|'deny'|'ask', reason:string, approvalId?:string|null}|null}
 */
export function guardDecisionToVerdict(result) {
  if (!result || !result.ok) return null
  switch (result.decision) {
    case 'allow':
      return { permission: 'allow', reason: result.reason }
    case 'deny':
      return { permission: 'deny', reason: result.reason }
    case 'approve':
      return { permission: 'ask', reason: result.reason, approvalId: result.approvalId }
    default:
      return { permission: 'deny', reason: result.reason || 'unknown guard decision' }
  }
}
