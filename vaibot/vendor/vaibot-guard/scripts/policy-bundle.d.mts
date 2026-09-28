// Type declarations for policy-bundle.mjs — signed policy bundle (Ed25519).
// Hand-written to pair with the plain-ESM source.

export const POLICY_BUNDLE_SCHEMA: 'vaibot/policy-bundle@1'

export interface PolicyBody {
  /** Tool names / exact command words always blocked — the un-overridable safety floor. */
  denylist?: string[]
  /** Word-boundary tokens denied anywhere in a command (e.g. "curl" blocks `curl …`). */
  denyTokens?: string[]
  /** Word-boundary tokens that escalate to human approval ("ask") anywhere in a command. */
  approveTokens?: string[]
  /** Paths whose mutation is denied/escalated (unioned onto the guard's local denyPaths). */
  denyPaths?: string[]
  /** Posture for file mutations outside the workspace; only TIGHTENS local ('deny' wins). */
  fileMutationOutsideWorkspaceAction?: 'deny' | 'approve'
  /** Optional overrides for the classifier rule tables. */
  classifierTables?: Record<string, unknown>
  /** Per-preset ask threshold on the risk ladder (safe<low<medium<high<dangerous):
   *  a classified risk >= this escalates to "ask"; DANGEROUS always denies. Absent ⇒
   *  MEDIUM (prior behavior). balanced=high, strict=medium, permissive=dangerous. */
  escalateAt?: 'safe' | 'low' | 'medium' | 'high' | 'dangerous'
  /** When an agent host runs with its own approvals disabled (Hermes --yolo, Claude
   *  Code --dangerously-skip-permissions, …) and the guard wants a human decision:
   *  'deny' blocks it, 'approve' honours the bypass and records the override.
   *  Absent ⇒ 'deny'. Never affects the catastrophic floor. */
  hostBypassAction?: 'deny' | 'approve'
}

export interface PolicyBundle {
  schema: string
  version: string
  issuer: string
  issuedAt: string
  expiresAt: string
  policy: PolicyBody
  signature?: string
}

export interface VerifyResult {
  ok: boolean
  reason: string
  policy: PolicyBody | null
}

export interface LoadResult extends VerifyResult {
  bundle: PolicyBundle | null
}

export interface EffectivePolicy {
  source: 'bundle' | 'builtin'
  denylist: string[]
  denyTokens: string[]
  approveTokens: string[]
  denyPaths: string[]
  fileMutationOutsideWorkspaceAction?: 'deny' | 'approve'
  classifierTables?: Record<string, unknown>
  escalateAt?: string
  /** Always resolved: 'deny' unless a verified bundle says 'approve'. */
  hostBypassAction: 'deny' | 'approve'
}

export function canonicalPayload(bundle: Partial<PolicyBundle>): string
export function computeBundleHash(bundle: Partial<PolicyBundle>): string
export function generateKeyPair(): { publicKey: string; privateKey: string }
export function signBundle(bundleWithoutSig: Omit<PolicyBundle, 'signature'>, privateKeyPem: string): PolicyBundle
export function verifyBundle(bundle: PolicyBundle, publicKeyPem: string, opts?: { now?: number }): VerifyResult
export function loadPolicyBundle(args: { path: string; publicKeyPem: string; now?: number }): LoadResult
export function effectivePolicy(loadResult: VerifyResult | LoadResult | null): EffectivePolicy
