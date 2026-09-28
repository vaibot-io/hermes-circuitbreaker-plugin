// @vaibot/shared — signed policy bundle: schema, sign, verify, load.
//
// In the no-allowlist model the denylist (the un-overridable safety floor) and
// any classifier-ruleset overrides come from a SIGNED, versioned policy bundle —
// never a locally-mutable file. The client verifies an Ed25519 signature over
// the canonical payload against a PINNED issuer public key (shipped in / pinned
// by the client — NEVER read from the bundle itself), plus an expiry.
//
// Fail-closed: a missing / malformed / expired / unverified bundle is NOT
// trusted. The caller falls back to the conservative BUILT-IN classifier
// defaults (which already deny dangerous commands and ask on the unknown) plus
// an empty denylist — it never RELAXES enforcement below that baseline on a bad
// bundle.
//
// computeBundleHash() is a sha256 fingerprint of the canonical payload — a LOCAL
// content label (the bundle's integrity comes from the Ed25519 signature, not
// this hash). It is NOT the on-chain anchor: anchoring uses a keccak256 leaf
// (viem-re-derivable) computed server-side at the prove boundary, separately.
//
// Plain ESM (.mjs) so the guard and the vendored hook copies can use it without
// importing a workspace package at runtime.

import {
  createHash,
  createPublicKey,
  createPrivateKey,
  sign as edSign,
  verify as edVerify,
  generateKeyPairSync,
} from 'node:crypto'
import { readFileSync } from 'node:fs'

export const POLICY_BUNDLE_SCHEMA = 'vaibot/policy-bundle@1'

// Deterministic JSON: recursively sorts object keys so the signed/hashed
// payload is stable regardless of key order. (Mirrors @vaibot/shared
// canonicalJson; inlined here to keep this module dependency-free.)
function canonicalize(value) {
  if (value === null || value === undefined) return value
  if (Array.isArray(value)) return value.map(canonicalize)
  if (typeof value === 'object') {
    const out = {}
    for (const key of Object.keys(value).sort()) out[key] = canonicalize(value[key])
    return out
  }
  return value
}

/** Canonical signable/hashable payload — the bundle minus its `signature`. */
export function canonicalPayload(bundle) {
  const { signature, ...rest } = bundle ?? {}
  return JSON.stringify(canonicalize(rest))
}

/** sha256 of the canonical payload — a local content fingerprint (NOT the
 *  on-chain anchor; that keccak leaf is computed server-side at /api/prove). */
export function computeBundleHash(bundle) {
  return 'sha256:' + createHash('sha256').update(canonicalPayload(bundle)).digest('hex')
}

/** Generate an Ed25519 keypair (PEM). For the signing tool / tests. */
export function generateKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
  return { publicKey, privateKey }
}

/** Sign a bundle (without `signature`); returns the bundle with `signature`. */
export function signBundle(bundleWithoutSig, privateKeyPem) {
  const key = createPrivateKey(privateKeyPem)
  const sig = edSign(null, Buffer.from(canonicalPayload(bundleWithoutSig)), key)
  return { ...bundleWithoutSig, signature: sig.toString('base64') }
}

function fail(reason) {
  return { ok: false, reason, policy: null }
}

/**
 * Verify a bundle against a pinned public key. Fail-closed on every problem.
 * @returns {{ok:boolean, reason:string, policy:object|null}}
 */
export function verifyBundle(bundle, publicKeyPem, opts = {}) {
  const now = typeof opts.now === 'number' ? opts.now : Date.now()
  if (!bundle || typeof bundle !== 'object') return fail('malformed')
  if (bundle.schema !== POLICY_BUNDLE_SCHEMA) return fail('bad-schema')
  if (typeof bundle.signature !== 'string' || bundle.signature === '') return fail('no-signature')
  if (!bundle.policy || typeof bundle.policy !== 'object') return fail('malformed')
  if (!publicKeyPem) return fail('no-public-key')

  const exp = Date.parse(bundle.expiresAt ?? '')
  if (!Number.isFinite(exp)) return fail('malformed')
  if (now > exp) return fail('expired')

  let valid = false
  try {
    const key = createPublicKey(publicKeyPem)
    valid = edVerify(null, Buffer.from(canonicalPayload(bundle)), key, Buffer.from(bundle.signature, 'base64'))
  } catch {
    valid = false
  }
  if (!valid) return fail('bad-signature')

  return { ok: true, reason: 'ok', policy: bundle.policy }
}

/**
 * Read a cached bundle from disk and verify it. Fail-closed: a missing or
 * malformed file returns ok:false (never throws).
 * @param {{path:string, publicKeyPem:string, now?:number}} args
 */
export function loadPolicyBundle(args = {}) {
  const { path, publicKeyPem, now } = args
  let raw
  try {
    raw = readFileSync(path, 'utf-8')
  } catch {
    return { ok: false, reason: 'not-found', policy: null, bundle: null }
  }
  let bundle
  try {
    bundle = JSON.parse(raw)
  } catch {
    return { ok: false, reason: 'malformed', policy: null, bundle: null }
  }
  const res = verifyBundle(bundle, publicKeyPem, { now })
  return { ...res, bundle }
}

/**
 * Resolve the effective policy from a verify/load result. On a verified
 * bundle, returns its denylist + denyTokens + classifier-table overrides. On
 * any failure, returns the safe BUILT-IN baseline (empty denials; the
 * classifier uses its own conservative default tables) — never relaxing
 * enforcement. denyTokens are word-boundary command-family denials (the guard
 * unions them onto its local denyTokens — additive, tighten-only).
 *
 * hostBypassAction governs what happens when an agent host is running with its
 * own approvals switched off (Hermes --yolo, Claude Code
 * --dangerously-skip-permissions, …) and the guard wants a human decision:
 * 'deny' blocks the action, 'approve' honours the bypass and records that it
 * did. Absent — including on any bundle failure — means 'deny'. It never
 * reaches the catastrophic floor, which denies before any approval exists.
 */
export function effectivePolicy(loadResult) {
  if (loadResult && loadResult.ok && loadResult.policy) {
    const p = loadResult.policy
    return {
      source: 'bundle',
      denylist: Array.isArray(p.denylist) ? p.denylist : [],
      denyTokens: Array.isArray(p.denyTokens) ? p.denyTokens : [],
      approveTokens: Array.isArray(p.approveTokens) ? p.approveTokens : [],
      denyPaths: Array.isArray(p.denyPaths) ? p.denyPaths : [],
      fileMutationOutsideWorkspaceAction:
        p.fileMutationOutsideWorkspaceAction === 'deny' || p.fileMutationOutsideWorkspaceAction === 'approve'
          ? p.fileMutationOutsideWorkspaceAction
          : undefined,
      classifierTables: p.classifierTables ?? undefined,
      escalateAt: typeof p.escalateAt === 'string' ? p.escalateAt : undefined,
      hostBypassAction: p.hostBypassAction === 'approve' ? 'approve' : 'deny',
    }
  }
  return {
    source: 'builtin',
    denylist: [],
    denyTokens: [],
    approveTokens: [],
    denyPaths: [],
    fileMutationOutsideWorkspaceAction: undefined,
    classifierTables: undefined,
    hostBypassAction: 'deny',
  }
}
