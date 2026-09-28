// Pinned policy-bundle Ed25519 public keys per Vaibot environment.
//
// Goal: end users install the guard / Codex plugin / Claude Code plugin and
// signed-bundle verification just works — no env var to set, no key file to
// drop. Signature checks against /v2/policy pass against a key shipped IN the
// published package.
//
// Selection (in pickPolicyPubkey below):
//   1. process.env.VAIBOT_POLICY_PUBKEY        — explicit override (dev/CI)
//   2. process.env.VAIBOT_ENV                  — 'staging' | 'production'
//   3. process.env.VAIBOT_POLICY_URL host      — inferred env (the CLI pins this
//                                                on the guard), so a staging guard
//                                                resolves staging without VAIBOT_ENV
//   4. default → PINNED_PROD_PUBKEY
//
// Why default-prod: the overwhelming majority of installs target production.
//
// Rotation: when a server key rotates, ship a new client version that pins
// the new pubkey (plus optionally the previous one as a deprecated entry for
// a grace window). Old clients keep verifying old signed bundles until those
// bundles expire (VAIBOT_POLICY_TTL_DAYS on the server, 90d by default).

// ── Staging ─────────────────────────────────────────────────────────────────
// Provisioned 2026-06-08 on Fly app `vaibot-api-still-silence-9697`.
// Private key lives in `VAIBOT_POLICY_SIGNING_KEY` Fly secret + operator
// backup at ~/.vaibot/keys/staging-policy-private.pem.
export const PINNED_STAGING_PUBKEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJR303uV+dldFIk9AbAoK4Qpy4MP2opdQEho2k7px0hs=
-----END PUBLIC KEY-----
`

// ── Production ──────────────────────────────────────────────────────────────
// Provisioned 2026-07-01 on Fly app `vaibot-api-v2`. Fresh Ed25519 keypair
// (NOT the staging key). Private key lives in the `VAIBOT_POLICY_SIGNING_KEY`
// Fly secret + operator backup at ~/.vaibot/keys/prod-policy-private.pem.
export const PINNED_PROD_PUBKEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9+/s5497t4v6KilCl6TfP80qf4KmMNwzswMzi4KUKuc=
-----END PUBLIC KEY-----
`

/**
 * Resolve the policy-bundle public key for the current process.
 *
 * @param {NodeJS.ProcessEnv} env — defaults to process.env; injectable for tests
 * @returns {string} a PEM-encoded SPKI Ed25519 public key, or '' if none pinned
 */
export function pickPolicyPubkey(env = process.env) {
  const override = env.VAIBOT_POLICY_PUBKEY
  if (override) return override

  // An explicit env name wins.
  const envName = (env.VAIBOT_ENV || '').toLowerCase()
  if (envName === 'staging') return PINNED_STAGING_PUBKEY
  if (envName === 'production') return PINNED_PROD_PUBKEY

  // No explicit VAIBOT_ENV — infer from the policy URL the CLI pinned on the
  // guard (VAIBOT_POLICY_URL), so a staging guard still resolves to the staging
  // key. Anything else (including production) → the prod pin.
  if (/\bstaging-api\.vaibot\.io\b/.test(env.VAIBOT_POLICY_URL || '')) return PINNED_STAGING_PUBKEY
  return PINNED_PROD_PUBKEY
}
