// @vaibot/shared — credential store + environment resolver.
//
// Single source of truth for: which environment a surface is operating in,
// where its credentials live on disk, and how to read/write them without one
// environment clobbering the other. See the bifurcation plan
// (credential-environment-bifurcation-plan-2026-05-22).
//
// Authored as plain ESM (.mjs) on purpose: the Claude Code and Codex hook
// plugins run as standalone node scripts and cannot import a workspace package
// at runtime, so they vendor a *verbatim copy* of this file at
// scripts/lib/creds.mjs, guarded by a parity test. TypeScript consumers
// (@vaibot/cli, the OpenClaw plugin) import it via the bundled creds.d.mts.
//
// Store schema (v3), ~/.vaibot/credentials.json:
//   {
//     "version": 3,
//     "active_env": "production",
//     "environments": {
//       "production": {
//         "api_key": "vb_live_…", "wallet_address": "0x…",
//         "governance": { "url": null },   // V2; null ⇒ canonical default
//         "provenance": { "url": null }    // V1; null ⇒ canonical default
//       },
//       "staging": { "api_key": "vb_stg_…", "wallet_address": "0x…" }
//     }
//   }
// api_key + wallet_address persist; governance/provenance URLs persist only when an
// explicit override is stored — otherwise each resolves to its canonical per-env
// default. V1 provenance and V2 governance bases are tracked SEPARATELY so a staging
// key can never anchor to a prod provenance endpoint. A v2 file (no slots) reads
// transparently and upgrades on next write. See docs/credentials-v2-split.md.

import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

export const STORE_VERSION = 3
export const ENVS = /** @type {const} */ (['production', 'staging'])
export const DEFAULT_ENV = 'production'

// V2 governance bases per env.
const API_BASE = {
  production: 'https://api.vaibot.io',
  staging: 'https://staging-api.vaibot.io',
}

// V1 provenance bases per env. The V1 proxy routes under /api, so the base
// INCLUDES /api; callers append /prove.
const PROVENANCE_BASE = {
  production: 'https://provenance.vaibot.io/api',
  staging: 'https://vaibot-api-v1.fly.dev/api',
}

// Server-enforced key prefixes (apps/api): vb_live_* on prod, vb_stg_* on staging.
const KEY_PREFIX = {
  production: 'vb_live_',
  staging: 'vb_stg_',
}

// ── Env helpers ──────────────────────────────────────────────────────────────

export function isEnv(value) {
  return value === 'production' || value === 'staging'
}

export function apiBaseForEnv(envName, override) {
  if (override) return String(override).replace(/\/+$/, '')
  return API_BASE[envName] ?? API_BASE[DEFAULT_ENV]
}

// Shared precedence: non-empty override → non-empty stored slot url → canonical.
function slotBase(override, stored, canonical) {
  if (override) return String(override).replace(/\/+$/, '')
  if (typeof stored === 'string' && stored) return stored.replace(/\/+$/, '')
  return canonical
}

// V2 GOVERNANCE base for an env: override → stored slot url → canonical.
// Policy, mode-poll, decide, and governance receipts hang off this.
export function governanceBaseForEnv(store, envName, override) {
  const canonical = API_BASE[envName] ?? API_BASE[DEFAULT_ENV]
  return slotBase(override, store?.environments?.[envName]?.governance?.url, canonical)
}

// V1 PROVENANCE base for an env: override → stored slot url → canonical.
// `/prove` anchoring hangs off this. Tracked separately from governance so a
// staging key can never anchor to the prod provenance endpoint.
export function provenanceBaseForEnv(store, envName, override) {
  const canonical = PROVENANCE_BASE[envName] ?? PROVENANCE_BASE[DEFAULT_ENV]
  return slotBase(override, store?.environments?.[envName]?.provenance?.url, canonical)
}

// Is the deliberate-act flag for a URL override set? (VAIBOT_ALLOW_URL_OVERRIDE
// = 1/true/yes.) Required — together with an admin account — to redirect a
// PRODUCTION base off its canonical host. Mirrors the CLI's url_override_allowed.
export function urlOverrideAllowed(env = process.env) {
  const v = String(env?.VAIBOT_ALLOW_URL_OVERRIDE ?? '').trim()
  return v === '1' || v === 'true' || v === 'yes' || v === 'TRUE'
}

// §5 LOCAL gate on a requested URL override — the env-injectable half.
// - non-production: honored. - production: honored ONLY when allowOverride is set,
// else SUPPRESSED (→ stored slot / canonical) so a prod key is never diverted by an
// env var alone. The ADMIN half (a prod override is admitted only for an admin
// account) is enforced by the guard's /me poll, which revokes a non-admin's prod
// override back to canonical. Falsy/empty in ⇒ null out.
export function gateUrlOverride(envName, requested, allowOverride) {
  if (!requested) return null
  if (envName === 'production' && !allowOverride) return null
  return requested
}

export function keyPrefixForEnv(envName) {
  return KEY_PREFIX[envName] ?? ''
}

// Which env does an api_key's prefix indicate? null if unrecognized
// (custom / legacy / test keys are intentionally not forced into an env).
export function envForKey(apiKey) {
  if (typeof apiKey !== 'string') return null
  if (apiKey.startsWith(KEY_PREFIX.production)) return 'production'
  if (apiKey.startsWith(KEY_PREFIX.staging)) return 'staging'
  return null
}

// Lenient prefix guard: a key with a *recognized* prefix must match envName;
// an unrecognized prefix is allowed rather than blocked (avoids false denials).
export function keyPrefixMatchesEnv(apiKey, envName) {
  const keyEnv = envForKey(apiKey)
  return keyEnv === null || keyEnv === envName
}

// Map an API base URL to an env. Unknown hosts → null (no custom/local envs;
// the env set is closed at production/staging).
export function envForApiUrl(url) {
  if (typeof url !== 'string' || !url) return null
  let host
  try { host = new URL(url).host } catch { return null }
  if (host === 'api.vaibot.io') return 'production'
  if (host === 'staging-api.vaibot.io' || host.includes('staging')) return 'staging'
  return null
}

// ── Path resolution ──────────────────────────────────────────────────────────

export function resolveCredsDir(opts = {}) {
  if (opts.dir) return opts.dir
  const env = opts.env ?? process.env
  return env.VAIBOT_CREDS_DIR || join(homedir(), '.vaibot')
}

export function credsPath(opts = {}) {
  return join(resolveCredsDir(opts), 'credentials.json')
}

// ── Environment resolution ───────────────────────────────────────────────────
// Precedence: VAIBOT_ENV → VAIBOT_API_URL → VAIBOT_API_KEY prefix →
//             stored active key prefix → stored active_env → default.

export function resolveEnv(opts = {}) {
  const env = opts.env ?? process.env
  if (isEnv(env.VAIBOT_ENV)) return env.VAIBOT_ENV

  const fromUrl = envForApiUrl(env.VAIBOT_API_URL)
  if (fromUrl) return fromUrl

  const fromEnvKey = envForKey(env.VAIBOT_API_KEY)
  if (fromEnvKey) return fromEnvKey

  const store = opts.store ?? loadStore(opts)
  const fromStoreKey = envForKey(store.environments?.[store.active_env]?.api_key)
  if (fromStoreKey) return fromStoreKey
  if (isEnv(store.active_env)) return store.active_env

  return DEFAULT_ENV
}

// ── Store: load / migrate / save ─────────────────────────────────────────────

export function emptyStore() {
  return { version: STORE_VERSION, active_env: DEFAULT_ENV, environments: {} }
}

// Persist only the slim schema, regardless of what extra fields a caller passes.
function slimRecord(rec) {
  const out = { api_key: rec.api_key }
  if (typeof rec.wallet_address === 'string' && rec.wallet_address) {
    out.wallet_address = rec.wallet_address
  }
  // Persist a slot only when it carries an explicit override — a stock record
  // (URLs derived from canonical defaults) stays as { api_key, wallet_address }.
  for (const slot of ['governance', 'provenance']) {
    const url = rec?.[slot]?.url
    if (typeof url === 'string' && url) out[slot] = { url }
  }
  return out
}

// Host-level guard endpoint (port-as-data). The guard is one-per-host, so its
// resolved address lives at the TOP LEVEL of the store, not per-env. Validates the
// port and keeps host + optional token. Returns null for anything malformed.
function slimGuard(g) {
  if (!g || typeof g !== 'object') return null
  const port = Number(g.port)
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null
  const out = { host: typeof g.host === 'string' && g.host ? g.host : '127.0.0.1', port }
  if (typeof g.token === 'string' && g.token) out.token = g.token
  return out
}

// Pure: normalize any parsed JSON into a v2 store (in memory). Never throws.
export function migrateStore(raw) {
  if (!raw || typeof raw !== 'object') return emptyStore()

  // v2 AND v3 both nest under `environments` — gate on its presence, NOT the version
  // number (gating on version>=3 would drop a v2 file to an empty store). slimRecord
  // carries the optional governance/provenance slots; absent in v2 ⇒ canonical
  // defaults on read, so a v2 file upgrades to v3 transparently on the next write.
  if (raw.environments && typeof raw.environments === 'object') {
    const out = emptyStore()
    out.active_env = isEnv(raw.active_env) ? raw.active_env : DEFAULT_ENV
    for (const e of ENVS) {
      const rec = raw.environments[e]
      if (rec && typeof rec.api_key === 'string' && rec.api_key) {
        out.environments[e] = slimRecord(rec)
      }
    }
    // Preserve the host-level guard endpoint across migrations (port-as-data).
    const g = slimGuard(raw.guard)
    if (g) out.guard = g
    return out
  }

  // v1 flat: { api_key, api_url?, wallet_address?, account_id?, ... }
  if (typeof raw.api_key === 'string' && raw.api_key) {
    const e = envForApiUrl(raw.api_url) ?? envForKey(raw.api_key) ?? DEFAULT_ENV
    const out = emptyStore()
    out.active_env = e
    out.environments[e] = slimRecord(raw)
    return out
  }

  return emptyStore()
}

// Read + migrate in memory. Never writes, never throws. Missing/corrupt → empty.
export function loadStore(opts = {}) {
  const path = opts.path ?? credsPath(opts)
  let raw
  try {
    raw = JSON.parse(readFileSync(path, 'utf-8'))
  } catch {
    return emptyStore()
  }
  return migrateStore(raw)
}

export function loadCredsForEnv(envName, opts = {}) {
  const store = opts.store ?? loadStore(opts)
  return store.environments?.[envName] ?? null
}

// Read the host-level guard endpoint (the durable "assigned" address).
// Returns { host, port, token? } or null. Clients resolve the LIVE rendezvous
// (~/.vaibot/guard/guard.json) first and fall back to this — never a hardcoded port.
export function readGuardEndpoint(opts = {}) {
  const store = opts.store ?? loadStore(opts)
  return store.guard ?? null
}

// Merge-on-write the host-level guard endpoint: re-read the latest store, set ONLY
// the guard block (validated), atomically replace. Never clobbers env creds.
export function writeGuardEndpoint(endpoint, opts = {}) {
  const slim = slimGuard(endpoint)
  if (!slim) throw new Error('writeGuardEndpoint: endpoint requires an integer { port } in 1..65535')
  const dir = resolveCredsDir(opts)
  const path = opts.path ?? credsPath(opts)
  const store = loadStore({ ...opts, path })
  store.guard = slim
  atomicWriteJson(dir, path, store)
  return slim
}

function atomicWriteJson(dir, path, value) {
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const tmp = join(dir, `credentials.json.tmp-${process.pid}-${Math.random().toString(36).slice(2)}`)
  writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 })
  renameSync(tmp, path)
}

// Merge-on-write: read the latest store, set ONLY this env's slot (slimmed),
// bump active_env, then write atomically (temp + rename). The merge prevents a
// concurrent save to the *other* env from being clobbered; the rename prevents
// a crash from truncating the file.
export function saveCredsForEnv(envName, record, opts = {}) {
  if (!isEnv(envName)) throw new Error(`saveCredsForEnv: unknown env "${envName}"`)
  if (!record || typeof record.api_key !== 'string' || !record.api_key) {
    throw new Error('saveCredsForEnv: record.api_key is required')
  }
  const dir = resolveCredsDir(opts)
  const path = join(dir, 'credentials.json')

  const store = loadStore({ ...opts, path })
  store.environments[envName] = slimRecord(record)
  store.active_env = envName

  atomicWriteJson(dir, path, store)
  return store
}

// One-time on-disk migration: if the file isn't already v2, back it up to
// credentials.json.bak (once) and rewrite it in v2 shape. Safe to call on every
// startup — a no-op when already v2, when no file exists, or when corrupt.
export function migrateFileIfNeeded(opts = {}) {
  const dir = resolveCredsDir(opts)
  const path = join(dir, 'credentials.json')

  let rawText
  try {
    rawText = readFileSync(path, 'utf-8')
  } catch {
    return { migrated: false, reason: 'no-file' }
  }

  let parsed
  try {
    parsed = JSON.parse(rawText)
  } catch {
    return { migrated: false, reason: 'unparseable' } // never touch corrupt files
  }

  if (parsed && parsed.version >= STORE_VERSION) {
    return { migrated: false, reason: 'already-current' }
  }

  const store = migrateStore(parsed)
  const bak = join(dir, 'credentials.json.bak')
  if (!existsSync(bak)) {
    try { writeFileSync(bak, rawText, { mode: 0o600 }) } catch { /* best-effort */ }
  }
  atomicWriteJson(dir, path, store)
  return { migrated: true, store }
}

// All-in-one resolver — the entry point surfaces call to talk to the right API.
//
//   { env, apiBaseUrl, apiKey, walletAddress, keyMismatch }
//
// - env:          production | staging (resolveEnv precedence)
// - apiBaseUrl:   V2 governance base (VAIBOT_GOVERNANCE_URL override → slot → canonical)
// - provenanceBaseUrl: V1 provenance base (VAIBOT_PROVENANCE_URL override → slot → canonical)
// - apiKey:       VAIBOT_API_KEY override, else the stored key for env.
//                 null when the only candidate fails the prefix guard.
// - walletAddress:stored public address for env (display only), or null
// - keyMismatch:  true when a candidate key's prefix names a different env
//                 (e.g. a vb_live_ key while resolving staging). Callers should
//                 treat apiKey as missing and re-bootstrap for this env.
export function resolveCredentials(opts = {}) {
  const env = opts.env ?? process.env
  const store = opts.store ?? loadStore(opts)
  const envName = resolveEnv({ ...opts, env, store })
  // V2 governance: VAIBOT_GOVERNANCE_URL → stored slot → canonical.
  // V1 provenance: VAIBOT_PROVENANCE_URL → stored slot → canonical.
  // Deprecated VAIBOT_API_URL overrides NEITHER base (env inference only) — it's too
  // overloaded (CLI's V2 base vs the guard's /prove base) to alias safely.
  // §5 flag-gate applied HERE (mirrors Rust resolve_credentials): a PRODUCTION
  // override is suppressed unless VAIBOT_ALLOW_URL_OVERRIDE is set, so every consumer
  // of resolveCredentials — including the plugin hooks, which have no preflight —
  // gets the unbypassable safe default and can never send a prod bearer to an
  // env-injected host. The admin half is layered by callers that can do a /me check.
  const allow = urlOverrideAllowed(env)
  const govOverride = gateUrlOverride(envName, env.VAIBOT_GOVERNANCE_URL, allow)
  const provOverride = gateUrlOverride(envName, env.VAIBOT_PROVENANCE_URL, allow)
  const apiBaseUrl = governanceBaseForEnv(store, envName, govOverride)
  const provenanceBaseUrl = provenanceBaseForEnv(store, envName, provOverride)

  const record = store.environments?.[envName] ?? null
  const walletAddress = record?.wallet_address ?? null

  const candidate = env.VAIBOT_API_KEY || record?.api_key || null
  let apiKey = candidate
  let keyMismatch = false
  if (candidate && !keyPrefixMatchesEnv(candidate, envName)) {
    apiKey = null
    keyMismatch = true
  }

  return { env: envName, apiBaseUrl, provenanceBaseUrl, apiKey, walletAddress, keyMismatch }
}
