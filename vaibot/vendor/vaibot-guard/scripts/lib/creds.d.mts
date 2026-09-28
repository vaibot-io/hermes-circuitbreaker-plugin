// Type declarations for creds.mjs — the canonical credential store + resolver.
// Hand-written to pair with the plain-ESM source so TS consumers
// (@vaibot/cli, the OpenClaw plugin) get types while the .mjs ships verbatim.

export type VaibotEnv = 'production' | 'staging'

/** Per-API endpoint slot. `url` absent/null ⇒ the env's canonical default. Nested
 *  so a per-slot api_key (approach B) can be added later without reshaping. */
export interface ApiSlot {
  url?: string | null
}

export interface CredsRecord {
  api_key: string
  /** Public on-chain identity — display only, never trusted for authz. */
  wallet_address?: string
  /** V2 governance endpoint override (absent ⇒ canonical default). */
  governance?: ApiSlot
  /** V1 provenance endpoint override (absent ⇒ canonical default). */
  provenance?: ApiSlot
}

export interface CredsStore {
  version: number
  active_env: VaibotEnv
  environments: Partial<Record<VaibotEnv, CredsRecord>>
}

export interface CredsOpts {
  /** Explicit credentials directory (overrides env + default ~/.vaibot). */
  dir?: string
  /** Environment-variable bag (defaults to process.env). */
  env?: Record<string, string | undefined>
  /** Explicit path to credentials.json (overrides dir resolution). */
  path?: string
  /** Pre-loaded store, to avoid a re-read. */
  store?: CredsStore
}

export interface ResolvedCredentials {
  env: VaibotEnv
  /** V2 governance base (policy / mode / decide / receipts). */
  apiBaseUrl: string
  /** V1 provenance base (`/prove` anchoring) — resolved separately from governance. */
  provenanceBaseUrl: string
  apiKey: string | null
  walletAddress: string | null
  keyMismatch: boolean
}

export interface MigrateFileResult {
  migrated: boolean
  reason?: 'no-file' | 'unparseable' | 'already-current'
  store?: CredsStore
}

export const STORE_VERSION: number
export const ENVS: readonly VaibotEnv[]
export const DEFAULT_ENV: VaibotEnv

export function isEnv(value: unknown): value is VaibotEnv
export function apiBaseForEnv(env: VaibotEnv, override?: string): string
/** V2 governance base: override → stored slot url → canonical default. */
export function governanceBaseForEnv(store: CredsStore | undefined, env: VaibotEnv, override?: string): string
/** V1 provenance base: override → stored slot url → canonical default. */
export function provenanceBaseForEnv(store: CredsStore | undefined, env: VaibotEnv, override?: string): string
/** Is VAIBOT_ALLOW_URL_OVERRIDE set (1/true/yes)? Required — with admin — to redirect a prod base. */
export function urlOverrideAllowed(env?: Record<string, string | undefined>): boolean
/** §5 local gate: a production override is suppressed (→ null) unless `allowOverride`; non-prod honored. */
export function gateUrlOverride(env: VaibotEnv, requested: string | null | undefined, allowOverride: boolean): string | null
export function keyPrefixForEnv(env: VaibotEnv): string
export function envForKey(apiKey: unknown): VaibotEnv | null
export function keyPrefixMatchesEnv(apiKey: unknown, env: VaibotEnv): boolean
export function envForApiUrl(url: unknown): VaibotEnv | null

export function resolveCredsDir(opts?: CredsOpts): string
export function credsPath(opts?: CredsOpts): string
export function resolveEnv(opts?: CredsOpts): VaibotEnv

export function emptyStore(): CredsStore
export function migrateStore(raw: unknown): CredsStore
export function loadStore(opts?: CredsOpts): CredsStore
export function loadCredsForEnv(env: VaibotEnv, opts?: CredsOpts): CredsRecord | null
export function saveCredsForEnv(env: VaibotEnv, record: CredsRecord, opts?: CredsOpts): CredsStore
export function migrateFileIfNeeded(opts?: CredsOpts): MigrateFileResult
export function resolveCredentials(opts?: CredsOpts): ResolvedCredentials
