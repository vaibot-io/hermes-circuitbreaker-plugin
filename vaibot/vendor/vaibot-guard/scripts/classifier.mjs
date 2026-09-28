// @vaibot/shared — stateless risk classifier for tool calls.
//
// Pure, deterministic classification of a SINGLE tool call by its intrinsic
// properties — category (read/write/exec/network), risk, trust-boundary
// crossing (ingress/egress), and reversibility. This drives three things in
// the no-allowlist model:
//   1. the local verdict hint (allow / ask / deny),
//   2. the offline fail-closed fallback (the breaker consults this when the
//      governance API is unreachable), and
//   3. the receipt tier (ledger vs signed receipt).
//
// There is deliberately NO allowlist. "Safe" is COMPUTED from properties on
// every call — never granted once and remembered — so there is no mutable,
// poisonable grant store. The built-in rule tables below are a sane baseline;
// they are overridable via `cfg.tables` so a signed policy bundle can inject
// an authoritative, richer ruleset without changing this engine.
//
// Authored as plain ESM (.mjs), same constraint as circuit-breaker.mjs and
// creds.mjs: the codex/claudecode hooks run as standalone node scripts and
// vendor a byte-identical copy under scripts/lib/classifier.mjs (guarded by a
// parity test). The openclaw plugin imports it from @vaibot/shared directly.

export const RISK = Object.freeze({
  SAFE: 'safe',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  DANGEROUS: 'dangerous',
})

export const CATEGORY = Object.freeze({
  READ: 'read',
  WRITE: 'write',
  EXEC: 'exec',
  NETWORK: 'network',
  UNKNOWN: 'unknown',
})

export const BOUNDARY = Object.freeze({
  NONE: 'none',
  INGRESS: 'ingress',
  EGRESS: 'egress',
  BOTH: 'both',
})

export const VERDICT = Object.freeze({ ALLOW: 'allow', ASK: 'ask', DENY: 'deny' })
export const RECEIPT_TIER = Object.freeze({ NONE: 'none', LEDGER: 'ledger', RECEIPT: 'receipt' })

const RISK_RANK = { safe: 0, low: 1, medium: 2, high: 3, dangerous: 4 }

// The vaibot self/governance MCP namespace — the agent querying its own
// governance must never be gated by governance (matches the existing
// `mcp__vaibot__.*` self-skip in the hooks).
const SELF_MCP_PREFIX = 'mcp__vaibot__'

// ── Built-in rule tables (overridable via cfg.tables) ───────────────────────

function defaultTables() {
  return {
    readTools: ['read', 'grep', 'glob', 'ls', 'notebookread'],
    writeTools: ['write', 'edit', 'multiedit', 'apply_patch', 'applypatch', 'notebookedit'],
    networkTools: ['webfetch', 'web_fetch', 'fetch'],
    searchTools: ['websearch', 'web_search'],
    execTools: ['bash', 'shell', 'sh', 'exec', 'run', 'run_command', 'local_shell'],

    // Bash leading-word tables.
    safeCmds: [
      'ls', 'pwd', 'echo', 'cat', 'head', 'tail', 'wc', 'grep', 'egrep', 'fgrep',
      'rg', 'find', 'which', 'type', 'file', 'stat', 'du', 'df', 'date', 'whoami',
      'hostname', 'uname', 'true', 'dirname', 'basename', 'realpath', 'readlink',
      'tree', 'sort', 'uniq', 'cut', 'tr', 'diff', 'cmp', 'sha256sum', 'md5sum',
    ],
    networkCmds: [
      'curl', 'wget', 'nc', 'ncat', 'netcat', 'ssh', 'scp', 'sftp', 'rsync',
      'telnet', 'ftp',
    ],
    writeCmds: [
      'mv', 'cp', 'mkdir', 'rmdir', 'touch', 'tee', 'ln', 'install', 'make',
      'sed', 'awk', 'npm', 'pnpm', 'yarn', 'npx', 'pip', 'pip3', 'python',
      'python3', 'node', 'cargo', 'go', 'docker', 'kubectl', 'git', 'chmod',
      'chown', 'apt', 'apt-get', 'brew', 'systemctl', 'service',
    ],
    // git subcommands that only read.
    readGitSub: [
      'status', 'log', 'diff', 'show', 'branch', 'remote', 'rev-parse',
      'describe', 'blame', 'tag', 'ls-files', 'cat-file',
    ],
  }
}

// ── Host tool vocabulary (always recognised) ────────────────────────────────
//
// Agent hosts name the same primitives differently. A host tool the classifier
// doesn't recognise lands on `unknown` → ask, which quietly hollows out the
// floor: a destructive shell command arriving under Hermes' `terminal` would be
// asked about instead of denied, and a plain `ls` would be asked about too.
// Mapping each host's names onto a table kind here keeps ONE vocabulary for
// every breaker instead of one per plugin.
//
// Consulted only AFTER the active tables, so an explicit table entry (built-in
// or signed) still wins. It lives outside defaultTables() on purpose: a signed
// bundle's classifierTables REPLACE the built-ins wholesale, and a bundle that
// predates a host must not silently erase that host's names.
const HOST_TOOL_KINDS = Object.freeze({
  // Hermes Agent — names as registered under hermes-agent/tools/.
  terminal: 'exec', //       { command, workdir, background, … }
  write_file: 'write', //    { path, content }
  patch: 'write', //         { mode, path, old_string, new_string } | { mode: 'patch', patch }
  read_file: 'read', //      { path, offset, limit }
  search_files: 'read', //   { pattern, target, path, … }
  web_extract: 'network', // { urls, … }
  // Deliberately absent: execute_code runs Python, not a shell command. Routing
  // it through classifyBash would read `cat = open(...)` as the safe `cat`
  // command and allow it, so it stays unknown → ask.
})

/**
 * The table kind a tool name resolves to — 'exec' | 'read' | 'write' | 'search'
 * | 'network' — or null when unrecognised. Resolution order is the one
 * classify() uses: the active tables first, then the built-in host vocabulary.
 *
 * @param {string} tool
 * @param {object} [tables] — defaults to the built-in tables
 * @returns {'exec'|'read'|'write'|'search'|'network'|null}
 */
export function toolKind(tool, tables) {
  const t = norm(tool)
  const tb = tables ?? defaultTables()
  const listed = (list) => Array.isArray(list) && list.includes(t)
  if (listed(tb.execTools)) return 'exec'
  if (listed(tb.readTools)) return 'read'
  if (listed(tb.writeTools)) return 'write'
  if (listed(tb.searchTools)) return 'search'
  if (listed(tb.networkTools)) return 'network'
  // Own-property check: a plain lookup would resolve `constructor` or
  // `toString` to a prototype member and hand back a non-kind.
  return Object.hasOwn(HOST_TOOL_KINDS, t) ? HOST_TOOL_KINDS[t] : null
}

// High-confidence destructive patterns → DENY. Kept conservative on purpose:
// the signed bundle carries the authoritative richer set. Anchored / bounded
// to avoid catastrophic backtracking.
const DENY_PATTERNS = [
  /\brm\s+(?:-[a-z]+\s+)*-[a-z]*[rf][a-z]*\s+(?:-[a-z]+\s+)*(?:\/|~|\*|\$HOME|\.\.)/i, // rm -rf on / ~ * .. $HOME
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, // fork bomb
  /\bmkfs(\.\w+)?\b/i,
  /\bdd\b[^|&;]*\bof=\/dev\/(sd|nvme|disk|hd)/i,
  /(^|[\s>])>\s*\/dev\/(sd|nvme|disk|hd)/i,
  /\bchmod\s+-R\s+0?777\s+\//i,
  /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|dash)\b/i, // pipe remote → shell
  /\b(shutdown|reboot|halt|poweroff|init\s+0|init\s+6)\b/i,
]

// VAIBot guard self-protection (Tier-0 floor). A governed agent must never be
// able to kill the guard's singleton (port 39111) or stop/disable its process or
// systemd unit — doing so would silently switch off enforcement itself. Matched
// by port AND by name; un-overridable by any signed bundle, enforced offline.
// Stateless limitation: a two-step `pid=$(lsof -ti:39111); kill $pid` split across
// separate commands, or obfuscated/encoded forms, can still evade — this blocks
// the discoverable one-liners, not every conceivable path. `restart`/`status` stay
// allowed so the guard's own lifecycle isn't broken.
const GUARD_PROTECT_PATTERNS = [
  // by the singleton port: fuser -k 39111, lsof -ti:39111 | xargs kill,
  // kill $(lsof -t -i:39111), npx kill-port 39111, P=39111; fuser -k $P/tcp …
  /(?=[\s\S]*\b39111\b)(?=[\s\S]*\b(?:kill|pkill|killall|fuser|kill-port)\b)/i,
  // by process/service name: pkill -f vaibot-guard-service, killall vaibot-guard,
  // systemctl --user stop|disable|mask vaibot-guard
  /(?=[\s\S]*\bvaibot-guard(?:-service)?\b)(?=[\s\S]*\b(?:kill|pkill|killall|stop|disable|mask|fuser|kill-port|sigkill|sigterm)\b)/i,
  // the guard's own CLI teardown, run by an agent
  /\bvaibot\s+guard\s+(?:stop|disable|uninstall|remove)\b/i,
]

// Destructive host-config verbs → un-overridable HARD-DENY (Phase-3 #4). Stopping,
// disabling, or masking a service, unloading/removing a launchd job, or wiping/installing
// a crontab can take down a security service (auditd/firewalld) or plant persistence.
// Matched on the FULL command so wrapped/absolute/`sh -c` forms are covered too
// (`/usr/bin/systemctl disable auditd`, `sh -c 'crontab job'`), and because the verdict is
// DANGEROUS it can't be downgraded to ask by any signed preset. Benign system-config
// (status/list/-l) is NOT matched here and stays on the ask lane (SYSTEM_CONFIG_CMDS below).
const SYSTEM_CONFIG_DENY_PATTERNS = [
  /\bsystemctl\b[^|&;\n]*\b(stop|disable|mask|kill)\b/i,
  /\bservice\b\s+\S+\s+(stop|force-reload)\b/i,
  /\blaunchctl\b[^|&;\n]*\b(unload|remove|bootout|disable)\b/i,
  // crontab -r (wipe all), crontab - (install from stdin), crontab <file> (install); -l/-e stay on ask
  /\bcrontab\b\s+(?:-u\s+\S+\s+)?(-r\b|-(?:\s|$)|[^\-\s]\S*)/i,
]

// The guard's OWN forward lifecycle → ALLOW (no prompt). Checked AFTER the self-protection +
// destructive-verb denies, so stop/disable/mask/unload/bootout/uninstall of the guard still
// hard-DENY. Each form is anchored (^…$) and rejects shell metacharacters so a chained /
// injected action can't ride along; any teardown verb also disqualifies. Covers systemd
// (Linux) AND launchctl (macOS, label io.vaibot.guard) plus the guard CLI/launcher and the
// localhost :39111 health probe — so an agent can start/inspect/health-check/(re)install the
// guard it runs under without a prompt.
const GUARD_TEARDOWN_VERBS = /\b(?:stop|disable|mask|unload|remove|bootout|uninstall|kill|purge)\b/i
const GUARD_LIFECYCLE_ALLOW = [
  /^(?:sudo\s+)?systemctl(?:\s+--user)?\s+(?:start|status|restart|enable|reload|is-active|is-enabled|show|cat)(?:\s+--now)?\s+vaibot-guard(?:-service)?(?:\.service)?\s*$/i,
  /^(?:sudo\s+)?launchctl\s+(?:load|list|start|kickstart|enable|bootstrap|print|blame)\s[^|&;<>`$()]*(?:io\.vaibot\.guard|vaibot-guard)[^|&;<>`$()]*$/i,
  /^(?:sudo\s+)?service\s+vaibot-guard(?:-service)?\s+(?:start|status|restart|reload)\s*$/i,
  /^(?:sudo\s+)?(?:node\s+\S*)?vaibot-guard(?:-service)?(?:\.mjs)?(?:\s+[\w:@%./=+-]+)*\s*$/i,
  /^(?:sudo\s+)?(?:curl|wget)\s[^|&;<>`$()]*(?:127\.0\.0\.1|localhost):39111[^|&;<>`$()]*$/i,
]

// Elevated-risk patterns → HIGH (ask). Recoverable-but-consequential.
const HIGH_PATTERNS = [
  /\bsudo\b/i,
  /(^|[\n|&;]\s*)su\b/i, // bare `su` — privilege escalation, same class as sudo
  /\bgit\s+push\b/i,
  /\b(npm|pnpm|yarn)\s+publish\b/i,
  /\b(flyctl?|fly|vercel|netlify)\s+deploy\b/i,
  /\bgit\s+reset\s+--hard\b/i,
  /\bgit\s+clean\s+-[a-z]*f/i,
  /(^|[\s>])>\s*\/etc\//i,
  /\bchown\s+-R\b[^|&;]*\s\/(?:\s|$)/i,
  /\beval\b/i,
  /\bbase64\s+-d\b[^|]*\|\s*(sh|bash)/i,
]

// Sensitive paths/identifiers — reading or touching these is high-value
// ingress/egress (secrets) → HIGH + always receipt.
const SENSITIVE_PATTERNS = [
  /\.ssh\b/i, /\bid_rsa\b/i, /\bid_ed25519\b/i, /\.aws(\/|\b)/i,
  /(^|\/|\s)\.env(\.[\w-]+)?(\s|$|['"])/i, /\/etc\/shadow\b/i, /\.npmrc\b/i,
  /\.git-credentials\b/i, /private[_-]?key/i, /\.pem\b/i, /credentials\.json\b/i,
  /\.kube\/config\b/i, /\bprintenv\b/i,
]

// System-config command HEADS → HIGH (ask). Managing host schedulers / process
// supervisors is consequential-but-reversible, so it takes human approval rather
// than a hard deny — this lets operators manage them under approval AND lets a
// fresh install bootstrap the guard's own unit under approval instead of being
// hard-blocked. Matched on the command HEAD (leadingWord) only, so the same word
// appearing as an argument ("restart the foo service") is NOT escalated.
const SYSTEM_CONFIG_CMDS = new Set(['systemctl', 'service', 'launchctl', 'crontab', 'cron'])

// ── Helpers ─────────────────────────────────────────────────────────────────

function norm(s) {
  return String(s ?? '').trim().toLowerCase()
}

function maxRisk(a, b) {
  return RISK_RANK[a] >= RISK_RANK[b] ? a : b
}

function unionBoundary(a, b) {
  if (a === b) return a
  if (a === BOUNDARY.NONE) return b
  if (b === BOUNDARY.NONE) return a
  return BOUNDARY.BOTH
}

function anyMatch(patterns, text) {
  for (const re of patterns) if (re.test(text)) return true
  return false
}

// Split a shell command into segments on pipes, sequencing, and logical ops.
function splitPipeline(command) {
  return String(command ?? '')
    .split(/\n|\||;|&&|\|\||&/)
    .map((s) => s.trim())
    .filter(Boolean)
}

function leadingWord(segment) {
  // Strip leading env-var assignments (FOO=bar cmd ...) to find the real
  // command word. (sudo is caught separately by HIGH_PATTERNS.)
  const tokens = segment.split(/\s+/).filter(Boolean)
  let i = 0
  while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) i++
  return norm(tokens[i] ?? '')
}

// Dynamic Tier-0 (port-as-data): also protect the guard's LIVE bound port, not just
// the static default already in GUARD_PROTECT_PATTERNS. Given a resolved port, flag a
// command that both names that port and carries a process-termination verb. No-op
// when the port is absent/invalid — the static default branch still covers it. The
// port is coerced to a bounded integer, so it can never inject into the regex.
function matchesLiveGuardPort(text, port) {
  const p = Number(port)
  if (!Number.isInteger(p) || p <= 0 || p > 65535) return false
  const re = new RegExp(`(?=[\\s\\S]*\\b${p}\\b)(?=[\\s\\S]*\\b(?:kill|pkill|killall|fuser|kill-port)\\b)`, 'i')
  return re.test(text)
}

/**
 * Classify a raw shell command string.
 * @param {string} command
 * @param {object} tables
 * @param {number} [guardPort] live guard port to protect (port-as-data); the default branch covers the static default
 * @returns {{category:string, risk:string, boundary:string, reversible:boolean, reasons:string[]}}
 */
// ── Data payloads are not commands (F4) ──────────────────────────────────────
//
// The floor matches patterns against the raw command string, which cannot tell
// an instruction from its data. So a heredoc body being written to a file, or a
// pattern being searched FOR, was matched as though it were being run: writing
// documentation about the guard, or grepping for the rule that fires, both got
// denied. Data is excluded from matching before the patterns run.
//
// This is NOT a weakening. The same bytes were already unmatched when written
// through a file-write tool, which never inspected content at all — this makes
// the two paths agree rather than opening anything new. Content that will
// actually be EXECUTED is deliberately still matched, which is why a heredoc
// feeding an interpreter keeps its body.
const CODE_RECEIVER = /\b(?:sh|bash|zsh|dash|ksh|python3?|node|perl|ruby|php|pwsh|powershell|osascript|env)\b/i

/** Drop heredoc bodies that are data. A body fed to an interpreter is kept. */
function stripHeredocBodies(command) {
  const lines = command.split('\n')
  const out = []
  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    out.push(line)
    const m = /<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_-]*)\1/.exec(line)
    if (!m) { i++; continue }
    // Is the thing receiving this heredoc going to run it?
    const executed = CODE_RECEIVER.test(line.slice(0, m.index))
    const delim = m[2]
    i++
    const body = []
    while (i < lines.length && lines[i].trim() !== delim) { body.push(lines[i]); i++ }
    if (executed) out.push(...body) // e.g. `python3 - <<PY` — this is code
    if (i < lines.length) out.push(lines[i]) // keep the terminator
    i++
  }
  return out.join('\n')
}

/** A search pattern is what you are looking for, not what you are doing. */
function stripSearchPatterns(command) {
  return command.replace(
    /\b(grep|egrep|fgrep|rg|ag|ack)\b((?:\s+-{1,2}[\w-]+)*)\s+('[^']*'|"[^"]*")/gi,
    (_m, cmd, flags) => `${cmd}${flags} ''`,
  )
}

/** A request body is data in flight. The URL and any pipe stay visible. */
function stripRequestBodies(command) {
  return command.replace(
    /(\s(?:-d|--data|--data-raw|--data-binary|--data-urlencode|--json)\s+)('[^']*'|"[^"]*")/gi,
    (_m, flag) => `${flag}''`,
  )
}

/**
 * What the floor should actually inspect: the command, with its data removed.
 * Exported so the behaviour is testable and so a host can reason about it.
 */
export function commandForMatching(command) {
  return stripRequestBodies(stripSearchPatterns(stripHeredocBodies(String(command ?? ''))))
}

export function classifyBash(command, tables = defaultTables(), guardPort) {
  const reasons = []
  const raw = String(command ?? '')
  // Match against the command with its data payloads removed (see above).
  const full = commandForMatching(raw)
  if (!raw.trim()) {
    return { category: CATEGORY.EXEC, risk: RISK.MEDIUM, boundary: BOUNDARY.NONE, reversible: true, reasons: ['empty command'] }
  }

  if (anyMatch(GUARD_PROTECT_PATTERNS, full) || matchesLiveGuardPort(full, guardPort)) {
    return { category: CATEGORY.EXEC, risk: RISK.DANGEROUS, boundary: BOUNDARY.EGRESS, reversible: false, reasons: ['would disable the VAIBot guard (protected: port 39111 / vaibot-guard)'] }
  }

  if (anyMatch(DENY_PATTERNS, full)) {
    return { category: CATEGORY.EXEC, risk: RISK.DANGEROUS, boundary: BOUNDARY.EGRESS, reversible: false, reasons: ['matches destructive pattern'] }
  }

  if (anyMatch(SYSTEM_CONFIG_DENY_PATTERNS, full)) {
    return { category: CATEGORY.EXEC, risk: RISK.DANGEROUS, boundary: BOUNDARY.EGRESS, reversible: false, reasons: ['destructive host-config verb (stop/disable/unload/mask or crontab install)'] }
  }

  // The guard's OWN forward lifecycle (manage the guard I run under) → ALLOW. Reached only
  // after the denies above, so teardown of the guard still hard-DENY; a teardown verb or any
  // shell chaining disqualifies (see GUARD_LIFECYCLE_ALLOW).
  if (!GUARD_TEARDOWN_VERBS.test(full) && anyMatch(GUARD_LIFECYCLE_ALLOW, full)) {
    return { category: CATEGORY.EXEC, risk: RISK.SAFE, boundary: BOUNDARY.NONE, reversible: true, reasons: ['vaibot-guard own lifecycle command'] }
  }

  let risk = RISK.SAFE
  let category = CATEGORY.READ
  let boundary = BOUNDARY.NONE
  let reversible = true

  if (anyMatch(HIGH_PATTERNS, full)) {
    risk = maxRisk(risk, RISK.HIGH)
    reversible = false
    reasons.push('matches elevated-risk pattern')
  }
  if (anyMatch(SENSITIVE_PATTERNS, full)) {
    risk = maxRisk(risk, RISK.HIGH)
    boundary = unionBoundary(boundary, BOUNDARY.BOTH)
    reasons.push('touches a sensitive path/secret')
  }

  const safe = new Set(tables.safeCmds)
  const net = new Set(tables.networkCmds)
  const write = new Set(tables.writeCmds)
  const readGit = new Set(tables.readGitSub)

  for (const seg of splitPipeline(full)) {
    const cmd = leadingWord(seg)
    if (!cmd) continue
    if (net.has(cmd)) {
      category = CATEGORY.NETWORK
      boundary = unionBoundary(boundary, BOUNDARY.BOTH)
      risk = maxRisk(risk, RISK.HIGH) // egress stays on the ask lane even at balanced's HIGH threshold
      reversible = false
      reasons.push(`network command: ${cmd}`)
    } else if (cmd === 'git') {
      const sub = norm(seg.split(/\s+/).filter(Boolean)[1])
      if (readGit.has(sub)) {
        category = maxRisk(risk, RISK.SAFE) === RISK.SAFE ? CATEGORY.READ : category
        boundary = unionBoundary(boundary, BOUNDARY.INGRESS)
        reasons.push(`git read: ${sub || '(none)'}`)
      } else {
        category = CATEGORY.WRITE
        boundary = unionBoundary(boundary, BOUNDARY.EGRESS)
        risk = maxRisk(risk, RISK.LOW)
        reversible = false
        reasons.push(`git mutating: ${sub || '(none)'}`)
      }
    } else if (SYSTEM_CONFIG_CMDS.has(cmd)) {
      // Host scheduler / process-supervisor management → HIGH ⇒ ask (approval),
      // never a hard deny. Command-head only (see SYSTEM_CONFIG_CMDS note).
      category = CATEGORY.EXEC
      boundary = unionBoundary(boundary, BOUNDARY.EGRESS)
      risk = maxRisk(risk, RISK.HIGH)
      reversible = false
      reasons.push(`system-config command (approval): ${cmd}`)
    } else if (write.has(cmd)) {
      category = CATEGORY.WRITE
      boundary = unionBoundary(boundary, BOUNDARY.EGRESS)
      risk = maxRisk(risk, RISK.LOW)
      reversible = false
      reasons.push(`mutating command: ${cmd}`)
    } else if (safe.has(cmd)) {
      boundary = unionBoundary(boundary, BOUNDARY.INGRESS)
      reasons.push(`safe command: ${cmd}`)
    } else {
      // Unknown command → ambiguous → ask.
      category = category === CATEGORY.READ ? CATEGORY.EXEC : category
      risk = maxRisk(risk, RISK.MEDIUM)
      reversible = false
      reasons.push(`unknown command: ${cmd}`)
    }
  }

  return { category, risk, boundary, reversible, reasons }
}

/**
 * Map a risk level to a verdict hint, given the (per-preset) escalation
 * threshold. DANGEROUS always denies (Tier-0 floor). Otherwise, risk that
 * meets/exceeds `escalateAt` asks; below it allows. Default MEDIUM preserves
 * the prior behavior; the balanced preset raises it to HIGH ("medium = safe").
 */
export function verdictForRisk(risk, escalateAt = RISK.MEDIUM) {
  if (risk === RISK.DANGEROUS) return VERDICT.DENY
  const threshold = RISK_RANK[escalateAt] ?? RISK_RANK[RISK.MEDIUM]
  if (RISK_RANK[risk] >= threshold) return VERDICT.ASK
  return VERDICT.ALLOW
}

/** Map risk + boundary to a receipt tier. */
export function receiptTierFor(risk, boundary) {
  if (
    RISK_RANK[risk] >= RISK_RANK[RISK.HIGH] ||
    boundary === BOUNDARY.EGRESS ||
    boundary === BOUNDARY.BOTH
  ) {
    return RECEIPT_TIER.RECEIPT
  }
  return RECEIPT_TIER.LEDGER // every governed call is at least ledgered
}

function inputText(input) {
  if (input == null) return ''
  if (typeof input === 'string') return input
  try {
    return JSON.stringify(input)
  } catch {
    return ''
  }
}

function inputPath(input) {
  if (!input || typeof input !== 'object') return ''
  return String(input.file_path ?? input.filePath ?? input.path ?? '')
}

/**
 * Classify a single tool call.
 *
 * @param {{tool: string, input?: any}} call
 * @param {{tables?: object}} [cfg]
 * @returns {{tool:string, category:string, risk:string, boundary:string, reversible:boolean, verdictHint:string, receiptTier:string, reasons:string[]}}
 */
export function classify(call, cfg = {}) {
  const tables = cfg.tables ?? defaultTables()
  const escalateAt = cfg.escalateAt // per-preset ask threshold (undefined ⇒ default MEDIUM)
  const rawTool = String(call?.tool ?? '')
  const tool = norm(rawTool)
  const input = call?.input
  const reasons = []

  let category = CATEGORY.UNKNOWN
  let risk = RISK.MEDIUM
  let boundary = BOUNDARY.BOTH
  let reversible = false

  if (rawTool.startsWith(SELF_MCP_PREFIX)) {
    // vaibot's own governance tools — never gate, never escalate.
    return finalize(rawTool, CATEGORY.READ, RISK.SAFE, BOUNDARY.NONE, true, ['vaibot self/governance call'])
  }

  const kind = toolKind(tool, tables)

  if (kind === 'exec') {
    const command = typeof input === 'string' ? input : input?.command ?? input?.cmd ?? ''
    const b = classifyBash(command, tables, cfg.guardPort)
    return finalize(rawTool, b.category, b.risk, b.boundary, b.reversible, b.reasons, escalateAt)
  }

  if (kind === 'read') {
    category = CATEGORY.READ
    boundary = BOUNDARY.INGRESS
    reversible = true
    risk = RISK.SAFE
    reasons.push(`read tool: ${tool}`)
  } else if (kind === 'write') {
    category = CATEGORY.WRITE
    boundary = BOUNDARY.EGRESS
    reversible = false
    risk = RISK.LOW
    reasons.push(`write tool: ${tool}`)
  } else if (kind === 'search') {
    category = CATEGORY.NETWORK
    boundary = BOUNDARY.INGRESS
    reversible = true
    risk = RISK.LOW
    reasons.push(`search tool: ${tool}`)
  } else if (kind === 'network') {
    category = CATEGORY.NETWORK
    boundary = BOUNDARY.BOTH
    reversible = false
    risk = RISK.HIGH // egress stays on the ask lane even at balanced's HIGH threshold
    reasons.push(`network tool: ${tool}`)
  } else if (rawTool.startsWith('mcp__')) {
    // Third-party MCP tool — its result is untrusted ingress; could egress too.
    category = CATEGORY.UNKNOWN
    boundary = BOUNDARY.BOTH
    reversible = false
    risk = RISK.MEDIUM
    reasons.push('third-party MCP tool')
  } else {
    reasons.push(`unknown tool: ${tool || '(empty)'}`)
  }

  // Path/secret escalation for read/write tools.
  const text = `${inputPath(input)} ${inputText(input)}`
  if (anyMatch(SENSITIVE_PATTERNS, text)) {
    risk = maxRisk(risk, RISK.HIGH)
    boundary = unionBoundary(boundary, BOUNDARY.BOTH)
    reasons.push('touches a sensitive path/secret')
  }

  return finalize(rawTool, category, risk, boundary, reversible, reasons, escalateAt)
}

function finalize(tool, category, risk, boundary, reversible, reasons, escalateAt) {
  return {
    tool,
    category,
    risk,
    boundary,
    reversible,
    verdictHint: verdictForRisk(risk, escalateAt),
    receiptTier: receiptTierFor(risk, boundary),
    reasons,
  }
}
