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
    // Unioned into the structural read set by isGitRead(); a signed policy can add a
    // subcommand this file has not heard of. It can never make a destructive form a
    // read — gitDestructiveReason() is checked first.
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
// ── git invocation parsing ──────────────────────────────────────────────────
//
// Two defects motivated this, both found when an agent deleted 41 branches on a
// developer's machine and this floor classified every one as `git read: branch`.
//
// 1. The subcommand was taken positionally, `seg.split(/\s+/)[1]`. Git accepts
//    global options BEFORE the subcommand, so `git -C pkg reset --hard` reported its
//    subcommand as `-c`. That misread the verb and also stopped the elevated-risk
//    regexes matching, because they require `git` immediately followed by it —
//    inserting `-C <path>` downgraded reset --hard, clean -f and push --force from
//    ask to allow. `git -C` is the ordinary way to act on another directory.
//
// 2. Flags were never consulted. `branch` and `tag` sit on the read list because
//    bare `git branch` lists; `git branch -D` force-deletes. Same word, opposite
//    consequence — the predicate was judged by what it meant to match rather than
//    by what it admitted.
//
// Kept in this file rather than a module of its own: classifier.mjs is vendored
// byte-identically into @vaibot/shared, whose src/ is flat, so a separate file
// could not carry the same relative import path in both places.

/**
 * Git's own global options, which may appear before the subcommand.
 * From `git --help`; the value-taking ones consume the following token.
 */
const GLOBAL_WITH_VALUE = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--super-prefix', '--config-env'])
const GLOBAL_BOOLEAN = new Set([
  '-P', '--no-pager', '--paginate', '--bare', '--no-replace-objects',
  '--literal-pathspecs', '--glob-pathspecs', '--noglob-pathspecs', '--icase-pathspecs',
  '--no-optional-locks', '--html-path', '--man-path', '--info-path',
])

/**
 * Resolve a git invocation's real subcommand and its arguments.
 *
 * @param {string} segment one pipeline segment whose leading word is `git`
 * @returns {{sub: string, args: string[]}} `sub` is '' when there is no subcommand
 */
export function parseGitInvocation(segment) {
  const tokens = String(segment ?? '').split(/\s+/).filter(Boolean)
  let i = 0
  // Leading env assignments (FOO=bar git ...), mirroring leadingWord().
  while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) i++
  // The `git` word itself, possibly a path like /usr/bin/git.
  if (i < tokens.length && /(^|\/)git$/i.test(tokens[i])) i++
  // Global options before the subcommand.
  while (i < tokens.length) {
    const t = tokens[i]
    if (!t.startsWith('-')) break
    // `--git-dir=path` / `-C=path` style: value is attached, consumes one token.
    const eq = t.indexOf('=')
    const name = eq === -1 ? t : t.slice(0, eq)
    if (GLOBAL_WITH_VALUE.has(name)) {
      i += eq === -1 ? 2 : 1 // separate value token, or attached
      continue
    }
    if (GLOBAL_BOOLEAN.has(name)) {
      i += 1
      continue
    }
    // An unrecognised option before any subcommand: skip it rather than treat it
    // as the subcommand, which is what produced `git mutating: -c`. Fail toward
    // "I do not know the subcommand" ('' — never a read) rather than a wrong one.
    i += 1
  }
  const sub = (tokens[i] ?? '').toLowerCase()
  return { sub, args: tokens.slice(i + 1) }
}

/** Does this argument list carry any of these short/long flags? */
function hasFlag(args, shorts, longs = []) {
  for (const a of args) {
    if (a === '--') break // everything after `--` is a pathspec, not a flag
    if (a.startsWith('--')) {
      const name = a.split('=')[0]
      if (longs.includes(name)) return true
    } else if (a.startsWith('-') && a.length > 1) {
      // Clustered shorts: -Dr, -fd. Compare character by character.
      for (const ch of a.slice(1)) if (shorts.includes(ch)) return true
    }
  }
  return false
}

/**
 * Forms that destroy work or destroy the ability to recover it.
 *
 * Every entry is on the SAME lane as the `git reset --hard` and `git clean -f`
 * patterns that the floor already elevated — high risk, which asks. Not a hard
 * deny: deleting a merged branch is ordinary hygiene, and a floor that refuses it
 * outright is a floor people switch off. What is not acceptable is doing it
 * silently, with a receipt that says "git read".
 *
 * @param {string} sub resolved subcommand
 * @param {string[]} args tokens after the subcommand
 * @returns {string|null} why it is destructive, or null
 */
export function gitDestructiveReason(sub, args) {
  /** Irreversible: cannot be undone by whoever authorised it. */
  const floor = (reason) => ({ reason, floorAsk: true })
  /** Consequential but recoverable, or routine enough that a preset should decide. */
  const high = (reason) => ({ reason, floorAsk: false })

  switch (sub) {
    case 'branch':
      if (hasFlag(args, ['d', 'D'], ['--delete'])) return floor('deletes a branch (git branch -d/-D)')
      return null
    case 'tag':
      if (hasFlag(args, ['d'], ['--delete'])) return floor('deletes a tag (git tag -d)')
      return null
    case 'checkout':
      // `-b`/`-B` create a branch; harmless.
      if (hasFlag(args, ['b', 'B'], ['--orphan'])) return null
      if (args.includes('--') || args.some((a) => a === '.' || a === './')) {
        return floor('discards uncommitted changes (git checkout -- <path>)')
      }
      if (hasFlag(args, ['f'], ['--force'])) return floor('force checkout discards local changes (git checkout -f)')
      return null
    case 'restore':
      return floor('discards uncommitted changes (git restore)')
    case 'stash':
      if (args[0] === 'drop' || args[0] === 'clear') return floor(`destroys stashed work (git stash ${args[0]})`)
      return null
    case 'reset':
      if (hasFlag(args, [], ['--hard'])) return floor('discards commits and working tree (git reset --hard)')
      return null
    case 'clean':
      if (hasFlag(args, ['f', 'x', 'd'], ['--force'])) return floor('deletes untracked files (git clean -f)')
      return null
    case 'push':
      if (hasFlag(args, ['f'], ['--force', '--force-with-lease', '--delete', '--mirror'])) {
        return floor('rewrites or deletes remote refs (git push --force/--delete)')
      }
      // An ordinary push is consequential but adds commits rather than destroying
      // them, and it is constant in normal work. Left for the preset to judge, which
      // is the behaviour the pre-existing `git push` pattern already had.
      return high('publishes to a remote (git push)')
    case 'submodule':
      // Discards a submodule's working tree, including local commits that were
      // never pushed. Was rated `low`, i.e. allowed on every preset.
      if (args[0] === 'deinit' && hasFlag(args, ['f'], ['--force'])) {
        return floor('discards a submodule working tree (git submodule deinit -f)')
      }
      return null
    // ── the recovery path itself ────────────────────────────────────────────
    // A deleted ref survives in the object store until it is pruned, which is the
    // only reason 41 deleted branches were recoverable. Destroying that is at least
    // as consequential as the deletion it follows.
    case 'reflog':
      if (args[0] === 'expire' || args[0] === 'delete') return floor(`destroys the recovery log (git reflog ${args[0]})`)
      return null
    case 'gc':
      if (hasFlag(args, [], ['--prune', '--aggressive'])) return floor('prunes unreachable objects, ending recoverability (git gc --prune)')
      return null
    case 'filter-branch':
      return floor('rewrites history across refs (git filter-branch)')
    case 'update-ref':
      if (hasFlag(args, ['d'], ['--delete'])) return floor('deletes a ref directly (git update-ref -d)')
      return null
    default:
      return null
  }
}

/**
 * Subcommands that only read, once flags have been taken into account.
 *
 * `branch` and `tag` appear here because bare `git branch` lists — but they reach
 * this only after gitDestructiveReason() has declined, so `git branch -D` never
 * does. A subcommand this does not recognise is NOT a read.
 */
const READ_SUBS = new Set([
  'status', 'log', 'diff', 'show', 'branch', 'remote', 'rev-parse',
  'describe', 'blame', 'tag', 'ls-files', 'cat-file', 'ls-remote',
  'ls-tree', 'show-ref', 'merge-base', 'shortlog', 'count-objects', 'fsck', 'reflog',
])

/**
 * Is this a read-only git invocation? Flags are already accounted for.
 *
 * `extraReadSubs` is the signed policy's `classifierTables.readGitSub`, unioned in
 * so that lever keeps working — a policy can still name a subcommand this file has
 * not heard of as a read. It cannot go the other way: `gitDestructiveReason` is
 * consulted first, so no policy can name a destructive form a read. Narrowing the
 * list no longer removes anything from the read set either, because destructiveness
 * is now decided structurally rather than by absence from a list. Both of those are
 * tightenings.
 */
export function isGitRead(sub, args, extraReadSubs = []) {
  if (!sub) return false
  if (gitDestructiveReason(sub, args)) return false
  if (!READ_SUBS.has(sub) && !extraReadSubs.includes(sub)) return false
  // A read subcommand that writes via a flag is not a read.
  if (sub === 'branch' && hasFlag(args, ['m', 'M', 'c', 'C'], ['--move', '--copy', '--edit-description', '--set-upstream-to', '--unset-upstream'])) return false
  if (sub === 'tag' && (hasFlag(args, ['a', 's', 'f'], ['--annotate', '--sign', '--force']) || args.some((a) => !a.startsWith('-')))) return false
  if (sub === 'reflog' && args[0] && args[0] !== 'show') return false
  return true
}

// ── floorAsk: consequences no preset may make silent ────────────────────────
//
// DANGEROUS denies and cannot be overridden. Everything below it is compared
// against the preset's `escalateAt`, and the `permissive` preset sets that to
// `dangerous` — so a HIGH-risk action resolves to ALLOW there. That is how an agent
// deleted 41 branches with no prompt, and it is also how `npm publish`, `fly deploy`
// and `rm -rf <dir>` run silently on the default production preset.
//
// floorAsk is the missing middle tier: it always ASKS, whatever `escalateAt` says,
// and no preset can lower it. It is not a deny — deleting a merged branch and
// publishing a release are both legitimate. It only means they may not happen
// without someone seeing them.
//
// The bar for entry is deliberately narrow, because a floor that interrupts routine
// work is a floor people switch off: the action cannot be undone by whoever
// authorised it, and it either leaves this machine or destroys the only copy.
// Ordinary `git push`, `gh pr merge`, `fly secrets set` and `psql` are left to the
// presets for exactly that reason.
const FLOOR_ASK_PATTERNS = [
  // Publishing to a registry. A version number can never be reused: npm refuses a
  // re-upload, and a crates.io yank does not remove the crate.
  [/\b(npm|pnpm|yarn)\s+publish\b/i, 'publishes to the npm registry — a version number cannot be reused'],
  [/\bnpm\s+unpublish\b/i, 'removes a published npm version others may depend on'],
  [/\bcargo\s+publish\b/i, 'publishes to crates.io — permanent, a yank does not remove it'],
  [/\bcargo\s+yank\b/i, 'yanks a published crate version'],
  [/\btwine\s+upload\b/i, 'publishes to PyPI — a version number cannot be reused'],
  [/\b(poetry|uv|flit)\s+publish\b/i, 'publishes a Python package — a version number cannot be reused'],

  // Production deploys. Fly's target comes from fly.toml and is invisible in the
  // command, so every `fly deploy` asks rather than guessing which app it hits.
  [/\b(fly|flyctl)\s+deploy\b/i, 'deploys to Fly — the target app comes from fly.toml, not the command'],
  [/\b(vercel|netlify)\b[^|&;]*--prod\b/i, 'deploys to production'],

  // Destruction with no git reflog behind it.
  [/\bshred\b/i, 'overwrites a file so it cannot be recovered'],
  [/\brm\s+(-\S+\s+)*-\S*[rR]/, 'recursive delete — removes a directory tree'],
  [/\bfind\b[^|&;]*\s-delete\b/i, 'deletes every matching file, unbounded by the match'],
  [/\bfind\b[^|&;]*-exec\s+rm\b/i, 'deletes every matching file, unbounded by the match'],
  [/\btruncate\b[^|&;]*-s\s*0\b/i, 'truncates a file to zero bytes'],

  // Deleting a hosted artefact. Irreversible and it affects everyone else, not just
  // this machine — the strongest form of the criterion.
  [/\b(gh|glab)\s+repo\s+delete\b/i, 'deletes a hosted repository'],
  [/\bgh\s+release\s+delete\b/i, 'deletes a published release'],

  // Destroying a secret's only copy. `set`/`add` are additive and the value is in
  // the operator's hands, so they stay with the presets; removal is one-way.
  [/\b(fly|flyctl)\s+secrets\s+(unset|remove)\b/i, 'removes a secret — the value is not recoverable from here'],
  [/\bvercel\s+env\s+(rm|remove)\b/i, 'removes an environment variable'],
  [/\bgh\s+secret\s+(delete|remove)\b/i, 'removes a repository secret'],

  // Resets the database. Unlike a bare `psql`, the command says outright that it is
  // destructive; which environment it points at is not visible either way, which is
  // precisely why it should not be silent.
  [/\bsupabase\s+db\s+reset\b/i, 'resets the database, dropping its contents'],
]

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
  let floorAsk = false

  // floorAsk first. These also imply HIGH, so a receipt is always written
  // (receiptTierFor keys off risk) and the reason names the consequence.
  for (const [re, why] of FLOOR_ASK_PATTERNS) {
    if (re.test(full)) {
      floorAsk = true
      risk = maxRisk(risk, RISK.HIGH)
      category = CATEGORY.WRITE
      boundary = unionBoundary(boundary, BOUNDARY.EGRESS)
      reversible = false
      reasons.push(`irreversible: ${why}`)
      break
    }
  }

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
      // The subcommand is resolved by skipping git's GLOBAL options rather than
      // taken positionally. `git -C pkg reset --hard` used to report its subcommand
      // as `-c`, which misread the verb AND stopped the elevated-risk regexes
      // matching (they require `git` immediately followed by it), so inserting
      // `-C <path>` silently downgraded reset --hard, clean -f and push --force from
      // ask to allow. Flags are consulted too: `git branch` lists, `git branch -D`
      // destroys, and the old read-list keyed on the word alone.
      const { sub, args } = parseGitInvocation(seg)
      const destructive = gitDestructiveReason(sub, args)
      if (destructive) {
        category = CATEGORY.WRITE
        boundary = unionBoundary(boundary, BOUNDARY.EGRESS)
        risk = maxRisk(risk, RISK.HIGH)
        reversible = false
        if (destructive.floorAsk) floorAsk = true
        reasons.push(`git destructive: ${destructive.reason}`)
      } else if (isGitRead(sub, args, tables.readGitSub ?? [])) {
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

  return { category, risk, boundary, reversible, reasons, floorAsk }
}

/**
 * Map a risk level to a verdict hint, given the (per-preset) escalation
 * threshold. DANGEROUS always denies (Tier-0 floor). Otherwise, risk that
 * meets/exceeds `escalateAt` asks; below it allows. Default MEDIUM preserves
 * the prior behavior; the balanced preset raises it to HIGH ("medium = safe").
 */
export function verdictForRisk(risk, escalateAt = RISK.MEDIUM, floorAsk = false) {
  if (risk === RISK.DANGEROUS) return VERDICT.DENY
  // floorAsk — the middle tier. Between "always denied" and "the preset decides"
  // there has to be "never silent": an irreversible action may proceed, but not
  // without someone seeing it. No `escalateAt` can lower this, which is the whole
  // point — `permissive` sets escalateAt to `dangerous`, so without this every
  // HIGH-risk action resolves to ALLOW there.
  if (floorAsk) return VERDICT.ASK
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
    return finalize(rawTool, b.category, b.risk, b.boundary, b.reversible, b.reasons, escalateAt, b.floorAsk)
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

function finalize(tool, category, risk, boundary, reversible, reasons, escalateAt, floorAsk = false) {
  return {
    tool,
    category,
    risk,
    boundary,
    reversible,
    // Surfaced so a caller can tell "the preset asked" from "this may never be
    // silent" — a receipt and an approval prompt want to say different things.
    floorAsk,
    verdictHint: verdictForRisk(risk, escalateAt, floorAsk),
    receiptTier: receiptTierFor(risk, boundary),
    reasons,
  }
}
