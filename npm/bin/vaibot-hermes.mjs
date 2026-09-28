#!/usr/bin/env node
/**
 * Install the VAIBot Hermes circuit breaker from its PyPI artifact.
 *
 * WHY THIS SHAPE
 *
 * Most people find VAIBot through npm, but this plugin is Python. Three ways to
 * bridge that, and two of them are wrong:
 *
 *   - `postinstall` that shells out to pip. Fails outright on PEP 668 systems
 *     (Ubuntu 23.04+ marks the system Python externally-managed), silently does not
 *     run under `npm ci --ignore-scripts` / pnpm's allowlist / Bun's defaults, picks
 *     whichever interpreter is on PATH rather than the one Hermes uses, and is
 *     exactly the "npm package shells out to a second package manager" pattern that
 *     security scanners flag. For a package whose job is governing an agent, shipping
 *     the behaviour our own guard exists to catch would be a self-inflicted wound.
 *   - Carrying a copy of the Python tree here. That is a second complete artifact in
 *     a second registry, and divergence between copies is how eight vendored guard
 *     versions ended up spanning 1.0.2 to 2.1.0.
 *   - What this does: fetch the wheel from PyPI, verify it against a digest pinned at
 *     npm-publish time, and unpack it. A wheel is a ZIP, so no pip, no interpreter,
 *     no venv guessing, no PEP 668 — and PyPI stays the single source of truth.
 *
 * It is invoked EXPLICITLY. There is no `postinstall` hook: installing a governance
 * plugin into an agent's config directory is something a person should ask for.
 */

import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

import { isSafeEntryName, listEntries, readEntry } from '../lib/unzip.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const ART = JSON.parse(readFileSync(join(HERE, '..', 'lib', 'artifact.json'), 'utf-8'))

const ok = (s) => console.log(`  [ok]   ${s}`)
const step = (s) => console.log(`  [step] ${s}`)
const warn = (s) => console.log(`  [warn] ${s}`)
const fail = (s) => {
  console.error(`  [fail] ${s}`)
  process.exit(1)
}

function usage() {
  console.log(`
VAIBot circuit breaker for Hermes — installer

  npx @vaibot/hermes-circuitbreaker-plugin install [options]

Fetches the plugin's published wheel from PyPI, verifies it against a pinned
SHA-256, and unpacks it where Hermes looks for plugins. No pip, no virtualenv,
and no Python needed to install — a wheel is a zip.

Options
  --dir <path>    Install into <path> instead of ~/.hermes/plugins
  --force         Replace an existing install (a backup is kept)
  --dry-run       Fetch and verify, then stop without writing
  --verify-only   Same as --dry-run
  -h, --help      This text

Installs ${ART.pypiProject} ${ART.version}
`)
}

function parseArgs(argv) {
  const o = { cmd: null, dir: null, force: false, dryRun: false }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '-h' || a === '--help') return { ...o, cmd: 'help' }
    else if (a === 'install' || a === 'verify') o.cmd = a
    else if (a === '--dir') o.dir = argv[++i]
    else if (a === '--force') o.force = true
    else if (a === '--dry-run' || a === '--verify-only') o.dryRun = true
    else if (a.startsWith('-')) fail(`unknown option ${a}`)
  }
  return o
}

async function fetchWheel() {
  step(`Fetching ${ART.filename} from PyPI…`)
  const res = await fetch(ART.url, { redirect: 'follow' })
  if (!res.ok) fail(`PyPI returned HTTP ${res.status} for ${ART.url}`)
  const buf = Buffer.from(await res.arrayBuffer())
  ok(`Downloaded ${(buf.length / 1024).toFixed(0)} KB`)
  return buf
}

/**
 * The gate. A mismatch is a hard stop, never a warning — the pinned digest is fixed
 * at npm-publish time, so if the bytes differ, either the registry is serving
 * something else or the download was tampered with. Neither is a thing to continue
 * through.
 */
function verify(buf) {
  step('Verifying the digest pinned in this package…')
  if (ART.size && buf.length !== ART.size) {
    fail(`size mismatch: expected ${ART.size} bytes, got ${buf.length}`)
  }
  const got = createHash('sha256').update(buf).digest('hex')
  if (got !== ART.sha256) {
    console.error(`  [fail] SHA-256 MISMATCH — refusing to install`)
    console.error(`         expected ${ART.sha256}`)
    console.error(`         got      ${got}`)
    process.exit(1)
  }
  ok(`sha256 ${got.slice(0, 16)}… matches`)
}

function hermesPluginDir(override) {
  if (override) return resolve(override)
  // Hermes discovers plugins from ~/.hermes/plugins/<name>/.
  return join(homedir(), '.hermes', 'plugins')
}

function extractPackageDir(buf, into) {
  const entries = listEntries(buf)
  const prefix = ART.packageDir + '/'
  const wanted = entries.filter((e) => e.name.startsWith(prefix) && !e.name.endsWith('/'))
  if (wanted.length === 0) fail(`the wheel contains no ${prefix} directory`)

  let written = 0
  for (const e of wanted) {
    if (!isSafeEntryName(e.name)) fail(`refusing unsafe entry name: ${e.name}`)
    const rel = e.name.slice(prefix.length)
    const target = join(into, rel)
    // Re-check after resolution: the name test and the path test can disagree on
    // platforms with odd separators, and this is the bug that becomes arbitrary write.
    if (!resolve(target).startsWith(resolve(into) + sep)) {
      fail(`refusing entry that escapes the target directory: ${e.name}`)
    }
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, readEntry(buf, e))
    written++
  }
  return written
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  if (args.cmd === 'help' || (!args.cmd && !args.dryRun)) {
    usage()
    process.exit(args.cmd === 'help' ? 0 : 1)
  }

  console.log(`\nVAIBot circuit breaker for Hermes — ${ART.pypiProject} ${ART.version}\n`)

  const buf = await fetchWheel()
  verify(buf)

  if (args.dryRun || args.cmd === 'verify') {
    const n = listEntries(buf).filter((e) => e.name.startsWith(ART.packageDir + '/') && !e.name.endsWith('/')).length
    ok(`Verified. ${n} files would be installed. Nothing written (--dry-run).`)
    return
  }

  const base = hermesPluginDir(args.dir)
  const dest = join(base, ART.packageDir)

  if (existsSync(dest) && !args.force) {
    warn(`${dest} already exists.`)
    console.log(`         Re-run with --force to replace it (the old copy is kept as a .bak).`)
    process.exit(1)
  }

  // Unpack to a sibling temp dir, then swap. A half-written plugin directory is worse
  // than no plugin: Hermes would try to load it.
  step(`Installing into ${dest}…`)
  mkdirSync(base, { recursive: true })
  const staging = mkdtempSync(join(base, '.vaibot-staging-'))
  let count
  try {
    count = extractPackageDir(buf, staging)
    if (existsSync(dest)) {
      const bak = `${dest}.bak-${Date.now()}`
      renameSync(dest, bak)
      warn(`Existing install moved to ${bak}`)
    }
    renameSync(staging, dest)
  } catch (e) {
    try { rmSync(staging, { recursive: true, force: true }) } catch { /* best effort */ }
    fail(`install failed: ${e.message}`)
  }
  ok(`${count} files installed.`)

  console.log(`
  Next:
    hermes plugins enable vaibot
    /vaibot status          — inside Hermes, to see what is governing the session

  The guard ships inside the plugin, so there is nothing else to install. It needs
  Node on PATH to run. If you already have \`vaibot-guard\` installed, that one is
  used in preference to the bundled copy.
`)
}

main().catch((e) => fail(e?.stack || String(e)))
