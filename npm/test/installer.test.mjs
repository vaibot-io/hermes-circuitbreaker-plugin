/**
 * Tests for the npm installer.
 *
 * Two things carry the weight, and neither involves the network:
 *
 *   1. The ZIP reader is hand-written (Node ships no unzip, and this package has zero
 *      dependencies on purpose). A reader that mis-parses a container is how an
 *      extractor becomes an arbitrary file write, so the zip-slip guard is tested
 *      directly rather than inferred from "it worked on a real wheel".
 *
 *   2. The pinned digest is the whole security model. It has to be a real SHA-256 of
 *      a real artifact, and a mismatch has to stop the install rather than warn.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { deflateRawSync } from 'node:zlib'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { isSafeEntryName, listEntries, readEntry } from '../lib/unzip.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const BIN = join(HERE, '..', 'bin', 'vaibot-hermes.mjs')
const ART = JSON.parse(readFileSync(join(HERE, '..', 'lib', 'artifact.json'), 'utf-8'))

// ── the pinned artifact ─────────────────────────────────────────────────────

test('the pinned artifact is fully specified', () => {
  assert.match(ART.sha256, /^[0-9a-f]{64}$/, 'sha256 must be a real digest')
  assert.notEqual(ART.sha256, '0'.repeat(64), 'placeholder digest left in place')
  assert.match(ART.version, /^\d+\.\d+\.\d+$/)
  assert.ok(ART.url.startsWith('https://files.pythonhosted.org/'), 'must point at PyPI')
  assert.ok(ART.url.endsWith('.whl'), 'must be a wheel, not an sdist — this installer unzips')
  assert.ok(Number.isInteger(ART.size) && ART.size > 0)
  assert.equal(ART.packageDir, 'vaibot')
  // The filename must name the same version the manifest claims, or the installer
  // would verify one artifact and describe another.
  assert.ok(ART.filename.includes(ART.version.replace(/\./g, '.')), 'filename and version disagree')
})

test('the npm version matches the artifact version', () => {
  // These are separate registries with separate numbers, but a wrapper claiming 0.2.0
  // that installs 0.3.1 would be actively misleading.
  const pkg = JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf-8'))
  assert.equal(pkg.version, ART.version, 'package.json and artifact.json disagree on the version')
})

test('nothing declares a runtime dependency', () => {
  // Zero dependencies is the point: this installs a security plugin.
  const pkg = JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf-8'))
  assert.equal(pkg.dependencies, undefined)
  assert.equal(pkg.scripts?.postinstall, undefined, 'there must be no postinstall hook')
})

// ── zip-slip, the bug that matters ──────────────────────────────────────────

test('unsafe entry names are refused', () => {
  for (const bad of [
    '../etc/passwd',
    'vaibot/../../etc/passwd',
    '/etc/passwd',
    '\\windows\\system32',
    'C:/windows/system32',
    'vaibot/..\\..\\x',
    'a\0b',
    '',
  ]) {
    assert.equal(isSafeEntryName(bad), false, `should refuse ${JSON.stringify(bad)}`)
  }
})

test('ordinary entry names are accepted', () => {
  for (const good of ['vaibot/__init__.py', 'vaibot/vendor/vaibot-guard/scripts/classifier.mjs', 'a.b.c']) {
    assert.equal(isSafeEntryName(good), true, `should accept ${good}`)
  }
})

// ── the zip reader, against a zip built here ────────────────────────────────

/** Build a minimal ZIP in memory so the reader is tested without the network. */
function buildZip(files) {
  const locals = []
  const centrals = []
  let offset = 0
  for (const [name, content] of files) {
    const data = Buffer.from(content, 'utf-8')
    const comp = deflateRawSync(data)
    const nameBuf = Buffer.from(name, 'utf-8')
    const crc = 0 // not validated by the reader
    const lfh = Buffer.alloc(30)
    lfh.writeUInt32LE(0x04034b50, 0)
    lfh.writeUInt16LE(20, 4)
    lfh.writeUInt16LE(0, 6)
    lfh.writeUInt16LE(8, 8) // deflate
    lfh.writeUInt32LE(crc, 14)
    lfh.writeUInt32LE(comp.length, 18)
    lfh.writeUInt32LE(data.length, 22)
    lfh.writeUInt16LE(nameBuf.length, 26)
    lfh.writeUInt16LE(0, 28)
    locals.push(lfh, nameBuf, comp)

    const cd = Buffer.alloc(46)
    cd.writeUInt32LE(0x02014b50, 0)
    cd.writeUInt16LE(20, 4)
    cd.writeUInt16LE(20, 6)
    cd.writeUInt16LE(0, 8)
    cd.writeUInt16LE(8, 10)
    cd.writeUInt32LE(crc, 16)
    cd.writeUInt32LE(comp.length, 20)
    cd.writeUInt32LE(data.length, 24)
    cd.writeUInt16LE(nameBuf.length, 28)
    cd.writeUInt32LE(offset, 42)
    centrals.push(cd, nameBuf)
    offset += lfh.length + nameBuf.length + comp.length
  }
  const cdBuf = Buffer.concat(centrals)
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt16LE(files.length, 8)
  eocd.writeUInt16LE(files.length, 10)
  eocd.writeUInt32LE(cdBuf.length, 12)
  eocd.writeUInt32LE(offset, 16)
  return Buffer.concat([Buffer.concat(locals), cdBuf, eocd])
}

test('the reader round-trips a zip it did not build', () => {
  const zip = buildZip([
    ['vaibot/__init__.py', '__version__ = "9.9.9"\n'],
    ['vaibot/sub/thing.py', 'x = 1\n'],
  ])
  const entries = listEntries(zip)
  assert.equal(entries.length, 2)
  assert.deepEqual(entries.map((e) => e.name), ['vaibot/__init__.py', 'vaibot/sub/thing.py'])
  assert.equal(readEntry(zip, entries[0]).toString(), '__version__ = "9.9.9"\n')
  assert.equal(readEntry(zip, entries[1]).toString(), 'x = 1\n')
})

test('a buffer that is not a zip is refused, not mis-parsed', () => {
  assert.throws(() => listEntries(Buffer.alloc(200)), /no end-of-central-directory/)
})

// ── the CLI's contract ──────────────────────────────────────────────────────

function run(args) {
  try {
    return { code: 0, out: execFileSync(process.execPath, [BIN, ...args], { encoding: 'utf-8', stdio: 'pipe' }) }
  } catch (e) {
    return { code: e.status ?? 1, out: (e.stdout || '') + (e.stderr || '') }
  }
}

test('--help exits 0 and names the explicit install command', () => {
  const r = run(['--help'])
  assert.equal(r.code, 0)
  assert.match(r.out, /install/)
  assert.match(r.out, /No pip|no pip/i, 'the help should say why this is not a pip wrapper')
})

test('running with no subcommand exits non-zero rather than doing something', () => {
  // An installer that guesses what you meant is the wrong kind of helpful.
  assert.equal(run([]).code, 1)
})

test('an unknown option is refused', () => {
  assert.equal(run(['install', '--wat']).code, 1)
})
