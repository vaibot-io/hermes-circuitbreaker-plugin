/**
 * A minimal, dependency-free ZIP reader. A wheel is a ZIP file.
 *
 * Node ships no unzip, and every VAIBot breaker has zero runtime dependencies on
 * purpose — this one installs a security plugin, so adding a transitive tree to do it
 * would be the wrong trade. `node:zlib` already has the only hard part (inflate);
 * what is left is the container format, which is about a hundred lines.
 *
 * Deliberately NOT a general-purpose implementation. It reads what a wheel is: no
 * ZIP64, no encryption, no multi-disk, no data descriptors. Each of those is refused
 * explicitly rather than mis-parsed, because a reader that guesses on a malformed
 * archive is worse than one that stops.
 */

import { inflateRawSync } from 'node:zlib'

const EOCD = 0x06054b50 // end of central directory
const CDFH = 0x02014b50 // central directory file header
const LFH = 0x04034b50 // local file header

/** Find the end-of-central-directory record, scanning back over the comment field. */
function findEocd(buf) {
  // The comment can be up to 65535 bytes, so bound the scan rather than the file.
  const min = Math.max(0, buf.length - (22 + 0xffff))
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === EOCD) return i
  }
  throw new Error('not a ZIP archive: no end-of-central-directory record')
}

/**
 * List the entries in a ZIP buffer.
 * @returns {Array<{name: string, method: number, compressedSize: number, size: number, offset: number}>}
 */
export function listEntries(buf) {
  const eocd = findEocd(buf)

  const disk = buf.readUInt16LE(eocd + 4)
  const cdDisk = buf.readUInt16LE(eocd + 6)
  if (disk !== 0 || cdDisk !== 0) throw new Error('multi-disk archives are not supported')

  const count = buf.readUInt16LE(eocd + 10)
  const cdSize = buf.readUInt32LE(eocd + 12)
  const cdOffset = buf.readUInt32LE(eocd + 16)

  // ZIP64 puts 0xffff/0xffffffff sentinels here. A wheel this large is not something
  // to handle by guessing.
  if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    throw new Error('ZIP64 archives are not supported')
  }

  const entries = []
  let p = cdOffset
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== CDFH) throw new Error(`corrupt central directory at entry ${i}`)
    const flags = buf.readUInt16LE(p + 8)
    const method = buf.readUInt16LE(p + 10)
    const compressedSize = buf.readUInt32LE(p + 20)
    const size = buf.readUInt32LE(p + 24)
    const nameLen = buf.readUInt16LE(p + 28)
    const extraLen = buf.readUInt16LE(p + 30)
    const commentLen = buf.readUInt16LE(p + 32)
    const offset = buf.readUInt32LE(p + 42)
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen)

    if (flags & 0x0001) throw new Error(`encrypted entry: ${name}`)
    // Bit 3 means sizes live in a trailing data descriptor rather than the header.
    // Wheels do not use it, and honouring it properly means streaming.
    if (flags & 0x0008) throw new Error(`entry uses a data descriptor: ${name}`)

    entries.push({ name, method, compressedSize, size, offset })
    p += 46 + nameLen + extraLen + commentLen
  }
  return entries
}

/** Inflate one entry's bytes. */
export function readEntry(buf, entry) {
  if (buf.readUInt32LE(entry.offset) !== LFH) throw new Error(`corrupt local header for ${entry.name}`)
  // The local header's extra field can differ in length from the central directory's,
  // so the data offset must come from the local header itself.
  const nameLen = buf.readUInt16LE(entry.offset + 26)
  const extraLen = buf.readUInt16LE(entry.offset + 28)
  const start = entry.offset + 30 + nameLen + extraLen
  const raw = buf.subarray(start, start + entry.compressedSize)

  if (entry.method === 0) return Buffer.from(raw) // stored
  if (entry.method === 8) return inflateRawSync(raw)
  throw new Error(`unsupported compression method ${entry.method} for ${entry.name}`)
}

/**
 * Is this entry name safe to write under a target directory?
 *
 * Zip-slip: an archive can name `../../etc/thing` or an absolute path and walk out of
 * the directory it is being extracted into. Checked on the NAME before any path is
 * built, and the caller re-checks the resolved path — belt and braces, because this
 * is the one bug in an extractor that turns into arbitrary file write.
 */
export function isSafeEntryName(name) {
  if (!name || name.startsWith('/') || name.startsWith('\\')) return false
  if (/^[a-zA-Z]:/.test(name)) return false // windows drive
  if (name.includes('\0')) return false
  return !name.split(/[/\\]/).some((seg) => seg === '..')
}
