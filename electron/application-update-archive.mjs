import path from 'node:path';
import { createHash, timingSafeEqual } from 'node:crypto';
import { constants } from 'node:fs';
import { Readable } from 'node:stream';
import * as zlib from 'node:zlib';
import { chmod, lstat, mkdir, open, realpath, rm, symlink, unlink } from 'node:fs/promises';
import unzipper from 'unzipper';

const DEFAULT_EXPANDED = 3 * 1024 ** 3;
const MAX_DIRECTORY_BYTES = 64 * 1024 ** 2;
const MAX_PATH_BYTES = 4096;
const BUNDLE = 'Envara.app';
const decoder = new TextDecoder('utf-8', { fatal: true });
const fail = code => Object.assign(new Error('应用更新压缩包无法安全解压。'), { code });
const invalid = () => fail('APPLICATION_UPDATE_ARCHIVE_INVALID');
const safeInteger = value => Number.isSafeInteger(value) && value >= 0;
const identityKeys = ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'];
const sameFile = (a, b) => identityKeys.every(key => a[key] === b[key]);
const owned = info => typeof process.getuid !== 'function' || info.uid === BigInt(process.getuid());
const regular = info => info.isFile() && !info.isSymbolicLink() && info.nlink === 1n && owned(info);
const fold = value => value.normalize('NFC').toLowerCase().toUpperCase().normalize('NFC');
const unsafeCharacters = /[\u0000-\u001f\u007f-\u009f\\:]/u;

function checkAbort(signal) {
  if (signal?.aborted) throw fail('APPLICATION_UPDATE_CANCELLED');
}
function text(bytes) {
  try { return decoder.decode(bytes); } catch { throw invalid(); }
}
function memberPath(bytes, directory) {
  const value = text(bytes);
  if (!value || Buffer.byteLength(value) > MAX_PATH_BYTES || unsafeCharacters.test(value) || value.startsWith('/')) throw invalid();
  const result = directory && value.endsWith('/') ? value.slice(0, -1) : value;
  const parts = result.split('/');
  if (parts[0] !== BUNDLE || parts.length > 128 || parts.some(part => !part || part === '.' || part === '..' || Buffer.byteLength(part) > 255)) throw invalid();
  if (result !== BUNDLE && !result.startsWith(`${BUNDLE}/`)) throw invalid();
  return result;
}
function linkTarget(bytes) {
  const value = text(bytes);
  if (!value || Buffer.byteLength(value) > MAX_PATH_BYTES || unsafeCharacters.test(value) || value.startsWith('/') ||
      value.split('/').some(part => !part || Buffer.byteLength(part) > 255)) throw invalid();
  return value;
}
async function bytesAt(handle, length, position, size) {
  if (!safeInteger(length) || !safeInteger(position) || position + length > size) throw invalid();
  const bytes = Buffer.alloc(length); let offset = 0;
  while (offset < length) {
    const result = await handle.read(bytes, offset, length - offset, position + offset);
    if (!result.bytesRead) throw invalid();
    offset += result.bytesRead;
  }
  return bytes;
}
function uint64(bytes, offset) {
  const value = bytes.readBigUInt64LE(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw invalid();
  return Number(value);
}

// Bound the directory before unzipper allocates its entry array (including ZIP64).
async function directoryBounds(handle, size, maxEntries, signal) {
  if (size < 22) throw invalid();
  const tailStart = Math.max(0, size - 65557), tail = await bytesAt(handle, size - tailStart, tailStart, size);
  let index = -1;
  for (let i = tail.length - 22; i >= 0; i--) if (tail.readUInt32LE(i) === 0x06054b50 && i + 22 + tail.readUInt16LE(i + 20) === tail.length) { index = i; break; }
  if (index < 0) throw invalid();
  const end = tail.subarray(index), endOffset = tailStart + index;
  if (end.readUInt16LE(4) !== 0 || end.readUInt16LE(6) !== 0) throw invalid();
  let count = end.readUInt16LE(10), length = end.readUInt32LE(12), start = end.readUInt32LE(16), boundary = endOffset;
  if (end.readUInt16LE(8) !== count) throw invalid();
  if (count === 0xffff || length === 0xffffffff || start === 0xffffffff) {
    const locator = await bytesAt(handle, 20, endOffset - 20, size);
    if (locator.readUInt32LE(0) !== 0x07064b50 || locator.readUInt32LE(4) !== 0 || locator.readUInt32LE(16) !== 1) throw invalid();
    const zip64Offset = uint64(locator, 8), record = await bytesAt(handle, 56, zip64Offset, size);
    if (record.readUInt32LE(0) !== 0x06064b50 || uint64(record, 4) < 44 || zip64Offset + 12 + uint64(record, 4) !== endOffset - 20 ||
        record.readUInt32LE(16) !== 0 || record.readUInt32LE(20) !== 0 || uint64(record, 24) !== uint64(record, 32)) throw invalid();
    count = uint64(record, 32); length = uint64(record, 40); start = uint64(record, 48); boundary = zip64Offset;
  }
  if (!count || count > maxEntries || length < count * 46 || length > MAX_DIRECTORY_BYTES || start + length !== boundary) throw invalid();
  let cursor = start;
  for (let i = 0; i < count; i++) {
    checkAbort(signal);
    const header = await bytesAt(handle, 46, cursor, size);
    if (header.readUInt32LE(0) !== 0x02014b50) throw invalid();
    const nameLength = header.readUInt16LE(28), extraLength = header.readUInt16LE(30), commentLength = header.readUInt16LE(32);
    if (!nameLength || nameLength > MAX_PATH_BYTES || header.readUInt16LE(34) !== 0) throw invalid();
    validateExtra(await bytesAt(handle, extraLength, cursor + 46 + nameLength, size));
    cursor += 46 + nameLength + extraLength + commentLength;
    if (cursor > start + length) throw invalid();
  }
  if (cursor !== start + length) throw invalid();
  return { count, start, tailSize: size - endOffset };
}

function validateExtra(bytes) {
  for (let offset = 0; offset < bytes.length;) {
    if (offset + 4 > bytes.length) throw invalid();
    const kind = bytes.readUInt16LE(offset), length = bytes.readUInt16LE(offset + 2);
    // Unix link/device metadata must never introduce a second interpretation.
    if ([0x000d, 0x756e].includes(kind) || offset + 4 + length > bytes.length) throw invalid();
    offset += 4 + length;
  }
}
async function localRecord(handle, entry, size, directoryStart) {
  const position = entry.offsetToLocalFileHeader;
  const header = await bytesAt(handle, 30, position, size);
  if (header.readUInt32LE(0) !== 0x04034b50 || header.readUInt16LE(6) !== entry.flags || header.readUInt16LE(8) !== entry.compressionMethod) throw invalid();
  const nameLength = header.readUInt16LE(26), extraLength = header.readUInt16LE(28);
  const name = await bytesAt(handle, nameLength, position + 30, size);
  if (!name.equals(entry.pathBuffer)) throw invalid();
  validateExtra(await bytesAt(handle, extraLength, position + 30 + nameLength, size));
  const end = position + 30 + nameLength + extraLength + entry.compressedSize;
  if (end > directoryStart) throw invalid();
  if (!(entry.flags & 8) && (header.readUInt32LE(14) !== entry.crc32 ||
      ![entry.compressedSize, 0xffffffff].includes(header.readUInt32LE(18)) || ![entry.uncompressedSize, 0xffffffff].includes(header.readUInt32LE(22)))) throw invalid();
  return { start: position, end };
}

const crcTable = Uint32Array.from({ length: 256 }, (_, index) => {
  let value = index; for (let i = 0; i < 8; i++) value = value & 1 ? 0xedb88320 ^ value >>> 1 : value >>> 1; return value >>> 0;
});
function crcUpdate(crc, bytes) {
  if (typeof zlib.crc32 === 'function') return (zlib.crc32(bytes, (crc ^ 0xffffffff) >>> 0) ^ 0xffffffff) >>> 0;
  for (const value of bytes) crc = crcTable[(crc ^ value) & 255] ^ crc >>> 8;
  return crc >>> 0;
}

async function consume(entry, { handle, signal, account, maximum, archiveStable, readFailure }) {
  checkAbort(signal); await archiveStable();
  let length = 0, crc = 0xffffffff; const chunks = handle ? null : [];
  // A zero-byte stored entry has no data stream; this also avoids unzipper's
  // descriptor scan for zero-byte entries with general-purpose bit 3 set.
  const stream = entry.compressedSize || entry.uncompressedSize ? entry.stream() : null;
  const abort = () => stream?.destroy(fail('APPLICATION_UPDATE_CANCELLED'));
  signal?.addEventListener('abort', abort, { once: true });
  try {
    if (stream) await Promise.race([(async () => {
      for await (const chunk of stream) {
        checkAbort(signal); length += chunk.length; account.bytes += chunk.length;
        if (length > entry.uncompressedSize || length > maximum || account.bytes > account.maximum) throw invalid();
        crc = crcUpdate(crc, chunk);
        if (handle) await handle.writeFile(chunk); else chunks.push(chunk);
      }
    })(), readFailure]);
    if (length !== entry.uncompressedSize || (crc ^ 0xffffffff) >>> 0 !== entry.crc32) throw invalid();
    await archiveStable(); checkAbort(signal);
    return chunks ? Buffer.concat(chunks) : null;
  } finally { signal?.removeEventListener('abort', abort); stream?.destroy(); }
}

function resolveLink(name, nodes) {
  const resolve = (parts, seen = new Set(), budget = { remaining: 40 }) => {
    let resolved = [];
    for (let index = 0; index < parts.length; index++) {
      const part = parts[index];
      if (part === '.') continue;
      if (part === '..') { if (resolved.length <= 1) throw invalid(); resolved.pop(); continue; }
      resolved.push(part);
      const node = nodes.get(resolved.join('/'));
      if (!node) throw invalid();
      if (node.kind === 'symlink') {
        if (seen.has(node.name) || --budget.remaining < 0) throw invalid();
        resolved = resolve([...resolved.slice(0, -1), ...node.target.split('/')], new Set([...seen, node.name]), budget);
      }
      if (index < parts.length - 1 && nodes.get(resolved.join('/'))?.kind !== 'directory') throw invalid();
    }
    if (resolved[0] !== BUNDLE) throw invalid();
    return resolved;
  };
  return resolve(name.split('/'));
}

function validateDirectoryLinks(nodes, links) {
  const edges = new Map([...nodes.values()].filter(node => node.kind === 'directory').map(node => [node.name, []]));
  for (const name of edges.keys()) if (name !== BUNDLE) edges.get(path.posix.dirname(name)).push(name);
  for (const node of links) {
    const target = resolveLink(node.name, nodes).join('/');
    if (nodes.get(target)?.kind === 'directory') edges.get(path.posix.dirname(node.name)).push(target);
  }
  const colour = new Map();
  for (const name of edges.keys()) {
    if (colour.get(name) === 2) continue;
    const stack = [{ name, next: 0 }]; colour.set(name, 1);
    while (stack.length) {
      const frame = stack.at(-1), children = edges.get(frame.name);
      if (frame.next === children.length) { colour.set(frame.name, 2); stack.pop(); continue; }
      const child = children[frame.next++];
      if (colour.get(child) === 1) throw invalid();
      if (colour.get(child) !== 2) { colour.set(child, 1); stack.push({ name: child, next: 0 }); }
    }
  }
}

/** Extract only a verified Envara.app into a fresh destination. The caller owns
 * its existing private staging parent. This function owns and cleans only the
 * destination it creates. No program is executed and no library extract() is used.
 */
export async function extractApplicationUpdate({ archivePath, destination, sha256, maxExpandedBytes = DEFAULT_EXPANDED,
  maxEntries = 100000, signal } = {}) {
  if (typeof archivePath !== 'string' || typeof destination !== 'string' || !path.isAbsolute(archivePath) || !path.isAbsolute(destination) ||
      path.resolve(destination) !== destination || /[\0\r\n]/.test(archivePath + destination) || !/^[a-fA-F0-9]{64}$/.test(sha256 ?? '') ||
      !Number.isSafeInteger(maxExpandedBytes) || maxExpandedBytes < 1 || maxExpandedBytes > DEFAULT_EXPANDED ||
      !Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > 100000 ||
      signal && (typeof signal.aborted !== 'boolean' || typeof signal.addEventListener !== 'function')) throw invalid();
  let source, copy, stageIdentity, archiveHandle, succeeded = false;
  const archiveStreams = new Set();
  const stopArchiveStreams = async () => Promise.all([...archiveStreams].map(stream => new Promise(resolve => {
    if (stream.closed) return resolve();
    stream.once('close', resolve); stream.destroy();
  })));
  const parent = path.dirname(destination), copyPath = path.join(destination, '.verified-update.zip');
  try {
    checkAbort(signal);
    const parentInfo = await lstat(parent, { bigint: true });
    if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink() || !owned(parentInfo) || parentInfo.mode & 0o077n || await realpath(parent) !== parent) throw invalid();
    const original = await lstat(archivePath, { bigint: true });
    if (!regular(original) || original.mode & 0o022n || original.size > BigInt(maxExpandedBytes + MAX_DIRECTORY_BYTES) || await realpath(archivePath) !== archivePath) throw invalid();
    source = await open(archivePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    if (!sameFile(original, await source.stat({ bigint: true }))) throw invalid();
    await mkdir(destination, { mode: 0o700 }); stageIdentity = await lstat(destination, { bigint: true });
    copy = await open(copyPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const hash = createHash('sha256'), input = source.createReadStream({ autoClose: false, start: 0, end: Number(original.size) });
    let copied = 0;
    const abortCopy = () => input.destroy(fail('APPLICATION_UPDATE_CANCELLED'));
    signal?.addEventListener('abort', abortCopy, { once: true });
    try { for await (const chunk of input) {
      checkAbort(signal); copied += chunk.length;
      if (copied > Number(original.size)) throw invalid();
      hash.update(chunk); await copy.writeFile(chunk);
    } }
    finally { signal?.removeEventListener('abort', abortCopy); if (!input.readableEnded) input.destroy(); }
    if (copied !== Number(original.size) || !sameFile(original, await source.stat({ bigint: true })) || !sameFile(original, await lstat(archivePath, { bigint: true })) ||
        !timingSafeEqual(hash.digest(), Buffer.from(sha256, 'hex'))) throw invalid();
    await copy.sync(); await copy.close(); copy = null; await source.close(); source = null;
    archiveHandle = await open(copyPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const verified = await archiveHandle.stat({ bigint: true }), size = Number(verified.size);
    const archiveStable = async () => {
      checkAbort(signal);
      if (!sameFile(verified, await lstat(copyPath, { bigint: true })) || !sameFile(verified, await archiveHandle.stat({ bigint: true }))) throw invalid();
    };
    const bounds = await directoryBounds(archiveHandle, size, maxEntries, signal);
    // Open.file hides the file streams and entry.destroy() does not close them.
    // Supply bounded reads from the held verified descriptor instead, so every
    // stream remains owned and can be stopped on corruption or cancellation.
    let failRead;
    const readFailure = new Promise((_resolve, reject) => { failRead = reject; });
    readFailure.catch(() => {});
    const archive = await Promise.race([unzipper.Open.custom({
      size: async () => size,
      stream(start, length) {
        const stream = Readable.from((async function* () {
          if (!safeInteger(start) || start > size || length !== undefined && !safeInteger(length)) throw invalid();
          const end = length === undefined ? size : Math.min(size, start + length);
          for (let offset = start; offset < end;) {
            checkAbort(signal);
            const chunk = await bytesAt(archiveHandle, Math.min(65536, end - offset), offset, size);
            if (stream.destroyed) return;
            offset += chunk.length; yield chunk;
          }
        })());
        archiveStreams.add(stream);
        stream.once('error', failRead);
        stream.once('close', () => archiveStreams.delete(stream));
        return stream;
      },
    }, { tailSize: bounds.tailSize }), readFailure]);
    await archiveStable();
    if (archive.files.length !== bounds.count) throw invalid();
    const nodes = new Map(), aliases = new Map(), declared = new Set(), ranges = []; let expanded = 0;
    const add = node => {
      const key = fold(node.name), alias = aliases.get(key);
      if (alias && alias !== node.name) throw invalid();
      const existing = nodes.get(node.name);
      if (existing && (existing.kind !== 'directory' || node.kind !== 'directory')) throw invalid();
      if (!existing && nodes.size >= maxEntries) throw invalid();
      if (existing?.entry && !node.entry) return;
      aliases.set(key, node.name); nodes.set(node.name, { ...existing, ...node });
    };
    for (const entry of archive.files) {
      checkAbort(signal);
      const mode = entry.externalFileAttributes >>> 16, type = mode & 0o170000;
      if (entry.versionMadeBy >>> 8 !== 3 || ![0o100000, 0o040000, 0o120000].includes(type) ||
          ![0, 8].includes(entry.compressionMethod) || entry.flags & ~0x080e ||
          !safeInteger(entry.uncompressedSize) || !safeInteger(entry.compressedSize) || !safeInteger(entry.offsetToLocalFileHeader) ||
          entry.uncompressedSize > maxExpandedBytes || entry.compressedSize > size) throw invalid();
      const kind = type === 0o040000 ? 'directory' : type === 0o120000 ? 'symlink' : 'file';
      const name = memberPath(entry.pathBuffer, kind === 'directory');
      if (declared.has(fold(name)) || name === BUNDLE && kind !== 'directory' || kind === 'directory' && (entry.uncompressedSize !== 0 || entry.crc32 !== 0) ||
          kind === 'symlink' && (entry.uncompressedSize === 0 || entry.uncompressedSize > MAX_PATH_BYTES)) throw invalid();
      declared.add(fold(name)); expanded += entry.uncompressedSize;
      if (!safeInteger(expanded) || expanded > maxExpandedBytes) throw invalid();
      ranges.push(await localRecord(archiveHandle, entry, size, bounds.start));
      const parts = name.split('/');
      for (let i = 1; i < parts.length; i++) add({ name: parts.slice(0, i).join('/'), kind: 'directory', mode: 0o755 });
      add({ name, kind, mode, entry });
    }
    ranges.sort((a, b) => a.start - b.start);
    for (let i = 1; i < ranges.length; i++) if (ranges[i].start < ranges[i - 1].end) throw invalid();
    if (nodes.get(BUNDLE)?.kind !== 'directory') throw invalid();
    const account = { bytes: 0, maximum: maxExpandedBytes }, links = [...nodes.values()].filter(node => node.kind === 'symlink');
    for (const node of links) node.target = linkTarget(await consume(node.entry, { signal, account, maximum: MAX_PATH_BYTES, archiveStable, readFailure }));
    validateDirectoryLinks(nodes, links);
    const directories = [...nodes.values()].filter(node => node.kind === 'directory').sort((a, b) => a.name.split('/').length - b.name.split('/').length);
    for (const node of directories) {
      checkAbort(signal); await mkdir(path.join(destination, node.name), { mode: 0o700 });
      if (node.entry) await consume(node.entry, { signal, account, maximum: 0, archiveStable, readFailure });
    }
    for (const node of nodes.values()) if (node.kind === 'file') {
      checkAbort(signal);
      const output = await open(path.join(destination, node.name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try {
        await consume(node.entry, { handle: output, signal, account, maximum: maxExpandedBytes, archiveStable, readFailure });
        await output.chmod(0o600 | node.mode & 0o155); await output.sync();
      } finally { await output.close(); }
    }
    for (const node of links) { checkAbort(signal); await symlink(node.target, path.join(destination, node.name)); }
    for (const node of directories.reverse()) await chmod(path.join(destination, node.name), 0o700 | node.mode & 0o055);
    await archiveStable(); checkAbort(signal);
    await stopArchiveStreams(); await archiveHandle.close(); archiveHandle = null; await unlink(copyPath);
    succeeded = true; return path.join(destination, BUNDLE);
  } catch (error) {
    if (error?.code === 'APPLICATION_UPDATE_CANCELLED' || signal?.aborted) throw fail('APPLICATION_UPDATE_CANCELLED');
    throw invalid();
  } finally {
    await stopArchiveStreams();
    await source?.close().catch(() => {}); await copy?.close().catch(() => {}); await archiveHandle?.close().catch(() => {});
    if (!succeeded && stageIdentity) {
      try {
        const current = await lstat(destination, { bigint: true }).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
        if (current) {
          if (!current.isDirectory() || current.isSymbolicLink() || current.dev !== stageIdentity.dev || current.ino !== stageIdentity.ino) throw invalid();
          await rm(destination, { recursive: true, force: true });
        }
      } catch { throw fail('APPLICATION_UPDATE_ARCHIVE_CLEANUP_FAILED'); }
    }
  }
}
