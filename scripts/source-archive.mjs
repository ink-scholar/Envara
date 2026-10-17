// Read-only, bounded inspection for the corresponding-source archive we ship.
// No extraction, filesystem writes, command execution or recursive expansion.
import { createReadStream } from 'node:fs';
import path from 'node:path';
import * as zlib from 'node:zlib';

export const SOURCE_ARCHIVE_LIMITS = Object.freeze({ compressedBytes: 64 * 1024 * 1024, expandedBytes: 256 * 1024 * 1024,
  entries: 60000, paxBytes: 64 * 1024 });
const fail = code => { throw Object.assign(new Error(code), { code }); };
const invalid = () => fail('SOURCE_ARCHIVE_INVALID');
const limited = () => fail('SOURCE_ARCHIVE_LIMIT_EXCEEDED');
const crcTable = Array.from({ length: 256 }, (_, number) => {
  for (let bit = 0; bit < 8; bit++) number = number & 1 ? 0xedb88320 ^ number >>> 1 : number >>> 1;
  return number >>> 0;
});
function crc32(bytes) {
  if (zlib.crc32) return zlib.crc32(bytes);
  let crc = 0xffffffff;
  for (const byte of bytes) crc = crcTable[(crc ^ byte) & 255] ^ crc >>> 8;
  return (crc ^ 0xffffffff) >>> 0;
}
function singleGzip(compressed, maximum) {
  const flags = compressed[3]; if (flags & 0xe0) invalid();
  let start = 10;
  if (flags & 4) { if (start + 2 > compressed.length) invalid(); start += 2 + compressed.readUInt16LE(start); }
  for (const flag of [8, 16]) if (flags & flag) {
    const end = compressed.indexOf(0, start); if (end < start || end - start > 65536) invalid(); start = end + 1;
  }
  if (flags & 2) {
    if (start + 2 > compressed.length || (crc32(compressed.subarray(0, start)) & 0xffff) !== compressed.readUInt16LE(start)) invalid(); start += 2;
  }
  if (start >= compressed.length - 8) invalid();
  let result;
  try { result = zlib.inflateRawSync(compressed.subarray(start), { maxOutputLength: maximum, info: true }); }
  catch (error) { if (error.code === 'ERR_BUFFER_TOO_LARGE') limited(); invalid(); }
  const trailer = start + result.engine.bytesWritten, bytes = result.buffer;
  // A second gzip member may carry names/comments even when it expands empty.
  if (!Number.isSafeInteger(trailer) || trailer + 8 !== compressed.length ||
      compressed.readUInt32LE(trailer) !== crc32(bytes) || compressed.readUInt32LE(trailer + 4) !== bytes.length >>> 0) invalid();
  return bytes;
}

async function compressedBytes(input, maximum) {
  if (Buffer.isBuffer(input)) { if (input.length > maximum) limited(); return input; }
  const chunks = []; let length = 0;
  for await (const chunk of createReadStream(input, { highWaterMark: 256 * 1024 })) {
    length += chunk.length; if (length > maximum) limited(); chunks.push(chunk);
  }
  return Buffer.concat(chunks, length);
}
function field(header, start, length) {
  const bytes = header.subarray(start, start + length), zero = bytes.indexOf(0);
  return bytes.subarray(0, zero < 0 ? bytes.length : zero).toString('utf8');
}
function octal(header, start, length) {
  const value = field(header, start, length).trim();
  if (value && !/^[0-7]+$/.test(value)) invalid();
  const number = value ? Number.parseInt(value, 8) : 0;
  if (!Number.isSafeInteger(number) || number < 0) invalid(); return number;
}
function archivePath(value) {
  if (!value || Buffer.byteLength(value) > 4096 || /[\x00-\x1f\x7f\\]/.test(value) || value.startsWith('/') || /^[A-Za-z]:/.test(value) || value.split('/').includes('..')) invalid();
  const normalized = path.posix.normalize(value).replace(/\/$/, '');
  if (!normalized || normalized === '.') invalid(); return normalized;
}
function archiveLink(name, value, hardlink) {
  if (!value || /[\x00-\x1f\x7f\\]/.test(value) || value.startsWith('/') || /^[A-Za-z]:/.test(value)) invalid();
  const resolved = path.posix.normalize(hardlink ? value : path.posix.join(path.posix.dirname(name), value));
  if (resolved === '..' || resolved.startsWith('../') || resolved.startsWith('/') ||
      name.includes('/') && resolved.split('/')[0] !== name.split('/')[0]) invalid();
  return value;
}
function paxFields(bytes, add) {
  const fields = Object.create(null);
  for (let at = 0; at < bytes.length;) {
    const space = bytes.indexOf(32, at);
    if (space < 0 || space - at > 10 || !/^[1-9][0-9]*$/.test(bytes.subarray(at, space).toString())) invalid();
    const length = Number(bytes.subarray(at, space).toString()), end = at + length;
    if (!Number.isSafeInteger(length) || end > bytes.length || end <= space + 2 || bytes[end - 1] !== 10) invalid();
    const record = bytes.subarray(space + 1, end - 1), equals = record.indexOf(61);
    if (equals < 1) invalid();
    const key = record.subarray(0, equals).toString('utf8'), value = record.subarray(equals + 1).toString('utf8');
    if (/[\x00-\x20\x7f]/.test(key) || Object.hasOwn(fields, key)) invalid();
    fields[key] = value;
    if (!['path', 'linkpath', 'size'].includes(key)) {
      add(/xattr|acl|com\.apple|resourcefork|finderinfo/i.test(key) ? 'ARCHIVE_EXTENDED_ATTRIBUTES' : 'ARCHIVE_HOST_METADATA');
    }
    at = end;
  }
  return fields;
}

/** Input is a filename or compressed Buffer. Findings contain rules/counts only.
 * onEntry sees source bytes but this metadata validator does not classify public
 * upstream test credentials as local secrets. Callers must audit content apart.
 * requireClean defaults true so build/cache callers cannot reuse a dirty bundle.
 */
export async function inspectSourceArchive(input, { requireClean = true, onEntry, limits = {} } = {}) {
  const bounds = { ...SOURCE_ARCHIVE_LIMITS, ...limits };
  for (const key of Object.keys(SOURCE_ARCHIVE_LIMITS)) if (!Number.isSafeInteger(bounds[key]) || bounds[key] < 1 || bounds[key] > SOURCE_ARCHIVE_LIMITS[key]) invalid();
  const compressed = await compressedBytes(input, bounds.compressedBytes);
  if (compressed.length < 18 || compressed[0] !== 0x1f || compressed[1] !== 0x8b || compressed[2] !== 8) invalid();
  const counts = new Map(), add = rule => counts.set(rule, (counts.get(rule) ?? 0) + 1);
  // Optional gzip names/comments and timestamps can also carry host metadata.
  if ((compressed[3] & 0x1c) || compressed.readUInt32LE(4) !== 0) add('ARCHIVE_HOST_METADATA');
  const bytes = singleGzip(compressed, bounds.expandedBytes);
  if (bytes.length % 512) invalid();
  let offset = 0, entries = 0, headers = 0, ended = false, pending = Object.create(null), global = Object.create(null);
  const names = new Set();
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512); offset += 512;
    if (header.every(byte => byte === 0)) {
      if (Object.keys(pending).length || bytes.length - offset < 512 || bytes.subarray(offset).some(byte => byte !== 0)) invalid();
      ended = true; break;
    }
    if (++headers > bounds.entries) limited();
    let checksum = 0; for (let index = 0; index < 512; index++) checksum += index >= 148 && index < 156 ? 32 : header[index];
    if (checksum !== octal(header, 148, 8) || field(header, 257, 6) !== 'ustar') invalid();
    const prefix = field(header, 345, 155), rawName = `${prefix ? `${prefix}/` : ''}${field(header, 0, 100)}`;
    archivePath(rawName);
    const uid = octal(header, 108, 8), gid = octal(header, 116, 8), mtime = octal(header, 136, 12);
    if (uid || gid || !['', 'root'].includes(field(header, 265, 32)) || !['', 'root'].includes(field(header, 297, 32))) add('ARCHIVE_ACCOUNT_METADATA');
    if (mtime) add('ARCHIVE_HOST_METADATA');
    const type = header[156] === 0 ? '0' : String.fromCharCode(header[156]);
    let size = octal(header, 124, 12);
    const fields = { ...global, ...pending };
    if (!['x', 'g'].includes(type) && fields.size !== undefined) {
      if (!/^(?:0|[1-9][0-9]*)$/.test(fields.size)) invalid(); size = Number(fields.size);
    }
    if (!Number.isSafeInteger(size) || size < 0 || size > bounds.expandedBytes) limited();
    const padded = Math.ceil(size / 512) * 512;
    if (offset + padded > bytes.length) invalid();
    const content = bytes.subarray(offset, offset + size); offset += padded;
    if (type === 'x' || type === 'g') {
      if (size > bounds.paxBytes) limited();
      const values = paxFields(content, add);
      if (type === 'g') global = { ...global, ...values }; else pending = { ...pending, ...values };
      continue;
    }
    if (!['0', '1', '2', '5'].includes(type)) invalid();
    const name = archivePath(fields.path ?? rawName);
    if (names.has(name)) invalid(); names.add(name); pending = Object.create(null);
    const linkpath = ['1', '2'].includes(type) ? archiveLink(name, fields.linkpath ?? field(header, 157, 100), type === '1') : null;
    if (type !== '0' && size) invalid();
    if (content.length >= 8 && content.readUInt32BE(0) === 0x00051607 && [0x00010000, 0x00020000].includes(content.readUInt32BE(4))) add('ARCHIVE_APPLEDOUBLE');
    else if (name.split('/').some(part => part.startsWith('._') || part === '__MACOSX')) add('ARCHIVE_MACOS_METADATA_NAME');
    entries++;
    if (onEntry) await onEntry({ name, type: ({ '0': 'file', '1': 'hardlink', '2': 'symlink', '5': 'directory' })[type], bytes: content, linkpath });
  }
  if (!ended || !entries) invalid();
  const findings = [...counts].map(([rule, count]) => ({ rule, count })).sort((a, b) => a.rule.localeCompare(b.rule));
  const result = { verified: findings.length === 0, entries, headers, expandedBytes: bytes.length, findings };
  if (requireClean && !result.verified) throw Object.assign(new Error('SOURCE_ARCHIVE_METADATA_REFUSED'), { code: 'SOURCE_ARCHIVE_METADATA_REFUSED', findings });
  return result;
}
