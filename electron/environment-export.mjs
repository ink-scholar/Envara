// Encrypted environment export: the environment's configuration plus the
// sign-in data it keeps on disk. Tokens held in the macOS Keychain are never
// read, so they are not part of an export.
import path from 'node:path';
import { createReadStream, createWriteStream, constants } from 'node:fs';
import { appendFile, lstat, mkdir, open, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { createCipheriv, createDecipheriv, randomBytes, randomUUID, scrypt as scryptCallback } from 'node:crypto';
import { createGunzip, createGzip } from 'node:zlib';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
export const EXPORT_SCHEMA = 'envara.environment-export';
export const EXPORT_MAGIC = Buffer.from('ENVARAX\x01', 'latin1');
const SALT = 16, IV = 12, TAG = 16, HEADER = EXPORT_MAGIC.length + SALT + IV;
const KDF = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const LIMITS = { entries: 500000, headerBytes: 64 * 1024, manifestBytes: 1024 * 1024, totalBytes: 32 * 1024 ** 3, pathBytes: 4096 };
const SECTION = /^(browser|terminal|app-[0-9]{1,3})$/;

const fail = (message, code) => Object.assign(new Error(message), { code });
const formatError = () => fail('文件不是有效的 Envara 环境导出。', 'EXPORT_FORMAT_INVALID');

export function checkedExportPassword(value) {
  if (typeof value !== 'string' || value.length < 8 || value.length > 256) throw fail('密码至少 8 个字符，最多 256 个字符。', 'EXPORT_PASSWORD_INVALID');
  return value;
}
const derive = (password, salt) => scrypt(password.normalize('NFC'), salt, 32, KDF);

/** True when the file starts with the export header; never reads further. */
export async function isEnvironmentExport(file) {
  const handle = await open(file, 'r');
  try { const head = Buffer.alloc(EXPORT_MAGIC.length); const { bytesRead } = await handle.read(head, 0, head.length, 0);
    return bytesRead === head.length && head.equals(EXPORT_MAGIC); }
  finally { await handle.close(); }
}

function frame(header) {
  const json = Buffer.from(JSON.stringify(header)), length = Buffer.alloc(4);
  if (json.length > (header.manifest ? LIMITS.manifestBytes : LIMITS.headerBytes)) throw fail('导出内容过多。', 'EXPORT_TOO_LARGE');
  length.writeUInt32BE(json.length); return Buffer.concat([length, json]);
}
function safeRelative(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > LIMITS.pathBytes || /[\0\\]/.test(value)) return null;
  return value.split('/').every(part => part && part !== '.' && part !== '..') ? value : null;
}

/* Directories and regular files only; links, sockets and devices are skipped,
 * so an export never follows a link out of the environment's own data. */
async function* walk(source, relative, counters) {
  const directory = relative ? path.join(source.root, ...relative.split('/')) : source.root;
  for (const name of (await readdir(directory)).sort()) {
    const child = relative ? `${relative}/${name}` : name;
    if (source.exclude?.(child, name)) continue;
    if (!safeRelative(child)) throw fail('导出资料含有不支持的文件路径。', 'EXPORT_SOURCE_INVALID');
    const filename = path.join(directory, name), info = await lstat(filename);
    if (!info.isDirectory() && !info.isFile()) continue;
    if (++counters.entries > LIMITS.entries) throw fail('导出内容过多。', 'EXPORT_TOO_LARGE');
    if (info.isDirectory()) { yield frame({ s: source.section, p: child, t: 'd' }); yield* walk(source, child, counters); continue; }
    counters.bytes += info.size;
    if (counters.bytes > LIMITS.totalBytes) throw fail('导出内容过大。', 'EXPORT_TOO_LARGE');
    yield frame({ s: source.section, p: child, t: 'f', x: (info.mode & 0o100) !== 0, z: info.size });
    if (!info.size) continue;
    let read = 0;
    for await (const chunk of createReadStream(filename, { flags: constants.O_RDONLY | constants.O_NOFOLLOW, start: 0, end: info.size - 1 })) {
      read += chunk.length; yield chunk;
    }
    if (read !== info.size) throw fail('有文件在导出时被修改，请停止相关程序后重试。', 'EXPORT_SOURCE_CHANGED');
  }
}
async function* records(manifest, sources, counters) {
  yield frame({ manifest });
  for (const source of sources) {
    if (!SECTION.test(source.section)) throw fail('导出分区无效。', 'EXPORT_SOURCE_INVALID');
    let info; try { info = await lstat(source.root); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
    if (!info.isDirectory() || info.isSymbolicLink()) continue;
    yield* walk(source, '', counters);
  }
  yield frame({ end: true });
}

/** Writes manifest and sources to file, encrypted with AES-256-GCM under a
 * scrypt key. The file appears only once it is complete. */
export async function writeEnvironmentExport({ file, password, manifest, sources = [] }) {
  checkedExportPassword(password);
  if (manifest?.schema !== EXPORT_SCHEMA || manifest.version !== 1) throw fail('导出清单无效。', 'EXPORT_SOURCE_INVALID');
  const salt = randomBytes(SALT), iv = randomBytes(IV), cipher = createCipheriv('aes-256-gcm', await derive(password, salt), iv);
  cipher.setAAD(EXPORT_MAGIC);
  const temporary = `${file}.${randomUUID()}.partial`, counters = { entries: 0, bytes: 0 };
  await writeFile(temporary, Buffer.concat([EXPORT_MAGIC, salt, iv]), { flag: 'wx', mode: 0o600 });
  try {
    await pipeline(Readable.from(records(manifest, sources, counters)), createGzip({ level: 6 }), cipher,
      createWriteStream(temporary, { flags: 'a' }));
    await appendFile(temporary, cipher.getAuthTag());
    const handle = await open(temporary, 'r+');
    try { await handle.sync(); } finally { await handle.close(); }
    await rename(temporary, file);
  } catch (error) { await rm(temporary, { force: true }); throw error; }
  return { entries: counters.entries, bytes: counters.bytes };
}

/** Decrypts into a fresh private staging directory and returns the manifest.
 * Nothing outside staging is written; a wrong password or any altered byte
 * fails authentication and removes everything staged. */
export async function readEnvironmentExport({ file, password, staging }) {
  if (typeof password !== 'string' || !password) throw fail('请输入导出时设置的密码。', 'EXPORT_PASSWORD_INVALID');
  const header = Buffer.alloc(HEADER), tag = Buffer.alloc(TAG);
  const handle = await open(file, 'r');
  let size;
  try {
    size = (await handle.stat()).size;
    if (size <= HEADER + TAG) throw formatError();
    await handle.read(header, 0, HEADER, 0); await handle.read(tag, 0, TAG, size - TAG);
  } finally { await handle.close(); }
  if (!header.subarray(0, EXPORT_MAGIC.length).equals(EXPORT_MAGIC)) throw formatError();
  const salt = header.subarray(EXPORT_MAGIC.length, EXPORT_MAGIC.length + SALT), iv = header.subarray(EXPORT_MAGIC.length + SALT);
  const decipher = createDecipheriv('aes-256-gcm', await derive(password, salt), iv);
  decipher.setAAD(EXPORT_MAGIC); decipher.setAuthTag(tag);
  await mkdir(staging, { mode: 0o700 });
  let manifest = null, ended = false;
  const extract = async function (source) {
    let buffer = Buffer.alloc(0), current = null, entries = 0, total = 0;
    try {
    for await (const chunk of source) {
      buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk;
      for (;;) {
        if (current) {
          if (!buffer.length) break;
          const take = Math.min(current.remaining, buffer.length);
          let written = 0;
          while (written < take) {
            const { bytesWritten } = await current.handle.write(buffer.subarray(written, take));
            if (!Number.isSafeInteger(bytesWritten) || bytesWritten < 1 || bytesWritten > take - written)
              throw fail('导入资料写入失败，请检查磁盘空间和权限。', 'EXPORT_IO_FAILED');
            written += bytesWritten;
          }
          buffer = buffer.subarray(take); current.remaining -= take;
          if (!current.remaining) { await current.handle.close(); current = null; }
          continue;
        }
        if (buffer.length < 4) break;
        const length = buffer.readUInt32BE(0);
        if (length < 2 || length > (manifest ? LIMITS.headerBytes : LIMITS.manifestBytes)) throw formatError();
        if (buffer.length < 4 + length) break;
        let record; try { record = JSON.parse(buffer.subarray(4, 4 + length).toString('utf8')); } catch { throw formatError(); }
        buffer = buffer.subarray(4 + length);
        if (ended) throw formatError();
        if (!manifest) {
          if (record?.manifest?.schema !== EXPORT_SCHEMA || record.manifest.version !== 1) throw formatError();
          manifest = record.manifest; continue;
        }
        if (record?.end === true) { ended = true; continue; }
        const relative = safeRelative(record?.p);
        if (!SECTION.test(record?.s ?? '') || !relative || !['d', 'f'].includes(record.t) || ++entries > LIMITS.entries) throw formatError();
        const target = path.join(staging, record.s, ...relative.split('/'));
        if (record.t === 'd') { await mkdir(target, { recursive: true, mode: 0o700 }); continue; }
        if (!Number.isSafeInteger(record.z) || record.z < 0 || (total += record.z) > LIMITS.totalBytes) throw formatError();
        await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
        const output = await open(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, record.x === true ? 0o700 : 0o600);
        if (record.z) current = { handle: output, remaining: record.z }; else await output.close();
      }
    }
    if (current || buffer.length) throw formatError();
    } finally {
      // Stream authentication, decompression and disk writes can fail while a
      // plaintext file is open. Close it before the outer staging cleanup.
      if (current) await current.handle.close();
    }
  };
  try {
    await pipeline(createReadStream(file, { start: HEADER, end: size - TAG - 1 }), decipher, createGunzip(), extract);
    if (!manifest || !ended) throw formatError();
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    if (['EXPORT_IO_FAILED', 'ENOSPC', 'EDQUOT', 'EACCES', 'EPERM', 'EROFS', 'EIO'].includes(error.code))
      throw fail('导入资料写入失败，请检查磁盘空间和权限。', 'EXPORT_IO_FAILED');
    if (error.code === 'EXPORT_FORMAT_INVALID' && manifest) throw error;
    throw fail('密码不正确，或文件已损坏。', 'EXPORT_PASSWORD_WRONG');
  }
  return manifest;
}
