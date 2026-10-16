import path from 'node:path';
import { constants } from 'node:fs';
import { open, lstat, opendir, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';

const METADATA_LIMIT = 1024 * 1024;
const CACHE_LIMIT = 128, CACHE_MS = 15000;
const signatureCaches = new WeakMap();
const unsupported = () => ({ supported: false, adapter: 'unsupported', reasonCode: 'APPLICATION_ADAPTER_UNSUPPORTED', dataScope: 'unavailable', verification: 'pending' });
const compatible = () => ({ supported: true, adapter: 'chromium-front', reasonCode: null, dataScope: 'environment', verification: 'pending' });
const invalid = () => Object.assign(new Error('所选软件不存在、不可执行或应用包不完整。'), { code: 'APPLICATION_INVALID_PATH' });
const validPath = value => typeof value === 'string' && path.isAbsolute(value) && value.length <= 8192 && !/[\0\r\n]/.test(value);
const contained = (root, filename) => {
  const relative = path.relative(root, filename);
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
};
const basename = value => typeof value === 'string' && /^[^/\\\0\r\n]{1,255}$/.test(value) && !['.', '..'].includes(value);
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9.-]{1,255}$/.test(value);
const version = value => typeof value === 'string' && value.length <= 64 && /^\d+(?:\.\d+){1,3}$/.test(value);
const identity = info => [info.dev, info.ino, info.size, info.mode, info.nlink, info.mtimeNs, info.ctimeNs].join(':');

function command(filename, args, { input, timeout = 5000, maxBuffer = METADATA_LIMIT } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(filename, args, { timeout, maxBuffer, cwd: '/', env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8' }, (error, stdout) => error ? reject(error) : resolve(stdout));
    child.stdin?.on('error', () => {});
    child.stdin?.end(input);
  });
}

// Parse XML ourselves for catalog scans rather than spawning one process per app.
// This accepts only plist syntax and never resolves a DTD or external entity.
function xmlPlist(content) {
  const xml = content.toString('utf8');
  if (xml.includes('\ufffd')) throw new Error();
  const tokens = xml.match(/<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!DOCTYPE[^>]*>|<[^>]*>|[^<]+/g) ?? [];
  let offset = 0, nodes = 0;
  const text = value => value.replace(/&([^;]+);/g, (_, entity) => {
    const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
    if (Object.hasOwn(named, entity)) return named[entity];
    const numeric = /^#(?:x([a-fA-F0-9]+)|([0-9]+))$/.exec(entity);
    const code = numeric ? Number.parseInt(numeric[1] ?? numeric[2], numeric[1] ? 16 : 10) : -1;
    if (!(code === 9 || code === 10 || code === 13 || code >= 32 && code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff))) throw new Error();
    return String.fromCodePoint(code);
  });
  const skip = () => { while (offset < tokens.length && (/^\s*$/.test(tokens[offset]) || /^(?:<!--|<\?|<!DOCTYPE)/.test(tokens[offset]))) offset++; };
  const string = tag => {
    const start = tokens[offset++];
    if (new RegExp(`^<${tag}\\s*/>$`).test(start)) return '';
    if (start !== `<${tag}>`) throw new Error();
    let value = '';
    while (offset < tokens.length && !tokens[offset].startsWith('<')) value += tokens[offset++];
    if (tokens[offset++] !== `</${tag}>` || /&(?![^;&\s]+;)/.test(value)) throw new Error();
    return text(value);
  };
  const read = depth => {
    skip(); if (depth > 24 || ++nodes > 20000) throw new Error();
    const token = tokens[offset];
    if (token === '<dict>' || /^<dict\s*\/>$/.test(token)) {
      offset++; const result = Object.create(null);
      if (token !== '<dict>') return result;
      for (;;) {
        skip(); if (tokens[offset] === '</dict>') { offset++; return result; }
        const key = string('key');
        if (Object.hasOwn(result, key)) throw new Error();
        result[key] = read(depth + 1);
      }
    }
    if (token === '<array>' || /^<array\s*\/>$/.test(token)) {
      offset++; const result = []; if (token !== '<array>') return result;
      for (;;) { skip(); if (tokens[offset] === '</array>') { offset++; return result; } result.push(read(depth + 1)); }
    }
    if (/^<string(?:>|\s*\/>)/.test(token)) return string('string');
    if (/^<(?:true|false)\s*\/>$/.test(token)) { offset++; return token.startsWith('<true'); }
    for (const tag of ['integer', 'real', 'date', 'data']) if (token === `<${tag}>` || new RegExp(`^<${tag}\\s*/>$`).test(token)) { string(tag); return null; }
    throw new Error();
  };
  skip(); if (!/^<plist(?:\s+version=(?:"1\.0"|'1\.0'))?\s*>$/.test(tokens[offset++] ?? '')) throw new Error();
  const result = read(0); skip(); if (tokens[offset++] !== '</plist>') throw new Error(); skip();
  if (offset !== tokens.length || !result || Array.isArray(result) || typeof result !== 'object') throw new Error();
  return result;
}

async function fileWithin(root, filename, { limit, executable = false, readContent = false } = {}) {
  const canonical = await realpath(filename);
  if (!contained(root, canonical)) throw new Error();
  const handle = await open(canonical, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || limit != null && before.size > BigInt(limit) || executable && !(before.mode & 0o111n)) throw new Error();
    let content = null;
    if (readContent) {
      const buffer = Buffer.alloc(Number(before.size) + 1); let total = 0;
      while (total < buffer.length) {
        const { bytesRead } = await handle.read(buffer, total, buffer.length - total, total);
        if (!bytesRead) break; total += bytesRead;
      }
      if (BigInt(total) !== before.size) throw new Error();
      content = buffer.subarray(0, total);
    }
    const after = await handle.stat({ bigint: true });
    if (identity(before) !== identity(after) || await realpath(filename) !== canonical || identity(await lstat(canonical, { bigint: true })) !== identity(after)) throw new Error();
    return { canonical, identity: identity(after), content };
  } finally { await handle.close(); }
}

async function metadata(root, filename) {
  const file = await fileWithin(root, filename, { limit: METADATA_LIMIT, readContent: true });
  const values = file.content.subarray(0, 6).toString() === 'bplist'
    ? JSON.parse(await command('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '-'], { input: file.content, timeout: 2500 }))
    : xmlPlist(file.content);
  if (!values || typeof values !== 'object' || Array.isArray(values)) throw new Error();
  return { values, fingerprint: `${file.canonical}:${file.identity}:${createHash('sha256').update(file.content).digest('hex')}` };
}

async function macho(root, filename, expectedType, executable = false) {
  const file = await fileWithin(root, filename, { executable });
  const handle = await open(file.canonical, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await handle.stat({ bigint: true });
    if (identity(info) !== file.identity) throw new Error();
    const size = Number(info.size);
    const read = async (length, position) => {
      if (!Number.isSafeInteger(position) || position < 0 || position + length > size) throw new Error();
      const content = Buffer.alloc(length); let total = 0;
      while (total < length) {
        const { bytesRead } = await handle.read(content, total, length - total, position + total);
        if (!bytesRead) throw new Error(); total += bytesRead;
      }
      return content;
    };
    const header = await read(8, 0), magic = header.readUInt32BE(0);
    const thin = async (position, sliceSize = size - position) => {
      const value = await read(16, position), marker = value.readUInt32BE(0);
      const little = marker === 0xcefaedfe || marker === 0xcffaedfe;
      if (![0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(marker) || (little ? value.readUInt32LE(12) : value.readUInt32BE(12)) !== expectedType) throw new Error();
      const headerSize = [0xfeedfacf, 0xcffaedfe].includes(marker) ? 32 : 28;
      const full = await read(headerSize, position), commands = little ? full.readUInt32LE(16) : full.readUInt32BE(16), commandBytes = little ? full.readUInt32LE(20) : full.readUInt32BE(20);
      if (commands > 65536 || commandBytes < commands * 8 || headerSize + commandBytes > sliceSize) throw new Error();
    };
    if ([0xcafebabe, 0xcafebabf, 0xbebafeca, 0xbfbafeca].includes(magic)) {
      const little = magic === 0xbebafeca || magic === 0xbfbafeca, wide = magic === 0xcafebabf || magic === 0xbfbafeca;
      const count = little ? header.readUInt32LE(4) : header.readUInt32BE(4), stride = wide ? 32 : 20;
      if (count < 1 || count > 32) throw new Error();
      const table = await read(count * stride, 8), offsets = new Set();
      for (let index = 0; index < count; index++) {
        const field = index * stride + 8;
        const value = wide ? (little ? table.readBigUInt64LE(field) : table.readBigUInt64BE(field)) : BigInt(little ? table.readUInt32LE(field) : table.readUInt32BE(field));
        const lengthField = field + (wide ? 8 : 4), length = wide ? (little ? table.readBigUInt64LE(lengthField) : table.readBigUInt64BE(lengthField)) : BigInt(little ? table.readUInt32LE(lengthField) : table.readUInt32BE(lengthField));
        const sliceOffset = Number(value), sliceSize = Number(length);
        if (!Number.isSafeInteger(sliceOffset) || !Number.isSafeInteger(sliceSize) || sliceOffset < 8 + count * stride || sliceSize < 28 || sliceOffset + sliceSize > size || offsets.has(sliceOffset)) throw new Error();
        offsets.add(sliceOffset); await thin(sliceOffset, sliceSize);
      }
    } else await thin(0);
    if (identity(await handle.stat({ bigint: true })) !== file.identity || await realpath(filename) !== file.canonical) throw new Error();
    return `${file.canonical}:${file.identity}`;
  } finally { await handle.close(); }
}

async function framework(root, directory, { expectedIdentifier, expectedExecutable }) {
  const canonical = await realpath(directory);
  if (!contained(root, canonical) || !(await lstat(canonical)).isDirectory()) throw new Error();
  const info = await metadata(root, path.join(directory, 'Resources/Info.plist')), values = info.values;
  if (values.CFBundlePackageType !== 'FMWK' || values.CFBundleIdentifier !== expectedIdentifier || values.CFBundleExecutable !== expectedExecutable || !version(values.CFBundleVersion)) throw new Error();
  return [info.fingerprint, await macho(root, path.join(directory, expectedExecutable), 6)];
}

async function frameworkEntries(root, directory) {
  const canonical = await realpath(directory);
  if (!contained(root, canonical)) throw new Error();
  const handle = await opendir(canonical), entries = [];
  try {
    for await (const entry of handle) {
      if (entries.length >= 64) throw new Error();
      entries.push(entry.name);
    }
  } finally { await handle.close().catch(() => {}); }
  return entries;
}

async function vscodeProduct(root, bundleIdentifier) {
  const stable = bundleIdentifier === 'com.microsoft.VSCode';
  const file = await fileWithin(root, path.join(root, 'Contents/Resources/app/product.json'), { limit: METADATA_LIMIT, readContent: true });
  const product = JSON.parse(file.content.toString('utf8'));
  if (!product || typeof product !== 'object' || Array.isArray(product) || product.darwinBundleIdentifier !== bundleIdentifier ||
      product.applicationName !== (stable ? 'code' : 'code-insiders') || product.quality !== (stable ? 'stable' : 'insider')) throw new Error();
  return `${file.canonical}:${file.identity}:${createHash('sha256').update(file.content).digest('hex')}`;
}

async function signedByDeveloper(bundle, { identifier: bundleIdentifier }) {
  try {
    await command('/usr/bin/codesign', ['--verify', '--strict', '--deep', '--all-architectures', `-R=anchor apple generic and identifier "${bundleIdentifier}"`, bundle], { timeout: 15000, maxBuffer: 16384 });
    return true;
  } catch { return false; }
}

async function signatureAccepted(bundle, bundleIdentifier, fingerprint, verifier) {
  let cache = signatureCaches.get(verifier); if (!cache) { cache = new Map(); signatureCaches.set(verifier, cache); }
  const cached = cache.get(bundle), now = Date.now();
  if (cached?.fingerprint === fingerprint && now - cached.at < CACHE_MS) return cached.accepted;
  const accepted = await verifier(bundle, { identifier: bundleIdentifier }) === true;
  cache.delete(bundle); cache.set(bundle, { fingerprint, accepted, at: Date.now() });
  if (cache.size > CACHE_LIMIT) cache.delete(cache.keys().next().value);
  return accepted;
}

/** Adapter eligibility only. Native launch independently rechecks signatures,
 * exports, sealed files, routing and data scope; even a candidate stays pending.
 * Catalog callers must set verifySignature:false to avoid whole-catalog codesign.
 */
export async function inspectApplicationCompatibility(target, { platform = process.platform, verifySignature = true, signatureVerifier = signedByDeveloper } = {}) {
  const descriptor = typeof target === 'string' ? { path: target } : target;
  if (!descriptor || typeof descriptor !== 'object' || Array.isArray(descriptor) || !validPath(descriptor.path) || typeof verifySignature !== 'boolean' || typeof signatureVerifier !== 'function') throw invalid();
  if (platform !== 'darwin') return unsupported();
  let bundle;
  try {
    bundle = await realpath(descriptor.path);
    if (!/\.app$/i.test(bundle) || !(await lstat(bundle)).isDirectory()) throw new Error();
  } catch { throw invalid(); }
  try {
    const main = await metadata(bundle, path.join(bundle, 'Contents/Info.plist')), values = main.values;
    if (values.CFBundlePackageType !== 'APPL' || !identifier(values.CFBundleIdentifier) || !basename(values.CFBundleExecutable) ||
        descriptor.identity != null && descriptor.identity !== `bundle:${values.CFBundleIdentifier}`) return unsupported();
    const mainPath = path.join(bundle, 'Contents/MacOS', values.CFBundleExecutable), fingerprint = [main.fingerprint, await macho(bundle, mainPath, 2, true)];
    if (descriptor.executablePath != null && (!validPath(descriptor.executablePath) || await realpath(descriptor.executablePath) !== await realpath(mainPath))) return unsupported();
    const frameworks = path.join(bundle, 'Contents/Frameworks'), entries = await frameworkEntries(bundle, frameworks);
    if (values.NSPrincipalClass === 'AtomApplication') {
      fingerprint.push(...await framework(bundle, path.join(frameworks, 'Electron Framework.framework'), { expectedIdentifier: 'com.github.Electron.framework', expectedExecutable: 'Electron Framework' }));
    } else if (values.NSPrincipalClass === 'BrowserCrApplication') {
      const candidates = [];
      for (const name of entries.filter(name => /^[A-Za-z0-9 ._-]+\.framework$/.test(name))) {
        try {
          candidates.push(await framework(bundle, path.join(frameworks, name), { expectedIdentifier: `${values.CFBundleIdentifier}.framework`, expectedExecutable: name.slice(0, -'.framework'.length) }));
        } catch { /* Native counts a candidate only after metadata and native
                   * binary checks; a metadata match with a script is ignored. */ }
      }
      if (candidates.length !== 1) return unsupported();
      fingerprint.push(...candidates[0]);
    } else return unsupported();
    if (values.NSPrincipalClass === 'AtomApplication' && ['com.microsoft.VSCode', 'com.microsoft.VSCodeInsiders'].includes(values.CFBundleIdentifier)) fingerprint.push(await vscodeProduct(bundle, values.CFBundleIdentifier));
    // This cache is advisory only. The native boundary validates the complete
    // signature on every launch, including resources outside these known pins.
    try { const seal = await fileWithin(bundle, path.join(bundle, 'Contents/_CodeSignature/CodeResources')); fingerprint.push(`${seal.canonical}:${seal.identity}`); } catch (error) { if (error.code !== 'ENOENT') return unsupported(); }
    if (verifySignature && !await signatureAccepted(bundle, values.CFBundleIdentifier, fingerprint.join('\n'), signatureVerifier)) return unsupported();
    return compatible();
  } catch { return unsupported(); }
}
