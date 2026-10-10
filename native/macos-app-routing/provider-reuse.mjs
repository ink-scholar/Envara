import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

export const productionIdentity = Object.freeze({
  hostIdentifier: 'io.envara.app-routing', providerIdentifier: 'io.envara.app-routing.proxy',
  applicationGroup: 'group.io.envara.app-routing', runtimeNamespace: 'production',
});
export const providerRelativePath = 'EnvaraAppRouting.app/Contents/Library/SystemExtensions/io.envara.app-routing.proxy.systemextension';
const binaryRelativePath = 'Contents/MacOS/EnvaraAppProxy';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const sha256 = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

async function regularFile(filename, maximum) {
  const info = await fs.lstat(filename);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > maximum) {
    throw new Error('Provider input must be a bounded, ordinary file.');
  }
  const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (opened.ino !== info.ino || opened.dev !== info.dev || opened.size !== info.size || opened.mode !== info.mode) {
      throw new Error('Provider input changed while opening.');
    }
    const bytes = await handle.readFile(), after = await handle.stat();
    if (after.size !== opened.size || bytes.length !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) {
      throw new Error('Provider input changed while reading.');
    }
    return bytes;
  } finally { await handle.close(); }
}

// Includes directories, permissions and every signed resource. Reject aliases,
// links and special files instead of copying a partially inspected tree.
export async function fingerprintProvider(bundle) {
  bundle = path.resolve(bundle);
  if (await fs.realpath(bundle) !== bundle) throw new Error('Provider bundle path must not contain symbolic links.');
  const root = await fs.lstat(bundle);
  if (!root.isDirectory() || root.isSymbolicLink()) throw new Error('An ordinary provider bundle directory is required.');
  const entries = [];
  let bytes = 0, files = 0;
  async function visit(relative) {
    const current = path.join(bundle, relative), info = await fs.lstat(current);
    if (entries.length >= 4096 || Buffer.byteLength(relative) > 1024 || info.isSymbolicLink()) throw new Error('Unsafe provider bundle tree.');
    const mode = info.mode & 0o777;
    if (info.isDirectory()) {
      entries.push({ path: relative.replaceAll(path.sep, '/'), type: 'directory', mode });
      const names = await fs.readdir(current, { encoding: 'buffer' });
      for (const bytes of names.sort(Buffer.compare)) {
        const name = bytes.toString('utf8');
        if (!Buffer.from(name).equals(bytes) || !name || name === '.' || name === '..' || /[\x00-\x1f\x7f\\/]/.test(name)) {
          throw new Error('Unsafe provider bundle filename.');
        }
        await visit(path.join(relative, name));
      }
    } else if (info.isFile() && info.nlink === 1) {
      if (info.size > 64 * 1024 * 1024 || bytes + info.size > 64 * 1024 * 1024) throw new Error('Provider bundle size exceeds its limit.');
      const data = await regularFile(current, 64 * 1024 * 1024);
      bytes += data.length; files++;
      entries.push({ path: relative.replaceAll(path.sep, '/'), type: 'file', mode, size: data.length, sha256: digest(data) });
    } else { throw new Error('Provider bundle contains a link or special file.'); }
  }
  await visit('');
  const binary = entries.find(item => item.path === binaryRelativePath);
  if (binary?.type !== 'file' || !(binary.mode & 0o111)) throw new Error('Provider executable is missing or not executable.');
  entries.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  const hash = createHash('sha256').update('envara-routing-provider-bundle-v1\0');
  for (const item of entries) {
    hash.update(`${item.path}\0${item.type}\0${item.mode.toString(8).padStart(3, '0')}\0`);
    if (item.type === 'file') hash.update(`${item.size}\0${item.sha256}\0`);
  }
  return { fingerprintVersion: 1, bundleSHA256: hash.digest('hex'), binarySHA256: binary.sha256,
    files, bytes, entries };
}

export function providerRecord(fingerprint, bundle = providerRelativePath) {
  const { fingerprintVersion, bundleSHA256, binarySHA256, files, bytes } = fingerprint;
  return { bundle, fingerprintVersion, bundleSHA256, binarySHA256, files, bytes };
}

export async function readProviderReuse(manifestPath, { mode, architecture = process.arch } = {}) {
  manifestPath = path.resolve(manifestPath);
  if (await fs.realpath(manifestPath) !== manifestPath) throw new Error('Provider manifest path must not contain symbolic links.');
  const manifest = JSON.parse((await regularFile(manifestPath, 1_048_576)).toString('utf8'));
  if (manifest.version !== 1 || manifest.platform !== 'darwin' || manifest.architecture !== architecture ||
      manifest.acceptanceOnly !== false || manifest.signingMode !== mode || manifest.signed !== (mode !== 'unsigned') ||
      manifest.helper !== 'EnvaraAppRouting.app/Contents/MacOS/EnvaraAppRoutingHelper' ||
      Object.entries(productionIdentity).some(([key, value]) => manifest[key] !== value) ||
      manifest.provider?.bundle !== providerRelativePath || manifest.provider.fingerprintVersion !== 1 ||
      !sha256(manifest.provider.binarySHA256) || !sha256(manifest.provider.bundleSHA256) ||
      (mode !== 'unsigned' && manifest.profileVerification?.verified !== true)) {
    throw new Error('An exact matching production provider manifest is required.');
  }
  const bundle = path.join(path.dirname(manifestPath), providerRelativePath);
  const fingerprint = await fingerprintProvider(bundle);
  if (fingerprint.binarySHA256 !== manifest.provider.binarySHA256 || fingerprint.bundleSHA256 !== manifest.provider.bundleSHA256) {
    throw new Error('Provider bytes no longer match the production manifest.');
  }
  // This is byte provenance, not Apple authorization. The build invokes the
  // native Security validator for signed source bundles before any sealing.
  return { manifestPath, manifest, bundle, fingerprint };
}

export async function copyProviderVerbatim(source, destination, expected) {
  const before = await fingerprintProvider(source);
  if (before.bundleSHA256 !== expected.bundleSHA256 || before.binarySHA256 !== expected.binarySHA256) {
    throw new Error('Provider source changed before copying.');
  }
  if (path.resolve(destination) === path.resolve(source)) throw new Error('Provider reuse requires a distinct staging directory.');
  try { await fs.lstat(destination); throw new Error('Provider copy destination already exists.'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  await fs.cp(source, destination, { recursive: true, preserveTimestamps: true, errorOnExist: true, force: false });
  const copied = await fingerprintProvider(destination);
  if (copied.bundleSHA256 !== before.bundleSHA256 || copied.binarySHA256 !== before.binarySHA256) {
    throw new Error('Provider copy changed signed bytes or permissions.');
  }
  const after = await fingerprintProvider(source);
  if (after.bundleSHA256 !== before.bundleSHA256) throw new Error('Provider source changed while copying.');
  return copied;
}

export function validateReceiptProvider(receipt, fingerprint, { osMajor } = {}) {
  if (!receipt || receipt.providerSHA256 !== fingerprint.binarySHA256 ||
      receipt.providerBundleSHA256 !== fingerprint.bundleSHA256 || receipt.providerVersion !== '1' ||
      receipt.passed !== true || typeof receipt.version !== 'string' || !receipt.version ||
      !Number.isInteger(receipt.osMajor) || receipt.osMajor < 13 || (osMajor !== undefined && receipt.osMajor !== osMajor) ||
      !['tcp', 'udp', 'dns', 'childProcesses', 'failClosed'].every(key => receipt.checks?.[key] === true) ||
      !Array.isArray(receipt.testedApplications) || !receipt.testedApplications.length ||
      !receipt.testedApplications.every(value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{1,255}$/.test(value))) {
    throw new Error('The supplied native receipt does not bind the complete tested provider bundle.');
  }
}
