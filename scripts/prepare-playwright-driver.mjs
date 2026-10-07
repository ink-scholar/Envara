import { createHash, randomUUID } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import { access, chmod, copyFile, cp, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { gunzipSync, inflateRawSync } from 'node:zlib';

const execFile = promisify(execFileCallback);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DRIVER_VERSION = '1.61.1';
export const NODE_VERSION = '24.18.0';
export const GO_WRAPPER_VERSION = 'v0.6100.0';
const NPM_INTEGRITY = 'sha512-h7Qlt6m4REp25qvIdvbDtVmD4LqVXfpRxhORv9L0jzETM05p4fuPJ3dKyuSXQxDSbXnmS79HAgi9589lGSpLkg==';
const WRAPPER_COMMIT = '1c4f6330ed40337c3582539dbeb2a42ff73d01f6';
const NODE_SHA256 = {
  'darwin-arm64': 'e1a97e14c99c803e96c7339403282ea05a499c32f8d83defe9ef5ec66f979ed1',
  'darwin-x64': 'dfd0dbd3e721503434df7b7205e719f61b3a3a31b2bcf9729b8b91fea240f080',
  'linux-arm64': '6b4484c2190274175df9aa8f28e2d758a819cb1c1fe6ab481e2f95b463ab8508',
  'linux-x64': '783130984963db7ba9cbd01089eaf2c2efb055c7c1693c943174b967b3050cb8',
  'win-arm64': 'f274669adb93b1fd0fbf8f21fd078609e9dcc84333d4f2718d2dde3f9a161a01',
  'win-x64': '0ae68406b42d7725661da979b1403ec9926da205c6770827f33aac9d8f26e821',
};

export function driverArtifacts(platform = process.platform, arch = process.arch) {
  const nodePlatform = platform === 'win32' ? 'win' : platform;
  const suffix = `${nodePlatform}-${arch}`;
  if (!NODE_SHA256[suffix]) throw new Error(`No pinned Node artifact for ${platform}/${arch}.`);
  const directory = `node-v${NODE_VERSION}-${suffix}`;
  const extension = platform === 'win32' ? 'zip' : 'tar.gz';
  return {
    platform, arch, nodeExecutable: platform === 'win32' ? 'node.exe' : 'node',
    packageUrl: `https://registry.npmjs.org/playwright-core/-/playwright-core-${DRIVER_VERSION}.tgz`,
    packageIntegrity: NPM_INTEGRITY,
    nodeUrl: `https://nodejs.org/dist/v${NODE_VERSION}/${directory}.${extension}`,
    nodeArchiveSha256: NODE_SHA256[suffix], nodeArchiveDirectory: directory,
    nodeArchiveExecutable: platform === 'win32' ? `${directory}/node.exe` : `${directory}/bin/node`,
    nodeArchiveLicense: `${directory}/LICENSE`, extension,
  };
}

export function verifyIntegrity(bytes, expected) {
  const separator = expected.indexOf('-');
  const algorithm = separator > 0 ? expected.slice(0, separator) : 'sha256';
  const wanted = separator > 0 ? expected.slice(separator + 1) : expected;
  const actual = createHash(algorithm).update(bytes).digest(separator > 0 ? 'base64' : 'hex');
  if (actual !== wanted) throw new Error(`Artifact ${algorithm} integrity check failed.`);
  return actual;
}

export function safeArchivePath(name) {
  if (typeof name !== 'string' || !name || name.includes('\0') || name.includes('\\') ||
      name.startsWith('/') || /^[A-Za-z]:/.test(name) || name.split('/').includes('..')) {
    throw new Error('Unsafe archive path.');
  }
  return name;
}

function tarString(header, offset, length) {
  return header.subarray(offset, offset + length).toString('utf8').split('\0')[0];
}

/** Reads regular files only. Official package archives contain no needed links. */
export function tarGzFiles(archive) {
  const bytes = gunzipSync(archive);
  const files = new Map();
  for (let offset = 0; offset + 512 <= bytes.length;) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const prefix = tarString(header, 345, 155);
    const name = safeArchivePath(`${prefix ? `${prefix}/` : ''}${tarString(header, 0, 100)}`);
    const sizeField = tarString(header, 124, 12).trim();
    if (!/^[0-7]+$/.test(sizeField)) throw new Error('Unsupported tar size.');
    const size = Number.parseInt(sizeField, 8);
    const dataOffset = offset + 512;
    if (!Number.isSafeInteger(size) || size < 0 || dataOffset + size > bytes.length) throw new Error('Truncated tar archive.');
    const type = header[156];
    if (type === 0 || type === 48) {
      files.set(name, bytes.subarray(dataOffset, dataOffset + size));
    }
    offset = dataOffset + Math.ceil(size / 512) * 512;
  }
  return files;
}

/** Extracts selected small entries from the official Windows Node ZIP. */
export function selectedZipFiles(bytes, selected) {
  let end = -1;
  for (let offset = bytes.length - 22; offset >= Math.max(0, bytes.length - 65557); offset -= 1) {
    if (bytes.readUInt32LE(offset) === 0x06054b50) { end = offset; break; }
  }
  if (end < 0 || bytes.readUInt16LE(end + 4) !== 0 || bytes.readUInt16LE(end + 6) !== 0) throw new Error('Unsupported ZIP archive.');
  const count = bytes.readUInt16LE(end + 10);
  let offset = bytes.readUInt32LE(end + 16);
  const result = new Map();
  for (let entry = 0; entry < count; entry += 1) {
    if (offset + 46 > bytes.length || bytes.readUInt32LE(offset) !== 0x02014b50) throw new Error('Invalid ZIP directory.');
    const flags = bytes.readUInt16LE(offset + 8);
    const method = bytes.readUInt16LE(offset + 10);
    const compressedSize = bytes.readUInt32LE(offset + 20);
    const size = bytes.readUInt32LE(offset + 24);
    const nameSize = bytes.readUInt16LE(offset + 28);
    const extraSize = bytes.readUInt16LE(offset + 30);
    const commentSize = bytes.readUInt16LE(offset + 32);
    const name = safeArchivePath(bytes.subarray(offset + 46, offset + 46 + nameSize).toString('utf8'));
    if (selected.has(name)) {
      const local = bytes.readUInt32LE(offset + 42);
      if (flags & 1 || local + 30 > bytes.length || bytes.readUInt32LE(local) !== 0x04034b50) throw new Error('Unsupported ZIP entry.');
      const start = local + 30 + bytes.readUInt16LE(local + 26) + bytes.readUInt16LE(local + 28);
      if (start + compressedSize > bytes.length) throw new Error('Truncated ZIP entry.');
      const compressed = bytes.subarray(start, start + compressedSize);
      const content = method === 0 ? compressed : method === 8 ? inflateRawSync(compressed) : null;
      if (!content || content.length !== size) throw new Error('Invalid ZIP compression or size.');
      result.set(name, content);
    }
    offset += 46 + nameSize + extraSize + commentSize;
  }
  return result;
}

export function patchDriverBundle(source) {
  const replacements = [
    ['pageError.location.url', 'pageError.location?.url || ""'],
    ['pageError.location.lineNumber', 'pageError.location?.lineNumber || 0'],
    ['pageError.location.columnNumber', 'pageError.location?.columnNumber || 0'],
  ];
  let result = source;
  for (const [original, patched] of replacements) {
    if (result.includes(original)) result = result.split(original).join(patched);
    else if (!result.includes(patched)) throw new Error('Playwright Go compatibility patch pattern is missing.');
  }
  return result;
}

async function exists(file) { try { await access(file); return true; } catch { return false; } }
async function sha256(file) { return createHash('sha256').update(await readFile(file)).digest('hex'); }

export async function treeSha256(directory) {
  const hash = createHash('sha256');
  async function walk(current, relative = '') {
    const entries = (await readdir(current, { withFileTypes: true })).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    for (const entry of entries) {
      if (entry.name === '.git') continue;
      const item = path.join(current, entry.name);
      const label = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) await walk(item, label);
      else if (entry.isFile()) { hash.update(label); hash.update('\0'); hash.update(await readFile(item)); hash.update('\0'); }
      else throw new Error('Artifact tree must not contain symbolic links.');
    }
  }
  await walk(directory);
  return hash.digest('hex');
}

async function download(url) {
  // curl is available on GitHub's macOS/Linux/Windows runners and honors the
  // developer's existing proxy environment. No browser installer is invoked.
  try {
    const { stdout } = await execFile('curl', ['--fail', '--location', '--silent', '--show-error', '--connect-timeout', '20', '--max-time', '240', url], {
      encoding: null, maxBuffer: 300 * 1024 * 1024,
    });
    return stdout;
  } catch (error) {
    if (error.code !== 'ENOENT') throw new Error(`Unable to download build artifact from ${new URL(url).hostname}.`);
    const response = await fetch(url, { signal: AbortSignal.timeout(240000) });
    if (!response.ok) throw new Error(`Build artifact download returned HTTP ${response.status}.`);
    return Buffer.from(await response.arrayBuffer());
  }
}

export function defaultDriverCaches(rootDir = ROOT, platform = process.platform, home = os.homedir()) {
  const cache = platform === 'darwin' ? path.join(home, 'Library', 'Caches')
    : platform === 'win32' ? path.join(home, 'AppData', 'Local') : path.join(home, '.cache');
  return [path.join(cache, 'ms-playwright-go', DRIVER_VERSION), path.join(rootDir, 'test-artifacts', 'sidecar-prototype', 'playwright-driver')];
}

async function validateNode(executable, platform, arch) {
  try {
    await access(executable, platform === 'win32' ? constants.F_OK : constants.X_OK);
    const { stdout } = await execFile(executable, ['-p', 'JSON.stringify({version:process.version,platform:process.platform,arch:process.arch})'], { timeout: 15000 });
    const info = JSON.parse(stdout.trim());
    return info.version === `v${NODE_VERSION}` && info.platform === platform && info.arch === arch;
  } catch { return false; }
}

async function cachedSources(caches, artifacts) {
  let packageDir = null;
  let node = null;
  let nodeLicense = null;
  for (const cache of [...new Set(caches.filter(Boolean).map((item) => path.resolve(item)))]) {
    try {
      const pkg = JSON.parse(await readFile(path.join(cache, 'package', 'package.json'), 'utf8'));
      if (!packageDir && pkg.name === 'playwright-core' && pkg.version === DRIVER_VERSION && await exists(path.join(cache, 'package', 'cli.js'))) packageDir = path.join(cache, 'package');
    } catch {}
    const candidate = path.join(cache, artifacts.nodeExecutable);
    if (!node && await validateNode(candidate, artifacts.platform, artifacts.arch)) node = candidate;
    for (const filename of ['node-LICENSE', 'NODE-LICENSE']) {
      if (!nodeLicense && await exists(path.join(cache, filename))) nodeLicense = path.join(cache, filename);
    }
  }
  return { packageDir, node, nodeLicense };
}

export async function preparePlaywrightDriver({ rootDir = ROOT, outputDir = path.join(rootDir, 'build', 'backend', 'playwright-driver'), platform = process.platform, arch = process.arch, caches, downloadImpl = download } = {}) {
  if (platform !== process.platform || arch !== process.arch) throw new Error('Prepare the driver on a native runner for the packaging target.');
  const goMod = await readFile(path.join(rootDir, 'third_party', 'browseforge', 'go.mod'), 'utf8');
  if (!goMod.includes(`github.com/mxschmitt/playwright-go ${GO_WRAPPER_VERSION}`)) throw new Error('Update pinned driver artifacts to match the vendored Go wrapper.');
  const artifacts = driverArtifacts(platform, arch);
  const cacheRoots = caches ?? [process.env.ENVARA_PLAYWRIGHT_DRIVER_CACHE, outputDir, ...defaultDriverCaches(rootDir, platform)];
  const cached = await cachedSources(cacheRoots, artifacts);
  await mkdir(path.dirname(outputDir), { recursive: true });
  const stage = `${outputDir}.stage-${randomUUID()}`;
  const previous = `${outputDir}.previous-${randomUUID()}`;
  await mkdir(stage, { mode: 0o755 });
  let oldMoved = false;
  try {
    let packageArchiveVerified = false;
    let nodeArchiveVerified = false;
    if (cached.packageDir) await cp(cached.packageDir, path.join(stage, 'package'), { recursive: true });
    else {
      const archive = await downloadImpl(artifacts.packageUrl);
      verifyIntegrity(archive, artifacts.packageIntegrity);
      const files = tarGzFiles(archive);
      let count = 0;
      for (const [name, bytes] of files) {
        if (!name.startsWith('package/')) continue;
        const file = path.join(stage, name);
        await mkdir(path.dirname(file), { recursive: true });
        await writeFile(file, bytes, { mode: 0o644 });
        count += 1;
      }
      if (!count) throw new Error('Official playwright-core archive contained no package files.');
      packageArchiveVerified = true;
    }
    if (cached.node) {
      await copyFile(cached.node, path.join(stage, artifacts.nodeExecutable));
      if (cached.nodeLicense) await copyFile(cached.nodeLicense, path.join(stage, 'node-LICENSE'));
      else await writeFile(path.join(stage, 'node-LICENSE'), await downloadImpl(`https://raw.githubusercontent.com/nodejs/node/v${NODE_VERSION}/LICENSE`));
    } else {
      const archive = await downloadImpl(artifacts.nodeUrl);
      verifyIntegrity(archive, artifacts.nodeArchiveSha256);
      const selected = new Set([artifacts.nodeArchiveExecutable, artifacts.nodeArchiveLicense]);
      const files = artifacts.extension === 'zip' ? selectedZipFiles(archive, selected) : tarGzFiles(archive);
      for (const [name, target] of [[artifacts.nodeArchiveExecutable, artifacts.nodeExecutable], [artifacts.nodeArchiveLicense, 'node-LICENSE']]) {
        if (!files.has(name)) throw new Error(`Official Node archive is missing ${target}.`);
        await writeFile(path.join(stage, target), files.get(name), { mode: target === artifacts.nodeExecutable ? 0o755 : 0o644 });
      }
      nodeArchiveVerified = true;
    }
    if (platform !== 'win32') await chmod(path.join(stage, artifacts.nodeExecutable), 0o755);
    const bundle = path.join(stage, 'package', 'lib', 'coreBundle.js');
    await writeFile(bundle, patchDriverBundle(await readFile(bundle, 'utf8')), { mode: 0o644 });
    await writeFile(path.join(stage, 'ENVARA_DRIVER_CHANGES.md'), `# Driver compatibility modification\n\nPlaywright ${DRIVER_VERSION} is pre-patched exactly as playwright-go ${GO_WRAPPER_VERSION} patchDriverBundle(): optional access and default values for pageError.location.url, lineNumber, and columnNumber. This makes the Go installer idempotent with read-only packaged resources. Browser binaries are not included.\n\nPatch source: https://github.com/mxschmitt/playwright-go/blob/${WRAPPER_COMMIT}/run.go\n`);
    const wrapperLicensePath = path.join(rootDir, 'test-artifacts', 'sidecar-prototype', 'go-mod-cache', 'github.com', 'mxschmitt', `playwright-go@${GO_WRAPPER_VERSION}`, 'LICENSE');
    const wrapperLicense = await exists(wrapperLicensePath) ? await readFile(wrapperLicensePath)
      : await downloadImpl(`https://raw.githubusercontent.com/mxschmitt/playwright-go/${WRAPPER_COMMIT}/LICENSE`);
    await writeFile(path.join(stage, 'playwright-go-LICENSE'), wrapperLicense);
    for (const file of ['LICENSE', 'NOTICE', 'ThirdPartyNotices.txt']) {
      if (!await exists(path.join(stage, 'package', file))) throw new Error(`Playwright package is missing required notice ${file}.`);
    }
    if (!await validateNode(path.join(stage, artifacts.nodeExecutable), platform, arch)) throw new Error('Bundled Node version or architecture does not match the target.');
    const { stdout } = await execFile(path.join(stage, artifacts.nodeExecutable), [path.join(stage, 'package', 'cli.js'), '--version'], { timeout: 15000 });
    if (stdout.trim() !== `Version ${DRIVER_VERSION}`) throw new Error('Bundled Playwright CLI version does not match the Go wrapper.');
    const provenance = {
      schema: 'envara.playwright-driver', version: 1, platform, arch,
      playwrightGo: GO_WRAPPER_VERSION, playwrightGoCommit: WRAPPER_COMMIT,
      playwrightCore: DRIVER_VERSION, node: NODE_VERSION,
      sources: {
        playwrightCore: { url: artifacts.packageUrl, expectedIntegrity: artifacts.packageIntegrity, archiveVerifiedThisBuild: packageArchiveVerified, cacheReused: Boolean(cached.packageDir) },
        node: { url: artifacts.nodeUrl, expectedArchiveSha256: artifacts.nodeArchiveSha256, archiveVerifiedThisBuild: nodeArchiveVerified, cacheReused: Boolean(cached.node) },
      },
      cacheVerification: 'Cached files are checked by CLI/Node version and native platform. Observed file hashes are not official archive checksums.',
      sha256: { node: await sha256(path.join(stage, artifacts.nodeExecutable)), coreBundle: await sha256(bundle), packageTree: await treeSha256(path.join(stage, 'package')) },
      licenses: ['node-LICENSE', 'playwright-go-LICENSE', 'package/LICENSE', 'package/NOTICE', 'package/ThirdPartyNotices.txt', 'package/lib/*.LICENSE'],
    };
    await writeFile(path.join(stage, 'provenance.json'), `${JSON.stringify(provenance, null, 2)}\n`);
    if (await exists(outputDir)) { await rename(outputDir, previous); oldMoved = true; }
    await rename(stage, outputDir);
    if (oldMoved) await rm(previous, { recursive: true, force: true });
    return { outputDir, nodePath: path.join(outputDir, artifacts.nodeExecutable), cliPath: path.join(outputDir, 'package', 'cli.js'), provenance };
  } catch (error) {
    await rm(stage, { recursive: true, force: true });
    if (oldMoved && !await exists(outputDir)) await rename(previous, outputDir);
    throw error;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const prepared = await preparePlaywrightDriver();
    console.log(`Prepared Playwright ${DRIVER_VERSION} / Node ${NODE_VERSION} for ${process.platform}/${process.arch}: ${prepared.outputDir}`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
