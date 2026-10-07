import { createHash, randomUUID } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import { access, chmod, copyFile, mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { gunzipSync } from 'node:zlib';
import { selectedZipFiles, tarGzFiles } from './prepare-playwright-driver.mjs';

const execFile = promisify(execFileCallback);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const PROXY_CORE_VERSION = 'v1.19.32';
export const PROXY_CORE_COMMIT = '88dcbf7f1614a67c3b36b848ee3592dfa92ada36';
export const PROXY_CORE_SOURCE_SHA256 = '77643ec763a92b330a0b4a44870f78ee05c08792897e7f5e40a3654415c5f077';
const SOURCE_ARCHIVE = 'mihomo-corresponding-source.tar.gz';
const ARTIFACTS = Object.freeze({
  'darwin-arm64': ['mihomo-darwin-arm64-v1.19.32.gz', '3312a6780652c622890fd4357c6a853bbf865464fd047ac7b7f52dab8de18652'],
  'linux-x64': ['mihomo-linux-amd64-compatible-v1.19.32.gz', 'ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20'],
  'win32-x64': ['mihomo-windows-amd64-compatible-v1.19.32.zip', '974a4d7ad69aed27aa2e8f91d61113573c14dadb14562c63e58effabf59816f0'],
});

/** Immutable official release assets, never the moving Alpha/latest URL. */
export function proxyCoreArtifacts(platform = process.platform, arch = process.arch) {
  const entry = ARTIFACTS[`${platform}-${arch}`];
  if (!entry) throw new Error(`No pinned Mihomo artifact for ${platform}/${arch}.`);
  const [archiveName, archiveSha256] = entry;
  return {
    platform, arch, version: PROXY_CORE_VERSION, commit: PROXY_CORE_COMMIT,
    archiveName, archiveSha256,
    binaryName: platform === 'win32' ? 'mihomo.exe' : 'mihomo',
    archiveEntry: archiveName.replace(/-v1\.19\.32\.zip$/, '.exe'),
    url: `https://github.com/MetaCubeX/mihomo/releases/download/${PROXY_CORE_VERSION}/${archiveName}`,
    sourceUrl: `https://codeload.github.com/MetaCubeX/mihomo/tar.gz/${PROXY_CORE_COMMIT}`,
    sourceSha256: PROXY_CORE_SOURCE_SHA256,
  };
}

export function verifyProxyCoreHash(bytes, expected) {
  if (!/^[a-f0-9]{64}$/.test(expected)) throw new Error('Invalid pinned SHA-256 digest.');
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== expected) throw new Error('Proxy core artifact SHA-256 verification failed.');
  return actual;
}

export function extractProxyCoreBinary(bytes, artifact) {
  verifyProxyCoreHash(bytes, artifact.archiveSha256);
  if (artifact.archiveName.endsWith('.gz')) return gunzipSync(bytes, { maxOutputLength: 150 * 1024 * 1024 });
  if (artifact.archiveName.endsWith('.zip')) {
    const files = selectedZipFiles(bytes, new Set([artifact.archiveEntry]));
    if (!files.has(artifact.archiveEntry)) throw new Error('Official Mihomo ZIP does not contain its declared executable.');
    return files.get(artifact.archiveEntry);
  }
  throw new Error('Unsupported Mihomo archive.');
}

/** The upstream workflow replaces its empty CA embed file before compilation. */
export function extractProxyCoreCA(binary) {
  const candidates = [...binary.toString('latin1').matchAll(/(?:-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n)+/g)]
    .map(match => Buffer.from(match[0], 'latin1')).filter(bytes => bytes.length > 100000);
  if (candidates.length !== 1 || candidates[0].length > 1024 * 1024) throw new Error('Official Mihomo binary CA build input could not be identified.');
  return candidates[0];
}

async function exists(file) { try { await access(file); return true; } catch { return false; } }
async function digest(file) { return createHash('sha256').update(await readFile(file)).digest('hex'); }

async function download(url) {
  // Build-time curl honors the developer's selected network, but no such
  // environment or download URL is passed to the runtime proxy process.
  try {
    const { stdout } = await execFile('curl', ['--fail', '--location', '--silent', '--show-error', '--connect-timeout', '20', '--max-time', '240', url], {
      encoding: null, maxBuffer: 200 * 1024 * 1024,
    });
    return stdout;
  } catch { throw new Error(`Unable to download proxy build artifact from ${new URL(url).hostname}.`); }
}

async function verifiedDownload(url, expected, cacheDir, downloadImpl) {
  const cached = path.join(cacheDir, expected);
  if (await exists(cached)) {
    const bytes = await readFile(cached);
    try { verifyProxyCoreHash(bytes, expected); return bytes; }
    catch { await rm(cached, { force: true }); }
  }
  const bytes = await downloadImpl(url);
  verifyProxyCoreHash(bytes, expected);
  await mkdir(cacheDir, { recursive: true });
  const temporary = `${cached}.tmp-${randomUUID()}`;
  await writeFile(temporary, bytes, { mode: 0o644 });
  try { await rename(temporary, cached); }
  finally { await rm(temporary, { force: true }); }
  return bytes;
}

export async function validateProxyCoreBinary(binary, artifact) {
  const { stdout, stderr } = await execFile(binary, ['-v'], { timeout: 15000, maxBuffer: 65536 });
  const text = `${stdout}\n${stderr}`;
  const goPlatform = artifact.platform === 'win32' ? 'windows' : artifact.platform;
  const goArch = artifact.arch === 'x64' ? 'amd64' : artifact.arch;
  if (!text.includes(`Mihomo Meta ${artifact.version}`) || !text.includes(`${goPlatform} ${goArch}`)) {
    throw new Error('Bundled Mihomo version or native architecture does not match the target.');
  }
  return text.trim();
}

/** Preserve all upstream source and notices, adding dependencies for offline builds. */
export async function prepareProxyCoreSource({ artifact, sourceBytes, binaryBytes, destination, rootDir = ROOT, execImpl = execFile }) {
  verifyProxyCoreHash(sourceBytes, artifact.sourceSha256);
  const sourceFiles = tarGzFiles(sourceBytes);
  const prefix = `mihomo-${artifact.commit}/`;
  if (!sourceFiles.has(`${prefix}go.mod`) || !sourceFiles.has(`${prefix}LICENSE`) || !sourceFiles.has(`${prefix}.github/workflows/build.yml`)) {
    throw new Error('Pinned Mihomo source archive is missing build source or licensing.');
  }
  if ([...sourceFiles.keys()].some(name => !name.startsWith(prefix))) throw new Error('Unexpected source archive root.');
  const work = await mkdtemp(path.join(os.tmpdir(), 'envara-mihomo-source-'));
  try {
    const archive = path.join(work, 'upstream.tar.gz');
    await writeFile(archive, sourceBytes);
    // The fixed archive digest and validated paths are checked before tar.
    await execImpl('tar', ['-xzf', archive, '-C', work], { timeout: 30000 });
    const sourceDir = path.join(work, `mihomo-${artifact.commit}`);
    const initialMod = await readFile(path.join(sourceDir, 'go.mod'));
    const initialSum = await readFile(path.join(sourceDir, 'go.sum'));
    await execImpl('go', ['mod', 'vendor'], {
      cwd: sourceDir, env: { ...process.env, GOTOOLCHAIN: 'auto', GOFLAGS: '' },
      timeout: 600000, maxBuffer: 2 * 1024 * 1024,
    });
    if (!(await readFile(path.join(sourceDir, 'go.mod'))).equals(initialMod) || !(await readFile(path.join(sourceDir, 'go.sum'))).equals(initialSum)) {
      throw new Error('Vendoring changed the pinned Mihomo module manifests.');
    }
    if (!await exists(path.join(sourceDir, 'vendor', 'modules.txt'))) throw new Error('Mihomo dependency source was not vendored.');
    const ca = extractProxyCoreCA(binaryBytes);
    await writeFile(path.join(sourceDir, 'component', 'ca', 'ca-certificates.crt'), ca);
    await copyFile(path.join(rootDir, 'third_party', 'proxy-core', 'build-from-source.mjs'), path.join(sourceDir, 'ENVARA_BUILD_FROM_SOURCE.mjs'));
    await writeFile(path.join(sourceDir, 'ENVARA_SOURCE_PROVENANCE.json'), `${JSON.stringify({
      core: 'mihomo', version: artifact.version, commit: artifact.commit,
      sourceUrl: artifact.sourceUrl, sourceArchiveSha256: artifact.sourceSha256,
      upstreamSourcePatches: [], additions: ['vendor/', 'ENVARA_BUILD_FROM_SOURCE.mjs', 'ENVARA_SOURCE_PROVENANCE.json'],
      releaseBuildInputs: { 'component/ca/ca-certificates.crt': {
        sha256: createHash('sha256').update(ca).digest('hex'), source: 'Public CA bundle extracted verbatim from the verified official executable; reproduces upstream release workflow Update CA step.',
      } },
      dependencyVerification: 'Go module download verifies pinned go.sum checksums before go mod vendor.',
      compiler: 'A compatible Go toolchain is a build prerequisite, not included in this source archive.',
    }, null, 2)}\n`);
    await execImpl('tar', ['-czf', destination, '-C', work, `mihomo-${artifact.commit}`], { timeout: 120000, maxBuffer: 65536 });
    return { filename: SOURCE_ARCHIVE, sha256: await digest(destination), offlineDependencies: true, releaseCA: true };
  } finally { await rm(work, { recursive: true, force: true }); }
}

async function verifiedPreparedBundle(outputDir, artifact, validateImpl) {
  try {
    const provenance = JSON.parse(await readFile(path.join(outputDir, 'provenance.json'), 'utf8'));
    if (provenance.core !== 'mihomo' || provenance.version !== artifact.version || provenance.commit !== artifact.commit ||
        provenance.platform !== artifact.platform || provenance.arch !== artifact.arch ||
        provenance.sha256?.archive !== artifact.archiveSha256 || provenance.sha256?.sourceArchive !== artifact.sourceSha256 ||
        provenance.correspondingSource !== SOURCE_ARCHIVE || provenance.source?.offlineDependencies !== true || provenance.source?.releaseCA !== true) return null;
    for (const [name, hash] of [[artifact.binaryName, provenance.sha256.binary], [SOURCE_ARCHIVE, provenance.sha256.correspondingSource], ['LICENSE', provenance.sha256.license]]) {
      verifyProxyCoreHash(await readFile(path.join(outputDir, name)), hash);
    }
    await readFile(path.join(outputDir, 'SOURCE.md'));
    await validateImpl(path.join(outputDir, artifact.binaryName), artifact);
    return { outputDir, binaryPath: path.join(outputDir, artifact.binaryName), provenance, reused: true };
  } catch { return null; }
}

export async function prepareProxyCore({ rootDir = ROOT, outputDir = path.join(rootDir, 'build', 'proxy-core'),
  cacheDir = path.join(rootDir, '.cache', 'proxy-core'), platform = process.platform, arch = process.arch,
  downloadImpl = download, validateImpl = validateProxyCoreBinary, prepareSourceImpl = prepareProxyCoreSource,
  artifact = proxyCoreArtifacts(platform, arch), force = false } = {}) {
  if (platform !== process.platform || arch !== process.arch) throw new Error('Prepare Mihomo on a native runner for the packaging target.');
  if (artifact.platform !== platform || artifact.arch !== arch) throw new Error('Proxy artifact does not match the packaging target.');
  if (!force) {
    const cached = await verifiedPreparedBundle(outputDir, artifact, validateImpl);
    if (cached) return cached;
  }
  await mkdir(path.dirname(outputDir), { recursive: true });
  const stage = `${outputDir}.stage-${randomUUID()}`;
  const previous = `${outputDir}.previous-${randomUUID()}`;
  await mkdir(stage, { mode: 0o755 });
  let oldMoved = false;
  try {
    const archive = await verifiedDownload(artifact.url, artifact.archiveSha256, cacheDir, downloadImpl);
    const binary = extractProxyCoreBinary(archive, artifact);
    const binaryPath = path.join(stage, artifact.binaryName);
    await writeFile(binaryPath, binary, { mode: 0o755 });
    if (platform !== 'win32') await chmod(binaryPath, 0o755);
    const observedVersion = await validateImpl(binaryPath, artifact);
    const sourceBytes = await verifiedDownload(artifact.sourceUrl, artifact.sourceSha256, cacheDir, downloadImpl);
    const source = await prepareSourceImpl({ artifact, sourceBytes, binaryBytes: binary, destination: path.join(stage, SOURCE_ARCHIVE), rootDir });
    if (source.offlineDependencies !== true || source.releaseCA !== true || source.sha256 !== await digest(path.join(stage, SOURCE_ARCHIVE))) {
      throw new Error('Corresponding Mihomo source bundle is incomplete or has an invalid digest.');
    }
    await copyFile(path.join(rootDir, 'third_party', 'proxy-core', 'LICENSE'), path.join(stage, 'LICENSE'));
    await copyFile(path.join(rootDir, 'third_party', 'proxy-core', 'SOURCE.md'), path.join(stage, 'SOURCE.md'));
    const provenance = {
      schema: 'envara.proxy-core', schemaVersion: 1, core: 'mihomo', version: artifact.version, commit: artifact.commit,
      platform, arch, binaryName: artifact.binaryName, observedVersion,
      sha256: { binary: createHash('sha256').update(binary).digest('hex'), archive: artifact.archiveSha256,
        sourceArchive: artifact.sourceSha256, correspondingSource: source.sha256, license: await digest(path.join(stage, 'LICENSE')) },
      sources: { binary: { url: artifact.url, sha256: artifact.archiveSha256 }, source: { url: artifact.sourceUrl, sha256: artifact.sourceSha256 } },
      licenses: ['LICENSE'], correspondingSource: SOURCE_ARCHIVE, source,
      relationship: 'Unmodified upstream executable invoked as a separate process; Envara does not link Mihomo code.',
    };
    await writeFile(path.join(stage, 'provenance.json'), `${JSON.stringify(provenance, null, 2)}\n`);
    if (await exists(outputDir)) { await rename(outputDir, previous); oldMoved = true; }
    await rename(stage, outputDir);
    if (oldMoved) await rm(previous, { recursive: true, force: true });
    return { outputDir, binaryPath: path.join(outputDir, artifact.binaryName), provenance, reused: false };
  } catch (error) {
    await rm(stage, { recursive: true, force: true });
    if (oldMoved && !await exists(outputDir)) await rename(previous, outputDir);
    throw error;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await prepareProxyCore({ force: process.argv.includes('--force') });
    console.log(`Prepared Mihomo ${PROXY_CORE_VERSION} with corresponding source for ${process.platform}/${process.arch}: ${result.outputDir}`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
