// Cross preparation is deliberately separate from native host preparation.
// This never installs an app/driver, activates capture, or publishes artifacts.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import { access, copyFile, cp, lstat, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import * as asar from '@electron/asar';
import { computeData as computeAsarIntegrity } from 'app-builder-lib/out/asar/integrity.js';
import { addWinAsarIntegrity } from 'app-builder-lib/out/electron/electronWin.js';
import { copyModuleLicenses } from './build-sidecar.mjs';
import { copyDependencyLicenses } from './prepare-native.mjs';
import { driverArtifacts, DRIVER_VERSION, NODE_VERSION, GO_WRAPPER_VERSION,
  patchDriverBundle, safeArchivePath, selectedZipFiles, tarGzFiles, treeSha256, verifyIntegrity } from './prepare-playwright-driver.mjs';
import { proxyCoreArtifacts, extractProxyCoreBinary, prepareProxyCoreSource,
  verifyProxyCoreHash } from './prepare-proxy-core.mjs';

const execFile = promisify(execFileCallback);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const GO_VERSION = '1.25.0';
const ELECTRON_VERSION = '44.6.0';
const ELECTRON_SHA256 = '04d6071f8deca081044e1398f96f65e4c1550ffdb3f882504cd78528d821d422';
const ELECTRON_URL = `https://github.com/electron/electron/releases/download/v${ELECTRON_VERSION}/electron-v${ELECTRON_VERSION}-win32-x64.zip`;
const DRIVER_NPM_INTEGRITY = 'sha512-h7Qlt6m4REp25qvIdvbDtVmD4LqVXfpRxhORv9L0jzETM05p4fuPJ3dKyuSXQxDSbXnmS79HAgi9589lGSpLkg==';
const PTY_FILES = ['conpty.node', 'conpty_console_list.node', 'pty.node', 'winpty-agent.exe', 'winpty.dll', 'conpty/conpty.dll', 'conpty/OpenConsole.exe'];
const SOURCE_PREFIXES = ['electron', 'shared', 'src', 'worker', 'public', 'scripts', 'native/macos-local-routing', 'native/windows-app-routing', 'third_party/browseforge', 'third_party/proxy-core', 'third_party/npm-licenses', '.openai'];
const SOURCE_FILES = ['package.json', 'package-lock.json', 'index.html', 'vite.config.mjs', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'build/icon.png'];
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
async function fileHash(file) { return sha256(await readFile(file)); }
async function exists(file) { try { await access(file); return true; } catch { return false; } }

export function windowsPE(bytes, { machines = [0x8664], label = 'Windows resource', napi = false } = {}) {
  assert.ok(bytes.length >= 64 && bytes.subarray(0, 2).toString() === 'MZ', `${label} is not a Windows PE executable`);
  const offset = bytes.readUInt32LE(0x3c);
  assert.ok(offset + 24 <= bytes.length && bytes.readUInt32LE(offset) === 0x4550, `${label} has an invalid PE header`);
  const machine = bytes.readUInt16LE(offset + 4);
  assert.ok(machines.includes(machine), `${label} has the wrong PE architecture`);
  if (napi) assert.ok(bytes.includes(Buffer.from('napi_register_module_v1')), `${label} does not export its N-API entry point`);
  return { machine: machine.toString(16), sha256: sha256(bytes), size: bytes.length, napi: napi ? 'N-API entry point present; native loading remains unverified' : undefined };
}

function zipNames(bytes) {
  let end = -1;
  for (let offset = bytes.length - 22; offset >= Math.max(0, bytes.length - 65557); offset--) {
    if (bytes.readUInt32LE(offset) === 0x06054b50) { end = offset; break; }
  }
  assert.ok(end >= 0 && bytes.readUInt16LE(end + 4) === 0 && bytes.readUInt16LE(end + 6) === 0, 'Unsupported Windows ZIP');
  const names = new Set(); let offset = bytes.readUInt32LE(end + 16);
  for (let index = 0; index < bytes.readUInt16LE(end + 10); index++) {
    assert.ok(offset + 46 <= bytes.length && bytes.readUInt32LE(offset) === 0x02014b50, 'Invalid Windows ZIP directory');
    const nameLength = bytes.readUInt16LE(offset + 28), extra = bytes.readUInt16LE(offset + 30), comment = bytes.readUInt16LE(offset + 32);
    const name = safeArchivePath(bytes.subarray(offset + 46, offset + 46 + nameLength).toString('utf8'));
    if (!name.endsWith('/')) names.add(name);
    offset += 46 + nameLength + extra + comment;
  }
  return names;
}

async function writeEntries(directory, files, prefix = '') {
  for (const [name, bytes] of files) {
    if (prefix && !name.startsWith(prefix)) continue;
    const relative = prefix ? name.slice(prefix.length) : name;
    if (!relative) continue;
    safeArchivePath(relative);
    const target = path.join(directory, relative);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, bytes, { mode: /\.(exe|dll|node|sys)$/i.test(relative) ? 0o755 : 0o644 });
  }
}

async function downloadVerified(url, expected, directory) {
  const key = createHash('sha256').update(expected).digest('hex');
  const cache = path.join(directory, expected.startsWith('sha') ? key : expected);
  const verify = bytes => expected.startsWith('sha') ? verifyIntegrity(bytes, expected) : verifyProxyCoreHash(bytes, expected);
  if (await exists(cache)) {
    const bytes = await readFile(cache);
    try { verify(bytes); return bytes; } catch { await rm(cache, { force: true }); }
  }
  console.log(`Preparing fixed build asset from ${new URL(url).hostname}`);
  const { stdout } = await execFile('curl', ['--fail', '--location', '--silent', '--show-error', '--connect-timeout', '20', '--max-time', '240', url], {
    encoding: null, maxBuffer: 350 * 1024 * 1024,
  });
  verify(stdout); await mkdir(directory, { recursive: true }); await writeFile(cache, stdout, { mode: 0o600 });
  return stdout;
}

async function walkFiles(root, prefix = '') {
  const rows = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name, filename = path.join(root, entry.name);
    if (entry.isDirectory()) rows.push(...await walkFiles(filename, name));
    else { assert.ok(entry.isFile(), `Unsupported symlink in prepared artifact: ${name}`); rows.push({ path: name, sha256: await fileHash(filename), size: (await lstat(filename)).size }); }
  }
  return rows.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}

async function prepareDriver({ project, cache }) {
  const artifact = driverArtifacts('win32', 'x64');
  const [packageBytes, nodeBytes] = await Promise.all([
    downloadVerified(artifact.packageUrl, DRIVER_NPM_INTEGRITY, cache),
    downloadVerified(artifact.nodeUrl, artifact.nodeArchiveSha256, cache),
  ]);
  const directory = path.join(project, 'build/backend/playwright-driver');
  await writeEntries(directory, tarGzFiles(packageBytes));
  const selected = selectedZipFiles(nodeBytes, new Set([artifact.nodeArchiveExecutable, artifact.nodeArchiveLicense]));
  assert.ok(selected.has(artifact.nodeArchiveExecutable) && selected.has(artifact.nodeArchiveLicense), 'Official Windows Node archive is incomplete');
  await writeFile(path.join(directory, 'node.exe'), selected.get(artifact.nodeArchiveExecutable), { mode: 0o755 });
  await writeFile(path.join(directory, 'node-LICENSE'), selected.get(artifact.nodeArchiveLicense));
  windowsPE(selected.get(artifact.nodeArchiveExecutable), { label: 'Playwright Node.exe' });
  const bundle = path.join(directory, 'package/lib/coreBundle.js');
  await writeFile(bundle, patchDriverBundle(await readFile(bundle, 'utf8')));
  const wrapperLicense = path.join(project, 'build/backend/licenses/playwright-go-LICENSE');
  await copyFile(wrapperLicense, path.join(directory, 'playwright-go-LICENSE'));
  await writeFile(path.join(directory, 'ENVARA_DRIVER_CHANGES.md'), `# Driver compatibility modification\n\nPlaywright ${DRIVER_VERSION}: the same pageError.location optional-access/default-value patch as playwright-go ${GO_WRAPPER_VERSION}. Pre-patched to keep packaged resources read-only. Windows Node ${NODE_VERSION} is selected from a checksum-verified official archive; it was not executed on the Mac build host.\n`);
  const provenance = { schema: 'envara.playwright-driver', version: 1, platform: 'win32', arch: 'x64',
    playwrightGo: GO_WRAPPER_VERSION, playwrightGoCommit: '1c4f6330ed40337c3582539dbeb2a42ff73d01f6', playwrightCore: DRIVER_VERSION, node: NODE_VERSION,
    sources: { playwrightCore: { url: artifact.packageUrl, expectedIntegrity: DRIVER_NPM_INTEGRITY, archiveVerifiedThisBuild: true },
      node: { url: artifact.nodeUrl, expectedArchiveSha256: artifact.nodeArchiveSha256, archiveVerifiedThisBuild: true } },
    sha256: { node: await fileHash(path.join(directory, 'node.exe')), coreBundle: await fileHash(bundle), packageTree: await treeSha256(path.join(directory, 'package')) },
    licenses: ['node-LICENSE', 'playwright-go-LICENSE', 'package/LICENSE', 'package/NOTICE', 'package/ThirdPartyNotices.txt'],
    validation: { archiveIntegrity: true, peX64: true, nativeNodeAndDriverExecution: false, reason: 'Prepared on another operating system; Windows acceptance is a separate gate' } };
  for (const filename of provenance.licenses) assert.ok(await exists(path.join(directory, filename)), `Missing driver license ${filename}`);
  await writeFile(path.join(directory, 'provenance.json'), JSON.stringify(provenance, null, 2) + '\n');
  return provenance;
}

async function prepareSidecar({ project, rootDir, packageInfo }) {
  const source = path.join(project, 'third_party/browseforge'), output = path.join(project, 'build/backend');
  const moduleCache = path.join(rootDir, await exists(path.join(rootDir, 'test-artifacts/sidecar-prototype/go-mod-cache')) ? 'test-artifacts/sidecar-prototype/go-mod-cache' : '.cache/go-mod');
  const buildEnv = { ...process.env, GOOS: 'windows', GOARCH: 'amd64', CGO_ENABLED: '0', GOTOOLCHAIN: `go${GO_VERSION}`,
    GOMODCACHE: moduleCache, GOCACHE: path.join(rootDir, '.cache/windows-desktop/go-build') };
  await mkdir(output, { recursive: true });
  const go = process.env.ENVARA_GO_BINARY || 'go';
  const version = `2.1.15-envara.${packageInfo.version}`;
  assert.ok((await execFile(go, ['version'], { cwd: source, env: buildEnv })).stdout.includes(`go${GO_VERSION} `), 'Pinned Go toolchain mismatch');
  assert.ok((await readFile(path.join(source, 'go.mod'), 'utf8')).includes(`go ${GO_VERSION}`), 'Vendored sidecar Go version changed');
  const sourceTreeSha256 = await treeSha256(source), binary = path.join(output, 'BrowseForge-sidecar.exe');
  await execFile(go, ['build', '-trimpath', '-buildvcs=false', '-mod=readonly', '-ldflags', `-s -w -buildid= -X main.Version=${version}`, '-o', binary, './cmd/server'], {
    cwd: source, env: buildEnv, timeout: 180000, maxBuffer: 8 * 1024 * 1024,
  });
  windowsPE(await readFile(binary), { label: 'BrowseForge-sidecar.exe' });
  const staticBuildInfo = (await execFile(go, ['version', '-m', binary], { cwd: source, env: buildEnv })).stdout.trim();
  assert.ok(staticBuildInfo.includes('GOOS=windows') && staticBuildInfo.includes('GOARCH=amd64'), 'Compiled sidecar build metadata target mismatch');
  const licenseDir = path.join(output, 'licenses'), licenses = await copyModuleLicenses(moduleCache, licenseDir);
  await copyFile(path.join(source, 'LICENSE'), path.join(licenseDir, 'BrowseForge-LICENSE')); licenses.push('BrowseForge-LICENSE');
  const goRoot = (await execFile(go, ['env', 'GOROOT'], { cwd: source, env: buildEnv })).stdout.trim();
  await copyFile(path.join(goRoot, 'LICENSE'), path.join(licenseDir, 'Go-LICENSE')); licenses.push('Go-LICENSE');
  const provenance = { schema: 'envara.browseforge-sidecar', version: 1, upstreamVersion: '2.1.15', envaraVersion: packageInfo.version,
    upstreamCommit: 'fa9e0bb670e749706a9c8f2d4095333347d6c521', goVersion: GO_VERSION, goos: 'windows', goarch: 'amd64', cgo: false,
    buildFlags: ['-trimpath', '-buildvcs=false', '-mod=readonly', '-s', '-w', '-buildid='], sourceTreeSha256, binarySha256: await fileHash(binary), licenses: licenses.sort(),
    validation: { peX64: true, staticBuildInfo, nativeExecution: false, reason: 'Cross compiled; Windows runtime/browser acceptance is separate' } };
  await writeFile(path.join(output, 'sidecar-provenance.json'), JSON.stringify(provenance, null, 2) + '\n');
  return { provenance, buildEnv };
}

async function prepareProxy({ project, rootDir, cache }) {
  const artifact = proxyCoreArtifacts('win32', 'x64'), directory = path.join(project, 'build/proxy-core');
  await mkdir(directory, { recursive: true });
  const [archive, sourceBytes] = await Promise.all([
    downloadVerified(artifact.url, artifact.archiveSha256, cache),
    downloadVerified(artifact.sourceUrl, artifact.sourceSha256, cache),
  ]);
  const binary = extractProxyCoreBinary(archive, artifact); windowsPE(binary, { label: 'Mihomo.exe' });
  await writeFile(path.join(directory, 'mihomo.exe'), binary, { mode: 0o755 });
  const source = await prepareProxyCoreSource({ artifact, sourceBytes, binaryBytes: binary,
    destination: path.join(directory, 'mihomo-corresponding-source.tar.gz'), rootDir });
  for (const filename of ['LICENSE', 'SOURCE.md']) await copyFile(path.join(project, 'third_party/proxy-core', filename), path.join(directory, filename));
  const provenance = { schema: 'envara.proxy-core', schemaVersion: 1, core: 'mihomo', version: artifact.version, commit: artifact.commit,
    platform: 'win32', arch: 'x64', binaryName: 'mihomo.exe',
    sha256: { binary: sha256(binary), archive: artifact.archiveSha256, sourceArchive: artifact.sourceSha256, correspondingSource: source.sha256, license: await fileHash(path.join(directory, 'LICENSE')) },
    sources: { binary: { url: artifact.url, sha256: artifact.archiveSha256 }, source: { url: artifact.sourceUrl, sha256: artifact.sourceSha256 } },
    licenses: ['LICENSE'], correspondingSource: source.filename, source,
    relationship: 'Unmodified official Windows executable, invoked as a separate process; source and licensing included',
    validation: { officialArchiveIntegrity: true, peX64: true, nativeExecution: false, reason: 'Prepared on another operating system; Windows AnyTLS acceptance is separate' } };
  await writeFile(path.join(directory, 'provenance.json'), JSON.stringify(provenance, null, 2) + '\n');
  return provenance;
}

async function preparePty({ project, cache, lock }) {
  const dependency = lock.packages['node_modules/node-pty'];
  assert.equal(dependency.version, '1.1.0', 'Pinned node-pty version changed');
  const archive = await downloadVerified('https://registry.npmjs.org/node-pty/-/node-pty-1.1.0.tgz', dependency.integrity, cache);
  const directory = path.join(project, 'node_modules/node-pty');
  await rm(directory, { recursive: true, force: true });
  await writeEntries(directory, tarGzFiles(archive), 'package/');
  for (const name of ['build/Release', 'build/Debug']) await rm(path.join(directory, name), { recursive: true, force: true });
  for (const name of await readdir(path.join(directory, 'prebuilds'))) if (name !== 'win32-x64') await rm(path.join(directory, 'prebuilds', name), { recursive: true, force: true });
  for (const name of ['win10-arm64']) await rm(path.join(directory, 'third_party/conpty/1.23.251008001', name), { recursive: true, force: true });
  const files = [];
  for (const filename of PTY_FILES) files.push({ path: `prebuilds/win32-x64/${filename}`,
    ...windowsPE(await readFile(path.join(directory, 'prebuilds/win32-x64', filename)), { label: `node-pty/${filename}`, napi: filename.endsWith('.node') }) });
  for (const filename of ['lib/worker/conoutSocketWorker.js', 'lib/shared/conout.js', 'lib/conpty_console_list_agent.js', 'lib/utils.js', 'LICENSE', 'deps/winpty/LICENSE']) {
    assert.ok(await exists(path.join(directory, filename)), `Missing Windows node-pty runtime/notice ${filename}`);
  }
  return { version: dependency.version, url: 'https://registry.npmjs.org/node-pty/-/node-pty-1.1.0.tgz', integrity: dependency.integrity,
    archiveSha256: sha256(archive), files, nativeElectronLoadTested: false,
    reason: 'Original N-API prebuild retained with all Windows workers; native load/PTY lifecycle still require Windows' };
}

export async function verifyWindowsDesktopBundle({ project, appDirectory, provenance }) {
  const resources = path.join(appDirectory, 'resources');
  const report = { schema: 'envara.windows-desktop-package', schemaVersion: 1, passed: false,
    platform: 'win32', arch: 'x64', buildHost: process.platform, generatedAt: new Date().toISOString(), files: [], nativeAcceptance: false };
  for (const prefix of ['backend', 'proxy-core', 'app-routing', 'licenses']) {
    const expected = await walkFiles(path.join(project, 'build', prefix === 'licenses' ? 'native/licenses' : prefix));
    const actual = await walkFiles(path.join(resources, prefix === 'licenses' ? 'licenses/npm' : prefix));
    assert.deepEqual(actual, expected, `Packaged ${prefix} differs from the prepared Windows resources`);
    report.files.push(...actual.map(row => ({ ...row, path: `${prefix}/${row.path}` })));
  }
  const archive = path.join(resources, 'app.asar');
  const metadata = JSON.parse(asar.extractFile(archive, 'package.json').toString());
  const staged = JSON.parse(await readFile(path.join(project, 'package.json'), 'utf8'));
  for (const field of ['name', 'version', 'author', 'license', 'main', 'dependencies']) assert.deepEqual(metadata[field], staged[field]);
  for (const prefix of ['electron', 'shared', 'dist/client', 'native/macos-local-routing']) for (const row of await walkFiles(path.join(project, prefix))) {
    if (['.gitignore', '.gitkeep', '.gitattributes', '.DS_Store'].includes(path.basename(row.path))) continue;
    if (prefix === 'electron' && (path.basename(row.path) === 'smoke.mjs' || path.basename(row.path).endsWith('-smoke.mjs'))) continue;
    const filename = `${prefix}/${row.path}`;
    assert.equal(sha256(asar.extractFile(archive, filename)), row.sha256, `Packaged source differs: ${filename}`);
  }
  report.runtime = {
    electron: windowsPE(await readFile(path.join(appDirectory, 'Envara.exe')), { label: 'Envara.exe' }),
    sidecar: windowsPE(await readFile(path.join(resources, 'backend/BrowseForge-sidecar.exe')), { label: 'Packaged sidecar' }),
    node: windowsPE(await readFile(path.join(resources, 'backend/playwright-driver/node.exe')), { label: 'Packaged Node.exe' }),
    proxy: windowsPE(await readFile(path.join(resources, 'proxy-core/mihomo.exe')), { label: 'Packaged Mihomo.exe' }),
    pty: [],
  };
  for (const filename of PTY_FILES) {
    const original = path.join(project, 'node_modules/node-pty/prebuilds/win32-x64', filename);
    const packaged = path.join(resources, 'app.asar.unpacked/node_modules/node-pty/prebuilds/win32-x64', filename);
    const bytes = await readFile(packaged); assert.equal(sha256(bytes), await fileHash(original));
    report.runtime.pty.push({ path: filename, ...windowsPE(bytes, { label: filename, napi: filename.endsWith('.node') }) });
  }
  const builderConfig = JSON.parse(await readFile(provenance.builderConfig, 'utf8'));
  const originalElectron = path.join(builderConfig.electronDist, 'electron.exe');
  assert.equal(await fileHash(originalElectron), provenance.electronExecutableSha256, 'Original Electron source changed');
  const expectedElectron = path.join(path.dirname(appDirectory), `.expected-electron-${randomUUID()}.exe`);
  try {
    await copyFile(originalElectron, expectedElectron);
    const integrity = await computeAsarIntegrity({ resourcesPath: resources, resourcesRelativePath: 'resources', resourcesDestinationPath: resources, extraResourceMatchers: [] });
    await addWinAsarIntegrity(expectedElectron, integrity);
    assert.equal(await fileHash(expectedElectron), report.runtime.electron.sha256, 'Electron differs beyond the expected ASAR-integrity resource update');
    report.runtime.electron.sourceSha256 = provenance.electronExecutableSha256;
    report.runtime.electron.modification = 'Only the expected electron-builder ASAR-integrity PE resource update; compared by reconstructing the exact executable';
  } finally { await rm(expectedElectron, { force: true }); }
  assert.equal(await fileHash(path.join(resources, 'proxy-core/mihomo.exe')), provenance.proxy.sha256.binary);
  const proxyManifest = JSON.parse(await readFile(path.join(resources, 'proxy-core/provenance.json'), 'utf8'));
  assert.equal(proxyManifest.platform, 'win32'); assert.equal(proxyManifest.arch, 'x64');
  assert.ok(!await exists(path.join(resources, 'backend/BrowseForge-sidecar')) && !await exists(path.join(resources, 'backend/playwright-driver/node')) && !await exists(path.join(resources, 'proxy-core/mihomo')));
  assert.deepEqual(await readdir(path.join(resources, 'app-routing')), ['win32']);
  report.passed = true; report.version = staged.version; report.archiveSha256 = await fileHash(archive);
  report.limitations = ['No Windows executable was run by this cross-host verifier.', 'Installer launch/uninstall, Electron GUI, browser, PTY lifecycle, AnyTLS traffic and application routing need actual Windows acceptance.', 'No driver/system service was installed or activated; current capture readiness gates remain unchanged.'];
  return report;
}

export async function verifyWindowsDesktopPreparation(run, rootDir = ROOT) {
  run = path.resolve(run);
  const allowed = path.join(rootDir, '.cache/windows-desktop');
  assert.equal(path.dirname(run), allowed, 'Verification must use an owned Windows preparation run');
  assert.ok(path.basename(run).startsWith('run-'), 'Unexpected Windows preparation directory');
  const info = await lstat(run); assert.ok(info.isDirectory() && !info.isSymbolicLink(), 'Preparation run cannot be a symlink');
  const filename = path.join(run, 'preparation.json');
  const provenance = JSON.parse(await readFile(filename, 'utf8'));
  assert.equal(provenance.run, run); assert.equal(provenance.project, path.join(run, 'project'));
  assert.equal(provenance.builderConfig, path.join(run, 'electron-builder.windows.json'));
  const appDirectory = path.join(run, 'release/win-unpacked');
  const verification = await verifyWindowsDesktopBundle({ project: provenance.project, appDirectory, provenance });
  const artifacts = [];
  for (const entry of await readdir(path.join(run, 'release'), { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith('.exe')) {
      const bytes = await readFile(path.join(run, 'release', entry.name));
      windowsPE(bytes, { machines: [0x14c, 0x8664], label: 'NSIS installer' });
      artifacts.push({ path: entry.name, sha256: sha256(bytes), size: bytes.length });
    }
  }
  assert.equal(artifacts.length, 1, 'Expected one local NSIS installation candidate');
  delete provenance.failure; delete provenance.passed;
  Object.assign(provenance, { built: true, artifacts, appDirectory, verification: path.join(run, 'verification.json') });
  provenance.signing.electronModification = 'Only the reconstructed expected ASAR-integrity PE resource update; original WinDivert driver and proxy files preserved';
  await writeFile(provenance.verification, JSON.stringify(verification, null, 2) + '\n', { mode: 0o600 });
  await writeFile(filename, JSON.stringify(provenance, null, 2) + '\n', { mode: 0o600 });
  return provenance;
}

export async function prepareWindowsDesktop({ rootDir = ROOT, build = false } = {}) {
  assert.ok(['darwin', 'win32', 'linux'].includes(process.platform), 'Unsupported build host');
  const packageInfo = JSON.parse(await readFile(path.join(rootDir, 'package.json'), 'utf8'));
  assert.equal(packageInfo.devDependencies.electron, ELECTRON_VERSION, 'Update the fixed official Windows Electron asset for the changed version');
  const lock = JSON.parse(await readFile(path.join(rootDir, 'package-lock.json'), 'utf8'));
  const run = path.join(rootDir, '.cache/windows-desktop', `run-${new Date().toISOString().replaceAll(/[:.]/g, '-')}-${randomUUID().slice(0, 8)}`);
  const project = path.join(run, 'project'), cache = path.join(rootDir, '.cache/windows-desktop/downloads');
  await mkdir(project, { recursive: true, mode: 0o700 });
  const provenance = { schema: 'envara.windows-desktop-preparation', schemaVersion: 1, version: packageInfo.version,
    platform: 'win32', arch: 'x64', buildHost: process.platform, buildHostArch: process.arch, generatedAt: new Date().toISOString(), run, project,
    nativeWindowsAcceptance: false, prepared: false, built: false };
  const report = path.join(run, 'preparation.json');
  try {
    const sourceFilter = filename => !filename.split(path.sep).some(value => ['.git', '.swift-build', '.build', 'node_modules'].includes(value));
    for (const prefix of SOURCE_PREFIXES) await cp(path.join(rootDir, prefix), path.join(project, prefix), { recursive: true, filter: sourceFilter });
    for (const filename of SOURCE_FILES) { await mkdir(path.dirname(path.join(project, filename)), { recursive: true }); await copyFile(path.join(rootDir, filename), path.join(project, filename)); }
    provenance.ownedSourceSnapshot = { electron: await treeSha256(path.join(project, 'electron')), frontend: await treeSha256(path.join(project, 'src')),
      browseforge: await treeSha256(path.join(project, 'third_party/browseforge')), windowsRouting: await treeSha256(path.join(project, 'native/windows-app-routing')) };
    console.log(`Preparing Windows x64 in isolated stage: ${run}`);
    const npmCommand = process.platform === 'win32' ? 'cmd.exe' : 'npm';
    const npmArguments = process.platform === 'win32'
      ? ['/d', '/s', '/c', 'npm ci --omit=dev --ignore-scripts --no-audit --no-fund']
      : ['ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund'];
    await execFile(npmCommand, npmArguments, { cwd: project, timeout: 240000, maxBuffer: 2 * 1024 * 1024 });
    const sidecar = await prepareSidecar({ project, rootDir, packageInfo }); provenance.sidecar = sidecar.provenance;
    const [driver, proxy, pty, electronArchive] = await Promise.all([
      prepareDriver({ project, cache }), prepareProxy({ project, rootDir, cache }), preparePty({ project, cache, lock }),
      downloadVerified(ELECTRON_URL, ELECTRON_SHA256, cache),
    ]);
    Object.assign(provenance, { driver, proxy, pty, electronArchiveSha256: ELECTRON_SHA256, electronSource: ELECTRON_URL });
    const electronDist = path.join(run, 'electron-win32-x64');
    await writeEntries(electronDist, selectedZipFiles(electronArchive, zipNames(electronArchive)));
    const electronBinary = await readFile(path.join(electronDist, 'electron.exe'));
    windowsPE(electronBinary, { label: 'Official Windows Electron.exe' }); provenance.electronExecutableSha256 = sha256(electronBinary);
    await copyDependencyLicenses(path.join(project, 'build/native/licenses'));
    const archives = path.join(rootDir, '.cache/windivert/archives');
    if (await exists(archives)) await cp(archives, path.join(project, '.cache/windivert/archives'), { recursive: true });
    await execFile(process.execPath, [path.join(project, 'scripts/build-windows-app-routing.mjs')], {
      cwd: project, env: sidecar.buildEnv, timeout: 180000, maxBuffer: 2 * 1024 * 1024,
    });
    await rm(path.join(project, 'build/app-routing/win32/arm64'), { recursive: true, force: true });
    await execFile(process.execPath, [path.join(rootDir, 'node_modules/vite/bin/vite.js'), 'build'], { cwd: project, timeout: 120000, maxBuffer: 2 * 1024 * 1024 });
    await execFile(process.execPath, [path.join(project, 'scripts/prepare-sites-build.mjs')], { cwd: project, timeout: 30000 });
    const config = { ...packageInfo.build, directories: { ...packageInfo.build.directories, output: path.join(run, 'release') },
      electronVersion: ELECTRON_VERSION, electronDist, npmRebuild: false, forceCodeSigning: false,
      win: { ...packageInfo.build.win, target: [{ target: 'nsis', arch: ['x64'] }], signAndEditExecutable: false },
    };
    const builderConfig = path.join(run, 'electron-builder.windows.json');
    await writeFile(builderConfig, JSON.stringify(config, null, 2) + '\n');
    provenance.prepared = true; provenance.builderConfig = builderConfig;
    provenance.nextBuild = { executable: process.execPath, arguments: [path.join(rootDir, 'node_modules/electron-builder/cli.js'), '--projectDir', project, '--win', '--x64', '--publish', 'never', '--config', builderConfig] };
    provenance.signing = { applicationSignedByEnvara: false, originalDriverAndProxyDependenciesPreserved: true,
      electronModification: 'electron-builder embeds the generated ASAR-integrity resource; the verifier reconstructs and checks this exact modification',
      executableResourceEditing: false, reason: 'Cross-host unsigned local candidate; no signing credential enrollment or driver modifications' };
    await writeFile(report, JSON.stringify(provenance, null, 2) + '\n', { mode: 0o600 });
    if (build) {
      console.log('Building local Windows NSIS candidate; publication disabled.');
      const result = await execFile(provenance.nextBuild.executable, provenance.nextBuild.arguments, {
        cwd: project, env: { ...process.env, CSC_IDENTITY_AUTO_DISCOVERY: 'false' }, timeout: 600000, maxBuffer: 8 * 1024 * 1024,
      });
      await writeFile(path.join(run, 'builder.log'), result.stdout + '\n' + result.stderr);
      Object.assign(provenance, await verifyWindowsDesktopPreparation(run, rootDir));
    }
    console.log(`Windows ${provenance.built ? 'candidate built and resources verified' : 'resources prepared'}; native acceptance remains pending. Evidence: ${report}`);
    return provenance;
  } catch (error) {
    provenance.failure = error.message; provenance.passed = false;
    await writeFile(report, JSON.stringify(provenance, null, 2) + '\n', { mode: 0o600 });
    if (error.stdout || error.stderr) await writeFile(path.join(run, 'builder-or-preparation-failure.log'), `${error.stdout ?? ''}\n${error.stderr ?? ''}`, { mode: 0o600 });
    throw new Error(`Windows desktop preparation/build failed; see ${report}`, { cause: error });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argumentsList = process.argv.slice(2);
  if (argumentsList.includes('--help')) console.log('Usage: node scripts/prepare-windows-desktop.mjs [--build]\n       node scripts/prepare-windows-desktop.mjs --verify /absolute/owned/run-directory\nCreates an isolated Windows x64 stage; --build also creates a local NSIS installer and verifies its packaged resources. --verify rechecks an existing owned candidate. No installation, capture activation or publication.');
  else if (argumentsList.length === 2 && argumentsList[0] === '--verify') verifyWindowsDesktopPreparation(argumentsList[1]).then(result => console.log(`Windows resource verification passed: ${result.verification}; native acceptance remains pending.`)).catch(error => { console.error(error.message); process.exitCode = 1; });
  else if (argumentsList.some(value => value !== '--build')) { console.error('Unknown argument. Use --help.'); process.exitCode = 1; }
  else prepareWindowsDesktop({ build: argumentsList.includes('--build') }).catch(error => { console.error(error.message); console.error(error.cause?.message ?? ''); process.exitCode = 1; });
}
