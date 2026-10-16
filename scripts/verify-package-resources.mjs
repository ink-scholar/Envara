// Read-only package/source comparison. No extraction, installation or network.
// node scripts/verify-package-resources.mjs /absolute/path/Envara.app
// node scripts/verify-package-resources.mjs /absolute/path/Envara.exe --arch x64
// node scripts/verify-package-resources.mjs --resources /absolute/path/resources --platform win32 --arch x64
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, open, readFile, readdir, readlink, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as asar from '@electron/asar';
import { minimatch } from 'minimatch';
import { NativeApplicationRouting, publicApplicationRoutingStatus } from '../electron/application-routing.mjs';
import { MacOSApplicationRouting } from '../electron/macos-application-routing.mjs';
import { MacOSPFApplicationRouting } from '../electron/macos-pf-application-routing.mjs';
import { inspectDependency } from '../native/macos-local-routing/dependency.mjs';
import { PF_INSTALLATION_SCHEMA, PF_MANIFEST_FILES, inspectPFBundledComponent } from '../native/macos-pf-routing/controller.mjs';
import { driverArtifacts, NODE_VERSION } from './prepare-playwright-driver.mjs';
import { PROXY_CORE_VERSION, PROXY_CORE_COMMIT, proxyCoreArtifacts } from './prepare-proxy-core.mjs';
import { PF_RUNTIME_MODULE_FILES } from './build-macos-pf-routing.mjs';
import { bundledPFRoutingPaths } from '../electron/macos-pf-resources.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const posix = value => value.split(path.sep).join('/');
const mode = info => (info.mode & 0o7777).toString(8).padStart(4, '0');
// builder-util/out/fs.js copyOrLinkFile: owner executable implies executable
// for group/others, all files become group/others readable, setuid/gid cleared.
const packagedFileMode = value => mode({ mode: (Number.parseInt(value, 8) | 0o44 | (Number.parseInt(value, 8) & 0o100 ? 0o11 : 0)) & ~0o6000 });
const sha256Bytes = bytes => createHash('sha256').update(bytes).digest('hex');
async function sha256File(filename) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filename)) hash.update(chunk);
  return hash.digest('hex');
}
const kind = info => info.isSymbolicLink() ? 'symlink' : info.isDirectory() ? 'directory' : info.isFile() ? 'file' : 'unsupported';
const excludedSmoke = filename => path.posix.basename(filename) === 'smoke.mjs' || path.posix.basename(filename).endsWith('-smoke.mjs');
const within = (root, filename) => filename === root || (!path.relative(root, filename).startsWith(`..${path.sep}`) && path.relative(root, filename) !== '..' && !path.isAbsolute(path.relative(root, filename)));

function parseArguments(values) {
  const result = {};
  for (let index = 0; index < values.length; index++) {
    const value = values[index];
    if (value === '--help' || value === '-h') result.help = true;
    else if (['--resources', '--platform', '--arch', '--build-platform'].includes(value)) {
      assert.ok(values[index + 1] && !values[index + 1].startsWith('--'), `${value} requires a value`);
      result[value.slice(2)] = values[++index];
    } else if (value.startsWith('--')) throw new Error(`Unknown option: ${value}`);
    else { assert.equal(result.target, undefined, 'Specify one application or resources path'); result.target = value; }
  }
  for (const key of ['target', 'resources']) if (result[key]) assert.ok(path.isAbsolute(result[key]), `${key} must be an absolute path`);
  result.platform = { macos: 'darwin', mac: 'darwin', windows: 'win32', win: 'win32' }[result.platform] ?? result.platform;
  result.buildPlatform = { macos: 'darwin', mac: 'darwin', windows: 'win32', win: 'win32' }[result['build-platform']] ?? result['build-platform'];
  result.arch = { aarch64: 'arm64', amd64: 'x64', x86_64: 'x64', x86: 'ia32' }[result.arch] ?? result.arch;
  if (result.platform) assert.ok(['darwin', 'win32', 'linux'].includes(result.platform), 'Unsupported platform');
  if (result.buildPlatform) assert.ok(['darwin', 'win32', 'linux'].includes(result.buildPlatform), 'Unsupported build platform');
  if (result.arch) assert.ok(['arm64', 'x64', 'ia32'].includes(result.arch), 'Unsupported architecture');
  return result;
}

async function binaryTarget(filename) {
  const handle = await open(filename, 'r');
  try {
    const header = Buffer.alloc(4096); const { bytesRead } = await handle.read(header, 0, header.length, 0);
    assert.ok(bytesRead >= 64, 'Main executable has no recognized binary header');
    const magic = header.readUInt32LE(0);
    if ([0xfeedfacf, 0xfeedface].includes(magic)) {
      const cpu = header.readUInt32LE(4);
      return { platform: 'darwin', arch: ({ 0x0100000c: 'arm64', 0x01000007: 'x64', 7: 'ia32' })[cpu] };
    }
    if (header[0] === 0x4d && header[1] === 0x5a) {
      const offset = header.readUInt32LE(0x3c); const pe = Buffer.alloc(6);
      assert.equal((await handle.read(pe, 0, pe.length, offset)).bytesRead, pe.length, 'Incomplete PE header');
      assert.equal(pe.subarray(0, 4).toString('hex'), '50450000', 'Invalid PE signature');
      return { platform: 'win32', arch: ({ 0xaa64: 'arm64', 0x8664: 'x64', 0x14c: 'ia32' })[pe.readUInt16LE(4)] };
    }
    if (header.subarray(0, 4).toString('hex') === '7f454c46') {
      const machine = header[5] === 1 ? header.readUInt16LE(18) : header.readUInt16BE(18);
      return { platform: 'linux', arch: ({ 183: 'arm64', 62: 'x64', 3: 'ia32' })[machine] };
    }
    throw new Error('Unrecognized main executable; supply a resources directory and explicit platform/arch');
  } finally { await handle.close(); }
}

async function locate(options) {
  let resources = options.resources, executable, detected = {};
  if (options.target) {
    const target = await realpath(options.target), info = await lstat(target);
    if (info.isDirectory() && target.toLowerCase().endsWith('.app')) {
      resources ??= path.join(target, 'Contents/Resources'); executable = path.join(target, 'Contents/MacOS/Envara');
    } else if (info.isFile() && target.toLowerCase().endsWith('.exe')) {
      resources ??= path.join(path.dirname(target), 'resources'); executable = target;
    } else if (info.isDirectory()) resources ??= target;
    else throw new Error('Target must be an Envara.app, Windows executable or resources directory');
  }
  assert.ok(resources, 'Provide an absolute application or resources path');
  resources = await realpath(resources);
  if (executable) detected = await binaryTarget(executable);
  else {
    const provenance = JSON.parse(await readFile(path.join(resources, 'backend/sidecar-provenance.json'), 'utf8'));
    detected = { platform: provenance.goos === 'windows' ? 'win32' : provenance.goos, arch: provenance.goarch === 'amd64' ? 'x64' : provenance.goarch === '386' ? 'ia32' : provenance.goarch };
  }
  for (const key of ['platform', 'arch']) {
    assert.ok(options[key] ?? detected[key], `Cannot infer ${key}; supply --${key}`);
    if (options[key] && detected[key]) assert.equal(options[key], detected[key], `Requested ${key} disagrees with package binary/provenance`);
  }
  return { resources, executable, platform: options.platform ?? detected.platform, arch: options.arch ?? detected.arch };
}

async function inventory(root, exclude = () => false) {
  const rows = [];
  const visit = async (filename, relative) => {
    if (exclude(relative)) return;
    const info = await lstat(filename); const entry = { relative, kind: kind(info), mode: mode(info), size: info.size };
    if (entry.kind === 'symlink') entry.link = await readlink(filename);
    rows.push(entry);
    if (entry.kind === 'directory') for (const name of (await readdir(filename)).sort()) await visit(path.join(filename, name), relative ? `${relative}/${name}` : name);
  };
  await visit(root, ''); return rows;
}

function resourceFilter(patterns = ['**/*']) {
  assert.ok(Array.isArray(patterns) && patterns.every(value => typeof value === 'string'), 'Resource filters must be a string array');
  const positive = patterns.filter(value => !value.startsWith('!')), negative = patterns.filter(value => value.startsWith('!')).map(value => value.slice(1));
  return relative => !relative || ((!positive.length || positive.some(pattern => minimatch(relative, pattern, { dot: true }))) && !negative.some(pattern => minimatch(relative, pattern, { dot: true })));
}

export function packagedResourceEntries(build, platform, arch) {
  const platformKey = { darwin: 'mac', win32: 'win', linux: 'linux' }[platform];
  assert.ok(platformKey && ['arm64', 'x64', 'ia32'].includes(arch), 'Unsupported resource target');
  const expand = value => value.replaceAll('${arch}', arch);
  return [...(build.extraResources ?? []), ...(build[platformKey]?.extraResources ?? [])].map(entry => ({
    ...entry, from: expand(entry.from), to: expand(entry.to), filter: entry.filter?.map(expand),
  }));
}

/** Resource integrity only: never installs, activates, or executes the PF payload. */
export async function inspectPFRoutingResources({ resourceRoot, arch = process.arch, sourceRoot = projectRoot } = {}) {
  assert.ok(path.isAbsolute(resourceRoot ?? ''), 'PF resource root must be absolute');
  assert.ok(['arm64', 'x64'].includes(arch), 'Unsupported PF resource architecture');
  const manifest = JSON.parse(await readFile(path.join(resourceRoot, 'manifest.json'), 'utf8'));
  assert.equal(manifest.schema, PF_INSTALLATION_SCHEMA);
  assert.equal(manifest.component, 'envara-pf-routing'); assert.equal(manifest.version, '1');
  assert.equal(manifest.backend, 'pf-utun'); assert.equal(manifest.platform, 'darwin'); assert.equal(manifest.arch, arch);
  assert.equal(manifest.ready, false, 'Bundled resources cannot advertise production readiness');
  assert.equal(manifest.nativeAcceptance, false, 'Resource build is not native routing acceptance');
  assert.ok(manifest.files && typeof manifest.files === 'object' && !Array.isArray(manifest.files));
  assert.deepEqual(Object.keys(manifest.files).sort(), Object.keys(PF_MANIFEST_FILES).sort(), 'PF manifest file contract differs');
  const expectedLeaves = [...Object.keys(PF_MANIFEST_FILES), 'manifest.json', 'EnvaraPFInstall'].sort();
  const rows = await inventory(resourceRoot);
  assert.deepEqual(rows.filter(row => row.kind !== 'directory').map(row => row.relative).sort(), expectedLeaves, 'PF resource inventory differs');
  for (const row of rows) {
    assert.notEqual(row.kind, 'symlink', 'PF resources must not contain symlinks');
    assert.ok(['file', 'directory'].includes(row.kind), 'PF resources must be ordinary files/directories');
  }
  for (const [name, executable] of Object.entries(PF_MANIFEST_FILES)) {
    const filename = path.join(resourceRoot, name), info = await lstat(filename);
    assert.ok(info.isFile() && !info.isSymbolicLink(), `${name} must be a regular file`);
    assert.match(manifest.files[name], /^[0-9a-f]{64}$/, `${name} has no SHA-256`);
    assert.equal(await sha256File(filename), manifest.files[name], `${name} differs from PF manifest`);
    assert.equal((info.mode & 0o111) !== 0, executable, `${name} executable permission differs`);
  }
  for (const name of ['node', 'mihomo', 'envara-pf-native', 'EnvaraPFInstall', 'fixtures/EnvaraRoutingAcceptanceFixture']) {
    assert.deepEqual(await binaryTarget(path.join(resourceRoot, name)), { platform: 'darwin', arch }, `${name} binary target differs`);
  }
  assert.ok((await lstat(path.join(resourceRoot, 'EnvaraPFInstall'))).mode & 0o111, 'PF installer must be executable');
  const nodeArtifact = driverArtifacts('darwin', arch);
  assert.equal(manifest.node?.version, NODE_VERSION); assert.equal(manifest.node?.archiveSha256, nodeArtifact.nodeArchiveSha256);
  assert.equal(manifest.node?.source, nodeArtifact.nodeUrl);
  assert.ok(manifest.nativeSourceFiles && typeof manifest.nativeSourceFiles === 'object' && !Array.isArray(manifest.nativeSourceFiles),
    'PF manifest must record native source SHA-256 values');
  const fixtureDirectory = path.join(sourceRoot, 'native/macos-pf-routing/fixture');
  const fixtureInfo = await lstat(fixtureDirectory);
  assert.ok(fixtureInfo.isDirectory() && !fixtureInfo.isSymbolicLink(),
    'PF fixture sources must be a regular directory');
  const fixtureSources = (await readdir(fixtureDirectory)).filter(name => name.endsWith('.swift')).sort();
  assert.ok(fixtureSources.length > 0, 'PF fixture compilation sources are absent');
  const requiredNativeSources = [
    ...['Makefile', 'native.h', 'main.c', 'launcher.c', 'tunnel.c', 'transport.c', 'authorize-install.c',
      'installer-upgrade-f8.h', 'known-installations/f8.manifest.json',
      'installer-upgrade-e940.h', 'known-installations/e940.manifest.json',
      'installer-upgrade-518.h', 'known-installations/518.manifest.json',
      'installer-upgrade-2a7.h', 'known-installations/2a7.manifest.json',
      'installer-upgrade-832.h', 'known-installations/832.manifest.json',
      'installer-upgrade-ff9.h', 'known-installations/ff9.manifest.json',
      'installer-upgrade-6f8.h', 'known-installations/6f8.manifest.json',
      'installer-upgrade-199.h', 'known-installations/199.manifest.json',
      'installer-upgrade-46a.h', 'known-installations/46a.manifest.json',
      'installer-upgrade-c37.h', 'known-installations/c37.manifest.json',
      'installer-upgrade-f99.h', 'known-installations/f99.manifest.json',
      'installer-upgrade-05d6.h', 'known-installations/05d6.manifest.json',
      'installer-upgrade-14b87.h', 'known-installations/14b87.manifest.json',
      'installer-upgrade-dbcf.h', 'known-installations/dbcf.manifest.json',
      'installer-upgrade-43b.h', 'known-installations/43b.manifest.json',
      'installer-upgrade-acfc.h', 'known-installations/acfc.manifest.json',
      'installer-upgrade-c34.h', 'known-installations/c34.manifest.json', 'installer-upgrade-4b9f85.h', 'known-installations/4b9f85.manifest.json', 'installer-upgrade-43392e.h', 'known-installations/43392e.manifest.json', 'installer-upgrade-03245359.h', 'known-installations/03245359.manifest.json', 'installer-upgrade-2059a0.h', 'known-installations/2059a0.manifest.json', 'installer-upgrade-127e83.h', 'known-installations/127e83.manifest.json', 'installer-upgrade-010117.h', 'known-installations/010117.manifest.json', 'installer-upgrade-9b51cf.h', 'known-installations/9b51cf.manifest.json', 'installer-upgrade-91b62a.h', 'known-installations/91b62a.manifest.json', 'installer-upgrade-7c91a1.h', 'known-installations/7c91a1.manifest.json', 'installer-upgrade-af79b1.h', 'known-installations/af79b1.manifest.json', 'installer-upgrade-dceba9.h', 'known-installations/dceba9.manifest.json', 'installer-upgrade-fa70a2.h', 'known-installations/fa70a2.manifest.json', 'installer-upgrade-32811e.h', 'known-installations/32811e.manifest.json', 'installer-upgrade-22a6f3.h', 'known-installations/22a6f3.manifest.json', 'installer-upgrade-f0b99f.h', 'known-installations/f0b99f.manifest.json', 'installer-upgrade-f39101.h', 'known-installations/f39101.manifest.json', 'installer-upgrade-a8bd00.h', 'known-installations/a8bd00.manifest.json', 'installer-upgrade-da6e7c.h', 'known-installations/da6e7c.manifest.json', 'pf-hook.c', 'pf-hook.h', 'pf-hook-abi.h', 'pf-run-ledger.c', 'pf-run-ledger.h',
      'pf-filter-command.c', 'pf-filter-command.h',
      'pf-filter-transaction.c', 'pf-filter-transaction.h',
      'app-command.c', 'app-command.h',
      'app-control.c', 'app-control.h',
      'app-ticket.c', 'app-ticket.h',
      'app-registry.c', 'app-registry.h',
      'app-supervisor.c', 'app-supervisor.h',
      'gui-launch.m', 'gui-launch.h',
      'launch-guardian.c', 'launch-guardian.h',
      'pf-production-filter.c', 'pf-production-filter.h',
      'app-native-factory.m', 'app-native-factory.h',
      'journal-retirement.c', 'journal-retirement.h',
      'app-scope-proof.c', 'app-scope-proof.h',
      'app-transport.c', 'app-transport.h', 'transport-session.h',
      'notion-launch.m', 'notion-launch.h'].map(name => `native/macos-pf-routing/${name}`),
    'scripts/build-macos-pf-routing.mjs',
    ...fixtureSources.map(name => `native/macos-pf-routing/fixture/${name}`),
  ].sort();
  assert.deepEqual(Object.keys(manifest.nativeSourceFiles).sort(), requiredNativeSources, 'PF native source inventory differs');
  for (const name of requiredNativeSources) {
    const filename = path.join(sourceRoot, name), info = await lstat(filename);
    assert.ok(info.isFile() && !info.isSymbolicLink(), `${name} must be a regular native source file`);
    assert.match(manifest.nativeSourceFiles[name], /^[0-9a-f]{64}$/, `${name} has no native source SHA-256`);
    assert.equal(manifest.nativeSourceFiles[name], await sha256File(filename), `${name} differs from build-time native source`);
  }
  for (const name of PF_RUNTIME_MODULE_FILES) {
    const filename = path.join(sourceRoot, 'native/macos-pf-routing', name), info = await lstat(filename);
    assert.ok(info.isFile() && !info.isSymbolicLink(), `${name} must be a regular production source file`);
    assert.equal(manifest.files[name], await sha256File(filename), `${name} differs from production source`);
  }
  const coreArtifact = proxyCoreArtifacts('darwin', arch);
  const coreRoot = path.join(sourceRoot, 'build/proxy-core');
  const core = JSON.parse(await readFile(path.join(coreRoot, 'provenance.json'), 'utf8'));
  assert.equal(core.core, 'mihomo'); assert.equal(core.version, PROXY_CORE_VERSION); assert.equal(core.commit, PROXY_CORE_COMMIT);
  assert.equal(core.platform, 'darwin'); assert.equal(core.arch, arch); assert.equal(core.binaryName, coreArtifact.binaryName);
  assert.equal(core.sha256?.archive, coreArtifact.archiveSha256); assert.equal(core.sha256?.sourceArchive, coreArtifact.sourceSha256);
  assert.equal(core.correspondingSource, 'mihomo-corresponding-source.tar.gz');
  assert.equal(manifest.mihomo?.version, PROXY_CORE_VERSION); assert.equal(manifest.mihomo?.commit, PROXY_CORE_COMMIT);
  assert.equal(manifest.mihomo?.sourceArchiveSha256, coreArtifact.sourceSha256);
  for (const [name, origin, digest] of [
    ['mihomo', core.binaryName, core.sha256.binary], ['mihomo-LICENSE', 'LICENSE', core.sha256.license],
    ['mihomo-corresponding-source.tar.gz', core.correspondingSource, core.sha256.correspondingSource],
    ['mihomo-SOURCE.md', 'SOURCE.md', await sha256File(path.join(coreRoot, 'SOURCE.md'))],
  ]) {
    assert.equal(manifest.files[name], digest, `${name} differs from pinned dependency provenance`);
    assert.equal(await sha256File(path.join(coreRoot, origin)), digest, `${name} source build differs from provenance`);
  }
  assert.equal(manifest.files.LICENSE, await sha256File(path.join(sourceRoot, 'LICENSE')), 'PF owned license differs');
  const staged = path.join(sourceRoot, 'build/app-routing/macos-pf');
  for (const name of ['node', 'node-LICENSE', 'envara-pf-native', 'EnvaraPFHelper', 'EnvaraPFInstall', 'fixtures/EnvaraRoutingAcceptanceFixture']) {
    assert.equal(await sha256File(path.join(resourceRoot, name)), await sha256File(path.join(staged, name)), `${name} differs from the prepared source build`);
  }
  const bundled = await inspectPFBundledComponent({ root: resourceRoot });
  assert.equal(bundled.verified, true, 'PF runtime bundled-resource inspector rejected the payload');
  assert.equal(bundled.installed, false, 'Bundled resources are not a privileged installation');
  return { verified: true, backend: 'pf-utun', component: 'envara-pf-routing', manifestSha256: await sha256File(path.join(resourceRoot, 'manifest.json')),
    installerSha256: await sha256File(path.join(resourceRoot, 'EnvaraPFInstall')), platform: 'darwin', arch,
    manifestFiles: Object.keys(PF_MANIFEST_FILES).length, nodeVersion: NODE_VERSION, mihomoVersion: PROXY_CORE_VERSION,
    binaryTargetChecked: true, dependencyLicenseAndSourceChecked: true, sourceBuildCompared: true,
    nativeSourceHashesChecked: true, nativeSourceFiles: requiredNativeSources.length,
    readOnly: true, installed: false, authorized: false, nativeAcceptance: false, ready: false };
}

async function verify(options) {
  const sourcePackage = JSON.parse(await readFile(path.join(projectRoot, 'package.json'), 'utf8'));
  // Preflight failures must replace the current attempt's report as well, so a
  // missing package/provenance cannot leave an old PASS looking freshly valid.
  let target = { resources: options.resources ?? options.target,
    platform: options.platform ?? (options.target?.toLowerCase().endsWith('.app') ? 'darwin' : options.target?.toLowerCase().endsWith('.exe') ? 'win32' : process.platform),
    arch: options.arch ?? process.arch };
  const report = { schema: 'envara.package-resources', schemaVersion: 1, passed: false, version: sourcePackage.version,
    platform: target.platform, arch: target.arch, resources: target.resources, generatedAt: new Date().toISOString(),
    scope: 'Byte-identical owned production modules, generated frontend, licenses and configured extraResources. ASAR stores executable flags, not full POSIX modes. Dependency inventory/runtime acceptance is covered by separate packaged tests.',
    counts: { archiveFiles: 0, resourceFiles: 0, directories: 0, symlinks: 0 }, checks: [], failures: [], files: [], nativeRouting: null,
    limitations: ['This resource comparison does not verify Windows ACLs or native routing acceptance on another operating system/architecture.'] };
  const recordFailure = (name, error) => report.failures.push({ path: name, message: error.message });
  const check = async (name, operation) => { try { await operation(); } catch (error) { recordFailure(name, error); } };
  const reportDirectory = path.join(projectRoot, 'test-artifacts/package-verification');
  try {
    target = await locate(options);
    Object.assign(report, { platform: target.platform, arch: target.arch, resources: target.resources, locationVerified: true });
    const archive = path.join(target.resources, 'app.asar');
    const archiveInfo = await lstat(archive); assert.ok(archiveInfo.isFile());
    report.archive = { sha256: await sha256File(archive), size: archiveInfo.size, mode: mode(archiveInfo) };
    if (process.platform !== 'win32') await check('app.asar/permissions', async () => assert.equal(mode(archiveInfo), '0644', 'ASAR must remain a regular readable, non-executable file'));
    report.permissionPolicy = { filesystemFiles: 'electron-builder copyOrLinkFile normalization: add group/others read; owner execute implies group/others execute; remove setuid/setgid',
      ruleSource: 'node_modules/builder-util/out/fs.js', ruleSourceSha256: await sha256File(path.join(projectRoot, 'node_modules/builder-util/out/fs.js')),
      filesystemDirectories: process.platform === 'win32' ? 'Compare observable Node directory modes; ACLs are not represented' : 'Installed resource directories must be 0755; builder copyDir creates directories rather than preserving source modes',
      archiveFiles: 'ASAR executable metadata represents owner execute on non-Windows build hosts; full POSIX mode is unavailable. An executable owned file requires --build-platform when its archive build host is ambiguous',
      buildPlatform: options.buildPlatform ?? (target.platform === 'darwin' ? 'darwin' : null),
      windowsLimit: 'Node permission modes do not verify Windows ACLs' };
    const packagedPackage = JSON.parse(asar.extractFile(archive, 'package.json').toString('utf8'));
    await check('package.json', async () => {
      for (const key of ['name', 'version', 'author', 'license', 'main', 'type', 'description', 'dependencies']) assert.deepEqual(packagedPackage[key], sourcePackage[key], `Packaged ${key} differs from source`);
      report.package = { name: packagedPackage.name, version: packagedPackage.version, author: packagedPackage.author, license: packagedPackage.license,
        sha256: sha256Bytes(asar.extractFile(archive, 'package.json')), permissionStorage: 'asar-executable-flag' };
      report.checks.push('Packaged identity, version, author, entry point and production dependency versions match package.json');
    });

    const archiveRows = asar.listPackage(archive).map(value => value.replace(/^[/\\]+/, '').replaceAll('\\', '/'));
    const archiveFiles = new Map(archiveRows.map(relative => [relative, asar.statFile(archive, relative, false)]));
    const verifyArchiveEntry = async relative => check(relative, async () => {
      const sourcePath = path.join(projectRoot, relative), info = await lstat(sourcePath), item = archiveFiles.get(relative);
      assert.ok(item, 'Missing from app.asar');
      const row = { path: relative, storage: 'asar', kind: kind(info), sourceMode: mode(info), permissionStorage: 'asar-executable-flag' };
      if (info.isSymbolicLink()) {
        const link = await readlink(sourcePath), resolved = path.resolve(path.dirname(sourcePath), link);
        assert.ok(within(projectRoot, resolved), 'Source symlink escapes project');
        assert.equal(item.link, posix(path.relative(projectRoot, resolved)), 'ASAR symlink target differs');
        row.link = item.link; report.counts.symlinks++;
      } else {
        assert.ok(info.isFile(), 'Unsupported source entry'); assert.equal(item.files, undefined, 'ASAR entry is a directory'); assert.equal(item.link, undefined, 'ASAR entry is a symlink');
        const expectedHash = await sha256File(sourcePath), bytes = asar.extractFile(archive, relative);
        assert.equal(bytes.length, info.size, 'File size differs'); assert.equal(sha256Bytes(bytes), expectedHash, 'File SHA-256 differs');
        const ownerExecutable = (info.mode & 0o100) !== 0, buildPlatform = report.permissionPolicy.buildPlatform;
        if (ownerExecutable) assert.ok(buildPlatform, 'Executable source file needs --build-platform to verify ASAR metadata across build hosts');
        assert.equal(item.executable === true, ownerExecutable && buildPlatform !== 'win32', 'Executable flag differs');
        if (item.integrity) { assert.equal(item.integrity.algorithm, 'SHA256'); assert.equal(item.integrity.hash, expectedHash, 'ASAR integrity metadata differs'); }
        Object.assign(row, { sha256: expectedHash, size: bytes.length, executable: item.executable === true }); report.counts.archiveFiles++;
      }
      report.files.push(row);
    });
    await check('native/macos-pf-routing/packaging-pattern', async () => assert.ok(sourcePackage.build.files.includes('native/macos-pf-routing/*.mjs'), 'PF production modules need their explicit ASAR packaging pattern'));
    for (const prefix of ['electron', 'shared', 'dist/client', 'native/macos-local-routing', 'native/macos-pf-routing']) {
      const expected = (await inventory(path.join(projectRoot, prefix), relative =>
        (prefix === 'electron' && excludedSmoke(relative)) || path.posix.basename(relative) === '.gitignore' ||
        (prefix === 'native/macos-pf-routing' && relative !== '' && !minimatch(relative, '*.mjs', { dot: true }))
      )).filter(row => row.kind !== 'directory').map(row => `${prefix}/${row.relative}`);
      const actual = [...archiveFiles].filter(([relative, item]) => relative.startsWith(`${prefix}/`) && !item.files).map(([relative]) => relative);
      await check(`${prefix}/inventory`, async () => assert.deepEqual(actual.sort(), expected.sort(), 'Archive file inventory differs; missing/stale/unexpected files'));
      for (const relative of expected) await verifyArchiveEntry(relative);
    }
    await check('electron/smoke-exclusion', async () => assert.ok(!archiveRows.some(relative => relative.startsWith('electron/') && excludedSmoke(relative)), 'Development smoke harness leaked into release'));
    for (const filename of ['LICENSE', 'THIRD_PARTY_NOTICES.md', 'build/icon.png']) await verifyArchiveEntry(filename);
    report.checks.push('All owned Electron production modules, shared language catalog, macOS local-routing modules, explicitly packaged macOS PF .mjs modules and all generated dist/client files compared by SHA-256; development smoke files excluded');

    assert.ok(Array.isArray(sourcePackage.build?.extraResources) && sourcePackage.build.extraResources.length, 'No configured extraResources');
    for (const configured of packagedResourceEntries(sourcePackage.build, target.platform, target.arch)) {
      assert.ok(configured && typeof configured.from === 'string' && typeof configured.to === 'string', 'extraResources must explicitly name from/to');
      const source = path.resolve(projectRoot, configured.from), destination = path.resolve(target.resources, configured.to);
      assert.ok(within(projectRoot, source) && within(target.resources, destination), 'Resource configuration escapes allowed root');
      await check(`resources/${configured.to}`, async () => {
        const rootInfo = await lstat(source);
        const excludedSwift = relative => relative.split('/').includes('.swift-build');
        const sourceRows = await inventory(source, configured.from === 'build/app-routing' ? excludedSwift : undefined);
        const include = resourceFilter(configured.filter);
        const sourceLeaves = sourceRows.filter(row => row.kind !== 'directory' && include(row.relative));
        const includedPaths = new Set(sourceLeaves.flatMap(row => {
          const values = [row.relative]; let parent = path.posix.dirname(row.relative);
          while (parent !== '.') { values.push(parent); parent = path.posix.dirname(parent); } values.push(''); return values;
        }));
        if (!rootInfo.isDirectory()) includedPaths.add('');
        const expectedRows = sourceRows.filter(row => includedPaths.has(row.relative));
        const actualRows = await inventory(destination);
        assert.deepEqual(actualRows.map(row => `${row.relative}:${row.kind}`).sort(), expectedRows.map(row => `${row.relative}:${row.kind}`).sort(), 'Resource inventory differs');
        const actualByPath = new Map(actualRows.map(row => [row.relative, row]));
        for (const sourceEntry of expectedRows) {
          const relative = sourceEntry.relative, actual = actualByPath.get(relative), from = path.join(source, relative), to = path.join(destination, relative);
          await check(`resources/${configured.to}${relative ? `/${relative}` : ''}`, async () => {
            const expectedPackagedMode = sourceEntry.kind === 'file' ? packagedFileMode(sourceEntry.mode) : sourceEntry.kind === 'directory' && process.platform !== 'win32' ? '0755' : sourceEntry.mode;
            const row = { path: `resources/${configured.to}${relative ? `/${relative}` : ''}`, source: posix(path.relative(projectRoot, from)), storage: 'filesystem', kind: sourceEntry.kind,
              sourceMode: sourceEntry.mode, expectedPackagedMode, packagedMode: actual.mode, permissionStorage: process.platform === 'win32' ? 'windows-node-mode-observation' : 'posix-mode' };
            if (sourceEntry.kind === 'file') {
              assert.equal(actual.size, sourceEntry.size, 'File size differs'); const expectedHash = await sha256File(from);
              assert.equal(await sha256File(to), expectedHash, 'File SHA-256 differs'); Object.assign(row, { sha256: expectedHash, size: sourceEntry.size }); report.counts.resourceFiles++;
            } else if (sourceEntry.kind === 'symlink') {
              assert.equal(actual.link, sourceEntry.link, 'Symlink text differs');
              assert.ok(!path.isAbsolute(actual.link) && within(destination, path.resolve(path.dirname(to), actual.link)), 'Packaged symlink escapes its resource');
              assert.ok(within(destination, await realpath(to)), 'Packaged symlink resolves outside its resource'); row.link = actual.link; report.counts.symlinks++;
            } else { assert.equal(sourceEntry.kind, 'directory'); report.counts.directories++; }
            report.files.push(row);
            assert.equal(actual.mode, expectedPackagedMode, 'Filesystem permissions differ from electron-builder normalization');
          });
        }
      });
    }
    report.checks.push('Every configured extraResources inventory, file SHA-256, permission mode and symlink compared; .swift-build excluded');
    await check('resources/app-routing/macos-pf-manifest', async () => {
      if (target.platform !== 'darwin') return;
      report.pfResources = await inspectPFRoutingResources({ resourceRoot: bundledPFRoutingPaths(target.resources).directory, arch: target.arch });
      report.checks.push('PF fixed-file manifest, native/Node/installer targets, dependency pins, licenses, corresponding source and source-build hashes verified read-only; bundled does not imply installed, authorized or ready');
    });
    /* The app pins one exact trial candidate and derives the carrier it loads
     * from that pin. A build whose pin and bundled carrier disagree passes every
     * per-file check above yet cannot authorize anything, and it hides the
     * component upgrade from the user. Compare them here, before handover. */
    await check('resources/local-authorization/pinned-carrier', async () => {
      if (target.platform !== 'darwin') return;
      const source = asar.extractFile(archive, 'electron/macos-pf-notion-trial.mjs').toString('utf8');
      const pinned = /PF_NOTION_TRIAL_CANDIDATE = Object\.freeze\(\{\s*authorizerSHA256: '([0-9a-f]{64})',\s*manifestSHA256: '([0-9a-f]{64})',/.exec(source);
      assert.ok(pinned, 'The packaged app does not declare a parseable trial candidate pin');
      const [, authorizerSHA256, manifestSHA256] = pinned;
      const carriers = (await readdir(path.join(target.resources, 'local-authorization'))).filter(name => name.endsWith('.app')).sort();
      const expected = `EnvaraPFAuthorization-${manifestSHA256.slice(0, 12)}.app`;
      assert.deepEqual(carriers, [expected], `Bundled carriers ${JSON.stringify(carriers)} do not match the pinned candidate ${expected}`);
      const payload = path.join(target.resources, 'local-authorization', expected, 'Contents/Resources/app-routing/macos-pf');
      assert.equal(await sha256File(path.join(payload, 'manifest.json')), manifestSHA256, 'Bundled carrier manifest differs from the pinned candidate');
      assert.equal(await sha256File(path.join(payload, 'EnvaraPFInstall')), authorizerSHA256, 'Bundled carrier installer differs from the pinned candidate');
      assert.equal(bundledPFRoutingPaths(target.resources).directory, payload, 'Production routing must use the pinned carrier payload');
      assert.equal(await lstat(path.join(target.resources, 'app-routing/macos-pf')).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; }), false,
        'A redundant second PF payload must not be packaged');
      assert.equal(await lstat(path.join(target.resources, 'app-routing/win32')).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; }), false,
        'Windows routing binaries must not be packaged in the Mac app');
      report.checks.push('Pinned trial candidate, its single complete carrier and production routing share one payload; duplicate PF and foreign Windows resources are absent');
    });
    await check('resources/app-routing/original-macos-dependency', async () => {
      if (target.platform !== 'darwin' || process.platform !== 'darwin') return;
      const appPath = path.join(target.resources, 'app-routing/macos-local/Resources/Mitmproxy Redirector.app');
      const original = await inspectDependency({ appPath });
      assert.equal(original.binaryVerified, true, 'Packaged original signature, hashes or dual-architecture identity mismatch');
      assert.equal(original.gatekeeperAccepted, true, 'Packaged original dependency did not pass Gatekeeper');
      report.originalMacDependency = { version: original.packageVersion, sourceCommit: original.sourceCommit,
        signatureVerified: true, gatekeeperAccepted: true, originalIdentityPreserved: true,
        nativeCaptureTested: false, fullAcceptance: false };
      assert.ok(!(await inventory(path.join(target.resources, 'app-routing/macos-local'))).some(row => /certificate-truster/i.test(row.relative)), 'Certificate truster must not be packaged');
      report.checks.push('Original macOS Redirector signature and notarization preserved; certificate-truster excluded; no activation performed');
    });
    await check('resources/provenance-target', async () => {
      const backend = JSON.parse(await readFile(path.join(target.resources, 'backend/sidecar-provenance.json'), 'utf8'));
      const proxy = JSON.parse(await readFile(path.join(target.resources, 'proxy-core/provenance.json'), 'utf8'));
      assert.equal(backend.envaraVersion, sourcePackage.version); assert.equal(backend.goos === 'windows' ? 'win32' : backend.goos, target.platform);
      assert.equal(({ amd64: 'x64', '386': 'ia32' })[backend.goarch] ?? backend.goarch, target.arch);
      assert.equal(proxy.platform, target.platform); assert.equal(proxy.arch, target.arch);
      const sidecar = path.join(target.resources, 'backend', target.platform === 'win32' ? 'BrowseForge-sidecar.exe' : 'BrowseForge-sidecar');
      assert.equal(await sha256File(sidecar), backend.binarySha256, 'Sidecar differs from bundled provenance');
      assert.equal(await sha256File(path.join(target.resources, 'proxy-core', proxy.binaryName)), proxy.sha256.binary, 'Proxy core differs from bundled provenance');
      report.checks.push('Sidecar/proxy binary hashes, architecture, platform and Envara version match bundled provenance');
    });
    await check('resources/app-routing/native-status', async () => {
      if (!['darwin', 'win32'].includes(target.platform) || target.platform !== process.platform || target.arch !== process.arch) {
        report.nativeRouting = { tested: false, ready: null, expectedReady: false, reason: 'Packaged native helper cannot be executed on this host/architecture' }; return;
      }
      const helperPath = target.platform === 'darwin'
        ? bundledPFRoutingPaths(target.resources).helperPath
        : path.join(target.resources, 'app-routing/win32', target.arch, 'EnvaraAppRouting.exe');
      if (target.platform === 'darwin') assert.equal(report.pfResources?.verified, true, 'Refuse to execute an unverified packaged PF helper');
      const adapter = new NativeApplicationRouting({ helperPath, platform: target.platform, timeoutMs: 5000 });
      try {
        const raw = await adapter.request('status');
        report.nativeRouting = { tested: true, helper: posix(path.relative(target.resources, helperPath)), ...publicApplicationRoutingStatus(raw, target.platform) };
        assert.equal(report.nativeRouting.ready, false, 'Current native routing must remain unavailable until complete system acceptance');
        assert.equal(raw.ready, false, 'Helper advertised unexpected readiness');
        if (target.platform === 'darwin') {
          assert.equal(raw.backend, 'pf-utun'); assert.equal(raw.readOnly, true); assert.equal(raw.productionReceiptAllowed, false);
          assert.equal(raw.verification?.native, false); assert.equal(raw.verification?.passed, false);
          report.nativeRouting.backend = 'pf-utun'; report.nativeRouting.nativeAcceptance = false;
        }
        report.checks.push('Packaged native helper read-only status round-trip succeeds and readiness remains false; no setup/route/launch called');
      } finally { await adapter.shutdown(); }
    });
    if (target.platform === 'darwin' && process.platform === 'darwin' && target.arch === process.arch) {
      await check('resources/app-routing/mac-production-status', async () => {
        assert.equal(report.pfResources?.verified, true, 'Refuse to execute an unverified packaged PF helper');
        const adapter = new MacOSPFApplicationRouting({ helperPath: bundledPFRoutingPaths(target.resources).helperPath });
        try {
          const raw = await adapter.status();
          report.macProductionRouting = { tested: true, ...raw };
          assert.equal(raw.backend, 'pf-utun'); assert.equal(raw.component?.name, 'envara-pf-routing');
          assert.equal(raw.requiresAppleNetworkExtension, false); assert.equal(raw.authorization?.kind, 'privileged-helper');
          assert.equal(raw.installed, report.nativeRouting.installed); assert.equal(raw.authorized, report.nativeRouting.authorized);
          assert.equal(raw.ready, false); assert.equal(raw.productionReady, false); assert.equal(raw.protected, false);
          assert.equal(raw.verification.native, false); assert.equal(raw.verification.passed, false);
          report.checks.push('Mac production status uses the PF privileged-helper acceptance gates and remains unready; no setup, route, installer, tunnel or application launch called');
        } finally { await adapter.shutdown(); }
      });
      await check('resources/app-routing/mac-legacy-ne-diagnostic-status', async () => {
        const adapter = new MacOSApplicationRouting({
          helperPath: path.join(target.resources, 'app-routing/macos/EnvaraAppRouting.app/Contents/MacOS/EnvaraAppRoutingHelper'),
          peerVerifierPath: path.join(target.resources, 'app-routing/macos-local/EnvaraPeerVerifier'),
          bundledAppPath: path.join(target.resources, 'app-routing/macos-local/Resources/Mitmproxy Redirector.app'),
        });
        try {
          const raw = await adapter.status();
          report.macLegacyNERouting = { tested: true, diagnosticOnly: true, ...publicApplicationRoutingStatus(raw, 'darwin') };
          assert.equal(report.macLegacyNERouting.component?.name, 'Envara · App Proxy');
          assert.equal(report.macLegacyNERouting.ready, false);
          report.checks.push('Legacy owned AppProxy status and original Redirector licensing/signature remain separate diagnostics, without activation or launch');
        } finally { await adapter.shutdown(); }
      });
    }
  } catch (error) { recordFailure('verification', error); }
  finally {
    report.passed = report.failures.length === 0;
    const reportPath = path.join(reportDirectory, `${sourcePackage.version}-${report.platform}-${report.arch}.json`);
    await mkdir(reportDirectory, { recursive: true }); await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
    console.log(`${report.passed ? 'PASS' : 'FAIL'} Envara ${report.version} ${report.platform}-${report.arch}: ${report.counts.archiveFiles} archive files, ${report.counts.resourceFiles} resource files, ${report.counts.directories} directories, ${report.counts.symlinks} symlinks.`);
    if (report.nativeRouting?.tested === false) console.log(`SKIP native helper status: ${report.nativeRouting.reason}. Native acceptance remains unverified.`);
    console.log(`Evidence: ${reportPath}`);
    if (report.failures.length) { for (const failure of report.failures) console.error(`${failure.path}: ${failure.message}`); process.exitCode = 1; }
    asar.uncacheAll();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) try {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) console.log('Usage: node scripts/verify-package-resources.mjs /absolute/Envara.app|Envara.exe\n       node scripts/verify-package-resources.mjs --resources /absolute/resources --platform darwin|win32|linux --arch arm64|x64|ia32\n       Optional: --build-platform darwin|win32|linux for executable owned ASAR files');
  else await verify(options);
} catch (error) { console.error(`Package verification failed: ${error.message}`); process.exitCode = 1; }
