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
    for (const prefix of ['electron', 'dist/client']) {
      const expected = (await inventory(path.join(projectRoot, prefix), relative => prefix === 'electron' && excludedSmoke(relative))).filter(row => row.kind !== 'directory').map(row => `${prefix}/${row.relative}`);
      const actual = [...archiveFiles].filter(([relative, item]) => relative.startsWith(`${prefix}/`) && !item.files).map(([relative]) => relative);
      await check(`${prefix}/inventory`, async () => assert.deepEqual(actual.sort(), expected.sort(), 'Archive file inventory differs; missing/stale/unexpected files'));
      for (const relative of expected) await verifyArchiveEntry(relative);
    }
    await check('electron/smoke-exclusion', async () => assert.ok(!archiveRows.some(relative => relative.startsWith('electron/') && excludedSmoke(relative)), 'Development smoke harness leaked into release'));
    for (const filename of ['LICENSE', 'THIRD_PARTY_NOTICES.md', 'build/icon.png']) await verifyArchiveEntry(filename);
    report.checks.push('All owned Electron production modules and all generated dist/client files compared by SHA-256; development smoke files excluded');

    assert.ok(Array.isArray(sourcePackage.build?.extraResources) && sourcePackage.build.extraResources.length, 'No configured extraResources');
    for (const configured of sourcePackage.build.extraResources) {
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
        ? path.join(target.resources, 'app-routing/macos/EnvaraAppRouting.app/Contents/MacOS/EnvaraAppRoutingHelper')
        : path.join(target.resources, 'app-routing/win32', target.arch, 'EnvaraAppRouting.exe');
      const adapter = new NativeApplicationRouting({ helperPath, platform: target.platform, timeoutMs: 5000 });
      try {
        const raw = await adapter.request('status');
        report.nativeRouting = { tested: true, helper: posix(path.relative(target.resources, helperPath)), ...publicApplicationRoutingStatus(raw, target.platform) };
        assert.equal(report.nativeRouting.ready, false, 'Current native routing must remain unavailable until complete system acceptance');
        assert.equal(raw.ready, false, 'Helper advertised unexpected readiness');
        report.checks.push('Packaged native helper read-only status round-trip succeeds and readiness remains false; no setup/route/launch called');
      } finally { await adapter.shutdown(); }
    });
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

try {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) console.log('Usage: node scripts/verify-package-resources.mjs /absolute/Envara.app|Envara.exe\n       node scripts/verify-package-resources.mjs --resources /absolute/resources --platform darwin|win32|linux --arch arm64|x64|ia32\n       Optional: --build-platform darwin|win32|linux for executable owned ASAR files');
  else await verify(options);
} catch (error) { console.error(`Package verification failed: ${error.message}`); process.exitCode = 1; }
