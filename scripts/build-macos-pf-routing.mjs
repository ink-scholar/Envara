import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { execFile as execFileCallback } from 'node:child_process';
import { promisify } from 'node:util';
import { access, copyFile, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { driverArtifacts, tarGzFiles, NODE_VERSION } from './prepare-playwright-driver.mjs';
import { PROXY_CORE_VERSION, PROXY_CORE_COMMIT, proxyCoreArtifacts } from './prepare-proxy-core.mjs';

const execute = promisify(execFileCallback);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
async function fileDigest(filename) { const hash = createHash('sha256'); for await (const bytes of createReadStream(filename)) hash.update(bytes); return hash.digest('hex'); }
async function exists(filename) { try { await access(filename); return true; } catch { return false; } }

// Shared source-only contracts. Runtime modules are copied/hash-pinned payload
// files; dependency preparers are build inputs, not native compiler sources.
export const PF_RUNTIME_MODULE_FILES = Object.freeze(['helper.mjs', 'controller.mjs',
  'helper-production-native.mjs', 'notion-front-service.mjs', 'notion-socks-front.mjs', 'notion-socks-reader.mjs',
  'policy.mjs', 'stateless-verifier.mjs']);
export const PF_BUILD_DEPENDENCY_INPUTS = Object.freeze(['scripts/prepare-playwright-driver.mjs', 'scripts/prepare-proxy-core.mjs']);

/** Build resources only. This never installs a helper, opens utun, or invokes PF. */
export async function buildMacOSPF({ root = ROOT, output = path.join(root, 'build/app-routing/macos-pf'),
  platform = process.platform, arch = process.arch, exec = execute } = {}) {
  if (platform !== 'darwin' || platform !== process.platform || arch !== process.arch) throw new Error('Build the PF helper on its native macOS architecture.');
  const source = path.join(root, 'native/macos-pf-routing');
  const fixtureNames = ['Entry.swift', 'FixtureRuntime.swift', 'FixtureProbe.swift', 'FixtureProtocol.swift', 'ProcessIdentity.swift'];
  const nativeInputs = [
    'Makefile',
    'native.h',
    'main.c',
    'launcher.c',
    'tunnel.c',
    'transport.c',
    'authorize-install.c',
    'installer-upgrade-f8.h',
    'known-installations/f8.manifest.json',
    'installer-upgrade-e940.h',
    'known-installations/e940.manifest.json',
    'installer-upgrade-518.h',
    'known-installations/518.manifest.json',
    'installer-upgrade-2a7.h',
    'known-installations/2a7.manifest.json',
    'installer-upgrade-832.h',
    'known-installations/832.manifest.json',
    'installer-upgrade-ff9.h',
    'known-installations/ff9.manifest.json',
    'installer-upgrade-6f8.h',
    'known-installations/6f8.manifest.json',
    'installer-upgrade-199.h',
    'known-installations/199.manifest.json',
    'installer-upgrade-46a.h',
    'known-installations/46a.manifest.json',
    'installer-upgrade-c37.h',
    'known-installations/c37.manifest.json',
    'installer-upgrade-f99.h',
    'known-installations/f99.manifest.json',
    'installer-upgrade-05d6.h',
    'known-installations/05d6.manifest.json',
    'installer-upgrade-14b87.h',
    'known-installations/14b87.manifest.json',
    'installer-upgrade-dbcf.h',
    'known-installations/dbcf.manifest.json',
    'installer-upgrade-43b.h',
    'known-installations/43b.manifest.json',
    'installer-upgrade-acfc.h',
    'known-installations/acfc.manifest.json',
    'installer-upgrade-c34.h',
    'known-installations/c34.manifest.json',
    'installer-upgrade-4b9f85.h',
    'known-installations/4b9f85.manifest.json',
    'installer-upgrade-43392e.h',
    'known-installations/43392e.manifest.json',
    'installer-upgrade-f0b99f.h',
    'known-installations/f0b99f.manifest.json',
    'installer-upgrade-f39101.h',
    'known-installations/f39101.manifest.json',
    'installer-upgrade-a8bd00.h',
    'known-installations/a8bd00.manifest.json',
    'installer-upgrade-da6e7c.h',
    'known-installations/da6e7c.manifest.json',
    'installer-upgrade-03245359.h',
    'known-installations/03245359.manifest.json',
    'installer-upgrade-2059a0.h',
    'known-installations/2059a0.manifest.json',
    'installer-upgrade-127e83.h',
    'known-installations/127e83.manifest.json',
    'installer-upgrade-010117.h',
    'known-installations/010117.manifest.json',
    'installer-upgrade-9b51cf.h',
    'known-installations/9b51cf.manifest.json',
    'installer-upgrade-91b62a.h',
    'known-installations/91b62a.manifest.json',
    'installer-upgrade-7c91a1.h',
    'known-installations/7c91a1.manifest.json',
    'installer-upgrade-af79b1.h',
    'known-installations/af79b1.manifest.json',
    'installer-upgrade-dceba9.h',
    'known-installations/dceba9.manifest.json',
    'installer-upgrade-fa70a2.h',
    'known-installations/fa70a2.manifest.json',
    'installer-upgrade-32811e.h',
    'known-installations/32811e.manifest.json',
    'pf-hook.c',
    'pf-hook.h',
    'pf-hook-abi.h',
    'pf-run-ledger.c',
    'pf-run-ledger.h',
    'installer-upgrade-22a6f3.h',
    'known-installations/22a6f3.manifest.json',
    'installer-upgrade-78c3.h',
    'known-installations/78c3.manifest.json',
    'installer-upgrade-fb74.h',
    'known-installations/fb74.manifest.json',
    'installer-upgrade-554c.h',
    'known-installations/554c.manifest.json',
    'installer-upgrade-2af8.h',
    'known-installations/2af8.manifest.json',
    'installer-upgrade-005f.h',
    'known-installations/005f.manifest.json',
    'installer-upgrade-88f8.h',
    'known-installations/88f8.manifest.json',
    'installer-upgrade-0b6d.h',
    'known-installations/0b6d.manifest.json',
    'installer-upgrade-0359.h',
    'known-installations/0359.manifest.json',
    'pf-filter-command.c',
    'pf-filter-command.h',
    'pf-filter-transaction.c',
    'pf-filter-transaction.h',
    'app-command.c',
    'app-command.h',
    'app-control.c',
    'app-control.h',
    'app-ticket.c',
    'app-ticket.h',
    'app-registry.c',
    'app-registry.h',
    'app-supervisor.c',
    'app-supervisor.h',
    'gui-launch.m',
    'gui-launch.h',
    'launch-guardian.c',
    'launch-guardian.h',
    'app-family.c',
    'app-family.h',
    'pf-production-filter.c',
    'pf-production-filter.h',
    'app-native-factory.m',
    'app-native-factory.h',
    'app-keychain.m',
    'app-keychain.h',
    'journal-retirement.c',
    'journal-retirement.h',
    'app-scope-proof.c',
    'app-scope-proof.h',
    'app-transport.c',
    'app-transport.h',
    'transport-session.h',
    'notion-launch.m',
    'notion-launch.h',
    ...fixtureNames.map(name => 'fixture/' + name)];
  const sourceSnapshot = {};
  for (const name of [...nativeInputs, ...PF_RUNTIME_MODULE_FILES]) sourceSnapshot[path.join(source, name)] = await fileDigest(path.join(source, name));
  for (const name of ['scripts/build-macos-pf-routing.mjs', 'LICENSE', ...PF_BUILD_DEPENDENCY_INPUTS]) {
    sourceSnapshot[path.join(root, name)] = await fileDigest(path.join(root, name));
  }
  const stage = output + '.stage-' + randomUUID(), previous = output + '.previous-' + randomUUID();
  let moved = false;
  await mkdir(stage, { recursive: true, mode: 0o755 });
  try {
    const nodeArtifact = driverArtifacts(platform, arch);
    const cache = path.join(root, '.cache/pf-routing');
    await mkdir(cache, { recursive: true });
    const archivePath = path.join(cache, nodeArtifact.nodeArchiveSha256);
    if (!await exists(archivePath)) {
      const downloaded = await exec('/usr/bin/curl', ['--fail', '--location', '--silent', '--show-error',
        '--connect-timeout', '15', '--max-time', '180', nodeArtifact.nodeUrl], { encoding: null, maxBuffer: 100 * 1024 * 1024 });
      if (sha256(downloaded.stdout) !== nodeArtifact.nodeArchiveSha256) throw new Error('Pinned Node archive hash does not match.');
      await writeFile(archivePath, downloaded.stdout, { flag: 'wx', mode: 0o644 });
    }
    const nodeArchive = await readFile(archivePath);
    if (sha256(nodeArchive) !== nodeArtifact.nodeArchiveSha256) throw new Error('Cached Node archive hash does not match.');
    const files = tarGzFiles(nodeArchive);
    for (const [entry, name] of [[nodeArtifact.nodeArchiveExecutable, 'node'], [nodeArtifact.nodeArchiveLicense, 'node-LICENSE']]) {
      if (!files.has(entry)) throw new Error('Pinned Node archive is incomplete.');
      await writeFile(path.join(stage, name), files.get(entry), { flag: 'wx', mode: name === 'node' ? 0o755 : 0o644 });
    }
    files.clear();
    const nodeCheck = await exec(path.join(stage, 'node'), ['-p', 'JSON.stringify({version:process.version,platform:process.platform,arch:process.arch})'], { timeout: 15000 });
    const nodeInfo = JSON.parse(nodeCheck.stdout);
    if (nodeInfo.version !== 'v' + NODE_VERSION || nodeInfo.platform !== platform || nodeInfo.arch !== arch) throw new Error('Node runtime architecture/version mismatch.');
    const coreDir = path.join(root, 'build/proxy-core'), artifact = proxyCoreArtifacts(platform, arch);
    const core = JSON.parse(await readFile(path.join(coreDir, 'provenance.json'), 'utf8'));
    if (core.core !== 'mihomo' || core.version !== PROXY_CORE_VERSION || core.commit !== PROXY_CORE_COMMIT ||
        core.platform !== platform || core.arch !== arch || core.sha256?.archive !== artifact.archiveSha256 ||
        core.sha256?.sourceArchive !== artifact.sourceSha256) throw new Error('Mihomo provenance does not match the pinned native dependency.');
    for (const [name, hash, target] of [[artifact.binaryName, core.sha256.binary, 'mihomo'],
      [core.correspondingSource, core.sha256.correspondingSource, 'mihomo-corresponding-source.tar.gz'], ['LICENSE', core.sha256.license, 'mihomo-LICENSE']]) {
      await copyFile(path.join(coreDir, name), path.join(stage, target));
      if (await fileDigest(path.join(stage, target)) !== hash) throw new Error('Pinned Mihomo file hash does not match.');
    }
    await copyFile(path.join(coreDir, 'SOURCE.md'), path.join(stage, 'mihomo-SOURCE.md'));
    const native = path.join(stage, 'envara-pf-native');
    await exec('/usr/bin/make', ['OUT=' + native], { cwd: source, timeout: 60000, maxBuffer: 1024 * 1024 });
    for (const name of PF_RUNTIME_MODULE_FILES) await copyFile(path.join(source, name), path.join(stage, name));
    await mkdir(path.join(stage, 'fixtures'), { mode: 0o755 });
    const fixtureSources = fixtureNames.map(name => path.join(source, 'fixture', name));
    await exec('/usr/bin/xcrun', ['swiftc', '-O', '-parse-as-library', '-target', arch === 'arm64' ? 'arm64-apple-macos13.0' : 'x86_64-apple-macos13.0',
      ...fixtureSources, '-o', path.join(stage, 'fixtures/EnvaraRoutingAcceptanceFixture')], { timeout: 60000, maxBuffer: 1024 * 1024 });
    const wrapper = '#!/bin/sh\nset -eu\nENVARA_PF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)\nexec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin "$ENVARA_PF_DIR/node" --no-addons --disable-proto=throw "$ENVARA_PF_DIR/helper.mjs" "$@"\n';
    await writeFile(path.join(stage, 'EnvaraPFHelper'), wrapper, { flag: 'wx', mode: 0o755 });
    await copyFile(path.join(root, 'LICENSE'), path.join(stage, 'LICENSE'));
    const inventory = ['node', 'node-LICENSE', 'mihomo', 'mihomo-LICENSE', 'mihomo-SOURCE.md', 'mihomo-corresponding-source.tar.gz',
      'envara-pf-native', ...PF_RUNTIME_MODULE_FILES, 'EnvaraPFHelper', 'LICENSE', 'fixtures/EnvaraRoutingAcceptanceFixture'];
    const digests = {};
    for (const name of inventory) digests[name] = await fileDigest(path.join(stage, name));
    const fixtureInputs = (await readdir(path.join(source, 'fixture'))).filter(name => name.endsWith('.swift')).sort();
    if (fixtureInputs.join('|') !== [...fixtureNames].sort().join('|')) throw new Error('PF fixture input inventory is ambiguous.');
    const nativeSourceFiles = {};
    for (const name of nativeInputs) nativeSourceFiles['native/macos-pf-routing/' + name] = await fileDigest(path.join(source, name));
    nativeSourceFiles['scripts/build-macos-pf-routing.mjs'] = await fileDigest(path.join(root, 'scripts/build-macos-pf-routing.mjs'));
    const manifest = { schema: 'envara.macos-pf-installation/v1', component: 'envara-pf-routing', version: '1', backend: 'pf-utun', platform, arch,
      ready: false, nativeAcceptance: false, node: { version: NODE_VERSION, archiveSha256: nodeArtifact.nodeArchiveSha256, source: nodeArtifact.nodeUrl },
      mihomo: { version: core.version, commit: core.commit, sourceArchiveSha256: artifact.sourceSha256 },
      files: digests, nativeSourceFiles };
    await writeFile(path.join(stage, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
    const executableFiles = new Set(['node', 'mihomo', 'envara-pf-native', 'EnvaraPFHelper', 'fixtures/EnvaraRoutingAcceptanceFixture']);
    const installFiles = [...Object.entries(digests), ['manifest.json', await fileDigest(path.join(stage, 'manifest.json'))]];
    // The installer resolves its held executable's own directory at runtime.
    // A build-machine path is neither a resource location nor a trust input.
    const header = '#define ENVARA_PF_INSTALL_MANIFEST_SHA256 ' + JSON.stringify(await fileDigest(path.join(stage, 'manifest.json'))) + '\n' +
      'typedef struct { const char *name; const char *sha256; unsigned int mode; } EnvaraPFInstallFile;\n' +
      'static const EnvaraPFInstallFile ENVARA_PF_INSTALL_FILES[] = {\n' + installFiles.map(([name, hash]) =>
        '{' + JSON.stringify(name) + ',' + JSON.stringify(hash) + ',' + (executableFiles.has(name) ? '0755' : '0644') + '}').join(',\n') +
      '\n};\n#define ENVARA_PF_INSTALL_FILE_COUNT (sizeof(ENVARA_PF_INSTALL_FILES)/sizeof(ENVARA_PF_INSTALL_FILES[0]))\n';
    const headerPath = path.join(stage, 'installer-manifest.h');
    await writeFile(headerPath, header, { flag: 'wx', mode: 0o600 });
    await exec('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-I', stage,
      path.join(source, 'authorize-install.c'), '-framework', 'Security', '-o', path.join(stage, 'EnvaraPFInstall')], { timeout: 30000, maxBuffer: 1024 * 1024 });
    await rm(headerPath);
    await exec(native, ['fixture'], { timeout: 15000, maxBuffer: 1024 * 1024 });
    for (const [filename, initialDigest] of Object.entries(sourceSnapshot)) {
      if (await fileDigest(filename) !== initialDigest) throw new Error('PF source changed during the build; keep the previous complete payload.');
    }
    if (await exists(output)) { await rename(output, previous); moved = true; }
    await rename(stage, output);
    if (moved) await rm(previous, { recursive: true, force: true });
    return { output, helperPath: path.join(output, 'EnvaraPFHelper'), installerPath: path.join(output, 'EnvaraPFInstall'), manifest, systemInstalled: false, nativeAcceptance: false };
  } catch (error) {
    await rm(stage, { recursive: true, force: true });
    if (moved && !await exists(output)) await rename(previous, output);
    throw error;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { const result = await buildMacOSPF(); console.log(JSON.stringify({ output: result.output, built: true, systemInstalled: false, nativeAcceptance: false })); }
  catch { console.error('PF resource build failed; no system installation or network activation was performed.'); process.exitCode = 1; }
}
