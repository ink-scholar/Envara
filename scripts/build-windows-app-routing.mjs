import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { prepareWinDivert, sha256, WINDIVERT } from './prepare-windivert.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const source = path.join(root, 'native/windows-app-routing');
const parent = path.join(root, 'build/app-routing');
mkdirSync(parent, { recursive: true });
const stage = mkdtempSync(path.join(parent, '.windows-stage-'));

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: source, stdio: 'inherit', ...options });
  if (result.error || result.status !== 0) throw new Error(`Windows component build failed: ${command}. Install Go and an x64 Windows C compiler.`, { cause: result.error });
}
function checkPE(file, machine, signed = false) {
  const bytes = readFileSync(file);
  const pe = bytes.readUInt32LE(0x3c);
  if (bytes.subarray(0, 2).toString() !== 'MZ' || pe + 168 > bytes.length || bytes.readUInt32LE(pe) !== 0x4550 || bytes.readUInt16LE(pe + 4) !== machine) {
    throw new Error(`Invalid Windows PE architecture: ${path.basename(file)}`);
  }
  if (signed) {
    // Presence is not Authenticode trust. The official pinned bytes are retained.
    const directory = pe + 24 + 112 + 8 * 4;
    const offset = bytes.readUInt32LE(directory), length = bytes.readUInt32LE(directory + 4);
    if (!offset || length < 8 || offset + length > bytes.length) throw new Error('Official WinDivert certificate table is absent.');
  }
}

try {
  const sdk = prepareWinDivert();
  for (const [arch, goarch] of [['x64', 'amd64'], ['arm64', 'arm64']]) {
    const output = path.join(stage, arch);
    mkdirSync(output);
    const exe = path.join(output, 'EnvaraAppRouting.exe');
    run('go', ['build', '-trimpath', '-ldflags=-s -w', '-o', exe, './cmd/envara-app-routing'], {
      env: { ...process.env, GOOS: 'windows', GOARCH: goarch, CGO_ENABLED: '0' },
    });
    checkPE(exe, arch === 'x64' ? 0x8664 : 0xaa64);
    copyFileSync(path.join(source, 'THIRD-PARTY-NOTICES.txt'), path.join(output, 'THIRD-PARTY-NOTICES.txt'));
    if (arch !== 'x64') {
      writeFileSync(path.join(output, 'CAPTURE-UNAVAILABLE.txt'), 'ARM64 helper source cross-build only. The pinned WinDivert release has no ARM64 driver. Application routing remains unavailable.\n');
      continue;
    }
    const dll = path.join(output, 'EnvaraCapture.dll');
    const compiler = process.env.ENVARA_WINDOWS_CC || (process.platform === 'win32' ? 'cl' : 'x86_64-w64-mingw32-gcc');
    if (/^cl(?:\.exe)?$/i.test(path.basename(compiler))) {
      const objects = path.join(stage, '.objects-x64');
      mkdirSync(objects);
      run(compiler, ['/nologo', '/std:c11', '/O2', '/W4', '/WX', '/GS', '/LD', '/DENVARA_CAPTURE_BUILD', '/D_WIN32_WINNT=0x0A00',
        'capture/capture_windows.c', 'capture/capture_core.c', `/Fo:${objects}${path.sep}`, `/Fe:${dll}`, '/link',
        `/DEF:${path.join(source, 'capture/EnvaraCapture.def')}`, '/DYNAMICBASE', '/NXCOMPAT', '/GUARD:CF',
        `/IMPLIB:${path.join(objects, 'EnvaraCapture.lib')}`,
        path.join(sdk, 'x64/WinDivert.lib'), 'ws2_32.lib', 'iphlpapi.lib']);
      rmSync(objects, { recursive: true, force: true });
    } else {
      run(compiler, ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-DENVARA_CAPTURE_BUILD', '-D_WIN32_WINNT=0x0A00', '-shared',
        'capture/capture_windows.c', 'capture/capture_core.c', 'capture/EnvaraCapture.def', path.join(sdk, 'x64/WinDivert.lib'),
        '-lws2_32', '-liphlpapi', '-Wl,--dynamicbase,--nxcompat', '-o', dll]);
    }
    checkPE(dll, 0x8664);
    for (const name of ['WinDivert.dll', 'WinDivert64.sys']) {
      copyFileSync(path.join(sdk, 'x64', name), path.join(output, name));
      checkPE(path.join(output, name), 0x8664, name.endsWith('.sys'));
    }
    for (const [from, to] of [['LICENSE', 'WinDivert-LICENSE'], ['README', 'WinDivert-README'],
      ['WinDivert-corresponding-source.tar.gz', 'WinDivert-corresponding-source.tar.gz'], ['provenance.json', 'WinDivert-provenance.json']]) {
      copyFileSync(path.join(sdk, from), path.join(output, to));
    }
    copyFileSync(path.join(source, 'capture/LICENSE'), path.join(output, 'ProxyBridge-LICENSE'));
    copyFileSync(path.join(source, 'capture/PROVENANCE.md'), path.join(output, 'CAPTURE-SOURCE.md'));
    // Build provenance never serves as a networking acceptance record.
    writeFileSync(path.join(output, 'capture-provenance.json'), JSON.stringify({
      schema: 1, captureAbi: 1, engine: 'windivert', architecture: 'x64',
      upstream: { project: 'basil00/WinDivert', version: WINDIVERT.version, commit: WINDIVERT.commit },
      files: ['EnvaraCapture.dll', 'WinDivert.dll', 'WinDivert64.sys'].map(name => ({ name, sha256: sha256(readFileSync(path.join(output, name))) })),
    }, null, 2) + '\n');
    const installFiles = ['EnvaraAppRouting.exe', 'EnvaraCapture.dll', 'WinDivert.dll', 'WinDivert64.sys',
      'capture-provenance.json', 'CAPTURE-SOURCE.md', 'ProxyBridge-LICENSE', 'THIRD-PARTY-NOTICES.txt',
      'WinDivert-LICENSE', 'WinDivert-README', 'WinDivert-provenance.json', 'WinDivert-corresponding-source.tar.gz'];
    const installManifest = Buffer.from(JSON.stringify({
      schema: 1, platform: 'windows', architecture: 'x64', service: 'EnvaraAppRouting', captureAbi: 1, engine: 'windivert',
      upstream: { project: 'basil00/WinDivert', version: WINDIVERT.version, commit: WINDIVERT.commit },
      files: installFiles.map(name => ({ name, sha256: sha256(readFileSync(path.join(output, name))) })),
    }, null, 2) + '\n');
    writeFileSync(path.join(output, 'install-manifest.json'), installManifest);
    console.log(`Windows x64 install manifest SHA-256: ${sha256(installManifest)}`);
  }
  const destination = path.join(parent, 'win32');
  const previous = path.join(parent, '.windows-previous');
  rmSync(previous, { recursive: true, force: true });
  let moved = false;
  try { renameSync(destination, previous); moved = true; } catch (error) { if (error.code !== 'ENOENT') throw error; }
  try { renameSync(stage, destination); }
  catch (error) { if (moved) renameSync(previous, destination); throw error; }
  rmSync(previous, { recursive: true, force: true });
  console.log('Built x64 Windows capture + Go service with unmodified signed WinDivert dependency. ARM64 is helper-only; DNS, guard-crash protection and native acceptance remain incomplete. No component was installed or activated.');
} finally { rmSync(stage, { recursive: true, force: true }); }
