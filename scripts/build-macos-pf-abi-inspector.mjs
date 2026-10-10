// Independent temporary diagnostic bundle; never installs or requests rights.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { mkdtemp, realpath, mkdir, writeFile, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export async function buildPFABIInspector({ output, exec = execute } = {}) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('This fixed diagnostic targets the reviewed Darwin 27 arm64 host.');
  const directory = output ? path.resolve(output) : await realpath(await mkdtemp(path.join(tmpdir(), 'envara-pf-abi-inspector-')));
  const app = path.join(directory, 'Envara PF ABI Inspector.app');
  const contents = path.join(app, 'Contents'), binaries = path.join(contents, 'MacOS');
  await mkdir(binaries, { recursive: true, mode: 0o700 });
  const source = path.join(root, 'native/macos-pf-routing/pf-abi-inspector.c');
  const sourceSHA256 = createHash('sha256').update(await readFile(source)).digest('hex');
  const binary = path.join(binaries, 'EnvaraPFABIInspector');
  await exec('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', source, '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
  const metadata = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n' +
    '<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.envara.pf-abi-inspector</string><key>CFBundleName</key><string>Envara PF ABI Inspector</string>' +
    '<key>CFBundleExecutable</key><string>EnvaraPFABIInspector</string><key>CFBundlePackageType</key><string>APPL</string>' +
    '<key>CFBundleVersion</key><string>1</string><key>LSUIElement</key><true/></dict></plist>\n';
  await writeFile(path.join(contents, 'Info.plist'), metadata, { flag: 'wx', mode: 0o600 });
  await exec('/usr/bin/codesign', ['--force', '--sign', '-', app], { timeout: 15000, maxBuffer: 1024 * 1024 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', app], { timeout: 15000, maxBuffer: 1024 * 1024 });
  const plan = JSON.parse((await exec(binary, ['--plan'], { timeout: 15000, maxBuffer: 1024 * 1024 })).stdout);
  const binarySHA256 = createHash('sha256').update(await readFile(binary)).digest('hex');
  await writeFile(path.join(directory, 'inspection-build.json'), JSON.stringify({ schema: 'envara.macos-pf-abi-build/v1',
    app, binary, sourceSHA256, binarySHA256, plan, authorizationRequested: false, installed: false, activation: false }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return { directory, app, binary, sourceSHA256, binarySHA256, plan, authorizationRequested: false, installed: false, activation: false };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) { console.error('Build accepts no operation or authorization arguments.'); process.exitCode = 1; }
  else { try { console.log(JSON.stringify(await buildPFABIInspector(), null, 2)); }
    catch (error) { console.error(error.message); process.exitCode = 1; } }
}
