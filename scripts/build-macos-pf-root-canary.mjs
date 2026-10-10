// Produces an independent temporary review bundle. It runs only --plan.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { mkdtemp, realpath, mkdir, writeFile, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const hash = async file => createHash('sha256').update(await readFile(file)).digest('hex');
export async function buildPFRootCanary({ output, exec = execute } = {}) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('This experimental diagnostic targets the reviewed Darwin 27 arm64 host.');
  const directory = output ? path.resolve(output) : await realpath(await mkdtemp(path.join(tmpdir(), 'envara-pf-root-canary-')));
  const app = path.join(directory, 'Envara PF Empty Root Canary.app');
  const contents = path.join(app, 'Contents'), binaries = path.join(contents, 'MacOS');
  await mkdir(binaries, { recursive: true, mode: 0o700 });
  const source = path.join(root, 'native/macos-pf-routing/pf-root-canary.c');
  const inspector = path.join(root, 'native/macos-pf-routing/pf-abi-inspector.c');
  const sourceSHA256 = await hash(source), inspectorSHA256 = await hash(inspector);
  const binary = path.join(binaries, 'EnvaraPFEmptyRootCanary');
  await exec('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', source, '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
  if (await hash(source) !== sourceSHA256 || await hash(inspector) !== inspectorSHA256) throw new Error('Review source changed while compiling; discard this bundle.');
  const metadata = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n' +
    '<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.envara.pf-empty-root-canary</string><key>CFBundleName</key><string>Envara PF Empty Root Canary</string>' +
    '<key>CFBundleExecutable</key><string>EnvaraPFEmptyRootCanary</string><key>CFBundlePackageType</key><string>APPL</string>' +
    '<key>CFBundleVersion</key><string>1</string><key>LSUIElement</key><true/></dict></plist>\n';
  await writeFile(path.join(contents, 'Info.plist'), metadata, { flag: 'wx', mode: 0o600 });
  await exec('/usr/bin/codesign', ['--force', '--sign', '-', app], { timeout: 15000, maxBuffer: 1024 * 1024 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', app], { timeout: 15000, maxBuffer: 1024 * 1024 });
  const plan = JSON.parse((await exec(binary, ['--plan'], { timeout: 15000, maxBuffer: 1024 * 1024 })).stdout);
  const binarySHA256 = await hash(binary);
  if (await hash(source) !== sourceSHA256 || await hash(inspector) !== inspectorSHA256) throw new Error('Review source changed before bundle completion.');
  const result = { schema: 'envara.macos-pf-root-canary-build/v1', directory, app, binary,
    sourceSHA256, inspectorSHA256, binarySHA256, plan, authorizationRequested: false,
    installed: false, activation: false, PFWriteExecuted: false, requiresSeparateApproval: true };
  await writeFile(path.join(directory, 'canary-build.json'), JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) { console.error('Build accepts no operation or authorization arguments.'); process.exitCode = 1; }
  else { try { console.log(JSON.stringify(await buildPFRootCanary(), null, 2)); }
    catch (error) { console.error(error.message); process.exitCode = 1; } }
}
