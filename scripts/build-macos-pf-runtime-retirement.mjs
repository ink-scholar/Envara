// Build an isolated fixed-run archive App. No authorization or system action.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { lstat, mkdir, mkdtemp, readFile, rename, rm, rmdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

assert.equal(process.platform, 'darwin');
assert.equal(process.argv.length, 2, 'This builder accepts no installation or authorization arguments');
const self = fileURLToPath(import.meta.url), root = path.resolve(path.dirname(self), '..');
const native = path.join(root, 'native/macos-pf-routing');
const source = path.join(native, 'recovery-runtime-retirement-518.m');
const tests = [
  ['recovery-readonly-518-inert-tests.m', 'Readonly fixed-run parser/output inert tests passed; no system inspection performed.'],
  ['recovery-runtime-inventory-518-inert-tests.m', 'Runtime inventory inert fixture tests passed; no installation, authorization, PF activation, or process inspection performed.'],
  ['recovery-gid-proof-518-inert-tests.m', /^PASS ([5-9][0-9]|[1-9][0-9]{2,}) inert GID-proof tests; no native process\/group scans executed$/],
  ['recovery-runtime-retirement-518-inert-tests.m', 'Runtime retirement inert fixture tests passed; only owned temporary fixtures were archived, without root/system activation.'],
];
const inputPaths = [source, ...tests.map(([name]) => path.join(native, name)),
  ...['recovery-readonly-518.m', 'recovery-runtime-inventory-518.h', 'recovery-gid-proof-518.h', 'pf-hook-abi.h'].map(name => path.join(native, name)), self];
const digest = async filename => createHash('sha256').update(await readFile(filename)).digest('hex');
const snapshot = async () => Promise.all(inputPaths.map(async filename => ({ path: path.relative(root, filename), sha256: await digest(filename) })));
const buildInputs = await snapshot(), inputSHA256 = createHash('sha256').update(JSON.stringify(buildInputs)).digest('hex');
const parent = path.join(root, 'build/local-authorization'); await mkdir(parent, { recursive: true });
const output = path.join(parent, `EnvaraPFRuntimeRetirement518-${inputSHA256.slice(0, 12)}.app`);
await assert.rejects(lstat(output), { code: 'ENOENT' }, 'Preserve existing archive Apps');
const stage = path.join(parent, `.EnvaraPFRuntimeRetirement518-${randomUUID()}.app`);
const temporary = await mkdtemp(path.join(os.tmpdir(), 'envara-retirement-inert-'));
const run = promisify(execFile), options = { timeout: 30000, maxBuffer: 65536, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' } };
const flags = ['-fobjc-arc', '-fblocks', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function'];
let committed = false;
try {
  const macOS = path.join(stage, 'Contents/MacOS'); await mkdir(macOS, { recursive: true });
  const executable = path.join(macOS, 'EnvaraPFRuntimeRetirement518');
  await run('/usr/bin/clang', [...flags, source, '-framework', 'Foundation', '-framework', 'Security', '-o', executable], options);
  for (const [name, expected] of tests) {
    const inert = path.join(temporary, name.slice(0, -2));
    await run('/usr/bin/clang', [...flags, path.join(native, name), '-framework', 'Foundation', '-framework', 'Security', '-o', inert], options);
    const lines = (await run(inert, [], options)).stdout.trim().split('\n');
    if (expected instanceof RegExp) assert.match(lines.at(-1), expected, `${name} did not finish its fixture suite`);
    else assert.equal(lines.at(-1), expected, `${name} did not finish its fixture suite`);
  }
  assert.deepEqual(await snapshot(), buildInputs, 'Archive build inputs changed during compilation');
  const info = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.envara.pf-runtime-retirement518.local</string><key>CFBundleName</key><string>Envara Runtime Archive</string><key>CFBundleExecutable</key><string>EnvaraPFRuntimeRetirement518</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>1</string><key>LSUIElement</key><true/></dict></plist>\n';
  await writeFile(path.join(stage, 'Contents/Info.plist'), info, { mode: 0o644 });
  await run('/usr/bin/plutil', ['-lint', path.join(stage, 'Contents/Info.plist')], options);
  for (const target of [executable, stage]) await run('/usr/bin/codesign', ['--force', '--sign', '-', '--timestamp=none', target], options);
  for (const target of [executable, stage]) await run('/usr/bin/codesign', ['--verify', '--strict', target], options);
  const plan = JSON.parse((await run(executable, ['--plan'], options)).stdout);
  assert.equal(plan.readOnly, true); assert.equal(plan.changesFilesystem, false);
  assert.equal(plan.cleanupConfirmed, false); assert.equal(plan.namespaceReclaimed, false);
  assert.equal(plan.installedManifestSHA256, '518a75d94bac4f17d9e1ce60e842648ba6ff657a68cc62e95ce13718abda6d5a');
  assert.equal(plan.scope, 'atomic-filesystem-archive-only');
  await mkdir(output); await rename(path.join(stage, 'Contents'), path.join(output, 'Contents')); await rmdir(stage); committed = true;
  await run('/usr/bin/codesign', ['--verify', '--strict', output], options);
  assert.deepEqual(await snapshot(), buildInputs, 'Archive build inputs changed before sealing');
  const main = path.join(output, 'Contents/MacOS/EnvaraPFRuntimeRetirement518');
  const report = { at: new Date().toISOString(), appPath: output, executable: main, inputSHA256, buildInputs,
    executableSHA256: await digest(main), compiledWithWarningsAsErrors: true, inertTestsPassed: tests.length,
    strictSignaturesVerified: true, nativePlan: plan, authorizationRequested: false, systemArchiveExecuted: false,
    systemMutated: false, ready: false, cleanupConfirmed: false };
  const filename = path.join(root, 'test-artifacts/mac-pf-routing', `runtime-retirement-518-${inputSHA256.slice(0, 12)}-build.json`);
  await writeFile(filename, JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  console.log(JSON.stringify({ reportPath: filename, appPath: output, executable: main, inputSHA256, inertTestsPassed: tests.length }));
} finally {
  if (!committed) await rm(stage, { recursive: true, force: true });
  await rm(temporary, { recursive: true, force: true });
}
