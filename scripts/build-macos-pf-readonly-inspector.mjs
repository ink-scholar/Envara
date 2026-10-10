// Builds a separate, fixed-run diagnostic App. Never requests native rights.
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
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = path.join(root, 'native/macos-pf-routing/recovery-readonly-518.m');
const tests = path.join(root, 'native/macos-pf-routing/recovery-readonly-518-inert-tests.m');
const inventoryTests = path.join(root, 'native/macos-pf-routing/recovery-runtime-inventory-518-inert-tests.m');
const inputPaths = [source, tests, inventoryTests,
  path.join(root, 'native/macos-pf-routing/recovery-runtime-inventory-518.h'),
  path.join(root, 'native/macos-pf-routing/pf-hook-abi.h')];
const digest = async filename => createHash('sha256').update(await readFile(filename)).digest('hex');
const sourceSHA256 = await digest(source), inertTestSHA256 = await digest(tests);
const inputSnapshot = async () => Promise.all(inputPaths.map(async filename => ({ path: path.relative(root, filename), sha256: await digest(filename) })));
const compiledInputs = await inputSnapshot();
const compiledInputSHA256 = createHash('sha256').update(JSON.stringify(compiledInputs)).digest('hex');
const parent = path.join(root, 'build/local-authorization');
await mkdir(parent, { recursive: true });
const output = path.join(parent, `EnvaraPFReadOnlyRecovery518-${compiledInputSHA256.slice(0, 12)}.app`);
await assert.rejects(lstat(output), { code: 'ENOENT' }, 'Preserve any existing diagnostic App');
const stage = path.join(parent, `.EnvaraPFReadOnlyRecovery518-${randomUUID()}.app`);
const temporary = await mkdtemp(path.join(os.tmpdir(), 'envara-readonly-inert-'));
const run = promisify(execFile), options = { timeout: 30000, maxBuffer: 65536, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' } };
const flags = ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror'];
let committed = false;
try {
  const macOS = path.join(stage, 'Contents/MacOS');
  await mkdir(macOS, { recursive: true });
  const executable = path.join(macOS, 'EnvaraPFReadOnlyRecovery518');
  await run('/usr/bin/clang', [...flags, source, '-framework', 'Foundation', '-framework', 'Security', '-o', executable], options);
  const inert = path.join(temporary, 'readonly-inert');
  await run('/usr/bin/clang', [...flags, '-Wno-unused-function', tests, '-framework', 'Foundation', '-framework', 'Security', '-o', inert], options);
  const fixture = await run(inert, [], options);
  assert.equal(fixture.stdout.trim(), 'Readonly fixed-run parser/output inert tests passed; no system inspection performed.');
  const inventoryInert = path.join(temporary, 'runtime-inventory-inert');
  await run('/usr/bin/clang', [...flags, '-Wno-unused-function', inventoryTests, '-framework', 'Foundation', '-framework', 'Security', '-o', inventoryInert], options);
  const inventoryFixture = await run(inventoryInert, [], options);
  assert.equal(inventoryFixture.stdout.trim(), 'Runtime inventory inert fixture tests passed; no installation, authorization, PF activation, or process inspection performed.');
  assert.deepEqual(await inputSnapshot(), compiledInputs, 'Inspector compiler inputs changed during compilation');
  const info = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.envara.pf-readonly-recovery518.local</string><key>CFBundleName</key><string>Envara Readonly Recovery</string><key>CFBundleExecutable</key><string>EnvaraPFReadOnlyRecovery518</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>1</string><key>LSUIElement</key><true/></dict></plist>\n';
  await writeFile(path.join(stage, 'Contents/Info.plist'), info, { mode: 0o644 });
  await run('/usr/bin/plutil', ['-lint', path.join(stage, 'Contents/Info.plist')], options);
  for (const target of [executable, stage]) await run('/usr/bin/codesign', ['--force', '--sign', '-', '--timestamp=none', target], options);
  for (const target of [executable, stage]) await run('/usr/bin/codesign', ['--verify', '--strict', target], options);
  const plan = JSON.parse((await run(executable, ['--plan'], options)).stdout);
  assert.equal(plan.readOnly, true); assert.equal(plan.changesSystem, false); assert.equal(plan.cleanupConfirmed, false);
  assert.equal(plan.installedManifestSHA256, '518a75d94bac4f17d9e1ce60e842648ba6ff657a68cc62e95ce13718abda6d5a');
  assert.equal(plan.runId, '0a00377a-0829-49f4-93d6-29a665e5c06b');
  await mkdir(output); await rename(path.join(stage, 'Contents'), path.join(output, 'Contents')); await rmdir(stage); committed = true;
  await run('/usr/bin/codesign', ['--verify', '--strict', output], options);
  const main = path.join(output, 'Contents/MacOS/EnvaraPFReadOnlyRecovery518');
  assert.deepEqual(await inputSnapshot(), compiledInputs, 'Inspector compiler inputs changed before sealing');
  const report = { at: new Date().toISOString(), appPath: output, executable: main, sourceSHA256, inertTestSHA256, compiledInputSHA256, compiledInputs,
    executableSHA256: await digest(main), compiledWithWarningsAsErrors: true, inertTestsPassed: true,
    strictSignaturesVerified: true, nativePlan: plan, authorizationRequested: false, systemInspectionExecuted: false,
    systemMutated: false, ready: false, cleanupConfirmed: false };
  await writeFile(path.join(root, 'test-artifacts/mac-pf-routing/readonly-recovery-518-extended-build.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  console.log(JSON.stringify(report));
} finally {
  if (!committed) await rm(stage, { recursive: true, force: true });
  await rm(temporary, { recursive: true, force: true });
}
