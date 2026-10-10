// Independent source-only recovery candidate. Runs only inert plan/refusal;
// never requests Authorization, root, PF, group or filesystem recovery.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { constants } from 'node:fs';
import { mkdtemp, realpath, mkdir, writeFile, readFile, open } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile), root = path.resolve(import.meta.dirname, '..');
const native = path.join(root, 'native/macos-pf-routing');
const MF = '46ae6acddd4f7b0a941bfbf6d6cc12aaedf59dd0c681b9aa440e72c38536d56b';
const RUN = '90401ced-5d54-4422-b80c-c7c4485a037b', ENV = 'f285429a-61e4-4023-8749-ec9073ce6a39';
const executableLeaves = new Set(['node', 'mihomo', 'envara-pf-native', 'EnvaraPFHelper', 'fixtures/EnvaraRoutingAcceptanceFixture']);
async function hash(file) {
  const fd = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const a = await fd.stat({ bigint: true });
    if (!a.isFile() || a.size > 1024n * 1024n * 1024n) throw new Error('Input is not a bounded regular file.');
    const sha = createHash('sha256'), bytes = Buffer.alloc(65536); let total = 0n;
    for (;;) { const { bytesRead } = await fd.read(bytes, 0, bytes.length, null); if (!bytesRead) break;
      total += BigInt(bytesRead); if (total > a.size) throw new Error('Input changed while hashing.'); sha.update(bytes.subarray(0, bytesRead)); }
    const b = await fd.stat({ bigint: true });
    if (total !== a.size || ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].some(k => a[k] !== b[k])) throw new Error('Input changed while hashing.');
    return sha.digest('hex');
  } finally { await fd.close(); }
}
export async function buildFixedApplicationRecovery46ae() {
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || process.getuid() === 0) throw new Error('This inert builder requires the unprivileged reviewed Darwin arm64 host.');
  const manifestFile = path.join(native, 'recovery-app-46ae-manifest.json');
  if (await hash(manifestFile) !== MF) throw new Error('Fixed 46ae manifest copy differs.');
  const manifest = JSON.parse(await readFile(manifestFile, 'utf8'));
  if (manifest.schema !== 'envara.macos-pf-installation/v1' || manifest.backend !== 'pf-utun' || Object.keys(manifest.files ?? {}).length !== 18) throw new Error('Fixed inventory is not the 18-leaf application candidate.');
  const source = path.join(native, 'recovery-app-46ae-run904.m'), inventory = path.join(native, 'recovery-app-46ae-inventory.h');
  const text = await readFile(inventory, 'utf8');
  if (!text.includes(MF) || !text.includes(RUN)) throw new Error('Fixed recovery identifiers differ.');
  for (const [name, sha] of Object.entries({ ...manifest.files, 'manifest.json': MF })) {
    if (!/^[a-zA-Z0-9_.-]+$/.test(name) && name !== 'fixtures/EnvaraRoutingAcceptanceFixture') throw new Error('Unexpected fixed leaf.');
    const mode = executableLeaves.has(name) ? '0755' : '0644';
    if (!text.includes(`{"${name}","${sha}",${mode}}`)) throw new Error(`Fixed recovery inventory differs: ${name}`);
  }
  const fixedInputs = ['app-scope-proof.c', 'app-scope-proof.h', 'pf-hook-abi.h'];
  for (const name of fixedInputs) if (await hash(path.join(native, name)) !== manifest.nativeSourceFiles[`native/macos-pf-routing/${name}`]) throw new Error(`Compiled dependency differs from the fixed 46ae source: ${name}`);
  const inputFiles = [source, inventory, manifestFile, ...fixedInputs.map(n => path.join(native, n)), fileURLToPath(import.meta.url), path.join(root, 'tests/macos-pf-app-recovery-46ae.test.mjs')];
  const sourceInputs = {};
  for (const file of inputFiles) sourceInputs[path.relative(root, file)] = await hash(file);
  const unchanged = async () => { for (const [name, sha] of Object.entries(sourceInputs)) if (await hash(path.join(root, name)) !== sha) return false; return true; };
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-recovery-46ae-run904-')));
  const app = path.join(directory, 'Envara Fixed Application Recovery 46ae Run904.app'), contents = path.join(app, 'Contents');
  await mkdir(path.join(contents, 'MacOS'), { recursive: true, mode: 0o700 });
  const binary = path.join(contents, 'MacOS/EnvaraPFApplicationRecovery46aeRun904');
  await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', source,
    path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
  if (!await unchanged()) throw new Error('Recovery source changed while compiling.');
  await writeFile(path.join(contents, 'Info.plist'), '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.envara.fixed-app-recovery-46ae-90401ced</string><key>CFBundleExecutable</key><string>EnvaraPFApplicationRecovery46aeRun904</string><key>CFBundleName</key><string>Envara Fixed Application Recovery 46ae Run904</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>1</string><key>LSUIElement</key><true/></dict></plist>\n', { flag: 'wx', mode: 0o600 });
  await exec('/usr/bin/codesign', ['--force', '--sign', '-', app], { timeout: 15000 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', app], { timeout: 15000 });
  const plan = JSON.parse((await exec(binary, ['--plan'], { timeout: 10000 })).stdout);
  if (plan.manifestSHA256 !== MF || plan.runId !== RUN || plan.environmentId !== ENV || plan.readOnly !== true || plan.runtimeLeafCount !== 19 || plan.ready !== false || plan.protected !== false || plan.cleanupConfirmed !== false) throw new Error('Recovery plan is not the fixed inert candidate.');
  const refusals = [];
  for (const operation of ['--request-readonly-existing-rights', '--request-cleanup-existing-rights']) {
    let stdout;
    try { await exec(binary, [operation], { timeout: 10000 }); throw new Error('Noninteractive root request unexpectedly succeeded.'); }
    catch (error) { if (error.code !== 1) throw error; stdout = error.stdout; }
    const refusal = JSON.parse(stdout);
    if (refusal.reason !== 'NONINTERACTIVE_PRIVILEGED_EXECUTION_UNAVAILABLE' || refusal.ok !== false || refusal.cleanupConfirmed !== false || refusal.cleanupUncertain !== true || refusal.readOnly !== true) throw new Error('Noninteractive request did not refuse safely.');
    refusals.push({ operation, refusal });
  }
  if (!await unchanged()) throw new Error('Recovery source changed before final proof.');
  const proof = { schema: 'envara.macos-pf-application-recovery-build/v1', directory, app, binary,
    fixedManifestSHA256: MF, fixedNativeSHA256: manifest.files['envara-pf-native'], fixedRunId: RUN, fixedEnvironmentId: ENV,
    installedRuntimeLeafCount: 19, sourceInputs, binarySHA256: await hash(binary), plan, refusals,
    authorizationRequested: false, rootExecuted: false, systemOperationExecuted: false, PFWriteExecuted: false,
    originalApplicationBaselineVerified: false, recoveryVerified: false, cleanupConfirmed: false,
    noninteractivePrivilegedExecutionAvailable: false, userPresenceRequiredForFutureAuthorization: true,
    installedCandidateChanged: false, productionReady: false };
  await writeFile(path.join(directory, 'recovery-build.json'), JSON.stringify(proof, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return proof;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) { console.error('This inert builder accepts no operation, path, UUID or authorization arguments.'); process.exitCode = 1; }
  else { try { console.log(JSON.stringify(await buildFixedApplicationRecovery46ae(), null, 2)); }
    catch (error) { console.error(error.message); process.exitCode = 1; } }
}
