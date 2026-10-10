// Independent fixed readonly inspector. Only own-temp compile/sign and inert
// plan/nonroot refusal; no Authorization, root, PF, group or runtime changes.
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
const MF = '05d6eb6ab3d63870d37825b47e2847789a6b5b8c3cf93c434636e0b8aad4f061';
const RUN = '877ab9cc-ed91-4f2d-a8cd-86cedc2f3e21', ENV = '72826f65-99c0-446c-a9c3-b825b36ad1a5';
const OBSERVATION_SHA = 'e77fae421722e7a5b61ed07ea1262178ea14cb0d33e6c017f6e04b9b566eaf05';
const PRIOR_RECEIPT_SHA = '6d89719207655152de65c951e684785b6840fd8ae20573f94fba4ee7b322d12c';
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
export async function buildFixedPrivateContextDiagnostic05D6Run877V2() {
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || process.getuid() === 0) throw new Error('This inert builder requires the unprivileged reviewed Darwin arm64 host.');
  const manifestFile = path.join(native, 'inspector-app-05d6-manifest.json');
  if (await hash(manifestFile) !== MF) throw new Error('Fixed 05d6 manifest copy differs.');
  const manifest = JSON.parse(await readFile(manifestFile, 'utf8'));
  if (manifest.schema !== 'envara.macos-pf-installation/v1' || manifest.backend !== 'pf-utun' || Object.keys(manifest.files ?? {}).length !== 18) throw new Error('Fixed inventory is not the 18-leaf application candidate.');
  const source = path.join(native, 'inspector-app-05d6-run877-private-context-diag-v2-20261009.m'), inventory = path.join(native, 'inspector-app-05d6-inventory.h');
  const observation = path.join(root, 'test-artifacts/mac-pf-routing/05d6-run877-source-observation-20261009.json');
  if (await hash(observation) !== OBSERVATION_SHA || await hash(path.join(native, 'inspector-app-05d6-run877-v2.m')) !== '61dc6f382961b70089e52181542cc01dc27e15a27e843f608687f5e1229df36e') throw new Error('Fixed nonprivileged source observation differs.');
  const text = await readFile(inventory, 'utf8');
  if (!text.includes(MF) || !text.includes(RUN)) throw new Error('Fixed inspector identifiers differ.');
  for (const [name, sha] of Object.entries({ ...manifest.files, 'manifest.json': MF })) {
    if (!/^[a-zA-Z0-9_.-]+$/.test(name) && name !== 'fixtures/EnvaraRoutingAcceptanceFixture') throw new Error('Unexpected fixed leaf.');
    const mode = executableLeaves.has(name) ? '0755' : '0644';
    if (!text.includes(`{"${name}","${sha}",${mode}}`)) throw new Error(`Fixed inspector inventory differs: ${name}`);
  }
  const fixedInputs = ['app-scope-proof.c', 'app-scope-proof.h', 'pf-hook-abi.h'];
  for (const name of fixedInputs) if (await hash(path.join(native, name)) !== manifest.nativeSourceFiles[`native/macos-pf-routing/${name}`]) throw new Error(`Compiled dependency differs from the fixed 05d6 source: ${name}`);
  const priorReceipt = path.join(root, 'test-artifacts/mac-pf-routing/05d6-run877-readonly-actual-20261009T072013Z.json');
  if (await hash(priorReceipt) !== PRIOR_RECEIPT_SHA) throw new Error('Fixed prior readonly receipt differs.');
  const inputFiles = [priorReceipt, source, path.join(native, 'inspector-app-05d6-run877-v2.m'), inventory, manifestFile, observation, ...fixedInputs.map(n => path.join(native, n)), fileURLToPath(import.meta.url), path.join(root, 'tests/macos-pf-private-context-diag-05d6-run877-v2.test.mjs')];
  const sourceInputs = {};
  for (const file of inputFiles) sourceInputs[path.relative(root, file)] = await hash(file);
  const unchanged = async () => { for (const [name, sha] of Object.entries(sourceInputs)) if (await hash(path.join(root, name)) !== sha) return false; return true; };
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-private-context-diag-v2-05d6-run877-')));
  const app = path.join(directory, 'Envara Fixed Private Context Diagnostic V2 05d6 Run877.app'), contents = path.join(app, 'Contents');
  await mkdir(path.join(contents, 'MacOS'), { recursive: true, mode: 0o700 });
  const binary = path.join(contents, 'MacOS/EnvaraPFPrivateContextDiagnostic05D6Run877V2');
  await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', source,
    path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
  if (!await unchanged()) throw new Error('Inspector source changed while compiling.');
  await writeFile(path.join(contents, 'Info.plist'), '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.envara.fixed-private-context-diag-v2-05d6-877ab9cc</string><key>CFBundleExecutable</key><string>EnvaraPFPrivateContextDiagnostic05D6Run877V2</string><key>CFBundleName</key><string>Envara Fixed Private Context Diagnostic V2 05d6 Run877</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>1</string><key>LSUIElement</key><true/></dict></plist>\n', { flag: 'wx', mode: 0o600 });
  await exec('/usr/bin/codesign', ['--force', '--sign', '-', app], { timeout: 15000 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', app], { timeout: 15000 });
  const imports = (await exec('/usr/bin/nm', ['-u', binary], { timeout: 10000 })).stdout;
  if (!/(?:^|\n)_getgroups(?:\n|$)/.test(imports) || imports.includes('_getgroups$DARWIN_EXTSN')) throw new Error('Inspector did not bind the legacy kernel credential getter.');
  const plan = JSON.parse((await exec(binary, ['--plan'], { timeout: 10000 })).stdout);
  if (plan.schema !== 'envara.macos-pf-live-application-recovery/v1' || plan.reason !== 'INERT_FIXED_LIVE_RECOVERY_PLAN' || plan.mutationEntryLinked !== false || plan.manifestSHA256 !== MF || plan.runId !== RUN || plan.environmentId !== ENV || plan.readOnly !== true || plan.ready !== false || plan.protected !== false || plan.cleanupConfirmed !== false) throw new Error('Inspector plan is not the fixed inert candidate.');
  const refusals = [];
  for (const operation of ['--inspect-fixed-root', '--cleanup-fixed-root', '--request-readonly-existing-rights']) {
    let stdout;
    try { await exec(binary, [operation], { timeout: 10000 }); throw new Error('Nonroot or unknown inspector operation unexpectedly succeeded.'); }
    catch (error) { if (error.code !== 1) throw error; stdout = error.stdout; }
    const refusal = JSON.parse(stdout);
    if (refusal.reason !== 'FIXED_LIVE_RECOVERY_PREFLIGHT_REFUSED' || refusal.ok !== false || refusal.cleanupConfirmed !== false || refusal.cleanupUncertain !== true || refusal.readOnly !== true || (operation === '--inspect-fixed-root' && refusal.gate !== 'root-credentials')) throw new Error('Inspector refusal is not readonly and uncertain.');
    refusals.push({ operation, refusal });
  }
  if (!await unchanged()) throw new Error('Inspector source changed before final proof.');
  const proof = { schema: 'envara.macos-pf-private-context-diagnostic-build/v1', directory, app, binary,
    fixedManifestSHA256: MF, fixedNativeSHA256: manifest.files['envara-pf-native'], fixedRunId: RUN, fixedEnvironmentId: ENV,
    installedRuntimeLeafCount: 19, priorReadonlyReceiptSHA256: PRIOR_RECEIPT_SHA, sourceInputs, binarySHA256: await hash(binary), plan, refusals,
    authorizationRequested: false, rootExecuted: false, systemOperationExecuted: false, PFWriteExecuted: false,
    kernelCredentialGetter: { symbol: '_getgroups', darwinDirectoryExtensionImported: false },
    originalApplicationBaselineVerified: false, nativeInspectionExecuted: false, cleanupConfirmed: false, cleanupOperationLinked: false, publicResultFieldCount: 51,
    privilegedExecutionAvailableInInspector: false, userPresenceRequiredForFutureAuthorization: true,
    installedCandidateChanged: false, productionReady: false };
  await writeFile(path.join(directory, 'inspector-build.json'), JSON.stringify(proof, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return proof;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) { console.error('This inert builder accepts no operation, path, UUID or authorization arguments.'); process.exitCode = 1; }
  else { try { console.log(JSON.stringify(await buildFixedPrivateContextDiagnostic05D6Run877V2(), null, 2)); }
    catch (error) { console.error(error.message); process.exitCode = 1; } }
}
