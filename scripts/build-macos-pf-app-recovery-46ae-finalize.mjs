// Builds a local, user-present authorization carrier. Only --plan is executed;
// no Authorization request, privileged stage, recovery or installation runs.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { constants } from 'node:fs';
import { mkdtemp, realpath, mkdir, readFile, writeFile, open } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createFixedRecoveryStage } from './lib/macos-fixed-recovery-stage.mjs';

const exec = promisify(execFile), root = path.resolve(import.meta.dirname, '..');
const native = path.join(root, 'native/macos-pf-routing');
const MF = '46ae6acddd4f7b0a941bfbf6d6cc12aaedf59dd0c681b9aa440e72c38536d56b';
const NODE = '/Library/PrivilegedHelperTools/io.envara.pf-routing/node';
const NODE_SHA = 'ee6fb0e015284d83a91e8ec5213f43a157f8a392b58555301682892ba928c04a';
const PAYLOAD_IDENTIFIER = 'io.envara.fixed-application-finalization-46ae-run904';
const priorReceiptFile = path.join(root, 'test-artifacts/mac-pf-routing/recovery-exact-cleanup-result-20261009.json');
const RUN = '90401ced-5d54-4422-b80c-c7c4485a037b', ENV = 'f285429a-61e4-4023-8749-ec9073ce6a39';
const buildReceiptFile = path.join(root, 'test-artifacts/mac-pf-routing/application-recovery-46ae-run904-finalize-build-20261009.json');
const sha = value => createHash('sha256').update(value).digest('hex');

async function heldBytes(filename, limit = 32 * 1024 * 1024) {
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(limit)) throw new Error('Input is not a bounded single-link regular file.');
    const bytes = await handle.readFile(), after = await handle.stat({ bigint: true });
    const keys = ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs'];
    if (BigInt(bytes.length) !== before.size || keys.some(key => before[key] !== after[key])) throw new Error('Input changed while reading.');
    return { bytes, stat: after, sha256: sha(bytes) };
  } finally { await handle.close(); }
}

export async function buildFixedFinalizationAuthorization46ae() {
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || process.getuid() === 0) throw new Error('This local inert builder requires an unprivileged Darwin arm64 process.');
  const priorReceipt = await heldBytes(priorReceiptFile, 16384);
  const prior = JSON.parse(priorReceipt.bytes), priorResult = prior.result;
  if (prior.exitCode !== 1 || priorResult?.runId !== RUN || priorResult?.environmentId !== ENV || priorResult?.manifestSHA256 !== MF ||
    priorResult?.reason !== 'CLEANUP_UNCONFIRMED' || priorResult?.ok !== false || priorResult?.cleanupConfirmed !== false ||
    priorResult?.originalHostBaselineVerified !== false || ['rootHookRemoved', 'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'deleteAttempted', 'bootstrapRootTargetBound'].some(key => priorResult[key] !== true)) {
    throw new Error('Expected the exact root-authorized partial receipt, without a completed recovery claim.');
  }
  const priorHeader = await heldBytes(path.join(native, 'recovery-app-46ae-run904-finalize-prior.h'));
  const headerText = priorHeader.bytes.toString('utf8');
  const sealedSHA = /^#define FINALIZER_PRIOR_SHA "([0-9a-f]{64})"$/m.exec(headerText)?.[1];
  const sealedBody = /static const unsigned char finalizerPriorBytes\[\] = \{([\s\S]*?)\};/.exec(headerText)?.[1];
  if (sealedSHA !== priorReceipt.sha256 || !sealedBody || sealedBody.replace(/0x[0-9a-f]{2}|[\s,]/g, '') ||
    !Buffer.from((sealedBody.match(/0x[0-9a-f]{2}/g) ?? []).map(value => Number.parseInt(value, 16))).equals(priorReceipt.bytes)) {
    throw new Error('The fixed compiled prior receipt does not match the exact reviewed bytes.');
  }
  const inputNames = ['recovery-app-46ae-run904-finalize.m', 'recovery-app-46ae-run904.m', 'recovery-app-46ae-inventory.h',
    'recovery-app-46ae-manifest.json', 'recovery-app-46ae-run904-finalize-prior.h', 'app-scope-proof.c', 'app-scope-proof.h',
    'pf-hook-abi.h', 'recovery-app-46ae-finalize-wrapper.m'];
  const sources = [...inputNames.map(name => path.join(native, name)), priorReceiptFile,
    path.join(root, 'scripts/lib/macos-fixed-recovery-stage.mjs'),
    path.join(root, 'tests/macos-pf-app-recovery-46ae-finalize.test.mjs'),
    path.join(root, 'tests/macos-pf-app-finalize-wrapper.test.mjs'), fileURLToPath(import.meta.url)];
  const sourceInputs = Object.fromEntries(await Promise.all(sources.map(async file => [path.relative(root, file), (await heldBytes(file)).sha256])));
  const sealedManifestBytes = await heldBytes(path.join(native, 'recovery-app-46ae-manifest.json'));
  if (sealedManifestBytes.sha256 !== MF) throw new Error('The sealed fixed 46ae manifest differs.');
  const sealedManifest = JSON.parse(sealedManifestBytes.bytes);
  if (sealedManifest.schema !== 'envara.macos-pf-installation/v1' || sealedManifest.backend !== 'pf-utun' ||
    Object.keys(sealedManifest.files ?? {}).length !== 18) throw new Error('The sealed fixed 46ae inventory is not the 18-leaf candidate.');
  for (const name of ['app-scope-proof.c', 'app-scope-proof.h', 'pf-hook-abi.h']) {
    if ((await heldBytes(path.join(native, name))).sha256 !== sealedManifest.nativeSourceFiles?.[`native/macos-pf-routing/${name}`]) {
      throw new Error(`Finalizer dependency differs from the sealed fixed 46ae source: ${name}`);
    }
  }
  const installedManifest = await heldBytes('/Library/PrivilegedHelperTools/io.envara.pf-routing/manifest.json');
  if (installedManifest.sha256 !== MF) throw new Error('The fixed installed prerequisite differs.');
  const node = await heldBytes(NODE, 256 * 1024 * 1024);
  if (node.sha256 !== NODE_SHA || node.stat.uid !== 0n || node.stat.gid !== 0n || (node.stat.mode & 0o7777n) !== 0o755n) throw new Error('Installed root-owned Node does not match the fixed prerequisite.');
  const dependencies = (await exec('/usr/bin/otool', ['-L', NODE], { timeout: 10000 })).stdout.split('\n').slice(1).map(line => line.trim().split(' (')[0]).filter(Boolean);
  if (dependencies.length !== 4 || dependencies.some(value => !value.startsWith('/System/Library/') && !value.startsWith('/usr/lib/'))) throw new Error('Node has an unexpected loader dependency.');
  const loadCommands = (await exec('/usr/bin/otool', ['-l', NODE], { timeout: 10000, maxBuffer: 1024 * 1024 })).stdout;
  if (/\bLC_RPATH\b/.test(loadCommands)) throw new Error('Node has a loader search override.');

  // Compile a separate post-retired finalizer directly outside every .app.
  // All privileged entry points remain unexecuted; only --plan is exercised.
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-finalization-46ae-authorization-')));
  const payloadDirectory = path.join(directory, 'standalone-payload');
  await mkdir(payloadDirectory, { mode: 0o700 });
  const payloadBinary = path.join(payloadDirectory, 'EnvaraPFApplicationFinalization46aeRun904');
  await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
    path.join(native, 'recovery-app-46ae-run904-finalize.m'), path.join(native, 'app-scope-proof.c'),
    '-framework', 'Foundation', '-framework', 'Security', '-o', payloadBinary], { timeout: 30000, maxBuffer: 1024 * 1024 });
  const originalPayload = await heldBytes(payloadBinary);
  await exec('/usr/bin/codesign', ['--force', '--sign', '-', '--identifier', PAYLOAD_IDENTIFIER, '--options', 'runtime', '--timestamp=none', payloadBinary], { timeout: 15000 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', payloadBinary], { timeout: 15000 });
  const payloadSignature = (await exec('/usr/bin/codesign', ['--display', '--verbose=4', payloadBinary], { timeout: 10000 })).stderr;
  if (!payloadSignature.split('\n').includes(`Identifier=${PAYLOAD_IDENTIFIER}`) || !payloadSignature.split('\n').includes('Info.plist=not bound')) throw new Error('Recovery payload retained a bundle signature dependency.');
  const payload = await heldBytes(payloadBinary);
  const payloadPlan = JSON.parse((await exec(payloadBinary, ['--plan'], { timeout: 10000 })).stdout);
  const relocatedDirectory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-finalization-46ae-relocated-')));
  const relocatedBinary = path.join(relocatedDirectory, 'EnvaraPFApplicationFinalization46aeRun904');
  await writeFile(relocatedBinary, payload.bytes, { flag: 'wx', mode: 0o755 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', relocatedBinary], { timeout: 15000 });
  const relocationPlan = JSON.parse((await exec(relocatedBinary, ['--plan'], { timeout: 10000 })).stdout);
  if (Object.keys(relocationPlan).length !== Object.keys(payloadPlan).length ||
    Object.entries(payloadPlan).some(([key, value]) => relocationPlan[key] !== value) ||
    relocationPlan.schema !== 'envara.macos-pf-application-finalization/v1' || relocationPlan.manifestSHA256 !== MF ||
    relocationPlan.runId !== RUN || relocationPlan.environmentId !== ENV || relocationPlan.priorRecoveryReceiptSHA256 !== priorReceipt.sha256 ||
    relocationPlan.finalizationHostNetworkUnchanged !== false || relocationPlan.recoveryHostNetworkUnchanged !== false ||
    relocationPlan.reason !== 'INERT_PLAN' || relocationPlan.ok !== true || relocationPlan.readOnly !== true ||
    relocationPlan.cleanupConfirmed !== false || relocationPlan.ready !== false || relocationPlan.protected !== false ||
    (await heldBytes(relocatedBinary)).sha256 !== payload.sha256 || (await heldBytes(payloadBinary)).sha256 !== payload.sha256) {
    throw new Error('Standalone recovery relocation did not preserve its signed bytes and inert plan.');
  }

  const rootTarget = `/Library/PrivilegedHelperTools/io.envara.pf-recovery-46ae-${payload.sha256}`;
  const stage = createFixedRecoveryStage({ binary: payload.bytes, binarySHA256: payload.sha256, rootTarget });
  const nodeArguments = ['--input-type=commonjs', '--no-addons', '--disable-proto=throw', '--disable-sigusr1', '--eval', stage.program];
  const argumentBytes = nodeArguments.reduce((total, value) => total + Buffer.byteLength(value) + 1, Buffer.byteLength(NODE) + 1);
  if (argumentBytes > 196608) throw new Error('Fixed argv exceeds its conservative Darwin limit.');

  const app = path.join(directory, 'Envara Fixed Finalization Authorization.app'), contents = path.join(app, 'Contents');
  await mkdir(path.join(contents, 'MacOS'), { recursive: true, mode: 0o700 });
  const binary = path.join(contents, 'MacOS/EnvaraFixedFinalizationAuthorization');
  const header = path.join(directory, 'recovery-app-46ae-finalize-wrapper-build.h');
  const definitions = {
    WRAPPER_SELF: binary, WRAPPER_CONSOLE_UID: process.getuid(), WRAPPER_RECOVERY_SHA: payload.sha256,
    WRAPPER_RECOVERY_BYTES: payload.bytes.length, WRAPPER_ROOT_TARGET: rootTarget, WRAPPER_PRIOR_RECEIPT_SHA: priorReceipt.sha256,
    WRAPPER_NODE: NODE, WRAPPER_NODE_SHA: NODE_SHA, WRAPPER_STAGE_PROGRAM: stage.program,
  };
  await writeFile(header, Object.entries(definitions).map(([key, value]) => `#define ${key} ${typeof value === 'number' ? value : JSON.stringify(value)}`).join('\n') + '\n', { flag: 'wx', mode: 0o600 });
  await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I', directory, path.join(native, 'recovery-app-46ae-finalize-wrapper.m'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
  await writeFile(path.join(contents, 'Info.plist'), '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.envara.fixed-finalization-authorization-46ae</string><key>CFBundleExecutable</key><string>EnvaraFixedFinalizationAuthorization</string><key>CFBundleName</key><string>Envara Fixed Finalization Authorization</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>1</string><key>LSUIElement</key><true/></dict></plist>\n', { flag: 'wx', mode: 0o600 });
  await exec('/usr/bin/codesign', ['--force', '--sign', '-', '--options', 'runtime', '--timestamp=none', app], { timeout: 15000 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', app], { timeout: 15000 });
  const signature = await exec('/usr/bin/codesign', ['--display', '--verbose=4', app], { timeout: 10000 });
  if (!/flags=0x[0-9a-f]+\([^\n]*runtime/.test(signature.stderr)) throw new Error('Local hardened runtime was not set.');
  const plan = JSON.parse((await exec(binary, ['--plan'], { timeout: 10000 })).stdout);
  if (plan.schema !== 'envara.macos-pf-application-finalization-wrapper/v1' || plan.priorRecoveryReceiptSHA256 !== priorReceipt.sha256 || plan.ok !== true || plan.readOnly !== true || plan.authorizationRequested !== false || plan.cleanupConfirmed !== false || plan.ready !== false || plan.protected !== false || plan.userPresenceRequired !== true || plan.localHardenedSelfVerified !== true) throw new Error('The plan did not stay inert or the local hardened runtime was not verified.');
  for (const [name, expected] of Object.entries(sourceInputs)) if ((await heldBytes(path.join(root, name))).sha256 !== expected) throw new Error(`Wrapper input changed during build: ${name}`);
  if ((await heldBytes(priorReceiptFile, 16384)).sha256 !== priorReceipt.sha256 ||
    (await heldBytes(payloadBinary)).sha256 !== payload.sha256 || (await heldBytes(relocatedBinary)).sha256 !== payload.sha256 ||
    (await heldBytes(NODE, 256 * 1024 * 1024)).sha256 !== NODE_SHA || (await heldBytes('/Library/PrivilegedHelperTools/io.envara.pf-routing/manifest.json')).sha256 !== MF) throw new Error('A fixed prerequisite changed during build.');
  const proof = {
    schema: 'envara.fixed-finalization-authorization-build/v1', checkedAt: new Date().toISOString(), directory, app, binary,
    binarySHA256: (await heldBytes(binary)).sha256, sourceInputs, priorRecoveryReceipt: priorReceiptFile, priorRecoveryReceiptSHA256: priorReceipt.sha256,
    recoveryBinarySHA256: payload.sha256, recoveryBinaryBytes: payload.bytes.length, rootTarget,
    originalRecoveryPayloadSHA: priorResult.recoveryBinarySHA256, compiledUnsignedPayloadSHA: originalPayload.sha256,
    newRecoveryPayloadSHA: payload.sha256, relocationChecked: true, scope: 'post-retired-finalization-only',
    PFTokenReleaseExecuted: false, DELETEExecuted: false, groupDeleteExecuted: false, originalHostBaselineVerified: false,
    standalonePayload: { binary: payloadBinary, relocatedBinary, identifier: PAYLOAD_IDENTIFIER,
      infoPlistBound: false, localAdHoc: true, hardenedRuntime: true, strictAllArchitecturesVerified: true, relocationPlan },
    fixedNode: { path: NODE, sha256: NODE_SHA, dependencies, rpathAbsent: true },
    fixedStage: { schema: stage.schema, programSHA256: sha(stage.program), argumentBytes, flags: nodeArguments.slice(0, -1) },
    signature: { localAdHoc: true, hardenedRuntime: true, strictVerified: true, distributionTrustEstablished: false },
    plan, rootTargetCreated: false, authorizationRequested: false, rootExecuted: false, systemOperationExecuted: false,
    recoveryVerified: false, cleanupConfirmed: false, bootstrapRootTargetBound: false, productionReady: false,
  };
  await writeFile(path.join(directory, 'finalization-authorization-build.json'), JSON.stringify(proof, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  await writeFile(buildReceiptFile, JSON.stringify(proof, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return proof;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) { console.error('This inert builder accepts no operation or path overrides.'); process.exitCode = 1; }
  else { try { const proof = await buildFixedFinalizationAuthorization46ae(); console.log(JSON.stringify(proof)); }
    catch (error) { console.error(error.message); process.exitCode = 1; } }
}
