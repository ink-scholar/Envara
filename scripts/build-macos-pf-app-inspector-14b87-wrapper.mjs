// Builds a local, user-present authorization carrier. Only --plan is executed;
// no Authorization request, privileged stage, inspection or installation runs.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { constants } from 'node:fs';
import { mkdtemp, realpath, mkdir, readFile, writeFile, open } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createFixedInspectorStage } from './lib/macos-fixed-inspector-14b87-stage.mjs';

const exec = promisify(execFile), root = path.resolve(import.meta.dirname, '..');
const native = path.join(root, 'native/macos-pf-routing');
const MF = '14b87d3452af4acaf67709c2494d637163d108a101f6d07fb27ce8e61c2d1d50';
const RUN = '5be11012-0c9e-456c-84b9-9e311df4cbdd';
const ENVIRONMENT = '5a50dcef-3314-4195-8ba5-c94ca6a0bef0';
const INSPECTOR_RECEIPT_SHA = '8f071b5983e10e77ed10ee22567994fce2492dfe23e327e258f8f180ae38d0c8';
const INSPECTOR_BINARY_SHA = 'acff3d3ad41bf0173e18d03a15e202715651866086c88d09aec7039fe6bf0bd0';
const NATIVE_SHA = '3fb52746b306e6ab9a52d61bb573405e4d191886702e3ae4c1932a17ee3939ee';
const NODE = '/Library/PrivilegedHelperTools/io.envara.pf-routing/node';
const NODE_SHA = 'ee6fb0e015284d83a91e8ec5213f43a157f8a392b58555301682892ba928c04a';
const PAYLOAD_IDENTIFIER = 'io.envara.fixed-application-inspector-14b87-run5be';
const receiptFile = path.join(root, 'test-artifacts/mac-pf-routing/14b87-run5be-inspector-build-20261009.json');
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

export async function buildFixedInspectorAuthorization14B87() {
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || process.getuid() === 0) throw new Error('This local inert builder requires an unprivileged Darwin arm64 process.');
  const inspectorReceipt = await heldBytes(receiptFile);
  if (inspectorReceipt.sha256 !== INSPECTOR_RECEIPT_SHA) throw new Error('The reviewed inspector receipt changed.');
  const inspector = JSON.parse(inspectorReceipt.bytes);
  if (inspector.schema !== 'envara.macos-pf-application-inspection-build/v1' || inspector.fixedManifestSHA256 !== MF || inspector.fixedRunId !== RUN || inspector.fixedEnvironmentId !== ENVIRONMENT ||
    inspector.fixedNativeSHA256 !== NATIVE_SHA || inspector.binarySHA256 !== INSPECTOR_BINARY_SHA || inspector.installedRuntimeLeafCount !== 19 ||
    inspector.rootExecuted !== false || inspector.authorizationRequested !== false || inspector.cleanupConfirmed !== false || inspector.nativeInspectionExecuted !== false || inspector.PFWriteExecuted !== false || inspector.installedCandidateChanged !== false ||
    inspector.kernelCredentialGetter?.symbol !== '_getgroups' || inspector.kernelCredentialGetter?.darwinDirectoryExtensionImported !== false) throw new Error('Expected reviewed, unexecuted fixed inspector receipt.');
  for (const [name, expected] of Object.entries(inspector.sourceInputs)) if ((await heldBytes(path.join(root, name))).sha256 !== expected) throw new Error(`Inspector input no longer matches the compiled receipt: ${name}`);
  const fixedManifest = await heldBytes(path.join(native, 'inspector-app-14b87-manifest.json'));
  if (fixedManifest.sha256 !== MF) throw new Error('The fixed source manifest changed.');
  const inventory = JSON.parse(fixedManifest.bytes);
  if (Object.keys(inventory.files ?? {}).length + 1 !== 19) throw new Error('The fixed runtime leaf count changed.');
  for (const name of ['app-scope-proof.c', 'app-scope-proof.h', 'pf-hook-abi.h']) {
    const key = `native/macos-pf-routing/${name}`;
    if (inventory.nativeSourceFiles?.[key] !== inspector.sourceInputs[key]) throw new Error(`Fixed native dependency differs: ${name}`);
  }
  const originalPayload = await heldBytes(inspector.binary);
  if (originalPayload.sha256 !== INSPECTOR_BINARY_SHA) throw new Error('Compiled inspector bytes changed.');
  await exec('/usr/bin/codesign', ['--verify', '--strict', inspector.app], { timeout: 15000 });
  const installedManifest = await heldBytes('/Library/PrivilegedHelperTools/io.envara.pf-routing/manifest.json');
  if (installedManifest.sha256 !== MF) throw new Error('The fixed installed prerequisite differs.');
  const node = await heldBytes(NODE, 256 * 1024 * 1024);
  if (node.sha256 !== NODE_SHA || node.stat.uid !== 0n || node.stat.gid !== 0n || (node.stat.mode & 0o7777n) !== 0o755n) throw new Error('Installed root-owned Node does not match the fixed prerequisite.');
  const dependencies = (await exec('/usr/bin/otool', ['-L', NODE], { timeout: 10000 })).stdout.split('\n').slice(1).map(line => line.trim().split(' (')[0]).filter(Boolean);
  if (dependencies.length !== 4 || dependencies.some(value => !value.startsWith('/System/Library/') && !value.startsWith('/usr/lib/'))) throw new Error('Node has an unexpected loader dependency.');
  const loadCommands = (await exec('/usr/bin/otool', ['-l', NODE], { timeout: 10000, maxBuffer: 1024 * 1024 })).stdout;
  if (/\bLC_RPATH\b/.test(loadCommands)) throw new Error('Node has a loader search override.');

  // The reviewed input was signed as an app executable. Its bundle Info.plist
  // special slot cannot survive relocation to a standalone root executable.
  // Preserve that input, then sign only a new owned copy outside any .app.
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-inspector-14b87-authorization-')));
  const payloadDirectory = path.join(directory, 'standalone-payload');
  await mkdir(payloadDirectory, { mode: 0o700 });
  const payloadBinary = path.join(payloadDirectory, 'EnvaraPFApplicationInspector14B87Run5BE');
  await writeFile(payloadBinary, originalPayload.bytes, { flag: 'wx', mode: 0o755 });
  await exec('/usr/bin/codesign', ['--remove-signature', payloadBinary], { timeout: 15000 });
  await exec('/usr/bin/codesign', ['--force', '--sign', '-', '--identifier', PAYLOAD_IDENTIFIER, '--options', 'runtime', '--timestamp=none', payloadBinary], { timeout: 15000 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', payloadBinary], { timeout: 15000 });
  const payloadSignature = (await exec('/usr/bin/codesign', ['--display', '--verbose=4', payloadBinary], { timeout: 10000 })).stderr;
  if (!payloadSignature.split('\n').includes(`Identifier=${PAYLOAD_IDENTIFIER}`) || !payloadSignature.split('\n').includes('Info.plist=not bound')) throw new Error('Inspector payload retained a bundle signature dependency.');
  const payload = await heldBytes(payloadBinary);
  const relocatedDirectory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-inspector-14b87-relocated-')));
  const relocatedBinary = path.join(relocatedDirectory, 'EnvaraPFApplicationInspector14B87Run5BE');
  await writeFile(relocatedBinary, payload.bytes, { flag: 'wx', mode: 0o755 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', relocatedBinary], { timeout: 15000 });
  const relocationPlan = JSON.parse((await exec(relocatedBinary, ['--plan'], { timeout: 10000 })).stdout);
  if (!inspector.plan || Object.keys(relocationPlan).length !== Object.keys(inspector.plan).length ||
    Object.entries(inspector.plan).some(([key, value]) => relocationPlan[key] !== value) ||
    relocationPlan.reason !== 'INERT_READ_ONLY_PLAN' || relocationPlan.ok !== true || relocationPlan.readOnly !== true ||
    relocationPlan.cleanupConfirmed !== false || relocationPlan.cleanupPermitted !== false || relocationPlan.ready !== false || relocationPlan.protected !== false ||
    (await heldBytes(relocatedBinary)).sha256 !== payload.sha256 || (await heldBytes(payloadBinary)).sha256 !== payload.sha256) {
    throw new Error('Standalone inspector relocation did not preserve its signed bytes and inert plan.');
  }

  const rootTarget = `/Library/PrivilegedHelperTools/io.envara.pf-inspector-14b87-${payload.sha256}`;
  const stage = createFixedInspectorStage({ binary: payload.bytes, binarySHA256: payload.sha256, rootTarget });
  const nodeArguments = ['--input-type=commonjs', '--no-addons', '--disable-proto=throw', '--disable-sigusr1', '--eval', stage.program];
  const argumentBytes = nodeArguments.reduce((total, value) => total + Buffer.byteLength(value) + 1, Buffer.byteLength(NODE) + 1);
  if (argumentBytes > 196608) throw new Error('Fixed argv exceeds its conservative Darwin limit.');

  const sources = [path.join(native, 'inspector-app-14b87-wrapper.m'), path.join(root, 'scripts/lib/macos-fixed-inspector-14b87-stage.mjs'), path.join(root, 'tests/macos-pf-app-inspector-14b87-wrapper.test.mjs'), fileURLToPath(import.meta.url)];
  const sourceInputs = Object.fromEntries(await Promise.all(sources.map(async file => [path.relative(root, file), (await heldBytes(file)).sha256])));
  const app = path.join(directory, 'Envara Fixed Readonly Inspector 14b87 Run5be Authorization.app'), contents = path.join(app, 'Contents');
  await mkdir(path.join(contents, 'MacOS'), { recursive: true, mode: 0o700 });
  const binary = path.join(contents, 'MacOS/EnvaraFixedInspectorAuthorization');
  const header = path.join(directory, 'inspector-app-14b87-wrapper-build.h');
  const definitions = {
    WRAPPER_SELF: binary, WRAPPER_CONSOLE_UID: process.getuid(), WRAPPER_INSPECTOR_SHA: payload.sha256,
    WRAPPER_INSPECTOR_BYTES: payload.bytes.length, WRAPPER_ROOT_TARGET: rootTarget,
    WRAPPER_NODE: NODE, WRAPPER_NODE_SHA: NODE_SHA, WRAPPER_STAGE_PROGRAM: stage.program,
  };
  await writeFile(header, Object.entries(definitions).map(([key, value]) => `#define ${key} ${typeof value === 'number' ? value : JSON.stringify(value)}`).join('\n') + '\n', { flag: 'wx', mode: 0o600 });
  await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I', directory, path.join(native, 'inspector-app-14b87-wrapper.m'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
  await writeFile(path.join(contents, 'Info.plist'), '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.envara.fixed-inspector-authorization-14b87</string><key>CFBundleExecutable</key><string>EnvaraFixedInspectorAuthorization</string><key>CFBundleName</key><string>Envara Fixed Readonly Inspector 14b87 Run5be Authorization</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>1</string><key>LSUIElement</key><true/></dict></plist>\n', { flag: 'wx', mode: 0o600 });
  await exec('/usr/bin/codesign', ['--force', '--sign', '-', '--options', 'runtime', '--timestamp=none', app], { timeout: 15000 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', app], { timeout: 15000 });
  const signature = await exec('/usr/bin/codesign', ['--display', '--verbose=4', app], { timeout: 10000 });
  if (!/flags=0x[0-9a-f]+\([^\n]*runtime/.test(signature.stderr)) throw new Error('Local hardened runtime was not set.');
  const plan = JSON.parse((await exec(binary, ['--plan'], { timeout: 10000 })).stdout);
  if (plan.ok !== true || plan.readOnly !== true || plan.authorizationRequested !== false || plan.cleanupConfirmed !== false || plan.cleanupPermitted !== false || plan.ready !== false || plan.protected !== false || plan.userPresenceRequired !== true || plan.localHardenedSelfVerified !== true) throw new Error('The plan did not stay inert or the local hardened runtime was not verified.');
  for (const [name, expected] of Object.entries(sourceInputs)) if ((await heldBytes(path.join(root, name))).sha256 !== expected) throw new Error(`Wrapper input changed during build: ${name}`);
  if ((await heldBytes(receiptFile)).sha256 !== INSPECTOR_RECEIPT_SHA || (await heldBytes(inspector.binary)).sha256 !== originalPayload.sha256 ||
    (await heldBytes(payloadBinary)).sha256 !== payload.sha256 || (await heldBytes(relocatedBinary)).sha256 !== payload.sha256 ||
    (await heldBytes(NODE, 256 * 1024 * 1024)).sha256 !== NODE_SHA || (await heldBytes('/Library/PrivilegedHelperTools/io.envara.pf-routing/manifest.json')).sha256 !== MF) throw new Error('A fixed prerequisite changed during build.');
  const proof = {
    schema: 'envara.fixed-inspector-authorization-build/v1', checkedAt: new Date().toISOString(), directory, app, binary,
    binarySHA256: (await heldBytes(binary)).sha256, sourceInputs, inspectorReceipt: receiptFile, inspectorReceiptSHA256: INSPECTOR_RECEIPT_SHA,
    fixedManifestSHA256: MF, fixedNativeSHA256: NATIVE_SHA, fixedRunId: RUN, fixedEnvironmentId: ENVIRONMENT,
    inspectorBinarySHA256: payload.sha256, inspectorBinaryBytes: payload.bytes.length, rootTarget,
    originalBundleBinarySHA: originalPayload.sha256, newInspectorPayloadSHA: payload.sha256, relocationChecked: true,
    standalonePayload: { binary: payloadBinary, relocatedBinary, identifier: PAYLOAD_IDENTIFIER,
      infoPlistBound: false, localAdHoc: true, hardenedRuntime: true, strictAllArchitecturesVerified: true, relocationPlan },
    fixedNode: { path: NODE, sha256: NODE_SHA, dependencies, rpathAbsent: true },
    fixedStage: { schema: stage.schema, programSHA256: sha(stage.program), argumentBytes, flags: nodeArguments.slice(0, -1) },
    signature: { localAdHoc: true, hardenedRuntime: true, strictVerified: true, distributionTrustEstablished: false },
    plan, rootTargetCreated: false, authorizationRequested: false, rootExecuted: false, systemOperationExecuted: false,
    nativeInspectionExecuted: false, cleanupConfirmed: false, cleanupPermitted: false, PFWriteExecuted: false, runtimeChanged: false, bootstrapRootTargetBound: false, productionReady: false,
  };
  await writeFile(path.join(directory, 'authorization-build.json'), JSON.stringify(proof, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  await writeFile(path.join(root, 'test-artifacts/mac-pf-routing/14b87-run5be-inspector-carrier-build-20261009.json'), JSON.stringify(proof, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return proof;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) { console.error('This inert builder accepts no operation or path overrides.'); process.exitCode = 1; }
  else { try { const proof = await buildFixedInspectorAuthorization14B87(); console.log(JSON.stringify(proof)); }
    catch (error) { console.error(error.message); process.exitCode = 1; } }
}
