// Builds a local, user-present authorization carrier. Only --plan is executed;
// no Authorization request, privileged stage, inspection or installation runs.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { constants } from 'node:fs';
import { mkdtemp, realpath, mkdir, readFile, writeFile, open } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify, isDeepStrictEqual } from 'node:util';
import { createFixedUTunAPIStage } from './lib/macos-fixed-utun-api-stage.mjs';

const exec = promisify(execFile), root = path.resolve(import.meta.dirname, '..');
const native = path.join(root, 'native/macos-pf-routing');
const PROBE_RECEIPT_SHA = 'fe145d37f3bfb973e277730ce4c1d59891bdaf4a4539c052f603432e0ff98a54';
const PROBE_BINARY_SHA = '387f1607c81d8eb694c1e3d28eb1020f794d3f2ba1d0b3c88d6e1a449b3cb248';
const PROBE_SOURCE_SHA = '48481c08174e0048c25d63b5a87fc467a7b7e91a68b344a3a27918b9cf7702be';
const NODE = '/Library/PrivilegedHelperTools/io.envara.pf-routing/node';
const NODE_SHA = 'ee6fb0e015284d83a91e8ec5213f43a157f8a392b58555301682892ba928c04a';
const PAYLOAD_IDENTIFIER = 'io.envara.fixed-utun-api-probe';
const receiptFile = path.join(root, 'test-artifacts/mac-pf-routing/utun-api-probe-build-20261009.json');
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

export async function buildFixedUTunAPIProbeAuthorization() {
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || process.getuid() === 0) throw new Error('This local inert builder requires an unprivileged Darwin arm64 process.');
  if (![PROBE_RECEIPT_SHA, PROBE_BINARY_SHA, PROBE_SOURCE_SHA].every(value => /^[0-9a-f]{64}$/.test(value))) throw new Error('Reviewed native UTUN probe pins are pending.');
  const probeReceipt = await heldBytes(receiptFile);
  if (probeReceipt.sha256 !== PROBE_RECEIPT_SHA) throw new Error('The reviewed native probe receipt changed.');
  const probe = JSON.parse(probeReceipt.bytes);
  if (probe.schema !== 'envara.macos-utun-api-probe-build/v1' || probe.binarySHA256 !== PROBE_BINARY_SHA ||
    probe.sourceInputs?.['native/macos-pf-routing/utun-api-probe.m'] !== PROBE_SOURCE_SHA ||
    Object.keys(probe.sourceInputs ?? {}).length !== 5 || probe.rootExecuted !== false || probe.authorizationRequested !== false || probe.nativeProbeExecuted !== false ||
    probe.systemOperationExecuted !== false || probe.PFWriteExecuted !== false || probe.configurationExecuted !== false || probe.applicationLaunchExecuted !== false ||
    probe.originalHostBaselineVerified !== false || probe.productionReady !== false ||
    probe.kernelCredentialGetter?.symbol !== '_getgroups' || probe.kernelCredentialGetter?.darwinDirectoryExtensionImported !== false ||
    probe.signature?.standalone !== true || probe.signature?.hardenedRuntime !== true || probe.signature?.strictAllArchitecturesVerified !== true) throw new Error('Expected a fixed, unexecuted native probe receipt.');
  for (const [name, expected] of Object.entries(probe.sourceInputs)) if ((await heldBytes(path.join(root, name))).sha256 !== expected) throw new Error(`Probe input changed: ${name}`);
  const originalPayload = await heldBytes(probe.binary);
  if (originalPayload.sha256 !== PROBE_BINARY_SHA) throw new Error('Compiled native probe bytes changed.');
  await exec('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', probe.binary], { timeout: 15000 });
  const node = await heldBytes(NODE, 256 * 1024 * 1024);
  if (node.sha256 !== NODE_SHA || node.stat.uid !== 0n || node.stat.gid !== 0n || (node.stat.mode & 0o7777n) !== 0o755n) throw new Error('Installed root-owned Node does not match the fixed prerequisite.');
  const dependencies = (await exec('/usr/bin/otool', ['-L', NODE], { timeout: 10000 })).stdout.split('\n').slice(1).map(line => line.trim().split(' (')[0]).filter(Boolean);
  if (dependencies.length !== 4 || dependencies.some(value => !value.startsWith('/System/Library/') && !value.startsWith('/usr/lib/'))) throw new Error('Node has an unexpected loader dependency.');
  const loadCommands = (await exec('/usr/bin/otool', ['-l', NODE], { timeout: 10000, maxBuffer: 1024 * 1024 })).stdout;
  if (/\bLC_RPATH\b/.test(loadCommands)) throw new Error('Node has a loader search override.');

  // Preserve the reviewed native input; sign only a new owned standalone copy.
  // A second copy must retain strict signature validity and its exact inert plan.
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-utun-api-probe-authorization-')));
  const payloadDirectory = path.join(directory, 'standalone-payload');
  await mkdir(payloadDirectory, { mode: 0o700 });
  const payloadBinary = path.join(payloadDirectory, 'EnvaraUTunAPIProbe');
  await writeFile(payloadBinary, originalPayload.bytes, { flag: 'wx', mode: 0o755 });
  await exec('/usr/bin/codesign', ['--remove-signature', payloadBinary], { timeout: 15000 });
  await exec('/usr/bin/codesign', ['--force', '--sign', '-', '--identifier', PAYLOAD_IDENTIFIER, '--options', 'runtime', '--timestamp=none', payloadBinary], { timeout: 15000 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', payloadBinary], { timeout: 15000 });
  const payloadSignature = (await exec('/usr/bin/codesign', ['--display', '--verbose=4', payloadBinary], { timeout: 10000 })).stderr;
  if (!payloadSignature.split('\n').includes(`Identifier=${PAYLOAD_IDENTIFIER}`) || !payloadSignature.split('\n').includes('Info.plist=not bound')) throw new Error('Probe payload retained a bundle signature dependency.');
  const payload = await heldBytes(payloadBinary);
  const relocatedDirectory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-utun-api-probe-relocated-')));
  const relocatedBinary = path.join(relocatedDirectory, 'EnvaraUTunAPIProbe');
  await writeFile(relocatedBinary, payload.bytes, { flag: 'wx', mode: 0o755 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', relocatedBinary], { timeout: 15000 });
  const relocationPlan = JSON.parse((await exec(relocatedBinary, ['--plan'], { timeout: 10000 })).stdout);
  if (!probe.plan || !isDeepStrictEqual(relocationPlan, probe.plan) ||
    relocationPlan.reason !== 'INERT_FIXED_UTUN_API_PLAN' || relocationPlan.ok !== true || relocationPlan.readOnly !== true ||
    relocationPlan.cleanupConfirmed !== false || relocationPlan.ready !== false || relocationPlan.protected !== false ||
    (await heldBytes(relocatedBinary)).sha256 !== payload.sha256 || (await heldBytes(payloadBinary)).sha256 !== payload.sha256) {
    throw new Error('Standalone native probe relocation did not preserve its signed bytes and inert plan.');
  }

  const rootTarget = `/Library/PrivilegedHelperTools/io.envara.utun-api-probe-${payload.sha256}`;
  const stage = createFixedUTunAPIStage({ binary: payload.bytes, binarySHA256: payload.sha256, rootTarget });
  const nodeArguments = ['--input-type=commonjs', '--no-addons', '--disable-proto=throw', '--disable-sigusr1', '--eval', stage.program];
  const argumentBytes = nodeArguments.reduce((total, value) => total + Buffer.byteLength(value) + 1, Buffer.byteLength(NODE) + 1);
  if (argumentBytes > 196608) throw new Error('Fixed argv exceeds its conservative Darwin limit.');

  const sources = [path.join(native, 'utun-api-probe-wrapper.m'), path.join(root, 'scripts/lib/macos-fixed-utun-api-stage.mjs'), path.join(root, 'tests/macos-utun-api-probe-wrapper.test.mjs'), fileURLToPath(import.meta.url)];
  const sourceInputs = Object.fromEntries(await Promise.all(sources.map(async file => [path.relative(root, file), (await heldBytes(file)).sha256])));
  const app = path.join(directory, 'Envara UTUN API Probe Authorization.app'), contents = path.join(app, 'Contents');
  await mkdir(path.join(contents, 'MacOS'), { recursive: true, mode: 0o700 });
  const binary = path.join(contents, 'MacOS/EnvaraUTunAPIProbeAuthorization');
  const header = path.join(directory, 'utun-api-probe-wrapper-build.h');
  const definitions = {
    WRAPPER_PROTOCOL_READY: 1, WRAPPER_SELF: binary, WRAPPER_CONSOLE_UID: process.getuid(), WRAPPER_PROBE_SHA: payload.sha256,
    WRAPPER_PROBE_BYTES: payload.bytes.length, WRAPPER_ROOT_TARGET: rootTarget,
    WRAPPER_NODE: NODE, WRAPPER_NODE_SHA: NODE_SHA, WRAPPER_STAGE_PROGRAM: stage.program,
  };
  await writeFile(header, Object.entries(definitions).map(([key, value]) => `#define ${key} ${typeof value === 'number' ? value : JSON.stringify(value)}`).join('\n') + '\n', { flag: 'wx', mode: 0o600 });
  await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I', directory, path.join(native, 'utun-api-probe-wrapper.m'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
  await writeFile(path.join(contents, 'Info.plist'), '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.envara.utun-api-probe-authorization</string><key>CFBundleExecutable</key><string>EnvaraUTunAPIProbeAuthorization</string><key>CFBundleName</key><string>Envara UTUN API Probe Authorization</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>1</string><key>LSUIElement</key><true/></dict></plist>\n', { flag: 'wx', mode: 0o600 });
  await exec('/usr/bin/codesign', ['--force', '--sign', '-', '--options', 'runtime', '--timestamp=none', app], { timeout: 15000 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', app], { timeout: 15000 });
  const signature = await exec('/usr/bin/codesign', ['--display', '--verbose=4', app], { timeout: 10000 });
  if (!/flags=0x[0-9a-f]+\([^\n]*runtime/.test(signature.stderr)) throw new Error('Local hardened runtime was not set.');
  const plan = JSON.parse((await exec(binary, ['--plan'], { timeout: 10000 })).stdout);
  if (plan.ok !== true || plan.readOnly !== true || plan.authorizationRequested !== false || plan.cleanupConfirmed !== false || plan.ready !== false || plan.protected !== false || plan.userPresenceRequired !== true || plan.localHardenedSelfVerified !== true) throw new Error('The plan did not stay inert or the local hardened runtime was not verified.');
  for (const [name, expected] of Object.entries(sourceInputs)) if ((await heldBytes(path.join(root, name))).sha256 !== expected) throw new Error(`Wrapper input changed during build: ${name}`);
  for (const [name, expected] of Object.entries(probe.sourceInputs)) if ((await heldBytes(path.join(root, name))).sha256 !== expected) throw new Error(`Native probe input changed during build: ${name}`);
  if ((await heldBytes(receiptFile)).sha256 !== PROBE_RECEIPT_SHA || (await heldBytes(probe.binary)).sha256 !== originalPayload.sha256 ||
    (await heldBytes(payloadBinary)).sha256 !== payload.sha256 || (await heldBytes(relocatedBinary)).sha256 !== payload.sha256 ||
    (await heldBytes(NODE, 256 * 1024 * 1024)).sha256 !== NODE_SHA) throw new Error('A fixed prerequisite changed during build.');
  const proof = {
    schema: 'envara.fixed-utun-api-probe-authorization-build/v1', checkedAt: new Date().toISOString(), directory, app, binary,
    binarySHA256: (await heldBytes(binary)).sha256, sourceInputs, nativeReceipt: receiptFile, nativeReceiptSHA256: PROBE_RECEIPT_SHA,
    fixedProbeSourceSHA256: PROBE_SOURCE_SHA, originalProbeBinarySHA256: PROBE_BINARY_SHA,
    rootOperations: ['--probe-fixed-root'], allowedWrapperOperations: ['--plan', '--request-readonly', '--request-install-and-readonly'],
    probeReadOnly: false, probeCreatesTemporaryInterface: true,
    probeBinarySHA256: payload.sha256, probeBinaryBytes: payload.bytes.length, rootTarget,
    originalBinarySHA: originalPayload.sha256, newProbePayloadSHA: payload.sha256, relocationChecked: true,
    standalonePayload: { binary: payloadBinary, relocatedBinary, identifier: PAYLOAD_IDENTIFIER,
      infoPlistBound: false, localAdHoc: true, hardenedRuntime: true, strictAllArchitecturesVerified: true, relocationPlan },
    fixedNode: { path: NODE, sha256: NODE_SHA, dependencies, rpathAbsent: true },
    fixedStage: { schema: stage.schema, programSHA256: sha(stage.program), argumentBytes, flags: nodeArguments.slice(0, -1) },
    signature: { localAdHoc: true, hardenedRuntime: true, strictVerified: true, distributionTrustEstablished: false },
    plan, rootTargetCreated: false, authorizationRequested: false, rootExecuted: false, systemOperationExecuted: false,
    probeExecuted: false, nativeProbeExecuted: false, socketCreated: false, interfaceCreated: false,
    PFWriteExecuted: false, routeWriteExecuted: false, DNSWriteExecuted: false, MTUWriteExecuted: false,
    IPConfigurationExecuted: false, coreLaunched: false, groupChanged: false, applicationLaunchExecuted: false,
    runtimeChanged: false, bootstrapRootTargetBound: false, productionReady: false,
  };
  await writeFile(path.join(directory, 'authorization-build.json'), JSON.stringify(proof, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  await writeFile(path.join(root, 'test-artifacts/mac-pf-routing/utun-api-probe-carrier-build-20261009.json'), JSON.stringify(proof, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return proof;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) { console.error('This inert builder accepts no operation or path overrides.'); process.exitCode = 1; }
  else { try { const proof = await buildFixedUTunAPIProbeAuthorization(); console.log(JSON.stringify(proof)); }
    catch (error) { console.error(error.message); process.exitCode = 1; } }
}
