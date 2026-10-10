// Independent fixed f99 live-run recovery source candidate. Only own-temp
// compile/sign/plan/nonroot refusal. No Authorization, root, signals, PF or FS
// recovery operation runs here. Fresh inspection and separate scope review are
// required before a user-present fixed carrier can be prepared.
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
const MF = 'f99aac934122ac3cafe992ac6fbf232ff917c1b8632034d19491b3dca7ab0d51';
const RUN = '14514ea6-7f9c-4cdc-92ae-c67d5ac31a7a', ENV = '9b5fb67d-7d8e-492b-a1f5-cccd893b0567';
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
export async function buildFixedLiveRecoveryF99SocketMetadata() {
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || process.getuid() === 0) throw new Error('This inert builder requires the unprivileged reviewed Darwin arm64 host.');
  const manifestFile = path.join(native, 'inspector-app-f99-manifest.json');
  if (await hash(manifestFile) !== MF) throw new Error('Fixed f99 manifest copy differs.');
  const manifest = JSON.parse(await readFile(manifestFile, 'utf8'));
  if (manifest.schema !== 'envara.macos-pf-installation/v1' || manifest.backend !== 'pf-utun' || Object.keys(manifest.files ?? {}).length !== 18) throw new Error('Fixed inventory is not the 18-leaf application candidate.');
  const source = path.join(native, 'recovery-app-f99-run145-socket-metadata.m'), inventory = path.join(native, 'inspector-app-f99-inventory.h');
  const text = await readFile(inventory, 'utf8');
  if (!text.includes(MF) || !text.includes(RUN)) throw new Error('Fixed inspector identifiers differ.');
  for (const [name, sha] of Object.entries({ ...manifest.files, 'manifest.json': MF })) {
    if (!/^[a-zA-Z0-9_.-]+$/.test(name) && name !== 'fixtures/EnvaraRoutingAcceptanceFixture') throw new Error('Unexpected fixed leaf.');
    const mode = executableLeaves.has(name) ? '0755' : '0644';
    if (!text.includes(`{"${name}","${sha}",${mode}}`)) throw new Error(`Fixed inspector inventory differs: ${name}`);
  }
  const fixedInputs = ['app-scope-proof.c', 'app-scope-proof.h', 'pf-hook-abi.h', 'app-transport.c', 'app-transport.h'];
  for (const name of fixedInputs) if (await hash(path.join(native, name)) !== manifest.nativeSourceFiles[`native/macos-pf-routing/${name}`]) throw new Error(`Compiled dependency differs from the fixed f99 source: ${name}`);
  const grounding = path.join(root,'test-artifacts/mac-pf-routing/f99-socketinfo-vs-fstat-source-20261009.json'), actualReadonly = path.join(root,'test-artifacts/mac-pf-routing/f99-run145-custody-diagnostic-actual-20261009T051555Z.json');
  const sourceGrounding = JSON.parse(await readFile(grounding,'utf8'));
  if (sourceGrounding.actualReadonlyReceiptSHA256 !== await hash(actualReadonly) || sourceGrounding.fixedManifestSHA256 !== MF || sourceGrounding.sourceCommit !== 'f6217f891ac0bb64f3d375211650a4c1ff8ca1ea') throw new Error('Exact source/actual readonly grounding differs.');
  const inputFiles = [source,grounding,actualReadonly, path.join(native, 'inspector-app-f99-run145.m'), inventory, manifestFile, ...fixedInputs.map(n => path.join(native, n)), fileURLToPath(import.meta.url), path.join(root, 'tests/macos-pf-live-recovery-f99-socket-metadata.test.mjs')];
  const sourceInputs = {};
  for (const file of inputFiles) sourceInputs[path.relative(root, file)] = await hash(file);
  const unchanged = async () => { for (const [name, sha] of Object.entries(sourceInputs)) if (await hash(path.join(root, name)) !== sha) return false; return true; };
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-live-recovery-f99-run145-socket-metadata-')));
  const app = path.join(directory, 'Envara Fixed Live Recovery Socket Metadata f99 Run145.app'), contents = path.join(app, 'Contents');
  await mkdir(path.join(contents, 'MacOS'), { recursive: true, mode: 0o700 });
  const binary = path.join(contents, 'MacOS/EnvaraPFLiveApplicationRecoveryF99SocketMetadataRun145');
  await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', source,
    path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
  if (!await unchanged()) throw new Error('Inspector source changed while compiling.');
  await writeFile(path.join(contents, 'Info.plist'), '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.envara.fixed-live-recovery-f99-socket-metadata-14514ea6</string><key>CFBundleExecutable</key><string>EnvaraPFLiveApplicationRecoveryF99SocketMetadataRun145</string><key>CFBundleName</key><string>Envara Fixed Live Recovery Socket Metadata f99 Run145</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>1</string><key>LSUIElement</key><true/></dict></plist>\n', { flag: 'wx', mode: 0o600 });
  await exec('/usr/bin/codesign', ['--force', '--sign', '-', app], { timeout: 15000 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', app], { timeout: 15000 });
  const imports = (await exec('/usr/bin/nm', ['-u', binary], { timeout: 10000 })).stdout;
  if (!/(?:^|\n)_getgroups(?:\n|$)/.test(imports) || imports.includes('_getgroups$DARWIN_EXTSN')) throw new Error('Inspector did not bind the legacy kernel credential getter.');
  const plan = JSON.parse((await exec(binary, ['--plan'], { timeout: 10000 })).stdout);
  if (plan.schema !== 'envara.macos-pf-live-application-recovery/v1' || plan.reason !== 'INERT_FIXED_LIVE_RECOVERY_PLAN' || plan.originalApplicationHostBaselineVerified !== false || plan.manifestSHA256 !== MF || plan.runId !== RUN || plan.environmentId !== ENV || plan.readOnly !== true || plan.mutationEntryLinked !== true || plan.ready !== false || plan.protected !== false || plan.cleanupConfirmed !== false) throw new Error('Inspector plan is not the fixed inert candidate.');
  const refusals = [];
  for (const operation of ['--inspect-fixed-root', '--cleanup-fixed-root', '--request-readonly-existing-rights']) {
    let stdout;
    try { await exec(binary, [operation], { timeout: 10000 }); throw new Error('Nonroot or unknown inspector operation unexpectedly succeeded.'); }
    catch (error) { if (error.code !== 1) throw error; stdout = error.stdout; }
    const refusal = JSON.parse(stdout);
    if (refusal.reason !== 'FIXED_LIVE_RECOVERY_PREFLIGHT_REFUSED' || refusal.ok !== false || refusal.cleanupConfirmed !== false || refusal.cleanupUncertain !== true || ['controllerStopped','keeperStopped','ownedFilterClearAttempted','ownedPFReferenceReleaseAttempted','rootHookDeleteAttempted','ownedGroupDeleteAttempted','runtimeArchived'].some(k => refusal[k] !== false)) throw new Error('Recovery nonroot refusal attempted an operation.');
    refusals.push({ operation, refusal });
  }
  if (!await unchanged()) throw new Error('Inspector source changed before final proof.');
  const proof = { schema: 'envara.macos-pf-live-application-recovery-build/v1', directory, app, binary,
    fixedManifestSHA256: MF, fixedNativeSHA256: manifest.files['envara-pf-native'], fixedRunId: RUN, fixedEnvironmentId: ENV,
    revisionOfRecoverySourceSHA256: 'f68e211ca1c974f1ca854eee762f9853f3667523f37923985c45693c837f718e',
    socketMetadataGrounding: { sourceCommit: sourceGrounding.sourceCommit, sources: sourceGrounding.sources, actualReadonlyReceiptSHA256: sourceGrounding.actualReadonlyReceiptSHA256, expectedSocketInfoUIDPlaceholder:0, expectedSocketInfoGIDPlaceholder:0, creatorCredentialVerified:false, originalDescriptorCustodyVerified:false, publicSourceEqualsLiveKernelSource:false },
    listenerCreatorSourceContract: { appTransportSHA256: manifest.nativeSourceFiles['native/macos-pf-routing/app-transport.c'],
      appTransportHeaderSHA256: manifest.nativeSourceFiles['native/macos-pf-routing/app-transport.h'], expectedSocketUID: 0, expectedSocketGID: 7100,
      expectedKeeperProcessUID: 0, expectedKeeperProcessGID: 0, sourcePinMatchesExactInstalledManifest: true, actualCurrentRootSocketReadbackAccepted: false },
    installedRuntimeLeafCount: 19, sourceInputs, binarySHA256: await hash(binary), plan, refusals,
    authorizationRequested: false, rootExecuted: false, systemOperationExecuted: false, PFWriteExecuted: false,
    kernelCredentialGetter: { symbol: '_getgroups', darwinDirectoryExtensionImported: false },
    originalApplicationBaselineVerified: false, nativeInspectionExecuted: false, nativeRecoveryExecuted: false, cleanupConfirmed: false,
    ownedKeeperSignalExecuted: false, ownedFilterClearExecuted: false, rootHookDeleteExecuted: false,
    groupOperationExecuted: false, runtimeArchiveExecuted: false,
    actualDescriptorCustodyAccepted: false, actualRecoveryAcceptance: false,
    requiredBeforeAuthorization: ['fresh-fixed-run-native-inspection', 'root-reviewed-exact-STOP-and-post-EMPTY-KILL-scope', 'independent-source-review'],
    authorizationEntryIncluded: false, userPresenceRequiredForFutureAuthorization: true,
    installedCandidateChanged: false, productionReady: false };
  await writeFile(path.join(directory, 'live-recovery-build.json'), JSON.stringify(proof, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return proof;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) { console.error('This inert recovery builder accepts no operation, path, UUID or authorization arguments.'); process.exitCode = 1; }
  else { try { console.log(JSON.stringify(await buildFixedLiveRecoveryF99SocketMetadata(), null, 2)); }
    catch (error) { console.error(error.message); process.exitCode = 1; } }
}
