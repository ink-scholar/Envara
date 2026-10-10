// Independent fixed 05d6/run877 current-custody recovery source candidate. Only own-temp
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
const MF = '05d6eb6ab3d63870d37825b47e2847789a6b5b8c3cf93c434636e0b8aad4f061';
const RUN = '877ab9cc-ed91-4f2d-a8cd-86cedc2f3e21', ENV = '72826f65-99c0-446c-a9c3-b825b36ad1a5';
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
export async function buildFixedLiveRecovery05D6Run877CurrentCustody() {
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || process.getuid() === 0) throw new Error('This inert builder requires the unprivileged reviewed Darwin arm64 host.');
  const manifestFile = path.join(native, 'inspector-app-05d6-manifest.json');
  if (await hash(manifestFile) !== MF) throw new Error('Fixed 05d6 manifest copy differs.');
  const manifest = JSON.parse(await readFile(manifestFile, 'utf8'));
  if (manifest.schema !== 'envara.macos-pf-installation/v1' || manifest.backend !== 'pf-utun' || Object.keys(manifest.files ?? {}).length !== 18) throw new Error('Fixed inventory is not the 18-leaf application candidate.');
  const source = path.join(native, 'recovery-app-05d6-run877-current-custody-20261009.m'), inventory = path.join(native, 'inspector-app-05d6-inventory.h');
  const text = await readFile(inventory, 'utf8');
  if (!text.includes(MF) || !text.includes(RUN)) throw new Error('Fixed inspector identifiers differ.');
  for (const [name, sha] of Object.entries({ ...manifest.files, 'manifest.json': MF })) {
    if (!/^[a-zA-Z0-9_.-]+$/.test(name) && name !== 'fixtures/EnvaraRoutingAcceptanceFixture') throw new Error('Unexpected fixed leaf.');
    const mode = executableLeaves.has(name) ? '0755' : '0644';
    if (!text.includes(`{"${name}","${sha}",${mode}}`)) throw new Error(`Fixed inspector inventory differs: ${name}`);
  }
  const fixedInputs = ['app-scope-proof.c', 'app-scope-proof.h', 'pf-hook-abi.h', 'app-transport.c', 'app-transport.h', 'pf-production-filter.c'];
  for (const name of fixedInputs) if (await hash(path.join(native, name)) !== manifest.nativeSourceFiles[`native/macos-pf-routing/${name}`]) throw new Error(`Compiled dependency differs from the fixed 05d6 source: ${name}`);
  // Current application development may change unlinked files while this fixed
  // recovery targets the already installed 05d6 runtime. Only the compilation
  // graph and copied-rule reference inputs above must equal their frozen pins.
  // Record every other difference; do not call current workspace source 05d6.
  const currentSourceBindings = {}, unlinkedSourceDifferences = [];
  for (const [name, expected] of Object.entries(manifest.nativeSourceFiles)) {
    const current = await hash(path.join(root, name));
    currentSourceBindings[name] = { installedSHA256: expected, currentSHA256: current, matches: current === expected };
    if (current !== expected) unlinkedSourceDifferences.push({ name, installedSHA256: expected, currentSHA256: current, compiledOrIncludedByRecovery: false });
  }
  const actualReadonly = path.join(root,'test-artifacts/mac-pf-routing/05d6-run877-v2-readonly-actual-20261009T075044Z.json');
  const actualReadonlySHA = '255860bf3659568b2bdbffb3bf5c1a0e1cf6911b3ae6a89fe0b5594daeebf9dc';
  if (await hash(actualReadonly) !== actualReadonlySHA) throw new Error('Fixed actual v2 readonly receipt differs.');
  const actual = JSON.parse(await readFile(actualReadonly,'utf8')), observed=actual.result, custody=observed?.kernelCustodyObservation, journal=observed?.journal;
  if (actual.cleanupAttempted!==false || actual.sourceAndSignaturesVerified!==true || observed?.runId!==RUN || observed.environmentId!==ENV || observed.manifestSHA256!==MF || observed.inspectionReadOnly!==true || observed.PFWriteExecuted!==false || observed.ownedAppOrKeeperSignalExecuted!==false || observed.runtimeChanged!==false || observed.gidScopeObservation!==1 || observed.realmGID!==7100 || observed.registryObservation?.childRecorded!==false || observed.registryObservation.resumed!==false || observed.lastJournalRevisionAndCountMatchActiveFilter!==true) throw new Error('Actual v2 fixed scope differs.');
  if (custody.firstComplete!==true || custody.secondComplete!==true || custody.metadataStable!==true || custody.keeperIdentityStable!==true || custody.firstListenerCount!==1 || custody.secondListenerCount!==1 || custody.firstUTunCount!==2 || custody.secondUTunCount!==2 || custody.firstUTunObjectCount!==1 || custody.secondUTunObjectCount!==1 || custody.firstUTunDescriptorsAliasSameObject!==true || custody.secondUTunDescriptorsAliasSameObject!==true || custody.interfaceIndex!==42) throw new Error('Actual current same-object custody differs.');
  if (journal.present!==true || journal.pendingIntent!==false || journal.eventCount!==4 || journal.lastReceipt?.sequence!==1 || journal.lastReceipt.mode!==3 || journal.lastReceipt.writerPid!==15492 || journal.lastReceipt.revision!==2 || journal.lastReceipt.ruleCount!==5) throw new Error('Actual FRONT5 journal differs.');
  const expectedProcesses=[['controller',15418,15417,'1791528610:634784'],['keeper',15492,15418,'1791528613:535164'],['core',15525,15492,'1791528615:767053']];
  if (observed.recordedProcesses?.length!==3 || expectedProcesses.some(([role,pid,parent,birth],i)=>{const p=observed.recordedProcesses[i];return p.role!==role||p.pid!==pid||p.parentPid!==parent||p.recordedBirth!==birth||p.uid!==0||p.gid!==0||p.state!=='live-exact-recorded-identity'})) throw new Error('Actual current process scope differs.');
  if(observed.zombieFrontObservation?.state!=='exact-recorded-zombie'||observed.zombieFrontObservation.exitStatusAvailable!==true||observed.zombieFrontObservation.exitCode!==1||observed.zombieFrontObservation.signal!==0||observed.zombieFrontObservation.causeVerified!==false)throw new Error('Actual front zombie scope differs.');
  const inputFiles = [source,actualReadonly, path.join(native, 'inspector-app-05d6-run877-v2.m'), inventory, manifestFile, ...fixedInputs.map(n => path.join(native, n)), fileURLToPath(import.meta.url), path.join(root, 'tests/macos-pf-live-recovery-05d6-run877-current-custody-20261009.test.mjs')];
  const sourceInputs = {};
  for (const file of inputFiles) sourceInputs[path.relative(root, file)] = await hash(file);
  const unchanged = async () => { for (const [name, sha] of Object.entries(sourceInputs)) if (await hash(path.join(root, name)) !== sha) return false; return true; };
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-live-recovery-05d6-run877-current-custody-')));
  const app = path.join(directory, 'Envara Fixed Live Recovery Current Custody 05d6 Run877.app'), contents = path.join(app, 'Contents');
  await mkdir(path.join(contents, 'MacOS'), { recursive: true, mode: 0o700 });
  const binary = path.join(contents, 'MacOS/EnvaraPFLiveApplicationRecovery05D6Run877CurrentCustody');
  await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', source,
    path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
  if (!await unchanged()) throw new Error('Inspector source changed while compiling.');
  await writeFile(path.join(contents, 'Info.plist'), '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.envara.fixed-live-recovery-05d6-current-custody-877ab9cc</string><key>CFBundleExecutable</key><string>EnvaraPFLiveApplicationRecovery05D6Run877CurrentCustody</string><key>CFBundleName</key><string>Envara Fixed Live Recovery Current Custody 05d6 Run877</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>1</string><key>LSUIElement</key><true/></dict></plist>\n', { flag: 'wx', mode: 0o600 });
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
    actualReadonlyGrounding: {receipt:path.relative(root,actualReadonly),SHA256:actualReadonlySHA,scope:'partial fixed readonly facts; not a whole inspection success',
      fixedGID:7100,controllerPID:15418,keeperPID:15492,corePID:15525,frontPID:15545,frontZombieExitCode:1,
      currentUTunDescriptorCount:2,currentUTunSocketObjectCount:1,originalDescriptorCustodyVerified:false,creatorCredentialVerified:false,
      ownedFilterMode:3,ownedFilterRuleCount:5,ownedFilterRevision:2,ownedDenialVerified:false,freshFullRuleReadbackRequired:true},
    sourceGrounding: {productionFilterSHA256:manifest.nativeSourceFiles['native/macos-pf-routing/pf-production-filter.c'],
      appTransportSHA256:manifest.nativeSourceFiles['native/macos-pf-routing/app-transport.c'],
      currentSourceBindingsObserved:Object.keys(currentSourceBindings).length,
      currentSourceBindingsMatchingInstalled:Object.values(currentSourceBindings).filter(value=>value.matches).length,
      currentSourceBindings,unlinkedSourceDifferences,
      compiledAndReferenceInputsVerified:fixedInputs,
      frontBirth:'private immutable sealed run877 transport plus actual twice-bound kernel zombie, never signalled',
      coreTermination:'twice-bound SZOMB/SIGKILL is not external reap; actual ESRCH required after keeper exit'},
    installedRuntimeLeafCount: 19, sourceInputs, binarySHA256: await hash(binary), plan, refusals,
    authorizationRequested: false, rootExecuted: false, systemOperationExecuted: false, PFWriteExecuted: false,
    kernelCredentialGetter: { symbol: '_getgroups', darwinDirectoryExtensionImported: false },
    originalApplicationBaselineVerified: false, nativeInspectionExecuted: false, nativeRecoveryExecuted: false, cleanupConfirmed: false,
    ownedKeeperSignalExecuted: false, ownedFilterClearExecuted: false, rootHookDeleteExecuted: false,
    groupOperationExecuted: false, runtimeArchiveExecuted: false,
    actualDescriptorCustodyAccepted: false, actualRecoveryAcceptance: false,
    requiredBeforeAuthorization: ['fresh-fixed-run-native-current-custody-and-FRONT5-inspection', 'root-reviewed-exact-core-termination-and-post-EMPTY-KILL-scope', 'independent-source-review'],
    authorizationEntryIncluded: false, userPresenceRequiredForFutureAuthorization: true,
    installedCandidateChanged: false, productionReady: false };
  await writeFile(path.join(directory, 'live-recovery-build.json'), JSON.stringify(proof, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return proof;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) { console.error('This inert recovery builder accepts no operation, path, UUID or authorization arguments.'); process.exitCode = 1; }
  else { try { console.log(JSON.stringify(await buildFixedLiveRecovery05D6Run877CurrentCustody(), null, 2)); }
    catch (error) { console.error(error.message); process.exitCode = 1; } }
}
