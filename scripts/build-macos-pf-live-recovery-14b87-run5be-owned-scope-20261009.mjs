// Independent fixed 14b87/run5be owned-session recovery source candidate.
// Running this inert builder performs only own-temp compile/sign/plan/nonroot
// refusal checks. It never requests Authorization or performs root recovery.
// The historical partial inspection below does not prove current custody or
// configuration-only private state; both require a fresh native preflight.
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
const MF = '14b87d3452af4acaf67709c2494d637163d108a101f6d07fb27ce8e61c2d1d50';
const RUN = '5be11012-0c9e-456c-84b9-9e311df4cbdd', ENV = '5a50dcef-3314-4195-8ba5-c94ca6a0bef0';
const RECOVERY_SCHEMA = 'envara.macos-pf-owned-session-recovery/v1';
const executableLeaves = new Set(['node', 'mihomo', 'envara-pf-native', 'EnvaraPFHelper', 'fixtures/EnvaraRoutingAcceptanceFixture']);
const falseFactKeys = ['cleanupConfirmed', 'originalApplicationHostBaselineVerified', 'hostComparisonAvailable', 'hostSnapshotsMatched',
  'ready', 'protected', 'productionReady', 'fullGuardFailureAccepted', 'ownedGIDScopeAbsent', 'ownedDenialVerified', 'ownedFrontVerified',
  'originalDescriptorCustodyVerified', 'uniqueCurrentKeeperCustodyVerified', 'controllerStopped', 'keeperStopped', 'ownedFilterClearAttempted',
  'ownedFilterEmptyVerified', 'keeperExitObserved', 'controllerExitObserved', 'ownedInterfaceAbsent', 'ownedListenerAbsent',
  'ownedPFReferenceReleaseAttempted', 'ownedPFReferenceReleased', 'rootHookDeleteAttempted', 'rootHookRemoved', 'originalRootRestored',
  'receiptRetired', 'namespaceReclaimed', 'ownedGroupDeleteAttempted', 'ownedGroupRemoved', 'runtimeArchived', 'recoveryScopeHostNetworkRestored',
  'coreStopped', 'coreTerminateAttempted', 'coreTerminatedObserved', 'coreReapedByRecovery', 'frontZombieBound', 'coreFinalAbsent', 'frontFinalAbsent',
  'currentUTunAliasCustodyVerified', 'globalFlushExecuted', 'PFEnableExecuted', 'globalPoolResetExecuted', 'applicationLaunchExecuted'];
const outcomeKeys = ['schema', 'manifestSHA256', 'runId', 'environmentId', 'readOnly', 'ok', 'reason', 'gate', 'cleanupUncertain', 'cleanupScope', ...falseFactKeys];
function fixedInertOutcome(value, { plan = false, readOnly = true } = {}) {
  const expected = [...outcomeKeys, ...(plan ? ['mutationEntryLinked', 'nativeStatusRequiredAfterCustodianExit'] : [])];
  return outcomeKeys.length === 54 && value && !Array.isArray(value) && Object.keys(value).sort().join('|') === expected.sort().join('|') &&
    value.schema === RECOVERY_SCHEMA && value.manifestSHA256 === MF && value.runId === RUN && value.environmentId === ENV &&
    value.cleanupScope === 'owned-current-session' && value.readOnly === readOnly && value.ok === plan && value.cleanupUncertain === true &&
    value.gate === 'not-started' && falseFactKeys.every(key => value[key] === false) &&
    value.reason === (plan ? 'INERT_FIXED_LIVE_RECOVERY_PLAN' : 'FIXED_LIVE_RECOVERY_PREFLIGHT_REFUSED') &&
    (!plan || value.mutationEntryLinked === true && value.nativeStatusRequiredAfterCustodianExit === true);
}
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
export async function buildFixedLiveRecovery14B87Run5beOwnedScope() {
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || process.getuid() === 0) throw new Error('This inert builder requires the unprivileged reviewed Darwin arm64 host.');
  const manifestFile = path.join(native, 'inspector-app-14b87-manifest.json');
  if (await hash(manifestFile) !== MF) throw new Error('Fixed 14b87 manifest copy differs.');
  const manifest = JSON.parse(await readFile(manifestFile, 'utf8'));
  if (manifest.schema !== 'envara.macos-pf-installation/v1' || manifest.backend !== 'pf-utun' ||
      Object.keys(manifest.files ?? {}).length !== 18 || Object.keys(manifest.nativeSourceFiles ?? {}).length !== 71) throw new Error('Fixed inventory is not the 18-leaf, 71-source application candidate.');
  const source = path.join(native, 'recovery-app-14b87-run5be-owned-scope-20261009.m'), inventory = path.join(native, 'inspector-app-14b87-inventory.h');
  const text = await readFile(inventory, 'utf8');
  if (!text.includes(MF) || !text.includes(RUN)) throw new Error('Fixed inspector identifiers differ.');
  for (const [name, sha] of Object.entries({ ...manifest.files, 'manifest.json': MF })) {
    if (!/^[a-zA-Z0-9_.-]+$/.test(name) && name !== 'fixtures/EnvaraRoutingAcceptanceFixture') throw new Error('Unexpected fixed leaf.');
    const mode = executableLeaves.has(name) ? '0755' : '0644';
    if (!text.includes(`{"${name}","${sha}",${mode}}`)) throw new Error(`Fixed inspector inventory differs: ${name}`);
  }
  const fixedInputs = ['app-scope-proof.c', 'app-scope-proof.h', 'pf-hook-abi.h', 'app-transport.c', 'app-transport.h', 'pf-production-filter.c'];
  for (const name of fixedInputs) if (await hash(path.join(native, name)) !== manifest.nativeSourceFiles[`native/macos-pf-routing/${name}`]) throw new Error(`Compiled dependency differs from the fixed 14b87 source: ${name}`);
  // Only the compilation graph and copied-rule reference inputs must equal the
  // installed pins. Record all 71 current source bindings and every unlinked
  // difference; never describe current workspace source as the installed build.
  const currentSourceBindings = {}, unlinkedSourceDifferences = [];
  for (const [name, expected] of Object.entries(manifest.nativeSourceFiles)) {
    const current = await hash(path.join(root, name));
    currentSourceBindings[name] = { installedSHA256: expected, currentSHA256: current, matches: current === expected };
    if (current !== expected) unlinkedSourceDifferences.push({ name, installedSHA256: expected, currentSHA256: current, compiledOrIncludedByRecovery: false });
  }
  const actualReadonly = path.join(root, 'test-artifacts/mac-pf-routing/14b87-run5be-readonly-actual-20261009T092123Z.json');
  const actualReadonlySHA = 'de1f82d89784168cdb5fc532ae94667fc6486eb7270b753e75ca0a748cd9e301';
  if (await hash(actualReadonly) !== actualReadonlySHA) throw new Error('Fixed actual run5be partial inspection receipt differs.');
  const actual = JSON.parse(await readFile(actualReadonly, 'utf8')), observed = actual.result, custody = observed?.kernelCustodyObservation, journal = observed?.journal;
  // This historical wrapper performed an authorized installation stage. Only
  // its inspector is read-only; the receipt is not a whole read-only success.
  if (actual.schema !== 'envara.actual-owned-session-readonly-authorization/v1' || actual.operation !== '--request-install-and-readonly' || actual.exitCode !== 1 ||
      observed?.runId !== RUN || observed.environmentId !== ENV || observed.manifestSHA256 !== MF || observed.inspectionReadOnly !== true ||
      observed.overallReadOnly !== false || observed.rootStageAttempted !== true || observed.rootStageCompleted !== true ||
      observed.ok !== false || observed.reason !== 'INSPECTION_UNCONFIRMED' || observed.cleanupPermitted !== false || observed.cleanupConfirmed !== false || observed.cleanupUncertain !== true ||
      observed.PFWriteExecuted !== false || observed.ownedAppOrKeeperSignalExecuted !== false || observed.runtimeChanged !== false ||
      observed.gidScopeObservation !== 1 || observed.realmGID !== 7100 || observed.registryObservation?.childRecorded !== false ||
      observed.registryObservation.resumed !== false || observed.registryObservation.transportRecorded !== true || observed.lastJournalRevisionAndCountMatchActiveFilter !== true) throw new Error('Actual fixed partial inspection scope differs.');
  if (!custody || custody.firstComplete !== true || custody.secondComplete !== true || custody.metadataStable !== true || custody.keeperIdentityStable !== true ||
      custody.firstListenerCount !== 1 || custody.secondListenerCount !== 1 || custody.firstUTunCount !== 2 || custody.secondUTunCount !== 2 ||
      custody.firstUTunObjectCount !== 1 || custody.secondUTunObjectCount !== 1 || custody.firstUTunDescriptorsAliasSameObject !== true ||
      custody.secondUTunDescriptorsAliasSameObject !== true || custody.interfaceIndex !== 42 || custody.originalDescriptorCustodyVerified !== false ||
      custody.creatorCredentialVerified !== false) throw new Error('Actual current same-object custody differs.');
  if (!journal || journal.present !== true || journal.pendingIntent !== false || journal.eventCount !== 4 || journal.lastReceipt?.sequence !== 1 ||
      journal.lastReceipt.mode !== 3 || journal.lastReceipt.writerPid !== 48779 || journal.lastReceipt.revision !== 2 || journal.lastReceipt.ruleCount !== 5 ||
      journal.inventorySHA256 !== 'ac40f3ac24e2588b9451d3a09af36e568a1e5043137cfd40ded542a5220d48e5' ||
      journal.eventBytesSHA256 !== 'dfd387040f5c0d4a954631bcd6b7d15b80fb62d4e21fdf3ea4ab1d5cfa9d0861') throw new Error('Actual FRONT5 journal differs.');
  const expectedProcesses = [['controller', 48707, 48706, '1791536844:980868'], ['keeper', 48779, 48707, '1791536847:878082'], ['core', 48782, 48779, '1791536849:738732']];
  if (observed.recordedProcesses?.length !== 3 || expectedProcesses.some(([role, pid, parent, birth], i) => {
    const p = observed.recordedProcesses[i]; return p.role !== role || p.pid !== pid || p.parentPid !== parent || p.recordedBirth !== birth || p.uid !== 0 || p.gid !== 0 || p.state !== 'live-exact-recorded-identity';
  })) throw new Error('Actual current process scope differs.');
  if (observed.zombieFrontObservation?.state !== 'exact-recorded-zombie' || observed.zombieFrontObservation.exitStatusAvailable !== true ||
      observed.zombieFrontObservation.exitCode !== 1 || observed.zombieFrontObservation.signal !== 0 || observed.zombieFrontObservation.causeVerified !== false) throw new Error('Actual front zombie scope differs.');
  const inputFiles = [source, actualReadonly, path.join(native, 'inspector-app-14b87-run5be.m'), inventory, manifestFile,
    ...fixedInputs.map(n => path.join(native, n)), fileURLToPath(import.meta.url), path.join(root, 'tests/macos-pf-live-recovery-14b87-run5be-owned-scope-20261009.test.mjs')];
  const sourceInputs = {};
  for (const file of inputFiles) sourceInputs[path.relative(root, file)] = await hash(file);
  const unchanged = async () => { for (const [name, sha] of Object.entries(sourceInputs)) if (await hash(path.join(root, name)) !== sha) return false; return true; };
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-live-recovery-14b87-run5be-owned-scope-')));
  const app = path.join(directory, 'Envara Fixed Owned Session Recovery 14b87 Run5be.app'), contents = path.join(app, 'Contents');
  await mkdir(path.join(contents, 'MacOS'), { recursive: true, mode: 0o700 });
  const binary = path.join(contents, 'MacOS/EnvaraPFOwnedSessionRecovery14B87Run5be');
  await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', source,
    path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
  if (!await unchanged()) throw new Error('Recovery source changed while compiling.');
  await writeFile(path.join(contents, 'Info.plist'), '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.envara.fixed-owned-session-recovery-14b87-5be11012</string><key>CFBundleExecutable</key><string>EnvaraPFOwnedSessionRecovery14B87Run5be</string><key>CFBundleName</key><string>Envara Fixed Owned Session Recovery 14b87 Run5be</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>1</string><key>LSUIElement</key><true/></dict></plist>\n', { flag: 'wx', mode: 0o600 });
  await exec('/usr/bin/codesign', ['--force', '--sign', '-', app], { timeout: 15000 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', app], { timeout: 15000 });
  const imports = (await exec('/usr/bin/nm', ['-u', binary], { timeout: 10000 })).stdout;
  if (!/(?:^|\n)_getgroups(?:\n|$)/.test(imports) || imports.includes('_getgroups$DARWIN_EXTSN')) throw new Error('Recovery did not bind the legacy kernel credential getter.');
  const plan = JSON.parse((await exec(binary, ['--plan'], { timeout: 10000 })).stdout);
  if (!fixedInertOutcome(plan, { plan: true })) throw new Error('Recovery plan is not the fixed 54-fact owned-session inert candidate.');
  const refusals = [];
  for (const operation of ['--inspect-fixed-root', '--cleanup-fixed-root', '--request-readonly-existing-rights']) {
    let stdout;
    try { await exec(binary, [operation], { timeout: 10000 }); throw new Error('Nonroot or unknown recovery operation unexpectedly succeeded.'); }
    catch (error) { if (error.code !== 1) throw error; stdout = error.stdout; }
    const refusal = JSON.parse(stdout);
    if (!fixedInertOutcome(refusal, { readOnly: operation !== '--cleanup-fixed-root' })) throw new Error('Recovery nonroot refusal attempted an operation or changed its fixed outcome facts.');
    refusals.push({ operation, refusal });
  }
  if (!await unchanged()) throw new Error('Recovery source changed before final proof.');
  const proof = { schema: 'envara.macos-pf-owned-session-recovery-build/v1', directory, app, binary,
    fixedManifestSHA256: MF, fixedNativeSHA256: manifest.files['envara-pf-native'], fixedRunId: RUN, fixedEnvironmentId: ENV,
    cleanupScope: 'owned-current-session', hostComparisonAvailable: false, hostSnapshotsMatched: false,
    actualReadonlyGrounding: { receipt: path.relative(root, actualReadonly), SHA256: actualReadonlySHA,
      scope: 'partial historical inspector facts within install-and-readonly authorization; not a whole inspection success',
      historicalWrapperOverallReadOnly: false, historicalInstallationStageCompleted: true, inspectionReadOnly: true,
      fixedGID: 7100, controllerPID: 48707, keeperPID: 48779, corePID: 48782, frontPID: 48784, frontZombieExitCode: 1,
      frontPIDBinding: 'fixed session candidate; fresh private transport binding required',
      currentUTunDescriptorCount: 2, currentUTunSocketObjectCount: 1, interfaceIndex: 42,
      originalDescriptorCustodyVerified: false, creatorCredentialVerified: false,
      ownedFilterMode: 3, ownedFilterRuleCount: 5, ownedFilterRevision: 2, ownedDenialVerified: false, freshFullRuleReadbackRequired: true },
    privateStateGrounding: { observed: false, receipt: null, SHA256: null, configurationOnlyObserved: false,
      exactStateLeavesRequired: ['transport-config.json'], cacheAbsenceRequired: true, rootUIDRequired: 0, rootGIDRequired: 0,
      modeRequired: '0600', singleLinkRequired: true, freshConfigurationOnlyHeldMetadataProofRequired: true,
      freshHeldFileBytesAndDirectoryIdentityRequired: true, wholePrivateRuntimeArchiveRequired: true, leafDeletionExecuted: false },
    sourceGrounding: { productionFilterSHA256: manifest.nativeSourceFiles['native/macos-pf-routing/pf-production-filter.c'],
      appTransportSHA256: manifest.nativeSourceFiles['native/macos-pf-routing/app-transport.c'],
      currentSourceBindingsObserved: Object.keys(currentSourceBindings).length,
      currentSourceBindingsMatchingInstalled: Object.values(currentSourceBindings).filter(value => value.matches).length,
      currentSourceBindings, unlinkedSourceDifferences, compiledAndReferenceInputsVerified: fixedInputs,
      frontBirth: 'private immutable sealed run5be transport plus actual twice-bound kernel zombie; never signalled',
      coreTermination: 'twice-bound SZOMB/SIGKILL is not external reap; actual ESRCH required after keeper exit' },
    installedRuntimeLeafCount: 19, sourceInputs, binarySHA256: await hash(binary), plan, refusals,
    authorizationRequested: false, rootExecuted: false, systemOperationExecuted: false, PFWriteExecuted: false,
    kernelCredentialGetter: { symbol: '_getgroups', darwinDirectoryExtensionImported: false },
    originalApplicationBaselineVerified: false, nativeInspectionExecuted: false, nativeRecoveryExecuted: false, cleanupConfirmed: false,
    ownedKeeperSignalExecuted: false, ownedFilterClearExecuted: false, rootHookDeleteExecuted: false,
    groupOperationExecuted: false, runtimeArchiveExecuted: false,
    actualDescriptorCustodyAccepted: false, actualRecoveryAcceptance: false,
    requiredBeforeAuthorization: ['fresh-fixed-run-native-current-custody-and-FRONT5-inspection',
      'root-reviewed-exact-core-termination-and-post-EMPTY-KILL-scope', 'fresh-exact-configuration-only-private-state-held-metadata-and-bytes-proof', 'independent-source-review'],
    authorizationEntryIncluded: false, userPresenceRequiredForFutureAuthorization: true,
    installedCandidateChanged: false, productionReady: false };
  await writeFile(path.join(directory, 'owned-session-recovery-14b87-run5be-build.json'), JSON.stringify(proof, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return proof;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) { console.error('This inert recovery builder accepts no operation, path, UUID or authorization arguments.'); process.exitCode = 1; }
  else { try { console.log(JSON.stringify(await buildFixedLiveRecovery14B87Run5beOwnedScope(), null, 2)); }
    catch (error) { console.error(error.message); process.exitCode = 1; } }
}
