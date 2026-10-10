// Fixed run877 build recipe, intentionally blocked before actual readonly facts.
// This file never runs an authorization, system command, compiler or recovery.
// A final source must be frozen under a new name after independent review;
// removing a draft guard in place is not this recipe's build workflow.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { readFile, open } from 'node:fs/promises';
import { constants } from 'node:fs';

const root = path.resolve(import.meta.dirname, '..');
const native = path.join(root, 'native/macos-pf-routing');
const MF = '05d6eb6ab3d63870d37825b47e2847789a6b5b8c3cf93c434636e0b8aad4f061';
const RUN = '877ab9cc-ed91-4f2d-a8cd-86cedc2f3e21';
const ENV = '72826f65-99c0-446c-a9c3-b825b36ad1a5';
const source = path.join(native, 'recovery-app-05d6-run877-draft-20261009.m');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

async function hash(file) {
  const fd = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await fd.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > 1024n * 1024n * 1024n) throw new Error('Fixed input is not a bounded single-link file.');
    const bytes = await fd.readFile();
    const after = await fd.stat({ bigint: true });
    if (BigInt(bytes.length) !== before.size || ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].some(k => before[k] !== after[k])) throw new Error('Fixed input changed while reading.');
    return digest(bytes);
  } finally { await fd.close(); }
}

export async function inspectFixedRun877Draft() {
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || process.getuid() === 0) throw new Error('The fixed draft recipe requires the unprivileged Darwin arm64 host.');
  const manifestFile = path.join(native, 'inspector-app-05d6-manifest.json');
  if (await hash(manifestFile) !== MF) throw new Error('Fixed 05d6 manifest copy differs.');
  const manifest = JSON.parse(await readFile(manifestFile, 'utf8'));
  if (manifest.schema !== 'envara.macos-pf-installation/v1' || manifest.backend !== 'pf-utun' || Object.keys(manifest.files ?? {}).length !== 18 || Object.keys(manifest.nativeSourceFiles ?? {}).length !== 69) throw new Error('Fixed 05d6 manifest shape differs.');
  const inventoryFile = path.join(native, 'inspector-app-05d6-inventory.h');
  const inventory = await readFile(inventoryFile, 'utf8');
  const inspectorFile = path.join(native, 'inspector-app-05d6-run877.m');
  const inspector = await readFile(inspectorFile, 'utf8');
  if (!inventory.includes(MF) || !inventory.includes(RUN) || !inspector.includes(`#define FIXED_ENV @"${ENV}"`)) throw new Error('Fixed run877 inventory identifiers differ.');
  const executableLeaves = new Set(['node', 'mihomo', 'envara-pf-native', 'EnvaraPFHelper', 'fixtures/EnvaraRoutingAcceptanceFixture']);
  for (const [name, sha] of Object.entries({ ...manifest.files, 'manifest.json': MF })) {
    if (!/^[a-zA-Z0-9_.-]+$/.test(name) && name !== 'fixtures/EnvaraRoutingAcceptanceFixture') throw new Error('Unexpected fixed installed leaf.');
    if (!inventory.includes(`{"${name}","${sha}",${executableLeaves.has(name) ? '0755' : '0644'}}`)) throw new Error(`Fixed inventory differs: ${name}`);
  }
  const sourceBindings = {};
  for (const [name, expected] of Object.entries(manifest.nativeSourceFiles)) {
    if (!/^(?:native\/macos-pf-routing|electron|scripts|tests)\/[A-Za-z0-9_./-]+$/.test(name) || name.split('/').includes('..')) throw new Error('Unexpected fixed source binding.');
    const actual = await hash(path.join(root, name));
    if (actual !== expected) throw new Error(`Current source differs from installed 05d6: ${name}`);
    sourceBindings[name] = actual;
  }
  const bytes = await readFile(source);
  const text = bytes.toString('utf8');
  if (!text.includes('#error RUN877_RECOVERY_DRAFT_REQUIRES_ACTUAL_READONLY_FACTS_AND_CHILD_SCOPE_REVIEW') || !text.includes('#define R877_FIXED_GID 0') || !text.includes('RO_REQUIRED_CONTROLLER_BIRTH') || !text.includes('RO_REQUIRED_KEEPER_BIRTH')) throw new Error('Fixed draft compilation refusal was changed.');
  if (!text.includes('#include "inspector-app-05d6-run877.m"') || /7600[78]|76082|76086|76088|14514ea6-7f9c-4cdc/.test(text)) throw new Error('Draft still contains prior-run executable bindings.');
  const inputs = [source, inventoryFile, manifestFile, path.join(native, 'inspector-app-05d6-run877.m'), fileURLToPath(import.meta.url)];
  const sourceInputs = {};
  for (const file of inputs) sourceInputs[path.relative(root, file)] = await hash(file);
  return {
    schema: 'envara.macos-pf-fixed-recovery-draft/v1', fixedManifestSHA256: MF,
    fixedNativeSHA256: manifest.files['envara-pf-native'], fixedRunId: RUN, fixedEnvironmentId: ENV,
    controllerPID: 15418, controllerParentPID: 15417, keeperPID: 15492, corePID: 15525, frontPID: 15545,
    sourceInputs, installedSourceBindingsVerified: Object.keys(sourceBindings).length,
    compilationBlocked: true, executableProduced: false, authorizationEntryIncluded: false,
    actualReadonlyFactsAccepted: false, currentLiveChildrenHandled: false,
    blockers: ['actual-run877-readonly-receipt-not-yet-frozen', 'exact-controller-keeper-core-front-birth-and-gid-required',
      'current-live-core-and-zombie-front-need-separate-reviewed-lifecycle', 'fresh-denial-custody-hook-reference-and-original-root-proof-required'],
    frozenFinalRecipe: { architecture: 'arm64', compiler: '/usr/bin/clang',
      flags: ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function'],
      additionalSource: 'native/macos-pf-routing/app-scope-proof.c', frameworks: ['Foundation', 'Security'],
      mustReverifyAllInputsBeforeAndAfterCompilation: true, mustUseNewFinalSourceName: true,
      mustCheckStrictCodeSignatureAndLegacyGetgroupsImport: true,
      requiredInertChecks: ['inert-plan-only', 'nonroot-refusal', 'DENY-native-constructor-parity', 'one-FILTER-no-retry-fault-cases', 'current-child-identity-negative-cases'] },
    readOnly: true, cleanupConfirmed: false, cleanupUncertain: true,
    ready: false, protected: false, productionReady: false, rootExecuted: false,
    systemOperationExecuted: false, PFWriteExecuted: false, ownedSignalExecuted: false,
    groupOperationExecuted: false, runtimeArchiveExecuted: false, installedCandidateChanged: false,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) { console.error('This fixed draft recipe accepts no paths, UUIDs or operation arguments.'); process.exitCode = 1; }
  else { try { console.log(JSON.stringify(await inspectFixedRun877Draft(), null, 2)); }
    catch (error) { console.error(error.message); process.exitCode = 1; } }
}
