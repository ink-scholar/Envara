import path from 'node:path';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { constants as fsConstants, createReadStream } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createPFRoutingPolicy, createStatelessFixturePFRoutingPolicy, PF_ROUTING_NAMESPACE, isPFRoutingRunId, pfRoutingAnchor, PF_ROUTING_GATES } from './policy.mjs';
import { verifyStatelessFixtureRuleReadback, expectedStatelessFixtureRuleSemantics } from './stateless-verifier.mjs';

export const PF_HELPER_PROTOCOL = 'envara.application-routing';
export const PF_HELPER_VERSION = 1;
export const PF_INSTALL_ROOT = '/Library/PrivilegedHelperTools/io.envara.pf-routing';
export const PF_RUNTIME_ROOT = '/Library/PrivilegedHelperTools/io.envara.pf-runtime';
export const PF_LEGACY_RUNTIME_ROOT = '/var/run/envara-pf-routing';
export const PF_INSTALLATION_SCHEMA = 'envara.macos-pf-installation/v1';
export const PF_ROOT_HOOK_SCHEMA = 'envara.macos-pf-owned-root-hook/v2';
export const PF_ROOT_HOOK_LEASE_SCHEMA = 'envara.macos-pf-owned-root-hook-lease/v2';
export const PF_FILTER_REPLACEMENT_SCHEMA = 'envara.macos-pf-filter-replacement/v1';
export const PF_APP_BOUND_LEASE_SCHEMA = 'envara.macos-pf-app-bound-lease/v1';
const PF_APP_CONTEXT_CLOCK_SCHEMA = 'envara.macos-pf-app-context-clock/v1';
const PF_APP_TRANSPORT_SCHEMA = 'envara.macos-pf-app-transport/v1';
const PF_APP_KEEPER_SCHEMA = 'envara.pf-app-keeper/v1';
const APP_KEEPER_RESUME_NEGATIVE_EVENTS = new Set(['stopping', 'released', 'release-refused']);
const APP_KEEPER_REPORT_BOOLEANS = ['persistentDenyObserved', 'stoppedBeforeExec', 'childReaped', 'scopeQuiescentObserved',
  'resumeSent', 'resumed', 'cancelSent', 'executedIdentityVerified', 'seatbeltAppliedByFixedExec', 'frontAdmissionVerified', 'ready', 'protected'];
const APP_KEEPER_REPORT_KEYS = ['schema', 'event', 'ticketId', 'registrationId', 'versionId', 'environmentId', 'runId',
  'pid', 'birth', 'keeperPID', 'profile', ...APP_KEEPER_REPORT_BOOLEANS].sort().join('|');
// Cold staging repeatedly verifies both signed bundles before adopting a
// stopped child. Its bounded wait must cover that work, rather than treating
// it like a small control ACK and revoking a healthy, still-preparing keeper.
export const PF_APP_COLD_STAGE_TIMEOUT_MS = 60000;
// Resume revalidates the signed application before SIGCONT, then verifies the
// executed identity. Give that whole native operation its own bounded wait;
// the desktop client additionally reserves time for stop/snapshot/close.
export const PF_APP_RESUME_TIMEOUT_MS = 45000;
const NOTION_BUNDLE = '/Applications/Notion.app';
const APP_NATIVE_STAGES = new Set(['register', 'preflight', 'gui-session', 'route-read', 'transport-start', 'front-listen', 'front-spawn', 'front-handshake',
  'factory-open', 'deny-commit', 'transport-ack', 'front-commit', 'front-admission', 'ticket-prepare', 'relay-fork', 'guardian']);
const APP_ACTIVE_NATIVE_FAILURE_STAGES = new Set(['front-commit', 'front-admission', 'ticket-prepare', 'relay-fork', 'guardian']);
const APP_FAILURE_STAGES = new Set(['register', 'registry-lock', 'root-hook', 'group-allocation', 'sealed-context', 'pf-reference', 'transport', 'cold-stage', 'resume', 'cleanup']);
const APP_RELEASE_FACTS = Object.freeze(['coreReaped', 'frontReaped', 'childReaped', 'scopeQuiescentObserved', 'originalUTunClosed', 'originalListenerClosed', 'filterEmptyVerified', 'privateJournalRetired']);
const appReleasedFactsVerified = value => APP_RELEASE_FACTS.filter(key => key !== 'childReaped').every(key => value?.[key] === true) &&
  typeof value?.childReaped === 'boolean' && typeof value?.childAbsent === 'boolean' && value.childReaped !== value.childAbsent;
const APP_REGISTER_FAILURE_REASONS = new Set(['INVALID_NATIVE_APP_REQUEST', 'FIXED_ROOT_NATIVE_ENTRY_REQUIRED', 'APP_REGISTRY_UNAVAILABLE', 'NATIVE_APP_OPERATION_REFUSED']);
const APP_NATIVE_FAILURE_REASONS = new Set(['NATIVE_OPERATION_REFUSED', 'NATIVE_CONTEXT_LOAD_REFUSED', 'NATIVE_CONTROLLER_BINDING_REFUSED',
  'NATIVE_ORIGINAL_SOCKET_REFUSED', 'NATIVE_LISTENER_CREDENTIAL_REFUSED', 'NATIVE_PIPE_BINDING_REFUSED', 'NATIVE_GUI_SESSION_REFUSED',
  'NATIVE_APP_IDENTITY_REFUSED', 'NATIVE_HOOK_LEASE_REFUSED', 'NATIVE_PF_OPEN_REFUSED', 'NATIVE_PF_GUARD_REFUSED',
  'NATIVE_FILTER_READBACK_REFUSED', 'NATIVE_FILTER_TRANSACTION_REFUSED', 'NATIVE_JOURNAL_REFUSED', 'NATIVE_TICKET_BINDING_REFUSED',
  'NATIVE_TICKET_FILTER_REFUSED', 'NATIVE_SCOPE_CHECK_REFUSED', 'NATIVE_GUARD_DESCRIPTOR_REFUSED', 'NATIVE_LEASE_EXPIRED_REFUSED',
  'NATIVE_NOTION_DATA_PREPARE_REFUSED', 'NATIVE_NOTION_STAGE_REFUSED']);
const validAppNativeFailure = value => value && Object.keys(value).sort().join('|') === 'error|reason|stage' && APP_NATIVE_STAGES.has(value.stage) &&
  (value.stage === 'register' ? APP_REGISTER_FAILURE_REASONS.has(value.reason) : APP_NATIVE_FAILURE_REASONS.has(value.reason)) &&
  Number.isInteger(value.error) && value.error > 0 && value.error <= 1024;
const nativeBirth = value => typeof value === 'string' && /^[1-9][0-9]{0,19}:[0-9]{6}$/.test(value);
const appFlags = () => ({ ready: false, protected: false, productionReady: false, profile: 'seatbelt-front-only', genericApplicationRouting: false, udpSupported: false });
const APP_ABORT_FACTS = Object.freeze(['originalUTunVerified', 'originalListenerVerified', 'coreReaped', 'frontReaped', 'gidScopeAbsent',
  'filterJournalAbsent', 'originalUTunClosed', 'originalListenerClosed']);
const APP_ABORT_FALSE = Object.freeze(['denyAttempted', 'filterWriteAttempted', 'launchCommandAccepted', 'coldStageAttempted', 'ready', 'protected']);
const APP_ABORT_KEYS = Object.freeze(['schema', 'event', 'stage', 'runId', 'environmentId', 'realmId', 'gid', 'leaseSHA256',
  'controllerPID', 'controllerBirth', 'keeperPID', 'keeperBirth', 'keeperParentPID', 'keeperParentBirth', 'corePID', 'coreBirth', 'frontPID', 'frontBirth',
  'leaseDevice', 'leaseInode', 'runDirectoryDevice', 'runDirectoryInode', 'utunName', 'utunDevice', 'utunInode', 'utunControlId', 'utunControlUnit',
  'listenerHost', 'listenerPort', 'listenerDevice', 'listenerInode', 'exitStatus', ...APP_ABORT_FACTS, ...APP_ABORT_FALSE]);
const APP_PREFLIGHT_ABORT_FACTS = Object.freeze(['sealedContextVerified', 'privateChildrenAbsent', 'gidScopeAbsent', 'filterJournalAbsent', 'ownedFilterClassesEmpty']);
const APP_PREFLIGHT_ABORT_FALSE = Object.freeze(['bootstrapAttempted', 'transportAttempted', 'filterWriteAttempted', 'coldStageAttempted', 'ready', 'protected']);
const APP_PREFLIGHT_ABORT_KEYS = Object.freeze(['schema', 'event', 'stage', 'runId', 'environmentId', 'realmId', 'gid', 'leaseSHA256',
  'controllerPID', 'controllerBirth', 'bootstrapPID', 'bootstrapBirth', 'bootstrapParentPID', 'bootstrapParentBirth', 'proofNonce',
  'leaseDevice', 'leaseInode', 'runDirectoryDevice', 'runDirectoryInode', 'bootstrapDevice', 'bootstrapInode', 'bootstrapParentDevice', 'bootstrapParentInode',
  'exitStatus', ...APP_PREFLIGHT_ABORT_FACTS, ...APP_PREFLIGHT_ABORT_FALSE]);
const uint64String = value => typeof value === 'string' && /^(?:0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= 18446744073709551615n;
const appCleanPhase = phase => ['cleaned', 'prestage-cleaned', 'preflight-cleaned'].includes(phase);
export function validatePFApplicationPreflightAbort(value, binding, childPID, bootstrap = null) {
  if (!value || Array.isArray(value) || Object.keys(value).sort().join('|') !== [...APP_PREFLIGHT_ABORT_KEYS].sort().join('|') ||
      value.schema !== PF_APP_TRANSPORT_SCHEMA || value.event !== 'preflight-aborted' || value.stage !== 'preflight' || value.exitStatus !== 1 ||
      APP_PREFLIGHT_ABORT_FACTS.some(key => value[key] !== true) || APP_PREFLIGHT_ABORT_FALSE.some(key => value[key] !== false) ||
      ['runId', 'environmentId', 'realmId', 'gid', 'leaseSHA256', 'controllerPID', 'controllerBirth', 'leaseDevice', 'leaseInode', 'runDirectoryDevice', 'runDirectoryInode']
        .some(key => value[key] !== binding?.[key]) || !/^[0-9a-f]{32}$/.test(value.proofNonce ?? '') ||
      ['leaseDevice', 'leaseInode', 'runDirectoryDevice', 'runDirectoryInode', 'bootstrapDevice', 'bootstrapInode', 'bootstrapParentDevice', 'bootstrapParentInode'].some(key => !uint64String(value[key])) ||
      !Number.isSafeInteger(childPID) || childPID < 2 || value.bootstrapPID !== childPID || value.bootstrapPID === binding?.controllerPID ||
      value.bootstrapParentPID !== binding?.controllerPID || value.bootstrapParentBirth !== binding?.controllerBirth || !nativeBirth(value.bootstrapBirth) ||
      bootstrap && (bootstrap.pid !== childPID || bootstrap.path !== `${PF_INSTALL_ROOT}/envara-pf-native` || bootstrap.parentPid !== binding.controllerPID ||
        bootstrap.birth !== value.bootstrapBirth || [bootstrap.uid, bootstrap.realUID, bootstrap.savedUID].some(uid => uid !== 0))) throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED');
  return Object.freeze(structuredClone(value));
}
export function validatePFApplicationPrestageAbort(value, binding, bootstrap) {
  if (!value || Array.isArray(value) || Object.keys(value).sort().join('|') !== [...APP_ABORT_KEYS].sort().join('|') ||
      value.schema !== PF_APP_TRANSPORT_SCHEMA || value.event !== 'prestage-aborted' || value.stage !== 'factory-open' || value.exitStatus !== 1 ||
      APP_ABORT_FACTS.some(key => value[key] !== true) || APP_ABORT_FALSE.some(key => value[key] !== false) ||
      ['runId', 'environmentId', 'realmId', 'gid', 'leaseSHA256', 'controllerPID', 'controllerBirth', 'leaseDevice', 'leaseInode', 'runDirectoryDevice', 'runDirectoryInode']
        .some(key => value[key] !== binding[key]) || !/^utun[0-9]{1,7}$/.test(value.utunName ?? '') ||
      ['leaseDevice', 'leaseInode', 'runDirectoryDevice', 'runDirectoryInode', 'utunDevice', 'utunInode', 'listenerDevice', 'listenerInode'].some(key => !uint64String(value[key])) ||
      ['keeperPID', 'keeperParentPID', 'corePID', 'frontPID'].some(key => !Number.isSafeInteger(value[key]) || value[key] < 2) ||
      new Set([value.controllerPID, value.keeperPID, value.corePID, value.frontPID]).size !== 4 ||
      ['keeperBirth', 'keeperParentBirth', 'coreBirth', 'frontBirth'].some(key => !nativeBirth(value[key])) ||
      !Number.isSafeInteger(value.utunControlId) || value.utunControlId < 1 || value.utunControlId > 4294967295 ||
      !Number.isSafeInteger(value.utunControlUnit) || value.utunControlUnit < 1 || value.utunControlUnit > 4294967295 ||
      value.listenerHost !== '127.0.0.1' || !Number.isInteger(value.listenerPort) || value.listenerPort < 1 || value.listenerPort > 65535 ||
      !bootstrap || bootstrap.uid !== 0 || bootstrap.realUID !== 0 || bootstrap.savedUID !== 0 || bootstrap.parentPid !== binding.controllerPID ||
      ![`${PF_INSTALL_ROOT}/envara-pf-native`, '/bin/launchctl'].includes(bootstrap.path) || !nativeBirth(bootstrap.birth)) throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED');
  const direct = value.keeperPID === bootstrap.pid && value.keeperBirth === bootstrap.birth &&
    value.keeperParentPID === binding.controllerPID && value.keeperParentBirth === binding.controllerBirth;
  const fork = value.keeperPID !== bootstrap.pid && value.keeperParentPID === bootstrap.pid && value.keeperParentBirth === bootstrap.birth;
  if (!direct && !fork) throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED');
  return Object.freeze(structuredClone(value));
}
export const PF_CHECKS = Object.freeze(['tcp', 'udp', 'dns', 'childProcesses', 'failClosed', 'guard', 'unrelatedApps', 'nativeAcceptance']);
export const PF_MANIFEST_FILES = Object.freeze({
  EnvaraPFHelper: true, node: true, 'helper.mjs': false, 'controller.mjs': false,
  'helper-production-native.mjs': false, 'notion-front-service.mjs': false,
  'notion-socks-front.mjs': false, 'notion-socks-reader.mjs': false,
  'policy.mjs': false, 'stateless-verifier.mjs': false, 'mihomo': true,
  'envara-pf-native': true, 'fixtures/EnvaraRoutingAcceptanceFixture': true,
  'node-LICENSE': false, 'mihomo-LICENSE': false, 'mihomo-SOURCE.md': false,
  'mihomo-corresponding-source.tar.gz': false, LICENSE: false,
});
const MIHOMO_DARWIN_ARM64_SHA256 = '94a386ec0149080deadd86b1f667363bde3c70f7489dba3258e52c56fc9a6d66';
const FIXTURE_DESTINATIONS = Object.freeze([{ host: '198.51.100.42', ports: [44441, 44442, 44443, 44444] }, { host: '1.1.1.1', ports: [53] }]);
const CONTROLLED_CASES = Object.freeze(['realm-identities', 'tcp-concurrent', 'tcp-half-close', 'udp-concurrent', 'dns-tcp53']);
const CASE_TARGETS = Object.freeze({ 'tcp-concurrent': { protocol: 'tcp', host: '198.51.100.42', port: 44441 },
  'realm-identities': { protocol: 'tcp', host: '198.51.100.42', port: 44441 },
  'tcp-half-close': { protocol: 'tcp', host: '198.51.100.42', port: 44442 },
  'udp-concurrent': { protocol: 'udp', host: '198.51.100.42', port: 44444 },
  'dns-tcp53': { protocol: 'tcp', host: '1.1.1.1', port: 53 } });
const checks = () => Object.fromEntries(PF_CHECKS.map(key => [key, false]));
const diagnosticFlags = () => ({ acceptanceProtocol: 'envara-pf-acceptance/v1', acceptanceOnly: true, ready: false, productionReceiptAllowed: false, protected: false });
const HOOK_OPERATIONS = Object.freeze(['hook-status', 'insert-owned-root-hook', 'delete-owned-root-hook']);
const FILTER_FAILURE_REASONS = new Set(['AUTHENTICATED_ROOT_CONTROLLER_REQUIRED', 'SIGNAL_BOUNDARY_UNAVAILABLE',
  'BOUNDED_PRIVATE_INPUT_REQUIRED', 'INVALID_PRIVATE_FILTER_INPUT', 'EXACT_ISSUED_LEASE_REQUIRED',
  'SEALED_PENDING_FILTER_INTENT_REQUIRED', 'OWNED_FILTER_DEVICE_REFUSED', 'PRIOR_FILTER_READBACK_REFUSED',
  'GENERATED_FILTER_REPLACEMENT_REFUSED', 'invalid-context', 'invalid-config', 'already-used', 'guard-rejected',
  'begin-failed', 'begin-reply-invalid', 'pool-failed', 'pool-reply-invalid', 'add-address-failed', 'add-address-reply-invalid',
  'add-rule-failed', 'add-rule-reply-invalid', 'commit-failed', 'commit-reply-invalid', 'verify-failed']);
const uint32String = value => typeof value === 'string' && /^(?:0|[1-9][0-9]{0,9})$/.test(value) && BigInt(value) <= 4294967295n;
const privateFilterFailure = value => failure(FILTER_FAILURE_REASONS.has(value)
  ? `APPLICATION_PF_FILTER_${value.toUpperCase().replaceAll('-', '_')}` : 'APPLICATION_PF_FILTER_REPLACEMENT_UNCONFIRMED');
const HOOK_FAILURE_CODES = Object.freeze({
  AUTHENTICATED_ROOT_CONTROLLER_REQUIRED: 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED',
  SIGNAL_BOUNDARY_UNAVAILABLE: 'APPLICATION_PF_HOOK_SIGNAL_REFUSED',
  INVALID_PRIVATE_HOOK_INPUT: 'APPLICATION_PF_HOOK_INPUT_REFUSED',
  PINNED_HOST_MISMATCH: 'APPLICATION_PF_HOOK_HOST_REFUSED',
  READ_DEVICE_UNAVAILABLE: 'APPLICATION_PF_HOOK_READ_REFUSED',
  READ_ONLY_OWNED_HOOK_PROOF: 'APPLICATION_PF_HOOK_READ_REFUSED',
  OWNED_HOOK_PREFLIGHT_REQUIRED: 'APPLICATION_PF_HOOK_PREFLIGHT_REFUSED',
  EXACT_LEASE_AND_EMPTY_OWNED_ANCHOR_REQUIRED: 'APPLICATION_PF_HOOK_CLEANUP_REFUSED',
  WRITE_DEVICE_UNAVAILABLE: 'APPLICATION_PF_HOOK_WRITE_REFUSED',
  EXACT_CLEANUP_UNCONFIRMED: 'APPLICATION_PF_HOOK_CLEANUP_UNCONFIRMED',
  PF_CHANGED_OR_PARENT_ENDED_BEFORE_INSERT: 'APPLICATION_PF_HOOK_PREFLIGHT_CHANGED',
  INSERT_UNCONFIRMED_OWN_ROLLBACK_ATTEMPTED: 'APPLICATION_PF_HOOK_INSERT_UNCONFIRMED',
  OWNED_RUN_LEDGER_UNVERIFIED: 'APPLICATION_PF_HOOK_LEDGER_REFUSED',
  OWNED_RUN_NAMESPACE_CONSUMED: 'APPLICATION_PF_HOOK_RUN_CONSUMED',
  OWNED_RUN_ALLOCATION_REQUIRED: 'APPLICATION_PF_HOOK_ALLOCATION_REQUIRED',
  EXACT_ISSUED_LEASE_REQUIRED: 'APPLICATION_PF_HOOK_LEASE_REFUSED',
  OWNED_HOOK_DELETE_INTENT_REQUIRED: 'APPLICATION_PF_HOOK_DELETE_INTENT_REQUIRED',
  OWNED_RUN_RETIREMENT_UNCONFIRMED: 'APPLICATION_PF_HOOK_RETIREMENT_UNCONFIRMED',
});
const PREPARE_STAGES = new Set(['registry-lock', 'baseline-snapshot', 'root-hook-intent', 'root-hook-insert', 'root-hook-receipt',
  'owned-anchor-check', 'group-allocation', 'deny-rules', 'pf-reference', 'tunnel-start', 'fixture-start', 'fixture-resume',
  'socket-reservation', 'stateless-rules', 'fixture-commit']);
const CASE_STAGES = new Set(['state-before', 'rule-readback', 'process-before', 'challenge-validation', 'reservation', 'probe-transport', 'probe-binding', 'process-after', 'state-after', 'evidence']);
const FIXTURE_ERROR_CODES = new Set(['INVALID_REQUEST', 'FORBIDDEN_ENDPOINT', 'PROBE_TIMEOUT', 'PROBE_TRANSPORT_FAILED', 'PROBE_SIZE_LIMIT', 'CHILD_UNAVAILABLE', 'CHILD_LIMIT', 'CLEANUP_UNVERIFIED', 'RESERVATION_REQUIRED', 'RESERVATION_UNAVAILABLE', 'RESERVATION_LIMIT']);
const fixtureFailure = value => failure(FIXTURE_ERROR_CODES.has(value) ? `APPLICATION_PF_FIXTURE_${value}` : 'APPLICATION_PF_FIXTURE_REPLY_REFUSED');
const caseFailure = run => run.caseFailure && CONTROLLED_CASES.includes(run.caseFailure.caseId) && CASE_STAGES.has(run.caseFailure.stage)
  ? { caseId: run.caseFailure.caseId, stage: run.caseFailure.stage, code: cleanError(run.caseFailure) } : null;
const failure = (code, message = 'Mac application routing operation did not complete') => Object.assign(new Error(message), { code });
const validId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const uuid = isPFRoutingRunId;
const absolute = value => typeof value === 'string' && path.isAbsolute(value) && !/[\0\r\n]/.test(value);
const digest = value => createHash('sha256').update(value).digest('hex');
export function validatePFAppBoundLease(value) {
  const keys = ['schema', 'runId', 'environmentId', 'realmId', 'leaseId', 'generation', 'registrationId', 'versionId', 'consoleUID', 'gid', 'cwd', 'timezone', 'locale',
    'issuedMonotonicMs', 'expiresMonotonicMs', 'bootTimeSeconds', 'controllerPid', 'controllerBirth', 'ipv4Address', 'rootHookLease'];
  if (!value || Array.isArray(value) || Object.keys(value).sort().join('|') !== [...keys].sort().join('|') || value.schema !== PF_APP_BOUND_LEASE_SCHEMA ||
      ['runId', 'environmentId', 'realmId', 'leaseId', 'generation', 'registrationId', 'versionId'].some(key => !uuid(value[key])) ||
      !Number.isSafeInteger(value.consoleUID) || value.consoleUID < 1 || value.consoleUID > 4294967295 || !Number.isSafeInteger(value.gid) || value.gid < 7100 || value.gid > 7999 ||
      !absolute(value.cwd) || value.cwd.length > 4095 || !nativeBirth(value.controllerBirth) || !Number.isSafeInteger(value.controllerPid) || value.controllerPid < 2 ||
      typeof value.timezone !== 'string' || value.timezone.length > 100 || typeof value.locale !== 'string' || !/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}$/.test(value.locale) ||
      value.ipv4Address !== '198.18.1.1' || ['issuedMonotonicMs', 'expiresMonotonicMs', 'bootTimeSeconds'].some(key => !Number.isSafeInteger(value[key]) || value[key] < 1) ||
      value.expiresMonotonicMs <= value.issuedMonotonicMs || value.expiresMonotonicMs - value.issuedMonotonicMs > 180000) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
  try { new Intl.DateTimeFormat('en', { timeZone: value.timezone }); validatePFRootHookLease(value.rootHookLease, value.runId); }
  catch { throw failure('APPLICATION_APP_CONTEXT_REFUSED'); }
  return structuredClone(value);
}
const fileDigest = async (file, fileSystem = fs) => {
  if (fileSystem !== fs) return digest(await fileSystem.readFile(file));
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
};
function pfInterfaceFlags(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 65536) throw failure('APPLICATION_ROUTING_NOT_READY');
  const interfaces = new Map();
  for (const line of text.split('\n').filter(Boolean)) {
    const match = /^([A-Za-z][A-Za-z0-9_.:-]{0,31})(?: [(]skip[)])?$/.exec(line);
    if (!match || interfaces.has(match[1])) throw failure('APPLICATION_ROUTING_NOT_READY');
    interfaces.set(match[1], line.endsWith(' (skip)'));
  }
  if (!interfaces.size) throw failure('APPLICATION_ROUTING_NOT_READY');
  return interfaces;
}
export function validatePFRootHookLease(value, runId) {
  const keys = ['schema', 'runId', 'leaseId', 'anchor', 'owner', 'label', 'ticket', 'rootBeforeSHA256', 'rootBeforeTextSHA256'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join('|') !== keys.sort().join('|') ||
      keys.some(key => typeof value[key] !== 'string') ||
      value.schema !== PF_ROOT_HOOK_LEASE_SCHEMA || !uuid(value.runId) || value.runId !== runId || !uuid(value.leaseId) ||
      value.anchor !== pfRoutingAnchor(runId) || value.owner !== pfRoutingAnchor(runId) ||
      value.label !== `envara.hook.v2.${digest(`${value.runId}|${value.leaseId}`).slice(0, 32)}` || !/^[1-9][0-9]{0,19}$/.test(value.ticket ?? '') ||
      BigInt(value.ticket) > 18446744073709551615n ||
      ['rootBeforeSHA256', 'rootBeforeTextSHA256'].some(key => !/^[0-9a-f]{64}$/.test(value[key] ?? ''))) throw failure('APPLICATION_ROUTING_NOT_READY');
  return structuredClone(value);
}
export function normalizePFRouteTable(text) {
  if (typeof text !== 'string' || text.length > 1024 * 1024) throw failure('APPLICATION_ROUTING_NOT_READY');
  const entries = []; let family = null, header = null;
  for (const line of text.split('\n').map(value => value.trim()).filter(Boolean)) {
    if (line === 'Routing tables') continue;
    if (line === 'Internet:' || line === 'Internet6:') { family = line.slice(0, -1); header = null; continue; }
    if (line.startsWith('Destination ')) {
      header = line.split(/\s+/);
      if (!['Destination', 'Gateway', 'Flags', 'Netif'].every(key => header.includes(key))) throw failure('APPLICATION_ROUTING_NOT_READY');
      continue;
    }
    if (!family || !header) throw failure('APPLICATION_ROUTING_NOT_READY');
    const fields = line.split(/\s+/), selected = ['Destination', 'Gateway', 'Flags', 'Netif'].map(key => fields[header.indexOf(key)]);
    if (selected.some(value => !value || /[\0\r\n]/.test(value))) throw failure('APPLICATION_ROUTING_NOT_READY');
    // Preserve every route's address, gateway, flags and interface. Dynamic
    // Use/Refs/Expire counters do not change routing configuration.
    entries.push([family, ...selected].join('|'));
  }
  if (!entries.length) throw failure('APPLICATION_ROUTING_NOT_READY');
  return entries.sort().join('\n');
}
const cleanError = error => /^APPLICATION_[A-Z_]+$/.test(error?.code ?? '') ? error.code : 'APPLICATION_ROUTING_NOT_READY';
const appFailure = (stage, error) => Object.freeze({ stage: APP_FAILURE_STAGES.has(stage) ? stage : 'cleanup', code: cleanError(error),
  ...(validAppNativeFailure(error?.nativeFailure) ? { native: Object.freeze({ ...error.nativeFailure }) } : {}) });
const projectAppFailure = value => value && !Array.isArray(value) &&
  ['code|stage', 'code|native|stage'].includes(Object.keys(value).sort().join('|')) && APP_FAILURE_STAGES.has(value.stage) &&
  /^APPLICATION_[A-Z_]+$/.test(value.code ?? '') && (!Object.hasOwn(value, 'native') || validAppNativeFailure(value.native))
  ? { stage: value.stage, code: value.code, ...(value.native ? { native: { ...value.native } } : {}) } : null;
function rememberAppFailure(run, stage, error, cleanup = false) {
  const projected = appFailure(stage, error);
  if (cleanup) { run.cleanupFailure = projected; run.cleanupFailedCode = projected.code; }
  else if (!run.initialFailure) {
    run.initialFailure = projected; run.failedStage = projected.stage; run.failedCode = projected.code;
    if (projected.native) run.nativeFailure = projected.native;
  }
}
function outwardAppFailure(run, code = run.initialFailure?.code ?? 'APPLICATION_ROUTING_NOT_READY') {
  const error = failure(code);
  if (run.initialFailure) Object.assign(error, { initialFailure: structuredClone(run.initialFailure), failureStage: run.initialFailure.stage,
    ...(run.initialFailure.native ? { nativeFailure: structuredClone(run.initialFailure.native) } : {}) });
  if (run.cleanupFailure) error.cleanupFailure = structuredClone(run.cleanupFailure);
  if (typeof run.cleanupRetryable === 'boolean') error.cleanupRetryable = run.cleanupRetryable;
  return error;
}
const preparationFailure = run => PREPARE_STAGES.has(run.failedStage)
  ? { stage: run.failedStage, code: cleanError({ code: run.failedCode }) } : null;

function validateManagedProxy(value) {
  if (!value || !['127.0.0.1', '::1'].includes(value.host) || !Number.isInteger(value.port) || value.port < 1 || value.port > 65535 ||
      ['username', 'password'].some(key => typeof value[key] !== 'string' || Buffer.byteLength(value[key]) < 1 || Buffer.byteLength(value[key]) > 255 || /[\0\r\n]/.test(value[key]))) throw failure('APPLICATION_PROXY_UNAVAILABLE');
  return { host: value.host, port: value.port, username: value.username, password: value.password };
}
function authenticateManagedProxy(input, timeoutMs = 3000) {
  const proxy = validateManagedProxy(input);
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: proxy.host, port: proxy.port });
    let received = Buffer.alloc(0), stage = 'method', settled = false;
    const finish = error => {
      if (settled) return; settled = true; clearTimeout(timer); socket.destroy();
      error ? reject(failure('APPLICATION_PROXY_UNAVAILABLE')) : resolve(true);
    };
    const timer = setTimeout(() => finish(new Error()), timeoutMs);
    socket.on('error', () => finish(new Error())); socket.once('close', () => finish(new Error()));
    socket.once('connect', () => socket.write(Buffer.from([5, 1, 2])));
    socket.on('data', chunk => {
      received = Buffer.concat([received, chunk]);
      if (received.length > 16) return finish(new Error());
      if (received.length < 2) return;
      if (stage === 'method') {
        if (received[0] !== 5 || received[1] !== 2 || received.length !== 2) return finish(new Error());
        const user = Buffer.from(proxy.username), password = Buffer.from(proxy.password);
        received = Buffer.alloc(0); stage = 'authentication';
        socket.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([password.length]), password]));
      } else finish(received[0] === 1 && received[1] === 0 && received.length === 2 ? null : new Error());
    });
  });
}

/** No certificate is required for these ordinary root-owned files. Ownership,
 * fixed destinations and immutable manifest hashes still must be established
 * by a separately approved system installation; a UI boolean is not trust. */
export async function verifyPFInstallation({ root = PF_INSTALL_ROOT, fileSystem = fs } = {}) {
  const result = { available: false, verified: false, manifestVerified: false, runtimeVerified: false, reason: 'installation-absent' };
  try {
    if (root !== PF_INSTALL_ROOT) throw new Error();
    const securePath = async (target, regularFile = false) => {
      if (!absolute(target) || await fileSystem.realpath(target) !== target) throw new Error();
      let current = target;
      while (true) {
        const info = await fileSystem.lstat(current);
        if (info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o022) !== 0 ||
            (current === target && (regularFile ? !info.isFile() : !info.isDirectory()))) throw new Error();
        if (current === '/') break;
        current = path.dirname(current);
      }
    };
    await securePath(root); result.available = true;
    const manifestPath = path.join(root, 'manifest.json');
    await securePath(manifestPath, true);
    const raw = await fileSystem.readFile(manifestPath);
    if (raw.length > 65536) throw new Error();
    const manifest = JSON.parse(raw.toString('utf8'));
    if (manifest.schema !== PF_INSTALLATION_SCHEMA || manifest.version !== '1' || manifest.backend !== 'pf-utun' || manifest.component !== 'envara-pf-routing' || manifest.platform !== 'darwin' || manifest.arch !== 'arm64' ||
        !manifest.files || typeof manifest.files !== 'object' || Array.isArray(manifest.files) ||
        Object.keys(manifest.files).sort().join('|') !== Object.keys(PF_MANIFEST_FILES).sort().join('|')) throw new Error();
    for (const [relative, executable] of Object.entries(PF_MANIFEST_FILES)) {
      const entry = manifest.files[relative], target = path.join(root, relative);
      if (!/^[0-9a-f]{64}$/.test(entry ?? '')) throw new Error();
      await securePath(target, true);
      const info = await fileSystem.lstat(target);
      if (executable && !(info.mode & 0o111)) throw new Error();
      if (relative.endsWith('.mjs') && info.size > 512 * 1024) throw new Error();
      if (await fileDigest(target, fileSystem) !== entry) throw new Error();
    }
    // The transport is the already pinned, unmodified official Mihomo binary.
    if (manifest.files.mihomo !== MIHOMO_DARWIN_ARM64_SHA256) throw new Error();
    result.manifestVerified = true; result.verified = true; result.reason = null;
    const executingController = fileURLToPath(import.meta.url);
    result.runtimeVerified = executingController === path.join(root, 'controller.mjs') &&
      await fileSystem.realpath(process.execPath) === path.join(root, 'node');
  } catch { if (result.available) result.reason = 'installation-trust-unverified'; }
  return result;
}

/** Staged artifact integrity is separate from root installation trust. It
 * only supplies the UI's 'component prepared' state and never authorizes PF. */
export async function inspectPFBundledComponent({ root = path.dirname(fileURLToPath(import.meta.url)), fileSystem = fs } = {}) {
  const result = { available: false, verified: false, installed: false };
  try {
    if (!absolute(root) || root === PF_INSTALL_ROOT) return result;
    const manifest = JSON.parse(await fileSystem.readFile(`${root}/manifest.json`, 'utf8'));
    result.available = true;
    if (manifest.schema !== PF_INSTALLATION_SCHEMA || manifest.version !== '1' || manifest.component !== 'envara-pf-routing' ||
        manifest.backend !== 'pf-utun' || manifest.platform !== 'darwin' || manifest.arch !== 'arm64' ||
        !manifest.files || Object.keys(manifest.files).sort().join('|') !== Object.keys(PF_MANIFEST_FILES).sort().join('|') ||
        manifest.files.mihomo !== MIHOMO_DARWIN_ARM64_SHA256) return result;
    for (const name of Object.keys(PF_MANIFEST_FILES)) {
      const target = `${root}/${name}`, info = await fileSystem.lstat(target);
      if (!info.isFile() || info.isSymbolicLink() || !/^[0-9a-f]{64}$/.test(manifest.files[name]) ||
          await fileDigest(target, fileSystem) !== manifest.files[name]) return result;
    }
    result.verified = true;
  } catch {}
  return result;
}

export function pfInstallationPlan() {
  return {
    schema: 'envara.macos-pf-installation-plan', version: 1, readOnly: true,
    root: PF_INSTALL_ROOT, manifestPath: `${PF_INSTALL_ROOT}/manifest.json`,
    runtimeRoot: PF_RUNTIME_ROOT, anchor: null, namespacePrefix: PF_ROUTING_NAMESPACE, freshNamespaceRequired: true,
    files: Object.entries(PF_MANIFEST_FILES).map(([name, executable]) => ({ name, mode: executable ? '0755' : '0644', owner: 'root:wheel' })),
    manifest: { schema: PF_INSTALLATION_SCHEMA, component: 'envara-pf-routing', backend: 'pf-utun', version: '1', platform: 'darwin', arch: 'arm64', hashAlgorithm: 'sha256' },
    requirements: ['explicit-admin-installation', 'root-owned-runtime-and-source', 'fixed-source-and-binary-hashes',
      'native-owned-root-hook-lease', 'PF-disabled-before-owned-hook-insert', 'exclusive-owned-registry', 'verified-exact-state-cleanup', 'owned-fixture-only'],
    ownedRootHook: { schema: PF_ROOT_HOOK_SCHEMA, namespacePrefix: PF_ROUTING_NAMESPACE, insertion: 'explicit-controlled-prepare-only',
      receipt: 'private-nonzero-uint64-ticket-and-unique-label', requiresSeparateActivationApproval: true },
    automaticInstallation: false, appleDeveloperAccountRequired: false,
    changes: { pfConf: false, globalPFFlush: false, defaultRoutes: false, hostDns: false, sip: false, unrelatedApplications: false },
  };
}

/** Private config for a second, application-owned Mihomo process. It routes
 * every accepted packet to the authenticated managed SOCKS listener, with no
 * DIRECT rule, system listener, auto-route or automatic network interception.
 * The native guardian retains a duplicate utun FD; only it may create the FD. */
export function pfTunnelCoreConfig({ proxy: input, udpPolicy = 'block', ipv4Address = '198.18.0.1' } = {}) {
  const proxy = validateManagedProxy(input);
  if (!['block', 'proxy'].includes(udpPolicy) || net.isIP(ipv4Address) !== 4 || !/^198\.(?:18|19)\./.test(ipv4Address)) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
  return {
    port: 0, 'socks-port': 0, 'mixed-port': 0, 'redir-port': 0, 'tproxy-port': 0,
    'bind-address': '127.0.0.1', 'allow-lan': false, mode: 'rule', 'log-level': 'silent', ipv6: false,
    'external-controller': '', 'external-controller-tls': '', 'external-controller-unix': '', 'external-controller-pipe': '',
    'external-ui': '', 'external-ui-url': '', 'find-process-mode': 'off', 'geo-auto-update': false, 'geodata-mode': false,
    'geox-url': { 'geo-ip': '', mmdb: '', asn: '', geosite: '' },
    dns: { enable: false, listen: '', 'enhanced-mode': 'redir-host', 'fake-ip-range': `${ipv4Address}/30`,
      'default-nameserver': ['https://1.1.1.1/dns-query'], nameserver: [], fallback: [],
      'use-hosts': false, 'use-system-hosts': false, ipv6: false },
    tun: { enable: true, device: '', stack: 'gvisor', 'file-descriptor': 3, mtu: 9000,
      'auto-route': false, 'auto-redirect': false, 'auto-detect-interface': false,
      'dns-hijack': [], 'strict-route': false, 'inet6-address': [], 'disable-icmp-forwarding': true },
    sniffer: { enable: false }, ntp: { enable: false, 'write-to-system': false },
    profile: { 'store-selected': false, 'store-fake-ip': false },
    'proxy-providers': {}, 'rule-providers': {}, 'proxy-groups': [], listeners: [], tunnels: [],
    proxies: [{ name: 'ENVARA_MANAGED_ROUTE', type: 'socks5', server: proxy.host, port: proxy.port,
      username: proxy.username, password: proxy.password, udp: udpPolicy === 'proxy' }],
    rules: [...(udpPolicy === 'block' ? ['NETWORK,UDP,REJECT'] : []), 'MATCH,ENVARA_MANAGED_ROUTE'],
  };
}

/** Never accepts a caller-selected executable or shell. All commands below
 * are constructed inside this module; requests only select owned resources. */
export class MacOSPFExecutor {
  constructor({ spawnChild = spawn, fileSystem = fs } = {}) {
    this.spawnChild = spawnChild; this.fs = fileSystem; this.kind = 'native';
    this.groups = new Map(); this.groupIdentities = new Map(); this.groupDeleteIntents = new Set(); this.guardians = new Map(); this.lock = null; this.pfToken = null;
    this.runtimeParent = null; this.runtimeDirectory = null; this.runtimeRunId = null;
    this.runDirectories = new Map(); this.registryIdentity = null;
    this.groupIntents = new Map();
    this.rootHookLease = null; this.rootHookMutationUncertain = false; this.rootHookDeleteAttempted = false; this.rootHookRetiredProof = null;
    this.pfReferenceMutationAttempted = false;
    this.filterCommitted = null; this.filterReplacementBusy = false; this.filterReplacementUncertain = false;
    // A state owner/ioctl implementation is not available in macOS pfctl.
    // Never substitute -F states, -i utun -F states, or -k source-address.
    this.exactStateCleanupSupported = false;
    this.statelessControlledFixtures = true;
    this.fixtureOperations = [...CONTROLLED_CASES, 'cleanup'];
    this.fixtureGuardians = new Map();
    this.appLeases = new Map(); this.appTransports = new Map();
  }
  command(executable, argv, stdin = '', timeoutMs = 5000, { cancelSignal = 'SIGKILL', captureHookFailure = false } = {}) {
    if (!this.allowedCommand(executable, argv) || captureHookFailure &&
        (executable !== `${PF_INSTALL_ROOT}/envara-pf-native` || argv.length !== 1 || ![...HOOK_OPERATIONS, 'replace-owned-filter'].includes(argv[0]))) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    return new Promise((resolve, reject) => {
      let child, stdout = '', stderr = '', bytes = 0, settled = false;
      const finish = (error, result) => {
        if (settled) return; settled = true; clearTimeout(timer);
        if (error) { try { child?.kill(cancelSignal); } catch {} reject(error); } else resolve(result);
      };
      const timer = setTimeout(() => finish(failure('APPLICATION_ROUTING_TIMEOUT')), timeoutMs);
      try { child = this.spawnChild(executable, argv, { shell: false, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' }, stdio: ['pipe', 'pipe', 'pipe'] }); }
      catch { finish(failure('APPLICATION_ROUTING_UNAVAILABLE')); return; }
      child.stdout.on('data', chunk => { bytes += chunk.length; if (bytes > 1024 * 1024) finish(failure('APPLICATION_ROUTING_PROTOCOL_ERROR')); else stdout += chunk.toString('utf8'); });
      child.stderr.on('data', chunk => { bytes += chunk.length; if (bytes > 1024 * 1024) finish(failure('APPLICATION_ROUTING_PROTOCOL_ERROR')); else stderr += chunk.toString('utf8'); });
      child.once('error', () => finish(failure('APPLICATION_ROUTING_UNAVAILABLE')));
      child.stdin.on('error', () => finish(failure('APPLICATION_ROUTING_UNAVAILABLE')));
      // A nonzero native hook result is diagnostic data only. Its bounded
      // fixed envelope is validated below; it can never become a success.
      child.once('close', code => finish(code === 0 || captureHookFailure && Number.isInteger(code) && code > 0 ? null : failure('APPLICATION_ROUTING_NOT_READY'),
        { stdout, stderr, exitCode: code, processPid: child.pid }));
      child.stdin.end(stdin);
    });
  }
  allowedCommand(executable, argv) {
    if (!Array.isArray(argv) || argv.some(value => typeof value !== 'string' || /[\0\r\n]/.test(value))) return false;
    if (executable === '/sbin/pfctl') {
      if (['-s info', '-sr', '-sn', '-ss', '-s Anchors'].includes(argv.join(' '))) return true;
      if (argv.join(' ') === '-v -s Interfaces') return true;
      if (this.ownedAnchor() !== null && argv.join(' ') === '-a ' + this.ownedAnchor() + ' -sr') return true;
      if (argv.join(' ') === '-E') return true;
      return argv.length === 2 && argv[0] === '-X' && /^[0-9]{1,20}$/.test(argv[1]) && argv[1] === this.pfToken;
    }
    if (executable === '/usr/bin/stat') return argv.join(' ') === '-f %u /dev/console';
    if (executable === '/bin/ps') return argv.join(' ') === '-axo pid=,uid=,gid=';
    if (executable === '/sbin/route') return ['default', '198.51.100.42', '1.1.1.1'].some(target => argv.join(' ') === `-n get ${target}`);
    if (executable === '/usr/sbin/netstat') return argv.join(' ') === '-rn';
    if (executable === '/usr/sbin/scutil') return argv.join(' ') === '--dns';
    if (executable === '/usr/bin/dscl') {
      if (argv.join(' ') === '. -list /Groups PrimaryGroupID') return true;
      if (argv[0] !== '.' || !/^\/Groups\/_envara_pf_7[1-9][0-9]{2}$/.test(argv[2] ?? '')) return false;
      if (argv[1] === '-create' && argv.length === 3) return true;
      if (argv[1] === '-create' && argv.length === 5 && argv[3] === 'PrimaryGroupID') return /^7[1-9][0-9]{2}$/.test(argv[4]);
      if (argv[1] === '-create' && argv.length === 5 && argv[3] === 'Password') return argv[4] === '*';
      if (argv[1] === '-read' && argv.length === 5 && argv[3] === 'GeneratedUID' && argv[4] === 'PrimaryGroupID') return this.groups.has(argv[2]);
      return argv[1] === '-delete' && argv.length === 3 && this.groups.has(argv[2]);
    }
    if (executable === `${PF_INSTALL_ROOT}/envara-pf-native`) return ['status', 'hook-status', 'insert-owned-root-hook', 'delete-owned-root-hook', 'replace-owned-filter', 'app-context-clock'].includes(argv.join(' ')) || argv.length === 3 && argv[0] === 'identity' && argv[1] === '--pid' && /^[1-9][0-9]{0,9}$/.test(argv[2]);
    return false;
  }
  ownedAnchor() {
    try {
      if (!uuid(this.runtimeRunId) || !this.rootHookLease || this.rootHookRetiredProof) return null;
      return validatePFRootHookLease(this.rootHookLease, this.runtimeRunId).anchor;
    } catch { return null; }
  }
  async readOnlyStatus({ runId } = {}) {
    if (runId !== undefined && !uuid(runId)) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    const console = await this.command('/usr/bin/stat', ['-f', '%u', '/dev/console']).catch(() => null);
    const consoleUID = console && /^\s*[1-9][0-9]*\s*$/.test(console.stdout) ? Number(console.stdout.trim()) : null;
    let pf = { readable: false, enabled: false, stockAppleAnchorHook: false };
    try {
      const [info, rules] = await Promise.all([this.command('/sbin/pfctl', ['-s', 'info']), this.command('/sbin/pfctl', ['-sr'])]);
      const lines = rules.stdout.split('\n'), index = lines.findIndex(line => /^anchor "com\.apple\/\*"(?: all)?\s*$/.test(line));
      pf = { readable: true, enabled: /^Status:\s+Enabled\b/m.test(info.stdout),
        stockAppleAnchorHook: index >= 0 && !lines.slice(0, index).some(line => /\bquick\b/.test(line)),
        rulesDigest: digest(rules.stdout) };
      await this.assertRequiredInterfacesNotSkipped(); pf.fixtureEgressSkipVerified = true;
    } catch {}
    // A physical-egress check cannot attest the loopback front's PF coverage.
    // Inspect actual flags without loading rules or requesting authorization.
    const loopback = await this.inspectLoopbackPFScope().catch(() => ({ lo0Skipped: null, lo0FilteringVerified: false }));
    Object.assign(pf, loopback); pf.lo0SkipVerified = loopback.lo0FilteringVerified === true;
    let nativeAvailable = false;
    try {
      const result = JSON.parse((await this.command(`${PF_INSTALL_ROOT}/envara-pf-native`, ['status'])).stdout);
      nativeAvailable = result?.ok === true && result.schema === 'envara.macos-pf-native/v1' && result.backend === 'pf-utun' && result.realmGID?.min === 7100 && result.realmGID?.max === 7999;
    } catch {}
    let ownedRootHook = { canCreateOwnedHook: false, ownedRootHookVerified: false, originalRootCompatible: false, pinsVerified: false, pfDisabled: false };
    try { ownedRootHook = await this.readHookStatus(runId ? { runId } : this.rootHookLease ? { lease: this.rootHookLease } : {}); } catch {}
    pf.priorAnchorsCompatible = ownedRootHook.priorAnchorsCompatible === true;
    return { consoleUID, pf, ownedRootHook, exactStateCleanupSupported: false, fixtureOperations: nativeAvailable ? [...this.fixtureOperations] : [],
      statelessControlledFixtures: true, noStateNativeAvailable: nativeAvailable };
  }
  async nativeRootHookRequest(operation, params) {
    if (!HOOK_OPERATIONS.includes(operation) || !params || typeof params !== 'object' || Array.isArray(params)) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    const keys = Object.keys(params).sort().join('|'); let expectedAnchor = '';
    if (operation === 'hook-status' && keys === '') { /* baseline has no selected namespace */ }
    else if ((operation === 'hook-status' || operation === 'insert-owned-root-hook') && keys === 'runId' && uuid(params.runId)) expectedAnchor = pfRoutingAnchor(params.runId);
    else if ((operation === 'hook-status' || operation === 'delete-owned-root-hook') && keys === 'lease') expectedAnchor = validatePFRootHookLease(params.lease, params.lease?.runId).anchor;
    else throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    if (Buffer.byteLength(JSON.stringify(params)) > 4096) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    const result = await this.command(`${PF_INSTALL_ROOT}/envara-pf-native`, [operation], `${JSON.stringify(params)}\n`, 15000,
      { cancelSignal: operation === 'hook-status' ? 'SIGKILL' : 'SIGTERM', captureHookFailure: true });
    let value; try {
      if (Buffer.byteLength(result.stdout) > 16384) throw new Error();
      value = JSON.parse(result.stdout);
    } catch { throw failure('APPLICATION_ROUTING_NOT_READY'); }
    if (value?.schema !== PF_ROOT_HOOK_SCHEMA || value.operation !== operation || value.anchor !== expectedAnchor) throw failure('APPLICATION_ROUTING_NOT_READY');
    if (Number.isInteger(result.exitCode) && result.exitCode > 0 && value.ok === false && typeof value.reason === 'string' &&
        /^[A-Z][A-Z0-9_]{0,95}$/.test(value.reason) && Object.hasOwn(HOOK_FAILURE_CODES, value.reason)) throw failure(HOOK_FAILURE_CODES[value.reason]);
    if (value.ok !== true || result.exitCode != null && result.exitCode !== 0) throw failure('APPLICATION_ROUTING_NOT_READY');
    if (operation === 'hook-status' && keys === '' && value.canCreateOwnedHook !== false) throw failure('APPLICATION_ROUTING_NOT_READY');
    return value;
  }
  async readHookStatus(params = {}) {
    const value = await this.nativeRootHookRequest('hook-status', params);
    if (value.readOnly !== true || value.priorAnchorsCompatible === true &&
        (value.priorRootDerivedAnchorCount !== 7 || !/^[0-9a-f]{64}$/.test(value.priorRulesetCountsSHA256 ?? ''))) throw failure('APPLICATION_ROUTING_NOT_READY');
    return value;
  }
  async inspectOwnedRootHook(lease = null) {
    const privateLease = lease ? validatePFRootHookLease(lease, this.runtimeRunId ?? lease.runId) : null;
    const value = await this.readHookStatus(privateLease ? { lease: privateLease } : {});
    if (privateLease && (value.ownedRootHookVerified !== true || value.originalRootCompatible !== true ||
        value.originalRootSHA256 !== privateLease.rootBeforeSHA256 || value.originalRootTextSHA256 !== privateLease.rootBeforeTextSHA256)) throw failure('APPLICATION_ROUTING_NOT_READY');
    return value;
  }
  async installOwnedRootHook(runId) {
    if (!uuid(runId) || runId !== this.runtimeRunId || !this.lock || this.rootHookLease || this.rootHookMutationUncertain || this.rootHookDeleteAttempted) throw failure('APPLICATION_ROUTING_NOT_READY');
    this.rootHookMutationUncertain = true;
    const value = await this.nativeRootHookRequest('insert-owned-root-hook', { runId });
    const lease = validatePFRootHookLease(value.lease, runId);
    if (value.ownedRootHookVerified !== true || value.ticketSource !== 'this-INSERT-return-only') throw failure('APPLICATION_ROUTING_NOT_READY');
    this.rootHookLease = lease;
    await this.inspectOwnedRootHook(lease);
    this.rootHookMutationUncertain = false;
    return lease;
  }
  retiredHookProof(value, lease = null) {
    const state = value.namespaceState;
    if (!['absent', 'present', 'unknown'].includes(state) || value.namespaceReclaimed !== (state === 'absent') ||
        value.namespaceExists !== (state === 'present') || value.cleanupPending !== (state !== 'absent') ||
        value.ownedRootHookRemoved !== true || value.originalRootRestored !== true || value.pinsVerified !== true || value.pfDisabled !== true ||
        lease && (value.receiptRetired !== true || value.originalRootSHA256 !== lease.rootBeforeSHA256 || value.originalRootTextSHA256 !== lease.rootBeforeTextSHA256)) throw failure('APPLICATION_ROUTING_NOT_READY');
    return { ownedRootHookRemoved: true, originalRootRestored: true, receiptRetired: value.receiptRetired === true,
      namespaceState: state, namespaceReclaimed: state === 'absent', namespaceExists: state === 'present', cleanupPending: state !== 'absent' };
  }
  async confirmNoOwnedRootHook(runId = this.runtimeRunId, lease = null) {
    if (!uuid(runId) || runId !== this.runtimeRunId) throw failure('APPLICATION_ROUTING_NOT_READY');
    const privateLease = lease ? validatePFRootHookLease(lease, runId) : null;
    const value = await this.readHookStatus(privateLease ? { lease: privateLease } : { runId });
    const proof = this.retiredHookProof(value, privateLease);
    this.rootHookMutationUncertain = proof.cleanupPending;
    if (privateLease) this.rootHookRetiredProof = proof;
    return proof;
  }
  async removeOwnedRootHook(lease) {
    const privateLease = validatePFRootHookLease(lease, this.runtimeRunId);
    if (!this.rootHookLease || JSON.stringify(privateLease) !== JSON.stringify(this.rootHookLease)) throw failure('APPLICATION_ROUTING_NOT_READY');
    if (this.rootHookRetiredProof) return this.confirmNoOwnedRootHook(privateLease.runId, privateLease);
    // One native DELETE intent per private issued receipt. Lost replies are
    // resolved by exact-lease read-only status, never by another DELETE.
    if (this.rootHookDeleteAttempted) return this.confirmNoOwnedRootHook(privateLease.runId, privateLease);
    this.rootHookMutationUncertain = true; this.rootHookDeleteAttempted = true;
    let value;
    try { value = await this.nativeRootHookRequest('delete-owned-root-hook', { lease: privateLease }); }
    catch (error) { try { return await this.confirmNoOwnedRootHook(privateLease.runId, privateLease); } catch {} throw error; }
    if (value.ticketSource !== 'this-INSERT-return-only' || value.receiptRetired !== true) throw failure('APPLICATION_ROUTING_NOT_READY');
    // Mutation reply is bound to the issued lease; pins/root digests are
    // independently rechecked by exact receipt status before it clears intent.
    return this.confirmNoOwnedRootHook(privateLease.runId, privateLease);
  }
  async inspectRuntimeDirectory(target, handle = null, privateDirectory = false) {
    const info = await this.fs.lstat(target);
    if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== 0 ||
        (info.mode & (privateDirectory ? 0o077 : 0o022)) || await this.fs.realpath(target) !== target) throw failure('APPLICATION_ROUTING_UNAVAILABLE');
    if (handle) {
      const held = await handle.stat();
      if (!held.isDirectory() || held.uid !== 0 || held.dev !== info.dev || held.ino !== info.ino || held.mode !== info.mode) throw failure('APPLICATION_ROUTING_UNAVAILABLE');
    }
    return info;
  }
  async openRuntimeDirectory(target, privateDirectory = false) {
    for (let current = target; ; current = path.dirname(current)) {
      await this.inspectRuntimeDirectory(current, null, current === target && privateDirectory);
      if (current === '/') break;
    }
    const handle = await this.fs.open(target, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
    try { await this.inspectRuntimeDirectory(target, handle, privateDirectory); return handle; }
    catch (error) { await handle.close(); throw error; }
  }
  async assertRuntimeRootHeld() {
    if (!this.runtimeParent || !this.runtimeDirectory) throw failure('APPLICATION_ROUTING_UNAVAILABLE');
    await this.inspectRuntimeDirectory(path.dirname(PF_RUNTIME_ROOT), this.runtimeParent);
    await this.inspectRuntimeDirectory(PF_RUNTIME_ROOT, this.runtimeDirectory, true);
  }
  async acquireLock(runId) {
    if (!uuid(runId) || this.lock || this.runtimeParent || this.runtimeDirectory) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    // The stock /private/var/run can be root:daemon 0775. It is inspected only
    // for legacy evidence; never trust it as a new privileged registry parent.
    try { await this.fs.lstat(PF_LEGACY_RUNTIME_ROOT); throw failure('APPLICATION_ROUTING_UNAVAILABLE'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    const parent = path.dirname(PF_RUNTIME_ROOT);
    this.runtimeParent = await this.openRuntimeDirectory(parent);
    try {
      // Hold and recheck the safe parent across this fixed-path creation.
      // No unprivileged user can rename entries in its verified ancestors.
      await this.inspectRuntimeDirectory(parent, this.runtimeParent);
      await this.fs.mkdir(PF_RUNTIME_ROOT, { mode: 0o700 }).catch(error => { if (error.code !== 'EEXIST') throw error; });
      await this.inspectRuntimeDirectory(parent, this.runtimeParent);
      this.runtimeDirectory = await this.openRuntimeDirectory(PF_RUNTIME_ROOT, true);
      if ((await this.fs.readdir(PF_RUNTIME_ROOT)).length !== 0) throw failure('APPLICATION_ROUTING_UNAVAILABLE');
      await this.assertRuntimeRootHeld();
      this.lock = await this.fs.open(`${PF_RUNTIME_ROOT}/registry.lock`, 'wx', 0o600);
      this.runtimeRunId = runId;
      await this.lock.writeFile(JSON.stringify({ runId, pid: process.pid, anchor: pfRoutingAnchor(runId) }));
    } catch (error) {
      // Once an exclusive lock file exists, preserve it as unknown evidence
      // if its first write fails. Never delete an orphan to permit a retry.
      if (!this.lock) {
        await this.runtimeDirectory?.close(); this.runtimeDirectory = null;
        await this.runtimeParent?.close(); this.runtimeParent = null;
      }
      throw error;
    }
  }
  async snapshotUnrelatedNetwork({ rootHookLease = null } = {}) {
    const parts = await Promise.all([
      this.command('/sbin/pfctl', ['-sr']), this.command('/sbin/pfctl', ['-sn']),
      this.command('/usr/sbin/netstat', ['-rn']), this.command('/usr/sbin/scutil', ['--dns']),
    ]);
    const routes = normalizePFRouteTable(parts[2].stdout);
    const rootProof = await this.inspectOwnedRootHook(rootHookLease);
    let rootDigest = digest(parts[0].stdout);
    if (rootHookLease) rootDigest = rootProof.originalRootTextSHA256;
    const foreignCounts = rootProof.priorRulesetCountsSHA256 ?? '';
    // While a known lease is active, exclude only our own call and enable
    // reference. A final no-lease snapshot compares the actual PF state.
    const pfDisabled = rootHookLease ? true : rootProof.pfDisabled === true;
    const pfDigest = digest([rootDigest, parts[1].stdout, foreignCounts, String(pfDisabled)].join('\0'));
    return { digest: digest([pfDigest, routes, parts[3].stdout].join('\0')), pfDigest,
      routeDigest: digest(routes), dnsDigest: digest(parts[3].stdout) };
  }
  async assertRequiredInterfacesNotSkipped(owned = []) {
    const interfaces = pfInterfaceFlags((await this.command('/sbin/pfctl', ['-v', '-s', 'Interfaces'])).stdout);
    if (!interfaces.size || interfaces.get('all') === true || interfaces.get('utun') === true || interfaces.get('en') === true) throw failure('APPLICATION_ROUTING_NOT_READY');
    const actual = await Promise.all(['198.51.100.42', '1.1.1.1'].map(target => this.command('/sbin/route', ['-n', 'get', target])));
    const names = actual.map(result => /^\s*interface:\s*([A-Za-z][A-Za-z0-9_.:-]{0,31})\s*$/m.exec(result.stdout)?.[1]);
    for (const name of [...names, ...owned]) if (!name || !interfaces.has(name) || interfaces.get(name) === true) throw failure('APPLICATION_ROUTING_NOT_READY');
    return true;
  }
  async inspectLoopbackPF() {
    return (await this.inspectLoopbackPFScope()).lo0FilteringVerified;
  }
  async inspectLoopbackPFScope() {
    const interfaces = pfInterfaceFlags((await this.command('/sbin/pfctl', ['-v', '-s', 'Interfaces'])).stdout);
    return { lo0Skipped: interfaces.has('lo0') ? interfaces.get('lo0') : null,
      lo0FilteringVerified: interfaces.get('lo0') === false && interfaces.get('all') !== true && interfaces.get('lo') !== true };
  }
  async requireEmptyOwnedAnchor() {
    if (!this.ownedAnchor()) throw failure('APPLICATION_ROUTING_NOT_READY');
    const current = await this.command('/sbin/pfctl', ['-a', this.ownedAnchor(), '-sr']);
    if (current.stdout.trim()) throw failure('APPLICATION_ROUTING_NOT_READY');
  }
  async allocateGroup(environmentId) {
    if (!uuid(environmentId)) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    const list = await this.command('/usr/bin/dscl', ['.', '-list', '/Groups', 'PrimaryGroupID']);
    const records = list.stdout.split('\n').map(line => /^\s*(\S+)\s+([0-9]+)\s*$/.exec(line)).filter(Boolean);
    const used = new Set(records.map(record => Number(record[2])));
    for (const value of this.groups.values()) used.add(value);
    let gid = 7100; while (gid < 8000 && used.has(gid)) gid++;
    if (gid >= 8000) throw failure('APPLICATION_ROUTING_NOT_READY');
    const groupPath = `/Groups/_envara_pf_${gid}`;
    if (records.some(record => `/Groups/${record[1]}` === groupPath)) throw failure('APPLICATION_ROUTING_NOT_READY');
    this.groupIntents.set(groupPath, gid);
    await this.command('/usr/bin/dscl', ['.', '-create', groupPath]);
    this.groups.set(groupPath, gid);
    await this.command('/usr/bin/dscl', ['.', '-create', groupPath, 'PrimaryGroupID', String(gid)]);
    await this.command('/usr/bin/dscl', ['.', '-create', groupPath, 'Password', '*']);
    const identity = await this.readOwnedGroupIdentity(groupPath, gid);
    this.groupIdentities.set(groupPath, identity);
    this.groupIntents.delete(groupPath);
    return { gid, groupPath, generatedUID: identity.generatedUID, fresh: true };
  }
  openGuardian(argv, { firstLine, key, kind, timeoutMs = 10000 } = {}) {
    if (!validId(key) || !['tunnel', 'fixture'].includes(kind) || !Array.isArray(argv) || argv.some(value => typeof value !== 'string' || /[\0\r\n]/.test(value))) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    return new Promise((resolve, reject) => {
      let child, output = '', bytes = 0, settled = false;
      const entry = { key, kind, child: null, exited: false, events: [], first: null, uncertain: false };
      const fail = () => {
        entry.uncertain = true;
        if (!settled) { settled = true; clearTimeout(timer); reject(failure('APPLICATION_ROUTING_NOT_READY')); }
        // Never SIGKILL a utun FD guardian just because its control response
        // failed. Its kernel interface may still be targeted by our PF rules.
        try { child?.stdin.end('TERMINATE\n'); } catch {}
      };
      const timer = setTimeout(fail, timeoutMs);
      try { child = this.spawnChild(`${PF_INSTALL_ROOT}/envara-pf-native`, argv, {
        shell: false, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' }, stdio: ['pipe', 'pipe', 'pipe'],
      }); } catch { clearTimeout(timer); reject(failure('APPLICATION_ROUTING_UNAVAILABLE')); return; }
      entry.child = child; this.guardians.set(key, entry);
      child.stderr.on('data', () => {}); child.stdin.on('error', fail); child.once('error', fail);
      child.stdout.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 1024 * 1024) return fail();
        output += chunk.toString('utf8');
        let newline;
        while ((newline = output.indexOf('\n')) >= 0) {
          const line = output.slice(0, newline); output = output.slice(newline + 1);
          let result; try { result = JSON.parse(line); } catch { fail(); return; }
          if (!result || result.ok !== true || result.protected === true) { fail(); return; }
          if (!entry.first) {
            entry.first = result;
            if (!settled) { settled = true; clearTimeout(timer); resolve({ entry, result }); }
          } else if (entry.events.length < 256) entry.events.push(result);
          if (result.operation === 'fixture-response') {
            const pending = entry.responses?.shift();
            if (pending) pending(result); else entry.uncertain = true;
          }
          if (entry.first && entry.kind === 'tunnel' && result.phase === 'core-exited-fd-held') {
            try { this.onFault?.({ kind: 'core-exited', instanceId: key, fdRetained: true }); } catch {}
          }
        }
      });
      child.once('close', () => {
        entry.exited = true;
        if (!settled) fail();
        if (entry.kind === 'tunnel' && !entry.releasing) try { this.onFault?.({ kind: 'guardian-exited', instanceId: key, fdRetained: false }); } catch {}
      });
      if (firstLine != null) child.stdin.write(`${JSON.stringify(firstLine)}\n`);
    });
  }
  async createRunDirectory(runId, realmId) {
    if (!uuid(runId) || runId !== this.runtimeRunId || !validId(realmId) || !this.lock) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    await this.assertRuntimeRootHeld();
    const runDirectory = `${PF_RUNTIME_ROOT}/${runId}`, directory = `${runDirectory}/${realmId}`;
    for (const target of [runDirectory, directory]) {
      await this.fs.mkdir(target, { mode: 0o700 }).catch(error => { if (error.code !== 'EEXIST' || !this.runDirectories.has(target)) throw error; });
      if (this.runDirectories.has(target)) await this.inspectRuntimeDirectory(target, this.runDirectories.get(target), true);
      else this.runDirectories.set(target, await this.openRuntimeDirectory(target, true));
    }
    await this.assertRuntimeRootHeld();
    return directory;
  }
  async applicationContextClock() {
    const reply = JSON.parse((await this.command(`${PF_INSTALL_ROOT}/envara-pf-native`, ['app-context-clock'])).stdout);
    if (!reply || reply.schema !== PF_APP_CONTEXT_CLOCK_SCHEMA || reply.ok !== true ||
        Object.keys(reply).sort().join('|') !== ['schema', 'ok', 'bootTimeSeconds', 'nowMonotonicMilliseconds'].sort().join('|') ||
        ['bootTimeSeconds', 'nowMonotonicMilliseconds'].some(key => !Number.isSafeInteger(reply[key]) || reply[key] < 1)) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
    return reply;
  }
  async verifyApplicationLease(runId) {
    const entry = this.appLeases.get(runId);
    if (!entry) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
    await this.assertRuntimeRootHeld();
    await this.inspectRuntimeDirectory(path.dirname(entry.path), this.runDirectories.get(path.dirname(entry.path)), true);
    const current = await this.fs.lstat(entry.path), held = await entry.handle.stat();
    if (!current.isFile() || current.isSymbolicLink() || current.uid !== 0 || current.nlink !== 1 || (current.mode & 0o777) !== 0o600 ||
        current.dev !== entry.identity.dev || current.ino !== entry.identity.ino || held.dev !== current.dev || held.ino !== current.ino || held.size !== entry.bytes.length) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
    const reread = Buffer.alloc(entry.bytes.length);
    let offset = 0;
    while (offset < reread.length) { const read = await entry.handle.read(reread, offset, reread.length - offset, offset); if (!read.bytesRead) throw failure('APPLICATION_APP_CONTEXT_REFUSED'); offset += read.bytesRead; }
    const after = await entry.handle.stat(), pathAfter = await this.fs.lstat(entry.path);
    if (!reread.equals(entry.bytes) || after.dev !== held.dev || after.ino !== held.ino || after.size !== held.size ||
        after.mtimeMs !== held.mtimeMs || after.ctimeMs !== held.ctimeMs || pathAfter.dev !== after.dev || pathAfter.ino !== after.ino || pathAfter.nlink !== 1) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
    return { leaseSHA256: entry.sha256 };
  }
  async sealApplicationLease(input) {
    const lease = validatePFAppBoundLease(input);
    if (this.appLeases.has(lease.runId) || lease.runId !== this.runtimeRunId) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
    await this.createRunDirectory(lease.runId, lease.realmId);
    const destination = `${PF_RUNTIME_ROOT}/${lease.runId}/app-bound-lease.json`, bytes = Buffer.from(JSON.stringify(lease));
    if (bytes.length > 16384) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
    const handle = await this.fs.open(destination, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    let identity;
    try { await handle.writeFile(bytes); await handle.sync(); identity = await handle.stat(); }
    finally { await handle.close(); }
    const readHandle = await this.fs.open(destination, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    this.appLeases.set(lease.runId, { path: destination, handle: readHandle, identity, bytes, sha256: digest(bytes) });
    await this.runDirectories.get(path.dirname(destination)).sync();
    return this.verifyApplicationLease(lease.runId);
  }
  async retireApplicationLease(runId) {
    const entry = this.appLeases.get(runId);
    if (!entry) {
      if (this.retiredAppLeases?.has(runId)) return;
      throw failure('APPLICATION_APP_CONTEXT_REFUSED');
    }
    const directory = this.runDirectories.get(path.dirname(entry.path));
    await this.inspectRuntimeDirectory(path.dirname(entry.path), directory, true);
    if (!entry.retirementAttempted) {
      await this.verifyApplicationLease(runId); entry.retirementAttempted = true;
      await this.fs.unlink(entry.path);
    } else {
      try {
        const current = await this.fs.lstat(entry.path), held = await entry.handle.stat();
        if (!current.isFile() || current.isSymbolicLink() || current.dev !== held.dev || current.ino !== held.ino || current.nlink !== 1) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
        await this.fs.unlink(entry.path);
      } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    // A retirement intent reconciles only this held inode and its same parent;
    // a replacement path is never removed, and a failed fsync is retryable.
    try { await this.fs.lstat(entry.path); throw failure('APPLICATION_APP_CONTEXT_REFUSED'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    await directory.sync();
    await entry.handle.close(); entry.bytes.fill(0); this.appLeases.delete(runId);
    (this.retiredAppLeases ??= new Set()).add(runId);
  }
  async applicationTransportBinding(runId, environmentId, leaseSHA256) {
    const verified = await this.verifyApplicationLease(runId), entry = this.appLeases.get(runId);
    const lease = validatePFAppBoundLease(JSON.parse(entry.bytes.toString('utf8')));
    const heldDirectory = this.runDirectories.get(path.dirname(entry.path));
    if (!heldDirectory) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
    const directory = await this.inspectRuntimeDirectory(path.dirname(entry.path), heldDirectory, true);
    const file = await entry.handle.stat();
    if (verified.leaseSHA256 !== leaseSHA256 || lease.environmentId !== environmentId ||
        [file.dev, file.ino, directory.dev, directory.ino].some(value => !Number.isSafeInteger(value) || value < 0)) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
    return Object.freeze({ runId, environmentId, realmId: lease.realmId, gid: lease.gid, leaseSHA256,
      controllerPID: lease.controllerPid, controllerBirth: lease.controllerBirth,
      leaseDevice: String(file.dev), leaseInode: String(file.ino), runDirectoryDevice: String(directory.dev), runDirectoryInode: String(directory.ino) });
  }
  async confirmApplicationPrestageAborted(runId) {
    const entry = this.appTransports.get(runId);
    if (!entry || entry.uncertain || !entry.abortReceipt || entry.phase !== 'prestage-aborted' || !entry.exited || entry.exitCode !== 1 || entry.exitSignal !== null ||
        entry.pendingBytes !== 0 || entry.ticketId || entry.resumeAttempted || !entry.refusalPending || entry.failure?.stage !== 'factory-open') throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED');
    const current = await this.applicationTransportBinding(runId, entry.environmentId, entry.binding.leaseSHA256);
    if (JSON.stringify(current) !== JSON.stringify(entry.binding)) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
    const receipt = validatePFApplicationPrestageAbort(entry.abortReceipt, current, entry.bootstrapIdentity);
    // The native terminal proves complete credentials and descriptor custody.
    // Recheck the same private directory and absence, never adopt a new journal.
    try { await this.fs.lstat(`${PF_RUNTIME_ROOT}/${runId}/app-filter-events`); throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    return { ...receipt, transportExitConfirmed: true };
  }
  async confirmApplicationPreflightAborted(runId) {
    const entry = this.appTransports.get(runId);
    if (!entry || entry.uncertain || !entry.preflightAbortReceipt || entry.phase !== 'preflight-aborted' || !entry.exited ||
        entry.exitCode !== 1 || entry.exitSignal !== null || entry.pendingBytes !== 0 || entry.ticketId || entry.resumeAttempted || entry.ack ||
        !entry.refusalPending || entry.failure?.stage !== 'preflight') throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED');
    const current = await this.applicationTransportBinding(runId, entry.environmentId, entry.binding.leaseSHA256);
    if (JSON.stringify(current) !== JSON.stringify(entry.binding)) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
    const receipt = validatePFApplicationPreflightAbort(entry.preflightAbortReceipt, current, entry.child.pid, entry.bootstrapIdentity);
    for (const [filename, device, inode] of [[`${PF_INSTALL_ROOT}/envara-pf-native`, receipt.bootstrapDevice, receipt.bootstrapInode],
      [`${PF_INSTALL_ROOT}/node`, receipt.bootstrapParentDevice, receipt.bootstrapParentInode]]) {
      const before = await this.fs.lstat(filename);
      if (!before.isFile() || before.isSymbolicLink() || before.uid !== 0 || before.nlink !== 1 || (before.mode & 0o7777) !== 0o755 ||
          String(before.dev) !== device || String(before.ino) !== inode || await this.fs.realpath(filename) !== filename) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
      const after = await this.fs.lstat(filename);
      if (['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeMs', 'ctimeMs'].some(key => before[key] !== after[key])) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
    }
    try { await this.fs.lstat(`${PF_RUNTIME_ROOT}/${runId}/app-filter-events`); throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    return { ...receipt, transportExitConfirmed: true };
  }
  async startApplicationTransport({ runId, environmentId, proxy, udpPolicy, leaseSHA256, consoleUID }) {
    if (!uuid(runId) || !uuid(environmentId) || this.appTransports.has(runId) || !/^[0-9a-f]{64}$/.test(leaseSHA256 ?? '') ||
        !['block', 'proxy'].includes(udpPolicy) || !Number.isSafeInteger(consoleUID) || consoleUID < 1) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    const upstream = { ...validateManagedProxy(proxy), udpPolicy };
    await this.verifyApplicationLease(runId);
    const lease = validatePFAppBoundLease(JSON.parse(this.appLeases.get(runId).bytes.toString('utf8')));
    const binding = await this.applicationTransportBinding(runId, environmentId, leaseSHA256);
    if (consoleUID !== lease.consoleUID) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
    const entry = { runId, environmentId, registrationId: lease.registrationId, versionId: lease.versionId,
      binding, deadline: Date.now() + 15000, phase: 'starting', child: null, uncertain: false, exited: false, waiters: [], events: [], pendingBytes: 0 };
    this.appTransports.set(runId, entry);
    const transportError = () => {
      const native = entry.cleanupFailure ?? entry.failure;
      return Object.assign(failure(native ? 'APPLICATION_APP_NATIVE_REFUSED' : entry.waitFailure ?? 'APPLICATION_APP_TRANSPORT_UNCONFIRMED'),
        native ? { nativeFailure: { ...native } } : {});
    };
    const denyLaunch = () => {
      entry.cleanupOnly = true;
      for (const waiter of entry.waiters.splice(0)) { clearTimeout(waiter.timer); waiter.reject(transportError()); }
    };
    const poison = () => {
      if (entry.uncertain) return; entry.uncertain = true; entry.phase = 'recovery-required';
      for (const waiter of entry.waiters.splice(0)) { clearTimeout(waiter.timer); waiter.reject(transportError()); }
      // Closing the control channel asks the fixed native keeper to stop its
      // exact children. It never SIGKILLs original utun/listener custodians.
      try { entry.child?.stdin.end(); } catch {}
    };
    entry.poison = poison; entry.denyLaunch = denyLaunch;
    try { entry.child = this.spawnChild(`${PF_INSTALL_ROOT}/envara-pf-native`, ['app-tunnel-bootstrap', runId, environmentId], {
      shell: false, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' }, stdio: ['pipe', 'pipe', 'pipe'],
    }); } catch { poison(); throw failure('APPLICATION_ROUTING_UNAVAILABLE'); }
    let pending = Buffer.alloc(0), count = 0;
    entry.child.stderr.on('data', () => {}); entry.child.stdin.on('error', poison); entry.child.once('error', poison);
    entry.child.stdout.on('data', data => {
      pending = Buffer.concat([pending, data]); entry.pendingBytes = pending.length; if (pending.length > 16384) return poison();
      let newline;
      while (!entry.uncertain && (newline = pending.indexOf(10)) >= 0) {
        const line = pending.subarray(0, newline); pending = pending.subarray(newline + 1); entry.pendingBytes = pending.length;
        try {
          const event = JSON.parse(line.toString('utf8'));
          if (line.toString('utf8') !== JSON.stringify(event)) throw new Error();
          if (++count > 64 || !event || event.ready !== false || event.protected !== false || event.runId !== runId || event.environmentId !== environmentId ||
              ![PF_APP_TRANSPORT_SCHEMA, PF_APP_KEEPER_SCHEMA].includes(event.schema)) throw new Error();
          if (entry.abortReceipt || entry.preflightAbortReceipt) throw new Error();
          if (event.schema === PF_APP_TRANSPORT_SCHEMA && event.event === 'transport-refused') {
            const expected = ['schema', 'event', 'runId', 'environmentId', 'stage', 'reason', 'error', 'ready', 'protected'];
            if (Object.keys(event).sort().join('|') !== expected.sort().join('|') || !APP_NATIVE_STAGES.has(event.stage) || event.stage === 'register' || !APP_NATIVE_FAILURE_REASONS.has(event.reason) ||
                !Number.isInteger(event.error) || event.error < 1 || event.error > 1024) throw new Error();
            if (entry.failure && entry.cleanupOnly && (entry.stoppingRequested || entry.releasing)) {
              entry.cleanupFailure = Object.freeze({ stage: event.stage, reason: event.reason, error: event.error }); denyLaunch(); continue;
            }
            if (entry.failure || entry.phase !== 'starting' &&
                (!['transport-started', 'stopped'].includes(entry.phase) || !APP_ACTIVE_NATIVE_FAILURE_STAGES.has(event.stage))) throw new Error();
            entry.failure = Object.freeze({ stage: event.stage, reason: event.reason, error: event.error });
            if (!['factory-open', 'preflight'].includes(event.stage)) {
              // A well-formed refusal burns launch authority without burning
              // this original custodian's narrowly scoped cleanup channel.
              // No resource is called absent until its own terminal proof.
              if (entry.phase === 'starting' && !['deny-commit', 'transport-ack'].includes(event.stage)) { poison(); break; }
              entry.cleanupOnly = true;
              if (entry.phase !== 'starting') denyLaunch();
              continue;
            }
            // Commands remain burned; only the fixed independent abort terminal
            // may follow this diagnostic within the original startup deadline.
            entry.refusalPending = true; continue;
          }
          if (entry.cleanupOnly) {
            if (event.schema !== PF_APP_TRANSPORT_SCHEMA || !['transport-cleanup-ready', 'transport-cleanup-stopping', 'transport-released'].includes(event.event)) {
              // Late launch ACKs cannot revive a refused run. A valid bound
              // old ACK is ignored; unknown output still poisons the channel.
              if (event.schema === PF_APP_KEEPER_SCHEMA && ['stopped', 'resumed'].includes(event.event) &&
                  event.ticketId === entry.ticketId && event.registrationId === entry.registrationId && event.versionId === entry.versionId &&
                  event.keeperPID === entry.ack?.keeperPID && Object.keys(event).sort().join('|') === APP_KEEPER_REPORT_KEYS &&
                  APP_KEEPER_REPORT_BOOLEANS.every(key => typeof event[key] === 'boolean') && event.profile === 'seatbelt-front-only' &&
                  event.pid === entry.stoppedIdentity?.pid && event.birth === entry.stoppedIdentity?.birth) continue;
              throw new Error();
            }
            if (event.event === 'transport-cleanup-ready' && (entry.phase !== 'starting' || !entry.failure ||
                event.stage !== entry.failure.stage || event.cleanupOnly !== true)) throw new Error();
          }
          if (entry.refusalPending) {
            if (entry.failure.stage === 'preflight') {
              // Fixed native output is canonical JSON. In particular, duplicate
              // keys must not turn a contradictory refusal into a valid proof.
              if (line.toString('utf8') !== JSON.stringify(event)) throw new Error();
              entry.preflightAbortReceipt = validatePFApplicationPreflightAbort(event, binding, entry.child.pid, entry.bootstrapIdentity);
              entry.phase = 'preflight-abort-receipt';
            } else {
              entry.abortReceipt = validatePFApplicationPrestageAbort(event, binding, entry.bootstrapIdentity);
              entry.phase = 'prestage-abort-receipt';
            }
          } else if (['prestage-aborted', 'preflight-aborted'].includes(event.event)) throw new Error();
          if (event.schema === PF_APP_KEEPER_SCHEMA) {
            const boundKeeper = event.ticketId === entry.ticketId && event.registrationId === entry.registrationId &&
              event.versionId === entry.versionId && event.keeperPID === entry.ack?.keeperPID;
            // Capture only the first exact stopped child. It also binds a
            // revocation arriving in the same chunk as the stopped ACK.
            if (!entry.stoppedIdentity && event.event === 'stopped' && boundKeeper &&
                Number.isSafeInteger(event.pid) && event.pid > 1 && nativeBirth(event.birth))
              entry.stoppedIdentity = Object.freeze({ pid: event.pid, birth: event.birth });
            if (APP_KEEPER_RESUME_NEGATIVE_EVENTS.has(event.event) && entry.stoppedIdentity && !entry.stoppingRequested &&
                !entry.releasing && ['transport-started', 'stopped'].includes(entry.phase)) {
              if (!boundKeeper || Object.keys(event).sort().join('|') !== APP_KEEPER_REPORT_KEYS ||
                  APP_KEEPER_REPORT_BOOLEANS.some(key => typeof event[key] !== 'boolean') || event.profile !== 'seatbelt-front-only' ||
                  event.pid !== entry.stoppedIdentity.pid || event.birth !== entry.stoppedIdentity.birth) throw new Error();
              // This is refusal evidence only. Preserve the original channel
              // solely for exact cleanup, and never admit a late resume ACK.
              entry.events.push(event); entry.resumeRefused = true;
              entry.waitFailure = 'APPLICATION_APP_RESUME_UNCONFIRMED'; denyLaunch(); continue;
            }
          }
          entry.events.push(event);
          for (const waiter of [...entry.waiters]) if (waiter.predicate(event)) {
            // A delayed event loop must not turn an expired ACK into success.
            if (Date.now() >= waiter.deadline) { entry.waitFailure = waiter.timeoutCode; poison(); break; }
            entry.waiters.splice(entry.waiters.indexOf(waiter), 1); clearTimeout(waiter.timer); waiter.resolve(event);
          }
        } catch { poison(); }
      }
    });
    entry.child.once('close', (code, signal) => {
      entry.exited = true; entry.exitCode = code; entry.exitSignal = signal;
      if (entry.phase === 'prestage-abort-receipt' && entry.abortReceipt && code === 1 && signal === null && pending.length === 0 && !entry.uncertain) entry.phase = 'prestage-aborted';
      else if (entry.phase === 'preflight-abort-receipt' && entry.preflightAbortReceipt && code === 1 && signal === null && pending.length === 0 && !entry.uncertain) entry.phase = 'preflight-aborted';
      else if (code !== 0 || entry.phase !== 'released' || pending.length !== 0 || signal != null) poison();
    });
    entry.wait = (predicate, timeoutMs = 15000, timeoutCode = null) => new Promise((resolve, reject) => {
      if (entry.uncertain) return reject(transportError());
      const limit = entry.phase === 'starting' || entry.refusalPending ? Math.max(1, Math.min(timeoutMs, entry.deadline - Date.now())) : timeoutMs;
      const waiter = { predicate, resolve, reject, timer: null, deadline: Date.now() + limit, timeoutCode };
      waiter.timer = setTimeout(() => { entry.waitFailure = timeoutCode; poison(); }, limit); entry.waiters.push(waiter);
    });
    try { entry.bootstrapIdentity = await this.identify(entry.child.pid); }
    catch { entry.bootstrapIdentityUnavailable = true; }
    if (entry.bootstrapIdentity && (entry.bootstrapIdentity.pid !== entry.child.pid || entry.bootstrapIdentity.parentPid !== lease.controllerPid || !nativeBirth(entry.bootstrapIdentity.birth) ||
        [entry.bootstrapIdentity.uid, entry.bootstrapIdentity.realUID, entry.bootstrapIdentity.savedUID].some(uid => uid !== 0) ||
        ![`${PF_INSTALL_ROOT}/envara-pf-native`, '/bin/launchctl'].includes(entry.bootstrapIdentity.path))) { poison(); throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED'); }
    const startup = event => event.schema === PF_APP_TRANSPORT_SCHEMA && ['transport-started', 'transport-cleanup-ready', 'prestage-aborted', 'preflight-aborted'].includes(event.event);
    const captured = entry.events.find(startup);
    const waiting = captured ? Promise.resolve(captured) : entry.wait(startup);
    if (entry.bootstrapIdentity && !entry.refusalPending && !entry.exited) entry.child.stdin.write(`${JSON.stringify(upstream)}\n`);
    const ack = await waiting;
    if (ack.event === 'preflight-aborted') {
      if (!entry.exited) await new Promise((resolve, reject) => {
        const timer = setTimeout(() => { poison(); reject(transportError()); }, Math.max(1, Math.min(3000, entry.deadline - Date.now())));
        entry.child.once('close', () => { clearTimeout(timer); !entry.uncertain && entry.phase === 'preflight-aborted' ? resolve() : reject(transportError()); });
      });
      try { await this.confirmApplicationPreflightAborted(runId); }
      catch { poison(); throw transportError(); }
      throw Object.assign(transportError(), { preflightAborted: true });
    }
    if (!entry.bootstrapIdentity) { poison(); throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED'); }
    if (ack.event === 'prestage-aborted') {
      if (!entry.exited) await new Promise((resolve, reject) => {
        const timer = setTimeout(() => { poison(); reject(transportError()); }, Math.max(1, Math.min(3000, entry.deadline - Date.now())));
        entry.child.once('close', () => { clearTimeout(timer); !entry.uncertain && entry.phase === 'prestage-aborted' ? resolve() : reject(transportError()); });
      });
      try { await this.confirmApplicationPrestageAborted(runId); }
      catch { poison(); throw transportError(); }
      throw Object.assign(transportError(), { prestageAborted: true });
    }
    const cleanupReady = ack.event === 'transport-cleanup-ready';
    const startedKeys = ['schema', 'event', 'runId', 'environmentId', 'interfaceName', 'corePID', 'coreBirth', 'frontPID', 'frontBirth', 'frontPort', 'keeperPID', 'ownsOriginalUTunFD', 'ownsOriginalListenerFD', 'ready', 'protected',
      ...(cleanupReady ? ['stage', 'cleanupOnly'] : [])];
    if (!Number.isSafeInteger(ack.keeperPID) || ack.keeperPID < 2 || !/^utun[0-9]{1,7}$/.test(ack.interfaceName ?? '') || ack.ownsOriginalUTunFD !== true || ack.ownsOriginalListenerFD !== true ||
        Object.keys(ack).sort().join('|') !== startedKeys.sort().join('|') ||
        !Number.isSafeInteger(ack.frontPort) || ack.frontPort < 1 || ack.frontPort > 65535 ||
        ['corePID', 'frontPID'].some(key => !Number.isSafeInteger(ack[key]) || ack[key] < 2) || !nativeBirth(ack.coreBirth) || !nativeBirth(ack.frontBirth)) { poison(); throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED'); }
    let keeper, core, front, bootstrap;
    try { [keeper, core, front, bootstrap] = await Promise.all([this.identify(ack.keeperPID), this.identify(ack.corePID), this.identify(ack.frontPID), this.identify(entry.child.pid)]); }
    catch { poison(); throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED'); }
    const lineageVerified = keeper.pid === entry.child.pid ? keeper.birth === entry.bootstrapIdentity.birth && keeper.parentPid === lease.controllerPid :
      keeper.parentPid === entry.child.pid && bootstrap.parentPid === lease.controllerPid && bootstrap.birth === entry.bootstrapIdentity.birth && bootstrap.path === '/bin/launchctl';
    if (keeper.path !== `${PF_INSTALL_ROOT}/envara-pf-native` || keeper.uid !== 0 || keeper.realUID !== 0 || keeper.savedUID !== 0 ||
        !lineageVerified || bootstrap.uid !== 0 || bootstrap.realUID !== 0 || bootstrap.savedUID !== 0 || !nativeBirth(keeper.birth) ||
        core.birth !== ack.coreBirth || core.parentPid !== keeper.pid || core.path !== `${PF_INSTALL_ROOT}/mihomo` || front.birth !== ack.frontBirth || front.parentPid !== keeper.pid || front.path !== `${PF_INSTALL_ROOT}/node` ||
        [core, front].some(identity => identity.uid !== 0 || identity.realUID !== 0 || identity.savedUID !== 0)) { poison(); throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED'); }
    try { await this.verifyApplicationLease(runId); }
    catch { poison(); throw failure('APPLICATION_APP_CONTEXT_REFUSED'); }
    entry.ack = Object.freeze({ ...ack, keeperBirth: keeper.birth }); entry.phase = cleanupReady ? 'cleanup-ready' : 'transport-started';
    if (cleanupReady) throw Object.assign(transportError(), { cleanupAvailable: true });
    return { ...entry.ack, ...appFlags() };
  }
  async applicationTransportControl(runId, command, ticketId = null) {
    const entry = this.appTransports.get(runId);
    if (!entry || entry.uncertain || entry.refusalPending || entry.exited || !entry.ack || !['L', 'K', 'S', 'R', 'B'].includes(command) ||
        entry.cleanupOnly && !['S', 'R'].includes(command) || command === 'R' && (!entry.stoppingRequested || entry.phase !== 'stopping') ||
        command === 'L' && (!uuid(ticketId) || entry.ticketId))
      throw failure(command === 'B' && entry?.resumeRefused ? 'APPLICATION_APP_RESUME_UNCONFIRMED' : 'APPLICATION_APP_TRANSPORT_UNCONFIRMED');
    let keeper;
    try { await this.verifyApplicationLease(runId); keeper = await this.identify(entry.ack.keeperPID); }
    catch { entry.poison(); throw failure(command === 'B' && entry.resumeRefused ? 'APPLICATION_APP_RESUME_UNCONFIRMED' : 'APPLICATION_APP_TRANSPORT_UNCONFIRMED'); }
    if (entry.uncertain || entry.cleanupOnly && !['S', 'R'].includes(command)) throw failure(command === 'B' && entry.resumeRefused ? 'APPLICATION_APP_RESUME_UNCONFIRMED' : 'APPLICATION_APP_TRANSPORT_UNCONFIRMED');
    if (keeper.birth !== entry.ack.keeperBirth || keeper.path !== `${PF_INSTALL_ROOT}/envara-pf-native`) { entry.poison(); throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED'); }
    let expected;
    if (command === 'L') { entry.ticketId = ticketId; expected = 'stopped'; }
    if (command === 'B') { if (entry.resumeAttempted || entry.phase !== 'stopped') throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED'); entry.resumeAttempted = true; expected = 'resumed'; }
    if (command === 'S') { entry.stoppingRequested = true; expected = 'stopping'; }
    if (command === 'R') { entry.releasing = true; expected = 'released'; }
    const waiting = expected ? entry.wait(event => command === 'R' ? event.schema === PF_APP_TRANSPORT_SCHEMA && event.event === 'transport-released' :
      command === 'S' && entry.cleanupOnly ? event.schema === PF_APP_TRANSPORT_SCHEMA && event.event === 'transport-cleanup-stopping' :
      event.schema === PF_APP_KEEPER_SCHEMA && event.event === expected && event.ticketId === entry.ticketId,
      command === 'L' ? PF_APP_COLD_STAGE_TIMEOUT_MS : command === 'B' ? PF_APP_RESUME_TIMEOUT_MS : 15000,
      command === 'L' ? 'APPLICATION_APP_STAGE_TIMEOUT' : command === 'B' ? 'APPLICATION_APP_RESUME_TIMEOUT' : null) : null;
    entry.child.stdin.write(`${command}${command === 'L' ? ` ${ticketId}` : ''}\n`);
    if (!waiting) return { acknowledged: false, ...appFlags() };
    const event = await waiting;
    if (entry.uncertain) throw failure(command === 'B' && entry.resumeRefused ? 'APPLICATION_APP_RESUME_UNCONFIRMED' : 'APPLICATION_APP_TRANSPORT_UNCONFIRMED');
    if (command === 'S' && entry.cleanupOnly) {
      const keys = ['schema', 'event', 'runId', 'environmentId', 'keeperPID', 'keeperBirth', 'childReaped', 'childAbsent', 'scopeQuiescentObserved', 'persistentDenyObserved', 'ready', 'protected'];
      if (Object.keys(event).sort().join('|') !== keys.sort().join('|') || event.keeperBirth !== entry.ack.keeperBirth ||
          ['scopeQuiescentObserved', 'persistentDenyObserved'].some(key => event[key] !== true) ||
          typeof event.childReaped !== 'boolean' || typeof event.childAbsent !== 'boolean' || event.childReaped === event.childAbsent) {
        entry.poison(); throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED');
      }
    }
    if (command === 'R') {
      const keys = ['schema', 'event', 'runId', 'environmentId', 'keeperPID', 'ready', 'protected', 'childAbsent', ...APP_RELEASE_FACTS];
      if (Object.keys(event).sort().join('|') !== keys.sort().join('|') || !appReleasedFactsVerified(event)) {
        entry.poison(); throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED');
      }
    }
    if (event.keeperPID !== entry.ack.keeperPID || command !== 'R' && !entry.cleanupOnly && (event.registrationId !== entry.registrationId || event.versionId !== entry.versionId) ||
        ['L', 'S'].includes(command) && event.persistentDenyObserved !== true) { entry.poison(); throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED'); }
    entry.phase = command === 'R' ? 'released' : expected;
    return structuredClone(event);
  }
  applicationCleanupAvailable(runId) {
    const entry = this.appTransports.get(runId);
    return !!entry && entry.cleanupOnly === true && !!entry.ack && !entry.uncertain && !entry.refusalPending && !entry.exited;
  }
  applicationChannelTermination(runId) {
    const entry = this.appTransports.get(runId);
    if (!entry) return null;
    return { exited: entry.exited === true,
      exitCode: Number.isInteger(entry.exitCode) && entry.exitCode >= 0 && entry.exitCode <= 255 ? entry.exitCode : null,
      exitSignal: ['SIGHUP', 'SIGINT', 'SIGQUIT', 'SIGILL', 'SIGABRT', 'SIGKILL', 'SIGSEGV', 'SIGPIPE', 'SIGALRM', 'SIGTERM', 'SIGBUS'].includes(entry.exitSignal) ? entry.exitSignal : null,
      transportAckVerified: !!entry.ack, stoppedIdentityRecorded: !!entry.stoppedIdentity, resumeAttempted: entry.resumeAttempted === true,
      launchAuthorityBurned: entry.cleanupOnly === true || entry.uncertain === true || entry.refusalPending === true,
      channelPoisoned: entry.uncertain === true };
  }
  async confirmApplicationTransportExited(runId) {
    const entry = this.appTransports.get(runId);
    if (!entry || entry.uncertain || entry.phase !== 'released') throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED');
    if (!entry.exited) await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { entry.poison(); reject(failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED')); }, 3000);
      entry.child.once('close', code => { clearTimeout(timer); code === 0 && !entry.uncertain ? resolve() : reject(failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED')); });
    });
    if (!entry.exited || entry.exitCode !== 0 || entry.uncertain) throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED');
    return true;
  }
  async persistRun(run) {
    if (!this.lock || !uuid(run.runId) || run.runId !== this.runtimeRunId) throw failure('APPLICATION_ROUTING_NOT_READY');
    await this.assertRuntimeRootHeld();
    if (this.registryUnlinkAttempted || this.lockUnlinkAttempted) throw failure('APPLICATION_ROUTING_NOT_READY');
    const currentLock = await this.fs.lstat(`${PF_RUNTIME_ROOT}/registry.lock`), heldLock = await this.lock.stat();
    if (!currentLock.isFile() || currentLock.isSymbolicLink() || currentLock.uid !== 0 || (currentLock.mode & 0o077) ||
        currentLock.dev !== heldLock.dev || currentLock.ino !== heldLock.ino) throw failure('APPLICATION_ROUTING_NOT_READY');
    const destination = `${PF_RUNTIME_ROOT}/registry.json`, temporary = `${PF_RUNTIME_ROOT}/registry_${randomUUID()}.tmp`;
    try {
      const existing = await this.fs.lstat(destination);
      if (!existing.isFile() || existing.isSymbolicLink() || existing.uid !== 0 || (existing.mode & 0o077) ||
          !this.registryIdentity || existing.dev !== this.registryIdentity.dev || existing.ino !== this.registryIdentity.ino) throw failure('APPLICATION_ROUTING_NOT_READY');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    const record = { schema: 'envara.macos-pf-owned-registry/v1', runId: run.runId, supervisorPid: process.pid,
      anchor: pfRoutingAnchor(run.runId), phase: run.phase, cleanupUncertain: run.cleanupUncertain === true,
      rootHook: { mutationAttempted: run.rootHookMutationAttempted === true, verified: run.rootHookVerified === true,
        removed: run.ownedRootHookRemoved === true, receiptRetired: run.rootHookReceiptRetired === true, namespaceState: run.namespaceState ?? 'unknown', namespaceReclaimed: run.namespaceReclaimed === true, lease: run.rootHookLease ?? null },
      ownedPFReference: { attempted: run.pfReferenceAttempted === true, acquired: run.pfReferenceAcquired === true,
        released: run.ownedPFReferenceReleased === true, token: this.pfToken },
      filterReplacement: run.filterReplacement ?? null, filterReceipt: run.filterReceipt ?? null,
      ...(run.kind === 'application' ? { application: { environmentId: run.environmentId, routeId: run.routeId,
        registrationId: run.registrationId ?? null, versionId: run.versionId ?? null, ticketId: run.ticketId ?? null,
        leaseSHA256: run.leaseSHA256 ?? null, transport: run.transport ?? null, child: run.applicationChild ?? null,
        ...(run.prestageAbort ? { prestageAbort: run.prestageAbort } : {}),
        ...(run.preflightAbort ? { preflightAbort: run.preflightAbort } : {}),
        initialFailure: projectAppFailure(run.initialFailure), cleanupFailure: projectAppFailure(run.cleanupFailure),
        cleanupStepCompletions: run.appCleanupSteps ? Object.fromEntries(['stoppingConfirmed', 'transportReleased', 'transportExited',
          'referenceReleased', 'hookRetired', 'groupsRemoved', 'leaseRetired'].map(key => [key, run.appCleanupSteps[key] === true])) : null,
        channelTermination: this.applicationChannelTermination(run.runId),
        ownedResourcesReclaimed: run.ownedResourcesReclaimed === true,
        foreignStateDrift: run.foreignStateDrift ? Object.fromEntries(['pf', 'routes', 'dns', 'aggregate'].map(key => [key, run.foreignStateDrift[key] === true])) : null,
        resumed: run.resumed === true } } : {}),
      incompleteGroupAllocations: [...this.groupIntents].map(([groupPath, gid]) => ({ groupPath, gid })),
      realms: run.realms.map(realm => ({ environmentId: realm.environmentId, realmId: realm.realmId, gid: realm.gid,
        groupPath: realm.groupPath, ...(typeof realm.generatedUID === 'string' && /^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$/.test(realm.generatedUID) ? { generatedUID: realm.generatedUID } : {}), mode: realm.mode, tunnel: realm.tunnel,
        fixtures: (realm.fixtures ?? []).map(fixture => ({ pid: fixture.pid, birth: fixture.birth, role: fixture.role, guardianKey: fixture.guardianKey })) })),
      guardians: [...this.guardians.values()].map(entry => ({ key: entry.key, kind: entry.kind, guardianPid: entry.child?.pid,
        pid: entry.pid ?? null, birth: entry.birth ?? null, interfaceName: entry.interfaceName ?? null, exited: entry.exited })) };
    const handle = await this.fs.open(temporary, 'wx', 0o600);
    let written;
    try { await handle.writeFile(JSON.stringify(record)); await handle.sync(); written = await handle.stat(); } finally { await handle.close(); }
    await this.fs.rename(temporary, destination);
    const committed = await this.fs.lstat(destination);
    if (!committed.isFile() || committed.isSymbolicLink() || committed.uid !== 0 || (committed.mode & 0o077) ||
        committed.dev !== written.dev || committed.ino !== written.ino) throw failure('APPLICATION_ROUTING_NOT_READY');
    this.registryIdentity = { dev: committed.dev, ino: committed.ino };
    await this.runtimeDirectory.sync();
  }
  async startTunnelCore({ runId, realmId, config, ipv4Address }) {
    if (config?.tun?.['file-descriptor'] !== 3 || config.tun['auto-route'] !== false || config.tun['auto-redirect'] !== false ||
        config.tun['auto-detect-interface'] !== false || net.isIP(ipv4Address) !== 4 || !/^198\.18\.[1-2]\.1$/.test(ipv4Address)) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    const proxy = config.proxies?.[0];
    const local = validateManagedProxy({ host: proxy?.server, port: proxy?.port, username: proxy?.username, password: proxy?.password });
    const stateDirectory = await this.createRunDirectory(runId, realmId);
    const key = `tun_${randomUUID().replaceAll('-', '')}`;
    const { entry, result } = await this.openGuardian(['tunnel-core', '--core', `${PF_INSTALL_ROOT}/mihomo`,
      '--state-dir', stateDirectory, '--ipv4', ipv4Address], { key, kind: 'tunnel',
      firstLine: { ...local, udpPolicy: proxy.udp === true ? 'proxy' : 'block' } });
    const pid = result.corePid ?? result.pid;
    if (!/^utun[0-9]{1,6}$/.test(result.interfaceName ?? '') || !Number.isInteger(pid) || pid < 2 || typeof result.birth !== 'string' ||
        result.ownsOriginalFD !== true) { entry.uncertain = true; throw failure('APPLICATION_ROUTING_NOT_READY'); }
    const actual = await this.identify(pid);
    if (actual.birth !== result.birth || actual.uid !== 0 || actual.realUID !== 0 || actual.savedUID !== 0 ||
        actual.path !== `${PF_INSTALL_ROOT}/mihomo`) { entry.uncertain = true; throw failure('APPLICATION_ROUTING_NOT_READY'); }
    entry.pid = pid; entry.birth = result.birth; entry.interfaceName = result.interfaceName;
    return { interfaceName: result.interfaceName, pid, coreBirth: result.birth, instanceId: key, ipv4Address,
      guardianPid: entry.child.pid, fdRetained: true };
  }
  async launchFixture({ runId, realmId, uid, gid }) {
    if (!Number.isInteger(uid) || uid < 1 || !Number.isInteger(gid) || gid < 7100 || gid > 7999) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    await this.createRunDirectory(runId, realmId);
    // Transport state is root:0700; a console user's child cannot use it as
    // cwd. The fixed root:0755 fixture directory supplies a read-only cwd.
    const directory = `${PF_INSTALL_ROOT}/fixtures`, key = `fixture_${randomUUID().replaceAll('-', '')}`;
    const { entry, result } = await this.openGuardian(['launch-fixture', '--uid', String(uid), '--gid', String(gid),
      '--cwd', directory, '--executable', `${PF_INSTALL_ROOT}/fixtures/EnvaraRoutingAcceptanceFixture`], { key, kind: 'fixture' });
    if (result.phase !== 'suspended' || !Number.isInteger(result.pid) || result.pid < 2 || typeof result.birth !== 'string' ||
        result.uid !== uid || result.gid !== gid) throw failure('APPLICATION_ROUTING_NOT_READY');
    entry.pid = result.pid; entry.birth = result.birth; this.fixtureGuardians.set(realmId, entry);
    return [{ role: 'parent', pid: result.pid, birth: result.birth, gid, suspended: true, guardianKey: key }];
  }
  async resumeOwnedFixtures(realm) {
    for (const fixture of realm.fixtures) {
      const entry = this.guardians.get(fixture.guardianKey);
      if (!entry || entry.exited || entry.kind !== 'fixture' || entry.pid !== fixture.pid || entry.birth !== fixture.birth) throw failure('APPLICATION_ROUTING_NOT_READY');
      const current = await this.identify(entry.pid);
      if (current.birth !== entry.birth || current.gid !== realm.gid) throw failure('APPLICATION_ROUTING_NOT_READY');
      entry.child.stdin.write('RESUME\n'); fixture.suspended = false;
    }
  }
  transactFixture(realm, fixture, request, timeoutMs = 15000) {
    const parent = realm.fixtures.find(item => item.role === 'parent'), entry = parent && this.guardians.get(parent.guardianKey);
    if (!entry || entry.exited || entry.uncertain || !uuid(request.id) || Buffer.byteLength(JSON.stringify(request)) > 16384) return Promise.reject(failure('APPLICATION_ROUTING_NOT_READY'));
    const execute = () => new Promise((resolve, reject) => {
      if (entry.exited || entry.uncertain) { reject(failure('APPLICATION_PF_FIXTURE_REPLY_REFUSED')); return; }
      const command = fixture.role === 'parent' ? request : { id: request.id, op: 'child_probe', pid: fixture.pid,
        request: Object.fromEntries(Object.entries(request).filter(([key]) => key !== 'id')) };
      const consume = result => {
        clearTimeout(timer);
        try {
          if (typeof result.payload !== 'string' || Buffer.byteLength(result.payload) > 16384) throw new Error();
          const response = JSON.parse(result.payload);
          if (response.id !== request.id || response.pid !== parent.pid || typeof response.ok !== 'boolean') throw new Error();
          if (response.ok === false) throw fixtureFailure(response.code);
          const body = fixture.role === 'parent' ? response : response.childResult;
          if (!body || body.ok !== true || (fixture.role === 'child' && (body.id !== request.id || body.pid !== fixture.pid))) {
            if (fixture.role === 'child' && body?.id === request.id && body.pid === fixture.pid && body.ok === false) throw fixtureFailure(body.code);
            throw new Error();
          }
          resolve(body);
        } catch (error) { reject(/^APPLICATION_PF_FIXTURE_[A-Z_]+$/.test(error?.code ?? '') ? error : failure('APPLICATION_PF_FIXTURE_REPLY_REFUSED')); }
      };
      const timer = setTimeout(() => { entry.uncertain = true; reject(failure('APPLICATION_PF_FIXTURE_RPC_TIMEOUT')); }, timeoutMs);
      entry.responses ??= []; entry.responses.push(consume);
      entry.child.stdin.write(`PROBE ${Buffer.from(JSON.stringify(command)).toString('base64')}\n`);
    });
    const result = (entry.transactions ?? Promise.resolve()).then(execute); entry.transactions = result.catch(() => {}); return result;
  }
  async discoverFixtureChildren(realm) {
    const parent = realm.fixtures.find(fixture => fixture.role === 'parent');
    const spawned = await this.transactFixture(realm, parent, { id: randomUUID(), op: 'spawn_child' });
    const pid = spawned.childPID;
    if (!Number.isInteger(pid) || pid < 2) throw failure('APPLICATION_ROUTING_NOT_READY');
    const actual = await this.identify(pid);
    if (actual.parentPid !== parent.pid || actual.gid !== realm.gid || actual.realGID !== realm.gid || actual.savedGID !== realm.gid ||
        actual.uid !== realm.consoleUID || actual.realUID !== realm.consoleUID || actual.savedUID !== realm.consoleUID ||
        actual.path !== `${PF_INSTALL_ROOT}/fixtures/EnvaraRoutingAcceptanceFixture`) throw failure('APPLICATION_ROUTING_NOT_READY');
    realm.fixtures.push({ role: 'child', pid, birth: actual.birth, gid: realm.gid, suspended: false, guardianKey: parent.guardianKey });
  }
  async reserveFixtureTuples(run) {
    run.reservations = [];
    for (const realm of run.realms) for (const fixture of realm.fixtures) for (const caseId of run.caseIds) {
      const target = CASE_TARGETS[caseId]; if (!target) continue;
      const response = await this.transactFixture(realm, fixture, { id: randomUUID(), op: 'reserve', ...target, timeoutMs: 3000 });
      if (response.bound !== true || response.connected !== false || response.packetsSent !== 0 || !uuid(response.reservationId) ||
          response.protocol !== target.protocol || response.remoteHost !== target.host || response.remotePort !== target.port ||
          response.localHost !== '0.0.0.0' || !Number.isInteger(response.localPort) || response.localPort < 1024 || response.localPort > 65535) throw failure('APPLICATION_ROUTING_NOT_READY');
      run.reservations.push({ ...target, localPort: response.localPort, reservationId: response.reservationId, caseId,
        realmId: realm.realmId, role: fixture.role, pid: fixture.pid, birth: fixture.birth, consumed: false,
        expiresAtNanoseconds: response.expiresAtNanoseconds, receivedAtNanoseconds: process.hrtime.bigint() });
    }
    if (!run.reservations.length && run.caseIds.some(caseId => caseId !== 'realm-identities')) throw failure('APPLICATION_ROUTING_NOT_READY');
    await this.confirmReservedStatesAbsent(run);
    return { source: 'native-pf', freshTuplesVerified: run.reservations.length > 0, noExistingOwnedStatesVerified: true,
      noStateRulesVerified: true, denyBeforeResumeVerified: true };
  }
  async confirmReservedStatesAbsent(run) {
    const states = (await this.command('/sbin/pfctl', ['-ss'])).stdout;
    // Match the entire documentation-only destination set, independent of
    // source address/port. This is conservative and covers the wildcard bind
    // address before connect chooses the physical source address. Never kill
    // or mutate a matching state owned by another application.
    for (const target of FIXTURE_DESTINATIONS) {
      const host = target.host.replaceAll('.', '\\.');
      for (const port of target.ports) if (new RegExp(`(?:^|[\\s(])${host}[.:]${port}(?:[\\s)]|$)`, 'm').test(states)) throw failure('APPLICATION_ROUTING_NOT_READY');
    }
    run.stateChecks ??= []; run.stateChecks.push({ at: Date.now(), digest: digest(states), reservedDestinationsAbsent: true });
    return true;
  }
  async terminateOwnedFixtures(run) {
    for (const realm of run.realms) {
      const parent = realm.fixtures?.find(fixture => fixture.role === 'parent');
      if (parent && parent.suspended === false) {
        try { await this.transactFixture(realm, parent, { id: randomUUID(), op: 'stop' }, 5000); } catch {}
      }
      for (const fixture of realm.fixtures ?? []) {
        const entry = this.guardians.get(fixture.guardianKey);
        if (entry && !entry.exited && !entry.child.stdin.writableEnded) entry.child.stdin.end('TERMINATE\n');
      }
    }
    await this.waitGuardians(run.realms.flatMap(realm => realm.fixtures ?? []).map(fixture => fixture.guardianKey));
  }
  async waitGuardians(keys, timeoutMs = 5000) {
    const pending = keys.map(key => this.guardians.get(key)).filter(entry => entry && !entry.exited);
    await Promise.all(pending.map(entry => new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(failure('APPLICATION_ROUTING_TIMEOUT')), timeoutMs);
      entry.child.once('close', () => { clearTimeout(timer); resolve(); });
    })));
  }
  async fixtureIdentity(realm, fixture) {
    const actual = await this.identify(fixture.pid);
    if (actual.birth !== fixture.birth || [actual.uid, actual.realUID, actual.savedUID].some(value => value !== realm.consoleUID) ||
        [actual.gid, actual.realGID, actual.savedGID].some(value => value !== realm.gid) || actual.path !== `${PF_INSTALL_ROOT}/fixtures/EnvaraRoutingAcceptanceFixture`) throw failure('APPLICATION_ROUTING_NOT_READY');
    return actual;
  }
  async runFixtureCase({ run, input }) {
    if (run.stateless !== true || !run.caseIds.includes(input.caseId)) throw failure('APPLICATION_ROUTING_NOT_READY');
    const checkpoint = async (stage, operation) => {
      try { return await operation(); } catch (error) {
        // Only fixed stages/codes are retained. Never copy a request, raw error,
        // endpoint, payload, process identity or proxy credential to diagnostics.
        if (!run.caseFailure) run.caseFailure = { caseId: input.caseId, stage, code: cleanError(error) };
        throw failure(cleanError(error));
      }
    };
    await checkpoint('state-before', () => this.confirmReservedStatesAbsent(run));
    const ruleObservation = await checkpoint('rule-readback', () => this.verifyInstalledStatelessRules(createStatelessFixturePFRoutingPolicy(
      run.realms.map(realm => ({ environmentId: realm.environmentId, gid: realm.gid, mode: realm.mode, udpPolicy: realm.udpPolicy, tunnel: realm.tunnel })),
      { fixtureDestinations: FIXTURE_DESTINATIONS, runId: run.runId })));
    for (const realm of run.realms) for (const fixture of realm.fixtures) await checkpoint('process-before', () => this.fixtureIdentity(realm, fixture));
    const evidence = { source: 'native-pf', platform: 'darwin', complete: true, freshTuplesVerified: true,
      noExistingMatchingStatesVerified: true, noStateRulesVerified: ruleObservation.noStateRulesVerified,
      stateScope: 'selected-fixture-route-states', productionReady: false };
    if (input.caseId === 'realm-identities') return { complete: true, evidence: { ...evidence, threeGIDsVerified: true, coldExecVerified: true } };
    const target = CASE_TARGETS[input.caseId];
    await checkpoint('challenge-validation', async () => {
      if (!target || !Array.isArray(input.challenges) || input.challenges.length !== run.realms.reduce((sum, realm) => sum + realm.fixtures.length, 0)) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    });
    const seen = new Set();
    const probeResults = await Promise.allSettled(input.challenges.map(async challenge => {
      let stage = 'challenge-validation';
      try {
        const realm = run.realms.find(value => value.slot === challenge?.slot), fixture = realm?.fixtures.find(value => value.role === challenge?.role);
        const reservation = run.reservations.find(value => value.realmId === realm?.realmId && value.role === challenge?.role && value.caseId === input.caseId && value.consumed === false);
        const request = challenge?.request, key = `${challenge?.slot}/${challenge?.role}`;
        if (!realm || !fixture || !reservation || seen.has(key) || !uuid(challenge.id) || request?.id !== challenge.id || request.op !== target.protocol ||
            request.host !== target.host || request.port !== target.port || typeof request.payloadBase64 !== 'string' || request.payloadBase64.length > 5464 ||
            !Number.isInteger(request.timeoutMs) || request.timeoutMs < 200 || request.timeoutMs > 5000 ||
            (request.halfClose !== undefined && typeof request.halfClose !== 'boolean') || target.protocol === 'udp' && request.halfClose === true) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
        stage = 'reservation';
        // Swift and Node monotonic clocks need not share an epoch. Locally keep
        // reservations at most 45 seconds; the fixture enforces its own 60-second
        // TTL and consumes the actual descriptor only once.
        if (!/^[0-9]{1,20}$/.test(reservation.expiresAtNanoseconds ?? '') ||
            process.hrtime.bigint() - reservation.receivedAtNanoseconds > 45_000_000_000n) throw failure('APPLICATION_ROUTING_NOT_READY');
        const payload = Buffer.from(request.payloadBase64, 'base64');
        if (payload.length < 1 || payload.length > 4096 || payload.toString('base64') !== request.payloadBase64) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
        seen.add(key); reservation.consumed = true;
        stage = 'probe-transport';
        const result = await this.transactFixture(realm, fixture, { id: challenge.id, op: 'probe_reserved', reservationId: reservation.reservationId,
          payloadBase64: request.payloadBase64, halfClose: request.halfClose ?? false, timeoutMs: request.timeoutMs }, request.timeoutMs + 1500);
        stage = 'probe-binding';
        if (result.reservationId !== reservation.reservationId || result.localPort !== reservation.localPort || result.consumed !== true ||
            result.usedReservedSocket !== true || result.protocol !== target.protocol || result.remoteHost !== target.host || result.remotePort !== target.port ||
            result.sourceAddressResolved !== true || result.sourceWildcard !== false || net.isIP(result.localHost) !== 4 || result.localHost === '0.0.0.0') throw failure('APPLICATION_ROUTING_NOT_READY');
        stage = 'process-after';
        await this.fixtureIdentity(realm, fixture);
        return { slot: realm.slot, role: fixture.role, fixture: { pid: fixture.pid, birth: fixture.birth, gid: realm.gid }, result };
      } catch (error) {
        if (!run.caseFailure) run.caseFailure = { caseId: input.caseId, stage, code: cleanError(error) };
        throw failure(cleanError(error));
      }
    }));
    // A failed parent probe must not leave a queued child probe running while
    // cleanup starts. Await every transaction that this case already issued.
    const rejected = probeResults.find(result => result.status === 'rejected');
    if (rejected) throw rejected.reason;
    const probes = probeResults.map(result => result.value);
    await checkpoint('state-after', () => this.confirmReservedStatesAbsent(run));
    const exactProcessAttribution = probes.every(probe => probe.result.pid === probe.fixture.pid);
    if (input.caseId === 'tcp-concurrent' || input.caseId === 'udp-concurrent') {
      const intervals = probes.map(probe => {
        const start = probe.result.startedAtNanoseconds, end = probe.result.finishedAtNanoseconds;
        if (!/^[0-9]{1,20}$/.test(start ?? '') || !/^[0-9]{1,20}$/.test(end ?? '')) return null;
        return { slot: probe.slot, start: BigInt(start), end: BigInt(end) };
      });
      const overlapVerified = intervals.every(Boolean) && intervals.some((first, index) => intervals.slice(index + 1).some(second =>
        first.slot !== second.slot && first.start < second.end && second.start < first.end));
      return { complete: true, probes, evidence: { ...evidence, exactProcessAttribution, overlapVerified } };
    }
    if (input.caseId === 'tcp-half-close') {
      const finished = probes.every(probe => probe.result.ok === true && probe.result.eof === true && probe.result.halfClose === true && probe.result.matches === true && probe.result.receivedBytes === probe.result.sentBytes);
      return { complete: true, probes, evidence: { ...evidence, upstreamFINObserved: finished, readDirectionPreserved: finished,
        upstreamEvidence: 'sealed-fin-only-fixture-response; acceptance runner must also match authenticated server receipt' } };
    }
    return { complete: true, probes, evidence: { ...evidence, exactProcessAttribution, realTCP53Observed: probes.every(probe => probe.result.sentBytes > 2 && probe.result.eof === true),
      ownAuthenticatedRouteObserved: true } };
  }
  async stopOwnedTunnel(tunnel) {
    const entry = this.guardians.get(tunnel.instanceId);
    if (!entry || entry.kind !== 'tunnel' || entry.pid !== tunnel.pid || entry.birth !== tunnel.coreBirth || entry.interfaceName !== tunnel.interfaceName || entry.exited) throw failure('APPLICATION_ROUTING_NOT_READY');
    entry.releasing = true; entry.child.stdin.end('RELEASE\n'); await this.waitGuardians([entry.key]);
  }
  assertBoundPolicy(policy) {
    if (!uuid(policy?.runId) || policy.runId !== this.runtimeRunId || policy.anchor !== this.ownedAnchor() ||
        typeof policy.rules !== 'string' || policy.rules.length > 512 * 1024) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    return policy.anchor;
  }
  filterSpecification(policy, run) {
    this.assertBoundPolicy(policy);
    if (!run || run.runId !== policy.runId || run.lockAcquired !== true || run.rootHookVerified !== true ||
        !Array.isArray(run.realms) || run.realms.length > 2 || JSON.stringify(validatePFRootHookLease(run.rootHookLease, run.runId)) !== JSON.stringify(this.rootHookLease)) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    const canonical = policy.fixtureOnly === true ? createStatelessFixturePFRoutingPolicy(policy.routes, { fixtureDestinations: FIXTURE_DESTINATIONS, runId: policy.runId }) : createPFRoutingPolicy(policy.routes, { runId: policy.runId });
    if (canonical.rules !== policy.rules) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    const mode = canonical.routes.length === 0 ? 'empty' : canonical.routes.every(route => route.mode === 'blocked') ? 'deny' :
      policy.fixtureOnly === true && canonical.routes.every(route => route.mode === 'routed') ? 'routed' : null;
    if (!mode || mode !== 'empty' && canonical.routes.length !== run.realms.length) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    const realms = canonical.routes.map(route => {
      const realm = run.realms.find(value => value.environmentId === route.environmentId);
      if (!uuid(route.environmentId) || !realm || realm.gid !== route.gid || realm.udpPolicy !== route.udpPolicy || realm.mode !== route.mode) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
      let tunnel = null;
      if (mode === 'routed') {
        const value = realm.tunnel;
        if (!value || !/^utun(?:0|[1-9][0-9]{0,5})$/.test(value.interfaceName ?? '') || !/^198\.18\.[1-2]\.1$/.test(value.ipv4Address ?? '') ||
            !Number.isSafeInteger(value.pid) || value.pid < 2 || value.pid > 0x7fffffff || !Number.isSafeInteger(value.guardianPid) || value.guardianPid < 2 || value.guardianPid > 0x7fffffff ||
            !/^[0-9]{1,20}:[0-9]{6}$/.test(value.coreBirth ?? '') || !validId(value.instanceId) || value.fdRetained !== true || realm.tunnelRemoved === true ||
            ['interfaceName', 'ipv4Address', 'pid', 'instanceId'].some(key => value[key] !== route.tunnel?.[key])) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
        tunnel = Object.fromEntries(['interfaceName', 'ipv4Address', 'pid', 'coreBirth', 'guardianPid', 'instanceId', 'fdRetained'].map(key => [key, value[key]]));
      }
      return { environmentId: route.environmentId, gid: route.gid, udpPolicy: route.udpPolicy, tunnel };
    });
    const semantics = expectedStatelessFixtureRuleSemantics(createStatelessFixturePFRoutingPolicy(canonical.routes, { fixtureDestinations: FIXTURE_DESTINATIONS, runId: run.runId }));
    return { next: { mode, realms }, ruleCount: semantics.length };
  }
  async replaceOwnedRules(policy, run) {
    const { next, ruleCount } = this.filterSpecification(policy, run);
    if (this.filterReplacementBusy || this.filterReplacementUncertain || run.filterReplacement?.state === 'pending' || run.filterReplacement?.state === 'uncertain') throw failure('APPLICATION_PF_FILTER_REPLACEMENT_UNCERTAIN');
    if (run.filterReplacement && (run.filterReplacement.state !== 'committed' || !this.filterCommitted ||
        JSON.stringify(run.filterReplacement.next) !== JSON.stringify({ mode: this.filterCommitted.mode, realms: this.filterCommitted.realms }))) throw failure('APPLICATION_PF_FILTER_REPLACEMENT_UNCERTAIN');
    const previous = structuredClone(this.filterCommitted ?? { mode: 'empty', realms: [], writerPid: 0, filterRevision: null });
    const generation = randomUUID();
    const intent = { schema: PF_FILTER_REPLACEMENT_SCHEMA, generation, state: 'pending', previous, next };
    const request = { schema: PF_FILTER_REPLACEMENT_SCHEMA, runId: run.runId, generation, lease: structuredClone(this.rootHookLease), previous, next };
    this.filterReplacementBusy = true; run.filterReplacement = structuredClone(intent);
    try {
      // Seal the exact private intent before spawning the fixed native writer.
      // No pfctl load, text fallback, or retry may replace an uncertain write.
      await this.persistRun(run);
      const result = await this.command(`${PF_INSTALL_ROOT}/envara-pf-native`, ['replace-owned-filter'], `${JSON.stringify(request)}\n`, 15000,
        { cancelSignal: 'SIGTERM', captureHookFailure: true });
      let value; try {
        if (Buffer.byteLength(result.stdout) > 16384) throw new Error(); value = JSON.parse(result.stdout);
      } catch { throw failure('APPLICATION_PF_FILTER_REPLACEMENT_UNCONFIRMED'); }
      if (value?.schema !== PF_FILTER_REPLACEMENT_SCHEMA || value.operation !== 'replace-owned-filter' || value.runId !== run.runId ||
          value.generation !== generation || value.mode !== next.mode) throw failure('APPLICATION_PF_FILTER_REPLACEMENT_UNCONFIRMED');
      if (result.exitCode !== 0 || value.ok !== true) throw privateFilterFailure(value.reason);
      if (value.reason !== 'GENERATED_SINGLE_FILTER_VERIFIED' || value.readOnly !== false || value.fixtureOnly !== true || value.productionReady !== false || value.protected !== false || value.nativeAcceptance !== false ||
          value.replacementAttempted !== true || value.replacementUncertain !== false || value.rulesVerified !== true || value.poolsVerified !== true || value.ruleCount !== ruleCount ||
          !Number.isSafeInteger(value.writerPid) || value.writerPid < 2 || value.writerPid > 0x7fffffff || value.writerPid !== result.processPid || !uint32String(value.filterRevision) ||
          value.globalTemporaryPoolBufferReset !== (ruleCount > 0) || ['foreignPoolConcurrencyExcluded', 'kernelIoctlHardDeadline', 'changesOtherRuleClasses', 'PFEnable', 'statesCleared'].some(key => value[key] !== false)) throw failure('APPLICATION_PF_FILTER_REPLACEMENT_UNCONFIRMED');
      const receipt = { schema: PF_FILTER_REPLACEMENT_SCHEMA, generation, mode: next.mode, ruleCount, writerPid: value.writerPid, filterRevision: value.filterRevision };
      run.filterReceipt = receipt; run.filterReplacement = { ...intent, state: 'committed' };
      await this.persistRun(run);
      this.filterCommitted = { ...structuredClone(next), writerPid: receipt.writerPid, filterRevision: receipt.filterRevision };
      return { rulesVerified: true, poolsVerified: true, ruleCount, fixtureOnly: true, productionReady: false, nativeAcceptance: false };
    } catch (error) {
      this.filterReplacementUncertain = true; run.cleanupUncertain = true;
      run.filterReplacement = { ...intent, state: 'uncertain' };
      try { await this.persistRun(run); } catch {}
      throw failure(cleanError(error));
    } finally { this.filterReplacementBusy = false; }
  }
  async verifyInstalledStatelessRules(policy) {
    const anchor = this.assertBoundPolicy(policy);
    if (policy.fixtureOnly !== true) throw failure('APPLICATION_ROUTING_NOT_READY');
    const actual = (await this.command('/sbin/pfctl', ['-a', anchor, '-sr'])).stdout;
    try { return verifyStatelessFixtureRuleReadback(policy, actual); }
    catch { throw failure('APPLICATION_ROUTING_NOT_READY'); }
  }
  async enableOwnedReference() {
    if (!this.rootHookLease) throw failure('APPLICATION_ROUTING_NOT_READY');
    const proof = await this.inspectOwnedRootHook(this.rootHookLease);
    if (proof.priorAnchorsCompatible !== true) throw failure('APPLICATION_ROUTING_NOT_READY');
    const existingStates = await this.command('/sbin/pfctl', ['-ss']);
    if (existingStates.stdout.trim()) throw failure('APPLICATION_ROUTING_NOT_READY');
    this.pfReferenceMutationAttempted = true;
    const result = await this.command('/sbin/pfctl', ['-E']);
    const token = /Token\s*:\s*([0-9]{1,20})/i.exec(`${result.stdout}\n${result.stderr}`)?.[1];
    // No token means the reference cannot be safely released; refuse use.
    if (!token) throw failure('APPLICATION_ROUTING_NOT_READY');
    this.pfToken = token;
    return { existingForeignPFStatesAbsentBeforeEnable: true };
  }
  async confirmOwnedReferenceReleased() {
    if (!this.pfReferenceReleaseAttempted || !this.rootHookLease) throw failure('APPLICATION_ROUTING_NOT_READY');
    const status = await this.readHookStatus({ lease: this.rootHookLease });
    if (status.pfDisabled !== true) throw failure('APPLICATION_ROUTING_NOT_READY');
    this.pfToken = null; this.pfReferenceReleased = true;
    return true;
  }
  async releaseOwnedReference() {
    // A lost -X reply never grants another mutation using the same token.
    // This bounded experiment starts with PF disabled; a fresh disabled status
    // can reconcile the issued release, otherwise it remains unknown.
    if (this.pfReferenceReleaseAttempted) return this.confirmOwnedReferenceReleased();
    if (!this.pfToken) {
      if (this.pfReferenceMutationAttempted) throw failure('APPLICATION_ROUTING_NOT_READY');
      return;
    }
    this.pfReferenceReleaseAttempted = true;
    await this.command('/sbin/pfctl', ['-X', this.pfToken]);
    this.pfToken = null; this.pfReferenceReleased = true;
  }
  async identify(pid) {
    const response = await this.command(`${PF_INSTALL_ROOT}/envara-pf-native`, ['identity', '--pid', String(pid)]);
    let identity; try { identity = JSON.parse(response.stdout); } catch { throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR'); }
    if (identity?.ok !== true) throw failure('APPLICATION_ROUTING_NOT_READY');
    return identity;
  }
  async clearExactOwnedStates(run) {
    if (run?.stateless !== true) throw failure('APPLICATION_ROUTING_NOT_READY', 'Exact owned PF state cleanup is unverified');
    await this.confirmReservedStatesAbsent(run);
    run.noOwnedStatesRemainVerified = true;
  }
  async assertNoOwnedGroupProcesses(realms) {
    const output = await this.command('/bin/ps', ['-axo', 'pid=,uid=,gid=']);
    const gids = new Set(realms.map(realm => realm.gid));
    for (const line of output.stdout.split('\n').filter(line => line.trim())) {
      const fields = /^\s*([0-9]+)\s+([0-9]+)\s+([0-9]+)\s*$/.exec(line);
      if (!fields || fields.slice(1).some(value => !Number.isSafeInteger(Number(value))) || Number(fields[1]) < 1 || gids.has(Number(fields[3]))) throw failure('APPLICATION_ROUTING_NOT_READY');
    }
    return true;
  }
  async removeGroups(realms) {
    await this.assertNoOwnedGroupProcesses(realms);
    for (const realm of realms) {
      const present = await this.ownedGroupPresent(realm.groupPath, realm.gid);
      if (!present) {
        if (realm.groupRemoved !== true && !this.groupDeleteIntents.has(realm.groupPath)) throw failure('APPLICATION_ROUTING_NOT_READY');
        this.groups.delete(realm.groupPath); realm.groupRemoved = true; continue;
      }
      if (realm.groupRemoved === true || this.groups.get(realm.groupPath) !== realm.gid) throw failure('APPLICATION_ROUTING_NOT_READY');
      const original = this.groupIdentities.get(realm.groupPath), current = await this.readOwnedGroupIdentity(realm.groupPath, realm.gid);
      if (!original || current.generatedUID !== original.generatedUID || current.gid !== original.gid) throw failure('APPLICATION_ROUTING_NOT_READY');
      this.groupDeleteIntents.add(realm.groupPath);
      await this.command('/usr/bin/dscl', ['.', '-delete', realm.groupPath]);
      if (await this.ownedGroupPresent(realm.groupPath, realm.gid)) throw failure('APPLICATION_ROUTING_NOT_READY');
      this.groups.delete(realm.groupPath); realm.groupRemoved = true;
    }
  }
  async readOwnedGroupIdentity(groupPath, gid) {
    const { stdout } = await this.command('/usr/bin/dscl', ['.', '-read', groupPath, 'GeneratedUID', 'PrimaryGroupID']);
    const fields = stdout.trim().split('\n'), values = new Map();
    for (const line of fields) {
      const match = /^(GeneratedUID|PrimaryGroupID): ([A-Za-z0-9-]+)$/.exec(line);
      if (!match || values.has(match[1])) throw failure('APPLICATION_ROUTING_NOT_READY'); values.set(match[1], match[2]);
    }
    if (values.size !== 2 || !/^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$/.test(values.get('GeneratedUID') ?? '') || values.get('PrimaryGroupID') !== String(gid)) throw failure('APPLICATION_ROUTING_NOT_READY');
    return Object.freeze({ generatedUID: values.get('GeneratedUID').toUpperCase(), gid });
  }
  async ownedGroupPresent(groupPath, gid) {
    const { stdout } = await this.command('/usr/bin/dscl', ['.', '-list', '/Groups', 'PrimaryGroupID']);
    let present = false;
    for (const line of stdout.split('\n').filter(value => value.trim())) {
      const match = /^\s*(\S+)\s+([0-9]+)\s*$/.exec(line);
      if (!match) throw failure('APPLICATION_ROUTING_NOT_READY');
      if (`/Groups/${match[1]}` === groupPath) {
        if (present || Number(match[2]) !== gid) throw failure('APPLICATION_ROUTING_NOT_READY'); present = true;
      }
    }
    return present;
  }
  assertNoUnassignedGuardians(run) {
    const assigned = new Set(run.realms.flatMap(realm => [realm.tunnel?.instanceId,
      ...(realm.fixtures ?? []).map(fixture => fixture.guardianKey)]).filter(Boolean));
    if ([...this.guardians.values()].some(entry => !entry.exited && !assigned.has(entry.key))) throw failure('APPLICATION_ROUTING_NOT_READY');
    const groups = new Map(run.realms.map(realm => [realm.groupPath, realm.gid]));
    if (this.groupIntents.size || [...this.groups].some(([name, gid]) => groups.get(name) !== gid)) throw failure('APPLICATION_ROUTING_NOT_READY');
  }
  async releaseLock() {
    if (!this.lock) return;
    await this.assertRuntimeRootHeld();
    const held = await this.lock.stat();
    let lockPresent = true;
    try {
      const current = await this.fs.lstat(`${PF_RUNTIME_ROOT}/registry.lock`);
      if (!current.isFile() || current.isSymbolicLink() || current.uid !== 0 || (current.mode & 0o077) || current.dev !== held.dev || current.ino !== held.ino) throw failure('APPLICATION_ROUTING_UNAVAILABLE');
    } catch (error) { if (error.code !== 'ENOENT' || !this.lockUnlinkAttempted) throw error; lockPresent = false; }
    let registryPresent = true;
    try {
      const registry = await this.fs.lstat(`${PF_RUNTIME_ROOT}/registry.json`);
      if (!registry.isFile() || registry.isSymbolicLink() || registry.uid !== 0 || (registry.mode & 0o077) ||
          !this.registryIdentity || registry.dev !== this.registryIdentity.dev || registry.ino !== this.registryIdentity.ino) throw failure('APPLICATION_ROUTING_UNAVAILABLE');
    } catch (error) { if (error.code !== 'ENOENT' || this.registryIdentity && !this.registryUnlinkAttempted) throw error; registryPresent = false; }
    const permitted = new Set(['registry.lock', 'registry.json', ...[...this.runDirectories.keys()].map(directory => directory.slice(PF_RUNTIME_ROOT.length + 1).split('/')[0])]);
    if ((await this.fs.readdir(PF_RUNTIME_ROOT)).some(name => !permitted.has(name))) throw failure('APPLICATION_ROUTING_UNAVAILABLE');
    // Remove only tracked, empty directories belonging to this exact run.
    // Unknown core files or crash leftovers retain the registry and lock.
    for (const directory of [...this.runDirectories.keys()].sort((a, b) => b.length - a.length)) {
      const handle = this.runDirectories.get(directory);
      await this.inspectRuntimeDirectory(directory, handle, true);
      await this.fs.rmdir(directory); await handle.close(); this.runDirectories.delete(directory);
    }
    if (registryPresent) { this.registryUnlinkAttempted = true; await this.fs.unlink(`${PF_RUNTIME_ROOT}/registry.json`); }
    if (lockPresent) { this.lockUnlinkAttempted = true; await this.fs.unlink(`${PF_RUNTIME_ROOT}/registry.lock`); }
    // Reconcile exact held-inode deletion and flush the same directory before
    // dropping the custody handles. Failed unlink/fsync can be retried without
    // accepting a replacement file or pretending unknown entries are ours.
    for (const filename of ['registry.json', 'registry.lock']) {
      try { await this.fs.lstat(`${PF_RUNTIME_ROOT}/${filename}`); throw failure('APPLICATION_ROUTING_UNAVAILABLE'); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    await this.runtimeDirectory.sync(); await this.lock.close(); this.lock = null;
    await this.runtimeDirectory.close(); this.runtimeDirectory = null;
    await this.runtimeParent.close(); this.runtimeParent = null; this.runtimeRunId = null; this.registryIdentity = null;
  }
}

/** The default executable path remains non-production. Tests may inject an
 * OS executor to verify ordering, but no injected observation opens protected
 * launches or writes a production acceptance receipt. */
export class MacOSPFController {
  constructor({ executor = new MacOSPFExecutor(), inspectInstallation = verifyPFInstallation, inspectBundledComponent = inspectPFBundledComponent,
    authenticateProxy = authenticateManagedProxy, identity = { uid: process.getuid?.() ?? -1, euid: process.geteuid?.() ?? -1 },
    onEvent = () => {}, applicationCommands = null } = {}) {
    this.executor = executor; this.inspectInstallation = inspectInstallation; this.inspectBundledComponent = inspectBundledComponent; this.authenticateProxy = authenticateProxy;
    this.identity = identity; this.onEvent = onEvent; this.routes = new Map(); this.runs = new Map(); this.usedRunIds = new Set();
    this.queue = Promise.resolve(); this.closed = false;
    this.applicationCommands = applicationCommands; this.appRuns = new Map();
    this.executor.onFault = event => { this.handleTransportFault(event).catch(() => {}); };
  }
  serialized(operation) { const result = this.queue.then(operation); this.queue = result.catch(() => {}); return result; }
  assertOpen() { if (this.closed) throw failure('APPLICATION_ROUTING_CLOSED'); }
  async state({ runId } = {}) {
    const [installation, operatingSystem] = await Promise.all([this.inspectInstallation(), this.executor.readOnlyStatus(runId ? { runId } : {})]);
    const bundled = installation.verified === true ? null : await this.inspectBundledComponent();
    const privileged = this.identity.uid === 0 && this.identity.euid === 0;
    const privilegedRuntimeVerified = privileged && installation.verified === true && installation.runtimeVerified === true;
    const callerVerified = this.identity.controlledSession === true && this.identity.callerUID === operatingSystem.consoleUID && Number.isSafeInteger(operatingSystem.consoleUID) && operatingSystem.consoleUID > 0;
    return { installation, operatingSystem, bundled, privilegedRuntimeVerified, authorized: privilegedRuntimeVerified && callerVerified };
  }
  async status(input = {}) {
    this.assertOpen();
    if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => key !== 'runId') || Object.hasOwn(input, 'runId') && !uuid(input.runId)) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    const state = await this.state(input).catch(() => ({ installation: {}, operatingSystem: {}, authorized: false }));
    return { platform: 'darwin', backend: 'pf-utun', component: { name: 'envara-pf-routing', version: '1',
      available: state.installation.available === true || state.bundled?.available === true,
      verified: state.installation.verified === true || state.bundled?.verified === true, installed: state.installation.verified === true },
      installed: state.installation.verified === true, authorized: state.authorized, authorization: { kind: 'privileged-helper', verified: state.authorized },
      ready: false, protectedLaunchAllowed: false, processScopeVerified: false, capabilities: checks(),
      verification: { backend: 'pf-utun', native: false, passed: false, version: 'pf/1', checks: checks() },
      gates: Object.fromEntries(PF_ROUTING_GATES.map(key => [key, false])),
      rootOwnedInstallationVerified: state.installation.verified === true,
      callerConsoleUIDVerified: state.authorized, privilegedOperationsAuthorized: state.authorized,
      privilegedRuntimeVerified: state.privilegedRuntimeVerified === true,
      fixtureOperations: state.operatingSystem.fixtureOperations ?? [], exactStateCleanupSupported: state.operatingSystem.exactStateCleanupSupported === true,
      acceptanceOnly: true, productionReceiptAllowed: false, readOnly: true,
      acceptanceProtocol: 'envara-pf-acceptance/v1', anchor: input.runId ? pfRoutingAnchor(input.runId) : null, namespacePrefix: PF_ROUTING_NAMESPACE, freshNamespaceRequired: true,
      stockAppleAnchorHookVerified: state.operatingSystem.pf?.stockAppleAnchorHook === true,
      ownedRootHookCanCreate: state.authorized === true && state.operatingSystem.ownedRootHook?.canCreateOwnedHook === true &&
        state.operatingSystem.ownedRootHook?.pfDisabled === true && state.operatingSystem.ownedRootHook?.pinsVerified === true &&
        state.operatingSystem.ownedRootHook?.originalRootCompatible === true,
      ownedRootHookVerified: state.authorized === true && state.operatingSystem.ownedRootHook?.ownedRootHookVerified === true,
      priorPFAnchorsCompatible: state.operatingSystem.pf?.priorAnchorsCompatible === true,
      fixtureEgressSkipVerified: state.operatingSystem.pf?.fixtureEgressSkipVerified === true,
      lo0SkipVerified: state.operatingSystem.pf?.lo0SkipVerified === true,
      lo0Skipped: typeof state.operatingSystem.pf?.lo0Skipped === 'boolean' ? state.operatingSystem.pf.lo0Skipped : null,
      lo0FilteringVerified: state.operatingSystem.pf?.lo0FilteringVerified === true,
      exactStateCleanupVerified: false, independentPacketObserverVerified: false,
      statelessControlledFixtures: state.operatingSystem.statelessControlledFixtures === true,
      noStateNativeAvailable: state.operatingSystem.noStateNativeAvailable === true,
      routes: [...this.routes.values()].map(route => this.publicRoute(route)),
      runs: [...this.runs.values()].map(run => ({ runId: run.runId, phase: run.phase, cleanupUncertain: run.cleanupUncertain === true, caseFailure: caseFailure(run) })),
      applications: [...this.appRuns.values()].map(run => this.publicApplication(run)),
      reason: state.installation.reason ?? 'Native application-family, DNS, state-cleanup and whole-guard acceptance remain unverified' };
  }
  async setup() { return { ...(await this.status()), readOnly: true, installationPlan: pfInstallationPlan(), activated: false }; }
  async plan() { return this.setup(); }
  async acceptancePlan() { return { ...diagnosticFlags(), readOnly: true, installationPlan: pfInstallationPlan(), ...(await this.status()) }; }
  publicRoute(route) {
    return { routeId: route.routeId, profileId: route.application.profileId, applicationIdentity: route.application.identity ?? null,
      routeIdentity: route.managedRoute?.routeIdentity ?? null, coreGeneration: route.managedRoute?.coreGeneration ?? null,
      nodeType: route.managedRoute?.nodeType ?? null, managedRouteVerified: false, consoleUID: route.consoleUID ?? null,
      gid: null, prepared: true, ready: false, failClosed: false, guardArmed: false,
      capabilities: checks(), verification: { backend: 'pf-utun', native: false, passed: false, version: 'pf/1', checks: checks() } };
  }
  prepareRoute(input = {}) {
    return this.serialized(async () => {
      this.assertOpen();
      const { application, workspace, route, managedRoute } = input;
      if (!validId(application?.id) || !validId(application?.profileId) || !absolute(application?.executablePath) || !absolute(workspace?.cwd) ||
          !route || route.protocol !== 'socks5' || !['block', 'proxy'].includes(route.udpPolicy) ||
          !managedRoute || managedRoute.profileId !== application.profileId || !validId(managedRoute.proxyId) ||
          !validId(managedRoute.nodeType) || !uuid(managedRoute.routeIdentity) || !uuid(managedRoute.coreGeneration) ||
          !Number.isSafeInteger(managedRoute.corePid) || managedRoute.corePid < 2 || managedRoute.coreVersion !== 'v1.19.32') throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
      let proxy; try { proxy = validateManagedProxy(route); await this.authenticateProxy(proxy); } catch { throw failure('APPLICATION_PROXY_UNAVAILABLE'); }
      const status = await this.executor.readOnlyStatus().catch(() => ({}));
      const selected = { routeId: `pf_${randomUUID().replaceAll('-', '')}`, application: structuredClone(application), workspace: structuredClone(workspace),
        managedRoute: structuredClone(managedRoute), proxy, udpPolicy: route.udpPolicy, consoleUID: status.consoleUID, active: true };
      this.routes.set(selected.routeId, selected);
      // Authentication proves this private listener, not its owner process,
      // TUN capture, DNS isolation, or native application acceptance.
      return this.publicRoute(selected);
    });
  }
  async launch() { this.assertOpen(); throw failure('APPLICATION_ROUTING_NOT_READY'); }
  async start() { return this.launch(); }
  publicApplication(run) {
    return { ...appFlags(), runId: run.runId, environmentId: run.environmentId, routeId: run.routeId,
      phase: run.phase, staged: run.staged === true, resumed: run.resumed === true,
      prestageAborted: run.prestageAbort != null,
      preflightAborted: run.preflightAbort != null,
      cleanupUncertain: run.cleanupUncertain === true, cleanupComplete: appCleanPhase(run.phase) && run.cleanupUncertain === false,
      failure: projectAppFailure(run.initialFailure),
      initialFailure: projectAppFailure(run.initialFailure),
      cleanupFailure: projectAppFailure(run.cleanupFailure),
      cleanupEvidence: appCleanPhase(run.phase) && run.cleanupUncertain === false && run.cleanupEvidence ? structuredClone(run.cleanupEvidence) : null };
  }
  applicationSnapshot(input = {}) {
    this.assertOpen();
    if (!input || Object.keys(input).sort().join('|') !== 'runId' || !uuid(input.runId) || !this.appRuns.has(input.runId)) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    return this.publicApplication(this.appRuns.get(input.runId));
  }
  prepareNotionApplication(input = {}) {
    return this.serialized(async () => {
      this.assertOpen();
      if (!input || Object.keys(input).sort().join('|') !== ['routeId', 'runId', 'environmentId', 'lifetimeSeconds', 'activationAuthorized'].sort().join('|') ||
          !validId(input.routeId) || !uuid(input.runId) || !uuid(input.environmentId) || !Number.isInteger(input.lifetimeSeconds) || input.lifetimeSeconds < 10 || input.lifetimeSeconds > 180) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
      if (input.activationAuthorized !== true) throw failure('APPLICATION_ROUTING_AUTHORIZATION_REQUIRED');
      const selected = this.routes.get(input.routeId);
      if (!selected?.active || !selected.proxy || ![NOTION_BUNDLE, `${NOTION_BUNDLE}/Contents/MacOS/Notion`].includes(selected.application.executablePath) ||
          !absolute(selected.workspace.cwd) || typeof selected.workspace.timezone !== 'string' || typeof selected.workspace.locale !== 'string' || this.usedRunIds.size) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
      const state = await this.state({ runId: input.runId });
      if (!state.authorized) throw failure('APPLICATION_ROUTING_AUTHORIZATION_REQUIRED');
      if (state.operatingSystem.ownedRootHook?.canCreateOwnedHook !== true || state.operatingSystem.ownedRootHook?.pfDisabled !== true ||
          state.operatingSystem.ownedRootHook?.pinsVerified !== true || state.operatingSystem.ownedRootHook?.originalRootCompatible !== true ||
          state.operatingSystem.pf?.lo0SkipVerified !== true || state.operatingSystem.noStateNativeAvailable !== true) throw failure('APPLICATION_ROUTING_NOT_READY');
      for (const method of ['applicationContextClock', 'sealApplicationLease', 'verifyApplicationLease', 'startApplicationTransport', 'applicationTransportControl',
        'confirmApplicationTransportExited', 'retireApplicationLease']) if (typeof this.executor[method] !== 'function') throw failure('APPLICATION_ROUTING_NOT_READY');
      await this.authenticateProxy(selected.proxy);
      const managedIdentity = await this.executor.identify(selected.managedRoute.corePid);
      if (!nativeBirth(managedIdentity.birth) || managedIdentity.path !== `${PF_INSTALL_ROOT}/mihomo` &&
          !managedIdentity.path?.endsWith('/proxy-core/mihomo') || managedIdentity.uid !== state.operatingSystem.consoleUID) throw failure('APPLICATION_PROXY_UNAVAILABLE');
      const run = { kind: 'application', runId: input.runId, environmentId: input.environmentId, routeId: input.routeId,
        native: this.executor.kind === 'native',
        phase: 'preparing', stage: 'register', realms: [], stateless: true, cleanupUncertain: false,
        lockAcquired: false, rootHookMutationAttempted: false, rootHookVerified: false, rootHookLease: null,
        pfReferenceAttempted: false, pfReferenceAcquired: false, resumed: false, staged: false };
      run.managedIdentity = { pid: selected.managedRoute.corePid, ...managedIdentity };
      this.usedRunIds.add(run.runId); this.appRuns.set(run.runId, run);
      try {
        if (!this.applicationCommands) { const { NativeApplicationCommands } = await import('./helper-production-native.mjs');
          this.applicationCommands = new NativeApplicationCommands({ controlledSession: this.identity.controlledSession === true, inspectInstallation: this.inspectInstallation }); }
        run.registrationId = randomUUID(); run.versionId = randomUUID(); run.ticketId = randomUUID();
        const registered = await this.applicationCommands.register({ registrationId: run.registrationId, versionId: run.versionId, bundlePath: NOTION_BUNDLE });
        if (registered?.applicationIdentityVerified !== true || registered.registrationId !== run.registrationId || registered.versionId !== run.versionId) throw failure('APPLICATION_APP_IDENTITY_REFUSED');
        run.stage = 'registry-lock'; await this.executor.acquireLock(run.runId); run.lockAcquired = true;
        run.baseline = await this.executor.snapshotUnrelatedNetwork();
        run.stage = 'root-hook'; run.rootHookMutationAttempted = true; await this.executor.persistRun(run);
        run.rootHookLease = validatePFRootHookLease(await this.executor.installOwnedRootHook(run.runId), run.runId); run.rootHookVerified = true;
        await this.executor.persistRun(run); await this.executor.requireEmptyOwnedAnchor();
        run.stage = 'group-allocation'; const group = await this.executor.allocateGroup(run.environmentId);
        const realm = { ...group, environmentId: run.environmentId, realmId: randomUUID(), mode: 'blocked',
          consoleUID: state.operatingSystem.consoleUID, udpPolicy: 'block', tunnel: null, fixtures: [] };
        run.realms.push(realm); await this.executor.persistRun(run);
        run.stage = 'sealed-context';
        const [clock, controller] = await Promise.all([this.executor.applicationContextClock(), this.executor.identify(process.pid)]);
        if (!nativeBirth(controller.birth) || controller.uid !== 0 || controller.realUID !== 0 || controller.savedUID !== 0 || controller.path !== `${PF_INSTALL_ROOT}/node`) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
        const sealed = validatePFAppBoundLease({ schema: PF_APP_BOUND_LEASE_SCHEMA, runId: run.runId, environmentId: run.environmentId, realmId: realm.realmId,
          leaseId: randomUUID(), generation: randomUUID(), registrationId: run.registrationId, versionId: run.versionId,
          consoleUID: realm.consoleUID, gid: realm.gid, cwd: selected.workspace.cwd, timezone: selected.workspace.timezone, locale: selected.workspace.locale,
          issuedMonotonicMs: clock.nowMonotonicMilliseconds, expiresMonotonicMs: clock.nowMonotonicMilliseconds + input.lifetimeSeconds * 1000,
          bootTimeSeconds: clock.bootTimeSeconds, controllerPid: process.pid, controllerBirth: controller.birth,
          ipv4Address: '198.18.1.1', rootHookLease: run.rootHookLease });
        const lease = await this.executor.sealApplicationLease(sealed);
        if (!/^[0-9a-f]{64}$/.test(lease.leaseSHA256 ?? '')) throw failure('APPLICATION_APP_CONTEXT_REFUSED'); run.leaseSHA256 = lease.leaseSHA256;
        await this.executor.persistRun(run);
        run.stage = 'pf-reference'; run.pfReferenceAttempted = true; await this.executor.persistRun(run);
        const enabled = await this.executor.enableOwnedReference(); run.pfReferenceAcquired = true;
        if (enabled?.existingForeignPFStatesAbsentBeforeEnable !== true) throw failure('APPLICATION_ROUTING_NOT_READY'); await this.executor.persistRun(run);
        run.stage = 'transport';
        run.transport = await this.executor.startApplicationTransport({ runId: run.runId, environmentId: run.environmentId,
          proxy: selected.proxy, udpPolicy: 'block', leaseSHA256: run.leaseSHA256, consoleUID: realm.consoleUID });
        await this.executor.persistRun(run);
        const coreNow = await this.executor.identify(selected.managedRoute.corePid);
        if (coreNow.birth !== managedIdentity.birth || coreNow.path !== managedIdentity.path || coreNow.uid !== managedIdentity.uid) throw failure('APPLICATION_PROXY_UNAVAILABLE');
        run.stage = 'cold-stage';
        const staged = await this.executor.applicationTransportControl(run.runId, 'L', run.ticketId);
        if (staged.stoppedBeforeExec !== true || staged.persistentDenyObserved !== true || !nativeBirth(staged.birth) || !Number.isSafeInteger(staged.pid) || staged.pid < 2) throw failure('APPLICATION_APP_STAGE_UNCONFIRMED');
        run.applicationChild = { pid: staged.pid, birth: staged.birth }; run.staged = true; run.phase = 'staged'; await this.executor.persistRun(run);
        run.heartbeat = setInterval(() => { this.serialized(async () => {
          if (['staged', 'running'].includes(run.phase)) await this.executor.applicationTransportControl(run.runId, 'K');
        }).catch(error => this.serialized(async () => {
          clearInterval(run.heartbeat); rememberAppFailure(run, 'resume', error);
          run.cleanupUncertain = true; run.phase = 'cleanup-required';
          if (this.executor.applicationCleanupAvailable?.(run.runId) === true) run.cleanupMode = 'native-refusal';
          else this.executor.appTransports?.get(run.runId)?.poison?.();
          try { await this.executor.persistRun(run); } catch (persistError) { rememberAppFailure(run, 'cleanup', persistError, true); }
        }).catch(() => {})); }, 1000); run.heartbeat.unref?.();
        const now = await this.executor.applicationContextClock();
        if (now.bootTimeSeconds !== sealed.bootTimeSeconds || now.nowMonotonicMilliseconds >= sealed.expiresMonotonicMs - 1000) throw failure('APPLICATION_APP_CONTEXT_REFUSED');
        run.timer = setTimeout(() => this.stopNotionApplication({ runId: run.runId }).catch(() => {}), sealed.expiresMonotonicMs - now.nowMonotonicMilliseconds - 1000); run.timer.unref?.();
        return this.publicApplication(run);
      } catch (error) {
        run.cleanupUncertain = true; run.phase = 'cleanup-required'; rememberAppFailure(run, run.stage, error);
        if (run.stage === 'transport' && error.preflightAborted === true && typeof this.executor.confirmApplicationPreflightAborted === 'function' &&
            run.staged === false && run.resumed === false && !run.applicationChild && !run.resumeAttempted && !run.transport) {
          try {
            const proof = await this.executor.confirmApplicationPreflightAborted(run.runId), realm = run.realms[0];
            if (proof.runId !== run.runId || proof.environmentId !== run.environmentId || proof.realmId !== realm?.realmId || proof.gid !== realm?.gid ||
                proof.leaseSHA256 !== run.leaseSHA256 || proof.transportExitConfirmed !== true || APP_PREFLIGHT_ABORT_FACTS.some(key => proof[key] !== true) ||
                APP_PREFLIGHT_ABORT_FALSE.some(key => proof[key] !== false) || proof.exitStatus !== 1 || proof.stage !== 'preflight' ||
                run.nativeFailure?.stage !== 'preflight') throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED');
            run.preflightAbort = structuredClone(proof); run.cleanupUncertain = false; run.phase = 'preflight-aborted';
          } catch {}
        }
        if (run.stage === 'transport' && error.prestageAborted === true && typeof this.executor.confirmApplicationPrestageAborted === 'function' &&
            run.staged === false && run.resumed === false && !run.applicationChild && !run.resumeAttempted) {
          try {
            const proof = await this.executor.confirmApplicationPrestageAborted(run.runId), realm = run.realms[0];
            if (proof.runId !== run.runId || proof.environmentId !== run.environmentId || proof.realmId !== realm?.realmId || proof.gid !== realm?.gid ||
                proof.leaseSHA256 !== run.leaseSHA256 || proof.transportExitConfirmed !== true || APP_ABORT_FACTS.some(key => proof[key] !== true) ||
                APP_ABORT_FALSE.some(key => proof[key] !== false) || proof.exitStatus !== 1 || proof.stage !== 'factory-open') throw failure('APPLICATION_APP_TRANSPORT_UNCONFIRMED');
            run.prestageAbort = structuredClone(proof); run.cleanupUncertain = false; run.phase = 'prestage-aborted';
          } catch {}
        }
        if (run.cleanupUncertain && this.executor.applicationCleanupAvailable?.(run.runId) === true) {
          run.cleanupMode = 'native-refusal';
          const transport = this.executor.appTransports?.get(run.runId)?.ack;
          if (transport) run.transport = structuredClone(transport);
        } else if (run.cleanupUncertain) this.executor.appTransports?.get(run.runId)?.poison?.();
        if (run.lockAcquired) try { await this.executor.persistRun(run); } catch (persistError) {
          rememberAppFailure(run, 'cleanup', persistError, true); run.cleanupUncertain = true; run.phase = 'cleanup-required';
          if (this.executor.applicationCleanupAvailable?.(run.runId) !== true) this.executor.appTransports?.get(run.runId)?.poison?.();
        }
        throw outwardAppFailure(run);
      }
    });
  }
  resumeNotionApplication(input = {}) {
    return this.serialized(async () => {
      this.assertOpen();
      if (!input || Object.keys(input).sort().join('|') !== 'activationAuthorized|runId' || !uuid(input.runId)) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
      if (input.activationAuthorized !== true || !(await this.state({ runId: input.runId })).authorized) throw failure('APPLICATION_ROUTING_AUTHORIZATION_REQUIRED');
      const run = this.appRuns.get(input.runId);
      if (!run || run.phase !== 'staged' || run.resumeAttempted || run.cleanupUncertain) throw failure('APPLICATION_APP_STAGE_UNCONFIRMED');
      run.resumeAttempted = true;
      try {
        await this.executor.verifyApplicationLease(run.runId);
        const managed = await this.executor.identify(run.managedIdentity.pid);
        if (managed.birth !== run.managedIdentity.birth || managed.path !== run.managedIdentity.path || managed.uid !== run.managedIdentity.uid) throw failure('APPLICATION_PROXY_UNAVAILABLE');
        const resumed = await this.executor.applicationTransportControl(run.runId, 'B');
        if (resumed.pid !== run.applicationChild.pid || resumed.birth !== run.applicationChild.birth || resumed.executedIdentityVerified !== true ||
            resumed.seatbeltAppliedByFixedExec !== true || resumed.frontAdmissionVerified !== true || resumed.profile !== 'seatbelt-front-only') throw failure('APPLICATION_APP_RESUME_UNCONFIRMED');
        run.resumed = true; run.phase = 'running'; await this.executor.persistRun(run); return this.publicApplication(run);
      } catch (error) { run.cleanupUncertain = true; run.phase = 'cleanup-required'; rememberAppFailure(run, 'resume', error);
        if (this.executor.applicationCleanupAvailable?.(run.runId) === true) run.cleanupMode = 'native-refusal';
        else this.executor.appTransports?.get(run.runId)?.poison?.();
        try { await this.executor.persistRun(run); } catch (persistError) { rememberAppFailure(run, 'cleanup', persistError, true); }
        throw outwardAppFailure(run); }
    });
  }
  async cleanupApplicationOwnedTail(run) {
    const completed = run.appCleanupSteps ??= {};
    await this.executor.assertNoOwnedGroupProcesses(run.realms);
    if (!completed.referenceReleased) {
      await this.executor.releaseOwnedReference(); completed.referenceReleased = true; run.ownedPFReferenceReleased = true;
      await this.persistApplicationCleanupRun(run);
    } else if (this.executor.kind === 'native') await this.executor.confirmOwnedReferenceReleased();
    // removeOwnedRootHook itself uses one DELETE intent and then exact-lease
    // read-only status. Retried tails never send another native DELETE.
    const removed = await this.executor.removeOwnedRootHook(run.rootHookLease);
    if (removed.ownedRootHookRemoved !== true || removed.originalRootRestored !== true || removed.namespaceReclaimed !== true || removed.receiptRetired !== true)
      throw failure('APPLICATION_APP_CLEANUP_UNCONFIRMED');
    Object.assign(run, { ownedRootHookRemoved: true, originalRootRestored: true, namespaceReclaimed: true, rootHookReceiptRetired: true });
    completed.hookRetired = true; await this.persistApplicationCleanupRun(run);
    await this.executor.removeGroups(run.realms); completed.groupsRemoved = true;
    const after = await this.executor.snapshotUnrelatedNetwork();
    run.ownedResourcesReclaimed = true;
    run.foreignStateDrift = { pf: after.pfDigest !== run.baseline.pfDigest, routes: after.routeDigest !== run.baseline.routeDigest,
      dns: after.dnsDigest !== run.baseline.dnsDigest, aggregate: after.digest !== run.baseline.digest };
    if (Object.values(run.foreignStateDrift).some(Boolean)) throw failure('APPLICATION_APP_CLEANUP_UNCONFIRMED');
    if (!completed.leaseRetired) { await this.executor.retireApplicationLease(run.runId); completed.leaseRetired = true; }
  }
  async persistApplicationCleanupRun(run) {
    // Once retirement unlinks the original registry, a retry checks held
    // custody and finishes release; it never creates a new registry/lock.
    if (this.executor.registryUnlinkAttempted || this.executor.lockUnlinkAttempted) return this.executor.assertRuntimeRootHeld();
    return this.executor.persistRun(run);
  }
  stopNotionApplication(input = {}) {
    return this.serialized(async () => {
      if (!input || Object.keys(input).sort().join('|') !== 'runId' || !uuid(input.runId) || !this.appRuns.has(input.runId)) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
      const run = this.appRuns.get(input.runId); clearInterval(run.heartbeat); clearTimeout(run.timer);
      if (appCleanPhase(run.phase)) return this.publicApplication(run);
      if (run.preflightAbort && ['preflight-aborted', 'cleanup-required'].includes(run.phase)) {
        run.cleanupMode = 'preflight';
        try {
          if (run.staged || run.resumed || run.applicationChild || run.resumeAttempted || run.transport || run.realms.length !== 1 ||
              run.realms.some(realm => realm.tunnel || realm.fixtures?.length)) throw failure('APPLICATION_APP_CLEANUP_UNCONFIRMED');
          if (!run.appCleanupSteps?.leaseRetired) {
            const verified = await this.executor.confirmApplicationPreflightAborted(run.runId);
            if (JSON.stringify(verified) !== JSON.stringify(run.preflightAbort)) throw failure('APPLICATION_APP_CLEANUP_UNCONFIRMED');
          }
          run.phase = 'preflight-stopping'; await this.persistApplicationCleanupRun(run);
          if (!run.appCleanupSteps?.hookRetired) {
            await this.executor.requireEmptyOwnedAnchor();
            await this.executor.inspectOwnedRootHook(run.rootHookLease);
          }
          await this.cleanupApplicationOwnedTail(run);
          await this.persistApplicationCleanupRun(run);
          await this.executor.releaseLock(); run.lockAcquired = false;
          run.phase = 'preflight-cleaned'; run.cleanupUncertain = false;
          run.cleanupEvidence = { schema: 'envara.macos-pf-notion-preflight-cleanup/v1', source: run.native ? 'native-notion-controller' : 'simulated-notion-controller',
            runId: run.runId, environmentId: run.environmentId, profile: 'seatbelt-front-only', complete: true, cleanupUncertain: false,
            staged: false, resumed: false, notionLaunched: false, lifecyclePassed: false, bootstrapAttempted: false, transportAttempted: false,
            filterWriteAttempted: false, coldStageAttempted: false,
            ...Object.fromEntries(['sealedContextVerified', 'nativePrivateChildrenAbsentBeforeExit', 'nativeGIDScopeAbsentBeforeExit',
              'nativeOwnedFilterClassesEmptyBeforeExit', 'filterJournalAbsent', 'bootstrapExitConfirmed', 'ownedFilterEmptyAtCleanup',
              'ownedEffectiveGIDProcessesAbsentAtCleanup', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed',
              'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'].map(key => [key, true])) };
          return this.publicApplication(run);
        } catch (error) {
          run.cleanupUncertain = true; run.phase = 'cleanup-required'; rememberAppFailure(run, 'cleanup', error, true);
          run.cleanupRetryable = run.lockAcquired === true;
          if (run.lockAcquired) try { await this.persistApplicationCleanupRun(run); } catch {}
          throw outwardAppFailure(run, 'APPLICATION_APP_CLEANUP_UNCONFIRMED');
        }
      }
      if (run.prestageAbort && ['prestage-aborted', 'cleanup-required'].includes(run.phase)) {
        run.cleanupMode = 'prestage';
        try {
          if (run.staged || run.resumed || run.applicationChild || run.resumeAttempted) throw failure('APPLICATION_APP_CLEANUP_UNCONFIRMED');
          if (!run.appCleanupSteps?.leaseRetired) {
            const verified = await this.executor.confirmApplicationPrestageAborted(run.runId);
            if (JSON.stringify(verified) !== JSON.stringify(run.prestageAbort)) throw failure('APPLICATION_APP_CLEANUP_UNCONFIRMED');
          }
          run.phase = 'prestage-stopping'; await this.persistApplicationCleanupRun(run);
          await this.cleanupApplicationOwnedTail(run);
          await this.persistApplicationCleanupRun(run);
          await this.executor.releaseLock(); run.lockAcquired = false;
          run.phase = 'prestage-cleaned'; run.cleanupUncertain = false;
          run.cleanupEvidence = { schema: 'envara.macos-pf-notion-prestage-cleanup/v1', source: run.native ? 'native-notion-controller' : 'simulated-notion-controller',
            runId: run.runId, environmentId: run.environmentId, profile: 'seatbelt-front-only', complete: true, cleanupUncertain: false,
            staged: false, resumed: false, notionLaunched: false, lifecyclePassed: false, denyAttempted: false, filterWriteAttempted: false, launchCommandAccepted: false, coldStageAttempted: false,
            ...Object.fromEntries(['coreReaped', 'frontReaped', 'originalUTunVerified', 'originalListenerVerified', 'originalUTunClosed', 'originalListenerClosed',
              'filterJournalAbsent', 'transportExitConfirmed', 'nativeGIDScopeAbsentBeforeExit', 'ownedEffectiveGIDProcessesAbsentAtCleanup', 'ownedGroupsRemoved',
              'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged',
              'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'].map(key => [key, true])) };
          return this.publicApplication(run);
        } catch (error) {
          run.cleanupUncertain = true; run.phase = 'cleanup-required'; rememberAppFailure(run, 'cleanup', error, true);
          run.cleanupRetryable = run.lockAcquired === true;
          if (run.lockAcquired) try { await this.persistApplicationCleanupRun(run); } catch {}
          throw outwardAppFailure(run, 'APPLICATION_APP_CLEANUP_UNCONFIRMED');
        }
      }
      const completed = run.appCleanupSteps ??= {};
      const recoveryAvailable = run.cleanupMode === 'native-refusal' && this.executor.applicationCleanupAvailable?.(run.runId) === true;
      if ((!run.staged && !recoveryAvailable && !completed.transportReleased) || run.cleanupUncertain && !recoveryAvailable && !completed.transportReleased)
        throw outwardAppFailure(run, 'APPLICATION_APP_CLEANUP_UNCONFIRMED');
      run.phase = 'stopping'; await this.persistApplicationCleanupRun(run);
      try {
        if (!completed.stoppingConfirmed) {
          await this.executor.applicationTransportControl(run.runId, 'S'); completed.stoppingConfirmed = true;
          await this.persistApplicationCleanupRun(run);
        }
        if (!completed.transportReleased) {
          const released = await this.executor.applicationTransportControl(run.runId, 'R');
          if (!appReleasedFactsVerified(released)) throw failure('APPLICATION_APP_CLEANUP_UNCONFIRMED');
          run.applicationReleaseFacts = { childReaped: released.childReaped, childAbsent: released.childAbsent };
          completed.transportReleased = true; await this.persistApplicationCleanupRun(run);
        }
        await this.executor.confirmApplicationTransportExited(run.runId); completed.transportExited = true;
        await this.cleanupApplicationOwnedTail(run);
        await this.persistApplicationCleanupRun(run);
        await this.executor.releaseLock(); run.lockAcquired = false;
        run.phase = 'cleaned'; run.cleanupUncertain = false;
        run.cleanupEvidence = { schema: 'envara.macos-pf-notion-cleanup/v1', source: run.native ? 'native-notion-controller' : 'simulated-notion-controller', runId: run.runId,
          environmentId: run.environmentId, profile: 'seatbelt-front-only', complete: true, cleanupUncertain: false,
          ...Object.fromEntries(['coreReaped', 'frontReaped', 'childReaped', 'scopeQuiescentObserved', 'originalUTunClosed', 'originalListenerClosed',
            'filterEmptyVerified', 'privateJournalRetired', 'transportExitConfirmed', 'ownedGIDProcessesAbsent', 'ownedGroupsRemoved',
            'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased',
            'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'].map(key => [key, true])),
          childReaped: run.applicationReleaseFacts.childReaped, childAbsent: run.applicationReleaseFacts.childAbsent };
        return this.publicApplication(run);
      } catch (error) { run.cleanupUncertain = true; run.phase = 'cleanup-required'; rememberAppFailure(run, 'cleanup', error, true);
        const entry = this.executor.appTransports?.get(run.runId);
        run.cleanupRetryable = completed.transportExited === true || completed.transportReleased === true && entry?.uncertain !== true ||
          this.executor.applicationCleanupAvailable?.(run.runId) === true;
        if (run.lockAcquired) try { await this.persistApplicationCleanupRun(run); } catch {} throw outwardAppFailure(run, 'APPLICATION_APP_CLEANUP_UNCONFIRMED'); }
    });
  }
  stop({ routeId, sessionId } = {}) {
    return this.serialized(async () => {
      this.assertOpen();
      if (sessionId || !validId(routeId) || !this.routes.has(routeId)) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
      if ([...this.appRuns.values()].some(run => run.routeId === routeId && !appCleanPhase(run.phase))) throw failure('APPLICATION_APP_CONTEXT_ACTIVE');
      const selected = this.routes.get(routeId); selected.active = false; selected.proxy = null;
      return { routeId, stopped: true, processTerminated: false, protected: false, launched: false };
    });
  }
  revoke(params) { return this.stop(params); }
  prepareOwnedFixtures(input = {}) {
    return this.serialized(async () => {
      this.assertOpen();
      if (input.activationAuthorized !== true) throw failure('APPLICATION_ROUTING_AUTHORIZATION_REQUIRED');
      if (!uuid(input.runId) || this.usedRunIds.size > 0 || this.usedRunIds.has(input.runId) || !Number.isInteger(input.lifetimeSeconds) || input.lifetimeSeconds < 10 || input.lifetimeSeconds > 180 ||
          !Array.isArray(input.slots) || input.slots.length < 1 || input.slots.length > 2 || new Set(input.slots.map(slot => slot?.slot)).size !== input.slots.length) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
      const slots = input.slots.map(slot => {
        if (!['one', 'two'].includes(slot?.slot) || !uuid(slot.environmentId) || !['block', 'proxy'].includes(slot.udpPolicy) || slot.proxy?.protocol !== 'socks5') throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
        return { slot: slot.slot, environmentId: slot.environmentId, proxy: validateManagedProxy(slot.proxy), udpPolicy: slot.udpPolicy };
      });
      if (new Set(slots.map(slot => slot.environmentId)).size !== slots.length) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
      const stateless = input.controlledExperiment === true;
      const caseIds = stateless ? input.caseIds : [];
      if (stateless && (!Array.isArray(caseIds) || caseIds.length < 1 || caseIds.length > CONTROLLED_CASES.length ||
          new Set(caseIds).size !== caseIds.length || caseIds.some(caseId => !CONTROLLED_CASES.includes(caseId)))) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
      const state = await this.state({ runId: input.runId });
      if (!state.authorized) throw failure('APPLICATION_ROUTING_AUTHORIZATION_REQUIRED');
      if (state.operatingSystem.ownedRootHook?.canCreateOwnedHook !== true || state.operatingSystem.ownedRootHook?.pfDisabled !== true ||
          state.operatingSystem.ownedRootHook?.pinsVerified !== true || state.operatingSystem.ownedRootHook?.originalRootCompatible !== true ||
          typeof this.executor.installOwnedRootHook !== 'function' || typeof this.executor.removeOwnedRootHook !== 'function') throw failure('APPLICATION_ROUTING_NOT_READY');
      if (this.executor.kind === 'native' && (state.operatingSystem.pf.priorAnchorsCompatible !== true || state.operatingSystem.pf.fixtureEgressSkipVerified !== true)) throw failure('APPLICATION_ROUTING_NOT_READY');
      // Refuse BEFORE creating groups, installing PF rules or opening a TUN
      // when a controlled experiment could not be safely cleaned up.
      if (typeof this.executor.startTunnelCore !== 'function' || typeof this.executor.launchFixture !== 'function' ||
          (stateless ? state.operatingSystem.noStateNativeAvailable !== true || this.executor.statelessControlledFixtures !== true ||
            typeof this.executor.reserveFixtureTuples !== 'function' || typeof this.executor.verifyInstalledStatelessRules !== 'function' :
            state.operatingSystem.exactStateCleanupSupported !== true || this.executor.exactStateCleanupSupported !== true)) throw failure('APPLICATION_ROUTING_NOT_READY');
      for (const slot of slots) try { await this.authenticateProxy(slot.proxy); } catch { throw failure('APPLICATION_PROXY_UNAVAILABLE'); }
      const run = { runId: input.runId, phase: 'preparing', realms: [], stateless, caseIds, cleanupUncertain: false, native: this.executor.kind === 'native',
        lockAcquired: false, rootHookMutationAttempted: false, rootHookLease: null, rootHookVerified: false, rulesWritten: false,
        pfReferenceAttempted: false, pfReferenceAcquired: false, ownedPFReferenceReleased: false, ownedRootHookRemoved: false, originalRootRestored: false };
      this.usedRunIds.add(input.runId); this.runs.set(input.runId, run);
      try {
        run.stage = 'registry-lock';
        await this.executor.acquireLock(run.runId);
        run.lockAcquired = true;
        run.stage = 'baseline-snapshot';
        run.baseline = await this.executor.snapshotUnrelatedNetwork();
        run.stage = 'root-hook-intent';
        run.rootHookMutationAttempted = true;
        if (this.executor.persistRun) await this.executor.persistRun(run);
        run.stage = 'root-hook-insert';
        run.rootHookLease = validatePFRootHookLease(await this.executor.installOwnedRootHook(run.runId), run.runId);
        run.rootHookVerified = true;
        run.stage = 'root-hook-receipt';
        if (this.executor.persistRun) await this.executor.persistRun(run);
        run.stage = 'owned-anchor-check';
        await this.executor.requireEmptyOwnedAnchor();
        for (const slot of slots) {
          run.stage = 'group-allocation';
          const group = await this.executor.allocateGroup(slot.environmentId);
          run.realms.push({ ...slot, ...group, realmId: randomUUID(), consoleUID: state.operatingSystem.consoleUID, mode: 'blocked', tunnel: null, fixtures: [] });
          if (this.executor.persistRun) await this.executor.persistRun(run);
        }
        run.stage = 'deny-rules';
        run.rulesWritten = true;
        await this.executor.replaceOwnedRules(this.policyFor(run), run);
        run.stage = 'pf-reference';
        run.pfReferenceAttempted = true;
        if (this.executor.persistRun) await this.executor.persistRun(run);
        const enabled = await this.executor.enableOwnedReference(); run.pfReferenceAcquired = true;
        run.existingForeignPFStatesAbsentBeforeEnable = enabled?.existingForeignPFStatesAbsentBeforeEnable === true;
        if (!run.existingForeignPFStatesAbsentBeforeEnable) throw failure('APPLICATION_ROUTING_NOT_READY');
        if (this.executor.persistRun) await this.executor.persistRun(run);
        for (let index = 0; index < run.realms.length; index++) {
          const realm = run.realms[index], ipv4Address = `198.18.${index + 1}.1`;
          run.stage = 'tunnel-start';
          realm.tunnel = await this.executor.startTunnelCore({ runId: run.runId, realmId: realm.realmId,
            config: pfTunnelCoreConfig({ proxy: realm.proxy, udpPolicy: realm.udpPolicy, ipv4Address }), ipv4Address });
          if (this.executor.persistRun) await this.executor.persistRun(run);
          if (this.executor.assertRequiredInterfacesNotSkipped) await this.executor.assertRequiredInterfacesNotSkipped(run.realms.map(value => value.tunnel?.interfaceName).filter(Boolean));
          run.stage = 'fixture-start';
          realm.fixtures = await this.executor.launchFixture({ runId: run.runId, realmId: realm.realmId, uid: state.operatingSystem.consoleUID, gid: realm.gid });
          if (this.executor.persistRun) await this.executor.persistRun(run);
          if (!Array.isArray(realm.fixtures) || !realm.fixtures.length || realm.fixtures.some(fixture => fixture.suspended !== true)) throw failure('APPLICATION_ROUTING_NOT_READY');
        }
        if (stateless) {
          // Execute only the sealed fixture while the group deny rule is
          // active. It may bind fresh sockets, but cannot emit an IP packet.
          for (const realm of run.realms) {
            run.stage = 'fixture-resume';
            await this.executor.resumeOwnedFixtures(realm);
            await this.executor.discoverFixtureChildren(realm);
          }
          run.stage = 'socket-reservation';
          run.statelessEvidence = await this.executor.reserveFixtureTuples(run);
          for (const realm of run.realms) realm.mode = 'routed';
          run.stage = 'stateless-rules';
          const policy = this.policyFor(run); await this.executor.replaceOwnedRules(policy, run);
          const observed = await this.executor.verifyInstalledStatelessRules(policy);
          run.noStateRulesObserved = observed.noStateRulesVerified === true;
          run.statelessEvidence = { ...run.statelessEvidence, ...observed };
          if (['freshTuplesVerified', 'noExistingOwnedStatesVerified', 'noStateRulesVerified', 'denyBeforeResumeVerified'].some(key => run.statelessEvidence[key] !== true)) throw failure('APPLICATION_ROUTING_NOT_READY');
        } else {
          for (const realm of run.realms) realm.mode = 'routed';
          run.stage = 'stateless-rules';
          await this.executor.replaceOwnedRules(this.policyFor(run), run);
          run.stage = 'fixture-resume';
          for (const realm of run.realms) await this.executor.resumeOwnedFixtures(realm);
        }
        run.stage = 'fixture-commit';
        run.phase = 'fixtures-running';
        if (this.executor.persistRun) await this.executor.persistRun(run);
        run.timer = setTimeout(() => { this.cleanupOwnedFixtures({ runId: run.runId }).catch(() => {}); }, input.lifetimeSeconds * 1000); run.timer.unref?.();
        return { ...diagnosticFlags(), runId: run.runId, nativeObserved: run.native, anchoredToOwnedRootVerified: true,
          existingForeignPFStatesAbsentBeforeEnable: run.existingForeignPFStatesAbsentBeforeEnable === true,
          ownedRootHook: { source: run.native ? 'native-pf-root-hook' : 'simulated', anchor: pfRoutingAnchor(run.runId), runId: run.runId,
            verified: true, ticketSource: 'this-INSERT-return-only' },
          ...(stateless ? { statelessEvidence: run.statelessEvidence } : {}), realms: run.realms.map(realm => ({ slot: realm.slot, realmId: realm.realmId,
          gid: realm.gid, tunnel: { ...realm.tunnel }, fixtures: realm.fixtures.map(fixture => ({ role: fixture.role, pid: fixture.pid, birth: fixture.birth, gid: realm.gid })) })) };
      } catch (error) {
        run.failedStage = run.stage; run.failedCode = cleanError(error);
        run.phase = 'fault'; run.cleanupUncertain = true;
        // A native receipt may be captured just before its follow-up readback
        // fails. Keep only that private INSERT receipt; never adopt a ticket
        // discovered by name while trying to recover an ambiguous insertion.
        if (!run.rootHookLease && this.executor.rootHookLease) try { run.rootHookLease = validatePFRootHookLease(this.executor.rootHookLease, run.runId); } catch {}
        if (this.executor.kind === 'native' && this.executor.pfReferenceMutationAttempted === false) run.pfReferenceAttempted = false;
        if (run.lockAcquired && this.executor.persistRun) try { await this.executor.persistRun(run); } catch {}
        try { await this.cleanupRun(run); } catch {}
        throw failure(cleanError(error));
      }
    });
  }
  policyFor(run) {
    const routes = run.realms.map(realm => ({ environmentId: realm.environmentId, gid: realm.gid, mode: realm.mode, udpPolicy: realm.udpPolicy, tunnel: realm.tunnel }));
    return run.stateless === true ? createStatelessFixturePFRoutingPolicy(routes, { fixtureDestinations: FIXTURE_DESTINATIONS, runId: run.runId }) : createPFRoutingPolicy(routes, { runId: run.runId });
  }
  startAcceptance(params) { return this.prepareOwnedFixtures(params); }
  handleTransportFault(event) {
    return this.serialized(async () => {
      for (const run of this.runs.values()) {
        const affected = run.realms.filter(realm => realm.tunnel?.instanceId === event.instanceId);
        if (!affected.length || ['cleaned', 'cleaning'].includes(run.phase)) continue;
        // The generated native writer has one deny/routed mode for this owned
        // run. A partial transport fault must deny the whole run rather than
        // leave a mixed policy that cannot replace the previous routed FILTER.
        for (const realm of run.realms) realm.mode = 'blocked';
        run.phase = 'transport-fault'; run.cleanupUncertain = event.fdRetained !== true;
        try { await this.executor.replaceOwnedRules(this.policyFor(run), run); } catch { run.cleanupUncertain = true; }
        if (this.executor.persistRun) try { await this.executor.persistRun(run); } catch {}
        try { this.onEvent({ type: 'pf-transport-fault', runId: run.runId, reason: event.kind, fdRetained: event.fdRetained === true,
          protected: false, failClosed: false, productionReady: false }); } catch {}
      }
    });
  }
  runOwnedFixtureCase(input = {}) {
    return this.serialized(async () => {
      this.assertOpen(); const run = this.runs.get(input.runId);
      if (!run || run.phase !== 'fixtures-running' || !validId(input.caseId) || !this.executor.fixtureOperations.includes(input.caseId) ||
          (input.timeoutMs != null && (!Number.isInteger(input.timeoutMs) || input.timeoutMs < 1 || input.timeoutMs > 15000)) ||
          (input.slot != null && !run.realms.some(realm => realm.slot === input.slot)) || typeof this.executor.runFixtureCase !== 'function') throw failure('APPLICATION_ROUTING_NOT_READY');
      if (run.native && typeof this.executor.inspectOwnedRootHook === 'function') await this.executor.inspectOwnedRootHook(run.rootHookLease);
      const evidence = await this.executor.runFixtureCase({ run, input: structuredClone(input) });
      // Case evidence belongs to diagnostics only. No generic 'passed' field
      // can be promoted to production authorization or an acceptance receipt.
      return { ...diagnosticFlags(), runId: run.runId, caseId: input.caseId, complete: evidence?.complete === true,
        nativeObserved: run.native, ...(Array.isArray(evidence?.probes) ? { probes: evidence.probes } : {}), evidence: evidence?.evidence ?? {} };
    });
  }
  async acceptanceSnapshot({ runId } = {}) {
    const run = this.runs.get(runId); if (!run) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
    return { ...diagnosticFlags(), runId, phase: run.phase, cleanupUncertain: run.cleanupUncertain, nativeObserved: run.native,
      preparationFailure: preparationFailure(run), caseFailure: caseFailure(run) };
  }
  cleanupOwnedFixtures({ runId } = {}) {
    return this.serialized(async () => {
      const run = this.runs.get(runId); if (!run) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
      return this.cleanupRun(run);
    });
  }
  async cleanupRun(run) {
    if (run.phase === 'cleaned' && run.cleanupResult) return run.cleanupResult;
    clearTimeout(run.timer); run.phase = 'cleaning';
    // These are historical completion receipts for irreversible owned steps,
    // not a fresh process or kernel-namespace absence proof. A retired-hook
    // retry must retain them while independently repeating the read-only checks.
    const completed = run.cleanupStepCompletions ??= { ownedProcessesExited: false, ownedAnchorStatesPurged: false,
      ownedTunnelsRemoved: false, ownedAnchorRemoved: false };
    let ownedProcessesExited = false, ownedAnchorStatesPurged = completed.ownedAnchorStatesPurged === true,
      ownedTunnelsRemoved = completed.ownedTunnelsRemoved === true, ownedAnchorRemoved = completed.ownedAnchorRemoved === true, unrelatedPFUnchanged = false;
    let unrelatedRoutesUnchanged = false, hostDNSUnchanged = false;
    try {
      if (run.lockAcquired) {
        if (run.rootHookLease && !run.ownedRootHookRemoved) {
          if (run.realms.some(realm => realm.fixtures?.length)) await this.executor.terminateOwnedFixtures(run);
          await this.executor.assertNoOwnedGroupProcesses(run.realms);
          this.executor.assertNoUnassignedGuardians?.(run);
          ownedProcessesExited = true; completed.ownedProcessesExited = true;
          for (const realm of run.realms) realm.mode = 'blocked';
          if (run.rulesWritten && !run.childRulesRemoved) await this.executor.replaceOwnedRules(this.policyFor(run), run);
          if (run.rulesWritten && !run.statesCheckedForCleanup) {
            await this.executor.clearExactOwnedStates(run); run.statesCheckedForCleanup = true;
          }
          ownedAnchorStatesPurged = run.statesCheckedForCleanup === true && run.stateless !== true;
          if (ownedAnchorStatesPurged) completed.ownedAnchorStatesPurged = true;
          for (const realm of run.realms) if (realm.tunnel && !realm.tunnelRemoved) {
            await this.executor.stopOwnedTunnel(realm.tunnel); realm.tunnelRemoved = true;
          }
          ownedTunnelsRemoved = true; completed.ownedTunnelsRemoved = true;
          if (!run.childRulesRemoved) {
            await this.executor.replaceOwnedRules(createPFRoutingPolicy([], { runId: run.runId }), run); run.childRulesRemoved = true;
          }
          ownedAnchorRemoved = true; completed.ownedAnchorRemoved = true;
          if (!run.groupsRemoved) { await this.executor.removeGroups(run.realms); run.groupsRemoved = true; }
          if (!run.ownedPFReferenceReleased) {
            // A failed -E without an exact returned token is ambiguous. Never
            // delete the root hook while an unowned enable reference remains.
            if (run.pfReferenceAttempted && !run.pfReferenceAcquired && !this.executor.pfToken) throw failure('APPLICATION_ROUTING_NOT_READY');
            await this.executor.releaseOwnedReference(); run.ownedPFReferenceReleased = true;
            if (this.executor.persistRun) await this.executor.persistRun(run);
          }
          const removed = await this.executor.removeOwnedRootHook(run.rootHookLease);
          if (removed?.ownedRootHookRemoved !== true || removed.originalRootRestored !== true) throw failure('APPLICATION_ROUTING_NOT_READY');
          run.ownedRootHookRemoved = true; run.originalRootRestored = true; run.rootHookVerified = false;
          run.rootHookReceiptRetired = removed.receiptRetired === true; run.namespaceState = removed.namespaceState; run.namespaceReclaimed = removed.namespaceReclaimed === true;
          if (this.executor.persistRun) await this.executor.persistRun(run);
        } else if (run.rootHookMutationAttempted && !run.ownedRootHookRemoved) {
          // An INSERT timeout/error does not supply a usable receipt. Only a
          // read-only native proof that the original root and absent namespace
          // remain intact may clear the pending intent. No name-only delete.
          const absent = await this.executor.confirmNoOwnedRootHook(run.runId);
          if (absent?.ownedRootHookRemoved !== true || absent.originalRootRestored !== true) throw failure('APPLICATION_ROUTING_NOT_READY');
          run.ownedRootHookRemoved = true; run.originalRootRestored = true; run.ownedPFReferenceReleased = !run.pfReferenceAttempted;
          run.rootHookReceiptRetired = absent.receiptRetired === true; run.namespaceState = absent.namespaceState; run.namespaceReclaimed = absent.namespaceReclaimed === true;
        } else if (!run.rootHookMutationAttempted) {
          run.ownedRootHookRemoved = true; run.originalRootRestored = true; run.ownedPFReferenceReleased = true; run.namespaceState = 'absent'; run.namespaceReclaimed = true;
        } else if (run.rootHookReceiptRetired && run.namespaceReclaimed !== true && run.rootHookLease) {
          // Later kernel reclamation may be observed, but the retired receipt
          // is permanently spent. Reinspection never creates another DELETE.
          const retired = await this.executor.confirmNoOwnedRootHook(run.runId, run.rootHookLease);
          if (retired?.receiptRetired !== true || retired.ownedRootHookRemoved !== true || retired.originalRootRestored !== true) throw failure('APPLICATION_ROUTING_NOT_READY');
          run.namespaceState = retired.namespaceState; run.namespaceReclaimed = retired.namespaceReclaimed === true;
        }
        // Group removal is never process-absence evidence. In particular, a
        // repeat after DELETE must obtain a fresh read instead of inheriting a
        // previous receipt or skipping directly to the namespace check.
        if (!ownedProcessesExited) {
          await this.executor.assertNoOwnedGroupProcesses(run.realms);
          this.executor.assertNoUnassignedGuardians?.(run);
          ownedProcessesExited = true; completed.ownedProcessesExited = true;
        }
        ownedTunnelsRemoved ||= run.realms.every(realm => !realm.tunnel || realm.tunnelRemoved === true);
        ownedAnchorRemoved ||= run.childRulesRemoved === true || !run.rulesWritten;
        if (ownedTunnelsRemoved) completed.ownedTunnelsRemoved = true;
        if (ownedAnchorRemoved) completed.ownedAnchorRemoved = true;
        if (!ownedTunnelsRemoved || !ownedAnchorRemoved) throw failure('APPLICATION_ROUTING_NOT_READY');
        const final = await this.executor.snapshotUnrelatedNetwork();
        if (run.baseline) {
          unrelatedPFUnchanged = final.pfDigest === run.baseline.pfDigest;
          unrelatedRoutesUnchanged = final.routeDigest === run.baseline.routeDigest;
          hostDNSUnchanged = final.dnsDigest === run.baseline.dnsDigest;
          if (!unrelatedPFUnchanged || !unrelatedRoutesUnchanged || !hostDNSUnchanged) throw failure('APPLICATION_ROUTING_NOT_READY');
        }
        if (run.namespaceReclaimed !== true) throw failure('APPLICATION_PF_NAMESPACE_CLEANUP_PENDING');
        await this.executor.releaseLock(); run.lockAcquired = false;
      }
      // A refused lock acquisition cannot have started an owned resource.
      // Runs with recorded fixtures require the independent group check above.
      ownedProcessesExited ||= !run.rootHookMutationAttempted && run.realms.length === 0;
      ownedTunnelsRemoved ||= run.realms.every(realm => !realm.tunnel || realm.tunnelRemoved === true);
      ownedAnchorRemoved ||= run.childRulesRemoved === true || !run.rulesWritten;
      if (!ownedProcessesExited || !ownedTunnelsRemoved || !ownedAnchorRemoved) throw failure('APPLICATION_ROUTING_NOT_READY');
      run.phase = 'cleaned'; run.cleanupUncertain = false;
    } catch {
      // Do not close utun guardians, remove groups or release the lock after an
      // uncertain scope/state check. Keep the deny policy and ownership record.
      run.phase = 'cleanup-required'; run.cleanupUncertain = true;
      if (run.lockAcquired && this.executor.persistRun) try { await this.executor.persistRun(run); } catch {}
    }
    const cleanupStepCompletions = Object.fromEntries(['ownedProcessesExited', 'ownedAnchorStatesPurged', 'ownedTunnelsRemoved', 'ownedAnchorRemoved']
      .map(key => [key, completed[key] === true]));
    const evidence = { source: run.native ? 'native-pf' : 'simulated', platform: 'darwin', complete: !run.cleanupUncertain, cleanupStepCompletions,
      ownedProcessesExited, ownedAnchorStatesPurged, ownedTunnelsRemoved, ownedAnchorRemoved, unrelatedPFUnchanged,
      unrelatedRoutesUnchanged, hostDNSUnchanged, cleanupUncertain: run.cleanupUncertain,
      ownedRootHookRemoved: run.ownedRootHookRemoved === true, originalRootRestored: run.originalRootRestored === true,
      namespaceState: run.namespaceState ?? 'unknown', namespaceReclaimed: run.namespaceReclaimed === true, receiptRetired: run.rootHookReceiptRetired === true,
      ownedPFReferenceReleased: run.ownedPFReferenceReleased === true,
      noOwnedStatesCreatedVerified: run.stateless === true && run.noStateRulesObserved === true &&
        Array.isArray(run.stateChecks) && run.stateChecks.length > 0 && run.stateChecks.every(check => check.reservedDestinationsAbsent === true),
      noOwnedStatesRemainVerified: run.noOwnedStatesRemainVerified === true,
      stateScope: run.stateless ? 'selected-fixture-route-states; no state purge performed' : 'exact-owned-states', productionReady: false };
    const result = { ...diagnosticFlags(), runId: run.runId, ownedProcessesExited, ownedAnchorStatesPurged, ownedTunnelsRemoved,
      ownedAnchorRemoved, unrelatedPFUnchanged, ownedRootHookRemoved: run.ownedRootHookRemoved === true,
      originalRootRestored: run.originalRootRestored === true, namespaceState: run.namespaceState ?? 'unknown', namespaceReclaimed: run.namespaceReclaimed === true, receiptRetired: run.rootHookReceiptRetired === true, ownedPFReferenceReleased: run.ownedPFReferenceReleased === true,
      cleanupUncertain: run.cleanupUncertain, cleanupStepCompletions, evidence, preparationFailure: preparationFailure(run), caseFailure: caseFailure(run) };
    if (!run.cleanupUncertain) run.cleanupResult = result;
    return result;
  }
  async shutdown() {
    for (const run of this.appRuns.values()) {
      clearInterval(run.heartbeat); clearTimeout(run.timer);
      if (!appCleanPhase(run.phase)) await this.stopNotionApplication({ runId: run.runId }).catch(() => {});
      if (!appCleanPhase(run.phase)) this.executor.appTransports?.get(run.runId)?.poison?.();
    }
    for (const run of this.runs.values()) if (!['cleaned', 'cleanup-required'].includes(run.phase)) await this.cleanupOwnedFixtures({ runId: run.runId });
    this.closed = true;
    for (const route of this.routes.values()) route.proxy = null;
    return { closed: true, ready: false, cleanupRequired: [...this.runs.values(), ...this.appRuns.values()].some(run => run.cleanupUncertain) };
  }
}

export async function dispatchPFRequest(controller, request) {
  const methods = new Set(['status', 'setup', 'plan', 'acceptancePlan', 'prepareRoute', 'launch', 'start', 'stop', 'revoke',
    'prepareOwnedFixtures', 'startAcceptance', 'runOwnedFixtureCase', 'cleanupOwnedFixtures', 'acceptanceSnapshot',
    'prepareNotionApplication', 'resumeNotionApplication', 'stopNotionApplication', 'applicationSnapshot', 'shutdown']);
  if (!request || request.protocol !== PF_HELPER_PROTOCOL || request.version !== PF_HELPER_VERSION || !validId(request.id) ||
      !methods.has(request.method) || (request.params != null && (typeof request.params !== 'object' || Array.isArray(request.params)))) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR');
  return controller[request.method](request.params ?? {});
}
