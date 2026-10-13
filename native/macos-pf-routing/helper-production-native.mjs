import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { isPFRoutingRunId } from './policy.mjs';
import { verifyPFInstallation } from './controller.mjs';

export const APP_NATIVE_PROTOCOL = 'envara.pf-app-control/v1';
export const APP_KEEPER_PROTOCOL = 'envara.pf-app-keeper/v1';
export const APP_NATIVE_EXECUTABLE = '/Library/PrivilegedHelperTools/io.envara.pf-routing/envara-pf-native';
const flags = Object.freeze({ ready: false, protected: false, productionReady: false });
const hash = /^[0-9a-f]{64}$/;
const registerFailureReasons = new Set(['INVALID_NATIVE_APP_REQUEST', 'FIXED_ROOT_NATIVE_ENTRY_REQUIRED', 'APP_REGISTRY_UNAVAILABLE', 'NATIVE_APP_OPERATION_REFUSED']);
/* Fixed refusals of the storage lifecycle commands that describe a state rather
 * than a fault: a registration that does not exist, was retired, or was left by
 * an interrupted copy; storage still in use; data that is already gone. */
const lifecycleReasons = new Set(['APPLICATION_NOT_REGISTERED', 'APPLICATION_REGISTRATION_RETIRED', 'APPLICATION_REGISTRATION_INCOMPLETE',
  'APPLICATION_IN_USE', 'APPLICATION_DATA_ABSENT']);
const lifecycleOperations = new Set(['app-current', 'app-delete', 'app-data-delete']);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const refusal = reason => Object.assign(new Error('Native application operation refused'), { code: 'APPLICATION_NATIVE_REFUSED', reason });
const fail = reason => { throw refusal(reason); };
function request(value, names) {
  if (!object(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('REQUEST_INVALID');
  const descriptors = Object.getOwnPropertyDescriptors(value), copy = {};
  if (Object.keys(descriptors).some(key => !names.includes(key) || !Object.hasOwn(descriptors[key], 'value'))) fail('REQUEST_INVALID');
  for (const key of Object.keys(descriptors)) copy[key] = descriptors[key].value;
  if (names.some(key => key !== 'bundlePath' && key !== 'previousVersionId' && !isPFRoutingRunId(copy[key])) ||
      copy.previousVersionId !== undefined && !isPFRoutingRunId(copy.previousVersionId)) fail('REQUEST_INVALID');
  return Object.freeze(copy);
}
export function parseNativeApplicationEnvelope(value, ids = {}, operation = null) {
  if (!object(value) || value.schema !== 1 || typeof value.ok !== 'boolean' ||
      value.ready !== false || value.protected !== false || value.activatesSystem !== false ||
      !Number.isInteger(value.error) || value.error < 0 || typeof value.reason !== 'string' || !/^[A-Z_]{1,80}$/.test(value.reason) ||
      ['applicationIdentityVerified', 'environmentLeaseVerified', 'ticketIssued'].some(key => typeof value[key] !== 'boolean') ||
      ['registrationId', 'versionId', 'ticketId', 'snapshotContentSHA256'].some(key => typeof value[key] !== 'string')) fail('NATIVE_APP_COMMANDS_UNAVAILABLE');
  if (!value.ok) {
    const error = refusal('NATIVE_OPERATION_REFUSED');
    if (operation === 'app-register' && value.error > 0 && value.error <= 1024 && registerFailureReasons.has(value.reason))
      error.nativeFailure = Object.freeze({ stage: 'register', reason: value.reason, error: value.error });
    if (lifecycleOperations.has(operation) && lifecycleReasons.has(value.reason)) error.lifecycleReason = value.reason;
    throw error;
  }
  if (value.error || Object.entries(ids).some(([key, expected]) => value[key] !== expected) ||
      value.applicationIdentityVerified && (!isPFRoutingRunId(value.registrationId) || !isPFRoutingRunId(value.versionId) || !hash.test(value.snapshotContentSHA256))) fail('NATIVE_BINDING_INVALID');
  return Object.freeze({ ...value, ...flags });
}
/* The storage inventory is its own fixed shape: every registration with its
 * identifier, original bundle, version count, retirement and size, and every
 * environment's data size. Nothing else is admitted. */
export function parseStorageInventory(value) {
  if (object(value) && value.ok === false) fail('NATIVE_OPERATION_REFUSED');
  if (!object(value) || Object.keys(value).sort().join('|') !== 'activatesSystem|environments|error|ok|protected|ready|registrations|schema' ||
      value.schema !== 1 || value.ok !== true || value.error !== 0 || value.ready !== false || value.protected !== false || value.activatesSystem !== false ||
      !Array.isArray(value.registrations) || !Array.isArray(value.environments) || value.registrations.length > 256 || value.environments.length > 256) fail('NATIVE_RESPONSE_INVALID');
  const registrations = value.registrations.map(item => {
    if (!object(item) || Object.keys(item).sort().join('|') !== 'bundle|bytes|identifier|registrationId|retired|versions' ||
        !isPFRoutingRunId(item.registrationId) || typeof item.identifier !== 'string' || item.identifier.length > 255 ||
        typeof item.bundle !== 'string' || item.bundle.length > 4095 || /[\0\r\n]/.test(item.bundle) ||
        !Number.isSafeInteger(item.versions) || item.versions < 0 || item.versions > 64 || typeof item.retired !== 'boolean' ||
        !Number.isSafeInteger(item.bytes) || item.bytes < 0) fail('NATIVE_RESPONSE_INVALID');
    return Object.freeze({ ...item });
  });
  const environments = value.environments.map(item => {
    if (!object(item) || Object.keys(item).sort().join('|') !== 'bytes|environmentId' || !isPFRoutingRunId(item.environmentId) ||
        !Number.isSafeInteger(item.bytes) || item.bytes < 0) fail('NATIVE_RESPONSE_INVALID');
    return Object.freeze({ ...item });
  });
  if (new Set(registrations.map(item => item.registrationId)).size !== registrations.length ||
      new Set(environments.map(item => item.environmentId)).size !== environments.length) fail('NATIVE_RESPONSE_INVALID');
  return Object.freeze({ registrations: Object.freeze(registrations), environments: Object.freeze(environments), ...flags });
}

/* Construct only within the installed authenticated helper. Dependencies are
 * native/test harness dependencies, never deserialized from RPC. This adapter
 * executes real fixed native commands; it does not synthesize coordinator
 * proofs, install policy, elevate via shell, or expose production resume. */
export class NativeApplicationCommands {
  #spawn; #inspect; #controlled; #timeout; #closed = false; #sessions = new Map(); #requests = new Set();
  constructor({ spawnChild = spawn, inspectInstallation = verifyPFInstallation, controlledSession = false, timeoutMs = 15000 } = {}) {
    if (typeof spawnChild !== 'function' || typeof inspectInstallation !== 'function' || typeof controlledSession !== 'boolean' ||
        !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) fail('OPTIONS_INVALID');
    this.#spawn = spawnChild; this.#inspect = inspectInstallation; this.#controlled = controlledSession; this.#timeout = timeoutMs;
  }
  status() { return { protocol: APP_NATIVE_PROTOCOL, ...flags, readOnly: true, protectedLaunchSupported: false,
    sessions: [...this.#sessions].map(([ticketId, record]) => ({ ticketId, phase: record.phase, recoveryRequired: record.phase === 'recovery-required' })) }; }
  async #installation(mutation) {
    if (mutation && this.#closed) fail('HELPER_CHANNEL_CLOSED');
    if (mutation && (!this.#controlled || process.getuid?.() !== 0 || process.geteuid?.() !== 0)) fail('AUTHENTICATED_ROOT_HELPER_REQUIRED');
    const installation = await this.#inspect();
    if (!object(installation) || installation.verified !== true) fail('REVIEWED_INSTALLATION_REQUIRED');
    if (mutation && installation.runtimeVerified !== true) fail('INSTALLED_HELPER_RUNTIME_REQUIRED');
    if (mutation && this.#closed) fail('HELPER_CHANNEL_CLOSED');
  }
  #spawnNative(args) {
    return this.#spawn(APP_NATIVE_EXECUTABLE, args, { shell: false,
      env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' }, stdio: ['pipe', 'pipe', 'pipe'] });
  }
  async #call(args, ids = {}, mutation = false, { maxBytes = 8192, parse = null } = {}) {
    await this.#installation(mutation);
    if (mutation && this.#closed) fail('HELPER_CHANNEL_CLOSED');
    return new Promise((resolve, reject) => {
      let child, buffer = Buffer.alloc(0), settled = false;
      const finish = (error, value) => { if (settled) return; settled = true; buffer = Buffer.alloc(0); clearTimeout(timer); error ? reject(error) : resolve(value); };
      const timer = setTimeout(() => { try { child?.stdin?.end(); child?.kill('SIGTERM'); } catch {} finish(refusal('NATIVE_OPERATION_UNCERTAIN')); }, this.#timeout);
      try { child = this.#spawnNative(args); } catch { finish(refusal('NATIVE_UNAVAILABLE')); return; }
      child.stdout.on('data', data => { if (settled) return; buffer = Buffer.concat([buffer, data]); if (buffer.length > maxBytes) { try { child.kill('SIGTERM'); } catch {} finish(refusal('NATIVE_RESPONSE_INVALID')); } });
      child.stderr.on('data', () => {}); // Never print private native errors/paths.
      child.once('error', () => finish(refusal('NATIVE_UNAVAILABLE')));
      child.stdin.on('error', () => finish(refusal('NATIVE_CHANNEL_LOST')));
      child.once('close', code => {
        if (settled) return;
        try { const decoded = JSON.parse(buffer.toString('utf8').trim());
          const value = parse ? parse(decoded) : parseNativeApplicationEnvelope(decoded, ids, args[0]); if (code !== 0) fail('NATIVE_OPERATION_REFUSED'); finish(null, value); }
        catch (error) { finish(error?.code === 'APPLICATION_NATIVE_REFUSED' ? error : refusal('NATIVE_RESPONSE_INVALID')); }
      });
      child.stdin.end();
    });
  }
  async plan(input) {
    const value = request(input, ['registrationId', 'versionId', 'environmentId', 'runId']);
    return this.#call(['app-plan', value.registrationId, value.versionId, value.environmentId, value.runId],
      { registrationId: value.registrationId, versionId: value.versionId });
  }
  async register(input) {
    const value = request(input, ['registrationId', 'versionId', 'bundlePath', 'previousVersionId']);
    if (typeof value.bundlePath !== 'string' || !value.bundlePath.startsWith('/') || value.bundlePath.length > 4095 ||
        !value.bundlePath.endsWith('.app') || /[\0\r\n]/.test(value.bundlePath) || value.bundlePath.split('/').some(part => part === '.' || part === '..')) fail('REQUEST_INVALID');
    return this.#call(['app-register', value.registrationId, value.versionId, value.bundlePath, value.previousVersionId ?? '-'],
      { registrationId: value.registrationId, versionId: value.versionId }, true);
  }
  async retire(input) { const value = request(input, ['registrationId']); return this.#call(['app-retire', value.registrationId], {}, true); }
  /* The latest committed version of one registration and whether it can be
   * reused for the current original. Read-only: never registers or copies. */
  async current(input) {
    const value = request(input, ['registrationId']);
    try {
      const result = await this.#call(['app-current', value.registrationId], { registrationId: value.registrationId });
      if (!isPFRoutingRunId(result.versionId)) fail('NATIVE_BINDING_INVALID');
      return Object.freeze({ state: result.applicationIdentityVerified ? 'current' : 'stale', registrationId: value.registrationId,
        versionId: result.versionId, ...flags });
    } catch (error) {
      const state = { APPLICATION_NOT_REGISTERED: 'absent', APPLICATION_REGISTRATION_RETIRED: 'retired',
        APPLICATION_REGISTRATION_INCOMPLETE: 'incomplete' }[error?.lifecycleReason];
      if (state) return Object.freeze({ state, registrationId: value.registrationId, versionId: null, ...flags });
      throw error;
    }
  }
  /* Removes one registration and its copies; refuses while a copy is running. */
  async deleteRegistration(input) {
    const value = request(input, ['registrationId']);
    try { await this.#call(['app-delete', value.registrationId], {}, true); return Object.freeze({ deleted: true, absent: false, ...flags }); }
    catch (error) {
      if (error?.lifecycleReason === 'APPLICATION_NOT_REGISTERED') return Object.freeze({ deleted: false, absent: true, ...flags });
      if (error?.lifecycleReason === 'APPLICATION_IN_USE') error.inUse = true;
      throw error;
    }
  }
  /* Removes one environment's attached-application data; refuses while any
   * attached application is running. */
  async deleteEnvironmentData(input) {
    const value = request(input, ['environmentId']);
    try { await this.#call(['app-data-delete', value.environmentId], {}, true); return Object.freeze({ deleted: true, absent: false, ...flags }); }
    catch (error) {
      if (error?.lifecycleReason === 'APPLICATION_DATA_ABSENT') return Object.freeze({ deleted: false, absent: true, ...flags });
      if (error?.lifecycleReason === 'APPLICATION_IN_USE') error.inUse = true;
      throw error;
    }
  }
  async storageInventory() {
    return this.#call(['app-storage-inventory'], {}, false, { maxBytes: 131072, parse: parseStorageInventory });
  }
  async prepareTicket(input) {
    const value = request(input, ['ticketId', 'registrationId', 'versionId', 'environmentId', 'runId']);
    if (this.#requests.has(value.ticketId)) fail('TICKET_ALREADY_ATTEMPTED');
    await this.#installation(true);
    if (this.#closed) fail('HELPER_CHANNEL_CLOSED');
    if (this.#requests.has(value.ticketId)) fail('TICKET_ALREADY_ATTEMPTED');
    this.#requests.add(value.ticketId); // Lost ACK never retries.
    return this.#call(['app-ticket-prepare', value.ticketId, value.registrationId, value.versionId, value.environmentId, value.runId],
      { ticketId: value.ticketId, registrationId: value.registrationId, versionId: value.versionId }, true);
  }
  async inspectTicket(input) { const value = request(input, ['ticketId']); return this.#call(['app-ticket-inspect', value.ticketId], { ticketId: value.ticketId }); }
  async stageTicket(input) {
    const value = request(input, ['ticketId', 'registrationId', 'versionId', 'environmentId', 'runId']);
    if (this.#sessions.has(value.ticketId)) fail('TICKET_ALREADY_ATTEMPTED');
    await this.#installation(true);
    if (this.#closed) fail('HELPER_CHANNEL_CLOSED');
    if (this.#sessions.has(value.ticketId)) fail('TICKET_ALREADY_ATTEMPTED');
    const record = { phase: 'stage-intent', child: null, stream: null, ack: false, abandon: null }; this.#sessions.set(value.ticketId, record);
    return new Promise((resolve, reject) => {
      let pending = Buffer.alloc(0), ack = false, settled = false, poisoned = false;
      const lost = reason => { poisoned = true; pending = Buffer.alloc(0); record.phase = 'recovery-required'; try { record.stream?.stdin?.end(); } catch {}
        // EOF revokes via native guardian. Never SIGKILL a keeper holding utun.
        if (!settled) { settled = true; clearTimeout(timer); reject(refusal(reason)); } };
      const timer = setTimeout(() => lost('NATIVE_STAGE_UNCERTAIN'), this.#timeout);
      record.abandon = lost;
      try { record.stream = this.#spawnNative(['gui-launch-lease', value.ticketId]); } catch { lost('NATIVE_UNAVAILABLE'); return; }
      const child = record.stream;
      child.stderr.on('data', () => {}); child.once('error', () => lost('NATIVE_UNAVAILABLE')); child.stdin.on('error', () => lost('NATIVE_CHANNEL_LOST'));
      child.stdout.on('data', data => {
        if (poisoned) return;
        pending = Buffer.concat([pending, data]); if (pending.length > 8192) { lost('NATIVE_RESPONSE_INVALID'); return; }
        let newline;
        while (!poisoned && (newline = pending.indexOf(10)) >= 0) {
          const line = pending.subarray(0, newline); pending = pending.subarray(newline + 1);
          try {
            const event = JSON.parse(line.toString('utf8'));
            if (!object(event) || event.schema !== APP_KEEPER_PROTOCOL || event.ready !== false || event.protected !== false ||
                Object.entries(value).some(([key, expected]) => event[key] !== expected)) fail('NATIVE_BINDING_INVALID');
            if (!ack && event.event === 'stopped' && event.keeperPID === child.pid && event.persistentDenyObserved === true &&
                event.stoppedBeforeExec === true && Number.isSafeInteger(event.pid) && event.pid > 1 &&
                /^[0-9]{1,20}:[0-9]{6}$/.test(event.birth ?? '')) {
              ack = true; record.ack = true; record.phase = 'native-guarding-stopped'; record.child = Object.freeze({ pid: event.pid, birth: event.birth });
              settled = true; clearTimeout(timer); resolve(Object.freeze({ protocol: APP_KEEPER_PROTOCOL, ...value, ...record.child, ...flags, resumed: false }));
            } else if (ack && event.event === 'released' && event.childReaped === true && event.persistentDenyObserved === true && event.scopeQuiescentObserved === true) record.phase = 'native-released';
            else fail('NATIVE_RESPONSE_INVALID');
          } catch { lost('NATIVE_STAGE_UNCERTAIN'); }
        }
      });
      child.once('close', code => { if (!ack || code !== 0 || record.phase !== 'native-released') lost('NATIVE_STAGE_UNCERTAIN'); });
    });
  }
  stop(input) {
    const value = request(input, ['ticketId']), record = this.#sessions.get(value.ticketId);
    if (!record) fail('SESSION_UNKNOWN');
    if (!record.ack) record.abandon?.('NATIVE_STAGE_CANCELLED');
    record.phase = 'recovery-required'; try { record.stream?.stdin?.write('S'); record.stream?.stdin?.end(); } catch {}
    return { protocol: APP_KEEPER_PROTOCOL, ...flags, stopped: false, recoveryRequired: true };
  }
  shutdown() { this.#closed = true; for (const record of this.#sessions.values()) { if (record.phase !== 'native-released') { if (!record.ack) record.abandon?.('NATIVE_STAGE_CANCELLED'); record.phase = 'recovery-required'; try { record.stream?.stdin?.end(); } catch {} } }
    return { ...flags, cleanupRequired: [...this.#sessions.values()].some(record => record.phase !== 'native-released') }; }
}

export function newApplicationRegistration() { return { registrationId: randomUUID(), versionId: randomUUID() }; }
