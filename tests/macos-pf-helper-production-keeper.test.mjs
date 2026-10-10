import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { NativeApplicationCommands, APP_NATIVE_EXECUTABLE, APP_KEEPER_PROTOCOL } from '../native/macos-pf-routing/helper-production-native.mjs';

// These are simulated transport/lifecycle tests only. Every child is an
// in-memory EventEmitter: no native process, app, privilege or routing action
// occurs, and no simulated ACK is evidence of native custody or readiness.
const uuid = value => `00000000-0000-4000-8000-${String(value).padStart(12, '0')}`;
const request = Object.freeze({ ticketId: uuid(201), registrationId: uuid(101), versionId: uuid(1001), environmentId: uuid(3001), runId: uuid(4001) });
const installation = Object.freeze({ verified: true, runtimeVerified: true });
const refused = reason => error => error.code === 'APPLICATION_NATIVE_REFUSED' && error.reason === reason;
const falseFlags = value => { for (const flag of ['ready', 'protected', 'productionReady']) assert.equal(value[flag], false, flag); };
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }

class SimulatedKeeper extends EventEmitter {
  constructor(pid) {
    super(); this.pid = pid; this.stdin = new PassThrough(); this.stdout = new PassThrough(); this.stderr = new PassThrough();
    this.signals = []; this.input = [];
    this.stdin.on('data', data => this.input.push(Buffer.from(data)));
  }
  kill(signal) { this.signals.push(signal); return true; }
  frame(value) { this.stdout.write(Buffer.from(`${JSON.stringify(value)}\n`)); }
  close(code = 0) { this.emit('close', code); }
  dispose() { this.stdin.destroy(); this.stdout.destroy(); this.stderr.destroy(); }
}
function stopped(child, binding = request) {
  return { schema: APP_KEEPER_PROTOCOL, event: 'stopped', ...binding, ready: false, protected: false,
    keeperPID: child.pid, persistentDenyObserved: true, stoppedBeforeExec: true, pid: 9201, birth: '1700000000:123456' };
}
function released(binding = request) {
  return { schema: APP_KEEPER_PROTOCOL, event: 'released', ...binding, ready: false, protected: false,
    childReaped: true, persistentDenyObserved: true, scopeQuiescentObserved: true };
}
function harness({ inspectInstallation = async () => installation, timeoutMs = 50 } = {}) {
  const children = [], calls = [], spawned = deferred();
  const commands = new NativeApplicationCommands({ controlledSession: true, inspectInstallation, timeoutMs,
    spawnChild(executable, args, options) {
      assert.equal(executable, APP_NATIVE_EXECUTABLE);
      assert.deepEqual(options, { shell: false, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' }, stdio: ['pipe', 'pipe', 'pipe'] });
      const child = new SimulatedKeeper(9101 + children.length); children.push(child); calls.push([...args]); spawned.resolve(child); return child;
    } });
  return { commands, calls, children, spawned: spawned.promise,
    dispose() { commands.shutdown(); for (const child of children) child.dispose(); } };
}
async function simulatedRoot(callback) {
  const getuid = process.getuid, geteuid = process.geteuid;
  assert.equal(typeof getuid, 'function'); assert.notEqual(getuid(), 0, 'the actual test process must stay unprivileged');
  process.getuid = () => 0; process.geteuid = () => 0;
  try { await callback(); } finally { process.getuid = getuid; process.geteuid = geteuid; }
  assert.notEqual(process.getuid(), 0);
}
function recovery(h) {
  const status = h.commands.status(); falseFlags(status); assert.equal(status.protectedLaunchSupported, false);
  assert.deepEqual(status.sessions, [{ ticketId: request.ticketId, phase: 'recovery-required', recoveryRequired: true }]);
  assert.equal(h.children[0].stdin.writableEnded, true); assert.deepEqual(h.children[0].signals, [], 'keeper revocation uses EOF, never a simulated kill');
}

test('simulated timeout permanently rejects a late stopped ACK', async () => simulatedRoot(async () => {
  const h = harness();
  try {
    const rejection = assert.rejects(h.commands.stageTicket(request), refused('NATIVE_STAGE_UNCERTAIN'));
    const child = await h.spawned; await rejection;
    child.frame(stopped(child)); recovery(h);
    await assert.rejects(h.commands.stageTicket(request), refused('TICKET_ALREADY_ATTEMPTED'));
    assert.deepEqual(h.calls, [['gui-launch-lease', request.ticketId]]); child.frame(released()); child.close(); recovery(h);
  } finally { h.dispose(); }
}));

test('malformed keeper frame poisons a valid stopped ACK in the same chunk', async () => simulatedRoot(async () => {
  const h = harness();
  try {
    const rejection = assert.rejects(h.commands.stageTicket(request), refused('NATIVE_STAGE_UNCERTAIN'));
    const child = await h.spawned;
    child.stdout.write(Buffer.from(`{malformed-json}\n${JSON.stringify(stopped(child))}\n`));
    await rejection; recovery(h); child.frame(stopped(child)); child.frame(released()); child.close(); recovery(h);
  } finally { h.dispose(); }
}));

test('stop and shutdown before ACK keep late stopped frames in recovery', async () => simulatedRoot(async () => {
  for (const action of ['stop', 'shutdown']) {
    const h = harness();
    try {
      const rejection = assert.rejects(h.commands.stageTicket(request), refused('NATIVE_STAGE_CANCELLED'));
      const child = await h.spawned;
      const result = action === 'stop' ? h.commands.stop({ ticketId: request.ticketId }) : h.commands.shutdown();
      falseFlags(result);
      if (action === 'stop') { assert.equal(result.stopped, false); assert.equal(result.recoveryRequired, true); }
      else assert.equal(result.cleanupRequired, true);
      await rejection; child.frame(stopped(child)); child.frame(released()); child.close(); recovery(h);
      assert.deepEqual(h.calls, [['gui-launch-lease', request.ticketId]]);
    } finally { h.dispose(); }
  }
}));

test('concurrent same-ticket stage and preparation each permit only one simulated fixed command', async () => simulatedRoot(async () => {
  for (const operation of ['stageTicket', 'prepareTicket']) {
    const gate = deferred(); let inspections = 0;
    const h = harness({ inspectInstallation: async () => { inspections++; return inspections <= 2 ? gate.promise : installation; } });
    try {
      const outcomes = Promise.allSettled([h.commands[operation](request), h.commands[operation]({ ...request })]);
      assert.equal(inspections, 2); assert.equal(h.calls.length, 0); gate.resolve(installation);
      const child = await h.spawned;
      if (operation === 'prepareTicket') {
        // A native refusal envelope terminates the simulated one-shot command;
        // it deliberately claims no application identity or issued ticket.
        child.frame({ schema: 1, ok: false, error: 13, ready: false, protected: false, activatesSystem: false,
          applicationIdentityVerified: false, environmentLeaseVerified: false, ticketIssued: false,
          reason: 'LIVE_NATIVE_LAUNCH_AUTHORITY_REQUIRED', registrationId: '', versionId: '', ticketId: request.ticketId, snapshotContentSHA256: '' });
        child.close(1);
      }
      const results = await outcomes; assert.equal(results.every(result => result.status === 'rejected'), true);
      const reasons = results.map(result => result.reason.reason).sort();
      assert.deepEqual(reasons, ['TICKET_ALREADY_ATTEMPTED', operation === 'stageTicket' ? 'NATIVE_STAGE_UNCERTAIN' : 'NATIVE_OPERATION_REFUSED'].sort());
      assert.deepEqual(h.calls, [operation === 'stageTicket' ? ['gui-launch-lease', request.ticketId] :
        ['app-ticket-prepare', request.ticketId, request.registrationId, request.versionId, request.environmentId, request.runId]]);
      await assert.rejects(h.commands[operation](request), refused('TICKET_ALREADY_ATTEMPTED')); assert.equal(h.calls.length, 1);
      falseFlags(h.commands.status()); if (operation === 'stageTicket') recovery(h);
    } finally { h.dispose(); }
  }
}));

test('request mutation during installation inspection cannot replace the bound ticket or ACK identity', async () => simulatedRoot(async () => {
  const gate = deferred(); const h = harness({ inspectInstallation: async () => gate.promise });
  try {
    const mutable = { ...request }, attempt = h.commands.stageTicket(mutable);
    mutable.ticketId = uuid(299); mutable.registrationId = uuid(199); mutable.runId = uuid(499); mutable.consoleUID = 0;
    gate.resolve(installation); const child = await h.spawned;
    assert.deepEqual(h.calls, [['gui-launch-lease', request.ticketId]]);
    child.frame(stopped(child)); const result = await attempt;
    for (const [key, value] of Object.entries(request)) assert.equal(result[key], value);
    assert.equal(result.consoleUID, undefined); assert.equal(result.resumed, false); assert.equal(Object.isFrozen(result), true); falseFlags(result);
    child.frame(released()); child.close();
    assert.deepEqual(h.commands.status().sessions, [{ ticketId: request.ticketId, phase: 'native-released', recoveryRequired: false }]);
    const closed = h.commands.shutdown(); falseFlags(closed); assert.equal(closed.cleanupRequired, false);
  } finally { h.dispose(); }
}));

test('shutdown between completed inspection and its caller continuation refuses before simulated spawn', async () => simulatedRoot(async () => {
  const gate = deferred(), h = harness({ inspectInstallation: () => gate.promise });
  try {
    const rejection = assert.rejects(h.commands.stageTicket(request), refused('HELPER_CHANNEL_CLOSED'));
    gate.resolve(installation); queueMicrotask(() => h.commands.shutdown()); await rejection;
    assert.equal(h.calls.length, 0); assert.deepEqual(h.commands.status().sessions, []); falseFlags(h.commands.status());
  } finally { h.dispose(); }
}));
