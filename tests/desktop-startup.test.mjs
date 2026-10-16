import test from 'node:test';
import assert from 'node:assert/strict';
import { createDesktopStartup } from '../electron/desktop-startup.mjs';

const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
const code = expected => error => error?.code === expected;

test('pending bootstrap reads wait, while actions refuse without queuing', async () => {
  const gate = deferred(), phases = []; let initialized = 0, reads = 0;
  const startup = createDesktopStartup({ initialize: async () => { initialized++; await gate.promise; return 'initialized'; }, onState: phase => phases.push(phase) });
  assert.equal(startup.phase, 'idle');
  assert.throws(startup.assertReady, code('APP_STARTING'));
  const read = startup.read(() => { reads++; return { settings: { language: 'ja' } }; });
  const first = startup.start();
  assert.equal(first, startup.ready);
  assert.equal(startup.start(), first);
  await turn();
  assert.equal(startup.phase, 'starting'); assert.equal(initialized, 1); assert.equal(reads, 0);
  assert.throws(startup.assertReady, code('APP_STARTING'));
  gate.resolve();
  assert.equal(await first, 'initialized');
  assert.deepEqual(await read, { settings: { language: 'ja' } });
  await startup.settled;
  assert.equal(startup.phase, 'ready'); assert.equal(reads, 1);
  assert.deepEqual(phases, ['starting', 'ready']);
  assert.equal(startup.start(), first); assert.equal(initialized, 1);
  assert.doesNotThrow(startup.assertReady);
});

test('initialization failure stays intact for every consumer but still releases cleanup', async () => {
  const error = Object.assign(new Error('fixture store failed'), { code: 'FIXTURE_STORAGE_FAILED' });
  const startup = createDesktopStartup({ initialize: () => { throw error; } });
  const ready = startup.start();
  await assert.rejects(ready, actual => actual === error);
  assert.equal(await startup.settled, undefined);
  assert.equal(startup.phase, 'failed');
  assert.throws(startup.assertReady, actual => actual === error);
  await assert.rejects(startup.read(() => assert.fail('A failed startup must not execute a read')), actual => actual === error);
  assert.equal(startup.start(), ready);
});

test('closing promptly rejects waiting reads but cleanup waits for the in-flight checkpoint', async () => {
  const gate = deferred(), stages = []; let didSettle = false;
  const startup = createDesktopStartup({ initialize: async ({ checkOpen }) => {
    stages.push('owned resource allocated'); await gate.promise; checkOpen(); stages.push('next resource allocated');
  } });
  const ready = startup.start();
  const read = startup.read(() => assert.fail('Closing startup cannot unlock a queued read'));
  void startup.settled.then(() => { didSettle = true; });
  await turn();
  assert.equal(startup.close(), startup.settled);
  assert.equal(startup.phase, 'closing');
  await assert.rejects(ready, code('APP_CLOSING'));
  await assert.rejects(read, code('APP_CLOSING'));
  assert.throws(startup.assertReady, code('APP_CLOSING'));
  assert.equal(didSettle, false, 'Cleanup cannot race an initializer still allocating resources');
  gate.resolve(); await startup.settled;
  assert.equal(didSettle, true);
  assert.deepEqual(stages, ['owned resource allocated']);
});

test('a late initializer that omitted a checkpoint cannot restore readiness after close', async () => {
  const gate = deferred(); let runs = 0;
  const startup = createDesktopStartup({ initialize: async () => { runs++; return gate.promise; } });
  const ready = startup.start(); await turn(); startup.close(); gate.resolve('late success');
  await startup.settled;
  await assert.rejects(ready, code('APP_CLOSING'));
  await assert.rejects(startup.read(() => assert.fail('A late success must not reopen startup')), code('APP_CLOSING'));
  assert.equal(startup.phase, 'closing'); assert.equal(startup.start(), ready); assert.equal(runs, 1);
});

test('closing before start prevents all initialization and settles the cleanup barrier', async () => {
  const startup = createDesktopStartup({ initialize: () => assert.fail('Closed startup cannot initialize') });
  const closing = startup.close();
  assert.equal(startup.close(), closing);
  await closing;
  assert.equal(startup.start(), startup.ready);
  await assert.rejects(startup.ready, code('APP_CLOSING'));
  assert.throws(startup.checkOpen, code('APP_CLOSING'));
});

test('a fulfilled ready promise does not authorize new reads after shutdown starts', async () => {
  const startup = createDesktopStartup({ initialize: async () => 'ready' });
  await startup.start(); await startup.close();
  assert.throws(startup.assertReady, code('APP_CLOSING'));
  await assert.rejects(startup.read(() => assert.fail('Previously ready is no longer launch authority')), code('APP_CLOSING'));
});

test('a read already in progress cannot deliver a stale snapshot after shutdown', async () => {
  const gate = deferred(); let reading = false;
  const startup = createDesktopStartup({ initialize: async () => {} });
  await startup.start();
  const read = startup.read(async () => { reading = true; await gate.promise; return { settings: {} }; });
  await turn(); assert.equal(reading, true);
  startup.close(); gate.resolve();
  await assert.rejects(read, code('APP_CLOSING'));
});

test('reentrant state observers cannot start twice or release a closed startup', async () => {
  let startup, initialized = 0;
  startup = createDesktopStartup({ initialize: () => { initialized++; }, onState: phase => {
    if (phase === 'starting') { startup.start(); startup.close(); }
  } });
  await assert.rejects(startup.start(), code('APP_CLOSING'));
  await startup.settled;
  assert.equal(startup.phase, 'closing'); assert.equal(initialized, 0);
});

test('observer failure does not replace backend readiness or its original failure', async () => {
  const error = new Error('fixture initialization failure');
  const startup = createDesktopStartup({ initialize: () => { throw error; }, onState: () => { throw new Error('observer failure'); } });
  await assert.rejects(startup.start(), actual => actual === error);
  await startup.settled;
  assert.equal(startup.phase, 'failed');
});
