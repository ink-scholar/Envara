// Inert fixtures only. No native authorizer, privilege prompt, PF command,
// application, proxy or network is invoked by this file.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createPFAuthorizedChannelMux } from '../electron/macos-pf-channel-mux.mjs';

/* A real Node peer that answers each request with a frame carrying the same id,
 * optionally out of order, and that exits after a chosen number of requests. */
function peerProgram({ reverse = false, deathAfter = -1 } = {}) {
  /* The peer is written as source for a child Node process, so the newline it
   * writes is built from a character code: a nested escape here is easy to get
   * wrong and would make the peer itself fail to parse. */
  return `import readline from 'node:readline';
    const LF = String.fromCharCode(10);
    let count = 0;
    const answer = line => { const request = JSON.parse(line);
      if (${deathAfter} >= 0 && count >= ${deathAfter}) process.exit(7);
      const frame = { protocol: 'envara.application-routing', version: 1, id: request.id,
        result: { runId: request.params && request.params.runId, n: count++ } };
      process.stdout.write(JSON.stringify(frame) + LF); };
    readline.createInterface({ input: process.stdin }).on('line', line => {
      if (${reverse}) setTimeout(() => answer(line), 5); else answer(line);
    });
    process.on('SIGTERM', () => process.exit(0));`;
}
function fixture(t, options = {}) {
  let child = null, spawnCount = 0;
  const mux = createPFAuthorizedChannelMux({ spawnRootControlledLifecycle: () => {
    spawnCount++;
    child = spawn(process.execPath, ['--input-type=module', '-e', peerProgram(options)], { stdio: ['pipe', 'pipe', 'pipe'] });
    return child;
  } });
  t.after(async () => { await mux.dispose(); if (child && child.exitCode === null) child.kill('SIGTERM'); });
  // The shared carrier starts lazily on the first request, so a test that needs
  // the peer to exist waits for it instead of assuming it is already up.
  const ready = async () => { while (spawnCount === 0) await new Promise(resolve => setTimeout(resolve, 2)); };
  return { mux, spawnCount: () => spawnCount, ready };
}

const LINE = (id, run) => `${JSON.stringify({ protocol: 'envara.application-routing', version: 1, id, method: 'status', params: { runId: run } })}\n`;
/* The shared carrier starts on the FIRST WRITE, so a test writes first and only
 * then waits for that spawn to happen. A request written before the carrier is
 * up is held by the mux and delivered when it starts, which is exactly the
 * behaviour under test. Waiting for the spawn before writing would deadlock. */
async function exchange(target, ready, id, run, expected = 1) {
  const frames = [];
  const collected = new Promise(resolve => {
    target.on('data', line => { frames.push(JSON.parse(line.toString('utf8'))); if (frames.length >= expected) resolve(frames); });
  });
  target.stdin.write(LINE(id, run));
  await ready();
  return collected;
}
const settle = ms => new Promise(resolve => setTimeout(resolve, ms));

test('one authorized spawn serves many run channels, and each reply reaches its own run', async t => {
  const f = fixture(t, { reverse: true });
  const first = f.mux.acquire({ key: 'run-1' });
  const second = f.mux.acquire({ key: 'run-2' });
  assert.equal(f.spawnCount(), 0, 'nothing is spawned before the first request');

  const [firstFrames, secondFrames] = await Promise.all([
    exchange(first, f.ready, 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa', 'run-1'),
    exchange(second, f.ready, 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb', 'run-2')]);
  assert.equal(firstFrames[0].id, 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa');
  assert.equal(firstFrames[0].result.runId, 'run-1', 'a reply is never delivered to the other run');
  assert.equal(secondFrames[0].id, 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb');
  assert.equal(secondFrames[0].result.runId, 'run-2');
  assert.equal(f.spawnCount(), 1, 'the shared carrier is spawned exactly once for both runs');
});

test('ending one run detaches only that run and keeps the shared session usable', async t => {
  const f = fixture(t);
  const first = f.mux.acquire({ key: 'run-1' });
  const second = f.mux.acquire({ key: 'run-2' });
  const [opened] = await exchange(second, f.ready, 'cccccccc-3333-4333-8333-cccccccccccc', 'run-2');
  assert.equal(opened.result.runId, 'run-2');

  const closed = new Promise(resolve => first.once('close', (code, signal) => resolve({ code, signal })));
  first.end();
  assert.deepEqual(await closed, { code: 0, signal: null }, 'the run ends cleanly');

  const [frame] = await exchange(second, f.ready, 'dddddddd-4444-4444-8444-dddddddddddd', 'run-2');
  assert.equal(frame.result.runId, 'run-2', 'the other run keeps working');
  assert.equal(f.mux.snapshot().connected, true, 'the shared session stayed open');
  assert.equal(f.mux.snapshot().targets, 1);
});

test('a duplicate request id is refused instead of being routed twice', async t => {
  const f = fixture(t, { reverse: true });
  const target = f.mux.acquire({ key: 'run-1' });
  const id = 'eeeeeeee-5555-4555-8555-eeeeeeeeeeee';
  target.stdin.write(LINE(id, 'run-1'));
  await f.ready();
  assert.throws(() => target.stdin.write(LINE(id, 'run-1')), { code: 'PF_HELPER_UNAVAILABLE' });
  await settle(30);
});

test('a run that ended receives nothing further, even for a late reply', async t => {
  const f = fixture(t, { reverse: true });
  const first = f.mux.acquire({ key: 'run-1' }), second = f.mux.acquire({ key: 'run-2' });
  const late = [];
  first.on('data', line => late.push(JSON.parse(line.toString('utf8'))));
  // This run ends while its own reply is still in flight.
  first.stdin.write(LINE('ffffffff-6666-4666-8666-ffffffffffff', 'run-1'));
  await f.ready();
  first.end();
  const [reply] = await exchange(second, f.ready, '99999999-7777-4777-8777-999999999999', 'run-2');
  assert.equal(reply.result.runId, 'run-2', 'the surviving run is unaffected');
  await settle(60);
  assert.deepEqual(late, [], 'a detached run receives nothing after it ended');
});

test('dispose ends every run channel and tears the shared session down', async t => {
  const f = fixture(t);
  const target = f.mux.acquire({ key: 'run-1' });
  const closed = new Promise(resolve => target.once('close', (code, signal) => resolve({ code, signal })));
  await f.mux.dispose();
  assert.deepEqual(await closed, { code: null, signal: null });
  assert.equal(f.mux.snapshot().disposed, true);
  assert.equal(f.mux.snapshot().targets, 0);
  assert.throws(() => f.mux.acquire({ key: 'run-2' }), { code: 'PF_HELPER_UNAVAILABLE' });
});

test('a shared child that dies is reported to every attached run', async t => {
  const f = fixture(t, { deathAfter: 0 });
  const first = f.mux.acquire({ key: 'run-1' }), second = f.mux.acquire({ key: 'run-2' });
  const errors = [];
  first.on('error', error => errors.push(['first', error.code]));
  second.on('error', error => errors.push(['second', error.code]));
  // The peer exits on the very first request: the shared session dies while an
  // attached application is still running.
  first.stdin.write(LINE('12121212-8888-4888-8888-121212121212', 'run-1'));
  await settle(500);
  assert.equal(errors.length, 2, 'both attached runs are told the session ended');
  assert.deepEqual(errors.map(([which]) => which).sort(), ['first', 'second']);
  assert.deepEqual([...new Set(errors.map(([, code]) => code))], ['PF_HELPER_UNAVAILABLE']);
});
