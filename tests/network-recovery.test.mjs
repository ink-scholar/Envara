import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { createNetworkRecoveryMonitor } from '../electron/network-recovery.mjs';

const flush = async () => { for (let index = 0; index < 5; index++) await new Promise(resolve => setImmediate(resolve)); };
const interfaces = address => ({ en0: [{ address, family: 'IPv4', internal: false }], lo0: [{ address: '127.0.0.1', family: 'IPv4', internal: true }] });
function clock() {
  const timeouts = new Set(), intervals = new Set();
  return { timeouts, intervals,
    setTimeout(fn) { timeouts.add(fn); return fn; }, clearTimeout(fn) { timeouts.delete(fn); },
    setInterval(fn) { intervals.add(fn); return fn; }, clearInterval(fn) { intervals.delete(fn); },
    fire() { const callbacks = [...timeouts]; timeouts.clear(); for (const fn of callbacks) fn(); } };
}

test('same-interface DHCP changes and offline-online hints trigger fresh recovery without startup probes', async () => {
  const timers = clock(); let address = '192.0.2.10', online = true, calls = 0;
  const monitor = createNetworkRecoveryMonitor({ timers, interfaces: () => interfaces(address), isOnline: () => online,
    recover: async () => { calls++; return { ok: true }; } });
  assert.equal(calls, 0);
  monitor.check(); await flush(); assert.equal(calls, 0);
  online = false; monitor.check(); await flush(); assert.equal(calls, 1);
  address = '198.51.100.20'; online = true; monitor.check(); await flush(); assert.equal(calls, 2);
  monitor.check(); await flush(); assert.equal(calls, 2);
  monitor.close(); assert.equal(timers.intervals.size, 0);
});

test('late DHCP failures retry and a real network event supersedes slow recovery', async () => {
  const timers = clock(), powerMonitor = new EventEmitter(); let calls = 0, finish; const options = [];
  const monitor = createNetworkRecoveryMonitor({ timers, powerMonitor, interfaces: () => interfaces('192.0.2.10'),
    recover: async value => { options.push(value); calls++; if (calls === 1) return { ok: false }; if (calls === 2) return new Promise(resolve => { finish = resolve; }); return { ok: true }; } });
  powerMonitor.emit('resume'); await flush(); assert.equal(calls, 1); assert.equal(timers.timeouts.size, 1);
  timers.fire(); await flush(); assert.equal(calls, 2);
  powerMonitor.emit('resume'); await flush(); assert.equal(calls, 3);
  finish({ ok: false }); await flush(); assert.equal(calls, 3); assert.equal(timers.timeouts.size, 0);
  assert.deepEqual(options.map(({ retry }) => retry), [false, true, false]);
  assert.equal(options[1].signal.aborted, true);
  monitor.close(); assert.equal(powerMonitor.listenerCount('resume'), 0);
});

test('shutdown prevents queued retry and a late recovery from scheduling more work', async () => {
  const timers = clock(), powerMonitor = new EventEmitter(); let finish, calls = 0, activeSignal;
  const monitor = createNetworkRecoveryMonitor({ timers, powerMonitor, interfaces: () => ({}),
    recover: ({ signal }) => { activeSignal = signal; calls++; return new Promise(resolve => { finish = resolve; }); } });
  powerMonitor.emit('resume'); monitor.close(); assert.equal(activeSignal.aborted, true); finish({ ok: false }); await flush();
  assert.equal(timers.timeouts.size, 0); assert.equal(timers.intervals.size, 0);
  monitor.check(); powerMonitor.emit('resume'); assert.equal(calls, 1);
});

function recoveryClock() {
  let now = Date.parse('2026-01-02T03:04:05.000Z');
  const timeouts = new Map(), intervals = new Set();
  return {
    timeouts, intervals, nowMs: () => now,
    setTimeout(fn, delay) { const timer = {}; timeouts.set(timer, { fn, at: now + delay }); return timer; },
    clearTimeout(timer) { timeouts.delete(timer); },
    setInterval(fn) { intervals.add(fn); return fn; },
    clearInterval(fn) { intervals.delete(fn); },
    advance(milliseconds) {
      now += milliseconds;
      for (const [timer, entry] of [...timeouts].sort((a, b) => a[1].at - b[1].at)) {
        if (entry.at <= now && timeouts.delete(timer)) entry.fn();
      }
    },
  };
}

const iso = value => new Date(value).toISOString();
const stateKeys = ['attempt', 'checkedAt', 'phase', 'reason', 'retryAt', 'revision'];

function recoveryFixture(t, options = {}) {
  const timers = recoveryClock(), powerMonitor = new EventEmitter(), changes = [];
  const monitor = createNetworkRecoveryMonitor({
    timers, nowMs: timers.nowMs, powerMonitor,
    interfaces: () => interfaces('192.0.2.10'),
    onChange: state => changes.push(state),
    recover: async () => ({ ok: true, checkedRouteCount: 1 }),
    ...options,
  });
  t.after(() => monitor.close());
  return { monitor, timers, powerMonitor, changes };
}

test('recovery status starts idle without a probe and exposes detached, bounded snapshots', async t => {
  let calls = 0;
  const { monitor, timers, changes } = recoveryFixture(t, {
    recover: async () => { calls++; return { ok: true, checkedRouteCount: 1, privateEndpoint: 'fixture.invalid' }; },
  });
  const initial = monitor.snapshot();
  assert.deepEqual(Object.keys(initial).sort(), stateKeys);
  assert.equal(initial.phase, 'idle');
  assert.equal(initial.reason, null);
  assert.equal(initial.attempt, 0);
  assert.equal(initial.checkedAt, null);
  assert.equal(initial.retryAt, null);
  assert.ok(Number.isSafeInteger(initial.revision));
  initial.phase = 'recovered';
  assert.equal(monitor.snapshot().phase, 'idle');
  monitor.check(); await flush();
  assert.equal(calls, 0);
  assert.equal(timers.timeouts.size, 0);

  await monitor.retryNow(); await flush();
  assert.equal(calls, 1);
  assert.equal(monitor.snapshot().phase, 'recovered');
  assert.equal(monitor.snapshot().checkedAt, iso(timers.nowMs()));
  assert.ok(changes.some(state => state.phase === 'checking'));
  for (const state of changes) assert.deepEqual(Object.keys(state).sort(), stateKeys);
  for (let index = 1; index < changes.length; index++) assert.ok(changes[index].revision > changes[index - 1].revision);
  changes.at(-1).phase = 'waiting';
  assert.equal(monitor.snapshot().phase, 'recovered');
  assert.doesNotMatch(JSON.stringify(monitor.snapshot()), /192\.0\.2|fixture\.invalid/);
});

test('failed checks publish retry deadlines and automatic attempts retain their own result timestamps', async t => {
  const calls = [], finish = [];
  let address = '192.0.2.10';
  const { monitor, timers, changes } = recoveryFixture(t, {
    interfaces: () => interfaces(address), retryDelaysMs: [1000, 3000],
    recover: options => { calls.push(options); return new Promise(resolve => finish.push(resolve)); },
  });
  address = '192.0.2.11'; monitor.check(); await flush();
  assert.deepEqual(calls.map(({ retry }) => retry), [false]);
  assert.equal(monitor.snapshot().phase, 'checking');
  assert.equal(monitor.snapshot().reason, 'network-change');
  assert.equal(monitor.snapshot().attempt, 1);
  assert.equal(monitor.snapshot().retryAt, null);

  timers.advance(250); finish[0]({ ok: false, checkedRouteCount: 1 }); await flush();
  const firstFailure = monitor.snapshot();
  assert.equal(firstFailure.phase, 'waiting');
  assert.equal(firstFailure.attempt, 1);
  assert.equal(firstFailure.checkedAt, iso(timers.nowMs()));
  assert.equal(firstFailure.retryAt, iso(timers.nowMs() + 1000));
  timers.advance(999); await flush(); assert.equal(calls.length, 1);
  timers.advance(1); await flush();
  assert.equal(calls.length, 2);
  assert.equal(calls[1].retry, true);
  assert.equal(monitor.snapshot().phase, 'checking');
  assert.equal(monitor.snapshot().reason, 'retry');
  assert.equal(monitor.snapshot().attempt, 2);
  assert.equal(monitor.snapshot().retryAt, null);

  timers.advance(400); finish[1]({ ok: false, checkedRouteCount: 1 }); await flush();
  assert.equal(monitor.snapshot().checkedAt, iso(timers.nowMs()));
  assert.equal(monitor.snapshot().retryAt, iso(timers.nowMs() + 3000));
  timers.advance(3000); await flush();
  assert.equal(calls.length, 3);
  assert.equal(monitor.snapshot().attempt, 3);
  finish[2]({ ok: true, checkedRouteCount: 1 }); await flush();
  assert.equal(monitor.snapshot().phase, 'recovered');
  assert.equal(monitor.snapshot().checkedAt, iso(timers.nowMs()));
  assert.equal(monitor.snapshot().retryAt, null);
  assert.equal(timers.timeouts.size, 0);
  assert.deepEqual(changes.map(({ phase }) => phase).filter(phase => phase !== 'idle'),
    ['checking', 'waiting', 'checking', 'waiting', 'checking', 'recovered']);
});

test('manual retry advances a waiting round immediately and coalesces repeated clicks during a check', async t => {
  const calls = []; let finish;
  const { monitor, timers, powerMonitor } = recoveryFixture(t, {
    recover: options => {
      calls.push(options);
      return calls.length === 1 ? Promise.resolve({ ok: false, checkedRouteCount: 1 }) : new Promise(resolve => { finish = resolve; });
    },
  });
  powerMonitor.emit('resume'); await flush();
  assert.equal(monitor.snapshot().phase, 'waiting');
  assert.equal(timers.timeouts.size, 1);
  timers.advance(300);
  const first = monitor.retryNow({}); await flush();
  assert.equal(calls.length, 2);
  assert.equal(calls[1].retry, true);
  assert.equal(monitor.snapshot().attempt, 2);
  assert.equal(monitor.snapshot().reason, 'manual');
  assert.equal(monitor.snapshot().phase, 'checking');
  assert.equal(timers.timeouts.size, 0);
  const checking = monitor.snapshot();
  const second = monitor.retryNow(), third = monitor.retryNow({}); await flush();
  assert.equal(calls.length, 2);
  assert.deepEqual(monitor.snapshot(), checking);
  timers.advance(1000); await flush(); assert.equal(calls.length, 2);
  finish({ ok: true, checkedRouteCount: 1 });
  await Promise.all([first, second, third]); await flush();
  assert.equal(monitor.snapshot().phase, 'recovered');
  assert.equal(timers.timeouts.size, 0);
});

test('manual checks from idle and recovered start fresh rounds instead of retrying old failures', async t => {
  const calls = [];
  const { monitor, timers } = recoveryFixture(t, {
    recover: async options => { calls.push(options); return { ok: true, checkedRouteCount: 1 }; },
  });
  await monitor.retryNow(); await flush();
  assert.equal(monitor.snapshot().phase, 'recovered');
  assert.equal(monitor.snapshot().reason, 'manual');
  assert.equal(monitor.snapshot().attempt, 1);
  const first = monitor.snapshot();
  timers.advance(5000);
  await monitor.retryNow({}); await flush();
  assert.deepEqual(calls.map(({ retry }) => retry), [false, false]);
  assert.equal(monitor.snapshot().attempt, 1);
  assert.equal(monitor.snapshot().checkedAt, iso(timers.nowMs()));
  assert.ok(monitor.snapshot().revision > first.revision);
});

test('manual retry notices a network change before polling and refreshes every selected route', async t => {
  let address = '192.0.2.10';
  const calls = [];
  const { monitor, timers, powerMonitor } = recoveryFixture(t, {
    interfaces: () => interfaces(address),
    recover: async options => {
      calls.push(options);
      return { ok: calls.length > 1, checkedRouteCount: 1 };
    },
  });
  powerMonitor.emit('resume'); await flush();
  assert.equal(monitor.snapshot().phase, 'waiting');
  assert.equal(timers.timeouts.size, 1);

  // DHCP changed before the periodic monitor could observe the new signature.
  address = '198.51.100.20';
  await monitor.retryNow(); await flush();
  assert.deepEqual(calls.map(({ retry }) => retry), [false, false]);
  assert.equal(monitor.snapshot().attempt, 1);
  assert.equal(monitor.snapshot().phase, 'recovered');
  assert.equal(timers.timeouts.size, 0);

  monitor.check(); await flush();
  assert.equal(calls.length, 2);
});

test('a completed check with no selected routes returns idle without claiming restored connectivity', async t => {
  const { monitor, timers, changes } = recoveryFixture(t, {
    recover: async () => ({ ok: true, checkedRouteCount: 0 }),
  });
  await monitor.retryNow(); await flush();
  assert.equal(monitor.snapshot().phase, 'idle');
  assert.equal(monitor.snapshot().retryAt, null);
  assert.equal(timers.timeouts.size, 0);
  assert.equal(changes.some(({ phase }) => phase === 'recovered'), false);
});

test('network changes and wake events supersede pending work without late status or retry publication', async t => {
  const calls = [], finish = []; let address = '192.0.2.10';
  const { monitor, timers, powerMonitor, changes } = recoveryFixture(t, {
    interfaces: () => interfaces(address),
    recover: options => { calls.push(options); return new Promise(resolve => finish.push(resolve)); },
  });
  const pending = monitor.retryNow(); await flush();
  address = '192.0.2.11'; monitor.check(); await flush();
  assert.equal(calls.length, 2);
  assert.equal(calls[0].signal.aborted, true);
  assert.equal(monitor.snapshot().reason, 'network-change');
  assert.equal(monitor.snapshot().attempt, 1);
  powerMonitor.emit('resume'); await flush();
  assert.equal(calls.length, 3);
  assert.equal(calls[1].signal.aborted, true);
  assert.equal(monitor.snapshot().reason, 'resume');
  assert.equal(monitor.snapshot().attempt, 1);
  assert.deepEqual(calls.map(({ retry }) => retry), [false, false, false]);
  timers.advance(200); finish[2]({ ok: true, checkedRouteCount: 1 }); await flush();
  const current = monitor.snapshot(), count = changes.length;
  timers.advance(500); finish[0]({ ok: false, checkedRouteCount: 1 }); finish[1]({ ok: false, checkedRouteCount: 1 });
  await pending; await flush();
  assert.deepEqual(monitor.snapshot(), current);
  assert.equal(changes.length, count);
  assert.equal(timers.timeouts.size, 0);
});

test('closing clears observable recovery state and prevents late completion from publishing', async t => {
  let finish, signal;
  const { monitor, timers, powerMonitor, changes } = recoveryFixture(t, {
    recover: options => { signal = options.signal; return new Promise(resolve => { finish = resolve; }); },
  });
  const pending = monitor.retryNow(); await flush();
  monitor.close();
  assert.equal(signal.aborted, true);
  assert.equal(monitor.snapshot().phase, 'idle');
  assert.equal(monitor.snapshot().retryAt, null);
  assert.equal(timers.timeouts.size, 0);
  assert.equal(timers.intervals.size, 0);
  assert.equal(powerMonitor.listenerCount('resume'), 0);
  const closed = monitor.snapshot(), count = changes.length;
  finish({ ok: true, checkedRouteCount: 1 }); await pending; await flush();
  assert.deepEqual(monitor.snapshot(), closed);
  assert.equal(changes.length, count);
  await assert.rejects(async () => monitor.retryNow(), error => error.code === 'APP_CLOSING');
});

test('manual recovery accepts only an empty plain request without accepting routing inputs', async t => {
  let calls = 0, reads = 0;
  const { monitor } = recoveryFixture(t, {
    recover: async () => { calls++; return { ok: true, checkedRouteCount: 1 }; },
  });
  const accessor = Object.defineProperty({}, 'url', { get() { reads++; return 'https://fixture.invalid'; } });
  for (const request of [null, [], 'retry', 1, true, new Date(0), new (class Request {})(),
    { url: 'https://fixture.invalid' }, { retry: true }, { signal: new AbortController().signal },
    { [Symbol('route')]: 'fixture' }, accessor]) {
    await assert.rejects(async () => monitor.retryNow(request), error => error.code === 'INVALID_NETWORK_RECOVERY_REQUEST');
  }
  assert.equal(calls, 0);
  assert.equal(reads, 0);
  assert.equal(monitor.snapshot().phase, 'idle');
  await monitor.retryNow({}); await flush();
  assert.equal(calls, 1);
});
