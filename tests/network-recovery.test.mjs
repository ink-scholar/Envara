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
