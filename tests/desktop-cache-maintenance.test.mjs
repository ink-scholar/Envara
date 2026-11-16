import test from 'node:test';
import assert from 'node:assert/strict';
import { createDesktopCacheMaintenance } from '../electron/desktop-cache-maintenance.mjs';
import { DesktopEnvironmentTransferLock } from '../electron/environment-import-lifecycle.mjs';

function fixture(overrides = {}) {
  let options;
  const calls = [], token = 'a'.repeat(64);
  const state = { profiles: [{ id: 'example', name: 'Example' }], sessions: [] };
  const service = { profilesDir: '/owned/browseforge/profiles', starting: new Set(),
    remote: async () => state,
    request: async (method, route, args) => {
      calls.push({ method, route, args });
      return { data: route.endsWith('/acquire') ? { token } : { released: true } };
    }, ...overrides };
  const terminal = { sessions: new Map() }, transferLock = new DesktopEnvironmentTransferLock();
  const maintenance = createDesktopCacheMaintenance({ dataDir: '/owned', service, terminal, transferLock,
    factory: value => { options = value; return {
      inventory: async () => { await value.listProfiles(); await value.assertProfileIdle('example'); return { read: true }; },
      quarantine: args => value.withMaintenance(['example'], args.operation),
      restore: args => value.withMaintenance(['example'], args.operation), purge: async () => ({ deleted: true }),
    }; } });
  return { maintenance, service, terminal, transferLock, state, calls, options, token };
}

test('cache inventory performs no maintenance, health repair or route operation', async () => {
  const value = fixture({ assertStopped: () => { throw new Error('must not repair sessions'); } });
  assert.deepEqual(await value.maintenance.inventory({}), { read: true });
  assert.deepEqual(value.calls, []);
  value.state.sessions.push({ profile_id: 'example', session_id: 'uncertain' });
  await assert.rejects(value.maintenance.inventory({}), { code: 'CACHE_PROFILE_BUSY' });
  assert.deepEqual(value.calls, []);
});

test('cache mutations retain both the transfer gate and sidecar reservation through the operation', async () => {
  const value = fixture();
  const result = await value.maintenance.quarantine({ operation: async () => {
    assert.equal(value.calls.length, 1);
    await assert.rejects(value.transferLock.mutate('startProfile', { id: 'example' }, () => assert.fail('started'), 'example'), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
    return { complete: true };
  } });
  assert.equal(result.complete, true);
  assert.deepEqual(value.calls, [
    { method: 'POST', route: '/api/maintenance/acquire', args: { profile_ids: ['example'] } },
    { method: 'POST', route: '/api/maintenance/release', args: { token: value.token } },
  ]);
  assert.equal(value.transferLock.transferring, false);
});

test('a session appearing after acquire prevents file work and still releases the known token', async () => {
  const value = fixture();
  const request = value.service.request;
  value.service.request = async (...args) => {
    const result = await request(...args);
    if (args[1].endsWith('/acquire')) value.state.sessions.push({ profile_id: 'example' });
    return result;
  };
  await assert.rejects(value.maintenance.restore({ operation: () => assert.fail('changed files') }), { code: 'CACHE_PROFILE_BUSY' });
  assert.equal(value.calls.at(-1).route, '/api/maintenance/release');
});

test('failed operation stays primary and release failure is never a successful maintenance result', async () => {
  const value = fixture();
  const request = value.service.request;
  value.service.request = (...args) => args[1].endsWith('/release') ? Promise.reject(new Error('private detail')) : request(...args);
  const first = Object.assign(new Error('safe first failure'), { code: 'CACHE_MOVE_INCOMPLETE' });
  await assert.rejects(value.maintenance.quarantine({ operation: () => { throw first; } }), error => error === first);
  await assert.rejects(value.maintenance.restore({ operation: () => ({ complete: true }) }), { code: 'CACHE_MAINTENANCE_RELEASE_FAILED' });
});

test('unknown acquire outcome cannot run file work or invent an unlock token', async () => {
  const value = fixture({ request: async () => ({ data: { token: 'bad' } }) });
  await assert.rejects(value.maintenance.quarantine({ operation: () => assert.fail('changed files') }), { code: 'CACHE_MAINTENANCE_UNAVAILABLE' });
});

test('shutdown waits for owned maintenance and refuses new inventory', async () => {
  const value = fixture();
  let finish, entered;
  const ready = new Promise(resolve => { entered = resolve; });
  const operation = value.maintenance.quarantine({ operation: () => { entered(); return new Promise(resolve => { finish = resolve; }); } });
  await ready;
  let closed = false;
  const closing = value.maintenance.close().then(() => { closed = true; });
  assert.throws(() => value.maintenance.inventory({}), { code: 'APP_CLOSING' });
  assert.equal(closed, false);
  finish({ complete: true });
  await operation; await closing;
  assert.equal(value.calls.at(-1).route, '/api/maintenance/release');
});

test('unfinished terminal or uncertain application state blocks maintenance', async () => {
  const value = fixture();
  value.terminal.sessions.set('terminal', { profileId: 'example', status: 'error', finished: false });
  await assert.rejects(value.maintenance.inventory({}), { code: 'CACHE_PROFILE_BUSY' });
  assert.deepEqual(value.calls, []);
});
