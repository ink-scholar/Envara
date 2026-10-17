import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import * as filesystem from 'node:fs/promises';
import { LinkPreferences } from '../electron/link-preferences.mjs';
import { createLinkRoutingControls } from '../electron/link-routing-controls.mjs';

const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
async function fixture(t, { saved, systemEnabled = false, request, io = filesystem } = {}) {
  const root = await filesystem.mkdtemp(path.join(os.tmpdir(), 'envara-link-controls-'));
  t.after(() => filesystem.rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'link-preferences.json');
  if (saved) await filesystem.writeFile(file, JSON.stringify(saved));
  const preferences = new LinkPreferences({ file, filesystem: io });
  const events = [], system = { enabled: systemEnabled };
  const status = async () => ({ available: true, enabled: system.enabled, preference: preferences.snapshot().openInEnvironment,
    declined: Boolean(preferences.snapshot().declinedAt), previous: 'org.envara.fixture-browser' });
  const controls = createLinkRoutingControls({ preferences, status,
    requestSystem: async () => {
      events.push('request');
      if (request) await request();
      system.enabled = true;
      return { granted: true };
    },
    restoreSystem: async () => { events.push('restore'); system.enabled = false; },
  });
  return { root, file, preferences, events, system, status, controls };
}

test('new-user initialization, status reads and enabling internal links never request a default browser', async t => {
  const f = await fixture(t);
  assert.deepEqual(await f.preferences.load(), { openInEnvironment: true, declinedAt: null });
  assert.equal((await f.status()).enabled, false);
  assert.deepEqual(f.events, []);
  await assert.rejects(filesystem.access(f.file), { code: 'ENOENT' });
  const result = await f.controls.setPreference(true);
  assert.equal(result.preference, true);
  assert.equal(result.enabled, false);
  assert.deepEqual(f.events, []);
  assert.equal(JSON.parse(await filesystem.readFile(f.file, 'utf8')).openInEnvironment, true);
});

test('only the explicit system action requests a default browser, and existing consent survives initialization', async t => {
  const f = await fixture(t, { systemEnabled: true });
  await f.preferences.load();
  assert.equal((await f.status()).enabled, true);
  assert.deepEqual(f.events, []);
  await f.controls.setPreference(true);
  assert.deepEqual(f.events, []);
  f.system.enabled = false;
  assert.equal((await f.controls.requestSystem()).granted, true);
  assert.equal(f.system.enabled, true);
  assert.deepEqual(f.events, ['request']);
});

test('an explicit request loads a saved disabled preference and refuses before invoking the system helper', async t => {
  const f = await fixture(t, { saved: { openInEnvironment: false, declinedAt: null } });
  await assert.rejects(f.controls.requestSystem(), { code: 'LINK_ROUTER_PREFERENCE_DISABLED' });
  assert.deepEqual(f.events, []);
  assert.equal(f.preferences.snapshot().openInEnvironment, false);
});

test('disabling internal links keeps the existing behavior of restoring the system browser', async t => {
  const f = await fixture(t, { systemEnabled: true });
  const result = await f.controls.setPreference(false);
  assert.equal(result.preference, false);
  assert.equal(result.enabled, false);
  assert.deepEqual(f.events, ['restore']);
  assert.equal(JSON.parse(await filesystem.readFile(f.file, 'utf8')).openInEnvironment, false);
});

test('disabling system routing restores the browser without changing internal-link preferences or refusal history', async t => {
  const saved = { openInEnvironment: true, declinedAt: '2026-10-17T00:00:00.000Z' };
  const f = await fixture(t, { saved, systemEnabled: true });
  await f.preferences.load();
  const before = await filesystem.readFile(f.file, 'utf8');
  const result = await f.controls.disableSystem();
  assert.equal(result.preference, true);
  assert.equal(result.enabled, false);
  assert.deepEqual(f.events, ['restore']);
  assert.deepEqual(f.preferences.snapshot(), saved);
  assert.equal(await filesystem.readFile(f.file, 'utf8'), before);
});

test('failed preference persistence and invalid arguments cannot alter the system browser', async t => {
  const f = await fixture(t, { systemEnabled: true, io: { ...filesystem,
    rename: async () => { throw Object.assign(new Error('fixture'), { code: 'EIO' }); },
  } });
  await assert.rejects(f.controls.setPreference('false'), { code: 'LINK_ROUTER_REQUEST_INVALID' });
  await assert.rejects(f.controls.setPreference(false), { code: 'LINK_PREFERENCES_SAVE_FAILED' });
  assert.equal(f.preferences.snapshot().openInEnvironment, true);
  assert.equal(f.system.enabled, true);
  assert.deepEqual(f.events, []);
});

test('a request queued after an internal opt-out cannot re-enable system routing', async t => {
  const entered = deferred(), proceed = deferred();
  const f = await fixture(t, { systemEnabled: true, io: { ...filesystem,
    rename: async (...args) => { entered.resolve(); await proceed.promise; return filesystem.rename(...args); },
  } });
  const off = f.controls.setPreference(false);
  await entered.promise;
  const request = assert.rejects(f.controls.requestSystem(), { code: 'LINK_ROUTER_PREFERENCE_DISABLED' });
  proceed.resolve();
  await off;
  await request;
  assert.deepEqual(f.events, ['restore']);
  assert.equal(f.system.enabled, false);
});

test('system opt-out waits for an already requested confirmation and restores afterward', async t => {
  const entered = deferred(), proceed = deferred();
  const f = await fixture(t, { request: async () => { entered.resolve(); await proceed.promise; } });
  const on = f.controls.requestSystem();
  await entered.promise;
  const off = f.controls.disableSystem();
  assert.deepEqual(f.events, ['request']);
  proceed.resolve();
  await on;
  assert.equal((await off).preference, true);
  assert.deepEqual(f.events, ['request', 'restore']);
  assert.equal(f.system.enabled, false);
});
