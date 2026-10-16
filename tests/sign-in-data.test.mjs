import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { signInDataRows, runningSignInDataId, signInDataInUse, SignInDataNames } from '../electron/sign-in-data.mjs';
import { ApplicationService } from '../electron/application-service.mjs';
import { pfAttachEnvironmentId, pfApplicationRegistrationId } from '../native/macos-pf-routing/policy.mjs';

const application = { id: 'binding', profileId: 'environment', name: 'Notes', path: '/Applications/Notes.app' };
const profile = { id: application.profileId, name: 'Workspace' };
const environmentId = pfAttachEnvironmentId(profile.id);
const registrationId = pfApplicationRegistrationId(application.path);
const id = `${environmentId}:${registrationId}`;
const owned = { environmentId, registrationId, bytes: 0, modifiedAt: null, dataScope: 'environment', hasDataDirectory: true };

test('a binding alone does not claim environment data or an erasable directory', () => {
  const [row] = signInDataRows({ applications: [application], profiles: [profile] });
  assert.equal(row.dataScope, 'unavailable');
  assert.equal(row.hasDataDirectory, false);
  assert.equal(row.bytes, 0);
  assert.equal(row.application.bindingId, application.id);
});

test('legacy or incomplete inventory records do not manufacture isolated data', () => {
  for (const inventory of [
    [{ environmentId, registrationId, bytes: 1234 }],
    [{ ...owned, dataScope: 'unavailable' }],
    [{ ...owned, hasDataDirectory: false }],
  ]) {
    const [row] = signInDataRows({ applications: [application], inventory });
    assert.equal(row.dataScope, 'unavailable');
    assert.equal(row.hasDataDirectory, false);
  }
});

test('owned existing empty directories retain their actual scope and running lock', () => {
  const [row] = signInDataRows({ applications: [application], profiles: [profile], inventory: [owned], running: new Set([id]) });
  assert.equal(row.dataScope, 'environment');
  assert.equal(row.hasDataDirectory, true);
  assert.equal(row.bytes, 0);
  assert.equal(row.running, true);
  assert.deepEqual(row.environment, { id: profile.id, name: profile.name });
  assert.equal(runningSignInDataId(application), id);
});

test('removed application data keeps its remembered name, including an existing empty directory', () => {
  const [row] = signInDataRows({ profiles: [profile], inventory: [owned], names: { [registrationId]: { name: application.name, path: application.path } } });
  assert.equal(row.application.name, application.name);
  assert.equal(row.application.bindingId, null);
  assert.equal(row.hasDataDirectory, true);
  assert.equal(row.dataScope, 'environment');
});

test('inventory sizes are carried through and separate environments keep separate rows', () => {
  const second = { ...application, id: 'second-binding', profileId: 'other-environment' };
  const rows = signInDataRows({ applications: [application, second], inventory: [{ ...owned, bytes: 4567 }] });
  assert.equal(rows.length, 2);
  assert.equal(rows.find(row => row.id === id).bytes, 4567);
  assert.equal(rows.find(row => row.id !== id).dataScope, 'unavailable');
});

async function namesFixture(t) {
  const dataDir = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-sign-in-names-')));
  t.after(() => rm(dataDir, { recursive: true, force: true }));
  return { dataDir, store: new SignInDataNames({ dataDir }) };
}

test('concurrent name snapshots retain every remembered application on disk and after restart', async t => {
  const { dataDir, store } = await namesFixture(t);
  await store.read();
  const second = { ...application, name: 'Other', path: '/Applications/Other.app' };
  await Promise.all([store.remember([application]), store.remember([second])]);
  const expected = [application.name, second.name].sort();
  assert.deepEqual(Object.values(await store.read()).map(item => item.name).sort(), expected);
  assert.deepEqual(Object.values(await new SignInDataNames({ dataDir }).read()).map(item => item.name).sort(), expected);
});

test('failed name persistence removes its temporary file and leaves the cache available for a retry', async t => {
  const { dataDir, store } = await namesFixture(t);
  const before = await store.remember([application]);
  const serialized = await readFile(store.file, 'utf8');
  await rm(store.file);
  await mkdir(store.file);
  const second = { ...application, name: 'Other', path: '/Applications/Other.app' };
  await assert.rejects(store.remember([second]));
  assert.deepEqual(await store.read(), before);
  assert.deepEqual(await readdir(dataDir), [path.basename(store.file)]);
  await rm(store.file, { recursive: true });
  await writeFile(store.file, serialized, { mode: 0o600 });
  const retried = await store.remember([second]);
  assert.deepEqual(Object.values(retried).map(item => item.name).sort(), [application.name, second.name].sort());
  assert.deepEqual(await new SignInDataNames({ dataDir }).read(), retried);
});

test('application data remains locked while cleanup retains a live session or route', async () => {
  const { signInDataInUse } = await import('../electron/sign-in-data.mjs');
  assert.equal(typeof signInDataInUse, 'function');
  for (const state of [
    { status: 'starting' }, { status: 'running' }, { status: 'stopping' },
    { status: 'error', sessionId: 'owned-session' },
    { status: 'error', routeId: 'owned-route' },
    { status: 'error', cleanupUncertain: true },
  ]) assert.equal(signInDataInUse({ ...application, ...state }), true, JSON.stringify(state));
});

test('preflight failures and successfully cleaned errors do not lock application data', async () => {
  const { signInDataInUse } = await import('../electron/sign-in-data.mjs');
  assert.equal(typeof signInDataInUse, 'function');
  for (const state of [
    null,
    { ...application, status: 'stopped' },
    { ...application, status: 'error', sessionId: null, routeId: null, cleanupUncertain: false,
      initialFailure: { code: 'APPLICATION_INVALID_PATH', message: 'Synthetic preflight failure' } },
    { ...application, status: 'error', sessionId: null, routeId: null, cleanupUncertain: false,
      initialFailure: { code: 'APPLICATION_APP_STAGE_TIMEOUT', message: 'Synthetic initial failure' },
      cleanupFailure: { code: 'APPLICATION_CLEANUP_FAILED', message: 'Synthetic prior cleanup failure' } },
  ]) assert.equal(signInDataInUse(state), false, JSON.stringify(state));
});

const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

async function mainDeletionBranch(method) {
  const source = await readFile(new URL('../electron/main.mjs', import.meta.url), 'utf8');
  const next = method === 'clearApplicationData' ? 'linkRouterStatus' : 'showApplicationWindow';
  const start = source.indexOf(`  if (method === '${method}') {`);
  const end = source.indexOf(`  if (method === '${next}')`, start);
  assert(start >= 0 && end > start, 'the actual main deletion branch must be present');
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  // A shared binding preserves main's live reservation: capturing a boolean
  // here would incorrectly keep it true after the trial's finally releases it.
  return new AsyncFunction('method', 'args', 'context', `with (context) { ${source.slice(start, end)} }`);
}

for (const method of ['clearApplicationData', 'deleteSignInData']) {
  test(`${method} refuses a live trial before its queue and cannot erase after a later stop`, async () => {
    const invoke = await mainDeletionBranch(method), started = deferred(), stop = deferred();
    const applications = Object.create(ApplicationService.prototype);
    applications.ready = Promise.resolve(); applications.queue = Promise.resolve();
    let erased = 0;
    const context = { applications, notionTrialReserved: true, signInDataInUse, pfApplicationRegistrationId,
      signInDataSnapshot: async () => ({ items: [{ ...owned, id, running: context.notionTrialReserved }] }),
      eraseAttachedApplicationData: async () => { erased++; return ['fixture']; },
      eraseEnvironmentData: async () => { erased++; return ['fixture']; } };
    applications.snapshot = async () => ({ applications: [{ ...application, status: 'stopped' }] });
    applications.routing = { controlledNotionTrialSnapshot: () => ({ applicationId: application.id, active: context.notionTrialReserved }) };
    const trial = applications.serialized(async () => { started.resolve(); await stop.promise; })
      .finally(() => { context.notionTrialReserved = false; });
    await started.promise;
    const deletion = invoke(method, { id: method === 'clearApplicationData' ? application.id : id }, context);
    const outcome = deletion.then(() => ({ accepted: true }), error => ({ code: error.code }));
    try {
      const immediate = await Promise.race([outcome, new Promise(resolve => setImmediate(() => resolve({ pending: true })))]);
      assert.deepEqual(immediate, { code: 'APPLICATION_RUNNING' }, 'refusal must not wait for the running trial to stop');
      assert.equal(context.notionTrialReserved, true);
      assert.equal(erased, 0);
    } finally {
      stop.resolve(); await trial; await outcome;
    }
    assert.equal(context.notionTrialReserved, false);
    assert.equal(erased, 0, 'stopping later must not execute an old destructive request');
    assert.equal(await applications.serialized(() => 'queue remains available'), 'queue remains available');
  });
}
