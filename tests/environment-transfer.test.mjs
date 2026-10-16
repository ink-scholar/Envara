import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { ClaudeAccountStore } from '../electron/claude-account-store.mjs';
import { EXPORT_SCHEMA, readEnvironmentExport } from '../electron/environment-export.mjs';
import { applyPendingApplicationData, assertEnvironmentIdle, checkedExportManifest, exportEnvironment, restoreEnvironment } from '../electron/environment-transfer.mjs';
import { finishPendingEnvironmentImport } from '../electron/environment-import-lifecycle.mjs';
import { pfApplicationRegistrationId, pfAttachEnvironmentId } from '../native/macos-pf-routing/policy.mjs';

const PASSWORD = 'test export password';
const PROFILE_ID = 'prof_transfer_source';
const IMPORTED_ID = 'prof_transfer_imported';
const OTHER_ID = 'prof_unrelated';
const TARGET_APP = { id: 'app_code', profileId: PROFILE_ID, identity: 'signed-test-code', name: 'Visual Studio Code', path: '/Applications/Visual Studio Code.app', status: 'stopped' };
const OTHER_APP = { id: 'app_other', profileId: OTHER_ID, identity: 'signed-test-other', name: 'Other application', path: '/Applications/Other.app', status: 'running' };

async function put(root, relative, contents = relative) {
  const target = path.join(root, relative);
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, contents);
  return target;
}
async function absent(target) { await assert.rejects(lstat(target), { code: 'ENOENT' }); }
const profileDocument = () => ({ schema: 'envara.profiles', version: 2, profiles: [{ id: PROFILE_ID, name: 'Transfer source', timezone: 'Asia/Manila' }] });
const manifestFor = (applications = [], accounts = []) => ({ schema: EXPORT_SCHEMA, version: 1, profile: profileDocument(), terminal: { accounts }, applications, keychainIncluded: false });
const applicationManifest = (application = TARGET_APP, section = 'app-0') => ({ section, identity: application.identity, name: application.name, path: application.path });

async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-transfer-test-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const browserRoot = path.join(root, 'browser-environments'), terminalRoot = path.join(root, 'terminal'), appRoot = path.join(root, 'application-data');
  const profilesDir = path.join(terminalRoot, 'profiles'), dataDir = path.join(root, 'envara-data');
  await Promise.all([browserRoot, profilesDir, appRoot, dataDir].map(directory => mkdir(directory, { recursive: true })));
  const accountStore = new ClaudeAccountStore({ root: terminalRoot });
  await accountStore.ready;
  const calls = [], bound = [], inspected = [], sessions = new Map(), apps = [structuredClone(TARGET_APP), structuredClone(OTHER_APP)], trials = new Map();
  const service = {
    async checkedDirectory({ id }) {
      assert.ok([PROFILE_ID, IMPORTED_ID, OTHER_ID].includes(id), 'service receives an explicit known environment');
      const directory = path.join(browserRoot, id);
      await mkdir(directory, { recursive: true });
      return directory;
    },
    async call(method, request) { calls.push({ method, request }); assert.equal(method, 'exportProfiles'); assert.deepEqual(request, { id: PROFILE_ID }); return profileDocument(); },
  };
  const terminal = { profilesDir, claudeAccounts: accountStore, async snapshot({ id }) { return { profiles: [{ profileId: id, sessions: sessions.get(id) ?? [] }, { profileId: OTHER_ID, sessions: [{ status: 'running' }] }] }; } };
  const applications = {
    async snapshot() { return { applications: apps }; },
    routing: { controlledNotionTrialSnapshot({ applicationId }) { return trials.get(applicationId); } },
    async inspectApplication(filename, options) { inspected.push({ filename, options }); return { ...TARGET_APP }; },
    async saveApplication(request) { bound.push(request); return request.application; },
  };
  const registration = (id = PROFILE_ID, app = TARGET_APP) => path.join(appRoot, pfAttachEnvironmentId(id), pfApplicationRegistrationId(app.path));
  return { root, browserRoot, profilesDir, appRoot, dataDir, service, terminal, applications, calls, bound, inspected, sessions, apps, trials, registration, profile: { id: PROFILE_ID, name: 'Transfer source', status: 'stopped' } };
}

test('assertEnvironmentIdle refuses each live browser, terminal, application and controlled trial state', async t => {
  const f = await fixture(t);
  for (const status of ['starting', 'running']) await t.test(`browser ${status}`, async () => {
    await assert.rejects(assertEnvironmentIdle({ ...f, profile: { ...f.profile, status } }), { code: 'EXPORT_ENVIRONMENT_RUNNING' });
  });
  for (const status of ['starting', 'running', 'closing']) await t.test(`terminal ${status}`, async () => {
    f.sessions.set(PROFILE_ID, [{ status }]);
    try { await assert.rejects(assertEnvironmentIdle(f), { code: 'EXPORT_ENVIRONMENT_RUNNING' }); }
    finally { f.sessions.delete(PROFILE_ID); }
  });
  for (const status of ['starting', 'running', 'stopping']) await t.test(`application ${status}`, async () => {
    f.apps[0].status = status;
    try { await assert.rejects(assertEnvironmentIdle(f), { code: 'EXPORT_ENVIRONMENT_RUNNING' }); }
    finally { f.apps[0].status = 'stopped'; }
  });
  f.trials.set(TARGET_APP.id, { active: true });
  await assert.rejects(assertEnvironmentIdle(f), { code: 'EXPORT_ENVIRONMENT_RUNNING' });
  f.trials.clear();
  f.sessions.set(PROFILE_ID, [{ status: 'exited' }, { status: 'closed' }]);
  await assertEnvironmentIdle(f); // Other environments' live terminals/apps do not block this export.
  await assertEnvironmentIdle({ profile: f.profile });
});

test('exportEnvironment refuses invalid passwords and live environments before reading configuration or creating a file', async t => {
  const f = await fixture(t), file = path.join(f.root, 'refused.envara');
  await assert.rejects(exportEnvironment({ ...f, file, password: 'short' }), { code: 'EXPORT_PASSWORD_INVALID' });
  await assert.rejects(exportEnvironment({ ...f, file, password: PASSWORD, profile: { ...f.profile, status: 'running' } }), { code: 'EXPORT_ENVIRONMENT_RUNNING' });
  assert.deepEqual(f.calls, []);
  await absent(file);
});

test('an encrypted environment transfer preserves browser sign-ins, terminal/Claude profiles and scoped application data without programs, caches or another environment', async t => {
  const f = await fixture(t), account = await f.terminal.claudeAccounts.create(PROFILE_ID, 'Work login');
  const sourceBrowser = path.join(await f.service.checkedDirectory({ id: PROFILE_ID }), 'browser-data');
  const sourceTerminal = path.join(f.profilesDir, PROFILE_ID), sourceApplication = f.registration();
  const browserFiles = { 'Default/Cookies': 'browser-auth', 'Default/Local Storage/site.db': 'site-state', 'Default/Service Worker/offline': 'offline-document' };
  const terminalFiles = { 'home/.envara_history': 'claude --help\n', 'claude/settings.json': '{"theme":"dark"}', 'claude/.claude.json': '{"onboardingComplete":true}', [`claude-accounts/${account.id}/config.json`]: 'account-settings' };
  const appFiles = { 'UserData/Local State': 'app-state', 'UserData/Default/Cookies': 'app-auth', 'UserData/Service Worker/offline': 'offline-app-document', 'Home/.config/preferences': 'scoped-home', 'Extensions/test-extension/package.json': 'extension-settings' };
  for (const [name, data] of Object.entries(browserFiles)) await put(sourceBrowser, name, data);
  for (const [name, data] of Object.entries(terminalFiles)) await put(sourceTerminal, name, data);
  for (const [name, data] of Object.entries(appFiles)) await put(sourceApplication, name, data);
  for (const name of ['Default/Cache/bytes', 'Default/Code Cache/bytes', 'SingletonLock', 'SingletonCookie', 'DevToolsActivePort']) await put(sourceBrowser, name, 'not-exported');
  for (const name of ['tmp/run', 'home/.cache/cache', 'home/.local/share/claude/version', 'home/.local/bin/claude', 'SingletonSocket']) await put(sourceTerminal, name, 'not-exported');
  for (const name of ['Cache/cache', 'Temp/run', 'Program/Executable', 'UserData/Cache/cache', 'UserData/code.lock']) await put(sourceApplication, name, 'not-exported');
  await put(f.registration(OTHER_ID, OTHER_APP), 'UserData/Cookies', 'other-environment-secret');
  const outside = await put(f.root, 'host-credentials', 'host-secret-not-exported');
  await symlink(outside, path.join(sourceTerminal, 'host-link'));
  const file = path.join(f.root, 'transfer.envara');
  const result = await exportEnvironment({ ...f, file, password: PASSWORD, root: f.appRoot, platform: 'darwin', appVersion: '0.5.test' });
  assert.deepEqual(result.applications, [TARGET_APP.name]);
  assert.ok(result.entries > 0 && result.bytes > 0);
  assert.deepEqual(f.calls, [{ method: 'exportProfiles', request: { id: PROFILE_ID } }]);
  const encrypted = await readFile(file);
  for (const secret of ['browser-auth', 'app-auth', 'account-settings', 'host-secret-not-exported', 'other-environment-secret']) assert.equal(encrypted.includes(Buffer.from(secret)), false);
  const staging = path.join(f.root, 'staging');
  const manifest = checkedExportManifest(await readEnvironmentExport({ file, password: PASSWORD, staging }));
  assert.equal(manifest.envara, '0.5.test');
  assert.equal(manifest.keychainIncluded, false);
  assert.ok(!Number.isNaN(Date.parse(manifest.createdAt)));
  assert.deepEqual(manifest.profile, profileDocument());
  assert.deepEqual(manifest.terminal.accounts, [{ id: account.id, name: 'Work login' }]);
  assert.deepEqual(manifest.applications, [applicationManifest()]);
  for (const [section, files] of [['browser', browserFiles], ['terminal', terminalFiles], ['app-0', appFiles]])
    for (const [name, data] of Object.entries(files)) assert.equal(await readFile(path.join(staging, section, name), 'utf8'), data);
  for (const name of ['browser/Default/Cache', 'browser/Default/Code Cache', 'browser/SingletonLock', 'terminal/tmp', 'terminal/home/.cache', 'terminal/home/.local/share/claude', 'terminal/home/.local/bin/claude', 'terminal/host-link', 'app-0/Cache', 'app-0/Temp', 'app-0/Program', 'app-0/UserData/Cache', 'app-0/UserData/code.lock', 'app-1']) await absent(path.join(staging, name));
  const restored = await restoreEnvironment({ ...f, staging, manifest, profileId: IMPORTED_ID, platform: 'darwin' });
  assert.deepEqual(restored, { browser: true, terminal: true, applications: [{ name: TARGET_APP.name, bound: true, reason: null }] });
  const importedBrowser = path.join(await f.service.checkedDirectory({ id: IMPORTED_ID }), 'browser-data');
  for (const [name, data] of Object.entries(browserFiles)) assert.equal(await readFile(path.join(importedBrowser, name), 'utf8'), data);
  for (const [name, data] of Object.entries(terminalFiles)) assert.equal(await readFile(path.join(f.profilesDir, IMPORTED_ID, name), 'utf8'), data);
  assert.deepEqual((await f.terminal.claudeAccounts.list(IMPORTED_ID)).filter(item => !item.default), [{ id: account.id, name: 'Work login', default: false }]);
  assert.deepEqual(f.bound, [{ application: { profileId: IMPORTED_ID, path: TARGET_APP.path, name: TARGET_APP.name } }]);
  assert.deepEqual(f.inspected, [{ filename: TARGET_APP.path, options: { platform: 'darwin' } }]);
  await absent(f.registration(IMPORTED_ID)); // Import never creates the privileged application's directories.
  const importedApp = { ...TARGET_APP, profileId: IMPORTED_ID };
  for (const name of ['UserData', 'Home', 'Extensions']) await put(f.registration(IMPORTED_ID), `${name}/first-run`, 'fresh-initialization');
  const cache = await put(f.registration(IMPORTED_ID), 'Cache/current', 'current-cache');
  assert.deepEqual(await applyPendingApplicationData({ ...f, application: importedApp, root: f.appRoot }), { applied: true });
  for (const [name, data] of Object.entries(appFiles)) assert.equal(await readFile(path.join(f.registration(IMPORTED_ID), name), 'utf8'), data);
  for (const name of ['UserData', 'Home', 'Extensions']) await absent(path.join(f.registration(IMPORTED_ID), name, 'first-run'));
  assert.equal(await readFile(cache, 'utf8'), 'current-cache');
  assert.deepEqual(await applyPendingApplicationData({ ...f, application: importedApp, root: f.appRoot }), { applied: false });
  assert.equal(await readFile(path.join(sourceBrowser, 'Default', 'Cookies'), 'utf8'), 'browser-auth', 'source data remains unchanged');
});

test('non-macOS export omits privileged application data and missing optional data sources are harmless', async t => {
  const f = await fixture(t), file = path.join(f.root, 'configuration-only.envara');
  const result = await exportEnvironment({ profile: f.profile, service: { call: f.service.call }, applications: f.applications, file, password: PASSWORD, root: f.appRoot, platform: 'win32' });
  assert.deepEqual(result, { entries: 0, bytes: 0, applications: [] });
  const manifest = await readEnvironmentExport({ file, password: PASSWORD, staging: path.join(f.root, 'staging') });
  assert.deepEqual(manifest.applications, []);
  assert.deepEqual(manifest.terminal.accounts, []);
});

test('checkedExportManifest accepts exactly one environment and rejects malformed profile/application/account shapes', async t => {
  const accountId = `account_${'a'.repeat(32)}`;
  const good = manifestFor([applicationManifest()], [{ id: accountId, name: 'Work' }]);
  assert.equal(checkedExportManifest(good), good);
  const cases = [
    ['missing manifest', () => null],
    ['wrong export schema', value => { value.schema = 'another.export'; return value; }],
    ['wrong export version', value => { value.version = 2; return value; }],
    ['wrong profile schema', value => { value.profile.schema = 'other'; return value; }],
    ['wrong profile version', value => { value.profile.version = 1; return value; }],
    ['profile list missing', value => { delete value.profile.profiles; return value; }],
    ['no profiles', value => { value.profile.profiles = []; return value; }],
    ['multiple profiles', value => { value.profile.profiles.push({ name: 'extra' }); return value; }],
    ['applications missing', value => { delete value.applications; return value; }],
    ['too many applications', value => { value.applications = Array.from({ length: 101 }, (_, i) => applicationManifest(TARGET_APP, `app-${i}`)); return value; }],
    ['wrong section order', value => { value.applications[0].section = 'app-1'; return value; }],
    ['unknown section', value => { value.applications[0].section = 'terminal'; return value; }],
    ['duplicate section', value => { value.applications.push(applicationManifest({ ...TARGET_APP, identity: 'another-identity' })); return value; }],
    ['duplicate application identity', value => { value.applications.push(applicationManifest(TARGET_APP, 'app-1')); return value; }],
    ['null application', value => { value.applications[0] = null; return value; }],
    ['non-string identity', value => { value.applications[0].identity = 7; return value; }],
    ['empty identity', value => { value.applications[0].identity = ''; return value; }],
    ['non-string name', value => { value.applications[0].name = {}; return value; }],
    ['non-string application path', value => { value.applications[0].path = null; return value; }],
    ['relative application path', value => { value.applications[0].path = '../Other.app'; return value; }],
    ['NUL in application path', value => { value.applications[0].path = '/Applications/Code\0.app'; return value; }],
    ['invalid accounts shape', value => { value.terminal.accounts = {}; return value; }],
    ['null account', value => { value.terminal.accounts = [null]; return value; }],
    ['invalid account id', value => { value.terminal.accounts[0].id = '../outside'; return value; }],
    ['default account metadata', value => { value.terminal.accounts[0].id = 'default'; return value; }],
    ['empty account name', value => { value.terminal.accounts[0].name = '   '; return value; }],
    ['account name too long', value => { value.terminal.accounts[0].name = 'x'.repeat(81); return value; }],
    ['control character in account name', value => { value.terminal.accounts[0].name = 'Work\n'; return value; }],
    ['duplicate account id', value => { value.terminal.accounts.push({ id: accountId, name: 'Personal' }); return value; }],
    ['duplicate normalized account name', value => { value.terminal.accounts.push({ id: `account_${'b'.repeat(32)}`, name: 'ｗｏｒｋ' }); return value; }],
    ['too many accounts', value => { value.terminal.accounts = Array.from({ length: 20 }, (_, i) => ({ id: `account_${i.toString(16).padStart(32, '0')}`, name: `Login ${i}` })); return value; }],
  ];
  for (const [name, change] of cases) await t.test(name, () => assert.throws(() => checkedExportManifest(change(structuredClone(good))), { code: 'EXPORT_FORMAT_INVALID' }));
  assert.equal(checkedExportManifest({ ...manifestFor(), terminal: undefined }).applications.length, 0, 'configuration-only legacy export may have no account metadata');
});

test('restoreEnvironment refuses a nonempty browser target without deleting its data or consuming staged sign-ins', async t => {
  const f = await fixture(t), staging = path.join(f.root, 'staging');
  const staged = await put(staging, 'browser/Default/Cookies', 'incoming-auth');
  const target = path.join(await f.service.checkedDirectory({ id: IMPORTED_ID }), 'browser-data');
  const existing = await put(target, 'Default/Cookies', 'existing-auth');
  await assert.rejects(restoreEnvironment({ ...f, staging, manifest: manifestFor(), profileId: IMPORTED_ID }), { code: 'IMPORT_TARGET_NOT_EMPTY' });
  assert.equal(await readFile(existing, 'utf8'), 'existing-auth');
  assert.equal(await readFile(staged, 'utf8'), 'incoming-auth');
});

test('restoreEnvironment accepts an empty browser target and does not require optional terminal or application managers', async t => {
  const f = await fixture(t), staging = path.join(f.root, 'staging');
  await put(staging, 'browser/Default/Cookies', 'incoming-auth');
  await mkdir(path.join(await f.service.checkedDirectory({ id: IMPORTED_ID }), 'browser-data'));
  assert.deepEqual(await restoreEnvironment({ service: f.service, dataDir: f.dataDir, staging, manifest: manifestFor(), profileId: IMPORTED_ID }), { browser: true, terminal: false, applications: [] });
  assert.equal(await readFile(path.join(f.browserRoot, IMPORTED_ID, 'browser-data', 'Default', 'Cookies'), 'utf8'), 'incoming-auth');
});

test('a fresh import commit conflict preserves a concurrent writer through lifecycle rollback', async t => {
  const f = await fixture(t), staging = path.join(f.root, 'staging');
  await put(staging, 'browser/Default/Cookies', 'incoming-auth');
  const parent = await f.service.checkedDirectory({ id: IMPORTED_ID }), target = path.join(parent, 'browser-data');
  await mkdir(target);
  const originalCopy = fs.promises.cp;
  let deletedProfiles = 0;
  const pending = { document: profileDocument(), bundle: { staging, manifest: manifestFor() } };
  const backend = { async call(method) {
    if (method === 'importProfiles') return { actionResult: { createdIds: [IMPORTED_ID] } };
    if (method === 'deleteProfile') { deletedProfiles++; await rm(parent, { recursive: true, force: true }); return {}; }
    throw new Error('Unexpected backend operation');
  } };
  fs.promises.cp = async (...args) => {
    await originalCopy(...args);
    // Deterministic competing writer after validation, before commit. This is
    // the same interleaving an external caller/process can cause in practice.
    if (args[0] === path.join(staging, 'browser')) await put(target, 'new-user-data', 'must survive');
  };
  syncBuiltinESMExports();
  try {
    await assert.rejects(finishPendingEnvironmentImport({ pending, service: backend,
      restore: async profileId => {
        try { return await restoreEnvironment({ ...f, staging, manifest: manifestFor(), profileId }); }
        catch (error) { assert.equal(error.code, 'IMPORT_TARGET_NOT_EMPTY'); throw error; }
      }, discard: async () => { throw new Error('Failed import must retain staging'); } }), { code: 'IMPORT_ROLLBACK_INCOMPLETE' });
  } finally { fs.promises.cp = originalCopy; syncBuiltinESMExports(); }
  assert.equal(deletedProfiles, 0, 'lifecycle must not undo the safe refusal by deleting the environment');
  assert.deepEqual(pending.createdResult.actionResult.createdIds, [IMPORTED_ID]);
  assert.equal(await readFile(path.join(target, 'new-user-data'), 'utf8'), 'must survive');
  assert.equal(await readFile(path.join(staging, 'browser/Default/Cookies'), 'utf8'), 'incoming-auth');
  await absent(path.join(target, 'Default/Cookies'));
  assert.deepEqual(await readdir(parent), ['browser-data']);
});

test('restoreEnvironment refuses existing terminal directories and files rather than overwriting history or settings', async t => {
  for (const relative of ['home/.claude/settings.json', '.zsh_history', 'workspace.json']) await t.test(relative, async t => {
    const f = await fixture(t), staging = path.join(f.root, 'staging');
    const staged = await put(staging, `terminal/${relative}`, 'incoming-data');
    const target = await put(path.join(f.profilesDir, IMPORTED_ID), relative, 'existing-data');
    await assert.rejects(restoreEnvironment({ ...f, staging, manifest: manifestFor(), profileId: IMPORTED_ID }), { code: 'IMPORT_TARGET_NOT_EMPTY' });
    assert.equal(await readFile(target, 'utf8'), 'existing-data');
    assert.equal(await readFile(staged, 'utf8'), 'incoming-data');
  });
});

test('restoreEnvironment retains pending application data when a local application is absent, changed or refused', async t => {
  for (const reason of ['missing', 'identity-mismatch', 'inspection-error']) await t.test(reason, async t => {
    const f = await fixture(t), staging = path.join(f.root, 'staging');
    await put(staging, 'app-0/UserData/Cookies', 'pending-auth');
    f.applications.inspectApplication = async () => {
      if (reason === 'inspection-error') throw Object.assign(new Error('Unsupported'), { code: 'APPLICATION_UNSUPPORTED' });
      return reason === 'missing' ? null : { identity: 'other-signer' };
    };
    const result = await restoreEnvironment({ ...f, staging, manifest: manifestFor([applicationManifest()]), profileId: IMPORTED_ID, platform: 'darwin' });
    assert.deepEqual(result.applications, [{ name: TARGET_APP.name, bound: false, reason: reason === 'inspection-error' ? 'APPLICATION_UNSUPPORTED' : 'APPLICATION_NOT_FOUND' }]);
    assert.deepEqual(f.bound, []);
    const pendingRoot = path.join(f.dataDir, 'imports', 'applications', IMPORTED_ID), directories = await readdir(pendingRoot);
    assert.equal(directories.length, 1);
    const pending = path.join(pendingRoot, directories[0]);
    assert.equal(await readFile(path.join(pending, 'UserData', 'Cookies'), 'utf8'), 'pending-auth');
    assert.deepEqual(JSON.parse(await readFile(path.join(pending, 'pending.json'), 'utf8')), { identity: TARGET_APP.identity, name: TARGET_APP.name, path: TARGET_APP.path });
    assert.equal((await lstat(path.join(pending, 'pending.json'))).mode & 0o777, 0o600);
    await absent(f.registration(IMPORTED_ID));
  });
});

test('missing and non-directory staging sections are not restored, while application bindings are restored without prior data', async t => {
  const f = await fixture(t), staging = path.join(f.root, 'staging');
  await put(staging, 'browser', 'file-not-a-data-directory');
  const outside = path.join(f.root, 'outside');
  await put(outside, 'secrets', 'not-imported');
  await symlink(outside, path.join(staging, 'terminal'));
  assert.deepEqual(await restoreEnvironment({ ...f, staging, manifest: manifestFor([applicationManifest()]), profileId: IMPORTED_ID }), { browser: false, terminal: false, applications: [{ name: TARGET_APP.name, bound: true, reason: null }] });
  assert.deepEqual(f.bound, [{ application: { profileId: IMPORTED_ID, path: TARGET_APP.path, name: TARGET_APP.name } }]);
  await absent(path.join(f.profilesDir, IMPORTED_ID));
  assert.equal(await readFile(path.join(outside, 'secrets'), 'utf8'), 'not-imported');
});

test('an account adoption failure rolls back every restored section, preserves staging and permits a complete retry', async t => {
  const f = await fixture(t), staging = path.join(f.root, 'staging');
  const account = await f.terminal.claudeAccounts.create(PROFILE_ID, 'Imported login');
  const stagedFiles = { 'browser/Default/Cookies': 'browser-sign-in', 'terminal/home/.envara_history': 'claude\n', 'terminal/claude/settings.json': 'claude-settings', 'app-0/UserData/Cookies': 'application-sign-in' };
  for (const [name, data] of Object.entries(stagedFiles)) await put(staging, name, data);
  const browserTarget = path.join(await f.service.checkedDirectory({ id: IMPORTED_ID }), 'browser-data');
  await mkdir(browserTarget);
  const manifest = manifestFor([applicationManifest()], [{ id: account.id, name: account.name }]);
  const originalAdopt = f.terminal.claudeAccounts.adopt.bind(f.terminal.claudeAccounts);
  f.terminal.claudeAccounts.adopt = async () => { throw Object.assign(new Error('metadata write failed'), { code: 'EIO' }); };
  await assert.rejects(restoreEnvironment({ ...f, staging, manifest, profileId: IMPORTED_ID, platform: 'darwin' }), { code: 'EIO' });
  assert.deepEqual(await readdir(browserTarget), [], 'the formerly empty browser target stays empty');
  await absent(path.join(f.profilesDir, IMPORTED_ID));
  assert.deepEqual(await readdir(path.join(f.dataDir, 'imports', 'applications', IMPORTED_ID)), [], 'no partial pending sign-ins survive');
  assert.deepEqual(f.bound, []);
  assert.deepEqual(f.inspected, []);
  for (const [name, data] of Object.entries(stagedFiles)) assert.equal(await readFile(path.join(staging, name), 'utf8'), data, `staging survives: ${name}`);
  assert.deepEqual(await readdir(path.join(f.browserRoot, IMPORTED_ID)), ['browser-data'], 'temporary browser copies are removed');
  assert.deepEqual(await readdir(f.profilesDir), [], 'temporary terminal copies are removed');
  assert.deepEqual((await f.terminal.claudeAccounts.list(IMPORTED_ID)).map(item => item.id), ['default']);
  f.terminal.claudeAccounts.adopt = originalAdopt;
  const result = await restoreEnvironment({ ...f, staging, manifest, profileId: IMPORTED_ID, platform: 'darwin' });
  assert.deepEqual(result, { browser: true, terminal: true, applications: [{ name: TARGET_APP.name, bound: true, reason: null }] });
  assert.equal(await readFile(path.join(browserTarget, 'Default', 'Cookies'), 'utf8'), 'browser-sign-in');
  assert.equal(await readFile(path.join(f.profilesDir, IMPORTED_ID, 'home', '.envara_history'), 'utf8'), 'claude\n');
  assert.equal((await f.terminal.claudeAccounts.list(IMPORTED_ID))[1].id, account.id);
});

test('restoreEnvironment rejects an aliased terminal parent before changing another section', async t => {
  const f = await fixture(t), staging = path.join(f.root, 'staging'), outside = path.join(f.root, 'other-profiles');
  await put(staging, 'browser/Default/Cookies', 'incoming-browser');
  await put(staging, 'terminal/home/.envara_history', 'incoming-history');
  await mkdir(outside);
  await rm(f.profilesDir, { recursive: true });
  await symlink(outside, f.profilesDir);
  await assert.rejects(restoreEnvironment({ ...f, staging, manifest: manifestFor(), profileId: IMPORTED_ID }), { code: 'IMPORT_TARGET_UNSAFE' });
  await absent(path.join(f.browserRoot, IMPORTED_ID, 'browser-data'));
  assert.deepEqual(await readdir(outside), []);
  assert.equal(await readFile(path.join(staging, 'browser', 'Default', 'Cookies'), 'utf8'), 'incoming-browser');
});

async function pendingFixture(t) {
  const f = await fixture(t), staging = path.join(f.root, 'staging');
  for (const name of ['UserData', 'Home', 'Extensions']) await put(staging, `app-0/${name}/imported`, `${name}-import`);
  await restoreEnvironment({ ...f, staging, manifest: manifestFor([applicationManifest()]), profileId: IMPORTED_ID, platform: 'darwin' });
  const application = { ...TARGET_APP, profileId: IMPORTED_ID }, registration = f.registration(IMPORTED_ID);
  for (const name of ['UserData', 'Home', 'Extensions']) await put(registration, `${name}/existing`, `${name}-existing`);
  return { ...f, application, registration };
}

test('applyPendingApplicationData leaves other environments and other application identities untouched', async t => {
  const f = await pendingFixture(t);
  assert.deepEqual(await applyPendingApplicationData({ ...f, application: { ...f.application, profileId: OTHER_ID }, root: f.appRoot }), { applied: false });
  assert.deepEqual(await applyPendingApplicationData({ ...f, application: { ...f.application, identity: 'different-identity' }, root: f.appRoot }), { applied: false });
  assert.equal(await readFile(path.join(f.registration, 'UserData', 'existing'), 'utf8'), 'UserData-existing');
  assert.deepEqual(await applyPendingApplicationData({ ...f, root: f.appRoot }), { applied: true });
});

test('applyPendingApplicationData rejects a target owned by another uid without replacing existing data', async t => {
  const f = await pendingFixture(t);
  await assert.rejects(applyPendingApplicationData({ ...f, root: f.appRoot, uid: (process.getuid?.() ?? 0) + 1 }), { code: 'IMPORT_TARGET_UNSAFE' });
  for (const name of ['UserData', 'Home', 'Extensions']) assert.equal(await readFile(path.join(f.registration, name, 'existing'), 'utf8'), `${name}-existing`);
  assert.deepEqual(await applyPendingApplicationData({ ...f, root: f.appRoot }), { applied: true }, 'refusal retains pending data for a later safe restoration');
});

test('applyPendingApplicationData validates every target leaf before replacing any existing application data', async t => {
  const f = await pendingFixture(t), outside = path.join(f.root, 'outside-home');
  await put(outside, 'must-remain', 'outside-secret');
  await rm(path.join(f.registration, 'Home'), { recursive: true });
  await symlink(outside, path.join(f.registration, 'Home'));
  await assert.rejects(applyPendingApplicationData({ ...f, root: f.appRoot }), { code: 'IMPORT_TARGET_UNSAFE' });
  assert.equal(await readFile(path.join(f.registration, 'UserData', 'existing'), 'utf8'), 'UserData-existing', 'an unsafe later leaf must not erase an earlier valid leaf');
  assert.equal(await readFile(path.join(f.registration, 'Extensions', 'existing'), 'utf8'), 'Extensions-existing');
  assert.equal(await readFile(path.join(outside, 'must-remain'), 'utf8'), 'outside-secret');
});

test('a re-export before the first application stop preserves pending imported sign-ins rather than first-run data', async t => {
  const f = await pendingFixture(t), file = path.join(f.root, 'reexport.envara');
  const applications = { ...f.applications, async snapshot() { return { applications: [f.application] }; } };
  const service = { ...f.service, async call(method, request) { assert.equal(method, 'exportProfiles'); assert.deepEqual(request, { id: IMPORTED_ID }); return { ...profileDocument(), profiles: [{ id: IMPORTED_ID, name: 'Imported environment' }] }; } };
  await exportEnvironment({ ...f, profile: { id: IMPORTED_ID, status: 'stopped' }, service, applications, file, password: PASSWORD, root: f.appRoot, platform: 'darwin' });
  const staging = path.join(f.root, 'reexport-staging');
  const manifest = checkedExportManifest(await readEnvironmentExport({ file, password: PASSWORD, staging }));
  assert.deepEqual(manifest.applications, [applicationManifest()]);
  for (const name of ['UserData', 'Home', 'Extensions']) {
    assert.equal(await readFile(path.join(staging, 'app-0', name, 'imported'), 'utf8'), `${name}-import`);
    await absent(path.join(staging, 'app-0', name, 'existing'));
  }
  await absent(path.join(staging, 'app-0', 'pending.json'));
  assert.equal(await readFile(path.join(f.registration, 'UserData', 'existing'), 'utf8'), 'UserData-existing', 'export does not apply pending data');
  assert.deepEqual(await applyPendingApplicationData({ ...f, root: f.appRoot }), { applied: true }, 'pending data remains available after export');
});

test('an application refused as already bound elsewhere still exports its pending sign-ins and metadata from the new environment', async t => {
  const f = await fixture(t), staging = path.join(f.root, 'first-import');
  await put(staging, 'app-0/UserData/Cookies', 'unbound-application-sign-in');
  await put(staging, 'app-0/Home/.config/application', 'unbound-scoped-settings');
  f.applications.saveApplication = async () => { throw Object.assign(new Error('Application belongs to another environment'), { code: 'APPLICATION_ALREADY_BOUND' }); };
  const restored = await restoreEnvironment({ ...f, staging, manifest: manifestFor([applicationManifest()]), profileId: IMPORTED_ID, platform: 'darwin' });
  assert.deepEqual(restored.applications, [{ name: TARGET_APP.name, bound: false, reason: 'APPLICATION_ALREADY_BOUND' }]);
  assert.deepEqual((await f.applications.snapshot()).applications.filter(item => item.profileId === IMPORTED_ID), [], 'there is no binding in the imported environment');
  const service = { ...f.service, async call(method, request) { assert.equal(method, 'exportProfiles'); assert.deepEqual(request, { id: IMPORTED_ID }); return { ...profileDocument(), profiles: [{ id: IMPORTED_ID, name: 'Imported environment' }] }; } };
  const file = path.join(f.root, 'unbound-reexport.envara');
  const exported = await exportEnvironment({ ...f, profile: { id: IMPORTED_ID, status: 'stopped' }, service, file, password: PASSWORD, root: f.appRoot, platform: 'darwin' });
  assert.deepEqual(exported.applications, [TARGET_APP.name]);
  const decrypted = path.join(f.root, 'unbound-reexport-staging');
  const manifest = checkedExportManifest(await readEnvironmentExport({ file, password: PASSWORD, staging: decrypted }));
  assert.deepEqual(manifest.applications, [applicationManifest()]);
  assert.equal(await readFile(path.join(decrypted, 'app-0', 'UserData', 'Cookies'), 'utf8'), 'unbound-application-sign-in');
  assert.equal(await readFile(path.join(decrypted, 'app-0', 'Home', '.config', 'application'), 'utf8'), 'unbound-scoped-settings');
  await absent(path.join(decrypted, 'app-0', 'pending.json'));
  await absent(f.registration(IMPORTED_ID));
});

test('a legacy pending application without its path refuses re-export when unbound instead of silently losing sign-ins', async t => {
  const f = await pendingFixture(t);
  const pendingRoot = path.join(f.dataDir, 'imports', 'applications', IMPORTED_ID);
  const [pendingName] = await readdir(pendingRoot), pending = path.join(pendingRoot, pendingName);
  await writeFile(path.join(pending, 'pending.json'), JSON.stringify({ identity: TARGET_APP.identity, name: TARGET_APP.name }));
  const service = { ...f.service, async call() { return { ...profileDocument(), profiles: [{ id: IMPORTED_ID, name: 'Imported environment' }] }; } };
  const file = path.join(f.root, 'legacy-unresolved.envara');
  await assert.rejects(exportEnvironment({ ...f, profile: { id: IMPORTED_ID, status: 'stopped' }, service, file, password: PASSWORD, root: f.appRoot, platform: 'darwin' }), { code: 'EXPORT_PENDING_APPLICATION_UNRESOLVED' });
  await absent(file);
  assert.equal(await readFile(path.join(pending, 'UserData', 'imported'), 'utf8'), 'UserData-import');
  const applications = { ...f.applications, async snapshot() { return { applications: [f.application] }; } };
  await exportEnvironment({ ...f, profile: { id: IMPORTED_ID, status: 'stopped' }, service, applications, file, password: PASSWORD, root: f.appRoot, platform: 'darwin' });
  const decrypted = path.join(f.root, 'legacy-resolved-staging');
  const manifest = checkedExportManifest(await readEnvironmentExport({ file, password: PASSWORD, staging: decrypted }));
  assert.deepEqual(manifest.applications, [applicationManifest()], 'an existing matching binding can resolve a legacy pending path');
  assert.equal(await readFile(path.join(decrypted, 'app-0', 'UserData', 'imported'), 'utf8'), 'UserData-import');
});

test('a missing later application leaf refuses restoration before changing earlier data', async t => {
  const f = await pendingFixture(t);
  await rm(path.join(f.registration, 'Extensions'), { recursive: true });
  await assert.rejects(applyPendingApplicationData({ ...f, root: f.appRoot }), { code: 'IMPORT_TARGET_UNSAFE' });
  assert.equal(await readFile(path.join(f.registration, 'UserData', 'existing'), 'utf8'), 'UserData-existing');
  assert.equal(await readFile(path.join(f.registration, 'Home', 'existing'), 'utf8'), 'Home-existing');
});

test('application-data restoration refuses a symlinked ancestor and leaves both old data and pending sign-ins intact', async t => {
  const f = await pendingFixture(t), environment = path.dirname(f.registration), outside = path.join(f.root, 'other-application-environment');
  await rename(environment, outside);
  await symlink(outside, environment);
  await assert.rejects(applyPendingApplicationData({ ...f, root: f.appRoot }), { code: 'IMPORT_TARGET_UNSAFE' });
  assert.equal(await readFile(path.join(f.registration, 'UserData', 'existing'), 'utf8'), 'UserData-existing');
  await rm(environment);
  await rename(outside, environment);
  assert.deepEqual(await applyPendingApplicationData({ ...f, root: f.appRoot }), { applied: true }, 'the intact pending data can be applied after the unsafe ancestor is fixed');
});
