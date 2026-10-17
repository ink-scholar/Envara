import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { ClaudeAccountStore } from '../electron/claude-account-store.mjs';
import { BrowseForgeService } from '../electron/browseforge-service.mjs';
import { EXPORT_SCHEMA, readEnvironmentExport } from '../electron/environment-export.mjs';
import { applyPendingApplicationData, assertEnvironmentIdle, checkedExportManifest, exportEnvironment, restoreEnvironment } from '../electron/environment-transfer.mjs';
import { pfApplicationRegistrationId, pfAttachEnvironmentId } from '../native/macos-pf-routing/policy.mjs';

const PASSWORD = 'scoped archive test password';
const SOURCE = 'prof_scoped_source', DESTINATION = 'prof_scoped_imported', OTHER = 'prof_scoped_other';
const SHELL_FILES = ['.envara_history', '.gitconfig', '.npmrc', '.zshenv', '.zshrc', '.bashrc'];
const APP = { id: 'app_code', profileId: SOURCE, identity: 'scoped-code-identity', name: 'Visual Studio Code', path: '/Applications/Visual Studio Code.app', status: 'stopped' };
const SECOND_APP = { id: 'app_notion', profileId: SOURCE, identity: 'scoped-notion-identity', name: 'Notion', path: '/Applications/Notion.app', status: 'stopped' };
const document = () => ({ schema: 'envara.profiles', version: 2, profiles: [{ id: SOURCE, name: 'Scoped source' }] });
const appMetadata = (application = APP, section = 'app-0') => ({ section, identity: application.identity, name: application.name, path: application.path });
function manifest(scope, { account = null, application = APP } = {}) {
  return { schema: EXPORT_SCHEMA, version: 1, scope, profile: document(), terminal: {
    accounts: scope === 'terminal' && account ? [{ id: account.id, name: account.name }] : [],
    ...(scope === 'terminal' ? { selectedAccountId: account?.id ?? 'default' } : {}),
  }, applications: scope === 'application' ? [appMetadata(application)] : [], keychainIncluded: false };
}
async function put(root, relative, content = relative) {
  const target = path.join(root, relative);
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, content);
  return target;
}
async function absent(target) { await assert.rejects(lstat(target), { code: 'ENOENT' }); }
async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-scoped-transfer-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const browserRoot = path.join(root, 'browser'), terminalRoot = path.join(root, 'terminal'), profilesDir = path.join(terminalRoot, 'profiles');
  const appRoot = path.join(root, 'applications'), dataDir = path.join(root, 'data');
  await Promise.all([browserRoot, profilesDir, appRoot, dataDir].map(directory => mkdir(directory, { recursive: true })));
  const accounts = new ClaudeAccountStore({ root: terminalRoot });
  await accounts.ready;
  const accountA = await accounts.create(SOURCE, 'Work'), accountB = await accounts.create(SOURCE, 'Personal');
  const sessions = [], apps = [structuredClone(APP), structuredClone(SECOND_APP)], trials = new Map(), saves = [];
  const profile = { id: SOURCE, name: 'Scoped source', status: 'stopped' };
  const service = {
    async checkedDirectory({ id }) { assert.ok([SOURCE, DESTINATION, OTHER].includes(id)); const target = path.join(browserRoot, id); await mkdir(target, { recursive: true }); return target; },
    async call(method, request) { assert.equal(method, 'exportProfiles'); assert.equal(request.id, profile.id); return { ...document(), profiles: [{ id: profile.id, name: profile.name }] }; },
  };
  const terminal = { profilesDir, claudeAccounts: accounts, async snapshot({ id }) { return { profiles: [{ profileId: id, sessions }, { profileId: OTHER, sessions: [{ status: 'running' }] }] }; } };
  const applications = {
    async snapshot() { return { applications: apps }; },
    routing: { controlledNotionTrialSnapshot({ applicationId }) { return trials.get(applicationId); } },
    async inspectApplication(filename) { return [...apps, APP].find(item => item.path === filename); },
    async saveApplication(request) { saves.push(request.application); return request.application; },
  };
  const registration = (id = SOURCE, application = APP) => path.join(appRoot, pfAttachEnvironmentId(id), pfApplicationRegistrationId(application.path));
  const browserData = path.join(await service.checkedDirectory({ id: SOURCE }), 'browser-data'), terminalData = path.join(profilesDir, SOURCE);
  await put(browserData, 'Default/Cookies', 'browser-sign-in');
  await put(browserData, 'Default/Service Worker/offline-document', 'browser-offline-content');
  await put(browserData, 'Default/Cache/cache', 'browser-cache');
  for (const name of SHELL_FILES) await put(terminalData, `home/${name}`, `shared-shell:${name}`);
  for (const [name, content] of Object.entries({ 'claude/settings.json': 'default-settings', 'claude/.claude.json': 'default-config', 'claude/history.jsonl': 'default-history', [`claude-accounts/${accountA.id}/settings.json`]: 'work-settings', [`claude-accounts/${accountA.id}/.claude.json`]: 'work-config', [`claude-accounts/${accountA.id}/history.jsonl`]: 'work-history', [`claude-accounts/${accountA.id}/projects/project/session.jsonl`]: 'work-conversation', [`claude-accounts/${accountB.id}/settings.json`]: 'personal-settings' })) await put(terminalData, name, content);
  for (const name of ['home/.config/unrelated-login', 'home/.ssh/id_rsa', 'home/.cache/cache', 'home/.local/bin/claude', 'home/.local/share/claude/version', 'tmp/runtime', 'unexpected-root-file']) await put(terminalData, name, `unselected:${name}`);
  await put(registration(), 'UserData/Cookies', 'code-sign-in');
  await put(registration(), 'UserData/Service Worker/offline', 'code-offline-content');
  await put(registration(), 'Home/.config/preferences', 'code-preferences');
  await put(registration(), 'Extensions/test-extension/package.json', 'code-extension');
  await put(registration(), 'Cache/bytes', 'code-cache');
  await put(registration(), 'Temp/bytes', 'code-temp');
  await put(registration(SOURCE, SECOND_APP), 'UserData/Cookies', 'notion-sign-in');
  const outside = await put(root, 'host-secret', 'host-secret');
  await symlink(outside, path.join(terminalData, 'claude-accounts', accountA.id, 'host-link'));
  return { root, browserRoot, profilesDir, appRoot, dataDir, profile, service, terminal, applications, accountA, accountB, sessions, apps, trials, saves, registration, browserData, terminalData };
}
async function exportAndRead(f, args = {}) {
  const file = path.join(f.root, `archive-${args.scope}-${args.accountId ?? args.applicationId ?? 'one'}.envara`);
  const result = await exportEnvironment({ ...f, root: f.appRoot, platform: 'darwin', file, password: PASSWORD, ...args });
  const staging = `${file}.staging`;
  const exportedManifest = checkedExportManifest(await readEnvironmentExport({ file, password: PASSWORD, staging }));
  return { file, staging, manifest: exportedManifest, result };
}

test('scoped idle checks allow the other consumers to remain active', async t => {
  for (const scope of ['browser', 'terminal', 'application']) await t.test(scope, async t => {
    const f = await fixture(t);
    f.profile.status = scope === 'browser' ? 'stopped' : 'running';
    if (scope !== 'terminal') f.sessions.push({ status: 'running', kind: 'claude-code', claudeAccountId: f.accountA.id });
    f.apps[0].status = scope === 'application' ? 'stopped' : 'running';
    f.apps[1].status = 'running';
    if (scope !== 'application') f.trials.set(APP.id, { active: true, cleanupUncertain: true });
    await assertEnvironmentIdle({ ...f, scope, applicationId: APP.id });
  });
});

test('scoped idle checks refuse only the relevant live browser, terminal or selected application', async t => {
  for (const status of ['starting', 'running', 'stopping', 'closing']) await t.test(`browser ${status}`, async t => {
    const f = await fixture(t);
    f.profile.status = status;
    await assert.rejects(assertEnvironmentIdle({ ...f, scope: 'browser' }), { code: 'EXPORT_ENVIRONMENT_RUNNING' });
  });
  for (const status of ['starting', 'running', 'closing']) await t.test(`terminal ${status}`, async t => {
    const f = await fixture(t);
    f.sessions.push({ status, kind: 'shell' });
    await assert.rejects(assertEnvironmentIdle({ ...f, scope: 'terminal', accountId: f.accountA.id }), { code: 'EXPORT_ENVIRONMENT_RUNNING' });
  });
  for (const status of ['starting', 'running', 'stopping']) await t.test(`application ${status}`, async t => {
    const f = await fixture(t);
    f.apps[0].status = status;
    await assert.rejects(assertEnvironmentIdle({ ...f, scope: 'application', applicationId: APP.id }), { code: 'EXPORT_ENVIRONMENT_RUNNING' });
  });
  for (const trial of [{ active: true }, { cleanupUncertain: true }]) await t.test(`application trial ${JSON.stringify(trial)}`, async t => {
    const f = await fixture(t);
    f.trials.set(APP.id, trial);
    await assert.rejects(assertEnvironmentIdle({ ...f, scope: 'application', applicationId: APP.id }), { code: 'EXPORT_ENVIRONMENT_RUNNING' });
  });
});

test('browser export carries only browser sign-ins and restores only browser data', async t => {
  const f = await fixture(t);
  f.sessions.push({ status: 'running' });
  for (const application of f.apps) application.status = 'running';
  const exported = await exportAndRead(f, { scope: 'browser' });
  assert.equal(exported.manifest.scope, 'browser');
  assert.deepEqual(exported.manifest.terminal.accounts, []);
  assert.deepEqual(exported.manifest.applications, []);
  assert.deepEqual(await readdir(exported.staging), ['browser']);
  assert.equal(await readFile(path.join(exported.staging, 'browser', 'Default', 'Cookies'), 'utf8'), 'browser-sign-in');
  assert.equal(await readFile(path.join(exported.staging, 'browser', 'Default', 'Service Worker', 'offline-document'), 'utf8'), 'browser-offline-content');
  await absent(path.join(exported.staging, 'browser', 'Default', 'Cache'));
  const restored = await restoreEnvironment({ ...f, ...exported, profileId: DESTINATION, platform: 'darwin' });
  assert.equal(restored.scope, 'browser');
  assert.equal(restored.browser, true);
  assert.equal(restored.terminal, false);
  assert.deepEqual(restored.applications, []);
  assert.equal(await readFile(path.join(f.browserRoot, DESTINATION, 'browser-data', 'Default', 'Cookies'), 'utf8'), 'browser-sign-in');
  await absent(path.join(f.profilesDir, DESTINATION));
  assert.deepEqual(f.saves, []);
});

test('browser export uses backend session ownership before configuration or source traversal', async t => {
  for (const scope of ['browser', 'environment']) for (const health of [true, null]) await t.test(`${scope} existing session health ${health}`, async t => {
    const f = await fixture(t), file = path.join(f.root, 'unknown-browser.envara');
    f.profile.status = 'error';
    const remote = { sessions: [{ profile_id: SOURCE, health }] };
    let inspected = false;
    f.service.starting = new Set();
    f.service.health = async session => ({ alive: session.health });
    f.service.remote = async () => remote;
    f.service.assertStopped = async (actual, id) => {
      assert.equal(actual, remote); assert.equal(id, SOURCE); inspected = true;
      return BrowseForgeService.prototype.assertStopped.call(f.service, actual, id);
    };
    f.service.call = async () => { throw new Error('configuration must not be read'); };
    f.service.checkedDirectory = async () => { throw new Error('data must not be traversed'); };
    await assert.rejects(exportEnvironment({ ...f, file, password: PASSWORD, scope }), { code: 'PROFILE_RUNNING' });
    assert.equal(inspected, true);
    await absent(file);
  });
});

test('old browser errors without a session remain exportable and non-browser scopes skip the browser guard', async t => {
  const f = await fixture(t);
  f.profile.status = 'error';
  let checks = 0;
  f.service.starting = new Set();
  f.service.remote = async () => ({ sessions: [] });
  f.service.assertStopped = async (remote, id) => {
    assert.deepEqual(remote.sessions, []); assert.equal(id, SOURCE); checks++;
    return BrowseForgeService.prototype.assertStopped.call(f.service, remote, id);
  };
  const exported = await exportAndRead(f, { scope: 'browser' });
  assert.equal(exported.manifest.scope, 'browser');
  assert.equal(checks, 1);
  f.service.remote = async () => { throw new Error('other consumer exports must not inspect browser sessions'); };
  await exportAndRead(f, { scope: 'terminal', accountId: f.accountA.id });
  await exportAndRead(f, { scope: 'application', applicationId: APP.id });
  assert.equal(checks, 1);
});

test('terminal export carries one selected Claude profile plus the exact shared-shell whitelist', async t => {
  for (const selection of ['default', 'named']) await t.test(selection, async t => {
    const f = await fixture(t), accountId = selection === 'default' ? 'default' : f.accountA.id;
    f.profile.status = 'running';
    for (const application of f.apps) application.status = 'running';
    const exported = await exportAndRead(f, { scope: 'terminal', accountId });
    assert.equal(exported.manifest.scope, 'terminal');
    assert.equal(exported.manifest.terminal.selectedAccountId, accountId);
    assert.deepEqual(exported.manifest.terminal.accounts, selection === 'default' ? [] : [{ id: f.accountA.id, name: f.accountA.name }]);
    assert.deepEqual(exported.manifest.applications, []);
    assert.deepEqual(await readdir(exported.staging), ['terminal']);
    const terminal = path.join(exported.staging, 'terminal');
    assert.deepEqual((await readdir(path.join(terminal, 'home'))).sort(), [...SHELL_FILES].sort());
    for (const name of SHELL_FILES) assert.equal(await readFile(path.join(terminal, 'home', name), 'utf8'), `shared-shell:${name}`);
    const selectedRoot = selection === 'default' ? 'claude' : `claude-accounts/${accountId}`;
    assert.equal(await readFile(path.join(terminal, selectedRoot, 'settings.json'), 'utf8'), selection === 'default' ? 'default-settings' : 'work-settings');
    assert.equal(await readFile(path.join(terminal, selectedRoot, '.claude.json'), 'utf8'), selection === 'default' ? 'default-config' : 'work-config');
    assert.equal(await readFile(path.join(terminal, selectedRoot, 'history.jsonl'), 'utf8'), selection === 'default' ? 'default-history' : 'work-history');
    await absent(path.join(terminal, 'claude-accounts', f.accountB.id));
    await absent(path.join(terminal, selection === 'default' ? 'claude-accounts' : 'claude'));
    for (const name of ['tmp', 'unexpected-root-file', 'home/.config', 'home/.ssh', 'home/.cache', 'home/.local', `${selectedRoot}/host-link`]) await absent(path.join(terminal, name));
    const restored = await restoreEnvironment({ ...f, ...exported, profileId: DESTINATION, platform: 'darwin' });
    assert.equal(restored.scope, 'terminal');
    assert.equal(restored.browser, false);
    assert.equal(restored.terminal, true);
    assert.deepEqual(restored.applications, []);
    assert.equal(await readFile(path.join(f.profilesDir, DESTINATION, selectedRoot, 'settings.json'), 'utf8'), selection === 'default' ? 'default-settings' : 'work-settings');
    const importedAccounts = (await f.terminal.claudeAccounts.list(DESTINATION)).filter(item => !item.default);
    assert.deepEqual(importedAccounts, selection === 'default' ? [] : [{ id: accountId, name: f.accountA.name, default: false }]);
    await absent(path.join(f.browserRoot, DESTINATION, 'browser-data'));
    assert.deepEqual(f.saves, []);
  });
});

test('encrypted terminal roundtrips preserve a renamed default and a named account called 默认', async t => {
  for (const selection of ['default', 'named']) await t.test(selection, async t => {
    const f = await fixture(t), accounts = f.terminal.claudeAccounts;
    await accounts.rename(SOURCE, 'default', '主档案');
    const named = await accounts.rename(SOURCE, f.accountA.id, '默认');
    const accountId = selection === 'default' ? 'default' : named.id;
    const exported = await exportAndRead(f, { scope: 'terminal', accountId });
    assert.equal(exported.manifest.terminal.defaultAccountName, '主档案');
    assert.equal(exported.manifest.terminal.selectedAccountName, selection === 'default' ? '主档案' : '默认');
    await restoreEnvironment({ ...f, ...exported, profileId: DESTINATION });
    const expected = [{ id: 'default', name: '主档案', default: true }, ...(selection === 'named' ? [{ ...named, default: false }] : [])];
    assert.deepEqual(await accounts.list(DESTINATION), expected);
    const restarted = new ClaudeAccountStore({ root: accounts.root });
    await restarted.ready;
    assert.deepEqual(await restarted.list(DESTINATION), expected, 'restored metadata must remain readable after restart');
    const relative = selection === 'default' ? 'claude/settings.json' : `claude-accounts/${named.id}/settings.json`;
    assert.equal(await readFile(path.join(f.profilesDir, DESTINATION, relative), 'utf8'), selection === 'default' ? 'default-settings' : 'work-settings');
    assert.equal((await accounts.get(SOURCE, 'default')).name, '主档案', 'export leaves source metadata intact');
  });
});

test('old scoped archives recover a selected default name without the new optional field', async t => {
  const f = await fixture(t);
  await f.terminal.claudeAccounts.rename(SOURCE, 'default', '旧档案');
  const exported = await exportAndRead(f, { scope: 'terminal' });
  delete exported.manifest.terminal.defaultAccountName;
  assert.equal(checkedExportManifest(exported.manifest), exported.manifest);
  await restoreEnvironment({ ...f, ...exported, profileId: DESTINATION });
  assert.equal((await f.terminal.claudeAccounts.get(DESTINATION, 'default')).name, '旧档案');
});

test('terminal account metadata survives an encrypted roundtrip before any session data exists', async t => {
  for (const selection of ['default', 'named']) await t.test(selection, async t => {
    const f = await fixture(t), accounts = f.terminal.claudeAccounts;
    await accounts.rename(SOURCE, 'default', '主档案');
    const named = await accounts.rename(SOURCE, f.accountA.id, '默认');
    await rm(f.terminalData, { recursive: true });
    const exported = await exportAndRead(f, { scope: 'terminal', accountId: selection === 'default' ? 'default' : named.id });
    assert.deepEqual(await readdir(exported.staging), []);
    const restored = await restoreEnvironment({ ...f, ...exported, profileId: DESTINATION });
    assert.equal(restored.terminal, true);
    const expected = [{ id: 'default', name: '主档案', default: true }, ...(selection === 'named' ? [named] : [])];
    assert.deepEqual(await accounts.list(DESTINATION), expected);
    const restarted = new ClaudeAccountStore({ root: accounts.root });
    await restarted.ready;
    assert.deepEqual(await restarted.list(DESTINATION), expected);
    await absent(path.join(f.profilesDir, DESTINATION));
  });
});

test('application export carries only the selected application and restores its data after a clean stop', async t => {
  const f = await fixture(t);
  f.profile.status = 'running';
  f.sessions.push({ status: 'running' });
  f.apps[1].status = 'running';
  const exported = await exportAndRead(f, { scope: 'application', applicationId: APP.id });
  assert.equal(exported.manifest.scope, 'application');
  assert.deepEqual(exported.manifest.terminal.accounts, []);
  assert.deepEqual(exported.manifest.applications, [appMetadata()]);
  assert.deepEqual(await readdir(exported.staging), ['app-0']);
  assert.deepEqual((await readdir(path.join(exported.staging, 'app-0'))).sort(), ['Extensions', 'Home', 'UserData']);
  assert.equal(await readFile(path.join(exported.staging, 'app-0', 'UserData', 'Cookies'), 'utf8'), 'code-sign-in');
  const restored = await restoreEnvironment({ ...f, ...exported, profileId: DESTINATION, platform: 'darwin' });
  assert.equal(restored.scope, 'application');
  assert.equal(restored.browser, false);
  assert.equal(restored.terminal, false);
  assert.deepEqual(restored.applications, [{ name: APP.name, bound: true, reason: null }]);
  await absent(f.registration(DESTINATION));
  for (const name of ['UserData', 'Home', 'Extensions']) await put(f.registration(DESTINATION), `${name}/first-run`, 'not-sign-in');
  assert.deepEqual(await applyPendingApplicationData({ ...f, application: { ...APP, profileId: DESTINATION }, root: f.appRoot }), { applied: true });
  assert.equal(await readFile(path.join(f.registration(DESTINATION), 'UserData', 'Cookies'), 'utf8'), 'code-sign-in');
  assert.equal(await readFile(path.join(f.registration(DESTINATION), 'UserData', 'Service Worker', 'offline'), 'utf8'), 'code-offline-content');
  await absent(path.join(f.profilesDir, DESTINATION));
  assert.deepEqual(f.saves, [{ profileId: DESTINATION, name: APP.name, path: APP.path }]);
});

test('invalid scopes, missing selected accounts and missing selected applications fail without an archive or a silent fallback', async t => {
  const cases = [
    ['invalid scope', { scope: 'everything' }, 'EXPORT_SCOPE_INVALID'],
    ['null scope', { scope: null }, 'EXPORT_SCOPE_INVALID'],
    ['missing named account', { scope: 'terminal', accountId: `account_${'f'.repeat(32)}` }, 'CLAUDE_ACCOUNT_NOT_FOUND'],
    ['missing application', { scope: 'application', applicationId: 'app_missing' }, 'EXPORT_APPLICATION_NOT_FOUND'],
  ];
  for (const [name, args, code] of cases) await t.test(name, async t => {
    const f = await fixture(t), file = path.join(f.root, 'refused.envara');
    await assert.rejects(exportEnvironment({ ...f, root: f.appRoot, platform: 'darwin', password: PASSWORD, file, ...args }), { code });
    await absent(file);
  });
});

test('scoped manifests reject mixed consumers and mismatched selected-account metadata', async t => {
  const account = { id: `account_${'a'.repeat(32)}`, name: 'Work' }, another = { id: `account_${'b'.repeat(32)}`, name: 'Personal' };
  for (const value of [manifest('browser'), manifest('terminal'), manifest('terminal', { account }), manifest('application')]) assert.equal(checkedExportManifest(value), value);
  const cases = [
    ['unknown kind', () => manifest('unknown')],
    ['browser with application', () => ({ ...manifest('browser'), applications: [appMetadata()] })],
    ['browser with account', () => ({ ...manifest('browser'), terminal: { accounts: [account], selectedAccountId: account.id } })],
    ['terminal with application', () => ({ ...manifest('terminal'), applications: [appMetadata()] })],
    ['default selection with named account', () => ({ ...manifest('terminal'), terminal: { selectedAccountId: 'default', accounts: [account] } })],
    ['named selection without metadata', () => ({ ...manifest('terminal'), terminal: { selectedAccountId: account.id, accounts: [] } })],
    ['named selection with another metadata', () => ({ ...manifest('terminal', { account }), terminal: { selectedAccountId: account.id, accounts: [another] } })],
    ['two named accounts', () => ({ ...manifest('terminal', { account }), terminal: { selectedAccountId: account.id, accounts: [account, another] } })],
    ['invalid default label', () => ({ ...manifest('terminal'), terminal: { accounts: [], selectedAccountId: 'default', defaultAccountName: null } })],
    ['control character in default label', () => ({ ...manifest('terminal'), terminal: { accounts: [], selectedAccountId: 'default', defaultAccountName: 'Primary\n' } })],
    ['oversized default label', () => ({ ...manifest('terminal'), terminal: { accounts: [], selectedAccountId: 'default', defaultAccountName: 'x'.repeat(81) } })],
    ['normalized collision with default label', () => ({ ...manifest('terminal', { account }), terminal: { accounts: [account], selectedAccountId: account.id, defaultAccountName: 'ｗｏｒｋ' } })],
    ['different default selected label', () => ({ ...manifest('terminal'), terminal: { accounts: [], selectedAccountId: 'default', defaultAccountName: 'Primary', selectedAccountName: 'Other' } })],
    ['different named selected label', () => ({ ...manifest('terminal', { account }), terminal: { accounts: [account], selectedAccountId: account.id, selectedAccountName: 'Other' } })],
    ['orphan selected label', () => ({ ...manifest('browser'), terminal: { accounts: [], selectedAccountName: 'Work' } })],
    ['browser carrying a default label', () => ({ ...manifest('browser'), terminal: { accounts: [], defaultAccountName: 'Primary' } })],
    ['application with account', () => ({ ...manifest('application'), terminal: { accounts: [account], selectedAccountId: account.id } })],
    ['multiple applications', () => ({ ...manifest('application'), applications: [appMetadata(), appMetadata(SECOND_APP, 'app-1')] })],
  ];
  for (const [name, build] of cases) await t.test(name, () => assert.throws(() => checkedExportManifest(build()), { code: 'EXPORT_FORMAT_INVALID' }));
});

test('restoreEnvironment rejects undeclared data sections and unselected Claude/home files before writing targets', async t => {
  const account = { id: `account_${'a'.repeat(32)}`, name: 'Work' };
  const cases = [
    ['browser carrying terminal', manifest('browser'), 'terminal/claude/settings.json'],
    ['browser carrying application', manifest('browser'), 'app-0/UserData/Cookies'],
    ['terminal carrying browser', manifest('terminal'), 'browser/Default/Cookies'],
    ['terminal carrying application', manifest('terminal'), 'app-0/UserData/Cookies'],
    ['named terminal carrying default account', manifest('terminal', { account }), 'terminal/claude/settings.json'],
    ['named terminal carrying another account', manifest('terminal', { account }), `terminal/claude-accounts/account_${'b'.repeat(32)}/settings.json`],
    ['terminal carrying a private unlisted home subtree', manifest('terminal'), 'terminal/home/.ssh/id_rsa'],
    ['application carrying browser', manifest('application'), 'browser/Default/Cookies'],
    ['application carrying terminal', manifest('application'), 'terminal/claude/settings.json'],
    ['application carrying second application', manifest('application'), 'app-1/UserData/Cookies'],
  ];
  for (const [name, selectedManifest, relative] of cases) await t.test(name, async t => {
    const f = await fixture(t), staging = path.join(f.root, 'invalid-staging');
    await put(staging, relative, 'unselected-secret');
    await assert.rejects(restoreEnvironment({ ...f, staging, manifest: selectedManifest, profileId: DESTINATION, platform: 'darwin' }), { code: 'EXPORT_FORMAT_INVALID' });
    await absent(path.join(f.browserRoot, DESTINATION, 'browser-data'));
    await absent(path.join(f.profilesDir, DESTINATION));
    assert.deepEqual(f.saves, []);
    assert.equal(await readFile(path.join(staging, relative), 'utf8'), 'unselected-secret');
  });
});

test('selected terminal metadata failure rolls back only its new target and preserves the selected data for retry', async t => {
  const f = await fixture(t), exported = await exportAndRead(f, { scope: 'terminal', accountId: f.accountA.id });
  const originalAdopt = f.terminal.claudeAccounts.adopt.bind(f.terminal.claudeAccounts);
  f.terminal.claudeAccounts.adopt = async () => { throw Object.assign(new Error('Metadata unavailable'), { code: 'EIO' }); };
  await assert.rejects(restoreEnvironment({ ...f, ...exported, profileId: DESTINATION, platform: 'darwin' }), { code: 'EIO' });
  await absent(path.join(f.profilesDir, DESTINATION));
  assert.equal(await readFile(path.join(exported.staging, 'terminal', 'claude-accounts', f.accountA.id, 'settings.json'), 'utf8'), 'work-settings');
  assert.equal(await readFile(path.join(f.browserData, 'Default', 'Cookies'), 'utf8'), 'browser-sign-in');
  f.terminal.claudeAccounts.adopt = originalAdopt;
  assert.equal((await restoreEnvironment({ ...f, ...exported, profileId: DESTINATION, platform: 'darwin' })).scope, 'terminal');
});

test('a renamed default metadata failure rolls back copied data and remains retryable', async t => {
  const f = await fixture(t), accounts = f.terminal.claudeAccounts;
  await accounts.rename(SOURCE, 'default', '主档案');
  const exported = await exportAndRead(f, { scope: 'terminal' });
  const save = accounts.save;
  accounts.save = async () => { throw Object.assign(new Error('Synthetic metadata failure'), { code: 'EIO' }); };
  await assert.rejects(restoreEnvironment({ ...f, ...exported, profileId: DESTINATION }), { code: 'EIO' });
  await absent(path.join(f.profilesDir, DESTINATION));
  assert.equal(await readFile(path.join(exported.staging, 'terminal', 'claude', 'settings.json'), 'utf8'), 'default-settings');
  assert.equal((await accounts.get(DESTINATION, 'default')).name, '默认');
  accounts.save = save;
  await restoreEnvironment({ ...f, ...exported, profileId: DESTINATION });
  assert.equal((await accounts.get(DESTINATION, 'default')).name, '主档案');
});

test('a selected application re-export preserves pending imported sign-ins instead of its first-run data', async t => {
  const f = await fixture(t), staging = path.join(f.root, 'pending-import');
  await put(staging, 'app-0/UserData/Cookies', 'pending-imported-sign-in');
  await put(staging, 'app-0/Home/.config/preferences', 'pending-imported-preferences');
  await restoreEnvironment({ ...f, staging, manifest: manifest('application'), profileId: DESTINATION, platform: 'darwin' });
  const importedApplication = { ...APP, id: 'app_imported_code', profileId: DESTINATION };
  f.apps.push(importedApplication);
  f.profile.id = DESTINATION;
  for (const name of ['UserData', 'Home', 'Extensions']) await put(f.registration(DESTINATION), `${name}/first-run`, 'new-account-not-imported');
  const exported = await exportAndRead(f, { scope: 'application', applicationId: importedApplication.id });
  assert.equal(exported.manifest.scope, 'application');
  assert.deepEqual(exported.manifest.applications, [appMetadata()]);
  assert.deepEqual(await readdir(exported.staging), ['app-0']);
  assert.equal(await readFile(path.join(exported.staging, 'app-0', 'UserData', 'Cookies'), 'utf8'), 'pending-imported-sign-in');
  assert.equal(await readFile(path.join(exported.staging, 'app-0', 'Home', '.config', 'preferences'), 'utf8'), 'pending-imported-preferences');
  for (const name of ['UserData', 'Home', 'Extensions']) await absent(path.join(exported.staging, 'app-0', name, 'first-run'));
  await absent(path.join(exported.staging, 'app-0', 'pending.json'));
  assert.equal(await readFile(path.join(f.registration(DESTINATION), 'UserData', 'first-run'), 'utf8'), 'new-account-not-imported');
});
