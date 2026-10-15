import test from 'node:test';
import assert from 'node:assert/strict';
import { TerminalController } from '../electron/terminal-controller.mjs';

function fixture(pickDirectory = async () => ({ canceled: false, path: '/selected/workspace' })) {
  const profiles = [{ id: 'prof_a', name: '工作环境', group: '工作', proxyId: 'proxy_a' }];
  const state = { profiles: [{ profileId: 'prof_a', cwd: null, sessions: [] }] };
  const calls = [];
  const terminal = {
    snapshot: async () => structuredClone(state),
    setDirectory: async ({ id, path }) => { calls.push(['directory', id, path]); state.profiles[0].cwd = path; },
    create: async (args) => { calls.push(['create', args.id]); const session = { sessionId: 'session_a', profileId: args.id, status: 'running' }; state.profiles[0].sessions = [session]; return session; },
    close: async (args) => { calls.push(['close', args.sessionId]); state.profiles[0].sessions = []; },
    write: async (args) => { calls.push(['write', args]); },
    resize: async (args) => { calls.push(['resize', args]); },
    removeProfile: async ({ id }) => { calls.push(['removeOwnedConfiguration', id]); },
  };
  const controller = new TerminalController({ terminal, service: { snapshot: async () => ({ profiles: structuredClone(profiles) }) }, pickDirectory });
  return { controller, terminal, profiles, state, calls };
}

test('directory picker cancellation never launches a shell or stores a directory', async () => {
  const { controller, calls } = fixture(async () => ({ canceled: true }));
  assert.deepEqual(await controller.dispatch('openTerminal', { id: 'prof_a' }), { canceled: true });
  assert.deepEqual(calls, []);
});

test('first terminal launch chooses a directory and rejects missing profiles', async () => {
  const { controller, calls } = fixture();
  await assert.rejects(controller.dispatch('openTerminal', { id: 'prof_missing' }), { code: 'PROFILE_NOT_FOUND' });
  await controller.dispatch('openTerminal', { id: 'prof_a', columns: 80, rows: 24 });
  assert.deepEqual(calls, [['directory', 'prof_a', '/selected/workspace'], ['create', 'prof_a']]);
});

test('duplicate dispatch validates the owning environment and never opens a directory picker', async () => {
  const f = fixture(async () => { throw new Error('Picker must not open'); });
  f.state.profiles[0].sessions = [{ sessionId: 'session_a', profileId: 'prof_a', status: 'running' }];
  f.terminal.duplicate = async args => ({ sessionId: 'session_b', profileId: 'prof_a', source: args.sessionId });
  assert.deepEqual(await f.controller.dispatch('duplicateTerminal', { sessionId: 'session_a' }), { sessionId: 'session_b', profileId: 'prof_a', source: 'session_a' });
  await assert.rejects(f.controller.dispatch('duplicateTerminal', { sessionId: 'missing' }), { code: 'TERMINAL_SESSION_NOT_FOUND' });
  f.profiles.length = 0;
  await assert.rejects(f.controller.dispatch('duplicateTerminal', { sessionId: 'session_a' }), { code: 'PROFILE_NOT_FOUND' });
  assert.deepEqual(f.calls, []);
});

test('profile deletion while a native directory picker is open never launches the deleted profile', async () => {
  let profiles;
  const chosen = fixture(async () => { profiles.length = 0; return { canceled: false, path: '/selected/workspace' }; });
  profiles = chosen.profiles;
  await assert.rejects(chosen.controller.dispatch('openTerminal', { id: 'prof_a' }), { code: 'PROFILE_NOT_FOUND' });
  assert.deepEqual(chosen.calls, []);
});

test('active terminal configuration is protected while unrelated proxies remain editable', async () => {
  const { controller, state } = fixture();
  state.profiles[0].sessions = [{ status: 'running', sessionId: 'session_a' }];
  let mutations = 0;
  const change = async () => { mutations++; return { updated: true }; };
  for (const [method, args] of [['updateProfile', { id: 'prof_a' }], ['deleteProfile', { id: 'prof_a' }], ['saveProxy', { proxy: { id: 'proxy_a' } }], ['clearGroupProxy', { name: '工作' }], ['bulkProfiles', { action: 'move', ids: ['prof_a'] }], ['bulkProfiles', { action: 'delete', ids: ['prof_a'] }]]) {
    await assert.rejects(controller.protectMutation(method, args, change), { code: 'TERMINAL_BUSY' });
  }
  await assert.rejects(controller.dispatch('chooseWorkspaceDirectory', { id: 'prof_a' }), { code: 'TERMINAL_BUSY' });
  assert.equal(mutations, 0);
  await controller.protectMutation('saveProxy', { proxy: { id: 'proxy_unused' } }, change);
  await controller.protectMutation('stopProfile', { id: 'prof_a' }, change);
  assert.equal(mutations, 2);
});

test('proxy edit cannot race past a terminal launch using the old proxy configuration', async () => {
  const { controller, terminal, state } = fixture();
  state.profiles[0].cwd = '/selected/workspace';
  let releaseLaunch;
  let enteredLaunch;
  const started = new Promise((resolve) => { enteredLaunch = resolve; });
  terminal.create = async () => {
    enteredLaunch();
    await new Promise((resolve) => { releaseLaunch = resolve; });
    state.profiles[0].sessions = [{ sessionId: 'session_a', status: 'running' }];
    return state.profiles[0].sessions[0];
  };
  const launch = controller.dispatch('openTerminal', { id: 'prof_a' });
  await started;
  let edited = false;
  const edit = controller.protectMutation('saveProxy', { proxy: { id: 'proxy_a' } }, async () => { edited = true; });
  releaseLaunch();
  await launch;
  await assert.rejects(edit, { code: 'TERMINAL_BUSY' });
  assert.equal(edited, false);
});

test('explicit profile deletion cleans only owned terminal configuration after backend deletion succeeds', async () => {
  const { controller, calls } = fixture();
  const result = await controller.protectMutation('deleteProfile', { id: 'prof_a' }, async () => ({ deleted: true }));
  assert.deepEqual(result, { deleted: true });
  assert.deepEqual(calls, [['removeOwnedConfiguration', 'prof_a']]);
  await assert.rejects(controller.protectMutation('deleteProfile', { id: 'prof_a' }, async () => { throw new Error('backend rejected'); }));
  assert.equal(calls.length, 1);
});

test('bulk deletion cleans only successful profile removals', async () => {
  const { controller, calls } = fixture();
  await controller.protectMutation('bulkProfiles', { action: 'delete', ids: ['prof_a', 'prof_missing'] }, async () => ({ results: [{ id: 'prof_a', ok: true }, { id: 'prof_missing', ok: false }] }));
  assert.deepEqual(calls, [['removeOwnedConfiguration', 'prof_a']]);
});

test('a new terminal can use its own picked folder while another terminal runs, and only a picked one', async () => {
  const created = [];
  const f = fixture(async () => ({ canceled: false, path: '/picked/for/this/terminal' }));
  f.state.profiles[0].cwd = '/saved/default';
  f.state.profiles[0].sessions = [{ sessionId: 'session_a', profileId: 'prof_a', status: 'running' }];
  f.terminal.create = async args => { created.push(args); return { sessionId: `session_${created.length + 1}`, profileId: args.id, status: 'running' }; };
  // Picking is allowed while a terminal runs: that terminal keeps its folder.
  const picked = await f.controller.dispatch('pickTerminalDirectory', { id: 'prof_a' });
  assert.equal(picked.canceled, false); assert.equal(picked.path, '/picked/for/this/terminal'); assert.match(picked.token, /^[0-9a-f-]{36}$/);
  await f.controller.dispatch('openTerminal', { id: 'prof_a', columns: 100, rows: 30, fresh: true, directoryToken: picked.token });
  assert.deepEqual(created.at(-1), { id: 'prof_a', columns: 100, rows: 30, fresh: true, directory: '/picked/for/this/terminal' });
  // The token is spent, bound to its environment, and a path from the caller is ignored.
  await assert.rejects(f.controller.dispatch('openTerminal', { id: 'prof_a', fresh: true, directoryToken: picked.token }), { code: 'TERMINAL_DIRECTORY_EXPIRED' });
  await f.controller.dispatch('openTerminal', { id: 'prof_a', fresh: true, directory: '/etc' });
  assert.equal(created.at(-1).directory, null, 'a directory never comes from the renderer');
  assert.equal(created.at(-1).fresh, true);
  // The folder was picked by the user for a new terminal; choosing another
  // browser (and so another environment) before opening keeps it.
  f.profiles.push({ id: 'prof_b', name: '另一个', group: '工作', proxyId: 'proxy_a' });
  f.state.profiles.push({ profileId: 'prof_b', cwd: '/b', sessions: [] });
  const other = await f.controller.dispatch('pickTerminalDirectory', { id: 'prof_a' });
  await f.controller.dispatch('openTerminal', { id: 'prof_b', fresh: true, directoryToken: other.token });
  assert.deepEqual([created.at(-1).id, created.at(-1).directory], ['prof_b', '/picked/for/this/terminal']);
  await assert.rejects(f.controller.dispatch('openTerminal', { id: 'prof_a', fresh: true, directoryToken: 'not-a-token' }), { code: 'TERMINAL_DIRECTORY_EXPIRED' });
});

test('Claude account IPC validates the environment and forwards only account metadata and launch ids', async () => {
  const f = fixture();
  f.state.profiles[0].cwd = '/selected/workspace';
  const seen = [];
  f.terminal.listClaudeAccounts = async args => { seen.push(['list', args]); return { accounts: [] }; };
  f.terminal.createClaudeAccount = async args => { seen.push(['createAccount', args]); return { account: { id: 'default', name: args.name } }; };
  f.terminal.renameClaudeAccount = async args => { seen.push(['renameAccount', args]); return { account: args }; };
  f.terminal.create = async args => { seen.push(['launch', args]); return { sessionId: 'test_session' }; };
  assert.deepEqual(await f.controller.dispatch('listClaudeAccounts', { id: 'prof_a', path: '/private/not-accepted' }), { accounts: [] });
  await f.controller.dispatch('createClaudeAccount', { id: 'prof_a', name: '工作', path: '/private/not-accepted', token: 'not-accepted' });
  await f.controller.dispatch('renameClaudeAccount', { id: 'prof_a', accountId: 'default', name: '个人', path: '/private/not-accepted' });
  await assert.rejects(f.controller.dispatch('listClaudeAccounts', { id: 'missing' }), { code: 'PROFILE_NOT_FOUND' });
  await f.controller.dispatch('openTerminal', { id: 'prof_a', kind: 'claude-code', browserProfileId: 'prof_a', claudeAccountId: 'default', requestId: 'request_a', fresh: true });
  assert.deepEqual(seen.slice(0, 3), [
    ['list', { id: 'prof_a' }], ['createAccount', { id: 'prof_a', name: '工作' }], ['renameAccount', { id: 'prof_a', accountId: 'default', name: '个人' }],
  ]);
  assert.equal(seen[3][1].claudeAccountId, 'default'); assert.equal(seen[3][1].requestId, 'request_a');
});

test('Close bypasses a pending launch queue so an installation can be cancelled', async () => {
  const f = fixture(); f.state.profiles[0].cwd = '/selected/workspace';
  let enter, cancel;
  const entered = new Promise(resolve => { enter = resolve; });
  f.terminal.create = async () => {
    enter();
    await new Promise(resolve => { cancel = resolve; });
    throw Object.assign(new Error('Cancelled.'), { code: 'TERMINAL_START_CANCELLED' });
  };
  f.terminal.close = async args => { cancel(); return { sessionId: args.sessionId, status: 'closed' }; };
  const creation = f.controller.dispatch('openTerminal', { id: 'prof_a', kind: 'claude-code', browserProfileId: 'prof_a', requestId: 'request_a', fresh: true });
  const refused = assert.rejects(creation, { code: 'TERMINAL_START_CANCELLED' });
  await entered;
  assert.deepEqual(await f.controller.dispatch('closeTerminal', { sessionId: 'installing_session' }), { sessionId: 'installing_session', status: 'closed' });
  await refused;
});

test('Claude install source and read-only status are explicitly scoped to the selected environment', async () => {
  const f = fixture(); f.state.profiles[0].cwd = '/selected/workspace';
  const seen = [];
  f.terminal.claudeInstallationStatus = async args => { seen.push(['status', args]); return { installed: false }; };
  f.terminal.create = async args => { seen.push(['create', args]); return { sessionId: 'test_session' }; };
  assert.deepEqual(await f.controller.dispatch('claudeInstallationStatus', { id: 'prof_a', home: '/not-accepted', source: 'local' }), { installed: false });
  await assert.rejects(f.controller.dispatch('claudeInstallationStatus', { id: 'missing' }), { code: 'PROFILE_NOT_FOUND' });
  await f.controller.dispatch('openTerminal', { id: 'prof_a', kind: 'claude-code', browserProfileId: 'prof_a', claudeInstallSource: 'local', fresh: true });
  assert.deepEqual(seen[0], ['status', { id: 'prof_a' }]);
  assert.equal(seen[1][1].claudeInstallSource, 'local');
});
