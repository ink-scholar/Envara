import test from 'node:test';
import assert from 'node:assert/strict';
import { TerminalController } from '../electron/terminal-controller.mjs';

function fixture(pickDirectory = async () => ({ canceled: false, path: '/selected/workspace' })) {
  const profiles = [{ id: 'prof_a', name: '工作环境', group: '工作', proxyId: 'proxy_a' }];
  const state = { profiles: [{ profileId: 'prof_a', cwd: null, sessions: [] }] };
  const calls = [];
  const terminal = {
    reserveClaudeAccountStart: () => () => {},
    reserveClaudeAccountDuplicateStart: () => () => {},
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

test('bulk deletion removes terminal data only for successful ids in real sidecar and legacy replies', async () => {
  for (const wrapped of [true, false]) {
    const f = fixture();
    const results = [{ id: 'prof_a', ok: true }, { id: 'prof_failed', ok: false }];
    const reply = wrapped ? { profiles: [], actionResult: { results } } : { results };
    assert.equal(await f.controller.protectMutation('bulkProfiles', { action: 'delete', ids: ['prof_a', 'prof_failed'] }, async () => reply), reply);
    assert.deepEqual(f.calls, [['removeOwnedConfiguration', 'prof_a']]);
  }
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
  f.terminal.deleteClaudeAccount = async args => { seen.push(['deleteAccount', args]); return { deleted: true }; };
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
  await f.controller.dispatch('deleteClaudeAccount', { id: 'prof_a', accountId: 'selected', confirmed: true, path: '/private/not-accepted', token: 'not-accepted' });
  assert.deepEqual(seen.at(-1), ['deleteAccount', { id: 'prof_a', accountId: 'selected', confirmed: true }]);
  await f.controller.dispatch('deleteClaudeAccount', { id: 'prof_a', accountId: 'selected', confirmed: 'true' });
  assert.equal(seen.at(-1)[1].confirmed, false);
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

test('an explicit null account keeps the existing default-account launch contract', async () => {
  const f = fixture(); f.state.profiles[0].cwd = '/selected/workspace';
  const reservations = [];
  f.terminal.reserveClaudeAccountStart = (id, accountId = 'default') => { reservations.push([id, accountId]); return () => reservations.push('released'); };
  await f.controller.dispatch('openTerminal', { id: 'prof_a', kind: 'claude-code', claudeAccountId: null });
  assert.deepEqual(reservations, [['prof_a', 'default'], 'released']);
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

function sshFixture(pickSSHIdentity) {
  const f = fixture();
  const sourceWindow = { destroyed: false, isDestroyed() { return this.destroyed; } };
  const publicConnection = { id: 'ssh_a', name: 'Fixture server', alias: 'envara-0123456789ab', host: 'server.example', port: 2222,
    user: 'fixture', keyLabel: 'fixture_key', keyFingerprint: 'SHA256:fixture-key', hostFingerprints: ['SHA256:fixture-host'] };
  const calls = [];
  f.controller.pickSSHIdentity = pickSSHIdentity ?? (async (args, context) => {
    calls.push(['pick', args, context.window]); return { canceled: false, path: '/native-picker/fixture_key' };
  });
  f.terminal.listTerminalSshConnections = async args => { calls.push(['list', args]); return { supported: true, connections: [publicConnection] }; };
  f.terminal.prepareTerminalSshIdentity = async args => { calls.push(['prepare', args]); return { ...publicConnection, selectionToken: 'manager-token', keyPath: '/never-public/key', privateBytes: 'not-public' }; };
  f.terminal.saveTerminalSshConnection = async args => { calls.push(['save', args]); return publicConnection; };
  f.terminal.removeTerminalSshConnection = async args => { calls.push(['remove', args]); return { removed: true }; };
  return { ...f, calls, sourceWindow, context: { window: sourceWindow }, publicConnection,
    request: { id: 'prof_a', host: 'server.example', port: 2222, user: 'fixture' } };
}

test('SSH listing and native key selection expose only public metadata and a window-sealed capability', async () => {
  const f = sshFixture();
  f.terminal.listTerminalSshConnections = async args => { f.calls.push(['list', args]); return { supported: true,
    connections: [{ ...f.publicConnection, keyPath: '/never-public/key', routeCredentials: 'not-public' }], agentSocket: '/never-public/socket' }; };
  assert.deepEqual(await f.controller.dispatch('listTerminalSshConnections', { id: 'prof_a', keyPath: '/renderer/key' }),
    { supported: true, connections: [f.publicConnection] });
  const prepared = await f.controller.dispatch('prepareTerminalSshIdentity', { ...f.request, keyPath: '/renderer/key', hostFingerprints: ['forged'] }, f.context);
  assert.match(prepared.selectionToken, /^[0-9a-f-]{36}$/);
  assert.notEqual(prepared.selectionToken, 'manager-token');
  assert.equal(Object.hasOwn(prepared, 'keyPath'), false);
  assert.equal(Object.hasOwn(prepared, 'privateBytes'), false);
  assert.deepEqual(prepared.hostFingerprints, ['SHA256:fixture-host']);
  assert.deepEqual(f.calls.find(([type]) => type === 'pick'), ['pick', f.request, f.sourceWindow]);
  assert.deepEqual(f.calls.find(([type]) => type === 'prepare'), ['prepare', { ...f.request, keyPath: '/native-picker/fixture_key' }]);
  const saved = await f.controller.dispatch('saveTerminalSshConnection', { id: 'prof_a', name: 'Saved name', selectionToken: prepared.selectionToken,
    host: 'forged.example', keyPath: '/renderer/key', hostFingerprints: ['forged'] }, f.context);
  assert.deepEqual(saved, { supported: true, connections: [f.publicConnection] });
  assert.deepEqual(f.calls.find(([type]) => type === 'save'), ['save', { id: 'prof_a', name: 'Saved name', selectionToken: 'manager-token' }]);
  await assert.rejects(f.controller.dispatch('saveTerminalSshConnection', { id: 'prof_a', name: 'Again', selectionToken: prepared.selectionToken }, f.context), { code: 'SSH_SELECTION_EXPIRED' });
});

test('SSH selections cannot cross windows or environments and cannot be supplied as manager tokens', async () => {
  const f = sshFixture();
  f.profiles.push({ id: 'prof_b', name: 'Other' });
  const prepared = await f.controller.dispatch('prepareTerminalSshIdentity', f.request, f.context);
  const save = { id: 'prof_a', name: 'Fixture', selectionToken: prepared.selectionToken };
  const otherWindow = { isDestroyed: () => false };
  await assert.rejects(f.controller.dispatch('saveTerminalSshConnection', save, { window: otherWindow }), { code: 'SSH_SELECTION_MISMATCH' });
  await assert.rejects(f.controller.dispatch('saveTerminalSshConnection', { ...save, id: 'prof_b' }, f.context), { code: 'SSH_SELECTION_MISMATCH' });
  await assert.rejects(f.controller.dispatch('saveTerminalSshConnection', { ...save, selectionToken: 'manager-token' }, f.context), { code: 'SSH_SELECTION_EXPIRED' });
  assert.equal(f.calls.some(([type]) => type === 'save'), false);
  await f.controller.dispatch('saveTerminalSshConnection', save, f.context);
  assert.equal(f.calls.filter(([type]) => type === 'save').length, 1, 'a rejected foreign window does not consume the owner’s token');
});

test('active SSH configuration is read-only while selection remains available and becomes savable after sessions close', async () => {
  const f = sshFixture();
  const prepared = await f.controller.dispatch('prepareTerminalSshIdentity', f.request, f.context);
  for (const status of ['starting', 'running', 'closing']) {
    f.state.profiles[0].sessions = [{ sessionId: 'active', status }];
    await f.controller.dispatch('listTerminalSshConnections', { id: 'prof_a' }, f.context);
    await assert.rejects(f.controller.dispatch('saveTerminalSshConnection', { id: 'prof_a', name: 'Fixture', selectionToken: prepared.selectionToken }, f.context), { code: 'SSH_TERMINAL_BUSY' });
    await assert.rejects(f.controller.dispatch('removeTerminalSshConnection', { id: 'prof_a', connectionId: 'ssh_a' }, f.context), { code: 'SSH_TERMINAL_BUSY' });
  }
  const replacement = await f.controller.dispatch('prepareTerminalSshIdentity', f.request, f.context);
  assert.equal(f.calls.filter(([type]) => ['save', 'remove'].includes(type)).length, 0);
  f.state.profiles[0].sessions = [{ sessionId: 'ended', status: 'exited' }];
  await f.controller.dispatch('saveTerminalSshConnection', { id: 'prof_a', name: 'Fixture', selectionToken: replacement.selectionToken }, f.context);
  await f.controller.dispatch('removeTerminalSshConnection', { id: 'prof_a', connectionId: 'ssh_a', keyPath: '/renderer/key' }, f.context);
  assert.deepEqual(f.calls.filter(([type]) => ['save', 'remove'].includes(type)), [
    ['save', { id: 'prof_a', name: 'Fixture', selectionToken: 'manager-token' }], ['remove', { id: 'prof_a', connectionId: 'ssh_a' }],
  ]);
});

test('cancelled SSH key selection and invalid targets never reach the identity manager', async () => {
  const f = sshFixture(async () => ({ canceled: true }));
  assert.deepEqual(await f.controller.dispatch('prepareTerminalSshIdentity', f.request, f.context), { canceled: true });
  for (const change of [{ host: '' }, { host: '-option' }, { host: 'bad\nhost' }, { port: 0 }, { port: '22' }, { port: 65536 }, { user: 'bad\nuser' }])
    await assert.rejects(f.controller.dispatch('prepareTerminalSshIdentity', { ...f.request, ...change }, f.context), { code: 'SSH_INVALID_INPUT' });
  await assert.rejects(f.controller.dispatch('prepareTerminalSshIdentity', f.request), { code: 'SSH_WINDOW_CLOSED' });
  assert.equal(f.calls.some(([type]) => type === 'prepare'), false);
});

test('closing the source window or deleting its environment during the SSH picker prevents preparation', async () => {
  for (const action of ['close', 'delete']) {
    let f;
    f = sshFixture(async () => {
      if (action === 'close') f.sourceWindow.destroyed = true;
      else f.profiles.length = 0;
      return { canceled: false, path: '/native-picker/fixture_key' };
    });
    await assert.rejects(f.controller.dispatch('prepareTerminalSshIdentity', f.request, f.context), { code: action === 'close' ? 'SSH_WINDOW_CLOSED' : 'PROFILE_NOT_FOUND' });
    assert.equal(f.calls.some(([type]) => type === 'prepare'), false);
    assert.equal(f.controller.pickedSSHIdentities.size, 0);
  }
});

test('SSH preparation rechecks source lifetime after the manager returns and selections expire', async () => {
  const f = sshFixture();
  f.terminal.prepareTerminalSshIdentity = async () => { f.sourceWindow.destroyed = true; return { ...f.publicConnection, selectionToken: 'manager-token' }; };
  await assert.rejects(f.controller.dispatch('prepareTerminalSshIdentity', f.request, f.context), { code: 'SSH_WINDOW_CLOSED' });
  assert.equal(f.controller.pickedSSHIdentities.size, 0);
  const fresh = sshFixture();
  const prepared = await fresh.controller.dispatch('prepareTerminalSshIdentity', fresh.request, fresh.context);
  fresh.controller.pickedSSHIdentities.get(prepared.selectionToken).expiresAt = Date.now() - 1;
  await assert.rejects(fresh.controller.dispatch('saveTerminalSshConnection', { id: 'prof_a', name: 'Fixture', selectionToken: prepared.selectionToken }, fresh.context), { code: 'SSH_SELECTION_EXPIRED' });
  assert.equal(fresh.calls.some(([type]) => type === 'save'), false);
});

test('a queued SSH save rechecks running terminals after an in-progress launch finishes', async () => {
  const f = sshFixture();
  const prepared = await f.controller.dispatch('prepareTerminalSshIdentity', f.request, f.context);
  f.state.profiles[0].cwd = '/selected/workspace';
  let resolveLaunch, entered;
  const starting = new Promise(resolve => { entered = resolve; });
  f.terminal.create = async () => { entered(); await new Promise(resolve => { resolveLaunch = resolve; }); f.state.profiles[0].sessions = [{ sessionId: 'new', status: 'running' }]; return f.state.profiles[0].sessions[0]; };
  const launch = f.controller.dispatch('openTerminal', { id: 'prof_a', fresh: true });
  await starting;
  const save = f.controller.dispatch('saveTerminalSshConnection', { id: 'prof_a', name: 'Fixture', selectionToken: prepared.selectionToken }, f.context);
  const rejected = assert.rejects(save, { code: 'SSH_TERMINAL_BUSY' });
  resolveLaunch(); await launch; await rejected;
  assert.equal(f.calls.some(([type]) => type === 'save'), false);
});
