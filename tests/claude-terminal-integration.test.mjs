import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fsPromises from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { chmod, copyFile, mkdtemp, mkdir, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { TerminalService } from '../electron/terminal-service.mjs';
import { LinkRouter } from '../electron/link-router.mjs';
import { ensureClaudeInstallation } from '../electron/claude-code-installation.mjs';

async function fixture(t, overrides = {}) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-claude-session-')));
  const cwd = path.join(root, 'project'); await mkdir(cwd);
  const hostExecutable = path.join(root, '2.1.296');
  await copyFile('/usr/bin/true', hostExecutable); await chmod(hostExecutable, 0o700);
  const launches = [], bindings = [], order = [];
  const context = { id: 'chosen', name: 'Chosen browser', proxyId: 'route_a', timezone: 'Asia/Manila', locale: 'en-PH',
    network: { ok: true, ip: '203.0.113.1' }, proxy: { protocol: 'http', host: '127.0.0.1', port: 45763, username: 'fixture', password: 'private-route-secret' } };
  const browserBroker = { createSession: async args => {
    const binding = { args, browser: { profileId: args.browserProfileId, name: 'Chosen browser' },
      environment: { ENVARA_BROWSER_SOCKET: '/private/test.sock', ENVARA_BROWSER_TOKEN: `browser-token-${bindings.length}`, ENVARA_LINK_SOCKET: '/private/test.sock', ENVARA_LINK_TOKEN: `link-token-${bindings.length}` },
      mcpServer: { command: process.execPath, args: ['/private/mcp.mjs'] },
      openLink: async url => ({ opened: 'environment', profileId: 'chosen', url }), dispose: async () => { binding.disposed = true; order.push('revoke'); } };
    bindings.push(binding); return binding;
  } };
  const service = new TerminalService({ dataDir: path.join(root, 'data'), resolveContext: async () => structuredClone(context), browserBroker,
    availableLocales: ['C', 'en_US.UTF-8', 'en_PH.UTF-8'],
    claudeExecutableResolver: async () => hostExecutable,
    // Product launches default to an explicit download. This suite exercises
    // that policy with native fixture bytes and never reaches a real network.
    claudeInstaller: options => ensureClaudeInstallation({ ...options, downloadNative: async ({ destination }) => {
      await copyFile(hostExecutable, destination);
      return { version: '2.1.296' };
    } }),
    linkChannel: { executableDirectory: async () => '/private/owned-bin', environment: () => ({ ENVARA_LINK_SOCKET: '/private/ordinary.sock', ENVARA_LINK_TOKEN: 'ordinary-link-token' }) },
    networkFence: { wrap: async (launch, options) => { order.push('fence'); return { ...launch, deviceIdentifierRestrictions: options.restrictDeviceIdentifiers === true }; } },
    ptyFactory: (executable, args, options) => {
      const exits = new Set(); const pty = { pid: 1000 + launches.length, onData: () => ({ dispose() {} }), onExit: fn => { exits.add(fn); return { dispose() {} }; }, kill: () => { for (const fn of exits) fn({ exitCode: 0 }); } };
      launches.push({ executable, args, options, pty }); return pty;
    }, processControl: { capture: async pid => ({ pid }), close: async () => { order.push('process-close'); return { ok: true }; } }, ...overrides });
  t.after(async () => { await service.shutdown().catch(() => {}); await rm(root, { recursive: true, force: true }); });
  return { service, root, cwd, context, launches, bindings, order,
    start: () => service.create({ id: 'chosen', directory: cwd, kind: 'claude-code', browserProfileId: 'chosen', fresh: true }) };
}

function deferred() {
  let resolve;
  const promise = new Promise(accept => { resolve = accept; });
  return { promise, resolve };
}

function managedContext(context, id = 'chosen', proxyId = 'route_a') {
  return { ...structuredClone(context), id, proxyId, managedProxy: true,
    managedRoute: { proxyId, routeIdentity: `fixture-${proxyId}`, coreGeneration: 1, corePid: 1234 } };
}

test('dedicated session opens a shell with a manual Claude wrapper and pinned MCP/link credentials', async t => {
  const f = await fixture(t), session = await f.start(), launch = f.launches[0];
  assert.equal(session.kind, 'claude-code'); assert.equal(session.browserProfileId, 'chosen'); assert.equal(session.browserName, 'Chosen browser');
  assert.equal(session.deviceIdentifierRestrictions, true);
  const internal = f.service.sessions.get(session.sessionId), prepared = internal.claudeLaunch;
  assert.equal(launch.executable, process.platform === 'darwin' ? '/bin/zsh' : '/bin/bash');
  assert.equal(launch.args.at(-1), '-i');
  assert(!launch.args.includes('--mcp-config'));
  assert.equal(prepared.executable, path.join(launch.options.env.HOME, '.local/share/claude/versions/2.1.296'));
  assert.equal(prepared.installation.entryPath, path.join(launch.options.env.HOME, '.local/bin/claude'));
  assert.notEqual((await stat(prepared.executable)).ino, (await stat(path.join(f.root, '2.1.296'))).ino);
  assert(prepared.args.includes('--strict-mcp-config')); assert(prepared.args.includes('--no-chrome'));
  assert.equal(launch.options.env.PATH.split(path.delimiter)[0], prepared.binDirectory);
  assert.equal(path.join(prepared.binDirectory, 'claude'), prepared.wrapperPath);
  assert.equal(launch.options.cwd, f.cwd); assert.equal(launch.options.env.TZ, 'Asia/Manila');
  assert.equal(launch.options.env.LANG, 'en_PH.UTF-8'); assert.equal(launch.options.env.LC_ALL, 'en_PH.UTF-8');
  assert.deepEqual(session.language, { requested: 'en-PH', effective: 'en-PH', posix: 'en_PH.UTF-8', fallback: false });
  const settings = JSON.parse(await readFile(prepared.args[prepared.args.indexOf('--settings') + 1], 'utf8'));
  assert.equal(settings.env.LANG, 'en_PH.UTF-8'); assert.equal(settings.env.LC_ALL, 'en_PH.UTF-8');
  assert(launch.options.env.CLAUDE_CONFIG_DIR.startsWith(path.join(f.root, 'data/terminal/profiles/chosen')));
  assert.equal(launch.options.env.ENVARA_LINK_SOCKET, '/private/test.sock');
  assert.equal(launch.options.env.ENVARA_BROWSER_TOKEN, f.bindings[0].environment.ENVARA_BROWSER_TOKEN);
  const config = prepared.args[prepared.args.indexOf('--mcp-config') + 1];
  assert.equal((await stat(config)).mode & 0o777, 0o600);
  const content = await readFile(config, 'utf8'); assert(!content.includes('token')); assert(!content.includes('private-route-secret'));
  assert(!JSON.stringify(await f.service.snapshot()).includes('browser-token'));
  assert.equal(f.service.redact(internal, 'browser-token-0 link-token-0', true), '[redacted] [redacted]');
  assert.equal(f.bindings[0].args.context.proxyId, 'route_a'); assert.deepEqual(f.bindings[0].args.context.network, f.context.network);
  await f.service.setLinkBrowser({ id: 'chosen', browserProfileId: 'system' });
  assert.equal((await f.service.boundBrowserLink(session.sessionId, 'https://example.com')).profileId, 'chosen');
  await f.service.close({ sessionId: session.sessionId });
  assert(f.order.indexOf('revoke') < f.order.indexOf('process-close'));
  await assert.rejects(stat(config), { code: 'ENOENT' });
});

test('duplicating Claude retains kind and context but receives fresh process and revocable browser token', async t => {
  const f = await fixture(t), first = await f.start();
  f.context.timezone = 'UTC';
  const second = await f.service.duplicate({ sessionId: first.sessionId });
  assert.notEqual(first.sessionId, second.sessionId); assert.equal(second.kind, 'claude-code'); assert.equal(second.timezone, 'Asia/Manila');
  assert.notEqual(f.launches[0].options.env.ENVARA_BROWSER_TOKEN, f.launches[1].options.env.ENVARA_BROWSER_TOKEN);
  assert.equal(f.launches[0].options.env.CLAUDE_CONFIG_DIR, f.launches[1].options.env.CLAUDE_CONFIG_DIR);
  await f.service.close({ sessionId: first.sessionId }); assert.equal(f.bindings[1].disposed, undefined);
  assert.equal((await f.service.boundBrowserLink(second.sessionId, 'https://example.com')).profileId, 'chosen');
  const shell = await f.service.create({ id: 'chosen', kind: 'shell' }); assert.equal(shell.kind, 'shell'); assert.notEqual(shell.sessionId, second.sessionId);
});

test('synthetic login data persists across close, recreation and duplication without crossing environments', async t => {
  const f = await fixture(t), first = await f.start();
  const firstEnvironment = f.launches[0].options.env;
  const markerFile = path.join(firstEnvironment.CLAUDE_CONFIG_DIR, '.credentials.json');
  const marker = JSON.stringify({ syntheticLoginMarker: 'fixture-only-chosen-account' });
  const userSettings = path.join(firstEnvironment.CLAUDE_CONFIG_DIR, 'settings.json');
  await writeFile(markerFile, marker, { mode: 0o600 });
  await writeFile(userSettings, '{"model":"sonnet"}', { mode: 0o600 });
  await writeFile(path.join(firstEnvironment.HOME, '.envara_history'), 'fixture shell history\n', { mode: 0o600 });
  const firstWrapper = f.service.sessions.get(first.sessionId).claudeLaunch.wrapperPath;
  await f.service.close({ sessionId: first.sessionId });
  await assert.rejects(stat(firstWrapper), { code: 'ENOENT' });
  assert.equal(await readFile(markerFile, 'utf8'), marker);
  const recreated = await f.start(), duplicate = await f.service.duplicate({ sessionId: recreated.sessionId });
  for (const index of [1, 2]) {
    assert.equal(f.launches[index].options.env.CLAUDE_CONFIG_DIR, firstEnvironment.CLAUDE_CONFIG_DIR);
    assert.equal(f.launches[index].options.env.HOME, firstEnvironment.HOME);
    assert.equal(await readFile(path.join(f.launches[index].options.env.CLAUDE_CONFIG_DIR, '.credentials.json'), 'utf8'), marker);
  }
  assert.notEqual(f.launches[1].options.env.PATH, f.launches[2].options.env.PATH);
  await f.service.close({ sessionId: recreated.sessionId });
  assert.equal(await readFile(markerFile, 'utf8'), marker);
  f.context.id = 'other';
  const other = await f.service.create({ id: 'other', directory: f.cwd, kind: 'claude-code', browserProfileId: 'other', fresh: true });
  const otherEnvironment = f.launches[3].options.env;
  assert.notEqual(otherEnvironment.CLAUDE_CONFIG_DIR, firstEnvironment.CLAUDE_CONFIG_DIR);
  assert.notEqual(otherEnvironment.HOME, firstEnvironment.HOME);
  await assert.rejects(stat(path.join(otherEnvironment.CLAUDE_CONFIG_DIR, '.credentials.json')), { code: 'ENOENT' });
  await writeFile(path.join(otherEnvironment.CLAUDE_CONFIG_DIR, '.credentials.json'), '{"syntheticLoginMarker":"fixture-other-account"}', { mode: 0o600 });
  await f.service.close({ sessionId: duplicate.sessionId }); await f.service.close({ sessionId: other.sessionId });
  assert.equal(await readFile(markerFile, 'utf8'), marker);
  assert.equal(await readFile(userSettings, 'utf8'), '{"model":"sonnet"}');
  assert.equal(await readFile(path.join(firstEnvironment.HOME, '.envara_history'), 'utf8'), 'fixture shell history\n');
});

test('named login profiles share the environment installation but keep independent persistent Claude state', async t => {
  const f = await fixture(t);
  assert.deepEqual(await f.service.listClaudeAccounts({ id: 'chosen' }), { accounts: [{ id: 'default', name: '默认', default: true, inUse: false }] });
  const legacy = await f.start();
  const legacyEnv = f.launches[0].options.env;
  assert.equal(legacy.claudeAccountId, 'default');
  assert.equal(legacyEnv.CLAUDE_CONFIG_DIR, path.join(f.root, 'data/terminal/profiles/chosen/claude'));
  const legacyMarker = path.join(legacyEnv.CLAUDE_CONFIG_DIR, '.credentials.json');
  await writeFile(legacyMarker, '{"syntheticLogin":"legacy"}', { mode: 0o600 });
  const { account } = await f.service.createClaudeAccount({ id: 'chosen', name: '工作账号' });
  assert.deepEqual(Object.keys(account).sort(), ['default', 'id', 'inUse', 'name']);
  const named = await f.service.create({ id: 'chosen', directory: f.cwd, kind: 'claude-code', browserProfileId: 'chosen', claudeAccountId: account.id, fresh: true });
  const namedEnv = f.launches[1].options.env;
  assert.equal(named.claudeAccountId, account.id); assert.equal(named.claudeAccountName, '工作账号');
  assert.equal(namedEnv.HOME, legacyEnv.HOME);
  assert.notEqual(namedEnv.CLAUDE_CONFIG_DIR, legacyEnv.CLAUDE_CONFIG_DIR);
  assert.equal(f.service.sessions.get(named.sessionId).claudeLaunch.installation.entryPath, f.service.sessions.get(legacy.sessionId).claudeLaunch.installation.entryPath);
  await assert.rejects(readFile(path.join(namedEnv.CLAUDE_CONFIG_DIR, '.credentials.json')), { code: 'ENOENT' });
  const namedMarker = path.join(namedEnv.CLAUDE_CONFIG_DIR, '.credentials.json');
  await writeFile(namedMarker, '{"syntheticLogin":"named"}', { mode: 0o600 });
  const duplicate = await f.service.duplicate({ sessionId: named.sessionId });
  assert.equal(duplicate.claudeAccountId, account.id);
  assert.equal(f.launches[2].options.env.CLAUDE_CONFIG_DIR, namedEnv.CLAUDE_CONFIG_DIR);
  const { accounts } = await f.service.listClaudeAccounts({ id: 'chosen' });
  assert(accounts.every(item => item.inUse));
  assert(!JSON.stringify(accounts).includes('credentials'));
  await assert.rejects(f.service.renameClaudeAccount({ id: 'chosen', accountId: account.id, name: '重命名' }), { code: 'CLAUDE_ACCOUNT_IN_USE' });
  await assert.rejects(f.service.create({ id: 'other', directory: f.cwd, kind: 'claude-code', browserProfileId: 'other', claudeAccountId: account.id }), { code: 'CLAUDE_ACCOUNT_NOT_FOUND' });
  for (const session of [legacy, named, duplicate]) await f.service.close({ sessionId: session.sessionId });
  assert.equal(await readFile(legacyMarker, 'utf8'), '{"syntheticLogin":"legacy"}');
  assert.equal(await readFile(namedMarker, 'utf8'), '{"syntheticLogin":"named"}');
  const renamed = await f.service.renameClaudeAccount({ id: 'chosen', accountId: account.id, name: '新名称' });
  assert.equal(renamed.account.name, '新名称');
  assert((await f.service.listClaudeAccounts({ id: 'chosen' })).accounts.every(item => !item.inUse));
  const ordinary = await f.service.create({ id: 'chosen', directory: f.cwd, kind: 'shell', fresh: true });
  assert.equal(ordinary.claudeAccountId, undefined);
  assert.equal(f.launches.at(-1).options.env.CLAUDE_CONFIG_DIR, legacyEnv.CLAUDE_CONFIG_DIR);
});

test('product sessions default to download, forward an explicit local choice and preserve it on duplicate', async t => {
  const sources = []; let hostLookups = 0;
  const f = await fixture(t, {
    claudeExecutableResolver: async () => { hostLookups++; throw new Error('A downloaded environment must not inspect this host.'); },
    claudeInstaller: options => {
      sources.push(options.source);
      return ensureClaudeInstallation({ ...options, downloadNative: async ({ destination }) => {
        await copyFile('/usr/bin/true', destination); return { version: '2.1.300' };
      } });
    },
  });
  const downloaded = await f.start();
  assert.equal(downloaded.claudeInstallSource, 'download'); assert.equal(hostLookups, 0);
  const duplicateDownload = await f.service.duplicate({ sessionId: downloaded.sessionId });
  assert.equal(duplicateDownload.claudeInstallSource, 'download');
  const local = await f.service.create({ id: 'chosen', directory: f.cwd, kind: 'claude-code', browserProfileId: 'chosen', claudeInstallSource: 'local', fresh: true });
  assert.equal(local.claudeInstallSource, 'local');
  const duplicateLocal = await f.service.duplicate({ sessionId: local.sessionId });
  assert.equal(duplicateLocal.claudeInstallSource, 'local');
  assert.deepEqual(sources, ['download', 'download', 'local', 'local']);
  assert.equal(hostLookups, 0, 'the existing environment install wins even when local was requested');
  for (const value of ['auto', 'invalid', null, 42]) await assert.rejects(f.service.create({ id: 'chosen', kind: 'claude-code', browserProfileId: 'chosen', claudeInstallSource: value }), { code: 'CLAUDE_CODE_INSTALL_SOURCE_INVALID' });
  await assert.rejects(f.service.create({ id: 'chosen', kind: 'shell', claudeInstallSource: 'download' }), { code: 'CLAUDE_CODE_INSTALL_SOURCE_INVALID' });
});

test('installation status is read-only and never bootstraps a terminal home or inspects the host', async t => {
  let hostLookups = 0;
  const f = await fixture(t, { claudeExecutableResolver: async () => { hostLookups++; throw new Error('No host probe.'); } });
  await f.service.ready;
  assert.deepEqual(await readdir(f.service.profilesDir), []);
  assert.deepEqual(await f.service.claudeInstallationStatus({ id: 'chosen' }), { installed: false });
  assert.deepEqual(await readdir(f.service.profilesDir), []);
  assert.equal(f.launches.length, 0); assert.equal(hostLookups, 0);
  const session = await f.start();
  assert.deepEqual(await f.service.claudeInstallationStatus({ id: 'chosen' }), { installed: true });
  assert.equal(hostLookups, 0); assert.equal(session.claudeInstallSource, 'download');
});

test('closing an installing session aborts its selected route and never starts a late CLI', async t => {
  const entered = deferred(), events = []; let options;
  const f = await fixture(t, { onEvent: event => events.push(event), claudeInstaller: async value => {
    options = value;
    value.onProgress({ phase: 'downloading', receivedBytes: 1024, totalBytes: 2048, version: '2.1.300', proxyUrl: 'private-route-secret' });
    value.onProgress({ phase: 'private-route-secret', receivedBytes: -1 });
    entered.resolve();
    await new Promise((resolve, reject) => value.downloadContext.signal.addEventListener('abort', () => reject(Object.assign(new Error('Download cancelled.'), { code: 'CLAUDE_CODE_DOWNLOAD_CANCELLED' })), { once: true }));
  } });
  const creation = f.service.create({ id: 'chosen', directory: f.cwd, kind: 'claude-code', browserProfileId: 'chosen', requestId: 'request_one', fresh: true });
  const refused = assert.rejects(creation, { code: 'TERMINAL_START_CANCELLED' });
  await entered.promise;
  assert.equal(options.downloadContext.proxyUrl, 'http://fixture:private-route-secret@127.0.0.1:45763');
  const session = [...f.service.sessions.values()][0];
  const metadata = f.service.metadata(session);
  assert.equal(metadata.requestId, 'request_one');
  assert.deepEqual(metadata.claudeInstall, { phase: 'downloading', receivedBytes: 1024, totalBytes: 2048, version: '2.1.300' });
  await f.service.close({ sessionId: session.sessionId }); await refused;
  assert.equal(options.downloadContext.signal.aborted, true);
  assert.equal(f.launches.length, 0); assert.equal(f.bindings.length, 0);
  assert.equal(session.status, 'closed');
  assert(!JSON.stringify(await f.service.snapshot()).includes('private-route-secret'));
  await new Promise(resolve => setImmediate(resolve));
  const progress = events.find(event => event.claudeInstall);
  assert.equal(progress.requestId, 'request_one'); assert.equal(progress.profileId, 'chosen');
  assert(!JSON.stringify(progress).includes('private-route-secret'));
});

test('shutdown and owned core failure abort a pending installation before waiting for its queue', async t => {
  for (const reason of ['shutdown', 'core']) {
    const entered = deferred(); let signal;
    const f = await fixture(t, { claudeInstaller: async options => {
      signal = options.downloadContext.signal; entered.resolve();
      await new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(Object.assign(new Error('Download cancelled.'), { code: 'CLAUDE_CODE_DOWNLOAD_CANCELLED' })), { once: true }));
    } });
    f.service.resolveContext = async () => managedContext(f.context);
    const creation = f.start();
    const refused = assert.rejects(creation, { code: reason === 'core' ? 'CLAUDE_NETWORK_ROUTE_LOST' : 'TERMINAL_START_CANCELLED' });
    await entered.promise;
    if (reason === 'core') await f.service.invalidateManagedProxy('route_a');
    else await f.service.shutdown();
    await refused;
    assert.equal(signal.aborted, true); assert.equal(f.launches.length, 0);
    if (reason === 'core') assert.equal([...f.service.sessions.values()][0].errorCode, 'CLAUDE_NETWORK_ROUTE_LOST');
  }
});

test('dedicated sessions reject a system or other browser and an unfenced route before CLI spawn', async t => {
  const f = await fixture(t, { networkFence: null });
  for (const browserProfileId of ['system', 'other', null]) await assert.rejects(f.service.create({ id: 'chosen', kind: 'claude-code', browserProfileId, directory: f.cwd }), { code: 'CLAUDE_BROWSER_REQUIRED' });
  await assert.rejects(f.start(), { code: 'CLAUDE_NETWORK_FENCE_REQUIRED' }); assert.equal(f.launches.length, 0); assert.equal(f.bindings.length, 0);
});

test('dedicated sessions and duplicates require confirmed device restrictions; ordinary terminals do not request them', async t => {
  const options = [];
  const f = await fixture(t, { networkFence: { wrap: async (launch, configuration) => {
    options.push(configuration); return { ...launch, deviceIdentifierRestrictions: configuration.restrictDeviceIdentifiers === true };
  } } });
  const first = await f.start();
  const duplicate = await f.service.duplicate({ sessionId: first.sessionId });
  assert.equal(first.deviceIdentifierRestrictions, true);
  assert.equal(duplicate.deviceIdentifierRestrictions, true);
  assert.equal(options[0].restrictDeviceIdentifiers, true);
  assert.equal(options[1].restrictDeviceIdentifiers, true);
  const ordinary = await f.service.create({ id: 'chosen', directory: f.cwd, fresh: true });
  assert.equal(options[2].restrictDeviceIdentifiers, undefined);
  assert.equal(ordinary.deviceIdentifierRestrictions, undefined);
});

test('an unconfirmed or refused device restriction never launches a Claude process and cleans its temporary authority', async t => {
  for (const refusal of ['missing-confirmation', 'failed-preflight']) await t.test(refusal, async t => {
    const f = await fixture(t, { networkFence: { wrap: async launch => {
      if (refusal === 'failed-preflight') throw Object.assign(new Error('设备标识读取限制不可用。'), { code: 'TERMINAL_DEVICE_IDENTIFIERS_UNAVAILABLE' });
      return launch;
    } } });
    await assert.rejects(f.start(), { code: 'TERMINAL_DEVICE_IDENTIFIERS_UNAVAILABLE' });
    assert.equal(f.launches.length, 0);
    assert.equal(f.bindings[0].disposed, true);
    const internal = [...f.service.sessions.values()][0];
    assert.equal(f.service.metadata(internal).deviceIdentifierRestrictions, false);
    await assert.rejects(stat(path.join(f.root, 'data/terminal/profiles/chosen/tmp', `claude-${internal.sessionId}`)), { code: 'ENOENT' });
  });
});

test('native launch failure revokes browser authority and deletes temporary MCP settings', async t => {
  const f = await fixture(t, { ptyFactory: () => { throw new Error('fixture PTY refusal'); } });
  await assert.rejects(f.start(), /fixture PTY refusal/); assert.equal(f.bindings[0].disposed, true);
  const internal = [...f.service.sessions.values()][0]; assert.equal(internal.status, 'error'); assert.equal(internal.browserBinding, null);
  await assert.rejects(stat(path.join(f.root, 'data/terminal/profiles/chosen/tmp', `claude-${internal.sessionId}`)), { code: 'ENOENT' });
});

test('failed installation cleanup keeps the first failure and a late retry handle after an earlier Close', async t => {
  for (const earlyClose of [false, true]) {
    let allowCleanup = false, cleanupAttempts = 0;
    const entered = deferred(), release = deferred();
    const failure = Object.assign(new Error('Claude 下载已取消。'), { code: 'CLAUDE_CODE_DOWNLOAD_CANCELLED', cleanupError: 'Claude 临时文件清理未完成。' });
    Object.defineProperty(failure, 'claudeCleanup', { value: async () => {
      cleanupAttempts++;
      if (!allowCleanup) throw new Error('fixture private cleanup path');
    } });
    const f = await fixture(t, { claudeInstaller: async () => { entered.resolve(); await release.promise; throw failure; } });
    const starting = f.start();
    const rejected = assert.rejects(starting, { code: earlyClose ? 'TERMINAL_START_CANCELLED' : 'CLAUDE_CODE_DOWNLOAD_CANCELLED' });
    await entered.promise;
    const session = [...f.service.sessions.values()][0];
    if (earlyClose) assert.equal((await f.service.close({ sessionId: session.sessionId })).status, 'closed');
    release.resolve(); await rejected;
    assert.equal(session.status, 'closing');
    assert.equal(session.finished, false);
    assert.ok(session.cleanupError);
    assert.equal(cleanupAttempts, 1, 'the newly returned cleanup handle cannot reuse a previous empty cleanup result');
    assert.equal(f.launches.length, 0);
    const snapshot = JSON.stringify(await f.service.snapshot());
    assert.doesNotMatch(snapshot, /fixture private cleanup path|claudeCleanup/);
    assert.equal(session.errorCode, earlyClose ? 'TERMINAL_START_CANCELLED' : 'CLAUDE_CODE_DOWNLOAD_CANCELLED');
    allowCleanup = true;
    const ended = await f.service.close({ sessionId: session.sessionId });
    assert.equal(ended.status, 'closed');
    assert.equal(ended.cleanupError, undefined);
    assert.equal(cleanupAttempts, 2);
    assert.equal(session.claudeLaunch, null);
  }
});

test('a successful late browser binding keeps failed disposal retryable after Close already completed', async t => {
  const entered = deferred(), release = deferred();
  let allowCleanup = false, cleanupAttempts = 0;
  const binding = { browser: { name: 'Fixture browser' }, dispose: async () => {
    cleanupAttempts++;
    if (!allowCleanup) throw Object.assign(new Error('fixture private binding directory'), { code: 'EACCES' });
  } };
  const f = await fixture(t, { claudeInstaller: async () => ({}), browserBroker: { createSession: async () => {
    entered.resolve(); await release.promise; return binding;
  } } });
  try {
    const starting = f.start();
    const rejected = assert.rejects(starting, { code: 'TERMINAL_START_CANCELLED' });
    await entered.promise;
    const session = [...f.service.sessions.values()][0];
    assert.equal((await f.service.close({ sessionId: session.sessionId })).status, 'closed');
    release.resolve(); await rejected;
    assert.equal(session.status, 'closing');
    assert.equal(session.finished, false);
    assert.equal(session.browserBinding, binding);
    assert.ok(session.cleanupError);
    assert.equal(cleanupAttempts, 1);
    assert.equal(f.launches.length, 0);
    assert.doesNotMatch(JSON.stringify(await f.service.snapshot()), /fixture private binding directory/);
    allowCleanup = true;
    assert.equal((await f.service.close({ sessionId: session.sessionId })).status, 'closed');
    assert.equal(cleanupAttempts, 2);
    assert.equal(session.browserBinding, null);
  } finally { allowCleanup = true; release.resolve(); }
});

test('a successful late Claude preparation keeps failed runtime cleanup retryable after Close', async t => {
  const f = await fixture(t);
  const entered = deferred(), release = deferred();
  const originalWrite = fsPromises.writeFile, originalRemove = fsPromises.rm;
  let runtime, allowCleanup = false, cleanupAttempts = 0;
  t.mock.method(fsPromises, 'writeFile', async (filename, ...args) => {
    const result = await originalWrite(filename, ...args);
    if (typeof filename === 'string' && filename.startsWith(f.root + path.sep) && filename.endsWith(path.join('bin', 'claude'))) {
      runtime = path.dirname(path.dirname(filename));
      entered.resolve(); await release.promise;
    }
    return result;
  });
  t.mock.method(fsPromises, 'rm', async (filename, ...args) => {
    if (filename === runtime) {
      cleanupAttempts++;
      if (!allowCleanup) throw Object.assign(new Error('fixture private prepared runtime'), { code: 'EACCES' });
    }
    return originalRemove(filename, ...args);
  });
  syncBuiltinESMExports();
  try {
    const starting = f.start();
    const rejected = assert.rejects(starting, { code: 'TERMINAL_START_CANCELLED' });
    await entered.promise;
    const session = [...f.service.sessions.values()][0];
    assert.equal((await f.service.close({ sessionId: session.sessionId })).status, 'closed');
    release.resolve(); await rejected;
    assert.equal(session.status, 'closing');
    assert.equal(session.finished, false);
    assert.equal(typeof session.claudeLaunch?.cleanup, 'function');
    assert.ok(session.cleanupError);
    assert.equal(cleanupAttempts, 1);
    assert.equal(f.launches.length, 0);
    assert.equal((await stat(runtime)).isDirectory(), true);
    assert.doesNotMatch(JSON.stringify(await f.service.snapshot()), /fixture private prepared runtime/);
    allowCleanup = true;
    assert.equal((await f.service.close({ sessionId: session.sessionId })).status, 'closed');
    assert.equal(cleanupAttempts, 2);
    await assert.rejects(stat(runtime), { code: 'ENOENT' });
  } finally { allowCleanup = true; release.resolve(); t.mock.restoreAll(); syncBuiltinESMExports(); }
});

test('failed broker filesystem cleanup still closes the process and permits an explicit cleanup retry', async t => {
  const f = await fixture(t), session = await f.start();
  let attempts = 0;
  f.bindings[0].dispose = async () => { f.order.push('revoke'); if (++attempts === 1) throw Object.assign(new Error('private runtime removal failed'), { code: 'EACCES' }); };
  await assert.rejects(f.service.close({ sessionId: session.sessionId }), /private runtime removal failed/);
  assert(f.order.includes('process-close'), 'process cleanup must survive broker cleanup failure');
  await assert.rejects(stat(path.join(f.root, 'data/terminal/profiles/chosen/tmp', `claude-${session.sessionId}`)), { code: 'ENOENT' });
  const closed = await f.service.close({ sessionId: session.sessionId });
  assert.equal(closed.status, 'closed'); assert.equal(attempts, 2);
});

test('a system-routed link attributed to Claude keeps its pinned browser despite ordinary fallback settings', async () => {
  let called = 0;
  const router = new LinkRouter({ service: { snapshot: async () => { throw new Error('ordinary browser preference must not be read'); } }, applications: { snapshot: async () => ({ applications: [] }) },
    terminal: { sessionForProcess: () => ({ profileId: 'chosen', sessionId: 'term_x' }), boundBrowserLink: async () => { called++; throw new Error('chosen browser is unavailable'); } },
    ps: async () => ({ stdout: '200 1 claude' }), enabled: () => false, openDefault: async () => { throw new Error('host browser must never open'); } });
  assert.equal((await router.openFromProcess({ pid: 200, url: 'https://example.com' })).opened, 'environment');
  await router.settled(); assert.equal(called, 1);
});

test('a failed managed core revokes only its Claude sessions and keeps ordinary shells and other nodes running', async t => {
  const events = [];
  const f = await fixture(t, { onEvent: event => { events.push(event); } });
  f.service.resolveContext = async id => managedContext(f.context, id, id === 'other' ? 'route_b' : 'route_a');
  const failed = await f.start();
  const ordinary = await f.service.create({ id: 'chosen', directory: f.cwd, kind: 'shell', fresh: true });
  const other = await f.service.create({ id: 'other', directory: f.cwd, kind: 'claude-code', browserProfileId: 'other', fresh: true });
  await f.service.invalidateManagedProxy('unrelated');
  assert.equal(f.bindings[0].disposed, undefined);
  const invalidation = f.service.invalidateManagedProxy('route_a');
  assert.equal(f.bindings[0].disposed, true, 'authority is revoked before asynchronous process cleanup');
  assert.equal(f.bindings[1].disposed, undefined);
  assert.deepEqual((await invalidation).map(result => result.status), ['fulfilled']);
  const status = f.service.metadata(f.service.sessions.get(failed.sessionId));
  assert.equal(status.status, 'error'); assert.equal(status.errorCode, 'CLAUDE_NETWORK_ROUTE_LOST');
  assert.equal(status.network.available, false); assert.match(status.error, /代理内核已停止/);
  assert.equal(f.service.sessions.get(ordinary.sessionId).status, 'running');
  assert.equal(f.service.sessions.get(other.sessionId).status, 'running');
  assert.throws(() => f.service.boundBrowserLink(failed.sessionId, 'https://example.com'), { code: 'TERMINAL_NOT_RUNNING' });
  assert.equal((await f.service.boundBrowserLink(other.sessionId, 'https://example.com')).opened, 'environment');
  await new Promise(resolve => setImmediate(resolve));
  const notices = events.filter(event => event.sessionId === failed.sessionId && event.errorCode === 'CLAUDE_NETWORK_ROUTE_LOST');
  assert(notices.some(event => event.type === 'exit' && event.status === 'error'));
  assert(!JSON.stringify(notices).includes('private-route-secret'));
  assert.deepEqual(await f.service.invalidateManagedProxy('route_a'), [], 'repeated core exit is idempotent');
});

test('core exit during context resolution refuses an obsolete managed route before starting the CLI', async t => {
  const f = await fixture(t), resolving = deferred(), response = deferred();
  f.service.resolveContext = async () => { resolving.resolve(); return response.promise; };
  const creation = f.start();
  const refused = assert.rejects(creation, { code: 'CLAUDE_NETWORK_ROUTE_LOST' });
  await resolving.promise;
  await f.service.invalidateManagedProxy('route_a');
  response.resolve(managedContext(f.context));
  await refused;
  assert.equal(f.launches.length, 0); assert.equal(f.bindings.length, 0);
  const session = [...f.service.sessions.values()][0];
  assert.equal(session.status, 'error'); assert.equal(session.errorCode, 'CLAUDE_NETWORK_ROUTE_LOST');
});

test('core exit while browser binding is pending disposes the late binding and never starts a CLI', async t => {
  const f = await fixture(t), pending = deferred(), response = deferred();
  f.service.resolveContext = async () => managedContext(f.context);
  const createBinding = f.service.browserBroker.createSession;
  f.service.browserBroker.createSession = async args => { pending.resolve(); await response.promise; return createBinding(args); };
  const creation = f.start();
  const refused = assert.rejects(creation, { code: 'CLAUDE_NETWORK_ROUTE_LOST' });
  await pending.promise;
  await f.service.invalidateManagedProxy('route_a');
  response.resolve(); await refused;
  assert.equal(f.bindings[0].disposed, true); assert.equal(f.launches.length, 0);
  assert.equal([...f.service.sessions.values()][0].errorCode, 'CLAUDE_NETWORK_ROUTE_LOST');
});

test('core exit while native PTY creation is pending reclaims the late process and preserves the route failure', async t => {
  const f = await fixture(t), pending = deferred(), response = deferred();
  f.service.resolveContext = async () => managedContext(f.context);
  const createPty = f.service.ptyFactory;
  f.service.ptyFactory = async (...args) => { pending.resolve(); await response.promise; return createPty(...args); };
  const creation = f.start();
  const refused = assert.rejects(creation, { code: 'CLAUDE_NETWORK_ROUTE_LOST' });
  await pending.promise;
  await f.service.invalidateManagedProxy('route_a');
  assert.equal(f.bindings[0].disposed, true);
  response.resolve(); await refused;
  assert.equal(f.launches.length, 1); assert(f.order.includes('process-close'));
  const session = [...f.service.sessions.values()][0];
  assert.equal(session.status, 'error'); assert.equal(session.pty, null);
  assert.equal(session.errorCode, 'CLAUDE_NETWORK_ROUTE_LOST');
});

test('core exit during process identity capture cannot return a running Claude session', async t => {
  const f = await fixture(t), pending = deferred(), response = deferred();
  f.service.resolveContext = async () => managedContext(f.context);
  f.service.processControl.capture = async pid => { pending.resolve(); await response.promise; return { pid }; };
  const creation = f.start();
  const refused = assert.rejects(creation, { code: 'CLAUDE_NETWORK_ROUTE_LOST' });
  await pending.promise;
  const invalidation = f.service.invalidateManagedProxy('route_a');
  assert.equal(f.bindings[0].disposed, true);
  response.resolve(); await Promise.all([invalidation, refused]);
  const session = [...f.service.sessions.values()][0];
  assert.equal(session.status, 'error'); assert.equal(session.pty, null);
  assert(f.order.includes('process-close'));
  const fresh = await f.start();
  assert.equal(fresh.status, 'running', 'an explicit new session can resolve a recovered route');
  assert.equal(fresh.errorCode, undefined);
});

test('process cleanup failure keeps the original network failure and supports an explicit cleanup retry', async t => {
  const f = await fixture(t);
  f.service.resolveContext = async () => managedContext(f.context);
  const running = await f.start(); let attempts = 0;
  f.service.processControl.close = async () => {
    f.order.push('process-close');
    if (++attempts === 1) throw new Error('fixture cleanup contains private-route-secret');
    return { ok: true };
  };
  const results = await f.service.invalidateManagedProxy('route_a');
  assert.equal(results[0].status, 'rejected'); assert.equal(f.bindings[0].disposed, true);
  const pending = f.service.metadata(f.service.sessions.get(running.sessionId));
  assert.equal(pending.status, 'closing'); assert.equal(pending.errorCode, 'CLAUDE_NETWORK_ROUTE_LOST');
  assert.match(pending.error, /代理内核已停止/); assert.match(pending.cleanupError, /清理未完成/);
  assert(!JSON.stringify(await f.service.snapshot()).includes('private-route-secret'));
  const ended = await f.service.close({ sessionId: running.sessionId });
  assert.equal(ended.status, 'error'); assert.equal(ended.errorCode, 'CLAUDE_NETWORK_ROUTE_LOST');
  assert.equal(ended.cleanupError, undefined); assert.equal(attempts, 2);
});
