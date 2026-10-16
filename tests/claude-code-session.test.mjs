import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fsPromises from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { chmod, copyFile, link, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { compileClaudeFixture } from './claude-native-fixture.mjs';
import { ensureClaudeInstallation, resolveClaudeInstallation } from '../electron/claude-code-installation.mjs';
import { findClaudeExecutable, prepareClaudeSession } from '../electron/claude-code-session.mjs';

const execute = promisify(execFile);

async function fixture(t) {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "envara claude's session-"));
  const root = await realpath(temporary);
  t.after(() => rm(root, { recursive: true, force: true }));
  const bin = path.join(root, '.local', 'bin');
  const versions = path.join(root, '.local', 'share', 'claude', 'versions');
  const temp = path.join(root, 'runtime');
  const home = path.join(root, 'home');
  const claude = path.join(root, 'claude');
  await mkdir(bin, { recursive: true }); await mkdir(versions, { recursive: true }); await mkdir(temp, { mode: 0o700 });
  await mkdir(home, { mode: 0o700 }); await mkdir(claude, { mode: 0o700 });
  const hostExecutable = path.join(versions, '2.1.296');
  await copyFile('/usr/bin/true', hostExecutable); await chmod(hostExecutable, 0o700);
  await symlink(hostExecutable, path.join(bin, 'claude'));
  const installation = await ensureClaudeInstallation({ home, findHostExecutable: async () => hostExecutable });
  const executable = await resolveClaudeInstallation(installation);
  const environment = { HOME: home, USERPROFILE: home, CLAUDE_CONFIG_DIR: claude, TMPDIR: temp, TZ: 'Asia/Manila', LANG: 'en_PH.UTF-8', LC_ALL: 'en_PH.UTF-8',
    PATH: '/owned/bin:/usr/bin:/bin', BROWSER: '/owned/bin/browser', ENVARA_LINK_SOCKET: '/owned/links.sock',
    ENVARA_BROWSER_SOCKET: '/owned/browser.sock', ENVARA_LINK_TOKEN: 'synthetic-link-secret', ENVARA_BROWSER_TOKEN: 'synthetic-browser-secret',
    HTTPS_PROXY: 'http://user:synthetic-proxy-secret@127.0.0.1:1234', HTTP_PROXY: 'http://user:synthetic-proxy-secret@127.0.0.1:1234',
    ALL_PROXY: 'http://user:synthetic-proxy-secret@127.0.0.1:1234', NO_PROXY: 'localhost,127.0.0.1,::1', NODE_USE_ENV_PROXY: '1' };
  const request = { sessionId: 'term_one', directories: { temp, home, claude }, installation, environment, privacy: { mode: 'standard' }, mcpServer: { command: process.execPath, args: ['/owned/envara-browser-mcp.mjs'] } };
  return { root, bin, temp, home, claude, executable, hostExecutable, installation, request };
}

const settingsFile = launch => launch.args[launch.args.indexOf('--settings') + 1];
async function saveSettings(f, settings) { await writeFile(path.join(f.claude, 'settings.json'), JSON.stringify(settings), { mode: 0o600 }); }

test('finds the native local install through its symlink without executing it', async t => {
  const f = await fixture(t);
  assert.equal(await findClaudeExecutable({ hostHome: f.root }), f.hostExecutable);
  assert.notEqual((await lstat(f.executable)).ino, (await lstat(f.hostExecutable)).ino);
});

test('ignores cwd and environment PATH and rejects an untrusted search directory', async t => {
  const f = await fixture(t);
  await assert.rejects(findClaudeExecutable({ hostHome: f.root, additionalExecutablePaths: ['.'] }), { code: 'CLAUDE_CODE_INVALID_CONFIGURATION' });
  await assert.rejects(findClaudeExecutable({ hostHome: '../home' }), { code: 'CLAUDE_CODE_INVALID_CONFIGURATION' });
  // win32 searches only the documented native executable, not a shell wrapper.
  await writeFile(path.join(f.bin, 'claude.cmd'), 'malicious\n', { mode: 0o700 });
  await assert.rejects(findClaudeExecutable({ hostHome: f.root, platform: 'win32' }), { code: 'CLAUDE_CODE_NOT_INSTALLED' });
});

test('a program writable by other users is not eligible', async t => {
  const f = await fixture(t);
  await chmod(f.executable, 0o777);
  await assert.rejects(prepareClaudeSession(f.request), { code: 'CLAUDE_CODE_INSTALLATION_INVALID' });
});

test('creates private session config with only the selected MCP and cleans only its runtime', async t => {
  const f = await fixture(t);
  const userSettings = path.join(f.claude, 'settings.json');
  await writeFile(userSettings, '{"theme":"dark","permissions":{"defaultMode":"default"}}', { mode: 0o600 });
  const launch = await prepareClaudeSession(f.request);
  const mcpFile = launch.args[launch.args.indexOf('--mcp-config') + 1];
  const settingsFile = launch.args[launch.args.indexOf('--settings') + 1];
  const runtime = path.dirname(mcpFile);
  assert.equal(launch.executable, f.executable);
  assert.deepEqual(launch.args, ['--no-chrome', '--strict-mcp-config', '--mcp-config', mcpFile, '--setting-sources', 'user', '--settings', settingsFile]);
  assert.deepEqual(JSON.parse(await readFile(mcpFile)), { mcpServers: { envara_browser: { type: 'stdio', ...f.request.mcpServer } } });
  const settings = JSON.parse(await readFile(settingsFile));
  assert.deepEqual(settings.sandbox, { enabled: false });
  assert.equal(settings.forceLoginMethod, 'claudeai');
  assert.equal(settings.permissions, undefined);
  assert.equal(settings.env.CLAUDE_CONFIG_DIR, f.claude);
  assert.equal(settings.env.TZ, 'Asia/Manila');
  assert.equal(settings.env.ANTHROPIC_API_KEY, '');
  assert.equal(launch.wrapperPath, path.join(runtime, 'bin', 'claude'));
  assert.equal(launch.binDirectory, path.dirname(launch.wrapperPath));
  assert.equal(launch.environment.PATH, `${launch.binDirectory}${path.delimiter}${path.dirname(f.installation.entryPath)}${path.delimiter}${f.request.environment.PATH}`);
  assert.equal(settings.env.PATH, launch.environment.PATH);
  assert.equal((await lstat(runtime)).mode & 0o777, 0o700);
  for (const file of [mcpFile, settingsFile]) assert.equal((await lstat(file)).mode & 0o777, 0o600);
  for (const file of [launch.wrapperPath, launch.binDirectory]) assert.equal((await lstat(file)).mode & 0o777, 0o700);
  const second = await prepareClaudeSession({ ...f.request, sessionId: 'term_two' });
  await launch.cleanup(); await launch.cleanup();
  await assert.rejects(lstat(runtime), { code: 'ENOENT' });
  assert.ok((await lstat(path.dirname(second.args[3]))).isDirectory());
  assert.equal(await readFile(userSettings, 'utf8'), '{"theme":"dark","permissions":{"defaultMode":"default"}}');
  await second.cleanup();
});

test('rejects path traversal, credential fields and malformed launch values before creating files', async t => {
  const f = await fixture(t);
  for (const override of [
    { sessionId: '../outside' },
    { mcpServer: { command: 'node', args: [] } },
    { mcpServer: { ...f.request.mcpServer, env: { SECRET: 'private' } } },
    { mcpServer: { ...f.request.mcpServer, args: ['bad\nargument'] } },
  ]) await assert.rejects(prepareClaudeSession({ ...f.request, ...override }), { code: 'CLAUDE_CODE_INVALID_CONFIGURATION' });
});

test('does not adopt a linked runtime or overwrite an existing session', async t => {
  const f = await fixture(t);
  const linkedTemp = path.join(f.root, 'linked-runtime');
  await symlink(f.temp, linkedTemp);
  await assert.rejects(prepareClaudeSession({ ...f.request, directories: { ...f.request.directories, temp: linkedTemp } }), { code: 'CLAUDE_CODE_UNSAFE_PATH' });
  const runtime = path.join(f.temp, 'claude-term_one');
  await symlink(f.root, runtime);
  await assert.rejects(prepareClaudeSession(f.request), { code: 'CLAUDE_CODE_SESSION_EXISTS' });
  assert.ok((await lstat(runtime)).isSymbolicLink());
});

test('cleanup refuses a replaced runtime and preserves the replacement target', async t => {
  const f = await fixture(t);
  const launch = await prepareClaudeSession(f.request);
  const runtime = path.dirname(launch.args[3]);
  const saved = runtime + '-saved';
  await rename(runtime, saved);
  const elsewhere = path.join(f.root, 'elsewhere');
  await mkdir(elsewhere); await writeFile(path.join(elsewhere, 'keep'), 'keep');
  await symlink(elsewhere, runtime);
  await assert.rejects(launch.cleanup(), { code: 'CLAUDE_CODE_UNSAFE_PATH' });
  assert.equal(await readFile(path.join(elsewhere, 'keep'), 'utf8'), 'keep');
});

test('a preparation failure retains its first error and private retryable cleanup', async t => {
  const f = await fixture(t), runtime = path.join(f.temp, 'claude-term_one');
  const primary = Object.assign(new Error('fixture disk write failed'), { code: 'ENOSPC' });
  const originalWrite = fsPromises.writeFile, originalRemove = fsPromises.rm;
  let refuseCleanup = true, observed;
  t.mock.method(fsPromises, 'writeFile', async (filename, ...args) => {
    if (filename === path.join(runtime, 'mcp.json')) throw primary;
    return originalWrite(filename, ...args);
  });
  t.mock.method(fsPromises, 'rm', async (filename, ...args) => {
    if (filename === runtime && refuseCleanup) throw Object.assign(new Error('fixture private cleanup path'), { code: 'EACCES' });
    return originalRemove(filename, ...args);
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(prepareClaudeSession(f.request), error => {
      observed = error;
      assert.equal(error, primary);
      assert.equal(error.code, 'ENOSPC');
      assert.equal(error.message, 'fixture disk write failed');
      assert.equal(error.cleanupError, 'Claude 会话临时文件清理未完成，请重试关闭会话。');
      assert.equal(typeof error.claudeCleanup, 'function');
      assert.equal(Object.getOwnPropertyDescriptor(error, 'claudeCleanup').enumerable, false);
      assert.equal(JSON.stringify(error).includes('fixture private cleanup path'), false);
      return true;
    });
    assert.ok((await lstat(runtime)).isDirectory());
    await assert.rejects(observed.claudeCleanup(), { code: 'EACCES' });
    refuseCleanup = false;
    await observed.claudeCleanup(); await observed.claudeCleanup();
    await assert.rejects(lstat(runtime), { code: 'ENOENT' });
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});

test('session policy scopes official opt-outs to each privacy mode without changing caller environment', async t => {
  const f = await fixture(t);
  const original = { ...f.request.environment };
  await saveSettings(f, { env: { DISABLE_AUTOUPDATER: '0', DISABLE_TELEMETRY: '1', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1' } });
  for (const mode of ['off', 'standard', 'strict']) {
    const launch = await prepareClaudeSession({ ...f.request, privacy: { mode } });
    const settings = JSON.parse(await readFile(settingsFile(launch)));
    for (const key of ['DO_NOT_TRACK', 'DISABLE_TELEMETRY', 'DISABLE_ERROR_REPORTING']) {
      assert.equal(launch.environment[key], mode === 'off' ? '' : '1');
      assert.equal(settings.env[key], launch.environment[key]);
    }
    assert.equal(launch.environment.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC, mode === 'strict' ? '1' : '');
    assert.equal(settings.env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC, launch.environment.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC);
    assert.equal(launch.environment.DISABLE_AUTOUPDATER, '1');
    assert.equal(settings.env.DISABLE_AUTOUPDATER, '1');
    assert.equal(launch.environment.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB, undefined);
    assert.equal(launch.environment.ANTHROPIC_API_KEY, undefined);
    assert.equal(launch.environment.CLAUDE_CODE_USE_BEDROCK, undefined);
    await launch.cleanup();
  }
  assert.deepEqual(f.request.environment, original);
});

test('private settings pin context without persisting proxy credentials or MCP/link tokens', async t => {
  const f = await fixture(t);
  await saveSettings(f, { env: { HTTPS_PROXY: f.request.environment.HTTPS_PROXY, ANTHROPIC_MODEL: 'sonnet' }, model: 'sonnet' });
  const launch = await prepareClaudeSession(f.request);
  const serialized = await readFile(settingsFile(launch), 'utf8');
  for (const secret of ['synthetic-proxy-secret', 'synthetic-browser-secret', 'synthetic-link-secret']) assert.ok(!serialized.includes(secret));
  const pins = JSON.parse(serialized).env;
  for (const key of ['HOME', 'USERPROFILE', 'CLAUDE_CONFIG_DIR', 'TMPDIR', 'TZ', 'LANG', 'LC_ALL', 'BROWSER', 'ENVARA_LINK_SOCKET', 'ENVARA_BROWSER_SOCKET', 'NODE_USE_ENV_PROXY', 'NO_PROXY']) assert.equal(pins[key], f.request.environment[key]);
  assert.equal(pins.PATH, launch.environment.PATH);
  for (const key of ['HTTPS_PROXY', 'ENVARA_LINK_TOKEN', 'ENVARA_BROWSER_TOKEN']) {
    assert.equal(pins[key], undefined);
    assert.equal(launch.environment[key], f.request.environment[key]);
  }
  assert.equal(pins.ANTHROPIC_MODEL, undefined);
  assert.ok(!launch.args.includes('--bare'));
  assert.ok(!launch.args.some(value => value.includes('skip-permissions')));
});

test('refuses API keys, helpers, gateway and external tokens before launch without exposing or rewriting them', async t => {
  const f = await fixture(t);
  const secret = 'synthetic-do-not-print';
  const cases = [
    { apiKeyHelper: `echo ${secret}` }, { awsAuthRefresh: secret }, { awsCredentialExport: secret }, { gcpAuthRefresh: secret },
    { forceLoginMethod: 'console' }, { forceLoginMethod: 'gateway' }, { forceLoginGatewayUrl: `https://${secret}.invalid` },
    ...['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL', 'ANTHROPIC_CUSTOM_HEADERS', 'ANTHROPIC_FEDERATION_RULE_ID',
      'CLAUDE_CODE_USE_BEDROCK', 'CLAUDE_CODE_USE_VERTEX', 'CLAUDE_CODE_USE_FOUNDRY', 'CLAUDE_CODE_USE_MANTLE', 'CLAUDE_CODE_USE_ANTHROPIC_AWS',
      'CLAUDE_CODE_OAUTH_TOKEN', 'CLAUDE_CODE_OAUTH_REFRESH_TOKEN', 'AWS_BEARER_TOKEN_BEDROCK'].map(key => ({ env: { [key]: secret } })),
  ];
  for (const settings of cases) {
    await saveSettings(f, settings);
    await assert.rejects(prepareClaudeSession(f.request), error => error.code === 'CLAUDE_CODE_ACCOUNT_CONFIGURATION_CONFLICT' && !error.message.includes(secret));
    assert.equal(await readFile(path.join(f.claude, 'settings.json'), 'utf8'), JSON.stringify(settings));
    assert.deepEqual(await readdir(f.temp), []);
  }
  await rm(path.join(f.claude, 'settings.json'));
  await assert.rejects(prepareClaudeSession({ ...f.request, environment: { ...f.request.environment, ANTHROPIC_API_KEY: secret } }), { code: 'CLAUDE_CODE_ACCOUNT_CONFIGURATION_CONFLICT' });
});

test('rejects saved network, tool directory, link and subprocess-scrub overrides', async t => {
  const f = await fixture(t);
  for (const key of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'NO_PROXY', 'no_proxy', 'TZ', 'HOME',
    'CLAUDE_CONFIG_DIR', 'LANG', 'LC_ALL', 'PATH', 'BROWSER', 'ENVARA_LINK_TOKEN', 'ENVARA_BROWSER_TOKEN', 'ENVARA_BROWSER_SOCKET', 'ENVARA_LINK_SOCKET', 'CLAUDE_CODE_SUBPROCESS_ENV_SCRUB', 'NODE_OPTIONS']) {
    await saveSettings(f, { env: { [key]: 'synthetic-conflicting-value' } });
    await assert.rejects(prepareClaudeSession(f.request), { code: 'CLAUDE_CODE_SESSION_POLICY_CONFLICT' });
  }
  await saveSettings(f, { proxyAuthHelper: 'echo synthetic-token' });
  await assert.rejects(prepareClaudeSession(f.request), { code: 'CLAUDE_CODE_SESSION_POLICY_CONFLICT' });
  assert.deepEqual(await readdir(f.temp), []);
});

test('explicitly disabled provider switches do not block the account session', async t => {
  const f = await fixture(t);
  await saveSettings(f, { forceLoginMethod: 'claudeai', env: { CLAUDE_CODE_USE_BEDROCK: '0', CLAUDE_CODE_USE_VERTEX: 'false', CLAUDE_CODE_USE_FOUNDRY: 'OFF', ANTHROPIC_API_KEY: '' } });
  const launch = await prepareClaudeSession(f.request);
  const settings = JSON.parse(await readFile(settingsFile(launch)));
  assert.equal(settings.env.CLAUDE_CODE_USE_BEDROCK, '');
  assert.equal(settings.env.CLAUDE_CODE_USE_VERTEX, '');
});

test('malformed, oversized or linked settings are refused without reading auth state', async t => {
  const f = await fixture(t);
  const filename = path.join(f.claude, 'settings.json');
  for (const source of ['{bad-synthetic-private-text', 'null', '[]', '{"env":[]}', '{"env":{"A":1}}', '{"env":{"BAD-NAME":"x"}}', ' '.repeat(1024 * 1024 + 1)]) {
    await writeFile(filename, source, { mode: 0o600 });
    await assert.rejects(prepareClaudeSession(f.request), error => error.code === 'CLAUDE_CODE_SETTINGS_INVALID' && !error.message.includes('synthetic-private-text'));
  }
  await rm(filename);
  const elsewhere = path.join(f.root, 'external-settings');
  await writeFile(elsewhere, '{}'); await symlink(elsewhere, filename);
  await assert.rejects(prepareClaudeSession(f.request), { code: 'CLAUDE_CODE_SETTINGS_INVALID' });
  await rm(filename); await symlink(path.join(f.root, 'missing-settings'), filename);
  await assert.rejects(prepareClaudeSession(f.request), { code: 'CLAUDE_CODE_SETTINGS_INVALID' });
  await rm(filename);
  // Unreadable credential storage is intentionally irrelevant to preparation.
  await mkdir(path.join(f.claude, '.credentials.json'));
  await writeFile(path.join(f.home, '.claude.json'), 'not-json-private-login-data');
  const launch = await prepareClaudeSession(f.request);
  assert.ok(launch.executable);
  assert.equal(await readFile(path.join(f.home, '.claude.json'), 'utf8'), 'not-json-private-login-data');
});

test('linked Claude config directories and mismatched launch roots cannot escape the environment', async t => {
  const f = await fixture(t);
  const linked = path.join(f.root, 'linked-claude');
  await symlink(f.claude, linked);
  await assert.rejects(prepareClaudeSession({ ...f.request, directories: { ...f.request.directories, claude: linked }, environment: { ...f.request.environment, CLAUDE_CONFIG_DIR: linked } }), { code: 'CLAUDE_CODE_UNSAFE_PATH' });
  await assert.rejects(prepareClaudeSession({ ...f.request, environment: { ...f.request.environment, HOME: f.root } }), { code: 'CLAUDE_CODE_SESSION_POLICY_CONFLICT' });
  await assert.rejects(prepareClaudeSession({ ...f.request, privacy: { mode: 'unknown' } }), { code: 'CLAUDE_CODE_INVALID_CONFIGURATION' });
});

test('manual wrapper preserves argv quoting and explicit permissions without enabling bypass itself', async t => {
  const f = await fixture(t);
  const special = path.join(f.root, "native and runtime's directory");
  await mkdir(special, { mode: 0o700 });
  await compileClaudeFixture(f.executable);
  const launch = await prepareClaudeSession({ ...f.request, directories: { ...f.request.directories, temp: special }, environment: { ...f.request.environment, TMPDIR: special } });
  for (const userArgs of [[], ['--permission-mode', 'bypassPermissions'], ['--permission-mode=bypassPermissions'],
    ['--model', 'sonnet', '--continue'], ['--resume', "conversation with space's quote"], ['-p', "explain `literal` and $(literal) 'quoted' \"double\""],
    ['--', '--settings=literal prompt text']]) {
    const { stdout } = await execute(launch.wrapperPath, userArgs, { env: launch.environment, timeout: 5000 });
    const observed = JSON.parse(stdout);
    assert.deepEqual(observed.args, [...launch.args, ...userArgs]);
    assert.equal(observed.home, f.home); assert.equal(observed.config, f.claude); assert.equal(observed.path, launch.environment.PATH);
  }
  assert.ok(!launch.args.includes('--permission-mode'));
  assert.ok(!launch.args.some(value => value.includes('skip-permissions')));
  const { stdout } = await execute('/bin/sh', ['-c', 'command -v claude'], { env: launch.environment });
  assert.equal(stdout.trim(), launch.wrapperPath);
});

test('manual wrapper refuses binding overrides in exact and equals forms before the native CLI runs', async t => {
  const f = await fixture(t), launch = await prepareClaudeSession(f.request);
  for (const flag of ['--mcp-config', '--strict-mcp-config', '--no-strict-mcp-config', '--settings', '--setting-sources', '--chrome', '--no-chrome', '--bare', '--safe-mode', '--restricted']) {
    for (const args of [[flag, 'untrusted'], [`${flag}=untrusted`]]) {
      await assert.rejects(execute(launch.wrapperPath, args, { env: launch.environment, timeout: 5000 }), error => error.code === 64 && error.stdout === '' && error.stderr.includes('此会话的浏览器和隔离配置已固定'));
    }
  }
  const script = await readFile(launch.wrapperPath, 'utf8');
  for (const secret of ['synthetic-proxy-secret', 'synthetic-browser-secret', 'synthetic-link-secret']) assert.ok(!script.includes(secret));
});

test('one wrapper uses the upgraded native entry immediately and keeps host, other environments and login data intact', async t => {
  const f = await fixture(t);
  await compileClaudeFixture(f.executable, '2.1.296');
  const next = path.join(f.installation.versionsDirectory, '2.1.300');
  await compileClaudeFixture(next, '2.1.300');
  const otherHome = path.join(f.root, 'other-home'); await mkdir(otherHome, { mode: 0o700 });
  const other = await ensureClaudeInstallation({ home: otherHome, findHostExecutable: async () => f.executable });
  const otherBefore = await resolveClaudeInstallation(other), hostBefore = await readFile(f.hostExecutable);
  const login = path.join(f.claude, '.credentials.json'), marker = 'synthetic-login-only';
  await writeFile(login, marker, { mode: 0o600 });
  const launch = await prepareClaudeSession(f.request);
  const invoke = async (args, environment = {}) => JSON.parse((await execute(launch.wrapperPath, args, { env: { ...launch.environment, ...environment }, timeout: 5000 })).stdout);
  assert.equal((await invoke(['--version'])).version, '2.1.296');
  const update = await invoke(['update'], { ENVARA_TEST_NEXT_VERSION: next });
  assert.deepEqual(update.args, [...launch.args, 'update']);
  const updated = await invoke(['--version']);
  assert.equal(updated.version, '2.1.300');
  assert.deepEqual(updated.args, [...launch.args, '--version']);
  assert.equal(updated.home, launch.environment.HOME); assert.equal(updated.config, launch.environment.CLAUDE_CONFIG_DIR);
  assert.equal(await resolveClaudeInstallation(other), otherBefore);
  assert.deepEqual(await readFile(f.hostExecutable), hostBefore);
  assert.equal(await readFile(login, 'utf8'), marker);
  assert.ok((await lstat(f.executable)).isFile(), 'upgrading does not delete the old binary in an active session');
  await launch.cleanup();
  const installation = await ensureClaudeInstallation({ home: f.home, findHostExecutable: async () => { throw new Error('host must not be inspected'); } });
  const reopened = await prepareClaudeSession({ ...f.request, installation });
  const duplicate = await prepareClaudeSession({ ...f.request, installation, sessionId: 'duplicate' });
  for (const prepared of [reopened, duplicate]) {
    assert.equal(prepared.executable, next);
    assert.equal(JSON.parse((await execute(prepared.wrapperPath, ['--version'], { env: prepared.environment })).stdout).version, '2.1.300');
    await prepared.cleanup();
  }
  assert.equal(await readFile(login, 'utf8'), marker);
});

test('broken or escaping installed entries refuse both a new session and an existing wrapper without host fallback', async t => {
  const f = await fixture(t), launch = await prepareClaudeSession(f.request);
  let lookups = 0;
  for (const target of [path.join(f.installation.versionsDirectory, '9.9.9'), f.hostExecutable]) {
    await rm(f.installation.entryPath); await symlink(target, f.installation.entryPath);
    await assert.rejects(ensureClaudeInstallation({ home: f.home, findHostExecutable: async () => { lookups++; return f.hostExecutable; } }), { code: 'CLAUDE_CODE_INSTALLATION_INVALID' });
    await assert.rejects(execute(launch.wrapperPath, ['--version'], { env: launch.environment }), error => error.code === 126 && error.stdout === '' && error.stderr.includes('CLAUDE_CODE_INSTALLATION_INVALID'));
  }
  assert.equal(lookups, 0);
});

test('native bootstrap is concurrent-safe, copies once per environment and rejects scripts or nonversion launchers', async t => {
  const f = await fixture(t);
  const home = path.join(f.root, 'new-home'); await mkdir(home, { mode: 0o700 });
  let count = 0;
  const requests = await Promise.all(Array.from({ length: 12 }, () => ensureClaudeInstallation({ home, findHostExecutable: async () => { count++; return f.hostExecutable; } })));
  assert.equal(count, 1);
  assert.ok(requests.every(value => value.entryPath === requests[0].entryPath));
  const own = await lstat(await resolveClaudeInstallation(requests[0])), host = await lstat(f.hostExecutable);
  assert.notEqual(own.ino, host.ino); assert.equal(own.nlink, 1);
  assert.deepEqual(await readdir(requests[0].versionsDirectory), ['2.1.296']);
  const scriptHome = path.join(f.root, 'script-home'); await mkdir(scriptHome, { mode: 0o700 });
  const fake = path.join(f.root, '3.0.0'); await writeFile(fake, '#!/bin/sh\nexit 99\n', { mode: 0o700 });
  await assert.rejects(ensureClaudeInstallation({ home: scriptHome, findHostExecutable: async () => fake }), { code: 'CLAUDE_CODE_NATIVE_INSTALL_REQUIRED' });
  await assert.rejects(ensureClaudeInstallation({ home: scriptHome, findHostExecutable: async () => '/usr/bin/true' }), { code: 'CLAUDE_CODE_NATIVE_INSTALL_REQUIRED' });
});

test('initialization recovers only exact interrupted bootstrap publication links', async t => {
  const f = await fixture(t);
  const staging = path.join(f.installation.versionsDirectory, '.envara-bootstrap-00000000-1111-2222-3333-444444444444');
  await link(f.executable, staging);
  await assert.rejects(resolveClaudeInstallation(f.installation), { code: 'CLAUDE_CODE_INSTALLATION_INVALID' });
  await ensureClaudeInstallation({ home: f.home });
  await assert.rejects(lstat(staging), { code: 'ENOENT' });
  assert.equal((await lstat(f.executable)).nlink, 1);
  // A hard link outside the precise bootstrap namespace cannot be repaired.
  const unknown = path.join(f.root, 'unknown-hard-link'); await link(f.executable, unknown);
  await assert.rejects(ensureClaudeInstallation({ home: f.home }), { code: 'CLAUDE_CODE_INSTALLATION_INVALID' });
  assert.ok((await lstat(unknown)).isFile());
});

test('linked HOME ancestors, versions paths, writable roots and inconsistent XDG data are refused', async t => {
  const f = await fixture(t);
  const linked = path.join(f.root, 'linked'); await symlink(f.home, linked);
  await assert.rejects(ensureClaudeInstallation({ home: linked }), { code: 'CLAUDE_CODE_INSTALLATION_INVALID' });
  await assert.rejects(ensureClaudeInstallation({ home: path.join(linked, 'inner') }), { code: 'ENOENT' });
  await assert.rejects(prepareClaudeSession({ ...f.request, environment: { ...f.request.environment, XDG_DATA_HOME: f.root } }), { code: 'CLAUDE_CODE_SESSION_POLICY_CONFLICT' });
  const original = f.installation.versionsDirectory + '-moved';
  await rename(f.installation.versionsDirectory, original); await symlink(original, f.installation.versionsDirectory);
  await assert.rejects(ensureClaudeInstallation({ home: f.home }), { code: 'CLAUDE_CODE_INSTALLATION_INVALID' });
  await rm(f.installation.versionsDirectory); await rename(original, f.installation.versionsDirectory);
  await chmod(f.home, 0o777);
  await assert.rejects(ensureClaudeInstallation({ home: f.home }), { code: 'CLAUDE_CODE_INSTALLATION_INVALID' });
});
