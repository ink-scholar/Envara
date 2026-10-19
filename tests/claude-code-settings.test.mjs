import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CLAUDE_ACCOUNT_ENV, CLAUDE_CONTEXT_ENV, preflightClaudeSettings, readClaudeSettings,
  resolveClaudeSettingsFiles, validateClaudeEnvironment, validateClaudeSettings,
} from '../electron/claude-code-settings.mjs';

const execute = promisify(execFile);
const helper = fileURLToPath(new URL('../electron/claude-code-settings.mjs', import.meta.url));
const ACCOUNT_CONFLICT = 'CLAUDE_CODE_ACCOUNT_CONFIGURATION_CONFLICT';
const POLICY_CONFLICT = 'CLAUDE_CODE_SESSION_POLICY_CONFLICT';
const INVALID_SETTINGS = 'CLAUDE_CODE_SETTINGS_INVALID';
const secret = 'synthetic-settings-do-not-print';

async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "envara settings' fixture-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const home = path.join(root, 'home'), configDir = path.join(root, 'named-account');
  const cwd = path.join(root, 'work'), temp = path.join(root, 'temp');
  await Promise.all([home, configDir, cwd, temp, path.join(configDir, 'anthropic')]
    .map(directory => mkdir(directory, { recursive: true, mode: 0o700 })));
  const route = 'http://fixture:synthetic-route-secret@127.0.0.1:43219';
  const environment = {
    HOME: home, USERPROFILE: home, CLAUDE_CONFIG_DIR: configDir,
    ANTHROPIC_CONFIG_DIR: path.join(configDir, 'anthropic'),
    XDG_CONFIG_HOME: path.join(home, '.config'), XDG_CACHE_HOME: path.join(home, '.cache'),
    XDG_DATA_HOME: path.join(home, '.local', 'share'), XDG_STATE_HOME: path.join(home, '.local', 'state'),
    TMPDIR: temp, TMP: temp, TEMP: temp, TZ: 'Asia/Manila', LANG: 'C', LC_ALL: 'C',
    PATH: process.platform === 'win32' ? process.env.PATH : '/usr/bin:/bin:/usr/sbin:/sbin',
    ...(process.platform === 'win32' ? { SystemRoot: process.env.SystemRoot ?? 'C:\\Windows' } : {}),
    BROWSER: path.join(root, 'owned-browser'), NODE_USE_ENV_PROXY: '1', NO_PROXY: 'localhost,127.0.0.1,::1',
    HTTP_PROXY: route, HTTPS_PROXY: route, ALL_PROXY: route,
    ENVARA_BROWSER_SOCKET: path.join(root, 'browser.sock'), ENVARA_BROWSER_TOKEN: 'synthetic-browser-token',
    ENVARA_LINK_SOCKET: path.join(root, 'browser.sock'), ENVARA_LINK_TOKEN: 'synthetic-link-token',
    SSH_AUTH_SOCK: path.join(root, 'agent.sock'), ENVARA_SSH_CONFIG: path.join(root, 'ssh-config'),
    ENVARA_SSH_TARGETS: path.join(root, 'targets.json'), ENVARA_SSH_CONNECTIONS: path.join(root, 'connections.json'),
    ENVARA_SSH_PROXY_URL: route,
  };
  const request = { configDir, home, cwd, environment, platform: process.platform };
  return { root, home, configDir, cwd, temp, environment, request };
}

async function save(filename, value) {
  await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
  const bytes = typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`;
  await writeFile(filename, bytes, { mode: 0o600 });
  return Buffer.from(bytes);
}

function refused(code) {
  return error => error?.code === code && !error.message.includes(secret);
}

function safeCliFailure(f, code) {
  return error => {
    assert.equal(error.code, 64);
    assert.equal(error.stdout, '');
    assert.match(error.stderr, new RegExp(`^envara: ${code}: [^\\r\\n]+\\n$`));
    for (const value of [secret, 'synthetic-route-secret', 'synthetic-browser-token', 'synthetic-link-token',
      f.root, f.home, f.configDir]) assert.ok(!error.stderr.includes(value), 'CLI errors must not contain configuration or credentials');
    return true;
  };
}

test('missing settings are optional and valid user preferences are read without rewriting bytes', async t => {
  const f = await fixture(t), filename = path.join(f.configDir, 'settings.json');
  assert.deepEqual(await readClaudeSettings(filename), {});
  const settings = {
    model: 'sonnet', permissions: { defaultMode: 'default', allow: ['Read'], deny: ['Bash(rm:*)'] },
    enabledPlugins: { 'fixture@local': true },
    mcpServers: { market_fixture: { type: 'stdio', command: 'fixture-market', args: ['--read-only'] } },
    env: { MARKET_FIXTURE_MODE: 'read-only', ANTHROPIC_MODEL: 'sonnet' },
  };
  const before = await save(filename, settings);
  assert.deepEqual(await readClaudeSettings(filename), settings);
  assert.doesNotThrow(() => validateClaudeSettings(settings, f.environment));
  assert.deepEqual(await readFile(filename), before);
  assert.deepEqual(settings, JSON.parse(before));
});

test('matching context, proxy and browser settings remain usable and untouched', async t => {
  const f = await fixture(t), filename = path.join(f.configDir, 'settings.json');
  const settings = { forceLoginMethod: 'claudeai', env: {
    HOME: f.home, CLAUDE_CONFIG_DIR: f.configDir, HTTPS_PROXY: f.environment.HTTPS_PROXY,
    BROWSER: f.environment.BROWSER, ENVARA_BROWSER_SOCKET: f.environment.ENVARA_BROWSER_SOCKET,
    ENVARA_BROWSER_TOKEN: f.environment.ENVARA_BROWSER_TOKEN,
    ENVARA_SSH_CONFIG: f.environment.ENVARA_SSH_CONFIG, ENVARA_SSH_PROXY_URL: f.environment.ENVARA_SSH_PROXY_URL,
    CLAUDE_CODE_USE_BEDROCK: 'false', CLAUDE_CODE_SKIP_VERTEX_AUTH: 'off', ANTHROPIC_API_KEY: '',
  } };
  const before = await save(filename, settings);
  assert.doesNotThrow(() => validateClaudeEnvironment(f.environment));
  assert.doesNotThrow(() => validateClaudeSettings(settings, f.environment));
  assert.equal(await preflightClaudeSettings(f.request), true);
  assert.deepEqual(await readFile(filename), before);
});

test('a fixed base PATH remains valid after the runtime wrapper is prepended without accepting arbitrary suffixes', async t => {
  const f = await fixture(t), filename = path.join(f.configDir, 'settings.json');
  const basePath = [path.join(f.root, 'base-bin'), path.dirname(process.execPath)].join(path.delimiter);
  const runtimePath = [path.join(f.root, 'runtime', 'bin'), basePath].join(path.delimiter);
  const environment = { ...f.environment, PATH: runtimePath };
  const settings = { model: 'sonnet', permissions: { defaultMode: 'default' }, env: { PATH: basePath } };
  const before = await save(filename, settings);
  assert.throws(() => validateClaudeSettings(settings, environment), refused(POLICY_CONFLICT));
  assert.doesNotThrow(() => validateClaudeSettings(settings, environment, { basePath }));
  assert.doesNotThrow(() => validateClaudeSettings({ env: { PATH: runtimePath } }, environment, { basePath }));
  assert.equal(await preflightClaudeSettings({ ...f.request, environment, basePath }), true);
  for (const value of [`${basePath}${path.delimiter}${path.join(f.root, 'unapproved-bin')}`,
    `${path.join(f.root, 'other-runtime')}${path.delimiter}${basePath}`]) {
    assert.throws(() => validateClaudeSettings({ env: { PATH: value } }, environment, { basePath }), refused(POLICY_CONFLICT));
  }
  for (const value of ['', 'relative-bin', `${basePath}${path.delimiter}`]) {
    assert.throws(() => validateClaudeSettings({}, environment, { basePath: value }), refused(POLICY_CONFLICT));
  }
  assert.deepEqual(await readFile(filename), before);
  const serialized = await readFile(filename, 'utf8');
  for (const value of ['synthetic-route-secret', 'synthetic-browser-token', 'synthetic-link-token']) assert.ok(!serialized.includes(value));
  const args = [helper, '--check', f.configDir, '--home', f.home, '--base-path', basePath];
  assert.deepEqual(await execute(process.execPath, args, { cwd: f.cwd, env: environment, timeout: 10000 }), { stdout: '', stderr: '' });
});

test('account redirects and credential helpers are rejected in settings without displaying their values', async t => {
  const f = await fixture(t);
  const settings = [
    ...['apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'gcpAuthRefresh', 'forceLoginGatewayUrl']
      .map(key => ({ [key]: secret })),
    { forceLoginMethod: 'console' }, { forceLoginMethod: 'gateway' },
  ];
  const credentials = [
    'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL', 'ANTHROPIC_CUSTOM_HEADERS',
    'ANTHROPIC_AWS_API_KEY', 'ANTHROPIC_AWS_BASE_URL', 'ANTHROPIC_AWS_WORKSPACE_ID',
    'ANTHROPIC_BEDROCK_BASE_URL', 'ANTHROPIC_BEDROCK_MANTLE_BASE_URL',
    'ANTHROPIC_FOUNDRY_API_KEY', 'ANTHROPIC_FOUNDRY_AUTH_TOKEN', 'ANTHROPIC_FOUNDRY_BASE_URL', 'ANTHROPIC_FOUNDRY_RESOURCE',
    'ANTHROPIC_VERTEX_BASE_URL', 'ANTHROPIC_VERTEX_PROJECT_ID', 'ANTHROPIC_PROFILE',
    'ANTHROPIC_FEDERATION_RULE_ID', 'ANTHROPIC_ORGANIZATION_ID', 'ANTHROPIC_WORKSPACE_ID',
    'CLAUDE_CODE_OAUTH_TOKEN', 'CLAUDE_CODE_OAUTH_REFRESH_TOKEN', 'CLAUDE_CODE_OAUTH_SCOPES',
    'CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST', 'DISABLE_LOGIN_COMMAND', 'AWS_BEARER_TOKEN_BEDROCK',
    'CLAUDE_CODE_USE_ANTHROPIC_AWS', 'CLAUDE_CODE_USE_BEDROCK', 'CLAUDE_CODE_USE_FOUNDRY', 'CLAUDE_CODE_USE_MANTLE', 'CLAUDE_CODE_USE_VERTEX',
    'CLAUDE_CODE_SKIP_ANTHROPIC_AWS_AUTH', 'CLAUDE_CODE_SKIP_BEDROCK_AUTH', 'CLAUDE_CODE_SKIP_FOUNDRY_AUTH',
    'CLAUDE_CODE_SKIP_MANTLE_AUTH', 'CLAUDE_CODE_SKIP_VERTEX_AUTH',
  ];
  for (const key of credentials) {
    assert.ok(CLAUDE_ACCOUNT_ENV.has(key), key);
    settings.push({ env: { [key]: secret } });
    assert.throws(() => validateClaudeEnvironment({ ...f.environment, [key]: secret }), refused(ACCOUNT_CONFLICT), key);
  }
  for (const setting of settings) assert.throws(() => validateClaudeSettings(setting, f.environment), refused(ACCOUNT_CONFLICT));
});

test('disabled provider flags are allowed without treating credential strings or false helper values as inactive', async t => {
  const f = await fixture(t);
  for (const value of ['', '0', 'false', 'NO', 'Off']) {
    const variables = { CLAUDE_CODE_USE_VERTEX: value, CLAUDE_CODE_SKIP_BEDROCK_AUTH: value,
      CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST: value, DISABLE_LOGIN_COMMAND: value };
    assert.doesNotThrow(() => validateClaudeEnvironment({ ...f.environment, ...variables }));
    assert.doesNotThrow(() => validateClaudeSettings({ env: variables }, f.environment));
  }
  for (const variables of [{ ANTHROPIC_API_KEY: '0' }, { CLAUDE_CODE_USE_VERTEX: ' false ' }]) {
    assert.throws(() => validateClaudeSettings({ env: variables }, f.environment), refused(ACCOUNT_CONFLICT));
  }
  for (const value of [false, 0, {}]) {
    assert.throws(() => validateClaudeSettings({ apiKeyHelper: value }, f.environment), refused(ACCOUNT_CONFLICT));
    assert.throws(() => validateClaudeSettings({ proxyAuthHelper: value }, f.environment), refused(POLICY_CONFLICT));
  }
  assert.throws(() => validateClaudeSettings({ forceLoginMethod: '' }, f.environment), refused(ACCOUNT_CONFLICT));
});

test('network, directory, browser and subprocess overrides are refused while unrelated options remain free', async t => {
  const f = await fixture(t);
  for (const key of [
    'HOME', 'USERPROFILE', 'CLAUDE_CONFIG_DIR', 'ANTHROPIC_CONFIG_DIR', 'TZ', 'LANG', 'LC_ALL', 'PATH', 'BROWSER',
    'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'NO_PROXY', 'no_proxy',
    'NODE_USE_ENV_PROXY', 'ENVARA_BROWSER_SOCKET', 'ENVARA_BROWSER_TOKEN', 'ENVARA_LINK_SOCKET', 'ENVARA_LINK_TOKEN',
    'SSH_AUTH_SOCK', 'ENVARA_SSH_CONFIG', 'ENVARA_SSH_TARGETS', 'ENVARA_SSH_CONNECTIONS', 'ENVARA_SSH_PROXY_URL',
    'ENVARA_UNRECOGNIZED_CAPABILITY', 'CLAUDE_CODE_SUBPROCESS_ENV_SCRUB', 'NODE_OPTIONS', 'BUN_OPTIONS',
    'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES',
  ]) assert.throws(() => validateClaudeSettings({ env: { [key]: secret } }, f.environment), refused(POLICY_CONFLICT), key);
  assert.ok(CLAUDE_CONTEXT_ENV.has('CLAUDE_CONFIG_DIR'));
  assert.ok(CLAUDE_CONTEXT_ENV.has('BROWSER'));
  assert.throws(() => validateClaudeSettings({ proxyAuthHelper: secret }, f.environment), refused(POLICY_CONFLICT));
  for (const key of ['CLAUDE_CODE_SUBPROCESS_ENV_SCRUB', 'NODE_OPTIONS', 'BUN_OPTIONS', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES']) {
    assert.throws(() => validateClaudeEnvironment({ ...f.environment, [key]: secret }), refused(POLICY_CONFLICT), key);
  }
});

test('malformed, oversized, writable and linked settings fail without exposing file content', async t => {
  const f = await fixture(t), filename = path.join(f.configDir, 'settings.json');
  for (const content of [
    `{${secret}`, 'null', '[]', '{"env":[]}', '{"env":{"BAD-NAME":"value"}}', '{"env":{"A":1}}',
    ' '.repeat(1024 * 1024 + 1),
  ]) {
    await save(filename, content);
    await assert.rejects(readClaudeSettings(filename), refused(INVALID_SETTINGS));
  }
  await save(filename, {});
  if (process.platform !== 'win32') {
    await chmod(filename, 0o666);
    await assert.rejects(readClaudeSettings(filename), refused(INVALID_SETTINGS));
    await chmod(filename, 0o600);
  }
  const target = path.join(f.root, 'unrelated-settings.json'), before = await save(target, { env: { ANTHROPIC_API_KEY: secret } });
  await rm(filename);
  await symlink(target, filename);
  await assert.rejects(readClaudeSettings(filename), refused(INVALID_SETTINGS));
  assert.deepEqual(await readFile(target), before);
  await rm(filename);
  await symlink(path.join(f.root, 'absent-settings.json'), filename);
  await assert.rejects(readClaudeSettings(filename), refused(INVALID_SETTINGS));
});

test('malformed launch environments are rejected before configuration is used', () => {
  for (const environment of [null, [], { A: 1 }, { 'BAD-NAME': 'value' }, { A: 'bad\0value' }]) {
    assert.throws(() => validateClaudeEnvironment(environment), { code: 'CLAUDE_CODE_INVALID_CONFIGURATION' });
  }
});

test('a linked settings directory is rejected even when the optional file target does not exist', async t => {
  const f = await fixture(t), directory = path.join(f.cwd, '.claude');
  const outside = path.join(f.root, 'unrelated-settings'); await mkdir(outside, { mode: 0o700 });
  await symlink(outside, directory, 'dir');
  await assert.rejects(readClaudeSettings(path.join(directory, 'settings.json')), refused(INVALID_SETTINGS));
  await assert.rejects(preflightClaudeSettings(f.request), refused(INVALID_SETTINGS));
});

test('preflight checks user, current project and current local files without rewriting MCP and plugin preferences', async t => {
  const f = await fixture(t), filenames = [
    path.join(f.configDir, 'settings.json'), path.join(f.cwd, '.claude', 'settings.json'),
    path.join(f.cwd, '.claude', 'settings.local.json'),
  ];
  const snapshots = new Map();
  for (const [index, filename] of filenames.entries()) snapshots.set(filename, await save(filename, {
    model: 'sonnet', enabledPlugins: { [`fixture-${index}@local`]: true }, permissions: { defaultMode: 'default' },
    mcpServers: { [`market_${index}`]: { type: 'stdio', command: 'fixture-market' } },
    env: { HTTPS_PROXY: f.environment.HTTPS_PROXY, MARKET_FIXTURE_MODE: 'read-only' },
  }));
  assert.equal(await preflightClaudeSettings(f.request), true);
  for (const [filename, before] of snapshots) assert.deepEqual(await readFile(filename), before);
  for (const filename of filenames) {
    await save(filename, { env: { HTTPS_PROXY: secret } });
    await assert.rejects(preflightClaudeSettings(f.request), refused(POLICY_CONFLICT));
    await writeFile(filename, snapshots.get(filename), { mode: 0o600 });
  }
});

test('each helper invocation uses its actual working directory and rereads newly changed settings', async t => {
  const f = await fixture(t), second = path.join(f.root, 'second project');
  await mkdir(second, { mode: 0o700 });
  const args = [helper, '--check', f.configDir, '--home', f.home];
  const call = cwd => execute(process.execPath, args, { cwd, env: f.environment, timeout: 10000 });
  const first = await call(f.cwd);
  assert.equal(first.stdout, ''); assert.equal(first.stderr, '');
  const filename = path.join(second, '.claude', 'settings.local.json');
  const before = await save(filename, { proxyAuthHelper: secret });
  await assert.rejects(call(second), safeCliFailure(f, POLICY_CONFLICT));
  assert.deepEqual(await readFile(filename), before);
  await save(filename, { model: 'sonnet', enabledPlugins: { 'fixture@local': true } });
  assert.deepEqual(await call(second), { stdout: '', stderr: '' });
  await save(path.join(f.cwd, '.claude', 'settings.json'), { env: { ANTHROPIC_API_KEY: secret } });
  await assert.rejects(call(f.cwd), safeCliFailure(f, ACCOUNT_CONFLICT));
});

test('a shell directory change is observed by the next helper invocation rather than the terminal starting directory', {
  skip: process.platform === 'win32',
}, async t => {
  const f = await fixture(t), second = path.join(f.root, "second project's directory");
  await mkdir(second, { mode: 0o700 });
  const before = await save(path.join(second, '.claude', 'settings.json'), { env: { ANTHROPIC_API_KEY: secret } });
  await assert.rejects(execute('/bin/sh', ['-c', 'cd "$1" && exec "$2" "$3" --check "$4" --home "$5"',
    'settings-check-fixture', second, process.execPath, helper, f.configDir, f.home], {
    cwd: f.cwd, env: f.environment, timeout: 10000,
  }), safeCliFailure(f, ACCOUNT_CONFLICT));
  assert.deepEqual(await readFile(path.join(second, '.claude', 'settings.json')), before);
});

test('malformed helper arguments fail with one safe diagnostic and no configuration echo', async t => {
  const f = await fixture(t);
  await assert.rejects(execute(process.execPath, [helper, '--check', path.join(f.root, secret)], {
    cwd: f.cwd, env: f.environment, timeout: 10000,
  }), safeCliFailure(f, INVALID_SETTINGS));
});

async function git(f, cwd, args) {
  const hooks = path.join(f.root, 'empty-hooks'), globalConfig = path.join(f.root, 'empty-gitconfig');
  await mkdir(hooks, { recursive: true, mode: 0o700 });
  await writeFile(globalConfig, '', { mode: 0o600 });
  const environment = { ...f.environment, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: globalConfig, GIT_TERMINAL_PROMPT: '0' };
  let executable = '/usr/bin/git';
  if (process.platform === 'darwin') {
    const selected = await execute('/usr/bin/xcode-select', ['-p'], { env: environment, timeout: 10000 });
    executable = await realpath(path.join(selected.stdout.trimEnd(), 'usr', 'bin', 'git'));
  }
  return execute(executable, ['-c', `core.hooksPath=${hooks}`, '-c', 'core.fsmonitor=false',
    '-c', 'commit.gpgSign=false', '-C', cwd, ...args], {
    env: environment,
    timeout: 10000, maxBuffer: 128 * 1024,
  });
}

async function repository(f, cwd = f.cwd) {
  await git(f, cwd, ['init', '--quiet']);
  await git(f, cwd, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
    'commit', '--quiet', '--allow-empty', '-m', 'Disposable fixture']);
}

test('a nested owned repository checks root local settings as well as current-directory legacy files', {
  skip: process.platform === 'win32',
}, async t => {
  const f = await fixture(t), nested = path.join(f.cwd, 'nested', 'directory');
  await repository(f); await mkdir(nested, { recursive: true, mode: 0o700 });
  const request = { ...f.request, cwd: nested };
  const rootLocal = path.join(f.cwd, '.claude', 'settings.local.json');
  assert.deepEqual(await resolveClaudeSettingsFiles(request), [
    path.join(f.configDir, 'settings.json'), path.join(nested, '.claude', 'settings.json'),
    path.join(nested, '.claude', 'settings.local.json'), rootLocal,
  ]);
  const before = await save(rootLocal, { env: { HTTPS_PROXY: secret } });
  await assert.rejects(preflightClaudeSettings(request), refused(POLICY_CONFLICT));
  assert.deepEqual(await readFile(rootLocal), before);
  await save(rootLocal, { enabledPlugins: { 'fixture@local': true } });
  assert.equal(await preflightClaudeSettings(request), true);
  const legacyLocal = path.join(nested, '.claude', 'settings.local.json');
  await save(legacyLocal, { apiKeyHelper: secret });
  await assert.rejects(preflightClaudeSettings(request), refused(ACCOUNT_CONFLICT));
});

test('linked worktrees discover the main checkout local settings without inventing another root-local source', {
  skip: process.platform === 'win32',
}, async t => {
  const f = await fixture(t), worktree = path.join(f.root, 'linked worktree');
  await repository(f);
  await git(f, f.cwd, ['worktree', 'add', '--quiet', '--detach', worktree, 'HEAD']);
  const nested = path.join(worktree, 'nested'); await mkdir(nested, { mode: 0o700 });
  const request = { ...f.request, cwd: nested };
  const mainLocal = path.join(f.cwd, '.claude', 'settings.local.json');
  const worktreeLocal = path.join(worktree, '.claude', 'settings.local.json');
  const expected = [path.join(f.configDir, 'settings.json'), path.join(nested, '.claude', 'settings.json'),
    path.join(nested, '.claude', 'settings.local.json'), mainLocal];
  assert.deepEqual(await resolveClaudeSettingsFiles(request), expected);
  await save(mainLocal, { env: { ANTHROPIC_BASE_URL: secret } });
  await assert.rejects(preflightClaudeSettings(request), refused(ACCOUNT_CONFLICT));
  await save(mainLocal, { model: 'sonnet' });
  await save(worktreeLocal, { env: { HTTPS_PROXY: secret } });
  assert.equal(await preflightClaudeSettings(request), true, 'a parent worktree local file is not an invented extra source');
  await assert.rejects(preflightClaudeSettings({ ...request, cwd: worktree }), refused(POLICY_CONFLICT),
    'the worktree root local file remains a legacy current-directory source when invoked there');
});

test('linked worktrees of a bare repository use only the invocation directory local settings', {
  skip: process.platform === 'win32',
}, async t => {
  const f = await fixture(t), bare = path.join(f.root, 'central repository.git'), linked = path.join(f.root, 'bare linked');
  await repository(f);
  await git(f, f.root, ['clone', '--quiet', '--bare', f.cwd, bare]);
  await git(f, f.root, ['--git-dir', bare, 'worktree', 'add', '--quiet', '--detach', linked, 'HEAD']);
  const nested = path.join(linked, 'nested'); await mkdir(nested, { mode: 0o700 });
  const bareLocal = path.join(bare, '.claude', 'settings.local.json');
  const linkedLocal = path.join(linked, '.claude', 'settings.local.json');
  const nestedLocal = path.join(nested, '.claude', 'settings.local.json');
  const before = await save(bareLocal, { apiKeyHelper: secret });
  for (const cwd of [linked, nested]) {
    assert.deepEqual(await resolveClaudeSettingsFiles({ ...f.request, cwd }), [path.join(f.configDir, 'settings.json'),
      path.join(cwd, '.claude', 'settings.json'), path.join(cwd, '.claude', 'settings.local.json')]);
    assert.equal(await preflightClaudeSettings({ ...f.request, cwd }), true, 'a bare central repository is not a settings source');
  }
  await save(linkedLocal, { enabledPlugins: { 'fixture@local': true } });
  assert.equal(await preflightClaudeSettings({ ...f.request, cwd: linked }), true);
  await save(linkedLocal, { env: { HTTPS_PROXY: secret } });
  await assert.rejects(preflightClaudeSettings({ ...f.request, cwd: linked }), refused(POLICY_CONFLICT));
  assert.equal(await preflightClaudeSettings({ ...f.request, cwd: nested }), true, 'the parent linked checkout local file is not loaded');
  await save(nestedLocal, { env: { ANTHROPIC_API_KEY: secret } });
  await assert.rejects(preflightClaudeSettings({ ...f.request, cwd: nested }), refused(ACCOUNT_CONFLICT));
  await save(nestedLocal, '{invalid-json');
  await assert.rejects(preflightClaudeSettings({ ...f.request, cwd: nested }), refused(INVALID_SETTINGS));
  await rm(nestedLocal);
  await symlink(linkedLocal, nestedLocal);
  await assert.rejects(preflightClaudeSettings({ ...f.request, cwd: nested }), refused(INVALID_SETTINGS));
  assert.deepEqual(await readFile(bareLocal), before);
});

test('bare fallback still refuses malformed and unsafe first-worktree records', {
  skip: process.platform === 'win32',
}, async t => {
  const f = await fixture(t); await mkdir(path.join(f.cwd, '.git'));
  const link = path.join(f.root, 'linked-main'); await symlink(f.cwd, link, 'dir');
  for (const output of [
    `worktree relative\0bare\0\0`,
    `worktree ${f.cwd}\0bare\0HEAD invalid\0\0`,
    `worktree ${f.cwd}\0bare\0`,
    `worktree ${link}\0bare\0\0`,
  ]) {
    await assert.rejects(resolveClaudeSettingsFiles({ ...f.request, platform: 'linux', executeGit: async (_file, args) => ({
      stdout: args.includes('rev-parse') ? `${f.cwd}\n` : output,
    }) }), refused(INVALID_SETTINGS));
  }
});

test('outside Git and a repository rooted at the selected home fall back to current-directory local settings', {
  skip: process.platform === 'win32',
}, async t => {
  const f = await fixture(t), local = path.join(f.cwd, '.claude', 'settings.local.json');
  assert.deepEqual(await resolveClaudeSettingsFiles(f.request), [path.join(f.configDir, 'settings.json'),
    path.join(f.cwd, '.claude', 'settings.json'), local]);
  await repository(f, f.home);
  const nested = path.join(f.home, 'nested'); await mkdir(nested, { mode: 0o700 });
  await save(path.join(f.home, '.claude', 'settings.local.json'), { apiKeyHelper: secret });
  const request = { ...f.request, cwd: nested };
  assert.deepEqual(await resolveClaudeSettingsFiles(request), [path.join(f.configDir, 'settings.json'),
    path.join(nested, '.claude', 'settings.json'), path.join(nested, '.claude', 'settings.local.json')]);
  assert.equal(await preflightClaudeSettings(request), true);
  await save(path.join(nested, '.claude', 'settings.local.json'), { apiKeyHelper: secret });
  await assert.rejects(preflightClaudeSettings(request), refused(ACCOUNT_CONFLICT));
});

test('Git discovery discards caller Git configuration and treats unexpected failures as invalid settings', {
  skip: process.platform === 'win32',
}, async t => {
  const f = await fixture(t); await mkdir(path.join(f.cwd, '.git'));
  const calls = [];
  const executeGit = async (file, args, options) => {
    calls.push({ file, args, options });
    return { stdout: args.includes('rev-parse') ? `${f.cwd}\n` : `worktree ${f.cwd}\0bare\0\0` };
  };
  await resolveClaudeSettingsFiles({ ...f.request, platform: 'linux', executeGit, environment: { ...f.environment,
    GIT_DIR: path.join(f.root, 'unrelated-git'), GIT_WORK_TREE: path.join(f.root, 'unrelated-tree'),
    GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'core.hooksPath', GIT_CONFIG_VALUE_0: secret,
    GIT_SSH_COMMAND: secret,
  } });
  assert.equal(calls.length, 2);
  for (const call of calls) {
    assert.equal(call.file, await realpath('/usr/bin/git'));
    assert.equal(call.options.env.HOME, f.home);
    assert.equal(call.options.env.LC_ALL, 'C');
    assert.equal(call.options.env.GIT_CONFIG_NOSYSTEM, '1');
    for (const key of ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_SSH_COMMAND']) {
      assert.equal(call.options.env[key], undefined, key);
    }
  }
  for (const error of [Object.assign(new Error(secret), { code: 'ETIMEDOUT' }),
    Object.assign(new Error(secret), { code: 128, stderr: `fatal: ${secret}` }),
    Object.assign(new Error(secret), { code: 'ENOENT' })]) {
    await assert.rejects(resolveClaudeSettingsFiles({ ...f.request, platform: 'linux', executeGit: async () => { throw error; } }), refused(INVALID_SETTINGS));
  }
});

test('ordinary folders do not invoke Git or developer-tool discovery', async t => {
  const f = await fixture(t); let calls = 0;
  const files = await resolveClaudeSettingsFiles({ ...f.request, platform: 'darwin', executeGit: async () => {
    calls++; throw new Error('No tools may run for an ordinary folder');
  } });
  assert.equal(calls, 0);
  assert.deepEqual(files, [path.join(f.configDir, 'settings.json'), path.join(f.cwd, '.claude', 'settings.json'),
    path.join(f.cwd, '.claude', 'settings.local.json')]);
});

test('unavailable macOS developer tools fail closed without invoking the installation-launching Git stub', async t => {
  const f = await fixture(t); await mkdir(path.join(f.cwd, '.git'));
  const calls = [];
  await assert.rejects(resolveClaudeSettingsFiles({ ...f.request, platform: 'darwin', executeGit: async (file, args) => {
    calls.push({ file, args });
    if (file === '/usr/bin/xcode-select') throw Object.assign(new Error(secret), { code: 2 });
    throw new Error('The Git stub must not be invoked');
  } }), refused(INVALID_SETTINGS));
  assert.deepEqual(calls, [{ file: '/usr/bin/xcode-select', args: ['-p'] }]);
});
