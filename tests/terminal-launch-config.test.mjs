import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { terminalChildEnvironment, terminalShell } from '../electron/terminal-launch-config.mjs';

function context(platform = 'darwin') {
  const paths = platform === 'win32' ? path.win32 : path.posix;
  const root = platform === 'win32' ? 'D:\\Owned\\environment' : '/owned/environment';
  const directories = Object.fromEntries(['home', 'config', 'cache', 'data', 'state', 'claude', 'anthropic', 'temp', 'history'].map(key => [key, paths.join(root, key)]));
  return { directories, platform, timezone: 'Asia/Tokyo', proxyEndpoint: null,
    language: { posix: 'ja_JP.UTF-8' }, hostHome: platform === 'win32' ? 'C:\\Users\\Fixture' : '/fixture/home',
    additionalExecutablePaths: [], hostEnvironment: { PATH: '/untrusted/bin', HOME: '/host/home',
      SSH_AUTH_SOCK: '/host/agent', NODE_OPTIONS: '--require private-hook', ANTHROPIC_API_KEY: 'private-key',
      GIT_AUTHOR_EMAIL: 'host@example.test', LANG: 'host-language' } };
}

test('launch configuration isolates supplied host secrets and preserves explicit child context on every platform', () => {
  for (const platform of ['darwin', 'linux', 'win32']) {
    const options = context(platform), before = structuredClone(options);
    const environment = terminalChildEnvironment(options);
    assert.equal(environment.HOME, options.directories.home);
    assert.equal(environment.CLAUDE_CONFIG_DIR, options.directories.claude);
    assert.equal(environment.ANTHROPIC_CONFIG_DIR, options.directories.anthropic);
    assert.equal(environment.TZ, 'Asia/Tokyo'); assert.equal(environment.LANG, 'ja_JP.UTF-8');
    for (const key of ['SSH_AUTH_SOCK', 'NODE_OPTIONS', 'ANTHROPIC_API_KEY', 'GIT_AUTHOR_EMAIL', 'HTTP_PROXY']) assert.equal(environment[key], undefined);
    assert.equal(environment.PATH.includes('/untrusted/bin'), false);
    assert.deepEqual(options, before, 'building a launch must not mutate caller or host input');
  }
});

test('Windows uses only its system allowlist and fresh host inputs without inheriting host PATH', () => {
  const options = context('win32');
  Object.assign(options.hostEnvironment, { SystemRoot: 'C:\\System', WINDIR: 'C:\\System', ComSpec: 'C:\\System\\cmd.exe', PATHEXT: '.EXE;.CMD', ProgramFiles: 'C:\\Programs' });
  const first = terminalChildEnvironment(options);
  assert.ok(first.PATH.split(';').includes('C:\\System\\System32'));
  assert.ok(first.PATH.split(';').includes('C:\\Programs\\nodejs'));
  assert.equal(first.HOMEDRIVE, 'D:'); assert.equal(first.HOMEPATH, '\\Owned\\environment\\home');
  assert.equal(first.ComSpec, 'C:\\System\\cmd.exe'); assert.equal(first.ProgramFiles, undefined);
  options.hostEnvironment.ComSpec = 'C:\\System\\replacement.exe';
  assert.equal(terminalChildEnvironment(options).ComSpec, 'C:\\System\\replacement.exe');
  const shell = terminalShell(first, { platform: 'win32', hostEnvironment: options.hostEnvironment });
  assert.equal(shell.executable, 'C:\\System\\replacement.exe'); assert.deepEqual(shell.args, ['/D', '/Q']);
  assert.equal(shell.environment.PROMPT, 'envara $P$G'); assert.equal(first.PROMPT, undefined);
});

test('owned proxy and link credentials retain their precise routing and priority rules', () => {
  const options = context();
  options.additionalExecutablePaths = ['/owned/tools', '/usr/bin', '/owned/tools'];
  options.linkShim = { directory: '/owned/link-shim', ENVARA_LINK_SOCKET: '/owned/socket', ENVARA_LINK_TOKEN: 'owned-token', unexpected: 'secret' };
  options.proxyEndpoint = 'http://owned-user:owned-password@127.0.0.1:24680'; options.privacy = { mode: 'strict' };
  const environment = terminalChildEnvironment(options);
  assert.deepEqual(environment.PATH.split(':').slice(0, 3), ['/owned/link-shim', '/owned/tools', '/usr/bin']);
  assert.equal(environment.PATH.split(':').filter(value => value === '/usr/bin').length, 1);
  for (const key of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) assert.equal(environment[key], options.proxyEndpoint);
  assert.equal(environment.NODE_USE_ENV_PROXY, '1'); assert.equal(environment.BROWSER, '/owned/link-shim/browser');
  assert.equal(environment.ENVARA_LINK_TOKEN, 'owned-token'); assert.equal(environment.unexpected, undefined);
  assert.equal(environment.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC, '1');
  options.linkShim.ENVARA_LINK_TOKEN = 'invalid\ncredential'; options.privacy = { mode: 'off' };
  const changed = terminalChildEnvironment(options);
  assert.equal(changed.ENVARA_LINK_TOKEN, undefined); assert.equal(changed.DO_NOT_TRACK, undefined);
});

test('native shell definitions retain private startup files without modifying supplied environment', () => {
  const environment = { HOME: '/owned/home', LANG: 'C' };
  assert.deepEqual(terminalShell(environment, { platform: 'darwin', hostEnvironment: {} }), {
    executable: '/bin/zsh', args: ['-d', '-i'], environment: { ...environment, SHELL: '/bin/zsh', PS1: 'envara %~ %# ' },
  });
  const linux = terminalShell(environment, { platform: 'linux', hostEnvironment: {} });
  assert.equal(linux.executable, '/bin/bash'); assert.deepEqual(linux.args, ['--noprofile', '--rcfile', '/owned/home/.bashrc', '-i']);
  assert.deepEqual(environment, { HOME: '/owned/home', LANG: 'C' });
});
