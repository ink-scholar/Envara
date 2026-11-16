import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, mkdir, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { componentVersionSnapshot } from '../shared/component-versions.mjs';
import { inspectClaudeComponent, readComponentVersions } from '../electron/component-versions.mjs';

const workspace = () => ({ system: { appVersion: '1.2.3', proxyCore: { supported: true, version: 'v1.19.5' } },
  profiles: [{ id: 'one', name: 'First', engine: 'camoufox', status: 'stopped' }, { id: 'two', name: 'Second', engine: 'cloakbrowser', status: 'running' }],
  engines: [{ id: 'camoufox', installed: true, supported: true, version: '135.0-beta.24' }, { id: 'cloakbrowser', supported: true, installed: false }],
  applications: [], applicationRouting: { installed: true, ready: false, component: { name: 'Envara · PF', version: '2.0.0', available: true, verified: true }, verification: { version: '1.0.0' } } });
const row = (value, id) => value.rows.find(item => item.id === id);

test('installed, bundled and running versions keep distinct evidence sources', () => {
  const result = componentVersionSnapshot({ snapshot: workspace(), terminals: { profiles: [] }, claude: [{ profileId: 'one', supported: true, installed: true, version: '2.1.7' }] });
  assert.equal(row(result, 'application').runningVersion, '1.2.3');
  assert.equal(row(result, 'camoufox').versionSource, 'installation-record');
  assert.equal(row(result, 'camoufox').runningVersion, null);
  assert.equal(row(result, 'proxy-core').versionSource, 'bundled-package');
  assert.equal(row(result, 'application-routing').version, '1.0.0');
  assert.equal(row(result, 'application-routing').bundledVersion, '2.0.0');
  assert.equal(row(result, 'claude-one').versionSource, 'validated-installation-entry');
  assert.equal(row(result, 'claude-one').runningVersion, null);
  assert.equal(row(result, 'claude-two').status, 'unknown');
});

test('engine updates account for other engines and dedicated terminal bindings', () => {
  const terminals = { profiles: [{ profileId: 'one', sessions: [{ sessionId: 'session_one', kind: 'claude-code', savedTerminalName: 'Work', status: 'running' },
    { sessionId: 'ended', kind: 'claude-code', status: 'exited' }] }] };
  const result = componentVersionSnapshot({ snapshot: workspace(), terminals });
  assert.deepEqual(row(result, 'camoufox').sessions.map(item => item.id), ['two', 'session_one']);
  assert.equal(row(result, 'camoufox').blocked, true);
  assert.deepEqual(row(result, 'claude-one').sessions.map(item => item.id), ['session_one']);
  assert.deepEqual(row(result, 'claude-two').sessions, []);
});

test('unknown terminal ownership blocks service replacement while a clean snapshot permits it', () => {
  const snapshot = workspace(); snapshot.profiles[1].status = 'stopped';
  assert.equal(row(componentVersionSnapshot({ snapshot }), 'camoufox').blocked, true);
  const result = componentVersionSnapshot({ snapshot, terminals: { profiles: [] } });
  assert.equal(row(result, 'camoufox').blocked, false);
  assert.equal(row(result, 'browseforge-chromium').support, 'unknown');
  assert.equal(row(result, 'browseforge-chromium').blocked, true);
});

test('application cleanup uncertainty stays associated and prevents routing setup', () => {
  const snapshot = workspace();
  snapshot.applications = [{ id: 'app', profileId: 'one', name: 'Editor', status: 'error', sessionId: 'owned-session' }];
  const result = componentVersionSnapshot({ snapshot, terminals: { profiles: [] } });
  assert.equal(row(result, 'application-routing').blocked, true);
  assert.deepEqual(row(result, 'application-routing').sessions.map(item => item.id), ['app']);
});

test('component projection excludes paths, credentials, terminal output and raw failures', () => {
  const snapshot = workspace();
  snapshot.engines[0].version = '/private/SECRET'; snapshot.engines[0].binaryPath = '/private/SECRET';
  snapshot.system.proxyCore.error = 'SECRET'; snapshot.proxies = [{ password: 'SECRET' }];
  const terminals = { profiles: [{ profileId: 'one', configDir: '/private/SECRET', sessions: [{ sessionId: 'term', status: 'running', kind: 'shell',
    replay: 'SECRET', cwd: '/private/SECRET', network: { username: 'SECRET' }, error: 'SECRET' }] }] };
  const result = componentVersionSnapshot({ snapshot, terminals });
  assert.equal(JSON.stringify(result).includes('SECRET'), false);
  assert.equal(row(result, 'camoufox').version, null);
});

test('CLI inspection uses only a validated local installation entry and preserves missing homes', async t => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-components-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const missing = path.join(directory, 'missing');
  assert.deepEqual(await inspectClaudeComponent({ home: missing }), { installed: false });
  assert.deepEqual(await readdir(directory), []);
  if (!['darwin', 'linux'].includes(process.platform)) return;
  const home = path.join(directory, 'home');
  for (const relative of ['', '.local', '.local/bin', '.local/share', '.local/share/claude', '.local/share/claude/versions'])
    await mkdir(path.join(home, relative), { mode: 0o700 });
  const binary = path.join(home, '.local/share/claude/versions/2.1.7');
  await writeFile(binary, Buffer.from(process.platform === 'darwin' ? 'cffaedfe' : '7f454c46', 'hex'), { mode: 0o700 });
  await symlink(binary, path.join(home, '.local/bin/claude'));
  assert.deepEqual(await inspectClaudeComponent({ home }), { installed: true, version: '2.1.7' });
  assert.deepEqual(await readdir(path.dirname(binary)), ['2.1.7']);
});

test('the reader scopes installation inspection to owned environment homes and isolates partial failures', async () => {
  const calls = [], snapshot = workspace();
  const terminal = { profilesDir: '/owned/profiles', ready: Promise.resolve(), snapshot: async () => { throw new Error('private failure'); } };
  const result = await readComponentVersions({ snapshot, terminal, platform: 'darwin', arch: 'arm64', now: () => 0,
    inspectClaude: async ({ home }) => { calls.push(home); if (home.includes('/two/')) throw new Error('private failure'); return { installed: true, version: '2.1.8' }; } });
  assert.deepEqual(calls, ['/owned/profiles/one/home', '/owned/profiles/two/home']);
  assert.equal(result.checkedAt, '1970-01-01T00:00:00.000Z');
  assert.equal(row(result, 'claude-one').version, '2.1.8');
  assert.equal(row(result, 'claude-two').status, 'unknown');
  assert.equal(row(result, 'camoufox').sessionsKnown, false);
  assert.equal(JSON.stringify(result).includes('private failure'), false);
});
