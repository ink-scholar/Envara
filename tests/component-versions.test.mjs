import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, mkdir, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { componentVersionSnapshot } from '../shared/component-versions.mjs';
import { inspectClaudeComponent, inspectPFComponent, readComponentVersions } from '../electron/component-versions.mjs';
import { PF_INSTALL_ROOT, PF_MANIFEST_FILES, pfInstallationPlan } from '../native/macos-pf-routing/controller.mjs';
const macOSFeature = process.platform !== 'darwin' && 'macOS-only feature';

const workspace = () => ({ system: { appVersion: '1.2.3', proxyCore: { supported: true, version: 'v1.19.5' } },
  profiles: [{ id: 'one', name: 'First', engine: 'camoufox', status: 'stopped' }, { id: 'two', name: 'Second', engine: 'cloakbrowser', status: 'running' }],
  engines: [{ id: 'camoufox', installed: true, supported: true, version: '135.0-beta.24' }, { id: 'cloakbrowser', supported: true, installed: false }],
  applications: [], applicationRouting: { installed: true, ready: false, component: { name: 'Envara · PF', version: '2.0.0', available: true, verified: true }, verification: { version: '1.0.0' } } });
const row = (value, id) => value.rows.find(item => item.id === id);
const pfWorkspace = () => ({ ...workspace(), applicationRouting: { backend: 'pf-utun', installed: true, ready: false,
  authorized: false, component: { name: 'Envara · PF', version: '1', available: true, verified: true },
  verification: { version: 'pf/1', passed: false } } });

test('PF version comes from a verified installation manifest without claiming running readiness', () => {
  const snapshot = pfWorkspace(), before = structuredClone(snapshot);
  const result = row(componentVersionSnapshot({ snapshot, pfInstallation: { status: 'installed', version: '1' },
    platform: 'darwin', arch: 'arm64' }), 'application-routing');
  assert.equal(result.version, '1');
  assert.equal(result.bundledVersion, '1');
  assert.equal(result.versionSource, 'validated-installation-manifest');
  assert.equal(result.status, 'installed');
  assert.equal(result.support, 'supported');
  assert.equal(result.runningVersion, null);
  assert.equal(result.blocked, false);
  assert.deepEqual(snapshot, before);
  assert.deepEqual(result.sessions, []);
});

test('PF missing, untrusted and unknown evidence supersedes cached installation claims', () => {
  const snapshot = pfWorkspace();
  snapshot.applicationRouting.ready = true;
  snapshot.applicationRouting.verification.version = '999';
  for (const [pfInstallation, expected] of [[null, 'unknown'], [{ status: 'unknown' }, 'unknown'],
    [{ status: 'missing' }, 'missing'], [{ status: 'untrusted', version: '1' }, 'needs-attention'],
    [{ status: 'installed', version: '/private/SECRET' }, 'unknown']]) {
    const result = row(componentVersionSnapshot({ snapshot, pfInstallation }), 'application-routing');
    assert.equal(result.status, expected);
    assert.equal(result.version, null);
    assert.equal(result.versionSource, 'unknown');
    assert.equal(result.runningVersion, null);
    assert.equal(result.support, 'unknown');
    assert.equal(result.blocked, true);
    assert.equal(JSON.stringify(result).includes('SECRET'), false);
  }
});

test('PF platform support and associated sessions never establish runtime readiness', () => {
  const snapshot = pfWorkspace();
  snapshot.applications = [{ id: 'app', profileId: 'one', name: 'Editor', status: 'running' }];
  for (const [platform, arch, support] of [['darwin', 'arm64', 'supported'], ['darwin', 'x64', 'unsupported'],
    ['win32', 'arm64', 'unsupported'], ['linux', 'x64', 'unsupported'], ['darwin', null, 'unknown'], [null, 'arm64', 'unknown']]) {
    const result = row(componentVersionSnapshot({ snapshot, platform, arch,
      pfInstallation: { status: 'installed', version: '1' } }), 'application-routing');
    assert.equal(result.support, support);
    assert.equal(result.status, 'installed');
    assert.equal(result.runningVersion, null);
    assert.deepEqual(result.sessions.map(item => item.id), ['app']);
    assert.equal(result.blocked, true);
  }
  snapshot.applicationRouting.ready = true;
  assert.equal(row(componentVersionSnapshot({ snapshot, pfInstallation: { status: 'installed', version: '1' } }), 'application-routing').status, 'ready');
});

test('other routing adapters retain their existing version, state and support contracts', () => {
  for (const backend of ['app-proxy', 'windivert', undefined]) {
    const snapshot = workspace(); snapshot.applicationRouting.backend = backend;
    const result = row(componentVersionSnapshot({ snapshot, pfInstallation: { status: 'installed', version: '99' },
      platform: 'darwin', arch: 'arm64' }), 'application-routing');
    assert.equal(result.version, '1.0.0');
    assert.equal(result.versionSource, 'installation-report');
    assert.equal(result.bundledVersion, '2.0.0');
    assert.equal(result.status, 'needs-attention');
    assert.equal(result.support, 'unknown');
    assert.equal(result.runningVersion, null);
  }
});

test('PF inventory reuses installation verification and publishes its accepted manifest contract version', async () => {
  const calls = [];
  const fileSystem = { lstat: async target => { calls.push(['lstat', target]); return {}; } };
  const verify = async ({ fileSystem: reader }) => {
    assert.equal(reader, fileSystem, 'retain the verifier filesystem and production streaming hashes');
    calls.push(['verify']);
    return { verified: true, manifestVerified: true, runtimeVerified: false };
  };
  assert.deepEqual(await inspectPFComponent({ fileSystem, verify }), { status: 'installed', version: pfInstallationPlan().manifest.version });
  assert.deepEqual(calls, [['lstat', PF_INSTALL_ROOT], ['verify']]);
  for (const evidence of [{ verified: false, manifestVerified: true }, { verified: true, manifestVerified: false }])
    assert.deepEqual(await inspectPFComponent({ fileSystem, verify: async options => { await verify(options); return evidence; } }), { status: 'untrusted' });
  assert.deepEqual(await inspectPFComponent({ fileSystem, verify: async () => { throw new Error('SECRET'); } }), { status: 'unknown' });
});

test('PF inventory distinguishes absent paths, inaccessible inspections and rejected ownership without writes', async () => {
  const refuseVerify = async () => { assert.fail('absent or inaccessible installation must not be inspected'); };
  for (const [code, status] of [['ENOENT', 'missing'], ['EACCES', 'unknown'], ['EIO', 'unknown']]) {
    assert.deepEqual(await inspectPFComponent({ fileSystem: { lstat: async () => { throw Object.assign(new Error('SECRET'), { code }); } },
      verify: refuseVerify }), { status });
  }
  const reads = [];
  assert.deepEqual(await inspectPFComponent({ fileSystem: {
    lstat: async target => { reads.push(target); return { uid: 501, mode: 0o755, isSymbolicLink: () => false }; },
    realpath: async target => target,
    readFile: async () => assert.fail('untrusted installation must not supply manifest evidence'),
  } }), { status: 'untrusted' });
  assert.deepEqual(reads, [PF_INSTALL_ROOT, PF_INSTALL_ROOT]);
});

test('the PF installation plan version matches the real verifier contract and cannot bypass file integrity', { skip: macOSFeature }, async () => {
  for (const [version, expectedFileReads] of [[pfInstallationPlan().manifest.version, 1], ['unrecognized-version', 0]]) {
    const fileReads = [];
    const manifest = { ...pfInstallationPlan().manifest, version,
      files: Object.fromEntries(Object.keys(PF_MANIFEST_FILES).map(name => [name, 'a'.repeat(64)])) };
    const fileSystem = {
      realpath: async target => target,
      lstat: async () => ({ uid: 0, mode: 0o755, size: 1024, isSymbolicLink: () => false, isFile: () => true, isDirectory: () => true }),
      readFile: async target => {
        if (target === `${PF_INSTALL_ROOT}/manifest.json`) return Buffer.from(JSON.stringify(manifest));
        fileReads.push(target); return Buffer.from('untrusted fixture bytes');
      },
    };
    assert.deepEqual(await inspectPFComponent({ fileSystem }), { status: 'untrusted' });
    assert.equal(fileReads.length, expectedFileReads, 'only the recognized manifest reaches file hash validation');
  }
});

test('PF reader refreshes installation evidence and isolates failures without querying other adapters', async () => {
  const snapshot = pfWorkspace(), original = structuredClone(snapshot);
  let inspections = 0;
  const options = { snapshot, platform: 'darwin', arch: 'arm64', inspectPF: async () => {
    inspections++; if (inspections === 2) throw new Error('SECRET'); return { status: 'installed', version: '1' };
  } };
  assert.equal(row(await readComponentVersions(options), 'application-routing').status, 'installed');
  const failed = row(await readComponentVersions(options), 'application-routing');
  assert.equal(failed.status, 'unknown'); assert.equal(failed.version, null);
  assert.equal(JSON.stringify(failed).includes('SECRET'), false);
  assert.deepEqual(snapshot, original);
  await readComponentVersions({ ...options, snapshot: workspace() });
  await readComponentVersions({ ...options, platform: 'win32' });
  assert.equal(inspections, 2);
});

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

test('the reader scopes installation inspection to owned environment homes and isolates partial failures', { skip: macOSFeature }, async () => {
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
