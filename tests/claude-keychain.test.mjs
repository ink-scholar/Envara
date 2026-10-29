import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { chmod, link, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { ClaudeKeychainManager, inspectClaudeKeychainResource, parseClaudeKeychainReply } from '../electron/claude-keychain.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const ready = changed => `${JSON.stringify({ schemaVersion: 1, status: 'ready', changed })}\n`;
const denied = (code, extra = {}) => Object.assign(new Error('private /fixture/user/keychain path and credential must not escape'), {
  code: 1, stdout: JSON.stringify({ schemaVersion: 1, status: 'error', code, stage: 'scoped-query', osStatus: -25307, ...extra }),
  stderr: 'private diagnostic from child',
});
async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-keychain-manager-')));
  const resourcesDir = path.join(root, 'resources'), directory = path.join(resourcesDir, 'darwin-arm64');
  await mkdir(directory, { recursive: true });
  const binary = Buffer.alloc(128); binary.writeUInt32LE(0xfeedfacf); binary.writeUInt32LE(0x0100000c, 4);
  const executable = path.join(directory, 'envara-claude-keychain'), manifestFile = path.join(directory, 'manifest.json');
  const manifest = { schemaVersion: 1, platform: 'darwin', architecture: 'arm64', executable: path.basename(executable),
    sha256: hash(binary), sourceSha256: hash('fixture source'), builderSha256: hash('fixture builder') };
  await writeFile(executable, binary, { mode: 0o700 });
  await writeFile(manifestFile, JSON.stringify(manifest), { mode: 0o600 });
  const home = path.join(root, 'private-home'), hostHome = path.join(root, 'source-home');
  await mkdir(home, { mode: 0o700 }); await mkdir(hostHome, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, resourcesDir, directory, executable, manifest, manifestFile, binary, home, hostHome,
    manager: execute => new ClaudeKeychainManager({ resourcesDir, platform: 'darwin', architecture: 'arm64', execute }) };
}

test('validates exact helper bytes and architecture before explicit session preparation', async t => {
  const f = await fixture(t), calls = [];
  assert.equal((await inspectClaudeKeychainResource(f)).executable, f.executable);
  const manager = f.manager(async (...args) => { calls.push(args); return { stdout: ready(true) }; });
  assert.deepEqual(await manager.prepare(f), { schemaVersion: 1, status: 'ready', changed: true });
  assert.equal(calls.length, 1);
  const [executable, args, options] = calls[0];
  assert.equal(executable, f.executable);
  assert.deepEqual(args, ['prepare', '--home', f.home, '--host-home', f.hostHome]);
  assert.deepEqual(options.env, { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: f.hostHome, LANG: 'C', LC_ALL: 'C' });
  assert.equal(options.cwd, '/'); assert.equal(options.timeout, 30000); assert.equal(options.maxBuffer, 4096);
  assert.equal(options.shell, undefined); assert.equal(options.signal, undefined);
});

test('resource inspection never executes native code or touches the requested HOME', async t => {
  const f = await fixture(t);
  await rm(f.home, { recursive: true });
  await inspectClaudeKeychainResource(f);
  await assert.rejects(readFile(f.home), { code: 'ENOENT' });
});

test('non-macOS preparation is inert and requires no native resource', async () => {
  const manager = new ClaudeKeychainManager({ platform: 'linux', execute: () => assert.fail('Must not execute') });
  assert.deepEqual(await manager.prepare(), { schemaVersion: 1, status: 'not-required', changed: false });
});

test('unsafe paths never reach a native process', async t => {
  const f = await fixture(t), manager = f.manager(() => assert.fail('Must not execute'));
  for (const home of [f.hostHome, '/', 'relative', `${f.home}/..`, `${f.home}\nprivate`])
    await assert.rejects(manager.prepare({ home, hostHome: f.hostHome }), { code: 'CLAUDE_KEYCHAIN_UNSAFE_PATH' });
});

test('wrong bytes, wrong architecture, writable resources, links and missing resources fail closed', async t => {
  for (const mode of ['digest', 'arch', 'writable', 'symlink', 'hardlink', 'manifest', 'missing']) await t.test(mode, async t => {
    const f = await fixture(t), manager = f.manager(() => assert.fail('Must not execute'));
    if (mode === 'digest') await writeFile(f.executable, Buffer.alloc(128));
    if (mode === 'arch') {
      f.binary.writeUInt32LE(0x01000007, 4); await writeFile(f.executable, f.binary);
      await writeFile(f.manifestFile, JSON.stringify({ ...f.manifest, sha256: hash(f.binary) }));
    }
    if (mode === 'writable') await chmod(f.executable, 0o777);
    if (mode === 'symlink') { await rm(f.executable); await writeFile(path.join(f.root, 'replacement'), f.binary); await symlink(path.join(f.root, 'replacement'), f.executable); }
    if (mode === 'hardlink') await link(f.executable, path.join(f.root, 'alias'));
    if (mode === 'manifest') await writeFile(f.manifestFile, JSON.stringify({ ...f.manifest, executable: '../outside' }));
    if (mode === 'missing') await rm(f.executable);
    await assert.rejects(manager.prepare(f), { code: 'CLAUDE_KEYCHAIN_RESOURCE_INVALID' });
  });
});

test('native failures preserve known categories but discard all child diagnostic text', async t => {
  const f = await fixture(t);
  for (const suffix of ['MISSING', 'LOCKED', 'EXISTING_SELECTION', 'HOST_CHANGED', 'UNSAFE_PATH', 'CLEANUP_FAILED']) {
    const code = `CLAUDE_KEYCHAIN_${suffix}`;
    await assert.rejects(f.manager(async () => { throw denied(code); }).prepare(f), error => {
      assert.equal(error.code, code); assert.equal(error.cause, undefined); assert.equal(error.stdout, undefined); assert.equal(error.stderr, undefined);
      assert(!error.message.includes('fixture')); assert(!error.message.includes('credential')); return true;
    });
  }
  await assert.rejects(f.manager(async () => { throw denied('CLAUDE_KEYCHAIN_UNAVAILABLE', { cleanupCode: 'CLAUDE_KEYCHAIN_CLEANUP_FAILED' }); }).prepare(f), error => {
    assert.equal(error.code, 'CLAUDE_KEYCHAIN_UNAVAILABLE'); assert.match(error.cleanupError, /联系维护者/); return true;
  });
});

test('timeouts and execution failures cannot surface a successful reply or private command', async t => {
  const f = await fixture(t);
  await assert.rejects(f.manager(async () => { throw Object.assign(denied('CLAUDE_KEYCHAIN_MISSING'), { killed: true, stdout: ready(true) }); }).prepare(f), { code: 'CLAUDE_KEYCHAIN_TIMEOUT' });
  await assert.rejects(f.manager(async () => { throw Object.assign(new Error(f.home), { code: 'EACCES' }); }).prepare(f), { code: 'CLAUDE_KEYCHAIN_UNAVAILABLE' });
  await assert.rejects(f.manager(async () => { throw Object.assign(new Error(f.home), { code: 1, stdout: ready(true) }); }).prepare(f), { code: 'CLAUDE_KEYCHAIN_PROTOCOL_ERROR' });
  for (const execute of [async () => ({ stdout: 'truncated reply' }), async () => { throw Object.assign(new Error('fixture'), { code: 1 }); }]) {
    await assert.rejects(f.manager(execute).prepare(f), error => {
      assert.equal(error.code, 'CLAUDE_KEYCHAIN_PROTOCOL_ERROR');
      assert.equal(error.keychainPreparationIncomplete, true);
      assert.match(error.cleanupError, /联系维护者/);
      return true;
    });
  }
});

test('strict reply parsing refuses stale formats, appended output and unrecognized diagnostics', () => {
  for (const value of ['', '{}', 'null', '[]', ready(true) + ready(false), JSON.stringify({ schemaVersion: 1, status: 'ready', changed: false, path: '/private' }),
    JSON.stringify({ schemaVersion: 1, status: 'error', code: 'UNKNOWN', stage: 'scoped-query', osStatus: 0 }), 'x'.repeat(4097)])
    assert.throws(() => parseClaudeKeychainReply(value, true), { code: 'CLAUDE_KEYCHAIN_PROTOCOL_ERROR' });
});

test('duplicate preparations serialize but query again after success or failure', async t => {
  const f = await fixture(t); let release, entered; const firstEntered = new Promise(resolve => { entered = resolve; });
  const gate = new Promise(resolve => { release = resolve; }); let calls = 0, active = 0, maximum = 0;
  const manager = f.manager(async () => {
    active++; maximum = Math.max(maximum, active); const current = ++calls;
    if (current === 1) { entered(); await gate; }
    active--; if (current === 1) throw denied('CLAUDE_KEYCHAIN_LOCKED');
    return { stdout: ready(false) };
  });
  const first = manager.prepare(f), failed = assert.rejects(first, { code: 'CLAUDE_KEYCHAIN_LOCKED' });
  await firstEntered; const second = manager.prepare(f); assert.equal(calls, 1); release();
  await failed; assert.equal((await second).status, 'ready');
  await manager.prepare(f); assert.equal(calls, 3); assert.equal(maximum, 1); assert.equal(manager.pending.size, 0);
});
