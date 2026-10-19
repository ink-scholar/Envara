import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { TerminalSshManager } from '../electron/terminal-ssh-manager.mjs';

const host = 'ssh-fixture.invalid';
const target = { host, port: 2222, user: 'fixture' };
const proxyUrl = 'http://fixture-user:fixture-password@127.0.0.1:12345';
const run = (command, args, options = {}) => new Promise((resolve, reject) => {
  const child = execFile(command, args, { timeout: 5000, encoding: 'utf8', ...options }, (error, stdout, stderr) => {
    if (error) { error.stdout = stdout; error.stderr = stderr; reject(error); } else resolve({ stdout, stderr });
  });
  child.stdin?.end();
});
const code = expected => error => error.code === expected;
const native = { skip: process.platform !== 'darwin' };
const publicKey = seed => {
  const fields = [Buffer.from('ssh-ed25519'), createHash('sha256').update(seed).digest()];
  const bytes = Buffer.concat(fields.flatMap(value => { const length = Buffer.alloc(4); length.writeUInt32BE(value.length); return [length, value]; }));
  return `ssh-ed25519 ${bytes.toString('base64')}`;
};

async function fixture(t, { real = false, passphrase = '', now = Date.now, execute: overrideExecute, spawn } = {}) {
  const root = await realpath(await mkdtemp(path.join(process.platform === 'darwin' ? '/private/tmp' : os.tmpdir(), 'evssh-')));
  const dataDir = path.join(root, 'data'), hostHome = path.join(root, 'host'), keyDirectory = path.join(root, 'keys');
  await Promise.all([dataDir, hostHome, keyDirectory].map(directory => mkdir(directory, { mode: 0o700 })));
  const hostSsh = path.join(hostHome, '.ssh'); await mkdir(hostSsh, { mode: 0o700 });
  const keyPath = path.join(keyDirectory, 'fixture_ed25519'), hostKeyPath = path.join(keyDirectory, 'server_ed25519');
  if (real) {
    await run('/usr/bin/ssh-keygen', ['-q', '-t', 'ed25519', '-N', passphrase, '-C', 'disposable-fixture', '-f', keyPath]);
    await run('/usr/bin/ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'disposable-host', '-f', hostKeyPath]);
  } else {
    await writeFile(keyPath, 'DISPOSABLE PRIVATE FIXTURE - NEVER A REAL KEY\n', { mode: 0o600 });
    await writeFile(`${keyPath}.pub`, `${publicKey('client')} fixture-comment\n`, { mode: 0o644 });
    await writeFile(`${hostKeyPath}.pub`, `${publicKey('server')} fixture-host-comment\n`, { mode: 0o644 });
  }
  const hostPublicKey = (await readFile(`${hostKeyPath}.pub`, 'utf8')).trim().split(/\s+/).slice(0, 2).join(' ');
  const knownHosts = path.join(hostSsh, 'known_hosts');
  await writeFile(knownHosts, `[${host}]:2222 ${hostPublicKey}\n`, { mode: 0o600 });
  const calls = [], managers = [];
  const execute = overrideExecute ?? (real ? run : async (command, args, options) => {
    calls.push({ command, args, options });
    if (command === '/usr/bin/ssh' && args[0] === '-V') return { stdout: '', stderr: 'OpenSSH_10.3p1' };
    if (command === '/usr/bin/ssh-keygen' && args[0] === '-F') {
      const text = await readFile(args[3], 'utf8');
      const matches = text.split('\n').filter(line => line.split(/\s+/).includes(args[1]));
      if (!matches.length) throw new Error('No matching fixture trust');
      return { stdout: matches.join('\n') + '\n', stderr: '' };
    }
    throw new Error(`Unexpected native command ${command}`);
  });
  const nodeExecutable = await realpath(process.execPath);
  const options = { dataDir, hostHome, nodeExecutable, agentRoot: path.join(root, 'agents'), platform: 'darwin', execute, now, ...(spawn ? { spawn } : {}) };
  const createManager = (extra = {}) => { const manager = new TerminalSshManager({ ...options, ...extra }); managers.push(manager); return manager; };
  const manager = createManager();
  t.after(async () => { await Promise.allSettled(managers.map(value => value.close())); await rm(root, { recursive: true, force: true }); });
  await manager.ready;
  const select = (extra = {}) => manager.prepareIdentity({ id: 'profile-a', ...target, keyPath, ...extra });
  const save = async (extra = {}) => manager.save({ id: extra.id ?? 'profile-a', name: extra.name ?? 'Fixture server', selectionToken: (await select(extra)).selectionToken });
  const session = (extra = {}) => manager.createSession({ profileId: 'profile-a', sessionId: 'session-a', directories: { home: hostHome }, proxyUrl, ...extra });
  return { root, dataDir, hostHome, hostSsh, keyDirectory, keyPath, hostKeyPath, hostPublicKey, knownHosts, manager, createManager, calls, select, save, session, nodeExecutable };
}

test('selection is redacted, profile-bound, single-use, and persisted outside profile exports', async t => {
  const f = await fixture(t);
  const selected = await f.select();
  assert.match(selected.selectionToken, /^sshsel_[a-f0-9]{48}$/);
  assert.match(selected.keyFingerprint, /^SHA256:/);
  assert.equal(selected.keyLabel, 'fixture_ed25519');
  assert.ok(!JSON.stringify(selected).includes(f.keyDirectory));
  await assert.rejects(f.manager.save({ id: 'profile-b', name: 'Fixture server', selectionToken: selected.selectionToken }), code('SSH_SELECTION_MISMATCH'));
  const saved = await f.manager.save({ id: 'profile-a', name: '  Fixture server  ', selectionToken: selected.selectionToken });
  assert.equal(saved.name, 'Fixture server');
  assert.match(saved.alias, /^envara-[a-f0-9]{12}$/);
  assert.ok(!JSON.stringify(saved).includes(f.keyDirectory));
  assert.deepEqual(await f.manager.list({ id: 'profile-a' }), { supported: true, connections: [saved] });
  assert.deepEqual(await f.manager.list({ id: 'profile-b' }), { supported: true, connections: [] });
  await assert.rejects(f.manager.save({ id: 'profile-a', name: 'Replay', selectionToken: selected.selectionToken }), code('SSH_SELECTION_EXPIRED'));
  assert.equal((await lstat(f.manager.filename)).mode & 0o777, 0o600);
  assert.equal(f.manager.root, path.join(f.dataDir, 'terminal', 'ssh-access'));
  const reopened = f.createManager(); await reopened.ready;
  assert.deepEqual(await reopened.list({ id: 'profile-a' }), { supported: true, connections: [saved] });
  const duplicate = await f.select();
  await assert.rejects(f.manager.save({ id: 'profile-a', name: 'Ｆｉｘｔｕｒｅ server', selectionToken: duplicate.selectionToken }), code('SSH_NAME_EXISTS'));
  await f.manager.remove({ id: 'profile-a', connectionId: saved.id });
  assert.equal((await f.manager.list({ id: 'profile-a' })).connections.length, 0);
  assert.ok((await lstat(f.keyPath)).isFile());
});

test('selection expires and failed persistence retains the selection and previous records', async t => {
  let time = 1000;
  const f = await fixture(t, { now: () => time });
  const expired = await f.select(); time += 30 * 60 * 1000;
  await assert.rejects(f.manager.save({ id: 'profile-a', name: 'Expired', selectionToken: expired.selectionToken }), code('SSH_SELECTION_EXPIRED'));
  const saved = await f.save();
  const previous = await readFile(f.manager.filename, 'utf8');
  const selected = await f.select();
  await chmod(f.manager.filename, 0o644);
  await assert.rejects(f.manager.save({ id: 'profile-a', name: 'Second', selectionToken: selected.selectionToken }), code('SSH_UNSAFE_PATH'));
  assert.equal(await readFile(f.manager.filename, 'utf8'), previous);
  assert.deepEqual((await f.manager.list({ id: 'profile-a' })).connections, [saved]);
  await chmod(f.manager.filename, 0o600);
  await f.manager.save({ id: 'profile-a', name: 'Second', selectionToken: selected.selectionToken });
  assert.equal((await f.manager.list({ id: 'profile-a' })).connections.length, 2);
});

test('rejects unsafe private paths, hardlinks, permissive modes and missing public counterparts', async t => {
  const f = await fixture(t);
  for (const keyPath of ['relative-key', `${f.keyDirectory}/./fixture_ed25519`, `${f.keyDirectory}/../keys/fixture_ed25519`]) {
    await assert.rejects(f.select({ keyPath }), code('SSH_UNSAFE_PATH'));
  }
  await chmod(f.keyPath, 0o644); await assert.rejects(f.select(), code('SSH_UNSAFE_PATH')); await chmod(f.keyPath, 0o600);
  const hard = path.join(f.keyDirectory, 'hard'); await link(f.keyPath, hard);
  await assert.rejects(f.select(), code('SSH_UNSAFE_PATH')); await rm(hard);
  const linked = path.join(f.root, 'linked-key'); await symlink(f.keyPath, linked);
  await assert.rejects(f.select({ keyPath: linked }), code('SSH_UNSAFE_PATH'));
  const linkedDirectory = path.join(f.root, 'linked-keys'); await symlink(f.keyDirectory, linkedDirectory);
  await assert.rejects(f.select({ keyPath: path.join(linkedDirectory, 'fixture_ed25519') }), code('SSH_UNSAFE_PATH'));
  await rm(`${f.keyPath}.pub`); await assert.rejects(f.select(), code('SSH_PUBLIC_KEY_REQUIRED'));
  await writeFile(`${f.keyPath}.pub`, 'not a public key\n', { mode: 0o644 }); await assert.rejects(f.select(), code('SSH_KEY_INVALID'));
  assert.ok(f.calls.every(value => value.command !== '/usr/bin/ssh-add'));
});

test('requires existing exact host trust and refuses changed, revoked or CA host records', async t => {
  const f = await fixture(t);
  await assert.rejects(f.select({ port: 22 }), code('SSH_HOST_UNTRUSTED'));
  const selected = await f.select();
  await writeFile(f.knownHosts, `[${host}]:2222 ${publicKey('changed-server')}\n`);
  await assert.rejects(f.manager.save({ id: 'profile-a', name: 'Changed', selectionToken: selected.selectionToken }), code('SSH_IDENTITY_CHANGED'));
  for (const marker of ['@revoked', '@cert-authority']) {
    await writeFile(f.knownHosts, `${marker} [${host}]:2222 ${f.hostPublicKey}\n`);
    await assert.rejects(f.select(), code('SSH_HOST_UNTRUSTED'));
  }
  assert.equal((await f.manager.list({ id: 'profile-a' })).connections.length, 0);
});

test('revalidates key inode and public identity before saving and all saved keys before launch', async t => {
  const f = await fixture(t);
  const selected = await f.select();
  await rename(f.keyPath, `${f.keyPath}.original`);
  await writeFile(f.keyPath, 'DISPOSABLE PRIVATE FIXTURE - NEVER A REAL KEY\n', { mode: 0o600 });
  await assert.rejects(f.manager.save({ id: 'profile-a', name: 'Replaced', selectionToken: selected.selectionToken }), code('SSH_IDENTITY_CHANGED'));
  await f.save();
  await writeFile(`${f.keyPath}.pub`, `${publicKey('changed-client')}\n`);
  await assert.rejects(f.session(), code('SSH_IDENTITY_CHANGED'));
  assert.equal(f.manager.sessions.size, 0);
});

test('protects selected keys across environments without starting an agent for empty environments', async t => {
  const f = await fixture(t, { spawn: () => { throw new Error('Must not start an agent'); } });
  await f.save();
  const secondKey = path.join(f.keyDirectory, 'other-key');
  await writeFile(secondKey, 'DISPOSABLE SECOND FIXTURE\n', { mode: 0o600 });
  await writeFile(`${secondKey}.pub`, `${publicKey('second-client')}\n`, { mode: 0o644 });
  await f.select({ id: 'profile-b', keyPath: secondKey });
  const session = await f.session({ profileId: 'profile-c' });
  assert.equal(session.binDirectory, null); assert.equal(session.agentSocket, null); assert.deepEqual(session.environment, {});
  for (const protectedPath of [f.hostSsh, f.manager.root, f.manager.agentRoot, f.keyPath, secondKey]) assert.ok(session.protectedPaths.includes(protectedPath));
  await session.dispose();
  await assert.rejects(f.session({ proxyUrl: 'http://127.0.0.1:12345' }), code('SSH_PROXY_REQUIRED'));
  await f.manager.removeProfile({ id: 'profile-b' });
  assert.ok(!f.manager.protection().protectedPaths.includes(secondKey));
});

test('unsupported platforms do not touch disk or execute native commands', async () => {
  const manager = new TerminalSshManager({ dataDir: path.join(os.tmpdir(), 'nonexistent-envara-fixture'), hostHome: path.join(os.tmpdir(), 'nonexistent-envara-host'), platform: 'win32',
    execute: () => { throw new Error('Must not execute'); }, spawn: () => { throw new Error('Must not spawn'); } });
  await manager.ready;
  assert.deepEqual(await manager.list({ id: 'profile-a' }), { supported: false, connections: [] });
  await assert.rejects(manager.prepareIdentity({ id: 'profile-a', ...target, keyPath: '/no-key' }), code('SSH_UNSUPPORTED'));
  const session = await manager.createSession({ profileId: 'profile-a', sessionId: 'session-a' });
  assert.deepEqual(session.environment, {});
  await manager.close();
});

test('corrupt metadata or permissive store modes fail closed without replacing the store', async t => {
  const f = await fixture(t); await f.save();
  const original = await readFile(f.manager.filename, 'utf8');
  await chmod(f.manager.filename, 0o644);
  await assert.rejects(f.createManager().ready, code('SSH_STORAGE_INVALID'));
  await chmod(f.manager.filename, 0o600);
  const document = JSON.parse(original); document.profiles[0].connections[0].keyFingerprint = 'SHA256:wrong';
  const corrupted = JSON.stringify(document); await writeFile(f.manager.filename, corrupted);
  await assert.rejects(f.createManager().ready, code('SSH_STORAGE_INVALID'));
  assert.equal(await readFile(f.manager.filename, 'utf8'), corrupted);
});

test('native agent holds only the chosen identity, refuses unconstrained signing and emits secret-free runtime files', native, async t => {
  const f = await fixture(t, { real: true }); const saved = await f.save();
  const session = await f.session();
  const publicDirectory = path.dirname(session.binDirectory), config = path.join(publicDirectory, 'config');
  assert.equal(session.allowedAgentSocket, session.agentSocket);
  assert.deepEqual(session.readOnlyPaths, [publicDirectory]);
  assert.deepEqual(session.readablePaths, [publicDirectory]);
  assert.equal((await lstat(publicDirectory)).mode & 0o777, 0o500);
  const agentEnv = f.manager.nativeEnvironment(publicDirectory, session.agentSocket);
  const loaded = await run('/usr/bin/ssh-add', ['-L'], { env: agentEnv });
  assert.match(loaded.stdout, /^ssh-ed25519 /); assert.equal(loaded.stdout.trim().split('\n').length, 1);
  const publicFile = path.join(publicDirectory, `${saved.id}.pub`);
  await assert.rejects(run('/usr/bin/ssh-add', ['-T', publicFile], { env: agentEnv }), error => /agent refused operation/.test(error.stderr));
  const parsed = await run('/usr/bin/ssh', ['-G', '-F', config, saved.alias], { env: agentEnv });
  assert.match(parsed.stdout, new RegExp(`^hostname ${host.replaceAll('.', '\\.')}$$`, 'm'));
  for (const required of ['stricthostkeychecking true', 'identitiesonly yes', 'forwardagent no', 'batchmode yes', 'passwordauthentication no', 'controlmaster false']) assert.ok(parsed.stdout.includes(required), required);
  for (const entry of await readdir(publicDirectory, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const filename = path.join(publicDirectory, entry.name), text = await readFile(filename, 'utf8');
    assert.equal((await lstat(filename)).mode & 0o777, 0o400);
    assert.ok(!text.includes(proxyUrl)); assert.ok(!text.includes(f.keyPath)); assert.ok(!text.includes('PRIVATE KEY'));
  }
  const targets = JSON.parse(await readFile(session.environment.ENVARA_SSH_TARGETS, 'utf8'));
  assert.deepEqual(targets, [{ host, port: 2222 }]);
  for (const args of [['-F', '/dev/null', saved.alias], ['-o', 'ProxyCommand=anything', saved.alias], ['-i', f.keyPath, saved.alias], ['unknown-alias']]) {
    await assert.rejects(run(path.join(session.binDirectory, 'ssh'), args, { env: { ...agentEnv, ...session.environment } }), error => error.code === 2 && /Custom connection options/.test(error.stderr));
  }
  await assert.rejects(f.manager.remove({ id: 'profile-a', connectionId: saved.id }), code('SSH_CONNECTION_IN_USE'));
  const directory = path.dirname(publicDirectory); await session.dispose(); await session.dispose();
  await assert.rejects(lstat(directory), { code: 'ENOENT' });
  await assert.rejects(run('/usr/bin/ssh-add', ['-L'], { env: agentEnv }));
  await f.manager.remove({ id: 'profile-a', connectionId: saved.id });
});

test('a single native identity retains constraints for every saved destination', native, async t => {
  const f = await fixture(t, { real: true });
  await f.save();
  await writeFile(f.knownHosts, `[${host}]:2222 ${f.hostPublicKey}\n[second-fixture.invalid]:2200 ${f.hostPublicKey}\n`);
  await f.save({ name: 'Second fixture', host: 'second-fixture.invalid', port: 2200, user: 'other' });
  const calls = [], execute = f.manager.execute;
  f.manager.execute = async (command, args, options) => { calls.push({ command, args, options }); return execute(command, args, options); };
  const session = await f.session();
  const additions = calls.filter(value => value.command === '/usr/bin/ssh-add' && value.args.includes('-q'));
  assert.equal(additions.length, 1); assert.equal(additions[0].args.filter(value => value === '-h').length, 2);
  assert.equal(additions[0].options.env.SSH_AUTH_SOCK, session.agentSocket);
  assert.equal(additions[0].options.env.SSH_ASKPASS_REQUIRE, 'never');
  assert.equal(Object.hasOwn(additions[0].options.env, 'DISPLAY'), false);
  await session.dispose();
});

test('encrypted native keys fail without prompting, retain stored connections, and clean the owned agent', native, async t => {
  const f = await fixture(t, { real: true, passphrase: 'disposable-fixture-passphrase' }); const saved = await f.save();
  await assert.rejects(f.session(), code('SSH_KEY_LOCKED'));
  assert.equal(f.manager.sessions.size, 0);
  assert.deepEqual(await readdir(f.manager.agentRoot), []);
  assert.deepEqual((await f.manager.list({ id: 'profile-a' })).connections, [saved]);
  assert.ok((await lstat(f.keyPath)).isFile());
});

test('native mismatched private and public counterparts never return a usable session', native, async t => {
  const f = await fixture(t, { real: true });
  await writeFile(`${f.keyPath}.pub`, await readFile(`${f.hostKeyPath}.pub`));
  await f.save();
  await assert.rejects(f.session(), code('SSH_IDENTITY_CHANGED'));
  assert.equal(f.manager.sessions.size, 0); assert.deepEqual(await readdir(f.manager.agentRoot), []);
});

test('revoked host trust is checked again before native agent startup', native, async t => {
  const f = await fixture(t, { real: true }); await f.save();
  await writeFile(f.knownHosts, `@revoked [${host}]:2222 ${f.hostPublicKey}\n`);
  let spawned = false; f.manager.spawn = () => { spawned = true; throw new Error('Must not spawn'); };
  await assert.rejects(f.session(), code('SSH_HOST_UNTRUSTED'));
  assert.equal(spawned, false); assert.equal(f.manager.sessions.size, 0);
});

test('cleanup refuses substituted directories and can retry without changing unrelated permissions', native, async t => {
  const f = await fixture(t, { real: true }); await f.save(); const session = await f.session();
  const publicDirectory = path.dirname(session.binDirectory), savedDirectory = `${publicDirectory}-owned`, outside = path.join(f.root, 'outside');
  await mkdir(outside, { mode: 0o500 }); await rename(publicDirectory, savedDirectory); await symlink(outside, publicDirectory);
  await assert.rejects(session.dispose(), code('SSH_CLEANUP_FAILED'));
  assert.equal((await lstat(outside)).mode & 0o777, 0o500);
  assert.equal(f.manager.sessions.size, 1);
  await rm(publicDirectory); await rename(savedDirectory, publicDirectory); await session.dispose();
  assert.equal(f.manager.sessions.size, 0);
  assert.equal((await lstat(outside)).mode & 0o777, 0o500);
});

test('close during agent loading cancels setup, waits for cleanup and cannot return a live lease', native, async t => {
  const f = await fixture(t, { real: true }); await f.save();
  const execute = f.manager.execute; let entered, release;
  const reached = new Promise(resolve => { entered = resolve; });
  const barrier = new Promise(resolve => { release = resolve; });
  f.manager.execute = async (command, args, options) => {
    if (command === '/usr/bin/ssh-add' && args.includes('-q')) { entered(); await barrier; }
    return execute(command, args, options);
  };
  const setup = f.session(); const rejected = assert.rejects(setup, code('SSH_SESSION_CLOSED'));
  await reached; const closed = f.manager.close(); release(); await rejected; await closed;
  assert.equal(f.manager.sessions.size, 0); assert.deepEqual(await readdir(f.manager.agentRoot), []);
  await f.manager.close();
});
