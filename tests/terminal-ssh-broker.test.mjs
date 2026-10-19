import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, mkdir, writeFile, readFile, readdir, realpath, rm, lstat } from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import { PassThrough, Writable } from 'node:stream';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { createPasswordSshBroker } from '../electron/terminal-ssh-broker.mjs';
import { runSshAskpass } from '../electron/terminal-ssh-askpass.mjs';

const connection = { id: 'ssh_fixture', alias: 'envara-abcdef123456', name: 'Owned fixture', host: 'ssh-fixture.invalid', port: 2222, user: 'fixture' };
const secret = 'synthetic-password-for-owned-tests';
const session = connections => ({ schema: 'envara.ssh-session', version: 2, connections,
  expiresAt: connections.some(record => record.expiresAt === null) ? null : Math.max(...connections.map(record => record.expiresAt)) });
const capture = () => { const chunks = []; return { chunks, stream: new Writable({ write(chunk, _encoding, done) { chunks.push(Buffer.from(chunk)); done(); } }), text: () => Buffer.concat(chunks).toString() }; };
async function waitFor(predicate, message = 'condition', timeout = 1500) {
  const deadline = Date.now() + timeout;
  while (!predicate()) { if (Date.now() > deadline) throw new Error(`Timed out waiting for ${message}`); await delay(5); }
}
async function fixture(t, overrides = {}) {
  const root = await mkdtemp(path.join(await realpath('/tmp'), 'evsb-'));
  const directory = path.join(root, 'lease'), publicDirectory = path.join(directory, 'public');
  await mkdir(publicDirectory, { recursive: true, mode: 0o700 });
  const configPath = path.join(publicDirectory, 'config'), targetsPath = path.join(publicDirectory, 'targets.json');
  await writeFile(configPath, 'Host synthetic\n', { mode: 0o400 });
  await writeFile(targetsPath, JSON.stringify([{ host: connection.host, port: connection.port }]), { mode: 0o400 });
  let clock = Date.now(), elapsed = 0, active = true, broker;
  t.after(async () => { await broker?.dispose(); await rm(root, { recursive: true, force: true }); });
  const children = [], wrapped = [], closed = [];
  const makeChild = (tty = false) => {
    const child = new EventEmitter(); child.pid = 20000 + children.length; child.fd = 100 + children.length; child.writes = []; child.resizes = [];
    child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.stdin = new PassThrough();
    child.stdin.on('data', value => child.writes.push(Buffer.from(value)));
    child.pause = () => { child.paused = true; }; child.resume = () => { child.paused = false; };
    child.write = data => child.writes.push(Buffer.from(data)); child.resize = (...args) => child.resizes.push(args);
    child.onData = handler => { child.on('data', handler); return { dispose: () => child.off('data', handler) }; };
    child.onExit = handler => { child.on('pty-exit', handler); return { dispose: () => child.off('pty-exit', handler) }; };
    child.finish = (code = 0, signal) => {
      if (child.finished) return; child.finished = true;
      child.stdout.end(); child.stderr.end(); child.stdin.end();
      child.emit(tty ? 'pty-exit' : 'close', ...(tty ? [{ exitCode: code, signal }] : [code, signal]));
    };
    child.kill = signal => child.finish(255, signal); children.push(child); return child;
  };
  const options = { directory, publicDirectory, configPath, targetsPath, nodeExecutable: await realpath(process.execPath),
    proxyUrl: 'http://fixture:synthetic-proxy-secret@127.0.0.1:49152', now: () => clock, monotonicNow: () => elapsed,
    expiresAt: clock + 3600000, isActive: () => active,
    manifest: { schema: 'envara.ssh-session', version: 1, expiresAt: clock + 3600000, connections: [connection] },
    passwords: new Map([[connection.alias, Buffer.from(secret)]]),
    fence: { wrap: async (command, settings) => { wrapped.push({ command, settings }); return { ...command, sshPrivateKeyProtection: true, deviceIdentifierRestrictions: true }; } },
    spawn: (file, args, settings) => { const child = makeChild(); child.launch = { file, args, settings }; return child; },
    ptyFactory: (file, args, settings) => { const child = makeChild(true); child.launch = { file, args, settings }; return child; },
    writePty: async (fd, buffer, offset) => { const child = children.find(item => item.fd === fd); child.writes.push(Buffer.from(buffer.subarray(offset))); return buffer.length - offset; },
    processControl: { capture: async pid => ({ pid }), close: async ({ pty, identity }) => { assert.equal(pty.pid, identity.pid); closed.push(pty.pid); pty.kill('SIGTERM'); return { ok: true }; } },
    ...overrides,
  };
  broker = await createPasswordSshBroker(options);
  return { root, directory, publicDirectory, broker, options, children, wrapped, closed,
    advance: milliseconds => { clock += milliseconds; }, advanceMonotonic: milliseconds => { elapsed += milliseconds; },
    revoke: () => { active = false; } };
}
async function connect(f, argv = [connection.alias, 'id'], extra = {}) {
  const channel = net.createConnection({ path: f.broker.socket }), frames = []; let buffer = '';
  channel.on('error', () => {});
  channel.on('data', chunk => { buffer += chunk; while (buffer.includes('\n')) { const i = buffer.indexOf('\n'); frames.push(JSON.parse(buffer.slice(0, i))); buffer = buffer.slice(i + 1); } });
  await new Promise((resolve, reject) => { channel.once('connect', resolve); channel.once('error', reject); });
  const send = frame => channel.write(`${JSON.stringify(frame)}\n`);
  send({ type: 'start', version: 1, argv, tty: false, cols: 80, rows: 24, ...extra });
  return { channel, frames, send };
}
async function askpass(f, index = 0) {
  const output = capture(), environment = f.wrapped[index].command.environment;
  const code = await runSshAskpass({ socket: environment.ENVARA_SSH_ASKPASS_SOCKET,
    token: environment.ENVARA_SSH_ASKPASS_TOKEN, output: output.stream });
  return { code, text: output.text() };
}

test('broker reparses authorization, launches fixed password-only SSH and delivers its secret only once', async t => {
  const f = await fixture(t), c = await connect(f);
  await waitFor(() => c.frames[0]?.type === 'ready');
  assert.equal(f.children.length, 1);
  const child = f.children[0], { command, settings } = f.wrapped[0];
  assert.equal(command.executable, '/usr/bin/ssh');
  assert.deepEqual(command.args.slice(-4), ['-T', '--', connection.alias, 'id']);
  for (const setting of ['PreferredAuthentications=password', 'NumberOfPasswordPrompts=1', 'KbdInteractiveAuthentication=no',
    'StrictHostKeyChecking=yes', 'PermitLocalCommand=no', 'EscapeChar=none', 'ControlPath=none']) assert.ok(command.args.includes(setting));
  assert.equal(command.environment.SSH_ASKPASS_REQUIRE, 'force');
  assert.equal(settings.restrictDeviceIdentifiers, true);
  assert.deepEqual(settings.sshProtection.allowedSockets, [path.join(f.directory, 'auth.sock')]);
  assert.doesNotMatch(JSON.stringify(command), new RegExp(secret));
  assert.equal((await lstat(f.broker.socket)).mode & 0o777, 0o600);
  // The caller may erase its own grant as soon as the factory returns.
  f.options.passwords.get(connection.alias).fill(0);
  const output = capture();
  assert.equal(await runSshAskpass({ socket: command.environment.ENVARA_SSH_ASKPASS_SOCKET,
    token: command.environment.ENVARA_SSH_ASKPASS_TOKEN, output: output.stream }), 0);
  assert.equal(output.text(), `${secret}\n`);
  const repeated = capture();
  assert.equal(await runSshAskpass({ socket: command.environment.ENVARA_SSH_ASKPASS_SOCKET,
    token: command.environment.ENVARA_SSH_ASKPASS_TOKEN, output: repeated.stream }), 1);
  assert.equal(repeated.text(), '');
  for (const name of await readdir(f.directory)) {
    const info = await lstat(path.join(f.directory, name));
    if (info.isFile()) assert.ok(!(await readFile(path.join(f.directory, name))).includes(secret));
  }
  child.stdout.write(Buffer.from([0, 1, 255, 10])); child.stderr.write('fixture-stderr');
  c.send({ type: 'stdin', data: Buffer.from('fixture-stdin').toString('base64') });
  c.send({ type: 'eof' });
  await waitFor(() => child.stdin.writableEnded);
  child.finish(17);
  await waitFor(() => c.frames.some(frame => frame.type === 'exit'));
  assert.deepEqual(c.frames.filter(frame => frame.type === 'stdout').map(frame => Buffer.from(frame.data, 'base64')), [Buffer.from([0, 1, 255, 10])]);
  assert.equal(Buffer.concat(c.frames.filter(frame => frame.type === 'stderr').map(frame => Buffer.from(frame.data, 'base64'))).toString(), 'fixture-stderr');
  assert.equal(Buffer.concat(child.writes).toString(), 'fixture-stdin');
  assert.equal(c.frames.at(-1).code, 17); assert.equal(f.closed.length, 1);
  assert.doesNotMatch(JSON.stringify(c.frames), new RegExp(secret));
});

test('untrusted arguments, wrong targets, extra start authority and non-password aliases never spawn', async t => {
  const f = await fixture(t);
  for (const [argv, extra] of [
    [['-oProxyCommand=untrusted', connection.alias], {}], [['other@ssh-fixture.invalid', '-p2222'], {}],
    [[connection.alias], { environment: { SSH_ASKPASS: '/untrusted' } }], [['help'], {}],
  ]) {
    const c = await connect(f, argv, extra);
    await waitFor(() => c.frames.some(frame => frame.type === 'error'));
    assert.equal(f.children.length, 0); c.channel.destroy();
  }
});

test('interactive requests use a main-owned PTY while all password input stays on askpass IPC', async t => {
  const f = await fixture(t), c = await connect(f, [connection.alias], { tty: true, cols: 101, rows: 37 });
  await waitFor(() => c.frames[0]?.type === 'ready');
  const child = f.children[0];
  assert.equal(child.launch.settings.cols, 101); assert.equal(child.launch.settings.rows, 37);
  assert.ok(child.launch.args.includes('-tt'));
  c.send({ type: 'resize', cols: 120, rows: 45 }); c.send({ type: 'stdin', data: Buffer.from('id\r').toString('base64') });
  c.send({ type: 'signal', signal: 'SIGINT' });
  await waitFor(() => child.writes.length === 2);
  assert.deepEqual(child.resizes, [[120, 45]]); assert.equal(Buffer.concat(child.writes).toString(), 'id\r\x03');
  assert.doesNotMatch(Buffer.concat(child.writes).toString(), new RegExp(secret));
  child.emit('data', 'fixture-shell-output'); child.finish();
  await waitFor(() => c.frames.some(frame => frame.type === 'exit'));
});

test('malformed input and client disconnect terminate only the registered owned run', async t => {
  const f = await fixture(t), first = await connect(f), second = await connect(f);
  await waitFor(() => first.frames[0]?.type === 'ready' && second.frames[0]?.type === 'ready');
  first.send({ type: 'stdin', data: 'not base64!' });
  await waitFor(() => f.children[0].finished);
  assert.equal(f.children[1].finished, undefined);
  second.channel.destroy();
  await waitFor(() => f.children[1].finished);
  assert.equal(new Set(f.closed).size, 2);
});

test('concurrency is bounded and a revoked lifecycle closes the broker and all owned runs', async t => {
  const f = await fixture(t), channels = await Promise.all(Array.from({ length: 4 }, () => connect(f)));
  await waitFor(() => channels.every(client => client.frames[0]?.type === 'ready'));
  const excess = await connect(f);
  await waitFor(() => excess.frames.some(frame => frame.code === 'SSH_BROKER_BUSY'));
  assert.equal(f.children.length, 4);
  f.revoke();
  await waitFor(() => f.children.every(child => child.finished), 'owned run cleanup', 2000);
  await waitFor(() => channels.every(client => client.channel.destroyed));
  await f.broker.dispose(); await assert.rejects(lstat(f.broker.socket), { code: 'ENOENT' });
});

test('legacy authorization expiry blocks new authentication while established pipe and PTY IO keep working', async t => {
  const f = await fixture(t), pipe = await connect(f), terminal = await connect(f, ['-t', connection.alias]);
  await waitFor(() => pipe.frames[0]?.type === 'ready' && terminal.frames[0]?.type === 'ready');
  assert.deepEqual(await askpass(f), { code: 0, text: `${secret}\n` });
  f.advance(3600000);
  const expired = await connect(f);
  await waitFor(() => expired.frames.some(frame => frame.code === 'SSH_AUTHORIZATION_EXPIRED'));
  assert.deepEqual(await askpass(f, 1), { code: 1, text: '' });
  // Observing expiry permanently erases this authorization, even if the wall
  // clock then moves backwards before the periodic sweep sees it.
  f.advance(-3600000);
  const rolledBack = await connect(f);
  await waitFor(() => rolledBack.frames.some(frame => frame.code === 'SSH_AUTHORIZATION_EXPIRED'));
  await delay(300);
  assert.equal(f.children.length, 2); assert.equal(f.closed.length, 0);
  assert.equal(pipe.channel.destroyed, false); assert.equal(terminal.channel.destroyed, false);
  f.children[0].stdout.write('still-connected'); f.children[1].emit('data', 'still-interactive');
  pipe.send({ type: 'stdin', data: Buffer.from('after-expiry').toString('base64') }); pipe.send({ type: 'eof' });
  terminal.send({ type: 'resize', cols: 120, rows: 40 });
  terminal.send({ type: 'stdin', data: Buffer.from('pwd\r').toString('base64') });
  terminal.send({ type: 'signal', signal: 'SIGINT' }); terminal.send({ type: 'eof' });
  await waitFor(() => f.children[0].stdin.writableEnded && f.children[1].writes.length === 3);
  assert.equal(Buffer.concat(f.children[0].writes).toString(), 'after-expiry');
  assert.equal(Buffer.concat(f.children[1].writes).toString(), 'pwd\r\x03\x04');
  assert.deepEqual(f.children[1].resizes, [[120, 40]]);
  await waitFor(() => pipe.frames.some(frame => frame.type === 'stdout') && terminal.frames.some(frame => frame.type === 'stdout'));
  f.children[0].finish(17); terminal.send({ type: 'cancel' });
  await waitFor(() => pipe.frames.some(frame => frame.type === 'exit') && terminal.frames.some(frame => frame.type === 'exit'));
  assert.equal(pipe.frames.at(-1).code, 17); assert.equal(terminal.frames.at(-1).code, 255);
  assert.equal(f.closed.length, 2);
});

test('application-lifetime password authorization survives elapsed time and an unrelated public-key deadline', async t => {
  const key = { ...connection, id: 'ssh_key', alias: 'envara-123456abcdef', authType: 'publickey', expiresAt: Date.now() + 1000 };
  const f = await fixture(t, { expiresAt: null, manifest: session([{ ...connection, authType: 'password', expiresAt: null }, key]) });
  const first = await connect(f); await waitFor(() => first.frames[0]?.type === 'ready');
  f.advance(10 * 365 * 86400000); f.advanceMonotonic(10 * 365 * 86400000);
  await delay(300);
  assert.equal(f.children[0].finished, undefined); assert.equal(first.channel.destroyed, false);
  const second = await connect(f); await waitFor(() => second.frames[0]?.type === 'ready');
  assert.deepEqual(await askpass(f, 1), { code: 0, text: `${secret}\n` });
  const keyRequest = await connect(f, [key.alias]);
  await waitFor(() => keyRequest.frames.some(frame => frame.code === 'SSH_TARGET_NOT_AUTHORIZED'));
  f.revoke(); await waitFor(() => f.children.every(child => child.finished));
});

test('a finite password alias expires independently of another application-lifetime password alias', async t => {
  const finite = { ...connection, authType: 'password', expiresAt: Date.now() + 5000 };
  const unlimited = { ...connection, id: 'ssh_second', alias: 'envara-123456abcdef', authType: 'password', expiresAt: null };
  const f = await fixture(t, { expiresAt: null, manifest: session([finite, unlimited]),
    passwords: new Map([[finite.alias, Buffer.from(secret)], [unlimited.alias, Buffer.from('synthetic-second')]]) });
  const first = await connect(f); await waitFor(() => first.frames[0]?.type === 'ready');
  f.advance(6000);
  const expired = await connect(f); await waitFor(() => expired.frames.some(frame => frame.code === 'SSH_AUTHORIZATION_EXPIRED'));
  assert.deepEqual(await askpass(f), { code: 1, text: '' });
  const second = await connect(f, [unlimited.alias]); await waitFor(() => second.frames[0]?.type === 'ready');
  assert.deepEqual(await askpass(f, 1), { code: 0, text: 'synthetic-second\n' });
  assert.equal(f.children[0].finished, undefined); assert.equal(first.channel.destroyed, false);
  assert.equal(f.closed.length, 0);
});

test('application-lifetime authorization retains the separate thirty-second askpass capability limit', async t => {
  for (const elapsedClock of ['advance', 'advanceMonotonic']) {
    const f = await fixture(t, { expiresAt: null, manifest: session([{ ...connection, authType: 'password', expiresAt: null }]) });
    const c = await connect(f); await waitFor(() => c.frames[0]?.type === 'ready');
    f[elapsedClock](30000);
    assert.deepEqual(await askpass(f), { code: 1, text: '' });
    assert.equal(f.children[0].finished, undefined);
  }
});

test('askpass rechecks its capability deadline after asynchronous process capture', async t => {
  let releaseCapture;
  const captured = new Promise(resolve => { releaseCapture = resolve; });
  const f = await fixture(t, { expiresAt: null, manifest: session([{ ...connection, authType: 'password', expiresAt: null }]),
    processControl: { capture: async pid => { await captured; return { pid }; },
      close: async ({ pty }) => { pty.kill('SIGTERM'); return { ok: true }; } } });
  const c = await connect(f); await waitFor(() => f.children.length === 1);
  const pending = askpass(f); await delay(20);
  f.advanceMonotonic(30000); releaseCapture();
  assert.deepEqual(await pending, { code: 1, text: '' });
  await waitFor(() => c.frames[0]?.type === 'ready');
  assert.equal(f.children[0].finished, undefined);
});

test('finite authorization expiry closes pending askpass and prevents startup from completing after capture', async t => {
  let releaseCapture;
  const captured = new Promise(resolve => { releaseCapture = resolve; });
  const f = await fixture(t, { processControl: { capture: async pid => { await captured; return { pid }; },
    close: async ({ pty }) => { pty.kill('SIGTERM'); return { ok: true }; } } });
  const c = await connect(f); await waitFor(() => f.children.length === 1);
  const pending = askpass(f); await delay(20);
  f.advance(3600000);
  // The periodic sweep must cancel a pending credential response even when
  // native identity capture has not returned yet.
  assert.deepEqual(await pending, { code: 1, text: '' });
  releaseCapture();
  await waitFor(() => c.frames.some(frame => frame.code === 'SSH_AUTHORIZATION_EXPIRED'));
  await waitFor(() => f.children[0].finished);
  assert.equal(c.frames.some(frame => frame.type === 'ready'), false);
});

test('factory validation compares only password deadlines while preserving the complete v2 manifest', async t => {
  const expiresAt = Date.now() + 3600000;
  const password = { ...connection, authType: 'password', expiresAt };
  const key = { ...connection, id: 'ssh_key', alias: 'envara-123456abcdef', authType: 'publickey', expiresAt: null };
  const f = await fixture(t, { expiresAt, manifest: session([password, key]) });
  const c = await connect(f); await waitFor(() => c.frames[0]?.type === 'ready');
  assert.deepEqual(await askpass(f), { code: 0, text: `${secret}\n` });
  await assert.rejects(fixture(t, { expiresAt: null, manifest: session([password, key]) }), { code: 'SSH_AUTHORIZATION_EXPIRED' });
});

test('cleanup failures retain disposal authority and later retry can close the same owned process', async t => {
  let attempts = 0;
  const f = await fixture(t, { processControl: { capture: async pid => ({ pid }), close: async ({ pty }) => {
    if (++attempts === 1) return { ok: false }; pty.kill('SIGTERM'); return { ok: true };
  } } });
  const c = await connect(f); await waitFor(() => c.frames[0]?.type === 'ready');
  await assert.rejects(f.broker.dispose(), { code: 'SSH_BROKER_CLEANUP_FAILED' });
  await f.broker.dispose(); assert.equal(f.children[0].finished, true);
});

test('askpass rejects confirmation prompts, unknown capabilities and oversized secret frames silently', async t => {
  const f = await fixture(t), output = capture();
  for (const promptKind of ['confirm', 'none']) assert.equal(await runSshAskpass({ socket: path.join(f.directory, 'auth.sock'),
    token: 'a'.repeat(64), promptKind, output: output.stream }), 1);
  assert.equal(await runSshAskpass({ socket: path.join(f.directory, 'auth.sock'), token: 'a'.repeat(64), output: output.stream }), 1);
  assert.equal(output.text(), '');
  const oversizedPath = path.join(f.root, 'oversized.sock');
  const server = net.createServer(client => { client.on('error', () => {}); client.once('data', () => client.end(`${'x'.repeat(4097)}\n`)); });
  await new Promise(resolve => server.listen(oversizedPath, resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  assert.equal(await runSshAskpass({ socket: oversizedPath, token: 'a'.repeat(64), output: output.stream }), 1);
  assert.equal(output.text(), '');
});

test('PTY input is serialized across partial native writes and EAGAIN without using node-pty unbounded writes', async t => {
  const received = []; let attempts = 0;
  const f = await fixture(t, { writePty: async (_fd, buffer, offset) => {
    if (++attempts === 1) throw Object.assign(new Error(), { code: 'EAGAIN' });
    const count = Math.min(3, buffer.length - offset); received.push(Buffer.from(buffer.subarray(offset, offset + count))); return count;
  } });
  const c = await connect(f, ['-t', connection.alias]); await waitFor(() => c.frames[0]?.type === 'ready');
  f.children[0].write = () => { throw new Error('Unbounded node-pty.write must never be called'); };
  const value = Buffer.from([1, 255, 2, 0, 3, 10, 4, 13]);
  c.send({ type: 'stdin', data: value.toString('base64') });
  await waitFor(() => Buffer.concat(received).length === value.length);
  assert.deepEqual(Buffer.concat(received), value); assert.equal(attempts, 4);
  c.channel.destroy(); await waitFor(() => f.children[0].finished);
});

test('a stalled native PTY cannot accumulate unbounded main-process input and overflow cancels its run', async t => {
  let attempts = 0;
  const f = await fixture(t, { writePty: async () => { attempts++; throw Object.assign(new Error(), { code: 'EAGAIN' }); } });
  const c = await connect(f, ['-t', connection.alias]); await waitFor(() => c.frames[0]?.type === 'ready');
  const frame = { type: 'stdin', data: Buffer.alloc(48 * 1024, 65).toString('base64') };
  for (let index = 0; index < 32; index++) c.send(frame);
  await waitFor(() => f.children[0].finished, 'bounded input cleanup');
  assert.equal(f.children[0].writes.length, 0); assert.ok(attempts < 20);
});

test('cancel and terminating signals bypass stalled PTY input and validate their complete frame', async t => {
  for (const control of [{ type: 'cancel' }, { type: 'signal', signal: 'SIGTERM' }, { type: 'signal', signal: 'SIGHUP' },
    { type: 'cancel', untrusted: true }, { type: 'signal', signal: 'SIGTERM', untrusted: true }]) {
    let attempts = 0;
    const f = await fixture(t, { writePty: async () => { attempts++; throw Object.assign(new Error(), { code: 'EAGAIN' }); } });
    const c = await connect(f, ['-t', connection.alias]); await waitFor(() => c.frames[0]?.type === 'ready');
    c.send({ type: 'stdin', data: 'QQ==' });
    await waitFor(() => attempts > 0);
    c.send(control);
    await waitFor(() => f.children[0].finished, 'cancellation while native input is stalled', 300);
    await waitFor(() => c.frames.some(frame => frame.type === (control.untrusted ? 'error' : 'exit')));
    assert.deepEqual(c.frames.at(-1), control.untrusted ? { type: 'error', code: 'SSH_BROKER_INVALID' } : { type: 'exit', code: 255 });
    const stoppedAttempts = attempts;
    await delay(15);
    assert.equal(attempts, stoppedAttempts);
    assert.equal(f.closed.length, 1);
  }
});

test('non-PTY input backpressure leaves the control channel available for cancellation', async t => {
  const f = await fixture(t), c = await connect(f);
  await waitFor(() => c.frames[0]?.type === 'ready');
  let pending;
  f.children[0].stdin.write = (_data, callback) => { pending = callback; return false; };
  c.send({ type: 'stdin', data: 'QQ==' });
  await waitFor(() => pending);
  c.send({ type: 'cancel' });
  await waitFor(() => f.children[0].finished, 'non-PTY cancellation while backpressured', 300);
  pending(new Error('fixture input closed'));
  await waitFor(() => c.frames.some(frame => frame.type === 'exit'));
  assert.deepEqual(c.frames.at(-1), { type: 'exit', code: 255 });
  assert.equal(f.closed.length, 1);
});

test('wall clock rollback cannot extend the monotonic password lifetime', async t => {
  let elapsed = 0;
  const f = await fixture(t, { monotonicNow: () => elapsed });
  const c = await connect(f); await waitFor(() => c.frames[0]?.type === 'ready');
  f.advance(-86400000); elapsed = 3600001;
  const expired = await connect(f);
  await waitFor(() => expired.frames.some(frame => frame.code === 'SSH_AUTHORIZATION_EXPIRED'));
  assert.deepEqual(await askpass(f), { code: 1, text: '' });
  assert.equal(f.children[0].finished, undefined); assert.equal(c.channel.destroyed, false);
  c.send({ type: 'stdin', data: Buffer.from('still-open').toString('base64') });
  await waitFor(() => f.children[0].writes.length === 1);
  assert.equal(Buffer.concat(f.children[0].writes).toString(), 'still-open');
});

test('many tiny queued frames cannot amplify a stalled native input into unbounded promise allocation', async t => {
  const f = await fixture(t, { writePty: async () => { throw Object.assign(new Error(), { code: 'EAGAIN' }); } });
  const c = await connect(f, ['-t', connection.alias]); await waitFor(() => c.frames[0]?.type === 'ready');
  c.send({ type: 'stdin', data: 'QQ==' });
  c.channel.write(`${JSON.stringify({ type: 'stdin', data: '' })}\n`.repeat(200));
  await waitFor(() => f.children[0].finished, 'bounded frame cleanup');
});
