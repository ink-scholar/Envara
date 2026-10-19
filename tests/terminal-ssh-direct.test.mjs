import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { chmod, lstat, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { PassThrough, Readable, Writable } from 'node:stream';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { createSshDirectTransport, runSshDirect, runSshDirectCli } from '../electron/terminal-ssh-direct.mjs';

const alias = 'envara-abcdef123456';
async function waitFor(predicate, timeout = 1500) {
  const deadline = Date.now() + timeout;
  while (!predicate()) { if (Date.now() >= deadline) throw new Error('Owned fixture condition timed out'); await delay(5); }
}
function collector({ slow = false } = {}) {
  const chunks = [];
  const output = new Writable({ highWaterMark: 256, write(chunk, _encoding, done) {
    chunks.push(Buffer.from(chunk)); if (slow) setTimeout(done, 1); else done();
  } });
  return { output, bytes: () => Buffer.concat(chunks) };
}
async function directory(t) {
  const root = await mkdtemp(path.join(await realpath('/tmp'), 'evsd-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true })); return root;
}
async function fixture(t, { onConnection = socket => { socket.on('end', () => socket.end()); socket.resume(); },
  connect: injectedConnect, connectTimeoutMs = 500, handshakeTimeoutMs = 500, cleanupTimeoutMs = 2000 } = {}) {
  const root = await mkdtemp(path.join(await realpath('/tmp'), 'evsd-')); await chmod(root, 0o700);
  const upstreams = new Set(), calls = []; let active = true, transport;
  const server = net.createServer({ allowHalfOpen: true }, socket => {
    upstreams.add(socket); socket.on('error', () => {}); socket.once('close', () => upstreams.delete(socket)); onConnection(socket);
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port, connections = [{ alias, host: '127.0.0.1', port }];
  t.after(async () => {
    await transport?.dispose();
    const closing = new Promise(resolve => server.close(resolve)); for (const socket of upstreams) socket.destroy(); await closing;
    await rm(root, { recursive: true, force: true });
  });
  transport = await createSshDirectTransport({ directory: root, connections, isActive: () => active,
    connect: options => { calls.push({ ...options }); return injectedConnect ? injectedConnect(options) : net.connect(options); },
    connectTimeoutMs, handshakeTimeoutMs, cleanupTimeoutMs });
  return { root, transport, connections, calls, upstreams, port, revoke: () => { active = false; } };
}
const run = (f, extra = {}) => runSshDirect({ alias, socket: f.transport.socket, token: f.transport.token,
  input: Readable.from([]), output: collector().output, connectTimeoutMs: 1000, ...extra });
async function rawRequest(socketPath, payload) {
  const channel = net.connect({ path: socketPath, allowHalfOpen: true }), chunks = [];
  channel.on('error', () => {}); channel.on('data', chunk => chunks.push(chunk));
  channel.once('connect', () => channel.end(payload));
  await once(channel, 'close'); return Buffer.concat(chunks).toString();
}
async function rawOpen(f, { send = true } = {}) {
  const channel = net.connect({ path: f.transport.socket, allowHalfOpen: true }); channel.on('error', () => {});
  channel.once('end', () => channel.end());
  const connected = new Promise(resolve => channel.once('connect', resolve)); await connected;
  let response = '';
  channel.on('data', chunk => { response += chunk; });
  if (send) {
    channel.write(JSON.stringify({ version: 1, token: f.transport.token, alias }) + '\n');
    await waitFor(() => response.includes('\n'));
  }
  return { channel, response: () => response };
}

test('the capability connects only its immutable saved endpoint and preserves binary handshake tails', async t => {
  const binary = Buffer.from([0, 255, 128, 13, 10, 83, 83, 72, 45]);
  let received = Buffer.alloc(0);
  const f = await fixture(t, { onConnection: socket => {
    socket.write(binary); socket.on('data', chunk => { received = Buffer.concat([received, chunk]); }); socket.on('end', () => socket.end());
  } });
  const output = collector(), payload = Buffer.from('client binary\0tail');
  f.connections[0].host = 'never-contact-this.invalid'; f.connections[0].port = 1;
  await run(f, { input: Readable.from([payload]), output: output.output });
  assert.deepEqual(output.bytes(), binary); assert.deepEqual(received, payload);
  assert.deepEqual(f.calls, [{ host: '127.0.0.1', port: f.port, allowHalfOpen: true }]);
  assert.equal((await lstat(f.transport.socket)).mode & 0o777, 0o600);
  assert.match(f.transport.token, /^[a-f0-9]{64}$/);
  assert.deepEqual(await readdir(f.root), ['transport.sock'], 'the session token is memory-only');
});

test('wrong tokens, aliases, fields, payload types and oversized handshakes are refused before connecting', async t => {
  const f = await fixture(t);
  const valid = { version: 1, token: f.transport.token, alias };
  for (const request of [{ ...valid, token: '0'.repeat(64) }, { ...valid, alias: 'foreign' }, { ...valid, host: '127.0.0.1' },
    { ...valid, port: 1 }, { ...valid, version: '1' }, { ...valid, token: null }, { ...valid, alias: {} }, [], null]) {
    assert.match(await rawRequest(f.transport.socket, JSON.stringify(request) + '\n'), /"ok":false/);
  }
  assert.match(await rawRequest(f.transport.socket, '{malformed}\n'), /"ok":false/);
  assert.equal(await rawRequest(f.transport.socket, 'x'.repeat(513)), '');
  assert.equal(f.calls.length, 0);
});

test('large bidirectional streams respect backpressure and flush the response after stdin EOF', async t => {
  const clientData = Buffer.alloc(1024 * 1024, 0x96), serverData = Buffer.alloc(1024 * 1024, 0x69);
  const chunks = [];
  const f = await fixture(t, { onConnection: socket => {
    socket.pause(); setTimeout(() => socket.resume(), 20);
    socket.on('data', chunk => chunks.push(Buffer.from(chunk))); socket.on('end', () => socket.end(serverData));
  } });
  const output = collector({ slow: true });
  await run(f, { input: Readable.from([clientData]), output: output.output });
  assert.deepEqual(Buffer.concat(chunks), clientData); assert.deepEqual(output.bytes(), serverData);
  assert.equal(output.output.writableFinished, true);
});

test('remote EOF reaches stdout before stdin ends while the reverse direction remains writable', async t => {
  const chunks = []; let inputEnded = false;
  const f = await fixture(t, { onConnection: socket => {
    socket.end('server sent EOF'); socket.on('data', chunk => chunks.push(Buffer.from(chunk)));
    socket.once('end', () => { inputEnded = true; });
  } });
  const input = new PassThrough(), output = collector(); let settled = false;
  const pending = run(f, { input, output: output.output }).then(() => { settled = true; });
  await once(output.output, 'finish'); assert.equal(output.bytes().toString(), 'server sent EOF');
  assert.equal(settled, false); input.end('final bytes after remote EOF'); await pending;
  await waitFor(() => inputEnded); assert.equal(Buffer.concat(chunks).toString(), 'final bytes after remote EOF');
});

test('revocation closes active target sockets and refuses subsequent direct requests', async t => {
  const f = await fixture(t);
  const client = await rawOpen(f); assert.equal(client.response(), '{"ok":true}\n'); await waitFor(() => f.upstreams.size === 1);
  const closed = once(client.channel, 'close'); f.revoke();
  await closed; await waitFor(() => f.upstreams.size === 0);
  assert.match(await rawRequest(f.transport.socket, JSON.stringify({ version: 1, token: f.transport.token, alias }) + '\n'), /"ok":false/);
  assert.equal(f.calls.length, 1);
});

test('revocation and disposal retain and close a connector that returns after cancellation', async t => {
  let resolveOpening;
  const f = await fixture(t, { connect: () => new Promise(resolve => { resolveOpening = resolve; }) });
  const rejected = assert.rejects(run(f), error => /^SSH_DIRECT_/.test(error.code));
  await waitFor(() => typeof resolveOpening === 'function'); f.revoke(); await rejected;
  let disposed = false;
  const closing = f.transport.dispose().then(() => { disposed = true; }); await delay(20); assert.equal(disposed, false);
  const late = new net.Socket({ allowHalfOpen: true }); resolveOpening(late); await closing;
  assert.equal(late.destroyed, true); assert.equal(late.closed, true);
  await assert.rejects(lstat(f.transport.socket), { code: 'ENOENT' });
});

test('an unfinished connector makes cleanup explicitly retryable without losing later socket custody', async t => {
  let resolveOpening;
  const f = await fixture(t, { cleanupTimeoutMs: 30, connect: () => new Promise(resolve => { resolveOpening = resolve; }) });
  const rejected = assert.rejects(run(f), error => /^SSH_DIRECT_/.test(error.code));
  await waitFor(() => typeof resolveOpening === 'function');
  await assert.rejects(f.transport.dispose(), { code: 'SSH_DIRECT_CLEANUP_FAILED' }); await rejected;
  assert.equal((await lstat(f.transport.socket)).isSocket(), true);
  const late = new net.Socket({ allowHalfOpen: true }); resolveOpening(late); await waitFor(() => late.closed === true);
  await f.transport.dispose(); await assert.rejects(lstat(f.transport.socket), { code: 'ENOENT' });
});

test('connection and incomplete-handshake deadlines release only their owned sockets', async t => {
  const f = await fixture(t, { connectTimeoutMs: 30, handshakeTimeoutMs: 30, connect: () => new net.Socket({ allowHalfOpen: true }) });
  await assert.rejects(run(f), error => /^SSH_DIRECT_/.test(error.code)); assert.equal(f.calls.length, 1);
  const raw = await rawOpen(f, { send: false }); const closed = once(raw.channel, 'close'); raw.channel.end(); await closed;
  assert.equal(f.calls.length, 1); await f.transport.dispose();
});

test('client abort and malformed server acknowledgement never produce a raw direct fallback', async t => {
  const f = await fixture(t);
  const already = new AbortController(); already.abort();
  await assert.rejects(run(f, { signal: already.signal }), { code: 'SSH_DIRECT_CANCELLED' }); assert.equal(f.calls.length, 0);
  const controller = new AbortController(), input = new PassThrough();
  const rejected = assert.rejects(run(f, { input, signal: controller.signal }), { code: 'SSH_DIRECT_CANCELLED' });
  await waitFor(() => f.upstreams.size === 1); controller.abort(); await rejected; await waitFor(() => f.upstreams.size === 0);
  const root = await directory(t), socket = path.join(root, 'transport.sock');
  const server = net.createServer(client => { client.on('error', () => {}); client.once('data', () => client.end('{"ok":true,"host":"forbidden"}\n')); });
  server.listen(socket); await once(server, 'listening'); await chmod(socket, 0o600);
  t.after(() => new Promise(resolve => server.close(resolve)));
  await assert.rejects(runSshDirect({ alias, socket, token: 'a'.repeat(64), input: Readable.from([]), output: collector().output }), { code: 'SSH_DIRECT_AUTHORIZATION' });
});

test('at most four active streams and sixteen accepted clients can retain transport authority', async t => {
  const f = await fixture(t, { handshakeTimeoutMs: 10000 });
  const clients = [];
  for (let index = 0; index < 4; index++) clients.push((await rawOpen(f)).channel);
  const refused = await rawOpen(f); assert.match(refused.response(), /"ok":false/); refused.channel.destroy();
  await waitFor(() => refused.channel.destroyed);
  assert.equal(f.calls.length, 4);
  for (let index = 0; index < 12; index++) clients.push((await rawOpen(f, { send: false })).channel);
  const extra = await rawOpen(f, { send: false }); await waitFor(() => extra.channel.destroyed); assert.equal(f.calls.length, 4);
  for (const client of clients) client.destroy();
});

test('unsafe roots, duplicate aliases and existing files are rejected without overwriting anything', async t => {
  const root = await directory(t), socket = path.join(root, 'transport.sock');
  const fields = { directory: root, connections: [{ alias, host: '127.0.0.1', port: 22 }], isActive: () => true };
  await writeFile(socket, 'synthetic existing file', { mode: 0o600 });
  await assert.rejects(createSshDirectTransport(fields), { code: 'SSH_DIRECT_CONFIGURATION' });
  assert.equal(await readFile(socket, 'utf8'), 'synthetic existing file'); await rm(socket);
  await assert.rejects(createSshDirectTransport({ ...fields, connections: [fields.connections[0], fields.connections[0]] }), { code: 'SSH_DIRECT_CONFIGURATION' });
  assert.deepEqual(await readdir(root), []);
  const linked = path.join(root, 'linked'); await symlink(root, linked);
  await assert.rejects(createSshDirectTransport({ ...fields, directory: linked }), { code: 'SSH_DIRECT_CONFIGURATION' });
  await chmod(root, 0o755);
  await assert.rejects(createSshDirectTransport(fields), { code: 'SSH_DIRECT_CONFIGURATION' }); await chmod(root, 0o700);
});

test('cleanup refuses a replaced socket path and can be retried after ownership is restored', async t => {
  const f = await fixture(t), backup = path.join(f.root, 'owned-backup.sock');
  await rename(f.transport.socket, backup); await writeFile(f.transport.socket, 'unrelated synthetic file', { mode: 0o600 });
  await assert.rejects(f.transport.dispose(), { code: 'SSH_DIRECT_CLEANUP_FAILED' });
  assert.equal(await readFile(f.transport.socket, 'utf8'), 'unrelated synthetic file');
  await rm(f.transport.socket); await rename(backup, f.transport.socket); await f.transport.dispose();
  await assert.rejects(lstat(f.transport.socket), { code: 'ENOENT' });
});

test('CLI input accepts only a fixed alias and diagnostics contain no capability, path, address or proxy', async t => {
  const root = await directory(t), error = collector();
  const environment = { ENVARA_SSH_DIRECT_SOCKET: path.join(root, 'transport.sock'), ENVARA_SSH_DIRECT_TOKEN: 'a'.repeat(64),
    ENVARA_SSH_PROXY_URL: 'http://synthetic-private@never-contact.invalid:5555', ENVARA_SSH_TARGETS: 'untrusted-targets-file' };
  const code = await runSshDirectCli(['--alias', alias, '--host', 'never-contact.invalid'], environment,
    { input: Readable.from([]), output: collector().output, errorOutput: error.output });
  assert.equal(code, 1); assert.match(error.bytes().toString(), /SSH_DIRECT_CONFIGURATION/);
  for (const secret of [environment.ENVARA_SSH_DIRECT_TOKEN, root, 'never-contact.invalid', 'synthetic-private', alias])
    assert.equal(error.bytes().includes(secret), false);
});

test('the real helper closes POSIX stdout at remote EOF and still forwards later stdin bytes', { timeout: 3000 }, async t => {
  const received = [];
  const f = await fixture(t, { onConnection: socket => {
    socket.end('SSH-fixture-remote-EOF'); socket.on('data', chunk => received.push(Buffer.from(chunk)));
  } });
  const child = spawn(process.execPath, [fileURLToPath(new URL('../electron/terminal-ssh-direct.mjs', import.meta.url)), '--alias', alias],
    { env: { PATH: '/usr/bin:/bin', ENVARA_SSH_DIRECT_SOCKET: f.transport.socket, ENVARA_SSH_DIRECT_TOKEN: f.transport.token },
      stdio: ['pipe', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); });
  const chunks = [], errors = []; child.stdout.on('data', chunk => chunks.push(Buffer.from(chunk))); child.stderr.on('data', chunk => errors.push(Buffer.from(chunk)));
  const ended = once(child, 'close'); await once(child.stdout, 'end');
  assert.equal(Buffer.concat(chunks).toString(), 'SSH-fixture-remote-EOF'); assert.equal(child.exitCode, null);
  child.stdin.end('last bytes after native stdout EOF');
  const [code, signal] = await ended; assert.equal(code, 0); assert.equal(signal, null); assert.equal(Buffer.concat(errors).length, 0);
  assert.equal(Buffer.concat(received).toString(), 'last bytes after native stdout EOF');
});
