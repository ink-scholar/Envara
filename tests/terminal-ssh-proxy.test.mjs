import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { constants } from 'node:fs';
import { chmod, link, mkdtemp, open, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { PassThrough, Readable, Writable } from 'node:stream';
import test from 'node:test';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';
import { readSshTargets, runSshProxy, sameSshTarget, validateSshProxyUrl, validateSshTarget } from '../electron/terminal-ssh-proxy.mjs';
import { cert, key } from './claude-download-fixture.mjs';

const target = { host: 'ssh-fixture.invalid', port: 2222 };
const credentials = 'fixture-user:fixture-password';
const authorization = `Basic ${Buffer.from(credentials).toString('base64')}`;
const helperPath = fileURLToPath(new URL('../electron/terminal-ssh-proxy.mjs', import.meta.url));

async function listen(t, server) {
  const sockets = new Set();
  server.on('connection', socket => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => {
    server.close(resolve);
    for (const socket of sockets) socket.destroy();
  }));
  return server.address().port;
}

async function proxyFixture(t, onRequest) {
  const requests = [];
  const server = net.createServer({ allowHalfOpen: true }, socket => {
    let buffer = Buffer.alloc(0);
    socket.on('data', function parse(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      const boundary = buffer.indexOf('\r\n\r\n');
      if (boundary < 0) return;
      socket.off('data', parse);
      const request = buffer.subarray(0, boundary).toString();
      requests.push(request);
      onRequest(socket, request, buffer.subarray(boundary + 4));
    });
  });
  const port = await listen(t, server);
  return { port, requests, url: `http://${credentials}@127.0.0.1:${port}` };
}

function collector({ delay = 0, highWaterMark = 16 * 1024 } = {}) {
  const chunks = [];
  const output = new Writable({ highWaterMark, write(chunk, encoding, callback) {
    chunks.push(Buffer.from(chunk));
    if (delay) setTimeout(callback, delay);
    else callback();
  } });
  return { output, bytes: () => Buffer.concat(chunks) };
}

function run(proxy, extra = {}) {
  return runSshProxy({ ...target, proxyUrl: proxy.url, allowedTargets: [target],
    input: Readable.from([]), output: collector().output, connectTimeoutMs: 500, ...extra });
}

async function targetFile(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-ssh-fixture-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'targets.json');
  await writeFile(file, JSON.stringify([target]), { mode: 0o400 });
  return { root, file };
}

async function invokeCli(t, argv, environment) {
  const env = { ...process.env };
  delete env.ENVARA_SSH_TARGETS;
  delete env.ENVARA_SSH_PROXY_URL;
  Object.assign(env, environment);
  const child = spawn(process.execPath, [helperPath, ...argv], { env, stdio: ['pipe', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  const stdout = [], stderr = [];
  child.stdout.on('data', chunk => stdout.push(chunk));
  child.stderr.on('data', chunk => stderr.push(chunk));
  const closed = once(child, 'close');
  child.stdin.end();
  const [code, signal] = await closed;
  return { code, signal, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr).toString() };
}

test('validates exact destinations and requires authenticated literal loopback proxies', () => {
  assert.deepEqual(validateSshTarget('SSH-Fixture.invalid', '2222'), target);
  assert.deepEqual(validateSshTarget('[::1]', 22), { host: '::1', port: 22 });
  assert.equal(validateSshProxyUrl('http://user:p%3Aass@127.0.0.1:1234').authorization,
    `Basic ${Buffer.from('user:p:ass').toString('base64')}`);
  assert.equal(validateSshProxyUrl('https://user:pass@[::1]:1234').secure, true);
  for (const host of ['', 'host\r\nInjected: value', 'foo.invalid/path', 'bad..host', '-bad.invalid', 'host.invalid.', 'fe80::1%en0']) {
    assert.throws(() => validateSshTarget(host, 22), { code: 'SSH_PROXY_CONFIGURATION' });
  }
  for (const port of [0, 65536, '22junk', 2.5]) assert.throws(() => validateSshTarget(target.host, port));
  for (const url of ['http://127.0.0.1:1234', 'http://user@127.0.0.1:1234', 'http://user:pass@localhost:1234',
    'http://user:pass@proxy.invalid:1234', 'http://user:pass@192.0.2.1:1234', 'socks5://user:pass@127.0.0.1:1234',
    'http://user:pass@127.0.0.1:1234/path', 'http://user:pass@127.0.0.1:1234#fragment',
    'http://user:pass@127.0.0.1:1234?query', 'http://u%3Aser:pass@127.0.0.1:1234', 'http://user:p%0Aass@127.0.0.1:1234']) {
    assert.throws(() => validateSshProxyUrl(url), { code: 'SSH_PROXY_CONFIGURATION' });
  }
});

test('numeric endpoint equality covers IPv6 spellings and IPv4-mapped forms without changing saved host text', () => {
  for (const hosts of [
    ['2001:db8::1', '2001:0db8:0000:0000:0000:0000:0000:0001', '[2001:DB8:0:0::1]'],
    ['192.0.2.1', '::ffff:192.0.2.1', '::ffff:c000:201', '[0000:0000:0000:0000:0000:FFFF:C000:0201]'],
    ['::', '0:0:0:0:0:0:0:0', '[0000::]'],
  ]) for (const first of hosts) for (const second of hosts) {
    assert.equal(sameSshTarget({ host: first, port: 2222 }, { host: second, port: 2222 }), true, `${first} / ${second}`);
    assert.equal(sameSshTarget({ host: first, port: 2222 }, { host: second, port: 22 }), false);
  }
  assert.equal(validateSshTarget('2001:0db8:0000:0000:0000:0000:0000:0001', 2222).host, '2001:0db8:0000:0000:0000:0000:0000:0001');
  for (const [first, second] of [['2001:db8::1', '2001:db8::2'], ['::192.0.2.1', '192.0.2.1'],
    ['::ffff:c000:201', '192.0.2.2'], ['ssh-fixture.invalid', '192.0.2.1'], ['ssh-fixture.invalid', 'alias-fixture.invalid']])
    assert.equal(sameSshTarget({ host: first, port: 2222 }, { host: second, port: 2222 }), false);
});

test('registered proxy matching accepts equivalent numeric hosts but sends the caller destination unchanged', async t => {
  for (const [stored, requested] of [['2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1'],
    ['::ffff:c000:201', '192.0.2.1'], ['192.0.2.1', '::ffff:192.0.2.1']]) {
    const proxy = await proxyFixture(t, socket => socket.end('HTTP/1.1 200 Connection established\r\n\r\nSSH-fixture\n'));
    const output = collector();
    await runSshProxy({ host: requested, port: 2222, proxyUrl: proxy.url, allowedTargets: [{ host: stored, port: 2222 }], input: Readable.from([]), output: output.output });
    const authority = `${net.isIP(requested) === 6 ? `[${requested}]` : requested}:2222`;
    assert.ok(proxy.requests[0].startsWith(`CONNECT ${authority} HTTP/1.1\r\n`));
    assert.equal(output.bytes().toString(), 'SSH-fixture\n');
  }
});

test('reads bounded private target files and rejects links, permissive modes and malformed paths', async t => {
  const { root, file } = await targetFile(t);
  assert.deepEqual(await readSshTargets(file), [target]);
  await chmod(file, 0o644);
  await assert.rejects(readSshTargets(file), { code: 'SSH_PROXY_CONFIGURATION' });
  await chmod(file, 0o600);
  const linked = path.join(root, 'linked.json');
  await symlink(file, linked);
  await assert.rejects(readSshTargets(linked), { code: 'SSH_PROXY_CONFIGURATION' });
  await assert.rejects(readSshTargets(`${root}/./targets.json`), { code: 'SSH_PROXY_CONFIGURATION' });
  await assert.rejects(readSshTargets('targets.json'), { code: 'SSH_PROXY_CONFIGURATION' });
  const hardlink = path.join(root, 'hardlink.json');
  await link(file, hardlink);
  await assert.rejects(readSshTargets(file), { code: 'SSH_PROXY_CONFIGURATION' });
  await rm(hardlink);
  await writeFile(file, JSON.stringify([{ ...target, wildcard: true }]));
  await assert.rejects(readSshTargets(file), { code: 'SSH_PROXY_CONFIGURATION' });
  await writeFile(file, ' '.repeat(16 * 1024 + 1));
  await assert.rejects(readSshTargets(file), { code: 'SSH_PROXY_CONFIGURATION' });
  await writeFile(file, '[]');
  await assert.rejects(readSshTargets(file), { code: 'SSH_PROXY_CONFIGURATION' });
});

test('authorizes host and port before contacting a proxy', async t => {
  const proxy = await proxyFixture(t, socket => socket.destroy());
  await assert.rejects(run(proxy, { host: 'different.invalid' }), { code: 'SSH_PROXY_TARGET_DENIED' });
  await assert.rejects(run(proxy, { port: target.port + 1 }), { code: 'SSH_PROXY_TARGET_DENIED' });
  for (const allowedTargets of [[], undefined]) {
    await assert.rejects(run(proxy, { allowedTargets }), { code: 'SSH_PROXY_CONFIGURATION' });
  }
  await assert.rejects(run(proxy, { proxyUrl: `http://127.0.0.1:${proxy.port}` }), { code: 'SSH_PROXY_CONFIGURATION' });
  assert.equal(proxy.requests.length, 0);
});

test('explicit environment policy connects an unregistered domain through the authenticated proxy', async t => {
  const selected = { host: 'unregistered-ssh.invalid', port: 2207 };
  const payload = Buffer.from([0, 255, 128, 13, 10, 83, 83, 72]);
  let received = Buffer.alloc(0);
  const proxy = await proxyFixture(t, socket => {
    socket.write('HTTP/1.1 200 OK\r\n\r\n');
    socket.on('data', chunk => { received = Buffer.concat([received, chunk]); });
    socket.on('end', () => socket.end(payload));
  });
  const { output, bytes } = collector();
  await runSshProxy({ ...selected, targetPolicy: 'environment', proxyUrl: proxy.url,
    input: Readable.from([payload]), output });
  assert.deepEqual(received, payload);
  assert.deepEqual(bytes(), payload);
  assert.equal(proxy.requests.length, 1);
  assert.match(proxy.requests[0], /^CONNECT unregistered-ssh\.invalid:2207 HTTP\/1\.1\r\n/);
  assert.ok(proxy.requests[0].includes(`\r\nProxy-Authorization: ${authorization}`));
});

test('environment policy still rejects malformed targets, invalid proxies and unknown policies before connecting', async t => {
  const proxy = await proxyFixture(t, socket => socket.destroy());
  for (const targetPolicy of ['', 'all', 'Environment', null, true, {}]) {
    await assert.rejects(run(proxy, { targetPolicy }), { code: 'SSH_PROXY_CONFIGURATION' });
  }
  for (const extra of [
    { host: 'host\r\nInjected: value' }, { host: 'bad..host' }, { port: '22junk' }, { port: 0 },
    { proxyUrl: undefined }, { proxyUrl: `http://127.0.0.1:${proxy.port}` },
    { proxyUrl: `http://${credentials}@localhost:${proxy.port}` },
    { proxyUrl: `http://${credentials}@192.0.2.1:${proxy.port}` },
  ]) await assert.rejects(run(proxy, { targetPolicy: 'environment', allowedTargets: undefined, ...extra }),
    { code: 'SSH_PROXY_CONFIGURATION' });
  assert.equal(proxy.requests.length, 0);
});

test('sends authenticated CONNECT with domain intact and preserves binary bytes pipelined after headers', async t => {
  const binary = Buffer.from([0, 255, 128, 13, 10, 83, 83, 72, 45]);
  const proxy = await proxyFixture(t, (socket, request, head) => {
    assert.equal(head.length, 0);
    socket.write(Buffer.concat([Buffer.from('HTTP/1.1 200 Connection established\r\n\r\n'), binary]));
    socket.on('end', () => socket.end());
    socket.resume();
  });
  const { output, bytes } = collector();
  await run(proxy, { output });
  assert.deepEqual(bytes(), binary);
  assert.match(proxy.requests[0], /^CONNECT ssh-fixture\.invalid:2222 HTTP\/1\.1\r\n/);
  assert.ok(proxy.requests[0].includes(`\r\nProxy-Authorization: ${authorization}`));
});

test('stdin EOF before CONNECT still sends buffered bytes and preserves response after half-close', async t => {
  const payload = Buffer.from('client input before tunnel completion');
  let received = Buffer.alloc(0);
  const proxy = await proxyFixture(t, socket => {
    setTimeout(() => socket.write('HTTP/1.1 200 OK\r\n\r\n'), 25);
    socket.on('data', chunk => { received = Buffer.concat([received, chunk]); });
    socket.on('end', () => socket.end(Buffer.from('server after client EOF')));
  });
  const input = new PassThrough();
  input.end(payload);
  const { output, bytes } = collector();
  await run(proxy, { input, output });
  assert.deepEqual(received, payload);
  assert.equal(bytes().toString(), 'server after client EOF');
});

test('propagates backpressure in both directions without losing bytes', async t => {
  const clientData = Buffer.alloc(1024 * 1024, 0x96);
  const serverData = Buffer.alloc(1024 * 1024, 0x69);
  let received = Buffer.alloc(0);
  const proxy = await proxyFixture(t, socket => {
    socket.write('HTTP/1.1 200 OK\r\n\r\n');
    socket.pause();
    setTimeout(() => socket.resume(), 20);
    socket.on('data', chunk => { received = Buffer.concat([received, chunk]); });
    socket.on('end', () => socket.end(serverData));
  });
  const { output, bytes } = collector({ delay: 1, highWaterMark: 256 });
  await run(proxy, { input: Readable.from([clientData]), output });
  if (!output.writableFinished) await once(output, 'finish');
  assert.deepEqual(received, clientData);
  assert.deepEqual(bytes(), serverData);
});

test('waits for pending output writes and final flush after the tunnel closes', { timeout: 5000 }, async t => {
  let closed, writing, finalizing, releaseWrite, releaseFinal;
  const transportClosed = new Promise(resolve => { closed = resolve; });
  const writeStarted = new Promise(resolve => { writing = resolve; });
  const finalStarted = new Promise(resolve => { finalizing = resolve; });
  const payload = Buffer.from('final remote bytes');
  const chunks = [];
  const output = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(Buffer.from(chunk)); releaseWrite = callback; writing();
    },
    final(callback) { releaseFinal = callback; finalizing(); },
  });
  t.after(() => { releaseWrite?.(); releaseFinal?.(); output.destroy(); });
  const proxy = await proxyFixture(t, socket => {
    socket.once('close', closed);
    socket.write('HTTP/1.1 200 OK\r\n\r\n');
    socket.on('end', () => socket.end(payload));
  });
  let completed = false;
  const result = run(proxy, { output }).then(() => { completed = true; });
  await Promise.all([writeStarted, transportClosed]);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(completed, false, 'transport closure cannot discard a pending output write');
  const write = releaseWrite; releaseWrite = null; write();
  await finalStarted;
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(completed, false, 'transport closure cannot skip the final output flush');
  const final = releaseFinal; releaseFinal = null; final();
  await result;
  assert.equal(output.writableFinished, true);
  assert.deepEqual(Buffer.concat(chunks), payload);
});

test('refuses premature output closure and write errors and closes the tunnel', { timeout: 5000 }, async t => {
  for (const mode of ['close', 'error']) {
    let closed;
    const transportClosed = new Promise(resolve => { closed = resolve; });
    const proxy = await proxyFixture(t, socket => {
      socket.once('close', closed);
      socket.on('end', () => socket.end());
      socket.write('HTTP/1.1 200 OK\r\n\r\nremote payload');
    });
    const output = new Writable({ write(_chunk, _encoding, callback) {
      if (mode === 'error') callback(Object.assign(new Error('private-output-detail'), { code: 'EPIPE' }));
      else { this.destroy(); callback(); }
    } });
    await assert.rejects(run(proxy, { output }), error => {
      assert.equal(error.code, 'SSH_PROXY_IO');
      assert.doesNotMatch(error.message, /private-output-detail|EPIPE|fixture/);
      return true;
    });
    await transportClosed;
  }
});

test('retains error handling while the final output flush is pending', { timeout: 5000 }, async t => {
  let closed, finalizing, releaseFinal;
  const transportClosed = new Promise(resolve => { closed = resolve; });
  const finalStarted = new Promise(resolve => { finalizing = resolve; });
  const output = new Writable({
    write(_chunk, _encoding, callback) { callback(); },
    final(callback) { releaseFinal = callback; finalizing(); },
  });
  t.after(() => { releaseFinal?.(); output.destroy(); });
  const proxy = await proxyFixture(t, socket => {
    socket.once('close', closed);
    socket.write('HTTP/1.1 200 OK\r\n\r\n');
    socket.on('end', () => socket.end('final remote bytes'));
  });
  const rejected = assert.rejects(run(proxy, { output }), { code: 'SSH_PROXY_IO' });
  await Promise.all([finalStarted, transportClosed]);
  await new Promise(resolve => setImmediate(resolve));
  const final = releaseFinal; releaseFinal = null;
  final(new Error('private final flush failure'));
  await rejected;
});

for (const status of [407, 403, 502]) {
  test(`refuses HTTP ${status} without exposing proxy response or credentials`, async t => {
    const proxy = await proxyFixture(t, socket => socket.end(`HTTP/1.1 ${status} private-server-detail\r\n\r\nprivate-body`));
    const { output, bytes } = collector();
    await assert.rejects(run(proxy, { output }), error => {
      assert.equal(error.code, `SSH_PROXY_HTTP_${status}`);
      assert.doesNotMatch(error.message, /private|fixture|127\.0\.0\.1|Basic/);
      return true;
    });
    assert.equal(bytes().length, 0);
  });
}

test('bounds handshake headers, validates syntax, and times out an unresponsive proxy', async t => {
  for (const response of ['HTTP/1.1 200 OK\r\nX-Large: ' + 'x'.repeat(500),
    'HTTP/1.1 200 OK\r\n bad-folded-header\r\n\r\n', 'HTTP/1.1 200 OK\r\nX-Test: bad\0value\r\n\r\n']) {
    const proxy = await proxyFixture(t, socket => socket.write(response));
    await assert.rejects(run(proxy, { maxHeaderBytes: 256 }), { code: 'SSH_PROXY_RESPONSE' });
  }
  const silent = await proxyFixture(t, () => {});
  await assert.rejects(run(silent, { connectTimeoutMs: 25 }), { code: 'SSH_PROXY_TIMEOUT' });
});

test('closed or unavailable proxy never contacts the direct destination', async t => {
  let directConnections = 0;
  const destination = net.createServer(socket => { directConnections++; socket.end('must not reach this'); });
  const port = await listen(t, destination);
  const temp = net.createServer();
  temp.listen(0, '127.0.0.1');
  await once(temp, 'listening');
  const refusedPort = temp.address().port;
  await new Promise(resolve => temp.close(resolve));
  const selected = { host: '127.0.0.1', port };
  await assert.rejects(runSshProxy({ ...selected, allowedTargets: [selected],
    proxyUrl: `http://${credentials}@127.0.0.1:${refusedPort}`, input: Readable.from([]), output: collector().output }),
  { code: 'SSH_PROXY_CONNECT' });
  const closed = await proxyFixture(t, socket => socket.end());
  await assert.rejects(run(closed, { ...selected, allowedTargets: [selected] }), { code: 'SSH_PROXY_RESPONSE' });
  assert.equal(directConnections, 0);
});

test('environment policy never falls back to the destination after proxy refusal, closure or connection failure', async t => {
  let directConnections = 0;
  const destination = net.createServer(socket => { directConnections++; socket.end('must not reach this'); });
  const port = await listen(t, destination);
  const selected = { host: '127.0.0.1', port, targetPolicy: 'environment', allowedTargets: undefined };
  for (const status of [403, 407, 502]) {
    const proxy = await proxyFixture(t, socket => socket.end(`HTTP/1.1 ${status} Refused\r\n\r\n`));
    await assert.rejects(run(proxy, selected), { code: `SSH_PROXY_HTTP_${status}` });
  }
  const closed = await proxyFixture(t, socket => socket.end());
  await assert.rejects(run(closed, selected), { code: 'SSH_PROXY_RESPONSE' });
  const unavailable = net.createServer();
  unavailable.listen(0, '127.0.0.1');
  await once(unavailable, 'listening');
  const refusedPort = unavailable.address().port;
  await new Promise(resolve => unavailable.close(resolve));
  await assert.rejects(run({ url: `http://${credentials}@127.0.0.1:${refusedPort}` }, selected),
    { code: 'SSH_PROXY_CONNECT' });
  assert.equal(directConnections, 0);
});

test('CLI environment flag uses authenticated CONNECT without a targets file while the original form still requires one', { timeout: 5000 }, async t => {
  const proxy = await proxyFixture(t, socket => {
    socket.write('HTTP/1.1 200 OK\r\n\r\nSSH-2.0-unregistered-fixture\r\n');
    socket.on('end', () => socket.end());
  });
  const argv = ['--host', 'unregistered-ssh.invalid', '--port', '2207'];
  const environment = { ENVARA_SSH_PROXY_URL: proxy.url };
  const accepted = await invokeCli(t, [...argv, '--environment-targets'], environment);
  assert.equal(accepted.code, 0, accepted.stderr);
  assert.equal(accepted.signal, null);
  assert.equal(accepted.stdout.toString(), 'SSH-2.0-unregistered-fixture\r\n');
  assert.equal(accepted.stderr, '');
  assert.equal(proxy.requests.length, 1);
  assert.match(proxy.requests[0], /^CONNECT unregistered-ssh\.invalid:2207 HTTP\/1\.1\r\n/);
  assert.ok(proxy.requests[0].includes(`\r\nProxy-Authorization: ${authorization}`));
  const refused = await invokeCli(t, argv, environment);
  assert.equal(refused.code, 1);
  assert.equal(refused.stdout.length, 0);
  assert.match(refused.stderr, /SSH proxy configuration is unavailable or invalid/);
  assert.equal(proxy.requests.length, 1);
});

test('CLI rejects misplaced, repeated or unknown environment flags and invalid environment targets without connecting', { timeout: 5000 }, async t => {
  const proxy = await proxyFixture(t, socket => socket.destroy());
  const argv = ['--host', target.host, '--port', String(target.port)];
  for (const args of [
    [...argv, '--all-targets'], ['--environment-targets', ...argv],
    ['--host', target.host, '--environment-targets', '--port', String(target.port)],
    [...argv, '--environment-targets', '--environment-targets'],
    ['--port', String(target.port), '--host', target.host, '--environment-targets'],
    ['--host', 'bad\r\nhost', '--port', String(target.port), '--environment-targets'],
    ['--host', target.host, '--port', '65536', '--environment-targets'],
  ]) {
    const result = await invokeCli(t, args, { ENVARA_SSH_PROXY_URL: proxy.url });
    assert.equal(result.code, 1);
    assert.equal(result.stdout.length, 0);
    assert.match(result.stderr, /SSH proxy configuration is unavailable or invalid/);
    assert.doesNotMatch(result.stderr, /fixture-password|Basic|127\.0\.0\.1|bad/);
  }
  const result = await invokeCli(t, [...argv, '--environment-targets'], {});
  assert.equal(result.code, 1);
  assert.equal(result.stdout.length, 0);
  assert.match(result.stderr, /SSH proxy configuration is unavailable or invalid/);
  assert.equal(proxy.requests.length, 0);
});

test('HTTPS proxy verifies certificates even when the inherited environment disables TLS checks', async t => {
  const { root, file } = await targetFile(t);
  const certificate = path.join(root, 'fixture-ca.pem');
  await writeFile(certificate, cert);
  const requests = [];
  const server = tls.createServer({ key, cert, allowHalfOpen: true }, socket => {
    socket.once('data', chunk => {
      requests.push(chunk.toString());
      socket.write('HTTP/1.1 200 OK\r\n\r\nSSH-2.0-fixture\r\n');
      socket.on('end', () => socket.end());
    });
  });
  server.on('tlsClientError', () => {});
  const port = await listen(t, server);
  const invoke = async trusted => {
    const env = { ...process.env, ENVARA_SSH_TARGETS: file, ENVARA_SSH_PROXY_URL: `https://${credentials}@127.0.0.1:${port}`,
      NODE_TLS_REJECT_UNAUTHORIZED: '0' };
    delete env.NODE_EXTRA_CA_CERTS;
    if (trusted) env.NODE_EXTRA_CA_CERTS = certificate;
    const child = spawn(process.execPath, [helperPath, '--host', target.host, '--port', String(target.port)], { env });
    t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
    let stdout = '', stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.stdin.end();
    const [code] = await once(child, 'close');
    return { code, stdout, stderr };
  };
  const refused = await invoke(false);
  assert.equal(refused.code, 1);
  assert.equal(refused.stdout, '');
  assert.equal(requests.length, 0);
  assert.match(refused.stderr, /SSH proxy connection failed/);
  assert.doesNotMatch(refused.stderr, /fixture-password|Basic/);
  const accepted = await invoke(true);
  assert.equal(accepted.code, 0, accepted.stderr);
  assert.equal(accepted.stdout, 'SSH-2.0-fixture\r\n');
  assert.equal(requests.length, 1);
  assert.ok(requests[0].includes(`Proxy-Authorization: ${authorization}`));
});

test('aborting a connected tunnel closes the owned proxy socket', async t => {
  let accept;
  let close;
  const accepted = new Promise(resolve => { accept = resolve; });
  const closed = new Promise(resolve => { close = resolve; });
  const proxy = await proxyFixture(t, socket => {
    socket.once('close', close);
    socket.on('end', () => socket.end());
    socket.write('HTTP/1.1 200 OK\r\n\r\n');
    accept();
  });
  const abort = new AbortController();
  const result = run(proxy, { input: new PassThrough(), signal: abort.signal });
  const rejected = assert.rejects(result, { code: 'SSH_PROXY_CANCELLED' });
  await accepted;
  abort.abort();
  await rejected;
  await closed;
});

test('CLI forwards remote EOF while its stdin half remains open', { timeout: 5000 }, async t => {
  const { file } = await targetFile(t);
  let received = '';
  const proxy = await proxyFixture(t, socket => {
    socket.on('data', chunk => { received += chunk; });
    socket.end('HTTP/1.1 200 OK\r\n\r\nremote finished');
  });
  const child = spawn(process.execPath, [helperPath, '--host', target.host, '--port', String(target.port)], {
    env: { ...process.env, ENVARA_SSH_TARGETS: file, ENVARA_SSH_PROXY_URL: proxy.url }, stdio: ['pipe', 'pipe', 'pipe'],
  });
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  await once(child.stdout, 'end');
  assert.equal(stdout, 'remote finished');
  assert.equal(child.exitCode, null);
  const exit = once(child, 'exit');
  child.stdin.end('input after remote EOF');
  assert.deepEqual(await exit, [0, null], stderr);
  assert.equal(received, 'input after remote EOF');
});

test('CLI closes a POSIX stdout pipe on remote EOF before stdin ends', { timeout: 5000, skip: process.platform === 'win32' }, async t => {
  const { file } = await targetFile(t);
  let received = '';
  const proxy = await proxyFixture(t, socket => {
    socket.on('data', chunk => { received += chunk; });
    socket.end('HTTP/1.1 200 OK\r\n\r\nremote pipe finished');
  });
  // Node spawn pipes use sockets on POSIX. A shell pipeline makes fd 1 a
  // real pipe, matching the descriptors supplied by OpenSSH ProxyCommand.
  const child = spawn('/bin/sh', ['-c', '"$1" "$2" --host "$3" --port "$4" | { /bin/cat; /bin/echo PIPE_EOF >&2; }', 'ssh-pipe-fixture',
    process.execPath, helperPath, target.host, String(target.port)], {
    env: { ...process.env, ENVARA_SSH_TARGETS: file, ENVARA_SSH_PROXY_URL: proxy.url },
    detached: true, stdio: ['pipe', 'pipe', 'pipe'],
  });
  t.after(() => {
    if (child.exitCode === null) { try { process.kill(-child.pid, 'SIGKILL'); } catch {} }
  });
  let stdout = '', stderr = '';
  const payload = new Promise(resolve => child.stdout.on('data', chunk => {
    stdout += chunk;
    if (stdout === 'remote pipe finished') resolve();
  }));
  // The waiting shell retains its own stdout descriptor. The consumer reports
  // EOF independently, while the first pipeline process still owns stdin.
  const eof = new Promise(resolve => child.stderr.on('data', chunk => {
    stderr += chunk;
    if (stderr.includes('PIPE_EOF\n')) resolve();
  }));
  await Promise.all([payload, eof]);
  assert.equal(stdout, 'remote pipe finished');
  assert.equal(child.exitCode, null);
  const exit = once(child, 'exit');
  child.stdin.end('input after pipe EOF');
  assert.deepEqual(await exit, [0, null]);
  assert.equal(received, 'input after pipe EOF');
});

test('CLI cancellation exits even when a POSIX stdout pipe remains blocked', { timeout: 6000, skip: process.platform === 'win32' }, async t => {
  const { root, file } = await targetFile(t);
  const fifo = path.join(root, 'blocked-output');
  const mkfifo = spawn('mkfifo', [fifo], { env: { PATH: '/usr/bin:/bin' }, stdio: 'ignore' });
  assert.deepEqual(await once(mkfifo, 'exit'), [0, null]);
  const reader = await open(fifo, constants.O_RDONLY | constants.O_NONBLOCK);
  t.after(() => reader.close());
  const proxy = await proxyFixture(t, socket => {
    socket.write('HTTP/1.1 200 OK\r\n\r\n');
    socket.write(Buffer.alloc(4 * 1024 * 1024, 0x69));
  });
  // Have the shell open the write end: Node's inherited stdio setup can mark
  // an already-open FIFO nonblocking, unlike OpenSSH's blocking POSIX pipe.
  const child = spawn('/bin/sh', ['-c',
    '"$1" "$2" --host "$3" --port "$4" <&0 > "$5" & helper=$!; printf "HELPER_PID:%s\\n" "$helper" >&2; wait "$helper"',
    'ssh-blocked-pipe-fixture', process.execPath, helperPath, target.host, String(target.port), fifo], {
    env: { ...process.env, ENVARA_SSH_TARGETS: file, ENVARA_SSH_PROXY_URL: proxy.url },
    detached: true, stdio: ['pipe', 'ignore', 'pipe'],
  });
  const exited = once(child, 'exit');
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      try { process.kill(-child.pid, 'SIGKILL'); } catch {}
    }
    await exited.catch(() => {});
  });
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  // Confirm a real pipe write has begun, then keep its read end open without
  // consuming the remaining bytes. The owned helper must cancel independently.
  const firstByte = Buffer.alloc(1);
  let received = false;
  for (let attempt = 0; attempt < 80 && !received; attempt++) {
    try { received = (await reader.read(firstByte, 0, 1, null)).bytesRead === 1; }
    catch (error) { if (!['EAGAIN', 'EWOULDBLOCK'].includes(error.code)) throw error; }
    if (!received) await new Promise(resolve => setTimeout(resolve, 25));
  }
  assert.equal(received, true, 'the helper must enter the POSIX pipe write');
  await new Promise(resolve => setTimeout(resolve, 25));
  const helperPid = Number(/^HELPER_PID:(\d+)$/m.exec(stderr)?.[1]);
  assert.ok(Number.isSafeInteger(helperPid) && helperPid > 1, 'only the fixture-owned helper may be signalled');
  process.kill(helperPid, 'SIGTERM');
  let timer;
  const result = await Promise.race([exited,
    new Promise(resolve => { timer = setTimeout(() => resolve(null), 2500); }),
  ]).finally(() => clearTimeout(timer));
  assert.deepEqual(result, [143, null], `cancellation must not wait for the pipe consumer to resume: ${stderr}`);
  assert.doesNotMatch(stderr, /fixture-user|fixture-password|Basic|127\.0\.0\.1|\.json/);
});

test('CLI reads session targets and SIGTERM cleans up its owned tunnel without revealing secrets', { timeout: 5000 }, async t => {
  const { file } = await targetFile(t);
  let accept;
  let close;
  const accepted = new Promise(resolve => { accept = resolve; });
  const closed = new Promise(resolve => { close = resolve; });
  const proxy = await proxyFixture(t, socket => {
    socket.once('close', close);
    socket.on('end', () => socket.end());
    socket.write('HTTP/1.1 200 OK\r\n\r\nSSH-2.0-fixture\r\n');
    accept();
  });
  const child = spawn(process.execPath, [helperPath, '--host', target.host, '--port', String(target.port)], {
    env: { ...process.env, ENVARA_SSH_TARGETS: file, ENVARA_SSH_PROXY_URL: proxy.url }, stdio: ['pipe', 'pipe', 'pipe'],
  });
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  await accepted;
  const exit = once(child, 'exit');
  child.kill('SIGTERM');
  assert.deepEqual(await exit, [143, null]);
  await closed;
  assert.doesNotMatch(stderr, /fixture|Basic|127\.0\.0\.1|\.json/);
});
