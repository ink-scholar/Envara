import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { chmod, mkdtemp, realpath, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { prepareClaudeCredentials } from '../electron/claude-credential-preflight.mjs';

const execute = promisify(execFile);
const client = fileURLToPath(new URL('../electron/claude-credential-preflight.mjs', import.meta.url));

async function fixture(t) {
  const parent = os.tmpdir().length < 40 ? os.tmpdir() : '/tmp';
  const root = await realpath(await mkdtemp(path.join(parent, 'envara-credential-client-')));
  await chmod(root, 0o700);
  const socketPath = path.join(root, 'broker.sock'), token = randomBytes(32).toString('hex');
  const state = { status: 200, body: { ready: true }, hang: false, calls: [], sockets: new Set() };
  const server = http.createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    const authorized = request.headers.authorization === `Bearer ${token}`;
    state.calls.push({ method: request.method, url: request.url, body, authorized });
    if (!authorized) { response.writeHead(403); response.end('{"error":"unauthorized"}'); return; }
    if (state.hang) return;
    response.writeHead(state.status, { 'Content-Type': 'application/json' });
    response.end(typeof state.body === 'string' ? state.body : JSON.stringify(state.body));
  });
  server.on('connection', socket => { state.sockets.add(socket); socket.once('close', () => state.sockets.delete(socket)); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socketPath, resolve); });
  await chmod(socketPath, 0o600);
  t.after(async () => {
    for (const socket of state.sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  });
  return { root, state, environment: { ENVARA_BROWSER_SOCKET: socketPath, ENVARA_BROWSER_TOKEN: token } };
}

test('credential client sends only an empty authenticated request to the pinned local socket', async t => {
  const f = await fixture(t);
  assert.deepEqual(await prepareClaudeCredentials({ environment: { ...f.environment,
    HOME: '/private/unrelated-home', ANTHROPIC_API_KEY: 'synthetic-never-transmitted' } }), { ready: true });
  assert.deepEqual(f.state.calls, [{ method: 'POST', url: '/credentials/prepare', body: '{}', authorized: true }]);
});

test('missing, malformed or unbounded authority is rejected before any request', async t => {
  const f = await fixture(t), original = f.environment;
  for (const environment of [{}, { ...original, ENVARA_BROWSER_SOCKET: undefined },
    { ...original, ENVARA_BROWSER_SOCKET: 'relative/socket' }, { ...original, ENVARA_BROWSER_SOCKET: '/private/line\nbreak' },
    { ...original, ENVARA_BROWSER_SOCKET: '/'.padEnd(101, 'x') }, { ...original, ENVARA_BROWSER_TOKEN: undefined },
    { ...original, ENVARA_BROWSER_TOKEN: 'F'.repeat(64) }, { ...original, ENVARA_BROWSER_TOKEN: 'x' },
    { ...original, ENVARA_BROWSER_TOKEN: `${original.ENVARA_BROWSER_TOKEN}\n` }]) {
    await assert.rejects(prepareClaudeCredentials({ environment }), error => {
      assert.equal(error.code, 'CLAUDE_KEYCHAIN_UNAVAILABLE');
      assert(!error.message.includes(original.ENVARA_BROWSER_TOKEN));
      assert(!error.message.includes(f.root));
      return true;
    });
  }
  for (const timeoutMs of [0, -1, 40001, Infinity, 1.5, '100'])
    await assert.rejects(prepareClaudeCredentials({ environment: original, timeoutMs }), { code: 'CLAUDE_KEYCHAIN_UNAVAILABLE' });
  assert.equal(f.state.calls.length, 0);
});

test('credential client refuses foreign tokens and does not follow server redirects', async t => {
  const f = await fixture(t);
  await assert.rejects(prepareClaudeCredentials({ environment: { ...f.environment, ENVARA_BROWSER_TOKEN: 'f'.repeat(64) } }), { code: 'CLAUDE_KEYCHAIN_UNAVAILABLE' });
  f.state.status = 302;
  await assert.rejects(prepareClaudeCredentials({ environment: f.environment }), { code: 'CLAUDE_KEYCHAIN_UNAVAILABLE' });
  assert.equal(f.state.calls.length, 2);
});

test('credential client accepts only the fixed success and failure frames', async t => {
  const f = await fixture(t), secret = '/private/synthetic-credential';
  f.state.status = 503; f.state.body = { error: 'credential-preparation-failed', code: 'CLAUDE_KEYCHAIN_LOCKED' };
  await assert.rejects(prepareClaudeCredentials({ environment: f.environment }), { code: 'CLAUDE_KEYCHAIN_LOCKED' });
  f.state.body.keychainDiagnostic = { stage: 'host-query', osStatus: -25308 };
  await assert.rejects(prepareClaudeCredentials({ environment: f.environment }), error => {
    assert.deepEqual(error.keychainDiagnostic, { stage: 'host-query', osStatus: -25308 });
    return error.code === 'CLAUDE_KEYCHAIN_LOCKED';
  });
  for (const keychainDiagnostic of [null, [], { stage: secret, osStatus: null }, { stage: 'select', osStatus: 2147483648 },
    { stage: 'select', osStatus: -2147483649 }, { stage: 'select', osStatus: 'private' },
    { stage: 'select', osStatus: 0, path: secret }, { stage: 'select' }]) {
    f.state.body.keychainDiagnostic = keychainDiagnostic;
    await assert.rejects(prepareClaudeCredentials({ environment: f.environment }), { code: 'CLAUDE_KEYCHAIN_PROTOCOL_ERROR' });
  }
  for (const [status, body, expected] of [
    [200, 'not-json', 'CLAUDE_KEYCHAIN_PROTOCOL_ERROR'],
    [200, null], [200, []], [200, { ready: false }], [200, { ready: true, path: secret }],
    [503, { error: 'credential-preparation-failed', code: 'CLAUDE_KEYCHAIN_SECRET' }],
    [503, { error: 'credential-preparation-failed', code: 'CLAUDE_KEYCHAIN_LOCKED', message: secret }],
    [500, { ready: true }], [403, { error: secret }],
  ]) {
    f.state.status = status; f.state.body = body;
    await assert.rejects(prepareClaudeCredentials({ environment: f.environment }), error => {
      assert.equal(error.code, expected ?? 'CLAUDE_KEYCHAIN_UNAVAILABLE');
      assert(!error.message.includes(secret)); assert.equal(error.cause, undefined);
      assert.equal(error.stdout, undefined); assert.equal(error.stderr, undefined);
      return true;
    });
  }
});

test('credential client bounds reply size and request duration and closes failed connections', async t => {
  const f = await fixture(t);
  f.state.body = 'x'.repeat(1025);
  await assert.rejects(prepareClaudeCredentials({ environment: f.environment }), { code: 'CLAUDE_KEYCHAIN_PROTOCOL_ERROR' });
  f.state.hang = true;
  await assert.rejects(prepareClaudeCredentials({ environment: f.environment, timeoutMs: 20 }), { code: 'CLAUDE_KEYCHAIN_TIMEOUT' });
  f.state.hang = false; f.state.body = { ready: true };
  assert.deepEqual(await prepareClaudeCredentials({ environment: f.environment }), { ready: true });
  await assert.rejects(prepareClaudeCredentials({ environment: { ...f.environment, ENVARA_BROWSER_SOCKET: path.join(f.root, 'absent.sock') } }), { code: 'CLAUDE_KEYCHAIN_UNAVAILABLE' });
});

test('the physical client exits before launch with fixed diagnostics and no private response text', async t => {
  const f = await fixture(t), environment = { PATH: '/usr/bin:/bin', ...f.environment };
  assert.deepEqual(await execute(process.execPath, [client], { env: environment }), { stdout: '', stderr: '' });
  f.state.status = 503; f.state.body = { error: 'credential-preparation-failed', code: 'CLAUDE_KEYCHAIN_MISSING' };
  await assert.rejects(execute(process.execPath, [client], { env: environment }), error =>
    error.code === 78 && error.stdout === '' && error.stderr.includes('CLAUDE_KEYCHAIN_MISSING')
    && !error.stderr.includes(f.environment.ENVARA_BROWSER_TOKEN) && !error.stderr.includes(f.root));
  f.state.body.keychainDiagnostic = { stage: 'host-query', osStatus: -25307 };
  await assert.rejects(execute(process.execPath, [client], { env: environment }), error =>
    error.code === 78 && error.stdout === '' && error.stderr.includes('[host-query; osStatus=-25307]')
    && !error.stderr.includes(f.environment.ENVARA_BROWSER_TOKEN) && !error.stderr.includes(f.root));
  const secret = '/private/synthetic-token';
  f.state.body = { error: secret, code: 'CLAUDE_KEYCHAIN_LOCKED', private: secret };
  await assert.rejects(execute(process.execPath, [client], { env: environment }), error =>
    error.code === 78 && error.stdout === '' && error.stderr.includes('CLAUDE_KEYCHAIN_UNAVAILABLE') && !error.stderr.includes(secret));
  const before = f.state.calls.length;
  await assert.rejects(execute(process.execPath, [client, secret], { env: environment }), error =>
    error.code === 78 && error.stdout === '' && error.stderr.includes('CLAUDE_KEYCHAIN_INVALID_ARGUMENT') && !error.stderr.includes(secret));
  assert.equal(f.state.calls.length, before);
});
