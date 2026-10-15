import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import net from 'node:net';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { LinkSocketServer, TerminalLinkChannel, linkShimScripts } from '../electron/terminal-link-channel.mjs';
import { processAncestry } from '../electron/link-router.mjs';

const execute = promisify(execFile);
async function channel(t, onLink = async ({ url }) => ({ opened: 'tab', browser: 'PH' })) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-link-')); t.after(() => rm(root, { recursive: true, force: true }));
  const value = new TerminalLinkChannel({ root, onLink });
  await value.listen();
  t.after(() => value.close());
  return value;
}
const post = async (socket, token, body) => {
  try {
    const { stdout } = await execute('/usr/bin/curl', ['--noproxy', '*', '-sS', '--fail', '--max-time', '10', '--unix-socket', socket, '-H', `Authorization: Bearer ${token}`, '--data-binary', body, 'http://localhost/link']);
    return { ok: true, body: stdout };
  } catch (error) { return { ok: false, code: error.code }; }
};

test('a token names its environment and only a lone url is accepted', async t => {
  const seen = [];
  const value = await channel(t, async request => { seen.push(request); return { opened: 'tab', browser: 'PH · AnyTLS' }; });
  const token = value.token('prof_a'), other = value.token('prof_b');
  assert.notEqual(token, other);
  assert.equal(value.token('prof_a'), token, 'one environment keeps one token');
  const socket = value.socketPath;
  assert.ok((await post(socket, token, '{"url":"https://example.com/a"}')).ok);
  assert.deepEqual(seen, [{ profileId: 'prof_a', url: 'https://example.com/a' }]);
  for (const [name, attempt] of [
    ['unknown token', post(socket, 'f'.repeat(64), '{"url":"https://example.com"}')],
    ['no token', post(socket, '', '{"url":"https://example.com"}')],
    ['extra fields', post(socket, token, '{"url":"https://example.com","profileId":"prof_b"}')],
    ['not json', post(socket, token, 'https://example.com')],
    ['not an object', post(socket, token, '"https://example.com"')],
  ]) assert.equal((await attempt).ok, false, name);
  assert.equal(seen.length, 1, 'only the valid request reached the opener');
});

test('the socket and its directory are private, and the scripts replace only the browser opener', async t => {
  const value = await channel(t);
  assert.equal((await stat(value.socketPath)).mode & 0o777, 0o600);
  assert.equal((await stat(path.dirname(value.socketPath))).mode & 0o777, 0o700);
  const scripts = linkShimScripts();
  assert.deepEqual(Object.keys(scripts).sort(), ['browser', 'envara-open', 'open']);
  assert.ok(scripts.browser.includes('exec "$(dirname "$0")/open" "$@"'), 'BROWSER callers reach the same channel');
  for (const [name, source] of Object.entries(scripts)) {
    assert.match(name, /^[a-z][a-z-]{1,16}$/); assert.ok(source.startsWith('#!/bin/sh\n'));
    if (name === 'open') assert.ok(source.includes('ENVARA_LINK_TOKEN'), 'the opener reports through the channel');
    else { assert.ok(source.includes('/open" "$@"'), `${name} runs the same opener`);
      assert.ok(!source.includes('ENVARA_LINK_TOKEN'), `${name} carries no credential of its own`); }
  }
  assert.ok(scripts.open.includes('exec /usr/bin/open "$@"'), 'everything else keeps the system opener');
  assert.ok(scripts.open.includes('passthrough=1'), 'flags are never reported as links');
});

test('the open shim says what happened to every link, and never opens one on the host by itself', async t => {
  const seen = [];
  const value = await channel(t, async ({ url }) => { seen.push(url); return url.includes('outside') ? { opened: 'default', browser: null } : { opened: 'environment', browser: '测试境舱' }; });
  const directory = await value.executableDirectory('prof_a');
  const shim = path.join(directory, 'open');
  const run = async (args, env) => {
    // The terminal's own locale: macOS /bin/sh mis-expands $name followed by Chinese text in it.
    try { const { stdout, stderr } = await execute(shim, args, { env: { PATH: '/usr/bin:/bin', TMPDIR: os.tmpdir(), LANG: 'zh_CN.UTF-8', ...env } }); return { code: 0, stdout, stderr }; }
    catch (error) { return { code: error.code, stdout: error.stdout, stderr: error.stderr }; }
  };
  const channelEnv = value.environment('prof_a');
  // Opened in the environment's browser: said, and the exact link was reported.
  const opened = await run(['https://example.com/oauth?next="a b"'], channelEnv);
  assert.equal(opened.code, 0, opened.stderr);
  assert.match(opened.stderr, /正在「测试境舱」中打开 https:\/\/example\.com\/oauth/);
  assert.deepEqual(seen, ['https://example.com/oauth?next="a b"'], 'quotes in a link are carried intact');
  // Sent to the host browser on purpose: said, and marked as outside the environment.
  const outside = await run(['https://outside.example/'], channelEnv);
  assert.equal(outside.code, 0); assert.match(outside.stderr, /不经过境舱网络/);
  // Without the channel: refused, with a reason, and nothing was started.
  const missing = await run(['https://example.com/'], {});
  assert.equal(missing.code, 1); assert.match(missing.stderr, /没有连上 Envara 的链接通道/);
  // Envara not answering: refused with a reason.
  const silent = await run(['https://example.com/'], { ...channelEnv, ENVARA_LINK_SOCKET: path.join(os.tmpdir(), 'no-such-envara.sock') });
  assert.equal(silent.code, 1); assert.match(silent.stderr, /Envara 没有响应/);
  // A stale token after a restart: refused with what to do.
  const stale = await run(['https://example.com/'], { ...channelEnv, ENVARA_LINK_TOKEN: 'f'.repeat(64) });
  assert.equal(stale.code, 1); assert.match(stale.stderr, /新建一个终端/);
  // A link mixed with other arguments is never half-routed.
  const mixed = await run(['-a', 'Safari', 'https://example.com/'], channelEnv);
  assert.equal(mixed.code, 1); assert.match(mixed.stderr, /不能和其他参数一起打开/);
  assert.equal(seen.length, 2, 'only the two good requests reached Envara');
  assert.deepEqual((await import('node:fs/promises').then(fs => fs.readdir(directory))).sort(), ['browser', 'envara-open', 'open']);
  assert.equal((await stat(shim)).mode & 0o777, 0o700);
});

test('a flat socket path is used as-is, replaced if stale, and stays private', async t => {
  /* The native router needs a socket path short enough for a unix socket: macOS
   * caps that at 104 bytes, and the application-support path is longer, so the
   * real one lives under the shared temporary directory. */
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-flat-')); t.after(() => rm(root, { recursive: true, force: true }));
  const flat = `/private/tmp/io.envara.link-router.${process.getuid()}.test-${process.pid}.sock`;
  await writeFile(flat, 'stale');
  const value = new LinkSocketServer({ root: '/nonexistent-support', socketPath: flat, onLink: async () => ({ opened: 'tab', browser: 'PH' }) });
  await value.listen();
  t.after(() => value.close().then(() => rm(flat, { force: true })));
  assert.equal(value.socketPath, flat, 'the path is used exactly as given');
  assert.equal((await stat(flat)).mode & 0o777, 0o600);
  assert.equal((await post(flat, '', '{"url":"https://example.com"}')).ok, false, 'it still authenticates');
  await value.close();
  assert.equal(await stat(flat).then(() => true, () => false), false, 'the socket is removed on close');
  // A path macOS cannot serve is refused rather than trusted, and so is a flat
  // path outside a temporary directory.
  assert.throws(() => new LinkSocketServer({ root, socketPath: path.join(root, 'x'.repeat(120), 'y.sock'), onLink: async () => ({}) }),
    error => error.code === 'LINK_CHANNEL_UNAVAILABLE');
  for (const place of ['/etc', '/Applications'])
    await assert.rejects(() => new LinkSocketServer({ root, socketPath: path.join(place, 'io.envara.test.sock'), onLink: async () => ({}) }).listen(),
      error => error.code === 'LINK_CHANNEL_UNAVAILABLE', `${place} is not a temporary directory`);
});

/* The exact request native/macos-link-router/main.swift sends: no token, a url
 * and the sender's pid. Refusing it sent every attached application's link
 * (Notion's Google sign-in) to the host browser. */
const helperRequest = (socketPath, body) => new Promise((resolve, reject) => {
  const socket = net.connect(socketPath, () => {
    socket.end(`POST /link HTTP/1.1\r\nhost: localhost\r\ncontent-length: ${Buffer.byteLength(body)}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n${body}`);
  });
  let data = ''; socket.on('data', chunk => { data += chunk; }); socket.on('end', () => resolve(data.split('\r\n')[0])); socket.on('error', reject);
});

test('the system link helper is heard without a token, and only with a url and its sender', async t => {
  const seen = [];
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-router-')); t.after(() => rm(root, { recursive: true, force: true }));
  const socketPath = `/private/tmp/io.envara.link-router.${process.getuid()}.helper-test-${process.pid}.sock`;
  const router = new LinkSocketServer({ root, socketPath, sender: 'owner', onLink: async request => { seen.push(request); return { opened: 'environment', browser: 'Notion 的境舱' }; } });
  await router.listen(); t.after(() => router.close());
  assert.equal((await stat(socketPath)).mode & 0o777, 0o600, 'only this user can reach it');
  assert.equal(await helperRequest(socketPath, JSON.stringify({ url: 'https://accounts.google.com/o/oauth2/auth', senderPid: 4242 })), 'HTTP/1.1 200 OK');
  assert.deepEqual(seen, [{ url: 'https://accounts.google.com/o/oauth2/auth', pid: 4242 }]);
  for (const body of [JSON.stringify({ url: 'https://example.com' }), JSON.stringify({ url: 'https://example.com', senderPid: 'x' }), JSON.stringify({ url: 'https://example.com', senderPid: 1, profileId: 'prof_x' }), '[]', 'not json'])
    assert.equal(await helperRequest(socketPath, body), 'HTTP/1.1 400 Bad Request', body);
  // A terminal's channel still needs its token, even for the same body.
  const terminal = await channel(t);
  assert.equal(await helperRequest(terminal.socketPath, JSON.stringify({ url: 'https://example.com', senderPid: 4242 })), 'HTTP/1.1 403 Forbidden');
});
