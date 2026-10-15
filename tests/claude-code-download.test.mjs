import assert from 'node:assert/strict';
import test from 'node:test';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { mkdtemp, realpath, chmod, readFile, lstat, writeFile, rm, rename, symlink } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { createClaudeNativeDownloader } from '../electron/claude-code-download.mjs';
import { cert, downloadFixture, proxyUsername, proxyPassword, proxyAuth } from './claude-download-fixture.mjs';

async function setup(t, fixtureOptions = {}, downloaderOptions = {}) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-claude-download-')));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const fixture = await downloadFixture(t, fixtureOptions);
  const destination = path.join(root, "Claude's staged download"), progress = [], signatures = [];
  const download = createClaudeNativeDownloader({ baseURL: fixture.baseURL, tlsOptions: { ca: cert }, deadlineMs: 3000,
    verifySignature: async (filename, { signal }) => {
      signatures.push({ filename, aborted: signal.aborted });
      assert.equal((await lstat(filename)).mode & 0o777, 0o600);
      assert.deepEqual(await readFile(filename), fixture.binary);
    }, ...downloaderOptions });
  const run = (options = {}) => download({ destination, proxyUrl: fixture.proxyUrl,
    platform: 'darwin', arch: 'arm64', onProgress: update => progress.push(update), ...options });
  return { ...fixture, root, destination, progress, signatures, run };
}

async function absent(filename) {
  await assert.rejects(lstat(filename), { code: 'ENOENT' });
}

async function rejectedCleanly(fixture, code, options) {
  let failure;
  await assert.rejects(fixture.run(options), error => {
    failure = error;
    assert.equal(error.code, code);
    return true;
  });
  const publicData = String(failure) + failure.stack + JSON.stringify(fixture.progress);
  for (const secret of [proxyUsername, proxyPassword, proxyAuth, fixture.proxyUrl]) assert.equal(publicData.includes(secret), false);
  await absent(fixture.destination);
}

for (const arch of ['arm64', 'x64']) test(`download success for ${arch} uses authenticated CONNECT for all three requests`, async t => {
  const fixture = await setup(t);
  const names = ['NO_PROXY', 'no_proxy', 'HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy'];
  const previous = names.map(name => [name, process.env[name]]);
  for (const name of names) process.env[name] = /no_proxy/i.test(name) ? '*' : 'http://127.0.0.1:1';
  t.after(() => { for (const [name, value] of previous) { if (value === undefined) delete process.env[name]; else process.env[name] = value; } });
  const result = await fixture.run({ arch });
  assert.deepEqual(result, { version: '2.1.300', checksum: fixture.checksum, size: fixture.binary.length });
  assert.deepEqual(await readFile(fixture.destination), fixture.binary);
  assert.equal((await lstat(fixture.destination)).mode & 0o777, 0o600, 'verification does not prematurely make the staging file executable');
  assert.deepEqual(fixture.requests.map(request => request.url), [
    '/releases/latest', '/releases/2.1.300/manifest.json', `/releases/2.1.300/darwin-${arch}/claude`,
  ]);
  assert.equal(fixture.connects.length, 3);
  for (const connection of fixture.connects) {
    assert.equal(connection.target, `localhost:${fixture.targetPort}`, 'destination hostname is delegated to CONNECT');
    assert.equal(connection.auth, proxyAuth);
  }
  for (const request of fixture.requests) {
    assert.equal(request.headers['accept-encoding'], 'identity');
    assert.equal(request.headers['proxy-authorization'], undefined, 'proxy credentials must not reach the HTTPS origin');
  }
  assert.deepEqual(fixture.signatures, [{ filename: fixture.destination, aborted: false }]);
  assert.deepEqual([...new Set(fixture.progress.map(update => update.phase))], ['metadata', 'downloading', 'verifying']);
  assert.ok(fixture.progress.some(update => update.receivedBytes === fixture.binary.length));
  const output = JSON.stringify({ result, progress: fixture.progress });
  for (const secret of [proxyUsername, proxyPassword, proxyAuth]) assert.equal(output.includes(secret), false);
});

test('missing, nonlocal, malformed and unsupported proxy routes refuse without requests', async t => {
  const fixture = await setup(t);
  for (const proxyUrl of [undefined, '', 'http://localhost:8080', 'http://192.0.2.1:8080', 'https://127.0.0.1:8080',
    'socks5://127.0.0.1:8080', 'http://127.0.0.1', 'http://127.0.0.1:8080/path', 'http://127.0.0.1:8080/?key=x',
    'http://127.0.0.1:8080/#fragment', 'http://bad%0d:password@127.0.0.1:8080']) {
    await rejectedCleanly(fixture, 'CLAUDE_CODE_DOWNLOAD_ROUTE_REQUIRED', { proxyUrl });
  }
  assert.equal(fixture.requests.length, 0); assert.equal(fixture.connects.length, 0);
});

test('a refused proxy connection never falls back to the reachable target', async t => {
  const fixture = await setup(t);
  const temporary = net.createServer();
  await new Promise(resolve => temporary.listen(0, '127.0.0.1', resolve));
  const port = temporary.address().port;
  await new Promise(resolve => temporary.close(resolve));
  await rejectedCleanly(fixture, 'CLAUDE_CODE_DOWNLOAD_FAILED', { proxyUrl: `http://127.0.0.1:${port}` });
  assert.equal(fixture.requests.length, 0); assert.equal(fixture.signatures.length, 0);
});

test('proxy 407 fails without a direct request or credential-bearing error', async t => {
  const fixture = await setup(t, { proxyMode: 'deny' });
  await rejectedCleanly(fixture, 'CLAUDE_CODE_DOWNLOAD_FAILED');
  assert.equal(fixture.connects.length, 1); assert.equal(fixture.requests.length, 0);
});

test('untrusted HTTPS certificate is refused even when a test seam requests insecure TLS', async t => {
  const fixture = await setup(t, {}, { tlsOptions: { rejectUnauthorized: false } });
  await rejectedCleanly(fixture, 'CLAUDE_CODE_DOWNLOAD_FAILED');
  assert.equal(fixture.connects.length, 1); assert.equal(fixture.requests.length, 0);
});

test('each release response rejects redirects instead of following another path or origin', async t => {
  for (const [index, suffix] of ['latest', 'manifest.json', '/claude'].entries()) {
    await t.test(suffix, async sub => {
      const fixture = await setup(sub, { respond: (request, response, { defaults }) => {
        if (request.url.endsWith(suffix)) { response.writeHead(302, { Location: 'https://127.0.0.1:1/untrusted' }); response.end(); }
        else defaults(request, response);
      } });
      await rejectedCleanly(fixture, 'CLAUDE_CODE_DOWNLOAD_FAILED');
      assert.equal(fixture.requests.length, index + 1); assert.equal(fixture.connects.length, index + 1);
      assert.equal(fixture.signatures.length, 0);
    });
  }
});

test('invalid and oversized release metadata cannot choose a download', async t => {
  const cases = [
    ['version mismatch', { mutateManifest: manifest => { manifest.version = '2.1.299'; } }],
    ['invalid checksum', { mutateManifest: manifest => { manifest.platforms['darwin-arm64'].checksum = 'not-a-hash'; } }],
    ['noninteger size', { mutateManifest: manifest => { manifest.platforms['darwin-arm64'].size = 1.5; } }],
    ['over maximum size', { mutateManifest: manifest => { manifest.platforms['darwin-arm64'].size = 512 * 1024 * 1024 + 1; } }],
    ['missing platform', { mutateManifest: manifest => { delete manifest.platforms['darwin-arm64']; } }],
    ['binary path traversal', { mutateManifest: manifest => { manifest.platforms['darwin-arm64'].binary = '../claude'; } }],
    ['release path traversal', { latest: '../../outside' }],
    ['latest body limit', { latest: '1'.repeat(257) }],
    ['manifest body limit', { respond: (request, response, { defaults }) => {
      if (request.url.endsWith('manifest.json')) response.end(' '.repeat(128 * 1024 + 1)); else defaults(request, response);
    } }],
    ['malformed JSON', { respond: (request, response, { defaults }) => {
      if (request.url.endsWith('manifest.json')) response.end('{broken'); else defaults(request, response);
    } }],
  ];
  for (const [name, options] of cases) await t.test(name, async sub => {
    const fixture = await setup(sub, options);
    await rejectedCleanly(fixture, 'CLAUDE_CODE_DOWNLOAD_INTEGRITY_FAILED');
    assert.ok(fixture.requests.length <= 2); assert.equal(fixture.signatures.length, 0);
  });
});

test('binary checksum and declared or streamed lengths are enforced before signature verification', async t => {
  const cases = [
    ['wrong checksum', { mutateManifest: manifest => { manifest.platforms['darwin-arm64'].checksum = '0'.repeat(64); } }],
    ['content length mismatch', { mutateManifest: manifest => { manifest.platforms['darwin-arm64'].size++; } }],
    ['short streamed binary', { respond: (request, response, { defaults, binary }) => {
      if (request.url.endsWith('/claude')) { response.write(binary.subarray(0, 16)); response.end(); } else defaults(request, response);
    } }],
    ['long streamed binary', { respond: (request, response, { defaults, binary }) => {
      if (request.url.endsWith('/claude')) { response.write(binary); response.end('extra bytes'); } else defaults(request, response);
    } }],
  ];
  for (const [name, options] of cases) await t.test(name, async sub => {
    const fixture = await setup(sub, options);
    await rejectedCleanly(fixture, 'CLAUDE_CODE_DOWNLOAD_INTEGRITY_FAILED');
    assert.equal(fixture.requests.length, 3); assert.equal(fixture.signatures.length, 0);
  });
});

test('non-identity content encoding is rejected without trusting compressed bytes', async t => {
  const fixture = await setup(t, { respond: (_request, response) => {
    response.writeHead(200, { 'Content-Encoding': 'gzip' }); response.end('untrusted compressed response');
  } });
  await rejectedCleanly(fixture, 'CLAUDE_CODE_DOWNLOAD_FAILED');
  assert.equal(fixture.requests.length, 1);
});

test('signature refusal discards the verified checksum staging file', async t => {
  let checks = 0;
  const fixture = await setup(t, {}, { verifySignature: async () => {
    checks++; throw Object.assign(new Error('CLAUDE_CODE_DOWNLOAD_SIGNATURE_FAILED'), { code: 'CLAUDE_CODE_DOWNLOAD_SIGNATURE_FAILED' });
  } });
  await rejectedCleanly(fixture, 'CLAUDE_CODE_DOWNLOAD_SIGNATURE_FAILED');
  assert.equal(checks, 1); assert.equal(fixture.requests.length, 3);
});

test('default macOS code-signature verification rejects a checksum-valid executable from another signer', { skip: process.platform !== 'darwin' }, async t => {
  const fixture = await setup(t, {}, { verifySignature: undefined });
  await rejectedCleanly(fixture, 'CLAUDE_CODE_DOWNLOAD_SIGNATURE_FAILED');
  assert.equal(fixture.requests.length, 3);
});

test('cancellation during a streaming download removes only its staging file', async t => {
  const controller = new AbortController();
  const fixture = await setup(t, { respond: (request, response, { defaults, binary }) => {
    if (!request.url.endsWith('/claude')) return defaults(request, response);
    response.writeHead(200, { 'Content-Length': binary.length }); response.write(binary.subarray(0, 16));
    const timer = setTimeout(() => response.end(binary.subarray(16)), 150);
    response.once('close', () => clearTimeout(timer));
  } });
  await rejectedCleanly(fixture, 'CLAUDE_CODE_DOWNLOAD_CANCELLED', { signal: controller.signal, onProgress: update => {
    fixture.progress.push(update);
    if (update.phase === 'downloading' && update.receivedBytes > 0) controller.abort();
  } });
  assert.ok(fixture.progress.some(update => update.receivedBytes === 16));
  assert.equal(fixture.signatures.length, 0);
});

test('cancellation during signature verification prevents a successful commit', async t => {
  const controller = new AbortController(); let checks = 0;
  const fixture = await setup(t, {}, { verifySignature: async () => { checks++; controller.abort(); } });
  await rejectedCleanly(fixture, 'CLAUDE_CODE_DOWNLOAD_CANCELLED', { signal: controller.signal });
  assert.equal(checks, 1);
});

test('pre-cancelled download does not contact the route', async t => {
  const fixture = await setup(t), controller = new AbortController(); controller.abort();
  await rejectedCleanly(fixture, 'CLAUDE_CODE_DOWNLOAD_CANCELLED', { signal: controller.signal });
  assert.equal(fixture.connects.length, 0); assert.equal(fixture.requests.length, 0);
});

test('CONNECT cancellation and absolute deadline terminate silent proxy handshakes', async t => {
  await t.test('deadline', async sub => {
    const fixture = await setup(sub, { proxyMode: 'silent' }, { deadlineMs: 100 });
    const started = performance.now();
    await rejectedCleanly(fixture, 'CLAUDE_CODE_DOWNLOAD_TIMEOUT');
    assert.ok(performance.now() - started < 1500);
    assert.equal(fixture.connects.length, 1); assert.equal(fixture.requests.length, 0);
  });
  await t.test('explicit cancellation', async sub => {
    const fixture = await setup(sub, { proxyMode: 'silent' });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 100); sub.after(() => clearTimeout(timer));
    const started = performance.now();
    await rejectedCleanly(fixture, 'CLAUDE_CODE_DOWNLOAD_CANCELLED', { signal: controller.signal });
    assert.ok(performance.now() - started < 1500);
    assert.equal(fixture.connects.length, 1); assert.equal(fixture.requests.length, 0);
  });
});

test('an existing destination or destination symlink is never overwritten or removed', async t => {
  for (const kind of ['file', 'symlink']) await t.test(kind, async sub => {
    const fixture = await setup(sub);
    const original = Buffer.from('existing user file');
    const other = path.join(fixture.root, 'keep'); await writeFile(other, original, { mode: 0o600 });
    if (kind === 'file') await writeFile(fixture.destination, original, { mode: 0o600 });
    else await symlink(other, fixture.destination);
    const before = await lstat(fixture.destination);
    await assert.rejects(fixture.run(), { code: 'CLAUDE_CODE_DOWNLOAD_FAILED' });
    assert.equal((await lstat(fixture.destination)).ino, before.ino);
    assert.deepEqual(await readFile(fixture.destination), original); assert.deepEqual(await readFile(other), original);
    assert.equal(fixture.requests.length, 2); assert.equal(fixture.signatures.length, 0);
  });
});

test('failure cleanup preserves a replacement destination whose inode it does not own', async t => {
  const replacement = Buffer.from('replacement owner'); let held;
  const fixture = await setup(t, {}, { verifySignature: async filename => {
    held = `${filename}.held`; await rename(filename, held); await writeFile(filename, replacement, { mode: 0o600 });
    throw new Error('synthetic verifier refusal');
  } });
  await assert.rejects(fixture.run(), { code: 'CLAUDE_CODE_DOWNLOAD_FAILED' });
  assert.deepEqual(await readFile(fixture.destination), replacement);
  assert.deepEqual(await readFile(held), fixture.binary);
});

test('unsupported platforms are refused without downloading an unchecked executable', async t => {
  const fixture = await setup(t);
  for (const [platform, arch] of [['linux', 'x64'], ['win32', 'x64'], ['darwin', 'ia32']]) {
    await rejectedCleanly(fixture, 'CLAUDE_CODE_PLATFORM_UNSUPPORTED', { platform, arch });
  }
  assert.equal(fixture.connects.length, 0); assert.equal(fixture.requests.length, 0);
});

test('progress listener exceptions cannot interrupt verified download completion', async t => {
  const fixture = await setup(t);
  const result = await fixture.run({ onProgress: () => { throw new Error('broken UI callback'); } });
  assert.equal(result.checksum, fixture.checksum); assert.equal(fixture.signatures.length, 1);
});

test('agent DEBUG output never prints proxy secrets or Basic credentials', async () => {
  const childEnvironment = { ...process.env, DEBUG: 'https-proxy-agent*' };
  // This is an independent CLI runner, not another worker on the parent's test IPC.
  delete childEnvironment.NODE_TEST_CONTEXT;
  const { stdout, stderr } = await promisify(execFile)(process.execPath,
    ['--test', '--test-name-pattern=download success', fileURLToPath(import.meta.url)],
    { env: childEnvironment, timeout: 20000, maxBuffer: 1024 * 1024 });
  const output = stdout + stderr;
  assert.ok(output.includes('https-proxy-agent'), 'test must actually exercise DEBUG output');
  for (const secret of [proxyUsername, proxyPassword, proxyAuth, Buffer.from(`${proxyUsername}:${proxyPassword}`).toString('base64')]) {
    assert.equal(output.includes(secret), false);
  }
});
