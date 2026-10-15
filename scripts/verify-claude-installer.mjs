/** Owned proxy/HTTPS installer fixtures. No credentials, login or user app data.
 * --probe-official-abort checks real official metadata and a bounded partial
 * download, then cancels. Full official download is run only by the packaged
 * terminal harness with --download-cli. */
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import os from 'node:os';
import { createReadStream } from 'node:fs';
import { access, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';

const execute = promisify(execFile);
const hashFile = async filename => { const hash = createHash('sha256'); for await (const chunk of createReadStream(filename)) hash.update(chunk); return hash.digest('hex'); };
const listen = async (server, sockets) => {
  server.on('connection', socket => { sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket)); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return server.address().port;
};

export function forwardOfficialClaudeDownload(request, socket, head, { stats, sockets }) {
  if (request.url !== 'downloads.claude.ai:443') return false;
  stats.officialTLSConnections = (stats.officialTLSConnections ?? 0) + 1;
  const connect = (upstream, upstreamHead = Buffer.alloc(0)) => {
    sockets.add(upstream); upstream.on('close', () => sockets.delete(upstream));
    upstream.on('data', chunk => { stats.officialTLSBytesReceived = (stats.officialTLSBytesReceived ?? 0) + chunk.length; });
    upstream.on('error', error => { stats.upstreamError = error.code ?? 'SOCKET_ERROR'; socket.destroy(); }); socket.on('error', () => upstream.destroy());
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length) upstream.write(head); if (upstreamHead.length) socket.write(upstreamHead);
    socket.pipe(upstream); upstream.pipe(socket); socket.on('close', () => upstream.destroy());
  };
  // This fixture's external leg may use the execution environment's explicit
  // proxy. The product still receives only this authenticated loopback route;
  // it never reads these variables and has no host-route fallback.
  const upstreamValue = process.env.HTTPS_PROXY ?? process.env.https_proxy;
  if (upstreamValue) {
    const upstreamURL = new URL(upstreamValue);
    assert(['http:', 'https:'].includes(upstreamURL.protocol), 'The verification upstream proxy must use HTTP or HTTPS.');
    stats.officialUpstreamMode = 'fixture-explicit-execution-environment-https-proxy';
    const headers = { Host: 'downloads.claude.ai:443' };
    if (upstreamURL.username || upstreamURL.password) headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(`${decodeURIComponent(upstreamURL.username)}:${decodeURIComponent(upstreamURL.password)}`).toString('base64');
    const pending = (upstreamURL.protocol === 'https:' ? https : http).request({ hostname: upstreamURL.hostname,
      port: upstreamURL.port || (upstreamURL.protocol === 'https:' ? 443 : 80), method: 'CONNECT', path: 'downloads.claude.ai:443', headers });
    pending.once('connect', (response, upstream, upstreamHead) => {
      stats.upstreamConnectStatus = response.statusCode;
      if (response.statusCode !== 200) { upstream.destroy(); socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); return; }
      connect(upstream, upstreamHead);
    });
    pending.once('error', error => { stats.upstreamError = error.code ?? 'CONNECT_ERROR'; socket.destroy(); });
    pending.setTimeout(15000, () => pending.destroy(Object.assign(new Error('Fixture upstream timeout.'), { code: 'ETIMEDOUT' })));
    socket.once('close', () => pending.destroy()); pending.end();
  } else {
    stats.officialUpstreamMode = 'fixture-direct-external-TLS';
    const upstream = net.connect({ host: 'downloads.claude.ai', port: 443 });
    sockets.add(upstream); upstream.once('error', error => { stats.upstreamError = error.code ?? 'CONNECT_ERROR'; socket.destroy(); });
    upstream.once('connect', () => connect(upstream));
    socket.once('close', () => upstream.destroy());
  }
  return true;
}

async function assertNoPublishedInstallation(home) {
  await assert.rejects(access(path.join(home, '.local/bin/claude')), { code: 'ENOENT' });
  const files = await readdir(path.join(home, '.local/share/claude/versions'));
  assert.deepEqual(files, [], 'Cancellation must leave neither a native version nor a staging file.');
}

/** A local TLS origin for a previously verified native release. Callers must
 * authenticate their selected proxy before invoking forward(). No external leg
 * exists in this fixture, and the production downloader still verifies SHA and
 * the original Apple signature. */
export async function createClaudeDownloadFixture({ executable, temporary }) {
  const root = path.join(temporary, 'route-download-fixture'); await mkdir(root, { mode: 0o700 });
  const version = path.basename(executable), size = (await stat(executable)).size, checksum = await hashFile(executable);
  assert(/^\d+\.\d+\.\d+/.test(version));
  const configuration = path.join(root, 'certificate.cnf');
  await writeFile(configuration, '[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=installer.envara.invalid\n[v3]\nsubjectAltName=DNS:installer.envara.invalid\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n');
  await execute('/usr/bin/openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-config', configuration, '-keyout', path.join(root, 'key.pem'), '-out', path.join(root, 'cert.pem')], { timeout: 15000 });
  const certificate = { key: await readFile(path.join(root, 'key.pem')), cert: await readFile(path.join(root, 'cert.pem')) };
  const sockets = new Set(), files = new Set(), stats = { metadataRequests: 0, binaryRequests: 0 };
  const server = https.createServer(certificate, (request, response) => {
    if (request.url === '/latest') { stats.metadataRequests++; response.writeHead(200); response.end(version); return; }
    if (request.url === `/${version}/manifest.json`) {
      stats.metadataRequests++; response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ version, platforms: { [`darwin-${process.arch}`]: { binary: 'claude', checksum, size } } })); return;
    }
    if (request.url === `/${version}/darwin-${process.arch}/claude`) {
      stats.binaryRequests++; response.writeHead(200, { 'Content-Length': size });
      const stream = createReadStream(executable); files.add(stream); stream.on('close', () => files.delete(stream));
      response.once('close', () => stream.destroy()); stream.on('error', () => response.destroy()); stream.pipe(response); return;
    }
    response.writeHead(404); response.end();
  });
  const port = await listen(server, sockets);
  return { version, checksum, size, stats, downloadOptions: { baseURL: 'https://installer.envara.invalid/', tlsOptions: { ca: certificate.cert } },
    forward(request, socket, head, routeStats) {
      if (request.url !== 'installer.envara.invalid:443') return false;
      routeStats.installerTLSConnections = (routeStats.installerTLSConnections ?? 0) + 1;
      const upstream = net.connect(port, '127.0.0.1'); sockets.add(upstream); upstream.on('close', () => sockets.delete(upstream));
      upstream.on('error', () => socket.destroy()); socket.on('error', () => upstream.destroy());
      upstream.once('connect', () => { socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); if (head.length) upstream.write(head); socket.pipe(upstream); upstream.pipe(socket); });
      socket.on('close', () => upstream.destroy()); return true;
    },
    async close() {
      for (const stream of files) stream.destroy(); for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve)); await rm(root, { recursive: true, force: true });
    } };
}

export async function verifyInstallerCancelRetry({ ensureClaudeInstallation, createClaudeNativeDownloader, executable, temporary, proof, check }) {
  const root = path.join(temporary, 'installer-cancel-retry'); await mkdir(root, { mode: 0o700 });
  const home = path.join(root, 'home'); await mkdir(home, { mode: 0o700 });
  const version = path.basename(executable), size = (await stat(executable)).size, checksum = await hashFile(executable);
  assert(/^\d+\.\d+\.\d+/.test(version));
  const configuration = path.join(root, 'certificate.cnf');
  await writeFile(configuration, '[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=installer.envara.invalid\n[v3]\nsubjectAltName=DNS:installer.envara.invalid\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n');
  await execute('/usr/bin/openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-config', configuration, '-keyout', path.join(root, 'key.pem'), '-out', path.join(root, 'cert.pem')], { timeout: 15000 });
  const certificate = { key: await readFile(path.join(root, 'key.pem')), cert: await readFile(path.join(root, 'cert.pem')) };
  const sockets = new Set(), stats = { authenticatedConnections: 0, metadataRequests: 0, binaryRequests: 0 };
  const files = new Set();
  const server = https.createServer(certificate, (request, response) => {
    if (request.url === '/latest') { stats.metadataRequests++; response.writeHead(200); response.end(version); return; }
    if (request.url === `/${version}/manifest.json`) {
      stats.metadataRequests++; response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ version, platforms: { [`darwin-${process.arch}`]: { binary: 'claude', checksum, size } } })); return;
    }
    if (request.url === `/${version}/darwin-${process.arch}/claude`) {
      stats.binaryRequests++; response.writeHead(200, { 'Content-Length': size });
      const stream = createReadStream(executable); files.add(stream); stream.on('close', () => files.delete(stream));
      response.once('close', () => stream.destroy()); stream.on('error', () => response.destroy()); stream.pipe(response); return;
    }
    response.writeHead(404); response.end();
  });
  const token = randomBytes(16).toString('hex');
  const expected = 'Basic ' + Buffer.from(`installer:${token}`).toString('base64');
  const proxy = http.createServer((_request, response) => { response.writeHead(403); response.end(); });
  let securePort;
  proxy.on('connect', (request, socket, head) => {
    if (request.headers['proxy-authorization'] !== expected) { socket.end('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n'); return; }
    if (request.url !== 'installer.envara.invalid:443') { socket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return; }
    stats.authenticatedConnections++;
    const upstream = net.connect(securePort, '127.0.0.1'); sockets.add(upstream); upstream.on('close', () => sockets.delete(upstream));
    upstream.on('error', () => socket.destroy()); socket.on('error', () => upstream.destroy());
    upstream.once('connect', () => { socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); if (head.length) upstream.write(head); socket.pipe(upstream); upstream.pipe(socket); });
    socket.on('close', () => upstream.destroy());
  });
  try {
    securePort = await listen(server, sockets); const proxyPort = await listen(proxy, sockets);
    const downloader = createClaudeNativeDownloader({ baseURL: 'https://installer.envara.invalid/', tlsOptions: { ca: certificate.cert } });
    const controller = new AbortController(), cancelledProgress = [];
    const options = { home, source: 'download', downloadNative: downloader, downloadContext: { proxyUrl: `http://installer:${token}@127.0.0.1:${proxyPort}`, signal: controller.signal },
      findHostExecutable: async () => { throw Object.assign(new Error('No host installation in this fixture.'), { code: 'CLAUDE_CODE_NOT_INSTALLED' }); },
      onProgress: event => { cancelledProgress.push(event); if (event.phase === 'downloading' && event.receivedBytes > 0) controller.abort(); } };
    await assert.rejects(ensureClaudeInstallation(options), { code: 'CLAUDE_CODE_DOWNLOAD_CANCELLED' });
    assert(cancelledProgress.some(event => event.receivedBytes > 0));
    await assertNoPublishedInstallation(home);
    const completedProgress = [];
    const installation = await ensureClaudeInstallation({ ...options, downloadContext: { ...options.downloadContext, signal: new AbortController().signal }, onProgress: event => completedProgress.push(event) });
    const installed = await realpath(installation.entryPath);
    assert.equal(await hashFile(installed), checksum);
    assert.equal(path.basename(installed), version);
    assert.deepEqual((await readdir(installation.versionsDirectory)).sort(), [version]);
    assert(completedProgress.some(event => event.phase === 'verifying'));
    assert(completedProgress.some(event => event.phase === 'installing'));
    proof.installerCancelRetry = { mode: 'authenticated-local-HTTPS-fixture', version, checksum, size, ...stats,
      cancelledAfterBytes: cancelledProgress.find(event => event.receivedBytes > 0).receivedBytes, noPartialInstallation: true, retryVerified: true, realAppleSignatureVerified: true };
    check('Cancelling a partially transferred native binary leaves no installed entry or staging file; retry through an authenticated HTTPS fixture validates the real binary checksum and Apple signature and installs successfully.');
  } finally {
    for (const stream of files) stream.destroy();
    for (const socket of sockets) socket.destroy();
    await Promise.all([server, proxy].map(item => item.listening ? new Promise(resolve => item.close(resolve)) : Promise.resolve()));
    await rm(root, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url) && process.argv.includes('--probe-official-abort')) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const { ensureClaudeInstallation } = await import(pathToFileURL(path.join(root, 'electron/claude-code-installation.mjs')));
  const artifact = path.join(root, 'build/local-verification/claude-installer'); await mkdir(artifact, { recursive: true, mode: 0o700 });
  const runDir = await mkdtemp(path.join(artifact, 'official-abort-'));
  const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-installer-probe-')));
  const home = path.join(temporary, 'home'); await mkdir(home, { mode: 0o700 });
  const sockets = new Set(), stats = { authenticatedConnections: 0 }, controller = new AbortController();
  const token = randomBytes(16).toString('hex'), expected = 'Basic ' + Buffer.from(`probe:${token}`).toString('base64');
  const proxy = http.createServer((_req, response) => { response.writeHead(403); response.end(); });
  proxy.on('connect', (request, socket, head) => {
    if (request.headers['proxy-authorization'] !== expected) { socket.end('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n'); return; }
    stats.authenticatedConnections++;
    if (!forwardOfficialClaudeDownload(request, socket, head, { stats, sockets })) socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
  });
  const proof = { passed: false, mode: 'real-official-partial-download-cancel', progress: [] };
  try {
    const port = await listen(proxy, sockets);
    await assert.rejects(ensureClaudeInstallation({ home, source: 'download', downloadContext: { proxyUrl: `http://probe:${token}@127.0.0.1:${port}`, signal: controller.signal },
      onProgress: event => { proof.progress.push(event); if (event.receivedBytes > 0) controller.abort(); } }), { code: 'CLAUDE_CODE_DOWNLOAD_CANCELLED' });
    assert(proof.progress.some(event => event.receivedBytes > 0));
    await assertNoPublishedInstallation(home); proof.passed = true; proof.noPartialInstallation = true;
  } catch (error) { proof.error = { code: error.code, message: error.message, stack: error.stack }; process.exitCode = 1; }
  finally {
    for (const socket of sockets) socket.destroy(); await new Promise(resolve => proxy.close(resolve));
    proof.route = stats; await rm(temporary, { recursive: true, force: true }); proof.temporaryFixtureRemoved = true;
    await writeFile(path.join(runDir, 'proof.json'), JSON.stringify(proof, null, 2) + '\n', { mode: 0o600 });
    console.log(JSON.stringify(proof, null, 2)); console.log('Verification proof: ' + path.join(runDir, 'proof.json'));
  }
}
