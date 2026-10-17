/** Real bundled-core transport checks, exclusively against owned loopback fixtures. */
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { once } from 'node:events';
import { randomBytes, X509Certificate } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { ProxyCoreManager } from '../electron/proxy-core-manager.mjs';
import { openSocksStream } from '../native/macos-local-routing/socks-stream.mjs';
import { createFixtureSocksServer } from './macos-app-proxy-fixture-matrix.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const runDir = await mkdtemp(path.join(os.tmpdir(), 'envara-ordinary-proxy-'));
const checks = [], managers = [], fixtures = [], pids = [];
const check = name => { checks.push(name); console.log(`PASS ${name}`); };
const credentials = { username: randomBytes(12).toString('hex'), password: randomBytes(24).toString('hex') };
const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const listen = async server => { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; };
const sockets = new Set();
const track = socket => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); return socket; };
let directConnections = 0;
const directCanary = net.createServer(socket => { directConnections++; socket.destroy(); });
const canaryPort = await listen(directCanary);
const target = { host: '127.0.0.1', port: canaryPort };

async function httpFixture(tlsOptions) {
  let authenticated = 0, rejected = 0;
  const server = tlsOptions ? https.createServer(tlsOptions) : http.createServer();
  server.on('connection', track); server.on('tlsClientError', () => {});
  server.on('connect', (request, socket, head) => {
    const valid = request.headers['proxy-authorization'] === `Basic ${Buffer.from(`${credentials.username}:${credentials.password}`).toString('base64')}`;
    if (!valid || request.url !== `127.0.0.1:${canaryPort}`) { rejected++; socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nConnection: close\r\n\r\n'); return; }
    authenticated++; socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    // Echo in the upstream itself. The reachable destination is a canary:
    // it must receive zero connections, including after authentication fails.
    socket.on('data', data => socket.write(data)); if (head.length) socket.write(head);
  });
  const port = await listen(server);
  const fixture = { proxy: { protocol: tlsOptions ? 'https' : 'http', host: '127.0.0.1', port, ...credentials },
    snapshot: () => ({ authenticated, rejected }), close: async () => { for (const socket of sockets) socket.destroy(); if (server.listening) await new Promise(resolve => server.close(resolve)); } };
  fixtures.push(fixture); return fixture;
}

function manager({ certificate } = {}) {
  const instance = new ProxyCoreManager({ dataDir: path.join(runDir, `manager-${managers.length}`), resourcesDir: path.join(root, 'build/proxy-core'),
    startupTimeoutMs: 5000, stopTimeoutMs: 1000,
    spawn(binary, args, options) {
      if (certificate) {
        // Test-only certificate pin for the disposable TLS fixture. Production
        // config keeps ordinary CA/hostname verification; the host is untouched.
        const config = JSON.parse(readFileSync(args[3], 'utf8'));
        assert.equal(config.proxies[0]['skip-cert-verify'], false);
        config.proxies[0].fingerprint = new X509Certificate(certificate).fingerprint256.replaceAll(':', '').toLowerCase();
        writeFileSync(args[3], JSON.stringify(config), { mode: 0o600 });
      }
      const child = spawn(binary, args, options); pids.push(child.pid); return child;
    },
  });
  managers.push(instance); return instance;
}

async function echo(wire, destination = target) {
  const payload = randomBytes(256);
  const { socket, buffered } = await openSocksStream({ ...wire, protocol: 'socks5' }, destination, 2000);
  try {
    const data = await new Promise((resolve, reject) => {
      let received = buffered;
      const timer = setTimeout(() => { reject(new Error('ECHO_TIMEOUT')); socket.destroy(); }, 2000);
      const finish = error => { clearTimeout(timer); error ? reject(error) : resolve(received); };
      socket.once('error', finish); socket.once('end', () => finish(new Error('ECHO_CLOSED')));
      socket.on('data', chunk => { received = Buffer.concat([received, chunk]); if (received.length >= payload.length) finish(); });
      socket.write(payload); socket.resume();
    });
    assert.deepEqual(data, payload);
  } finally { socket.destroy(); }
}

try {
  const owned = manager(), httpProxy = await httpFixture();
  let wire = await owned.ensure({ ...httpProxy.proxy, id: 'fixture-http' });
  await echo(wire); assert.equal(httpProxy.snapshot().authenticated, 1); assert.equal(directConnections, 0);
  assert.equal(owned.routingIdentity('fixture-http').nodeType, 'http');
  check('Authenticated HTTP CONNECT upstream carries application SOCKS traffic through the owned core');
  const beforeWrongListener = httpProxy.snapshot().authenticated;
  await assert.rejects(echo({ ...wire, password: 'wrong-owned-listener-secret' }));
  assert.equal(httpProxy.snapshot().authenticated, beforeWrongListener);
  check('Wrong private listener credentials never reach the upstream');
  wire = await owned.ensure({ ...httpProxy.proxy, id: 'fixture-http', password: 'wrong-upstream-secret' });
  await assert.rejects(echo(wire)); assert.ok(httpProxy.snapshot().rejected > 0); assert.equal(directConnections, 0);
  check('HTTP upstream authentication refusal cannot fall back to the reachable direct canary');
  wire = await owned.ensure({ ...httpProxy.proxy, id: 'fixture-http' }); await echo(wire);
  await httpProxy.close(); await assert.rejects(echo(wire)); assert.equal(directConnections, 0);
  check('HTTP upstream shutdown fails closed without direct target traffic');

  const socks = await createFixtureSocksServer({ slot: 'one', ttlMs: 60000, dnsDelayMs: 0 }); fixtures.push(socks);
  const socksTarget = { host: '198.51.100.42', port: 44441 };
  let socksWire = await owned.ensure({ ...socks.route, id: 'fixture-socks5' });
  await echo(socksWire, socksTarget); assert.equal(socks.snapshot().authenticated, 1); assert.equal(socks.snapshot().echoPayloadBytes, 256);
  assert.equal(owned.routingIdentity('fixture-socks5').nodeType, 'socks5');
  check('Authenticated SOCKS5 upstream returns exact bytes through the owned application route');
  socksWire = await owned.ensure({ ...socks.route, id: 'fixture-socks5', password: 'wrong-upstream-secret' });
  await assert.rejects(echo(socksWire, socksTarget)); assert.ok(socks.snapshot().rejected > 0);
  check('SOCKS5 upstream authentication refusal is returned to the application');

  await promisify(execFile)('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '1', '-nodes',
    '-keyout', path.join(runDir, 'fixture.key'), '-out', path.join(runDir, 'fixture.crt'), '-subj', '/CN=127.0.0.1',
    '-addext', 'subjectAltName=IP:127.0.0.1'], { timeout: 10000, maxBuffer: 16384 });
  const certificate = await readFile(path.join(runDir, 'fixture.crt'), 'utf8'), key = await readFile(path.join(runDir, 'fixture.key'), 'utf8');
  const secure = await httpFixture({ cert: certificate, key });
  const untrusted = await owned.ensure({ ...secure.proxy, id: 'fixture-https-untrusted', skipCertVerify: true });
  await assert.rejects(echo(untrusted)); assert.equal(secure.snapshot().authenticated, 0); assert.equal(directConnections, 0);
  check('HTTPS upstream rejects the untrusted local certificate even when caller requests a bypass');
  const trusted = manager({ certificate }), secureWire = await trusted.ensure({ ...secure.proxy, id: 'fixture-https-trusted' });
  await echo(secureWire); assert.equal(secure.snapshot().authenticated, 1); assert.equal(directConnections, 0);
  assert.equal(trusted.routingIdentity('fixture-https-trusted').nodeType, 'https');
  check('HTTPS CONNECT and authentication succeed with a test-only certificate pin; production certificate rejection is tested separately');

  const dying = owned.routes.get('fixture-http'), identity = owned.routingIdentity('fixture-http');
  dying.child.kill('SIGKILL');
  const deadline = Date.now() + 3000;
  while (owned.routingIdentity('fixture-http') && Date.now() < deadline) await delay(20);
  assert.ok(identity); assert.equal(owned.routingIdentity('fixture-http'), null);
  await assert.rejects(echo(wire)); assert.equal(directConnections, 0);
  check('Core death revokes managed identity and the old authenticated listener');
} finally {
  for (const instance of managers) await instance.close();
  for (const fixture of fixtures) await fixture.close();
  for (const socket of sockets) socket.destroy();
  await new Promise(resolve => directCanary.close(resolve));
  for (const pid of pids) assert.equal(alive(pid), false, 'Owned core remains alive');
  for (const instance of managers) assert.deepEqual(await readdir(instance.baseDir), []);
  await rm(runDir, { recursive: true, force: true });
}
check('Every owned core, fixture socket, credential file and temporary directory is removed');
console.log(JSON.stringify({ passed: true, checks, scope: 'Owned local transports only; no GUI, PF authorization, public egress or platform acceptance claim.' }, null, 2));
