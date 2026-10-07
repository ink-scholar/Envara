/** Owned, loopback-only AnyTLS integration fixture. Never reads host VPN configuration. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import net from 'node:net';
import path from 'node:path';

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const isAlive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
export async function waitForLoopback(port, { child, timeoutMs = 15_000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child && (child.exitCode != null || child.signalCode != null)) throw new Error('FIXTURE_CORE_EXITED');
    const available = await new Promise(resolve => {
      const socket = net.connect({ host: '127.0.0.1', port });
      let settled = false;
      const done = value => { if (!settled) { settled = true; socket.destroy(); resolve(value); } };
      socket.once('connect', () => done(true));
      socket.once('error', () => done(false));
      socket.setTimeout(200, () => done(false));
    });
    if (available) return;
    await delay(40);
  }
  throw new Error('FIXTURE_CORE_START_TIMEOUT');
}
async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
async function command(command, args, { cwd } = {}) {
  const child = spawn(command, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', chunk => { output += chunk.toString(); });
  child.stderr.on('data', chunk => { output += chunk.toString(); });
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
  if (code !== 0) throw new Error(`FIXTURE_COMMAND_FAILED:${path.basename(command)}`);
  return output;
}
async function stopChild(child) {
  if (!child || child.exitCode != null || child.signalCode != null) return;
  child.kill('SIGTERM');
  const deadline = Date.now() + 2000;
  while (isAlive(child.pid) && Date.now() < deadline) await delay(20);
  if (isAlive(child.pid)) child.kill('SIGKILL');
  const killDeadline = Date.now() + 2000;
  while (isAlive(child.pid) && Date.now() < killDeadline) await delay(20);
  assert.equal(isAlive(child.pid), false, 'Owned fixture core must be gone');
}

/**
 * Server-side Mihomo routes only loopback targets; other destinations are REJECT.
 * A TCP relay records TLS record framing, without saving payloads or credentials.
 */
export async function startAnyTlsFixture({ binaryPath, runDir, openssl = 'openssl' }) {
  const privateDir = path.join(runDir, 'fixture-private');
  await mkdir(privateDir, { recursive: true, mode: 0o700 });
  const password = randomUUID();
  const marker = randomUUID();
  const certificatePath = path.join(privateDir, 'server.crt');
  const keyPath = path.join(privateDir, 'server.key');
  const configPath = path.join(privateDir, 'server.json');
  const sockets = new Set();
  const requests = [];
  const wire = { connections: 0, tlsRecords: 0, bytes: 0 };
  let child;
  let relay;
  let origin;
  let secureOrigin;
  let stopped = false;
  const track = socket => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
    return socket;
  };
  const close = async () => {
    if (stopped) return;
    stopped = true;
    for (const socket of sockets) socket.destroy();
    if (relay?.listening) await new Promise(resolve => relay.close(resolve));
    await stopChild(child);
    if (origin?.listening) await new Promise(resolve => origin.close(resolve));
    if (secureOrigin?.listening) await new Promise(resolve => secureOrigin.close(resolve));
    await rm(privateDir, { recursive: true, force: true });
  };
  try {
    await command(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '1', '-nodes',
      '-keyout', keyPath, '-out', certificatePath, '-subj', '/CN=fixture.anytls.test',
      '-addext', 'subjectAltName=DNS:fixture.anytls.test,IP:127.0.0.1'], { cwd: privateDir });
    const certificate = await readFile(certificatePath, 'utf8');
    const privateKey = await readFile(keyPath, 'utf8');
    assert.match(certificate, /BEGIN CERTIFICATE/);
    assert.match(privateKey, /BEGIN PRIVATE KEY/);
    const originHandler = (request, response) => {
      const valid = request.url === `/anytls-marker/${marker}`;
      const geo = request.url === `/geo/${marker}`;
      requests.push({ method: request.method, markerMatched: valid, geoMatched: geo,
        tls: !!request.socket.encrypted, remoteAddress: request.socket.remoteAddress,
        proxyCredentialsForwarded: !!request.headers['proxy-authorization'],
        nodeSecretInHeaders: Object.values(request.headers).some(value => String(value).includes(password)) });
      response.writeHead(valid || geo ? 200 : 404, { 'Content-Type': 'application/json', Connection: 'close' });
      response.end(JSON.stringify(geo ? { success: true, ip: '8.8.8.8', country_code: 'JP', country: 'Fixture Japan',
        city: 'Fixture Tokyo', timezone: { id: 'Asia/Tokyo' }, synthetic: true } :
        { marker: valid ? marker : null, route: 'owned-anytls-fixture', requestNumber: requests.length }));
    };
    origin = createServer(originHandler);
    origin.on('connection', track);
    await new Promise((resolve, reject) => { origin.once('error', reject); origin.listen(0, '127.0.0.1', resolve); });
    const originPort = origin.address().port;
    secureOrigin = createHttpsServer({ cert: certificate, key: privateKey }, originHandler);
    secureOrigin.on('connection', track);
    await new Promise((resolve, reject) => { secureOrigin.once('error', reject); secureOrigin.listen(0, '127.0.0.1', resolve); });
    const secureOriginPort = secureOrigin.address().port;
    const inboundPort = await freePort();
    const config = {
      mode: 'rule', 'log-level': 'silent', ipv6: false, 'allow-lan': false, 'bind-address': '127.0.0.1',
      listeners: [{ name: 'envara-anytls-fixture', type: 'anytls', listen: '127.0.0.1', port: inboundPort,
        users: { fixture: password }, certificate, 'private-key': privateKey }],
      dns: { enable: false }, profile: { 'store-selected': false, 'store-fake-ip': false },
      hosts: { 'origin.anytls.test': '127.0.0.1' },
      rules: ['IP-CIDR,127.0.0.0/8,DIRECT,no-resolve', 'MATCH,REJECT'],
    };
    await writeFile(configPath, JSON.stringify(config), { mode: 0o600 });
    child = spawn(binaryPath, ['-d', privateDir, '-f', configPath], { cwd: privateDir, stdio: 'ignore',
      env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: privateDir, TMPDIR: privateDir } });
    let spawnError;
    child.once('error', () => { spawnError = new Error('FIXTURE_CORE_SPAWN_FAILED'); });
    await waitForLoopback(inboundPort, { child });
    if (spawnError) throw spawnError;
    relay = net.createServer(client => {
      track(client);
      wire.connections++;
      let first = true;
      client.on('data', chunk => {
        wire.bytes += chunk.length;
        if (first) { first = false; if (chunk.length >= 3 && chunk[0] === 22 && chunk[1] === 3) wire.tlsRecords++; }
      });
      const upstream = track(net.connect({ host: '127.0.0.1', port: inboundPort }));
      upstream.once('error', () => client.destroy());
      client.once('close', () => upstream.destroy());
      upstream.once('close', () => client.destroy());
      client.pipe(upstream); upstream.pipe(client);
    });
    await new Promise((resolve, reject) => { relay.once('error', reject); relay.listen(0, '127.0.0.1', resolve); });
    return {
      binaryPath, pid: child.pid, privateDir, password, marker,
      proxy: { protocol: 'anytls', host: '127.0.0.1', port: relay.address().port,
        password, serverName: 'fixture.anytls.test', clientFingerprint: 'chrome', skipCertVerify: false },
      originURL: `http://origin.anytls.test:${originPort}/anytls-marker/${marker}`,
      httpsOriginURL: `https://127.0.0.1:${secureOriginPort}/anytls-marker/${marker}`,
      geoURL: `https://127.0.0.1:${secureOriginPort}/geo/${marker}`,
      certificate, certificatePath,
      requests, wire,
      async stopAnyTlsServer() {
        for (const socket of sockets) socket.destroy();
        if (relay.listening) await new Promise(resolve => relay.close(resolve));
        await stopChild(child);
      },
      close,
    };
  } catch (error) { await close(); throw error; }
}
