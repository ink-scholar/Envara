import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import dgram from 'node:dgram';
import fs from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createPFFixtureSocksServer, snapshotPFFixtureUDP } from '../native/macos-pf-routing/acceptance-plan.mjs';
import { SocketReader } from '../native/macos-local-routing/socks-stream.mjs';

// This is a native proxy-core protocol test, never a PF/utun activation test.
const binary = fileURLToPath(new URL('../build/app-routing/macos-pf/mihomo', import.meta.url));
const expectedSHA = '94a386ec0149080deadd86b1f667363bde3c70f7489dba3258e52c56fc9a6d66';
const bounded = (promise, ms = 5000) => {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('OWNED_LOOPBACK_TIMEOUT')), ms); })]).finally(() => clearTimeout(timer));
};
async function availablePort() {
  const server = net.createServer(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port;
}
async function association(proxy) {
  const socket = net.createConnection({ host: '127.0.0.1', port: proxy.port }); socket.on('error', () => {});
  const reader = new SocketReader(socket);
  try {
    socket.write(Buffer.from([5, 1, 2])); assert.deepEqual(await reader.read(2), Buffer.from([5, 2]));
    const username = Buffer.from(proxy.username), password = Buffer.from(proxy.password);
    socket.write(Buffer.concat([Buffer.from([1, username.length]), username, Buffer.from([password.length]), password]));
    assert.deepEqual(await reader.read(2), Buffer.from([1, 0]));
    socket.write(Buffer.from([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]));
    assert.deepEqual(await reader.read(4), Buffer.from([5, 0, 0, 1]));
    const address = await reader.read(6);
    assert.ok([0, 127].includes(address[0]));
    reader.release(); socket.resume(); return { socket, port: address.readUInt16BE(4) };
  } catch { socket.destroy(); throw new Error('OWNED_LOOPBACK_ASSOCIATION_REFUSED'); }
}
async function core(t, upstream) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'envara-mihomo-udp-'));
  const port = await availablePort(), credentials = { username: 'owned-loopback', password: randomBytes(16).toString('hex') };
  const configuration = { 'socks-port': port, 'bind-address': '127.0.0.1', 'allow-lan': false, mode: 'rule', ipv6: false,
    'log-level': 'silent', authentication: [`${credentials.username}:${credentials.password}`],
    tun: { enable: false, 'auto-route': false, 'auto-redirect': false }, dns: { enable: false },
    profile: { 'store-selected': false, 'store-fake-ip': false },
    proxies: [{ name: 'OWNED_FIXTURE', type: 'socks5', server: '127.0.0.1', port: upstream.port,
      username: upstream.username, password: upstream.password, udp: true }], rules: ['MATCH,OWNED_FIXTURE'] };
  const configPath = path.join(directory, 'configuration.json'); await fs.writeFile(configPath, JSON.stringify(configuration), { mode: 0o600 });
  const child = spawn('/usr/bin/nice', ['-n', '10', binary, '-d', directory, '-f', configPath], {
    shell: false, env: { PATH: '/usr/bin:/bin', HOME: directory, LANG: 'C' }, stdio: ['ignore', 'ignore', 'ignore'] });
  let exited = false; const stopped = new Promise(resolve => { child.once('error', () => { exited = true; resolve(false); }); child.once('exit', () => { exited = true; resolve(true); }); });
  let closePromise;
  const stop = () => closePromise ??= (async () => {
    // A live ChildProcess remains an unreaped owned child; an exit latch prevents
    // signaling a reused PID. Never signal any PID from a response or inventory.
    if (!exited) child.kill('SIGTERM');
    try { await bounded(stopped, 3000); } catch { if (!exited) child.kill('SIGKILL'); await bounded(stopped, 1000); }
    assert.equal(exited, true); await fs.rm(directory, { recursive: true, force: true });
    return true;
  })();
  t.after(stop);
  const deadline = Date.now() + 5000;
  while (!exited && Date.now() < deadline) {
    const open = await new Promise(resolve => { const socket = net.createConnection({ host: '127.0.0.1', port });
      socket.once('error', () => { socket.destroy(); resolve(false); }); socket.once('connect', () => { socket.destroy(); resolve(true); }); });
    if (open) return { port, ...credentials, stop };
    await new Promise(resolve => setTimeout(resolve, 30));
  }
  throw new Error('OWNED_LOOPBACK_CORE_UNAVAILABLE');
}
async function exchange(t, relay, payload) {
  const control = await bounded(association(relay)); t.after(() => control.socket.destroy());
  const udp = dgram.createSocket('udp4'); udp.on('error', () => {}); t.after(() => { try { udp.close(); } catch {} });
  const header = Buffer.from([0, 0, 0, 1, 198, 51, 100, 42, 0, 0]); header.writeUInt16BE(44444, 8);
  return bounded(new Promise((resolve, reject) => {
    udp.once('message', (bytes, peer) => { try { assert.equal(peer.address, '127.0.0.1'); assert.equal(peer.port, control.port);
      assert.deepEqual(bytes, Buffer.concat([header, payload])); resolve(true); } catch { reject(new Error('OWNED_LOOPBACK_REPLY_REFUSED')); } });
    udp.send(Buffer.concat([header, payload]), control.port, '127.0.0.1', error => { if (error) reject(new Error('OWNED_LOOPBACK_SEND_FAILED')); });
  }));
}

test('pinned unmodified Mihomo relays concurrent UDP to two authenticated loopback fixtures without TUN/PF', { timeout: 20000,
  skip: process.platform !== 'darwin' || process.arch !== 'arm64' }, async t => {
  assert.notEqual(process.getuid(), 0);
  const before = await fs.lstat(binary); assert.equal(before.isFile(), true); assert.equal(before.isSymbolicLink(), false);
  const hash = createHash('sha256'); for await (const bytes of createReadStream(binary)) hash.update(bytes);
  assert.equal(hash.digest('hex'), expectedSHA); const after = await fs.lstat(binary);
  assert.deepEqual([after.dev, after.ino, after.size, after.mtimeMs], [before.dev, before.ino, before.size, before.mtimeMs]);
  const proxies = await Promise.all(['one', 'two'].map(slot => createPFFixtureSocksServer({ slot })));
  for (const proxy of proxies) t.after(() => proxy.close());
  const cores = await Promise.all(proxies.map(proxy => core(t, proxy.route)));
  const challenges = proxies.map((proxy, index) => {
    const payload = randomBytes(2048); proxy.register(`owned-${index}`, payload, 'udp'); return { proxy, payload, id: `owned-${index}` };
  });
  assert.deepEqual(await Promise.all(challenges.map((challenge, index) => exchange(t, cores[index], challenge.payload))), [true, true]);
  for (const challenge of challenges) {
    assert.equal(challenge.proxy.received(challenge.id), true); assert.equal(challenge.proxy.snapshot().udpReceipts, 1);
    assert.equal(challenge.proxy.snapshot().crossRouteRejected, 0);
    assert.deepEqual(snapshotPFFixtureUDP(challenge.proxy.snapshot()), { udpAssociations: 1, udpPacketsReceived: 1,
      udpPeerRejected: 0, udpHeaderRejected: 0, udpDestinationRejected: 0, udpChallengeRejected: 0, udpDNSRejected: 0,
      udpRepliesQueued: 1, udpReplySendFailed: 0, udpSocketErrors: 0 });
  }
  const counts = proxies.map((proxy, index) => ({ slot: index ? 'two' : 'one', counts: snapshotPFFixtureUDP(proxy.snapshot()) }));
  assert.deepEqual(await Promise.all(cores.map(core => core.stop())), [true, true]);
  assert.deepEqual(await Promise.all(proxies.map(proxy => proxy.close())), [true, true]);
  const artifact = fileURLToPath(new URL('../test-artifacts/mac-pf-routing/mihomo-udp-loopback-core.json', import.meta.url));
  await fs.mkdir(path.dirname(artifact), { recursive: true });
  await fs.writeFile(artifact, JSON.stringify({ schema: 'envara.macos-pf-loopback-udp/v1', checkedAt: new Date().toISOString(),
    source: 'owned-loopback-socks', binarySHA256: expectedSHA, routeCount: 2, requestCount: 2, allResponsesMatched: true,
    allOwnedCoresExited: true, allOwnedFixturesClosed: true, systemRoutingActivated: false, pfUTUNTested: false,
    nativeRoutingAcceptance: false, productionReady: false, counts }, null, 2) + '\n', { mode: 0o600 });
});
