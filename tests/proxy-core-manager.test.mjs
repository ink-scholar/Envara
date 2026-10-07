import assert from 'node:assert/strict';
import test from 'node:test';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { mkdtemp, mkdir, readdir, stat, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { anyTlsSettings, anyTlsCoreConfig, ProxyCoreManager, probeCoreListener, PROXY_CORE_VERSION, PROXY_CORE_BOOTSTRAP_DNS,
  physicalInterfaceFromRoute, detectMacPhysicalInterface } from '../electron/proxy-core-manager.mjs';

const node = (extra = {}) => ({ id: 'fixture-node', protocol: 'anytls', host: 'node.example.test', port: 443,
  password: 'only-the-owned-config-may-contain-this-secret', serverName: 'tls.example.test',
  skipCertVerify: false, clientFingerprint: 'chrome', ...extra });
const code = expected => error => error.code === expected;
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };

async function fixture(t, overrides = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'envara-proxy-core-test-'));
  const calls = []; let nextPort = 42000;
  const spawn = (binary, args, options) => {
    const child = new EventEmitter();
    child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.exitCode = null; child.kills = [];
    child.kill = signal => {
      child.kills.push(signal);
      if (child.exitCode === null) queueMicrotask(() => { child.exitCode = 0; child.emit('exit', 0); });
      return true;
    };
    const config = JSON.parse(readFileSync(args[3], 'utf8'));
    calls.push({ binary, args, options, child, config });
    return child;
  };
  const manager = new ProxyCoreManager({ dataDir: directory, resourcesDir: directory,
    resolveBinary: async () => process.execPath, spawn, choosePort: async () => nextPort++,
    probeListener: async () => {}, detectInterface: async () => 'en0', startupTimeoutMs: 2000, retryDelayMs: 1, stopTimeoutMs: 5, ...overrides });
  t.after(async () => { await manager.close(); await rm(directory, { recursive: true, force: true }); });
  return { directory, manager, calls };
}
async function dirs(manager) { try { return await readdir(manager.baseDir); } catch (error) { if (error.code === 'ENOENT') return []; throw error; } }

test('AnyTLS only accepts bounded node fields and keeps secure defaults', () => {
  assert.deepEqual(anyTlsSettings(node({ serverName: '' })), {
    host: 'node.example.test', port: 443, password: node().password, serverName: 'node.example.test',
    skipCertVerify: false, clientFingerprint: 'chrome', alpn: [], udp: true,
  });
  assert.equal(anyTlsSettings(node({ host: '[::1]', serverName: '' })).host, '::1');
  for (const invalid of [{ protocol: 'trojan' }, { host: 'host/path' }, { host: 'example\n.test' },
    { port: 0 }, { port: 65536 }, { password: '' }, { password: 'a\nb' }, { serverName: 'tls.test/evil' },
    { skipCertVerify: 'false' }, { clientFingerprint: 'chrome\n' }, { id: 'id\0' }, { udp: 'true' },
    { alpn: 'h2' }, { alpn: ['h2\n'] }, { alpn: [3] }, { alpn: ['a'.repeat(65)] }, { alpn: Array(9).fill('h2') }]) {
    assert.throws(() => anyTlsSettings(node(invalid)), code('INVALID_ANYTLS_PROXY'));
  }
  const config = anyTlsCoreConfig(anyTlsSettings(node({ skipCertVerify: true })), { port: 40000, username: 'owned', password: 'local' });
  assert.deepEqual(config.rules, ['MATCH,ENVARA_ANYTLS']);
  assert.equal(config.proxies.length, 1); assert.equal(config.proxies[0]['skip-cert-verify'], true);
  assert.equal(config.proxies[0]['client-metadata'], '');
  assert.equal(config['bind-address'], '127.0.0.1'); assert.deepEqual(config['skip-auth-prefixes'], []);
  assert.equal(config['geo-auto-update'], false); assert.equal(config.dns.enable, true);
  assert.equal(config.dns.listen, ''); assert.equal(config.dns['enhanced-mode'], 'redir-host');
  assert.equal(config.dns['respect-rules'], false); assert.equal(config.dns['use-hosts'], false);
  assert.equal(config.dns['use-system-hosts'], false); assert.equal(config.dns.ipv6, false);
  assert.deepEqual(config.dns['default-nameserver'], PROXY_CORE_BOOTSTRAP_DNS);
  assert.deepEqual(config.dns['proxy-server-nameserver'], PROXY_CORE_BOOTSTRAP_DNS);
  assert.deepEqual(config.dns.nameserver, PROXY_CORE_BOOTSTRAP_DNS); assert.deepEqual(config.dns.fallback, []);
  assert.equal(config.tun.enable, false); assert.equal(config.ntp['write-to-system'], false);
  assert.equal(config['external-controller'], ''); assert.equal(config['external-ui-url'], '');
  assert.deepEqual(config['proxy-groups'], []); assert.deepEqual(config['proxy-providers'], {});
  assert.equal(config.proxies[0].udp, true); assert.equal(config.proxies[0].alpn, undefined);
  const alpn = ['h2', 'http/1.1'];
  const transport = anyTlsCoreConfig(anyTlsSettings(node({ alpn, udp: false })), { port: 40000, username: 'owned', password: 'local' });
  assert.deepEqual(transport.proxies[0].alpn, alpn); assert.notEqual(transport.proxies[0].alpn, alpn);
  assert.equal(transport.proxies[0].udp, false);
});

test('one owned core supplies private authenticated loopback transport with no environment or metadata secrets', async t => {
  const { manager, calls } = await fixture(t);
  const wire = await manager.ensure(node());
  assert.equal(wire.protocol, 'http'); assert.equal(wire.host, '127.0.0.1');
  assert.match(wire.username, /^[a-f0-9]{32}$/); assert.match(wire.password, /^[a-f0-9]{64}$/);
  assert.equal(calls.length, 1);
  const { args, options, config } = calls[0];
  assert.equal(args.join(' ').includes(node().password), false);
  assert.equal(options.shell, false); assert.equal(options.cwd, args[1]);
  assert.equal(config.proxies[0].password, node().password);
  assert.equal(config.proxies[0].sni, node().serverName);
  assert.deepEqual(config.authentication, [`${wire.username}:${wire.password}`]);
  assert.equal(options.env.HOME, args[1]);
  for (const forbidden of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NODE_OPTIONS', 'SSL_CERT_FILE', 'SSH_AUTH_SOCK', 'ENVARA_DEV_DATA']) {
    assert.equal(options.env[forbidden], undefined);
  }
  if (process.platform !== 'win32') {
    assert.equal((await stat(args[1])).mode & 0o777, 0o700);
    assert.equal((await stat(args[3])).mode & 0o777, 0o600);
  }
  const snapshot = JSON.stringify(manager.snapshot());
  for (const secret of [node().password, node().host, node().serverName, wire.password, wire.username]) assert.equal(snapshot.includes(secret), false);
  assert.equal(manager.snapshot().activeCount, 1); assert.equal(manager.snapshot().version, PROXY_CORE_VERSION);
  await manager.release(node().id);
  assert.equal(manager.snapshot().activeCount, 0); assert.deepEqual(await dirs(manager), []);
  assert.deepEqual(calls[0].child.kills, ['SIGTERM']);
});

test('concurrent requests reuse the route but changed credentials replace only their owned process', async t => {
  const { manager, calls } = await fixture(t);
  const [first, second] = await Promise.all([manager.ensure(node()), manager.ensure(node())]);
  assert.deepEqual(first, second); assert.notEqual(first, second); assert.equal(calls.length, 1);
  first.password = 'caller mutation';
  assert.deepEqual(await manager.ensure(node()), second);
  const another = await manager.ensure(node({ id: 'another-node' }));
  assert.notEqual(another.port, second.port); assert.equal(calls.length, 2);
  const replacement = await manager.ensure(node({ password: 'updated-private-password' }));
  assert.equal(calls.length, 3); assert.notEqual(replacement.port, second.port);
  assert.deepEqual(calls[0].child.kills, ['SIGTERM']); assert.deepEqual(calls[1].child.kills, []);
  assert.equal(manager.snapshot().activeCount, 2);
});

test('release cancels pending starts and queued ensures without leaving a child or private config', async t => {
  const gate = deferred();
  const { manager, calls } = await fixture(t, { resolveBinary: () => gate.promise });
  const first = manager.ensure(node()); const second = manager.ensure(node());
  await delay(5);
  const release = manager.release(node().id);
  gate.resolve(process.execPath);
  const results = await Promise.allSettled([first, second, release]);
  assert.equal(results[0].reason.code, 'PROXY_CORE_CANCELLED');
  assert.equal(results[1].reason.code, 'PROXY_CORE_CANCELLED');
  assert.equal(results[2].status, 'fulfilled'); assert.equal(calls.length, 0);
  assert.equal(manager.routes.size, 0); assert.deepEqual(await dirs(manager), []);
});

test('shutdown during awaited port allocation cancels the late start and removes its private directory', async t => {
  const gate = deferred(); let entered = false;
  const { manager, calls } = await fixture(t, { choosePort: () => { entered = true; return gate.promise; } });
  const starting = manager.ensure(node());
  while (!entered) await delay(1);
  const closing = manager.close(); gate.resolve(42000);
  await assert.rejects(starting, code('PROXY_CORE_CANCELLED')); await closing;
  assert.equal(calls.length, 0); assert.deepEqual(await dirs(manager), []);
  await assert.rejects(manager.ensure(node()), code('PROXY_CORE_CANCELLED'));
});

test('an aborted readiness wait stops its owned process and a crash never leaves a cached successful route', async t => {
  let ready = false;
  const { manager, calls } = await fixture(t, { probeListener: async () => { if (!ready) throw new Error('not ready'); } });
  const controller = new AbortController();
  const starting = manager.ensure(node(), { signal: controller.signal });
  while (!calls.length) await delay(1);
  controller.abort(); await assert.rejects(starting, code('PROXY_CORE_CANCELLED'));
  assert.deepEqual(calls[0].child.kills, ['SIGTERM']); assert.deepEqual(await dirs(manager), []);
  ready = true; await manager.ensure(node());
  const before = calls[1], crashed = manager.routes.get(node().id);
  before.child.exitCode = 1; before.child.emit('exit', 1);
  assert.equal(manager.snapshot().activeCount, 0);
  await crashed.cleanupPromise;
  assert.deepEqual(await dirs(manager), []);
  await manager.ensure(node()); assert.equal(calls.length, 3);
});

test('crash recovery restores the exact same private listener and emits only safe route identity events', async t => {
  const events = [];
  const { manager, calls } = await fixture(t, { onChange: event => { if (event) events.push(event); } });
  const original = await manager.ensure(node());
  const crashed = manager.routes.get(node().id);
  calls[0].child.exitCode = 1; calls[0].child.emit('exit', 1);
  assert.deepEqual(crashed.recoveryWire, original); assert.equal(crashed.wire, null);
  await crashed.cleanupPromise;
  assert.deepEqual(await dirs(manager), []);
  const restored = await manager.ensure(node());
  assert.deepEqual(restored, original); assert.equal(calls.length, 2);
  assert.equal(calls[1].config['mixed-port'], original.port);
  assert.deepEqual(calls[1].config.authentication, [`${original.username}:${original.password}`]);
  assert.equal(crashed.recoveryWire, null); assert.equal(manager.routes.get(node().id).recoveryWire, null);
  assert.ok(events.some(event => event.id === node().id && event.status === 'failed' && event.error === 'PROXY_CORE_EXITED'));
  assert.ok(events.some(event => event.id === node().id && event.status === 'running'));
  const serialized = JSON.stringify(events);
  for (const secret of [original.username, original.password, node().password, node().host, node().serverName]) assert.equal(serialized.includes(secret), false);
  const current = manager.routes.get(node().id); await manager.release(node().id);
  assert.equal(current.recoveryWire, null); assert.equal(current.wire, null);
});

test('an occupied old listener rejects recovery without switching ports and keeps that target until explicit release', async t => {
  const occupied = net.createServer();
  await new Promise(resolve => occupied.listen(0, '127.0.0.1', resolve));
  const port = occupied.address().port;
  await new Promise(resolve => occupied.close(resolve));
  let portChoices = 0;
  const { manager, calls } = await fixture(t, { choosePort: async () => { portChoices++; return port; } });
  const original = await manager.ensure(node());
  calls[0].child.exitCode = 1; calls[0].child.emit('exit', 1); await delay(5);
  await new Promise(resolve => occupied.listen(port, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => occupied.close(resolve)));
  await assert.rejects(manager.ensure(node()), code('PROXY_CORE_RECOVERY_FAILED'));
  await assert.rejects(manager.ensure(node()), code('PROXY_CORE_RECOVERY_FAILED'));
  assert.equal(portChoices, 1); assert.equal(calls.length, 1);
  assert.deepEqual(manager.routes.get(node().id).recoveryWire, original);
  assert.deepEqual(await dirs(manager), []); assert.equal(manager.snapshot().activeCount, 0);
  const pending = manager.routes.get(node().id);
  await manager.close(); assert.equal(pending.recoveryWire, null); assert.equal(pending.wire, null);
  assert.equal(manager.routes.size, 0);
});

test('port collisions retry with fresh credentials but startup timeouts remove every attempted route', async t => {
  let manager; let calls;
  const fixtureData = await fixture(t, { probeListener: async () => {
    if (calls.length === 1) {
      calls[0].child.stderr.write('bind: address already in use with secret text that must be discarded');
      calls[0].child.exitCode = 1; calls[0].child.emit('exit', 1);
      throw new Error('collision');
    }
  } });
  ({ manager, calls } = fixtureData);
  await manager.ensure(node()); assert.equal(calls.length, 2);
  assert.notEqual(calls[0].config.authentication[0], calls[1].config.authentication[0]);
  assert.notEqual(calls[0].config['mixed-port'], calls[1].config['mixed-port']);
  assert.equal((await dirs(manager)).length, 1);
  const timeout = await fixture(t, { startupTimeoutMs: 20, probeListener: async () => { throw new Error('fixture-not-ready'); } });
  await assert.rejects(timeout.manager.ensure(node()), code('PROXY_CORE_START_TIMEOUT'));
  assert.deepEqual(timeout.calls[0].child.kills, ['SIGTERM']); assert.deepEqual(await dirs(timeout.manager), []);
});

test('silent listener collisions retry even when the core stays alive without diagnostic output', async t => {
  let calls;
  const data = await fixture(t, { startupTimeoutMs: 60, probeListener: async () => {
    if (calls.length === 1) throw new Error('wrong-listener-credentials');
  } });
  calls = data.calls;
  await data.manager.ensure(node());
  assert.equal(calls.length, 2); assert.deepEqual(calls[0].child.kills, ['SIGTERM']);
  assert.equal(data.manager.snapshot().activeCount, 1); assert.equal((await dirs(data.manager)).length, 1);
});

test('unavailable or mismatched bundled binaries fail before any node config is written', async t => {
  const { directory, manager, calls } = await fixture(t, { resolveBinary: undefined });
  await mkdir(directory, { recursive: true });
  await writeFile(path.join(directory, 'provenance.json'), JSON.stringify({ core: 'mihomo', version: 'wrong', binaryName: 'mihomo' }));
  await assert.rejects(manager.ensure(node()), code('PROXY_CORE_UNAVAILABLE'));
  assert.equal(calls.length, 0); assert.deepEqual(await dirs(manager), []);
  assert.equal(manager.snapshot().available, false); assert.equal(manager.snapshot().error, 'PROXY_CORE_UNAVAILABLE');
});

test('macOS detects a validated physical default interface using a read-only route query', async () => {
  const interfaces = { en0: [{ family: 'IPv4', internal: false, address: '192.0.2.10' }],
    lo0: [{ family: 'IPv4', internal: true, address: '127.0.0.1' }], utun6: [{ family: 'IPv4', internal: false }] };
  assert.equal(physicalInterfaceFromRoute('route to: default\n  interface: en0\n', interfaces), 'en0');
  for (const output of ['interface: utun6\n', 'interface: lo0\n', 'interface: en9\n', 'interface: en0#evil\n', 'no interface']) {
    assert.throws(() => physicalInterfaceFromRoute(output, interfaces), code('PROXY_CORE_INTERFACE_UNAVAILABLE'));
  }
  const actual = await detectMacPhysicalInterface({ interfaces: () => interfaces, command: async (file, args, options) => {
    assert.equal(file, '/sbin/route'); assert.deepEqual(args, ['-n', 'get', 'default']);
    assert.equal(options.timeout, 2500); assert.equal(options.env.HTTP_PROXY, undefined);
    return { stdout: '  interface: en0\n' };
  } });
  assert.equal(actual, 'en0');
  await assert.rejects(detectMacPhysicalInterface({ command: async () => { throw new Error('private-diagnostic'); } }), code('PROXY_CORE_INTERFACE_UNAVAILABLE'));
});

test('owned remote nodes and bootstrap DoH bind to the detected physical interface without OS settings', async t => {
  let detections = 0;
  const { manager, calls } = await fixture(t, { platform: 'darwin', detectInterface: async () => { detections++; return 'en0'; } });
  await manager.ensure(node()); assert.equal(detections, 1);
  const { config } = calls[0];
  assert.equal(config.proxies[0]['interface-name'], 'en0'); assert.equal(config['interface-name'], undefined);
  const bound = PROXY_CORE_BOOTSTRAP_DNS.map(url => `${url}#en0`);
  assert.deepEqual(config.dns['proxy-server-nameserver'], bound);
  assert.deepEqual(config.dns['default-nameserver'], bound); assert.deepEqual(config.dns.nameserver, bound);
  assert.equal(config.dns.listen, ''); assert.equal(config.tun.enable, false); assert.deepEqual(config.rules, ['MATCH,ENVARA_ANYTLS']);
  const unavailable = await fixture(t, { platform: 'darwin', detectInterface: async () => { throw new Error('no-default-interface'); } });
  await assert.rejects(unavailable.manager.ensure(node()), code('PROXY_CORE_INTERFACE_UNAVAILABLE'));
  assert.equal(unavailable.calls.length, 0); assert.deepEqual(await dirs(unavailable.manager), []);
});

test('loopback fixtures and non-macOS routes skip physical interface detection', async t => {
  let detections = 0;
  const { manager, calls } = await fixture(t, { platform: 'darwin', detectInterface: async () => { detections++; throw new Error('unexpected-interface-query'); } });
  for (const host of ['localhost', '127.0.0.1', '127.22.33.44', '::1']) {
    await manager.ensure(node({ id: host, host }));
  }
  assert.equal(detections, 0);
  for (const call of calls) {
    assert.equal(call.config.proxies[0]['interface-name'], undefined);
    assert.deepEqual(call.config.dns['proxy-server-nameserver'], PROXY_CORE_BOOTSTRAP_DNS);
    assert.equal(call.config.dns.listen, '');
  }
  const other = await fixture(t, { platform: 'linux', detectInterface: async () => { throw new Error('unexpected-platform-query'); } });
  await other.manager.ensure(node()); assert.equal(other.calls[0].config.proxies[0]['interface-name'], undefined);
});

test('listener readiness proves randomized credentials without sending an outbound destination', async t => {
  const received = [];
  const server = net.createServer(socket => {
    let phase = 0;
    socket.on('data', data => {
      received.push([...data]);
      if (phase++ === 0) socket.write(Buffer.from([5, 2]));
      else {
        const length = data[1]; const user = data.subarray(2, 2 + length).toString();
        const passLength = data[2 + length]; const pass = data.subarray(3 + length, 3 + length + passLength).toString();
        socket.write(Buffer.from([1, user === 'owned-user' && pass === 'owned-password' ? 0 : 1]));
      }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const local = { port: server.address().port, username: 'owned-user', password: 'owned-password' };
  await probeCoreListener(local);
  await assert.rejects(probeCoreListener({ ...local, password: 'wrong' }), code('PROXY_CORE_NOT_READY'));
  assert.equal(received.length, 4); assert.deepEqual(received[0], [5, 1, 2]);
  // Greeting and username/password only; no SOCKS CONNECT command or destination.
  assert.equal(received[1][0], 1); assert.equal(received[3][0], 1);
});
