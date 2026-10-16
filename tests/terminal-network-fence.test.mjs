import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { KNOWN_LOCAL_PROXY_PORTS, TERMINAL_FENCE_EXECUTABLE, TerminalNetworkFence, environmentProxyPorts, systemProxyPorts, terminalFenceProfile } from '../electron/terminal-network-fence.mjs';

const run = promisify(execFile);
const onlyMac = { skip: process.platform !== 'darwin' };
const SCUTIL = `<dictionary> {
  ExceptionsList : <array> {
    0 : localhost
  }
  HTTPEnable : 1
  HTTPPort : 7897
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 7444
  HTTPSProxy : localhost
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://127.0.0.1:33331/proxy.pac
  SOCKSEnable : 1
  SOCKSPort : 1086
  SOCKSProxy : 10.0.0.2
}`;
const rootFile = { isFile: () => true, isSymbolicLink: () => false, uid: 0, mode: 0o100755 };
const shell = { executable: '/bin/zsh', args: ['-d', '-i'], environment: { TZ: 'UTC' } };
const sorted = values => [...values].sort((a, b) => a - b);

test('host proxy discovery keeps only loopback listeners from system settings and inherited variables', () => {
  assert.deepEqual(sorted(systemProxyPorts(SCUTIL)), [7444, 7897, 33331]);
  assert.deepEqual(sorted(systemProxyPorts('<dictionary> {\n}')), []);
  assert.deepEqual(sorted(environmentProxyPorts({ https_proxy: 'http://127.0.0.1:7897', ALL_PROXY: 'socks5://[::1]:7891',
    socks_proxy: 'socks5://localhost', HTTP_PROXY: 'http://proxy.example:8080', no_proxy: 'localhost', PATH: '/usr/bin' })), [1080, 7891, 7897]);
});

test('the profile allows loopback only, then refuses proxy and DNS listeners and the DNS-SD resolver', () => {
  const profile = terminalFenceProfile({ deniedLoopbackPorts: [7444, 70000, 'x'] });
  const lines = profile.split('\n'), at = prefix => lines.findIndex(line => line.startsWith(prefix));
  assert.equal(lines[0], '(version 1)');
  // Later Seatbelt rules win: the blanket denial, then loopback, then refusals.
  assert.ok(at('(deny network-outbound)') < at('(allow network-outbound (remote ip "localhost:*"))'));
  assert.ok(at('(allow network-outbound (remote ip "localhost:*"))') < at('(deny network-outbound (remote ip'));
  const refusals = lines[at('(deny network-outbound (remote ip')];
  for (const port of [...KNOWN_LOCAL_PROXY_PORTS, 7444]) assert.ok(refusals.includes(`(remote ip "localhost:${port}")`), `port ${port}`);
  assert.doesNotMatch(refusals, /70000|localhost:x/);
  assert.doesNotMatch(profile, /\(allow network-outbound \(remote (?:ip|tcp|udp)\S* "\*/);
  assert.match(profile, /\(deny mach-lookup \(global-name "com\.apple\.dnssd\.service"\)\)/);
  assert.match(profile, /\(remote unix-socket \(literal "\/private\/var\/run\/mDNSResponder"\)\)/);
  assert.doesNotMatch(profile, /iokit-get-properties|SYS_gethostuuid|kern\.uuid/);
});

test('device identifier restrictions are explicit and preserve the existing network fence', () => {
  const networkOnly = terminalFenceProfile({ deniedLoopbackPorts: [7444] });
  const restricted = terminalFenceProfile({ deniedLoopbackPorts: [7444], restrictDeviceIdentifiers: true });
  assert.ok(restricted.startsWith(networkOnly + '\n'));
  assert.match(restricted, /\(deny iokit-get-properties \(iokit-property "IOPlatformSerialNumber" "IOPlatformUUID"\)\)/);
  assert.match(restricted, /\(deny syscall-unix \(syscall-number SYS_gethostuuid\)\)/);
  assert.match(restricted, /\(deny sysctl-read \(sysctl-name "kern\.uuid"\)\)/);
  assert.doesNotMatch(restricted, /\(deny iokit-get-properties\)|\(deny sysctl-read\)|kern\.hostname|kern\.bootsessionuuid|hw\.model|hw\.memsize/);
  for (const value of ['true', null, 1, {}]) assert.throws(() => terminalFenceProfile({ restrictDeviceIdentifiers: value }), { code: 'TERMINAL_DEVICE_IDENTIFIERS_UNAVAILABLE' });
});

test('wrapping refuses instead of starting an unfenced shell', async () => {
  const execute = async () => ({ stdout: SCUTIL }), fence = options => new TerminalNetworkFence({ platform: 'darwin', execute, inspect: async () => rootFile, environment: {}, ...options });
  const refused = { code: 'TERMINAL_NETWORK_FENCE_UNAVAILABLE' };
  await assert.rejects(fence({ platform: 'linux' }).wrap(shell, { routePort: 50000 }), refused);
  await assert.rejects(fence({ inspect: async () => ({ ...rootFile, uid: 501 }) }).wrap(shell, { routePort: 50000 }), refused);
  await assert.rejects(fence({ inspect: async () => ({ ...rootFile, mode: 0o100777 }) }).wrap(shell, { routePort: 50000 }), refused);
  await assert.rejects(fence({ inspect: async () => { throw Object.assign(new Error('missing'), { code: 'ENOENT' }); } }).wrap(shell, { routePort: 50000 }), refused);
  await assert.rejects(fence({ execute: async () => { throw new Error('scutil failed'); } }).wrap(shell, { routePort: 50000 }), refused);
  await assert.rejects(fence().wrap(shell, { routePort: 7897 }), refused, 'the bridge may not share a host proxy port');
  await assert.rejects(fence().wrap(shell, { routePort: 0 }), refused);
  const wrapped = await fence({ environment: { https_proxy: 'http://127.0.0.1:8118' } }).wrap(shell, { routePort: 50000 });
  assert.equal(wrapped.executable, '/usr/bin/sandbox-exec');
  assert.equal(wrapped.args[0], '-p');
  assert.deepEqual(wrapped.args.slice(2), ['/bin/zsh', '-d', '-i']);
  assert.equal(wrapped.environment, shell.environment);
  assert.equal(wrapped.deviceIdentifierRestrictions, false);
  for (const port of [7897, 7444, 33331, 8118]) assert.ok(wrapped.deniedLoopbackPorts.includes(port), `port ${port}`);
  assert.ok(!wrapped.deniedLoopbackPorts.includes(50000));
});

test('restricted wrapping preflights the combined profile once and returns confirmed metadata without nesting', async () => {
  const calls = [];
  const fence = new TerminalNetworkFence({ platform: 'darwin', environment: {}, inspect: async () => rootFile,
    execute: async (...args) => { calls.push(args); return { stdout: args[0] === '/usr/sbin/scutil' ? SCUTIL : '' }; } });
  const wrapped = await fence.wrap(shell, { routePort: 50000, restrictDeviceIdentifiers: true });
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0].slice(0, 2), ['/usr/sbin/scutil', ['--proxy']]);
  assert.deepEqual(calls[1].slice(0, 2), [TERMINAL_FENCE_EXECUTABLE, ['-p', wrapped.args[1], '/usr/bin/true']]);
  assert.equal(calls[1][2].timeout, 5000);
  assert.equal(calls[1][2].maxBuffer, 4096);
  assert.deepEqual(wrapped.args.slice(2), [shell.executable, ...shell.args]);
  assert.equal(wrapped.args.filter(value => value === TERMINAL_FENCE_EXECUTABLE).length, 0, 'only the returned executable is a sandbox interpreter');
  assert.equal(wrapped.deviceIdentifierRestrictions, true);
  assert.equal(wrapped.environment, shell.environment);
  assert.match(wrapped.args[1], /IOPlatformSerialNumber/);
});

test('a rejected, unsupported or timed-out restriction never returns an unrestricted launch or raw diagnostics', async () => {
  let shellStarted = false;
  const fence = new TerminalNetworkFence({ platform: 'darwin', environment: {}, inspect: async () => rootFile,
    execute: async (executable) => {
      if (executable === '/usr/sbin/scutil') return { stdout: SCUTIL };
      if (executable === shell.executable) shellStarted = true;
      throw Object.assign(new Error('private host hardware value'), { stderr: 'private host UUID', code: 'ETIMEDOUT' });
    } });
  await assert.rejects(fence.wrap(shell, { routePort: 50000, restrictDeviceIdentifiers: true }), value => {
    assert.equal(value.code, 'TERMINAL_DEVICE_IDENTIFIERS_UNAVAILABLE');
    assert.doesNotMatch(value.message, /private|UUID|ETIMEDOUT/);
    assert.equal(value.stderr, undefined);
    return true;
  });
  assert.equal(shellStarted, false);
  await assert.rejects(fence.wrap(shell, { routePort: 50000, restrictDeviceIdentifiers: 'true' }), { code: 'TERMINAL_DEVICE_IDENTIFIERS_UNAVAILABLE' });
});

test('the real Seatbelt fence permits loopback but refuses proxy listeners, external addresses and external names', onlyMac, async t => {
  const listen = () => new Promise(resolve => { const server = net.createServer(socket => socket.end('ok')).listen(0, '127.0.0.1', () => resolve(server)); });
  const allowed = await listen(), refused = await listen();
  t.after(() => { allowed.close(); refused.close(); });
  // The production wrapper must produce a profile that this macOS accepts.
  const wrapped = await new TerminalNetworkFence({ environment: {} }).wrap({ executable: '/usr/bin/true', args: [], environment: {} }, { routePort: allowed.address().port });
  await run(wrapped.executable, wrapped.args, { timeout: 10000 });
  const probe = `const net = require('net'), dns = require('dns');
    const attempt = (port, host) => new Promise(r => { const s = net.connect(port, host); s.once('data', d => { r(String(d)); s.destroy(); }); s.once('error', e => r(e.code)); setTimeout(() => { r('TIMEOUT'); s.destroy(); }, 4000).unref(); });
    const lookup = name => new Promise(r => dns.lookup(name, error => r(error ? 'FAILED' : 'RESOLVED')));
    (async () => console.log(JSON.stringify({ allowed: await attempt(${allowed.address().port}, '127.0.0.1'), refused: await attempt(${refused.address().port}, '127.0.0.1'),
      external: await attempt(443, '203.0.113.1'), localhost: await lookup('localhost'), externalName: await lookup('example.com') })))();`;
  for (const restrictDeviceIdentifiers of [false, true]) {
    const profile = terminalFenceProfile({ deniedLoopbackPorts: [refused.address().port], restrictDeviceIdentifiers });
    const { stdout } = await run('/usr/bin/sandbox-exec', ['-p', profile, process.execPath, '-e', probe], { timeout: 30000, env: { PATH: '/usr/bin:/bin' } });
    // EPERM comes from connect() itself: no packet leaves for a refused peer.
    assert.deepEqual(JSON.parse(stdout), { allowed: 'ok', refused: 'EPERM', external: 'EPERM', localhost: 'RESOLVED', externalName: 'FAILED' });
  }
});
