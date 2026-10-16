/** Nonroot acceptance of the native attached-application front Seatbelt profile.
 * Uses owned listeners and executables only. Never launches a user application,
 * creates a route/group/PF rule, changes DNS, or acquires administrator authority.
 * The system DNS probe opens/closes the stock daemon connection without a query.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';
import { createSocket } from 'node:dgram';
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const native = path.join(root, 'native/macos-pf-routing');
const artifacts = path.join(root, 'build/local-verification/application-front-isolation');
await mkdir(artifacts, { recursive: true, mode: 0o700 });
const runDir = await realpath(await mkdtemp(path.join(artifacts, 'run-')));
const temporary = await realpath(await mkdtemp('/private/tmp/envara-app-front-'));
await chmod(temporary, 0o700);
const proof = { passed: false, runDir, platform: `${process.platform}-${process.arch}`, checks: [], observations: [],
  scope: 'Actual native-emitted Seatbelt profile, stock resolver broker connection, descendant inheritance and owned fixture endpoints.',
  limitations: [
    'This is a nonroot local acceptance. It does not install or activate PF, utun, AnyTLS or a privileged helper, and does not launch or validate VS Code, Notion or another user application.',
    'Owned listener and resolver-connection probes do not establish coverage of every external XPC delegate, pre-existing application process or future macOS network API.',
    'A DNS-shaped datagram is sent only to an owned high-port receiver. UDP connect checks at DNS ports send no datagrams, and DNSServiceCreateConnection submits no name query.',
  ] };
const children = new Set(), serverSockets = new Set(), servers = [], datagrams = [];
const emittedSourceFiles = ['notion-launch.m', 'notion-launch.h', 'notion-launch-fixture.m', 'gui-launch.m', 'launcher.c', 'native.h'];
const sourceHashes = async () => Object.fromEntries(await Promise.all(emittedSourceFiles.map(async file => [file, createHash('sha256').update(await readFile(path.join(native, file))).digest('hex')])));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const check = message => { proof.checks.push(message); console.log('PASS ' + message); };
const cleanEnvironment = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: temporary, TMPDIR: temporary + '/', LANG: 'C', LC_ALL: 'C' };

async function run(executable, args, { timeout = 15000, env = cleanEnvironment } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd: temporary, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    children.add(child); let stdout = '', stderr = '', timedOut = false;
    let forceTimer;
    const timer = setTimeout(() => {
      timedOut = true; try { process.kill(-child.pid, 'SIGTERM'); } catch {}
      forceTimer = setTimeout(() => { try { process.kill(-child.pid, 'SIGKILL'); } catch {} }, 10000);
    }, timeout);
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', value => { stdout += value; }); child.stderr.on('data', value => { stderr += value; });
    child.once('error', error => { clearTimeout(timer); clearTimeout(forceTimer); children.delete(child); reject(error); });
    child.once('close', (code, signal) => {
      clearTimeout(timer); clearTimeout(forceTimer); children.delete(child);
      if (code !== 0 || signal || timedOut) reject(Object.assign(new Error(`Owned ${path.basename(executable)} failed: ${code ?? signal}${timedOut ? ' timeout' : ''}\n${stderr.slice(-4000)}\n${stdout.slice(-4000)}`), { code: 'OWNED_PROBE_FAILED' }));
      else resolve({ stdout: stdout.trim(), stderr: stderr.trim(), pid: child.pid });
    });
  });
}

async function tcpServer(host, port = 0, label = host === '::1' ? 'loopback-v6' : 'loopback-v4') {
  const received = new Set();
  const server = createServer(socket => {
    serverSockets.add(socket); socket.on('close', () => serverSockets.delete(socket)); socket.on('error', () => {});
    socket.on('data', bytes => { received.add(bytes.toString('hex')); socket.end(bytes); });
  });
  servers.push(server);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen({ host, port, ipv6Only: host === '::1' }, resolve); });
  return { host, port: server.address().port, label, received, operation: 'tcp' };
}

async function udpServer(host, port = 0) {
  const received = new Set(), v6 = host.includes(':');
  const socket = createSocket({ type: v6 ? 'udp6' : 'udp4', ipv6Only: v6 }); datagrams.push(socket);
  socket.on('message', bytes => received.add(bytes.toString('hex')));
  await new Promise((resolve, reject) => { socket.once('error', reject); socket.bind(port, host, resolve); });
  return { host, port: socket.address().port, label: v6 ? 'udp-v6' : 'udp-v4', received, operation: 'udp' };
}

async function unixServer() {
  const filename = path.join(temporary, 's'), received = new Set(); assert(Buffer.byteLength(filename) < 104);
  const server = createServer(socket => {
    serverSockets.add(socket); socket.on('close', () => serverSockets.delete(socket)); socket.on('error', () => {});
    socket.on('data', bytes => { received.add(bytes.toString('hex')); socket.end(bytes); });
  });
  servers.push(server);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(filename, resolve); });
  await chmod(filename, 0o600);
  return { host: filename, port: 0, label: 'owned-unix-socket', received, operation: 'unix' };
}

const dnsPacket = nonce => Buffer.concat([Buffer.from('456e01000001000000000000', 'hex'), Buffer.from([nonce.length]), Buffer.from(nonce), Buffer.from([7]), Buffer.from('invalid'), Buffer.from('0000010001', 'hex')]);
const payload = (operation, nonce) => (operation === 'udp-dns' ? dnsPacket(nonce) : Buffer.from(nonce)).toString('hex');
async function waitReceipt(endpoint, bytes) {
  const deadline = Date.now() + 1500;
  while (!endpoint.received.has(bytes) && Date.now() < deadline) await sleep(10);
  assert(endpoint.received.has(bytes), `The owned ${endpoint.label} control must independently observe the exact nonce.`);
}

try {
  assert.equal(process.platform, 'darwin'); assert.notEqual(process.getuid(), 0);
  assert.equal(process.getuid(), process.geteuid()); assert.equal(process.getgid(), process.getegid());
  proof.uid = process.getuid(); proof.sourceHashes = await sourceHashes();
  const fixture = path.join(temporary, 'native-profile-fixture'), probe = path.join(temporary, 'network-probe'), descriptors = path.join(temporary, 'descriptor-probe');
  const flags = ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`];
  await run('/usr/bin/xcrun', [...flags, path.join(native, 'gui-launch.m'), path.join(native, 'launcher.c'), path.join(native, 'notion-launch-fixture.m'),
    '-framework', 'Foundation', '-framework', 'AppKit', '-framework', 'Security', '-lbsm', '-o', fixture], { timeout: 60000 });
  await run('/usr/bin/xcrun', [...flags, path.join(root, 'scripts/fixtures/application-front-probe.c'), '-o', probe], { timeout: 30000 });
  await run('/usr/bin/xcrun', [...flags, '-I', native, path.join(root, 'scripts/fixtures/application-front-descriptors.c'), path.join(native, 'launcher.c'), '-o', descriptors], { timeout: 30000 });

  const environmentA = randomUUID(), environmentB = randomUUID(), registrationA = randomUUID(), registrationB = randomUUID();
  const contexts = [];
  for (const [environment, registration, language] of [[environmentA, registrationA, 'zh-CN'], [environmentB, registrationA, 'en-US'], [environmentA, registrationB, 'ms-MY']]) {
    const base = `/Library/PrivilegedHelperTools/io.envara.pf-app-data/${environment}/${registration}`;
    await assert.rejects(lstat(base), { code: 'ENOENT' });
    const context = JSON.parse((await run(fixture, ['context', environment, registration, language], {
      env: { ...cleanEnvironment, ENVARA_FIXTURE_HOST_SENTINEL: 'must-not-be-inherited', HTTP_PROXY: 'http://unreachable.fixture.invalid:1' },
    })).stdout);
    assert.equal(context.ok, true); assert.equal(context.allocationVerified, false);
    for (const flag of ['ready', 'protected', 'activatesSystem']) assert.equal(context[flag], false);
    for (const name of ['UserData', 'Home', 'Cache', 'Temp', 'Extensions']) assert.equal(context[name], path.join(base, name));
    assert.equal(context.SharedData, path.join(base, 'Home/.vscode-shared'));
    const environmentValues = Object.fromEntries(context.environment.map(value => { const at = value.indexOf('='); assert(at > 0); return [value.slice(0, at), value.slice(at + 1)]; }));
    for (const [key, value] of Object.entries({ HOME: context.Home, TMPDIR: context.Temp + '/', TMP: context.Temp, TEMP: context.Temp,
      XDG_CACHE_HOME: context.Cache, XDG_CONFIG_HOME: context.UserData, LANG: context.posixLocale, LC_CTYPE: context.posixLocale,
      LC_ALL: context.posixLocale, TZ: 'Asia/Manila', ENVARA_BROWSER_LOCALE: language })) assert.equal(environmentValues[key], value);
    assert.equal(environmentValues.HTTP_PROXY, undefined); assert.equal(environmentValues.ENVARA_FIXTURE_HOST_SENTINEL, undefined);
    for (const [flag, value] of [['--user-data-dir', context.UserData], ['--disk-cache-dir', context.Cache], ['--extensions-dir', context.Extensions], ['--shared-data-dir', context.SharedData]]) assert(context.arguments.includes(`${flag}=${value}`));
    assert(context.arguments.includes('--proxy-server=socks5://127.0.0.1:23456'));
    assert(context.arguments.includes('--proxy-bypass-list=<-loopback>'));
    assert(context.arguments.includes('--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'));
    assert.equal((await run('/usr/bin/locale', ['charmap'], { env: environmentValues })).stdout, 'UTF-8');
    await assert.rejects(lstat(base), { code: 'ENOENT' });
    contexts.push(context);
  }
  for (const name of ['UserData', 'Home', 'Cache', 'Temp', 'Extensions', 'SharedData']) assert.equal(new Set(contexts.map(context => context[name])).size, 3);
  assert.equal(contexts[2].localeFallback, true); assert.equal(contexts[2].posixLocale, 'en_US.UTF-8');
  proof.generatedContexts = contexts;
  proof.limitations.push('Native path/argument/environment builders were exercised with separate environment and registration ids. No root-owned data allocation, filesystem containment or real application adoption of those settings is asserted.');
  check('Actual native context builders produce independent UserData/Home/Cache/Temp/Extensions paths for each environment and registration, pass scoped arguments/environment and UTF-8 locale, and create no data directories.');

  const front = await tcpServer('127.0.0.1'); front.label = 'owned-front';
  const other = await tcpServer('127.0.0.1'); other.label = 'other-loopback-port';
  const ipv6 = await tcpServer('::1', front.port); ipv6.label = 'same-port-ipv6';
  const udp4 = await udpServer('127.0.0.1', front.port), udp6 = await udpServer('::1', front.port), unix = await unixServer();
  proof.descriptorClosure = JSON.parse((await run(descriptors, ['127.0.0.1', String(other.port), temporary], { timeout: 30000 })).stdout);
  for (const key of ['ok', 'parentConnectedFD200Present', 'parentFD200Listed', 'parentFD200NonCloexec', 'nativeColdStageUsed',
    'stoppedFD200Absent', 'resumed', 'execChildFD200Closed', 'ownedChildReaped', 'ownedDescriptorsClosed']) assert.equal(proof.descriptorClosure[key], true, key);
  for (const key of ['nativeExecError', 'error', 'cleanupError']) assert.equal(proof.descriptorClosure[key], 0, key);
  check('The production launcher in nonroot fixture mode closes an already-connected non-CLOEXEC socket before its own child stops; the executed child confirms EBADF and is reaped.');
  const deniedEndpoints = [other, ipv6, udp4, udp6, { ...udp4, operation: 'udp-dns', label: 'DNS-payload-v4' }, { ...udp6, operation: 'udp-dns', label: 'DNS-payload-v6' }, unix];
  const interfaces = Object.entries(os.networkInterfaces()).sort(([a], [b]) => Number(b === 'en0') - Number(a === 'en0'));
  const address = interfaces.flatMap(([, rows]) => rows ?? []).find(item => item.family === 'IPv4' && !item.internal && !item.address.startsWith('169.254.'))?.address;
  if (address) {
    try { deniedEndpoints.push(await tcpServer(address, 0, 'owned-host-interface-v4')); proof.ownedNonLoopbackIPv4Listener = true; }
    catch (error) { proof.ownedNonLoopbackIPv4Listener = false; proof.limitations.push(`An owned non-loopback IPv4 listener was unavailable (${error.code}); loopback protocol/address denial remains measured.`); }
  } else { proof.ownedNonLoopbackIPv4Listener = false; proof.limitations.push('No non-loopback IPv4 interface was available for an owned listener.'); }

  const scoped = (await run(fixture, ['scoped-profile', String(front.port)])).stdout;
  assert(scoped.includes('(deny network-outbound)'));
  assert(scoped.includes(`(allow network-outbound (remote tcp4 "localhost:${front.port}"))`));
  assert.equal((scoped.match(/\(allow network-outbound/g) ?? []).length, 1);
  for (const fragment of ['com.apple.dnssd.service', 'mDNSResponder', '(remote tcp "*:53")', '(remote udp "*:53")', '(remote tcp "*:853")', '(remote udp "*:853")', '(remote udp "*:5353")']) assert(scoped.includes(fragment), fragment);
  await writeFile(path.join(runDir, 'native-scoped-profile.sb'), scoped + '\n', { mode: 0o600 });
  proof.profileSha256 = createHash('sha256').update(scoped).digest('hex');
  check('The harness uses the native scoped-profile output unchanged; its only outbound allowance is the held IPv4 TCP front and its resolver/DNS exclusions remain present.');

  const invoke = async (endpoint, mode, sandboxed) => {
    const nonce = 'envara-' + randomBytes(12).toString('hex');
    const args = [endpoint.operation, endpoint.host, String(endpoint.port), nonce, 'owned-fixture', mode];
    const result = sandboxed ? await run('/usr/bin/sandbox-exec', ['-p', scoped, probe, ...args]) : await run(probe, args);
    const report = JSON.parse(result.stdout);
    assert.equal(report.mode, mode); assert.equal(report.dnsNameQueriesSent, 0);
    if (mode === 'direct') assert.equal(report.pid, result.pid); else assert.equal(report.ppid, result.pid);
    const evidence = { endpoint: endpoint.label, mode, sandboxed, ...report };
    if (result.stderr) evidence.diagnostic = result.stderr.slice(-1000);
    proof.observations.push(evidence);
    return { report, nonce };
  };

  for (const mode of ['direct', 'fork', 'exec']) {
    for (const sandboxed of [false, true]) {
      const { report, nonce } = await invoke(front, mode, sandboxed);
      assert.equal(report.success, true); assert.equal(report.echoed, true); assert.equal(report.error, 0);
      await waitReceipt(front, payload('tcp', nonce));
    }
    for (const endpoint of deniedEndpoints) {
      const control = await invoke(endpoint, mode, false);
      assert.equal(control.report.success, true); assert.equal(control.report.error, 0);
      if (['tcp', 'unix'].includes(endpoint.operation)) assert.equal(control.report.echoed, true);
      await waitReceipt(endpoint, payload(endpoint.operation, control.nonce));
      const blocked = await invoke(endpoint, mode, true);
      assert.equal(blocked.report.success, false, `${mode} ${endpoint.label} escaped the native profile.`);
      assert([1, 13].includes(blocked.report.error), `Expected kernel EPERM/EACCES, received ${blocked.report.error}.`);
      await sleep(30); assert(!endpoint.received.has(payload(endpoint.operation, blocked.nonce)), 'The denied nonce must not reach its owned endpoint.');
    }
    check(`${mode}: the exact front exchanges a nonce, while other IPv4/IPv6 TCP, UDP4/UDP6, DNS-shaped datagrams and the owned Unix socket are denied with no receiver delivery.`);

    for (const host of ['127.0.0.1', '::1']) for (const port of [53, 853, 5353]) {
      const endpoint = { host, port, operation: 'udp-connect', label: `DNS-port-${port}-${host.includes(':') ? 'v6' : 'v4'}-connect-only` };
      assert.equal((await invoke(endpoint, mode, false)).report.success, true);
      const { report } = await invoke(endpoint, mode, true);
      assert.equal(report.success, false); assert([1, 13].includes(report.error));
    }
    check(`${mode}: UDP connect to DNS, encrypted-DNS and mDNS ports is refused for IPv4 and IPv6 without sending any datagram.`);

    const dns = { operation: 'dnssd', host: 'unused', port: 0, label: 'stock-system-DNS-broker-connection-only' };
    const before = (await invoke(dns, mode, false)).report;
    assert.equal(before.success, true); assert.equal(before.status, 0); assert(before.socketFD >= 0);
    const denied = (await invoke(dns, mode, true)).report;
    assert.equal(denied.success, false); assert([-65555, -65563].includes(denied.status), `Unexpected DNSServiceCreateConnection failure ${denied.status}.`);
    const after = (await invoke(dns, mode, false)).report;
    assert.equal(after.success, true); assert.equal(after.status, 0);
    const mach = { operation: 'dns-mach', host: 'unused', port: 0, label: 'system-DNS-mach-lookup-only' };
    const machBefore = (await invoke(mach, mode, false)).report;
    const machDenied = (await invoke(mach, mode, true)).report;
    if (machBefore.success) {
      assert.equal(machDenied.success, false); assert.equal(machDenied.status, 1100, 'The actual DNS Mach lookup must report BOOTSTRAP_NOT_PRIVILEGED.');
    } else proof.limitations.push(`${mode} DNS Mach positive control returned ${machBefore.status}; only the stock DNSServiceCreateConnection path has a successful broker control.`);
    check(`${mode}: the stock system DNS connection is available before and after but refused inside the native fence; no DNS query API or hostname lookup is called.`);
  }

  const ordinary = await invoke(other, 'direct', false);
  assert.equal(ordinary.report.success, true); await waitReceipt(other, payload('tcp', ordinary.nonce));
  check('The ordinary process outside the fence still reaches its owned endpoint after all sandbox probes.');
  assert.deepEqual(await sourceHashes(), proof.sourceHashes, 'Native sources changed during acceptance; rerun the final frozen source.');
  proof.passed = true;
} catch (error) {
  proof.error = { code: error.code ?? null, message: error.message, stack: error.stack };
  process.exitCode = 1; console.error(error.message);
} finally {
  for (const child of children) { try { process.kill(-child.pid, 'SIGKILL'); } catch {} }
  for (const socket of serverSockets) socket.destroy();
  await Promise.all(servers.map(server => server.listening ? new Promise(resolve => server.close(resolve)) : Promise.resolve()));
  await Promise.all(datagrams.map(socket => new Promise(resolve => { try { socket.close(resolve); } catch { resolve(); } })));
  await rm(temporary, { recursive: true, force: true });
  proof.temporaryFixtureRemoved = true; proof.remainingOwnedProbeProcesses = children.size;
  await writeFile(path.join(runDir, 'proof.json'), JSON.stringify(proof, null, 2) + '\n', { mode: 0o600 });
  console.log('Verification proof: ' + path.join(runDir, 'proof.json'));
}
