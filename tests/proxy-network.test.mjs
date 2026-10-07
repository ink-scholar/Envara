import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import test from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { ProxyNetworkProbe, isPublicIP, proxyFingerprint } from '../electron/proxy-network.mjs';

// Test-only localhost certificate. Never disable TLS verification in production.
const key = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/rZHvXB3H0y+I
nPzMUftkDYwD2FIPYMRSb0Di+O1B+KXdQgLEO81bAunox769dqqb2L8sCH/qsrMe
pg3eVrKQ7p7NQNn9f8L65CPt6ZAd5eNXcBMSh8IjnB0BWUkP5V5z+/0wgtOe3dzC
Qb+E7CsJMylENoCLLmvRknAOhU1lmEAbm5uJ4+HcHfvTXp+sThqCtkeQbFU66aPm
OsdxNQkKnr08tK8zsgr50s/SrA7SUZlbd5Psn+alRqsXdc0o9ZBHUQzt4QaXATgC
HMJ5S616tTn8Tzj0ycmxXYGH+lcJENc+hqQLbNeWoG2dxlBnDdYptzP3QMXCKzNN
lFuDOWsdAgMBAAECggEAGQJloyyKujLk5ddN6L7dpS1bUnkcI+OFWhgoCDVgh5YQ
1jCxubbv0Wss5/GAAqqEEjeSogUt44qTcnFKJ/N58w0fbTqD9t5/q0qvIXCzHCON
qS/3XRiXjRvmcPGcZdWQoGOFopm/UOAz2KjJe2dxKg8h2EOgPAi/iqWnt01PTuz3
xx+LbXZqSwBczojh3JosbMdB0RJXm8wjrxsMaZ4eUgnzVBcvWKiMsb6+oXTEuGgR
zWrtaRjlL2BvDc93I0YGtVkuvv5dwbweQgczF6jJmODcm/0ys2IhkLTTaBXryCs7
cs8rrawVJ7QHvVhJ7DdJB1Xkj/RF/d9RznePbsJKgQKBgQDh9dEZzmVmjmffk0VU
/LiUKDnbl9m/3GV/ZrU4E15P9izXmZP+xh6DWb6TzEpoKxgZpfzBTjw6GjePgIuT
17BjYxwCIgr255fU0/CLNNBoovX8Ir04/xyOylSnJ/jNMTNBM7PnVR+5FKTT34pu
cu3fUmbKobO3twMPE9yhPFe9/QKBgQDZKQPC/z+ef4neIc+SjXQkoyALj4uWabDL
sdNaed/yG2mQMWC2qOqjjHTc9ziKckVCHJ/Uza6pCEVusK0P5Bx9eS6aSKyicDdc
eEkaO1qg+NhBU8DNYIAlHMqjcQBBTPuQxZ4ua+Hqklp1/GJnpEYgvFehLFTNjX9j
+ErJRCpboQKBgG2JlrYl4e4Xdq9hWyjZ4jigT3vuXvatRt690Xe/m+azdgWGQ8Is
FLqkFMjdLezVhzdXyfGDlZqs/uYn8IHY+38Smo9GJX6PwoC/xUoWbjlrVkfGJ2ir
8xIdb3Ag5nHCOhCPmdS45Un5gfXb1eW4/StXbNEqFk8m/uqePERFVluZAoGBALIm
V5Os2oAomO3GRwcvTEySFkPlqtnmMseoRn8+5F0159AG8hRnVrZ9D5IGrjfFrtOh
r+1gHx1ET9GS1ybmOAknVPf1DsrjzEbr1uzSLHNKMf7FurHBrN7FU+fpWBA6G1aV
CEOE9Xz+O3/3YLMtrOpGGI18VMWcgxl8I74hUa6BAoGARfonFd0vAGe2sOTOInTp
47g1ODHANnage1zvkfWVR3twxhLs/2va5MzpG0n2qyyzcGhbEbH2EnN3ujyUi3lC
dx8TommWxOt7pfTluvMMNj6d07Rc+RjLRG01YKNAYy5oZwu/YNhDVfs5zmSJlbWD
5UJbZFS79d+KUL080i4Dnyk=
-----END PRIVATE KEY-----`;
const cert = `-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIURhKlSBjUu0ta9GwZplvfMKMxOmcwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAwNzEwMjYxMVoXDTM2MTAw
NDEwMjYxMVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAv62R71wdx9MviJz8zFH7ZA2MA9hSD2DEUm9A4vjtQfil
3UICxDvNWwLp6Me+vXaqm9i/LAh/6rKzHqYN3laykO6ezUDZ/X/C+uQj7emQHeXj
V3ATEofCI5wdAVlJD+Vec/v9MILTnt3cwkG/hOwrCTMpRDaAiy5r0ZJwDoVNZZhA
G5ubiePh3B37016frE4agrZHkGxVOumj5jrHcTUJCp69PLSvM7IK+dLP0qwO0lGZ
W3eT7J/mpUarF3XNKPWQR1EM7eEGlwE4AhzCeUuterU5/E849MnJsV2Bh/pXCRDX
PoakC2zXlqBtncZQZw3WKbcz90DFwiszTZRbgzlrHQIDAQABo28wbTAdBgNVHQ4E
FgQUkOFwk/CUJSTjxGD8/a/egeTsINIwHwYDVR0jBBgwFoAUkOFwk/CUJSTjxGD8
/a/egeTsINIwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH
BH8AAAEwDQYJKoZIhvcNAQELBQADggEBAFJnImSTRDGZxQ//KSL+WngHOrN/IEN2
0YU+Ds/DjlIV1S9xHDeOT1xEHlaOFuvbefHt7ffwspa+/bzfv7/hoJ5cURPkAyhE
GLUDzXDq8MlVmEgVWh8HWuJzSGH9lhs9ds+ybUKkcKVg3jwMyH7+KwSXxARXr76i
1snM5VszjMD8uevYSLuZh1t+zCFCrdohC7ZrcfjcdvABzHDTuan/BSOsDJANy4a+
bfJieeBz/COWxE4UOh8DJrpqJ1g8WwOTztdDhcrE51ZqdDuK5vhJZICrxae+++53
usL0De8navbofMctVAg7QWaXQNBPEecQgU4Y5XgvMxkl1e9gn4QqW14=
-----END CERTIFICATE-----`;
const geo = { success: true, ip: '8.8.8.8', country: 'United States', country_code: 'US', region: 'New York', city: 'New York', timezone: { id: 'America/New_York' } };

async function listen(t, server) {
  const sockets = new Set();
  server.on('connection', (socket) => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve)); });
  return server.address().port;
}
async function serverFixture(t, responder = (_request, response) => response.end(JSON.stringify(geo))) {
  let targetHits = 0;
  const server = https.createServer({ key, cert }, (request, response) => { targetHits++; responder(request, response); });
  const targetPort = await listen(t, server);
  const endpoints = [{ url: `https://localhost:${targetPort}/geo`, source: 'fixture', format: 'ipwho' }];
  const probe = (options = {}) => new ProxyNetworkProbe({ endpoints, tlsOptions: { ca: cert }, timeoutMs: 1000, ...options });
  return { targetPort, probe, hits: () => targetHits };
}
async function connectProxy(t, targetPort, protocol, auth = true) {
  const observations = [];
  const server = protocol === 'https' ? https.createServer({ key, cert }) : http.createServer();
  server.on('connect', (request, socket, head) => {
    observations.push({ target: request.url, auth: request.headers['proxy-authorization'] });
    if (!auth || request.headers['proxy-authorization'] !== `Basic ${Buffer.from('alice:dummy-secret').toString('base64')}`) { socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n'); return; }
    const upstream = net.connect(targetPort, '127.0.0.1', () => { socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); if (head.length) upstream.write(head); socket.pipe(upstream); upstream.pipe(socket); });
    socket.once('close', () => upstream.destroy()); upstream.once('error', () => socket.destroy());
  });
  const port = await listen(t, server);
  return { proxy: { protocol, host: 'localhost', port, username: 'alice', password: 'dummy-secret' }, observations };
}

test('public egress rejects private, special-purpose, documentation and mapped addresses', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '2001:4860:4860::8888']) assert.equal(isPublicIP(ip), true, ip);
  for (const ip of ['127.0.0.1', '10.0.0.1', '100.64.0.2', '169.254.1.1', '192.168.1.1', '192.0.0.8', '192.0.2.1', '198.51.100.2', '203.0.113.2', '224.1.1.1', '255.255.255.255', '::1', 'fe80::1', 'fc00::1', '2001:db8::1', '::ffff:8.8.8.8', 'not-ip']) assert.equal(isPublicIP(ip), false, ip);
});

for (const protocol of ['http', 'https']) test(`real HTTPS egress traverses ${protocol.toUpperCase()} authenticated CONNECT without environment bypass`, async (t) => {
  const target = await serverFixture(t), tunnel = await connectProxy(t, target.targetPort, protocol);
  const previous = process.env.NO_PROXY;
  process.env.NO_PROXY = '*';
  t.after(() => { if (previous === undefined) delete process.env.NO_PROXY; else process.env.NO_PROXY = previous; });
  const result = await target.probe().probe(tunnel.proxy);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.scope, 'egress'); assert.equal(result.ip, geo.ip); assert.equal(result.timezone, 'America/New_York');
  assert.equal(tunnel.observations.length, 1); assert.equal(target.hits(), 1);
  assert.equal(JSON.stringify(result).includes('dummy-secret'), false); assert.equal(JSON.stringify(result).includes('alice'), false);
});

test('proxy authentication rejection never reaches the target or falls back directly', async (t) => {
  const target = await serverFixture(t), tunnel = await connectProxy(t, target.targetPort, 'http', false);
  const result = await target.probe().probe(tunnel.proxy);
  assert.equal(result.ok, false); assert.equal(result.errorCode, 'PROXY_AUTH_FAILED'); assert.equal(result.ip, null);
  assert.equal(target.hits(), 0); assert.equal(tunnel.observations.length, 1);
});

test('SOCKS5 credentials and target hostname use remote DNS with real tunneled TLS', async (t) => {
  const target = await serverFixture(t), observations = [];
  const server = net.createServer((socket) => {
    let state = 'greeting', buffered = Buffer.alloc(0);
    const receive = (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      while (buffered.length) {
        if (state === 'greeting') { if (buffered.length < 2 || buffered.length < 2 + buffered[1]) return; assert.ok(buffered.subarray(2, 2 + buffered[1]).includes(2)); buffered = buffered.subarray(2 + buffered[1]); socket.write(Buffer.from([5, 2])); state = 'auth'; }
        else if (state === 'auth') { if (buffered.length < 2 || buffered.length < 3 + buffered[1]) return; const end = 2 + buffered[1], size = 3 + buffered[1] + buffered[end]; if (buffered.length < size) return; observations.push({ user: buffered.subarray(2, end).toString(), password: buffered.subarray(end + 1, size).toString() }); buffered = buffered.subarray(size); socket.write(Buffer.from([1, 0])); state = 'connect'; }
        else { if (buffered.length < 5) return; assert.equal(buffered[3], 3, 'socks5h must send the hostname to the proxy'); const size = 7 + buffered[4]; if (buffered.length < size) return; observations[0].host = buffered.subarray(5, 5 + buffered[4]).toString(); const remainder = buffered.subarray(size); socket.removeListener('data', receive); const upstream = net.connect(target.targetPort, '127.0.0.1', () => { socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0])); if (remainder.length) upstream.write(remainder); socket.pipe(upstream); upstream.pipe(socket); }); socket.once('close', () => upstream.destroy()); upstream.once('error', () => socket.destroy()); return; }
      }
    };
    socket.on('data', receive);
  });
  const port = await listen(t, server);
  const result = await target.probe().probe({ protocol: 'socks5', host: 'localhost', port, username: 'alice', password: 'dummy-secret' });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.deepEqual(observations, [{ user: 'alice', password: 'dummy-secret', host: 'localhost' }]); assert.equal(target.hits(), 1);
});

test('redirects, invalid geolocation, body overflow and silent servers fail within the deadline', async (t) => {
  const responders = [
    (_request, response) => { response.writeHead(302, { Location: 'https://example.com/' }); response.end(); },
    (_request, response) => response.end(JSON.stringify({ ...geo, ip: '127.0.0.1' })),
    (_request, response) => response.end(JSON.stringify({ ...geo, timezone: { id: 'not/a-zone' } })),
    (_request, response) => response.end('a'.repeat(1024)),
    () => {},
  ];
  const codes = ['GEO_HTTP_ERROR', 'INVALID_GEO_RESPONSE', 'INVALID_GEO_RESPONSE', 'GEO_BODY_TOO_LARGE', 'NETWORK_TIMEOUT'];
  for (let index = 0; index < responders.length; index++) {
    const target = await serverFixture(t, responders[index]);
    const result = await target.probe({ timeoutMs: 100, maxBodyBytes: 512 }).probe(null);
    assert.equal(result.ok, false); assert.equal(result.errorCode, codes[index]); assert.equal(target.hits(), 1);
  }
});

test('silent HTTP and SOCKS handshake sockets are aborted by the absolute deadline', async (t) => {
  const target = await serverFixture(t);
  const server = net.createServer(() => {}), port = await listen(t, server);
  for (const protocol of ['http', 'socks5']) {
    const started = performance.now();
    const result = await target.probe({ timeoutMs: 80 }).probe({ protocol, host: '127.0.0.1', port });
    assert.equal(result.ok, false); assert.equal(result.errorCode, 'NETWORK_TIMEOUT');
    assert.ok(performance.now() - started < 1000); assert.equal(target.hits(), 0);
  }
});

test('agent DEBUG diagnostics do not contain configured credentials or their Basic encoding', async () => {
  const { stdout, stderr } = await promisify(execFile)(process.execPath, ['--test', '--test-name-pattern=authenticated CONNECT|SOCKS5 credentials', fileURLToPath(import.meta.url)], {
    env: { ...process.env, DEBUG: 'https-proxy-agent*,socks-proxy-agent' }, timeout: 10000,
  });
  const output = stdout + stderr;
  assert.equal(output.includes('dummy-secret'), false);
  assert.equal(output.includes('alice'), false);
  assert.equal(output.includes(Buffer.from('alice:dummy-secret').toString('base64')), false);
});

test('cache matches credentials/configuration, deduplicates concurrent requests and contains safe result fields', async () => {
  let requests = 0, clock = 1000, release;
  const gate = new Promise((resolve) => { release = resolve; });
  const probe = new ProxyNetworkProbe({ nowMs: () => clock, transport: async () => { requests++; await gate; return geo; } });
  const proxy = { protocol: 'http', host: 'proxy.example', port: 8080, username: 'alice', password: 'dummy-secret', region: 'us-ny' };
  const requestsPending = Promise.all([probe.probe(proxy), probe.probe(proxy)]); release();
  assert.equal((await requestsPending)[0].ok, true); assert.equal(requests, 1);
  await probe.probe(proxy); assert.equal(requests, 1);
  assert.equal(probe.peek({ ...proxy, password: 'changed-secret' }), null);
  assert.equal(probe.peek({ ...proxy, region: 'us-ca' }), null);
  assert.notEqual(proxyFingerprint(proxy), proxyFingerprint({ ...proxy, password: 'changed-secret' }));
  assert.equal(JSON.stringify([...probe.cache.values()]).includes('dummy-secret'), false);
  clock = 61001; assert.equal(probe.peek(proxy).stale, true);
  await probe.probe(proxy); assert.equal(requests, 2);
  await probe.probe(proxy, { force: true }); assert.equal(requests, 3);
});

test('invalidating an in-flight configuration prevents its late response from recreating a cache entry', async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const probe = new ProxyNetworkProbe({ transport: async () => { await gate; return geo; } });
  const proxy = { protocol: 'http', host: 'proxy.example', port: 8080 };
  const pending = probe.probe(proxy); probe.invalidate(proxy); release(); await pending;
  assert.equal(probe.peek(proxy), null);
});

test('SOCKS proxy IPv6 literals are passed to socket transport without URL brackets', async () => {
  let host;
  const probe = new ProxyNetworkProbe({ transport: async ({ agent }) => { host = agent.proxy.host; return geo; } });
  assert.equal((await probe.probe({ protocol: 'socks5', host: '[::1]', port: 1080 })).ok, true);
  assert.equal(host, '::1');
});

test('IP coordinates are coarse and invalid coordinates cannot become device location', async () => {
  for (const [latitude, longitude, expected] of [[0, 0, true], [14.6, 121, true], [91, 121, false], [14.6, -181, false], ['14.6', 121, false]]) {
    const probe = new ProxyNetworkProbe({ transport: async () => ({ ...geo, latitude, longitude }) });
    const result = await probe.probe(null);
    assert.equal(result.ok, true);
    assert.equal(!!result.geolocation, expected);
    if (expected) assert.deepEqual(result.geolocation, { latitude, longitude, accuracy: 50000 });
  }
});
