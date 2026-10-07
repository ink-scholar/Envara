import assert from 'node:assert/strict';
import { once } from 'node:events';
import http from 'node:http';
import net from 'node:net';
import test from 'node:test';
import { createTerminalProxyBridge } from '../electron/terminal-proxy-bridge.mjs';

async function listen(t, server) {
  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => {
    server.close(resolve);
    for (const socket of sockets) socket.destroy();
  }));
  return server.address().port;
}

async function socksFixture(t, { hang = false, reject = false } = {}) {
  const destinations = [];
  const authentications = [];
  const clients = new Set();
  const upstreams = new Set();
  const server = net.createServer((socket) => {
    clients.add(socket);
    socket.once('close', () => clients.delete(socket));
    let buffer = Buffer.alloc(0);
    let state = 'greeting';
    let upstream;
    socket.on('data', function onData(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      while (true) {
        if (state === 'greeting') {
          if (buffer.length < 2 || buffer.length < 2 + buffer[1]) return;
          assert.equal(buffer[0], 5);
          assert.ok(buffer.subarray(2, 2 + buffer[1]).includes(2));
          buffer = buffer.subarray(2 + buffer[1]);
          state = 'authentication';
          if (!hang) socket.write(Buffer.from([5, 2]));
          else return;
        } else if (state === 'authentication') {
          if (buffer.length < 2) return;
          const userLength = buffer[1];
          if (buffer.length < 3 + userLength) return;
          const passwordLength = buffer[2 + userLength];
          if (buffer.length < 3 + userLength + passwordLength) return;
          const user = buffer.subarray(2, 2 + userLength).toString();
          const password = buffer.subarray(3 + userLength, 3 + userLength + passwordLength).toString();
          authentications.push({ user, password });
          buffer = buffer.subarray(3 + userLength + passwordLength);
          const accepted = !reject && user === 'fixture-user' && password === 'fixture-password';
          socket.write(Buffer.from([1, accepted ? 0 : 1]));
          if (!accepted) return socket.end();
          state = 'destination';
        } else if (state === 'destination') {
          if (buffer.length < 5) return;
          assert.equal(buffer[0], 5);
          assert.equal(buffer[1], 1);
          const atyp = buffer[3];
          const addressLength = atyp === 1 ? 4 : atyp === 4 ? 16 : buffer[4];
          const offset = atyp === 3 ? 5 : 4;
          if (buffer.length < offset + addressLength + 2) return;
          const host = atyp === 3 ? buffer.subarray(offset, offset + addressLength).toString()
            : atyp === 1 ? [...buffer.subarray(offset, offset + addressLength)].join('.') : 'ipv6';
          const port = buffer.readUInt16BE(offset + addressLength);
          destinations.push({ host, port, atyp });
          buffer = buffer.subarray(offset + addressLength + 2);
          state = 'connecting';
          // Only this SOCKS server resolves fixture domains, never the bridge.
          upstream = net.connect(port, '127.0.0.1');
          upstreams.add(upstream);
          upstream.on('error', () => socket.destroy());
          upstream.once('close', () => upstreams.delete(upstream));
          socket.once('close', () => upstream.destroy());
          upstream.once('connect', () => {
            socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
            socket.off('data', onData);
            if (buffer.length) upstream.write(buffer);
            socket.pipe(upstream);
            upstream.pipe(socket);
          });
          return;
        } else return;
      }
    });
  });
  const port = await listen(t, server);
  t.after(() => { for (const socket of upstreams) socket.destroy(); });
  return {
    proxy: { type: 'socks5', host: '127.0.0.1', port, username: 'fixture-user', password: 'fixture-password' },
    destinations, authentications, clients,
  };
}

async function bridgeFixture(t, proxy, options) {
  const bridge = await createTerminalProxyBridge(proxy, options);
  t.after(() => bridge.close());
  return bridge;
}

function localAuth(bridge) {
  const url = new URL(bridge.url);
  return `Basic ${Buffer.from(`${url.username}:${url.password}`).toString('base64')}`;
}

async function proxyRequest(bridge, destination, { method = 'GET', headers = {}, body, auth = true } = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: bridge.host, port: bridge.port, method, path: destination,
      headers: { ...(auth ? { 'Proxy-Authorization': localAuth(bridge) } : {}), ...headers },
      agent: false,
    });
    request.on('error', reject);
    request.on('response', (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.once('error', reject);
      response.once('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks) }));
    });
    request.end(body);
  });
}

async function rawRequest(bridge, bytes) {
  const socket = net.connect(bridge.port, bridge.host);
  await once(socket, 'connect');
  const chunks = [];
  socket.on('data', (chunk) => chunks.push(chunk));
  socket.write(bytes);
  await once(socket, 'close');
  return Buffer.concat(chunks);
}

function waitForBytes(socket, predicate, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    let bytes = Buffer.alloc(0);
    const timer = setTimeout(() => finish(new Error('Timed out reading tunnel')), timeoutMs);
    function finish(error) {
      clearTimeout(timer);
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
      if (error) reject(error);
      else resolve(bytes);
    }
    function onData(chunk) {
      bytes = Buffer.concat([bytes, chunk]);
      if (predicate(bytes)) finish();
    }
    function onError(error) { finish(error); }
    function onClose() { finish(new Error('Tunnel closed before expected bytes')); }
    socket.on('data', onData);
    socket.once('error', onError);
    socket.once('close', onClose);
  });
}

test('streams HTTP GET, HEAD and POST through authenticated SOCKS with remote DNS and sanitized headers', async (t) => {
  const observed = [];
  const origin = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    observed.push({ method: request.method, path: request.url, headers: request.headers, body: Buffer.concat(chunks) });
    response.setHeader('Content-Type', 'application/json');
    response.setHeader('Connection', 'x-origin-hop');
    response.setHeader('X-Origin-Hop', 'should-be-removed');
    response.setHeader('Proxy-Authenticate', 'should-be-removed');
    response.end(JSON.stringify({ accepted: true }));
  });
  const originPort = await listen(t, origin);
  const socks = await socksFixture(t);
  const bridge = await bridgeFixture(t, socks.proxy);
  const destination = `http://origin.invalid:${originPort}/path?q=remote`;
  assert.equal(new URL(bridge.url).hostname, '127.0.0.1');
  assert.equal(new URL(bridge.url).password.includes(socks.proxy.password), false);
  const get = await proxyRequest(bridge, destination, { headers: {
    Authorization: 'Bearer origin-only', Connection: 'x-client-hop', 'X-Client-Hop': 'remove', 'Proxy-Connection': 'keep-alive',
  } });
  assert.equal(get.status, 200);
  assert.deepEqual(JSON.parse(get.body.toString()), { accepted: true });
  assert.equal(get.headers['x-origin-hop'], undefined);
  assert.equal(get.headers['proxy-authenticate'], undefined);
  const head = await proxyRequest(bridge, destination, { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(head.body.length, 0);
  const payload = Buffer.alloc(512 * 1024, 0x6b);
  const post = await proxyRequest(bridge, destination, { method: 'POST', body: payload, headers: { 'Content-Type': 'application/octet-stream' } });
  assert.equal(post.status, 200);
  assert.deepEqual(observed.map(({ method }) => method), ['GET', 'HEAD', 'POST']);
  assert.equal(observed[0].headers.authorization, 'Bearer origin-only');
  assert.equal(observed[0].headers.host, `origin.invalid:${originPort}`);
  assert.equal(observed[0].headers['proxy-authorization'], undefined);
  assert.equal(observed[0].headers['proxy-connection'], undefined);
  assert.equal(observed[0].headers['x-client-hop'], undefined);
  assert.deepEqual(observed[2].body, payload);
  assert.deepEqual(socks.destinations, [0, 1, 2].map(() => ({ host: 'origin.invalid', port: originPort, atyp: 3 })));
  assert.equal(socks.authentications.length, 3);
});

test('forwards raw HTTP paths and queries without normalizing literal or encoded dot segments', async (t) => {
  const observed = [];
  const originPort = await listen(t, http.createServer((request, response) => {
    observed.push(request.url);
    response.end('raw path received');
  }));
  const socks = await socksFixture(t);
  const bridge = await bridgeFixture(t, socks.proxy);
  const rawTargets = [
    '/bucket/a/../object?signature=demo',
    '/bucket/a/./object?signature=a%2Fb%2B&part=1&part=2',
    '/bucket/a/%2e%2e/object?signature=demo',
    '/bucket/a/%2E./object?signature=demo',
    '/bucket//a/..%2fobject?literal=%2e%2e&empty=',
    '/bucket/object?',
  ];
  for (const target of rawTargets) {
    assert.equal((await proxyRequest(bridge, `http://origin.invalid:${originPort}${target}`)).status, 200);
  }
  assert.equal((await proxyRequest(bridge, `http://origin.invalid:${originPort}?signature=demo`)).status, 200);
  assert.equal((await proxyRequest(bridge, `http://origin.invalid:${originPort}`)).status, 200);
  assert.deepEqual(observed, [...rawTargets, '/?signature=demo', '/']);
  assert.ok(socks.destinations.every(({ host, port, atyp }) => host === 'origin.invalid' && port === originPort && atyp === 3));
});

test('CONNECT preserves opaque TLS-like bytes including bytes sent with the handshake', async (t) => {
  const echo = net.createServer((socket) => socket.pipe(socket));
  const echoPort = await listen(t, echo);
  const socks = await socksFixture(t);
  const bridge = await bridgeFixture(t, socks.proxy);
  const socket = net.connect(bridge.port, bridge.host);
  t.after(() => socket.destroy());
  await once(socket, 'connect');
  const initial = Buffer.from([0x16, 0x03, 0x03, 0x00, 0x07, 0x00, 0xff, 0x80, 0x41]);
  const firstReply = waitForBytes(socket, (bytes) => bytes.includes(initial));
  socket.write(Buffer.concat([
    Buffer.from(`CONNECT tls-origin.invalid:${echoPort} HTTP/1.1\r\nHost: tls-origin.invalid:${echoPort}\r\nProxy-Authorization: ${localAuth(bridge)}\r\n\r\n`), initial,
  ]));
  const first = await firstReply;
  const boundary = first.indexOf('\r\n\r\n');
  assert.match(first.subarray(0, boundary).toString(), /^HTTP\/1\.1 200 Connection Established/);
  assert.deepEqual(first.subarray(boundary + 4), initial);
  const payload = Buffer.alloc(256 * 1024, 0xa7);
  const echoed = waitForBytes(socket, (bytes) => bytes.length >= payload.length);
  socket.write(payload);
  assert.deepEqual(await echoed, payload);
  assert.deepEqual(socks.destinations, [{ host: 'tls-origin.invalid', port: echoPort, atyp: 3 }]);
});

test('rejects missing, wrong and duplicate local auth for HTTP and CONNECT before contacting SOCKS', async (t) => {
  const socks = await socksFixture(t);
  const bridge = await bridgeFixture(t, socks.proxy);
  const denied = await proxyRequest(bridge, 'http://origin.invalid:80/', { auth: false });
  assert.equal(denied.status, 407);
  assert.match(denied.headers['proxy-authenticate'], /^Basic /);
  assert.equal((await proxyRequest(bridge, 'http://origin.invalid:80/', { headers: { 'Proxy-Authorization': 'Basic wrong' } })).status, 407);
  for (const headers of ['', 'Proxy-Authorization: Basic wrong\r\n', `Proxy-Authorization: ${localAuth(bridge)}\r\nProxy-Authorization: ${localAuth(bridge)}\r\n`]) {
    const reply = await rawRequest(bridge, `CONNECT origin.invalid:443 HTTP/1.1\r\nHost: origin.invalid:443\r\n${headers}\r\n`);
    assert.match(reply.toString(), /^HTTP\/1\.1 407 /);
  }
  assert.equal(socks.clients.size, 0);
  assert.equal(socks.authentications.length, 0);
});

test('does not fall back to direct access after upstream authentication or connection failure', async (t) => {
  let originRequests = 0;
  const originPort = await listen(t, http.createServer((_request, response) => { originRequests += 1; response.end('direct bypass'); }));
  const socks = await socksFixture(t, { reject: true });
  const bridge = await bridgeFixture(t, socks.proxy);
  const reply = await proxyRequest(bridge, `http://127.0.0.1:${originPort}/`);
  assert.equal(reply.status, 502);
  assert.equal(reply.body.includes(Buffer.from(socks.proxy.password)), false);
  assert.equal(originRequests, 0);
  assert.equal(socks.destinations.length, 0);
  const closedServer = net.createServer();
  const closedPort = await listen(t, closedServer);
  await new Promise((resolve) => closedServer.close(resolve));
  const unavailable = await bridgeFixture(t, { ...socks.proxy, port: closedPort });
  assert.equal((await proxyRequest(unavailable, `http://127.0.0.1:${originPort}/`)).status, 502);
  assert.equal(originRequests, 0);
});

test('returns redirects to the client without following them', async (t) => {
  let requests = 0;
  const originPort = await listen(t, http.createServer((_request, response) => {
    requests += 1;
    response.writeHead(302, { Location: 'https://unreachable.invalid/private' }).end();
  }));
  const socks = await socksFixture(t);
  const bridge = await bridgeFixture(t, socks.proxy);
  const reply = await proxyRequest(bridge, `http://origin.invalid:${originPort}/`);
  assert.equal(reply.status, 302);
  assert.equal(reply.headers.location, 'https://unreachable.invalid/private');
  assert.equal(requests, 1);
  assert.equal(socks.destinations.length, 1);
});

test('rejects unsupported destinations, malformed framing and giant headers', async (t) => {
  const socks = await socksFixture(t);
  const bridge = await bridgeFixture(t, socks.proxy, { maxHeaderBytes: 1024 });
  for (const destination of ['/relative', 'https://origin.invalid/', 'ftp://origin.invalid/', 'http://origin.invalid:0/', 'http://user:secret@origin.invalid/', 'http://:@origin.invalid/', 'http://origin.invalid/#', 'http:///origin.invalid/']) {
    assert.equal((await proxyRequest(bridge, destination)).status, 400, destination);
  }
  for (const destination of ['origin.invalid:0', 'origin.invalid:65536', 'origin.invalid', 'origin.invalid:443/path', 'http://origin.invalid:443']) {
    const reply = await rawRequest(bridge, `CONNECT ${destination} HTTP/1.1\r\nHost: origin.invalid\r\nProxy-Authorization: ${localAuth(bridge)}\r\n\r\n`);
    assert.match(reply.toString(), /^HTTP\/1\.1 400 /, destination);
  }
  const giant = await rawRequest(bridge, `GET http://origin.invalid/ HTTP/1.1\r\nHost: origin.invalid\r\nX-Giant: ${'x'.repeat(2048)}\r\n\r\n`);
  assert.match(giant.toString(), /^HTTP\/1\.1 431 /);
  const malformed = await rawRequest(bridge, 'POST http://origin.invalid/ HTTP/1.1\r\nHost: origin.invalid\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n');
  assert.match(malformed.toString(), /^HTTP\/1\.1 400 /);
  assert.equal(socks.destinations.length, 0);
});

test('bounds concurrent requests and incoming connections and closes pending SOCKS handshakes', async (t) => {
  const socks = await socksFixture(t, { hang: true });
  const bridge = await bridgeFixture(t, socks.proxy, { maxRequests: 1, maxConnections: 3, connectTimeoutMs: 5000 });
  const pending = proxyRequest(bridge, 'http://origin.invalid:80/').catch((error) => error);
  // Wait for the first real SOCKS transport to be accepted, with a bounded wait.
  const start = Date.now();
  while (!socks.clients.size && Date.now() - start < 1000) await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(socks.clients.size, 1);
  assert.equal((await proxyRequest(bridge, 'http://origin.invalid:80/')).status, 503);
  const upstreamClosed = once([...socks.clients][0], 'close');
  await bridge.close();
  await Promise.all([upstreamClosed, pending]);
  assert.equal(socks.clients.size, 0);
  await bridge.close();
  await assert.rejects(proxyRequest(bridge, 'http://origin.invalid:80/'), { code: 'ECONNREFUSED' });

  const connectionBridge = await bridgeFixture(t, socks.proxy, { maxConnections: 2 });
  const idle = net.connect(connectionBridge.port, connectionBridge.host);
  t.after(() => idle.destroy());
  idle.on('error', () => {});
  await once(idle, 'connect');
  const idle2 = net.connect(connectionBridge.port, connectionBridge.host);
  t.after(() => idle2.destroy());
  idle2.on('error', () => {});
  await once(idle2, 'connect');
  const flood = await rawRequest(connectionBridge, 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n').catch((error) => error);
  // A TCP peer can reset while rejecting unread input; either outcome rejects
  // the excess socket before any upstream connection is opened.
  if (flood instanceof Error) assert.equal(flood.code, 'ECONNRESET');
  else assert.match(flood.toString(), /^HTTP\/1\.1 503 /);
  const pendingClosed = once(idle, 'close');
  const pendingClosed2 = once(idle2, 'close');
  await connectionBridge.close();
  await Promise.all([pendingClosed, pendingClosed2]);
  assert.equal(socks.clients.size, 0);
});

test('closing the bridge terminates an established CONNECT tunnel and its SOCKS socket', async (t) => {
  const echoPort = await listen(t, net.createServer((socket) => socket.pipe(socket)));
  const socks = await socksFixture(t);
  const bridge = await bridgeFixture(t, socks.proxy);
  const socket = net.connect(bridge.port, bridge.host);
  await once(socket, 'connect');
  const reply = waitForBytes(socket, (bytes) => bytes.includes(Buffer.from('\r\n\r\n')));
  socket.write(`CONNECT origin.invalid:${echoPort} HTTP/1.1\r\nHost: origin.invalid\r\nProxy-Authorization: ${localAuth(bridge)}\r\n\r\n`);
  assert.match((await reply).toString(), /^HTTP\/1\.1 200 /);
  const closed = once(socket, 'close');
  const upstreamClosed = once([...socks.clients][0], 'close');
  await bridge.close();
  await Promise.all([closed, upstreamClosed]);
  assert.equal(socks.clients.size, 0);
});

test('request timeout and client cancellation immediately destroy pending SOCKS transports', async (t) => {
  const socks = await socksFixture(t, { hang: true });
  const bridge = await bridgeFixture(t, socks.proxy, { requestTimeoutMs: 30, connectTimeoutMs: 5000 });
  const timedOut = await proxyRequest(bridge, 'http://origin.invalid:80/');
  assert.equal(timedOut.status, 504);
  const deadline = Date.now() + 1000;
  while (socks.clients.size && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(socks.clients.size, 0);

  const tunnelBridge = await bridgeFixture(t, socks.proxy, { connectTimeoutMs: 5000 });
  const socket = net.connect(tunnelBridge.port, tunnelBridge.host);
  await once(socket, 'connect');
  socket.write(`CONNECT origin.invalid:443 HTTP/1.1\r\nHost: origin.invalid\r\nProxy-Authorization: ${localAuth(tunnelBridge)}\r\n\r\n`);
  const accepted = Date.now() + 1000;
  while (!socks.clients.size && Date.now() < accepted) await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(socks.clients.size, 1);
  const closed = once([...socks.clients][0], 'close');
  const cancellationStart = Date.now();
  socket.destroy();
  await closed;
  assert.ok(Date.now() - cancellationStart < 1000, 'cancellation must not wait for the 5000 ms SOCKS timeout');
  assert.equal(socks.clients.size, 0);
});

test('an aborted HTTP upload closes the owned SOCKS connection without an unhandled stream error', async (t) => {
  const socks = await socksFixture(t, { hang: true });
  const bridge = await bridgeFixture(t, socks.proxy, { connectTimeoutMs: 5000 });
  const socket = net.connect(bridge.port, bridge.host);
  await once(socket, 'connect');
  socket.write(`POST http://origin.invalid/upload HTTP/1.1\r\nHost: origin.invalid\r\nContent-Length: 1000\r\nProxy-Authorization: ${localAuth(bridge)}\r\n\r\nx`);
  const deadline = Date.now() + 1000;
  while (!socks.clients.size && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(socks.clients.size, 1);
  const closed = once([...socks.clients][0], 'close');
  const cancellationStart = Date.now();
  socket.destroy();
  await closed;
  assert.ok(Date.now() - cancellationStart < 1000);
  assert.equal(socks.clients.size, 0);
});

test('validates SOCKS configuration and refuses invalid limits without exposing credentials', async () => {
  for (const proxy of [null, { type: 'http', host: '127.0.0.1', port: 1234 }, { host: 'invalid/host', port: 1234 }, { host: '127.0.0.1', port: 0 }, { host: '127.0.0.1', port: 1234, password: 'private-password' }]) {
    await assert.rejects(createTerminalProxyBridge(proxy), (error) => error instanceof TypeError && !error.message.includes('private-password'));
  }
  await assert.rejects(createTerminalProxyBridge({ host: '127.0.0.1', port: 1234 }, { maxConnections: 0 }), TypeError);
});
