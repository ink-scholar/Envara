import assert from 'node:assert/strict';
import net from 'node:net';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { openSshRouteSocket } from '../electron/terminal-ssh-route-socket.mjs';

const hostRoute = { route: { kind: 'host' }, isActive: () => true };
const username = 'synthetic-client', password = 'synthetic:password';
const authorization = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;

async function waitFor(predicate, timeoutMs = 1500) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    assert(Date.now() < deadline, 'Owned socket fixture did not reach its expected state');
    await delay(5);
  }
}

async function listen(t, handler) {
  const sockets = new Set();
  const own = socket => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
    return socket;
  };
  const server = net.createServer({ allowHalfOpen: true }, socket => handler(own(socket), own));
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(async () => {
    const closed = new Promise(resolve => server.close(resolve));
    for (const socket of sockets) socket.destroy();
    await closed;
  });
  return { port: server.address().port, sockets };
}

function environmentRoute(port, extra = {}) {
  return { route: { kind: 'environment', profileId: 'synthetic_environment' },
    proxyUrl: `http://${username}:${encodeURIComponent(password)}@127.0.0.1:${port}`,
    isActive: () => true, ...extra };
}

function receiveHeader(socket, callback) {
  let bytes = Buffer.alloc(0);
  const onData = chunk => {
    bytes = Buffer.concat([bytes, chunk]);
    const end = bytes.indexOf('\r\n\r\n');
    if (end < 0) return;
    socket.off('data', onData);
    socket.pause();
    callback(bytes.subarray(0, end + 4).toString('latin1'), bytes.subarray(end + 4));
  };
  socket.on('data', onData);
}

async function readAll(socket) {
  const chunks = [];
  for await (const chunk of socket) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

test('host routing opens only the fixed owned target and preserves banner and bidirectional EOF', { timeout: 4000 }, async t => {
  const banner = Buffer.from('SSH-2.0-owned-host\r\n'), payload = Buffer.from('opaque client\0bytes');
  const received = [], calls = [];
  const destination = await listen(t, socket => {
    socket.write(banner);
    socket.on('data', chunk => received.push(Buffer.from(chunk)));
    socket.once('end', () => socket.end(Buffer.concat(received)));
  });
  const socket = await openSshRouteSocket({ target: { host: '127.0.0.1', port: destination.port },
    routeContext: hostRoute, connect: options => {
      calls.push(options);
      return net.connect(options);
    } });
  t.after(() => socket.destroy());
  assert.equal(socket.isPaused(), true, 'the receiving transport owns when raw data starts flowing');
  assert.deepEqual(calls, [{ host: '127.0.0.1', port: destination.port, allowHalfOpen: true }]);
  socket.end(payload);
  assert.deepEqual(await readAll(socket), Buffer.concat([banner, payload]));
  assert.deepEqual(Buffer.concat(received), payload);
});

test('authenticated CONNECT preserves a banner coalesced with HTTP 200 and tunnels real owned target bytes', { timeout: 4000 }, async t => {
  const banner = Buffer.from('SSH-2.0-owned-proxy\r\n\0\xff', 'latin1');
  const payload = Buffer.alloc(128 * 1024, 0x96), received = [], requests = [], calls = [];
  let destinationConnections = 0;
  const destination = await listen(t, socket => {
    destinationConnections++;
    socket.write(banner);
    socket.on('data', chunk => received.push(Buffer.from(chunk)));
    socket.once('end', () => socket.end(Buffer.concat(received)));
  });
  const proxy = await listen(t, (socket, own) => receiveHeader(socket, (header, head) => {
    requests.push(header);
    const upstream = own(net.connect({ host: '127.0.0.1', port: destination.port, allowHalfOpen: true }));
    upstream.once('data', firstBanner => {
      socket.write(Buffer.concat([Buffer.from('HTTP/1.1 200 Connection established\r\nX-Owned: yes\r\n\r\n'), firstBanner]));
      upstream.pipe(socket);
      if (head.length) upstream.write(head);
      socket.pipe(upstream);
    });
  }));
  const socket = await openSshRouteSocket({ target: { host: '127.0.0.1', port: destination.port },
    routeContext: environmentRoute(proxy.port), connect: options => {
      calls.push(options);
      return net.connect(options);
    } });
  t.after(() => socket.destroy());
  assert.equal(socket.isPaused(), true);
  assert.deepEqual(calls, [{ host: '127.0.0.1', port: proxy.port, allowHalfOpen: true }]);
  assert.deepEqual(requests, [`CONNECT 127.0.0.1:${destination.port} HTTP/1.1\r\nHost: 127.0.0.1:${destination.port}\r\nProxy-Authorization: ${authorization}\r\n\r\n`]);
  socket.end(payload);
  assert.deepEqual(await readAll(socket), Buffer.concat([banner, payload]));
  assert.deepEqual(Buffer.concat(received), payload);
  assert.equal(destinationConnections, 1);
});

test('CONNECT waits for a complete split header and sends an IPv6 authority without resolving the target', { timeout: 4000 }, async t => {
  const requests = [], calls = [], banner = Buffer.from('SSH-2.0-split\r\n');
  const proxy = await listen(t, socket => receiveHeader(socket, header => {
    requests.push(header);
    socket.write('HTTP/1.0 200 OK\r\nX-Owned: split\r\n');
    setTimeout(() => socket.end(Buffer.concat([Buffer.from('\r\n'), banner])), 10);
  }));
  const socket = await openSshRouteSocket({ target: { host: '[::1]', port: 2222 },
    routeContext: environmentRoute(proxy.port), connect: options => {
      calls.push(options);
      return net.connect(options);
    } });
  t.after(() => socket.destroy());
  socket.end();
  assert.deepEqual(await readAll(socket), banner);
  assert.match(requests[0], /^CONNECT \[::1\]:2222 HTTP\/1\.1\r\nHost: \[::1\]:2222\r\n/);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].host, '127.0.0.1');
});

test('HTTP 407 rejects without falling back to an otherwise reachable owned target', { timeout: 4000 }, async t => {
  let destinationConnections = 0;
  const calls = [], requests = [];
  const destination = await listen(t, socket => { destinationConnections++; socket.end('must not arrive'); });
  const proxy = await listen(t, socket => receiveHeader(socket, header => {
    requests.push(header);
    socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n');
    socket.resume();
  }));
  await assert.rejects(openSshRouteSocket({ target: { host: '127.0.0.1', port: destination.port },
    routeContext: environmentRoute(proxy.port), connect: options => {
      calls.push(options);
      return net.connect(options);
    } }), error => error.code === 'SSH_ROUTE_UNAVAILABLE' && !error.message.includes(password));
  assert.equal(requests.length, 1);
  assert.deepEqual(calls, [{ host: '127.0.0.1', port: proxy.port, allowHalfOpen: true }]);
  assert.equal(destinationConnections, 0);
  await waitFor(() => proxy.sockets.size === 0);
});

test('already cancelled or inactive routes refuse before any socket is created', async () => {
  let calls = 0;
  const connect = () => { calls++; throw new Error('No socket should be created'); };
  const options = { target: { host: '127.0.0.1', port: 2222 }, connect };
  const controller = new AbortController(); controller.abort();
  await assert.rejects(openSshRouteSocket({ ...options, routeContext: hostRoute, signal: controller.signal }), { code: 'SSH_ROUTE_CANCELLED' });
  await assert.rejects(openSshRouteSocket({ ...options, routeContext: { ...hostRoute, isActive: () => false } }), { code: 'SSH_ROUTE_CHANGED' });
  await assert.rejects(openSshRouteSocket({ ...options, routeContext: { ...hostRoute, isActive: () => { throw new Error('revoked'); } } }), { code: 'SSH_ROUTE_CHANGED' });
  assert.equal(calls, 0);
});

test('cancellation during an incomplete CONNECT handshake destroys the owned connection', { timeout: 4000 }, async t => {
  let requested = false, opened;
  const proxy = await listen(t, socket => receiveHeader(socket, () => {
    requested = true;
    socket.once('end', () => socket.end());
    socket.resume();
  }));
  const controller = new AbortController();
  const pending = openSshRouteSocket({ target: { host: '127.0.0.1', port: 2222 },
    routeContext: environmentRoute(proxy.port), signal: controller.signal,
    connect: options => { opened = net.connect(options); return opened; } });
  const rejected = assert.rejects(pending, { code: 'SSH_ROUTE_CANCELLED' });
  await waitFor(() => requested);
  controller.abort();
  await rejected;
  assert.equal(opened.destroyed, true);
  await waitFor(() => proxy.sockets.size === 0);
});

test('route revocation at TCP connect refuses before sending CONNECT', { timeout: 4000 }, async t => {
  let active = true, opened, bytes = 0;
  const proxy = await listen(t, socket => { socket.on('data', chunk => { bytes += chunk.length; }); socket.once('end', () => socket.end()); });
  await assert.rejects(openSshRouteSocket({ target: { host: '127.0.0.1', port: 2222 },
    routeContext: environmentRoute(proxy.port, { isActive: () => active }), connect: options => {
      opened = net.connect(options);
      opened.once('connect', () => { active = false; });
      return opened;
    } }), { code: 'SSH_ROUTE_CHANGED' });
  assert.equal(opened.destroyed, true);
  await waitFor(() => proxy.sockets.size === 0);
  assert.equal(bytes, 0);
});

test('route revocation before the CONNECT response cannot release a raw stream', { timeout: 4000 }, async t => {
  let active = true, opened, calls = 0;
  const proxy = await listen(t, socket => receiveHeader(socket, () => {
    active = false;
    socket.end('HTTP/1.1 200 OK\r\n\r\nSSH-2.0-revoked\r\n');
    socket.resume();
  }));
  await assert.rejects(openSshRouteSocket({ target: { host: '127.0.0.1', port: 2222 },
    routeContext: environmentRoute(proxy.port, { isActive: () => active }), connect: options => {
      calls++; opened = net.connect(options); return opened;
    } }), { code: 'SSH_ROUTE_CHANGED' });
  assert.equal(calls, 1);
  assert.equal(opened.destroyed, true);
  await waitFor(() => proxy.sockets.size === 0);
});

test('incomplete, oversized and malformed proxy replies fail closed and release their sockets', { timeout: 4000 }, async t => {
  for (const response of [null, 'x'.repeat(16385), 'HTTP/1.1 200 OK\r\nInvalid header\r\n\r\n', 'HTTP/1.1 201 Created\r\n\r\n']) {
    await t.test(response === null ? 'handshake deadline' : `reply ${response.length} bytes`, async context => {
      let opened;
      const proxy = await listen(context, socket => receiveHeader(socket, () => {
        if (response !== null) socket.write(response);
        socket.resume();
        socket.once('end', () => socket.end());
      }));
      await assert.rejects(openSshRouteSocket({ target: { host: '127.0.0.1', port: 2222 },
        routeContext: environmentRoute(proxy.port), timeoutMs: 50,
        connect: options => { opened = net.connect(options); return opened; } }), { code: 'SSH_ROUTE_UNAVAILABLE' });
      assert.equal(opened.destroyed, true);
      await waitFor(() => proxy.sockets.size === 0);
    });
  }
});

test('HTTPS proxy connections require certificate verification and reject an unauthorized TLS stream', async () => {
  let options, writes = 0, plainConnects = 0;
  const socket = new net.Socket({ allowHalfOpen: true });
  socket.authorized = false;
  socket.write = () => { writes++; return true; };
  await assert.rejects(openSshRouteSocket({ target: { host: '127.0.0.1', port: 2222 },
    routeContext: environmentRoute(12345, { proxyUrl: `https://${username}:${encodeURIComponent(password)}@127.0.0.1:12345` }),
    connect: () => { plainConnects++; throw new Error('TLS must not fall back to TCP'); },
    secureConnect: fields => {
      options = fields;
      queueMicrotask(() => socket.emit('secureConnect'));
      return socket;
    } }), { code: 'SSH_ROUTE_UNAVAILABLE' });
  assert.deepEqual(options, { host: '127.0.0.1', port: 12345, allowHalfOpen: true, rejectUnauthorized: true });
  assert.equal(plainConnects, 0);
  assert.equal(writes, 0, 'proxy credentials must not reach an unauthorized TLS connection');
  assert.equal(socket.destroyed, true);
});

test('invalid routes, target injection and missing proxy credentials refuse before connecting', async () => {
  let calls = 0;
  const options = { target: { host: '127.0.0.1', port: 2222 }, routeContext: hostRoute,
    connect: () => { calls++; throw new Error('No network call is authorized'); } };
  for (const change of [
    { target: { host: '127.0.0.1\r\nInjected: header', port: 2222 } },
    { routeContext: { ...hostRoute, proxyUrl: 'http://synthetic:password@127.0.0.1:12345' } },
    { routeContext: { route: { kind: 'environment', profileId: 'synthetic_environment' }, isActive: () => true } },
    { routeContext: { ...environmentRoute(12345), proxyUrl: 'http://127.0.0.1:12345' } },
    { routeContext: { route: { kind: 'host' } } },
    { timeoutMs: 1 },
  ]) await assert.rejects(openSshRouteSocket({ ...options, ...change }), { code: 'SSH_ROUTE_INVALID' });
  assert.equal(calls, 0);
});
