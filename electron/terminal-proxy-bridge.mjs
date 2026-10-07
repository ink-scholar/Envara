import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import { domainToASCII } from 'node:url';
import { SocksClient } from 'socks';

const HOP_HEADERS = new Set([
  'connection', 'proxy-connection', 'keep-alive', 'proxy-authenticate',
  'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

function boundedInteger(value, fallback, minimum, maximum, name) {
  const selected = value ?? fallback;
  if (!Number.isInteger(selected) || selected < minimum || selected > maximum) {
    throw new TypeError(`Invalid terminal proxy ${name}`);
  }
  return selected;
}

function normalizedHost(value) {
  if (typeof value !== 'string' || !value || /[\s\x00-\x1f\x7f/\\@?#]/.test(value)) {
    throw new TypeError('Invalid terminal proxy host');
  }
  const unbracketed = value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;
  if (net.isIP(unbracketed)) return unbracketed;
  const host = domainToASCII(value);
  if (!host || host.length > 253 || !/^[a-z\d.-]+$/i.test(host)) throw new TypeError('Invalid terminal proxy host');
  const labels = host.replace(/\.$/, '').split('.');
  if (labels.some((label) => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) {
    throw new TypeError('Invalid terminal proxy host');
  }
  return host;
}

function normalizedProxy(proxy) {
  if (!proxy || typeof proxy !== 'object' || (proxy.type !== undefined && proxy.type !== 'socks5')) {
    throw new TypeError('Terminal bridge requires a SOCKS5 proxy');
  }
  const host = normalizedHost(proxy.host);
  const port = boundedInteger(proxy.port, undefined, 1, 65535, 'upstream port');
  const username = proxy.username ?? '';
  const password = proxy.password ?? '';
  if (typeof username !== 'string' || typeof password !== 'string'
    || Buffer.byteLength(username) > 255 || Buffer.byteLength(password) > 255
    || (!username && password)) throw new TypeError('Invalid terminal proxy credentials');
  return { host, port, type: 5, userId: username, password };
}

function destinationFromHttp(value) {
  if (typeof value !== 'string' || !/^http:\/\/[^/]/i.test(value) || /[\s\x00-\x1f\x7f\\#]/.test(value)) {
    throw new TypeError('An absolute HTTP URL is required');
  }
  const [, authority, rawTarget] = /^http:\/\/([^/?]+)(.*)$/i.exec(value) ?? [];
  if (!authority || authority.includes('@')) throw new TypeError('Invalid HTTP destination');
  const url = new URL(value);
  if (url.protocol !== 'http:' || url.username || url.password || url.hash) throw new TypeError('Invalid HTTP destination');
  const host = normalizedHost(url.hostname);
  const port = boundedInteger(url.port ? Number(url.port) : 80, undefined, 1, 65535, 'destination port');
  // WHATWG URL parsing validates the authority but normalizes dot segments.
  // Preserve the caller's path and query, including signed or encoded paths.
  const path = rawTarget ? (rawTarget.startsWith('?') ? `/${rawTarget}` : rawTarget) : '/';
  return { host, port, hostHeader: url.host, path };
}

function destinationFromConnect(value) {
  if (typeof value !== 'string') throw new TypeError('Invalid CONNECT destination');
  const match = /^(\[[a-f\d:.]+\]|[^:\s/\\@?#]+):(\d{1,5})$/i.exec(value);
  if (!match) throw new TypeError('CONNECT requires a host and port');
  const host = normalizedHost(match[1]);
  const port = boundedInteger(Number(match[2]), undefined, 1, 65535, 'destination port');
  return { host, port };
}

function strippedHeaders(headers) {
  const blocked = new Set(HOP_HEADERS);
  for (const name of String(headers.connection ?? '').split(',')) {
    const token = name.trim().toLowerCase();
    if (token) blocked.add(token);
  }
  return Object.fromEntries(Object.entries(headers).filter(([name]) => !blocked.has(name.toLowerCase())));
}

function hasDuplicateSensitiveHeaders(request) {
  const seen = new Set();
  for (let i = 0; i < request.rawHeaders.length; i += 2) {
    const name = request.rawHeaders[i].toLowerCase();
    if (['host', 'proxy-authorization', 'authorization', 'content-length', 'transfer-encoding'].includes(name)) {
      if (seen.has(name)) return true;
      seen.add(name);
    }
  }
  return false;
}

function errorResponse(response, status, message) {
  if (response.destroyed || response.writableEnded) return;
  if (response.headersSent) {
    response.destroy();
    return;
  }
  response.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', Connection: 'close',
    ...(status === 407 ? { 'Proxy-Authenticate': 'Basic realm="Envara terminal"' } : {}),
  });
  response.end(`${message}\n`);
}

function socketErrorResponse(socket, status, message) {
  if (socket.destroyed) return;
  const body = Buffer.from(`${message}\n`);
  socket.end(`HTTP/1.1 ${status} ${http.STATUS_CODES[status]}\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${body.length}\r\n${status === 407 ? 'Proxy-Authenticate: Basic realm="Envara terminal"\r\n' : ''}\r\n${body}`);
  socket.destroySoon();
}

/**
 * A loopback HTTP proxy for proxy-aware terminal clients. HTTP destinations are
 * opened through SOCKS5 (including remote DNS); CONNECT is an opaque TCP tunnel.
 * This does not intercept TLS or constrain programs that ignore proxy settings.
 */
export async function createTerminalProxyBridge(proxy, options = {}) {
  const upstreamProxy = normalizedProxy(proxy);
  const maxConnections = boundedInteger(options.maxConnections, 32, 1, 512, 'connection limit');
  const maxRequests = boundedInteger(options.maxRequests, 32, 1, 512, 'request limit');
  const maxHeaderBytes = boundedInteger(options.maxHeaderBytes, 16 * 1024, 1024, 64 * 1024, 'header limit');
  const connectTimeoutMs = boundedInteger(options.connectTimeoutMs, 10_000, 10, 120_000, 'connection timeout');
  const requestTimeoutMs = boundedInteger(options.requestTimeoutMs, 120_000, 10, 3_600_000, 'request timeout');
  const idleTimeoutMs = boundedInteger(options.idleTimeoutMs, 120_000, 10, 3_600_000, 'idle timeout');
  const username = crypto.randomBytes(16).toString('hex');
  const password = crypto.randomBytes(32).toString('hex');
  const auth = Buffer.from(`Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`);
  const sockets = new Set();
  const incomingSockets = new Set();
  let activeRequests = 0;
  let closing = false;
  let closePromise;

  function trackSocket(socket) {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
    return socket;
  }

  function authorized(request) {
    if (request.rawHeaders.length > 200 || hasDuplicateSensitiveHeaders(request)) return false;
    const supplied = Buffer.from(request.headers['proxy-authorization'] ?? '');
    return supplied.length === auth.length && crypto.timingSafeEqual(supplied, auth);
  }

  function connectUpstream(destination, ownSocket) {
    return new Promise((resolve, reject) => {
      const socket = trackSocket(new net.Socket());
      ownSocket(socket);
      let settled = false;
      const timer = setTimeout(() => socket.destroy(new Error('Terminal proxy upstream timeout')), connectTimeoutMs);
      timer.unref();
      function complete(error) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error || closing) {
          socket.destroy();
          reject(new Error('Upstream proxy connection failed'));
        } else {
          socket.setTimeout(idleTimeoutMs, () => socket.destroy());
          resolve(socket);
        }
      }
      socket.once('error', () => complete(true));
      socket.once('close', () => complete(true));
      socket.once('connect', () => {
        if (closing) return complete(true);
        try {
          const client = new SocksClient({ proxy: upstreamProxy, command: 'connect', destination, timeout: connectTimeoutMs });
          client.once('error', () => complete(true));
          client.once('established', () => complete());
          // The socket is already connected, and remains tracked during the
          // entire SOCKS handshake so shutdown cannot leave pending sockets.
          client.connect(socket);
        } catch {
          complete(true);
        }
      });
      if (closing) complete(true);
      else socket.connect(upstreamProxy.port, upstreamProxy.host);
    });
  }

  async function forwardHttp(request, response, expectContinue = false) {
    request.pause();
    request.once('error', () => response.destroy());
    if (response.destroyed || response.writableEnded) return;
    if (!authorized(request)) return errorResponse(response, 407, 'Proxy authentication required');
    let destination;
    try { destination = destinationFromHttp(request.url); } catch { return errorResponse(response, 400, 'Invalid HTTP destination'); }
    if (closing || activeRequests >= maxRequests) return errorResponse(response, 503, 'Terminal proxy is busy');
    activeRequests += 1;
    let finished = false;
    let upstreamSocket;
    let outgoing;
    let agent;
    const timeout = setTimeout(() => errorResponse(response, 504, 'Terminal proxy request timed out'), requestTimeoutMs);
    timeout.unref();
    function finish() {
      if (finished) return;
      finished = true;
      clearTimeout(timeout);
      activeRequests -= 1;
      outgoing?.destroy();
      upstreamSocket?.destroy();
      agent?.destroy();
    }
    response.once('close', finish);
    response.once('finish', finish);
    request.once('aborted', () => { response.destroy(); finish(); });
    if (expectContinue) response.writeContinue();
    try {
      upstreamSocket = await connectUpstream({ host: destination.host, port: destination.port }, (socket) => { upstreamSocket = socket; });
      if (finished || closing || response.destroyed) return upstreamSocket.destroy();
      const headers = strippedHeaders(request.headers);
      headers.host = destination.hostHeader;
      delete headers.expect;
      agent = new http.Agent({ keepAlive: false, maxSockets: 1 });
      agent.createConnection = () => upstreamSocket;
      outgoing = http.request({
        host: destination.host, port: destination.port, path: destination.path,
        method: request.method, headers, agent, maxHeaderSize: maxHeaderBytes,
      });
      outgoing.once('error', () => errorResponse(response, 502, 'Upstream proxy request failed'));
      outgoing.once('upgrade', (_originResponse, upgradedSocket) => {
        upgradedSocket.destroy();
        errorResponse(response, 502, 'HTTP upgrade is unsupported');
      });
      outgoing.once('response', (originResponse) => {
        if (finished || response.destroyed) return originResponse.destroy();
        originResponse.once('error', () => response.destroy());
        originResponse.once('aborted', () => response.destroy());
        response.writeHead(originResponse.statusCode ?? 502, strippedHeaders(originResponse.headers));
        originResponse.pipe(response);
      });
      request.pipe(outgoing);
    } catch {
      errorResponse(response, 502, 'Upstream proxy connection failed');
    }
  }

  const server = http.createServer({
    maxHeaderSize: maxHeaderBytes, requestTimeout: requestTimeoutMs,
    headersTimeout: Math.min(requestTimeoutMs, connectTimeoutMs), keepAliveTimeout: 1_000,
    insecureHTTPParser: false,
  }, (request, response) => { void forwardHttp(request, response); });
  // Read all headers within the byte limit so none can be silently truncated
  // before authentication or hop-header validation.
  server.maxHeadersCount = 0;
  server.on('connection', (socket) => {
    trackSocket(socket);
    if (closing || incomingSockets.size >= maxConnections) return socketErrorResponse(socket, 503, 'Terminal proxy is busy');
    incomingSockets.add(socket);
    socket.setTimeout(idleTimeoutMs, () => socket.destroy());
    socket.once('close', () => incomingSockets.delete(socket));
  });
  server.on('checkContinue', (request, response) => { void forwardHttp(request, response, true); });
  server.on('clientError', (error, socket) => {
    socketErrorResponse(socket, error.code === 'HPE_HEADER_OVERFLOW' ? 431 : 400, 'Invalid proxy request');
  });
  server.on('upgrade', (_request, socket) => socketErrorResponse(socket, 501, 'HTTP upgrade is unsupported'));
  server.on('connect', (request, socket, head) => {
    if (!authorized(request)) return socketErrorResponse(socket, 407, 'Proxy authentication required');
    let destination;
    try { destination = destinationFromConnect(request.url); } catch { return socketErrorResponse(socket, 400, 'Invalid CONNECT destination'); }
    if (closing || activeRequests >= maxRequests) return socketErrorResponse(socket, 503, 'Terminal proxy is busy');
    activeRequests += 1;
    let finished = false;
    let established = false;
    let upstreamSocket;
    function finish() {
      if (finished) return;
      finished = true;
      activeRequests -= 1;
      upstreamSocket?.destroy();
      socket.destroy();
    }
    socket.once('close', finish);
    socket.once('end', () => { if (!established) finish(); });
    void connectUpstream(destination, (upstream) => { upstreamSocket = upstream; }).then((upstream) => {
      upstreamSocket = upstream;
      if (finished || closing || socket.destroyed) return upstream.destroy();
      established = true;
      upstream.once('error', finish);
      upstream.once('close', () => {
        if (upstream.readableEnded) socket.end();
        else finish();
      });
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      socket.pipe(upstream);
      upstream.pipe(socket);
    }, () => socketErrorResponse(socket, 502, 'Upstream proxy connection failed'));
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const port = server.address().port;
  return Object.freeze({
    url: `http://${username}:${password}@127.0.0.1:${port}`,
    host: '127.0.0.1', port,
    close() {
      if (!closePromise) {
        closing = true;
        closePromise = new Promise((resolve) => {
          server.close(resolve);
          for (const socket of sockets) socket.destroy();
        });
      }
      return closePromise;
    },
  });
}
