import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { domainToASCII } from 'node:url';
import { createProxyDestinationResolver, isPublicDestinationIPv4 } from './proxy-destination-dns.mjs';

const HOP_HEADERS = new Set(['connection', 'proxy-connection', 'keep-alive', 'proxy-authenticate',
  'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
const POLICY_ERROR = /\b(?:policy|forbidden|blocked|denied|prohibited|acl|authentication|permission|quota|payment)\b|not allowed|rate[ -]?limit/i;
const failure = (code = 'PROXY_CONNECT_FAILED') => Object.assign(new Error('Proxy compatibility connection failed'), { code });
const policyError = value => POLICY_ERROR.test(String(value).replace(/_/g, ' '));
const responsePolicyError = response => policyError(response.statusMessage ?? '') ||
  Object.entries(response.headers).some(([key, value]) => policyError(`${key} ${value}`));
const statusError = status => status === 401 || status === 407 ? 'PROXY_AUTH_REQUIRED' : status === 403 ? 'PROXY_DENIED' :
  status === 429 ? 'PROXY_RATE_LIMITED' : 'PROXY_CONNECT_FAILED';
const PUBLIC_CODES = new Set(['AUTH_REQUIRED', 'DENIED', 'RATE_LIMITED', 'DESTINATION_DNS_FAILED', 'CONNECT_FAILED', 'TLS_FAILED', 'RECOVERED']);
function publicCode(value) { const code = typeof value === 'string' ? value.replace(/^PROXY_/, '') : ''; return PUBLIC_CODES.has(code) ? code : 'CONNECT_FAILED'; }

function integer(value, fallback, min, max) {
  const result = value ?? fallback;
  if (!Number.isInteger(result) || result < min || result > max) throw new TypeError('Invalid proxy compatibility limit');
  return result;
}
function host(value) {
  if (typeof value !== 'string' || !value || /[\s\x00-\x1f\x7f/\\@?#%]/.test(value)) throw new TypeError('Invalid proxy compatibility host');
  const bare = value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;
  if (net.isIP(bare)) return bare;
  const ascii = domainToASCII(value).toLowerCase();
  if (!ascii || ascii.length > 253 || !/^[a-z\d.-]+$/.test(ascii) || ascii.replace(/\.$/, '').split('.').some(
    label => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) throw new TypeError('Invalid proxy compatibility host');
  return ascii;
}
function credentials(value, required = false) {
  const username = value?.username ?? '';
  const password = value?.password ?? '';
  if (typeof username !== 'string' || typeof password !== 'string' || username.includes(':') ||
      /[\x00-\x1f\x7f]/.test(username + password) || Buffer.byteLength(username) > 2048 || Buffer.byteLength(password) > 2048 ||
      (required && (!username || !password))) throw new TypeError('Invalid proxy compatibility credentials');
  return { username, password };
}
function authority(value) {
  const match = typeof value === 'string' && /^(\[[a-f\d:.]+\]|[^:\s/\\@?#]+):([1-9]\d{0,4})$/i.exec(value);
  if (!match) throw new TypeError('Invalid CONNECT authority');
  const hostname = host(match[1]);
  return { host: hostname, port: integer(Number(match[2]), null, 1, 65535) };
}
const formattedAuthority = (hostname, port) => `${net.isIP(hostname) === 6 ? `[${hostname}]` : hostname}:${port}`;
function httpDestination(value) {
  if (typeof value !== 'string' || /[\s\x00-\x1f\x7f\\#]/.test(value)) throw new TypeError('Invalid HTTP destination');
  const match = /^http:\/\/([^/?]+)(.*)$/i.exec(value);
  if (!match || match[1].includes('@')) throw new TypeError('Invalid HTTP destination');
  const url = new URL(value);
  if (url.protocol !== 'http:' || url.username || url.password || url.hash) throw new TypeError('Invalid HTTP destination');
  host(url.hostname);
  integer(url.port ? Number(url.port) : 80, null, 1, 65535);
  // Validate with URL, but preserve signed paths, query strings and dot segments.
  return { target: `http://${url.host}${match[2] ? (match[2].startsWith('?') ? '/' : '') + match[2] : '/'}`, host: url.host };
}
function strippedHeaders(headers) {
  const blocked = new Set(HOP_HEADERS);
  for (const name of String(headers.connection ?? '').split(',')) blocked.add(name.trim().toLowerCase());
  return Object.fromEntries(Object.entries(headers).filter(([name]) => !blocked.has(name.toLowerCase())));
}
function duplicateSensitive(request) {
  const seen = new Set();
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    const name = request.rawHeaders[index].toLowerCase();
    if (['host', 'proxy-authorization', 'authorization', 'content-length', 'transfer-encoding'].includes(name)) {
      if (seen.has(name)) return true;
      seen.add(name);
    }
  }
  return false;
}
function socketResponse(socket, status, headers = {}, body = Buffer.alloc(0)) {
  if (socket.destroyed || socket.writableEnded) return;
  const safe = strippedHeaders(headers);
  if (status === 407) { for (const key of Object.keys(safe)) delete safe[key]; body = Buffer.alloc(0); }
  delete safe['content-length'];
  const lines = Object.entries(safe).flatMap(([name, value]) => (Array.isArray(value) ? value : [value]).map(item => `${name}: ${item}`));
  socket.end(Buffer.concat([Buffer.from(`HTTP/1.1 ${status} ${http.STATUS_CODES[status] ?? 'Proxy Response'}\r\n${lines.length ? lines.join('\r\n') + '\r\n' : ''}Connection: close\r\nContent-Length: ${body.length}\r\n${status === 407 ? 'Proxy-Authenticate: Basic realm="Envara"\r\n' : ''}\r\n`), body]));
  socket.destroySoon();
}
function responseError(response, status) {
  if (response.destroyed || response.writableEnded) return;
  if (response.headersSent) return response.destroy();
  response.writeHead(status, { Connection: 'close', 'Content-Length': '0', ...(status === 407 ? { 'Proxy-Authenticate': 'Basic realm="Envara"' } : {}) });
  response.end();
}

// CONNECT errors are inspected only within a small, unambiguous body. Unknown
// framing or oversized bodies retain the original status without a retry.
function errorBody(socket, response, head, signal, limit) {
  const length = response.headers['content-length'];
  const chunked = response.headers['transfer-encoding'];
  if (chunked || response.headers['content-encoding'] && response.headers['content-encoding'] !== 'identity' ||
      (length !== undefined && !/^\d+$/.test(length)) || Number(length ?? 0) > limit) return Promise.resolve({ complete: false, body: Buffer.alloc(0) });
  const wanted = length === undefined ? null : Number(length);
  if (wanted === null && !/\bclose\b/i.test(response.headers.connection ?? '')) return Promise.resolve({ complete: false, body: Buffer.alloc(0) });
  return new Promise(resolve => {
    const chunks = []; let bytes = 0; let settled = false;
    const finish = complete => {
      if (settled) return;
      settled = true;
      socket.off('data', data); socket.off('end', ended); socket.off('close', ended); socket.off('error', failed);
      signal.removeEventListener('abort', failed);
      socket.pause();
      resolve({ complete, body: complete ? Buffer.concat(chunks) : Buffer.alloc(0) });
    };
    const data = chunk => {
      bytes += chunk.length;
      if (bytes > limit || (wanted !== null && bytes > wanted)) return finish(false);
      chunks.push(chunk);
      if (wanted !== null && bytes === wanted) finish(true);
    };
    const ended = () => finish(wanted === null || bytes === wanted);
    const failed = () => finish(false);
    socket.on('data', data); socket.once('end', ended); socket.once('close', ended); socket.once('error', failed);
    signal.addEventListener('abort', failed, { once: true });
    if (signal.aborted) return failed();
    data(head);
    if (!settled) socket.resume();
  });
}

/** Opaque route compatibility, without target TLS interception or HTTP replay.
 * Options are trusted main-process inputs, never renderer/IPC configuration.
 */
export async function createProxyCompatibilityBridge(input, options = {}) {
  const protocol = input?.protocol ?? input?.type;
  if (!['http', 'https'].includes(protocol) || (input?.protocol && input?.type && input.protocol !== input.type)) throw new TypeError('HTTP or HTTPS proxy required');
  const proxy = { protocol, host: host(input.host), port: integer(input.port, null, 1, 65535), ...credentials(input) };
  const upstreamAddress = options.upstreamAddress;
  const localAddress = options.localAddress;
  if (upstreamAddress != null && (!net.isIP(upstreamAddress) || (!isPublicDestinationIPv4(upstreamAddress) && upstreamAddress !== proxy.host)) ||
      localAddress != null && net.isIP(localAddress) !== 4) throw new TypeError('Invalid proxy compatibility address');
  const maxConnections = integer(options.maxConnections, 64, 1, 512);
  const maxRequests = integer(options.maxRequests, 64, 1, 512);
  const maxHeaderBytes = integer(options.maxHeaderBytes, 16384, 1024, 65536);
  const maxConnectHeadBytes = integer(options.maxConnectHeadBytes, 65536, 0, 262144);
  const earlyConnectAck = options.earlyConnectAck ?? false;
  if (typeof earlyConnectAck !== 'boolean') throw new TypeError('Invalid proxy compatibility acknowledgement');
  const maxPendingBytes = earlyConnectAck ? Math.min(maxConnectHeadBytes, 65536) : maxConnectHeadBytes;
  const connectTimeoutMs = integer(options.connectTimeoutMs, 20000, 10, 120000);
  const requestTimeoutMs = integer(options.requestTimeoutMs, 120000, 10, 3600000);
  const idleTimeoutMs = integer(options.idleTimeoutMs, 120000, 10, 3600000);
  const local = credentials(options.credentials ?? { username: crypto.randomBytes(16).toString('hex'), password: crypto.randomBytes(32).toString('hex') }, true);
  const localAuth = Buffer.from(`Basic ${Buffer.from(`${local.username}:${local.password}`).toString('base64')}`);
  const upstreamAuth = proxy.username || proxy.password ? `Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString('base64')}` : null;
  const resolver = options.resolver ?? createProxyDestinationResolver(proxy, { upstreamAddress, localAddress, ...(options.ca ? { ca: options.ca } : {}) });
  if (!resolver || typeof resolver.resolve !== 'function' || typeof resolver.close !== 'function') throw new TypeError('Invalid proxy compatibility resolver');
  const sockets = new Set(); const incoming = new Set(); const operations = new Set();
  let closing = false; let closePromise; let recovered = 0; let failed = 0; let lastErrorCode = null; let lastUpstreamStatus = null;
  const diagnostic = (stage, status, recovery, code) => {
    lastErrorCode = publicCode(code); lastUpstreamStatus = status;
    try { options.onDiagnostic?.(Object.freeze({ stage, status, recovery, code: lastErrorCode })); } catch { /* Diagnostics never affect routing. */ }
  };
  const recordFailure = (stage, status = null, code = statusError(status)) => { failed++; diagnostic(stage, status, false, code); };
  const track = socket => {
    sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); return socket;
  };
  function authorized(request) {
    if (request.rawHeaders.length > 200 || duplicateSensitive(request)) return false;
    const supplied = Buffer.from(request.headers['proxy-authorization'] ?? '');
    return supplied.length === localAuth.length && crypto.timingSafeEqual(supplied, localAuth);
  }
  function operation(timeout) {
    const controller = new AbortController();
    const state = { controller, deadline: performance.now() + timeout, cleanup: new Set() };
    operations.add(state);
    const timer = setTimeout(() => controller.abort(), timeout); timer.unref();
    controller.signal.addEventListener('abort', () => { for (const dispose of state.cleanup) dispose(); }, { once: true });
    state.establish = () => { clearTimeout(timer); operations.delete(state); };
    state.finish = () => { clearTimeout(timer); controller.abort(); operations.delete(state); };
    return state;
  }
  function openSocket(state) {
    return new Promise((resolve, reject) => {
      if (closing || state.controller.signal.aborted) return reject(failure());
      let socket = track(new net.Socket()); let tlsPhase = false;
      const timer = setTimeout(() => socket.destroy(), Math.min(connectTimeoutMs, Math.max(1, state.deadline - performance.now()))); timer.unref();
      const dispose = () => socket.destroy(); state.cleanup.add(dispose);
      const done = (error) => {
        clearTimeout(timer);
        socket.off('error', bad); socket.off('close', bad);
        if (error || closing || state.controller.signal.aborted) { socket.destroy(); reject(failure(tlsPhase ? 'PROXY_TLS_FAILED' : 'PROXY_CONNECT_FAILED')); }
        else { socket.setTimeout(idleTimeoutMs, () => socket.destroy()); resolve(socket); }
      };
      const bad = () => done(true);
      socket.once('error', bad); socket.once('close', bad);
      socket.once('connect', () => {
        if (protocol !== 'https') return done();
        tlsPhase = true;
        const plain = socket; plain.off('error', bad); plain.off('close', bad);
        try {
          socket = track(tls.connect({ socket: plain, rejectUnauthorized: true, ...(options.ca ? { ca: options.ca } : {}),
            ...(net.isIP(proxy.host) ? {} : { servername: proxy.host }),
            checkServerIdentity: (_name, certificate) => tls.checkServerIdentity(proxy.host, certificate) }));
          socket.once('error', bad); socket.once('close', bad); socket.once('secureConnect', () => done());
        } catch { plain.destroy(); done(true); }
      });
      try { socket.connect({ host: upstreamAddress ?? proxy.host, port: proxy.port, ...(localAddress ? { localAddress, family: 4 } : {}) }); }
      catch { done(true); }
    });
  }
  async function upstreamConnect(destination, state) {
    const socket = await openSocket(state);
    return new Promise((resolve, reject) => {
      let settled = false;
      const agent = new http.Agent({ keepAlive: false, maxSockets: 1 }); agent.createConnection = () => socket;
      const request = http.request({ method: 'CONNECT', host: proxy.host, port: proxy.port, path: destination,
        headers: { Host: destination, ...(upstreamAuth ? { 'Proxy-Authorization': upstreamAuth } : {}) },
        agent, maxHeaderSize: maxHeaderBytes, signal: state.controller.signal });
      const dispose = () => { request.destroy(); socket.destroy(); agent.destroy(); }; state.cleanup.add(dispose);
      const finish = (error, result) => { if (settled) return; settled = true; if (error) { dispose(); reject(failure()); } else resolve(result); };
      request.once('error', () => finish(true));
      request.once('connect', (response, connected, head) => {
        connected.pause();
        if (duplicateSensitive(response) || response.rawHeaders.length > 200) return finish(true);
        finish(false, { response, socket: connected, head, dispose });
      });
      request.end();
    });
  }
  function resolveDestination(destination, state) {
    const signal = state.controller.signal;
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error, answer) => {
        if (settled) return;
        settled = true; signal.removeEventListener('abort', aborted);
        if (error) reject(failure('PROXY_DESTINATION_DNS_FAILED')); else resolve(answer);
      };
      const aborted = () => finish(true);
      signal.addEventListener('abort', aborted, { once: true });
      if (signal.aborted) return aborted();
      const remaining = Math.ceil(state.deadline - performance.now());
      Promise.resolve().then(() => {
        if (signal.aborted || remaining < 1) throw failure();
        return resolver.resolve(destination, { signal, timeoutMs: Math.min(10000, remaining) });
      }).then(answer => finish(false, answer), () => finish(true));
    });
  }
  async function forwardHttp(request, response, expectContinue = false) {
    request.pause(); request.on('error', () => response.destroy());
    if (!authorized(request)) return responseError(response, 407);
    let destination;
    try { destination = httpDestination(request.url); } catch { return responseError(response, 400); }
    if (closing || operations.size >= maxRequests) return responseError(response, 503);
    const state = operation(requestTimeoutMs); let outgoing;
    const finish = () => state.finish();
    response.once('close', finish); response.once('finish', finish);
    request.once('aborted', () => { response.destroy(); finish(); });
    state.controller.signal.addEventListener('abort', () => responseError(response, 504), { once: true });
    try {
      const socket = await openSocket(state);
      if (state.controller.signal.aborted || response.destroyed) return;
      const headers = strippedHeaders(request.headers); headers.host = destination.host;
      delete headers.expect;
      if (upstreamAuth) headers['proxy-authorization'] = upstreamAuth;
      const agent = new http.Agent({ keepAlive: false, maxSockets: 1 }); agent.createConnection = () => socket;
      outgoing = http.request({ host: proxy.host, port: proxy.port, method: request.method, path: destination.target,
        headers, agent, maxHeaderSize: maxHeaderBytes, signal: state.controller.signal });
      state.cleanup.add(() => { outgoing.destroy(); agent.destroy(); socket.destroy(); });
      outgoing.once('error', () => { if (!state.controller.signal.aborted) recordFailure('http'); responseError(response, 502); });
      outgoing.once('upgrade', (_reply, upgraded) => { upgraded.destroy(); responseError(response, 502); });
      outgoing.once('response', upstream => {
        if (response.destroyed) return upstream.destroy();
        if (upstream.statusCode >= 400) recordFailure('http', upstream.statusCode);
        if (upstream.statusCode === 407) { upstream.destroy(); responseError(response, 407); return; }
        upstream.on('error', () => response.destroy()); upstream.once('aborted', () => response.destroy());
        response.writeHead(upstream.statusCode ?? 502, strippedHeaders(upstream.headers));
        upstream.pipe(response);
      });
      if (expectContinue) response.writeContinue();
      request.pipe(outgoing);
    } catch (error) { if (!state.controller.signal.aborted) recordFailure('http', null, error.code); responseError(response, 502); }
  }
  async function forwardConnect(request, socket, head) {
    socket.pause();
    if (!authorized(request)) return socketResponse(socket, 407);
    let destination;
    try { destination = authority(request.url); } catch { return socketResponse(socket, 400); }
    if (request.headers['transfer-encoding'] !== undefined || request.headers['content-length'] !== undefined && request.headers['content-length'] !== '0') return socketResponse(socket, 400);
    if (head.length > maxPendingBytes) return socketResponse(socket, 413);
    if (closing || operations.size >= maxRequests) return socketResponse(socket, 503);
    const state = operation(connectTimeoutMs); let established = false; let acknowledged = false; let recoveryError = null;
    let failureRecorded = false; let lastStatus = null; let phase = 'connect';
    const failedConnect = (stage = phase, status = lastStatus, code = stage === 'resolve' ? 'PROXY_DESTINATION_DNS_FAILED' : statusError(status)) => {
      if (!failureRecorded && !closing) { failureRecorded = true; recordFailure(stage, status, code); }
    };
    const refuse = (status, headers, body) => {
      // Only the private core hop may be acknowledged early. Once acknowledged,
      // this is an opaque stream: a later refusal can only close it.
      if (acknowledged) socket.destroy(); else socketResponse(socket, status, headers, body);
    };
    const early = [head]; let earlyBytes = head.length;
    const retain = chunk => {
      earlyBytes += chunk.length;
      if (earlyBytes > maxPendingBytes) { failedConnect('connect', null); refuse(413); state.finish(); }
      else early.push(chunk);
    };
    socket.on('data', retain); socket.resume();
    const abort = () => {
      if (!established && !socket.destroyed && !socket.writableEnded && !socket.readableEnded) failedConnect();
      if (established) socket.destroy(); else refuse(502);
    };
    state.controller.signal.addEventListener('abort', abort, { once: true });
    socket.once('close', () => state.finish());
    socket.once('end', () => { if (!established) state.finish(); });
    try {
      if (earlyConnectAck) {
        acknowledged = true;
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      }
      let result = await upstreamConnect(formattedAuthority(destination.host, destination.port), state);
      lastStatus = result.response.statusCode;
      if (result.response.statusCode === 502 && !net.isIP(destination.host) && !('retry-after' in result.response.headers)) {
        const inspected = await errorBody(result.socket, result.response, result.head, state.controller.signal, 8192);
        const policy = responsePolicyError(result.response) || policyError(inspected.body.toString('utf8'));
        result.body = inspected.body;
        if (inspected.complete && !policy && !state.controller.signal.aborted) {
          result.dispose();
          try {
            phase = 'resolve';
            const answer = await resolveDestination(destination.host, state);
            const addresses = [...new Set(answer?.addresses ?? [])].filter(isPublicDestinationIPv4).slice(0, 2);
            if (!addresses.length) recoveryError = 'PROXY_DESTINATION_DNS_FAILED';
            for (const address of addresses) {
              if (closing || state.controller.signal.aborted || performance.now() >= state.deadline) break;
              phase = 'connect';
              let next;
              try { next = await upstreamConnect(formattedAuthority(address, destination.port), state); } catch { break; }
              result = next;
              lastStatus = result.response.statusCode;
              if (result.response.statusCode === 200) { recovered += 1; diagnostic('connect', 200, true, 'PROXY_RECOVERED'); break; }
              // Authentication, policy and throttling refusals are final. Only
              // another qualified 502 can advance to the second public address.
              if (result.response.statusCode !== 502 || 'retry-after' in result.response.headers) break;
              const body = await errorBody(result.socket, result.response, result.head, state.controller.signal, 8192);
              result.body = body.body;
              if (!body.complete || responsePolicyError(result.response) || policyError(body.body.toString('utf8'))) break;
              result.dispose();
            }
          } catch { recoveryError = 'PROXY_DESTINATION_DNS_FAILED'; }
        }
      }
      if (closing || state.controller.signal.aborted || socket.destroyed) return result.dispose();
      if (result.response.statusCode !== 200) {
        failedConnect(recoveryError ? 'resolve' : 'connect', result.response.statusCode ?? 502, recoveryError ?? statusError(result.response.statusCode));
        refuse(result.response.statusCode ?? 502, result.response.headers, result.body);
        return result.dispose();
      }
      established = true;
      // A tunnel has an idle limit, not a handshake deadline. Its socket close
      // still aborts all owned resources, including the resolver waiters.
      state.controller.signal.removeEventListener('abort', abort);
      state.establish();
      socket.pause(); socket.off('data', retain);
      if (!acknowledged) { acknowledged = true; socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); }
      for (const chunk of early) if (chunk.length) result.socket.write(chunk);
      early.length = 0;
      if (result.head.length) socket.write(result.head);
      result.socket.once('close', () => socket.destroy()); socket.once('close', () => result.socket.destroy());
      socket.pipe(result.socket); result.socket.pipe(socket);
      socket.resume(); result.socket.resume();
    } catch (error) {
      if (established) socket.destroy();
      else { if (!state.controller.signal.aborted) failedConnect('connect', null, error.code); refuse(502); }
    }
    finally { socket.off('data', retain); if (!established) state.finish(); }
  }
  const server = http.createServer({ maxHeaderSize: maxHeaderBytes, insecureHTTPParser: false,
    requestTimeout: requestTimeoutMs, headersTimeout: Math.min(connectTimeoutMs, requestTimeoutMs), keepAliveTimeout: 1000 },
  (request, response) => { void forwardHttp(request, response); });
  server.maxHeadersCount = 0;
  server.on('connection', socket => {
    track(socket);
    if (closing || incoming.size >= maxConnections) return socketResponse(socket, 503);
    incoming.add(socket); socket.once('close', () => incoming.delete(socket));
    socket.setTimeout(idleTimeoutMs, () => socket.destroy());
  });
  server.on('connect', (request, socket, head) => { void forwardConnect(request, socket, head); });
  server.on('checkContinue', (request, response) => { void forwardHttp(request, response, true); });
  server.on('upgrade', (_request, socket) => socketResponse(socket, 501));
  server.on('clientError', (error, socket) => socketResponse(socket, error.code === 'HPE_HEADER_OVERFLOW' ? 431 : 400));
  const close = () => {
    if (!closePromise) {
      closing = true;
      try { resolver.close(); } catch { /* Socket teardown must still complete. */ }
      for (const state of operations) state.finish();
      closePromise = new Promise(resolve => {
        server.close(resolve);
        for (const socket of sockets) socket.destroy();
      });
    }
    return closePromise;
  };
  server.on('error', () => { if (!closing) { try { options.onError?.({ code: 'PROXY_COMPATIBILITY_BRIDGE_FAILED' }); } catch {} void close(); } });
  server.on('close', () => { if (!closing) { try { options.onClose?.({ code: 'PROXY_COMPATIBILITY_BRIDGE_CLOSED' }); } catch {} void close(); } });
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); }); });
  } catch { await close(); throw failure(); }
  return Object.freeze({ host: '127.0.0.1', port: server.address().port, ...local, protocol: 'http', close,
    snapshot: () => Object.freeze({ status: closing ? 'closed' : 'running', activeConnections: incoming.size, pendingConnections: operations.size,
      ownedSockets: sockets.size, recoveredConnections: recovered, failedConnections: failed, lastErrorCode, lastUpstreamStatus }) });
}
