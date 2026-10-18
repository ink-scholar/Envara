import https from 'node:https';
import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { bootstrapDNSQuestion } from './proxy-bootstrap-dns.mjs';
import { createProxyAgent, isPublicIP } from './proxy-network.mjs';

// Main-process constants. Destination names are resolved inside the selected
// proxy tunnel; the bootstrap resolver's direct transport must not be reused.
export const PROXY_DESTINATION_DOH_ENDPOINTS = Object.freeze([
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/dns-query',
]);
const MAX_DNS_BYTES = 16384;
const MAX_HEADER_BYTES = 8192;
const failure = suffix => Object.assign(new Error(`PROXY_DESTINATION_DNS_${suffix}`), { code: `PROXY_DESTINATION_DNS_${suffix}` });
const invalid = () => failure('INVALID_RESPONSE');
export const isPublicDestinationIPv4 = value => typeof value === 'string' && net.isIP(value) === 4 && isPublicIP(value);

export function destinationDNSQuestion(host) {
  try { return bootstrapDNSQuestion(host); }
  catch { throw failure('INVALID_HOST'); }
}

function readName(bytes, start) {
  let cursor = start, end, length = 0, jumps = 0;
  const labels = [], visited = new Set();
  while (cursor < bytes.length) {
    if (visited.has(cursor)) throw invalid();
    visited.add(cursor);
    const at = cursor, size = bytes[cursor++];
    if (size === 0) return { name: labels.join('.').toLowerCase(), end: end ?? cursor };
    if ((size & 0xc0) === 0xc0) {
      if (cursor >= bytes.length || ++jumps > 32) throw invalid();
      const destination = ((size & 0x3f) << 8) | bytes[cursor++];
      if (destination < 12 || destination >= at) throw invalid();
      end ??= cursor; cursor = destination;
    } else {
      if (size > 63 || cursor + size > bytes.length || (length += size + 1) > 254) throw invalid();
      const raw = bytes.subarray(cursor, cursor + size);
      if (raw.some(value => value > 0x7f)) throw invalid();
      const label = raw.toString('ascii');
      if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)) throw invalid();
      labels.push(label); cursor += size;
    }
  }
  throw invalid();
}

/** Bind a complete A response to its exact question and a single CNAME chain. */
export function parseDestinationDNSAnswer(bytes, question) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 12 || bytes.length > MAX_DNS_BYTES ||
      !Buffer.isBuffer(question?.bytes) || question.bytes.length < 17 || bytes.readUInt16BE(0) !== question.bytes.readUInt16BE(0)) throw invalid();
  const flags = bytes.readUInt16BE(2), qd = bytes.readUInt16BE(4), an = bytes.readUInt16BE(6), ns = bytes.readUInt16BE(8), ar = bytes.readUInt16BE(10);
  if (!(flags & 0x8000) || flags & 0x7800 || flags & 0x0200 || flags & 0x0040 || qd !== 1 || an < 1 || an + ns + ar > 128) throw invalid();
  const q = readName(bytes, 12);
  if (q.name !== question.name || q.end + 4 > bytes.length || bytes.readUInt16BE(q.end) !== 1 || bytes.readUInt16BE(q.end + 2) !== 1) throw invalid();
  let offset = q.end + 4, extendedRcode = 0, optSeen = false;
  const records = new Map();
  for (let index = 0; index < an + ns + ar; index++) {
    const ownerStart = offset, owner = readName(bytes, offset); offset = owner.end;
    if (offset + 10 > bytes.length) throw invalid();
    const type = bytes.readUInt16BE(offset), klass = bytes.readUInt16BE(offset + 2), rawTtl = bytes.readUInt32BE(offset + 4), size = bytes.readUInt16BE(offset + 8);
    const ttl = rawTtl > 0x7fffffff ? 0 : rawTtl; offset += 10;
    if (offset + size > bytes.length) throw invalid();
    let address, alias;
    if (type === 41) {
      if (index < an + ns || optSeen || owner.name || bytes[ownerStart] !== 0 || owner.end !== ownerStart + 1 || ((rawTtl >>> 16) & 255) !== 0) throw invalid();
      optSeen = true; extendedRcode = rawTtl >>> 24;
      let option = offset;
      while (option < offset + size) {
        if (option + 4 > offset + size) throw invalid();
        const length = bytes.readUInt16BE(option + 2); option += 4;
        if (option + length > offset + size) throw invalid();
        option += length;
      }
    } else if (klass === 1 && type === 1) {
      if (size !== 4) throw invalid();
      address = [...bytes.subarray(offset, offset + 4)].join('.');
    } else if (klass === 1 && type === 5) {
      const target = readName(bytes, offset);
      if (!target.name || target.end !== offset + size) throw invalid();
      alias = target.name;
    }
    if (index < an && (address || alias)) {
      const group = records.get(owner.name) ?? [];
      group.push({ address, alias, ttl }); records.set(owner.name, group);
    }
    offset += size;
  }
  if (offset !== bytes.length || extendedRcode || flags & 15) throw invalid();
  const visited = new Set(); let name = question.name, ttl = Infinity;
  for (let hop = 0; hop < 16; hop++) {
    if (visited.has(name)) throw invalid();
    visited.add(name);
    const group = records.get(name) ?? [], aliases = group.filter(record => record.alias), addresses = group.filter(record => record.address);
    if (aliases.length) {
      if (addresses.length || new Set(aliases.map(record => record.alias)).size !== 1) throw invalid();
      ttl = Math.min(ttl, ...aliases.map(record => record.ttl)); name = aliases[0].alias;
    } else {
      if (!addresses.length || addresses.some(record => !isPublicDestinationIPv4(record.address))) throw invalid();
      ttl = Math.min(ttl, ...addresses.map(record => record.ttl));
      return { addresses: [...new Set(addresses.map(record => record.address))].slice(0, 2), ttlMs: ttl * 1000 };
    }
  }
  throw invalid();
}

/** Fixed HTTPS DNS-wire POST, mandatory proxy agent, verified TLS, no redirects. */
export function requestProxyDestinationDNS({ url, question, agent, timeoutMs, signal, maxBodyBytes = MAX_DNS_BYTES, ca }) {
  return new Promise((resolve, reject) => {
    let request, response, settled = false, size = 0;
    const chunks = [];
    const finish = (error, bytes) => {
      if (settled) return;
      settled = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
      if (error) { response?.destroy(); request?.destroy(); reject(failure('UNAVAILABLE')); } else resolve(bytes);
    };
    const abort = () => finish(failure('UNAVAILABLE'));
    const timer = setTimeout(abort, timeoutMs);
    try {
      if (!PROXY_DESTINATION_DOH_ENDPOINTS.includes(url) || !agent || typeof agent.addRequest !== 'function' ||
          !Buffer.isBuffer(question) || question.length < 17 || question.length > 512 ||
          !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000 ||
          !Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 12 || maxBodyBytes > MAX_DNS_BYTES || signal?.aborted) return abort();
      signal?.addEventListener('abort', abort, { once: true });
      request = https.request(url, { agent, method: 'POST', signal, maxHeaderSize: MAX_HEADER_BYTES, rejectUnauthorized: true, ...(ca ? { ca } : {}),
        headers: { Accept: 'application/dns-message', 'Content-Type': 'application/dns-message', 'Content-Length': question.length } }, incoming => {
        response = incoming;
        const length = incoming.headers['content-length'], rawAge = incoming.headers.age;
        const ageCount = incoming.rawHeaders.filter((_value, index) => index % 2 === 0 && incoming.rawHeaders[index].toLowerCase() === 'age').length;
        const ageSeconds = rawAge == null ? 0 : Number(rawAge);
        if (incoming.statusCode !== 200 || !/^application\/dns-message(?:\s*;|$)/i.test(incoming.headers['content-type'] ?? '') ||
            length != null && (!/^\d+$/.test(length) || Number(length) > maxBodyBytes) || ageCount > 1 ||
            rawAge != null && (!/^\d+$/.test(rawAge) || !Number.isSafeInteger(ageSeconds) || ageSeconds > 2147483648)) return abort();
        incoming.on('data', chunk => { size += chunk.length; if (size > maxBodyBytes) abort(); else chunks.push(chunk); });
        incoming.once('error', abort); incoming.once('aborted', abort);
        incoming.once('end', () => finish(null, { bytes: Buffer.concat(chunks), ageSeconds }));
      });
      request.once('error', abort); request.end(question);
    } catch { abort(); }
  });
}

function boundedInteger(value, minimum, maximum) { return Number.isSafeInteger(value) && value >= minimum && value <= maximum; }

// HttpsProxyAgent supplies shared route/auth validation, but its CONNECT parser
// buffers arbitrary headers. Use Node's bounded HTTP parser for this new path.
function boundedProxyAgent(proxy, timeoutMs, options, signal) {
  const agent = createProxyAgent(proxy, timeoutMs, options, signal), sockets = new Set();
  const own = socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); return socket; };
  const destroy = agent.destroy.bind(agent);
  agent.destroy = () => { for (const socket of sockets) socket.destroy(); destroy(); };
  agent.connect = (_request, target) => new Promise((resolve, reject) => {
    let request, socket, settled = false;
    const finish = (error, connected) => {
      if (settled) return;
      settled = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
      if (error) { socket?.destroy(); request?.destroy(); reject(failure('UNAVAILABLE')); } else resolve(connected);
    };
    const abort = () => finish(failure('UNAVAILABLE'));
    const timer = setTimeout(abort, timeoutMs);
    try {
      if (!target.secureEndpoint || !PROXY_DESTINATION_DOH_ENDPOINTS.some(url => new URL(url).hostname === target.host) ||
          Number(target.port) !== 443 || signal?.aborted) return abort();
      const authority = `${target.host}:443`;
      const headers = typeof agent.proxyHeaders === 'function' ? agent.proxyHeaders() : agent.proxyHeaders;
      signal?.addEventListener('abort', abort, { once: true });
      request = (proxy.protocol === 'https' ? https : http).request({
        ...agent.connectOpts, agent: false, method: 'CONNECT', path: authority, maxHeaderSize: MAX_HEADER_BYTES,
        rejectUnauthorized: true, signal, headers: { ...headers, Host: authority, 'Proxy-Connection': 'close' },
      });
      request.once('socket', connected => { socket = own(connected); });
      request.once('error', abort);
      request.once('response', response => { response.destroy(); abort(); });
      request.once('connect', (response, connected, head) => {
        socket = connected;
        if (settled || response.statusCode !== 200 || head.length || signal?.aborted) { connected.destroy(); abort(); return; }
        const secured = own(tls.connect({ socket: connected, servername: target.host, rejectUnauthorized: true,
          ALPNProtocols: ['http/1.1'], ...(options.ca ? { ca: options.ca } : {}), signal }));
        finish(null, secured);
      });
      request.end();
    } catch { abort(); }
  });
  return agent;
}

/** One immutable upstream route per instance. Options are trusted main-process
 * dependencies, never renderer/IPC fields. `transport`, `nowMs` and a test CA
 * permit isolated fixtures without weakening production TLS verification. */
export function createProxyDestinationResolver(input, {
  timeoutMs = 4000, maxTtlMs = 300000, negativeTtlMs = 2000, maxEntries = 256, maxInflight = 16,
  transport = requestProxyDestinationDNS, nowMs = Date.now, upstreamAddress, localAddress, ca,
} = {}) {
  if (!input || !['http', 'https'].includes(input.protocol ?? input.type) || !boundedInteger(timeoutMs, 1, 10000) ||
      !boundedInteger(maxTtlMs, 0, 300000) || !boundedInteger(negativeTtlMs, 0, 30000) || !boundedInteger(maxEntries, 1, 4096) ||
      !boundedInteger(maxInflight, 1, 128) || typeof transport !== 'function' || typeof nowMs !== 'function') throw failure('INVALID_OPTIONS');
  const proxy = { protocol: input.protocol ?? input.type, host: input.host, port: input.port, username: input.username, password: input.password };
  const proxyHost = typeof proxy.host === 'string' ? proxy.host.replace(/^\[|\]$/g, '') : '';
  if (upstreamAddress != null && !(isPublicDestinationIPv4(upstreamAddress) || net.isIP(proxyHost) && upstreamAddress === proxyHost) ||
      localAddress != null && net.isIP(localAddress) !== 4) throw failure('INVALID_OPTIONS');
  const agentOptions = { rejectUnauthorized: true, ...(ca ? { ca } : {}), ...(localAddress ? { localAddress, family: 4 } : {}) };
  if (upstreamAddress) agentOptions.lookup = (hostname, options, callback) => {
    if (typeof options === 'function') { callback = options; options = {}; }
    if (hostname.toLowerCase() !== proxyHost.toLowerCase()) return callback(failure('UNAVAILABLE'));
    const family = net.isIP(upstreamAddress);
    callback(null, options?.all ? [{ address: upstreamAddress, family }] : upstreamAddress, family);
  };
  if (proxy.protocol === 'https' && !net.isIP(proxyHost)) agentOptions.servername = proxyHost;
  // Validate the entire saved route and HTTP authentication before any lookup.
  try { createProxyAgent(proxy, timeoutMs, agentOptions).destroy(); }
  catch { throw failure('INVALID_OPTIONS'); }
  const cache = new Map(), inflight = new Map(); let closed = false;
  const remember = (name, entry) => {
    cache.delete(name);
    while (cache.size >= maxEntries) cache.delete(cache.keys().next().value);
    cache.set(name, entry);
  };
  const lookup = (name, outerSignal) => new Promise((resolve, reject) => {
    const controller = new AbortController(), agents = new Set(), question = destinationDNSQuestion(name);
    let settled = false, pending = PROXY_DESTINATION_DOH_ENDPOINTS.length;
    const finish = (error, answer) => {
      if (settled) return;
      settled = true; clearTimeout(timer); outerSignal.removeEventListener('abort', abort);
      controller.abort(); for (const agent of agents) agent.destroy();
      error ? reject(error) : resolve(answer);
    };
    const abort = () => finish(failure(closed ? 'CLOSED' : 'ABORTED'));
    const timer = setTimeout(() => finish(failure('TIMEOUT')), timeoutMs);
    outerSignal.addEventListener('abort', abort, { once: true });
    if (outerSignal.aborted) return abort();
    for (const url of PROXY_DESTINATION_DOH_ENDPOINTS) {
      Promise.resolve().then(() => {
        if (settled) throw failure('ABORTED');
        const agent = boundedProxyAgent(proxy, timeoutMs, agentOptions, controller.signal); agents.add(agent);
        return transport({ url, question: Buffer.from(question.bytes), agent, timeoutMs, maxBodyBytes: MAX_DNS_BYTES, signal: controller.signal, ca });
      }).then(packet => {
        if (settled) return;
        // Raw bytes are supported only for the trusted in-process test transport.
        const bytes = Buffer.isBuffer(packet) ? packet : packet?.bytes;
        const ageSeconds = Buffer.isBuffer(packet) ? 0 : packet?.ageSeconds;
        if (!boundedInteger(ageSeconds, 0, 2147483648)) throw invalid();
        const result = parseDestinationDNSAnswer(bytes, question);
        finish(null, { addresses: result.addresses, ttlMs: Math.min(maxTtlMs, Math.max(0, result.ttlMs - ageSeconds * 1000)) });
      }).catch(() => {}).finally(() => {
        if (!settled && --pending === 0) finish(failure('UNAVAILABLE'));
      });
    }
  });
  async function resolve(host, { signal, timeoutMs: callerTimeout = timeoutMs } = {}) {
    if (closed) throw failure('CLOSED');
    if (!boundedInteger(callerTimeout, 1, 10000) || signal && (typeof signal.addEventListener !== 'function' || typeof signal.removeEventListener !== 'function')) throw failure('INVALID_OPTIONS');
    if (signal?.aborted) throw failure('ABORTED');
    const name = destinationDNSQuestion(host).name, now = nowMs(), cached = cache.get(name);
    if (cached && cached.expiresAt > now) {
      cache.delete(name); cache.set(name, cached);
      if (!cached.result) throw failure('UNAVAILABLE');
      return { addresses: [...cached.result.addresses], ttlMs: cached.expiresAt - now };
    }
    cache.delete(name);
    let operation = inflight.get(name);
    if (!operation) {
      if (inflight.size >= maxInflight) throw failure('UNAVAILABLE');
      operation = { controller: new AbortController(), waiters: new Set(), settled: false };
      inflight.set(name, operation);
      operation.promise = Promise.resolve().then(() => lookup(name, operation.controller.signal)).then(result => {
        if (!closed && !operation.controller.signal.aborted && result.ttlMs > 0) remember(name, { result, expiresAt: nowMs() + result.ttlMs });
        return result;
      }, error => {
        if (!closed && !operation.controller.signal.aborted && negativeTtlMs > 0) remember(name, { expiresAt: nowMs() + negativeTtlMs });
        throw error;
      }).finally(() => {
        operation.settled = true;
        if (inflight.get(name) === operation) inflight.delete(name);
      });
    }
    return new Promise((resolveWaiter, rejectWaiter) => {
      const waiter = {}; operation.waiters.add(waiter); let settled = false;
      const finish = (error, result) => {
        if (settled) return;
        settled = true; clearTimeout(timer); signal?.removeEventListener('abort', abort); operation.waiters.delete(waiter);
        if (!operation.settled && !operation.waiters.size) {
          operation.controller.abort();
          if (inflight.get(name) === operation) inflight.delete(name);
        }
        error ? rejectWaiter(error) : resolveWaiter({ addresses: [...result.addresses], ttlMs: result.ttlMs });
      };
      const abort = () => finish(failure('ABORTED'));
      const timer = setTimeout(() => finish(failure('TIMEOUT')), callerTimeout);
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) abort();
      operation.promise.then(result => finish(null, result), error => finish(error));
    });
  }
  return { resolve, close() { closed = true; cache.clear(); for (const operation of inflight.values()) operation.controller.abort(); inflight.clear(); } };
}
