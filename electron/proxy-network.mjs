import { createHash } from 'node:crypto';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';
import ipaddr from 'ipaddr.js';
import { assertHttpProxyUsername } from '../shared/proxy-auth.mjs';
import { NETWORK_DIAGNOSTIC_STAGES, networkDiagnosticElapsed, networkDiagnosticSource, sanitizeNetworkDiagnostics } from '../shared/proxy-network-diagnostics.mjs';

// This allowlist belongs to the main process. IPC never accepts a lookup URL.
export const GEO_ENDPOINTS = Object.freeze([
  Object.freeze({ url: 'https://ipwho.is/', source: 'ipwho.is', format: 'ipwho' }),
  Object.freeze({ url: 'https://ipapi.co/json/', source: 'ipapi.co', format: 'ipapi' }),
]);
const failure = (code) => Object.assign(new Error(code), { code });

function proxyValues(input) {
  if (input == null) return null;
  const protocol = input.protocol ?? input.type;
  let host = input.host;
  if (typeof host === 'string' && host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  const port = Number(input.port);
  if (!['http', 'https', 'socks5'].includes(protocol) || typeof host !== 'string' || !host ||
      host.length > 253 || /[\s\x00-\x1f\x7f/@?#\\]/.test(host) || (host.includes(':') && net.isIP(host) !== 6) ||
      !Number.isInteger(port) || port < 1 || port > 65535) throw failure('INVALID_PROXY');
  for (const key of ['username', 'password']) if (input[key] != null && (typeof input[key] !== 'string' || input[key].length > 2048 || /[\x00\r\n]/.test(input[key]))) throw failure('INVALID_PROXY');
  const region = input.region ?? '';
  if (typeof region !== 'string' || region.length > 64 || /[\x00\r\n]/.test(region)) throw failure('INVALID_PROXY');
  return { protocol, host: host.toLowerCase(), port, username: input.username ?? '', password: input.password ?? '', region };
}

/** The digest is internal only; usernames/passwords never appear in cache values. */
export function proxyFingerprint(input) {
  return createHash('sha256').update(JSON.stringify(proxyValues(input))).digest('hex');
}

export function isPublicIP(value) {
  if (typeof value !== 'string' || value.includes('%') || !net.isIP(value)) return false;
  const address = ipaddr.parse(value);
  if (address.range() !== 'unicast') return false;
  // Be conservative for public egress claims: exclude IPv4 special-purpose blocks
  // even when a library classifies part of a block as globally reachable.
  if (address.kind() === 'ipv4') return !['192.0.0.0/24', '192.88.99.0/24'].some((cidr) => address.match(ipaddr.parseCIDR(cidr)));
  return address.match(ipaddr.parseCIDR('2000::/3'));
}

function timezone(value) {
  if (typeof value !== 'string' || value.length > 128 || !value || /[\x00-\x1f\x7f]/.test(value)) throw failure('INVALID_GEO_RESPONSE');
  try { return new Intl.DateTimeFormat('en', { timeZone: value }).resolvedOptions().timeZone; }
  catch { throw failure('INVALID_GEO_RESPONSE'); }
}
function label(value, secrets, max = 100) {
  if (value == null) return null;
  if (typeof value !== 'string') throw failure('INVALID_GEO_RESPONSE');
  let result = value.replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, max);
  for (const secret of secrets) if (secret) result = result.split(secret).join('[redacted]');
  return result || null;
}

export function parseGeoResponse(data, endpoint, proxy) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw failure('INVALID_GEO_RESPONSE');
  if (data.success === false || data.error) throw failure('GEO_PROVIDER_REJECTED');
  const ip = data.ip;
  const rawCountryCode = endpoint.format === 'ipapi' ? data.country_code ?? data.country : data.country_code;
  const countryCode = typeof rawCountryCode === 'string' ? rawCountryCode.toUpperCase() : null;
  const rawTimezone = endpoint.format === 'ipapi' ? data.timezone : data.timezone?.id;
  if (!isPublicIP(ip) || typeof countryCode !== 'string' || !/^[A-Z]{2}$/.test(countryCode)) throw failure('INVALID_GEO_RESPONSE');
  const secrets = [proxy?.username, proxy?.password];
  const latitude = data.latitude;
  const longitude = data.longitude;
  // These coordinates describe an IP estimate, never a GPS fix or street address.
  const geolocation = Number.isFinite(latitude) && latitude >= -90 && latitude <= 90 &&
    Number.isFinite(longitude) && longitude >= -180 && longitude <= 180
    ? { latitude, longitude, accuracy: 50000 } : null;
  return { ip, countryCode, country: label(endpoint.format === 'ipapi' ? data.country_name : data.country, secrets),
    region: label(data.region, secrets), city: label(data.city, secrets), timezone: timezone(rawTimezone),
    ...(geolocation ? { geolocation, locationSource: 'ip-estimate' } : {}) };
}

export function createProxyAgent(input, timeoutMs, tlsOptions = {}, signal) {
  const proxy = proxyValues(input);
  if (!proxy) return false; // Explicit direct mode, never environment-derived routing.
  assertHttpProxyUsername(proxy.protocol, proxy.username);
  const host = net.isIP(proxy.host) === 6 ? `[${proxy.host}]` : proxy.host;
  const url = new URL(`${proxy.protocol === 'socks5' ? 'socks5h' : proxy.protocol}://${host}:${proxy.port}`);
  if (proxy.protocol === 'socks5') {
    url.username = proxy.username; url.password = proxy.password;
    const agent = new SocksProxyAgent(url, { timeout: timeoutMs, socketOptions: { signal } });
    agent.proxy.host = proxy.host; // Node sockets expect an IPv6 literal without URL brackets.
    // socks-proxy-agent keeps auth properties non-enumerable for its diagnostics;
    // also remove credentials from its informational proxy event URL.
    url.username = ''; url.password = ''; agent.proxyUrl = url.href;
    return agent;
  }
  // Keep the URI credential-free: the library can log it under DEBUG. Authentication
  // remains in a private header callback, omitted from diagnostic connect options.
  const headers = proxy.username || proxy.password ? () => ({ 'Proxy-Authorization': `Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString('base64')}` }) : undefined;
  return new HttpsProxyAgent(url, { timeout: timeoutMs, ...tlsOptions, signal, headers });
}

/** No redirects, absolute deadline (including proxy handshake), and bounded JSON. */
export function requestGeoJSON({ url, agent, timeoutMs, maxBodyBytes, tlsOptions = {}, controller = new AbortController(), headers = {}, onDiagnostic }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let request;
    let secure = false, responseRead = false;
    const observe = (stage, status) => { if (!settled) { try { onDiagnostic?.({ stage, status }); } catch {} } };
    const observeSecure = socket => {
      // This is the origin TLS socket, not the HTTP/SOCKS proxy's listener or
      // CONNECT acknowledgement. No separate DNS/upstream TLS success is inferred.
      if (!secure && socket?.encrypted === true && socket.authorized === true) {
        secure = true; observe('https', 'passed');
      }
    };
    const finish = (value, result) => {
      if (settled) return;
      if (value) {
        if (!secure) observe('https', 'failed');
        else if (!responseRead) observe('response', 'failed');
      }
      settled = true;
      clearTimeout(timer);
      if (value) { controller.abort(value); request?.destroy(); reject(value); } else resolve(result);
    };
    const timer = setTimeout(() => finish(failure('NETWORK_TIMEOUT')), timeoutMs);
    try {
      request = https.request(url, { method: 'GET', agent, ...tlsOptions, signal: controller.signal,
        headers: { Accept: 'application/json', 'User-Agent': 'Envara/0.2 (egress verification)', ...headers } }, (response) => {
        observeSecure(response.socket);
        if (response.statusCode !== 200) { observe('response', 'failed'); response.destroy(); finish(failure(response.statusCode === 407 ? 'PROXY_AUTH_FAILED' : 'GEO_HTTP_ERROR')); return; }
        if (Number(response.headers['content-length']) > maxBodyBytes) { response.destroy(); finish(failure('GEO_BODY_TOO_LARGE')); return; }
        const chunks = []; let length = 0;
        response.on('data', (chunk) => { length += chunk.length; if (length > maxBodyBytes) { response.destroy(); finish(failure('GEO_BODY_TOO_LARGE')); } else chunks.push(chunk); });
        response.once('error', () => finish(failure('NETWORK_FAILED')));
        response.once('aborted', () => finish(failure('NETWORK_FAILED')));
        response.once('end', () => {
          if (settled) return;
          responseRead = true; observe('response', 'passed');
          try { finish(null, JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
          catch { observe('validation', 'failed'); finish(failure('INVALID_GEO_RESPONSE')); }
        });
      });
      request.once('socket', socket => { observeSecure(socket); socket.once('secureConnect', () => observeSecure(socket)); });
      request.once('error', (value) => finish(failure(value.code === 'ETIMEDOUT' ? 'NETWORK_TIMEOUT' : /authentication|auth.*failed|Socks5.*authentication/i.test(value.message) ? 'PROXY_AUTH_FAILED' : 'NETWORK_FAILED')));
      request.end();
    } catch { finish(failure('NETWORK_FAILED')); }
  });
}

const messages = {
  NETWORK_TIMEOUT: '出口验证超时；未切换为直接连接。',
  PROXY_AUTH_FAILED: '代理认证失败，请检查凭据。',
  GEO_BODY_TOO_LARGE: '地理服务响应超出大小限制。',
  INVALID_GEO_RESPONSE: '地理服务未返回有效的公网出口 IP 和 IANA 时区。',
  GEO_PROVIDER_REJECTED: '地理服务暂时无法提供出口信息。',
  GEO_HTTP_ERROR: '代理或地理服务返回了非成功响应。',
  NETWORK_FAILED: '无法经指定网络出口完成 HTTPS 验证，请检查代理、认证及网络。',
};

/** Ask an HTTP(S) proxy for one CONNECT to `target` and read only its status
 * line: true when it answers 407. Nothing is sent through an accepted tunnel,
 * which is closed at once. Used after a managed route fails, because the
 * local proxy core accepts CONNECT before dialing upstream and so hides 407. */
export function httpProxyRejectsAuthentication(input, { target, timeoutMs = 5000, tlsOptions = {} } = {}) {
  let proxy;
  try { proxy = proxyValues(input); } catch { return Promise.resolve(false); }
  if (!proxy || !['http', 'https'].includes(proxy.protocol) || typeof target !== 'string' || !/^[A-Za-z0-9.-]+:\d{1,5}$/.test(target)) return Promise.resolve(false);
  return new Promise(resolve => {
    let settled = false, buffered = '';
    const done = value => { if (settled) return; settled = true; clearTimeout(timer); socket.destroy(); resolve(value); };
    const timer = setTimeout(() => done(false), timeoutMs);
    const options = { host: proxy.host, port: proxy.port };
    const socket = proxy.protocol === 'https' ? tls.connect({ ...options, servername: net.isIP(proxy.host) ? undefined : proxy.host, ...tlsOptions }) : net.connect(options);
    socket.once(proxy.protocol === 'https' ? 'secureConnect' : 'connect', () => {
      const auth = proxy.username || proxy.password ? `Proxy-Authorization: Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString('base64')}\r\n` : '';
      socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${auth}\r\n`);
    });
    socket.on('data', chunk => {
      buffered += chunk.toString('latin1');
      if (buffered.length > 1024) return done(false);
      const line = buffered.indexOf('\r\n');
      if (line >= 0) done(/^HTTP\/1\.[01] 407(?:\s|$)/.test(buffered.slice(0, line)));
    });
    socket.once('error', () => done(false));
    socket.once('close', () => done(false));
  });
}

/** Injectable transport/endpoints/TLS are trusted native test seams, never IPC options. */
export class ProxyNetworkProbe {
  constructor({ endpoints = GEO_ENDPOINTS, transport = requestGeoJSON, timeoutMs = 10000, maxBodyBytes = 32768,
    cacheTtlMs = 60000, nowMs = Date.now, tlsOptions = {} } = {}) {
    if (!Array.isArray(endpoints) || !endpoints.length || endpoints.length > 3 || !Number.isFinite(timeoutMs) || timeoutMs <= 0 ||
        !Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 64 || maxBodyBytes > 1024 * 1024 || !Number.isFinite(cacheTtlMs) || cacheTtlMs < 0) throw failure('INVALID_PROBE_OPTIONS');
    this.endpoints = endpoints.map((endpoint) => { const url = new URL(endpoint.url); if (url.protocol !== 'https:' || url.username || url.password || url.hash || !['ipwho', 'ipapi'].includes(endpoint.format)) throw failure('INVALID_PROBE_OPTIONS'); return { url: url.href, source: endpoint.source, format: endpoint.format }; });
    this.transport = transport; this.timeoutMs = timeoutMs; this.maxBodyBytes = maxBodyBytes;
    this.cacheTtlMs = cacheTtlMs; this.nowMs = nowMs; this.tlsOptions = tlsOptions;
    this.cache = new Map(); this.inflight = new Map(); this.controllers = new Set(); this.closed = false; this.networkRevision = 0;
  }
  /** Reclassify a failed managed-route check when the upstream proxy itself refuses the credentials. */
  async explainFailure(result, upstream) {
    if (result?.ok !== false || result.errorCode !== 'NETWORK_FAILED' || this.closed) return result;
    const target = `${new URL(this.endpoints[0].url).hostname}:443`;
    if (!await httpProxyRejectsAuthentication(upstream, { target, timeoutMs: Math.min(this.timeoutMs, 5000), tlsOptions: this.tlsOptions })) return result;
    return { ...result, errorCode: 'PROXY_AUTH_FAILED', message: messages.PROXY_AUTH_FAILED };
  }
  peek(proxy) { const entry = this.cache.get(proxyFingerprint(proxy)); return entry ? { ...structuredClone(entry.result), stale: this.nowMs() - entry.timestamp >= this.cacheTtlMs } : null; }
  invalidate(proxy) { const key = proxyFingerprint(proxy); this.cache.delete(key); this.inflight.delete(key); }
  invalidateNetwork() {
    this.networkRevision++;
    this.cache.clear(); this.inflight.clear();
    for (const controller of this.controllers) controller.abort();
  }
  close() { this.closed = true; for (const controller of this.controllers) controller.abort(); }
  async probe(input, { force = false } = {}) {
    if (this.closed) throw failure('APP_CLOSING');
    const proxy = proxyValues(input);
    assertHttpProxyUsername(proxy?.protocol, proxy?.username);
    const key = proxyFingerprint(proxy);
    const pending = this.inflight.get(key);
    if (pending) return structuredClone(await pending);
    const entry = this.cache.get(key);
    if (!force && entry?.result.ok && this.nowMs() - entry.timestamp < this.cacheTtlMs) return structuredClone(entry.result);
    const operation = this.lookup(proxy).then((result) => {
      if (this.inflight.get(key) === operation) {
        if (this.cache.size >= 512 && !this.cache.has(key)) this.cache.delete(this.cache.keys().next().value);
        this.cache.set(key, { timestamp: this.nowMs(), result });
      }
      return result;
    });
    this.inflight.set(key, operation);
    try { return structuredClone(await operation); }
    finally { if (this.inflight.get(key) === operation) this.inflight.delete(key); }
  }
  async lookup(proxy) {
    const revision = this.networkRevision;
    const started = this.nowMs(); let code = 'NETWORK_FAILED', source = null;
    const attempts = [];
    const diagnostics = () => sanitizeNetworkDiagnostics({ version: 1, attempts });
    for (const endpoint of this.endpoints) {
      if (this.closed || revision !== this.networkRevision) break;
      source = endpoint.source;
      const attemptStarted = this.nowMs();
      const attempt = { source: networkDiagnosticSource(endpoint.source), elapsedMs: 0, outcome: 'failure', errorCode: 'NETWORK_FAILED',
        stages: NETWORK_DIAGNOSTIC_STAGES.map(stage => ({ stage, status: 'unobserved' })) };
      attempts.push(attempt);
      let observing = true, configurationReady = false, validating = false;
      const observe = (stage, status) => { if (observing) attempt.stages.find(item => item.stage === stage).status = status; };
      const onDiagnostic = event => {
        if (event && ['https', 'response', 'validation'].includes(event.stage) && ['passed', 'failed'].includes(event.status) &&
            (event.stage !== 'validation' || event.status === 'failed')) observe(event.stage, event.status);
      };
      const finishAttempt = (outcome, errorCode) => {
        observing = false; attempt.elapsedMs = networkDiagnosticElapsed(this.nowMs() - attemptStarted);
        attempt.outcome = outcome;
        if (errorCode) attempt.errorCode = errorCode; else delete attempt.errorCode;
      };
      let agent; const controller = new AbortController(); this.controllers.add(controller);
      try {
        agent = createProxyAgent(proxy, this.timeoutMs, this.tlsOptions, controller.signal);
        configurationReady = true; observe('configuration', 'passed');
        const data = await this.transport({ url: endpoint.url, agent, timeoutMs: this.timeoutMs, maxBodyBytes: this.maxBodyBytes, tlsOptions: this.tlsOptions, controller, onDiagnostic });
        if (this.closed || revision !== this.networkRevision) { finishAttempt('cancelled', this.closed ? 'APP_CLOSING' : 'NETWORK_CHANGED'); break; }
        validating = true;
        const geo = parseGeoResponse(data, endpoint, proxy);
        observe('validation', 'passed'); finishAttempt('success');
        return { ok: true, scope: 'egress', ...geo, source, checkedAt: new Date(this.nowMs()).toISOString(), latencyMs: Math.max(0, Math.round(this.nowMs() - started)), message: '已通过 HTTPS 验证实际网络出口；位置为 IP 地理估算。', diagnostics: diagnostics() };
      } catch (value) {
        code = Object.hasOwn(messages, value?.code) ? value.code : 'NETWORK_FAILED';
        if (!configurationReady) observe('configuration', 'failed');
        else if (validating) observe('validation', 'failed');
        finishAttempt(this.closed || revision !== this.networkRevision ? 'cancelled' : 'failure', this.closed ? 'APP_CLOSING' : revision !== this.networkRevision ? 'NETWORK_CHANGED' : code);
      }
      finally { this.controllers.delete(controller); agent?.destroy?.(); }
    }
    return { ok: false, scope: 'egress', ip: null, country: null, countryCode: null, region: null, city: null, timezone: null,
      source, checkedAt: new Date(this.nowMs()).toISOString(), latencyMs: null, errorCode: code, message: messages[code], diagnostics: diagnostics() };
  }
}

export default ProxyNetworkProbe;
