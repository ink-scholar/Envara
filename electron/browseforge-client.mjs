import { Buffer } from 'node:buffer';

// REST contract: nczz/BrowseForge fa9e0bb670e749706a9c8f2d4095333347d6c521,
// internal/api/{router,sessions,groups,backup}.go. Keep response envelopes intact
// so the desktop adapter does not mistake capabilities for installed binaries.
export const BROWSEFORGE_CONTRACT_REVISION = 'fa9e0bb670e749706a9c8f2d4095333347d6c521';

export class BrowseForgeApiError extends Error {
  constructor(message, { status = null, code = 'SERVICE_UNAVAILABLE', details = null } = {}) {
    super(message);
    this.name = 'BrowseForgeApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function baseURL(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError('BrowseForge baseUrl must be a loopback HTTP URL.'); }
  if (!['http:', 'https:'].includes(url.protocol) ||
      !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) ||
      url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new TypeError('BrowseForge baseUrl must be a loopback HTTP URL without credentials or a path.');
  }
  return url;
}

function apiURL(base, path) {
  if (typeof path !== 'string' || !path.startsWith('/api/') || path.includes('#') || path.includes('\\')) {
    throw new TypeError('BrowseForge request path must start with /api/.');
  }
  const url = new URL(path, base);
  if (url.origin !== base.origin || !url.pathname.startsWith('/api/')) {
    throw new TypeError('BrowseForge request path must stay within the local /api/ service.');
  }
  return url;
}

function bodySecrets(value, found = [], depth = 0) {
  if (!value || typeof value !== 'object' || depth > 12) return found;
  for (const [key, item] of Object.entries(value)) {
    if (/^(?:password|token|authorization|api[_-]?token)$/i.test(key) && typeof item === 'string' && item) found.push(item);
    else if (item && typeof item === 'object') bodySecrets(item, found, depth + 1);
  }
  return found;
}

function redact(value, secrets) {
  if (typeof value === 'string') {
    return secrets.reduce((text, secret) => secret ? text.split(secret).join('[redacted]') : text, value);
  }
  if (Array.isArray(value)) return value.map((item) => redact(item, secrets));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [
      key, /^(?:password|token|authorization|api[_-]?token)$/i.test(key) ? '[redacted]' : redact(item, secrets),
    ]));
  }
  return value;
}

function requestBody(body, headers) {
  if (body === undefined) return undefined;
  if (typeof FormData !== 'undefined' && body instanceof FormData) return body;
  if (body instanceof URLSearchParams || typeof body === 'string' || Buffer.isBuffer(body) || body instanceof Uint8Array) return body;
  headers.set('Content-Type', 'application/json');
  return JSON.stringify(body);
}

function segment(value) {
  if (typeof value !== 'string' || !value || value.includes('\0')) throw new TypeError('A nonempty identifier is required.');
  return encodeURIComponent(value);
}

/** Main-process client for an automatically managed, loopback-only sidecar. */
export class BrowseForgeClient {
  #baseUrl;
  #token;
  #fetch;
  #timeout;
  #rpcSequence = 0;

  constructor({ baseUrl = 'http://127.0.0.1:19280', token = '', fetchImpl = globalThis.fetch, timeoutMs = 15000 } = {}) {
    if (typeof baseUrl !== 'function') baseURL(baseUrl);
    if (typeof token !== 'string' && typeof token !== 'function') throw new TypeError('token must be a string or getter.');
    if (typeof fetchImpl !== 'function') throw new TypeError('fetchImpl must be a function.');
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new TypeError('timeoutMs must be positive.');
    this.#baseUrl = baseUrl;
    this.#token = token;
    this.#fetch = fetchImpl;
    this.#timeout = timeoutMs;
  }

  /** Returns raw JSON envelopes, text, or a Node Buffer. Mutations are never retried. */
  request(method, path, body, options) { return this.#request(method, path, body, options); }

  /** Main-process-only MCP transport. Callers must constrain the tool and profile. */
  async callMcpTool(name, args, options = {}) {
    if (typeof name !== 'string' || !/^[a-z_]{1,64}$/.test(name) || !args || typeof args !== 'object' || Array.isArray(args)) throw new TypeError('Invalid BrowseForge MCP tool call.');
    const id = `envara-${++this.#rpcSequence}`;
    const response = await this.#request('POST', '/mcp', { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }, { timeoutMs: 45000, ...options }, true);
    if (response?.jsonrpc !== '2.0' || response.id !== id) throw new BrowseForgeApiError('BrowseForge returned an invalid MCP response.', { code: 'INVALID_RESPONSE' });
    if (response.error) throw new BrowseForgeApiError('The selected browser action failed.', { code: 'MCP_TOOL_FAILED' });
    if (!response.result || !Array.isArray(response.result.content)) throw new BrowseForgeApiError('BrowseForge returned an invalid MCP tool result.', { code: 'INVALID_RESPONSE' });
    return response.result;
  }

  async #request(method, path, body, { responseType = 'json', timeoutMs = this.#timeout, signal } = {}, mcp = false) {
    if (typeof method !== 'string' || !['GET', 'POST', 'PUT', 'DELETE'].includes(method.toUpperCase())) {
      throw new TypeError('Unsupported BrowseForge HTTP method.');
    }
    method = method.toUpperCase();
    if (!['json', 'text', 'arraybuffer'].includes(responseType)) throw new TypeError('Unsupported responseType.');
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new TypeError('timeoutMs must be positive.');
    const base = baseURL(typeof this.#baseUrl === 'function' ? await this.#baseUrl() : this.#baseUrl);
    const url = mcp ? new URL('/mcp', base) : apiURL(base, path);
    const token = typeof this.#token === 'function' ? await this.#token() : this.#token;
    if (typeof token !== 'string' || /[\r\n]/.test(token)) throw new TypeError('Invalid BrowseForge authentication token.');
    const secrets = [...new Set([token, ...bodySecrets(body)].filter(Boolean))];
    const headers = new Headers({ Accept: responseType === 'json' ? 'application/json' : '*/*' });
    if (token) headers.set('Authorization', `Bearer ${token}`);
    const payload = requestBody(body, headers);
    const controller = new AbortController();
    let timedOut = false;
    const abort = () => controller.abort();
    if (signal?.aborted) controller.abort();
    else signal?.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
    try {
      const response = await this.#fetch(url.href, {
        method, headers, body: payload, signal: controller.signal,
        // A redirected local request must never send the sidecar token elsewhere.
        redirect: 'error',
      });
      if (!response.ok) {
        const raw = await response.text();
        let parsed;
        try { parsed = JSON.parse(raw); } catch { parsed = null; }
        const details = redact(parsed?.error ?? null, secrets);
        const code = typeof details?.code === 'string' ? details.code : `HTTP_${response.status}`;
        const reason = typeof details?.message === 'string' ? details.message : redact(raw.slice(0, 4096), secrets);
        throw new BrowseForgeApiError(reason || `BrowseForge returned HTTP ${response.status}.`, {
          status: response.status, code, details,
        });
      }
      if (responseType === 'arraybuffer') return Buffer.from(await response.arrayBuffer());
      if (responseType === 'text') return await response.text();
      const raw = await response.text();
      if (!raw.trim()) return null;
      try { return JSON.parse(raw); }
      catch {
        throw new BrowseForgeApiError('BrowseForge returned an invalid JSON response.', {
          status: response.status, code: 'INVALID_RESPONSE',
        });
      }
    } catch (error) {
      if (error instanceof BrowseForgeApiError) throw error;
      const code = timedOut ? 'REQUEST_TIMEOUT' : signal?.aborted ? 'REQUEST_ABORTED' : 'SERVICE_UNAVAILABLE';
      const message = timedOut ? 'BrowseForge request timed out.' : signal?.aborted
        ? 'BrowseForge request was cancelled.' : 'Unable to reach the local BrowseForge service.';
      throw new BrowseForgeApiError(message, { code });
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
    }
  }

  status(options) { return this.request('GET', '/api/status', undefined, options); }
  health(options) { return this.request('GET', '/api/health', undefined, options); }
  listRuntimes(options) { return this.request('GET', '/api/runtimes', undefined, options); }
  listProfiles({ group, tag, ...options } = {}) {
    const query = new URLSearchParams();
    if (group) query.set('group', group);
    if (tag) query.set('tag', tag);
    return this.request('GET', `/api/profiles${query.size ? `?${query}` : ''}`, undefined, options);
  }
  getProfile(id, options) { return this.request('GET', `/api/profiles/${segment(id)}`, undefined, options); }
  createProfile(profile, options) { return this.request('POST', '/api/profiles', profile, options); }
  updateProfile(id, patch, options) { return this.request('PUT', `/api/profiles/${segment(id)}`, patch, options); }
  deleteProfile(id, options) { return this.request('DELETE', `/api/profiles/${segment(id)}`, undefined, options); }
  listGroups(options) { return this.request('GET', '/api/groups', undefined, options); }
  updateGroup(name, policy, options) { return this.request('PUT', `/api/groups/${segment(name)}`, policy, options); }
  clearGroupProxy(name, options) { return this.request('DELETE', `/api/groups/${segment(name)}/proxy`, undefined, options); }
  deleteGroup(name, options) { return this.request('DELETE', `/api/groups/${segment(name)}`, undefined, options); }
  listSessions(options) { return this.request('GET', '/api/sessions', undefined, options); }
  createSession(profileId, options = {}) {
    // Launch includes GeoIP lookup, browser startup and Bind endpoint validation.
    return this.request('POST', '/api/sessions', { profile_id: profileId }, { timeoutMs: 180000, ...options });
  }
  closeSession(id, options) { return this.request('DELETE', `/api/sessions/${segment(id)}`, undefined, options); }
  screenshot(id, { fullPage = false, ...options } = {}) {
    return this.request('GET', `/api/sessions/${segment(id)}/screenshot${fullPage ? '?full_page=true' : ''}`, undefined, {
      ...options, responseType: 'arraybuffer',
    });
  }
  getPlaywrightEndpoints(options) { return this.request('GET', '/api/playwright/endpoint', undefined, options); }
  exportProfile(id, options) {
    return this.request('POST', `/api/profiles/${segment(id)}/export`, undefined, { ...options, responseType: 'arraybuffer' });
  }
  importProfile(zip, filename = 'profile.zip', options) {
    const form = new FormData();
    form.set('file', new Blob([zip], { type: 'application/zip' }), filename);
    return this.request('POST', '/api/profiles/import', form, options);
  }
}

export default BrowseForgeClient;
