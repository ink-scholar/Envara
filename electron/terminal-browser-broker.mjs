// A terminal grants browser authority for one profile and one network only.
// The owner process holds the global BrowseForge bearer; the stdio child sees
// only its revocable session token. No raw Playwright endpoint is exposed.
import http from 'node:http';
import path from 'node:path';
import os from 'node:os';
import { chmod, lstat, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { TERMINAL_TOOLS } from './terminal-browser-mcp.mjs';
import { describeSshSession } from './terminal-ssh-command.mjs';

const fail = (message, code = 'CLAUDE_BROWSER_UNAVAILABLE') => Object.assign(new Error(message), { code });
const id = value => { if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(value)) throw fail('Invalid browser binding.', 'CLAUDE_BROWSER_INVALID_BINDING'); return value; };
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().filter(key => value[key] !== undefined).map(key => [key, canonical(value[key])])) : value;
const digest = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
const text = value => ({ content: [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value) }] });
const profileSignature = profile => digest(Object.fromEntries(['engine', 'platform', 'seed', 'fingerprintGeneration', 'locale', 'timezone', 'launchOverrides', 'fingerprint', 'group', 'proxyId', 'profileProxyId', 'proxyMode'].map(key => [key, profile?.[key] ?? null])));

/** Private identity: proxy credentials are hashed in memory and never exported. */
export function browserRouteSignature(context) {
  const managed = context?.managedRoute;
  // TerminalService intentionally keeps only the actual connection fields.
  // The service wire also carries e.g. a BrowseForge geographic preset, which
  // is not another route. Compare the connection semantics, not object shape.
  const source = context?.proxy;
  const proxy = source ? { protocol: source.protocol ?? source.type, host: String(source.host ?? '').replace(/^\[|\]$/g, '').toLowerCase(), port: Number(source.port), username: source.username ?? '', password: source.password ?? '' } : null;
  return digest({ proxyId: context?.proxyId ?? null, proxy,
    managedRoute: managed ? Object.fromEntries(Object.entries(managed).filter(([key]) => key !== 'profileId')) : null });
}
export function browserContextSignature(context) {
  return digest({ route: browserRouteSignature(context), timezone: context?.timezone ?? null, locale: context?.locale ?? null,
    geolocation: context?.geolocation ?? null, selectedLocation: context?.selectedLocation ?? null, privacy: context?.privacy ?? null });
}
function webURL(value) {
  if (typeof value !== 'string' || value.length > 8192 || /[\0\r\n]/.test(value)) throw fail('A valid HTTP or HTTPS URL is required.', 'CLAUDE_BROWSER_INVALID_ARGUMENT');
  let url; try { url = new URL(value); } catch { throw fail('A valid HTTP or HTTPS URL is required.', 'CLAUDE_BROWSER_INVALID_ARGUMENT'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw fail('Only HTTP or HTTPS URLs without credentials are allowed.', 'CLAUDE_BROWSER_INVALID_ARGUMENT');
  return url.href;
}
function validate(value, schema, name = 'arguments') {
  const invalid = () => { throw fail(`Invalid ${name}.`, 'CLAUDE_BROWSER_INVALID_ARGUMENT'); };
  if (schema.type === 'object') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
    if (Object.keys(value).some(key => !Object.hasOwn(schema.properties, key))) invalid();
    if (schema.required?.some(key => !Object.hasOwn(value, key))) invalid();
    for (const [key, item] of Object.entries(value)) validate(item, schema.properties[key], `${name}.${key}`);
  } else if (schema.type === 'string') {
    if (typeof value !== 'string' || value.includes('\0') || value.length < (schema.minLength ?? 0) || value.length > (schema.maxLength ?? Infinity) || schema.enum && !schema.enum.includes(value)) invalid();
  } else if (schema.type === 'integer') {
    if (!Number.isInteger(value) || value < schema.minimum || value > schema.maximum) invalid();
  } else if (schema.type === 'boolean') { if (typeof value !== 'boolean') invalid(); }
  else if (schema.type === 'array') {
    if (!Array.isArray(value) || value.length < schema.minItems || value.length > schema.maxItems) invalid();
    value.forEach((item, index) => validate(item, schema.items, `${name}[${index}]`));
  }
}
function checkedTool(name, args) {
  const tool = TERMINAL_TOOLS.find(item => item.name === name);
  if (!tool) throw fail('Unknown browser tool.', 'CLAUDE_BROWSER_UNKNOWN_TOOL');
  validate(args, tool.inputSchema);
  if (name === 'browser_navigate') webURL(args.url);
  if (name === 'browser_tabs') {
    if (['select', 'close'].includes(args.action)) { if (!Number.isInteger(args.index) || args.url != null) throw fail('Tab select/close requires only an index.', 'CLAUDE_BROWSER_INVALID_ARGUMENT'); }
    else if (args.index != null || args.action === 'list' && args.url != null) throw fail('Unexpected tab argument.', 'CLAUDE_BROWSER_INVALID_ARGUMENT');
    if (args.url != null) webURL(args.url);
  }
}

function publicSshDescription(value) {
  // Only bounded, authored output crosses into the model transcript. Never
  // forward a provider's arbitrary metadata, usage text, or error message.
  if (!value || !['empty', 'ready', 'expired', 'closed', 'unavailable'].includes(value.status)) throw fail('SSH connection status is unavailable. Start a new terminal session.', 'CLAUDE_BROWSER_SSH_UNAVAILABLE');
  const unavailableAliases = [];
  if (value.version === 2 && Array.isArray(value.connections)) {
    for (const connection of value.connections) {
      if (!connection || !['ready', 'expired', 'unavailable'].includes(connection.status)
        || connection.available !== (connection.status === 'ready')) throw fail('SSH connection status is unavailable. Start a new terminal session.', 'CLAUDE_BROWSER_SSH_UNAVAILABLE');
      if (connection.status === 'unavailable') unavailableAliases.push(connection.alias);
    }
  }
  const result = describeSshSession({ schema: value.schema, version: value.version,
    connections: value.connections, expiresAt: value.expiresAt }, Date.now(),
  { closed: value.status === 'closed', unavailable: value.status === 'unavailable', unavailableAliases });
  if (result.status !== value.status || result.available !== value.available) throw fail('SSH connection status changed. Refresh the connection list.', 'CLAUDE_BROWSER_SSH_UNAVAILABLE');
  if (result.version === 2 && result.connections.some((connection, index) => connection.status !== value.connections[index].status
    || connection.available !== value.connections[index].available)) throw fail('SSH connection status changed. Refresh the connection list.', 'CLAUDE_BROWSER_SSH_UNAVAILABLE');
  return { ...result, connections: result.connections.map(connection => ({ ...connection, command: `ssh ${connection.alias}` })) };
}
const SNAPSHOT = `(() => {
  const visible = e => !!(e.getClientRects().length) && getComputedStyle(e).visibility !== 'hidden';
  const selector = e => {
    if (e.id) return '#' + CSS.escape(e.id);
    const parts = []; let node = e;
    while (node && node.nodeType === 1 && parts.length < 8) {
      let part = node.tagName.toLowerCase();
      const siblings = node.parentElement ? [...node.parentElement.children].filter(s => s.tagName === node.tagName) : [];
      if (siblings.length > 1) part += ':nth-of-type(' + (siblings.indexOf(node) + 1) + ')';
      parts.unshift(part); node = node.parentElement;
    }
    return parts.join(' > ');
  };
  return { url: location.href, title: document.title,
    text: (document.body?.innerText ?? '').slice(0, 40000),
    elements: [...document.querySelectorAll('a,button,input,textarea,select,[role="button"],[role="link"],[contenteditable="true"]')].filter(visible).slice(0, 200).map(e => ({ selector: selector(e), tag: e.tagName.toLowerCase(), role: e.getAttribute('role'), type: e.getAttribute('type'), label: (e.getAttribute('aria-label') || e.labels?.[0]?.innerText || e.innerText || e.getAttribute('placeholder') || '').slice(0, 300), disabled: !!e.disabled })) };
})()`;

export class TerminalBrowserBroker {
  constructor({ service, dataDir, nodeExecutable, onError = () => {}, protectBrowserOperation = (_profileId, operation) => operation() }) {
    if (!service || !path.isAbsolute(dataDir ?? '') || !path.isAbsolute(nodeExecutable ?? '')) throw fail('Browser broker configuration is invalid.');
    this.service = service; this.dataDir = dataDir; this.nodeExecutable = nodeExecutable; this.onError = onError;
    this.protectBrowserOperation = protectBrowserOperation;
    this.sessions = new Map(); this.pending = new Set(); this.closed = false;
  }
  async createSession({ sessionId, profileId, browserProfileId, context, readSshConnections = null }) {
    id(sessionId); id(profileId);
    if (!browserProfileId || browserProfileId === 'system') throw fail('Choose an Envara browser for Claude Code.', 'CLAUDE_BROWSER_REQUIRED');
    id(browserProfileId);
    if (readSshConnections !== null && typeof readSshConnections !== 'function') throw fail('Invalid SSH discovery binding.', 'CLAUDE_BROWSER_INVALID_BINDING');
    if (this.closed || this.sessions.has(sessionId)) throw fail('Browser session is unavailable.');
    if (context?.id !== profileId || !context.proxy || !context.proxyId || context.network?.ok !== true) throw fail('Verify the selected network before starting Claude Code.', 'CLAUDE_BROWSER_NETWORK_REQUIRED');
    const session = { sessionId, profileId, browserProfileId, readSshConnections, routeSignature: browserRouteSignature(context), sourceSignature: browserContextSignature(context), token: randomBytes(32).toString('hex'), disposed: false, queue: Promise.resolve(), sockets: new Set() };
    this.sessions.set(sessionId, session);
    try {
      const chosen = await this.validateBinding(session, { initial: true });
      session.browser = { profileId: browserProfileId, name: chosen.name };
      let temporary = await realpath(os.tmpdir());
      if (Buffer.byteLength(path.join(temporary, 'evb-XXXXXX', 'browser.sock')) > 100) temporary = await realpath('/tmp');
      session.directory = await mkdtemp(path.join(temporary, 'evb-')); await chmod(session.directory, 0o700);
      if (session.disposed || this.closed) throw fail('Browser session ended.');
      session.socketPath = path.join(session.directory, 'browser.sock');
      const script = path.join(session.directory, 'terminal-browser-mcp.mjs');
      // Electron can read its asar; the physical bundled Node cannot. Always
      // copy this self-contained, credential-free script to a private directory.
      await writeFile(script, await readFile(new URL('./terminal-browser-mcp.mjs', import.meta.url)), { mode: 0o600, flag: 'wx' });
      session.server = http.createServer((request, response) => { void this.handle(session, request, response); });
      session.server.requestTimeout = 15000; session.server.headersTimeout = 10000;
      session.server.on('connection', socket => { session.sockets.add(socket); socket.on('close', () => session.sockets.delete(socket)); });
      await new Promise((resolve, reject) => { session.server.once('error', reject); session.server.listen(session.socketPath, resolve); });
      await chmod(session.socketPath, 0o600);
      if (session.disposed || this.closed) throw fail('Browser session ended.');
      return { environment: { ENVARA_BROWSER_SOCKET: session.socketPath, ENVARA_BROWSER_TOKEN: session.token,
          ENVARA_LINK_SOCKET: session.socketPath, ENVARA_LINK_TOKEN: session.token },
        mcpServer: { command: this.nodeExecutable, args: [script] }, browser: session.browser,
        openLink: url => this.enqueue(session, () => this.operate(session, 'browser_tabs', { action: 'new', url: webURL(url) })).then(() => ({ opened: 'environment', profileId: browserProfileId, browser: session.browser.name })),
        dispose: () => this.dispose(session) };
    } catch (error) { await this.dispose(session); throw error; }
  }
  async validateBinding(session, { initial = false } = {}) {
    if (session.disposed || this.closed) throw fail('This terminal browser session has ended.', 'CLAUDE_BROWSER_SESSION_ENDED');
    const snapshot = await this.service.snapshot();
    const source = snapshot.profiles?.find(item => item.id === session.profileId);
    const chosen = snapshot.profiles?.find(item => item.id === session.browserProfileId);
    if (!source || !chosen || !source.proxyId || source.proxyId !== chosen.proxyId) throw fail('The selected browser no longer belongs to this network. Start a new Claude Code session.', 'CLAUDE_BROWSER_BINDING_CHANGED');
    const selectedProfileSignature = profileSignature(chosen);
    if (initial) session.profileSignature = selectedProfileSignature;
    else if (session.profileSignature !== selectedProfileSignature) throw fail('The selected browser profile changed. Start a new Claude Code session.', 'CLAUDE_BROWSER_BINDING_CHANGED');
    const context = await this.service.resolveWorkspaceContext(session.profileId, { force: false });
    if (context.network?.ok !== true || browserContextSignature(context) !== session.sourceSignature) throw fail('The terminal network or configuration changed. Start a new Claude Code session.', 'CLAUDE_BROWSER_BINDING_CHANGED');
    const browserContext = session.profileId === session.browserProfileId ? context : await this.service.resolveWorkspaceContext(session.browserProfileId, { force: false });
    if (browserContext.network?.ok !== true || browserRouteSignature(browserContext) !== session.routeSignature) throw fail('The selected browser network changed. Start a new Claude Code session.', 'CLAUDE_BROWSER_BINDING_CHANGED');
    const signature = browserContextSignature(browserContext);
    if (initial) session.browserSignature = signature;
    else if (session.browserSignature !== signature) throw fail('The selected browser configuration changed. Start a new Claude Code session.', 'CLAUDE_BROWSER_BINDING_CHANGED');
    session.browserContext = browserContext;
    if (session.disposed || this.closed) throw fail('This terminal browser session has ended.', 'CLAUDE_BROWSER_SESSION_ENDED');
    return chosen;
  }
  enqueue(session, operation) {
    const pending = session.queue.then(async () => {
      if (session.disposed || this.closed) throw fail('This terminal browser session has ended.', 'CLAUDE_BROWSER_SESSION_ENDED');
      return operation();
    });
    session.queue = pending.catch(() => {});
    this.pending.add(pending); pending.finally(() => this.pending.delete(pending)).catch(() => {});
    return pending;
  }
  async operate(session, name, args) {
    checkedTool(name, args);
    const operation = () => this.operateBound(session, name, args);
    // A tool can start the browser, then write its storage through REST or MCP.
    // Hold one target-browser reservation across that entire operation.
    return ['browser_status', 'envara_ssh_connections'].includes(name) ? operation() : this.protectBrowserOperation(session.browserProfileId, operation);
  }
  async operateBound(session, name, args) {
    const chosen = await this.validateBinding(session);
    if (name === 'envara_ssh_connections') {
      try {
        return text(publicSshDescription(session.readSshConnections?.() ?? {
          schema: 'envara.ssh-session', version: 1, status: 'unavailable', available: false, connections: [], expiresAt: null,
        }));
      } catch {
        throw fail('SSH connection status is unavailable. Check Envara and start a new terminal session.', 'CLAUDE_BROWSER_SSH_UNAVAILABLE');
      }
    }
    if (name === 'browser_status') return text({ browser: session.browser, network: { proxyId: chosen.proxyId, timezone: session.browserContext.timezone, egress: session.browserContext.network?.ip ?? null }, binding: 'terminal-session', engine: 'Playwright' });
    // This service method validates its launch receipt for an already-running
    // browser. It must never silently reuse a session with an unknown route.
    if (typeof this.service.ensureBoundBrowser !== 'function') throw fail('Bound browser launch is not available.');
    const browser = await this.service.ensureBoundBrowser({ profileId: session.browserProfileId, expectedContext: session.browserContext });
    if (!browser?.session_id || browser.profile_id !== session.browserProfileId) throw fail('Bound browser launch returned a different profile.');
    await this.validateBinding(session);
    const endpoint = `/api/sessions/${encodeURIComponent(browser.session_id)}`;
    const request = (method, suffix, body, options) => this.service.request(method, endpoint + suffix, body, { timeoutMs: 45000, ...options });
    const mcp = async (tool, arguments_) => {
      if (typeof this.service.callBoundBrowserTool !== 'function') throw fail('Bound browser action is not available.');
      return this.service.callBoundBrowserTool(session.browserProfileId, tool, arguments_);
    };
    if (session.disposed || this.closed) throw fail('This terminal browser session has ended.', 'CLAUDE_BROWSER_SESSION_ENDED');
    if (name === 'browser_navigate') return text((await request('POST', '/navigate', { url: webURL(args.url), wait_until: 'domcontentloaded' }))?.data);
    if (name === 'browser_snapshot') return text((await request('POST', '/eval', { script: SNAPSHOT }))?.data);
    if (name === 'browser_click') return text((await request('POST', '/click', { selector: args.selector }))?.data);
    if (name === 'browser_fill') return mcp('form_fill', { fields: [{ selector: args.selector, text: args.value, clear: true }] });
    if (name === 'browser_press_key') return mcp('press_key', { key: args.key });
    if (name === 'browser_select') return mcp('select_option', { selector: args.selector, values: args.values, timeout: 10000 });
    if (name === 'browser_check') return mcp('check', { selector: args.selector, checked: args.checked, timeout: 10000 });
    if (name === 'browser_scroll') return text((await request('POST', '/eval', { script: `(() => { window.scrollBy(${args.x ?? 0}, ${args.y}); return {x:scrollX,y:scrollY}; })()` }))?.data);
    if (name === 'browser_wait_for') return text((await request('POST', '/wait', { selector: args.selector, timeout: args.timeoutMs ?? 10000 }))?.data);
    if (name === 'browser_screenshot') {
      const png = await request('GET', `/screenshot${args.fullPage ? '?full_page=true' : ''}`, undefined, { responseType: 'arraybuffer' });
      if (!png?.byteLength || png.byteLength > 12 * 1024 * 1024) throw fail('Screenshot exceeds the size limit.');
      return { content: [{ type: 'image', mimeType: 'image/png', data: Buffer.from(png).toString('base64') }] };
    }
    if (name === 'browser_tabs') {
      const operation = { list: 'list_tabs', new: 'new_tab', select: 'switch_tab', close: 'close_tab' }[args.action];
      return mcp(operation, { ...(args.index != null ? { index: args.index } : {}), ...(args.url ? { url: webURL(args.url) } : {}) });
    }
    throw fail('Unsupported browser action.');
  }
  async rpc(session, request) {
    if (!request || typeof request !== 'object' || Array.isArray(request) || request.jsonrpc !== '2.0' || typeof request.method !== 'string' || Object.keys(request).some(key => !['jsonrpc', 'id', 'method', 'params'].includes(key)) || (Object.hasOwn(request, 'id') && request.id !== null && typeof request.id !== 'string' && !Number.isFinite(request.id))) return { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid JSON-RPC request.' } };
    if (!Object.hasOwn(request, 'id')) return null;
    const response = result => ({ jsonrpc: '2.0', id: request.id, result });
    if (request.method === 'initialize') {
      const requested = request.params?.protocolVersion;
      return response({ protocolVersion: ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'].includes(requested) ? requested : '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'envara-browser', version: '1.0.0' }, instructions: 'Browser tools operate only the browser and network selected for this terminal. Use them for browser tasks; do not launch a separate browser or use other browser MCP servers. For SSH tasks, first call envara_ssh_connections to discover this session\'s authorized connections and usage. It is read-only and does not connect or authorize servers. Execute returned SSH aliases through the terminal; do not read host private keys or change routes. Remote commands run under the server\'s permissions and network, outside this Mac\'s process fence.' });
    }
    if (request.method === 'ping') return response({});
    if (request.method === 'tools/list') return response({ tools: TERMINAL_TOOLS });
    if (request.method !== 'tools/call') return { jsonrpc: '2.0', id: request.id, error: { code: -32601, message: 'Method not found.' } };
    try {
      const params = request.params;
      if (!params || typeof params !== 'object' || Array.isArray(params) || Object.keys(params).some(key => !['name', 'arguments', '_meta'].includes(key))) throw fail('Invalid tool request.', 'CLAUDE_BROWSER_INVALID_ARGUMENT');
      return response(await this.enqueue(session, () => this.operate(session, params.name, params.arguments ?? {})));
    } catch (error) {
      // Operational errors may contain private route details. Only our bounded
      // codes and authored messages can cross into the model's transcript.
      const own = typeof error?.code === 'string' && error.code.startsWith('CLAUDE_BROWSER_');
      return response({ isError: true, content: [{ type: 'text', text: own ? `${error.code}: ${error.message}` : 'CLAUDE_BROWSER_ACTION_FAILED: The selected browser action failed. Check Envara; no other browser or network was used.' }] });
    }
  }
  async handle(session, request, response) {
    const send = (status, payload) => { if (response.destroyed) return; response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); response.end(payload == null ? '' : JSON.stringify(payload)); };
    if (session.disposed || this.closed) return send(403, { error: 'session-ended' });
    const received = request.headers.authorization;
    const expected = `Bearer ${session.token}`;
    if (typeof received !== 'string' || Buffer.byteLength(received) !== Buffer.byteLength(expected) || !timingSafeEqual(Buffer.from(received), Buffer.from(expected))) { request.resume(); return send(403, { error: 'unauthorized' }); }
    if (request.method !== 'POST' || !['/mcp', '/link'].includes(request.url) || request.headers.origin) { request.resume(); return send(404, { error: 'not-found' }); }
    try {
      let size = 0; const chunks = [];
      for await (const chunk of request) { size += chunk.length; if (size > 256 * 1024) { send(413, { error: 'too-large' }); request.destroy(); return; } chunks.push(chunk); }
      let payload; try { payload = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return send(request.url === '/link' ? 400 : 200, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Invalid JSON.' } }); }
      if (request.url === '/link') {
        let url;
        try {
          if (!payload || typeof payload !== 'object' || Array.isArray(payload) || Object.keys(payload).length !== 1 || !Object.hasOwn(payload, 'url')) throw fail('Invalid link.');
          url = webURL(payload.url);
          await this.validateBinding(session);
        } catch { return send(400, { error: 'invalid-browser-link' }); }
        // The shell shim has a 30-second limit; a cold browser can take longer.
        // Confirm the pinned destination immediately, as the existing link
        // router does. Never redirect a failed opening to a host browser.
        this.enqueue(session, () => this.operate(session, 'browser_tabs', { action: 'new', url })).catch(() => {
          try { this.onError({ sessionId: session.sessionId, profileId: session.browserProfileId, code: 'CLAUDE_BROWSER_LINK_FAILED', message: 'Claude Code 的链接未能在所选境舱浏览器打开，请检查该浏览器和网络。' }); } catch {}
        });
        return send(200, { opened: 'environment', browser: session.browser.name, profileId: session.browserProfileId });
      }
      const result = await this.rpc(session, payload); send(result == null ? 204 : 200, result);
    } catch { send(500, { error: 'browser-session-unavailable' }); }
  }
  async dispose(session) {
    // Creation may still be yielding while disposal happens. A second cleanup
    // must collect resources that creation allocated before noticing revocation.
    session.disposed = true; session.token = ''; this.sessions.delete(session.sessionId);
    session.readSshConnections = null;
    // Keep cleanup attempts serialized, but a failed filesystem removal must
    // not poison every later Close. Revocation above never depends on cleanup.
    session.disposal = Promise.resolve(session.disposal).catch(() => {}).then(async () => {
      for (const socket of session.sockets) socket.destroy();
      if (session.server?.listening) await new Promise(resolve => session.server.close(resolve));
      if (session.directory) {
        const info = await lstat(session.directory).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
        if (info && (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid?.())) throw fail('Browser session cleanup path changed.', 'CLAUDE_BROWSER_CLEANUP_UNCONFIRMED');
        if (info) await rm(session.directory, { recursive: true, force: true });
      }
    });
    return session.disposal;
  }
  async shutdown() {
    this.closed = true;
    await Promise.allSettled([...this.sessions.values()].map(session => this.dispose(session)));
  }
}
