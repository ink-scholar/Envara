import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import os from 'node:os';
import { chmod, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { TerminalBrowserBroker, browserContextSignature, browserRouteSignature } from '../electron/terminal-browser-broker.mjs';
import { BROWSER_TOOLS, requestBrowserBroker } from '../electron/terminal-browser-mcp.mjs';

const clone = value => structuredClone(value);
const seed = { id: 'prof_a', proxyId: 'node_a', proxy: { protocol: 'http', host: '127.0.0.1', port: 19321, username: 'local-user', password: 'fixture-local-secret' },
  managedRoute: { profileId: 'prof_a', proxyId: 'node_a', coreGeneration: 'generation_a', corePid: 1234, routeIdentity: 'route-a' },
  timezone: 'Asia/Manila', locale: 'en-PH', privacy: { mode: 'standard' }, geolocation: { latitude: 14.6, longitude: 121, accuracy: 10000 },
  selectedLocation: { confirmed: true, source: 'ip', timezone: 'Asia/Manila' }, network: { ok: true, ip: '198.51.100.1' } };
const rpc = (name, args = {}) => ({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'broker-test-'));
  const contexts = new Map(['prof_a', 'prof_b'].map(profileId => [profileId, { ...clone(seed), id: profileId, name: profileId, managedRoute: { ...seed.managedRoute, profileId } }]));
  const state = { profiles: [{ id: 'prof_a', name: 'Terminal environment', proxyId: 'node_a' }, { id: 'prof_b', name: 'Chosen browser', proxyId: 'node_a' }] };
  const calls = [], errors = [];
  const service = {
    async snapshot() { return clone(state); },
    async resolveWorkspaceContext(profileId) { calls.push({ kind: 'resolve', profileId }); return clone(contexts.get(profileId)); },
    async ensureBoundBrowser({ profileId, expectedContext }) { calls.push({ kind: 'ensure', profileId, expectedContext }); return { session_id: `sess_${profileId}`, profile_id: profileId }; },
    async request(method, endpoint, body) { calls.push({ kind: 'rest', method, endpoint, body }); return endpoint.includes('/screenshot') ? Buffer.from('fixture-png') : { data: { url: 'https://example.test/', success: true } }; },
    async callBoundBrowserTool(profileId, name, args) { calls.push({ kind: 'mcp', profileId, name, args }); return { content: [{ type: 'text', text: `done ${name}` }] }; },
  };
  const broker = new TerminalBrowserBroker({ service, dataDir: root, nodeExecutable: process.execPath, onError: event => errors.push(event) });
  t.after(async () => { await broker.shutdown(); await rm(root, { recursive: true, force: true }); });
  const create = (sessionId = 'term_a', browserProfileId = 'prof_b') => broker.createSession({ sessionId, profileId: 'prof_a', browserProfileId, context: clone(contexts.get('prof_a')) });
  return { broker, service, contexts, state, calls, errors, create };
}
const send = (binding, request) => requestBrowserBroker(request, { socketPath: binding.environment.ENVARA_BROWSER_SOCKET, token: binding.environment.ENVARA_BROWSER_TOKEN });
const postLink = (binding, payload) => new Promise((resolve, reject) => {
  const body = JSON.stringify(payload);
  const request = http.request({ socketPath: binding.environment.ENVARA_LINK_SOCKET, path: '/link', method: 'POST', headers: { Authorization: `Bearer ${binding.environment.ENVARA_LINK_TOKEN}`, 'Content-Length': Buffer.byteLength(body) } }, response => {
    let text = ''; response.setEncoding('utf8'); response.on('data', chunk => text += chunk); response.on('end', () => resolve({ status: response.statusCode, body: JSON.parse(text) }));
  }); request.on('error', reject); request.end(body);
});

test('a real filesystem cleanup failure revokes authority immediately and an explicit retry removes the runtime', { skip: process.platform === 'win32' || process.getuid?.() === 0 }, async t => {
  const f = await fixture(t), binding = await f.create();
  const session = f.broker.sessions.get('term_a');
  const directory = session.directory;
  t.after(async () => { await chmod(directory, 0o700).catch(() => {}); await binding.dispose(); });
  await chmod(directory, 0o500);
  await assert.rejects(binding.dispose(), error => ['EACCES', 'EPERM'].includes(error.code));
  assert.equal(session.disposed, true); assert.equal(session.token, '');
  assert.equal(f.broker.sessions.has('term_a'), false);
  await assert.rejects(send(binding, rpc('browser_status')));
  await chmod(directory, 0o700);
  await binding.dispose();
  await assert.rejects(stat(directory), { code: 'ENOENT' });
});

test('one private channel grants only its terminal browser, with no global credential or endpoint exported', async t => {
  const f = await fixture(t), binding = await f.create();
  assert.deepEqual(binding.browser, { profileId: 'prof_b', name: 'Chosen browser' });
  assert.equal(binding.mcpServer.command, process.execPath);
  assert.equal((await stat(binding.environment.ENVARA_BROWSER_SOCKET)).mode & 0o777, 0o600);
  assert.equal((await stat(path.dirname(binding.environment.ENVARA_BROWSER_SOCKET))).mode & 0o777, 0o700);
  const script = await readFile(binding.mcpServer.args[0], 'utf8');
  for (const secret of [seed.proxy.password, binding.environment.ENVARA_BROWSER_TOKEN]) {
    assert.ok(!script.includes(secret)); assert.ok(!JSON.stringify(binding.mcpServer).includes(secret));
  }
  assert.equal(f.calls.filter(call => call.kind === 'ensure').length, 0, 'registration does not launch a browser');
  const status = await send(binding, rpc('browser_status'));
  assert.equal(status.result.isError, undefined);
  assert.match(status.result.content[0].text, /Chosen browser/);
  assert.equal(f.calls.filter(call => call.kind === 'ensure').length, 0, 'status stays read-only');
});

test('wrong or other-session tokens are refused before any operation', async t => {
  const f = await fixture(t), a = await f.create(), b = await f.create('term_b');
  const before = f.calls.length;
  for (const token of ['f'.repeat(64), b.environment.ENVARA_BROWSER_TOKEN]) await assert.rejects(requestBrowserBroker(rpc('browser_navigate', { url: 'https://example.test/' }), { socketPath: a.environment.ENVARA_BROWSER_SOCKET, token }));
  assert.equal(f.calls.length, before);
});

test('all practical browser tools use only the pinned existing Playwright context', async t => {
  const f = await fixture(t), binding = await f.create();
  const cases = [
    ['browser_navigate', { url: 'https://example.test/a' }], ['browser_snapshot', {}], ['browser_click', { selector: '#ok' }],
    ['browser_fill', { selector: '#text', value: 'hello' }], ['browser_press_key', { key: 'Enter' }],
    ['browser_select', { selector: '#select', values: ['one'] }], ['browser_check', { selector: '#checkbox', checked: true }],
    ['browser_scroll', { x: 0, y: 500 }], ['browser_wait_for', { selector: '#ready', timeoutMs: 1000 }],
    ['browser_screenshot', { fullPage: true }], ['browser_tabs', { action: 'list' }],
    ['browser_tabs', { action: 'new', url: 'https://example.test/new' }], ['browser_tabs', { action: 'select', index: 1 }], ['browser_tabs', { action: 'close', index: 1 }],
  ];
  for (const [name, args] of cases) {
    const answer = await send(binding, rpc(name, args));
    assert.equal(answer.result.isError, undefined, `${name}: ${JSON.stringify(answer)}`);
    if (name === 'browser_screenshot') assert.deepEqual(answer.result.content[0], { type: 'image', mimeType: 'image/png', data: Buffer.from('fixture-png').toString('base64') });
  }
  for (const call of f.calls.filter(call => call.kind === 'rest')) assert.match(call.endpoint, /^\/api\/sessions\/sess_prof_b\//);
  for (const call of f.calls.filter(call => ['ensure', 'mcp'].includes(call.kind))) assert.equal(call.profileId, 'prof_b');
  assert.deepEqual(f.calls.find(call => call.name === 'form_fill').args, { fields: [{ selector: '#text', text: 'hello', clear: true }] });
  assert.ok(!f.calls.some(call => JSON.stringify(call).includes('playwright/endpoint')), 'no raw Playwright authority is exported or requested');
});

test('profile selection, arbitrary launch, endpoint, unknown fields and non-web navigation are rejected', async t => {
  const f = await fixture(t), binding = await f.create();
  const bad = [
    ['browser_navigate', { url: 'https://example.test', profileId: 'prof_other' }], ['browser_click', { selector: '#ok', session_id: 'sess_other' }],
    ['open_browser', { profile_id: 'other' }], ['browser_snapshot', { cdpUrl: 'ws://127.0.0.1:9222' }],
    ['browser_tabs', { action: 'select' }], ['browser_tabs', { action: 'list', index: 1 }], ['browser_tabs', { action: 'close', index: -1 }],
    ['browser_navigate', { url: 'file:///etc/passwd' }], ['browser_navigate', { url: 'javascript:alert(1)' }],
    ['browser_navigate', { url: 'https://user:password@example.test/' }], ['browser_select', { selector: 'select', values: [{ profile_id: 'other' }] }],
  ];
  for (const [name, args] of bad) assert.equal((await send(binding, rpc(name, args))).result.isError, true, name);
  assert.equal(f.calls.filter(call => ['ensure', 'rest', 'mcp'].includes(call.kind)).length, 0);
});

test('changing the selected browser, network, core generation or context revokes operations without fallback', async t => {
  for (const change of [
    f => f.state.profiles.pop(),
    f => { f.state.profiles[1].proxyId = 'node_b'; },
    f => { f.contexts.get('prof_b').proxy.port++; },
    f => { f.contexts.get('prof_a').managedRoute.coreGeneration = 'new'; },
    f => { f.contexts.get('prof_b').timezone = 'Europe/London'; },
    f => { f.state.profiles[1].seed = 9999; },
    f => { f.contexts.get('prof_a').network.ok = false; },
  ]) {
    const f = await fixture(t), binding = await f.create(); change(f);
    const answer = await send(binding, rpc('browser_navigate', { url: 'https://example.test/' }));
    assert.equal(answer.result.isError, true); assert.match(answer.result.content[0].text, /CLAUDE_BROWSER_BINDING_CHANGED/);
    assert.equal(f.calls.filter(call => ['ensure', 'rest', 'mcp'].includes(call.kind)).length, 0);
  }
});

test('changing fingerprint generation revokes an idle binding before any browser launch', async t => {
  const generation = { provider: 'browseforge-chromium', version: 1, tuple_id: 'fixture-macos', generated_fields: {} };
  for (const [name, change] of [
    ['remove an empty generation marker', profile => { profile.fingerprintGeneration = null; }],
    ['change the generated tuple', profile => { profile.fingerprintGeneration.tuple_id = 'fixture-macos-other'; }],
    ['change generated values', profile => { profile.fingerprintGeneration.generated_fields.hardware_concurrency = 8; }],
  ]) await t.test(name, async subtest => {
    const f = await fixture(subtest);
    const profile = f.state.profiles[1];
    Object.assign(profile, { engine: 'browseforge-chromium', seed: 123, fingerprint: {}, fingerprintGeneration: clone(generation) });
    const binding = await f.create();
    change(profile);
    const answer = await send(binding, rpc('browser_navigate', { url: 'https://example.test/' }));
    assert.equal(answer.result.isError, true);
    assert.match(answer.result.content[0].text, /CLAUDE_BROWSER_BINDING_CHANGED/);
    assert.equal(f.calls.filter(call => ['ensure', 'rest', 'mcp'].includes(call.kind)).length, 0);
  });
});

test('system browser, missing network and another node cannot create a binding', async t => {
  const f = await fixture(t);
  await assert.rejects(f.create('term_system', 'system'), { code: 'CLAUDE_BROWSER_REQUIRED' });
  f.contexts.get('prof_a').proxyId = null;
  await assert.rejects(f.create('term_missing'), { code: 'CLAUDE_BROWSER_NETWORK_REQUIRED' });
  f.contexts.get('prof_a').proxyId = 'node_a'; f.state.profiles[1].proxyId = 'node_b';
  await assert.rejects(f.create('term_other'), { code: 'CLAUDE_BROWSER_BINDING_CHANGED' });
  assert.equal(f.broker.sessions.size, 0);
});

test('disposal revokes a token, removes only the private runtime and does not close the browser', async t => {
  const f = await fixture(t), binding = await f.create();
  const directory = path.dirname(binding.environment.ENVARA_BROWSER_SOCKET);
  await binding.dispose(); await binding.dispose();
  await assert.rejects(send(binding, rpc('browser_status')));
  await assert.rejects(stat(directory), { code: 'ENOENT' });
  await assert.rejects(binding.openLink('https://example.test/'), { code: 'CLAUDE_BROWSER_SESSION_ENDED' });
  assert.equal(f.calls.filter(call => ['rest', 'mcp'].includes(call.kind)).length, 0);
});

test('OAuth open shim uses the same bound socket; additional fields and changed routes are refused', async t => {
  const f = await fixture(t), binding = await f.create();
  assert.equal(binding.environment.ENVARA_LINK_SOCKET, binding.environment.ENVARA_BROWSER_SOCKET);
  assert.equal(binding.environment.ENVARA_LINK_TOKEN, binding.environment.ENVARA_BROWSER_TOKEN);
  const response = await postLink(binding, { url: 'https://example.test/oauth' });
  assert.equal(response.status, 200); assert.equal(response.body.profileId, 'prof_b');
  await Promise.all([...f.broker.pending]);
  assert.deepEqual(f.calls.find(call => call.name === 'new_tab').args, { url: 'https://example.test/oauth' });
  assert.equal((await postLink(binding, { url: 'https://example.test/oauth', profileId: 'other' })).status, 400);
  f.state.profiles[1].proxyId = 'node_b';
  assert.equal((await postLink(binding, { url: 'https://example.test/oauth' })).status, 400);
});

test('backend errors are bounded and cannot leak proxy credentials into the Claude transcript', async t => {
  const f = await fixture(t), binding = await f.create();
  f.service.request = async () => { throw new Error(`connection rejected ${seed.proxy.password}`); };
  const response = await send(binding, rpc('browser_navigate', { url: 'https://example.test/' }));
  assert.equal(response.result.isError, true); assert.ok(!JSON.stringify(response).includes(seed.proxy.password));
});

test('disposal during cold startup prevents the pending and queued actions from using a browser', async t => {
  const f = await fixture(t), binding = await f.create();
  let release, started;
  const reached = new Promise(resolve => started = resolve);
  const gate = new Promise(resolve => release = resolve);
  f.service.ensureBoundBrowser = async ({ profileId }) => { started(); await gate; return { session_id: `sess_${profileId}`, profile_id: profileId }; };
  const first = binding.openLink('https://example.test/first').catch(error => error);
  await reached;
  const next = binding.openLink('https://example.test/next').catch(error => error);
  await binding.dispose(); release();
  assert.equal((await first).code, 'CLAUDE_BROWSER_SESSION_ENDED');
  assert.equal((await next).code, 'CLAUDE_BROWSER_SESSION_ENDED');
  assert.equal(f.calls.filter(call => ['rest', 'mcp'].includes(call.kind)).length, 0);
});

test('shutdown during registration cannot leave a usable session', async t => {
  const f = await fixture(t);
  let release, started;
  const reached = new Promise(resolve => started = resolve);
  const gate = new Promise(resolve => release = resolve);
  const original = f.service.snapshot;
  f.service.snapshot = async () => { started(); await gate; return original(); };
  const creating = f.create().catch(error => error);
  await reached; await f.broker.shutdown(); release();
  assert.equal((await creating).code, 'CLAUDE_BROWSER_SESSION_ENDED');
  assert.equal(f.broker.sessions.size, 0);
});

test('copied physical stdio client completes MCP initialization, listing and browser operation', async t => {
  const f = await fixture(t), binding = await f.create();
  const child = spawn(binding.mcpServer.command, binding.mcpServer.args, { env: { PATH: process.env.PATH, NODE_USE_ENV_PROXY: '1', HTTP_PROXY: 'http://127.0.0.1:1', HTTPS_PROXY: 'http://127.0.0.1:1', NO_PROXY: '', ...binding.environment }, stdio: ['pipe', 'pipe', 'pipe'] });
  t.after(() => child.kill());
  let stdout = '', stderr = ''; child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', value => stdout += value); child.stderr.on('data', value => stderr += value);
  const exited = new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', (code, signal) => resolve({ code, signal })); });
  const requests = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'fixture', version: '1' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    { ...rpc('browser_navigate', { url: 'https://example.test/protocol' }), id: 3 },
    { ...rpc('browser_click', { selector: '#ok', profileId: 'other' }), id: 4 },
  ];
  child.stdin.end(requests.map(item => JSON.stringify(item)).join('\n') + '\n');
  assert.deepEqual(await exited, { code: 0, signal: null }, stderr);
  const replies = stdout.trim().split('\n').map(line => JSON.parse(line));
  assert.deepEqual(replies.map(item => item.id), [1, 2, 3, 4]);
  assert.equal(replies[0].result.protocolVersion, '2025-11-25');
  assert.deepEqual(replies[1].result.tools.map(tool => tool.name), BROWSER_TOOLS.map(tool => tool.name));
  assert.equal(replies[2].result.isError, undefined); assert.equal(replies[3].result.isError, true);
  assert.ok(!stdout.includes(seed.proxy.password)); assert.equal(stderr, '');
});

test('context identity ignores profile ownership but keeps route generations and confirmed context', () => {
  const other = clone(seed); other.id = 'other'; other.managedRoute.profileId = 'other';
  assert.equal(browserRouteSignature(seed), browserRouteSignature(other));
  assert.equal(browserContextSignature(seed), browserContextSignature(other));
  other.managedRoute.coreGeneration = 'changed';
  assert.notEqual(browserRouteSignature(seed), browserRouteSignature(other));
});

test('route identity accepts normalized terminal proxy fields while retaining all routing credentials', async t => {
  const f = await fixture(t);
  for (const context of f.contexts.values()) context.proxy.region = '';
  const normalized = clone(f.contexts.get('prof_a')); delete normalized.proxy.region;
  const binding = await f.broker.createSession({ sessionId: 'term_normalized', profileId: 'prof_a', browserProfileId: 'prof_b', context: normalized });
  assert.equal((await send(binding, rpc('browser_status'))).result.isError, undefined);
  const alternate = clone(normalized); alternate.proxy.type = alternate.proxy.protocol; delete alternate.proxy.protocol;
  assert.equal(browserRouteSignature(alternate), browserRouteSignature(normalized));
  alternate.proxy.password = 'another-password';
  assert.notEqual(browserRouteSignature(alternate), browserRouteSignature(normalized));
});
