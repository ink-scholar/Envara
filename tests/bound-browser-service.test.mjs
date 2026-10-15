import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { BrowseForgeService } from '../electron/browseforge-service.mjs';
import { BrowseForgeClient } from '../electron/browseforge-client.mjs';

async function fixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'envara-bound-browser-'));
  const state = { sessions: [], requests: [], generation: 0, endpointUnavailable: false, healthFailure: false,
    profile: { id: 'prof_a', name: 'Browser A', runtime_id: 'cloakbrowser', managed_proxy_required: true },
    context: { id: 'prof_a', profileId: 'prof_a', proxyId: 'proxy_a', proxy: { protocol: 'http', host: '127.0.0.1', port: 18452, username: 'test-user', password: 'test-password' },
      timezone: 'Asia/Manila', locale: 'en-PH', geolocation: { latitude: 14.6, longitude: 121, accuracy: 1000 }, network: { ok: true, ip: '203.0.113.8' }, privacy: { mode: 'standard' }, managedProxy: true } };
  const client = {
    async request(method, route, body) {
      state.requests.push({ method, route, body });
      if (route === '/api/profiles') return { data: [structuredClone(state.profile)] };
      if (route === '/api/groups') return { data: [] };
      if (route === '/api/runtimes') return { data: [{ id: 'cloakbrowser' }] };
      if (route === '/api/sessions' && method === 'GET') return { data: structuredClone(state.sessions) };
      if (route === '/api/sessions' && method === 'POST') {
        state.generation++;
        const session = { profile_id: body.profile_id, session_id: 'sess_' + body.profile_id, runtime_id: 'cloakbrowser' };
        state.sessions.push(session); return { data: structuredClone(session) };
      }
      if (route === '/api/playwright/endpoint') {
        if (state.endpointUnavailable) throw new Error('endpoint unavailable');
        return { data: state.sessions.map(session => ({ ...session, endpoint: `ws://127.0.0.1:18460/${state.generation}` })) };
      }
      if (route.endsWith('/eval')) { if (state.healthFailure) throw new Error('Target page has been closed'); return { data: { timezone: state.context.timezone } }; }
      if (route.endsWith('/focus')) return { data: 'ok' };
      if (method === 'DELETE' && route.startsWith('/api/sessions/')) { state.sessions = []; return { data: 'closed' }; }
      throw new Error('Unexpected fixture route');
    },
    async callMcpTool(name, args) { state.requests.push({ mcp: name, args }); return { content: [{ type: 'text', text: 'done' }] }; },
  };
  const service = new BrowseForgeService(directory, client, {}, () => {}, { shutdown: async () => {} });
  await service.ready;
  service.resolveWorkspaceContext = async () => structuredClone(state.context);
  service.engines = async () => [{ id: 'cloakbrowser', enabled: true, installed: true }];
  service.capture = async () => {};
  t.after(async () => { await service.shutdown(); await rm(directory, { recursive: true, force: true }); });
  return { service, state };
}

test('bound browser starts through the existing lifecycle and reuses only its launch receipt', async t => {
  const { service, state } = await fixture(t);
  const browser = await service.ensureBoundBrowser({ profileId: 'prof_a', expectedContext: structuredClone(state.context) });
  assert.deepEqual(browser, { session_id: 'sess_prof_a', profile_id: 'prof_a' });
  assert.equal(state.requests.filter(item => item.method === 'POST' && item.route === '/api/sessions').length, 1);
  assert.deepEqual((await service.ensureBoundBrowser({ profileId: 'prof_a', expectedContext: state.context })), browser);
  assert.equal(state.generation, 1);
  assert.equal(JSON.stringify(browser).includes('endpoint'), false);
  assert.equal(JSON.stringify(browser).includes('test-password'), false);
  const receipt = service.browserLaunchReceipts.get('prof_a');
  assert.equal(receipt.context.timezone, 'Asia/Manila');
  assert.equal(receipt.context.network.ip, '203.0.113.8');
  assert.equal(receipt.endpoint.startsWith('ws:'), false);
});

test('an already-running browser with no owned launch receipt is not adopted', async t => {
  const { service, state } = await fixture(t);
  state.sessions.push({ profile_id: 'prof_a', session_id: 'sess_prof_a', runtime_id: 'cloakbrowser' });
  await assert.rejects(service.ensureBoundBrowser({ profileId: 'prof_a', expectedContext: state.context }), { code: 'CLAUDE_BROWSER_ROUTE_UNVERIFIED' });
  assert.equal(state.requests.some(item => item.method === 'POST' && item.route === '/api/sessions'), false);
});

test('route, location and timezone changes cannot reuse an earlier browser launch', async t => {
  const { service, state } = await fixture(t);
  const original = structuredClone(state.context);
  await service.ensureBoundBrowser({ profileId: 'prof_a', expectedContext: original });
  for (const update of [
    context => { context.proxy.password = 'changed'; },
    context => { context.timezone = 'Asia/Tokyo'; },
    context => { context.geolocation.latitude = 35; },
    context => { context.privacy.mode = 'strict'; },
  ]) {
    state.context = structuredClone(original); update(state.context);
    await assert.rejects(service.ensureBoundBrowser({ profileId: 'prof_a', expectedContext: original }), { code: 'CLAUDE_BROWSER_BINDING_CHANGED' });
    await assert.rejects(service.ensureBoundBrowser({ profileId: 'prof_a', expectedContext: state.context }), { code: 'CLAUDE_BROWSER_ROUTE_UNVERIFIED' });
  }
});

test('foreign restart with the same deterministic session id is rejected by its unique Bind endpoint', async t => {
  const { service, state } = await fixture(t);
  await service.ensureBoundBrowser({ profileId: 'prof_a', expectedContext: state.context });
  state.generation++;
  await assert.rejects(service.ensureBoundBrowser({ profileId: 'prof_a', expectedContext: state.context }), { code: 'CLAUDE_BROWSER_ROUTE_UNVERIFIED' });
});

test('a profile changed outside the manager cannot reuse its former launch receipt', async t => {
  const { service, state } = await fixture(t);
  await service.ensureBoundBrowser({ profileId: 'prof_a', expectedContext: state.context });
  state.profile.fingerprint_seed = 91823;
  await assert.rejects(service.ensureBoundBrowser({ profileId: 'prof_a', expectedContext: state.context }), { code: 'CLAUDE_BROWSER_ROUTE_UNVERIFIED' });
});

test('an existing backend session with an unhealthy page is not promoted by POST session reuse', async t => {
  const { service, state } = await fixture(t);
  state.sessions.push({ profile_id: 'prof_a', session_id: 'sess_prof_a', runtime_id: 'cloakbrowser' });
  state.healthFailure = true;
  await service.startProfile({ id: 'prof_a' });
  assert.equal(service.browserLaunchReceipts.has('prof_a'), false);
});

test('receipt failure does not break an ordinary launch but cannot enable bound automation', async t => {
  const { service, state } = await fixture(t);
  state.endpointUnavailable = true;
  await service.startProfile({ id: 'prof_a' });
  assert.equal(state.sessions.length, 1);
  assert.equal(service.browserLaunchReceipts.has('prof_a'), false);
  await assert.rejects(service.ensureBoundBrowser({ profileId: 'prof_a', expectedContext: state.context }), { code: 'CLAUDE_BROWSER_ROUTE_UNVERIFIED' });
});

test('bound page tools override the profile, exclude alternate sessions and forbid global tools', async t => {
  const { service, state } = await fixture(t);
  await service.ensureBoundBrowser({ profileId: 'prof_a', expectedContext: state.context });
  assert.deepEqual(await service.callBoundBrowserTool('prof_a', 'form_fill', { profile_id: 'prof_other', fields: [{ selector: '#name', text: 'Example', clear: true }] }), { content: [{ type: 'text', text: 'done' }] });
  assert.equal(state.requests.at(-1).args.profile_id, 'prof_a');
  for (const name of ['create_profile', 'open_browser', 'web_search', 'create_session', 'evaluate', 'run_workflow', 'constructor']) {
    await assert.rejects(service.callBoundBrowserTool('prof_a', name, {}), { code: 'CLAUDE_BROWSER_UNKNOWN_TOOL' });
  }
  for (const [name, args] of [
    ['list_tabs', { session_id: 'another-session' }],
    ['form_fill', { fields: [{ selector: '#name', text: 'x', session_id: 'another-session' }] }],
    ['switch_tab', { index: '0' }],
    ['new_tab', { url: 'file:///etc/passwd' }],
  ]) await assert.rejects(service.callBoundBrowserTool('prof_a', name, args));
  await service.stopProfile({ id: 'prof_a' });
  assert.equal(service.browserLaunchReceipts.has('prof_a'), false);
  await assert.rejects(service.callBoundBrowserTool('prof_a', 'list_tabs', {}), { code: 'CLAUDE_BROWSER_ROUTE_UNVERIFIED' });
});

test('private MCP transport authenticates and preserves result while REST cannot access its endpoint', async () => {
  const seen = [];
  const client = new BrowseForgeClient({ token: 'private-sidecar-token', fetchImpl: async (url, options) => {
    const rpc = JSON.parse(options.body); seen.push({ url, options, rpc });
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: { content: [{ type: 'text', text: 'done' }] } }));
  } });
  const result = await client.callMcpTool('list_tabs', { profile_id: 'prof_a' });
  assert.deepEqual(result, { content: [{ type: 'text', text: 'done' }] });
  assert.equal(seen[0].url, 'http://127.0.0.1:19280/mcp');
  assert.equal(seen[0].options.headers.get('Authorization'), 'Bearer private-sidecar-token');
  assert.equal(seen[0].options.redirect, 'error');
  assert.deepEqual(seen[0].rpc.params, { name: 'list_tabs', arguments: { profile_id: 'prof_a' } });
  await assert.rejects(client.request('POST', '/mcp', {}), TypeError);
});

test('malformed MCP responses and errors cannot echo private diagnostics to the terminal', async () => {
  for (const payload of [{ jsonrpc: '2.0', id: 'wrong', result: {} }, { error: { code: -32000, message: 'private-sidecar-token' } }]) {
    const client = new BrowseForgeClient({ token: 'private-sidecar-token', fetchImpl: async (_url, options) => {
      const rpc = JSON.parse(options.body);
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, ...payload }));
    } });
    await assert.rejects(client.callMcpTool('list_tabs', { profile_id: 'prof_a' }), error => !error.message.includes('private-sidecar-token'));
  }
});
