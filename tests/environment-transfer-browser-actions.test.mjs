import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import os from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { DesktopEnvironmentTransferLock } from '../electron/environment-import-lifecycle.mjs';
import { LinkRouter } from '../electron/link-router.mjs';
import { TerminalBrowserBroker } from '../electron/terminal-browser-broker.mjs';
import { requestBrowserBroker } from '../electron/terminal-browser-mcp.mjs';

// Own Unix IPC and in-memory backend only: no app, browser or personal data.
const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};
const rpc = (name, args = {}) => ({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
const backendCalls = calls => calls.filter(call => ['ensure', 'rest', 'mcp', 'link'].includes(call.kind));
const idle = lock => {
  assert.equal(lock.mutations, 0);
  assert.equal(lock.scopes.size, 0);
  assert.equal(lock.transferring, false);
};

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-transfer-browser-'));
  const lock = new DesktopEnvironmentTransferLock(), calls = [], notifications = [], hostLinks = [], errors = [];
  const hooks = {}, gates = [], pending = new Set();
  const track = promise => {
    pending.add(promise);
    promise.finally(() => pending.delete(promise)).catch(() => {});
    return promise;
  };
  const pause = (kind, options = {}) => {
    const gate = { entered: deferred(), release: deferred(), ...options };
    hooks[kind] = gate; gates.push(gate); return gate;
  };
  const block = async (kind, profileId) => {
    const gate = hooks[kind];
    if (!gate || gate.used || gate.profileId && gate.profileId !== profileId) return;
    gate.used = true; gate.entered.resolve();
    await gate.release.promise;
    if (gate.error) throw gate.error;
  };
  const profiles = ['prof_a', 'prof_b', 'prof_c'].map(id => ({ id, name: id, proxyId: 'node_fixture', group: 'same-network' }));
  const contexts = new Map(profiles.map(profile => [profile.id, {
    ...profile, proxy: { protocol: 'http', host: '127.0.0.1', port: 19321, username: 'fixture', password: 'synthetic-fixture' },
    timezone: 'Asia/Manila', locale: 'en-PH', privacy: { mode: 'standard' }, network: { ok: true, ip: '198.51.100.7' },
  }]));
  const service = {
    async snapshot() { await block('validation'); return { profiles: structuredClone(profiles), proxies: [] }; },
    async resolveWorkspaceContext(profileId) { return structuredClone(contexts.get(profileId)); },
    async ensureBoundBrowser({ profileId }) {
      calls.push({ kind: 'ensure', profileId }); await block('ensure', profileId);
      return { session_id: `session_${profileId}`, profile_id: profileId };
    },
    async request(method, endpoint) {
      const profileId = profiles.find(profile => endpoint.startsWith(`/api/sessions/session_${profile.id}/`))?.id;
      calls.push({ kind: 'rest', method, endpoint }); await block('rest', profileId);
      return { data: { success: true } };
    },
    async callBoundBrowserTool(profileId, name) {
      calls.push({ kind: 'mcp', profileId, name }); await block('mcp', profileId);
      return { content: [{ type: 'text', text: 'fixture action completed' }] };
    },
    async openProfileLink({ id, url }) {
      calls.push({ kind: 'link', profileId: id, url }); await block('link', id);
      return { opened: 'tab' };
    },
  };
  // The same reservation callback main injects; the destination browser owns it.
  const protectBrowserOperation = (profileId, operation) => lock.mutate('startProfile', { id: profileId }, operation, profileId);
  const broker = new TerminalBrowserBroker({ service, dataDir: root, nodeExecutable: process.execPath,
    protectBrowserOperation, onError: event => errors.push(event) });
  const router = new LinkRouter({ service, protectBrowserOperation,
    applications: { snapshot: async () => ({ applications: [] }) },
    terminal: { linkBrowser: profileId => profileId === 'prof_a' ? 'prof_b' : profileId },
    openDefault: async url => hostLinks.push(url), notify: event => notifications.push(event) });
  t.after(async () => {
    for (const gate of gates) gate.release.resolve();
    await Promise.allSettled([...pending]); await router.settled();
    await broker.shutdown(); await rm(root, { recursive: true, force: true });
  });
  const create = (browserProfileId = 'prof_b', sessionId = `terminal_${browserProfileId}`) =>
    broker.createSession({ sessionId, profileId: 'prof_a', browserProfileId, context: structuredClone(contexts.get('prof_a')) });
  const send = (binding, name, args) => track(requestBrowserBroker(rpc(name, args), {
    socketPath: binding.environment.ENVARA_BROWSER_SOCKET, token: binding.environment.ENVARA_BROWSER_TOKEN, timeoutMs: 5000,
  }));
  const holdExport = async profileId => {
    const gate = { entered: deferred(), release: deferred() }; gates.push(gate);
    const copying = track(lock.transfer(async () => { gate.entered.resolve(); await gate.release.promise; }, profileId));
    await gate.entered.promise;
    return async () => { gate.release.resolve(); await copying; };
  };
  return { lock, calls, contexts, errors, notifications, hostLinks, broker, router, create, send, pause, holdExport };
}

test('a link from A to exporting B is refused without a host fallback; C and a later B link still work', { timeout: 5000 }, async t => {
  const f = await fixture(t), finishExport = await f.holdExport('prof_b');
  const chosen = await f.router.openFromProfile({ profileId: 'prof_a', url: 'https://example.test/exported' });
  assert.equal(chosen.profileId, 'prof_b', 'the immediate decision names the intended browser, not the source');
  await f.router.settled();
  assert.deepEqual(backendCalls(f.calls), []);
  assert.deepEqual(f.hostLinks, []);
  assert.equal(f.notifications.at(-1).type, 'error');
  assert.equal(f.notifications.at(-1).profileId, 'prof_b');
  assert.ok(f.notifications.every(event => event.outside !== true));
  await f.router.openFromProfile({ profileId: 'prof_c', url: 'https://example.test/other' });
  await f.router.settled();
  assert.deepEqual(f.calls.map(call => call.profileId), ['prof_c']);
  await finishExport();
  await f.router.openFromProfile({ profileId: 'prof_a', url: 'https://example.test/retry' });
  await f.router.settled();
  assert.deepEqual(f.calls.map(call => call.profileId), ['prof_c', 'prof_b']);
  assert.deepEqual(f.hostLinks, []); idle(f.lock);
});

for (const fails of [false, true]) test(`an in-flight background link holds B until its ${fails ? 'failure' : 'completion'}`, { timeout: 5000 }, async t => {
  const f = await fixture(t);
  const gate = f.pause('link', { profileId: 'prof_b', ...(fails ? { error: new Error('owned fixture failure') } : {}) });
  await f.router.openFromProfile({ profileId: 'prof_a', url: 'https://example.test/pending' });
  await gate.entered.promise;
  await assert.rejects(f.lock.transfer(async () => 'must not export B', 'prof_b'), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  assert.equal(await f.lock.transfer(async () => 'A remains independent', 'prof_a'), 'A remains independent');
  gate.release.resolve(); await f.router.settled();
  assert.equal(f.notifications.at(-1).type, fails ? 'error' : 'link');
  assert.deepEqual(f.hostLinks, []);
  assert.equal(await f.lock.transfer(async () => 'B unlocked', 'prof_b'), 'B unlocked'); idle(f.lock);
});

test('exporting B refuses bound REST, MCP and open-link actions before launch while status and C remain usable', { timeout: 5000 }, async t => {
  const f = await fixture(t), binding = await f.create(), other = await f.create('prof_c');
  const finishExport = await f.holdExport('prof_b');
  for (const [name, args] of [['browser_navigate', { url: 'https://example.test/' }], ['browser_fill', { selector: '#name', value: 'fixture' }]]) {
    const reply = await f.send(binding, name, args);
    assert.equal(reply.result.isError, true);
  }
  await assert.rejects(binding.openLink('https://example.test/link'), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  assert.deepEqual(backendCalls(f.calls), []);
  const status = await f.send(binding, 'browser_status', {});
  assert.notEqual(status.result.isError, true);
  assert.match(status.result.content[0].text, /prof_b/);
  assert.deepEqual(backendCalls(f.calls), [], 'status cannot launch or mutate the browser');
  assert.notEqual((await f.send(other, 'browser_navigate', { url: 'https://example.test/other' })).result.isError, true);
  assert.ok(f.calls.every(call => call.kind === 'rest' ? call.endpoint.includes('session_prof_c') : call.profileId === 'prof_c'));
  await finishExport();
  assert.notEqual((await f.send(binding, 'browser_navigate', { url: 'https://example.test/retry' })).result.isError, true);
  idle(f.lock);
});

for (const [wire, tool, args] of [
  ['rest', 'browser_navigate', { url: 'https://example.test/full-action' }],
  ['mcp', 'browser_fill', { selector: '#name', value: 'fixture' }],
]) test(`the entire bound ${wire.toUpperCase()} action holds the destination through validation, startup and backend work`, { timeout: 5000 }, async t => {
  const f = await fixture(t), binding = await f.create(), other = await f.create('prof_c');
  const validating = f.pause('validation'), starting = f.pause('ensure', { profileId: 'prof_b' }), writing = f.pause(wire, { profileId: 'prof_b' });
  const action = f.send(binding, tool, args);
  await validating.entered.promise;
  await assert.rejects(f.lock.transfer(async () => {}, 'prof_b'), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  assert.deepEqual(backendCalls(f.calls), [], 'the reservation precedes the initial binding validation');
  validating.release.resolve(); await starting.entered.promise;
  await assert.rejects(f.lock.transfer(async () => {}, 'prof_b'), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  starting.release.resolve(); await writing.entered.promise;
  await assert.rejects(f.lock.transfer(async () => {}, 'prof_b'), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  assert.equal(await f.lock.transfer(async () => 'source is not the destination', 'prof_a'), 'source is not the destination');
  assert.notEqual((await f.send(other, 'browser_tabs', { action: 'list' })).result.isError, true);
  writing.release.resolve();
  assert.notEqual((await action).result.isError, true);
  assert.equal(await f.lock.transfer(async () => 'completed action released B', 'prof_b'), 'completed action released B'); idle(f.lock);
});

for (const failure of ['binding', 'rest', 'mcp']) test(`a ${failure} refusal releases the browser reservation for export and retry`, { timeout: 5000 }, async t => {
  const f = await fixture(t), binding = await f.create();
  if (failure === 'binding') f.contexts.get('prof_b').timezone = 'Europe/London';
  else {
    const gate = f.pause(failure, { profileId: 'prof_b', error: new Error('synthetic backend refusal') });
    gate.release.resolve();
  }
  const tool = failure === 'mcp' ? 'browser_fill' : 'browser_navigate';
  const args = failure === 'mcp' ? { selector: '#name', value: 'fixture' } : { url: 'https://example.test/refused' };
  assert.equal((await f.send(binding, tool, args)).result.isError, true);
  assert.equal(await f.lock.transfer(async () => 'failure released B', 'prof_b'), 'failure released B');
  if (failure === 'binding') f.contexts.get('prof_b').timezone = 'Asia/Manila';
  assert.notEqual((await f.send(binding, tool, args)).result.isError, true);
  idle(f.lock);
});

test('the authenticated asynchronous link endpoint cannot bypass an active destination export', { timeout: 5000 }, async t => {
  const f = await fixture(t), binding = await f.create(), finishExport = await f.holdExport('prof_b');
  const body = JSON.stringify({ url: 'https://example.test/oauth' });
  const reply = await new Promise((resolve, reject) => {
    const request = http.request({ socketPath: binding.environment.ENVARA_LINK_SOCKET, agent: false, path: '/link', method: 'POST',
      headers: { Authorization: `Bearer ${binding.environment.ENVARA_LINK_TOKEN}`, 'Content-Length': Buffer.byteLength(body) } }, response => {
      const chunks = []; response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: JSON.parse(Buffer.concat(chunks)) }));
    });
    request.setTimeout(3000, () => request.destroy(new Error('owned IPC deadline')));
    request.on('error', reject); request.end(body);
  });
  assert.equal(reply.status, 200); assert.equal(reply.body.profileId, 'prof_b');
  await Promise.allSettled([...f.broker.pending]);
  assert.deepEqual(backendCalls(f.calls), []);
  assert.equal(f.errors.at(-1).code, 'CLAUDE_BROWSER_LINK_FAILED');
  assert.deepEqual(f.hostLinks, []);
  await finishExport();
  assert.equal((await binding.openLink('https://example.test/retry')).profileId, 'prof_b'); idle(f.lock);
});
