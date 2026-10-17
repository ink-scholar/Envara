import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { BrowseForgeService } from '../electron/browseforge-service.mjs';
import { LinkRouter } from '../electron/link-router.mjs';

const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const routeDigest = proxy => {
  const digest = createHash('sha256').update('envara-browser-route-v1\0');
  for (const field of [proxy.protocol.toLowerCase(), proxy.host.replace(/^\[|\]$/g, '').replace(/[A-Z]/g, letter => letter.toLowerCase()), String(proxy.port), proxy.username ?? '', proxy.password ?? '']) digest.update(`${Buffer.byteLength(field)}:`).update(field);
  return digest.digest('hex');
};
async function fixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'envara-link-route-'));
  const proxy = { id: 'node_a', name: 'Owned fixture A', protocol: 'http', host: '127.0.0.1', port: 18452, username: 'fixture-user', password: 'fixture-password', region: '' };
  const state = { profiles: ['source', 'target'].map(id => ({ id, name: id, group: 'group_a', runtime_id: 'cloakbrowser' })), proxies: [proxy],
    sessions: [], identities: new Map(), generation: 0, requests: [], navigations: [], hooks: {} };
  const client = { async request(method, route, body) {
    state.requests.push({ method, route, body: structuredClone(body) });
    if (route === '/api/profiles') return { data: structuredClone(state.profiles) };
    if (route === '/api/groups') return { data: [] };
    if (route === '/api/runtimes') return { data: [{ id: 'cloakbrowser' }] };
    if (route === '/api/sessions' && method === 'GET') return { data: structuredClone(state.sessions) };
    if (route === '/api/sessions' && method === 'POST') {
      const instance_id = (++state.generation).toString(16).padStart(32, '0');
      const session = { profile_id: body.profile_id, session_id: `sess_${body.profile_id}`, runtime_id: 'cloakbrowser', instance_id };
      const actualProxy = await state.hooks.launchProxy?.() ?? state.proxies[0];
      state.sessions.push(session); state.identities.set(session.session_id, { instance_id, route_digest: routeDigest(actualProxy) });
      return { data: structuredClone(session) };
    }
    if (route === '/api/playwright/endpoint') return { data: state.sessions.map(session => ({ ...session, endpoint: `ws://127.0.0.1:18460/${session.instance_id}` })) };
    const match = route.match(/^\/api\/sessions\/([^/]+)(?:\/(.+))?$/);
    if (match?.[2] === 'identity') return { data: structuredClone(state.identities.get(match[1])) };
    if (match?.[2] === 'eval') return { data: {} };
    if (match?.[2] === 'open-link') {
      await state.hooks.beforeOpen?.();
      const actual = state.identities.get(match[1]);
      if (actual?.instance_id !== body.instance_id || actual?.route_digest !== body.route_digest) throw Object.assign(new Error('Selected browser changed'), { code: 'LINK_BROWSER_CHANGED' });
      state.navigations.push({ url: body.url, ...actual }); return { data: { opened: 'tab' } };
    }
    if (match && method === 'DELETE') { state.sessions = state.sessions.filter(session => session.session_id !== match[1]); state.identities.delete(match[1]); return { data: 'closed' }; }
    throw new Error(`Unexpected fixture request ${method} ${route}`);
  } };
  const service = new BrowseForgeService(directory, client, {}, () => {}, { shutdown: async () => {} });
  await service.ready;
  await service.store.transaction(next => { next.proxies = structuredClone(state.proxies); next.profiles = state.profiles.map(p => ({ id: p.id, proxyId: 'node_a' })); });
  service.engines = async () => [{ id: 'cloakbrowser', installed: true, enabled: true }];
  service.capture = async () => {};
  service.resolveWorkspaceContext = async id => ({ id, profileId: id, proxyId: 'node_a', proxy: structuredClone(state.proxies[0]), managedProxy: false,
    timezone: 'Asia/Manila', locale: 'en-PH', privacy: { mode: 'standard' }, network: { ok: true } });
  service.snapshot = async () => ({ profiles: state.profiles.map(p => ({ ...structuredClone(p), proxyId: 'node_a' })), proxies: structuredClone(state.proxies) });
  t.after(async () => { await service.shutdown(); await rm(directory, { recursive: true, force: true }); });
  const selected = () => service.snapshot().then(snapshot => service.linkNetworkSelection(snapshot.profiles[0], snapshot));
  return { service, state, selected, proxy };
}

test('links bind to a verified actual launch and use its production new-tab endpoint', async t => {
  const { service, state, selected } = await fixture(t);
  const result = await service.openProfileLink({ id: 'target', sourceProfileId: 'source', expectedNetwork: await selected(), url: 'https://example.test/path' });
  assert.equal(result.opened, 'tab'); assert.equal(state.navigations.length, 1);
  const request = state.requests.find(item => item.route.endsWith('/open-link'));
  assert.match(request.body.instance_id, /^[a-f0-9]{32}$/); assert.match(request.body.route_digest, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(result).includes('route_digest'), false);
  assert.equal(JSON.stringify(result).includes('fixture-password'), false);
  assert.equal(state.requests.some(item => item.route.endsWith('/navigate') || item.body?.script?.includes('window.open')), false);
});

for (const change of ['destination-group', 'source-group', 'same-node-credentials']) test(`a queued link refuses ${change} changes instead of following another route`, async t => {
  const { service, state, selected } = await fixture(t);
  const expectedNetwork = await selected(), held = deferred(), started = deferred();
  const mutation = service.serializeMutation(async () => { started.resolve(); await held.promise; });
  await started.promise;
  const opening = service.openProfileLink({ id: 'target', sourceProfileId: 'source', expectedNetwork, url: 'https://example.test/' });
  if (change === 'same-node-credentials') {
    state.proxies[0].password = 'changed-fixture-password';
    await service.store.transaction(next => { next.proxies[0].password = state.proxies[0].password; });
  } else state.profiles.find(profile => profile.id === (change === 'source-group' ? 'source' : 'target')).group = 'different-group';
  held.resolve(); await mutation;
  await assert.rejects(opening, { code: 'LINK_BROWSER_CHANGED' });
  assert.equal(state.navigations.length, 0);
});

test('a transient external profile change cannot mint a receipt for a different actual launch route', async t => {
  const { service, state, selected, proxy } = await fixture(t);
  state.hooks.launchProxy = async () => ({ ...proxy, port: 18453 });
  await assert.rejects(service.openProfileLink({ id: 'target', sourceProfileId: 'source', expectedNetwork: await selected(), url: 'https://example.test/' }), { code: 'CLAUDE_BROWSER_ROUTE_UNVERIFIED' });
  assert.equal(service.browserLaunchReceipts.has('target'), false); assert.equal(state.navigations.length, 0);
});

for (const changedId of ['source', 'target']) test(`a ${changedId} node-ID change during launch is refused even when both endpoints match`, async t => {
  const { service, state, selected, proxy } = await fixture(t);
  state.hooks.launchProxy = async () => {
    await service.store.transaction(next => {
      next.proxies.push({ ...proxy, id: 'node_identical' });
      next.profiles.find(profile => profile.id === changedId).proxyId = 'node_identical';
    });
    return proxy;
  };
  await assert.rejects(service.openProfileLink({ id: 'target', sourceProfileId: 'source', expectedNetwork: await selected(), url: 'https://example.test/' }), { code: 'LINK_BROWSER_CHANGED' });
  assert.equal(state.navigations.length, 0);
});

test('replacing a session after route validation cannot receive the pending URL', async t => {
  const { service, state, selected } = await fixture(t);
  state.hooks.beforeOpen = async () => {
    const session = state.sessions[0]; session.instance_id = 'f'.repeat(32);
    state.identities.get(session.session_id).instance_id = session.instance_id;
  };
  await assert.rejects(service.openProfileLink({ id: 'target', sourceProfileId: 'source', expectedNetwork: await selected(), url: 'https://example.test/' }), { code: 'LINK_BROWSER_CHANGED' });
  assert.equal(state.navigations.length, 0);
});

test('Stop and unrelated configuration changes do not wait for link navigation', async t => {
  const { service, state, selected } = await fixture(t);
  const entered = deferred(), release = deferred();
  state.hooks.beforeOpen = async () => { entered.resolve(); await release.promise; };
  const opening = service.openProfileLink({ id: 'target', sourceProfileId: 'source', expectedNetwork: await selected(), url: 'https://example.test/' });
  // Attach the rejection handler before Stop can make the pending request fail.
  const outcome = opening.catch(error => error);
  await entered.promise;
  await Promise.race([service.call('stopProfile', { id: 'target' }), new Promise((_, reject) => setTimeout(() => reject(new Error('Stop blocked behind navigation')), 1000))]);
  await service.serializeMutation(() => service.saveSettings({ settings: { language: 'en' } }));
  release.resolve();
  assert.equal((await outcome).code, 'LINK_BROWSER_CHANGED'); assert.equal(state.navigations.length, 0);
});

test('the asynchronous router supplies source selection evidence and reports refusal without host fallback', async t => {
  const { service, state } = await fixture(t);
  const held = deferred(), entered = deferred(), notifications = [];
  const mutation = service.serializeMutation(async () => { entered.resolve(); await held.promise; });
  await entered.promise;
  const router = new LinkRouter({ service, terminal: { linkBrowser: () => 'target' }, notify: item => notifications.push(item), openDefault: async () => assert.fail('must not fall back to host') });
  assert.equal((await router.openFromProfile({ profileId: 'source', url: 'https://example.test/' })).profileId, 'target');
  state.profiles[1].group = 'different-group'; held.resolve(); await mutation; await router.settled();
  assert.equal(notifications.at(-1).type, 'error'); assert.equal(state.navigations.length, 0);
});

test('production browser identity matches the Go UTF-8 contract without Unicode host folding', async t => {
  // Fixed vectors also live in browser/session_link_test.go. The backend stub
  // supplies those bytes directly so this exercises the production digest.
  const vectors = [
    { host: 'İ.example', digest: '8717aaa6eea033aa60d3b39da990d4988be7004e4ab2e6147fe33e580250f6c1', differentHost: 'i\u0307.example' },
    { host: 'ΟΣ.example', digest: 'a55ae542bbdebc738c2b55cfa0673ac044de5d232c01f111f90d952777233a31', differentHost: 'ος.example' },
    { host: 'PrOxY.ExAmPlE', digest: '7ba9b565cc608c5a4f81de2eea67118c9be06b88011ce600f12b59acd21f3916', equivalentHost: 'proxy.example' },
    { host: '[::1]', digest: '49d4611f53592b564b206536260bc34acefc60f0dfec2009cec008d4c7ff0496', equivalentHost: '::1' },
    { host: '[::1]', username: 'fixture-用户名', password: 'a:<>&\u2028', digest: 'd8bb7ea0644b32b8520f0a82447b41a1170edd0782fe47792ea72a97366944f9' },
  ];
  for (const vector of vectors) await t.test(vector.host + (vector.username ? ' Unicode credentials' : ''), async () => {
    const proxy = { protocol: 'HTTP', host: vector.host, port: 18452,
      username: vector.username ?? 'fixture-user', password: vector.password ?? 'fixture-password' };
    const before = structuredClone(proxy), instance_id = 'a'.repeat(32), session = { session_id: 'sess_vector', instance_id };
    const identity = { instance_id, route_digest: vector.digest };
    const service = { request: async (method, route) => {
      assert.equal(method, 'GET'); assert.equal(route, '/api/sessions/sess_vector/identity');
      return { data: identity };
    } };
    const verify = selected => BrowseForgeService.prototype.browserSessionIdentity.call(service, session, { proxy: selected });
    assert.deepEqual(await verify(proxy), identity);
    assert.equal(routeDigest(proxy), vector.digest);
    assert.deepEqual(proxy, before, 'digest verification must not rewrite the actual proxy host');
    if (vector.equivalentHost) assert.deepEqual(await verify({ ...proxy, host: vector.equivalentHost }), identity);
    if (vector.differentHost) await assert.rejects(verify({ ...proxy, host: vector.differentHost }), { code: 'CLAUDE_BROWSER_ROUTE_UNVERIFIED' });
  });
});
