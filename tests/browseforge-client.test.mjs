import assert from 'node:assert/strict';
import { once } from 'node:events';
import http from 'node:http';
import test from 'node:test';
import { BrowseForgeApiError, BrowseForgeClient } from '../electron/browseforge-client.mjs';

async function serverFixture(t, handler) {
  const server = http.createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => {
    server.close(resolve);
    server.closeAllConnections();
  }));
  return `http://127.0.0.1:${server.address().port}`;
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks);
}

test('uses exact REST envelopes and bearer authentication for profile CRUD and provider capabilities', async (t) => {
  const requests = [];
  const baseUrl = await serverFixture(t, async (request, response) => {
    requests.push({ method: request.method, url: request.url, auth: request.headers.authorization, type: request.headers['content-type'], body: await readBody(request) });
    response.setHeader('Content-Type', 'application/json');
    if (request.method === 'POST') {
      response.writeHead(201).end(JSON.stringify({ data: { ...JSON.parse(requests.at(-1).body), id: 'prof_local' } }));
    } else {
      response.end(JSON.stringify({ data: [{ id: 'camoufox', family: 'firefox', enabled: false, capabilities: { supports_seed_fingerprint: false } }], default_runtime_id: 'camoufox' }));
    }
  });
  const client = new BrowseForgeClient({ baseUrl, token: 'local-test-token' });
  const created = await client.createProfile({ name: '测试环境', runtime_id: 'camoufox' });
  assert.equal(created.data.name, '测试环境');
  assert.equal(created.data.runtime_id, 'camoufox');
  const runtimes = await client.listRuntimes();
  assert.equal(runtimes.default_runtime_id, 'camoufox');
  assert.equal(runtimes.data[0].enabled, false);
  assert.equal(runtimes.data[0].installed, undefined);
  assert.deepEqual(requests.map(({ method, url, auth }) => ({ method, url, auth })), [
    { method: 'POST', url: '/api/profiles', auth: 'Bearer local-test-token' },
    { method: 'GET', url: '/api/runtimes', auth: 'Bearer local-test-token' },
  ]);
  assert.equal(requests[0].type, 'application/json');
  assert.equal(requests[1].type, undefined);
});

test('preserves error codes and actionable fields while redacting echoed auth and passwords', async () => {
  const client = new BrowseForgeClient({
    token: 'opaque-private-token',
    fetchImpl: async () => new Response(JSON.stringify({ error: {
      code: 'GROUP_HAS_ACTIVE_SESSIONS', message: 'opaque-private-token secret-password',
      active_sessions: 2, restart_required: true, password: 'secret-password',
    } }), { status: 409 }),
  });
  await assert.rejects(client.request('PUT', '/api/groups/team', { proxy: { password: 'secret-password' } }), (error) => {
    assert.ok(error instanceof BrowseForgeApiError);
    assert.equal(error.status, 409);
    assert.equal(error.code, 'GROUP_HAS_ACTIVE_SESSIONS');
    assert.equal(error.details.active_sessions, 2);
    assert.equal(error.details.restart_required, true);
    assert.equal(error.details.password, '[redacted]');
    assert.equal(error.message, '[redacted] [redacted]');
    assert.equal(JSON.stringify(error).includes('secret-password'), false);
    return true;
  });
});

test('returns screenshot and export bytes and uploads ZIP import as multipart file', async (t) => {
  const png = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const zip = Buffer.from([80, 75, 3, 4, 0, 1, 2]);
  const requests = [];
  const baseUrl = await serverFixture(t, async (request, response) => {
    const body = await readBody(request);
    requests.push({ url: request.url, method: request.method, type: request.headers['content-type'], body });
    if (request.url.includes('screenshot')) response.writeHead(200, { 'Content-Type': 'image/png' }).end(png);
    else if (request.url.endsWith('/export')) response.writeHead(200, { 'Content-Type': 'application/zip' }).end(zip);
    else response.writeHead(201, { 'Content-Type': 'application/json' }).end(JSON.stringify({ data: { id: 'prof_imported' } }));
  });
  const client = new BrowseForgeClient({ baseUrl });
  assert.deepEqual(await client.screenshot('sess_prof_one', { fullPage: true }), png);
  assert.deepEqual(await client.exportProfile('prof_one'), zip);
  assert.equal((await client.importProfile(zip, 'profile.zip')).data.id, 'prof_imported');
  assert.equal(requests[0].url, '/api/sessions/sess_prof_one/screenshot?full_page=true');
  assert.equal(requests[1].method, 'POST');
  assert.match(requests[2].type, /^multipart\/form-data; boundary=/);
  assert.match(requests[2].body.toString('latin1'), /name="file"; filename="profile.zip"/);
  assert.ok(requests[2].body.includes(zip));
});

test('resolves restarted sidecar URL and token on each request and encodes group and tag filters', async () => {
  const observed = [];
  let baseUrl = 'http://127.0.0.1:19281';
  let token = 'first-token';
  const client = new BrowseForgeClient({
    baseUrl: () => baseUrl, token: () => token,
    fetchImpl: async (url, options) => {
      observed.push({ url, auth: options.headers.get('Authorization'), redirect: options.redirect });
      return new Response('{"data":null,"total":0}');
    },
  });
  assert.deepEqual(await client.listProfiles({ group: '工作 / A', tag: '标签&1' }), { data: null, total: 0 });
  baseUrl = 'http://[::1]:19282';
  token = 'second-token';
  await client.listGroups();
  assert.equal(new URL(observed[0].url).searchParams.get('group'), '工作 / A');
  assert.equal(new URL(observed[0].url).searchParams.get('tag'), '标签&1');
  assert.equal(observed[1].url, 'http://[::1]:19282/api/groups');
  assert.deepEqual(observed.map(({ auth, redirect }) => ({ auth, redirect })), [
    { auth: 'Bearer first-token', redirect: 'error' }, { auth: 'Bearer second-token', redirect: 'error' },
  ]);
});

test('rejects nonlocal targets, URL credentials and paths outside the API before sending tokens', async () => {
  for (const baseUrl of ['https://example.com', 'http://127.0.0.1/path', 'http://user:secret@localhost:19280', 'file:///tmp/service']) {
    assert.throws(() => new BrowseForgeClient({ baseUrl }), /loopback/);
  }
  let requests = 0;
  const client = new BrowseForgeClient({ fetchImpl: async () => { requests += 1; return new Response('{}'); } });
  for (const path of ['https://example.com/api/profiles', '//example.com/api/profiles', '/api/../../profiles', '/api/profiles#token', '/api/\\example.com']) {
    await assert.rejects(client.request('GET', path), TypeError);
  }
  assert.equal(requests, 0);
});

test('a redirect is not followed and mutations are never retried', async (t) => {
  let requests = 0;
  const baseUrl = await serverFixture(t, (request, response) => {
    requests += 1;
    response.writeHead(302, { Location: 'https://example.invalid/token-target' }).end();
  });
  const client = new BrowseForgeClient({ baseUrl, token: 'private-local-token' });
  await assert.rejects(client.createProfile({ name: '一次操作', runtime_id: 'camoufox' }), { code: 'SERVICE_UNAVAILABLE' });
  assert.equal(requests, 1);
});

test('timeout and cancellation abort the transport with distinct errors and no retries', async () => {
  let requests = 0;
  let aborted = 0;
  const fetchImpl = async (url, { signal }) => {
    requests += 1;
    return new Promise((resolve, reject) => {
      const fail = () => { aborted += 1; reject(new Error('aborted')); };
      if (signal.aborted) fail();
      else signal.addEventListener('abort', fail, { once: true });
    });
  };
  const client = new BrowseForgeClient({ fetchImpl, timeoutMs: 15 });
  await assert.rejects(client.request('POST', '/api/sessions', { profile_id: 'prof_one' }), { code: 'REQUEST_TIMEOUT' });
  const controller = new AbortController();
  const pending = client.listSessions({ signal: controller.signal, timeoutMs: 1000 });
  setTimeout(() => controller.abort(), 5);
  await assert.rejects(pending, { code: 'REQUEST_ABORTED' });
  assert.equal(requests, 2);
  assert.equal(aborted, 2);
});

test('distinguishes invalid JSON from an empty response and preserves binary HTTP errors', async () => {
  const replies = [new Response('not JSON'), new Response(null, { status: 204 }), new Response('{"error":{"code":"NOT_FOUND","message":"session missing"}}', { status: 404 })];
  const client = new BrowseForgeClient({ fetchImpl: async () => replies.shift() });
  await assert.rejects(client.health(), { code: 'INVALID_RESPONSE', status: 200 });
  assert.equal(await client.health(), null);
  await assert.rejects(client.screenshot('sess_missing'), { code: 'NOT_FOUND', status: 404 });
});

test('the request deadline also covers a stalled response body', async (t) => {
  let finish;
  const baseUrl = await serverFixture(t, (request, response) => {
    response.writeHead(200, { 'Content-Type': 'text/plain' });
    response.write('partial');
    finish = setTimeout(() => response.end(' done'), 200);
  });
  t.after(() => clearTimeout(finish));
  const client = new BrowseForgeClient({ baseUrl, timeoutMs: 20 });
  await assert.rejects(client.request('GET', '/api/status', undefined, { responseType: 'text' }), { code: 'REQUEST_TIMEOUT' });
});
