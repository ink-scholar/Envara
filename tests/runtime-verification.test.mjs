import test from 'node:test';
import assert from 'node:assert/strict';
import { RuntimeVerificationService, sanitizeRuntimeObservation } from '../electron/runtime-verification.mjs';

function fixture() {
  let time = 1_700_000_000_000;
  const state = { profileId: 'fixture', revision: 'configuration-one', available: true,
    expected: { locale: 'en-US', timezone: 'America/New_York', ip: '8.8.8.8' },
    sessionId: 'session_fixture', instanceId: 'a'.repeat(32), routeDigest: 'b'.repeat(64) };
  const requests = [];
  const browser = {
    async captureRuntimeVerificationContext(id, options) {
      assert.equal(id, 'fixture');
      return options?.verifyReceipt ? structuredClone(state) : { ...structuredClone(state), sessionId: undefined, routeDigest: undefined };
    },
    async request(...args) { requests.push(args); return { data: { locale: 'en-US', timezone: 'America/New_York', ip: '8.8.8.8', token: 'must-not-return', endpoint: 'http://secret.example' } }; },
  };
  const terminal = { sessions: new Map([['term_fixture', { profileId: 'fixture', sessionId: 'term_fixture', status: 'running',
    startedAt: new Date(time - 10000).toISOString(), timezone: 'America/New_York', language: 'en_US.UTF-8', networkFence: true,
    replay: 'PRIVATE TRANSCRIPT', launchContext: { proxy: { password: 'PRIVATE PASSWORD' } }, network: { ip: '8.8.8.8' } }]]) };
  return { service: new RuntimeVerificationService({ browserService: browser, terminalService: terminal, now: () => time }),
    state, browser, requests, terminal, advance(ms) { time += ms; } };
}
test('manual browser observation is pinned and terminal launch settings never claim live client verification', async () => {
  const f = fixture();
  assert.deepEqual(await f.service.runtimeVerificationSnapshot({}), { results: [], pending: [] });
  assert.equal(f.requests.length, 0);
  const result = await f.service.checkRuntimeVerification({ id: 'fixture' });
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0][1], '/api/sessions/session_fixture/runtime-verification');
  assert.deepEqual(Object.keys(f.requests[0][2]).sort(), ['instance_id', 'route_digest']);
  assert.equal(result.browser.status, 'observed');
  assert.deepEqual(result.browser.checks, { locale: 'match', timezone: 'match', ip: 'match' });
  assert.equal(result.terminal.status, 'unknown');
  assert.deepEqual(result.terminal.observed, { locale: null, timezone: null, ip: null });
  assert.equal(result.terminal.sessions[0].configurationMatches, true);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE|token|secret\.example|configuration-one|routeDigest|instanceId/);
  await f.service.runtimeVerificationSnapshot({ id: 'fixture' });
  assert.equal(f.requests.length, 1);
});
test('unverified or missing route cannot start an observation or report egress from main', async () => {
  const f = fixture(); f.state.available = false;
  const result = await f.service.checkRuntimeVerification({ id: 'fixture' });
  assert.equal(f.requests.length, 0);
  assert.equal(result.browser.status, 'unknown');
  assert.equal(result.browser.observed.ip, null);
  assert.equal(result.stale, true);
});
test('receipt failure cannot reuse snapshot-only route hints as authority', async () => {
  const f = fixture(); const capture = f.browser.captureRuntimeVerificationContext;
  f.browser.captureRuntimeVerificationContext = (id, options) => { if (options?.verifyReceipt) throw new Error('private route failed'); return capture(id, options); };
  const result = await f.service.checkRuntimeVerification({ id: 'fixture' });
  assert.equal(f.requests.length, 0); assert.equal(result.browser.status, 'unknown');
});
test('CORS or fetch failure leaves only document locale and timezone observed', async () => {
  const f = fixture(); f.browser.request = async () => ({ data: { locale: 'fr-FR', timezone: 'Europe/Paris', ip: null } });
  const result = await f.service.checkRuntimeVerification({ id: 'fixture' });
  assert.equal(result.browser.status, 'partial');
  assert.deepEqual(result.browser.checks, { locale: 'mismatch', timezone: 'mismatch', ip: 'unknown' });
});
test('unsupported background runtimes remain unknown with a fixed capability reason', async () => {
  const f = fixture(); f.browser.request = async () => { throw Object.assign(new Error('private runtime details'), { code: 'RUNTIME_VERIFICATION_UNSUPPORTED' }); };
  const result = await f.service.checkRuntimeVerification({ id: 'fixture' });
  assert.equal(result.browser.status, 'unknown'); assert.equal(result.browser.reason, 'unsupported-runtime');
  assert.doesNotMatch(JSON.stringify(result), /private runtime/);
});
test('changed configuration during the request invalidates the result; results also age', async () => {
  const f = fixture(); const request = f.browser.request;
  f.browser.request = async (...args) => { f.state.revision = 'changed'; return request(...args); };
  assert.equal((await f.service.checkRuntimeVerification({ id: 'fixture' })).staleReason, 'configuration');
  f.browser.request = request;
  await f.service.checkRuntimeVerification({ id: 'fixture' });
  f.advance(300_001);
  assert.equal((await f.service.runtimeVerificationSnapshot({ id: 'fixture' })).results[0].staleReason, 'age');
});
test('one profile check is deduplicated and invalid arguments cannot reach browser authority', async () => {
  const f = fixture(); let resolve;
  f.browser.request = () => new Promise(done => { resolve = done; });
  const first = f.service.checkRuntimeVerification({ id: 'fixture' });
  const second = f.service.checkRuntimeVerification({ id: 'fixture' });
  assert.equal(first, second);
  await new Promise(done => setImmediate(done));
  assert.deepEqual((await f.service.runtimeVerificationSnapshot({})).pending, ['fixture']);
  resolve({ data: {} }); await first;
  assert.throws(() => f.service.checkRuntimeVerification({ id: 'fixture', url: 'https://elsewhere.test/' }), /参数/);
  assert.throws(() => f.service.checkRuntimeVerification({ id: '../fixture' }), /参数/);
});
test('malformed browser replies cannot turn private addresses or payload text into evidence', () => {
  assert.deepEqual(sanitizeRuntimeObservation({ locale: 'en-US\nsecret', timezone: 'not-a-zone', ip: '127.0.0.1' }), { locale: null, timezone: null, ip: null });
});
