import test from 'node:test';
import assert from 'node:assert/strict';
import { MacOSApplicationRouting } from '../electron/macos-application-routing.mjs';
import { APPLICATION_ROUTING_CHECKS, applicationRoutingReady, publicApplicationRoutingStatus } from '../electron/application-routing.mjs';

const checks = Object.fromEntries(APPLICATION_ROUTING_CHECKS.map(key => [key, true]));
const verified = () => ({ installed: true, authorized: true, ready: true, capabilities: checks,
  verification: { passed: true, version: 'fixture/1', checks }, sessions: [] });
function adapters(state) {
  const calls = [];
  const native = { status: async () => state,
    resolveRealm: async params => { calls.push({ provider: 'native', method: 'resolveRealm', params }); return { vpnUUID: '11111111-2222-4333-8444-555555555555' }; },
    ...Object.fromEntries(['setup', 'prepareRoute', 'launch', 'stop', 'revoke', 'shutdown'].map(method => [method, async params => { calls.push({ provider: 'native', method, params }); return { provider: 'native', method }; }])) };
  const diagnostic = { status: async () => ({ ...verified(), sessions: [{ sessionId: 'diagnostic_only' }],
    component: { name: 'mitmproxy-redirector', version: '0.12.11', available: true, installed: true, verified: true, password: 'fixture-secret' } }),
    ...Object.fromEntries(['setup', 'prepareRoute', 'launch', 'stop', 'revoke', 'shutdown'].map(method => [method, async () => { calls.push({ provider: 'diagnostic', method }); }])) };
  return { calls, native, diagnostic };
}

test('authorized diagnostic provider cannot fill missing production gates or receive a launch', async () => {
  const state = { installed: false, authorized: false, ready: false, error: 'APPLICATION_ROUTING_UNAVAILABLE' };
  const fixtures = adapters(state), adapter = new MacOSApplicationRouting(fixtures);
  const result = await adapter.status();
  assert.equal(result.installed, false); assert.equal(result.authorized, false);
  assert.equal(result.sessions, undefined); assert.equal(applicationRoutingReady(result), false);
  const publicState = publicApplicationRoutingStatus(result, 'darwin');
  assert.equal(publicState.status, 'unavailable'); assert.equal(publicState.diagnosticComponent.installed, true);
  assert.equal(publicState.diagnosticComponent.authorized, true); assert.equal(publicState.diagnosticComponent.password, undefined);
  await assert.rejects(adapter.prepareRoute({ route: { password: 'fixture-private' } }), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
  await assert.rejects(adapter.launch({ routeId: 'fixture' }), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
  assert.deepEqual(fixtures.calls, []);
});

test('production launch rechecks the complete native receipt even with an authorized original component', async () => {
  for (const key of APPLICATION_ROUTING_CHECKS) {
    const state = verified(); state.verification = { ...state.verification, checks: { ...checks, [key]: false } };
    const fixtures = adapters(state), adapter = new MacOSApplicationRouting(fixtures);
    await assert.rejects(adapter.prepareRoute({}), { code: 'APPLICATION_ROUTING_NOT_READY' });
    await assert.rejects(adapter.launch({}), { code: 'APPLICATION_ROUTING_NOT_READY' });
    assert.deepEqual(fixtures.calls, []);
  }
});

test('setup, credentials, launch and cleanup remain assigned to the same production provider', async () => {
  const state = verified(), fixtures = adapters(state), adapter = new MacOSApplicationRouting(fixtures);
  const setup = { activate: true }, params = { application: { path: '/Applications/Fixture.app', executablePath: '/Applications/Fixture.app/Contents/MacOS/Fixture' },
    vpnUUID: 'untrusted-uuid', route: { password: 'fixture-private' } };
  await adapter.setup(setup); await adapter.prepareRoute(params); await adapter.launch({ routeId: 'fixture' });
  state.ready = false;
  // Cleanup must remain possible after the provider loses readiness.
  await adapter.stop({ sessionId: 'fixture' }); await adapter.revoke({ routeId: 'fixture' });
  assert.deepEqual(fixtures.calls.map(call => [call.provider, call.method]), [
    ['native', 'setup'], ['native', 'resolveRealm'], ['native', 'prepareRoute'], ['native', 'launch'], ['native', 'stop'], ['native', 'revoke'],
  ]);
  assert.equal(fixtures.calls[0].params, setup); assert.deepEqual(fixtures.calls[1].params, { application: params.application });
  assert.equal(fixtures.calls[2].params.vpnUUID, '11111111-2222-4333-8444-555555555555');
  assert.equal(fixtures.calls[2].params.route, params.route);
  await adapter.shutdown();
  assert.deepEqual(fixtures.calls.slice(-2).map(call => call.provider), ['native', 'diagnostic']);
  await assert.rejects(adapter.status(), { code: 'APPLICATION_ROUTING_CLOSED' });
});

test('missing or malformed native realm rejects before credentials reach route preparation', async () => {
  for (const result of [{}, { vpnUUID: 'invalid' }, { vpnUUID: null }]) {
    const fixtures = adapters(verified()); fixtures.native.resolveRealm = async () => result;
    await assert.rejects(new MacOSApplicationRouting(fixtures).prepareRoute({ route: { password: 'fixture-private' } }), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
    assert.deepEqual(fixtures.calls, []);
  }
  const fixtures = adapters(verified()); fixtures.native.resolveRealm = async () => { throw Object.assign(new Error('private details'), { code: 'APPLICATION_ROUTING_NOT_READY' }); };
  await assert.rejects(new MacOSApplicationRouting(fixtures).prepareRoute({}), { code: 'APPLICATION_ROUTING_NOT_READY' });
  assert.deepEqual(fixtures.calls, []);
});

test('diagnostic inspection failure cannot hide a ready native provider; primary failure cannot promote diagnostics', async () => {
  const fixtures = adapters(verified()); fixtures.diagnostic.status = async () => { throw new Error('private diagnostic error'); };
  assert.equal(applicationRoutingReady(await new MacOSApplicationRouting(fixtures).status()), true);
  fixtures.native.status = async () => { throw new Error('fixture-private'); };
  const state = await new MacOSApplicationRouting(fixtures).status();
  assert.equal(applicationRoutingReady(state), false); assert.equal(JSON.stringify(state).includes('fixture-private'), false);
});
