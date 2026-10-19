import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveTerminalView, terminalViewSnapshot } from '../electron/terminal-view.mjs';
import { terminalNetworks } from '../src/link-browser.mjs';
import { CLAUDE_SESSION, sessionChoiceHost, sessionNetworks } from '../src/terminal-session-choice.mjs';

test('opening a view validates profile ownership and never silently attaches an unavailable session', () => {
  const workspace = { profiles: [{ id: 'prof_a', name: 'A' }, { id: 'prof_b', name: 'B' }] };
  const state = { profiles: [{ profileId: 'prof_a', sessions: [{ sessionId: 'term_a', status: 'running' }] }, { profileId: 'prof_b', sessions: [{ sessionId: 'term_b', status: 'running' }] }] };
  assert.deepEqual(resolveTerminalView({ id: 'prof_a' }, workspace, state), { profileId: 'prof_a', name: 'A', sessionId: 'term_a' });
  for (const sessionId of ['term_missing', 'term_b']) assert.throws(() => resolveTerminalView({ id: 'prof_a', sessionId }, workspace, state), { code: 'TERMINAL_SESSION_NOT_FOUND' });
  assert.throws(() => resolveTerminalView({ id: '../a' }, workspace, state), { code: 'VALIDATION_ERROR' });
  assert.throws(() => resolveTerminalView({ id: 'missing' }, workspace, state), { code: 'PROFILE_NOT_FOUND' });
  assert.equal(resolveTerminalView({ id: 'prof_a' }, workspace, { profiles: [] }).sessionId, undefined);
});

test('independent terminal workspace notifications omit credentials and privileged connection configuration', () => {
  const safe = terminalViewSnapshot({ profiles: [{ id: 'prof_a', name: 'A', notes: 'private notes', proxy: { password: 'secret' }, status: 'stopped' }], proxies: [{ username: 'private', password: 'secret' }], settings: { secret: 'secret' }, system: { platform: 'darwin', appVersion: '0.3.0', localApi: 'privileged', terminal: { supported: true } }, integration: { mcp: { token: 'secret' } } });
  assert.deepEqual(safe.profiles, [{ id: 'prof_a', name: 'A', status: 'stopped' }]);
  assert.equal(JSON.stringify(safe).includes('secret'), false);
  assert.equal(safe.system.localApi, undefined);
  const event = { sessionId: 'term_a', profileId: 'prof_a', sequence: 3, status: 'running' };
  assert.equal(terminalViewSnapshot(event), event);
});

test('independent terminals follow only the explicit system accessibility state', () => {
  for (const state of [true, false, undefined, null, 1, 'true', {}]) {
    const value = terminalViewSnapshot({ profiles: [], system: { accessibilitySupportEnabled: state, localApi: 'excluded' } });
    assert.equal(value.system.accessibilitySupportEnabled, state === true);
    assert.equal(value.system.localApi, undefined);
  }
});

test('detached terminal retains saved timezone and failed-context provenance without private network details', () => {
  const profile = { id: 'prof_a', resolvedTimezone: null, timezoneSource: null,
    selectedLocation: { confirmed: true, timezone: 'Asia/Manila', label: 'private address' },
    network: { ok: false, password: 'private-password', ip: '8.8.8.8' }, networkLastError: 'private diagnostic' };
  const result = terminalViewSnapshot({ profiles: [profile], system: { platform: 'darwin' } });
  assert.equal(result.profiles[0].savedNetworkTimezone, 'Asia/Manila');
  assert.equal(result.profiles[0].networkContextUnavailable, true);
  assert.equal(result.profiles[0].resolvedTimezone, null);
  assert.equal(result.profiles[0].timezoneSource, null);
  assert.equal(JSON.stringify(result).includes('private'), false);
  assert.equal(result.profiles[0].network, undefined);
  assert.equal(result.profiles[0].selectedLocation, undefined);
});

test('detached terminal keeps its managed network choice and privacy mode without its connection authority', () => {
  const full = { profiles: [{ id: 'prof_a', name: 'A', proxyId: 'route_a', privacy: { mode: 'strict', private: 'excluded' } }],
    proxies: [{ id: 'route_a', name: 'Work route', host: 'excluded.invalid', port: 1234, username: 'excluded', password: 'excluded', listener: { url: 'excluded' } }], system: {} };
  const safe = terminalViewSnapshot(full);
  const networks = sessionNetworks(terminalNetworks(safe.profiles), CLAUDE_SESSION);
  assert.equal(networks.length, 1);
  assert.equal(networks[0].id, 'route_a'); assert.equal(networks[0].name, 'Work route');
  assert.equal(sessionChoiceHost(networks, { kind: CLAUDE_SESSION, networkId: 'route_a', browserId: 'prof_a' }).id, 'prof_a');
  assert.deepEqual(safe.profiles[0].privacy, { mode: 'strict' });
  assert.deepEqual(safe.proxies, []);
  assert.equal(JSON.stringify(safe).includes('excluded'), false);
});

test('detached terminal labels prefer the safe profile label and validate added fields without coercion', () => {
  const snapshot = profile => terminalViewSnapshot({ profiles: [profile], proxies: [{ id: 'route_a', name: 'Saved route', password: 'excluded' }], system: {} }).profiles[0];
  assert.equal(snapshot({ proxyId: 'route_a', networkName: 'Current route' }).networkName, 'Current route');
  assert.equal(snapshot({ proxyId: null }).proxyId, null);
  assert.equal(snapshot({ proxyId: 'missing' }).networkName, undefined);
  for (const mode of ['off', 'standard', 'strict']) assert.deepEqual(snapshot({ privacy: { mode, unknown: 'excluded' } }).privacy, { mode });
  for (const value of [{ value: 'excluded' }, [], 1, true, '', 'x'.repeat(201), 'bad\nlabel', 'bad\0label']) {
    const safe = snapshot({ proxyId: value, networkName: value, privacy: { mode: value, unknown: 'excluded' } });
    assert.equal(safe.proxyId, undefined);
    assert.equal(safe.networkName, undefined);
    assert.equal(safe.privacy, undefined);
  }
  assert.equal(snapshot({ proxyId: 'route_a', networkName: { toString: () => 'excluded' } }).networkName, 'Saved route');
  assert.equal(terminalViewSnapshot({ profiles: [{ proxyId: 'route_a' }], proxies: [{ id: 'route_a', name: { private: 'excluded' } }], system: {} }).profiles[0].networkName, undefined);
});
