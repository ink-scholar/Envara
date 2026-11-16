import assert from 'node:assert/strict';
import test from 'node:test';
import { ProxyNetworkProbe } from '../electron/proxy-network.mjs';
import { NETWORK_DIAGNOSTIC_STAGES, sanitizeNetworkDiagnostics } from '../shared/proxy-network-diagnostics.mjs';

const geo = { ip: '8.8.8.8', country: 'United States', country_code: 'US', timezone: { id: 'America/New_York' } };
const stages = attempt => Object.fromEntries(attempt.stages.map(entry => [entry.stage, entry.status]));

test('diagnostics retain a failed provider before a successful fallback with bounded elapsed time', async () => {
  let clock = 1000, calls = 0;
  const probe = new ProxyNetworkProbe({ nowMs: () => clock, transport: async ({ onDiagnostic }) => {
    calls++;
    onDiagnostic({ stage: 'https', status: 'passed' });
    if (calls === 1) { clock += 13; onDiagnostic({ stage: 'response', status: 'failed' }); throw Object.assign(new Error('private response'), { code: 'GEO_HTTP_ERROR' }); }
    clock += 24; onDiagnostic({ stage: 'response', status: 'passed' });
    return { ...geo, timezone: 'America/New_York' };
  } });
  const result = await probe.probe(null);
  assert.equal(result.ok, true); assert.equal(calls, 2); assert.equal(result.source, 'ipapi.co');
  assert.deepEqual(result.diagnostics, { version: 1, attempts: [
    { source: 'ipwho.is', elapsedMs: 13, outcome: 'failure', errorCode: 'GEO_HTTP_ERROR', stages: [
      { stage: 'configuration', status: 'passed' }, { stage: 'https', status: 'passed' },
      { stage: 'response', status: 'failed' }, { stage: 'validation', status: 'unobserved' }] },
    { source: 'ipapi.co', elapsedMs: 24, outcome: 'success', stages: NETWORK_DIAGNOSTIC_STAGES.map(stage => ({ stage, status: 'passed' })) },
  ] });
});

test('legacy injected transports do not imply HTTPS, response, DNS or upstream handshake observations', async () => {
  const result = await new ProxyNetworkProbe({ transport: async () => geo }).probe(null);
  assert.equal(result.ok, true);
  assert.deepEqual(stages(result.diagnostics.attempts[0]), { configuration: 'passed', https: 'unobserved', response: 'unobserved', validation: 'passed' });
  assert.equal(JSON.stringify(result.diagnostics).includes('dns'), false);
});

test('failed validation is distinct from successfully observed transport and response stages', async () => {
  const probe = new ProxyNetworkProbe({ endpoints: [{ url: 'https://example.invalid/', source: 'fixture', format: 'ipwho' }], transport: async ({ onDiagnostic }) => {
    onDiagnostic({ stage: 'https', status: 'passed' }); onDiagnostic({ stage: 'response', status: 'passed' });
    return { ...geo, timezone: { id: 'not/a-zone' } };
  } });
  const result = await probe.probe(null);
  assert.equal(result.ok, false); assert.equal(result.errorCode, 'INVALID_GEO_RESPONSE');
  assert.deepEqual(stages(result.diagnostics.attempts[0]), { configuration: 'passed', https: 'passed', response: 'passed', validation: 'failed' });
});

test('diagnostics discard arbitrary provider labels, observations and raw error properties', async () => {
  const secret = 'diagnostic-fixture-secret';
  const result = await new ProxyNetworkProbe({ endpoints: [{ url: 'https://example.invalid/private', source: secret, format: 'ipwho' }], transport: async ({ onDiagnostic }) => {
    onDiagnostic({ stage: secret, status: 'passed', headers: secret });
    onDiagnostic({ stage: 'response', status: secret });
    onDiagnostic({ stage: 'validation', status: 'passed' });
    throw Object.assign(new Error(secret), { code: secret, url: secret, token: secret, diagnostics: { secret } });
  } }).probe({ protocol: 'http', host: 'private-proxy.example.invalid', port: 8080, username: 'fixture-user', password: secret });
  const attempt = result.diagnostics.attempts[0];
  assert.equal(attempt.source, 'custom'); assert.equal(attempt.errorCode, 'NETWORK_FAILED');
  assert.deepEqual(stages(attempt), { configuration: 'passed', https: 'unobserved', response: 'unobserved', validation: 'unobserved' });
  for (const value of [secret, 'private-proxy', 'fixture-user', 'url', 'headers', 'token']) assert.equal(JSON.stringify(result.diagnostics).includes(value), false, value);
});

test('sanitizer rebuilds only a bounded fixed schema and refuses ambiguous stages', () => {
  const attempt = { source: 'private-host', elapsedMs: 1e20, outcome: 'failure', errorCode: 'private-exception', password: 'private-password',
    stages: [{ stage: 'configuration', status: 'passed', headers: 'private-headers' }] };
  assert.deepEqual(sanitizeNetworkDiagnostics({ version: 1, attempts: [attempt], token: 'private-token' }), {
    version: 1, attempts: [{ source: 'custom', elapsedMs: 120000, outcome: 'failure', errorCode: 'NETWORK_FAILED',
      stages: NETWORK_DIAGNOSTIC_STAGES.map(stage => ({ stage, status: stage === 'configuration' ? 'passed' : 'unobserved' })) }],
  });
  assert.equal(sanitizeNetworkDiagnostics({ version: 2, attempts: [] }), null);
  assert.equal(sanitizeNetworkDiagnostics({ version: 1, attempts: Array(4).fill(attempt) }), null);
  for (const change of [{ outcome: 'private-result' }, { elapsedMs: Infinity }, { stages: [{ stage: 'private-stage', status: 'passed' }] },
    { stages: Array(2).fill({ stage: 'response', status: 'passed' }) }, { stages: [{ stage: 'response', status: 'private-status' }] }]) {
    assert.equal(sanitizeNetworkDiagnostics({ version: 1, attempts: [{ ...attempt, ...change }] }), null);
  }
});

test('network change records cancellation and discards late transport observations without new fallback', async () => {
  let finish, observer, calls = 0;
  const probe = new ProxyNetworkProbe({ transport: ({ onDiagnostic }) => { calls++; observer = onDiagnostic; return new Promise(resolve => { finish = resolve; }); } });
  const pending = probe.probe(null);
  probe.invalidateNetwork(); finish(geo);
  const result = await pending;
  assert.equal(result.ok, false); assert.equal(calls, 1);
  assert.equal(result.diagnostics.attempts[0].outcome, 'cancelled');
  assert.equal(result.diagnostics.attempts[0].errorCode, 'NETWORK_CHANGED');
  observer({ stage: 'https', status: 'passed' });
  assert.equal(stages(result.diagnostics.attempts[0]).https, 'unobserved');
  assert.equal(probe.peek(null), null);
});

test('cached diagnostics are isolated from callers and clock rollback or jumps stay bounded', async () => {
  for (const delta of [-5000, 1e8]) {
    let clock = 1000;
    const probe = new ProxyNetworkProbe({ nowMs: () => clock, transport: async () => { clock += delta; return geo; } });
    const result = await probe.probe(null);
    assert.equal(result.diagnostics.attempts[0].elapsedMs, delta < 0 ? 0 : 120000);
    result.diagnostics.attempts[0].stages[0].status = 'failed';
    const cached = probe.peek(null); assert.equal(stages(cached.diagnostics.attempts[0]).configuration, 'passed');
    cached.diagnostics.attempts[0].source = 'mutated';
    assert.equal(probe.peek(null).diagnostics.attempts[0].source, 'ipwho.is');
  }
});
