import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readFile, readdir, realpath, rm, stat, symlink, link, writeFile } from 'node:fs/promises';
import { collectSupportDiagnostics, exportSupportDiagnostics, existingNetworkDiagnostics, SUPPORT_DIAGNOSTICS_SCHEMA } from '../electron/support-diagnostics.mjs';

const now = 1700000000000;
const secret = 'PRIVATE_SUPPORT_SENTINEL';
const runId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const environmentId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const privateFields = { password: secret, ip: '192.0.2.77', endpoint: 'https://private.example.test:9999',
  path: '/Users/private/support', command: 'cat private-account', deviceId: secret, output: secret };
const stages = ['configuration', 'https', 'response', 'validation'].map(stage => ({ stage, status: 'passed', ...privateFields }));
const network = () => ({ ok: true, scope: 'egress', checkedAt: new Date(now).toISOString(), latencyMs: 23, ...privateFields,
  diagnostics: { version: 1, attempts: [{ source: 'ipwho.is', outcome: 'success', elapsedMs: 23, stages, ...privateFields }] } });
const application = () => ({ applicationId: 'app_private_fixture', runId, environmentId, phase: 'cleanup-required', active: false,
  initialFailure: { stage: 'cold-stage', code: 'APPLICATION_APP_NATIVE_REFUSED', native: { stage: 'guardian', reason: 'NATIVE_OPERATION_REFUSED', error: 13 } },
  cleanupFailure: { stage: 'cleanup', code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' },
  events: [{ sequence: 1, stage: 'failed', code: 'APPLICATION_APP_NATIVE_REFUSED', ...privateFields }], ...privateFields,
  sessionDiagnostics: { selectedStatusRunId: runId, lastStatusRunId: runId, observationPolls: 3, observationPollFailures: 1,
    pending: true, uncertaintyLatched: true, callHistory: ['status'], ...privateFields } });
const options = () => ({ appVersion: '0.5.18', platform: 'darwin', arch: 'arm64', nowMs: () => now,
  readers: {
    startup: () => ({ version: secret, startedAtMs: now, totalMs: 12, entryUptimeMs: 5, code: secret, ...privateFields,
      stages: [{ name: 'sidecar-start', status: 'failed', startedMs: 2, durationMs: 10, code: 'SIDECAR_START_FAILED', ...privateFields },
        { name: secret, status: 'completed', startedMs: 12, durationMs: 0, code: secret }] }),
    runtime: () => ({ schema: 'envara.runtime-diagnostics/v1', elapsedMs: 20, dropped: 0, ...privateFields,
      pending: [{ ordinal: 2, stage: 'ipc.dispatch', startedMs: 15, elapsedMs: 5, ...privateFields }],
      recent: [{ ordinal: 1, stage: 'ipc.snapshot', status: 'completed', startedMs: 0, elapsedMs: 10, ...privateFields }] }),
    network: () => [network()],
    recovery: () => ({ revision: 4, phase: 'waiting', reason: 'resume', attempt: 2, retryAt: new Date(now + 1000).toISOString(),
      checkedAt: new Date(now).toISOString(), ...privateFields }),
    applications: () => [application()],
  } });

async function fixture(t) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-support-fixture-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return { directory, destination: path.join(directory, 'support.json') };
}

test('support bundle rebuilds all five sections without identifiers, addresses, paths, commands or output', async () => {
  const document = await collectSupportDiagnostics(options());
  assert.equal(document.schema, SUPPORT_DIAGNOSTICS_SCHEMA);
  assert.equal(document.scope, 'existing-records-only');
  assert.equal(document.createdAt, new Date(now).toISOString());
  assert.deepEqual(document.app, { version: '0.5.18', platform: 'darwin', arch: 'arm64' });
  assert.deepEqual(Object.values(document.sections).map(part => part.collection), Array(5).fill('success'));
  assert.equal(document.sections.startup.data.stages[0].code, 'SIDECAR_START_FAILED');
  assert.equal(document.sections.startup.data.stages[1].stage, 'other');
  assert.equal(document.sections.startup.data.code, 'OTHER');
  assert.equal(document.sections.runtime.data.pending[0].status, 'pending');
  assert.equal(document.sections.network.data.records[0].diagnostics.attempts[0].stages[1].status, 'passed');
  assert.equal(document.sections.applications.data.records[0].initialFailure.code, 'APPLICATION_APP_NATIVE_REFUSED');
  assert.equal(document.sections.applications.data.records[0].cleanupFailure.code, 'APPLICATION_APP_CLEANUP_UNCONFIRMED');
  assert.equal(document.sections.applications.data.records[0].observation.failedPolls, 1);
  const encoded = JSON.stringify(document);
  for (const forbidden of [secret, '192.0.2.77', 'private.example.test', '/Users/private', 'cat private-account',
    'app_private_fixture', runId, environmentId, 'password', 'endpoint', 'command', 'deviceId', 'selectedStatusRunId', 'callHistory'])
    assert.equal(encoded.includes(forbidden), false, forbidden);
});

test('missing, malformed, failed and timed-out sources remain distinct and do not suppress available sections', async () => {
  const document = await collectSupportDiagnostics({ ...options(), timeoutMs: 15, readers: {
    startup: () => null,
    runtime: () => { throw new Error(secret); },
    network: () => [{ ...network(), scope: secret }],
    recovery: () => new Promise(() => {}),
    applications: () => [],
  } });
  assert.deepEqual(document.sections.startup, { collection: 'missing', reason: 'no-records' });
  assert.deepEqual(document.sections.runtime, { collection: 'failed', reason: 'unavailable' });
  assert.deepEqual(document.sections.network, { collection: 'failed', reason: 'invalid-record' });
  assert.deepEqual(document.sections.recovery, { collection: 'failed', reason: 'timeout' });
  assert.deepEqual(document.sections.applications, { collection: 'missing', reason: 'no-records' });
  assert.equal(JSON.stringify(document).includes(secret), false);
  const absent = await collectSupportDiagnostics({ nowMs: () => now });
  assert.ok(Object.values(absent.sections).every(part => part.collection === 'missing' && part.reason === 'unavailable'));
});

test('reader completion after a bounded timeout cannot rewrite an exported document', async () => {
  let finish;
  const document = await collectSupportDiagnostics({ timeoutMs: 10, nowMs: () => now,
    readers: { network: () => new Promise(resolve => { finish = resolve; }) } });
  const before = JSON.stringify(document);
  finish([network()]); await new Promise(resolve => setImmediate(resolve));
  assert.equal(JSON.stringify(document), before);
});

test('existing network diagnostics read cached evidence without invoking workspace, health, route or probe operations', () => {
  const result = network();
  const service = { snapshot() { assert.fail('No workspace snapshot'); }, prepareProxy() { assert.fail('No route preparation'); },
    networkProbe: { cacheTtlMs: 60000, nowMs: () => now,
      cache: new Map([[secret, { timestamp: now - 60001, result }]]),
      probe() { assert.fail('No network probe'); }, peek() { assert.fail('No credential lookup'); } } };
  const records = existingNetworkDiagnostics(service);
  assert.equal(records.length, 1); assert.equal(records[0].stale, true);
  assert.equal(records[0].diagnostics.attempts[0].outcome, 'success');
  assert.equal(JSON.stringify(records).includes(secret), false);
  assert.equal(JSON.stringify(records).includes('192.0.2.77'), false);
  records[0].diagnostics.attempts[0].stages[0].status = 'failed';
  assert.equal(result.diagnostics.attempts[0].stages[0].status, 'passed');
  assert.equal(existingNetworkDiagnostics({}), null);
});

test('section record limits and diagnostic vocabulary prevent oversized or forged content', async () => {
  const input = options();
  const net = network(); net.diagnostics.attempts[0].source = secret;
  const app = application(); app.initialFailure = { stage: secret, code: secret };
  input.readers.network = () => Array.from({ length: 103 }, () => net);
  input.readers.applications = () => Array.from({ length: 52 }, () => app);
  input.appVersion = `1.2.3+${secret}`; input.platform = secret; input.arch = secret;
  const document = await collectSupportDiagnostics(input);
  assert.deepEqual(document.app, { version: 'unknown', platform: 'unknown', arch: 'unknown' });
  assert.equal(document.sections.network.data.records.length, 100);
  assert.equal(document.sections.network.data.limited, true);
  assert.equal(document.sections.network.data.records[0].diagnostics.attempts[0].source, 'custom');
  assert.equal(document.sections.applications.data.records.length, 50);
  assert.equal(document.sections.applications.data.limited, true);
  assert.equal(document.sections.applications.data.records[0].initialFailure, null);
  net.diagnostics.attempts[0].stages[0].status = 'failed';
  assert.equal(document.sections.network.data.records[0].diagnostics.attempts[0].stages[0].status, 'passed');
  assert.equal(JSON.stringify(document).includes(secret), false);
});

test('only empty requests can export, and native cancellation creates no file', async t => {
  const f = await fixture(t); let dialogs = 0, reads = 0;
  const operation = { ...options(), readers: { startup: () => { reads++; return null; } },
    showSaveDialog: async dialog => { dialogs++; assert.equal(dialog.defaultPath, 'Envara-Support-Diagnostics.json'); return { canceled: true, filePath: f.destination }; } };
  for (const args of [null, [], { path: f.destination }, { output: secret }, { [Symbol('file')]: f.destination }])
    await assert.rejects(exportSupportDiagnostics({ ...operation, args }), { code: 'SUPPORT_DIAGNOSTICS_INVALID_REQUEST' });
  assert.equal(dialogs, 0); assert.equal(reads, 0);
  assert.deepEqual(await exportSupportDiagnostics(operation), { canceled: true });
  assert.equal(dialogs, 1); assert.equal(reads, 1); assert.deepEqual(await readdir(f.directory), []);
});

test('approved export atomically replaces a regular file with private permissions and no path in its result', async t => {
  const f = await fixture(t);
  await writeFile(f.destination, 'old-document', { mode: 0o644 });
  const result = await exportSupportDiagnostics({ ...options(), showSaveDialog: async () => ({ filePath: f.destination, canceled: false }) });
  assert.deepEqual(result, { exported: true });
  const document = JSON.parse(await readFile(f.destination, 'utf8'));
  assert.equal(document.schema, SUPPORT_DIAGNOSTICS_SCHEMA);
  assert.equal(JSON.stringify(document).includes(f.directory), false);
  assert.deepEqual(await readdir(f.directory), ['support.json']);
  if (process.platform !== 'win32') assert.equal((await stat(f.destination)).mode & 0o777, 0o600);
});

test('linked targets and failed destinations preserve existing files and return no private error details', async t => {
  const f = await fixture(t), original = path.join(f.directory, 'keep.json');
  await writeFile(original, 'keep-private-original');
  await symlink(original, f.destination);
  const run = filename => exportSupportDiagnostics({ ...options(), showSaveDialog: async () => ({ filePath: filename }) });
  await assert.rejects(run(f.destination), error => error.code === 'SUPPORT_DIAGNOSTICS_SAVE_FAILED' && !error.message.includes(f.directory));
  const hard = path.join(f.directory, 'hard.json'); await link(original, hard);
  await assert.rejects(run(hard), { code: 'SUPPORT_DIAGNOSTICS_SAVE_FAILED' });
  await assert.rejects(run(path.join(f.directory, 'missing', 'support.json')), { code: 'SUPPORT_DIAGNOSTICS_SAVE_FAILED' });
  assert.equal(await readFile(original, 'utf8'), 'keep-private-original');
  assert.equal((await readdir(f.directory)).some(name => name.startsWith('.envara-support-')), false);
});

test('closing while the save dialog is pending prevents publishing the package', async t => {
  const f = await fixture(t); let closed = false;
  await assert.rejects(exportSupportDiagnostics({ ...options(),
    checkOpen: () => { if (closed) throw Object.assign(new Error('应用正在退出。'), { code: 'APP_CLOSING' }); },
    showSaveDialog: async () => { closed = true; return { filePath: f.destination }; },
  }), { code: 'APP_CLOSING' });
  assert.deepEqual(await readdir(f.directory), []);
});

test('native save dialog failures never return their private messages or paths', async () => {
  await assert.rejects(exportSupportDiagnostics({ ...options(), showSaveDialog: async () => { throw new Error(secret); } }),
    error => error.code === 'SUPPORT_DIAGNOSTICS_SAVE_FAILED' && !error.message.includes(secret));
});
