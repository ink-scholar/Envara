import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { performance } from 'node:perf_hooks';
import { fingerprintProvider, providerRecord, productionIdentity } from '../native/macos-app-routing/provider-reuse.mjs';
import { fixtureRuntimeNamespace, validateAcceptanceBuild, createAcceptanceRPCTransport, acceptanceFailureReason } from '../scripts/macos-app-proxy-acceptance-transport.mjs';
import { parseAcceptanceArguments, runAcceptanceCLI } from '../scripts/accept-macos-app-proxy.mjs';

const wait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const identifiers = Object.fromEntries(['hostIdentifier', 'providerIdentifier', 'applicationGroup'].map(key => [key, productionIdentity[key]]));
function status() { return { ready: false, acceptanceOnly: true, productionReceiptAllowed: false, authorized: false,
  extensionEnabled: false, runtimeNamespace: fixtureRuntimeNamespace, fixtures: ['one', 'two'], ...identifiers }; }
function envelope(request, result = status()) { return { protocol: request.protocol, version: request.version, id: request.id, result }; }
function fakeSpawn(behavior) {
  const children = [], invocations = [];
  const spawnProcess = (command, args, options) => {
    const child = new EventEmitter(); child.pid = 62000 + children.length; child.exitCode = null; child.signalCode = null;
    child.stdout = new PassThrough(); child.stderr = null; child.signals = []; let input = '';
    child.stdin = new Writable({ write(bytes, encoding, callback) { input += bytes.toString(); callback(); } });
    child.terminal = (code = 0, signal = null, close = true) => {
      child.exitCode = code; child.signalCode = signal; child.emit('exit', code, signal);
      if (close) { child.stdout.end(); child.emit('close', code, signal); }
    };
    child.kill = signal => { child.signals.push(signal); behavior?.onSignal?.(child, signal); return true; };
    child.stdin.once('finish', () => behavior?.onRequest?.(child, JSON.parse(input), children.length - 1));
    children.push(child); invocations.push({ command, args, options }); return child;
  };
  return { spawnProcess, children, invocations };
}
function transport(fake) { return createAcceptanceRPCTransport({ helperPath: '/owned/unit/fixture-helper', spawnProcess: fake.spawnProcess, killGraceMs: 10, terminalGraceMs: 10 }); }

test('mock helper valid stdout cannot resolve until terminal close, with no inherited secrets or stderr capture', async () => {
  let observedClose = false;
  const fake = fakeSpawn({ onRequest(child, request) {
    child.stdout.write(JSON.stringify(envelope(request))); child.terminal(0, null, false);
    setTimeout(() => { observedClose = true; child.stdout.end(); child.emit('close', 0, null); }, 30);
  } });
  const call = transport(fake); let resolved = false; const pending = call('status').then(result => { resolved = true; return result; });
  await wait(10); assert.equal(resolved, false); assert.equal(call.inFlight, true);
  const result = await pending; assert.equal(observedClose, true); assert.equal(result.transport.helperCloseObserved, true);
  assert.equal(result.transport.helperExitObserved, true); assert.equal(result.ready, false); assert.equal(call.inFlight, false);
  assert.deepEqual(fake.invocations[0].args, ['--acceptance-rpc']); assert.deepEqual(fake.invocations[0].options.env, { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' });
  assert.deepEqual(fake.invocations[0].options.stdio, ['pipe', 'pipe', 'ignore']);
});

test('mock stubborn helper honors short deadline, TERM then KILL, and rejects only after observed close', async () => {
  let closed = false;
  const fake = fakeSpawn({ onRequest(child, request) { child.stdout.write(JSON.stringify(envelope(request))); },
    onSignal(child, signal) { if (signal === 'SIGKILL') setTimeout(() => { closed = true; child.terminal(null, 'SIGKILL'); }, 2); } });
  const call = transport(fake), began = performance.now();
  await assert.rejects(call('launchFixture', { routeId: 'owned-unit' }, { timeoutMs: 20 }), error => {
    assert.equal(closed, true); assert.equal(error.code, 'ACCEPTANCE_HELPER_DEADLINE'); assert.equal(error.helperExitObserved, true);
    assert.equal(error.helperCloseObserved, true); assert.equal(error.mutationUncertain, true); return true;
  });
  assert.deepEqual(fake.children[0].signals, ['SIGTERM', 'SIGKILL']); assert.ok(performance.now() - began < 200); assert.equal(call.mutationBlocked, false);
});

test('unobserved helper terminal state permanently blocks later mutations, including after late close', async () => {
  const fake = fakeSpawn({ onRequest(child, request, index) { if (index > 0) { child.stdout.write(JSON.stringify(envelope(request))); child.terminal(); } } });
  const call = transport(fake);
  await assert.rejects(call('prepareFixture', { fixture: 'one' }, { timeoutMs: 15 }), error => error.code === 'ACCEPTANCE_HELPER_EXIT_UNVERIFIED' && error.helperExitObserved === false && error.forcedStreamClose === true);
  assert.equal(call.mutationBlocked, true); assert.equal(fake.children[0].stdin.destroyed, true); assert.equal(fake.children[0].stdout.destroyed, true);
  fake.children[0].terminal(); fake.children[0].emit('error', new Error('late private secret'));
  await assert.rejects(call('stopFixture', { routeId: 'owned-unit' }), error => error.code === 'ACCEPTANCE_MUTATION_BLOCKED'); assert.equal(fake.children.length, 1);
  assert.equal((await call('status')).ready, false); assert.equal(fake.children.length, 2); assert.equal(call.mutationBlocked, true);
});

test('exited mock helper with inherited stdio is not signalled again and stream teardown remains explicit uncertainty', async () => {
  const fake = fakeSpawn({ onRequest(child, request) { child.stdout.write(JSON.stringify(envelope(request))); child.terminal(0, null, false); } });
  const call = transport(fake);
  await assert.rejects(call('launchFixture', { routeId: 'owned-unit' }, { timeoutMs: 15 }), error => error.code === 'ACCEPTANCE_HELPER_EXIT_UNVERIFIED' && error.helperExitObserved === true && error.helperCloseObserved === false);
  assert.deepEqual(fake.children[0].signals, []); assert.equal(call.mutationBlocked, true);
});

test('abort before spawn starts no helper; abort after stdout still rejects and closes the owned helper', async () => {
  const pre = new AbortController(); pre.abort(); const unused = fakeSpawn({}), first = transport(unused);
  await assert.rejects(first('launchFixture', {}, { signal: pre.signal }), error => error.code === 'ACCEPTANCE_HELPER_ABORTED' && error.mutationUncertain === false); assert.equal(unused.children.length, 0);
  const controller = new AbortController();
  const fake = fakeSpawn({ onRequest(child, request) { child.stdout.write(JSON.stringify(envelope(request))); setTimeout(() => controller.abort(), 5); },
    onSignal(child, signal) { if (signal === 'SIGTERM') setTimeout(() => child.terminal(null, 'SIGTERM'), 2); } });
  await assert.rejects(transport(fake)('launchFixture', {}, { signal: controller.signal }), error => error.code === 'ACCEPTANCE_HELPER_ABORTED' && error.helperCloseObserved === true);
  assert.deepEqual(fake.children[0].signals, ['SIGTERM']);
});

test('malformed, mismatched, oversized and native-error mock replies never echo private input or output', async () => {
  const secret = 'private-runtime-value-do-not-log';
  for (const variant of ['malformed', 'mismatch', 'oversized', 'nativeError', 'namespace']) {
    const fake = fakeSpawn({ onRequest(child, request) {
      const bytes = variant === 'malformed' ? secret : variant === 'mismatch' ? JSON.stringify({ ...envelope(request), id: secret }) :
        variant === 'oversized' ? Buffer.alloc(65537, 65) : variant === 'nativeError' ? JSON.stringify({ protocol: request.protocol, version: 1, id: request.id, error: { code: 'notReady', message: secret } }) :
          JSON.stringify(envelope(request, { ...status(), runtimeNamespace: 'production' }));
      child.stdout.write(bytes); if (variant !== 'oversized') child.terminal();
    }, onSignal(child) { setTimeout(() => child.terminal(null, 'SIGTERM'), 1); } });
    await assert.rejects(transport(fake)('status', { secret }), error => !error.message.includes(secret) && !acceptanceFailureReason(error).includes(secret) && error.helperCloseObserved === true);
  }
});

test('mock missing executable and stdin errors converge on bounded close, and concurrent calls do not spawn', async () => {
  const missing = fakeSpawn({}); const spawnProcess = (...args) => { const child = missing.spawnProcess(...args); child.pid = undefined;
    queueMicrotask(() => { child.emit('error', new Error('ENOENT secret')); child.emit('close', -2, null); }); return child; };
  const noFile = createAcceptanceRPCTransport({ helperPath: '/owned/unit/missing', spawnProcess, killGraceMs: 10, terminalGraceMs: 10 });
  await assert.rejects(noFile('status'), error => error.code === 'ACCEPTANCE_HELPER_UNAVAILABLE' && error.helperCloseObserved === true);
  const pipe = fakeSpawn({ onRequest(child) { child.stdin.emit('error', new Error('EPIPE secret')); }, onSignal(child) { setTimeout(() => child.terminal(null, 'SIGTERM'), 1); } });
  await assert.rejects(transport(pipe)('launchFixture', {}), error => error.code === 'ACCEPTANCE_REQUEST_TRANSPORT_FAILED' && error.helperCloseObserved === true);
  const busy = fakeSpawn({ onRequest(child, request) { setTimeout(() => { child.stdout.write(JSON.stringify(envelope(request))); child.terminal(); }, 20); } }), call = transport(busy);
  const pending = call('status'); await assert.rejects(call('setupProfiles'), error => error.code === 'ACCEPTANCE_HELPER_BUSY'); await pending; assert.equal(busy.children.length, 1);
});

function macho() { const bytes = Buffer.alloc(64); Buffer.from('cffaedfe', 'hex').copy(bytes); bytes.writeUInt32LE(process.arch === 'arm64' ? 0x0100000c : 0x01000007, 4); return bytes; }
function plist(identifier, executable) { return `<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${identifier}</string><key>CFBundleExecutable</key><string>${executable}</string><key>CFBundleVersion</key><string>1</string></dict></plist>`; }
async function buildFixture(t) {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'envara-cli-unit-')), output = await fs.realpath(temporary); t.after(() => fs.rm(output, { recursive: true, force: true }));
  const host = path.join(output, 'EnvaraRoutingAcceptance.app'), helper = path.join(host, 'Contents/MacOS/EnvaraAppRoutingHelper');
  await fs.mkdir(path.dirname(helper), { recursive: true }); await fs.writeFile(helper, macho(), { mode: 0o755 }); await fs.writeFile(path.join(host, 'Contents/Info.plist'), plist(identifiers.hostIdentifier, 'EnvaraAppRoutingHelper'));
  const providerBundle = `EnvaraRoutingAcceptance.app/Contents/Library/SystemExtensions/${identifiers.providerIdentifier}.systemextension`, provider = path.join(output, providerBundle);
  await fs.mkdir(path.join(provider, 'Contents/MacOS'), { recursive: true }); await fs.writeFile(path.join(provider, 'Contents/MacOS/EnvaraAppProxy'), macho(), { mode: 0o755 });
  await fs.writeFile(path.join(provider, 'Contents/Info.plist'), plist(identifiers.providerIdentifier, 'EnvaraAppProxy')); const fingerprint = await fingerprintProvider(provider);
  const resources = path.join(host, 'Contents/Resources'); await fs.mkdir(resources);
  const fixtureManifest = { version: 1, fixtures: {} };
  for (const slot of ['one', 'two']) {
    const bundle = `EnvaraRoutingFixture${slot === 'one' ? 'One' : 'Two'}.app`, root = path.join(host, 'Contents/Helpers', bundle), bytes = macho();
    await fs.mkdir(path.join(root, 'Contents/MacOS'), { recursive: true }); await fs.writeFile(path.join(root, 'Contents/MacOS/EnvaraRoutingAcceptanceFixture'), bytes, { mode: 0o755 });
    await fs.writeFile(path.join(root, 'Contents/Info.plist'), plist(`io.envara.routing.fixture.${slot}`, 'EnvaraRoutingAcceptanceFixture'));
    fixtureManifest.fixtures[slot] = { bundle, identifier: `io.envara.routing.fixture.${slot}`, sha256: createHash('sha256').update(bytes).digest('hex') };
  }
  const manifest = { version: 1, platform: 'darwin', architecture: process.arch, helper: 'EnvaraRoutingAcceptance.app/Contents/MacOS/EnvaraAppRoutingHelper', args: ['--acceptance-rpc'],
    signed: false, signingMode: 'unsigned', profileVerification: { verified: false }, acceptanceOnly: true, productionReceiptAllowed: false, ...identifiers,
    runtimeNamespace: fixtureRuntimeNamespace, reusedProductionProvider: true, provider: providerRecord(fingerprint, providerBundle) };
  await fs.writeFile(path.join(output, 'manifest.json'), JSON.stringify(manifest)); await fs.writeFile(path.join(resources, 'acceptance-fixtures.json'), JSON.stringify(fixtureManifest));
  await fs.writeFile(path.join(resources, 'provider-reuse.json'), JSON.stringify({ version: 1, providerIdentifier: identifiers.providerIdentifier,
    runtimeNamespace: fixtureRuntimeNamespace, acceptanceOnly: true, provider: providerRecord(fingerprint, `${identifiers.providerIdentifier}.systemextension`) }));
  return { output, host, provider, resources, manifest };
}

test('ordinary non-executed mock build validates provider tree and sealed fixture bytes without claiming Apple authority', async t => {
  const f = await buildFixture(t), proof = await validateAcceptanceBuild(f.output); assert.equal(proof.bytesVerified, true); assert.equal(proof.appleAuthorizationVerified, false);
  assert.equal(proof.signed, false); assert.equal(proof.runtimeNamespace, fixtureRuntimeNamespace); assert.equal(proof.identifiers.providerIdentifier, identifiers.providerIdentifier);
  assert.ok(proof.fixtures.one.sha256); assert.ok(proof.provider.bundleSHA256); assert.ok(Object.isFrozen(proof.identifiers));
});

test('mock build rejects stale namespace, changed provider/fixture, arbitrary executable and production receipt before helper spawn', async t => {
  for (const variant of ['namespace', 'provider', 'fixture', 'helper', 'receipt', 'symlink']) {
    const f = await buildFixture(t);
    if (variant === 'namespace') await fs.writeFile(path.join(f.output, 'manifest.json'), JSON.stringify({ ...f.manifest, runtimeNamespace: 'production' }));
    if (variant === 'provider') await fs.appendFile(path.join(f.provider, 'Contents/Info.plist'), 'changed');
    if (variant === 'fixture') await fs.appendFile(path.join(f.host, 'Contents/Helpers/EnvaraRoutingFixtureOne.app/Contents/MacOS/EnvaraRoutingAcceptanceFixture'), 'changed');
    if (variant === 'helper') await fs.writeFile(path.join(f.host, 'Contents/MacOS/EnvaraAppRoutingHelper'), '#!/bin/sh\nexit 0\n');
    if (variant === 'receipt') await fs.writeFile(path.join(f.resources, 'routing-acceptance.plist'), 'not a readiness receipt');
    if (variant === 'symlink') { await fs.rename(path.join(f.resources, 'acceptance-fixtures.json'), path.join(f.resources, 'fixture-other.json')); await fs.symlink('fixture-other.json', path.join(f.resources, 'acceptance-fixtures.json')); }
    await assert.rejects(validateAcceptanceBuild(f.output), error => error.code === 'ACCEPTANCE_BUILD_INVALID');
  }
});

test('CLI dispatch preserves default status and explicit setup/activation, and only --run-fixtures calls the matrix', async () => {
  assert.equal(parseAcceptanceArguments([]), 'status'); for (const args of [['--run-fixtures', '--activate-extension'], ['--unknown']]) assert.throws(() => parseAcceptanceArguments(args));
  const build = { helperPath: '/owned/unit/helper', identifiers, runtimeNamespace: fixtureRuntimeNamespace, signed: false, signingMode: 'unsigned', bytesVerified: true, provider: {}, fixtures: {} };
  for (const [args, operation] of [[[], 'status'], [['--setup-profiles'], 'setupProfiles'], [['--activate-extension'], 'activateExtension'], [['--run-fixtures'], 'runFixtures']]) {
    const calls = [], saved = []; let matrixCalls = 0;
    const call = async (method, params) => { calls.push({ method, params }); return status(); }; Object.defineProperty(call, 'maximumTeardownGraceMs', { value: 2000 });
    const result = await runAcceptanceCLI({ args, projectRoot: '/owned/unit/project', loadBuild: async () => build, makeCall: () => call,
      runMatrix: async options => { matrixCalls++; assert.equal(options.call, call); assert.deepEqual(options.identifiers, identifiers); return { operation: 'runOwnedAppProxyFixtures', productionReady: false, productionReceiptAllowed: false, maximumMatrixSeconds: 115, testedFixtureSubsetPassed: false }; },
      saveReport: async (...values) => saved.push(values), platform: 'darwin', osRelease: 'unit' });
    assert.equal(result.report.productionReady, false); assert.equal(result.report.productionReceiptAllowed, false); assert.equal(saved.length, 1);
    if (operation === 'runFixtures') { assert.equal(matrixCalls, 1); assert.equal(calls.length, 0); assert.equal(result.exitCode, 2); assert.equal(result.report.maximumMatrixSecondsIncludingUnconfirmedHelperTeardown, 117); }
    else { assert.deepEqual(calls, [{ method: operation, params: operation === 'activateExtension' ? { activate: true } : {} }]); assert.equal(matrixCalls, 0); assert.equal(result.report.fixtureProcessesStarted, false); }
  }
});
