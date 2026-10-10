import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, copyFileSync, chmodSync, rmSync,
  realpathSync, lstatSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PassThrough, Readable } from 'node:stream';
import { NativeApplicationCommands, APP_NATIVE_EXECUTABLE, APP_NATIVE_PROTOCOL } from '../native/macos-pf-routing/helper-production-native.mjs';
import { serveNativeApplicationHelper } from '../native/macos-pf-routing/helper-production-cli.mjs';

const directory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../native/macos-pf-routing');
const uuid = value => `00000000-0000-4000-8000-${String(value).padStart(12, '0')}`;
const planRequest = Object.freeze({ registrationId: uuid(101), versionId: uuid(1001), environmentId: uuid(3001), runId: uuid(4001) });
const ticketRequest = Object.freeze({ ticketId: uuid(2001), ...planRequest });
const falseFlags = value => { for (const flag of ['ready', 'protected', 'productionReady']) assert.equal(value[flag], false, flag); };
const refused = reason => error => error.code === 'APPLICATION_NATIVE_REFUSED' && error.reason === reason;

function image(root) {
  if (!existsSync(root)) return null;
  const result = [];
  function visit(target) {
    const stat = lstatSync(target);
    result.push({ path: path.relative(root, target), mode: stat.mode & 0o7777, inode: stat.ino,
      mtime: stat.mtimeMs, ctime: stat.ctimeMs,
      bytes: stat.isFile() ? createHash('sha256').update(readFileSync(target)).digest('hex') : null });
    if (stat.isDirectory()) for (const name of readdirSync(target).sort()) visit(path.join(target, name));
  }
  visit(root); return result;
}
function removable(root) {
  const stat = lstatSync(root);
  if (stat.isDirectory()) { chmodSync(root, 0o700); for (const name of readdirSync(root)) removable(path.join(root, name)); }
  else if (stat.isFile()) chmodSync(root, 0o600);
}
async function rpc(commands, requests) {
  const output = new PassThrough(); let bytes = '';
  output.on('data', chunk => { bytes += chunk.toString('utf8'); });
  await serveNativeApplicationHelper({ commands, input: Readable.from(requests.map(value => Buffer.from(`${JSON.stringify(value)}\n`))), output });
  return bytes.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
}

test('fixed native bridge plans a real registered fixture and refuses a changed source', async () => {
  assert.equal(process.platform, 'darwin'); assert.notEqual(process.getuid(), 0);
  const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'envara-native-app-bridge-'))); chmodSync(temporary, 0o700);
  try {
    const fixture = path.join(temporary, 'app-control-fixture');
    const compiled = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
      '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`,
      ...['app-control.c', 'app-ticket.c', 'app-registry.c', 'gui-launch.m', 'launcher.c', 'app-control-fixture.c'].map(name => path.join(directory, name)),
      '-framework', 'Foundation', '-framework', 'AppKit', '-framework', 'Security', '-lbsm', '-o', fixture], { encoding: 'utf8', timeout: 60_000 });
    assert.equal(compiled.status, 0, compiled.stderr);
    const parent = path.join(temporary, 'case'); mkdirSync(parent, { mode: 0o700 });
    const bundle = path.join(parent, 'Fixture.app'), workspace = path.join(parent, 'workspace');
    const registry = path.join(parent, 'registry'), tickets = path.join(parent, 'tickets'), lease = uuid(5001);
    mkdirSync(workspace, { mode: 0o700 }); mkdirSync(path.join(bundle, 'Contents', 'MacOS'), { recursive: true, mode: 0o755 });
    mkdirSync(path.join(bundle, 'Contents', 'Resources'), { mode: 0o755 });
    copyFileSync(fixture, path.join(bundle, 'Contents', 'MacOS', 'Fixture')); chmodSync(path.join(bundle, 'Contents', 'MacOS', 'Fixture'), 0o755);
    writeFileSync(path.join(bundle, 'Contents', 'Info.plist'), '<plist version="1.0"><dict><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleIdentifier</key><string>io.envara.app-control-fixture</string><key>CFBundleExecutable</key><string>Fixture</string></dict></plist>', { mode: 0o644 });
    const marker = path.join(bundle, 'Contents', 'Resources', 'marker'); writeFileSync(marker, 'original', { mode: 0o644 });
    // The compiled main performs the real registrar operation. The copied app
    // bytes are inspected and sealed only; its executable is never launched.
    const nativeArgs = args => ['control', registry, tickets, workspace, lease, 'none', ...args, planRequest.registrationId];
    const sourceBefore = image(bundle);
    const registration = spawnSync(fixture, nativeArgs(['app-register', planRequest.registrationId, planRequest.versionId, bundle, '-']), { encoding: 'utf8', timeout: 15_000 });
    assert.equal(registration.status, 0, registration.stderr);
    const registered = JSON.parse(registration.stdout); assert.equal(registered.applicationIdentityVerified, true);
    assert.deepEqual(image(bundle), sourceBefore);
    const calls = [];
    const commands = new NativeApplicationCommands({ inspectInstallation: async () => ({ verified: true }),
      spawnChild(executable, args, options) {
        assert.equal(executable, APP_NATIVE_EXECUTABLE);
        assert.deepEqual(args, ['app-plan', planRequest.registrationId, planRequest.versionId, planRequest.environmentId, planRequest.runId]);
        assert.deepEqual(options, { shell: false, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' }, stdio: ['pipe', 'pipe', 'pipe'] });
        calls.push({ executable, args: [...args] });
        return spawn(fixture, nativeArgs(args), options);
      } });
    const beforePlan = image(parent), plan = await commands.plan(planRequest);
    falseFlags(plan); assert.equal(plan.applicationIdentityVerified, true); assert.equal(plan.environmentLeaseVerified, false);
    assert.equal(plan.ticketIssued, false); assert.equal(plan.reason, 'LIVE_NATIVE_LAUNCH_AUTHORITY_REQUIRED');
    assert.equal(plan.snapshotContentSHA256, registered.snapshotContentSHA256); assert.equal(Object.isFrozen(plan), true);
    assert.deepEqual(image(parent), beforePlan); assert.equal(existsSync(tickets), false);
    const [response] = await rpc(commands, [{ id: 'real-plan', method: 'plan', params: planRequest }]);
    assert.equal(response.protocol, APP_NATIVE_PROTOCOL); assert.equal(response.ok, true); falseFlags(response.result);
    assert.equal(response.result.snapshotContentSHA256, registered.snapshotContentSHA256);
    assert.deepEqual(image(parent), beforePlan); assert.equal(calls.length, 2);
    writeFileSync(marker, 'changed-original'); const changed = image(parent);
    await assert.rejects(commands.plan(planRequest), refused('NATIVE_OPERATION_REFUSED'));
    assert.equal(calls.length, 3); assert.deepEqual(image(parent), changed); assert.equal(existsSync(tickets), false);
    falseFlags(commands.status()); assert.equal(commands.status().protectedLaunchSupported, false);
    assert.equal(commands.status().sessions.length, 0); falseFlags(commands.shutdown());
  } finally { removable(temporary); rmSync(temporary, { recursive: true, force: true }); }
});

test('unsupported request fields and unavailable installation or root session refuse before exec', async () => {
  assert.notEqual(process.getuid(), 0);
  let executions = 0, inspections = 0;
  const noExec = () => { executions++; throw new Error('native exec must not occur'); };
  const commands = new NativeApplicationCommands({ spawnChild: noExec, inspectInstallation: async () => { inspections++; return { verified: true }; }, controlledSession: true });
  for (const extra of [{ proxy: { host: '127.0.0.1', port: 9999 } }, { consoleUID: process.getuid() }, { realmGID: process.getgid() },
    { authorizer: () => true }, { inspectInstallation: () => ({ verified: true }) }, { proof: { ready: true, protected: true } }]) {
    await assert.rejects(commands.plan({ ...planRequest, ...extra }), refused('REQUEST_INVALID'));
  }
  for (const input of [null, [], { ...planRequest, runId: 'invalid' }, { ...planRequest, environmentId: undefined }]) {
    await assert.rejects(commands.plan(input), refused('REQUEST_INVALID'));
  }
  assert.equal(inspections, 0); assert.equal(executions, 0);
  await assert.rejects(commands.register({ registrationId: planRequest.registrationId, versionId: planRequest.versionId, bundlePath: '/private/tmp/Fixture.app' }), refused('AUTHENTICATED_ROOT_HELPER_REQUIRED'));
  await assert.rejects(commands.prepareTicket(ticketRequest), refused('AUTHENTICATED_ROOT_HELPER_REQUIRED'));
  await assert.rejects(commands.stageTicket(ticketRequest), refused('AUTHENTICATED_ROOT_HELPER_REQUIRED'));
  assert.equal(inspections, 0); assert.equal(executions, 0); assert.deepEqual(commands.status().sessions, []);
  const defaultSession = new NativeApplicationCommands({ spawnChild: noExec, inspectInstallation: async () => ({ verified: true }) });
  await assert.rejects(defaultSession.register({ registrationId: planRequest.registrationId, versionId: planRequest.versionId, bundlePath: '/private/tmp/Fixture.app' }), refused('AUTHENTICATED_ROOT_HELPER_REQUIRED'));
  const unverified = new NativeApplicationCommands({ spawnChild: noExec, inspectInstallation: async () => ({ verified: false }) });
  await assert.rejects(unverified.plan(planRequest), refused('REVIEWED_INSTALLATION_REQUIRED'));
  await assert.rejects(unverified.inspectTicket({ ticketId: ticketRequest.ticketId }), refused('REVIEWED_INSTALLATION_REQUIRED'));
  assert.equal(executions, 0);
  for (const instance of [commands, defaultSession, unverified, new NativeApplicationCommands()]) {
    falseFlags(instance.status()); assert.equal(instance.status().protectedLaunchSupported, false);
    assert.equal(instance.resume, undefined); assert.equal(instance.resumeGUI, undefined); falseFlags(instance.shutdown());
  }
});

test('RPC rejects unknown methods, authority overrides and supplied readiness proofs', async () => {
  let executions = 0, inspections = 0;
  const commands = new NativeApplicationCommands({ spawnChild: () => { executions++; throw new Error('must not exec'); },
    inspectInstallation: async () => { inspections++; return { verified: true }; } });
  const invalid = [
    { id: 'unknown', method: 'resume', params: { ticketId: ticketRequest.ticketId } },
    { id: 'private', method: 'shutdown', params: {} },
    { id: 'constructor', method: 'constructor', params: {} },
    { id: 'override', method: 'plan', params: planRequest, authorizer: { verified: true } },
    { id: 'native-option', method: 'plan', params: { ...planRequest, controlledSession: true } },
    { id: 'proof', method: 'plan', params: { ...planRequest, proof: { nativeObserved: true, ready: true, protected: true } } },
    { id: 'status-proof', method: 'status', params: { ready: true } },
    { id: 'bad-params', method: 'plan', params: [] },
  ];
  const responses = await rpc(commands, [...invalid, { id: 'status', method: 'status', params: {} }]);
  assert.equal(responses.length, invalid.length + 1);
  for (let i = 0; i < invalid.length; i++) {
    assert.equal(responses[i].id, invalid[i].id); assert.equal(responses[i].protocol, APP_NATIVE_PROTOCOL);
    assert.equal(responses[i].ok, false); assert.equal(responses[i].error.code, 'APPLICATION_NATIVE_REFUSED');
    assert.equal(responses[i].result, undefined);
  }
  const status = responses.at(-1); assert.equal(status.ok, true); falseFlags(status.result);
  assert.equal(status.result.readOnly, true); assert.equal(status.result.protectedLaunchSupported, false);
  assert.deepEqual(status.result.sessions, []); assert.equal(inspections, 0); assert.equal(executions, 0);
});

test('lost RPC output stops dispatch of later requests already in the input buffer', async () => {
  let resolveInspection, inspectionStarted, inspections = 0, executions = 0;
  const started = new Promise(resolve => { inspectionStarted = resolve; });
  const commands = new NativeApplicationCommands({ spawnChild: () => { executions++; throw new Error('must not exec'); },
    inspectInstallation: async () => {
      inspections++;
      if (inspections === 1) { inspectionStarted(); return new Promise(resolve => { resolveInspection = resolve; }); }
      return { verified: false };
    } });
  const output = new PassThrough();
  const bytes = [1, 2].map(id => JSON.stringify({ id: `queued-${id}`, method: 'plan', params: planRequest })).join('\n') + '\n';
  const serving = serveNativeApplicationHelper({ commands, input: Readable.from([Buffer.from(bytes)]), output });
  await started; output.emit('error', new Error('owned fixture output channel closed')); resolveInspection({ verified: false });
  await serving.catch(error => assert.equal(error.code, 'ERR_STREAM_PREMATURE_CLOSE'));
  assert.equal(inspections, 1, 'closed output must not authorize dispatch of the second buffered request');
  assert.equal(executions, 0); assert.deepEqual(commands.status().sessions, []); falseFlags(commands.status());
});
