import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { mkdtemp, mkdir, writeFile, chmod, realpath, rm, symlink } from 'node:fs/promises';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { inspectLocalApplication } from '../electron/application-service.mjs';
import { applicationRoutingReady } from '../electron/application-routing.mjs';
import { MacOSPFApplicationRouting, MACOS_PF_INSTALLED_HELPER, MACOS_PF_ROUTING_BACKEND, MACOS_PF_ROUTING_CHECKS, macOSPFApplicationRoutingReady } from '../electron/macos-pf-application-routing.mjs';

let directory, application, cwd;
before(async () => {
  directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-pf-adapter-')));
  const app = path.join(directory, 'OwnedFixture.app'), executable = path.join(app, 'Contents/MacOS/OwnedFixture');
  await mkdir(path.dirname(executable), { recursive: true });
  await writeFile(path.join(app, 'Contents/Info.plist'), '<plist><dict><key>CFBundleIdentifier</key><string>io.envara.pf-test</string><key>CFBundleExecutable</key><string>OwnedFixture</string><key>CFBundleName</key><string>Owned fixture</string></dict></plist>');
  await writeFile(executable, '#!/bin/sh\nexit 0\n'); await chmod(executable, 0o700);
  cwd = path.join(directory, 'workspace'); await mkdir(cwd);
  application = { id: 'owned_fixture', profileId: 'environment_one', ...(await inspectLocalApplication(app, { platform: 'darwin' })), args: [] };
});
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }); });

const allChecks = () => Object.fromEntries(MACOS_PF_ROUTING_CHECKS.map(key => [key, true]));
function acceptedState() {
  return { backend: MACOS_PF_ROUTING_BACKEND, installed: true, authorized: true, ready: true, processScopeVerified: true,
    authorization: { kind: 'privileged-helper', verified: true }, capabilities: allChecks(),
    verification: { backend: MACOS_PF_ROUTING_BACKEND, native: true, passed: true, version: 'pf-fixture/1', checks: allChecks() },
    component: { available: true, verified: true }, sessions: [] };
}
function parameters() {
  return { application: { ...application, args: [] },
    workspace: { cwd, timezone: 'Asia/Manila', timezoneSource: 'proxy', locale: 'en-PH', privacy: { mode: 'standard' },
      geolocation: { latitude: 14.6, longitude: 121, accuracy: 50000 } },
    route: { protocol: 'socks5', host: '127.0.0.1', port: 23456, username: 'owned-fixture-user', password: 'private-fixture-password', udp: false, udpPolicy: 'block' },
    managedRoute: { profileId: application.profileId, proxyId: 'owned_proxy', nodeType: 'anytls', routeIdentity: '12345678-1234-4234-8234-123456789abc',
      coreGeneration: '12345678-1234-4234-8234-123456789abd', corePid: process.pid, coreVersion: 'v1.19.32' } };
}
function fixture(state = acceptedState()) {
  const calls = [];
  let sequence = 0;
  const native = {
    status: async () => state,
    setup: async params => { calls.push({ method: 'setup', params }); return { ready: false }; },
    prepareRoute: async params => {
      calls.push({ method: 'prepareRoute', params });
      return { routeId: `owned_route_${++sequence}`, ready: true, failClosed: true, guardArmed: true, managedRouteVerified: true,
        profileId: params.application.profileId, applicationIdentity: params.application.identity, routeIdentity: params.managedRoute.routeIdentity,
        coreGeneration: params.managedRoute.coreGeneration, consoleUID: 501, gid: 7100, capabilities: allChecks(), verification: structuredClone(state.verification) };
    },
    launch: async params => { calls.push({ method: 'launch', params }); return { routeId: params.routeId, sessionId: 'owned_session', pid: 70001, protected: true, guardArmed: true, failClosed: true }; },
    stop: async params => { calls.push({ method: 'stop', params }); return { stopped: true }; },
    revoke: async params => { calls.push({ method: 'revoke', params }); return { revoked: true }; },
    shutdown: async () => { calls.push({ method: 'shutdown' }); },
  };
  return { state, calls, native, adapter: new MacOSPFApplicationRouting({ native }) };
}
function launchParameters(routeId) { return { routeId, application: { ...application }, args: ['literal;$(never-a-shell)'], cwd,
  env: { TZ: 'Asia/Manila', ENVARA_PROFILE_ID: application.profileId, ENVARA_ROUTE_ID: routeId } }; }

test('missing PF helper stays unavailable without borrowing NE authorization', async () => {
  const adapter = new MacOSPFApplicationRouting();
  const state = await adapter.status();
  assert.equal(state.requiresAppleNetworkExtension, false); assert.equal(state.installed, false); assert.equal(state.authorized, false);
  assert.equal(state.ready, false); assert.equal(state.productionReady, false); assert.equal(applicationRoutingReady(state), false);
  assert.ok(MACOS_PF_ROUTING_CHECKS.every(key => state.capabilities[key] === false && state.verification.checks[key] === false));
  await assert.rejects(adapter.prepareRoute(parameters()), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
  await assert.rejects(adapter.launch(launchParameters('not_prepared')), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
  await assert.rejects(adapter.setup({ activate: true }), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
  await adapter.shutdown();
});

test('NE, primitive and pure policy readiness cannot promote PF launch', async () => {
  for (const update of [{ backend: 'envara-app-proxy' }, { authorization: { kind: 'apple-network-extension', verified: true } },
    { verification: { ...acceptedState().verification, native: false } }, { processScopeVerified: undefined }]) {
    const value = fixture({ ...acceptedState(), ...update });
    assert.equal(macOSPFApplicationRoutingReady(await value.adapter.status()), false);
    await assert.rejects(value.adapter.prepareRoute(parameters()));
    await assert.rejects(value.adapter.launch(launchParameters('not_prepared')));
    assert.deepEqual(value.calls, []);
  }
});

test('every PF native acceptance gate is required before credentials reach prepare', async () => {
  for (const key of MACOS_PF_ROUTING_CHECKS) {
    const state = acceptedState(); state.verification.checks[key] = false;
    const value = fixture(state);
    await assert.rejects(value.adapter.prepareRoute(parameters()), { code: 'APPLICATION_ROUTING_NOT_READY' });
    assert.deepEqual(value.calls, []);
  }
});

test('plan validates an unsigned owned local bundle and managed route without activating any helper', async () => {
  const value = fixture({ backend: MACOS_PF_ROUTING_BACKEND, installed: false });
  const plan = await value.adapter.plan(parameters());
  assert.equal(plan.readOnly, true); assert.equal(plan.protected, false); assert.equal(plan.ready, false);
  assert.equal(plan.requiresAppleNetworkExtension, false); assert.equal(plan.requiresAdministrator, true);
  assert.equal(plan.environmentId, application.profileId); assert.equal(plan.network.nodeType, 'anytls'); assert.equal(plan.network.requiresAuthentication, true);
  assert.equal(plan.network.verified, false);
  assert.equal(plan.network.udpPolicy, 'block'); assert.deepEqual(plan.requiredChecks, MACOS_PF_ROUTING_CHECKS);
  const output = JSON.stringify(plan);
  for (const secret of ['private-fixture-password', 'owned-fixture-user', '23456', '12345678-1234']) assert.equal(output.includes(secret), false);
  assert.deepEqual(value.calls, []);
});

test('managed proof must belong to this profile and live pinned core, not renderer proxy syntax', async () => {
  const changes = [params => { delete params.managedRoute; }, params => { params.managedRoute.profileId = 'other_environment'; },
    params => { params.managedRoute.corePid = 0; }, params => { params.managedRoute.coreGeneration = 'stale'; },
    params => { params.managedRoute.coreVersion = 'unknown'; }, params => { params.route.password = ''; },
    params => { params.route.host = '198.51.100.1'; }, params => { params.route.protocol = 'http'; },
    params => { params.route.udpPolicy = 'proxy'; }, params => { params.workspace.geolocation.accuracy = 10; }];
  for (const change of changes) {
    const value = fixture(), params = parameters(); change(params);
    await assert.rejects(value.adapter.plan(params), { code: 'APPLICATION_ROUTING_NOT_READY' });
    await assert.rejects(value.adapter.prepareRoute(params), { code: 'APPLICATION_ROUTING_NOT_READY' });
    assert.deepEqual(value.calls, []);
  }
  const params = parameters(); params.managedRoute.nodeType = 'vless';
  assert.equal((await fixture().adapter.plan(params)).network.nodeType, 'vless');
});

test('read-only setup never requests administrator actions; explicit setup cannot dispatch to a NE helper', async () => {
  const value = fixture(); assert.equal((await value.adapter.setup()).readOnly, true); assert.deepEqual(value.calls, []);
  await value.adapter.setup({ activate: true, password: 'never-forward-this' });
  assert.deepEqual(value.calls, [{ method: 'setup', params: { activate: true, backend: MACOS_PF_ROUTING_BACKEND } }]);
  const other = fixture({ ...acceptedState(), backend: 'envara-app-proxy' });
  await assert.rejects(other.adapter.setup({ activate: true }), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
  assert.deepEqual(other.calls, []);
});

const installedReceipt = () => ({ schema: 'envara.macos-pf-install/v1', action: 'installedResourcesOnly', installed: true,
  changed: true, ready: false, productionReady: false, manifestSHA256: 'a'.repeat(64), reason: 'installed-resources-only' });
async function installationFixture(options = {}) {
  const owned = await mkdtemp(path.join(directory, 'installer-'));
  const installerPath = path.join(owned, 'EnvaraPFInstall');
  // Metadata only; fake spawn below never executes this file or requests OS UI.
  await writeFile(installerPath, '# owned inert installation fixture\n', { mode: 0o700 });
  const value = fixture({ ...acceptedState(), authorized: false, ready: false,
    authorization: { kind: 'privileged-helper', verified: false } });
  const spawned = [];
  const spawn = (...params) => {
    const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.stdin = new PassThrough();
    child.killed = false; child.kill = () => { child.killed = true; child.emit('close', null, 'SIGTERM'); };
    spawned.push({ params, child });
    if (!options.silent) queueMicrotask(() => {
      child.stderr.write('private-fixture-password must never appear in returned errors');
      child.stdout.write(options.output ?? JSON.stringify(options.receipt ?? installedReceipt()));
      child.emit('close', options.exitCode ?? 0, null);
    });
    return child;
  };
  value.adapter = new MacOSPFApplicationRouting({ native: value.native, installerPath, spawn,
    installationTimeoutMs: options.timeoutMs ?? 1000, ...options.adapter });
  return { ...value, installerPath, spawned };
}

test('fixed installer is not spawned by status or any read-only setup request', async () => {
  const value = await installationFixture();
  await value.adapter.status();
  for (const params of [{}, { activate: false }, { activate: 'true', password: 'private-fixture-password' }])
    assert.equal((await value.adapter.setup(params)).readOnly, true);
  assert.deepEqual(value.spawned, []); assert.deepEqual(value.calls, []);
});

test('explicit installation spawns only fixed request-install with clean env and retargets read-only helper', async () => {
  const value = await installationFixture();
  let inspectedPath;
  value.native.status = async () => { inspectedPath = value.native.helperPath; return value.state; };
  const result = await value.adapter.setup({ activate: true, path: '/caller-command', password: 'private-fixture-password' });
  assert.equal(value.spawned.length, 1);
  const [file, argv, options] = value.spawned[0].params;
  assert.equal(file, value.installerPath); assert.deepEqual(argv, ['--request-install']);
  assert.equal(options.shell, false); assert.deepEqual(options.env, { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' });
  assert.deepEqual(options.stdio, ['pipe', 'pipe', 'pipe']);
  assert.equal(inspectedPath, MACOS_PF_INSTALLED_HELPER);
  assert.equal(result.installed, true); assert.equal(result.authorized, false); assert.equal(result.ready, false);
  assert.equal(result.productionReady, false); assert.equal(result.protected, false);
  assert.equal(result.installation.action, 'installedResourcesOnly');
  assert.equal(JSON.stringify(result).includes('private-fixture-password'), false);
  assert.deepEqual(value.calls, [], 'helper setup/launch must not be used as installation fallback');
});

test('installation receipt cannot authorize, activate or silently launch any routing operation', async () => {
  for (const changes of [{ schema: 'untrusted' }, { action: 'routing-ready' }, { installed: false }, { ready: true },
    { productionReady: true }, { authorized: true }, { activation: true }, { manifestSHA256: 'unknown' },
    { operations: { changePF: true } }]) {
    const value = await installationFixture({ receipt: { ...installedReceipt(), ...changes } });
    await assert.rejects(value.adapter.setup({ activate: true }), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
    assert.equal(value.native.helperPath, undefined); assert.deepEqual(value.calls, []);
  }
});

test('denied, malformed and timed-out installer responses remain sanitized with no fallback', async () => {
  for (const [options, code] of [[{ exitCode: 1 }, 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED'],
    [{ output: 'private-fixture-password invalid JSON' }, 'APPLICATION_ROUTING_PROTOCOL_ERROR'],
    [{ silent: true, timeoutMs: 15 }, 'APPLICATION_ROUTING_TIMEOUT']]) {
    const value = await installationFixture(options);
    await assert.rejects(value.adapter.setup({ activate: true }), error => error.code === code && !error.message.includes('private-fixture-password'));
    assert.equal(value.native.helperPath, undefined); assert.deepEqual(value.calls, []);
    assert.equal(value.adapter.installationPending, false);
    if (options.silent) assert.equal(value.spawned[0].child.killed, true);
  }
});

test('missing and symlink installers fail before spawn even with an injectable executor', async () => {
  const value = await installationFixture();
  const target = path.join(path.dirname(value.installerPath), 'original');
  await writeFile(target, 'inert fixture', { mode: 0o700 });
  await rm(value.installerPath); await symlink(target, value.installerPath);
  await assert.rejects(value.adapter.setup({ activate: true }), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
  await rm(value.installerPath);
  await assert.rejects(value.adapter.setup({ activate: true }), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
  assert.deepEqual(value.spawned, []); assert.deepEqual(value.calls, []);
});

test('in-flight installation refuses a second prompt and active routes forbid helper retarget', async () => {
  let complete;
  const value = await installationFixture({ adapter: { executeInstaller: () => new Promise(resolve => { complete = resolve; }) } });
  const first = value.adapter.setup({ activate: true });
  for (let i = 0; i < 50 && !complete; i++) await new Promise(resolve => setTimeout(resolve, 1));
  assert.equal(typeof complete, 'function');
  await assert.rejects(value.adapter.setup({ activate: true }), { code: 'APPLICATION_ROUTING_NOT_READY' });
  complete(installedReceipt()); await first;
  value.adapter.routes.set('owned_route', { ready: false });
  await assert.rejects(value.adapter.setup({ activate: true }), { code: 'APPLICATION_ROUTING_NOT_READY' });
});

test('prepared route binds managed core, application identity and GID before native launch', async () => {
  const value = fixture(), params = parameters();
  const result = await value.adapter.prepareRoute(params);
  assert.equal(result.ready, true); assert.equal(result.guardArmed, true);
  assert.equal(value.calls[0].params.route.password, params.route.password);
  assert.deepEqual(value.calls[0].params.managedRoute, params.managedRoute);
  const launched = await value.adapter.launch(launchParameters(result.routeId));
  assert.equal(launched.sessionId, 'owned_session'); assert.equal(launched.pid, 70001);
  const payload = value.calls.find(call => call.method === 'launch').params;
  assert.deepEqual(payload.args, ['literal;$(never-a-shell)']); assert.equal(payload.route, undefined);
  assert.equal(JSON.stringify(payload).includes(params.route.password), false);
  await value.adapter.shutdown();
  assert.deepEqual(value.calls.slice(-3).map(call => call.method), ['stop', 'revoke', 'shutdown']);
});

test('route receipt cannot swap environment, core, identity or unverified guard', async () => {
  for (const replacement of [{ profileId: 'other' }, { coreGeneration: 'stale' }, { routeIdentity: 'stale' },
    { applicationIdentity: 'different' }, { gid: 501 }, { guardArmed: false }, { managedRouteVerified: false },
    { verification: { ...acceptedState().verification, native: false } }]) {
    const value = fixture(), original = value.native.prepareRoute;
    value.native.prepareRoute = async params => ({ ...(await original(params)), ...replacement });
    await assert.rejects(value.adapter.prepareRoute(parameters()), { code: 'APPLICATION_ROUTING_NOT_READY' });
    assert.deepEqual(value.calls.map(call => call.method), ['prepareRoute', 'stop', 'revoke']);
  }
});

test('separate environments cannot share the same prepared GID', async () => {
  const value = fixture(), first = await value.adapter.prepareRoute(parameters()), other = parameters();
  other.application.profileId = 'environment_two'; other.managedRoute.profileId = 'environment_two';
  await assert.rejects(value.adapter.prepareRoute(other), { code: 'APPLICATION_ROUTING_NOT_READY' });
  assert.equal(value.adapter.routes.has(first.routeId), true);
  await value.adapter.shutdown();
});

test('an uncertain rejected preparation reserves its GID but can never launch', async () => {
  const value = fixture(), original = value.native.prepareRoute;
  value.native.prepareRoute = async params => ({ ...(await original(params)), guardArmed: false });
  value.native.stop = async params => { value.calls.push({ method: 'stop', params }); return { stopped: false }; };
  await assert.rejects(value.adapter.prepareRoute(parameters()), { code: 'APPLICATION_ROUTING_NOT_READY' });
  await assert.rejects(value.adapter.launch(launchParameters('owned_route_1')), { code: 'APPLICATION_ROUTING_NOT_READY' });
  value.native.prepareRoute = original;
  const other = parameters(); other.application.profileId = 'environment_two'; other.managedRoute.profileId = 'environment_two';
  await assert.rejects(value.adapter.prepareRoute(other), { code: 'APPLICATION_ROUTING_NOT_READY' });
  assert.equal(value.calls.some(call => call.method === 'launch' || call.method === 'revoke'), false);
});

test('launch rechecks readiness, prepared identity and rejects proxy environment fallback', async () => {
  const value = fixture();
  await assert.rejects(value.adapter.launch(launchParameters('not_prepared')), { code: 'APPLICATION_ROUTING_NOT_READY' });
  const prepared = await value.adapter.prepareRoute(parameters());
  const changed = launchParameters(prepared.routeId); changed.application.id = 'different';
  await assert.rejects(value.adapter.launch(changed), { code: 'APPLICATION_ROUTING_NOT_READY' });
  const proxyEnv = launchParameters(prepared.routeId); proxyEnv.env.HTTPS_PROXY = 'http://127.0.0.1:1';
  await assert.rejects(value.adapter.launch(proxyEnv), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  value.state.verification.checks.dns = false;
  await assert.rejects(value.adapter.launch(launchParameters(prepared.routeId)), { code: 'APPLICATION_ROUTING_NOT_READY' });
  assert.equal(value.calls.some(call => call.method === 'launch'), false);
  // A loss of readiness must leave cleanup available.
  assert.deepEqual(await value.adapter.stop({ routeId: prepared.routeId }), { stopped: true });
  assert.deepEqual(await value.adapter.revoke({ routeId: prepared.routeId }), { revoked: true });
});

test('uncertain launch cleanup retains deny route and refuses supervisor shutdown', async () => {
  const value = fixture(), prepared = await value.adapter.prepareRoute(parameters());
  value.native.launch = async params => { value.calls.push({ method: 'launch', params }); return { pid: 70001 }; };
  value.native.stop = async params => { value.calls.push({ method: 'stop', params }); return { stopped: false }; };
  await assert.rejects(value.adapter.launch(launchParameters(prepared.routeId)), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  await assert.rejects(value.adapter.launch(launchParameters(prepared.routeId)), { code: 'APPLICATION_ROUTING_NOT_READY' });
  assert.equal(value.adapter.routes.has(prepared.routeId), true);
  assert.equal(value.calls.some(call => call.method === 'revoke'), false);
  await assert.rejects(value.adapter.shutdown(), { code: 'APPLICATION_ROUTING_NOT_READY' });
  assert.equal(value.calls.some(call => call.method === 'shutdown'), false);
});

test('status and native errors expose only approved fields, never endpoints, env or credentials', async () => {
  const state = acceptedState(); state.password = 'fixture-private'; state.verification.password = 'fixture-private';
  state.sessions = [{ sessionId: 'owned_session', routeId: 'owned_route', status: 'running', pid: 70001, env: { PASSWORD: 'fixture-private' }, route: parameters().route }];
  const value = fixture(state), status = await value.adapter.status();
  assert.equal(JSON.stringify(status).includes('fixture-private'), false); assert.equal(JSON.stringify(status).includes('private-fixture-password'), false);
  value.native.setup = async () => { throw Object.assign(new Error('fixture-private'), { code: 'APPLICATION_ROUTING_NOT_READY' }); };
  await assert.rejects(value.adapter.setup({ activate: true }), error => error.code === 'APPLICATION_ROUTING_NOT_READY' && !error.message.includes('fixture-private'));
  const prepared = await value.adapter.prepareRoute(parameters());
  await value.adapter.revoke({ routeId: prepared.routeId }); await value.adapter.shutdown();
  await assert.rejects(value.adapter.status(), { code: 'APPLICATION_ROUTING_CLOSED' });
});

test('a failed installer reports only its fixed result reason and never echoes free text', async () => {
  const failed = (reason, schema = 'envara.macos-pf-install/v1') => JSON.stringify({ schema, action: 'installedResourcesOnly', installed: false, changed: false,
    ready: false, productionReady: false, manifestSHA256: 'a'.repeat(64), reason, needsManualReview: false });
  for (const [output, code] of [
    [failed('administrator-authorization-canceled'), 'APPLICATION_ROUTING_AUTHORIZATION_CANCELED'],
    [failed('administrator-authorization-denied'), 'APPLICATION_ROUTING_AUTHORIZATION_DENIED'],
    [failed('controlled-runtime-still-present'), 'APPLICATION_ROUTING_RUNTIME_PRESENT'],
    [failed('existing-installation-conflict'), 'APPLICATION_ROUTING_INSTALL_CONFLICT'],
    [failed('owned-staging-review-required'), 'APPLICATION_ROUTING_INSTALL_REVIEW'],
    [failed('installation-maintenance-busy'), 'APPLICATION_ROUTING_INSTALL_BUSY'],
    [failed('installation-completion-unconfirmed'), 'APPLICATION_ROUTING_INSTALL_INCOMPLETE'],
    [failed('private-fixture-password'), 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED'],
    [failed('controlled-runtime-still-present', 'untrusted'), 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED'],
    ['private-fixture-password', 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED']]) {
    const value = await installationFixture({ exitCode: 1, output });
    await assert.rejects(value.adapter.setup({ activate: true }), error => error.code === code && !error.message.includes('private-fixture-password') && /[一-鿿]/.test(error.message), code);
    assert.equal(value.native.helperPath, undefined); assert.deepEqual(value.calls, []);
    assert.equal(value.adapter.installationPending, false);
  }
});
