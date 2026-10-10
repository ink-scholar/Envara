import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { EventEmitter } from 'node:events';
import { createHash, randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import { MacOSPFController, MacOSPFExecutor, dispatchPFRequest, pfTunnelCoreConfig, pfInstallationPlan, normalizePFRouteTable,
  verifyPFInstallation, validatePFRootHookLease, PF_ROOT_HOOK_SCHEMA, PF_ROOT_HOOK_LEASE_SCHEMA, PF_INSTALL_ROOT, PF_RUNTIME_ROOT, PF_LEGACY_RUNTIME_ROOT, PF_MANIFEST_FILES } from '../native/macos-pf-routing/controller.mjs';
import { servePFHelper } from '../native/macos-pf-routing/helper.mjs';
import { createStatelessFixturePFRoutingPolicy, PF_ROUTING_ANCHOR, pfRoutingAnchor } from '../native/macos-pf-routing/policy.mjs';
import { statelessFixtureRoutes, statelessFixtureDestinations, printedStatelessFixtureReadback } from './fixtures/macos-pf-stateless-readback.mjs';

const proxy = { protocol: 'socks5', host: '127.0.0.1', port: 12345, username: 'private-fixture-user', password: 'private-fixture-password', udpPolicy: 'proxy' };
const inputRoute = () => ({ application: { id: 'application', profileId: 'environment', identity: 'fixture-identity', executablePath: '/Applications/Notion.app/Contents/MacOS/Notion' },
  workspace: { cwd: '/tmp/selected-workspace', timezone: 'Asia/Manila' }, route: { ...proxy },
  managedRoute: { profileId: 'environment', proxyId: 'managed-node', nodeType: 'anytls', routeIdentity: randomUUID(), coreGeneration: randomUUID(), corePid: 4242, coreVersion: 'v1.19.32' } });
const validInstallation = async () => ({ available: true, verified: true, runtimeVerified: true });
const hookPreflight = () => ({ canCreateOwnedHook: true, pfDisabled: true, pinsVerified: true, originalRootCompatible: true, priorAnchorsCompatible: true });
const leaseFor = runId => {
  const leaseId = randomUUID();
  return { schema: PF_ROOT_HOOK_LEASE_SCHEMA, runId, leaseId, anchor: pfRoutingAnchor(runId), owner: pfRoutingAnchor(runId),
    label: `envara.hook.v2.${createHash('sha256').update(`${runId}|${leaseId}`).digest('hex').slice(0, 32)}`,
    ticket: '1234605616436508552', rootBeforeSHA256: 'a'.repeat(64), rootBeforeTextSHA256: 'b'.repeat(64) };
};
function fakeExecutor(overrides = {}) {
  const logs = [], executor = {
    kind: 'simulated', exactStateCleanupSupported: true, fixtureOperations: ['realm-identities'],
    readOnlyStatus: async ({ runId } = {}) => ({ consoleUID: 501, pf: { enabled: false, stockAppleAnchorHook: false, priorAnchorsCompatible: true, fixtureEgressSkipVerified: true },
      ownedRootHook: { ...hookPreflight(), canCreateOwnedHook: Boolean(runId) }, exactStateCleanupSupported: true, fixtureOperations: ['realm-identities'] }),
    acquireLock: async runId => { executor.runtimeRunId = runId; logs.push('lock'); }, snapshotUnrelatedNetwork: async () => ({ digest: 'unchanged', pfDigest: 'pf', routeDigest: 'routes', dnsDigest: 'dns' }),
    installOwnedRootHook: async runId => { logs.push('insert-hook'); executor.rootHookLease = leaseFor(runId); return executor.rootHookLease; },
    removeOwnedRootHook: async lease => { assert.deepEqual(lease, executor.rootHookLease); logs.push('delete-hook'); executor.rootHookLease = null; return { ownedRootHookRemoved: true, originalRootRestored: true, namespaceState: 'absent', namespaceReclaimed: true, namespaceExists: false, receiptRetired: true, cleanupPending: false }; },
    confirmNoOwnedRootHook: async () => { logs.push('prove-absent-hook'); return { ownedRootHookRemoved: true, originalRootRestored: true, namespaceState: 'absent', namespaceReclaimed: true, namespaceExists: false, receiptRetired: true, cleanupPending: false }; },
    enableOwnedReference: async () => { logs.push('enable-reference'); executor.pfToken = '123456'; return { existingForeignPFStatesAbsentBeforeEnable: true }; },
    requireEmptyOwnedAnchor: async () => logs.push('empty-anchor'),
    allocateGroup: async () => { const gid = 7100 + logs.filter(event => event === 'group').length; logs.push('group'); return { gid, groupPath: `/Groups/_envara_pf_${gid}`, fresh: true }; },
    replaceOwnedRules: async (policy, run) => { assert.equal(run.runId, policy.runId); logs.push(policy.routes.length === 0 ? 'remove-anchor' : policy.routes.every(route => route.mode === 'blocked') ? 'block' : 'route'); },
    startTunnelCore: async ({ ipv4Address }) => { logs.push('core'); return { interfaceName: 'utun99', pid: 3210, instanceId: 'fixture_tunnel_identity', ipv4Address }; },
    launchFixture: async ({ gid }) => { logs.push('fixture'); return [{ role: 'parent', pid: 3220, birth: '1:000001', gid, suspended: true }]; },
    resumeOwnedFixtures: async () => logs.push('resume'), runFixtureCase: async () => ({ complete: true, evidence: { passed: true } }),
    terminateOwnedFixtures: async () => logs.push('stop-fixture'), assertNoOwnedGroupProcesses: async () => logs.push('quiescent'),
    clearExactOwnedStates: async () => logs.push('exact-states'), stopOwnedTunnel: async () => logs.push('release-tunnel'),
    removeGroups: async () => logs.push('delete-groups'), releaseOwnedReference: async () => { logs.push('release-reference'); executor.pfToken = null; },
    releaseLock: async () => logs.push('unlock'),
    ...overrides,
  };
  return { executor, logs };
}
function controllerFor(executor, extra = {}) { return new MacOSPFController({ executor, inspectInstallation: validInstallation,
  authenticateProxy: async () => true, identity: { uid: 0, euid: 0, callerUID: 501, controlledSession: true }, ...extra }); }
const acceptanceInput = () => ({ runId: randomUUID(), activationAuthorized: true, lifetimeSeconds: 30,
  slots: [{ slot: 'one', environmentId: randomUUID(), proxy: { ...proxy }, udpPolicy: 'proxy' }] });

function runtimeFilesystem() {
  const entries = new Map(), calls = []; let nextInode = 100;
  const add = (target, { type = 'directory', uid = 0, mode = 0o755, ino = nextInode++, realpath = target } = {}) => {
    const entry = { uid, mode, ino, dev: 1, type, realpath,
      isDirectory: () => type === 'directory', isFile: () => type === 'file', isSymbolicLink: () => type === 'symlink' };
    entries.set(target, entry); return entry;
  };
  for (const target of ['/', '/Library', '/Library/PrivilegedHelperTools']) add(target);
  const error = code => Object.assign(new Error(code), { code });
  const get = target => { if (!entries.has(target)) throw error('ENOENT'); return entries.get(target); };
  const children = target => [...entries.keys()].filter(name => path.dirname(name) === target).map(name => path.basename(name));
  const fileSystem = {
    lstat: async target => { calls.push(['lstat', target]); return get(target); },
    realpath: async target => get(target).realpath,
    readdir: async target => { get(target); return children(target); },
    mkdir: async (target, options) => { calls.push(['mkdir', target, options]); if (entries.has(target)) throw error('EEXIST'); get(path.dirname(target)); add(target, { mode: options.mode }); },
    open: async (target, flags, mode) => {
      calls.push(['open', target, flags, mode]);
      if (flags === 'wx') { if (entries.has(target)) throw error('EEXIST'); get(path.dirname(target)); add(target, { type: 'file', mode }); }
      const entry = get(target), captured = { ...entry };
      return { stat: async () => captured, writeFile: async contents => { entry.contents = String(contents); }, sync: async () => calls.push(['sync', target]), close: async () => calls.push(['close', target]) };
    },
    rename: async (from, to) => { calls.push(['rename', from, to]); entries.set(to, get(from)); entries.delete(from); },
    unlink: async target => { calls.push(['unlink', target]); get(target); entries.delete(target); },
    rmdir: async target => { calls.push(['rmdir', target]); get(target); if (children(target).length) throw error('ENOTEMPTY'); entries.delete(target); },
  };
  return { fileSystem, entries, calls, add };
}

test('default status and setup remain read-only with no readiness promotion', async () => {
  const { executor, logs } = fakeExecutor(); const controller = controllerFor(executor);
  const status = await controller.status(), setup = await controller.setup({ activate: true, activationAuthorized: true });
  assert.equal(status.backend, 'pf-utun'); assert.equal(status.ready, false); assert.equal(status.verification.native, false);
  assert.equal(status.authorization.kind, 'privileged-helper'); assert.ok(Object.values(status.capabilities).every(value => value === false));
  assert.equal(setup.activated, false); assert.equal(setup.readOnly, true); assert.equal(setup.installationPlan.automaticInstallation, false);
  assert.deepEqual(logs, []); await controller.shutdown();
});

test('prepared routes keep proxy credentials private and never launch an application', async () => {
  const { executor, logs } = fakeExecutor(); const controller = controllerFor(executor);
  const input = inputRoute(), receipt = await controller.prepareRoute(input);
  assert.equal(receipt.prepared, true); assert.equal(receipt.managedRouteVerified, false); assert.equal(receipt.ready, false);
  assert.equal(receipt.routeIdentity, input.managedRoute.routeIdentity);
  const status = JSON.stringify(await controller.status());
  assert.ok(!status.includes(proxy.username) && !status.includes(proxy.password) && !status.includes('selected-workspace'));
  await assert.rejects(controller.launch({ routeId: receipt.routeId, activationAuthorized: true }), { code: 'APPLICATION_ROUTING_NOT_READY' });
  assert.deepEqual(logs, []); await controller.revoke({ routeId: receipt.routeId }); await controller.shutdown();
});

test('managed generation and authentication failures cannot become prepare receipts', async () => {
  const { executor } = fakeExecutor(); const controller = controllerFor(executor);
  const input = inputRoute(); delete input.managedRoute;
  await assert.rejects(controller.prepareRoute(input), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  const wrongProfile = inputRoute(); wrongProfile.managedRoute.profileId = 'different';
  await assert.rejects(controller.prepareRoute(wrongProfile), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  const failing = controllerFor(executor, { authenticateProxy: async () => { throw new Error(proxy.password); } });
  await assert.rejects(failing.prepareRoute(inputRoute()), error => error.code === 'APPLICATION_PROXY_UNAVAILABLE' && !error.message.includes(proxy.password));
  await controller.shutdown(); await failing.shutdown();
});

test('no privileged mutation precedes root-owned runtime trust, authorization and exact cleanup', async () => {
  for (const mode of ['no-authorization', 'no-runtime-trust', 'no-cleanup', 'no-hook']) {
    const options = mode === 'no-cleanup' ? { exactStateCleanupSupported: false } : mode === 'no-hook' ? { readOnlyStatus: async () => ({ consoleUID: 501, pf: { stockAppleAnchorHook: true }, ownedRootHook: { canCreateOwnedHook: false } }) } : {};
    const { executor, logs } = fakeExecutor(options);
    const controller = controllerFor(executor, mode === 'no-runtime-trust' ? { inspectInstallation: async () => ({ verified: true, runtimeVerified: false }) } : {});
    const input = acceptanceInput(); if (mode === 'no-authorization') input.activationAuthorized = false;
    await assert.rejects(controller.prepareOwnedFixtures(input)); assert.deepEqual(logs, []); await controller.shutdown();
  }
});

test('controlled fixture ordering commits deny before transport, then routes before resume', async () => {
  const { executor, logs } = fakeExecutor(); const controller = controllerFor(executor), input = acceptanceInput();
  const run = await controller.prepareOwnedFixtures(input);
  assert.equal(run.protected, false); assert.equal(run.productionReceiptAllowed, false); assert.equal(run.nativeObserved, false);
  assert.deepEqual(logs, ['lock', 'insert-hook', 'empty-anchor', 'group', 'block', 'enable-reference', 'core', 'fixture', 'route', 'resume']);
  const evidence = await controller.runOwnedFixtureCase({ runId: input.runId, caseId: 'realm-identities' });
  assert.equal(evidence.nativeObserved, false); assert.equal(evidence.ready, false);
  assert.equal((await controller.status()).verification.passed, false);
  const cleanup = await controller.cleanupOwnedFixtures({ runId: input.runId });
  assert.equal(cleanup.cleanupUncertain, false); assert.equal(cleanup.ownedProcessesExited, true);
  assert.ok(logs.indexOf('quiescent') < logs.indexOf('exact-states'));
  assert.ok(logs.indexOf('exact-states') < logs.indexOf('release-tunnel'));
  assert.ok(logs.indexOf('release-tunnel') < logs.indexOf('remove-anchor'));
  assert.ok(logs.indexOf('delete-groups') < logs.indexOf('unlock'));
  assert.ok(logs.indexOf('release-reference') < logs.indexOf('delete-hook'));
  assert.ok(logs.indexOf('delete-hook') < logs.indexOf('unlock'));
  assert.equal(cleanup.evidence.ownedRootHookRemoved, true); assert.equal(cleanup.evidence.originalRootRestored, true);
  assert.equal(cleanup.evidence.ownedPFReferenceReleased, true);
  await assert.rejects(controller.prepareOwnedFixtures(input), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  await controller.shutdown();
});

test('uncertain cleanup retains groups, tunnels and lock rather than opening direct routing', async () => {
  const { executor, logs } = fakeExecutor({ clearExactOwnedStates: async () => { logs.push('exact-states-failed'); throw new Error(); } });
  const controller = controllerFor(executor), input = acceptanceInput(); await controller.prepareOwnedFixtures(input);
  const result = await controller.cleanupOwnedFixtures({ runId: input.runId });
  assert.equal(result.cleanupUncertain, true); assert.equal(result.ownedProcessesExited, true); assert.equal(result.ownedAnchorStatesPurged, false);
  assert.ok(!logs.includes('release-tunnel') && !logs.includes('delete-groups') && !logs.includes('unlock') && !logs.includes('remove-anchor'));
  assert.equal((await controller.shutdown()).cleanupRequired, true);
});

test('tunnel config has authenticated managed SOCKS, owned FD and no global interception or direct fallback', () => {
  const config = pfTunnelCoreConfig({ proxy, udpPolicy: 'proxy', ipv4Address: '198.18.2.1' });
  assert.equal(config.tun['file-descriptor'], 3); assert.equal(config.tun['auto-route'], false); assert.equal(config.tun['auto-redirect'], false);
  assert.equal(config.tun.mtu, 9000); assert.ok(config.tun.mtu > 4096 + 20 + 8);
  assert.equal(config.tun['auto-detect-interface'], false); assert.equal(config.dns.enable, false); assert.equal(config.dns.listen, '');
  assert.equal(config.proxies[0].username, proxy.username); assert.deepEqual(config.rules, ['MATCH,ENVARA_MANAGED_ROUTE']);
  assert.equal(config.ntp['write-to-system'], false); assert.equal(config['external-controller'], '');
  assert.ok(!JSON.stringify(config).includes('DIRECT'));
  assert.throws(() => pfTunnelCoreConfig({ proxy: { ...proxy, host: '8.8.8.8' } }));
});

test('restricted executor denies global flush, root rules, routes, host DNS, arbitrary executables and state guesses', () => {
  const executor = new MacOSPFExecutor();
  for (const args of [['-F', 'all'], ['-F', 'states'], ['-i', 'utun9', '-F', 'states'], ['-k', '198.18.1.1'], ['-k', 'id', '-k', '42'],
    ['-a', 'other-anchor', '-f', '-'], ['-f', '/etc/pf.conf'], ['-d']]) assert.equal(executor.allowedCommand('/sbin/pfctl', args), false);
  assert.equal(executor.allowedCommand('/sbin/pfctl', ['-a', PF_ROUTING_ANCHOR, '-f', '-']), false);
  const lease = leaseFor(randomUUID()); executor.rootHookLease = lease; executor.runtimeRunId = lease.runId;
  assert.equal(executor.allowedCommand('/sbin/pfctl', ['-a', lease.anchor, '-f', '-']), false);
  assert.equal(executor.allowedCommand('/sbin/pfctl', ['-n', '-a', lease.anchor, '-f', '-']), false);
  assert.equal(executor.allowedCommand(`${PF_INSTALL_ROOT}/envara-pf-native`, ['replace-owned-filter']), true);
  assert.equal(executor.allowedCommand('/sbin/route', ['add', 'default', '198.18.1.1']), false);
  assert.equal(executor.allowedCommand('/usr/sbin/networksetup', ['-setdnsservers', 'Wi-Fi', '1.1.1.1']), false);
  assert.equal(executor.allowedCommand('/bin/sh', ['-c', 'anything']), false);
  assert.equal(executor.allowedCommand('/usr/bin/dscl', ['.', '-delete', '/Groups/staff']), false);
  assert.equal(executor.exactStateCleanupSupported, false);
});

test('installation plan is fixed and rejects a caller-controlled destination', async () => {
  const plan = pfInstallationPlan();
  assert.equal(plan.root, PF_INSTALL_ROOT); assert.equal(plan.appleDeveloperAccountRequired, false);
  assert.equal(plan.runtimeRoot, '/Library/PrivilegedHelperTools/io.envara.pf-runtime');
  assert.notEqual(plan.root, plan.runtimeRoot);
  assert.ok(Object.values(plan.changes).every(value => value === false));
  assert.equal((await verifyPFInstallation({ root: '/tmp/user-owned' })).verified, false);
});

test('the private registry holds a safe fixed parent and does not depend on stock var/run permissions', async () => {
  const fixture = runtimeFilesystem(), executor = new MacOSPFExecutor({ fileSystem: fixture.fileSystem }), runId = randomUUID();
  fixture.add('/private/var/run', { uid: 0, mode: 0o775 });
  await executor.acquireLock(runId);
  assert.equal(PF_RUNTIME_ROOT, '/Library/PrivilegedHelperTools/io.envara.pf-runtime');
  assert.equal(PF_LEGACY_RUNTIME_ROOT, '/var/run/envara-pf-routing');
  assert.equal(fixture.entries.get(PF_RUNTIME_ROOT).mode, 0o700);
  const parentOpen = fixture.calls.find(call => call[0] === 'open' && call[1] === path.dirname(PF_RUNTIME_ROOT));
  for (const flag of [fsConstants.O_DIRECTORY, fsConstants.O_NOFOLLOW]) assert.equal(parentOpen[2] & flag, flag);
  assert.ok(!fixture.calls.some(call => call[1] === '/private/var/run'));
  const realmId = randomUUID();
  await executor.createRunDirectory(runId, realmId); await executor.createRunDirectory(runId, realmId);
  await executor.persistRun({ runId, phase: 'cleaned', realms: [] });
  assert.ok(fixture.entries.has(`${PF_RUNTIME_ROOT}/registry.json`));
  await executor.releaseLock();
  assert.deepEqual(await fixture.fileSystem.readdir(PF_RUNTIME_ROOT), []);
  assert.equal(executor.lock, null); assert.equal(executor.runtimeDirectory, null); assert.equal(executor.runtimeParent, null);
  const removed = fixture.calls.filter(call => call[0] === 'rmdir').map(call => call[1]);
  assert.deepEqual(removed, [`${PF_RUNTIME_ROOT}/${runId}/${realmId}`, `${PF_RUNTIME_ROOT}/${runId}`]);
});

test('production registry stores the exact private filter intent and receipt then flushes the held runtime parent', async () => {
  const fixture = runtimeFilesystem(), executor = new MacOSPFExecutor({ fileSystem: fixture.fileSystem }), runId = randomUUID();
  await executor.acquireLock(runId);
  const intent = { schema: 'envara.macos-pf-filter-replacement/v1', generation: randomUUID(), state: 'pending',
    previous: { mode: 'empty', realms: [], writerPid: 0, filterRevision: null }, next: { mode: 'empty', realms: [] } };
  const receipt = { schema: intent.schema, generation: randomUUID(), mode: 'deny', ruleCount: 6, writerPid: 6000, filterRevision: '0' };
  await executor.persistRun({ runId, phase: 'preparing', realms: [], filterReplacement: intent, filterReceipt: receipt });
  const record = JSON.parse(fixture.entries.get(`${PF_RUNTIME_ROOT}/registry.json`).contents);
  assert.deepEqual(record.filterReplacement, intent); assert.deepEqual(record.filterReceipt, receipt);
  const rename = fixture.calls.findIndex(call => call[0] === 'rename');
  assert.ok(fixture.calls.slice(rename + 1).some(call => call[0] === 'sync' && call[1] === PF_RUNTIME_ROOT));
  await executor.releaseLock();
});

test('application registry persists only projected first and cleanup failures without creating a pinned run diagnostic file', async () => {
  const fixture = runtimeFilesystem(), executor = new MacOSPFExecutor({ fileSystem: fixture.fileSystem }), runId = randomUUID();
  await executor.acquireLock(runId);
  const initialFailure = { stage: 'cold-stage', code: 'APPLICATION_APP_NATIVE_REFUSED', native: { stage: 'guardian', reason: 'NATIVE_NOTION_STAGE_REFUSED', error: 13 } };
  const cleanupFailure = { stage: 'cleanup', code: 'APPLICATION_APP_TRANSPORT_UNCONFIRMED' };
  await executor.persistRun({ kind: 'application', runId, phase: 'cleanup-required', realms: [], initialFailure, cleanupFailure });
  const stored = JSON.parse(fixture.entries.get(`${PF_RUNTIME_ROOT}/registry.json`).contents);
  assert.deepEqual(stored.application.initialFailure, initialFailure); assert.deepEqual(stored.application.cleanupFailure, cleanupFailure);
  assert.equal(stored.application.channelTermination, null);
  assert.deepEqual(await fixture.fileSystem.readdir(PF_RUNTIME_ROOT), ['registry.lock', 'registry.json']);
  await executor.releaseLock();
});
test('lost owned PF release reply can only reconcile disabled state and never replay its issued token', async () => {
  for (const disabled of [false, true]) {
    const executor = new MacOSPFExecutor(), runId = randomUUID(), calls = [];
    executor.rootHookLease = leaseFor(runId); executor.pfToken = '123'; executor.pfReferenceMutationAttempted = true;
    executor.command = async (executable, argv) => { calls.push(argv); throw new Error('lost reply'); };
    executor.readHookStatus = async value => { assert.deepEqual(value, { lease: executor.rootHookLease }); return { pfDisabled: disabled }; };
    await assert.rejects(executor.releaseOwnedReference());
    if (disabled) { await executor.releaseOwnedReference(); assert.equal(executor.pfToken, null); }
    else { await assert.rejects(executor.releaseOwnedReference()); assert.equal(executor.pfToken, '123'); }
    assert.deepEqual(calls, [['-X', '123']]);
  }
});
test('Directory Services cleanup compares the captured GeneratedUID and reconciles only its own attempted deletion', async () => {
  for (const scenario of ['replacement', 'lost-delete', 'absent-no-intent']) {
    const executor = new MacOSPFExecutor(), groupPath = '/Groups/_envara_pf_7100', realm = { gid: 7100, groupPath }, deleted = [];
    executor.groups.set(groupPath, 7100); executor.groupIdentities.set(groupPath, { gid: 7100, generatedUID: 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA' });
    let present = scenario !== 'absent-no-intent';
    executor.command = async (executable, argv) => {
      if (executable === '/bin/ps') return { stdout: '1 0 0\n' };
      if (argv[1] === '-list') return { stdout: present ? '_envara_pf_7100 7100\n' : '' };
      if (argv[1] === '-read') return { stdout: `GeneratedUID: ${scenario === 'replacement' ? 'BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB' : 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA'}\nPrimaryGroupID: 7100\n` };
      deleted.push(argv); present = false; throw new Error('delete response lost');
    };
    await assert.rejects(executor.removeGroups([realm]));
    if (scenario === 'lost-delete') { await executor.removeGroups([realm]); assert.equal(realm.groupRemoved, true); assert.equal(deleted.length, 1); }
    else { assert.equal(deleted.length, 0); assert.notEqual(realm.groupRemoved, true); }
  }
});
test('partial exact registry retirement retries absent own inodes but refuses replacement files and new registry writes', async () => {
  for (const replacement of [false, true]) {
    const fixture = runtimeFilesystem(), executor = new MacOSPFExecutor({ fileSystem: fixture.fileSystem }), runId = randomUUID();
    await executor.acquireLock(runId); await executor.persistRun({ runId, phase: 'cleaned', realms: [] });
    const unlink = fixture.fileSystem.unlink; let failed = false;
    fixture.fileSystem.unlink = async target => {
      if (target === `${PF_RUNTIME_ROOT}/registry.lock` && !failed) { failed = true; throw Object.assign(new Error(), { code: 'EIO' }); }
      return unlink(target);
    };
    await assert.rejects(executor.releaseLock()); assert.equal(fixture.entries.has(`${PF_RUNTIME_ROOT}/registry.json`), false);
    await assert.rejects(executor.persistRun({ runId, phase: 'cleaned', realms: [] }));
    if (replacement) fixture.add(`${PF_RUNTIME_ROOT}/registry.json`, { type: 'file', mode: 0o600 });
    if (replacement) { await assert.rejects(executor.releaseLock()); assert.equal(fixture.entries.has(`${PF_RUNTIME_ROOT}/registry.json`), true); }
    else { await executor.releaseLock(); assert.equal(executor.lock, null); assert.deepEqual(await fixture.fileSystem.readdir(PF_RUNTIME_ROOT), []); }
  }
});

test('readonly loopback coverage requires explicit actual lo0 and rejects skipped groups or unknown flags', async () => {
  for (const [stdout, expected] of [['all\nlo\nlo0\nen0\n', true], ['en0\nlo0 (skip)\n', false], ['en0\n', false],
    ['all (skip)\nlo0\n', false], ['lo (skip)\nlo0\n', false]]) {
    const executor = new MacOSPFExecutor(), calls = [];
    executor.command = async (file, args) => { calls.push({ file, args }); return { stdout }; };
    assert.equal(await executor.inspectLoopbackPF(), expected);
    assert.deepEqual(calls, [{ file: '/sbin/pfctl', args: ['-v', '-s', 'Interfaces'] }]);
  }
  for (const stdout of ['', 'lo0\nlo0\n', 'lo0 unknown\n']) {
    const executor = new MacOSPFExecutor(); executor.command = async () => ({ stdout });
    await assert.rejects(executor.inspectLoopbackPF(), { code: 'APPLICATION_ROUTING_NOT_READY' });
  }
});

test('any legacy runtime entry blocks new registry creation without opening or deleting the old evidence', async () => {
  for (const type of ['directory', 'file', 'symlink']) {
    const fixture = runtimeFilesystem(); fixture.add(PF_LEGACY_RUNTIME_ROOT, { type, uid: 0, mode: 0o700 });
    const executor = new MacOSPFExecutor({ fileSystem: fixture.fileSystem });
    await assert.rejects(executor.acquireLock(randomUUID()), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
    assert.deepEqual(fixture.calls, [['lstat', PF_LEGACY_RUNTIME_ROOT]]);
    assert.ok(fixture.entries.has(PF_LEGACY_RUNTIME_ROOT)); assert.ok(!fixture.entries.has(PF_RUNTIME_ROOT));
  }
});

test('unsafe new registry roots and any stale entries are rejected without deleting or overwriting evidence', async () => {
  for (const condition of ['writable-parent', 'nonroot-parent', 'root-symlink', 'public-root', 'registry', 'unknown']) {
    const fixture = runtimeFilesystem();
    if (condition === 'writable-parent') fixture.add(path.dirname(PF_RUNTIME_ROOT), { mode: 0o775 });
    if (condition === 'nonroot-parent') fixture.add(path.dirname(PF_RUNTIME_ROOT), { uid: 501 });
    if (condition === 'root-symlink') fixture.add(PF_RUNTIME_ROOT, { type: 'symlink', mode: 0o700 });
    if (condition === 'public-root') fixture.add(PF_RUNTIME_ROOT, { mode: 0o755 });
    if (condition === 'registry' || condition === 'unknown') {
      fixture.add(PF_RUNTIME_ROOT, { mode: 0o700 });
      fixture.add(`${PF_RUNTIME_ROOT}/${condition === 'registry' ? 'registry.json' : 'unrecognized-evidence'}`, { type: 'file', mode: 0o600 });
    }
    const before = [...fixture.entries.keys()], executor = new MacOSPFExecutor({ fileSystem: fixture.fileSystem });
    await assert.rejects(executor.acquireLock(randomUUID()), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
    assert.deepEqual([...fixture.entries.keys()], before);
    assert.ok(!fixture.calls.some(call => ['unlink', 'rmdir', 'rename'].includes(call[0]) || call[0] === 'open' && call[2] === 'wx'));
    assert.equal(executor.runtimeDirectory, null); assert.equal(executor.runtimeParent, null);
  }
});

test('a replaced held parent or runtime directory cannot receive a registry write or cleanup', async () => {
  const parentRace = runtimeFilesystem(), originalMkdir = parentRace.fileSystem.mkdir;
  parentRace.fileSystem.mkdir = async (...args) => { await originalMkdir(...args); parentRace.add(path.dirname(PF_RUNTIME_ROOT)); };
  await assert.rejects(new MacOSPFExecutor({ fileSystem: parentRace.fileSystem }).acquireLock(randomUUID()), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
  assert.ok(!parentRace.calls.some(call => call[0] === 'open' && call[2] === 'wx'));
  const fixture = runtimeFilesystem(), executor = new MacOSPFExecutor({ fileSystem: fixture.fileSystem }), runId = randomUUID();
  await executor.acquireLock(runId); fixture.add(PF_RUNTIME_ROOT, { mode: 0o700 });
  await assert.rejects(executor.persistRun({ runId, phase: 'cleaned', realms: [] }), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
  await assert.rejects(executor.releaseLock(), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
  assert.ok(fixture.entries.has(`${PF_RUNTIME_ROOT}/registry.lock`));
  assert.ok(!fixture.calls.some(call => call[0] === 'unlink' || call[0] === 'rename'));
});

test('unknown files in an owned run directory retain the exact registry and lock during cleanup', async () => {
  const fixture = runtimeFilesystem(), executor = new MacOSPFExecutor({ fileSystem: fixture.fileSystem }), runId = randomUUID(), realmId = randomUUID();
  await executor.acquireLock(runId); await executor.createRunDirectory(runId, realmId);
  await executor.persistRun({ runId, phase: 'cleaned', realms: [] });
  const unknown = `${PF_RUNTIME_ROOT}/${runId}/${realmId}/unknown-core-file`;
  fixture.add(unknown, { type: 'file', mode: 0o600 });
  await assert.rejects(executor.releaseLock(), { code: 'ENOTEMPTY' });
  for (const target of [unknown, `${PF_RUNTIME_ROOT}/registry.json`, `${PF_RUNTIME_ROOT}/registry.lock`]) assert.ok(fixture.entries.has(target));
  assert.ok(executor.lock); assert.ok(!fixture.calls.some(call => call[0] === 'unlink'));
  await assert.rejects(executor.createRunDirectory(randomUUID(), realmId), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
});

test('a replaced lock, registry or unknown root entry is never removed to make a runtime idle', async () => {
  for (const condition of ['foreign-lock', 'foreign-registry', 'unknown-entry']) {
    const fixture = runtimeFilesystem(), executor = new MacOSPFExecutor({ fileSystem: fixture.fileSystem }), runId = randomUUID();
    await executor.acquireLock(runId); await executor.persistRun({ runId, phase: 'cleaned', realms: [] });
    if (condition === 'foreign-lock') fixture.add(`${PF_RUNTIME_ROOT}/registry.lock`, { type: 'file', mode: 0o600 });
    else if (condition === 'foreign-registry') fixture.add(`${PF_RUNTIME_ROOT}/registry.json`, { type: 'file', mode: 0o600 });
    else fixture.add(`${PF_RUNTIME_ROOT}/unrecognized-evidence`, { type: 'file', mode: 0o600 });
    await assert.rejects(executor.releaseLock(), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
    assert.ok(fixture.entries.has(`${PF_RUNTIME_ROOT}/registry.json`));
    assert.ok(fixture.entries.has(`${PF_RUNTIME_ROOT}/registry.lock`));
    assert.ok(!fixture.calls.some(call => call[0] === 'unlink'));
  }
});

test('a replaced empty realm directory is preserved rather than removed by its old pathname', async () => {
  const fixture = runtimeFilesystem(), executor = new MacOSPFExecutor({ fileSystem: fixture.fileSystem }), runId = randomUUID(), realmId = randomUUID();
  await executor.acquireLock(runId); await executor.createRunDirectory(runId, realmId);
  const directory = `${PF_RUNTIME_ROOT}/${runId}/${realmId}`; fixture.add(directory, { mode: 0o700 });
  await assert.rejects(executor.releaseLock(), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
  assert.ok(fixture.entries.has(directory)); assert.ok(fixture.entries.has(`${PF_RUNTIME_ROOT}/registry.lock`));
  assert.ok(!fixture.calls.some(call => ['rmdir', 'unlink'].includes(call[0])));
});

test('root-owned manifests must hash exact runtime files and retain pinned Mihomo provenance', async () => {
  const contents = Object.fromEntries(Object.keys(PF_MANIFEST_FILES).map(name => [name, Buffer.from(`fixture-${name}`)]));
  const sha = bytes => createHash('sha256').update(bytes).digest('hex');
  const manifest = { schema: 'envara.macos-pf-installation/v1', component: 'envara-pf-routing', backend: 'pf-utun', version: '1', platform: 'darwin', arch: 'arm64',
    files: Object.fromEntries(Object.entries(contents).map(([name, bytes]) => [name, sha(bytes)])) };
  const fileSystem = {
    realpath: async target => target,
    lstat: async target => { const regular = target.startsWith(`${PF_INSTALL_ROOT}/`) && (target.endsWith('manifest.json') || Object.keys(contents).some(name => target === `${PF_INSTALL_ROOT}/${name}`));
      return { uid: 0, mode: regular ? 0o755 : 0o755, size: 1024, isSymbolicLink: () => false, isFile: () => regular, isDirectory: () => !regular }; },
    readFile: async target => target.endsWith('/manifest.json') ? Buffer.from(JSON.stringify(manifest)) : contents[target.slice(PF_INSTALL_ROOT.length + 1)],
  };
  const result = await verifyPFInstallation({ fileSystem });
  assert.equal(result.available, true); assert.equal(result.verified, false); // Fixture bytes cannot pretend to be the fixed official Mihomo.
  const insecureFS = { ...fileSystem, lstat: async target => ({ ...(await fileSystem.lstat(target)), uid: target.endsWith('controller.mjs') ? 501 : 0 }) };
  assert.equal((await verifyPFInstallation({ fileSystem: insecureFS })).verified, false);
});

test('RPC dispatch cannot select shell operations or accept a forged envelope', async () => {
  const { executor, logs } = fakeExecutor(); const controller = controllerFor(executor);
  for (const request of [{ protocol: 'other', version: 1, id: 'a', method: 'status' }, { protocol: 'envara.application-routing', version: 1, id: 'a', method: 'exec', params: { command: '/bin/sh' } }]) await assert.rejects(dispatchPFRequest(controller, request), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  assert.deepEqual(logs, []); await controller.shutdown();
});

test('bounded private RPC returns sanitized errors, never credentials or request details', async () => {
  const input = new PassThrough(), output = new PassThrough(); let response = '';
  output.on('data', bytes => { response += bytes.toString('utf8'); });
  const controller = { closed: false, status: async () => { throw Object.assign(new Error(proxy.password), { code: 'APPLICATION_ROUTING_NOT_READY' }); }, shutdown: async () => ({ cleanupRequired: false }) };
  const running = servePFHelper({ controller, input, output, maxBytes: 1024 });
  input.end(JSON.stringify({ protocol: 'envara.application-routing', version: 1, id: 'safe-id', method: 'status', params: { password: proxy.password } }));
  await running;
  const parsed = JSON.parse(response); assert.equal(parsed.error.code, 'APPLICATION_ROUTING_NOT_READY'); assert.ok(!response.includes(proxy.password));
  const hugeInput = new PassThrough(), hugeOutput = new PassThrough(); let huge = '';
  hugeOutput.on('data', bytes => { huge += bytes; });
  const oversized = servePFHelper({ controller, input: hugeInput, output: hugeOutput, maxBytes: 1024 }); hugeInput.end(Buffer.alloc(4096, 65));
  await oversized; assert.equal(JSON.parse(huge).error.code, 'APPLICATION_ROUTING_PROTOCOL_ERROR'); assert.ok(huge.length < 512);
});

test('root UID alone or an RPC caller-uid claim cannot authorize the controlled lifecycle', async () => {
  const { executor, logs } = fakeExecutor();
  for (const identity of [{ uid: 0, euid: 0 }, { uid: 501, euid: 501, callerUID: 501, controlledSession: true },
    { uid: 0, euid: 0, callerUID: 502, controlledSession: true }]) {
    const controller = controllerFor(executor, { identity });
    assert.equal((await controller.status()).authorization.verified, false);
    await assert.rejects(controller.prepareOwnedFixtures({ ...acceptanceInput(), callerUID: 501, trusted: true }), { code: 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED' });
    await controller.shutdown();
  }
  assert.deepEqual(logs, []);
});

test('stateless experiment resumes sealed bind-only fixtures under deny, reserves descriptors, then commits no-state routing', async () => {
  const { executor, logs } = fakeExecutor();
  executor.statelessControlledFixtures = true;
  executor.readOnlyStatus = async () => ({ consoleUID: 501, pf: { enabled: false, stockAppleAnchorHook: false }, ownedRootHook: hookPreflight(),
    exactStateCleanupSupported: false, statelessControlledFixtures: true, noStateNativeAvailable: true });
  executor.discoverFixtureChildren = async realm => { logs.push('child'); realm.fixtures.push({ role: 'child', pid: 3221, birth: '1:000002', gid: realm.gid, suspended: false }); };
  executor.reserveFixtureTuples = async run => { logs.push('reserve'); run.stateChecks = [{ reservedDestinationsAbsent: true }];
    return { source: 'native-pf', freshTuplesVerified: true, noExistingOwnedStatesVerified: true, noStateRulesVerified: true, denyBeforeResumeVerified: true }; };
  executor.verifyInstalledStatelessRules = async policy => { logs.push('readback'); assert.equal(policy.fixtureOnly, true);
    assert.ok(!policy.rules.includes('keep state')); assert.ok(policy.rules.includes('flags any no state')); return { noStateRulesVerified: true }; };
  executor.clearExactOwnedStates = async run => { logs.push('states-absent'); assert.equal(run.stateless, true); run.noOwnedStatesRemainVerified = true; };
  const controller = controllerFor(executor), input = { ...acceptanceInput(), controlledExperiment: true, caseIds: ['realm-identities', 'tcp-half-close'] };
  const result = await controller.prepareOwnedFixtures(input);
  assert.deepEqual(logs, ['lock', 'insert-hook', 'empty-anchor', 'group', 'block', 'enable-reference', 'core', 'fixture', 'resume', 'child', 'reserve', 'route', 'readback']);
  assert.equal(result.nativeObserved, false); assert.equal(result.ready, false); assert.equal(result.productionReceiptAllowed, false);
  assert.equal(result.realms[0].fixtures.length, 2); assert.equal(result.statelessEvidence.freshTuplesVerified, true);
  const cleanup = await controller.cleanupOwnedFixtures({ runId: input.runId });
  assert.equal(cleanup.ownedAnchorStatesPurged, false); assert.equal(cleanup.evidence.noOwnedStatesRemainVerified, true);
  assert.equal(cleanup.evidence.noOwnedStatesCreatedVerified, true); assert.equal(cleanup.evidence.source, 'simulated');
  assert.equal(cleanup.cleanupUncertain, false); assert.deepEqual(await controller.cleanupOwnedFixtures({ runId: input.runId }), cleanup);
  await controller.shutdown();
});

test('unexpected existing reserved-destination PF state is refused without killing any state', async () => {
  const executor = new MacOSPFExecutor(); const calls = [];
  executor.command = async (file, args) => { calls.push({ file, args }); return { stdout: 'en0 tcp 192.0.2.15:59210 -> 198.51.100.42:44441 ESTABLISHED:ESTABLISHED\n' }; };
  await assert.rejects(executor.confirmReservedStatesAbsent({ reservations: [] }), { code: 'APPLICATION_ROUTING_NOT_READY' });
  assert.deepEqual(calls, [{ file: '/sbin/pfctl', args: ['-ss'] }]);
});

test('PF skip or unreadable interfaces refuse a fixture rather than editing the user configuration', async () => {
  for (const text of ['en0 (skip)\nutun9\nlo0 (skip)\n', 'unrecognised interface data\n', '']) {
    const executor = new MacOSPFExecutor(), calls = [];
    executor.command = async (file, args) => { calls.push({ file, args }); return { stdout: file === '/sbin/pfctl' ? text : 'interface: en0\n' }; };
    await assert.rejects(executor.assertRequiredInterfacesNotSkipped(['utun9']), { code: 'APPLICATION_ROUTING_NOT_READY' });
    assert.ok(calls.every(call => call.file === '/sbin/pfctl' && call.args.join(' ') === '-v -s Interfaces' || call.file === '/sbin/route' && call.args[0] === '-n'));
  }
});

test('the owned-anchor writer rejects arbitrary PF text even with a correct anchor name', async () => {
  const executor = new MacOSPFExecutor(); let calls = 0; executor.command = async () => { calls++; return { stdout: '' }; };
  await assert.rejects(executor.replaceOwnedRules({ anchor: PF_ROUTING_ANCHOR, routes: [], rules: 'pass out quick all\n' }), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  assert.equal(calls, 0);
});

test('native executor compares real-shaped expanded singleton readback rather than source pass-line count', async () => {
  const policy = createStatelessFixturePFRoutingPolicy(statelessFixtureRoutes, { fixtureDestinations: statelessFixtureDestinations, runId: 'e152b0ec-3e0c-4b6a-a4ec-18cf1f3435b5' });
  const actual = printedStatelessFixtureReadback(), executor = new MacOSPFExecutor(), calls = [];
  executor.runtimeRunId = policy.runId; executor.rootHookLease = leaseFor(policy.runId);
  executor.command = async (file, args, stdin) => { calls.push({ file, args, stdin }); return { stdout: actual }; };
  const result = await executor.verifyInstalledStatelessRules(policy);
  assert.equal(policy.rules.split('\n').filter(line => line.startsWith('pass ')).length, 16);
  assert.equal(result.passRuleCount, 40); assert.equal(result.expandedRuleCount, 56);
  assert.equal(result.noStateRulesVerified, true); assert.equal(result.nativeAcceptance, false); assert.equal(result.productionReady, false);
  assert.equal(result.installedRulesDigest, createHash('sha256').update(actual).digest('hex'));
  assert.deepEqual(calls, [{ file: '/sbin/pfctl', args: ['-a', policy.anchor, '-sr'], stdin: undefined }]);
});

test('native readback refuses same-count scope changes, extra rules, source-text mocks and stateful rules', async () => {
  const policy = createStatelessFixturePFRoutingPolicy(statelessFixtureRoutes, { fixtureDestinations: statelessFixtureDestinations, runId: 'e152b0ec-3e0c-4b6a-a4ec-18cf1f3435b5' });
  const actual = printedStatelessFixtureReadback();
  for (const stdout of [policy.rules, actual.replace('port = 44442', 'port = 44441'),
    actual.replace('group = 7100', 'group = 7101'), actual.replace('route-to (utun42', 'route-to (utun43'),
    actual.replace('no state', 'keep state'), `${actual}${actual.split('\n')[4]}\n`]) {
    const executor = new MacOSPFExecutor(), calls = [];
    executor.runtimeRunId = policy.runId; executor.rootHookLease = leaseFor(policy.runId);
    executor.command = async (file, args) => { calls.push({ file, args }); return { stdout }; };
    await assert.rejects(executor.verifyInstalledStatelessRules(policy), { code: 'APPLICATION_ROUTING_NOT_READY' });
    assert.deepEqual(calls, [{ file: '/sbin/pfctl', args: ['-a', policy.anchor, '-sr'] }]);
  }
});

test('readback errors never expose malformed native text or caller policy details', async () => {
  const policy = createStatelessFixturePFRoutingPolicy(statelessFixtureRoutes, { fixtureDestinations: statelessFixtureDestinations, runId: 'e152b0ec-3e0c-4b6a-a4ec-18cf1f3435b5' });
  const executor = new MacOSPFExecutor(); executor.runtimeRunId = policy.runId; executor.rootHookLease = leaseFor(policy.runId); executor.command = async () => ({ stdout: `password=${proxy.password}\n` });
  await assert.rejects(executor.verifyInstalledStatelessRules(policy), error => error.code === 'APPLICATION_ROUTING_NOT_READY' &&
    !error.message.includes(proxy.password) && !Object.hasOwn(error, 'stdout') && !Object.hasOwn(error, 'cause'));
  let reads = 0; executor.command = async () => { reads++; return { stdout: '' }; };
  await assert.rejects(executor.verifyInstalledStatelessRules(null), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  await assert.rejects(executor.verifyInstalledStatelessRules({ fixtureOnly: false }), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  assert.equal(reads, 0);
});

test('the imported stateless verifier is a required immutable installation resource', () => {
  assert.equal(Object.hasOwn(PF_MANIFEST_FILES, 'stateless-verifier.mjs'), true);
  assert.equal(PF_MANIFEST_FILES['stateless-verifier.mjs'], false);
  assert.equal(PF_MANIFEST_FILES['controller.mjs'], false);
});

test('route snapshots compare IPv4 and IPv6 routes while ignoring only runtime counters', () => {
  const before = 'Routing tables\nInternet:\nDestination Gateway Flags Netif Expire\ndefault 192.0.2.1 UGScg en0\n192.0.2.1 aa:bb:cc:dd:ee:ff UHLWI en0 1200\nInternet6:\nDestination Gateway Flags Netif Expire\ndefault fe80::1%en0 UGcIg en0\n';
  assert.equal(normalizePFRouteTable(before), normalizePFRouteTable(before.replace('1200', '1198')));
  assert.notEqual(normalizePFRouteTable(before), normalizePFRouteTable(before.replace('fe80::1%en0', 'fe80::2%en0')));
  assert.notEqual(normalizePFRouteTable(before), normalizePFRouteTable(before.replace('UGScg en0', 'UGScg utun9')));
  assert.throws(() => normalizePFRouteTable('unexpected route output'));
});

test('an absent Apple hook is factual while native owned-hook preparation remains a separate readonly precondition', async () => {
  const { executor, logs } = fakeExecutor(); const controller = controllerFor(executor);
  const status = await controller.status();
  assert.equal(status.stockAppleAnchorHookVerified, false); assert.equal(status.ownedRootHookCanCreate, false);
  const runId = randomUUID(), candidate = await controller.status({ runId });
  assert.equal(candidate.ownedRootHookCanCreate, true); assert.equal(candidate.anchor, pfRoutingAnchor(runId));
  assert.equal(status.ownedRootHookVerified, false); assert.equal(status.ready, false); assert.deepEqual(logs, []);
  const unprivileged = controllerFor(executor, { identity: { uid: 501, euid: 501 } });
  assert.equal((await unprivileged.status()).ownedRootHookCanCreate, false);
  await controller.shutdown(); await unprivileged.shutdown();
});

test('owned root leases retain full uint64 tickets and reject forged namespaces, run bindings and extra fields', () => {
  const runId = randomUUID(), lease = leaseFor(runId);
  assert.equal(validatePFRootHookLease(lease, runId).ticket, '1234605616436508552');
  assert.equal(validatePFRootHookLease({ ...lease, ticket: '18446744073709551615' }, runId).ticket, '18446744073709551615');
  for (const change of [{ ticket: '0' }, { ticket: 42 }, { ticket: '01' }, { ticket: '18446744073709551616' },
    { owner: 'com.sangfor.vpn' }, { anchor: 'com.apple/envara.pf.v1' }, { runId: randomUUID() },
    { leaseId: randomUUID() },
    { label: 'envara.fake\npass all' }, { callerTrusted: true }]) assert.throws(() => validatePFRootHookLease({ ...lease, ...change }, runId));
  assert.equal(PF_ROUTING_ANCHOR, 'io.envara.pf.root.v1');
});

test('private native lease goes only through bounded stdin and its exact receipt survives active proof and cleanup', async () => {
  const executor = new MacOSPFExecutor(); executor.lock = {};
  const runId = randomUUID(), lease = leaseFor(runId), calls = []; executor.runtimeRunId = runId;
  executor.command = async (file, args, stdin) => {
    calls.push({ file, args, body: JSON.parse(stdin) });
    const operation = args[0];
    const result = { schema: PF_ROOT_HOOK_SCHEMA, anchor: lease.anchor, ok: true, operation, ticketSource: 'this-INSERT-return-only',
      ownedRootHookVerified: true, originalRootCompatible: true, priorAnchorsCompatible: true, readOnly: operation === 'hook-status',
      priorRootDerivedAnchorCount: 7, priorRulesetCountsSHA256: 'c'.repeat(64),
      originalRootSHA256: lease.rootBeforeSHA256, originalRootTextSHA256: lease.rootBeforeTextSHA256,
      ownedRootHookRemoved: calls.some(call => call.args[0] === 'delete-owned-root-hook'), originalRootRestored: calls.some(call => call.args[0] === 'delete-owned-root-hook'), lease,
      pinsVerified: true, pfDisabled: true, namespaceState: 'absent', namespaceReclaimed: true, namespaceExists: false, cleanupPending: false, receiptRetired: true };
    return { stdout: JSON.stringify(result), stderr: '' };
  };
  assert.deepEqual(await executor.installOwnedRootHook(runId), lease);
  assert.equal(executor.rootHookMutationUncertain, false);
  assert.deepEqual(await executor.removeOwnedRootHook(lease), { ownedRootHookRemoved: true, originalRootRestored: true, namespaceState: 'absent', namespaceReclaimed: true, namespaceExists: false, cleanupPending: false, receiptRetired: true });
  assert.deepEqual(executor.rootHookLease, lease);
  assert.deepEqual(calls.map(call => call.args), [['insert-owned-root-hook'], ['hook-status'], ['delete-owned-root-hook'], ['hook-status']]);
  assert.deepEqual(calls[0].body, { runId }); assert.deepEqual(calls[2].body, { lease });
  assert.ok(calls.every(call => call.file === `${PF_INSTALL_ROOT}/envara-pf-native` && !JSON.stringify(call.args).includes(lease.ticket)));
});

test('only a fixed native hook nonzero envelope can propagate a whitelisted safe failure code', async () => {
  const runId = randomUUID(), operation = 'insert-owned-root-hook', base = { schema: PF_ROOT_HOOK_SCHEMA, operation, anchor: pfRoutingAnchor(runId),
    ok: false, reason: 'INSERT_UNCONFIRMED_OWN_ROLLBACK_ATTEMPTED' };
  const secret = 'private-password-and-subscription-token';
  const scenarios = [
    { body: { ...base, message: secret, stderr: secret, lease: { password: secret } }, exitCode: 1, expected: 'APPLICATION_PF_HOOK_INSERT_UNCONFIRMED' },
    { body: { ...base, reason: 'WRITE_DEVICE_UNAVAILABLE' }, exitCode: 1, expected: 'APPLICATION_PF_HOOK_WRITE_REFUSED' },
    { body: { ...base, reason: secret }, exitCode: 1 },
    { body: { ...base, reason: 'UNKNOWN_UPPERCASE_REASON' }, exitCode: 1 },
    { body: { ...base, reason: ['WRITE_DEVICE_UNAVAILABLE'] }, exitCode: 1 },
    { body: { ...base, schema: 'untrusted-schema' }, exitCode: 1 },
    { body: { ...base, operation: 'delete-owned-root-hook' }, exitCode: 1 },
    { body: { ...base, anchor: 'com.apple/foreign' }, exitCode: 1 },
    { body: { ...base, ok: true }, exitCode: 1 },
    { body: base, exitCode: 0 },
    { text: `malformed:${secret}`, exitCode: 1 },
  ];
  for (const scenario of scenarios) {
    const executor = new MacOSPFExecutor({ spawnChild: (file, args, options) => {
      assert.equal(file, `${PF_INSTALL_ROOT}/envara-pf-native`); assert.deepEqual(args, [operation]); assert.equal(options.shell, false);
      const child = new EventEmitter(); child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => true;
      queueMicrotask(() => { child.stdout.end(scenario.text ?? JSON.stringify(scenario.body)); child.stderr.end(secret); child.emit('close', scenario.exitCode); });
      return child;
    } });
    await assert.rejects(executor.nativeRootHookRequest(operation, { runId }), error => {
      assert.equal(error.code, scenario.expected ?? 'APPLICATION_ROUTING_NOT_READY');
      assert.deepEqual(Object.keys(error), ['code']); assert.ok(!JSON.stringify(error).includes(secret) && !error.message.includes(secret)); return true;
    });
  }
});

test('nonzero diagnostic capture cannot be selected for another executable or accepted as native success', async () => {
  const executor = new MacOSPFExecutor();
  assert.throws(() => executor.command('/sbin/pfctl', ['-sr'], '', 5000, { captureHookFailure: true }), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  const failed = new MacOSPFExecutor({ spawnChild: () => {
    const child = new EventEmitter(); child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => true;
    queueMicrotask(() => { child.stdout.end('{"ok":true}'); child.stderr.end(); child.emit('close', 1); }); return child;
  } });
  await assert.rejects(failed.command(`${PF_INSTALL_ROOT}/envara-pf-native`, ['hook-status']), { code: 'APPLICATION_ROUTING_NOT_READY' });
});

test('a root-hook failure retains its fixed preparation stage through cleanup without claiming a completed fixture matrix', async () => {
  const { executor, logs } = fakeExecutor({ installOwnedRootHook: async () => {
    logs.push('insert-refused'); throw Object.assign(new Error(proxy.password), { code: 'APPLICATION_PF_HOOK_INSERT_UNCONFIRMED' });
  } });
  const controller = controllerFor(executor), input = acceptanceInput();
  await assert.rejects(controller.prepareOwnedFixtures(input), { code: 'APPLICATION_PF_HOOK_INSERT_UNCONFIRMED' });
  const snapshot = await controller.acceptanceSnapshot({ runId: input.runId }), cleanup = await controller.cleanupOwnedFixtures({ runId: input.runId });
  const expected = { stage: 'root-hook-insert', code: 'APPLICATION_PF_HOOK_INSERT_UNCONFIRMED' };
  assert.deepEqual(snapshot.preparationFailure, expected); assert.deepEqual(cleanup.preparationFailure, expected);
  assert.equal(snapshot.phase, 'cleaned'); assert.equal(cleanup.cleanupUncertain, false);
  assert.equal(cleanup.evidence.ownedRootHookRemoved, true); assert.equal(cleanup.evidence.originalRootRestored, true);
  assert.equal(cleanup.evidence.ownedPFReferenceReleased, true); assert.equal(cleanup.evidence.noOwnedStatesCreatedVerified, false);
  assert.ok(!logs.includes('group') && !logs.includes('enable-reference') && !logs.includes('core'));
  assert.ok(!JSON.stringify([snapshot, cleanup]).includes(proxy.password));
  assert.equal((await controller.status()).ready, false); await controller.shutdown();
});

test('successful prepare exposes only the run-bound hook proof while registry retains the exact private receipt', async () => {
  const records = [], { executor } = fakeExecutor({ persistRun: async run => records.push(structuredClone({ hook: run.rootHookLease, attempted: run.rootHookMutationAttempted })) });
  const controller = controllerFor(executor), input = acceptanceInput(), prepared = await controller.prepareOwnedFixtures(input);
  assert.deepEqual(prepared.ownedRootHook, { source: 'simulated', anchor: pfRoutingAnchor(input.runId), runId: input.runId, verified: true, ticketSource: 'this-INSERT-return-only' });
  assert.equal(prepared.anchoredToOwnedRootVerified, true);
  assert.ok(records.some(record => record.attempted && record.hook === null));
  const recorded = records.find(record => record.hook)?.hook; assert.ok(recorded);
  const publicOutput = JSON.stringify([prepared, await controller.status(), await controller.acceptanceSnapshot({ runId: input.runId })]);
  assert.ok(!publicOutput.includes(recorded.ticket) && !publicOutput.includes(recorded.label) && !publicOutput.includes(recorded.leaseId));
  const cleaned = await controller.cleanupOwnedFixtures({ runId: input.runId });
  for (const key of ['ownedRootHookRemoved', 'originalRootRestored', 'ownedPFReferenceReleased']) assert.equal(cleaned.evidence[key], true);
  await controller.shutdown();
});

test('ambiguous or foreign root-hook insertion retains intent and lock without starting a group, PF reference or transport', async () => {
  const { executor, logs } = fakeExecutor({ installOwnedRootHook: async () => { logs.push('insert-hook-uncertain'); throw new Error(); },
    confirmNoOwnedRootHook: async () => { logs.push('absence-unconfirmed'); throw new Error(); } });
  const controller = controllerFor(executor), input = acceptanceInput();
  await assert.rejects(controller.prepareOwnedFixtures(input), { code: 'APPLICATION_ROUTING_NOT_READY' });
  assert.deepEqual(logs, ['lock', 'insert-hook-uncertain', 'absence-unconfirmed']);
  assert.equal((await controller.acceptanceSnapshot({ runId: input.runId })).cleanupUncertain, true);
  assert.equal((await controller.shutdown()).cleanupRequired, true);
  assert.ok(!logs.includes('delete-hook') && !logs.includes('unlock'));
});

test('lost insertion reply may release an untouched lease intent only after a fresh native absence proof', async () => {
  const { executor, logs } = fakeExecutor({ installOwnedRootHook: async () => { logs.push('insert-hook-lost'); throw new Error(); } });
  const controller = controllerFor(executor), input = acceptanceInput(); await assert.rejects(controller.prepareOwnedFixtures(input));
  assert.deepEqual(logs, ['lock', 'insert-hook-lost', 'prove-absent-hook', 'quiescent', 'unlock']);
  assert.equal((await controller.shutdown()).cleanupRequired, false);
  assert.ok(!logs.includes('delete-hook') && !logs.includes('enable-reference'));
});

test('PF enable refuses independently loaded foreign rules despite compatible original root syntax', async () => {
  const executor = new MacOSPFExecutor(); executor.rootHookLease = leaseFor(randomUUID()); const calls = [];
  executor.inspectOwnedRootHook = async () => ({ originalRootCompatible: true, ownedRootHookVerified: true, priorAnchorsCompatible: false });
  executor.command = async (file, args) => { calls.push({ file, args }); return { stdout: 'Token : 123456', stderr: '' }; };
  await assert.rejects(executor.enableOwnedReference(), { code: 'APPLICATION_ROUTING_NOT_READY' }); assert.deepEqual(calls, []);
});

test('PF enable refuses stale baseline states without clearing or enabling anything', async () => {
  const executor = new MacOSPFExecutor(); executor.rootHookLease = leaseFor(randomUUID()); const calls = [];
  executor.inspectOwnedRootHook = async () => ({ originalRootCompatible: true, ownedRootHookVerified: true, priorAnchorsCompatible: true });
  executor.command = async (file, args) => { calls.push({ file, args }); return { stdout: 'en0 tcp 192.0.2.1:1234 -> 192.0.2.2:443 ESTABLISHED:ESTABLISHED\n', stderr: '' }; };
  await assert.rejects(executor.enableOwnedReference(), { code: 'APPLICATION_ROUTING_NOT_READY' });
  assert.deepEqual(calls, [{ file: '/sbin/pfctl', args: ['-ss'] }]); assert.equal(executor.pfReferenceMutationAttempted, false);
});

test('failure after an unknown PF reference never deletes the hook or claims cleanup succeeded', async () => {
  const { executor, logs } = fakeExecutor({ enableOwnedReference: async () => { logs.push('enable-reference-uncertain'); throw new Error(); } });
  const controller = controllerFor(executor), input = acceptanceInput(); await assert.rejects(controller.prepareOwnedFixtures(input));
  const result = await controller.cleanupOwnedFixtures({ runId: input.runId });
  assert.equal(result.cleanupUncertain, true); assert.equal(result.evidence.ownedPFReferenceReleased, false);
  assert.equal(result.evidence.ownedRootHookRemoved, false); assert.ok(!logs.includes('delete-hook') && !logs.includes('unlock'));
  await controller.shutdown();
});

test('an executor failure before DELETE intent may retry cleanup without replaying transport release or PF enable', async () => {
  const { executor, logs } = fakeExecutor(); const remove = executor.removeOwnedRootHook; let first = true;
  executor.removeOwnedRootHook = async lease => { if (first) { first = false; logs.push('delete-hook-failed'); throw new Error(); } return remove(lease); };
  const controller = controllerFor(executor), input = acceptanceInput(); await controller.prepareOwnedFixtures(input);
  assert.equal((await controller.cleanupOwnedFixtures({ runId: input.runId })).cleanupUncertain, true);
  assert.equal((await controller.cleanupOwnedFixtures({ runId: input.runId })).cleanupUncertain, false);
  assert.equal(logs.filter(value => value === 'release-tunnel').length, 1);
  assert.equal(logs.filter(value => value === 'release-reference').length, 1);
  assert.equal(logs.filter(value => value === 'enable-reference').length, 1);
  await controller.shutdown();
});

test('prepare stage failures roll back only the verified owned hook after all created resources become quiet', async () => {
  for (const stage of ['group', 'block', 'core', 'fixture', 'route']) {
    const { executor, logs } = fakeExecutor(); let failed = false;
    const name = { group: 'allocateGroup', block: 'replaceOwnedRules', core: 'startTunnelCore', fixture: 'launchFixture', route: 'replaceOwnedRules' }[stage];
    const original = executor[name];
    executor[name] = async (...args) => {
      const matches = name !== 'replaceOwnedRules' || args[0].routes.length > 0 &&
        (stage === 'block' ? args[0].routes.every(route => route.mode === 'blocked') : args[0].routes.some(route => route.mode === 'routed'));
      if (!failed && matches) { failed = true; logs.push(`${stage}-failed`); throw new Error(); }
      return original(...args);
    };
    const controller = controllerFor(executor), input = acceptanceInput(); await assert.rejects(controller.prepareOwnedFixtures(input));
    const result = await controller.cleanupOwnedFixtures({ runId: input.runId });
    assert.equal(result.cleanupUncertain, false, stage); assert.equal(result.evidence.ownedRootHookRemoved, true, stage);
    assert.ok(logs.indexOf('insert-hook') < logs.indexOf(`${stage}-failed`));
    assert.ok(logs.indexOf('release-reference') < logs.indexOf('delete-hook')); assert.ok(logs.indexOf('delete-hook') < logs.indexOf('unlock'));
    await controller.shutdown();
  }
});

test('incomplete native group or transport ownership prevents falsely releasing the root lease', () => {
  const executor = new MacOSPFExecutor(), run = { realms: [] };
  executor.groupIntents.set('/Groups/_envara_pf_7100', 7100);
  assert.throws(() => executor.assertNoUnassignedGuardians(run)); executor.groupIntents.clear();
  executor.guardians.set('unconfirmed', { key: 'unconfirmed', exited: false });
  assert.throws(() => executor.assertNoUnassignedGuardians(run));
});

test('helper signal and broken private output close the lifecycle and invoke owned cleanup', async () => {
  for (const reason of ['SIGTERM', 'output']) {
    const input = new PassThrough(), output = new PassThrough(), signals = new EventEmitter(); let cleaned = 0;
    const controller = { closed: false, shutdown: async () => { cleaned++; return { cleanupRequired: false }; } };
    const running = servePFHelper({ controller, input, output, signalSource: signals });
    reason === 'SIGTERM' ? signals.emit('SIGTERM') : output.emit('error', new Error('closed private channel'));
    await running; assert.equal(cleaned, 1); assert.equal(signals.listenerCount('SIGTERM'), 0);
  }
});

test('status candidate selection is strict readonly and replay cannot select a second lifecycle', async () => {
  const { executor, logs } = fakeExecutor(), controller = controllerFor(executor), input = acceptanceInput();
  const baseline = await controller.status(); assert.equal(baseline.anchor, null); assert.equal(baseline.ownedRootHookCanCreate, false);
  const candidate = await dispatchPFRequest(controller, { protocol: 'envara.application-routing', version: 1, id: 'candidate', method: 'status', params: { runId: input.runId } });
  assert.equal(candidate.anchor, pfRoutingAnchor(input.runId)); assert.equal(candidate.ownedRootHookCanCreate, true); assert.deepEqual(logs, []);
  const wrongVersion = input.runId.replace(/^([0-9a-f]{8}-[0-9a-f]{4}-)4/, (_match, prefix) => `${prefix}3`);
  for (const params of [{ runId: null }, { runId: input.runId.toUpperCase() }, { runId: wrongVersion }, { anchor: pfRoutingAnchor(input.runId) }, { runId: input.runId, callerTrusted: true }]) {
    await assert.rejects(controller.status(params), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  }
  await controller.prepareOwnedFixtures(input); await controller.cleanupOwnedFixtures({ runId: input.runId });
  const count = logs.length;
  await assert.rejects(controller.prepareOwnedFixtures(input), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  await assert.rejects(controller.prepareOwnedFixtures({ ...input, runId: randomUUID() }), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  assert.equal(logs.length, count); await controller.shutdown();
});

test('v1, uppercase, wrong-run, unknown anchor and cross-run policy never reach native stdin or PF', async () => {
  const runId = randomUUID(), lease = leaseFor(runId), executor = new MacOSPFExecutor();
  executor.runtimeRunId = runId; executor.rootHookLease = lease; executor.lock = {};
  let calls = 0; executor.command = async () => { calls++; throw new Error('must not execute'); };
  for (const patch of [{ schema: 'envara.macos-pf-owned-root-hook-lease/v1' }, { runId: runId.toUpperCase() }, { leaseId: lease.leaseId.toUpperCase() },
    { anchor: 'io.envara.pf.root.v1' }, { owner: pfRoutingAnchor(randomUUID()) }, { runId: randomUUID() }]) {
    assert.throws(() => validatePFRootHookLease({ ...lease, ...patch }, runId));
    await assert.rejects(executor.removeOwnedRootHook({ ...lease, ...patch }));
  }
  for (const params of [{ runId: runId.toUpperCase() }, { anchor: lease.anchor }, { runId, anchor: lease.anchor }, { lease, runId }]) await assert.rejects(executor.nativeRootHookRequest('hook-status', params));
  const differentRun = randomUUID(), policy = createStatelessFixturePFRoutingPolicy(statelessFixtureRoutes, { fixtureDestinations: statelessFixtureDestinations, runId: differentRun });
  await assert.rejects(executor.replaceOwnedRules(policy), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  await assert.rejects(executor.verifyInstalledStatelessRules(policy), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
  assert.equal(calls, 0);
  for (const anchor of [PF_ROUTING_ANCHOR, pfRoutingAnchor(differentRun), `${lease.anchor}/child`, lease.anchor.toUpperCase()]) assert.equal(executor.allowedCommand('/sbin/pfctl', ['-a', anchor, '-f', '-']), false);
});

function exactRetiredStatus(lease, state = 'absent') {
  return { schema: PF_ROOT_HOOK_SCHEMA, operation: 'hook-status', anchor: lease.anchor, ok: true, readOnly: true,
    pfDisabled: true, pinsVerified: true, originalRootCompatible: true, ownedRootHookVerified: false,
    ownedRootHookRemoved: true, originalRootRestored: true, receiptRetired: true,
    originalRootSHA256: lease.rootBeforeSHA256, originalRootTextSHA256: lease.rootBeforeTextSHA256,
    namespaceState: state, namespaceReclaimed: state === 'absent', namespaceExists: state === 'present', cleanupPending: state !== 'absent' };
}

test('lost DELETE reply is resolved only by exact retired lease readonly proof and is never replayed', async () => {
  for (const state of ['absent', 'present', 'unknown']) {
    const runId = randomUUID(), lease = leaseFor(runId), executor = new MacOSPFExecutor(), calls = [];
    executor.runtimeRunId = runId; executor.rootHookLease = lease;
    executor.nativeRootHookRequest = async (operation, params) => {
      calls.push({ operation, params }); assert.deepEqual(params, { lease });
      if (operation === 'delete-owned-root-hook') throw new Error('reply lost');
      return exactRetiredStatus(lease, state);
    };
    const result = await executor.removeOwnedRootHook(lease);
    assert.equal(result.originalRootRestored, true); assert.equal(result.namespaceReclaimed, state === 'absent');
    assert.equal(result.cleanupPending, state !== 'absent'); assert.equal(executor.rootHookMutationUncertain, state !== 'absent');
    assert.deepEqual(await executor.removeOwnedRootHook(lease), result);
    assert.deepEqual(calls.map(value => value.operation), ['delete-owned-root-hook', 'hook-status', 'hook-status']);
    assert.equal(executor.ownedAnchor(), null);
  }
});

test('root absence without durable retirement or matching issued digests never clears a lost DELETE intent', async () => {
  for (const patch of [{ receiptRetired: false }, { originalRootSHA256: 'c'.repeat(64) }, { namespaceState: 'present', namespaceReclaimed: true }, { pfDisabled: false }]) {
    const runId = randomUUID(), lease = leaseFor(runId), executor = new MacOSPFExecutor(), operations = [];
    executor.runtimeRunId = runId; executor.rootHookLease = lease;
    executor.nativeRootHookRequest = async operation => { operations.push(operation); if (operation === 'delete-owned-root-hook') throw new Error(); return { ...exactRetiredStatus(lease), ...patch }; };
    await assert.rejects(executor.removeOwnedRootHook(lease)); await assert.rejects(executor.removeOwnedRootHook(lease));
    assert.deepEqual(operations, ['delete-owned-root-hook', 'hook-status', 'hook-status']);
    assert.equal(executor.rootHookMutationUncertain, true); assert.equal(executor.rootHookRetiredProof, null);
  }
});

test('restored root with a retired but retained namespace keeps registry and lock without deleting again', async () => {
  const { executor, logs } = fakeExecutor(); let records = 0;
  executor.persistRun = async run => { records++; assert.equal(run.runId, executor.runtimeRunId); };
  const retained = { ownedRootHookRemoved: true, originalRootRestored: true, receiptRetired: true, namespaceState: 'present', namespaceReclaimed: false, cleanupPending: true };
  executor.removeOwnedRootHook = async () => { logs.push('delete-hook'); return retained; };
  executor.confirmNoOwnedRootHook = async (runId, lease) => { assert.equal(runId, executor.runtimeRunId); assert.deepEqual(lease, executor.rootHookLease); logs.push('readonly-retired'); return retained; };
  const controller = controllerFor(executor), input = acceptanceInput(); await controller.prepareOwnedFixtures(input);
  const result = await controller.cleanupOwnedFixtures({ runId: input.runId });
  assert.equal(result.originalRootRestored, true); assert.equal(result.ownedRootHookRemoved, true); assert.equal(result.namespaceReclaimed, false);
  assert.equal(result.receiptRetired, true); assert.equal(result.cleanupUncertain, true); assert.equal(result.evidence.complete, false);
  assert.equal((await controller.acceptanceSnapshot({ runId: input.runId })).phase, 'cleanup-required');
  const before = records; await controller.cleanupOwnedFixtures({ runId: input.runId });
  assert.equal(logs.filter(value => value === 'delete-hook').length, 1); assert.ok(!logs.includes('unlock')); assert.ok(records > before);
  await controller.shutdown();
});

test('repeat retired-namespace cleanup retains completed steps but obtains fresh process absence for each receipt', async () => {
  const { executor, logs } = fakeExecutor(); let processReads = 0, processUnknown = false;
  const retained = { ownedRootHookRemoved: true, originalRootRestored: true, receiptRetired: true,
    namespaceState: 'present', namespaceReclaimed: false, cleanupPending: true };
  executor.assertNoOwnedGroupProcesses = async () => { processReads++; if (processUnknown) throw new Error('unreadable'); };
  executor.removeOwnedRootHook = async () => { logs.push('delete-hook'); return retained; };
  executor.confirmNoOwnedRootHook = async () => { logs.push('readonly-retired'); return retained; };
  const controller = controllerFor(executor), input = acceptanceInput(); await controller.prepareOwnedFixtures(input);
  const first = await controller.cleanupOwnedFixtures({ runId: input.runId });
  const second = await controller.cleanupOwnedFixtures({ runId: input.runId });
  for (const receipt of [first, second]) {
    assert.equal(receipt.ownedProcessesExited, true); assert.equal(receipt.ownedTunnelsRemoved, true); assert.equal(receipt.ownedAnchorRemoved, true);
    assert.deepEqual(receipt.cleanupStepCompletions, { ownedProcessesExited: true, ownedAnchorStatesPurged: true,
      ownedTunnelsRemoved: true, ownedAnchorRemoved: true });
    assert.deepEqual(receipt.evidence.cleanupStepCompletions, receipt.cleanupStepCompletions);
    assert.equal(receipt.cleanupUncertain, true); assert.equal(receipt.evidence.complete, false);
  }
  assert.equal(processReads, 2); assert.equal(logs.filter(value => value === 'delete-hook').length, 1);
  assert.equal(logs.filter(value => value === 'release-tunnel').length, 1); assert.ok(!logs.includes('unlock'));
  // Actual group removal from the first pass cannot substitute for a current
  // unreadable process inventory, even though its historical receipt remains.
  assert.equal(controller.runs.get(input.runId).groupsRemoved, true); processUnknown = true;
  const failed = await controller.cleanupOwnedFixtures({ runId: input.runId });
  assert.equal(failed.ownedProcessesExited, false); assert.equal(failed.cleanupStepCompletions.ownedProcessesExited, true);
  assert.equal(failed.cleanupUncertain, true); assert.equal(failed.evidence.complete, false); assert.equal(processReads, 3);
  assert.equal(logs.filter(value => value === 'delete-hook').length, 1); assert.ok(!logs.includes('unlock'));
  await controller.shutdown();
});

test('failed tunnel release never records completed tunnels or child rules on a repeated cleanup', async () => {
  const { executor, logs } = fakeExecutor(); let stopCalls = 0, coreIndex = 0;
  executor.startTunnelCore = async ({ ipv4Address }) => { const index = ++coreIndex;
    return { interfaceName: `utun${90 + index}`, pid: 3210 + index, instanceId: `fixture_tunnel_${index}`, ipv4Address }; };
  executor.stopOwnedTunnel = async () => { if (++stopCalls > 1) throw new Error('unconfirmed second tunnel'); logs.push('release-one-tunnel'); };
  const input = acceptanceInput(); input.slots.push({ slot: 'two', environmentId: randomUUID(), proxy: { ...proxy }, udpPolicy: 'proxy' });
  const controller = controllerFor(executor); await controller.prepareOwnedFixtures(input);
  for (let attempt = 0; attempt < 2; attempt++) {
    const receipt = await controller.cleanupOwnedFixtures({ runId: input.runId });
    assert.equal(receipt.ownedProcessesExited, true); assert.equal(receipt.ownedTunnelsRemoved, false); assert.equal(receipt.ownedAnchorRemoved, false);
    assert.equal(receipt.cleanupStepCompletions.ownedProcessesExited, true);
    assert.equal(receipt.cleanupStepCompletions.ownedTunnelsRemoved, false); assert.equal(receipt.cleanupStepCompletions.ownedAnchorRemoved, false);
    assert.equal(receipt.cleanupUncertain, true); assert.equal(receipt.evidence.complete, false);
  }
  assert.equal(controller.runs.get(input.runId).realms[0].tunnelRemoved, true);
  assert.notEqual(controller.runs.get(input.runId).realms[1].tunnelRemoved, true);
  assert.equal(logs.filter(value => value === 'release-one-tunnel').length, 1);
  assert.ok(!logs.includes('delete-hook') && !logs.includes('release-reference') && !logs.includes('unlock'));
  await controller.shutdown();
});

test('issued receipt captured before INSERT follow-up proof failure remains available for exact cleanup', async () => {
  const { executor, logs } = fakeExecutor(); let issued;
  executor.installOwnedRootHook = async runId => { issued = leaseFor(runId); executor.rootHookLease = issued; logs.push('insert-then-read-failed'); throw Object.assign(new Error(), { code: 'APPLICATION_PF_HOOK_READ_REFUSED' }); };
  executor.removeOwnedRootHook = async lease => { assert.deepEqual(lease, issued); logs.push('delete-exact-issued'); return { ownedRootHookRemoved: true, originalRootRestored: true, receiptRetired: true, namespaceState: 'absent', namespaceReclaimed: true }; };
  const controller = controllerFor(executor), input = acceptanceInput(); await assert.rejects(controller.prepareOwnedFixtures(input), { code: 'APPLICATION_PF_HOOK_READ_REFUSED' });
  const cleanup = await controller.cleanupOwnedFixtures({ runId: input.runId });
  assert.equal(cleanup.cleanupUncertain, false); assert.equal(cleanup.namespaceReclaimed, true);
  assert.equal(logs.filter(value => value === 'delete-exact-issued').length, 1); assert.ok(!logs.includes('group') && !logs.includes('enable-reference'));
  assert.ok(!logs.includes('prove-absent-hook')); await controller.shutdown();
});
