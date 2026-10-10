import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import net from 'node:net';
import dgram from 'node:dgram';
import { MacOSPFExecutor, MacOSPFController } from '../native/macos-pf-routing/controller.mjs';
import { createPFFixtureSocksServer, snapshotPFFixtureUDP, PF_FIXTURE_UDP_COUNTS, PF_ACCEPTANCE_PROTOCOL, runPFAcceptanceMatrix } from '../native/macos-pf-routing/acceptance-plan.mjs';
import { SocketReader } from '../native/macos-local-routing/socks-stream.mjs';
import { pfRoutingAnchor } from '../native/macos-pf-routing/policy.mjs';

function transport(reply) {
  const executor = new MacOSPFExecutor(), parent = { role: 'parent', pid: 101, guardianKey: 'owned' }, child = { role: 'child', pid: 102 };
  const realm = { fixtures: [parent, child] };
  const entry = { exited: false, uncertain: false, child: { stdin: { write(line) {
    const request = JSON.parse(Buffer.from(line.slice(6).trim(), 'base64'));
    queueMicrotask(() => entry.responses.shift()({ payload: JSON.stringify(reply(request, parent, child)) }));
  } } } };
  executor.guardians.set('owned', entry); return { executor, realm, parent, child, entry };
}

test('verified native fixture semantic failures retain only a fixed safe code', async () => {
  for (const role of ['parent', 'child']) {
    const { executor, realm, parent, child } = transport((request, p, c) => role === 'parent'
      ? { id: request.id, pid: p.pid, ok: false, code: 'PROBE_TIMEOUT', secret: 'private-node-password' }
      : { id: request.id, pid: p.pid, ok: true, childResult: { id: request.id, pid: c.pid, ok: false, code: 'PROBE_TIMEOUT', secret: 'private-node-password' } });
    await assert.rejects(executor.transactFixture(realm, role === 'parent' ? parent : child, { id: randomUUID(), op: 'status' }),
      error => error.code === 'APPLICATION_PF_FIXTURE_PROBE_TIMEOUT' && !JSON.stringify(error).includes('private-node-password'));
  }
});

test('malformed, forged-identity and unknown native replies never reflect their error contents', async () => {
  for (const reply of [
    request => ({ id: request.id, pid: 999, ok: false, code: 'PROBE_TIMEOUT' }),
    (_request, parent) => ({ id: randomUUID(), pid: parent.pid, ok: false, code: 'PROBE_TIMEOUT' }),
    (request, parent) => ({ id: request.id, pid: parent.pid, ok: false, code: 'private-node-password' }),
    (request, parent, child) => ({ id: request.id, pid: parent.pid, ok: true, childResult: { id: request.id, pid: child.pid + 1, ok: false, code: 'PROBE_TIMEOUT' } }),
  ]) {
    const { executor, realm, child } = transport(reply);
    await assert.rejects(executor.transactFixture(realm, child, { id: randomUUID(), op: 'status' }),
      error => error.code === 'APPLICATION_PF_FIXTURE_REPLY_REFUSED' && !JSON.stringify(error).includes('private-node-password'));
  }
});

test('a timed-out native guardian refuses its queued probe instead of starting another background transaction', async () => {
  const executor = new MacOSPFExecutor(), parent = { role: 'parent', pid: 101, guardianKey: 'owned' }, realm = { fixtures: [parent] };
  let writes = 0; const entry = { uncertain: false, exited: false, child: { stdin: { write() { writes++; } } } };
  executor.guardians.set('owned', entry);
  const results = await Promise.allSettled([executor.transactFixture(realm, parent, { id: randomUUID(), op: 'status' }, 15),
    executor.transactFixture(realm, parent, { id: randomUUID(), op: 'status' }, 15)]);
  assert.deepEqual(results.map(result => result.reason.code), ['APPLICATION_PF_FIXTURE_RPC_TIMEOUT', 'APPLICATION_PF_FIXTURE_REPLY_REFUSED']);
  assert.equal(writes, 1); assert.equal(entry.uncertain, true);
});

function fixtureCase() {
  const executor = new MacOSPFExecutor(); let stateReads = 0;
  executor.confirmReservedStatesAbsent = async () => { stateReads++; };
  executor.verifyInstalledStatelessRules = async () => ({ noStateRulesVerified: true });
  executor.fixtureIdentity = async () => {};
  const fixtures = [{ role: 'parent', pid: 101, birth: '1:000001' }, { role: 'child', pid: 102, birth: '1:000002' }];
  const realm = { environmentId: randomUUID(), realmId: randomUUID(), slot: 'one', gid: 7101, mode: 'routed', udpPolicy: 'proxy', fixtures,
    tunnel: { interfaceName: 'utun99', pid: 201, instanceId: 'owned-tunnel', ipv4Address: '198.18.1.1' } };
  const run = { runId: randomUUID(), stateless: true, caseIds: ['udp-concurrent'], realms: [realm], reservations: fixtures.map(fixture => ({
    realmId: realm.realmId, role: fixture.role, caseId: 'udp-concurrent', reservationId: randomUUID(), localPort: 45000 + fixture.pid,
    consumed: false, expiresAtNanoseconds: '10000000000000000000', receivedAtNanoseconds: process.hrtime.bigint(),
  })) };
  const input = { caseId: 'udp-concurrent', challenges: fixtures.map(fixture => {
    const id = randomUUID(); return { id, slot: 'one', role: fixture.role, request: { id, op: 'udp', host: '198.51.100.42', port: 44444,
      payloadBase64: Buffer.from('owned-probe').toString('base64'), timeoutMs: 500 } };
  }) };
  return { executor, run, input, stateReads: () => stateReads };
}

test('a failed native case waits for every issued probe before cleanup can start', async () => {
  const { executor, run, input, stateReads } = fixtureCase(); let release, secondFinished = false;
  const second = new Promise(resolve => { release = resolve; });
  executor.transactFixture = async (_realm, fixture) => {
    if (fixture.role === 'parent') throw Object.assign(new Error('private-node-password'), { code: 'APPLICATION_PF_FIXTURE_PROBE_TIMEOUT' });
    await second; secondFinished = true; throw Object.assign(new Error('private-other-secret'), { code: 'APPLICATION_PF_FIXTURE_PROBE_TRANSPORT_FAILED' });
  };
  let returned = false;
  const outcome = executor.runFixtureCase({ run, input }).catch(error => { returned = true; return error; });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(returned, false); assert.equal(secondFinished, false);
  release(); const error = await outcome;
  assert.equal(secondFinished, true); assert.equal(error.code, 'APPLICATION_PF_FIXTURE_PROBE_TIMEOUT'); assert.equal(stateReads(), 1);
  assert.deepEqual(run.caseFailure, { caseId: 'udp-concurrent', stage: 'probe-transport', code: 'APPLICATION_PF_FIXTURE_PROBE_TIMEOUT' });
  const controller = new MacOSPFController({ executor }); controller.runs.set(run.runId, run);
  const snapshot = await controller.acceptanceSnapshot({ runId: run.runId });
  assert.deepEqual(snapshot.caseFailure, run.caseFailure); assert.equal(snapshot.ready, false);
  assert.equal(JSON.stringify(snapshot).includes('private-'), false);
});

test('native tuple mismatch is distinguished from transport failure without reflecting a tuple', async () => {
  const { executor, run, input } = fixtureCase(); executor.transactFixture = async () => ({ ok: true, reservationId: randomUUID(), private: 'secret' });
  await assert.rejects(executor.runFixtureCase({ run, input }), { code: 'APPLICATION_ROUTING_NOT_READY' });
  assert.deepEqual(run.caseFailure, { caseId: 'udp-concurrent', stage: 'probe-binding', code: 'APPLICATION_ROUTING_NOT_READY' });
  assert.deepEqual(Object.keys(run.caseFailure).sort(), ['caseId', 'code', 'stage']);
});

test('UDP diagnostics count real loopback header, destination, challenge and peer refusal without private fields', { timeout: 4000 }, async t => {
  const proxy = await createPFFixtureSocksServer({ slot: 'one' }); t.after(() => proxy.close());
  const socket = net.createConnection({ host: '127.0.0.1', port: proxy.route.port }); socket.on('error', () => {}); t.after(() => socket.destroy());
  const reader = new SocketReader(socket);
  socket.write(Buffer.from([5, 1, 2])); assert.deepEqual(await reader.read(2), Buffer.from([5, 2]));
  const username = Buffer.from(proxy.route.username), password = Buffer.from(proxy.route.password);
  socket.write(Buffer.concat([Buffer.from([1, username.length]), username, Buffer.from([password.length]), password]));
  assert.deepEqual(await reader.read(2), Buffer.from([1, 0])); socket.write(Buffer.from([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]));
  assert.deepEqual(await reader.read(4), Buffer.from([5, 0, 0, 1])); const port = (await reader.read(6)).readUInt16BE(4);
  reader.release(); socket.resume();
  const udp = dgram.createSocket('udp4'), other = dgram.createSocket('udp4');
  for (const client of [udp, other]) { client.on('error', () => {}); t.after(() => { try { client.close(); } catch {} }); }
  const send = (client, bytes) => new Promise((resolve, reject) => client.send(bytes, port, '127.0.0.1', error => error ? reject(error) : resolve()));
  const header = Buffer.from([0, 0, 0, 1, 198, 51, 100, 42, 173, 156]);
  await send(udp, Buffer.from([0, 0]));
  const badDestination = Buffer.from(header); badDestination[4] = 192;
  await send(udp, Buffer.concat([badDestination, Buffer.from('unregistered')]));
  await send(udp, Buffer.concat([header, Buffer.from('unregistered')]));
  const payload = Buffer.from('owned-valid-payload'); proxy.register('owned', payload, 'udp');
  const reply = new Promise(resolve => udp.once('message', resolve)); await send(udp, Buffer.concat([header, payload]));
  assert.deepEqual(await reply, Buffer.concat([header, payload]));
  await send(other, Buffer.concat([header, payload]));
  const deadline = Date.now() + 500;
  while (proxy.snapshot().udpPacketsReceived < 5 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 5));
  const counts = snapshotPFFixtureUDP(proxy.snapshot());
  assert.deepEqual(counts, { udpAssociations: 1, udpPacketsReceived: 5, udpPeerRejected: 1, udpHeaderRejected: 1,
    udpDestinationRejected: 1, udpChallengeRejected: 1, udpDNSRejected: 0, udpRepliesQueued: 1, udpReplySendFailed: 0, udpSocketErrors: 0 });
  assert.equal(proxy.receiptCount('owned'), 1); assert.equal(proxy.receiptCount('unknown'), 0);
  assert.equal(Object.keys(counts).length, PF_FIXTURE_UDP_COUNTS.length);
  for (const secret of [proxy.route.username, proxy.route.password, 'owned-valid-payload', '198.51.100.42']) assert.equal(JSON.stringify(counts).includes(secret), false);
});

test('missing, boolean, fractional or excessive UDP counters remain unknown rather than a zero-egress proof', () => {
  const good = Object.fromEntries(PF_FIXTURE_UDP_COUNTS.map(key => [key, 0]));
  for (const value of [undefined, true, 0.5, -1, 1048577]) assert.equal(snapshotPFFixtureUDP({ ...good, udpPacketsReceived: value }), null);
  assert.deepEqual(snapshotPFFixtureUDP({ ...good, username: 'private', password: 'private' }), good);
});

test('missing or throwing optional UDP observers cannot replace failure or prevent fixture/control cleanup', async () => {
  for (const observer of ['missing', 'throwing']) {
    let closed = 0, controlClosed = false, cleanupCalled = false;
    const flags = { acceptanceProtocol: PF_ACCEPTANCE_PROTOCOL, acceptanceOnly: true, ready: false, productionReceiptAllowed: false };
    const report = await runPFAcceptanceMatrix({ controlledCaseIds: ['realm-identities'], evidenceMode: 'simulation',
      createControl: async () => ({ existing: async () => true, fresh: async () => true, close: async () => { controlClosed = true; return true; } }),
      createProxy: async () => ({ route: {}, ...(observer === 'throwing' ? { snapshot: () => { throw new Error('private-node-password'); } } : {}),
        close: async () => { closed++; return true; } }),
      call: async (method, params) => {
        if (method === 'status') return { ...flags, anchor: pfRoutingAnchor(params.runId), rootOwnedInstallationVerified: true,
          callerConsoleUIDVerified: true, privilegedOperationsAuthorized: true, ownedRootHookCanCreate: true,
          statelessControlledFixtures: true, noStateNativeAvailable: true, fixtureOperations: ['realm-identities', 'cleanup'] };
        if (method === 'prepareOwnedFixtures') return { ...flags, runId: params.runId, realms: [] };
        cleanupCalled = true; return { ...flags, runId: params.runId, cleanupUncertain: true };
      },
    });
    assert.equal(report.reason, 'PF_OWNED_ROOT_HOOK_EVIDENCE_REQUIRED'); assert.equal(cleanupCalled, true);
    assert.equal(closed, 2); assert.equal(controlClosed, true); assert.equal(report.localFixturesClosed, true);
    assert.equal(report.productionReady, false); assert.equal(report.nativeRoutingAcceptance, false);
    assert.deepEqual(report.fixtureUDPDiagnostics.map(value => value.counts), [null, null]);
    assert.equal(JSON.stringify(report).includes('private-node-password'), false);
  }
});
