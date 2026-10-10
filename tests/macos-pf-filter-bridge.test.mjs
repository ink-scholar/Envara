import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { MacOSPFController, MacOSPFExecutor, PF_INSTALL_ROOT, PF_ROOT_HOOK_LEASE_SCHEMA, PF_FILTER_REPLACEMENT_SCHEMA } from '../native/macos-pf-routing/controller.mjs';
import { createPFRoutingPolicy, createStatelessFixturePFRoutingPolicy, pfRoutingAnchor } from '../native/macos-pf-routing/policy.mjs';

const targets = [{ host: '198.51.100.42', ports: [44441, 44442, 44443, 44444] }, { host: '1.1.1.1', ports: [53] }];
function fixture({ mutate, failPersist } = {}) {
  const runId = randomUUID(), leaseId = randomUUID(), records = [], calls = [];
  const lease = { schema: PF_ROOT_HOOK_LEASE_SCHEMA, runId, leaseId, anchor: pfRoutingAnchor(runId), owner: pfRoutingAnchor(runId),
    label: `envara.hook.v2.${createHash('sha256').update(`${runId}|${leaseId}`).digest('hex').slice(0, 32)}`,
    ticket: '1234605616436508552', rootBeforeSHA256: 'a'.repeat(64), rootBeforeTextSHA256: 'b'.repeat(64) };
  const run = { runId, lockAcquired: true, rootHookVerified: true, rootHookLease: lease, cleanupUncertain: false,
    realms: [{ environmentId: randomUUID(), gid: 7100, udpPolicy: 'proxy', mode: 'blocked', fixtures: [], tunnel: null }] };
  const executor = new MacOSPFExecutor({ spawnChild: (file, args, options) => {
    assert.equal(file, `${PF_INSTALL_ROOT}/envara-pf-native`); assert.deepEqual(args, ['replace-owned-filter']);
    assert.equal(options.shell, false); assert.deepEqual(options.stdio, ['pipe', 'pipe', 'pipe']);
    assert.equal(records.at(-1).filterReplacement.state, 'pending');
    const child = new EventEmitter(); child.pid = 6000 + calls.length;
    child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => {};
    let input = ''; child.stdin.on('data', bytes => { input += bytes; });
    child.stdin.on('finish', () => {
      const request = JSON.parse(input); calls.push({ file, args, request });
      assert.deepEqual(Object.keys(request).sort(), ['schema', 'runId', 'generation', 'lease', 'previous', 'next'].sort());
      assert.deepEqual(records.at(-1).filterReplacement.previous, request.previous);
      assert.deepEqual(records.at(-1).filterReplacement.next, request.next);
      const ruleCount = request.next.realms.reduce((count, realm) => count + (request.next.mode === 'deny'
        ? realm.udpPolicy === 'proxy' ? 6 : 7 : realm.udpPolicy === 'proxy' ? 28 : 19), 0);
      const reply = { schema: PF_FILTER_REPLACEMENT_SCHEMA, operation: 'replace-owned-filter', ok: true,
        runId: request.runId, generation: request.generation, mode: request.next.mode, reason: 'GENERATED_SINGLE_FILTER_VERIFIED',
        readOnly: false, fixtureOnly: true, productionReady: false, protected: false, nativeAcceptance: false,
        replacementAttempted: true, replacementUncertain: false, rulesVerified: true, poolsVerified: true,
        ruleCount, writerPid: child.pid, filterRevision: String(calls.length - 1), globalTemporaryPoolBufferReset: ruleCount > 0,
        foreignPoolConcurrencyExcluded: false, kernelIoctlHardDeadline: false, changesOtherRuleClasses: false, PFEnable: false, statesCleared: false };
      mutate?.(reply, request);
      queueMicrotask(() => { child.stdout.write(JSON.stringify(reply)); child.emit('close', reply.ok === true ? 0 : 1); });
    });
    return child;
  } });
  executor.runtimeRunId = runId; executor.rootHookLease = lease; executor.lock = {};
  executor.persistRun = async value => {
    const captured = structuredClone(value); records.push(captured);
    if (failPersist?.(captured)) throw Object.assign(new Error('private fixture detail'), { code: 'EIO' });
  };
  const policy = () => createStatelessFixturePFRoutingPolicy(run.realms, { fixtureDestinations: targets, runId });
  return { executor, run, lease, records, calls, policy };
}
function tunnel() { return { interfaceName: 'utun42', ipv4Address: '198.18.1.1', pid: 3210,
  coreBirth: '1:000001', guardianPid: 3200, instanceId: 'tun_fixture', fdRetained: true }; }

test('actual native writer channel seals each intent before spawn and advances only exact ACK identity and revision', async () => {
  const value = fixture(), { executor, run, records, calls, policy } = value;
  const denial = await executor.replaceOwnedRules(policy(), run);
  assert.equal(denial.ruleCount, 6); assert.equal(denial.productionReady, false);
  assert.deepEqual(calls[0].request.previous, { mode: 'empty', realms: [], writerPid: 0, filterRevision: null });
  assert.equal(run.filterReceipt.filterRevision, '0'); assert.equal(run.filterReceipt.writerPid, 6000);
  run.realms[0].mode = 'routed'; run.realms[0].tunnel = tunnel();
  const routed = await executor.replaceOwnedRules(policy(), run);
  assert.equal(routed.ruleCount, 28);
  assert.equal(calls[1].request.previous.mode, 'deny'); assert.equal(calls[1].request.previous.filterRevision, '0');
  assert.deepEqual(calls[1].request.next.realms[0].tunnel, tunnel());
  run.realms[0].mode = 'blocked';
  await executor.replaceOwnedRules(policy(), run);
  run.realms[0].tunnelRemoved = true;
  const empty = await executor.replaceOwnedRules(createPFRoutingPolicy([], { runId: run.runId }), run);
  assert.equal(empty.ruleCount, 0); assert.equal(calls[3].request.next.mode, 'empty'); assert.deepEqual(calls[3].request.next.realms, []);
  assert.equal(records.length, 8); assert.deepEqual(records.map(record => record.filterReplacement.state), ['pending', 'committed', 'pending', 'committed', 'pending', 'committed', 'pending', 'committed']);
  assert.ok(calls.every(call => call.file !== '/sbin/pfctl'));
  assert.deepEqual(Object.keys(run.filterReceipt).sort(), ['schema', 'generation', 'mode', 'ruleCount', 'writerPid', 'filterRevision'].sort());
});

test('one failed owned tunnel writes a uniform deny for both realms instead of retaining the previous routed FILTER', async () => {
  const { executor, run, calls, policy } = fixture(), events = [];
  run.stateless = true; run.phase = 'fixtures-running';
  run.realms[0].mode = 'routed'; run.realms[0].tunnel = tunnel();
  run.realms.push({ environmentId: randomUUID(), gid: 7101, udpPolicy: 'block', mode: 'routed', fixtures: [],
    tunnel: { ...tunnel(), interfaceName: 'utun43', ipv4Address: '198.18.2.1', pid: 3211, guardianPid: 3201, instanceId: 'tun_second' } });
  const routed = await executor.replaceOwnedRules(policy(), run);
  assert.equal(routed.ruleCount, 47);
  const controller = new MacOSPFController({ executor, onEvent: event => events.push(event) });
  controller.runs.set(run.runId, run);
  await controller.handleTransportFault({ instanceId: run.realms[0].tunnel.instanceId, fdRetained: true, kind: 'owned-core-exited' });
  assert.deepEqual(run.realms.map(realm => realm.mode), ['blocked', 'blocked']);
  assert.equal(calls.length, 2); assert.equal(calls[1].request.next.mode, 'deny');
  assert.equal(calls[1].request.previous.mode, 'routed'); assert.equal(calls[1].request.next.realms.length, 2);
  assert.ok(calls[1].request.next.realms.every(realm => realm.tunnel === null)); assert.equal(run.filterReceipt.ruleCount, 13);
  assert.equal(events[0].protected, false); assert.equal(events[0].failClosed, false); assert.equal(events[0].productionReady, false);
  assert.equal(run.phase, 'transport-fault');
});

test('native ACK cannot change identity, count, receipt provenance or unresolved security gates', async t => {
  const mutations = {
    'foreign run': reply => { reply.runId = randomUUID(); }, 'foreign generation': reply => { reply.generation = randomUUID(); },
    'foreign writer': reply => { reply.writerPid++; }, 'boolean writer': reply => { reply.writerPid = true; },
    'wrong mode': reply => { reply.mode = 'routed'; }, 'wrong count': reply => { reply.ruleCount++; },
    'boolean count': reply => { reply.ruleCount = true; }, 'missing pools proof': reply => { delete reply.poolsVerified; },
    'uncertain replacement': reply => { reply.replacementUncertain = true; },
    'noncanonical revision': reply => { reply.filterRevision = '00'; }, 'overflow revision': reply => { reply.filterRevision = '4294967296'; },
    'numeric revision': reply => { reply.filterRevision = 0; }, 'promoted production': reply => { reply.productionReady = true; },
    'foreign classes': reply => { reply.changesOtherRuleClasses = true; }, 'claimed concurrency': reply => { reply.foreignPoolConcurrencyExcluded = true; },
  };
  for (const [label, mutate] of Object.entries(mutations)) await t.test(label, async () => {
    const { executor, run, calls, records, policy } = fixture({ mutate });
    await assert.rejects(executor.replaceOwnedRules(policy(), run), { code: 'APPLICATION_PF_FILTER_REPLACEMENT_UNCONFIRMED' });
    assert.equal(run.filterReplacement.state, 'uncertain'); assert.equal(run.cleanupUncertain, true);
    assert.equal(records.at(-1).filterReplacement.state, 'uncertain'); assert.equal(executor.filterCommitted, null);
    await assert.rejects(executor.replaceOwnedRules(policy(), run), { code: 'APPLICATION_PF_FILTER_REPLACEMENT_UNCERTAIN' });
    assert.equal(calls.length, 1);
  });
});

test('sealed intent and ACK persistence faults never issue a subsequent native write', async t => {
  for (const stage of ['pending', 'committed']) await t.test(stage, async () => {
    const { executor, run, calls, records, policy } = fixture({ failPersist: record => record.filterReplacement.state === stage });
    await assert.rejects(executor.replaceOwnedRules(policy(), run), { code: 'APPLICATION_ROUTING_NOT_READY' });
    assert.equal(calls.length, stage === 'pending' ? 0 : 1); assert.equal(records.at(-1).filterReplacement.state, 'uncertain');
    assert.equal(executor.filterCommitted, null); assert.equal(run.filterReceipt?.rulesVerified, undefined);
    if (stage === 'committed') assert.equal(run.filterReceipt.writerPid, 6000);
    await assert.rejects(executor.replaceOwnedRules(policy(), run), { code: 'APPLICATION_PF_FILTER_REPLACEMENT_UNCERTAIN' });
    assert.equal(calls.length, stage === 'pending' ? 0 : 1);
  });
});

test('native nonzero, transport loss and untrusted diagnostics poison the intent without reflecting private output', async t => {
  for (const reason of ['guard-rejected', 'private-password-and-path']) await t.test(reason, async () => {
    const { executor, run, calls, policy } = fixture({ mutate: reply => { reply.ok = false; reply.reason = reason; reply.readOnly = true; reply.replacementAttempted = false; } });
    await assert.rejects(executor.replaceOwnedRules(policy(), run), error => error.code === (reason === 'guard-rejected' ? 'APPLICATION_PF_FILTER_GUARD_REJECTED' : 'APPLICATION_PF_FILTER_REPLACEMENT_UNCONFIRMED') && !error.message.includes(reason));
    assert.equal(run.filterReplacement.state, 'uncertain'); assert.equal(calls.length, 1);
    await assert.rejects(executor.replaceOwnedRules(policy(), run), { code: 'APPLICATION_PF_FILTER_REPLACEMENT_UNCERTAIN' });
  });
  const { executor, run, records, policy } = fixture();
  executor.command = async () => { throw Object.assign(new Error('private-password-and-path'), { code: 'APPLICATION_ROUTING_TIMEOUT' }); };
  await assert.rejects(executor.replaceOwnedRules(policy(), run), { code: 'APPLICATION_ROUTING_TIMEOUT' });
  assert.equal(records.at(-1).filterReplacement.state, 'uncertain'); assert.equal(executor.filterCommitted, null);
});

test('production stateful routes, unowned context and incomplete tunnel proofs refuse before persistence or spawn', async t => {
  for (const cause of ['stateful', 'missing run', 'no lock', 'foreign lease', 'missing retained FD', 'wrong source policy']) await t.test(cause, async () => {
    const { executor, run, records, calls, policy } = fixture();
    run.realms[0].mode = 'routed'; run.realms[0].tunnel = tunnel();
    let input = policy(), context = run;
    if (cause === 'stateful') input = createPFRoutingPolicy(run.realms, { runId: run.runId });
    if (cause === 'missing run') context = undefined;
    if (cause === 'no lock') run.lockAcquired = false;
    if (cause === 'foreign lease') run.rootHookLease = { ...run.rootHookLease, ticket: '2' };
    if (cause === 'missing retained FD') run.realms[0].tunnel.fdRetained = false;
    if (cause === 'wrong source policy') input.rules = 'pass out quick all\n';
    await assert.rejects(executor.replaceOwnedRules(input, context), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
    assert.equal(records.length, 0); assert.equal(calls.length, 0);
  });
});
