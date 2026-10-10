import test from 'node:test';
import assert from 'node:assert/strict';
import { createPFRoutingPolicy as createPolicy, planPFTransition as planTransition, MacOSPFPolicyPlanner,
  PF_ROUTING_ANCHOR, PF_ROUTING_GATES, createStatelessFixturePFRoutingPolicy as createFixturePolicy, pfRoutingAnchor, isPFRoutingRunId,
  PF_ROUTING_GID_MIN, PF_ROUTING_GID_MAX } from '../native/macos-pf-routing/policy.mjs';
import { applicationRoutingReady } from '../electron/application-routing.mjs';

const RUN = 'e152b0ec-3e0c-4b6a-a4ec-18cf1f3435b5';
const createPFRoutingPolicy = (routes, options = {}) => createPolicy(routes, { runId: RUN, ...options });
const createStatelessFixturePFRoutingPolicy = (routes, options = {}) => createFixturePolicy(routes, { runId: RUN, ...options });
const planPFTransition = (input = {}) => planTransition({ runId: RUN, ...input });
const proxy = { protocol: 'socks5', host: '127.0.0.1', port: 43101, username: 'private-user-a', password: 'private-password-a' };
const first = () => ({ environmentId: 'environment_a', gid: 7101, udpPolicy: 'block', mode: 'routed',
  tunnel: { interfaceName: 'utun101', pid: 10001, instanceId: 'core_generation_a', ipv4Address: '198.18.10.1' } });
const second = () => ({ environmentId: 'environment_b', gid: 7102, udpPolicy: 'proxy', mode: 'routed',
  tunnel: { interfaceName: 'utun102', pid: 10002, instanceId: 'core_generation_b', ipv4Address: '198.18.11.1' } });
const error = code => value => value.code === code && !value.message.includes('private');

test('two environments route only their own groups to distinct owned interfaces', () => {
  const result = createPFRoutingPolicy([second(), first()]);
  assert.equal(result.anchor, pfRoutingAnchor(RUN));
  assert.match(result.rules, /route-to \(utun101 198\.18\.10\.1\) inet proto tcp from any to any group 7101/);
  assert.match(result.rules, /route-to \(utun102 198\.18\.11\.1\) inet proto \{ tcp udp \} from any to any group 7102/);
  assert.equal(result.rules.split('\n').filter(line => line && !line.includes('group 7101') && !line.includes('group 7102')).length, 0);
  assert.deepEqual(result.routes.map(item => item.environmentId), ['environment_a', 'environment_b']);
  assert.equal(result.ready, false); assert.equal(result.failClosed, false);
});

test('initial blocked policy needs no live core and contains no pass rule', () => {
  const result = createPFRoutingPolicy([{ environmentId: 'new_env', gid: 7103 }]);
  assert.equal(result.routes[0].mode, 'blocked');
  assert.equal(result.routes[0].tunnel, null);
  assert.doesNotMatch(result.rules, /pass|route-to|DIRECT/);
});

test('strict rules block loopback escapes, UDP when disabled, and IPv6 TCP/UDP before IPv4 routing', () => {
  const { rules, gates } = createPFRoutingPolicy([first()]);
  assert.match(rules, /^block return out quick on lo0 proto \{ tcp udp \}/);
  assert.ok(rules.indexOf('inet6 proto { tcp udp }') < rules.indexOf('pass out'));
  assert.ok(rules.indexOf('inet proto udp') < rules.indexOf('pass out'));
  assert.doesNotMatch(rules, /pass.*inet6|pass.*proto \{ tcp udp \}/);
  assert.equal(gates.nonTcpUdp, false); assert.equal(gates.dnsRealm, false);
});

test('policy rejects rule injection and ambiguous ownership identities', () => {
  for (const patch of [{ environmentId: 'x\npass all' }, { gid: '7101' }, { gid: 0 }, { mode: 'direct' }, { udpPolicy: 'direct' }]) {
    assert.throws(() => createPFRoutingPolicy([{ ...first(), ...patch }]), /not ready/);
  }
  for (const patch of [{ interfaceName: 'utun101) pass all' }, { interfaceName: 'en0' }, { pid: 1 },
    { ipv4Address: '127.0.0.1' }, { ipv4Address: '198.018.10.1' }, { ipv4Address: '224.0.0.1' }, { instanceId: 'x"' }]) {
    assert.throws(() => createPFRoutingPolicy([{ ...first(), tunnel: { ...first().tunnel, ...patch } }]), /not ready/);
  }
  assert.throws(() => createPFRoutingPolicy([{ ...first(), tunnel: null }]), error('PF_ROUTING_INVALID_TUNNEL'));
});

test('distinct environments cannot share gid, interface, core instance, or assigned IP', () => {
  for (const patch of [{ gid: first().gid }, { tunnel: { ...second().tunnel, interfaceName: first().tunnel.interfaceName } },
    { tunnel: { ...second().tunnel, instanceId: first().tunnel.instanceId } }, { tunnel: { ...second().tunnel, ipv4Address: first().tunnel.ipv4Address } }]) {
    assert.throws(() => createPFRoutingPolicy([first(), { ...second(), ...patch }]), error('PF_ROUTING_IDENTITY_CONFLICT'));
  }
});

test('transitions isolate anchor updates and cannot invent unsafe state cleanup commands', () => {
  const old = first(), changed = { ...old, mode: 'blocked' };
  const plan = planPFTransition({ current: [old, second()], next: [changed, second()] });
  assert.deepEqual(plan.changed, ['environment_a']);
  assert.deepEqual(plan.steps.slice(0, 2).map(item => item.kind), ['stop-owned-processes', 'purge-exact-owned-states']);
  assert.equal(plan.steps[1].command, null);
  assert.equal(plan.steps[1].requireConfirmedEmpty, true);
  for (const operation of plan.steps.filter(item => item.executable)) {
    assert.equal(operation.executable, '/sbin/pfctl');
    assert.ok(operation.argv.includes(pfRoutingAnchor(RUN)));
    assert.doesNotMatch(operation.argv.join(' '), /(?:^| )-F|(?:^| )-k|(?:^| )-i|(?:^| )-d|(?:^| )-e/);
  }
  assert.equal(plan.executable, false); assert.equal(plan.failClosed, false);
  assert.ok(plan.preconditions.includes('exactStateCleanup'));
  assert.ok(plan.preconditions.includes('utunIdentityReuse'));
});

test('revoke stops processes and clears exact state before anchor removal and transport teardown', () => {
  const plan = planPFTransition({ current: [first(), second()], next: [second()] });
  assert.deepEqual(plan.steps.map(item => item.kind), ['stop-owned-processes', 'purge-exact-owned-states', 'validate-owned-anchor', 'replace-owned-anchor', 'teardown-owned-transports']);
  assert.doesNotMatch(plan.policy.rules, /group 7101/);
  assert.match(plan.policy.rules, /group 7102/);
  assert.equal(plan.steps.at(-1).requireProcessesStopped, true);
  assert.equal(plan.steps.at(-1).requireStatesEmpty, true);
});

test('unchanged policy does not perturb any anchor or unrelated state', () => {
  assert.deepEqual(planPFTransition({ current: [first(), second()], next: [second(), first()] }).steps, []);
});

test('planner registration forces blocked mode and stores authenticated proxy only privately', () => {
  const planner = new MacOSPFPolicyPlanner(), result = planner.prepareRoute({ ...first(), proxy });
  assert.equal(result.policy.routes[0].mode, 'blocked');
  const output = JSON.stringify({ result, snapshot: planner.snapshot(), planner });
  assert.equal(output.includes(proxy.username), false); assert.equal(output.includes(proxy.password), false);
  assert.equal(output.includes(String(proxy.port)), false);
  const privateConfig = planner.privateTransportConfig('environment_a');
  assert.deepEqual(privateConfig.proxy, proxy); assert.equal(privateConfig.directFallback, false);
  privateConfig.proxy.password = 'changed';
  assert.equal(planner.privateTransportConfig('environment_a').proxy.password, proxy.password);
  assert.throws(() => planner.prepareRoute({ ...first(), proxy }), error('PF_ROUTING_ROUTE_EXISTS'));
});

test('managed route must be authenticated loopback SOCKS, never external or direct', () => {
  for (const patch of [{ protocol: 'http' }, { host: 'localhost' }, { host: '192.0.2.1' }, { port: 0 },
    { username: '' }, { password: '' }, { password: 'x'.repeat(256) }, { username: 'x\nprivate' }]) {
    const planner = new MacOSPFPolicyPlanner();
    assert.throws(() => planner.prepareRoute({ ...first(), proxy: { ...proxy, ...patch } }), error('PF_ROUTING_MANAGED_PROXY_REQUIRED'));
    assert.deepEqual(planner.snapshot().routes, []);
  }
});

test('same-name replacement interface with a new generation or pid immediately invalidates planned routing', () => {
  for (const replacement of [{ ...first().tunnel, pid: 10099 }, { ...first().tunnel, instanceId: 'unrelated_vpn' }, null]) {
    const planner = new MacOSPFPolicyPlanner(); planner.prepareRoute({ ...first(), proxy }); planner.planActivation('environment_a');
    const failure = planner.observeRuntime('environment_a', replacement);
    assert.equal(failure.runtimeIdentityLost, true); assert.equal(failure.retainBlockingPolicy, true);
    assert.equal(failure.ready, false); assert.equal(failure.failClosed, false);
    assert.doesNotMatch(failure.policy.rules, /pass/);
    assert.equal(failure.steps[0].kind, 'stop-owned-processes');
    assert.equal(planner.snapshot().routes[0].mode, 'blocked');
  }
});

test('matching witness is still no native acceptance or launch authorization', () => {
  const planner = new MacOSPFPolicyPlanner(); planner.prepareRoute({ ...first(), proxy }); planner.planActivation('environment_a');
  assert.equal(planner.observeRuntime('environment_a', first().tunnel).changed, false);
  const status = planner.snapshot();
  assert.equal(applicationRoutingReady(status), false);
  assert.ok(PF_ROUTING_GATES.every(key => status.gates[key] === false));
  assert.equal(status.verification.passed, false);
  assert.equal(status.processScopeVerified, false);
  assert.ok(Object.values(status.capabilities).every(value => value === false));
});

test('releasing unconfirmed route refuses and retains private config and blocking plan', () => {
  const planner = new MacOSPFPolicyPlanner(); planner.prepareRoute({ ...first(), proxy });
  for (const observations of [{}, { ownedProcessesStopped: true }, { ownedStatesEmpty: true }]) {
    assert.throws(() => planner.release('environment_a', observations), error('PF_ROUTING_CLEANUP_REQUIRED'));
    assert.deepEqual(planner.privateTransportConfig('environment_a').proxy, proxy);
  }
  assert.equal(planner.release('environment_a', { ownedProcessesStopped: true, ownedStatesEmpty: true }).released, true);
  assert.deepEqual(planner.snapshot().routes, []);
  assert.throws(() => planner.privateTransportConfig('environment_a'), error('PF_ROUTING_ROUTE_NOT_FOUND'));
});

test('close erases credentials, requests stopped processes/exact cleanup, and plans persistent blocking', () => {
  const planner = new MacOSPFPolicyPlanner(); planner.prepareRoute({ ...first(), proxy }); planner.planActivation('environment_a');
  const closed = planner.close();
  assert.equal(closed.retainBlockingPolicy, true); assert.equal(closed.closed, true);
  assert.doesNotMatch(closed.policy.rules, /pass/);
  assert.equal(closed.steps[0].kind, 'stop-owned-processes');
  assert.equal(closed.steps[1].kind, 'purge-exact-owned-states');
  assert.equal(planner.snapshot().status, 'closed');
  assert.equal(JSON.stringify(closed).includes(proxy.password), false);
  assert.throws(() => planner.privateTransportConfig('environment_a'), error('PF_ROUTING_CLOSED'));
  assert.throws(() => planner.prepareRoute({ ...second(), proxy }), error('PF_ROUTING_CLOSED'));
});

const fixtureDestinations = [{ host: '198.51.100.42', ports: [44441, 44442, 44443, 44444] }, { host: '1.1.1.1', ports: [53] }];

test('controlled candidate routes only reserved fixture destinations and creates no state in either direction', () => {
  const policy = createStatelessFixturePFRoutingPolicy([second()], { fixtureDestinations });
  assert.equal(policy.fixtureOnly, true); assert.equal(policy.productionReady, false);
  assert.equal(policy.ready, false); assert.equal(policy.failClosed, false); assert.equal(policy.executable, false);
  assert.equal(policy.statePolicy, 'stateless-fixture');
  assert.doesNotMatch(policy.rules, /keep state|modulate state|synproxy state/);
  const passes = policy.rules.split('\n').filter(line => line.startsWith('pass'));
  assert.equal(passes.length, 8);
  assert.ok(passes.every(line => line.includes('flags any no state')));
  const outbound = passes.filter(line => line.startsWith('pass out'));
  assert.ok(outbound.every(line => line.includes('group 7102') && line.includes('route-to (utun102 198.18.11.1)')));
  assert.ok(outbound.every(line => /to (?:198\.51\.100\.42|1\.1\.1\.1) port/.test(line)));
  const inbound = passes.filter(line => line.startsWith('pass in'));
  assert.ok(inbound.every(line => line.includes('on utun102') && /from (?:198\.51\.100\.42|1\.1\.1\.1) port/.test(line)));
  assert.match(policy.rules, /block return in quick on utun102 proto \{ tcp udp \}/);
  assert.equal(policy.experiment.statesAbsenceVerified, false);
  assert.ok(policy.experiment.requires.includes('boundFreshSourceTuples'));
  assert.ok(policy.experiment.requires.includes('preflightMatchingStatesAbsent'));
  assert.ok(policy.experiment.requires.includes('postflightMatchingStatesAbsent'));
  assert.match(policy.experiment.onUnexpectedState, /retain-owned-guardian/);
});

test('blocked cold fixture policy never opens inbound or outbound traffic', () => {
  const policy = createStatelessFixturePFRoutingPolicy([{ ...first(), mode: 'blocked' }], { fixtureDestinations });
  assert.doesNotMatch(policy.rules, /pass|route-to|keep state/);
  assert.ok(PF_ROUTING_GATES.every(key => policy.gates[key] === false));
});

test('stateless two-node fixtures retain each group/interface and do not authorize arbitrary destinations', () => {
  const policy = createStatelessFixturePFRoutingPolicy([first(), second()], { fixtureDestinations });
  assert.ok(policy.rules.split('\n').filter(line => line.startsWith('pass out') && line.includes('group 7101')).every(line => line.includes('utun101') && line.includes('proto tcp')));
  assert.doesNotMatch(policy.rules, /pass out.*to any/);
  for (const targets of [[], [{ host: '8.8.8.8', ports: [443] }], [{ host: '198.51.100.42', ports: [443] }],
    [{ host: '1.1.1.1', ports: [443] }], [{ host: '198.51.100.42', ports: [44441, 44441] }],
    [{ host: '198.51.100.42\npass all', ports: [44441] }]]) {
    assert.throws(() => createStatelessFixturePFRoutingPolicy([first()], { fixtureDestinations: targets }), /not ready/);
  }
});

test('policy follows the allocated private GID range rather than accepting arbitrary host groups', () => {
  assert.equal(PF_ROUTING_GID_MIN, 7100); assert.equal(PF_ROUTING_GID_MAX, 7999);
  for (const selectedGid of [20, 80, 1000, 7099, 8000]) assert.throws(() => createPFRoutingPolicy([{ ...first(), gid: selectedGid }]), error('PF_ROUTING_INVALID_GID'));
});

test('new policies require a canonical lower RFC v4 run and never use the historical namespace', () => {
  assert.equal(PF_ROUTING_ANCHOR, 'io.envara.pf.root.v1');
  assert.equal(pfRoutingAnchor(RUN), `io.envara.pf.run.${RUN}`);
  for (const value of [undefined, RUN.toUpperCase(), RUN.replace('-4b6a-', '-3b6a-'), RUN.replace('-a4ec-', '-74ec-'), `${RUN}/child`, '../root', 42]) {
    assert.equal(isPFRoutingRunId(value), false);
    assert.throws(() => pfRoutingAnchor(value), { code: 'PF_ROUTING_INVALID_RUN' });
    assert.throws(() => createPolicy([first()], { runId: value }), { code: 'PF_ROUTING_INVALID_RUN' });
    assert.throws(() => createFixturePolicy([first()], { runId: value, fixtureDestinations }), { code: 'PF_ROUTING_INVALID_RUN' });
    assert.throws(() => planTransition({ next: [first()], runId: value }), { code: 'PF_ROUTING_INVALID_RUN' });
  }
});

test('the same routes in a new run have a distinct anchor and labels; planner transitions retain one immutable run', () => {
  const nextRun = '66d5514e-771f-4c09-8da7-3f869c3c5166';
  const before = createPFRoutingPolicy([first()]), after = createPFRoutingPolicy([first()], { runId: nextRun });
  assert.notEqual(before.anchor, after.anchor); assert.notEqual(before.rules, after.rules);
  const planner = new MacOSPFPolicyPlanner({ runId: RUN });
  const prepared = planner.prepareRoute({ ...first(), proxy });
  const activated = planner.planActivation(first().environmentId), closed = planner.close();
  for (const result of [prepared, activated, closed]) {
    assert.equal(result.policy.runId, RUN); assert.equal(result.policy.anchor, pfRoutingAnchor(RUN));
    for (const step of result.steps.filter(value => value.argv)) assert.ok(step.argv.includes(pfRoutingAnchor(RUN)));
  }
  assert.equal(planner.snapshot().runId, RUN); assert.equal(planner.snapshot().ready, false);
});
