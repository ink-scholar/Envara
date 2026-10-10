import assert from 'node:assert/strict';
import test from 'node:test';
import { runSystemResolverIsolationMatrix, DNS_MATRIX_PHASES, aggregateDnsFamilyChecks } from '../scripts/accept-macos-dns-routing.mjs';
import { classifyDiagnosticDnsAnswers } from '../native/macos-local-routing/diagnostic-child.mjs';

const routes = [
  { name: 'one', address4: '203.0.113.42', address6: '2001:db8::42' },
  { name: 'two', address4: '203.0.113.43', address6: '2001:db8::43' },
];
const unbound = { name: 'unbound' };

function fixtureModel({ sharedCache = false, coalesced = false, contaminateUnbound = false,
  unboundFailure = 'ENOTFOUND', unboundAddresses = null, unknownBound = false,
  repeatWithoutReply = false, noFreshEvidence = false } = {}) {
  const cache = new Map(), calls = [], rawResults = [];
  let question = 0;
  return {
    calls, rawResults,
    options: { routes, unbound, newQuestion: () => `${(++question).toString(16).padStart(32, '0')}.example.com`,
      runQuery: async ({ endpoint, request }) => {
        calls.push({ name: endpoint.name, hostname: request.hostname, id: request.id });
        const own = [request.expectedAddress4, request.expectedAddress6].filter(Boolean);
        let answers = own, code = 'FIXTURE_DNS_RESOLVED', resolved = true;
        if (endpoint.name === 'unbound') {
          if (contaminateUnbound) answers = [routes[0].address4, routes[0].address6];
          else if (unboundAddresses) answers = unboundAddresses;
          else { answers = []; code = unboundFailure; resolved = false; }
        } else if (unknownBound) answers = ['192.0.2.99'];
        else if (sharedCache) {
          if (!cache.has(request.hostname)) cache.set(request.hostname, answers);
          answers = cache.get(request.hostname);
        } else if (coalesced && request.id === 'family4_concurrentSameQuestion_two') {
          answers = [routes[0].address4, routes[0].address6];
        }
        const result = { id: request.id, type: 'dns-result', family: request.family, code, resolved,
          ...classifyDiagnosticDnsAnswers(answers.map(address => ({ address })), {
            ownAddresses: own, otherAddresses: request.otherFixtureAddresses,
            diagnosticFixtureAddresses: request.diagnosticFixtureAddresses,
          }), ...(own.length ? { matchedExpectedAddresses: own.every(value => answers.includes(value)) && answers.every(value => own.includes(value)) } : {}) };
        rawResults.push(result);
        return result;
      },
      // Deliberately claim a native reply for every bound lookup. Answer-source
      // checks must still reject leaks when transport counters appear healthy.
      observeReplies: async ({ endpoint, result }) => ({ replyCount: endpoint.name === 'unbound' ||
        noFreshEvidence || (repeatWithoutReply && result.id.endsWith('_repeat2')) ? 0 : 2 }),
    },
  };
}

test('isolated resolver realms cover both serial cache orders and the unbound process', async () => {
  const model = fixtureModel();
  const report = await runSystemResolverIsolationMatrix(model.options);
  assert.equal(report.systemResolverIsolationPassed, true);
  assert.equal(report.unaffectedResolverPassed, true);
  assert.equal(Object.keys(report.checks).length, 14);
  assert.deepEqual(report.resolverMatrix.phases.map(value => value.id), DNS_MATRIX_PHASES.map(value => value.id));
  assert.equal(new Set(model.calls.map(value => value.hostname)).size, 5);
  for (const phase of report.resolverMatrix.phases) {
    const calls = model.calls.filter(value => value.id.startsWith(`family4_${phase.id}_`));
    assert.equal(new Set(calls.map(value => value.hostname)).size, 1);
    assert.deepEqual(calls.map(value => value.name), phase.order);
  }
  assert.equal(report.checks.family4_serialOneThenTwo_one_repeat2.queryPosition, 3);
  assert.equal(report.checks.family4_serialTwoThenOne_two_repeat2.queryPosition, 3);
  assert.equal(report.resolverMatrix.unboundScope, 'one unbound owned diagnostic process only');
  const serialized = JSON.stringify(report);
  for (const value of [...model.calls.map(value => value.hostname), ...routes.flatMap(value => [value.address4, value.address6])]) {
    assert.equal(serialized.includes(value), false);
  }
  assert.equal(report.resolverMatrix.queryContentsStored, false);
  assert.equal(report.resolverMatrix.answerAddressesStored, false);
});

test('global cache leaks are caught in both route orders despite native reply evidence', async () => {
  const report = await runSystemResolverIsolationMatrix(fixtureModel({ sharedCache: true }).options);
  assert.equal(report.systemResolverIsolationPassed, false);
  for (const key of ['family4_serialOneThenTwo_two', 'family4_serialTwoThenOne_one']) {
    assert.equal(report.checks[key].passed, false);
    assert.equal(report.checks[key].answerSource, 'other');
    assert.equal(report.checks[key].otherFixtureAnswerObserved, true);
    assert.equal(report.checks[key].signedDNSReplyCount, 2);
  }
  assert.equal(report.checks.family4_serialOneThenTwo_one_repeat2.passed, true);
  assert.equal(report.unaffectedResolverPassed, true);
});

test('same-route warm cache is accepted only with a native reply earlier in the same phase', async () => {
  const model = fixtureModel({ repeatWithoutReply: true });
  const report = await runSystemResolverIsolationMatrix(model.options);
  assert.equal(report.systemResolverIsolationPassed, true);
  for (const key of ['family4_serialOneThenTwo_one_repeat2', 'family4_serialTwoThenOne_two_repeat2']) {
    assert.equal(report.checks[key].signedDNSReplyCount, 0);
    assert.equal(report.checks[key].cacheConsistentWithOwnRoute, true);
    assert.equal(report.checks[key].passed, true);
  }
  // Remove fresh-question evidence: even the correct answer and previous
  // phases' successful routes must not grant a new phase cache exception.
  const native = model.options.observeReplies;
  model.options.newQuestion = (() => { let question = 0; return () => `${(++question).toString(16).padStart(32, '0')}.example.com`; })();
  model.options.observeReplies = args => args.result.id.startsWith('family4_serialTwoThenOne_') ? { replyCount: 0 } : native(args);
  const unproven = await runSystemResolverIsolationMatrix(model.options);
  assert.equal(unproven.checks.family4_serialTwoThenOne_two_repeat2.cacheConsistentWithOwnRoute, false);
  assert.equal(unproven.checks.family4_serialTwoThenOne_two_repeat2.passed, false);
  assert.equal(unproven.systemResolverIsolationPassed, false);
});

test('cross-route cache contamination is never rescued by a warm-cache exception', async () => {
  const report = await runSystemResolverIsolationMatrix(fixtureModel({ sharedCache: true, repeatWithoutReply: true }).options);
  assert.equal(report.systemResolverIsolationPassed, false);
  assert.equal(report.checks.family4_serialOneThenTwo_two.answerSource, 'other');
  assert.equal(report.checks.family4_serialOneThenTwo_two.cacheConsistentWithOwnRoute, false);
  assert.equal(report.checks.family4_serialOneThenTwo_two.passed, false);
  assert.equal(report.checks.family4_serialOneThenTwo_one_repeat2.cacheConsistentWithOwnRoute, true);
  assert.equal(report.checks.family4_serialTwoThenOne_one.passed, false);
});

test('same-question coalescing fails acceptance even if both requests were observed', async () => {
  const report = await runSystemResolverIsolationMatrix(fixtureModel({ coalesced: true }).options);
  assert.equal(report.checks.family4_concurrentSameQuestion_one.passed, true);
  assert.equal(report.checks.family4_concurrentSameQuestion_two.answerSource, 'other');
  assert.equal(report.checks.family4_concurrentSameQuestion_two.passed, false);
  assert.equal(report.systemResolverIsolationPassed, false);
});

test('unbound resolver synthetic answers fail the separate unaffected-fixture gate', async () => {
  const report = await runSystemResolverIsolationMatrix(fixtureModel({ contaminateUnbound: true }).options);
  assert.equal(report.unaffectedResolverPassed, false);
  assert.equal(report.systemResolverIsolationPassed, false);
  for (const key of ['family4_concurrentWithUnbound_unbound', 'family4_serialWithUnbound_unbound']) {
    assert.equal(report.checks[key].answerSource, 'other');
    assert.equal(report.checks[key].otherFixtureAnswerObserved, true);
    assert.equal(report.checks[key].noCurrentFixtureAnswerObserved, false);
    assert.equal(report.checks[key].passed, false);
  }
});

test('ordinary unbound answers are outside the fixture classification and remain unaffected', async () => {
  const report = await runSystemResolverIsolationMatrix(fixtureModel({ unboundAddresses: ['192.0.2.99'] }).options);
  assert.equal(report.unaffectedResolverPassed, true);
  assert.equal(report.checks.family4_serialWithUnbound_unbound.answerSource, 'unexpected');
  assert.equal(report.checks.family4_serialWithUnbound_unbound.unexpectedAnswersObserved, true);
  assert.equal(JSON.stringify(report).includes('192.0.2.99'), false);
});

test('temporary failure and missing classification cannot prove unaffected behavior', async () => {
  const report = await runSystemResolverIsolationMatrix(fixtureModel({ unboundFailure: 'EAI_AGAIN' }).options);
  assert.equal(report.unaffectedResolverPassed, false);
  assert.equal(report.checks.family4_concurrentWithUnbound_unbound.completedResolverCall, false);
  const model = fixtureModel();
  model.options.runQuery = async () => ({ resolved: false, code: 'ENOTFOUND' });
  const unavailable = await runSystemResolverIsolationMatrix(model.options);
  assert.equal(unavailable.unaffectedResolverPassed, false);
  assert.equal(unavailable.checks.family4_concurrentWithUnbound_unbound.classificationAvailable, false);
});

test('unknown bound answers fail and raw errors never enter the report', async () => {
  const model = fixtureModel({ unknownBound: true });
  const report = await runSystemResolverIsolationMatrix(model.options);
  assert.equal(report.systemResolverIsolationPassed, false);
  assert.equal(report.checks.family4_serialOneThenTwo_one.unexpectedAnswersObserved, true);
  assert.equal(JSON.stringify(report).includes('192.0.2.99'), false);
  model.options.runQuery = async () => { throw Object.assign(new Error('secret query payload'), { code: 'not a safe code: secret' }); };
  const failure = await runSystemResolverIsolationMatrix(model.options);
  assert.equal(failure.checks.family4_concurrentSameQuestion_one.resolverCode, 'FIXTURE_UNAVAILABLE');
  assert.equal(JSON.stringify(failure).includes('secret'), false);
});

test('bounded IPC timeout leaves incomplete matrix failed without a native capture', async () => {
  const model = fixtureModel();
  model.options.runQuery = () => new Promise(() => {});
  model.options.queryTimeoutMs = 100;
  model.options.matrixTimeoutMs = 160;
  const began = Date.now();
  const report = await runSystemResolverIsolationMatrix(model.options);
  assert.ok(Date.now() - began < 1500);
  assert.equal(report.resolverMatrix.complete, false);
  assert.equal(report.systemResolverIsolationPassed, false);
  assert.equal(report.unaffectedResolverPassed, false);
  assert.equal(report.checks.family4_concurrentSameQuestion_one.resolverCode, 'FIXTURE_IPC_TIMEOUT');
});

test('fresh questions cannot accidentally reuse an earlier phase cache key', async () => {
  const model = fixtureModel();
  model.options.newQuestion = () => 'a'.repeat(32) + '.example.com';
  await assert.rejects(runSystemResolverIsolationMatrix(model.options), { code: 'ERR_ASSERTION' });
});

test('explicit family matrices expect one address and retain separate family evidence', async () => {
  const reports = [];
  for (const family of [4, 6]) {
    const model = fixtureModel();
    const query = model.options.runQuery;
    model.options.family = family;
    model.options.runQuery = args => {
      assert.equal(args.request.family, family);
      if (args.endpoint.name !== 'unbound') {
        assert.equal(args.request[family === 4 ? 'expectedAddress6' : 'expectedAddress4'], undefined);
        assert.equal(args.request[family === 4 ? 'expectedAddress4' : 'expectedAddress6'], family === 4 ? args.endpoint.address4 : args.endpoint.address6);
      }
      return query(args);
    };
    const report = await runSystemResolverIsolationMatrix(model.options);
    assert.equal(report.systemResolverIsolationPassed, true);
    assert.equal(report.resolverMatrix.family, family);
    assert.ok(Object.values(report.checks).every(value => value.family === family && value.familyAcknowledged));
    reports.push(report);
  }
  const aggregate = aggregateDnsFamilyChecks(Object.assign({}, ...reports.map(value => value.checks)));
  assert.equal(aggregate.concurrentSameQuestion_one.passed, true);
  assert.deepEqual(aggregate.concurrentSameQuestion_one.families, [4, 6]);
  assert.equal(aggregate.concurrentSameQuestion_two.matchedOwnRouteAnswers, true);
});

test('IPv6 failure or missing family evidence cannot inherit IPv4 acceptance', async () => {
  const v4 = await runSystemResolverIsolationMatrix(fixtureModel().options);
  const model = fixtureModel();
  model.options.family = 6;
  const query = model.options.runQuery;
  model.options.runQuery = async args => args.endpoint.name === 'unbound' ? query(args) : ({
    id: args.request.id, family: 6, type: 'dns-result', resolved: false, code: 'ENOTFOUND',
    ...classifyDiagnosticDnsAnswers([], { ownAddresses: [args.endpoint.address6], otherAddresses: args.request.otherFixtureAddresses }),
    matchedExpectedAddresses: false,
  });
  const v6 = await runSystemResolverIsolationMatrix(model.options);
  assert.equal(v6.systemResolverIsolationPassed, false);
  assert.equal(v6.checks.family6_concurrentSameQuestion_one.resolverCode, 'ENOTFOUND');
  assert.equal(v6.checks.family6_concurrentSameQuestion_one.answerSource, 'unexpected');
  assert.equal(v6.checks.family6_concurrentSameQuestion_one.otherFixtureAnswerObserved, false);
  const aggregate = aggregateDnsFamilyChecks({ ...v4.checks, ...v6.checks });
  assert.equal(aggregate.concurrentSameQuestion_one.passed, false);
  assert.deepEqual(aggregate.concurrentSameQuestion_one.resolverCodes, { 4: 'FIXTURE_DNS_RESOLVED', 6: 'ENOTFOUND' });
  const missing = fixtureModel();
  const lookup = missing.options.runQuery;
  missing.options.runQuery = async args => { const result = await lookup(args); delete result.family; return result; };
  const unacknowledged = await runSystemResolverIsolationMatrix(missing.options);
  assert.equal(unacknowledged.systemResolverIsolationPassed, false);
  assert.equal(unacknowledged.unaffectedResolverPassed, false);
});

test('unbound synthetic IPv6 format variants and missing format evidence fail unaffected acceptance', async () => {
  for (const address of ['2001:0db8:0000:0000:0000:0000:0000:0042', '::ffff:203.0.113.42', '2001:db8:1234::cb00:712b']) {
    const model = fixtureModel({ unboundAddresses: [address] });
    model.options.family = 6;
    const report = await runSystemResolverIsolationMatrix(model.options);
    const check = report.checks.family6_concurrentWithUnbound_unbound;
    assert.equal(check.answerSource, 'unexpected');
    assert.ok(check.canonicalFixtureAnswerObserved || check.fixtureIpv4TailObserved);
    assert.equal(check.noCurrentFixtureAnswerObserved, false);
    assert.equal(report.unaffectedResolverPassed, false);
    assert.equal(JSON.stringify(report).includes(address), false);
  }
  const model = fixtureModel({ unboundAddresses: ['2001:db8:1234::dead:beef', '2001:db8:cb00:712a::'] });
  model.options.family = 6;
  const unrelated = await runSystemResolverIsolationMatrix(model.options);
  assert.equal(unrelated.unaffectedResolverPassed, true);
  const query = model.options.runQuery;
  model.options.runQuery = async args => { const result = await query(args); delete result.fixtureIpv4TailObserved; return result; };
  assert.equal((await runSystemResolverIsolationMatrix(model.options)).unaffectedResolverPassed, false);
});
