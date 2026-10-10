import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { classifyDiagnosticDnsAnswers } from '../native/macos-local-routing/diagnostic-child.mjs';

const childURL = new URL('../native/macos-local-routing/diagnostic-child.mjs', import.meta.url);
const childPath = fileURLToPath(childURL);
const ownAddresses = Object.freeze(['203.0.113.42', '2001:db8::42']);
const otherAddresses = Object.freeze(['203.0.113.43', '2001:db8::43']);
const unknownAddress = '198.51.100.99';
const expandedIPv6 = '2001:0db8:0000:0000:0000:0000:0000:0042';
const mappedIPv6 = '::ffff:203.0.113.42';
const unknownPrefixTailIPv6 = '2001:db8:abcd:1234:5678:90ab:cb00:712a';
const unrelatedIPv6 = '2001:db8::1234';
const trailingCompressedIPv6 = '2001:db8:cb00:712a::';
const rawErrorMessage = 'private resolver diagnostic: 203.0.113.42 2001:db8::43 secret-host.example.com';
const host = digit => `${digit.repeat(16)}.example.com`;
const answers = addresses => addresses.map(address => ({ address, family: address.includes(':') ? 6 : 4 }));
const classification = (answerSource, ownFixtureAnswerObserved, otherFixtureAnswerObserved, unexpectedAnswersObserved,
  actualAddressFamilies = [], canonicalFixtureAnswerObserved = false, fixtureIpv4TailObserved = false) => ({
  answerSource, ownFixtureAnswerObserved, otherFixtureAnswerObserved, unexpectedAnswersObserved,
  actualAddressFamilies, canonicalFixtureAnswerObserved, fixtureIpv4TailObserved,
});

function assertPrivateResponse(value, hostname) {
  const json = JSON.stringify(value);
  for (const secret of [...ownAddresses, ...otherAddresses, unknownAddress, expandedIPv6, mappedIPv6, unknownPrefixTailIPv6, unrelatedIPv6, trailingCompressedIPv6,
    rawErrorMessage, 'secret-host.example.com', hostname].filter(Boolean)) {
    assert.equal(json.includes(secret), false, 'DNS result leaked a query, answer or resolver message');
  }
  assert.doesNotMatch(json, /"(?:address|addresses|hostname|message|error)"\s*:/);
}

test('answer provenance distinguishes own, other, mixed and unknown answers without returning addresses', () => {
  const cases = [
    ['own dual stack', answers(ownAddresses), classification('own', true, false, false, [4, 6], true)],
    ['own subset', answers([ownAddresses[0]]), classification('own', true, false, false, [4])],
    ['own duplicates', answers([ownAddresses[0], ownAddresses[0]]), classification('own', true, false, false, [4])],
    ['other dual stack', answers(otherAddresses), classification('other', false, true, false, [4, 6], true)],
    ['both fixture realms', answers([ownAddresses[0], otherAddresses[1]]), classification('unexpected', true, true, false, [4, 6], true)],
    ['own plus unknown', answers([ownAddresses[0], unknownAddress]), classification('unexpected', true, false, true, [4])],
    ['other plus unknown', answers([otherAddresses[0], unknownAddress]), classification('unexpected', false, true, true, [4])],
    ['unknown only', answers([unknownAddress]), classification('unexpected', false, false, true, [4])],
    ['empty answer set', [], classification('unexpected', false, false, false)],
    ['missing answer set', undefined, classification('unexpected', false, false, false)],
    ['malformed answer entry', [null, {}], classification('unexpected', false, false, true)],
    ['families follow text and are sorted unique', [{ address: ownAddresses[1], family: 4 }, { address: ownAddresses[0], family: 6 },
      { address: ownAddresses[1], family: 4 }], classification('own', true, false, false, [4, 6], true)],
  ];
  for (const [name, input, expected] of cases) {
    const actual = classifyDiagnosticDnsAnswers(input, { ownAddresses, otherAddresses });
    assert.deepEqual(actual, expected, name);
    assertPrivateResponse(actual);
  }
  assert.deepEqual(classifyDiagnosticDnsAnswers(answers(ownAddresses)), classification('unexpected', false, false, true, [4, 6]));
  assert.deepEqual(classifyDiagnosticDnsAnswers(answers(otherAddresses), { otherAddresses }), classification('other', false, true, false, [4, 6], true));
});

test('IPv6 normalization and IPv4 tails are diagnostic observations rather than own-answer proof', () => {
  for (const [address, canonical, tail] of [[expandedIPv6, true, false], [mappedIPv6, false, true],
    [unknownPrefixTailIPv6, false, true], [unrelatedIPv6, false, false], [trailingCompressedIPv6, false, false]]) {
    const actual = classifyDiagnosticDnsAnswers(answers([address]), { ownAddresses: [ownAddresses[1]],
      otherAddresses: [otherAddresses[1]], diagnosticFixtureAddresses: [ownAddresses[0]] });
    assert.deepEqual(actual, classification('unexpected', false, false, true, [6], canonical, tail));
    assertPrivateResponse(actual);
  }
});

test('answer configuration accepts only bounded, disjoint reserved fixture addresses', () => {
  const invalidConfigurations = [
    { ownAddresses: '203.0.113.42' },
    { otherAddresses: null },
    { ownAddresses: [ownAddresses[0], ...ownAddresses, ...ownAddresses] },
    { otherAddresses: Array(1) },
    { ownAddresses: ['127.0.0.1'] },
    { otherAddresses: ['203.0.113.44'] },
    { ownAddresses: ['2001:db8:0:0:0:0:0:42'] },
    { otherAddresses: ['2001:DB8::43'] },
    { ownAddresses: ['203.0.113.42\n'] },
    { otherAddresses: [{ address: otherAddresses[0] }] },
    { ownAddresses, otherAddresses: [ownAddresses[0]] },
    { ownAddresses, otherAddresses: [ownAddresses[1]] },
    { diagnosticFixtureAddresses: null },
    { diagnosticFixtureAddresses: ['127.0.0.1'] },
    { diagnosticFixtureAddresses: [...ownAddresses, ...ownAddresses, ownAddresses[0]] },
  ];
  for (const configured of invalidConfigurations) {
    assert.throws(() => classifyDiagnosticDnsAnswers(answers(ownAddresses), configured), TypeError);
  }
  // Duplicate configured entries remain valid; provenance is set membership,
  // whereas completeness of a requested A/AAAA pair is a separate IPC check.
  assert.deepEqual(classifyDiagnosticDnsAnswers(answers([ownAddresses[0]]), {
    ownAddresses: [ownAddresses[0], ownAddresses[0]], otherAddresses,
  }), classification('own', true, false, false, [4]));
});

// The preload replaces the same default dns object imported by the child.
// Every possible lookup remains synthetic, including unexpected requests.
const preload = `
  import dns from 'node:dns';
  const own = ${JSON.stringify(answers(ownAddresses))};
  const other = ${JSON.stringify(answers(otherAddresses))};
  const unknown = ${JSON.stringify(answers([unknownAddress]))};
  const diagnostic = ${JSON.stringify([expandedIPv6, mappedIPv6, unknownPrefixTailIPv6, unrelatedIPv6, trailingCompressedIPv6].map(address => answers([address])))};
  const rawErrorMessage = ${JSON.stringify(rawErrorMessage)};
  const hostname = digit => digit.repeat(16) + '.example.com';
  dns.lookup = (query, options, callback) => {
    process.send?.({ type: 'test-lookup', allAddressesRequested: options?.all === true, requestedFamily: options?.family });
    const byFamily = values => options?.family ? values.filter(value => value.family === options.family) : values;
    if (query === hostname('f')) return;
    if (query === hostname('4')) {
      setTimeout(() => callback(null, byFamily(own)), 250);
      return;
    }
    queueMicrotask(() => {
      if (query === hostname('a')) return callback(null, byFamily(own));
      if (query === hostname('b')) return callback(null, byFamily(other));
      if (query === hostname('c')) return callback(null, byFamily([own[0], other[1]]));
      if (query === hostname('d')) return callback(null, byFamily(unknown));
      if (query === hostname('0')) return callback(null, byFamily([own[0]]));
      if (query === hostname('3')) return callback(null, []);
      for (const [index, digit] of ['5', '6', '7', '8', '9'].entries()) {
        if (query === hostname(digit)) return callback(null, byFamily(diagnostic[index]));
      }
      const error = new Error(rawErrorMessage);
      error.code = query === hostname('1') ? 'unsafe-code: ' + rawErrorMessage : 'ENOTFOUND';
      callback(error, query === hostname('2') ? byFamily([other[0], unknown[0]]) : undefined);
    });
  };
`;
const preloadURL = `data:text/javascript,${encodeURIComponent(preload)}`;

function fixtureProcess(t, { ipc = true, args = [childPath] } = {}) {
  const child = spawn(process.execPath, ['--import', preloadURL, ...args], {
    env: { PATH: '/usr/bin:/bin' },
    stdio: ['ignore', 'pipe', 'pipe', ...(ipc ? ['ipc'] : [])],
  });
  const messages = [];
  let stdout = '', stderr = '', failure;
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', value => { stdout += value; });
  child.stderr.on('data', value => { stderr += value; });
  child.on('message', value => messages.push(value));
  child.on('error', error => { failure = error; });
  const closed = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
  const receive = (predicate, timeoutMs = 3000) => new Promise((resolve, reject) => {
    const existing = messages.find(predicate);
    if (existing) return resolve(existing);
    if (failure) return reject(failure);
    if (child.exitCode !== null || child.signalCode !== null) return reject(new Error('fixture exited before its IPC reply'));
    const finish = (error, value) => {
      clearTimeout(timer); child.removeListener('message', onMessage);
      child.removeListener('error', onError); child.removeListener('close', onClose);
      if (error) reject(error); else resolve(value);
    };
    const onMessage = value => { if (predicate(value)) finish(null, value); };
    const onError = error => finish(error);
    const onClose = () => finish(new Error('fixture exited before its IPC reply'));
    const timer = setTimeout(() => finish(new Error('fixture IPC deadline')), timeoutMs);
    child.on('message', onMessage); child.once('error', onError); child.once('close', onClose);
  });
  const stop = async () => {
    if (child.exitCode === null && child.signalCode === null) {
      if (child.connected) child.send({ id: 'test_exit', type: 'exit' }, () => {});
      else child.kill();
      const timer = setTimeout(() => child.kill(), 1000);
      try { await closed; } finally { clearTimeout(timer); }
    } else await closed;
  };
  t.after(stop);
  return {
    child, messages, closed, stop, receive,
    output: () => ({ stdout, stderr }),
    call: async request => {
      const reply = receive(value => value?.id === request.id);
      child.send(request);
      return reply;
    },
  };
}

function dnsRequest(id, hostname, extra = {}) {
  return { id, type: 'dns', hostname, expectedAddress4: ownAddresses[0], expectedAddress6: ownAddresses[1],
    otherFixtureAddresses: [...otherAddresses], timeoutMs: 100, ...extra };
}

test('real private IPC returns provenance and complete-match evidence with no DNS network or raw diagnostics', async t => {
  const fixture = fixtureProcess(t);
  const ready = await fixture.receive(value => value?.type === 'ready');
  assert.equal(ready.pid, fixture.child.pid); assert.equal(ready.parentPid, process.pid);
  const cases = [
    ['own', 'a', 'FIXTURE_DNS_RESOLVED', true, true, classification('own', true, false, false, [4, 6], true)],
    ['other', 'b', 'FIXTURE_DNS_RESOLVED', true, false, classification('other', false, true, false, [4, 6], true)],
    ['mixed', 'c', 'FIXTURE_DNS_RESOLVED', true, false, classification('unexpected', true, true, false, [4, 6], true)],
    ['unknown', 'd', 'FIXTURE_DNS_RESOLVED', true, false, classification('unexpected', false, false, true, [4])],
    ['partial', '0', 'FIXTURE_DNS_RESOLVED', true, false, classification('own', true, false, false, [4])],
    ['empty', '3', 'FIXTURE_DNS_RESOLVED', true, false, classification('unexpected', false, false, false)],
    ['nxdomain', 'e', 'ENOTFOUND', false, false, classification('unexpected', false, false, false)],
    ['unsafe_error_code', '1', 'FIXTURE_DNS_FAILED', false, false, classification('unexpected', false, false, false)],
    ['error_with_answers', '2', 'ENOTFOUND', false, false, classification('unexpected', false, true, true, [4])],
    ['timeout', 'f', 'FIXTURE_DNS_TIMEOUT', false, false, classification('unexpected', false, false, false)],
  ];
  for (const [name, digit, code, resolved, matchedExpectedAddresses, expected] of cases) {
    const request = dnsRequest(`dns_${name}`, host(digit));
    const response = await fixture.call(request);
    assert.deepEqual(response, { id: request.id, type: 'dns-result', code, resolved, ...expected, matchedExpectedAddresses }, name);
    assertPrivateResponse(response, request.hostname);
  }
  // Both realm identities work; the classification must follow the request's
  // expected addresses rather than hard-code the .42 fixture as the owner.
  const reversed = dnsRequest('dns_reversed', host('b'), {
    expectedAddress4: otherAddresses[0], expectedAddress6: otherAddresses[1], otherFixtureAddresses: [...ownAddresses],
  });
  assert.deepEqual(await fixture.call(reversed), { id: reversed.id, type: 'dns-result', code: 'FIXTURE_DNS_RESOLVED', resolved: true,
    ...classification('own', true, false, false, [4, 6], true), matchedExpectedAddresses: true });
  // Boundary/default deadlines must accept immediate synthetic success.
  for (const timeoutMs of [undefined, 100, 15000]) {
    const request = dnsRequest(`dns_deadline_${timeoutMs ?? 'default'}`, host('a'), { timeoutMs });
    const response = await fixture.call(request);
    assert.equal(response.matchedExpectedAddresses, true); assertPrivateResponse(response, request.hostname);
  }
  assert.equal(fixture.messages.filter(value => value.type === 'test-lookup').length, cases.length + 4);
  assert.ok(fixture.messages.filter(value => value.type === 'test-lookup').every(value => value.allAddressesRequested === true));
  assert.ok(fixture.messages.filter(value => value.type === 'test-lookup').every(value => value.requestedFamily === 0));
  await fixture.stop(); assert.deepEqual(fixture.output(), { stdout: '', stderr: '' });
});

test('explicit IPv4 and IPv6 queries reach lookup with that family and require only its own answer', async t => {
  const fixture = fixtureProcess(t);
  await fixture.receive(value => value?.type === 'ready');
  for (const family of [4, 6]) {
    const request = dnsRequest(`dns_family_${family}`, host('a'), {
      family,
      expectedAddress4: family === 4 ? ownAddresses[0] : undefined,
      expectedAddress6: family === 6 ? ownAddresses[1] : undefined,
      otherFixtureAddresses: [otherAddresses[family === 4 ? 0 : 1]],
    });
    const response = await fixture.call(request);
    assert.deepEqual(response, { id: request.id, type: 'dns-result', code: 'FIXTURE_DNS_RESOLVED', resolved: true, family,
      ...classification('own', true, false, false, [family], family === 6), matchedExpectedAddresses: true });
    assertPrivateResponse(response, request.hostname);
  }
  const nxdomain = dnsRequest('dns_family_6_nxdomain', host('e'), {
    family: 6, expectedAddress4: undefined, otherFixtureAddresses: [otherAddresses[1]],
  });
  const response = await fixture.call(nxdomain);
  assert.deepEqual(response, { id: nxdomain.id, type: 'dns-result', code: 'ENOTFOUND', resolved: false, family: 6,
    ...classification('unexpected', false, false, false), matchedExpectedAddresses: false });
  assertPrivateResponse(response, nxdomain.hostname);
  const lookups = fixture.messages.filter(value => value.type === 'test-lookup');
  assert.deepEqual(lookups.map(value => value.requestedFamily), [4, 6, 6]);
  assert.ok(lookups.every(value => value.allAddressesRequested === true));
  await fixture.stop(); assert.deepEqual(fixture.output(), { stdout: '', stderr: '' });
});

test('real IPv6 IPC reports canonical and tail observations without fabricating fixture provenance or a match', async t => {
  const fixture = fixtureProcess(t);
  await fixture.receive(value => value?.type === 'ready');
  for (const [digit, canonical, tail] of [['5', true, false], ['6', false, true], ['7', false, true], ['8', false, false], ['9', false, false]]) {
    const request = dnsRequest(`dns_ipv6_diagnostic_${digit}`, host(digit), { family: 6, expectedAddress4: undefined,
      otherFixtureAddresses: [otherAddresses[1]], diagnosticFixtureAddresses: [ownAddresses[0]] });
    const response = await fixture.call(request);
    assert.deepEqual(response, { id: request.id, type: 'dns-result', code: 'FIXTURE_DNS_RESOLVED', resolved: true, family: 6,
      ...classification('unexpected', false, false, true, [6], canonical, tail), matchedExpectedAddresses: false });
    assertPrivateResponse(response, request.hostname);
  }
  assert.deepEqual(fixture.messages.filter(value => value.type === 'test-lookup').map(value => value.requestedFamily), [6, 6, 6, 6, 6]);
  await fixture.stop(); assert.deepEqual(fixture.output(), { stdout: '', stderr: '' });
});

test('a bounded timeout sends one result even if a synthetic DNS callback arrives later', async t => {
  const fixture = fixtureProcess(t);
  await fixture.receive(value => value?.type === 'ready');
  const request = dnsRequest('dns_late_callback', host('4'));
  assert.deepEqual(await fixture.call(request), { id: request.id, type: 'dns-result', code: 'FIXTURE_DNS_TIMEOUT', resolved: false,
    ...classification('unexpected', false, false, false), matchedExpectedAddresses: false });
  // A second query's synthetic delayed callback proves the first callback has
  // run, without relying on a long real DNS timeout or wall-clock assertions.
  const barrier = dnsRequest('dns_late_barrier', host('4'), { timeoutMs: 1000 });
  assert.equal((await fixture.call(barrier)).matchedExpectedAddresses, true);
  const replies = fixture.messages.filter(value => value.id === request.id);
  assert.equal(replies.length, 1); assertPrivateResponse(replies[0], request.hostname);
  await fixture.stop(); assert.deepEqual(fixture.output(), { stdout: '', stderr: '' });
});

test('invalid DNS requests are refused before lookup and never echo private input', async t => {
  const fixture = fixtureProcess(t);
  await fixture.receive(value => value?.type === 'ready');
  const invalid = [
    ...['example.com', host('a') + '\n', 'a'.repeat(15) + '.example.com', 'a'.repeat(64) + '.example.com', 'g'.repeat(16) + '.example.com', host('a') + '.invalid']
      .map(hostname => ({ hostname })),
    ...['127.0.0.1', '203.0.113.44', '2001:db8::42', '203.0.113.42 ', null, [], {}].map(expectedAddress4 => ({ expectedAddress4 })),
    ...['::1', '203.0.113.42', '2001:db8:0:0:0:0:0:42', '2001:DB8::42', null, [], {}].map(expectedAddress6 => ({ expectedAddress6 })),
    ...['203.0.113.43', null, {}, ['127.0.0.1'], [otherAddresses[0], ...otherAddresses, ...otherAddresses], [null], [ownAddresses[0]], [ownAddresses[1]]]
      .map(otherFixtureAddresses => ({ otherFixtureAddresses })),
    ...[99, 15001, 0, -1, 100.5, '100', null, true, {}].map(timeoutMs => ({ timeoutMs })),
    ...[0, 1, 5, 7, '4', null, true, {}, [], 4.5].map(family => ({ family })),
    { family: 4, expectedAddress6: ownAddresses[1] },
    { family: 6, expectedAddress4: ownAddresses[0] },
    ...[null, '203.0.113.42', {}, ['127.0.0.1'], [...ownAddresses, ...ownAddresses, ownAddresses[0]], [null]]
      .map(diagnosticFixtureAddresses => ({ diagnosticFixtureAddresses })),
  ];
  for (const [index, patch] of invalid.entries()) {
    const request = dnsRequest(`dns_invalid_${index}`, host('a'), patch);
    const response = await fixture.call(request);
    assert.deepEqual(response, { id: request.id, type: 'fixture-error', code: 'FIXTURE_REQUEST_INVALID' });
    assertPrivateResponse(response, request.hostname);
  }
  assert.equal(fixture.messages.some(value => value.type === 'test-lookup'), false, 'invalid request reached DNS lookup');
  await fixture.stop(); assert.deepEqual(fixture.output(), { stdout: '', stderr: '' });
});

test('import has no IPC side effects, while the direct entry point requires private IPC', async t => {
  const script = `
    const before = { message: process.listenerCount('message'), disconnect: process.listenerCount('disconnect') };
    const imported = await import(${JSON.stringify(childURL.href)});
    console.log(JSON.stringify({ classifier: typeof imported.classifyDiagnosticDnsAnswers,
      unchanged: before.message === process.listenerCount('message') && before.disconnect === process.listenerCount('disconnect') }));
  `;
  const imported = fixtureProcess(t, { ipc: false, args: ['--input-type=module', '-e', script] });
  assert.deepEqual(await imported.closed, { code: 0, signal: null });
  assert.equal(imported.output().stderr, '');
  assert.deepEqual(JSON.parse(imported.output().stdout), { classifier: 'function', unchanged: true });
  const direct = fixtureProcess(t, { ipc: false });
  const exited = await direct.closed;
  assert.equal(exited.code, 1); assert.equal(exited.signal, null);
  assert.equal(direct.output().stdout, ''); assert.match(direct.output().stderr, /private parent IPC required/);
});
