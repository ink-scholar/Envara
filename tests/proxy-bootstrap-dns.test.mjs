import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { bootstrapDNSQuestion, parseBootstrapDNSAnswer, resolveProxyBootstrapHost, PROXY_BOOTSTRAP_DOH_ENDPOINTS } from '../electron/proxy-bootstrap-dns.mjs';

const rejected = error => error.code === 'PROXY_CORE_BOOTSTRAP_UNAVAILABLE';
const invalid = error => error.code === 'PROXY_BOOTSTRAP_RESPONSE_INVALID';
function response(query, { rcode = 0, addresses = ['93.184.215.14'], questionType = 1, questionClass = 1, flags = 0x8180, owner = Buffer.from([0xc0, 0x0c]), type = 1, klass = 1 } = {}) {
  const question = Buffer.from(query), header = Buffer.alloc(12); question.subarray(0, 2).copy(header);
  header.writeUInt16BE(flags | rcode, 2); header.writeUInt16BE(1, 4); header.writeUInt16BE(addresses.length, 6);
  question.writeUInt16BE(questionType, question.length - 4); question.writeUInt16BE(questionClass, question.length - 2);
  const records = addresses.map(address => { const data = Buffer.from(address.split('.').map(Number)), fields = Buffer.alloc(10);
    fields.writeUInt16BE(type, 0); fields.writeUInt16BE(klass, 2); fields.writeUInt32BE(60, 4); fields.writeUInt16BE(data.length, 8);
    return Buffer.concat([owner, fields, data]); });
  return Buffer.concat([header, question.subarray(12), ...records]);
}
const wire = input => bootstrapDNSQuestion(input ?? 'private-node.example.test');
function withOPT(query, { extendedRcode = 1, version = 0, count = 1, owner = Buffer.from([0]), data = Buffer.alloc(0), section = 'additional' } = {}) {
  const answer = response(query); answer.writeUInt16BE(count, section === 'additional' ? 10 : 8);
  const fields = Buffer.alloc(10); fields.writeUInt16BE(41, 0); fields.writeUInt16BE(1232, 2);
  fields.writeUInt32BE(((extendedRcode << 24) | (version << 16)) >>> 0, 4); fields.writeUInt16BE(data.length, 8);
  return Buffer.concat([answer, ...Array.from({ length: count }, () => Buffer.concat([owner, fields, data]))]);
}

test('a fast NXDOMAIN cannot beat the slower valid public answer and only fixed IP DoH endpoints are queried', async () => {
  const calls = [], host = 'private-node.example.test';
  const result = await resolveProxyBootstrapHost(host, { localAddress: '192.0.2.10', timeoutMs: 100, transport: async options => {
    calls.push(options);
    if (options.url === PROXY_BOOTSTRAP_DOH_ENDPOINTS[0]) return response(options.question, { rcode: 3, addresses: [] });
    await delay(15); return response(options.question);
  } });
  assert.equal(result, '93.184.215.14'); assert.deepEqual(calls.map(call => call.url), PROXY_BOOTSTRAP_DOH_ENDPOINTS);
  assert.equal(calls.every(call => call.localAddress === '192.0.2.10' && call.maxBodyBytes === 16384), true);
  assert.equal(calls.every(call => call.signal.aborted), true); assert.notEqual(calls[0].question, calls[1].question);
});

test('both negative answers, transport failures and hung providers fail without system or direct DNS fallback', async () => {
  let calls = 0;
  await assert.rejects(resolveProxyBootstrapHost('private-node.example.test', { transport: async options => { calls++; return response(options.question, { rcode: 3, addresses: [] }); } }), rejected);
  assert.equal(calls, 2);
  await assert.rejects(resolveProxyBootstrapHost('private-node.example.test', { transport: async () => { throw new Error('secret host/user/password URL must be discarded'); } }), rejected);
  const at = Date.now(); let signal;
  await assert.rejects(resolveProxyBootstrapHost('private-node.example.test', { timeoutMs: 20, transport: options => { signal = options.signal; return new Promise(() => {}); } }), rejected);
  assert.equal(signal.aborted, true); assert.ok(Date.now() - at < 1000);
});

test('a failed provider cannot hide a valid peer, and losing transport is cancelled after first positive', async () => {
  let loser;
  const result = await resolveProxyBootstrapHost('private-node.example.test', { timeoutMs: 100, transport: options => {
    if (options.url === PROXY_BOOTSTRAP_DOH_ENDPOINTS[0]) { loser = options.signal; return new Promise(() => {}); }
    return response(options.question);
  } });
  assert.equal(result, '93.184.215.14'); assert.equal(loser.aborted, true);
  const recovered = await resolveProxyBootstrapHost('private-node.example.test', { transport: options => options.url === PROXY_BOOTSTRAP_DOH_ENDPOINTS[0]
    ? Promise.reject(new Error('TLS rejected')) : response(options.question) });
  assert.equal(recovered, '93.184.215.14');
});

test('EDNS extended BADVERS overrides a header-success public A, and malformed OPT structures are rejected', () => {
  const question = wire();
  assert.deepEqual(parseBootstrapDNSAnswer(withOPT(question.bytes), question), { rcode: 16, addresses: [] });
  assert.deepEqual(parseBootstrapDNSAnswer(withOPT(question.bytes, { extendedRcode: 0 }), question), { rcode: 0, addresses: ['93.184.215.14'] });
  for (const options of [{ count: 2 }, { section: 'authority' }, { version: 1 }, { owner: Buffer.from([0xc0, 0x0c]) },
    { data: Buffer.from([0, 1]) }, { data: Buffer.from([0, 1, 0, 2, 0]) }]) {
    assert.throws(() => parseBootstrapDNSAnswer(withOPT(question.bytes, options), question), invalid);
  }
});

test('a fast extended BADVERS with a matched public A cannot preempt a slower genuine positive peer', async () => {
  let pendingPositive = false;
  const result = await resolveProxyBootstrapHost('private-node.example.test', { timeoutMs: 100, transport: async options => {
    if (options.url === PROXY_BOOTSTRAP_DOH_ENDPOINTS[0]) return withOPT(options.question);
    await delay(15); pendingPositive = true; return response(options.question);
  } });
  assert.equal(pendingPositive, true); assert.equal(result, '93.184.215.14');
});

test('wrong ID/question/type/class, truncation, unsafe address and oversized packets never become a core endpoint', async () => {
  const question = wire();
  const cases = [
    value => { value[0] ^= 1; return value; },
    value => { value[13] = 0x78; return value; },
    () => response(question.bytes, { questionType: 28 }),
    () => response(question.bytes, { questionClass: 3 }),
    () => response(question.bytes, { flags: 0x8380 }),
    value => value.subarray(0, value.length - 1),
    value => Buffer.concat([value, Buffer.from([0])]),
    () => Buffer.alloc(16385),
    () => response(question.bytes, { owner: Buffer.from([0xff, 0xff]) }),
    value => { value.writeUInt16BE(129, 6); return value; },
  ];
  for (const alter of cases) assert.throws(() => parseBootstrapDNSAnswer(alter(response(question.bytes)), question), invalid);
  for (const address of ['127.0.0.1', '10.0.0.1', '192.168.1.1', '198.18.0.1', '203.0.113.42', '0.0.0.0', '224.0.0.1']) {
    assert.deepEqual(parseBootstrapDNSAnswer(response(question.bytes, { addresses: [address] }), question).addresses, []);
    await assert.rejects(resolveProxyBootstrapHost(question.name, { transport: options => response(options.question, { addresses: [address] }) }), rejected);
  }
  for (const alter of cases.slice(0, 4)) await assert.rejects(resolveProxyBootstrapHost(question.name, { transport: options => {
    const current = { name: question.name, bytes: options.question }; return alter(response(current.bytes));
  } }), rejected);
});

test('answer owner and A type bind the selected result, while a valid CNAME chain is supported', () => {
  const question = wire();
  assert.deepEqual(parseBootstrapDNSAnswer(response(question.bytes, { type: 28 }), question).addresses, []);
  assert.deepEqual(parseBootstrapDNSAnswer(response(question.bytes, { klass: 3 }), question).addresses, []);
  const other = Buffer.from([5, ...Buffer.from('other'), 4, ...Buffer.from('test'), 0]);
  assert.deepEqual(parseBootstrapDNSAnswer(response(question.bytes, { owner: other }), question).addresses, []);
  const header = Buffer.from(question.bytes.subarray(0, 12)); header.writeUInt16BE(0x8180, 2); header.writeUInt16BE(2, 6);
  const fields = Buffer.alloc(10); fields.writeUInt16BE(5, 0); fields.writeUInt16BE(1, 2); fields.writeUInt16BE(other.length, 8);
  const a = response(question.bytes, { owner: other }).subarray(question.bytes.length);
  const chained = Buffer.concat([header, question.bytes.subarray(12), Buffer.from([0xc0, 0x0c]), fields, other, a]);
  assert.deepEqual(parseBootstrapDNSAnswer(chained, question).addresses, ['93.184.215.14']);
});

test('abort and invalid private input are refused with generic errors, never credentials or node hostname', async () => {
  const controller = new AbortController(); let received;
  const resolving = resolveProxyBootstrapHost('private-node.example.test', { signal: controller.signal, transport: options => { received = options.signal; return new Promise(() => {}); } });
  await delay(1); controller.abort(); await assert.rejects(resolving, rejected); assert.equal(received.aborted, true);
  for (const host of ['127.0.0.1', 'host/path', 'bad\n.test', '', '.bad', '-bad.test', 'a'.repeat(64) + '.test']) assert.throws(() => bootstrapDNSQuestion(host), rejected);
  for (const options of [{ timeoutMs: true }, { timeoutMs: 0 }, { timeoutMs: 10001 }, { localAddress: '::1' }, { transport: 1 }]) await assert.rejects(resolveProxyBootstrapHost('private-node.example.test', options), rejected);
  try { await resolveProxyBootstrapHost('private-node.example.test', { transport: async () => { throw new Error('password private-node.example.test https://user:secret@host'); } }); }
  catch (error) { assert.equal(error.message.includes('private-node'), false); assert.equal(error.message.includes('secret'), false); }
});
