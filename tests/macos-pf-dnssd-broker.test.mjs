import test from 'node:test'
import assert from 'node:assert/strict'
import { parseDNSSDRequest, encodeDNSSDReply, DNSSD_ERROR, DNSSDProtocolError } from '../native/macos-pf-routing/dnssd-broker-protocol.mjs'
import { probeOwnedDNSSDBroker } from '../native/macos-pf-routing/dnssd-broker-acceptance.mjs'

function frame(op, body = Buffer.alloc(0), ipcFlags = 0, context = Buffer.from('0102030405060708', 'hex')) {
  const header = Buffer.alloc(28); header.writeUInt32BE(1); header.writeUInt32BE(body.length, 4)
  header.writeUInt32BE(ipcFlags, 8); header.writeUInt32BE(op, 12); context.copy(header, 16)
  return Buffer.concat([header, body])
}
function query({ shared = false, flags = shared ? 0x15000 : 0, type = 1, tlvs = Buffer.alloc(0), ipcFlags = tlvs.length ? 2 : 0 } = {}) {
  const prefix = Buffer.alloc((shared ? 1 : 0) + 8), name = Buffer.from('fixture.invalid\0'), suffix = Buffer.alloc(4)
  prefix.writeUInt32BE(flags, shared ? 1 : 0); suffix.writeUInt16BE(type); suffix.writeUInt16BE(1, 2)
  return frame(8, Buffer.concat([prefix, name, suffix, tlvs]), ipcFlags)
}
const refuses = (input, reason, options = {}) => assert.throws(() => parseDNSSDRequest(input, options), error => error instanceof DNSSDProtocolError && error.code === reason)

test('shared and independent DNS-SD requests use different error-channel shapes', () => {
  assert.equal(parseDNSSDRequest(query()).kind, 'resolve')
  const request = parseDNSSDRequest(query({ shared: true }), { shared: true, errorSocket: true })
  assert.equal(request.name, 'fixture.invalid'); assert.deepEqual(request.types, [1]); assert.equal(request.flags, 0x15000)
  refuses(query({ shared: true }), 'ERROR_CHANNEL', { shared: true })
  refuses(query(), 'ERROR_CHANNEL', { errorSocket: true })
  const sharedWrongFlags = query({ shared: true, flags: 0 })
  refuses(sharedWrongFlags, 'SHARED_FLAGS', { shared: true, errorSocket: true })
})
test('opaque callback context is returned byte-for-byte in A and AAAA wire replies', () => {
  const request = parseDNSSDRequest(query({ type: 28 }))
  const reply = encodeDNSSDReply(request, { type: 28, rdata: Buffer.from('20010db8000000000000000000000001', 'hex') })
  assert.equal(reply.readUInt32BE(12), 68); assert.deepEqual(reply.subarray(16, 24), request.context)
  assert.equal(reply.readUInt32BE(4), reply.length - 28); assert.equal(reply.readUInt32BE(28), 2)
  assert.equal(reply.readUInt16BE(28 + 12 + Buffer.byteLength('fixture.invalid.\0') + 4), 16)
})
test('malformed headers and all body truncations throw instead of reading outside buffers', () => {
  const good = query()
  for (let length = 0; length < good.length; length++) assert.throws(() => parseDNSSDRequest(good.subarray(0, length)), DNSSDProtocolError)
  const wrongVersion = Buffer.from(good); wrongVersion.writeUInt32BE(2); refuses(wrongVersion, 'HEADER')
  const badIndex = Buffer.from(good); badIndex.writeUInt32BE(1, 24); refuses(badIndex, 'HEADER')
  for (let length = 0; length < good.length - 28; length++) assert.throws(() => parseDNSSDRequest(frame(8, good.subarray(28, 28 + length))), DNSSDProtocolError)
  refuses(Buffer.concat([good, Buffer.from([0])]), 'HEADER')
  refuses(frame(8, Buffer.alloc(4097)), 'FRAME_LENGTH')
})
test('unsupported opcode, DNS semantics, NOERRSD and NOREPLY are explicit refusals', () => {
  refuses(frame(6), 'OPCODE'); refuses(query({ type: 16 }), 'RECORD_TYPE')
  refuses(query({ flags: 0x400 }), 'DNS_FLAGS'); refuses(query({ flags: 0x200000 }), 'DNS_FLAGS')
  refuses(query({ ipcFlags: 4 }), 'IPC_FLAGS'); refuses(query({ ipcFlags: 1 }), 'IPC_FLAGS')
  const scoped = query(); scoped.writeUInt32BE(1, 32); refuses(scoped, 'INTERFACE_SCOPE')
})
test('TLVs are bounded; unknown privacy/override and requested AAAA fallback are refused', () => {
  const tlv = (type, value = 1) => { const bytes = Buffer.alloc(8); bytes.writeUInt16BE(type); bytes.writeUInt16BE(4, 2); bytes.writeUInt32BE(value, 4); return bytes }
  const allowed = parseDNSSDRequest(query({ tlvs: tlv(4) }))
  assert.deepEqual(allowed.attributes, [{ type: 4, value: 1 }])
  for (const type of [1, 2, 5, 6, 7, 8, 9, 10, 11]) refuses(query({ tlvs: tlv(type) }), 'TLV_UNSUPPORTED')
  refuses(query({ tlvs: tlv(3) }), 'TLV_POLICY')
  refuses(query({ tlvs: Buffer.concat([tlv(4), tlv(4)]) }), 'TLV_LENGTH_OR_DUPLICATE')
  refuses(query({ tlvs: tlv(4).subarray(0, 7) }), 'TLV_LENGTH_OR_DUPLICATE')
  refuses(query({ ipcFlags: 2 }), 'EMPTY_TLV_LIST')
})
test('connection and cancel shapes are strict and cancel has no DNS record response', () => {
  assert.equal(parseDNSSDRequest(frame(1)).kind, 'connection')
  assert.equal(parseDNSSDRequest(frame(63), { shared: true }).kind, 'cancel')
  refuses(frame(63), 'CANCEL_SHAPE'); refuses(frame(1, Buffer.from([0])), 'CONNECTION_SHAPE')
  refuses(frame(63, Buffer.from([0])), 'CANCEL_SHAPE', { shared: true })
})
test('negative records carry the DNS-SD error and no fabricated address bytes', () => {
  const request = parseDNSSDRequest(query())
  const answer = encodeDNSSDReply(request, { type: 1, rdata: Buffer.alloc(0), errorCode: DNSSD_ERROR.noSuchRecord, ttl: 0 })
  assert.equal(answer.readInt32BE(36), DNSSD_ERROR.noSuchRecord)
  assert.equal(answer.readUInt32BE(28), 0)
  assert.throws(() => encodeDNSSDReply(request, { type: 1, rdata: Buffer.alloc(16) }), DNSSDProtocolError)
})
test('native protocol, concurrent realm isolation and honest unsupported stock-library/getaddrinfo boundary',
  { skip: process.platform !== 'darwin' || process.getuid?.() === 0, timeout: 45000 }, async () => {
    const report = await probeOwnedDNSSDBroker()
    assert.equal(report.ready, false); assert.equal(report.productionReady, false); assert.equal(report.networkFrameworkCovered, false)
    assert.equal(report.systemDNSRouteSupported, false); assert.equal(report.stockGetaddrinfoPositivePassed, false)
    assert.deepEqual(report.checks.filter(item => !item.passed), [])
    assert.equal(report.passed, true); assert.equal(report.cleanup.ownedFixturesRemaining, 0)
  })
