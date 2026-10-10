// Independent, bounded prototype of the DNS-SD IPC ABI, pinned to Apple's
// mDNSResponder-2881.0.25 (tag peeled commit d4658af3f5f291311c6aee4210aa6d39bda82bbe).
export const DNSSD_PROTOCOL_SOURCE = Object.freeze({
  tag: 'mDNSResponder-2881.0.25', commit: 'd4658af3f5f291311c6aee4210aa6d39bda82bbe',
  ipc: 'https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSShared/dnssd_ipc.h',
  client: 'https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSShared/dnssd_clientstub.c',
  daemon: 'https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSShared/uds_daemon.c',
  libinfoCommit: '39b70c515baee5b609e7e91693edbd934b6845a1',
  libinfo: 'https://github.com/apple-oss-distributions/Libinfo/blob/39b70c515baee5b609e7e91693edbd934b6845a1/lookup.subproj/mdns_module.c',
})
export const DNSSD_ERROR = Object.freeze({ badParam: -65540, unsupported: -65544, noSuchRecord: -65554, timeout: -65568 })
export class DNSSDProtocolError extends Error {
  constructor(reason, errorCode = DNSSD_ERROR.badParam) { super(reason); this.code = reason; this.errorCode = errorCode }
}
const refuse = (reason, error = DNSSD_ERROR.badParam) => { throw new DNSSDProtocolError(reason, error) }
const unsupported = reason => refuse(reason, DNSSD_ERROR.unsupported)

export function parseDNSSDRequest(frame, { shared = false, errorSocket = false } = {}) {
  if (!Buffer.isBuffer(frame) || frame.length < 28 || frame.length > 4124) refuse('FRAME_LENGTH')
  const version = frame.readUInt32BE(0), length = frame.readUInt32BE(4), ipcFlags = frame.readUInt32BE(8), op = frame.readUInt32BE(12)
  if (version !== 1 || length !== frame.length - 28 || frame.readUInt32BE(24) !== 0) refuse('HEADER')
  if (ipcFlags & ~2) unsupported('IPC_FLAGS') // NOERRSD and NOREPLY are not supported query modes.
  const context = Buffer.from(frame.subarray(16, 24)), body = frame.subarray(28)
  if (op === 1) {
    if (length || ipcFlags || shared || errorSocket) refuse('CONNECTION_SHAPE')
    return { op, context, kind: 'connection' }
  }
  if (op === 63) {
    if (length || ipcFlags || !shared || errorSocket) refuse('CANCEL_SHAPE')
    return { op, context, kind: 'cancel' }
  }
  if (shared !== errorSocket) refuse('ERROR_CHANNEL')
  if (![8, 15].includes(op)) unsupported('OPCODE')
  let offset = shared ? 1 : 0
  if (shared && body[0] !== 0) refuse('SHARED_CONTROL_PATH')
  const u32 = () => { if (offset + 4 > body.length) refuse('BODY_TRUNCATED'); const n = body.readUInt32BE(offset); offset += 4; return n }
  const u16 = () => { if (offset + 2 > body.length) refuse('BODY_TRUNCATED'); const n = body.readUInt16BE(offset); offset += 2; return n }
  const flags = u32(), interfaceIndex = u32()
  // Shared connection, return intermediates, and timeout are supported. This is
  // a single snapshot resolver, never multicast, local-only, DNSSEC, or stale data.
  if (flags & ~0x15000) unsupported('DNS_FLAGS')
  if (Boolean(flags & 0x4000) !== shared) refuse('SHARED_FLAGS')
  if (interfaceIndex !== 0) unsupported('INTERFACE_SCOPE')
  const protocols = op === 15 ? u32() : null
  if (protocols !== null && (protocols & ~3)) unsupported('ADDRESS_PROTOCOLS')
  const end = body.indexOf(0, offset)
  if (end < 0 || end - offset > 254 || end === offset) refuse('HOSTNAME_LENGTH')
  const bytes = body.subarray(offset, end)
  if (bytes.some(b => b < 33 || b > 126)) refuse('HOSTNAME_ENCODING')
  const wireName = bytes.toString('ascii'), name = wireName.toLowerCase().replace(/\.$/, '')
  if (name.length > 253 || !name.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) refuse('HOSTNAME')
  if (name.endsWith('.local') || name === 'localhost') unsupported('LOCAL_OR_MULTICAST_NAME')
  offset = end + 1
  const type = op === 8 ? u16() : null, rrclass = op === 8 ? u16() : 1
  if (type !== null && ![1, 28].includes(type)) unsupported('RECORD_TYPE')
  if (rrclass !== 1) unsupported('RECORD_CLASS')
  const attributes = []
  if (ipcFlags & 2) {
    if (offset === body.length) refuse('EMPTY_TLV_LIST')
    const seen = new Set()
    while (offset < body.length) {
      const tlvType = u16(), tlvLength = u16()
      if (seen.has(tlvType) || offset + tlvLength > body.length) refuse('TLV_LENGTH_OR_DUPLICATE')
      seen.add(tlvType)
      // Apple's ordinary getaddrinfo can grant failover permission. Permission
      // does not require fallback; this broker has exactly one injected resolver.
      // AAAA policy None is supported; fallback/privacy/override/validation are refused.
      if (![3, 4].includes(tlvType)) unsupported('TLV_UNSUPPORTED')
      if (tlvLength !== 4) refuse('TLV_VALUE_LENGTH')
      const value = body.readUInt32BE(offset); offset += tlvLength
      if ((tlvType === 3 && value !== 0) || (tlvType === 4 && value > 1)) unsupported('TLV_POLICY')
      attributes.push({ type: tlvType, value })
    }
  } else if (offset !== body.length) refuse('BODY_TRAILING_BYTES')
  return { kind: 'resolve', op, context, name, wireName, flags, interfaceIndex, attributes,
    types: type === null ? ((protocols || 3) === 1 ? [1] : (protocols || 3) === 2 ? [28] : [1, 28]) : [type] }
}

export function encodeDNSSDReply(request, { type, rdata, errorCode = 0, moreComing = false, ttl = 60 }) {
  if (!request || ![8, 15].includes(request.op) || !Buffer.isBuffer(request.context) || request.context.length !== 8 ||
      ![1, 28].includes(type) || !Buffer.isBuffer(rdata) || (errorCode === 0 && rdata.length !== (type === 1 ? 4 : 16)) ||
      !Number.isInteger(errorCode) || !Number.isInteger(ttl) || ttl < 0 || ttl > 300) refuse('REPLY_ARGUMENTS')
  const name = Buffer.from(`${request.wireName}.`.replace(/\.\.$/, '.') + '\0', 'ascii')
  const body = Buffer.alloc(12 + name.length + 6 + rdata.length + 4)
  body.writeUInt32BE((errorCode ? 0 : 2) | (moreComing ? 1 : 0), 0)
  body.writeInt32BE(errorCode, 8); name.copy(body, 12)
  let offset = 12 + name.length
  body.writeUInt16BE(type, offset); body.writeUInt16BE(1, offset + 2); body.writeUInt16BE(rdata.length, offset + 4)
  offset += 6; rdata.copy(body, offset); body.writeUInt32BE(ttl, offset + rdata.length)
  const header = Buffer.alloc(28); header.writeUInt32BE(1); header.writeUInt32BE(body.length, 4)
  header.writeUInt32BE(request.op === 8 ? 68 : 72, 12); request.context.copy(header, 16)
  return Buffer.concat([header, body])
}
