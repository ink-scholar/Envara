// Bounded standard QUERY codec; no resolver, network I/O, or diagnostic payloads.
// RFC 1035 §§4.1/4.1.4, RFC 6891 §6, RFC 3597 §4, RFC 9267 §§2–3.
export const MAX_DNS_QUERY = 4096
export const MAX_DNS_RESPONSE = 65535
export const DNS_ERROR_CODES = Object.freeze([
  'DNS_SIZE_INVALID', 'DNS_DESCRIPTOR_INVALID', 'DNS_HEADER_INVALID',
  'DNS_QUERY_UNSUPPORTED', 'DNS_QUESTION_MISMATCH', 'DNS_TRANSACTION_MISMATCH',
  'DNS_MESSAGE_TRUNCATED', 'DNS_TRAILING_BYTES', 'DNS_NAME_INVALID',
  'DNS_COMPRESSION_INVALID', 'DNS_COMPRESSION_DEPTH', 'DNS_RR_INVALID',
  'DNS_RR_UNSUPPORTED', 'DNS_EDNS_INVALID', 'DNS_EDNS_UNSUPPORTED',
])
const errorCodes = new Set(DNS_ERROR_CODES)
const descriptors = new WeakMap()
const MAX_POINTER_DEPTH = 32
const TYPE_OPT = 41
const unsupportedQueryTypes = new Set([0, 24, TYPE_OPT, 249, 250, 251, 252, 253, 254, 255])

function invalid(code) { return Object.assign(new Error('DNS wire message rejected'), { code }) }
export function dnsFailureCode(error) { return errorCodes.has(error?.code) ? error.code : null }
function requireBytes(bytes, offset, count, end = bytes.length) {
  if (offset < 0 || count < 0 || offset > end || count > end - offset) throw invalid('DNS_MESSAGE_TRUNCATED')
}
function message(bytes, maximum) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 12 || bytes.length > maximum) throw invalid('DNS_SIZE_INVALID')
  return bytes
}
function header(bytes, response) {
  const flags = bytes.readUInt16BE(2)
  // AD/CD have assigned meanings. Only the remaining Z bit is reserved.
  if (!!(flags & 0x8000) !== response || (flags & 0x7800) || (flags & 0x0040)) throw invalid('DNS_HEADER_INVALID')
  if (!response && (flags & ~0x0130)) throw invalid('DNS_HEADER_INVALID')
  const counts = [4, 6, 8, 10].map(offset => bytes.readUInt16BE(offset))
  if (counts[0] !== 1) throw invalid('DNS_HEADER_INVALID')
  return { id: bytes.readUInt16BE(0), flags, counts }
}

function parser(bytes) {
  // Entries are published only after a complete name is decoded. A pointer
  // cannot target an unfinished name, header byte, or arbitrary opaque RDATA.
  const names = new Map()
  function name(offset, end = bytes.length, compression = true) {
    let cursor = offset; let size = 0; let depth = 0; let tail
    const labels = []; const boundaries = []
    while (true) {
      requireBytes(bytes, cursor, 1, end)
      const length = bytes[cursor]
      if ((length & 0xc0) === 0xc0) {
        if (!compression) throw invalid('DNS_COMPRESSION_INVALID')
        requireBytes(bytes, cursor, 2, end)
        const target = ((length & 0x3f) << 8) | bytes[cursor + 1]
        const previous = names.get(target)
        if (target < 12 || target >= cursor || !previous) throw invalid('DNS_COMPRESSION_INVALID')
        depth = previous.depth + 1
        if (depth > MAX_POINTER_DEPTH) throw invalid('DNS_COMPRESSION_DEPTH')
        tail = previous.wire
        boundaries.push({ offset: cursor, start: size })
        cursor += 2
        break
      }
      if (length & 0xc0) throw invalid('DNS_NAME_INVALID')
      boundaries.push({ offset: cursor, start: size })
      cursor++
      if (!length) { tail = Buffer.from([0]); break }
      requireBytes(bytes, cursor, length, end)
      const label = Buffer.alloc(length + 1); label[0] = length
      for (let i = 0; i < length; i++) {
        const byte = bytes[cursor + i]
        label[i + 1] = byte >= 65 && byte <= 90 ? byte + 32 : byte
      }
      labels.push(label); size += label.length; cursor += length
      if (size >= 255) throw invalid('DNS_NAME_INVALID')
    }
    if (size + tail.length > 255) throw invalid('DNS_NAME_INVALID')
    const wire = Buffer.concat([...labels, tail], size + tail.length)
    for (const boundary of boundaries) names.set(boundary.offset, { wire: wire.subarray(boundary.start), depth })
    return { wire, end: cursor }
  }
  function characterString(offset, end) {
    requireBytes(bytes, offset, 1, end)
    const length = bytes[offset]
    requireBytes(bytes, offset + 1, length, end)
    return offset + 1 + length
  }
  function typeBitmap(offset, end, allowEmpty = false) {
    let lastWindow = -1
    if (offset === end && !allowEmpty) throw invalid('DNS_RR_INVALID')
    while (offset < end) {
      requireBytes(bytes, offset, 2, end)
      const window = bytes[offset++]; const length = bytes[offset++]
      if (window <= lastWindow || length < 1 || length > 32) throw invalid('DNS_RR_INVALID')
      requireBytes(bytes, offset, length, end)
      if (bytes[offset + length - 1] === 0) throw invalid('DNS_RR_INVALID')
      offset += length; lastWindow = window
    }
    return offset
  }
  function options(offset, end) {
    while (offset < end) {
      requireBytes(bytes, offset, 4, end)
      const length = bytes.readUInt16BE(offset + 2)
      offset += 4; requireBytes(bytes, offset, length, end); offset += length
    }
    return offset
  }
  function rdata(type, start, end) {
    let offset = start
    const length = end - start
    const exact = expected => { if (length !== expected) throw invalid('DNS_RR_INVALID') }
    const minimum = expected => { if (length < expected) throw invalid('DNS_RR_INVALID') }
    switch (type) {
      case 1: exact(4); return // A
      case 28: exact(16); return // AAAA
      case 108: exact(6); return // EUI48
      case 109: exact(8); return // EUI64
      case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12:
        offset = name(offset, end).end; break
      case 39: // DNAME does not permit compression in RDATA.
        offset = name(offset, end, false).end; break
      case 6: // SOA: two names and five uint32 values.
        offset = name(offset, end).end; offset = name(offset, end).end
        requireBytes(bytes, offset, 20, end); offset += 20; break
      case 14: case 17: // MINFO / RP
        offset = name(offset, end).end; offset = name(offset, end).end; break
      case 15: case 18: case 21: case 36: // MX / AFSDB / RT / KX
        requireBytes(bytes, offset, 2, end); offset += 2
        offset = name(offset, end, type !== 36).end; break
      case 13: // HINFO
        offset = characterString(offset, end); offset = characterString(offset, end); break
      case 16: case 99: // TXT / SPF
        minimum(1)
        while (offset < end) offset = characterString(offset, end)
        break
      case 33: // SRV
        requireBytes(bytes, offset, 6, end); offset += 6
        offset = name(offset, end, false).end; break
      case 35: // NAPTR
        requireBytes(bytes, offset, 4, end); offset += 4
        for (let i = 0; i < 3; i++) offset = characterString(offset, end)
        offset = name(offset, end, false).end; break
      case 46: // RRSIG: fixed fields, uncompressed signer, opaque signature.
        requireBytes(bytes, offset, 18, end); offset += 18
        offset = name(offset, end, false).end
        if (offset === end) throw invalid('DNS_RR_INVALID')
        return
      case 47: // NSEC
        offset = name(offset, end, false).end
        offset = typeBitmap(offset, end); break
      case 50: { // NSEC3: fixed fields, salt, next hash, bitmap.
        requireBytes(bytes, offset, 5, end)
        const saltLength = bytes[offset + 4]; offset += 5
        requireBytes(bytes, offset, saltLength + 1, end); offset += saltLength
        const hashLength = bytes[offset++]
        if (!hashLength) throw invalid('DNS_RR_INVALID')
        requireBytes(bytes, offset, hashLength, end); offset += hashLength
        // Empty non-terminals and Opt-Out proofs may have no type bitmap.
        offset = typeBitmap(offset, end, true); break
      }
      case 51: { // NSEC3PARAM
        requireBytes(bytes, offset, 5, end)
        const saltLength = bytes[offset + 4]; offset += 5
        requireBytes(bytes, offset, saltLength, end); offset += saltLength; break
      }
      case 64: case 65: { // SVCB / HTTPS: target and ordered service parameters.
        requireBytes(bytes, offset, 2, end); offset += 2
        offset = name(offset, end, false).end
        let lastKey = -1
        while (offset < end) {
          requireBytes(bytes, offset, 4, end)
          const key = bytes.readUInt16BE(offset); const valueLength = bytes.readUInt16BE(offset + 2)
          if (key <= lastKey) throw invalid('DNS_RR_INVALID')
          offset += 4; requireBytes(bytes, offset, valueLength, end); offset += valueLength; lastKey = key
        }
        break
      }
      case 257: // CAA: flags, nonempty tag, opaque value.
        minimum(3)
        if (!bytes[start + 1] || bytes[start + 1] > length - 2) throw invalid('DNS_RR_INVALID')
        return
      case 11: minimum(5); return // WKS
      case 37: minimum(6); return // CERT
      case 43: case 59: minimum(5); return // DS / CDS
      case 44: minimum(3); return // SSHFP
      case 48: case 60: minimum(4); return // DNSKEY / CDNSKEY
      case 52: case 53: minimum(4); return // TLSA / SMIMEA
      case 256: minimum(5); return // URI
      // Unknown RDATA is opaque, as required by RFC 3597. It never creates
      // compression targets and is not scanned for apparent pointer bytes.
      default: return
    }
    if (offset !== end) throw invalid('DNS_RR_INVALID')
  }
  function record(offset, section, { query = false, ednsAllowed = false, seenOpt = false } = {}) {
    const start = offset; const owner = name(offset, bytes.length, !query); offset = owner.end
    requireBytes(bytes, offset, 10)
    const type = bytes.readUInt16BE(offset); const rrclass = bytes.readUInt16BE(offset + 2)
    const ttl = bytes.readUInt32BE(offset + 4); const length = bytes.readUInt16BE(offset + 8)
    const dataStart = offset + 10; const end = dataStart + length
    requireBytes(bytes, dataStart, length)
    if (type === TYPE_OPT) {
      if (section !== 'additional' || seenOpt || !ednsAllowed || bytes[start] !== 0 || owner.end !== start + 1) throw invalid('DNS_EDNS_INVALID')
      if ((ttl >>> 16 & 0xff) !== 0) throw invalid('DNS_EDNS_UNSUPPORTED')
      if (query && (ttl >>> 24)) throw invalid('DNS_EDNS_INVALID')
      // Unassigned EDNS flags and option codes are opaque to this receiver.
      options(dataStart, end)
      return { end, opt: true, ttl, udpPayloadSize: Math.max(512, Math.min(4096, rrclass)) }
    }
    // No query additional data except EDNS0; no legacy SIG, signed transaction,
    // or key exchange records on this unsigned standard-QUERY transport.
    if (query || type === 24 || type === 249 || type === 250 || type === 0 || type >= 251 && type <= 255) throw invalid('DNS_RR_UNSUPPORTED')
    if (rrclass !== 1) throw invalid('DNS_RR_UNSUPPORTED')
    rdata(type, dataStart, end)
    return { end, opt: false }
  }
  return { name, record }
}

function question(bytes, reader, compression) {
  const parsed = reader.name(12, bytes.length, compression)
  requireBytes(bytes, parsed.end, 4)
  return { name: parsed.wire, type: bytes.readUInt16BE(parsed.end),
    rrclass: bytes.readUInt16BE(parsed.end + 2), end: parsed.end + 4 }
}
function descriptorState(descriptor) {
  const state = descriptor && typeof descriptor === 'object' ? descriptors.get(descriptor) : undefined
  if (!state) throw invalid('DNS_DESCRIPTOR_INVALID')
  return state
}

/** Accept one uncompressed unsigned IN question and at most one EDNS0 OPT. */
export function validateDnsQuery(input) {
  const bytes = Buffer.from(message(input, MAX_DNS_QUERY))
  const info = header(bytes, false)
  if (info.counts[1] || info.counts[2] || info.counts[3] > 1) throw invalid('DNS_QUERY_UNSUPPORTED')
  const reader = parser(bytes); const asked = question(bytes, reader, false)
  if (asked.rrclass !== 1 || unsupportedQueryTypes.has(asked.type)) throw invalid('DNS_QUERY_UNSUPPORTED')
  let offset = asked.end; let udpPayloadSize = 512
  const edns = info.counts[3] === 1
  if (edns) {
    const opt = reader.record(offset, 'additional', { query: true, ednsAllowed: true })
    offset = opt.end; udpPayloadSize = opt.udpPayloadSize
  }
  if (offset !== bytes.length) throw invalid('DNS_TRAILING_BYTES')
  const descriptor = Object.freeze({ id: info.id, questionEnd: asked.end, udpPayloadSize })
  descriptors.set(descriptor, { ...info, asked, edns, question: Buffer.from(bytes.subarray(12, asked.end)) })
  return descriptor
}

function responseMessage(input, state) {
  const bytes = message(input, MAX_DNS_RESPONSE)
  const info = header(bytes, true)
  if (info.id !== state.id) throw invalid('DNS_TRANSACTION_MISMATCH')
  const reader = parser(bytes); const asked = question(bytes, reader, true)
  if (asked.type !== state.asked.type || asked.rrclass !== state.asked.rrclass || !asked.name.equals(state.asked.name)) throw invalid('DNS_QUESTION_MISMATCH')
  let offset = asked.end; let opt = null
  // Each RR needs at least a root owner and ten fixed bytes. Counts therefore
  // cannot turn a bounded packet into an unbounded parsing loop.
  if (info.counts[1] + info.counts[2] + info.counts[3] > Math.floor((bytes.length - offset) / 11)) throw invalid('DNS_RR_INVALID')
  for (let section = 1; section <= 3; section++) {
    const sectionName = section === 3 ? 'additional' : section === 2 ? 'authority' : 'answer'
    for (let i = 0; i < info.counts[section]; i++) {
      const rr = reader.record(offset, sectionName, { ednsAllowed: state.edns, seenOpt: !!opt })
      offset = rr.end; if (rr.opt) opt = rr
    }
  }
  if (offset !== bytes.length) throw invalid('DNS_TRAILING_BYTES')
  // RFC 6891 §7 permits a non-EDNS server's FORMERR without OPT. Limit that
  // exception to a complete, untruncated question-only error. A successful or
  // TC response to an EDNS query must include its unique OPT record.
  const legacyFormerr = (info.flags & 0x000f) === 1 && !(info.flags & 0x0200) &&
    info.counts[1] === 0 && info.counts[2] === 0 && info.counts[3] === 0
  if (state.edns && !opt && !legacyFormerr) throw invalid('DNS_EDNS_INVALID')
  return { bytes, opt }
}

/** Validate response identity and complete RR framing; this does not verify DNSSEC. */
export function validateDnsResponse(input, descriptor) {
  return responseMessage(input, descriptorState(descriptor)).bytes
}

/** Oversized UDP answers become a complete minimal TC response, never a sliced RR. */
export function truncateDnsUdpResponse(input, descriptor) {
  const state = descriptorState(descriptor); const { bytes, opt } = responseMessage(input, state)
  if (bytes.length <= descriptor.udpPayloadSize) return bytes
  const result = Buffer.alloc(12 + state.question.length + (opt ? 11 : 0))
  bytes.copy(result, 0, 0, 12)
  result.writeUInt16BE(bytes.readUInt16BE(2) | 0x8200, 2)
  result.writeUInt16BE(1, 4)
  result.fill(0, 6, 12)
  state.question.copy(result, 12)
  if (opt) {
    const offset = 12 + state.question.length
    // Keep extended RCODE, supported version, and DO; emit no option payload
    // and clear unassigned flags as required for a newly emitted OPT record.
    result.writeUInt16BE(1, 10)
    result.writeUInt16BE(TYPE_OPT, offset + 1)
    result.writeUInt16BE(opt.udpPayloadSize, offset + 3)
    result.writeUInt32BE((opt.ttl & 0xffff8000) >>> 0, offset + 5)
  }
  return result
}
