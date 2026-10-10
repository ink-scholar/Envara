// Pure owned-fixture bytes. No resolver, network, user domain or settings access.
import { validateDnsQuery, validateDnsResponse } from './dns-wire.mjs'

export function makeDiagnosticDnsResponse(query, { address4 = '203.0.113.42', address6 = '2001:db8::42' } = {}) {
  const expected = validateDnsQuery(query)
  if (!/^203\.0\.113\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4])$/.test(address4) || !['2001:db8::42', '2001:db8::43'].includes(address6)) throw new Error('documentation addresses required')
  const type = query.readUInt16BE(expected.questionEnd - 4)
  if (![1, 28].includes(type)) throw new Error('fixture supports address questions only')
  const data = type === 1 ? Buffer.from(address4.split('.').map(Number)) : Buffer.alloc(16)
  if (type === 28) { data.writeUInt32BE(0x20010db8, 0); data[15] = address6.endsWith('43') ? 0x43 : 0x42 }
  const answer = Buffer.alloc(12 + data.length)
  answer.writeUInt16BE(0xc00c, 0); answer.writeUInt16BE(type, 2); answer.writeUInt16BE(1, 4)
  answer.writeUInt32BE(0, 6); answer.writeUInt16BE(data.length, 10); data.copy(answer, 12)
  const header = Buffer.alloc(12)
  header.writeUInt16BE(expected.id, 0); header.writeUInt16BE(0x8080 | (query.readUInt16BE(2) & 0x0110), 2)
  header.writeUInt16BE(1, 4); header.writeUInt16BE(1, 6)
  let opt = Buffer.alloc(0)
  if (query.readUInt16BE(10) === 1) {
    opt = Buffer.alloc(11); opt.writeUInt16BE(41, 1); opt.writeUInt16BE(expected.udpPayloadSize, 3)
    opt.writeUInt32BE(query.readUInt32BE(expected.questionEnd + 5) & 0x8000, 5); header.writeUInt16BE(1, 10)
  }
  const response = Buffer.concat([header, query.subarray(12, expected.questionEnd), answer, opt])
  validateDnsResponse(response, expected)
  return response
}
