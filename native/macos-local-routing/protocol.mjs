// Original wire schema: mitmproxy_rs v0.12.11, see dependency-lock.json.
// This bounded codec handles only the messages used by the original Redirector.
import { TextDecoder } from 'node:util'

export const MAX_HANDSHAKE = 16 * 1024
const utf8 = new TextDecoder('utf-8', { fatal: true })
const protocolCodes = new Set(['PROTOBUF_SIZE_INVALID', 'PROTOBUF_INTEGER_TRUNCATED', 'PROTOBUF_INTEGER_INVALID', 'PROTOBUF_INTEGER_OVERFLOW',
  'PROTOBUF_FIELD_INVALID', 'PROTOBUF_FIELD_TRUNCATED', 'PROTOBUF_WIRE_UNSUPPORTED', 'PROTOBUF_FIELD_UNKNOWN', 'PROTOBUF_BYTES_REQUIRED',
  'PROTOBUF_INTEGER_REQUIRED', 'PROTOBUF_UTF8_INVALID', 'FLOW_ENDPOINT_INVALID', 'FLOW_PROCESS_ID_INVALID', 'FLOW_PROCESS_PATH_INVALID', 'FLOW_AMBIGUOUS'])
function invalid(code) { return Object.assign(new Error('redirector protocol rejected'), { code }) }
export function protocolFailureCode(error) { return protocolCodes.has(error?.code) ? error.code : null }
function decodeText(bytes) { try { return utf8.decode(bytes) } catch { throw invalid('PROTOBUF_UTF8_INVALID') } }

function varint(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) throw new Error('invalid protobuf integer')
  const bytes = []
  do { const byte = value % 128; value = Math.floor(value / 128); bytes.push(byte | (value ? 128 : 0)) } while (value)
  return Buffer.from(bytes)
}
function field(number, value) {
  const bytes = Buffer.from(value)
  return Buffer.concat([varint(number * 8 + 2), varint(bytes.length), bytes])
}
function numberField(number, value) { return Buffer.concat([varint(number * 8), varint(value)]) }

function fields(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_HANDSHAKE) throw invalid('PROTOBUF_SIZE_INVALID')
  const entries = new Map(); let offset = 0
  function readVarint() {
    let value = 0; let factor = 1
    for (let i = 0; i < 5; i++) {
      if (offset >= bytes.length) throw invalid('PROTOBUF_INTEGER_TRUNCATED')
      const byte = bytes[offset++]; value += (byte & 127) * factor
      if (!(byte & 128)) {
        if (value > 0xffffffff || (i > 0 && byte === 0)) throw invalid('PROTOBUF_INTEGER_INVALID')
        return value
      }
      factor *= 128
    }
    throw invalid('PROTOBUF_INTEGER_OVERFLOW')
  }
  while (offset < bytes.length) {
    const tag = readVarint(); const number = Math.floor(tag / 8); const wire = tag % 8
    if (!number || entries.has(number)) throw invalid('PROTOBUF_FIELD_INVALID')
    let value
    if (wire === 0) value = readVarint()
    else if (wire === 2) {
      const length = readVarint()
      if (length > bytes.length - offset) throw invalid('PROTOBUF_FIELD_TRUNCATED')
      value = bytes.subarray(offset, offset + length); offset += length
    } else throw invalid('PROTOBUF_WIRE_UNSUPPORTED')
    entries.set(number, { wire, value })
  }
  return entries
}
function known(map, names) { for (const number of map.keys()) if (!names.includes(number)) throw invalid('PROTOBUF_FIELD_UNKNOWN') }
function bytesField(map, number, required = true) {
  const item = map.get(number)
  if (!item && !required) return undefined
  if (!item || item.wire !== 2) throw invalid('PROTOBUF_BYTES_REQUIRED')
  return item.value
}
function integerField(map, number) {
  const item = map.get(number)
  if (!item || item.wire !== 0) throw invalid('PROTOBUF_INTEGER_REQUIRED')
  return item.value
}
function decodeAddress(bytes, allowZeroPort = false) {
  try {
    const map = fields(bytes); known(map, [1, 2])
    const host = decodeText(bytesField(map, 1))
    // Address.port is a non-optional proto3 uint32. The original Swift serializer
    // omits its default zero; only UDP local_address may use that wildcard value.
    const port = allowZeroPort && !map.has(2) ? 0 : integerField(map, 2)
    if (!host || host.length > 255 || host.includes('\0') || port < (allowZeroPort ? 0 : 1) || port > 65535) throw invalid('FLOW_ENDPOINT_INVALID')
    return { host, port }
  } catch (error) { error.decodeContext = allowZeroPort ? 'local-address' : 'remote-address'; throw error }
}
function decodeTunnel(bytes) {
  const map = fields(bytes); known(map, [1, 2])
  const pid = integerField(map, 1)
  const name = bytesField(map, 2, false)
  if (pid < 2 || pid > 0x7fffffff) throw invalid('FLOW_PROCESS_ID_INVALID')
  const processPath = name === undefined ? null : decodeText(name)
  if (processPath !== null && (processPath.length > 4096 || processPath.includes('\0'))) throw invalid('FLOW_PROCESS_PATH_INVALID')
  return { pid, processPath }
}
export function decodeNewFlow(bytes) {
  const outer = fields(bytes); known(outer, [1, 2])
  if (outer.size !== 1) throw invalid('FLOW_AMBIGUOUS')
  if (outer.has(1)) {
    const tcp = fields(bytesField(outer, 1)); known(tcp, [1, 2])
    return { kind: 'tcp', destination: decodeAddress(bytesField(tcp, 1)), ...decodeTunnel(bytesField(tcp, 2)) }
  }
  const udp = fields(bytesField(outer, 2)); known(udp, [1, 3])
  const local = bytesField(udp, 1, false)
  return { kind: 'udp', local: local ? decodeAddress(local, true) : null, ...decodeTunnel(bytesField(udp, 3)) }
}
export function decodeUdpPacket(bytes) {
  const map = fields(bytes); known(map, [1, 2])
  const data = bytesField(map, 1, false) ?? Buffer.alloc(0)
  return { data, destination: decodeAddress(bytesField(map, 2)) }
}
export function frame(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_HANDSHAKE) throw new Error('invalid frame size')
  const prefix = Buffer.alloc(4); prefix.writeUInt32BE(bytes.length)
  return Buffer.concat([prefix, bytes])
}
export function encodeInterceptPids(pids) {
  const selected = [...new Set(pids)].sort((a, b) => a - b)
  if (selected.length > 256 || selected.some(pid => !Number.isInteger(pid) || pid < 2 || pid > 0x7fffffff)) throw new Error('invalid intercept scope')
  // v0.12.11 indexes actions[0], so an empty repeated field would crash it.
  // An inclusion of PID 0 matches no routable user process and never includes all.
  return frame(Buffer.concat((selected.length ? selected : [0]).map(pid => field(1, String(pid)))))
}

// Test fixture encoder mirrors the pinned schema without running Network Extension.
export function encodeTcpFlow({ pid, host, port, processPath = '/fixture' }) {
  const address = Buffer.concat([field(1, host), numberField(2, port)])
  const tunnel = Buffer.concat([numberField(1, pid), field(2, processPath)])
  return frame(field(1, Buffer.concat([field(1, address), field(2, tunnel)])))
}
export function encodeUdpFlow({ pid, host = '0.0.0.0', port = 0, processPath = '/fixture' }) {
  const address = Buffer.concat([field(1, host), ...(port === 0 ? [] : [numberField(2, port)])])
  const tunnel = Buffer.concat([numberField(1, pid), field(2, processPath)])
  return frame(field(2, Buffer.concat([field(1, address), field(3, tunnel)])))
}
export function encodeUdpPacket({ host, port, data }) {
  const address = Buffer.concat([field(1, host), numberField(2, port)])
  return frame(Buffer.concat([field(1, data), field(2, address)]))
}
