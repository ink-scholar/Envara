// Observation only. These witnesses never set ready or grant a protected launch.
const kinds = new Set(['tcp-connected', 'tcp-response', 'udp-blocked', 'upstream-error', 'upstream-closed', 'dns-response', 'dns-error'])
const stages = new Set(['frame-prefix', 'frame-body', 'new-flow', 'binding', 'udp-frame-prefix', 'udp-frame-body', 'udp-packet', 'flow-handler'])
const rejectionCodes = new Set(['PROTOBUF_SIZE_INVALID', 'PROTOBUF_INTEGER_TRUNCATED', 'PROTOBUF_INTEGER_INVALID', 'PROTOBUF_INTEGER_OVERFLOW',
  'PROTOBUF_FIELD_INVALID', 'PROTOBUF_FIELD_TRUNCATED', 'PROTOBUF_WIRE_UNSUPPORTED', 'PROTOBUF_FIELD_UNKNOWN', 'PROTOBUF_BYTES_REQUIRED',
  'PROTOBUF_INTEGER_REQUIRED', 'PROTOBUF_UTF8_INVALID', 'FLOW_ENDPOINT_INVALID', 'FLOW_PROCESS_ID_INVALID', 'FLOW_PROCESS_PATH_INVALID',
  'FLOW_AMBIGUOUS', 'FLOW_FRAME_SIZE_INVALID', 'FLOW_OPERATION_FAILED'])
const error = code => Object.assign(new Error('diagnostic observation did not complete'), { code })

export class RoutingDiagnostics {
  constructor(getBinding) { this.getBinding = getBinding; this.sequence = 0; this.events = []; this.rejections = []; this.waiters = new Set() }
  recordRejection(event) {
    if (event.kind !== 'flow-rejected' || !stages.has(event.stage) || !rejectionCodes.has(event.code) || event.signedPeer !== true) return
    const safe = { kind: 'flow-rejected', stage: event.stage, code: event.code, signedPeer: true,
      metadataDecoded: event.metadataDecoded === true, attributedToSession: false }
    if (['local-address', 'remote-address'].includes(event.decodeContext)) safe.decodeContext = event.decodeContext
    const binding = this.getBinding(event.pid)
    if (event.metadataDecoded === true && ['tcp', 'udp'].includes(event.flowKind)) safe.flowKind = event.flowKind
    if (binding && binding.birth === event.birth && binding.routeId === event.routeId) {
      safe.pid = event.pid; safe.birth = event.birth; safe.routeId = event.routeId; safe.attributedToSession = true
    }
    const observed = Object.freeze({ ...safe, sequence: ++this.sequence, observedAt: new Date().toISOString() })
    this.rejections.push(observed); if (this.rejections.length > 64) this.rejections.shift()
    return observed
  }
  record(event) {
    const binding = this.getBinding(event.pid)
    if (!kinds.has(event.kind) || !binding || binding.routeId !== event.routeId || binding.birth !== event.birth) return
    const safe = { kind: event.kind, pid: event.pid, routeId: event.routeId, birth: event.birth }
    const dnsEvent = event.kind === 'dns-response' || event.kind === 'dns-error'
    if (!dnsEvent && typeof event.host === 'string') safe.host = event.host.slice(0, 255)
    if (!dnsEvent && Number.isInteger(event.port)) safe.port = event.port
    if (Number.isInteger(event.bytes)) safe.bytes = event.bytes
    if (['udp', 'tcp'].includes(event.transport)) safe.transport = event.transport
    if (/^[A-Z][A-Z0-9_]{1,95}$/.test(event.code ?? '')) safe.code = event.code
    if (!dnsEvent && event.local) safe.local = Object.freeze({ host: String(event.local.host).slice(0, 255), port: event.local.port })
    if (!dnsEvent && event.sample) safe.sample = Object.freeze(event.sample.unavailable ? { unavailable: true } : {
      host: String(event.sample.host).slice(0, 255), port: event.sample.port, bytes: event.sample.bytes,
    })
    const observed = Object.freeze({ ...safe, sequence: ++this.sequence, observedAt: new Date().toISOString() })
    this.events.push(observed); if (this.events.length > 256) this.events.shift()
    for (const waiter of [...this.waiters]) if (waiter.matches(observed)) waiter.finish(observed)
    return observed
  }
  snapshot() { return { sequence: this.sequence, events: this.events.map(event => ({ ...event })), rejections: this.rejections.map(event => ({ ...event })), diagnostic: true, scopeAcknowledged: false, productionReady: false } }
  wait({ sessionId, kind, afterSequence = this.sequence, timeoutMs = 5000 } = {}) {
    const binding = this.getBinding(null, sessionId)
    if (!binding || !kinds.has(kind) || !Number.isInteger(afterSequence) || afterSequence < 0 ||
        !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) return Promise.reject(error('APPLICATION_ROUTING_PROTOCOL_ERROR'))
    const matches = event => event.sequence > afterSequence && event.kind === kind && event.pid === binding.pid && event.birth === binding.birth && event.routeId === binding.routeId
    const existing = this.events.find(matches)
    if (existing) return Promise.resolve({ observed: true, event: { ...existing }, diagnostic: true, scopeAcknowledged: false, productionReady: false })
    return new Promise((resolve, reject) => {
      const waiter = { matches, finish: event => { clearTimeout(timer); this.waiters.delete(waiter); resolve({ observed: true, event: { ...event }, diagnostic: true, scopeAcknowledged: false, productionReady: false }) },
        cancel: () => { clearTimeout(timer); this.waiters.delete(waiter); reject(error('APPLICATION_ROUTING_CLOSED')) } }
      const timer = setTimeout(() => { this.waiters.delete(waiter); reject(error('APPLICATION_ROUTING_DIAGNOSTIC_TIMEOUT')) }, timeoutMs)
      this.waiters.add(waiter)
    })
  }
  close() { for (const waiter of [...this.waiters]) waiter.cancel() }
}
