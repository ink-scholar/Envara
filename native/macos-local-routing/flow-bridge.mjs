import net from 'node:net'
import fs from 'node:fs/promises'
import { EventEmitter } from 'node:events'
import { SocketReader, openSocksStream } from './socks-stream.mjs'
import { decodeNewFlow, decodeUdpPacket, encodeUdpPacket, encodeInterceptPids, MAX_HANDSHAKE, protocolFailureCode } from './protocol.mjs'
import { validateDnsQuery, truncateDnsUdpResponse } from './dns-wire.mjs'
import { DNS_FAILURE_CODES } from './dns-doh.mjs'

const dnsCodes = new Set(DNS_FAILURE_CODES)
const dnsFailure = code => Object.assign(new Error('managed DNS flow did not complete'), { code })

// The low-level bridge requires peer and process verification callbacks. The
// production controller always supplies the native signed-peer verifier.
export class RedirectorFlowBridge extends EventEmitter {
  constructor({ socketPath, verifyPeer, resolveBinding, selectedPids, maxFlows = 256, dnsResolver = null }) {
    super()
    if (typeof socketPath !== 'string' || !socketPath.startsWith('/tmp/') || Buffer.byteLength(socketPath) > 100 ||
        [verifyPeer, resolveBinding, selectedPids].some(value => typeof value !== 'function')) throw new Error('invalid bridge configuration')
    this.socketPath = socketPath; this.verifyPeer = verifyPeer; this.resolveBinding = resolveBinding; this.selectedPids = selectedPids
    this.maxFlows = maxFlows; this.server = null; this.control = null; this.connections = new Set(); this.flows = new Map(); this.closed = false; this.faulted = false; this.peerQueue = Promise.resolve()
    this.metrics = { peerRejected: 0, tcpObserved: 0, tcpConnected: 0, udpBlocked: 0, unknownBlocked: 0, malformedBlocked: 0 }
    this.metrics.tcpClientBytes = 0; this.metrics.tcpProxyBytes = 0; this.metrics.upstreamFailed = 0; this.metrics.cancelled = 0
    this.metrics.dnsUdpObserved = 0; this.metrics.dnsTcpObserved = 0; this.metrics.dnsAnswered = 0; this.metrics.dnsFailed = 0
    this.diagnosticUdpSampling = false; this.diagnosticDnsForwarding = false; this.dnsResolver = dnsResolver
  }
  async listen() {
    if (this.server || this.closed) throw new Error('bridge already started')
    this.server = net.createServer({ allowHalfOpen: true }, socket => {
      socket.on('error', () => {})
      this.connections.add(socket); socket.once('close', () => this.connections.delete(socket))
      if (this.connections.size > this.maxFlows + 8 || this.closed || this.faulted) { socket.destroy(); return }
      socket.pause()
      // Assign control in accept order, even if peer validation completes at
      // different speeds. Flow I/O itself remains concurrent after validation.
      const authenticated = this.peerQueue.then(() => this.accept(socket))
      this.peerQueue = authenticated.catch(() => { socket.destroy() })
    })
    await new Promise((resolve, reject) => {
      this.server.once('error', reject)
      this.server.listen(this.socketPath, () => { this.server.removeListener('error', reject); resolve() })
    })
    this.server.on('error', () => this.fault('IPC listener failed'))
    await fs.chmod(this.socketPath, 0o600)
    return this.socketPath
  }
  async accept(socket) {
    let peer
    try { peer = await this.verifyPeer(socket) } catch (error) {
      this.metrics.peerRejected++
      this.emit('peer-rejected', { code: /^[A-Z][A-Z0-9_]{1,95}$/.test(error.code ?? '') ? error.code : 'PEER_VERIFICATION_REJECTED' })
      socket.destroy(); return
    }
    if (this.closed || this.faulted || socket.destroyed || peer?.verified !== true) {
      this.metrics.peerRejected++
      this.emit('peer-rejected', { code: this.closed ? 'BRIDGE_CLOSED' : this.faulted ? 'BRIDGE_FAULTED' : socket.destroyed ? 'PEER_SOCKET_CLOSED_BEFORE_VALIDATION' : 'PEER_VERIFIER_DID_NOT_ACCEPT' })
      socket.destroy(); return
    }
    if (!this.control) {
      // The pinned provider establishes control before applying its network
      // settings. Every connection is independently signed-peer authenticated.
      this.control = socket
      socket.on('data', () => this.fault('Unexpected data on control channel'))
      socket.once('end', () => this.fault('Redirector control channel ended'))
      socket.once('close', () => { if (!this.closed) this.fault('Redirector control channel closed') })
      this.sendScope(); socket.resume(); this.emit('control', peer); return
    }
    if (!this.control || this.flows.size >= this.maxFlows) { socket.destroy(); return }
    this.handleFlow(socket).catch(() => { this.metrics.malformedBlocked++; this.reportRejection(null, 'flow-handler'); socket.destroy() })
  }
  reportRejection(error, stage, flow, binding) {
    const event = { kind: 'flow-rejected', stage, code: protocolFailureCode(error) ?? (error?.code === 'FLOW_FRAME_SIZE_INVALID' ? error.code : 'FLOW_OPERATION_FAILED'),
      signedPeer: true, metadataDecoded: !!flow }
    if (['local-address', 'remote-address'].includes(error?.decodeContext)) event.decodeContext = error.decodeContext
    if (flow) { event.flowKind = flow.kind; event.pid = flow.pid }
    if (binding) { event.routeId = binding.routeId; event.birth = binding.birth }
    this.emit('flow-rejected', event)
  }
  trackFlow(socket, flow, binding) {
    const state = { pid: flow.pid, routeId: binding.routeId, birth: binding.birth, upstream: null, abort: new AbortController(), responseObserved: false, closureReported: false }
    this.flows.set(socket, state)
    socket.once('close', () => { state.abort.abort(); state.upstream?.destroy(); this.flows.delete(socket) })
    return state
  }
  async readDnsPart(reader, length, socket, state) {
    const timer = setTimeout(() => socket.destroy(), 10000)
    try { if (state.abort.signal.aborted) throw dnsFailure('DNS_ABORTED'); return await reader.read(length) }
    finally { clearTimeout(timer) }
  }
  async writeDnsReply(socket, bytes, state) {
    if (state.abort.signal.aborted || socket.destroyed) throw dnsFailure('DNS_ABORTED')
    await new Promise((resolve, reject) => {
      let settled = false
      const finish = error => { if (settled) return; settled = true; clearTimeout(timer); state.abort.signal.removeEventListener('abort', cancelled); error ? reject(error) : resolve() }
      const cancelled = () => finish(dnsFailure('DNS_ABORTED'))
      const timer = setTimeout(() => { finish(dnsFailure('DNS_DEADLINE')); socket.destroy() }, 5000)
      state.abort.signal.addEventListener('abort', cancelled, { once: true })
      socket.write(bytes, error => finish(error ? dnsFailure('DNS_ABORTED') : null))
    })
  }
  async dnsExchange(socket, flow, binding, state, data, transport) {
    let expected
    try { expected = validateDnsQuery(data) } catch { throw dnsFailure('DNS_QUERY_INVALID') }
    if (!this.dnsResolver || !this.diagnosticDnsForwarding || !await this.resolveBinding(flow, binding)) throw dnsFailure('DNS_ABORTED')
    this.metrics[transport === 'udp' ? 'dnsUdpObserved' : 'dnsTcpObserved']++
    const result = await this.dnsResolver.resolve(binding.proxy, data, { signal: state.abort.signal })
    if (state.abort.signal.aborted || socket.destroyed || this.closed || this.faulted || !await this.resolveBinding(flow, binding)) throw dnsFailure('DNS_ABORTED')
    return transport === 'udp' ? truncateDnsUdpResponse(result, expected) : result
  }
  dnsDiagnostic(kind, flow, binding, transport, detail = {}) {
    this.emit('diagnostic', { kind, pid: flow.pid, routeId: binding.routeId, birth: binding.birth, transport, ...detail })
  }
  async handleDnsTcp(socket, reader, flow, binding) {
    const state = this.trackFlow(socket, flow, binding)
    try {
      for (let count = 0; count < 16 && !socket.destroyed; count++) {
        const size = (await this.readDnsPart(reader, 2, socket, state)).readUInt16BE()
        if (size < 12 || size > 4096) throw dnsFailure('DNS_QUERY_INVALID')
        const data = await this.readDnsPart(reader, size, socket, state)
        const answer = await this.dnsExchange(socket, flow, binding, state, data, 'tcp')
        const prefix = Buffer.alloc(2); prefix.writeUInt16BE(answer.length)
        await this.writeDnsReply(socket, Buffer.concat([prefix, answer]), state)
        state.responseObserved = true
        this.metrics.dnsAnswered++; this.dnsDiagnostic('dns-response', flow, binding, 'tcp', { bytes: answer.length })
      }
    } catch (error) {
      if (!state.abort.signal.aborted && !(state.responseObserved && reader.ended && reader.length === 0)) { this.metrics.dnsFailed++; this.dnsDiagnostic('dns-error', flow, binding, 'tcp', { code: dnsCodes.has(error.code) ? error.code : 'DNS_ABORTED' }) }
    } finally { state.abort.abort(); socket.destroy(); this.flows.delete(socket) }
  }
  async handleUdp(socket, reader, flow, binding) {
    if (!this.diagnosticDnsForwarding && !this.diagnosticUdpSampling) {
      this.metrics.udpBlocked++; this.emit('diagnostic', { kind: 'udp-blocked', pid: flow.pid, routeId: binding.routeId, birth: binding.birth, local: flow.local, sample: null }); socket.destroy(); return
    }
    const state = this.trackFlow(socket, flow, binding); let stage = 'udp-frame-prefix', dnsPacket = false
    try {
      for (let count = 0; count < 16 && !socket.destroyed; count++) {
        stage = 'udp-frame-prefix'; const size = (await this.readDnsPart(reader, 4, socket, state)).readUInt32BE()
        if (size < 1 || size > MAX_HANDSHAKE) throw Object.assign(new Error('invalid UDP frame'), { code: 'FLOW_FRAME_SIZE_INVALID' })
        stage = 'udp-frame-body'; const data = await this.readDnsPart(reader, size, socket, state)
        stage = 'udp-packet'; const packet = decodeUdpPacket(data)
        dnsPacket = this.diagnosticDnsForwarding && packet.destination.port === 53
        if (dnsPacket) {
          const answer = await this.dnsExchange(socket, flow, binding, state, packet.data, 'udp')
          await this.writeDnsReply(socket, encodeUdpPacket({ ...packet.destination, data: answer }), state)
          state.responseObserved = true
          this.metrics.dnsAnswered++; this.dnsDiagnostic('dns-response', flow, binding, 'udp', { bytes: answer.length })
          continue
        }
        const sample = this.diagnosticUdpSampling ? { host: packet.destination.host, port: packet.destination.port, bytes: packet.data.length } : null
        this.metrics.udpBlocked++; this.emit('diagnostic', { kind: 'udp-blocked', pid: flow.pid, routeId: binding.routeId, birth: binding.birth, local: flow.local, sample }); return
      }
    } catch (error) {
      if (!state.abort.signal.aborted && !(state.responseObserved && reader.ended && reader.length === 0)) {
        if (dnsPacket) { this.metrics.dnsFailed++; this.dnsDiagnostic('dns-error', flow, binding, 'udp', { code: dnsCodes.has(error.code) ? error.code : 'DNS_ABORTED' }) }
        else { this.reportRejection(error, stage, flow, binding); this.metrics.udpBlocked++; this.emit('diagnostic', { kind: 'udp-blocked', pid: flow.pid, routeId: binding.routeId, birth: binding.birth, local: flow.local, sample: { unavailable: true } }) }
      }
    } finally { state.abort.abort(); socket.destroy(); this.flows.delete(socket) }
  }
  async handleFlow(socket) {
    const reader = new SocketReader(socket)
    const timer = setTimeout(() => socket.destroy(), 5000)
    socket.resume()
    let flow, upstream, provisional, binding, stage = 'frame-prefix'
    try {
      const length = (await reader.read(4)).readUInt32BE()
      if (length < 1 || length > MAX_HANDSHAKE) throw Object.assign(new Error('invalid flow frame'), { code: 'FLOW_FRAME_SIZE_INVALID' })
      stage = 'frame-body'; const metadata = await reader.read(length)
      stage = 'new-flow'; flow = decodeNewFlow(metadata)
      clearTimeout(timer)
      if (flow.kind === 'udp') {
        stage = 'binding'; binding = await this.resolveBinding(flow)
        if (!binding) { this.metrics.unknownBlocked++; socket.destroy(); return }
        await this.handleUdp(socket, reader, flow, binding); return
      }
      this.metrics.tcpObserved++
      stage = 'binding'; binding = await this.resolveBinding(flow)
      if (!binding || (flow.destination.port === 53 && !this.diagnosticDnsForwarding)) { this.metrics.unknownBlocked++; socket.destroy(); return }
      if (flow.destination.port === 53) { await this.handleDnsTcp(socket, reader, flow, binding); return }
      if (this.closed || this.faulted || socket.destroyed) return
      provisional = this.trackFlow(socket, flow, binding)
      stage = 'socks-connect'; upstream = await openSocksStream(binding.proxy, flow.destination, 5000, { signal: provisional.abort.signal })
      const state = this.flows.get(socket)
      if (!state) { upstream.socket.destroy(); socket.destroy(); return }
      state.upstream = upstream.socket
      stage = 'binding-recheck'
      if (this.closed || socket.destroyed || !await this.resolveBinding(flow, binding)) { upstream.socket.destroy(); socket.destroy(); return }
      stage = 'stream-handoff'
      const buffered = reader.release()
      if (reader.failure) throw new Error('flow read failed')
      const closePair = () => { socket.destroy(); upstream.socket.destroy() }
      const diagnostic = (kind, detail = {}) => this.emit('diagnostic', { kind, pid: flow.pid, routeId: binding.routeId, birth: binding.birth, host: flow.destination.host, port: flow.destination.port, ...detail })
      const reportClosure = code => {
        if (provisional.closureReported || provisional.abort.signal.aborted) return
        provisional.closureReported = true; diagnostic('upstream-closed', { code })
      }
      socket.once('error', closePair)
      upstream.socket.once('end', () => reportClosure('UPSTREAM_EOF'))
      upstream.socket.once('error', () => { reportClosure('UPSTREAM_TRANSPORT_ERROR'); closePair() })
      upstream.socket.once('close', () => {
        reportClosure(upstream.socket.readableEnded ? 'UPSTREAM_EOF' : 'UPSTREAM_DISCONNECTED')
        // Preserve queued response bytes and a normal upstream FIN. Destroying
        // the IPC socket here would discard a response under backpressure.
        if (!upstream.socket.readableEnded) socket.destroy()
        else if (!socket.writableEnded) socket.end()
        this.flows.delete(socket)
      })
      socket.on('data', bytes => { this.metrics.tcpClientBytes += bytes.length })
      upstream.socket.on('data', bytes => {
        this.metrics.tcpProxyBytes += bytes.length
        if (!provisional.responseObserved) { provisional.responseObserved = true; diagnostic('tcp-response', { bytes: bytes.length }) }
      })
      this.metrics.tcpClientBytes += buffered.length; this.metrics.tcpProxyBytes += upstream.buffered.length
      if (upstream.buffered.length) { provisional.responseObserved = true; diagnostic('tcp-response', { bytes: upstream.buffered.length }) }
      if (buffered.length) upstream.socket.write(buffered)
      if (upstream.buffered.length) socket.write(upstream.buffered)
      if (reader.ended) upstream.socket.end(); else socket.pipe(upstream.socket)
      if (upstream.ended) socket.end(); else upstream.socket.pipe(socket)
      socket.resume(); upstream.socket.resume()
      this.metrics.tcpConnected++; this.emit('flow', { kind: 'tcp', pid: flow.pid, routeId: binding.routeId, host: flow.destination.host, port: flow.destination.port })
      diagnostic('tcp-connected')
    } catch (error) {
      if (provisional?.abort.signal.aborted) this.metrics.cancelled++
      else if (flow?.kind === 'tcp' && provisional) {
        this.metrics.upstreamFailed++
        this.emit('diagnostic', { kind: 'upstream-error', pid: flow.pid, routeId: provisional.routeId, birth: provisional.birth,
          host: flow.destination.host, port: flow.destination.port, code: 'PROXY_CONNECTION_FAILED' })
      } else { this.metrics.malformedBlocked++; this.reportRejection(error, stage, flow, binding) }
      upstream?.socket.destroy(); socket.destroy(); this.flows.delete(socket)
    } finally { clearTimeout(timer) }
  }
  sendScope() {
    if (!this.control || this.control.destroyed) throw new Error('control unavailable')
    const bytes = encodeInterceptPids(this.selectedPids())
    if (this.control.writableLength > 65536) { this.fault('control backpressure bound exceeded'); throw new Error('control overloaded') }
    this.control.write(bytes)
  }
  closePid(pid) {
    for (const [socket, flow] of this.flows) if (flow.pid === pid) { flow.abort.abort(); flow.upstream?.destroy(); socket.destroy(); this.flows.delete(socket) }
  }
  fault(reason) {
    if (this.closed || this.faulted) return
    this.faulted = true
    for (const flow of this.flows.values()) flow.abort.abort()
    for (const socket of this.connections) socket.destroy()
    this.emit('fault', reason)
  }
  async close() {
    if (this.closed) return
    this.closed = true
    for (const flow of this.flows.values()) flow.abort.abort()
    for (const socket of this.connections) socket.destroy()
    this.flows.clear()
    if (this.server) await new Promise(resolve => this.server.close(resolve))
    try { await fs.unlink(this.socketPath) } catch (error) { if (error.code !== 'ENOENT') throw error }
  }
}
