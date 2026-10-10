import { spawn } from 'node:child_process'
import { lstat, realpath } from 'node:fs/promises'
import { parseDNSSDRequest, encodeDNSSDReply, DNSSD_ERROR, DNSSD_PROTOCOL_SOURCE } from './dnssd-broker-protocol.mjs'

const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no }); return { promise, resolve, reject } }
const safeError = code => Object.assign(new Error(code), { code })

// This is an owned-fixture prototype, not an app-routing adapter. The native
// front checks real Unix peer credentials/PID/birth/executable and parent PID.
// This module has no host DNS resolver or direct network transport at all.
export async function createOwnedDNSSDBroker({ frontPath, fixturePath, socketPath, routeContext, resolver, timeoutMs = 600 }) {
  if (process.platform !== 'darwin' || process.getuid?.() === 0) throw safeError('UNPRIVILEGED_MAC_FIXTURE_REQUIRED')
  if (!uuid(routeContext?.routeId) || !uuid(routeContext?.environmentId) || typeof resolver !== 'function' ||
      !Number.isInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 2000) throw safeError('BROKER_OPTIONS')
  const context = Object.freeze({ routeId: routeContext.routeId, environmentId: routeContext.environmentId })
  const paths = await Promise.all([realpath(frontPath), realpath(fixturePath)])
  for (const name of paths) {
    const stat = await lstat(name)
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o022)) throw safeError('OWNED_EXECUTABLE_REQUIRED')
  }
  const child = spawn(paths[0], [socketPath, paths[1], context.routeId], { stdio: ['pipe', 'pipe', 'pipe'] })
  const ready = deferred(), exited = deferred(), registrations = new Map(), peers = new Map(), pending = new Map()
  const observations = [], counts = { requests: 0, resolved: 0, refused: 0, timedOut: 0, resolverFailed: 0, peerRejected: 0 }
  let buffer = '', stopping = false, finished = false, parseFailed = false, stdoutBytes = 0
  function observe(event) { observations.push(Object.freeze(event)); if (observations.length > 128) observations.shift() }
  function send(id, sequence, errorCode, frames = Buffer.alloc(0)) {
    if (!finished && !stopping && child.stdin.writable) child.stdin.write(`REPLY ${id} ${sequence} ${errorCode} ${frames.length ? frames.toString('hex') : '-'}\n`)
  }
  function abortConnection(id) {
    for (const [key, state] of pending) if (state.connectionId === id) { state.abort.abort(); pending.delete(key) }
  }
  async function handleRequest(event) {
    const peer = peers.get(event.peer?.pid)
    if (!peer || peer.uid !== event.peer.uid || peer.birthSec !== event.peer.birthSec || peer.birthUsec !== event.peer.birthUsec ||
        !Number.isInteger(event.connectionId) || !Number.isInteger(event.sequence) || typeof event.frameHex !== 'string' ||
        event.frameHex.length > 8248 || !/^(?:[0-9a-f]{2})+$/.test(event.frameHex)) { parseFailed = true; child.stdin.end(); return }
    let request
    try { request = parseDNSSDRequest(Buffer.from(event.frameHex, 'hex'), event) }
    catch (error) {
      counts.refused++; observe({ kind: 'refused', pid: peer.pid, reason: error.code ?? 'PROTOCOL_ERROR' })
      send(event.connectionId, event.sequence, error.errorCode ?? DNSSD_ERROR.badParam); return
    }
    counts.requests++
    const proof = Object.freeze({ ...context, ...peer, nativePeerVerified: true })
    observe({ kind: 'request', op: request.op, pid: peer.pid, types: request.types ?? [], flags: request.flags ?? 0,
      attributeTypes: request.attributes?.map(item => item.type) ?? [], routeContextProof: proof })
    if (request.kind !== 'resolve') { send(event.connectionId, event.sequence, 0); return }
    const key = `${event.connectionId}:${event.sequence}`, abort = new AbortController()
    const state = { connectionId: event.connectionId, abort }; pending.set(key, state)
    let timer
    try {
      const timeout = new Promise((_, reject) => { timer = setTimeout(() => { abort.abort(); reject(safeError('RESOLVER_TIMEOUT')) }, timeoutMs) })
      const cancelled = new Promise((_, reject) => { abort.signal.addEventListener('abort', () => reject(safeError('RESOLVER_CANCELLED')), { once: true }) })
      const answers = await Promise.race([
        Promise.resolve().then(() => resolver(Object.freeze({ name: request.name, types: [...request.types], routeContext: context, peer: proof, signal: abort.signal }))),
        timeout, cancelled,
      ])
      if (!pending.has(key) || abort.signal.aborted) return
      if (!answers || typeof answers !== 'object') throw safeError('RESOLVER_INVALID_ANSWER')
      const records = []
      for (const type of request.types) {
        const values = answers[type === 1 ? 'A' : 'AAAA'] ?? []
        if (!Array.isArray(values) || values.length > 2) throw safeError('RESOLVER_INVALID_ANSWER')
        for (const raw of values) {
          if (!Buffer.isBuffer(raw) || raw.length !== (type === 1 ? 4 : 16)) throw safeError('RESOLVER_INVALID_ANSWER')
          records.push({ type, rdata: Buffer.from(raw) })
        }
        if (!values.length) records.push({ type, rdata: Buffer.alloc(0), errorCode: DNSSD_ERROR.noSuchRecord })
      }
      const frames = Buffer.concat(records.map((record, index) => encodeDNSSDReply(request, { ...record, moreComing: index < records.length - 1 })))
      counts.resolved++; observe({ kind: 'resolved', pid: peer.pid, answers: records.filter(record => !record.errorCode).length, routeContextProof: proof })
      send(event.connectionId, event.sequence, 0, frames)
    } catch (error) {
      if (!pending.has(key) || stopping) return
      const timedOut = error.code === 'RESOLVER_TIMEOUT' || (error.code === 'RESOLVER_CANCELLED' && timer)
      if (timedOut) counts.timedOut++; else counts.resolverFailed++
      observe({ kind: 'resolverRefused', pid: peer.pid, reason: timedOut ? 'RESOLVER_TIMEOUT' : 'RESOLVER_FAILED' })
      send(event.connectionId, event.sequence, timedOut ? DNSSD_ERROR.timeout : DNSSD_ERROR.unsupported)
    } finally { clearTimeout(timer); pending.delete(key) }
  }
  child.stdout.on('data', bytes => {
    stdoutBytes += bytes.length
    buffer += bytes.toString('utf8')
    if (buffer.length > 65536) { parseFailed = true; child.stdin.end(); return }
    let index
    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index); buffer = buffer.slice(index + 1)
      let event
      try { event = JSON.parse(line) } catch { parseFailed = true; child.stdin.end(); return }
      if (event.kind === 'listening') ready.resolve()
      else if (event.kind === 'registered') {
        const operation = registrations.get(event.pid); registrations.delete(event.pid)
        if (event.verified) operation?.resolve(); else operation?.reject(safeError('PEER_REGISTRATION_REFUSED'))
      } else if (event.kind === 'request') void handleRequest(event)
      else if (event.kind === 'peerRejected') { counts.peerRejected++; observe({ kind: 'peerRejected' }) }
      else if (event.kind === 'closed') { abortConnection(event.connectionId); observe({ kind: 'closed', reason: event.reason }) }
      else if (event.kind === 'stopped') observe({ kind: 'stopped', activeConnections: event.activeConnections })
      else { parseFailed = true; child.stdin.end() }
    }
  })
  child.stderr.on('data', () => {}) // Do not include platform diagnostics or query payloads in reports.
  child.stdin.on('error', () => {})
  child.once('error', () => { ready.reject(safeError('BROKER_START_FAILED')); exited.resolve({ exitCode: null }) })
  child.once('close', (exitCode, signal) => {
    finished = true; ready.reject(safeError('BROKER_EXITED'))
    for (const operation of registrations.values()) operation.reject(safeError('BROKER_EXITED'))
    registrations.clear(); for (const state of pending.values()) state.abort.abort(); pending.clear()
    exited.resolve({ exitCode, signal })
  })
  const startupTimer = setTimeout(() => ready.reject(Object.assign(safeError('BROKER_START_TIMEOUT'), { stdoutBytes, parseFailed })), 8000)
  try { await ready.promise } catch (error) { child.stdin.end(); child.kill('SIGTERM'); await exited.promise; throw error } finally { clearTimeout(startupTimer) }
  return Object.freeze({
    socketPath, pid: child.pid, routeContext: context, ready: false, source: DNSSD_PROTOCOL_SOURCE,
    async registerPeer(peer) {
      if (stopping || finished || !Number.isInteger(peer?.pid) || peer.uid !== process.getuid() ||
          !Number.isSafeInteger(peer.birthSec) || peer.birthSec < 1 || !Number.isSafeInteger(peer.birthUsec) || peer.birthUsec < 0 || peer.birthUsec > 999999 || peers.has(peer.pid)) throw safeError('PEER_IDENTITY')
      const operation = deferred(); registrations.set(peer.pid, operation)
      const timer = setTimeout(() => operation.reject(safeError('PEER_REGISTRATION_TIMEOUT')), 1000)
      child.stdin.write(`ADD ${peer.pid} ${peer.birthSec} ${peer.birthUsec} ${context.routeId}\n`)
      try { await operation.promise; peers.set(peer.pid, Object.freeze({ pid: peer.pid, uid: peer.uid, birthSec: peer.birthSec, birthUsec: peer.birthUsec })) }
      finally { clearTimeout(timer); registrations.delete(peer.pid) }
    },
    snapshot() { return { ready: false, productionReady: false, networkFrameworkCovered: false, resolverFallback: false,
      ...counts, activeRequests: pending.size, registeredPeers: peers.size, protocolFailed: parseFailed, observations: [...observations] } },
    async close() {
      if (!stopping) { stopping = true; for (const state of pending.values()) state.abort.abort(); child.stdin.end() }
      const killTimer = setTimeout(() => { if (!finished) child.kill('SIGTERM') }, 1000)
      const forceTimer = setTimeout(() => { if (!finished) child.kill('SIGKILL') }, 2000)
      try { const result = await exited.promise; return { ...result, ownedFrontExited: finished, activeRequests: pending.size, protocolFailed: parseFailed } }
      finally { clearTimeout(killTimer); clearTimeout(forceTimer) }
    },
  })
}
