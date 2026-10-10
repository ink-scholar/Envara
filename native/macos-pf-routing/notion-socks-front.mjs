import net from 'node:net'
import { randomUUID } from 'node:crypto'
import { NotionSOCKSReader, notionSOCKSError as fail } from './notion-socks-reader.mjs'

const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)
const port = value => Number.isInteger(value) && value > 0 && value <= 65535
const identityEqual = (a, b) => ['pid', 'uid', 'gid', 'birthSec', 'birthUsec'].every(key => a[key] === b[key])
const kernelEqual = (a, b) => ['runId', 'environmentId', 'leaseId', 'generation', 'leaseSHA256', 'gid', 'frontPort', 'keeperPID', 'keeperBirth', 'frontPID', 'frontBirth', 'filterRevision', 'writerPid', 'expiresMonotonicMs', 'bootTimeSeconds'].every(key => a[key] === b[key])
function validateKernelReceipt(receipt, context, tuple, previous) {
  const admission = receipt?.admission
  if (receipt?.authorized !== true || receipt.kind !== 'native-kernel-gid' || !admission ||
      admission.runId !== context.runId || admission.environmentId !== context.environmentId || admission.leaseId !== context.leaseId || admission.generation !== context.generation ||
      !/^[0-9a-f]{64}$/.test(admission.leaseSHA256 ?? '') || !Number.isInteger(admission.gid) || admission.gid < 7100 || admission.gid > 7999 ||
      admission.frontPort !== tuple.frontPort || admission.profile !== 'seatbelt-front-only' ||
      ['keeperPID', 'frontPID'].some(key => !Number.isInteger(admission[key]) || admission[key] < 2) ||
      ['keeperBirth', 'frontBirth'].some(key => !/^[1-9][0-9]{0,19}:[0-9]{6}$/.test(admission[key] ?? '')) ||
      ['filterRevision', 'writerPid'].some(key => !Number.isInteger(admission[key]) || admission[key] < 0 || admission[key] > 4294967295) || admission.writerPid < 2 ||
      ['expiresMonotonicMs', 'bootTimeSeconds'].some(key => !Number.isSafeInteger(admission[key]) || admission[key] < 1) ||
      ['rulesVerified', 'poolsVerified', 'lo0FilteringVerified', 'originalListenerHeld', 'originalUTunHeld'].some(key => admission[key] !== true) ||
      admission.ready !== false || admission.protected !== false || (previous && !kernelEqual(previous.admission, admission))) throw fail('OWNERSHIP_REFUSED')
  // Kernel GID admission is a separate native pipe authority. It never invents
  // a per-connection PID or upgrades the prototype's racy tuple observation.
  return { kind: 'native-kernel-gid', admission: Object.freeze({ ...admission }) }
}
function validateReceipt(receipt, context, tuple, previous) {
  const identity = receipt?.identity, witness = receipt?.witness
  if (receipt?.authorized !== true || receipt.registered !== true || receipt.routeId !== context.routeId || receipt.registryEpoch !== context.registryEpoch ||
      !identity || !Number.isInteger(identity.pid) || identity.pid < 2 || !Number.isInteger(identity.uid) || !Number.isInteger(identity.gid) ||
      !Number.isSafeInteger(identity.birthSec) || identity.birthSec < 1 || !Number.isInteger(identity.birthUsec) || identity.birthUsec < 0 || identity.birthUsec > 999999 ||
      witness?.nativeVerified !== true || witness.stable !== true || witness.matchCount !== 1 || witness.raceFree !== false ||
      !Number.isInteger(witness.fd) || witness.fd < 0 || !/^[0-9a-f]{1,16}$/.test(witness.pcbGeneration ?? '') || /^0+$/.test(witness.pcbGeneration) ||
      witness.clientHost !== tuple.clientHost || witness.clientPort !== tuple.clientPort || witness.frontHost !== tuple.frontHost || witness.frontPort !== tuple.frontPort ||
      (previous && (!identityEqual(previous.identity, identity) || previous.witness.fd !== witness.fd || previous.witness.pcbGeneration !== witness.pcbGeneration))) throw fail('OWNERSHIP_REFUSED')
  return { identity: { ...identity }, witness: { ...witness } }
}
async function bounded(operation, timeoutMs, signal) {
  let timer, onAbort
  try { return await Promise.race([
    Promise.resolve().then(operation), new Promise((_, reject) => { timer = setTimeout(() => reject(fail('OPERATION_TIMEOUT')), timeoutMs) }),
    new Promise((_, reject) => { onAbort = () => reject(fail('REVOKED')); if (signal.aborted) onAbort(); else signal.addEventListener('abort', onAbort, { once: true }) }),
  ]) } finally { clearTimeout(timer); signal.removeEventListener('abort', onAbort) }
}
async function connectUpstream(config, signal, timeoutMs) {
  const socket = net.createConnection({ host: config.host, port: config.port, allowHalfOpen: true })
  socket.on('error', () => {})
  try { await bounded(() => new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', () => reject(fail('UPSTREAM_FAILED'))) }), timeoutMs, signal); return socket }
  catch (error) { socket.destroy(); throw error }
}
async function readReply(reader, timeoutMs) {
  const head = await reader.read(4, timeoutMs)
  if (head[0] !== 5 || head[1] > 8 || head[2] !== 0) throw fail('UPSTREAM_REPLY')
  let address
  if (head[3] === 1) address = await reader.read(6, timeoutMs)
  else if (head[3] === 4) address = await reader.read(18, timeoutMs)
  else if (head[3] === 3) { const length = await reader.read(1, timeoutMs); if (!length[0]) throw fail('UPSTREAM_REPLY'); address = Buffer.concat([length, await reader.read(length[0] + 2, timeoutMs)]) }
  else throw fail('UPSTREAM_REPLY')
  if (head[1] !== 0) throw fail('UPSTREAM_CONNECT_REFUSED')
  return Buffer.concat([head, address])
}

// Unintegrated, Notion-candidate prototype. The auth-required managed upstream
// stays unchanged. authorizeOwnership MUST provide sealed/native identity proof;
// tuple observation is deliberately marked raceFree:false and never opens gates.
export async function createNotionSOCKSFront({ routeContext, upstream, authorizeOwnership, admissionMode = 'prototype-tuple', listenFD = null, timeoutMs = 1000, recheckMs = 150, maxConnections = 16 } = {}) {
  const kernelMode = admissionMode === 'native-kernel-gid'
  if (!['prototype-tuple', 'native-kernel-gid'].includes(admissionMode) || (listenFD !== null && listenFD !== 3) ||
      (kernelMode ? listenFD !== 3 || ['runId', 'environmentId', 'leaseId', 'generation'].some(key => !uuid(routeContext?.[key])) :
        !uuid(routeContext?.routeId) || !uuid(routeContext?.environmentId) || !Number.isSafeInteger(routeContext.registryEpoch) || routeContext.registryEpoch < 1) ||
      typeof authorizeOwnership !== 'function' || !upstream || !['127.0.0.1', '::1'].includes(upstream.host) || !port(upstream.port) ||
      !Number.isInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 5000 || !Number.isInteger(recheckMs) || recheckMs < 50 || recheckMs > 1000 ||
      !Number.isInteger(maxConnections) || maxConnections < 1 || maxConnections > 32) throw fail('FRONT_OPTIONS')
  const username = Buffer.from(upstream.username ?? '', 'utf8'), password = Buffer.from(upstream.password ?? '', 'utf8')
  if (username.length < 1 || username.length > 255 || password.length < 1 || password.length > 255) throw fail('UPSTREAM_CREDENTIALS')
  const context = Object.freeze(kernelMode ? { runId: routeContext.runId, environmentId: routeContext.environmentId, leaseId: routeContext.leaseId, generation: routeContext.generation } :
    { routeId: routeContext.routeId, environmentId: routeContext.environmentId, registryEpoch: routeContext.registryEpoch })
  const endpoint = Object.freeze({ host: upstream.host, port: upstream.port }), sessions = new Map(), revocations = new Set()
  const counters = { accepted: 0, authorized: 0, connected: 0, refused: 0, revoked: 0 }
  const observations = []; let closed = false, routeRevoked = false, closePromise = null
  const observe = event => { observations.push(event); if (observations.length > 128) observations.shift() }
  const destroy = (session, reason) => {
    if (session.stopped) return; session.stopped = true; session.abort.abort(); clearInterval(session.recheckTimer)
    session.client.destroy(); session.upstream?.destroy(); session.clientReader?.release(); session.upstreamReader?.release()
    sessions.delete(session.id); observe({ kind: 'closed', reason, ...(session.receipt?.identity ? { pid: session.receipt.identity.pid } : {}) })
  }
  const authorize = async (session, phase) => {
    if (closed || routeRevoked || session.stopped) throw fail('REVOKED')
    const receipt = await bounded(() => authorizeOwnership(Object.freeze({ routeContext: context, tuple: session.tuple, phase,
      signal: session.abort.signal, previousIdentity: session.receipt?.identity ? { ...session.receipt.identity } : null })), timeoutMs, session.abort.signal)
    const verified = kernelMode ? validateKernelReceipt(receipt, context, session.tuple, session.receipt) : validateReceipt(receipt, context, session.tuple, session.receipt)
    if (closed || routeRevoked || session.stopped || (verified.identity && revocations.has(`${verified.identity.pid}:${verified.identity.birthSec}:${verified.identity.birthUsec}`))) throw fail('REVOKED')
    session.receipt = verified; return verified
  }
  const server = net.createServer({ allowHalfOpen: true }, client => {
    client.on('error', () => {})
    if (closed || routeRevoked || sessions.size >= maxConnections || client.remoteAddress !== '127.0.0.1' || client.localAddress !== '127.0.0.1') { client.destroy(); counters.refused++; return }
    const session = { id: randomUUID(), client, abort: new AbortController(), stopped: false,
      tuple: Object.freeze({ clientHost: client.remoteAddress, clientPort: client.remotePort, frontHost: client.localAddress, frontPort: client.localPort }) }
    sessions.set(session.id, session); counters.accepted++
    client.once('close', () => destroy(session, 'CLIENT_CLOSED'))
    void (async () => {
      try {
        await authorize(session, 'accepted'); counters.authorized++
        const reader = session.clientReader = new NotionSOCKSReader(client, { signal: session.abort.signal })
        const greeting = await reader.read(2, timeoutMs)
        if (greeting[0] !== 5 || greeting[1] !== 1 || (await reader.read(1, timeoutMs))[0] !== 0) throw fail('FRONT_METHOD')
        await authorize(session, 'before-method-reply'); client.write(Buffer.from([5, 0]))
        const header = await reader.read(4, timeoutMs)
        if (header[0] !== 5 || header[1] !== 1 || header[2] !== 0 || ![1, 3, 4].includes(header[3])) throw fail('FRONT_REQUEST')
        let address
        if (header[3] === 3) {
          const length = await reader.read(1, timeoutMs)
          if (!length[0]) throw fail('FRONT_DOMAIN')
          const domain = await reader.read(length[0], timeoutMs)
          if (domain.some(byte => byte < 33 || byte > 126) || domain.includes(0)) throw fail('FRONT_DOMAIN')
          address = Buffer.concat([length, domain]) // Preserve DOMAIN octets exactly; no getaddrinfo.
        } else address = await reader.read(header[3] === 1 ? 4 : 16, timeoutMs)
        const destinationPort = await reader.read(2, timeoutMs)
        if (!destinationPort.readUInt16BE()) throw fail('FRONT_PORT')
        const request = Buffer.concat([header, address, destinationPort])
        await authorize(session, 'before-upstream-connect')
        session.upstream = await connectUpstream(endpoint, session.abort.signal, timeoutMs)
        session.upstream.once('close', hadError => {
          // A normal EOF must let the client's queued tail drain. The client
          // close callback completes cleanup after pipe forwards the FIN.
          if (hadError || !session.upstream.readableEnded) destroy(session, 'UPSTREAM_CLOSED')
        })
        const upstreamReader = session.upstreamReader = new NotionSOCKSReader(session.upstream, { signal: session.abort.signal })
        session.upstream.write(Buffer.from([5, 1, 2])) // Offer RFC1929 exclusively; never downgrade to no-auth.
        const method = await upstreamReader.read(2, timeoutMs)
        if (method[0] !== 5 || method[1] !== 2) throw fail('UPSTREAM_AUTH_METHOD')
        const auth = Buffer.concat([Buffer.from([1, username.length]), username, Buffer.from([password.length]), password])
        try { await bounded(() => new Promise((resolve, reject) => session.upstream.write(auth,
          error => error ? reject(fail('UPSTREAM_WRITE_FAILED')) : resolve())), timeoutMs, session.abort.signal) }
        finally { auth.fill(0) }
        const status = await upstreamReader.read(2, timeoutMs)
        if (status[0] !== 1 || status[1] !== 0) throw fail('UPSTREAM_AUTH_REFUSED')
        await authorize(session, 'after-upstream-auth')
        session.upstream.write(request)
        const reply = await readReply(upstreamReader, timeoutMs)
        await authorize(session, 'before-connect-reply')
        client.write(reply); counters.connected++; observe({ kind: 'connected', ...(kernelMode ? { environmentId: context.environmentId, admission: 'native-kernel-gid' } :
          { routeId: context.routeId, pid: session.receipt.identity.pid }), domainATYP: header[3] === 3 })
        reader.release(); upstreamReader.release(); session.clientReader = null; session.upstreamReader = null
        client.pipe(session.upstream); session.upstream.pipe(client); client.resume(); session.upstream.resume()
        let checking = false
        session.recheckTimer = setInterval(() => {
          if (checking || session.stopped) return; checking = true
          void authorize(session, 'stream-recheck').catch(() => { counters.revoked++; destroy(session, 'OWNERSHIP_RECHECK_REFUSED') }).finally(() => { checking = false })
        }, recheckMs)
      } catch (error) { if (!session.stopped) { counters.refused++; destroy(session, ['REVOKED', 'OWNERSHIP_REFUSED'].includes(error.code) ? error.code : 'SOCKS_REFUSED') } }
    })()
  })
  server.on('error', () => {})
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); listenFD === 3 ? server.listen({ fd: 3 }, resolve) : server.listen(0, '127.0.0.1', resolve) })
    const address = server.address()
    if (!address || typeof address === 'string' || address.address !== '127.0.0.1' || !port(address.port)) throw fail('FRONT_LISTENER_REFUSED')
  } catch (error) { username.fill(0); password.fill(0); if (server.listening) server.close(); throw error }
  return Object.freeze({
    host: '127.0.0.1', port: server.address().port, routeContext: context, ready: false, productionReady: false,
    revoke(identity = null) {
      if (!identity) routeRevoked = true
      else if (kernelMode) throw fail('FRONT_REVOCATION_ARGUMENT')
      else revocations.add(`${identity.pid}:${identity.birthSec}:${identity.birthUsec}`)
      for (const session of sessions.values()) if (!identity || !session.receipt || identityEqual(identity, session.receipt.identity)) { counters.revoked++; destroy(session, 'REVOKED') }
    },
    snapshot() { return { ready: false, productionReady: false, raceFreeOwnership: false, automaticChildren: false, admissionMode,
      routeRevoked, activeConnections: sessions.size, ...counters, observations: [...observations] } },
    async close() {
      if (closePromise) return closePromise; closed = true; routeRevoked = true
      for (const session of sessions.values()) destroy(session, 'FRONT_CLOSED')
      username.fill(0); password.fill(0)
      closePromise = server.listening ? new Promise(resolve => server.close(resolve)) : Promise.resolve()
      await closePromise
    },
  })
}
