// Real local sockets only. This suite never runs the original app or activates NE.
import assert from 'node:assert/strict'
import net from 'node:net'
import tls from 'node:tls'
import https from 'node:https'
import dgram from 'node:dgram'
import dns from 'node:dns'
import fs from 'node:fs/promises'
import path from 'node:path'
import { once } from 'node:events'
import { execFile } from 'node:child_process'
import { spawn } from 'node:child_process'
import { promisify } from 'node:util'
import { randomBytes } from 'node:crypto'
import { RedirectorFlowBridge } from '../native/macos-local-routing/flow-bridge.mjs'
import { decodeNewFlow, decodeUdpPacket, encodeInterceptPids, encodeTcpFlow, encodeUdpFlow, encodeUdpPacket, frame } from '../native/macos-local-routing/protocol.mjs'
import { SocketReader, openSocksStream, authenticateManagedProxy } from '../native/macos-local-routing/socks-stream.mjs'
import { inspectDependency, buildPeerVerifier, lock } from '../native/macos-local-routing/dependency.mjs'
import { createNativeInspector } from '../native/macos-local-routing/native-identity.mjs'
import { MacOSLocalRoutingAdapter } from '../native/macos-local-routing/controller.mjs'
import { RoutingDiagnostics } from '../native/macos-local-routing/diagnostics.mjs'
import { DnsOverHttpsResolver } from '../native/macos-local-routing/dns-doh.mjs'
import { validateDnsQuery, validateDnsResponse, truncateDnsUdpResponse } from '../native/macos-local-routing/dns-wire.mjs'
import { makeDiagnosticDnsResponse } from '../native/macos-local-routing/diagnostic-dns-fixture.mjs'

const execute = promisify(execFile)
const directory = await fs.mkdtemp('/tmp/envara-mac-test-')
const cleanup = []
let assertions = 0
const tick = () => new Promise(resolve => setTimeout(resolve, 5))
async function until(condition) {
  const deadline = Date.now() + 4000
  while (!condition()) { if (Date.now() > deadline) throw new Error('fixture deadline'); await tick() }
}
async function check(name, run) { await run(); assertions++; console.log(`PASS ${name}`) }
async function listen(server, address = { host: '127.0.0.1', port: 0 }) {
  server.listen(address); await once(server, 'listening'); return server.address()
}
function ownServer(server) {
  const sockets = new Set()
  server.on('connection', socket => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)) })
  cleanup.push(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)) })
  return server
}
function collect(socket) {
  return new Promise((resolve, reject) => {
    const chunks = []; const timer = setTimeout(() => { socket.destroy(); reject(new Error('fixture receive deadline')) }, 7000)
    socket.on('data', bytes => chunks.push(bytes)); socket.on('error', () => {})
    socket.once('close', () => { clearTimeout(timer); resolve(Buffer.concat(chunks)) })
  })
}
async function connectUnix(socketPath) {
  const socket = net.createConnection({ path: socketPath, allowHalfOpen: true }); socket.on('error', () => {})
  await once(socket, 'connect'); return socket
}
async function sendFlow(socketPath, header, payload = Buffer.alloc(0), fragmented = false) {
  const socket = await connectUnix(socketPath); const result = collect(socket)
  if (fragmented) { socket.write(header.subarray(0, 3)); await tick(); socket.end(Buffer.concat([header.subarray(3), payload])) }
  else socket.end(Buffer.concat([header, payload]))
  return result
}
function dnsQuery(id, type = 1) {
  const header = Buffer.alloc(12); header.writeUInt16BE(id); header.writeUInt16BE(0x0100, 2); header.writeUInt16BE(1, 4)
  const question = Buffer.concat(['fixture', 'example', 'com'].map(label => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])))
  const end = Buffer.from([0, 0, type, 0, 1])
  return Buffer.concat([header, question, end])
}

async function makeSocks({ targetPort, username = 'fixture', password = 'fixture-secret', noAuth = false, holdConnect = null } = {}) {
  const state = { authenticated: 0, connects: [], targetConnections: 0, failures: [], sockets: new Set() }
  const server = ownServer(net.createServer({ allowHalfOpen: true }, socket => {
    socket.on('error', () => {})
    state.sockets.add(socket); socket.once('close', () => state.sockets.delete(socket))
    ;(async () => {
      const reader = new SocketReader(socket)
      assert.deepEqual(await reader.read(3), Buffer.from([5, 1, 2]))
      socket.write(Buffer.from([5, noAuth ? 0 : 2])); if (noAuth) { socket.end(); return }
      const auth = await reader.read(2); assert.equal(auth[0], 1)
      const user = (await reader.read(auth[1])).toString(); const length = (await reader.read(1))[0]
      const pass = (await reader.read(length)).toString()
      if (user !== username || pass !== password) { socket.end(Buffer.from([1, 1])); return }
      state.authenticated++; socket.write(Buffer.from([1, 0]))
      // Authentication probes deliberately close before requesting a CONNECT.
      let prefix
      try { prefix = await reader.read(4) } catch { return }
      assert.deepEqual(prefix.subarray(0, 3), Buffer.from([5, 1, 0]))
      let host
      if (prefix[3] === 1) host = [...await reader.read(4)].join('.')
      else if (prefix[3] === 3) host = (await reader.read((await reader.read(1))[0])).toString()
      else if (prefix[3] === 4) host = (await reader.read(16)).toString('hex')
      else throw new Error('fixture SOCKS address')
      const port = (await reader.read(2)).readUInt16BE()
      state.connects.push({ host, port })
      if (holdConnect) await holdConnect
      if (socket.destroyed) return
      const target = net.createConnection({ host: '127.0.0.1', port: targetPort, allowHalfOpen: true })
      target.on('error', () => socket.destroy()); socket.once('close', () => target.destroy())
      await once(target, 'connect'); state.targetConnections++
      socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 1]))
      const buffered = reader.release(); if (buffered.length) target.write(buffered)
      if (reader.ended) target.end(); else socket.pipe(target)
      target.pipe(socket); socket.resume()
    })().catch(error => { state.failures.push(error.message); socket.destroy() })
  }))
  const address = await listen(server)
  return { proxy: { host: '127.0.0.1', port: address.port, username, password }, state, server }
}

try {
  await check('pinned protobuf vectors and bounded exact PID scope', async () => {
    // Hand-authored bytes: NewFlow.tcp(Address("1.2.3.4",443), TunnelInfo(42,"/x")).
    const wire = Buffer.from('0a150a0c0a07312e322e332e3410bb031205082a12022f78', 'hex')
    // The outer length above intentionally has a mismatch; malformed messages must close.
    assert.throws(() => decodeNewFlow(wire))
    const good = Buffer.from('0a160a0c0a07312e322e332e3410bb031206082a12022f78', 'hex')
    assert.deepEqual(decodeNewFlow(good), { kind: 'tcp', destination: { host: '1.2.3.4', port: 443 }, pid: 42, processPath: '/x' })
    // Original Swift proto3 serializer omits Address.port when it is zero.
    const zeroLocal = Buffer.from('12130a090a07302e302e302e301a06082a12022f78', 'hex')
    assert.deepEqual(decodeNewFlow(zeroLocal), { kind: 'udp', local: { host: '0.0.0.0', port: 0 }, pid: 42, processPath: '/x' })
    assert.throws(() => decodeNewFlow(Buffer.from('0a130a090a07312e322e332e341206082a12022f78', 'hex')), { code: 'PROTOBUF_INTEGER_REQUIRED', decodeContext: 'remote-address' })
    assert.throws(() => decodeNewFlow(Buffer.from('0a150a0b0a07312e322e332e3410001206082a12022f78', 'hex')), { code: 'FLOW_ENDPOINT_INVALID', decodeContext: 'remote-address' })
    assert.throws(() => decodeUdpPacket(Buffer.from('12090a07312e322e332e34', 'hex')), { code: 'PROTOBUF_INTEGER_REQUIRED', decodeContext: 'remote-address' })
    assert.equal(encodeInterceptPids([]).toString('hex'), '000000030a0130')
    assert.equal(encodeInterceptPids([43, 42, 42]).toString('hex'), '000000080a0234320a023433')
    assert.throws(() => decodeNewFlow(Buffer.concat([good, Buffer.from([0x18, 1])])))
    assert.throws(() => decodeNewFlow(Buffer.from('0a160a0c0a07312e322e332e3410bb03120608800012012f', 'hex')))
  })

  let echoConnections = 0
  const echo = ownServer(net.createServer({ allowHalfOpen: true }, socket => { echoConnections++; socket.pipe(socket) }))
  const echoPort = (await listen(echo)).port
  const first = await makeSocks({ targetPort: echoPort, username: 'first', password: 'first-secret' })
  const second = await makeSocks({ targetPort: echoPort, username: 'second', password: 'second-secret' })
  const routes = new Map([[42, { routeId: 'first', birth: '42:1', proxy: first.proxy }], [43, { routeId: 'second', birth: '43:1', proxy: second.proxy }]])
  const socketPath = path.join(directory, 'bridge.sock')
  let peerCalls = 0
  const bridge = new RedirectorFlowBridge({ socketPath, selectedPids: () => [...routes.keys()],
    verifyPeer: async () => { if (++peerCalls === 1) await new Promise(resolve => setTimeout(resolve, 25)); return { verified: true, pid: 999 } },
    resolveBinding: async (flow, previous) => {
      const route = routes.get(flow.pid); return route && (!previous || previous.routeId === route.routeId) ? route : null
    } })
  bridge.on('fault', () => {})
  const diagnostics = new RoutingDiagnostics((pid, sessionId) => {
    const selected = pid ?? Number(sessionId?.replace('session_', ''))
    const route = routes.get(selected); return route ? { ...route, pid: selected, sessionId: `session_${selected}` } : null
  })
  bridge.on('diagnostic', event => diagnostics.record(event))
  bridge.on('flow-rejected', event => diagnostics.recordRejection(event))
  await bridge.listen(); cleanup.push(() => bridge.close())
  const control = await connectUnix(socketPath); const controlReader = new SocketReader(control)
  cleanup.push(async () => { try { controlReader.release() } catch {}; control.destroy() })

  await check('fragmented Unix metadata plus raw binary stream, two authenticated environment routes', async () => {
    const payload = randomBytes(128 * 1024)
    const routed = sendFlow(socketPath, encodeTcpFlow({ pid: 42, host: '127.0.0.1', port: echoPort }), payload, true)
    assert.equal((await controlReader.read(4)).readUInt32BE(), 8)
    assert.equal((await controlReader.read(8)).toString('hex'), '0a0234320a023433')
    assert.deepEqual(await routed, payload)
    const otherPayload = Buffer.from([0, 0xff, 0x16, 0x03, 0x01, 0, 0x42])
    assert.deepEqual(await sendFlow(socketPath, encodeTcpFlow({ pid: 43, host: 'route.invalid', port: 443 }), otherPayload), otherPayload)
    assert.equal(first.state.targetConnections, 1); assert.equal(second.state.targetConnections, 1)
    assert.equal(second.state.connects[0].host, 'route.invalid')
    assert.equal(bridge.metrics.tcpConnected, 2)
  })

  await check('unknown PID, UDP and DNS port blocked before proxy or target contact', async () => {
    const before = echoConnections
    assert.equal((await sendFlow(socketPath, encodeTcpFlow({ pid: 44, host: '127.0.0.1', port: echoPort }))).length, 0)
    assert.equal((await sendFlow(socketPath, encodeTcpFlow({ pid: 42, host: '127.0.0.1', port: 53 }))).length, 0)
    assert.equal((await sendFlow(socketPath, frame(Buffer.from('12041a02082a', 'hex')))).length, 0)
    assert.equal(echoConnections, before); assert.equal(bridge.metrics.udpBlocked, 1); assert.equal(bridge.metrics.unknownBlocked, 2)
  })

  await check('SOCKS authentication refusal never falls back to a direct target', async () => {
    const before = echoConnections
    const noAuth = await makeSocks({ targetPort: echoPort, noAuth: true })
    await assert.rejects(openSocksStream(noAuth.proxy, { host: '127.0.0.1', port: echoPort }))
    await assert.rejects(openSocksStream({ ...first.proxy, password: 'incorrect' }, { host: '127.0.0.1', port: echoPort }))
    await assert.rejects(openSocksStream({ ...first.proxy, host: '192.0.2.1' }, { host: '127.0.0.1', port: echoPort }))
    await assert.rejects(openSocksStream(first.proxy, { host: '127.0.0.1', port: 53 }))
    assert.equal(echoConnections, before)
    assert.equal(await authenticateManagedProxy(first.proxy), true)
  })

  await check('silent SOCKS endpoint deadline rejects and leaves the next authentication usable', async () => {
    const silent = ownServer(net.createServer(() => {}))
    const port = (await listen(silent)).port; const started = Date.now()
    await assert.rejects(authenticateManagedProxy({ ...first.proxy, port }, 50))
    assert.ok(Date.now() - started < 2000)
    await assert.rejects(openSocksStream({ ...first.proxy, port }, { host: '127.0.0.1', port: echoPort }, 50))
    assert.equal(await authenticateManagedProxy(first.proxy), true)
  })

  await check('revocation during an in-flight SOCKS CONNECT does not attach a late upstream', async () => {
    let release; const held = new Promise(resolve => { release = resolve })
    const delayed = await makeSocks({ targetPort: echoPort, holdConnect: held })
    routes.set(45, { routeId: 'delayed', birth: '45:1', proxy: delayed.proxy })
    const response = sendFlow(socketPath, encodeTcpFlow({ pid: 45, host: '127.0.0.1', port: echoPort }), Buffer.from('revoked'))
    await until(() => delayed.state.connects.length === 1)
    routes.delete(45); bridge.closePid(45); release()
    assert.equal((await response).length, 0)
    await until(() => [...bridge.flows.values()].every(flow => flow.pid !== 45))
  })

  await check('1 MiB early upload applies backpressure through delayed SOCKS handshake', async () => {
    const held = new Promise(resolve => setTimeout(resolve, 200))
    const delayed = await makeSocks({ targetPort: echoPort, holdConnect: held })
    routes.set(47, { routeId: 'early-upload', birth: '47:1', proxy: delayed.proxy })
    const payload = randomBytes(1024 * 1024)
    const before = bridge.metrics.malformedBlocked
    assert.deepEqual(await sendFlow(socketPath, encodeTcpFlow({ pid: 47, host: '127.0.0.1', port: echoPort }), payload), payload)
    assert.equal(bridge.metrics.malformedBlocked, before); assert.equal(delayed.state.targetConnections, 1)
  })

  await check('opaque TLS keeps end-to-end certificate validation and half-close response bytes', async () => {
    const cert = path.join(directory, 'fixture-cert.pem'); const key = path.join(directory, 'fixture-key.pem')
    await execute('/usr/bin/openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', key, '-out', cert], { maxBuffer: 16384 })
    const certificate = await fs.readFile(cert)
    const tlsServer = ownServer(tls.createServer({ key: await fs.readFile(key), cert: certificate, allowHalfOpen: true }, socket => socket.pipe(socket)))
    const tlsPort = (await listen(tlsServer)).port
    const tlsProxy = await makeSocks({ targetPort: tlsPort })
    routes.set(46, { routeId: 'tls', birth: '46:1', proxy: tlsProxy.proxy })
    const ipc = await connectUnix(socketPath)
    ipc.write(encodeTcpFlow({ pid: 46, host: '127.0.0.1', port: tlsPort }))
    const secure = tls.connect({ socket: ipc, servername: 'localhost', ca: certificate, rejectUnauthorized: true })
    const response = collect(secure)
    await once(secure, 'secureConnect'); assert.equal(secure.authorized, true)
    const payload = randomBytes(512 * 1024); secure.end(payload)
    assert.deepEqual(await response, payload)
    assert.equal(tlsProxy.state.targetConnections, 1)
  })

  await check('UDP diagnostic samples bounded metadata, never forwards data or grants readiness', async () => {
    bridge.diagnosticUdpSampling = true
    const baseline = diagnostics.snapshot().sequence; const before = echoConnections
    const observed = diagnostics.wait({ sessionId: 'session_42', kind: 'udp-blocked', afterSequence: baseline })
    const bytes = Buffer.from('private-fixture-payload')
    assert.equal((await sendFlow(socketPath, encodeUdpFlow({ pid: 42 }), encodeUdpPacket({ host: '198.51.100.42', port: 53, data: bytes }))).length, 0)
    const result = await observed
    assert.deepEqual(result.event.sample, { host: '198.51.100.42', port: 53, bytes: bytes.length })
    assert.equal(result.productionReady, false); assert.equal(result.scopeAcknowledged, false); assert.equal(echoConnections, before)
    diagnostics.record({ kind: 'tcp-connected', pid: 42, routeId: 'first', birth: '42:1', password: 'fixture-secret', data: bytes })
    const serialized = JSON.stringify(diagnostics.snapshot())
    assert.equal(serialized.includes('private-fixture-payload'), false); assert.equal(serialized.includes('fixture-secret'), false)
    bridge.diagnosticUdpSampling = false
  })

  await check('signed-flow decoder rejection reports bounded categorical metadata without raw payload', async () => {
    const sequence = diagnostics.snapshot().sequence; const before = echoConnections
    const bad = Buffer.from('12080a001a04082a1200', 'hex') // empty local Address, valid TunnelInfo
    assert.equal((await sendFlow(socketPath, frame(bad), Buffer.from('do-not-report-this-payload'))).length, 0)
    const rejection = diagnostics.snapshot().rejections.find(value => value.sequence > sequence)
    assert.equal(rejection.code, 'PROTOBUF_BYTES_REQUIRED'); assert.equal(rejection.stage, 'new-flow'); assert.equal(rejection.decodeContext, 'local-address')
    assert.equal(rejection.signedPeer, true); assert.equal(rejection.metadataDecoded, false); assert.equal(rejection.attributedToSession, false)
    assert.equal(echoConnections, before)
    for (let i = 0; i < 80; i++) diagnostics.recordRejection({ kind: 'flow-rejected', stage: 'new-flow', code: 'FLOW_AMBIGUOUS', signedPeer: true,
      metadataDecoded: false, data: 'secret-content', host: 'private-dns-server', password: 'fixture-secret' })
    assert.equal(diagnostics.snapshot().rejections.length, 64)
    const serialized = JSON.stringify(diagnostics.snapshot().rejections)
    for (const secret of ['secret-content', 'private-dns-server', 'fixture-secret', 'do-not-report-this-payload']) assert.equal(serialized.includes(secret), false)
    assert.equal(diagnostics.recordRejection({ kind: 'flow-rejected', stage: 'arbitrary-stage', code: 'FLOW_AMBIGUOUS', signedPeer: true }), undefined)
  })

  await check('DNS header, transaction, question and compressed answer validation are bounded', async () => {
    const query = dnsQuery(0x1234); const expected = validateDnsQuery(query)
    const valid = makeDiagnosticDnsResponse(query)
    assert.equal(validateDnsResponse(valid, expected), valid)
    const badId = Buffer.from(valid); badId.writeUInt16BE(0x1235)
    assert.throws(() => validateDnsResponse(badId, expected), { code: 'DNS_TRANSACTION_MISMATCH' })
    const badQuestion = Buffer.from(valid); badQuestion[13] = 120
    assert.throws(() => validateDnsResponse(badQuestion, expected), { code: 'DNS_QUESTION_MISMATCH' })
    const cycle = Buffer.from(valid); cycle.writeUInt16BE(0xc000 | expected.questionEnd, expected.questionEnd)
    assert.throws(() => validateDnsResponse(cycle, expected), { code: 'DNS_COMPRESSION_INVALID' })
    const wrongQr = Buffer.from(query); wrongQr.writeUInt16BE(0x8100, 2)
    assert.throws(() => validateDnsQuery(wrongQr), { code: 'DNS_HEADER_INVALID' })
    const compressedQuery = Buffer.concat([query.subarray(0, 12), Buffer.from([0xc0, 0x0c, 0, 1, 0, 1])])
    assert.throws(() => validateDnsQuery(compressedQuery), { code: 'DNS_COMPRESSION_INVALID' })
    assert.throws(() => validateDnsQuery(Buffer.alloc(4097)), { code: 'DNS_SIZE_INVALID' })
    assert.throws(() => validateDnsResponse(Buffer.concat([valid, Buffer.from([0])]), expected), { code: 'DNS_TRAILING_BYTES' })
    const large = Buffer.concat([valid.subarray(0, expected.questionEnd), ...Array.from({ length: 50 }, () => valid.subarray(expected.questionEnd))]); large.writeUInt16BE(50, 6)
    const truncated = truncateDnsUdpResponse(large, expected)
    assert.equal(truncated.length, expected.questionEnd); assert.equal(truncated.readUInt16BE(2) & 0x8200, 0x8200); assert.equal(truncated.readUInt16BE(6), 0)
    assert.equal(validateDnsResponse(truncated, expected), truncated)
    const ednsQuery = Buffer.concat([query, Buffer.from('00002904d0000080000000', 'hex')]); ednsQuery.writeUInt16BE(1, 10)
    const ednsExpected = validateDnsQuery(ednsQuery); assert.equal(ednsExpected.udpPayloadSize, 1232)
    const ednsAnswer = makeDiagnosticDnsResponse(ednsQuery); assert.equal(validateDnsResponse(ednsAnswer, ednsExpected), ednsAnswer)
    const ednsLarge = Buffer.concat([ednsAnswer.subarray(0, ednsExpected.questionEnd), ...Array.from({ length: 100 }, () => ednsAnswer.subarray(ednsExpected.questionEnd, -11)), ednsAnswer.subarray(-11)])
    ednsLarge.writeUInt16BE(100, 6); ednsLarge.writeUInt32BE(0x01008000, ednsLarge.length - 6)
    const ednsTC = truncateDnsUdpResponse(ednsLarge, ednsExpected)
    assert.equal(ednsTC.readUInt16BE(10), 1); assert.equal(ednsTC.readUInt32BE(ednsTC.length - 6), 0x01008000); validateDnsResponse(ednsTC, ednsExpected)
    for (const type of [5, 15, 16, 33, 43, 48, 52, 64, 65]) assert.equal(validateDnsQuery(dnsQuery(9, type)).id, 9)
    for (const type of [0, 24, 41, 249, 250, 251, 252, 253, 254, 255]) assert.throws(() => validateDnsQuery(dnsQuery(9, type)), { code: 'DNS_QUERY_UNSUPPORTED' })
  })

  await check('DNS typed RDATA, opaque unknown types and EDNS errors retain wire boundaries', async () => {
    const query = dnsQuery(0x3456); const descriptor = validateDnsQuery(query)
    const record = (type, data, owner = Buffer.from([0xc0, 0x0c])) => {
      const fixed = Buffer.alloc(10); fixed.writeUInt16BE(type); fixed.writeUInt16BE(1, 2)
      fixed.writeUInt32BE(60, 4); fixed.writeUInt16BE(data.length, 8)
      return Buffer.concat([owner, fixed, data])
    }
    const response = records => {
      const bytes = Buffer.from(query); bytes.writeUInt16BE(0x8180, 2); bytes.writeUInt16BE(records.length, 6)
      return Buffer.concat([bytes, ...records])
    }
    for (const [type, data] of [[1, Buffer.alloc(3)], [28, Buffer.alloc(17)], [6, Buffer.from([0, 0])], [16, Buffer.from([9, 1, 2])]]) {
      assert.throws(() => validateDnsResponse(response([record(type, data)]), descriptor))
    }
    const cname = response([record(5, Buffer.from([0xc0, 0x0c]))])
    assert.equal(validateDnsResponse(cname, descriptor), cname)
    const opaque = record(65000, Buffer.from([0xc0, 0xff, 0]))
    const opaqueResponse = response([opaque]); assert.equal(validateDnsResponse(opaqueResponse, descriptor), opaqueResponse)
    const illegalTarget = Buffer.alloc(2); illegalTarget.writeUInt16BE(0xc000 | (descriptor.questionEnd + 12))
    assert.throws(() => validateDnsResponse(response([opaque, record(1, Buffer.from([203, 0, 113, 42]), illegalTarget)]), descriptor), { code: 'DNS_COMPRESSION_INVALID' })
    const ednsQuery = Buffer.concat([query, Buffer.from('0000290200000000000000', 'hex')]); ednsQuery.writeUInt16BE(1, 10)
    const expected = validateDnsQuery(ednsQuery)
    const unsupportedVersion = Buffer.from(ednsQuery); unsupportedVersion.writeUInt32BE(0x00010000, query.length + 5)
    assert.throws(() => validateDnsQuery(unsupportedVersion), { code: 'DNS_EDNS_UNSUPPORTED' })
    const duplicateOpt = Buffer.concat([ednsQuery, ednsQuery.subarray(query.length)]); duplicateOpt.writeUInt16BE(2, 10)
    assert.throws(() => validateDnsQuery(duplicateOpt), { code: 'DNS_QUERY_UNSUPPORTED' })
    const malformedOption = Buffer.concat([ednsQuery, Buffer.from([0, 12, 0, 1])]); malformedOption.writeUInt16BE(4, query.length + 9)
    assert.throws(() => validateDnsQuery(malformedOption), { code: 'DNS_MESSAGE_TRUNCATED' })
    const formerr = Buffer.from(query); formerr.writeUInt16BE(0x8181, 2)
    assert.equal(validateDnsResponse(formerr, expected), formerr)
    const missingOpt = Buffer.from(query); missingOpt.writeUInt16BE(0x8180, 2)
    assert.throws(() => validateDnsResponse(missingOpt, expected), { code: 'DNS_EDNS_INVALID' })
    assert.throws(() => validateDnsResponse(makeDiagnosticDnsResponse(ednsQuery), descriptor), { code: 'DNS_EDNS_INVALID' })
  })

  let dnsOne, dnsTwo, dnsProxyOne, dnsProxyTwo, fixtureCa, dnsResolver, dnsMode = 'valid'
  async function makeDoh(address4) {
    const server = ownServer(https.createServer({ key: await fs.readFile(path.join(directory, 'fixture-key.pem')), cert: fixtureCa }, (request, response) => {
      const chunks = []; let total = 0
      request.on('data', bytes => { total += bytes.length; if (total > 4096) request.destroy(); else chunks.push(bytes) })
      request.on('end', () => {
        assert.equal(request.method, 'POST'); assert.equal(request.url, '/dns-query'); assert.equal(request.headers['content-type'], 'application/dns-message')
        if (dnsMode === 'silent') return
        if (dnsMode === 'redirect') { response.writeHead(302, { Location: 'https://ignored.invalid/dns-query' }); response.end(); return }
        const data = makeDiagnosticDnsResponse(Buffer.concat(chunks), { address4 })
        if (dnsMode === 'wrong-id') data.writeUInt16BE(data.readUInt16BE(0) ^ 1, 0)
        if (dnsMode === 'large') {
          const expected = validateDnsQuery(Buffer.concat(chunks))
          const large = Buffer.concat([data.subarray(0, expected.questionEnd), ...Array.from({ length: 70 }, () => data.subarray(expected.questionEnd))])
          large.writeUInt16BE(70, 6)
          response.writeHead(200, { 'Content-Type': 'application/dns-message', 'Content-Length': large.length }); response.end(large); return
        }
        response.writeHead(200, { 'Content-Type': 'application/dns-message', 'Content-Length': data.length }); response.end(data)
      })
    }))
    return { server, port: (await listen(server)).port }
  }
  await check('DNS DoH uses route authentication and fixed-IP bootstrap with strict TLS', async () => {
    fixtureCa = await fs.readFile(path.join(directory, 'fixture-cert.pem'))
    dnsOne = await makeDoh('203.0.113.42'); dnsTwo = await makeDoh('203.0.113.43')
    dnsProxyOne = await makeSocks({ targetPort: dnsOne.port, username: 'dns_one', password: 'dns_one_secret' })
    dnsProxyTwo = await makeSocks({ targetPort: dnsTwo.port, username: 'dns_two', password: 'dns_two_secret' })
    const endpoint = { bootstrapIP: '198.51.100.43', port: 44443, servername: 'localhost', path: '/dns-query', testCa: fixtureCa }
    dnsResolver = new DnsOverHttpsResolver(endpoint)
    const query = dnsQuery(100)
    let lookupCalls = 0; const originalLookup = dns.lookup; dns.lookup = () => { lookupCalls++; throw new Error('host DNS must not resolve a DoH endpoint') }
    let one, two
    try { one = await dnsResolver.resolve(dnsProxyOne.proxy, query); two = await dnsResolver.resolve(dnsProxyTwo.proxy, query) }
    finally { dns.lookup = originalLookup }
    assert.equal(lookupCalls, 0)
    assert.deepEqual([...one.subarray(-4)], [203, 0, 113, 42]); assert.deepEqual([...two.subarray(-4)], [203, 0, 113, 43])
    for (const proxy of [dnsProxyOne, dnsProxyTwo]) { assert.deepEqual(proxy.state.connects, [{ host: '198.51.100.43', port: 44443 }]); assert.equal(proxy.state.authenticated, 1) }
    await assert.rejects(new DnsOverHttpsResolver({ ...endpoint, testCa: undefined }).resolve(dnsProxyOne.proxy, query), { code: 'DNS_TLS_VERIFY_FAILED' })
    await assert.rejects(new DnsOverHttpsResolver({ ...endpoint, servername: 'wrong.fixture' }).resolve(dnsProxyOne.proxy, query), { code: 'DNS_TLS_VERIFY_FAILED' })
    assert.throws(() => new DnsOverHttpsResolver({ ...endpoint, rejectUnauthorized: false }), { code: 'DNS_QUERY_INVALID' })
    const before = dnsProxyOne.state.connects.length
    await assert.rejects(dnsResolver.resolve(dnsProxyOne.proxy, Buffer.alloc(12)), { code: 'DNS_QUERY_INVALID' })
    assert.equal(dnsProxyOne.state.connects.length, before)
  })

  await check('DNS deadline, response mismatch, redirect and cancellation never use direct fallback', async () => {
    const endpoint = { bootstrapIP: '198.51.100.43', port: 44443, servername: 'localhost', path: '/dns-query', testCa: fixtureCa, timeoutMs: 150 }
    const resolver = new DnsOverHttpsResolver(endpoint); const query = dnsQuery(101)
    dnsMode = 'wrong-id'; await assert.rejects(resolver.resolve(dnsProxyOne.proxy, query), { code: 'DNS_RESPONSE_INVALID' })
    dnsMode = 'redirect'; await assert.rejects(resolver.resolve(dnsProxyOne.proxy, query), { code: 'DNS_HTTP_INVALID' })
    dnsMode = 'silent'; const began = Date.now(); await assert.rejects(resolver.resolve(dnsProxyOne.proxy, query), { code: 'DNS_DEADLINE' }); assert.ok(Date.now() - began < 2000)
    const abort = new AbortController(); const pending = dnsResolver.resolve(dnsProxyTwo.proxy, query, { signal: abort.signal }); setTimeout(() => abort.abort(), 50)
    await assert.rejects(pending, { code: 'DNS_ABORTED' }); assert.equal(dnsResolver.inFlight, 0)
    const refused = await makeSocks({ targetPort: dnsOne.port, noAuth: true }); await assert.rejects(dnsResolver.resolve(refused.proxy, query), { code: 'DNS_PROXY_FAILED' })
    dnsMode = 'valid'; assert.equal((await dnsResolver.resolve(dnsProxyOne.proxy, query)).readUInt16BE(0), 101)
  })

  await check('UDP and TCP DNS streams use separate route proxies and revoke pending DNS', async () => {
    bridge.dnsResolver = dnsResolver; bridge.diagnosticDnsForwarding = true
    routes.set(49, { routeId: 'dns-one', birth: '49:1', proxy: dnsProxyOne.proxy }); routes.set(50, { routeId: 'dns-two', birth: '50:1', proxy: dnsProxyTwo.proxy })
    const udp = await connectUnix(socketPath); const udpReader = new SocketReader(udp)
    const query = dnsQuery(102); udp.write(Buffer.concat([encodeUdpFlow({ pid: 49 }), encodeUdpPacket({ host: '192.0.2.53', port: 53, data: query })]))
    const size = (await udpReader.read(4)).readUInt32BE(); const reply = decodeUdpPacket(await udpReader.read(size))
    assert.deepEqual(reply.destination, { host: '192.0.2.53', port: 53 }); assert.deepEqual([...reply.data.subarray(-4)], [203, 0, 113, 42])
    udpReader.release(); udp.destroy()
    const tcp = await connectUnix(socketPath); const tcpReader = new SocketReader(tcp)
    const query6 = dnsQuery(103, 28); const prefix = Buffer.alloc(2); prefix.writeUInt16BE(query6.length)
    tcp.write(Buffer.concat([encodeTcpFlow({ pid: 50, host: '192.0.2.53', port: 53 }), prefix, query6]))
    const tcpSize = (await tcpReader.read(2)).readUInt16BE(); const tcpAnswer = await tcpReader.read(tcpSize)
    const expected6 = Buffer.alloc(16); expected6.writeUInt32BE(0x20010db8); expected6[15] = 0x42
    assert.equal(tcpAnswer.readUInt16BE(0), 103); assert.deepEqual(tcpAnswer.subarray(-16), expected6)
    tcpReader.release(); tcp.destroy()
    assert.equal(bridge.metrics.dnsUdpObserved, 1); assert.equal(bridge.metrics.dnsTcpObserved, 1); assert.equal(bridge.metrics.dnsAnswered, 2)
    diagnostics.record({ kind: 'dns-response', pid: 49, routeId: 'dns-one', birth: '49:1', transport: 'udp', bytes: reply.data.length,
      host: 'private-dns-server', sample: { host: 'private-dns-server', port: 53, bytes: query.length }, data: query, password: 'dns_one_secret' })
    const saved = diagnostics.snapshot().events.filter(value => value.kind.startsWith('dns-'))
    assert.equal(saved.length >= 2, true); assert.equal(JSON.stringify(saved).includes('private-dns-server'), false); assert.equal(JSON.stringify(saved).includes('dns_one_secret'), false)
    dnsMode = 'silent'; const pending = await connectUnix(socketPath); pending.once('end', () => pending.end()); const result = collect(pending)
    const before = dnsProxyOne.state.connects.length
    pending.write(Buffer.concat([encodeUdpFlow({ pid: 49 }), encodeUdpPacket({ host: '192.0.2.53', port: 53, data: dnsQuery(104) })]))
    await until(() => dnsProxyOne.state.connects.length > before)
    routes.delete(49); bridge.closePid(49); assert.equal((await result).length, 0); await until(() => dnsResolver.inFlight === 0)
    dnsMode = 'valid'; bridge.diagnosticDnsForwarding = false
  })

  await check('UDP truncation gives a complete TC reply and TCP fallback returns full reusable answers', async () => {
    bridge.diagnosticDnsForwarding = true; dnsMode = 'large'
    routes.set(51, { routeId: 'dns-fallback', birth: '51:1', proxy: dnsProxyOne.proxy })
    const query = dnsQuery(105); const expected = validateDnsQuery(query)
    const udp = await connectUnix(socketPath); const udpReader = new SocketReader(udp)
    udp.write(Buffer.concat([encodeUdpFlow({ pid: 51 }), encodeUdpPacket({ host: '192.0.2.53', port: 53, data: query })]))
    const size = (await udpReader.read(4)).readUInt32BE(); const reply = decodeUdpPacket(await udpReader.read(size))
    assert.equal(validateDnsResponse(reply.data, expected), reply.data); assert.equal(reply.data.length, query.length)
    assert.equal(reply.data.readUInt16BE(2) & 0x0200, 0x0200); assert.equal(reply.data.readUInt16BE(6), 0)
    udpReader.release(); udp.destroy()
    const tcp = await connectUnix(socketPath); const reader = new SocketReader(tcp)
    tcp.write(encodeTcpFlow({ pid: 51, host: '192.0.2.53', port: 53 }))
    for (const id of [105, 106]) {
      const asked = dnsQuery(id); const prefix = Buffer.alloc(2); prefix.writeUInt16BE(asked.length)
      tcp.write(Buffer.concat([prefix, asked]))
      const answerSize = (await reader.read(2)).readUInt16BE(); const answer = await reader.read(answerSize)
      assert.equal(validateDnsResponse(answer, validateDnsQuery(asked)), answer)
      assert.ok(answer.length > 512); assert.equal(answer.readUInt16BE(6), 70); assert.equal(answer.readUInt16BE(2) & 0x0200, 0)
    }
    reader.release(); tcp.destroy(); dnsMode = 'valid'; bridge.diagnosticDnsForwarding = false
  })

  await check('upstream disconnect and later dial refusal stay captured without target fallback', async () => {
    const proxy = await makeSocks({ targetPort: echoPort })
    routes.set(48, { routeId: 'failure', birth: '48:1', proxy: proxy.proxy })
    const client = await connectUnix(socketPath); const received = collect(client)
    const baseline = diagnostics.snapshot().sequence
    const response = diagnostics.wait({ sessionId: 'session_48', kind: 'tcp-response', afterSequence: baseline })
    client.write(Buffer.concat([encodeTcpFlow({ pid: 48, host: '127.0.0.1', port: echoPort }), Buffer.from('before-drop')]))
    await response
    const closure = diagnostics.wait({ sessionId: 'session_48', kind: 'upstream-closed', afterSequence: baseline })
    for (const socket of proxy.state.sockets) socket.destroy()
    await closure; client.end(); await received
    await new Promise(resolve => proxy.server.close(resolve))
    const before = echoConnections; const failureSequence = diagnostics.snapshot().sequence
    const failure = diagnostics.wait({ sessionId: 'session_48', kind: 'upstream-error', afterSequence: failureSequence })
    assert.equal((await sendFlow(socketPath, encodeTcpFlow({ pid: 48, host: '127.0.0.1', port: echoPort }), Buffer.from('after-drop'))).length, 0)
    assert.equal((await failure).event.code, 'PROXY_CONNECTION_FAILED')
    assert.equal(echoConnections, before); assert.equal(bridge.control.destroyed, false)
  })

  await check('read-only dependency and setup distinguish bundled verification from installation', async () => {
    const bundledAppPath = path.resolve('build/app-routing/macos-local/Resources/Mitmproxy Redirector.app')
    const adapter = new MacOSLocalRoutingAdapter({ bundledAppPath, peerVerifierPath: path.resolve('build/app-routing/macos-local/EnvaraPeerVerifier') })
    const status = await adapter.setup()
    assert.equal(status.ready, false); assert.equal(status.protectedLaunchAllowed, false)
    assert.deepEqual(status.verification.checks, { tcp: false, udp: false, dns: false, childProcesses: false, failClosed: false })
    assert.equal(status.component.name, 'mitmproxy-redirector'); assert.equal(status.component.version, lock.version)
    await assert.rejects(adapter.launch(), error => error.code === 'APPLICATION_ROUTING_NOT_READY')
    await assert.rejects(adapter.startCapture(), error => error.code === 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED')
    await adapter.shutdown()
    const dependency = await inspectDependency({ appPath: bundledAppPath })
    if (dependency.present) { assert.equal(dependency.binaryVerified, true); assert.equal(dependency.gatekeeperAccepted, true) }
  })

  await check('PID reuse removes interception, uncertain identity retains it and refuses shutdown', async () => {
    const adapter = new MacOSLocalRoutingAdapter()
    const binding = { pid: 77, birth: '100:000001', routeId: 'fixture', sessionId: 'fixture', active: true }
    adapter.bindings.set(77, binding); adapter.seenPids.add(77)
    let scopeUpdates = 0; let closed = 0; let result = new Error('temporary inspection failure')
    adapter.native = { identity: async () => { if (result instanceof Error) throw result; return result } }
    adapter.bridge = { control: {}, faulted: false, closePid: () => { closed++ }, sendScope: () => { scopeUpdates++ }, close: async () => { closed++ } }
    await adapter.refreshBindings(); assert.equal(adapter.bindings.size, 1); assert.equal(scopeUpdates, 0)
    await assert.rejects(adapter.shutdown(), error => error.code === 'APPLICATION_ROUTING_NOT_READY')
    assert.ok(adapter.bridge); assert.equal(closed, 0)
    const stopped = await adapter.stop({ sessionId: 'fixture' })
    assert.equal(stopped.stopped, false); assert.equal(stopped.captureStopped, true); assert.equal(adapter.bindings.size, 1)
    result = { verified: true, alive: true, pid: 77, birth: '200:000002' }
    await adapter.refreshBindings(); assert.equal(adapter.bindings.size, 0); assert.equal(scopeUpdates, 1); assert.equal(adapter.seenPids.has(77), true)
    const missingBinding = { ...binding, pid: 78 }; adapter.bindings.set(78, missingBinding)
    result = { verified: true, alive: false, pid: 78, reason: 'not-found' }
    await adapter.refreshBindings(); assert.equal(adapter.bindings.size, 0); assert.equal(scopeUpdates, 2)
    await adapter.shutdown(); assert.equal(adapter.closed, true)
  })

  if (process.platform === 'darwin') await check('native PID birth identity and real Unix peer signature rejection', async () => {
    const verifier = path.join(directory, 'EnvaraPeerVerifier'); await buildPeerVerifier(verifier)
    const inspector = createNativeInspector(verifier)
    const identity = await inspector.identity(process.pid)
    assert.equal(identity.pid, process.pid); assert.equal(identity.uid, process.getuid()); assert.match(identity.birth, /^\d+:\d{6}$/)
    assert.deepEqual(await inspector.identity(process.pid), identity)
    await assert.rejects(inspector.identity(1))
    const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' })
    cleanup.push(async () => { if (child.exitCode === null && child.signalCode === null) { child.kill(); await once(child, 'close') } })
    assert.equal((await inspector.identity(child.pid)).alive, true)
    child.kill(); await once(child, 'close')
    assert.deepEqual(await inspector.identity(child.pid), { verified: true, pid: child.pid, alive: false, reason: 'not-found' })
    let result
    const server = ownServer(net.createServer(socket => { socket.pause(); result = inspector.peer(socket).then(() => false, () => true).finally(() => socket.destroy()) }))
    const peerPath = path.join(directory, 'peer.sock'); await listen(server, peerPath)
    const client = await connectUnix(peerPath); client.on('error', () => {})
    await until(() => result); assert.equal(await result, true); client.destroy()
  })

  if (process.platform === 'darwin') await check('owned native fixture family binds explicit parent graph and performs local TCP/UDP only', async () => {
    const inspector = createNativeInspector(path.join(directory, 'EnvaraPeerVerifier'))
    const child = spawn(process.execPath, ['native/macos-local-routing/diagnostic-child.mjs'], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'], env: { PATH: '/usr/bin:/bin' } })
    cleanup.push(async () => { if (child.exitCode === null && child.signalCode === null) { child.kill(); await once(child, 'close') } })
    const [ready] = await once(child, 'message'); assert.equal(ready.type, 'ready')
    const call = request => new Promise((resolve, reject) => {
      const timer = setTimeout(() => { child.removeListener('message', receive); reject(new Error('fixture IPC deadline')) }, 12000)
      const receive = value => { if (value?.id === request.id && !['udp-sent', 'child-progress'].includes(value.type)) { clearTimeout(timer); child.removeListener('message', receive); resolve(value) } }
      child.on('message', receive); child.send(request)
    })
    const family = await call({ id: 'family', type: 'spawn-children', count: 2 }); assert.equal(family.processes.length, 2)
    for (const hostname of ['example.com', 'a'.repeat(15) + '.example.com', 'a'.repeat(64) + '.example.com', 'a'.repeat(65) + '.example.com', 'a'.repeat(16) + '.example.com.evil.invalid', 'g'.repeat(16) + '.example.com', 'a'.repeat(16) + '.example.com\n']) {
      const invalid = await call({ id: 'dns_invalid', type: 'dns', hostname })
      assert.deepEqual(invalid, { id: 'dns_invalid', type: 'fixture-error', code: 'FIXTURE_REQUEST_INVALID' })
    }
    const invalidDnsChild = await call({ id: 'dns_child_invalid', type: 'forward-child', pid: family.processes[0].pid, request: { id: 'dns_invalid_forward', type: 'dns', hostname: 'user-setting.invalid' } })
    assert.deepEqual(invalidDnsChild, { id: 'dns_child_invalid', type: 'child-result', pid: family.processes[0].pid, result: { id: 'dns_invalid_forward', type: 'fixture-error', code: 'FIXTURE_REQUEST_INVALID' } })
    for (const value of [{ expectedAddress4: '127.0.0.1' }, { expectedAddress6: '::1' }, { expectedAddress4: '203.0.113.42\n' }]) {
      const invalid = await call({ id: 'dns_expected_invalid', type: 'dns', hostname: 'a'.repeat(16) + '.example.com', ...value })
      assert.deepEqual(invalid, { id: 'dns_expected_invalid', type: 'fixture-error', code: 'FIXTURE_REQUEST_INVALID' })
    }
    const adapter = new MacOSLocalRoutingAdapter(); adapter.native = inspector
    adapter.routes.set('fixture_family', { active: true, application: { executablePath: process.execPath } })
    let scopeWrites = 0
    adapter.bridge = { control: {}, faulted: false, sendScope: () => { scopeWrites++ }, closePid: () => {}, close: async () => {} }
    await assert.rejects(adapter.bindDiagnosticFamily({ routeId: 'fixture_family', ownerPid: process.pid, processes: [family.processes[0]] }))
    assert.equal(adapter.bindings.size, 0)
    const bound = await adapter.bindDiagnosticFamily({ routeId: 'fixture_family', ownerPid: process.pid, processes: [{ pid: child.pid }, ...family.processes] })
    assert.equal(bound.sessions.length, 3); assert.equal(scopeWrites, 1); assert.equal(bound.automaticChildren, false); assert.equal(bound.atomic, false); assert.equal(bound.protected, false)
    const payload = Buffer.from('owned-fixture-test').toString('hex')
    const response = await call({ id: 'tcp', type: 'forward-child', pid: family.processes[0].pid, request: { id: 'tcp_child', type: 'tcp', target: { host: '127.0.0.1', port: echoPort }, payload } })
    assert.equal(response.result.passed, true); assert.equal(response.result.receivedBytes, payload.length / 2)
    const udp = dgram.createSocket('udp4'); udp.on('message', (bytes, peer) => udp.send(bytes, peer.port, peer.address))
    udp.bind(0, '127.0.0.1'); await once(udp, 'listening')
    const datagram = await call({ id: 'udp', type: 'forward-child', pid: family.processes[1].pid, request: { id: 'udp_child', type: 'udp', target: { host: '127.0.0.1', port: udp.address().port }, payload } })
    assert.equal(datagram.result.code, 'FIXTURE_RESPONSE'); assert.equal(datagram.result.sendIsNotCaptureProof, true)
    await new Promise(resolve => udp.close(resolve))
    child.send({ id: 'exit', type: 'exit' }); await once(child, 'close')
    await adapter.refreshBindings(); assert.equal(adapter.bindings.size, 0); await adapter.shutdown()
  })

  await check('private JSON RPC status/setup do not activate, and reject launch/activation', async () => {
    const methods = ['status', 'setup', 'launch', 'startCapture', 'bindPid', 'bindDiagnosticFamily', 'setDiagnosticOptions', 'diagnosticSnapshot', 'waitForDiagnosticEvent']
    const requests = methods.map((method, i) => JSON.stringify({ protocol: 'envara.application-routing', version: 1, id: String(i), method, params: { dnsForwarding: true, testCa: 'not-allowed' } }))
    const result = await new Promise((resolve, reject) => {
      import('node:child_process').then(({ spawn }) => {
        const child = spawn(process.execPath, ['native/macos-local-routing/main.mjs'], { stdio: ['pipe', 'pipe', 'pipe'] })
        let output = ''; child.stdout.on('data', bytes => { output += bytes }); child.stderr.resume(); child.once('error', reject)
        child.once('close', code => { if (code !== 0) reject(new Error('RPC fixture failed')); else resolve(output) })
        child.stdin.end(`${requests.join('\n')}\n`)
      }, reject)
    })
    const responses = result.trim().split('\n').map(line => JSON.parse(line))
    assert.equal(responses.length, methods.length); assert.equal(responses[0].result.ready, false); assert.equal(responses[1].result.ready, false)
    assert.equal(responses[2].error.code, 'APPLICATION_ROUTING_NOT_READY')
    for (const response of responses.slice(3)) assert.equal(response.error.code, 'APPLICATION_ROUTING_PROTOCOL_ERROR')
  })
  assert.deepEqual(first.state.failures, []); assert.deepEqual(second.state.failures, [])
  console.log(JSON.stringify({ passed: true, assertions, nativeCaptureTested: false, installedBySuite: false, activatedBySuite: false, dns: false, children: false, failClosed: false }))
} finally {
  for (const operation of cleanup.reverse()) await operation()
  await fs.rm(directory, { recursive: true, force: true })
}
