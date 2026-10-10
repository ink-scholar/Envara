// Owned fixtures only. No activation, user application, credentials or files.
import net from 'node:net'
import dgram from 'node:dgram'
import dns from 'node:dns'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const fixtureAddresses = new Set(['203.0.113.42', '203.0.113.43', '2001:db8::42', '2001:db8::43'])
const safeResolverCode = error => /^[A-Z][A-Z0-9_]{1,63}$/.test(error?.code ?? '') ? error.code : 'FIXTURE_DNS_FAILED'

// The caller supplies only this diagnostic's synthetic reserved answers. Raw
// addresses stay inside the process; these labels never identify a real egress.
export function classifyDiagnosticDnsAnswers(addresses, { ownAddresses = [], otherAddresses = [], diagnosticFixtureAddresses = [] } = {}) {
  if (!Array.isArray(ownAddresses) || !Array.isArray(otherAddresses) || !Array.isArray(diagnosticFixtureAddresses) ||
      ownAddresses.length > 4 || otherAddresses.length > 4 || diagnosticFixtureAddresses.length > 4 ||
      [...ownAddresses, ...otherAddresses, ...diagnosticFixtureAddresses].some(value => !fixtureAddresses.has(value)) ||
      ownAddresses.some(value => otherAddresses.includes(value))) throw new TypeError('reserved diagnostic answers required')
  const values = Array.isArray(addresses) ? addresses.map(value => value?.address) : []
  const ownFixtureAnswerObserved = values.some(value => ownAddresses.includes(value))
  const otherFixtureAnswerObserved = values.some(value => otherAddresses.includes(value))
  const unexpectedAnswersObserved = values.some(value => !ownAddresses.includes(value) && !otherAddresses.includes(value))
  const answerSource = values.length > 0 && values.every(value => ownAddresses.includes(value)) ? 'own' :
    values.length > 0 && values.every(value => otherAddresses.includes(value)) ? 'other' : 'unexpected'
  const configured = [...ownAddresses, ...otherAddresses, ...diagnosticFixtureAddresses]
  const normalize6 = value => { try { return new URL(`http://[${value}]/`).hostname.slice(1, -1) } catch { return null } }
  const configured6 = configured.filter(value => net.isIP(value) === 6).map(normalize6)
  const configured4Tails = configured.filter(value => net.isIP(value) === 4).map(value => value.split('.').reduce((total, octet) => total * 256 + Number(octet), 0))
  const actualAddressFamilies = [...new Set(values.map(value => typeof value === 'string' ? net.isIP(value) : 0).filter(value => value === 4 || value === 6))].sort()
  const returned6 = values.filter(value => typeof value === 'string' && net.isIP(value) === 6).map(normalize6).filter(Boolean)
  const canonicalFixtureAnswerObserved = returned6.some(value => configured6.includes(value))
  const fixtureIpv4TailObserved = returned6.some(value => {
    const [left, right] = value.split('::')
    const leading = left ? left.split(':') : [], trailing = right ? right.split(':') : []
    const words = right === undefined ? leading : [...leading, ...Array(8 - leading.length - trailing.length).fill('0'), ...trailing]
    const tail = (Number.parseInt(words[6], 16) * 65536) + Number.parseInt(words[7], 16)
    return configured4Tails.includes(tail)
  })
  return { answerSource, ownFixtureAnswerObserved, otherFixtureAnswerObserved, unexpectedAnswersObserved,
    actualAddressFamilies, canonicalFixtureAnswerObserved, fixtureIpv4TailObserved }
}

export function runDiagnosticChild() {
if (!process.send) throw new Error('private parent IPC required')
const children = new Set(); const sockets = new Set()
const reply = value => { if (process.connected) process.send(value) }
const targetValid = target => target && ['198.51.100.42', '127.0.0.1', '::1', '::ffff:198.51.100.42'].includes(target.host) &&
  Number.isInteger(target.port) && target.port > 0 && target.port <= 65535
const payloadValid = value => typeof value === 'string' && value.length > 0 && value.length <= 2 * 1024 * 1024 && value.length % 2 === 0 && /^[a-f0-9]+$/i.test(value)

process.on('message', request => {
  if (!request || typeof request.id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(request.id)) return
  if (request.type === 'exit') {
    for (const socket of sockets) { try { socket.destroy ? socket.destroy() : socket.close() } catch {} }
    for (const child of children) child.send({ id: 'exit', type: 'exit' })
    if (process.connected) process.disconnect(); return
  }
  if (request.type === 'spawn-children') {
    if (!Number.isInteger(request.count) || request.count < 1 || request.count > 4 || children.size + request.count > 8) return reply({ id: request.id, type: 'fixture-error', code: 'FIXTURE_REQUEST_INVALID' })
    ;(async () => {
      const ready = []
      for (let i = 0; i < request.count; i++) {
        const child = spawn(process.execPath, [fileURLToPath(import.meta.url)], { env: { PATH: '/usr/bin:/bin' }, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] })
        children.add(child); child.once('exit', () => children.delete(child))
        const entry = await new Promise((resolve, reject) => {
          const timer = setTimeout(() => { child.kill(); reject(new Error('fixture startup deadline')) }, 5000)
          child.once('message', value => { clearTimeout(timer); if (value?.type !== 'ready') reject(new Error('fixture startup')); else resolve(value) })
          child.once('error', () => { clearTimeout(timer); reject(new Error('fixture startup')) })
        })
        ready.push({ pid: entry.pid, parentPid: entry.parentPid })
      }
      reply({ id: request.id, type: 'children-ready', processes: ready })
    })().catch(() => reply({ id: request.id, type: 'fixture-error', code: 'FIXTURE_CHILD_FAILED' }))
    return
  }
  if (request.type === 'forward-child') {
    const child = [...children].find(value => value.pid === request.pid)
    if (!child || !request.request || !['tcp', 'udp', 'dns'].includes(request.request.type)) return reply({ id: request.id, type: 'fixture-error', code: 'FIXTURE_REQUEST_INVALID' })
    const timer = setTimeout(() => {
      child.removeListener('message', receive)
      reply({ id: request.id, type: 'fixture-error', code: 'FIXTURE_CHILD_TIMEOUT' })
    }, 17000)
    const receive = value => {
      if (value?.id !== request.request.id) return
      const terminal = ['tcp-result', 'udp-result', 'dns-result', 'fixture-error'].includes(value.type)
      if (terminal) { clearTimeout(timer); child.removeListener('message', receive) }
      reply({ id: request.id, type: terminal ? 'child-result' : 'child-progress', pid: child.pid, result: value })
    }
    child.on('message', receive); child.send(request.request); return
  }
  if (request.type === 'dns') {
    if (typeof request.hostname !== 'string' || request.hostname !== request.hostname.trim() || !/^[a-f0-9]{16,63}\.example\.com$/i.test(request.hostname) ||
        (request.expectedAddress4 !== undefined && !['203.0.113.42', '203.0.113.43'].includes(request.expectedAddress4)) ||
        (request.expectedAddress6 !== undefined && !['2001:db8::42', '2001:db8::43'].includes(request.expectedAddress6)) ||
        (request.family !== undefined && request.family !== 4 && request.family !== 6) ||
        (request.family === 4 && request.expectedAddress6 !== undefined) ||
        (request.family === 6 && request.expectedAddress4 !== undefined) ||
        (request.otherFixtureAddresses !== undefined && (!Array.isArray(request.otherFixtureAddresses) || request.otherFixtureAddresses.length > 4 || request.otherFixtureAddresses.some(value => !fixtureAddresses.has(value)))) ||
        (request.diagnosticFixtureAddresses !== undefined && (!Array.isArray(request.diagnosticFixtureAddresses) || request.diagnosticFixtureAddresses.length > 4 || request.diagnosticFixtureAddresses.some(value => !fixtureAddresses.has(value)))) ||
        (request.timeoutMs !== undefined && (!Number.isInteger(request.timeoutMs) || request.timeoutMs < 100 || request.timeoutMs > 15000))) return reply({ id: request.id, type: 'fixture-error', code: 'FIXTURE_REQUEST_INVALID' })
    const expected = [request.expectedAddress4, request.expectedAddress6].filter(value => value !== undefined)
    const other = request.otherFixtureAddresses ?? []
    const classificationOptions = { ownAddresses: expected, otherAddresses: other, diagnosticFixtureAddresses: request.diagnosticFixtureAddresses ?? [] }
    if (expected.some(value => other.includes(value))) return reply({ id: request.id, type: 'fixture-error', code: 'FIXTURE_REQUEST_INVALID' })
    let settled = false
    const finish = (code, resolved, matchedExpectedAddresses = false, classification = classifyDiagnosticDnsAnswers([], classificationOptions)) => {
      if (settled) return; settled = true; clearTimeout(timer)
      reply({ id: request.id, type: 'dns-result', code, resolved, ...(request.family ? { family: request.family } : {}),
        ...classification, ...(expected.length ? { matchedExpectedAddresses } : {}) })
    }
    const timer = setTimeout(() => finish('FIXTURE_DNS_TIMEOUT', false), request.timeoutMs ?? 15000)
    // System getaddrinfo, not dns.Resolver or a manually chosen DNS server.
    // Never return addresses, query contents, settings, or the hostname.
    dns.lookup(request.hostname, { all: true, family: request.family ?? 0 }, (error, addresses) => {
      const matched = !error && Array.isArray(addresses) && expected.length > 0 && expected.every(address => addresses.some(value => value.address === address)) &&
        addresses.every(value => expected.includes(value.address))
      finish(error ? safeResolverCode(error) : 'FIXTURE_DNS_RESOLVED', !error, matched,
        classifyDiagnosticDnsAnswers(addresses, classificationOptions))
    })
    return
  }
  if (!['tcp', 'udp'].includes(request.type) || !targetValid(request.target) || !payloadValid(request.payload)) return reply({ id: request.id, type: 'fixture-error', code: 'FIXTURE_REQUEST_INVALID' })
  const payload = Buffer.from(request.payload, 'hex')
  if (request.type === 'tcp') {
    const socket = net.createConnection({ ...request.target, allowHalfOpen: true }); sockets.add(socket)
    const received = []; let settled = false; let progressSent = false
    const done = code => {
      if (settled) return; settled = true; clearTimeout(timer); socket.destroy(); sockets.delete(socket)
      const bytes = Buffer.concat(received)
      reply({ id: request.id, type: 'tcp-result', passed: bytes.equals(payload), receivedBytes: bytes.length, code, mode: request.mode === 'half-close' ? 'half-close' : 'normal-stream' })
    }
    const timer = setTimeout(() => done('FIXTURE_TIMEOUT'), 10000)
    socket.once('connect', () => { if (request.mode === 'half-close') socket.end(payload); else socket.write(payload) })
    socket.on('data', bytes => {
      received.push(bytes)
      const receivedBytes = received.reduce((sum, part) => sum + part.length, 0)
      if (receivedBytes >= payload.length && request.mode === 'hold') {
        if (!progressSent) { progressSent = true; reply({ id: request.id, type: 'tcp-progress', receivedBytes, passed: Buffer.concat(received).equals(payload), keepOpen: true }) }
      } else if (receivedBytes >= payload.length) done('FIXTURE_RESPONSE')
    })
    socket.once('end', () => done('FIXTURE_EOF')); socket.once('error', () => done('FIXTURE_ERROR')); socket.once('close', () => done('FIXTURE_CLOSED'))
    return
  }
  const socket = dgram.createSocket(request.target.host.includes(':') ? 'udp6' : 'udp4'); sockets.add(socket)
  let settled = false; let localPort = null
  const done = (code, receivedBytes = 0) => {
    if (settled) return; settled = true; clearTimeout(timer); try { socket.close() } catch {}; sockets.delete(socket)
    reply({ id: request.id, type: 'udp-result', code, sentBytes: payload.length, receivedBytes, localPort, sendIsNotCaptureProof: true })
  }
  const timer = setTimeout(() => done('FIXTURE_NO_RESPONSE'), 1000)
  socket.on('message', bytes => done(bytes.equals(payload) ? 'FIXTURE_RESPONSE' : 'FIXTURE_UNEXPECTED_RESPONSE', bytes.length))
  socket.once('error', () => done('FIXTURE_ERROR'))
  socket.send(payload, request.target.port, request.target.host, error => {
    if (error) done('FIXTURE_ERROR'); else { localPort = socket.address().port; reply({ id: request.id, type: 'udp-sent', sentBytes: payload.length, localPort, sendIsNotCaptureProof: true }) }
  })
})
process.on('disconnect', () => {
  for (const socket of sockets) { try { socket.destroy ? socket.destroy() : socket.close() } catch {} }
  for (const child of children) child.disconnect()
})
reply({ type: 'ready', pid: process.pid, parentPid: process.ppid })
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) runDiagnosticChild()
