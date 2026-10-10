import test from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { randomUUID, randomBytes, createHash } from 'node:crypto'
import { PassThrough } from 'node:stream'
import { runNotionFrontService, NOTION_FRONT_PROTOCOL, NOTION_ADMISSION_PROTOCOL } from '../native/macos-pf-routing/notion-front-service.mjs'
import { NotionSOCKSReader } from '../native/macos-pf-routing/notion-socks-reader.mjs'
import { createNotionSOCKSFront } from '../native/macos-pf-routing/notion-socks-front.mjs'

// Unprivileged constructor fixtures exercise the real inherited-FD3 listener
// and SOCKS transport. Synthetic read-only native replies are deliberately not
// evidence of root PF admission, signed identity or protected application use.
const servicePath = path.resolve('native/macos-pf-routing/notion-front-service.mjs')
const nativePath = '/Library/PrivilegedHelperTools/io.envara.pf-routing/envara-pf-native'
const nodePath = '/Library/PrivilegedHelperTools/io.envara.pf-routing/node'
const birth = '1791459449:000123', frontBirth = '1791459449:000456'
const delay = ms => new Promise(resolve => setTimeout(resolve, ms))
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex')
const request = name => Buffer.concat([Buffer.from([5, 1, 0, 3, name.length]), name, Buffer.from([1, 187])])
const start = upstream => ({ schema: NOTION_FRONT_PROTOCOL, runId: randomUUID(), environmentId: randomUUID(), leaseId: randomUUID(), generation: randomUUID(), upstream: { ...upstream, udpPolicy: 'block' } })
function leaseFor(context, controllerPid) {
  return { schema: 'envara.macos-pf-app-bound-lease/v1', runId: context.runId, environmentId: context.environmentId, realmId: randomUUID(),
    leaseId: context.leaseId, generation: context.generation, registrationId: randomUUID(), versionId: randomUUID(), consoleUID: 501, gid: 7101,
    cwd: '/private/tmp', timezone: 'Asia/Manila', locale: 'en-PH', issuedMonotonicMs: 1000, expiresMonotonicMs: 101000, bootTimeSeconds: 1791400000,
    controllerPid, controllerBirth: birth, ipv4Address: '198.18.1.1', rootHookLease: { runId: context.runId } }
}
const identity = (pid, parentPid, executable, processBirth = birth) => ({ schema: 'envara.macos-pf-native/v1', ok: true, protected: false,
  pid, parentPid, consoleUID: 0, uid: 0, realUID: 0, savedUID: 0, gid: 0, realGID: 0, savedGID: 0, birth: processBirth, path: executable })
function activation(context, lease, ack, keeperPID) {
  return { schema: NOTION_ADMISSION_PROTOCOL, operation: 'activate', runId: context.runId, environmentId: context.environmentId,
    leaseId: context.leaseId, generation: context.generation, leaseSHA256: digest(lease), keeperPID, keeperBirth: birth, frontPID: ack.pid,
    frontBirth, frontPort: ack.port, gid: lease.gid, filterRevision: 0, writerPid: keeperPID, profile: 'seatbelt-front-only', rulesVerified: true,
    poolsVerified: true, lo0FilteringVerified: true, originalListenerHeld: true, originalUTunHeld: true,
    expiresMonotonicMs: lease.expiresMonotonicMs, bootTimeSeconds: lease.bootTimeSeconds, ready: false, protected: false }
}
async function fakeUpstream({ noAuth = false } = {}) {
  const username = randomBytes(10).toString('hex'), password = randomBytes(15).toString('hex'), sockets = new Set()
  const stats = { connections: 0, authenticated: 0, requests: [], payloads: [], halfCloses: 0 }
  const server = net.createServer({ allowHalfOpen: true }, socket => {
    sockets.add(socket); stats.connections++; socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket))
    const reader = new NotionSOCKSReader(socket)
    void (async () => {
      try {
        assert.deepEqual(await reader.read(3, 2000), Buffer.from([5, 1, 2]))
        socket.write(Buffer.from([5, noAuth ? 0 : 2])); if (noAuth) return
        const auth = await reader.read(2, 2000), user = await reader.read(auth[1], 2000), length = await reader.read(1, 2000), pass = await reader.read(length[0], 2000)
        assert.equal(auth[0], 1); assert.equal(user.toString(), username); assert.equal(pass.toString(), password); user.fill(0); pass.fill(0)
        stats.authenticated++; socket.write(Buffer.from([1, 0]))
        const head = await reader.read(4, 2000), nameLength = await reader.read(1, 2000), name = await reader.read(nameLength[0], 2000), destinationPort = await reader.read(2, 2000)
        stats.requests.push(Buffer.concat([head, nameLength, name, destinationPort]))
        socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0])); reader.release()
        socket.on('data', bytes => { stats.payloads.push(Buffer.from(bytes)); socket.write(bytes) })
        socket.once('end', () => { stats.halfCloses++; socket.end(Buffer.from('native-front-tail')) }); socket.resume()
      } catch { reader.release(); socket.destroy() }
    })()
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  return { config: { host: '127.0.0.1', port: server.address().port, username, password }, stats,
    async close() { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)) } }
}
async function fixture(t, upstream, { remainingMs = 100000, intermediary = false } = {}) {
  const temporary = await mkdtemp(path.join(tmpdir(), 'envara-front-service-'))
  const context = start(upstream), controllerPid = process.pid + 50000, lease = leaseFor(context, controllerPid)
  lease.expiresMonotonicMs = 1001 + remainingMs
  const runner = path.join(temporary, 'runner.mjs')
  await writeFile(runner, `import dns from 'node:dns';
import { runNotionFrontService } from ${JSON.stringify(servicePath)};
const lease = ${JSON.stringify(lease)};
const identity = ${identity.toString()};
const nativePath = ${JSON.stringify(nativePath)}, nodePath = ${JSON.stringify(nodePath)}, birth = ${JSON.stringify(birth)}, frontBirth = ${JSON.stringify(frontBirth)};
let altered = false, bootstrapAltered = false, expired = false, changedLease = false, replacedLease = false, dnsLookups = 0, nativeQueries = 0;
dns.lookup = () => { dnsLookups++; throw new Error('LOCAL_DNS_FORBIDDEN'); };
const service = await runNotionFrontService({
 inspectInstallation: async () => ({ verified: true, runtimeVerified: true }),
 inspectExecution: async () => ({ pid: process.pid, parentPid: process.ppid }),
 readBoundLease: async () => ({ lease, sha256: changedLease ? 'e'.repeat(64) : ${JSON.stringify(digest(lease))}, fileIdentity: { device: 1, inode: replacedLease ? 3 : 2, size: 1024, mtimeMs: 1000, ctimeMs: 1000 } }),
 readNativeClock: async () => { nativeQueries++; return { schema: 'envara.macos-pf-app-context-clock/v1', ok: true, bootTimeSeconds: lease.bootTimeSeconds, nowMonotonicMilliseconds: expired ? lease.expiresMonotonicMs : 1001 }; },
 readNativeIdentity: async id => { nativeQueries++; return id === process.pid ? identity(id, process.ppid, nodePath, frontBirth) : id === process.ppid ? identity(id, ${intermediary ? 'lease.controllerPid + 1' : 'lease.controllerPid'}, nativePath, altered ? '1791459449:000999' : birth) : id === lease.controllerPid + 1 ? identity(id, lease.controllerPid, '/bin/launchctl', bootstrapAltered ? '1791459449:000888' : birth) : identity(id, 1, nodePath); },
});
process.on('message', message => {
 if (message.action === 'parentChanged') altered = true;
 if (message.action === 'bootstrapChanged') bootstrapAltered = true;
 if (message.action === 'expired') expired = true;
 if (message.action === 'leaseChanged') changedLease = true;
 if (message.action === 'leaseReplaced') replacedLease = true;
 if (message.action === 'snapshot') process.send({ kind: 'snapshot', requestId: message.requestId, ...service.snapshot(), dnsLookups, nativeQueries });
});
process.send({ kind: 'fixture-ready' });
const result = await service.done; process.send({ kind: 'done', ...result, dnsLookups }); if(result.failed) process.exitCode = 1; process.disconnect();
`, { mode: 0o600 })
  // The duplicate reaches FD3 through stdio inheritance; no front port is
  // selected or rebound by the child. Close this test owner's copy before use.
  const holder = net.createServer(); await new Promise(resolve => holder.listen(0, '127.0.0.1', resolve))
  const inheritedPort = holder.address().port, fd = holder._handle.fd
  const child = spawn(process.execPath, [runner], { stdio: ['pipe', 'pipe', 'pipe', fd, 'ipc'] })
  await new Promise(resolve => holder.close(resolve))
  let buffer = '', stderr = '', ack, resolveAck, rejectAck, resolveDone
  const ackPromise = new Promise((resolve, reject) => { resolveAck = resolve; rejectAck = reject })
  const done = new Promise(resolve => { resolveDone = resolve }), pending = new Map()
  child.stderr.on('data', bytes => { stderr += bytes.toString(); if (stderr.length > 8192) child.kill('SIGTERM') })
  child.stdout.on('data', bytes => {
    buffer += bytes.toString(); const newline = buffer.indexOf('\n')
    if (newline >= 0) { const line = buffer.slice(0, newline); buffer = buffer.slice(newline + 1); try { ack = JSON.parse(line); resolveAck({ ack, line }) } catch { rejectAck(new Error('INVALID_ACK')) } }
  })
  child.stdin.on('error', () => {})
  child.on('message', message => {
    if (message.kind === 'snapshot') { const resolve = pending.get(message.requestId); pending.delete(message.requestId); resolve?.(message) }
  })
  child.once('error', rejectAck)
  child.once('close', (code, signal) => { rejectAck(new Error('FIXTURE_EXITED')); resolveDone({ code, signal, stderr }); for (const resolve of pending.values()) resolve(null); pending.clear() })
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) { child.stdin.end(); const timeout = setTimeout(() => child.kill('SIGTERM'), 1500); await done; clearTimeout(timeout) } await rm(temporary, { recursive: true, force: true }) })
  child.stdin.write(`${JSON.stringify(context)}\n`)
  const timeout = setTimeout(() => rejectAck(new Error('ACK_TIMEOUT')), 2500)
  const acknowledged = await ackPromise; clearTimeout(timeout)
  assert.equal(ack.port, inheritedPort)
  const snapshot = () => new Promise(resolve => { const requestId = randomUUID(); pending.set(requestId, resolve); child.send({ action: 'snapshot', requestId }) })
  return { context, lease, ack, line: acknowledged.line, child, done, snapshot,
    admit(change = {}) { child.stdin.write(`${JSON.stringify({ ...activation(context, lease, ack, process.pid), ...change })}\n`) },
    async admitted() { for (let tries = 0; tries < 100; tries++) { const value = await snapshot(); if (value?.admitted) return value; await delay(15) } throw new Error('ADMISSION_TIMEOUT') } }
}
async function connect(front) {
  const socket = net.createConnection({ host: '127.0.0.1', port: front.port, allowHalfOpen: true }); socket.on('error', () => {})
  await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject) })
  return socket
}
async function handshake(front, name = Buffer.from('Unresolved.Mixed-Case.invalid')) {
  const socket = await connect(front), reader = new NotionSOCKSReader(socket)
  try {
    socket.write(Buffer.from([5, 1, 0])); assert.deepEqual(await reader.read(2, 1500), Buffer.from([5, 0]))
    socket.write(request(name)); assert.deepEqual(await reader.read(10, 1500), Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]))
    return { socket, reader, name }
  } catch (error) { reader.release(); socket.destroy(); throw error }
}
async function closes(socket) {
  if (socket.destroyed) return
  let timer
  try { await new Promise((resolve, reject) => {
    const ended = () => { socket.destroy(); resolve() }
    socket.once('close', resolve); socket.once('end', ended); socket.resume()
    timer = setTimeout(() => { socket.destroy(); reject(new Error('SOCKET_NOT_REVOKED')) }, 2000)
  }) } finally { clearTimeout(timer) }
}

test('kernel mode requires the private inherited descriptor and an installed runtime', async () => {
  const routeContext = { runId: randomUUID(), environmentId: randomUUID(), leaseId: randomUUID(), generation: randomUUID() }
  await assert.rejects(createNotionSOCKSFront({ routeContext, admissionMode: 'native-kernel-gid', upstream: { host: '127.0.0.1', port: 1, username: 'a', password: 'b' }, authorizeOwnership: () => ({ authorized: true }) }), { code: 'FRONT_OPTIONS' })
  const input = new PassThrough(), output = new PassThrough()
  let writes = ''; output.on('data', bytes => { writes += bytes })
  const service = await runNotionFrontService({ input, output, inspectInstallation: async () => ({ verified: true, runtimeVerified: false }) })
  input.write(`${JSON.stringify(start({ host: '127.0.0.1', port: 1, username: 'secret-user', password: 'secret-password' }))}\n`)
  const result = await service.done
  assert.equal(result.admitted, false); assert.equal(result.failed, true); assert.equal(result.reason, 'INSTALLATION_REFUSED'); assert.equal(writes, '')
})

test('malformed, duplicate-key and oversized private bootstrap never reach installation or network', async () => {
  const context = start({ host: '127.0.0.1', port: 1, username: 'private-user', password: 'private-password' }), canonical = JSON.stringify(context)
  for (const line of ['{}', `${canonical.slice(0, -1)},"runId":${JSON.stringify(context.runId)}}`, ` ${canonical}`, canonical.replace('127.0.0.1', 'remote.invalid'), 'x'.repeat(8193)]) {
    const input = new PassThrough(), output = new PassThrough(); let inspected = 0, written = ''
    output.on('data', bytes => { written += bytes })
    const service = await runNotionFrontService({ input, output, inspectInstallation: async () => { inspected++; return { verified: true, runtimeVerified: true } } })
    input.write(`${line}\n`); const result = await service.done
    assert.equal(result.failed, true); assert.equal(result.phase, 'bootstrap'); assert.equal(result.reason, 'BOOTSTRAP_REFUSED')
    assert.equal(inspected, 0); assert.equal(written, '')
  }
})

test('inherited FD3 remains closed to traffic until native admission, then preserves auth, DOMAIN and FIN', { timeout: 15000 }, async t => {
  const upstream = await fakeUpstream(); t.after(() => upstream.close())
  const service = await fixture(t, upstream.config)
  assert.equal(service.line, JSON.stringify({ schema: NOTION_FRONT_PROTOCOL, operation: 'front-started', runId: service.context.runId,
    environmentId: service.context.environmentId, leaseId: service.context.leaseId, generation: service.context.generation, pid: service.ack.pid,
    host: '127.0.0.1', port: service.ack.port, ready: false, protected: false }))
  const denied = await connect(service.ack); denied.write(Buffer.from([5, 1, 0])); await closes(denied)
  assert.equal(upstream.stats.connections, 0)
  service.admit(); const status = await service.admitted(); assert.equal(status.ready, false); assert.equal(status.protected, false)
  const { socket, reader, name } = await handshake(service.ack), payload = randomBytes(4096)
  socket.write(payload); assert.deepEqual(await reader.read(payload.length, 2000), payload)
  socket.end(); assert.deepEqual(await reader.read(Buffer.byteLength('native-front-tail'), 2000), Buffer.from('native-front-tail'))
  reader.release(); socket.resume(); await closes(socket)
  assert.deepEqual(upstream.stats.requests, [request(name)]); assert.equal(upstream.stats.authenticated, 1); assert.equal(upstream.stats.halfCloses, 1)
  const after = await service.snapshot()
  assert.equal(after.dnsLookups, 0)
  // SOCKS phases share a checked cycle; they do not spawn four helpers each.
  assert.ok(after.nativeQueries - status.nativeQueries <= 4)
  service.child.stdin.end(); assert.deepEqual(await service.done, { code: 0, signal: null, stderr: '' })
})

for (const action of ['parentChanged', 'expired', 'leaseChanged', 'leaseReplaced', 'stdinEOF']) {
  test(`active TCP and future traffic revoked on ${action}`, { timeout: 10000 }, async t => {
    const upstream = await fakeUpstream(); t.after(() => upstream.close())
    const service = await fixture(t, upstream.config); service.admit(); await service.admitted()
    const { socket, reader } = await handshake(service.ack)
    if (action === 'stdinEOF') service.child.stdin.end(); else service.child.send({ action })
    await closes(socket); reader.release()
    const result = await service.done; assert.equal(result.code, action === 'stdinEOF' ? 0 : 1); assert.equal(result.stderr, '')
    assert.equal(upstream.stats.connections, 1)
  })
}

test('fixed native lease deadline expires independently of the 500ms native query cycle', { timeout: 10000 }, async t => {
  const upstream = await fakeUpstream(); t.after(() => upstream.close())
  const service = await fixture(t, upstream.config, { remainingMs: 220 }); await delay(40)
  service.admit(); await service.admitted()
  const { socket, reader } = await handshake(service.ack)
  const sinceAdmission = performance.now(); await closes(socket); reader.release()
  assert.ok(performance.now() - sinceAdmission < 400)
  assert.equal((await service.done).code, 1)
})

test('fixed root launchctl intermediary is birth-bound and revoked when it changes', { timeout: 10000 }, async t => {
  const upstream = await fakeUpstream(); t.after(() => upstream.close())
  const service = await fixture(t, upstream.config, { intermediary: true }); service.admit(); await service.admitted()
  const { socket, reader } = await handshake(service.ack)
  service.child.send({ action: 'bootstrapChanged' }); await closes(socket); reader.release()
  assert.equal((await service.done).code, 1); assert.equal(upstream.stats.authenticated, 1)
})

test('one-shot admission rejects forged proof, binding and repeated activation without exposing credentials', { timeout: 20000 }, async t => {
  const upstream = await fakeUpstream(); t.after(() => upstream.close())
  for (const patch of [{ lo0FilteringVerified: false }, { originalListenerHeld: false }, { leaseSHA256: 'f'.repeat(64) },
    { keeperBirth: '1791459449:000777' }, { frontBirth: '1791459449:000777' }, { frontPort: 1 }, { gid: 7999 }, { profile: 'prototype-tuple' },
    { expiresMonotonicMs: 101002 }, { protected: true }, { writerPid: 2 }, { extraProof: true }]) {
    const service = await fixture(t, upstream.config); service.admit(patch)
    const result = await service.done; assert.equal(result.code, 1); assert.equal(result.stderr, '')
  }
  const service = await fixture(t, upstream.config); service.admit(); await service.admitted(); service.admit()
  assert.equal((await service.done).code, 1); assert.equal(upstream.stats.connections, 0)
})

test('managed upstream no-auth downgrade is refused after native admission', { timeout: 10000 }, async t => {
  const upstream = await fakeUpstream({ noAuth: true }); t.after(() => upstream.close())
  const service = await fixture(t, upstream.config); service.admit(); await service.admitted()
  await assert.rejects(handshake(service.ack))
  assert.equal(upstream.stats.authenticated, 0); assert.equal(upstream.stats.requests.length, 0)
})
