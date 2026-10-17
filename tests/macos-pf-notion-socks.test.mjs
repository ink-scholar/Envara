import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { chmod, mkdtemp, rm } from 'node:fs/promises'
import path from 'node:path'
import net from 'node:net'
import { randomBytes, randomUUID } from 'node:crypto'
import { createNotionSOCKSFront } from '../native/macos-pf-routing/notion-socks-front.mjs'
import { createNotionOwnedFixtureAuthorizer } from '../native/macos-pf-routing/notion-socks-attestor.mjs'
import { NotionSOCKSReader } from '../native/macos-pf-routing/notion-socks-reader.mjs'

const context = () => ({ routeId: randomUUID(), environmentId: randomUUID(), registryEpoch: 1 })
const request = (name = Buffer.from('Same.Realm.Example.invalid'), command = 1) => Buffer.concat([Buffer.from([5, command, 0, 3, name.length]), name, Buffer.from([1, 187])])
const pause = ms => new Promise(resolve => setTimeout(resolve, ms))
function exec(command, args, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] }); let output = '', error = ''
    child.stdout.on('data', bytes => { output += bytes; if (output.length > 16384) child.kill('SIGKILL') })
    child.stderr.on('data', bytes => { error += bytes; if (error.length > 16384) child.kill('SIGKILL') })
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs)
    child.once('error', error => { clearTimeout(timer); reject(error) })
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, output, error }) })
  })
}
function client(binary, clients) {
  const child = spawn(binary, [], { stdio: ['pipe', 'pipe', 'pipe'] }); clients.add(child)
  let buffer = '', identity, readyResolve, readyReject, doneResolve; const pending = []
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject })
  const done = new Promise(resolve => { doneResolve = resolve })
  child.stdout.on('data', bytes => {
    buffer += bytes.toString('utf8'); if (buffer.length > 131072) { child.kill('SIGKILL'); return }
    let index
    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index); buffer = buffer.slice(index + 1)
      let response; try { response = JSON.parse(line) } catch { child.kill('SIGKILL'); return }
      if (response.ready) { identity = response.identity; readyResolve(identity) }
      else { const operation = pending.shift(); if (operation) { clearTimeout(operation.timer); operation.resolve(response) } }
    }
  })
  child.stderr.on('data', () => {}); child.stdin.on('error', () => {})
  child.once('error', readyReject)
  child.once('close', (exitCode, signal) => {
    clients.delete(child); readyReject(new Error('OWNED_FIXTURE_EXITED'))
    for (const operation of pending) { clearTimeout(operation.timer); operation.resolve({ ok: false, closed: true }) }
    doneResolve({ exitCode, signal })
  })
  const cmd = value => new Promise(resolve => {
    const operation = { resolve, timer: setTimeout(() => { child.kill('SIGKILL'); resolve({ ok: false, timeout: true }) }, 3500) }
    pending.push(operation); child.stdin.write(value + '\n')
  })
  return { ready, done, get identity() { return identity }, cmd, write: bytes => cmd(`WRITE ${bytes.toString('hex')}`),
    read: async length => { const result = await cmd(`READ ${length}`); return { ...result, data: Buffer.from(result.hex ?? '', 'hex') } },
    async connect(front) { return cmd(`CONNECT ${front.port}`) },
    async close() { if (clients.has(child)) { child.stdin.end('QUIT\n'); const timer = setTimeout(() => child.kill('SIGKILL'), 1000); const result = await done; clearTimeout(timer); return result } return done },
  }
}
async function upstream({ tail = Buffer.from('fixture-tail'), authFailure = false, downgrade = false, authStall = false } = {}) {
  const username = randomBytes(12).toString('hex'), password = randomBytes(20).toString('hex'), sockets = new Set()
  const stats = { connections: 0, authenticated: 0, requests: [], payloadBytes: 0, halfCloses: 0, authWaiting: false }
  const server = net.createServer({ allowHalfOpen: true }, socket => {
    sockets.add(socket); stats.connections++; socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket))
    const reader = new NotionSOCKSReader(socket)
    void (async () => {
      try {
        const greeting = await reader.read(3, 2000)
        if (!greeting.equals(Buffer.from([5, 1, 2]))) { socket.end(Buffer.from([5, 255])); return }
        socket.write(Buffer.from([5, downgrade ? 0 : 2])); if (downgrade) return
        const auth = await reader.read(2, 2000), user = await reader.read(auth[1], 2000), length = await reader.read(1, 2000), pass = await reader.read(length[0], 2000)
        const valid = auth[0] === 1 && user.equals(Buffer.from(username)) && pass.equals(Buffer.from(password)) && !authFailure
        user.fill(0); pass.fill(0); stats.authWaiting = true
        if (authStall) return
        socket.write(Buffer.from([1, valid ? 0 : 1])); if (!valid) return
        stats.authenticated++
        const header = await reader.read(4, 2000), nameLength = await reader.read(1, 2000), domain = await reader.read(nameLength[0], 2000), port = await reader.read(2, 2000)
        if (header[0] !== 5 || header[1] !== 1 || header[2] !== 0 || header[3] !== 3) throw new Error('FIXTURE_REQUEST')
        stats.requests.push(Buffer.concat([header, nameLength, domain, port]))
        socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0])); reader.release()
        const payload = []; let acknowledged = false
        socket.on('data', bytes => { payload.push(bytes); stats.payloadBytes += bytes.length; if (!acknowledged) { acknowledged = true; socket.write(Buffer.from('ACK')) } })
        socket.once('end', () => { stats.halfCloses++; socket.end(Buffer.concat([...payload, tail])) }); socket.resume()
      } catch { socket.destroy() }
    })()
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  return { config: { host: '127.0.0.1', port: server.address().port, username, password }, stats,
    async close() { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)) } }
}

test('front has no permissive authorization default or remote upstream endpoint', async () => {
  await assert.rejects(createNotionSOCKSFront(), { code: 'FRONT_OPTIONS' })
  await assert.rejects(createNotionSOCKSFront({ routeContext: context(), upstream: { host: '127.0.0.1', port: 1, username: 'a', password: 'b' } }), { code: 'FRONT_OPTIONS' })
  await assert.rejects(createNotionSOCKSFront({ routeContext: context(), upstream: { host: 'remote.invalid', port: 1, username: 'a', password: 'b' }, authorizeOwnership: () => ({ authorized: true }) }), { code: 'FRONT_OPTIONS' })
})

test('owned native TCP attestation, exact DOMAIN/auth/FIN, two realms, refusal and revocation',
  { skip: process.platform !== 'darwin' || process.getuid?.() === 0, timeout: 45000 }, async t => {
    const temporary = await mkdtemp('/private/tmp/envara-notion-socks-'); await chmod(temporary, 0o700)
    const attestor = path.join(temporary, 'notion-socks-attestor'), fixture = path.join(temporary, 'notion-socks-fixture')
    const clients = new Set(), owners = [], fronts = [], cores = []
    async function owner() { const c = client(fixture, clients); await c.ready; owners.push(c); return c }
    async function core(options) { const c = await upstream(options); cores.push(c); return c }
    async function front(c, u, options = {}) {
      const routeContext = context(), nativeAuthorize = await createNotionOwnedFixtureAuthorizer({ binaryPath: attestor, routeContext, identities: [c.identity] })
      const f = await createNotionSOCKSFront({ routeContext, upstream: u.config, authorizeOwnership: options.wrap ? options.wrap(nativeAuthorize) : nativeAuthorize,
        timeoutMs: options.timeoutMs ?? 700, recheckMs: 100 }); fronts.push(f); return f
    }
    async function handshake(c, f, bytes = request(), methods = Buffer.from([5, 1, 0])) {
      assert.equal((await c.connect(f)).ok, true); assert.equal((await c.write(methods)).ok, true)
      const greeting = await c.read(2); assert.equal(greeting.ok, true); assert.equal(greeting.data.equals(Buffer.from([5, 0])), true)
      assert.equal((await c.write(bytes)).ok, true); const reply = await c.read(10); return reply.ok && reply.data[0] === 5 && reply.data[1] === 0
    }
    try {
      for (const [source, binary] of [['notion-socks-attestor.c', attestor], ['notion-socks-fixture.c', fixture]]) {
        const build = await exec('/usr/bin/clang', ['-Wall', '-Wextra', '-Werror', path.resolve('native/macos-pf-routing', source), '-o', binary])
        assert.equal(build.code, 0, build.error); await chmod(binary, 0o700)
      }
      await t.test('DOMAIN octets unchanged, RFC1929 auth required, complete large tail after client FIN', async () => {
        const c = await owner(), tail = randomBytes(262144), u = await core({ tail }), f = await front(c, u)
        assert.equal(await handshake(c, f), true); assert.equal(u.stats.requests[0].equals(request()), true)
        assert.equal(u.stats.authenticated, 1)
        const payload = randomBytes(173); assert.equal((await c.write(payload)).ok, true)
        assert.equal((await c.read(3)).data.equals(Buffer.from('ACK')), true); assert.equal(u.stats.payloadBytes, payload.length)
        assert.equal((await c.cmd('END')).ok, true)
        const expected = Buffer.concat([payload, tail]), chunks = []
        for (let read = 0; read < expected.length; read += 32768) { const next = await c.read(Math.min(32768, expected.length - read)); assert.equal(next.ok, true); chunks.push(next.data) }
        assert.equal(Buffer.concat(chunks).equals(expected), true); assert.equal(u.stats.halfCloses, 1)
        assert.equal(f.snapshot().raceFreeOwnership, false); assert.equal(f.ready, false); await c.close()
      })
      await t.test('same DOMAIN concurrently uses independent authenticated realm routes', async () => {
        const a = await owner(), b = await owner(), ua = await core(), ub = await core(), fa = await front(a, ua), fb = await front(b, ub)
        const results = await Promise.all([handshake(a, fa), handshake(b, fb)]); assert.deepEqual(results, [true, true])
        assert.equal(ua.stats.requests[0].equals(ub.stats.requests[0]), true); assert.equal(ua.stats.authenticated, 1); assert.equal(ub.stats.authenticated, 1)
        await a.close(); await b.close()
      })
      await t.test('curl default and basic method offers select only noauth while upstream remains RFC1929', async () => {
        const maximum = Buffer.alloc(257, 1); maximum[0] = 5; maximum[1] = 255; maximum[256] = 0
        for (const greeting of [Buffer.from([5, 2, 0, 1]), Buffer.from([5, 1, 0]), Buffer.from([5, 3, 2, 0, 1]), maximum]) {
          const c = await owner(), u = await core(), f = await front(c, u)
          assert.equal(await handshake(c, f, request(), greeting), true)
          assert.equal(u.stats.authenticated, 1)
          assert.equal(u.stats.requests[0].equals(request()), true)
          assert.equal(f.snapshot().connected, 1)
          await c.close()
        }
      })
      await t.test('fragmented method list and pipelined CONNECT retain every domain byte', async () => {
        const c = await owner(), u = await core(), f = await front(c, u)
        assert.equal((await c.connect(f)).ok, true)
        assert.equal((await c.write(Buffer.from([5, 3]))).ok, true)
        assert.equal((await c.write(Buffer.from([1]))).ok, true)
        assert.equal((await c.write(Buffer.concat([Buffer.from([2, 0]), request()]))).ok, true)
        assert.deepEqual((await c.read(2)).data, Buffer.from([5, 0]))
        assert.deepEqual((await c.read(10)).data, Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]))
        assert.equal(u.stats.authenticated, 1)
        assert.equal(u.stats.requests[0].equals(request()), true)
        await c.close()
      })
      await t.test('unknown same-UID peer and wrong realm never reach upstream', async () => {
        const allowed = await owner(), other = await owner(), u = await core(), otherCore = await core(), f = await front(allowed, u), otherFront = await front(other, otherCore)
        await other.connect(f); await other.write(Buffer.from([5, 2, 0, 1])); assert.equal((await other.read(2)).ok, false)
        assert.equal(u.stats.connections, 0); assert.equal(f.snapshot().connected, 0)
        assert.equal((await other.cmd('CLOSE')).ok, true); assert.equal(await handshake(other, otherFront), true)
        assert.equal(otherCore.stats.authenticated, 1); assert.equal(u.stats.connections, 0); await other.close(); await allowed.close()
      })
      await t.test('real native duplicate descriptors are ambiguous and rejected', async () => {
        const c = await owner(), holding = net.createServer(s => { s.on('error', () => {}); owners.push({ close: async () => s.destroy() }) })
        await new Promise(resolve => holding.listen(0, '127.0.0.1', resolve)); const tuple = await c.cmd(`CONNECT ${holding.address().port}`)
        assert.equal(tuple.ok, true); assert.equal((await c.cmd('DUP')).ok, true)
        const i = c.identity, result = await exec(attestor, ['witness', i.pid, i.birthSec, i.birthUsec, i.uid, i.gid, tuple.clientPort, tuple.frontPort].map(String))
        const receipt = JSON.parse(result.output); assert.equal(receipt.verified, false); assert.equal(receipt.reason, 'AMBIGUOUS_TUPLE')
        await c.close(); await new Promise(resolve => holding.close(resolve))
      })
      await t.test('malformed method, non-CONNECT and incomplete framing have no upstream fallback', async () => {
        for (const mode of ['method', 'command', 'timeout', 'no-methods', 'no-noauth', 'wrong-version', 'partial-methods']) {
          const c = await owner(), u = await core(), f = await front(c, u, { timeoutMs: 150 })
          const greetings = { method: [5, 1, 2], timeout: [5], 'no-methods': [5, 0], 'no-noauth': [5, 2, 1, 2],
            'wrong-version': [4, 1, 0], 'partial-methods': [5, 2, 0] }
          await c.connect(f); await c.write(Buffer.from(greetings[mode] ?? [5, 1, 0]))
          if (mode === 'command') { assert.equal((await c.read(2)).ok, true); await c.write(request(undefined, 3)); assert.equal((await c.read(10)).ok, false) }
          else assert.equal((await c.read(2)).ok, false)
          assert.equal(u.stats.connections, 0); await c.close()
        }
      })
      await t.test('upstream auth failure and attempted noauth downgrade are strict refusals', async () => {
        for (const options of [{ authFailure: true }, { downgrade: true }]) {
          const c = await owner(), u = await core(options), f = await front(c, u)
          assert.equal(await handshake(c, f), false); assert.equal(u.stats.connections, 1); assert.equal(u.stats.requests.length, 0)
          assert.equal(f.snapshot().connected, 0); await c.close()
        }
      })
      await t.test('pending ownership and pending upstream authentication cancel on revocation', async () => {
        let aborted = false
        const c = await owner(), u = await core(), f = await front(c, u, { wrap: native => async input => {
          const result = await native(input)
          if (input.phase === 'before-method-reply') return new Promise(() => input.signal.addEventListener('abort', () => { aborted = true }, { once: true }))
          return result
        } })
        await c.connect(f); await c.write(Buffer.from([5, 1, 0])); await pause(80); f.revoke(c.identity)
        assert.equal((await c.read(2)).ok, false); assert.equal(aborted, true); assert.equal(u.stats.connections, 0); await c.close()
        const c2 = await owner(), u2 = await core({ authStall: true }), f2 = await front(c2, u2)
        await c2.connect(f2); await c2.write(Buffer.from([5, 1, 0])); assert.equal((await c2.read(2)).ok, true); await c2.write(request())
        for (let tries = 0; !u2.stats.authWaiting && tries < 30; tries++) await pause(10)
        assert.equal(u2.stats.authWaiting, true); f2.revoke()
        assert.equal((await c2.read(10)).ok, false); assert.equal(u2.stats.requests.length, 0); assert.equal(f2.snapshot().activeConnections, 0); await c2.close()
      })
      await t.test('live route revocation closes both directions and cannot reopen', async () => {
        const c = await owner(), u = await core(), f = await front(c, u); assert.equal(await handshake(c, f), true)
        f.revoke(); assert.equal((await c.read(1)).ok, false); assert.equal(f.snapshot().activeConnections, 0)
        const other = await owner(); await other.connect(f); await other.write(Buffer.from([5, 1, 0])); assert.equal((await other.read(2)).ok, false)
        assert.equal(u.stats.connections, 1); await c.close(); await other.close()
      })
    } finally {
      await Promise.all(fronts.map(f => f.close())); await Promise.all(owners.map(c => c.close())); await Promise.all(cores.map(u => u.close()))
      assert.equal(clients.size, 0); assert.equal(fronts.every(f => f.snapshot().activeConnections === 0), true)
      await rm(temporary, { recursive: true, force: true })
    }
  })
