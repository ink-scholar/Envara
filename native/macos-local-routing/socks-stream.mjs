import net from 'node:net'
import { domainToASCII } from 'node:url'

export function validateManagedProxy(proxy) {
  if (!proxy || !['127.0.0.1', '::1'].includes(proxy.host) || !Number.isInteger(proxy.port) || proxy.port < 1 || proxy.port > 65535) throw new Error('managed loopback SOCKS listener required')
  for (const key of ['username', 'password']) {
    if (typeof proxy[key] !== 'string' || !proxy[key] || Buffer.byteLength(proxy[key]) > 255 || proxy[key].includes('\0')) throw new Error('SOCKS authentication required')
  }
  return Object.freeze({ host: proxy.host, port: proxy.port, username: proxy.username, password: proxy.password })
}

export class SocketReader {
  constructor(socket, maxBuffered = 256 * 1024) {
    this.socket = socket; this.maxBuffered = maxBuffered; this.parts = []; this.length = 0; this.pending = null; this.failure = null
    this.bufferPause = false; this.highWaterMark = Math.floor(maxBuffered / 2)
    this.onData = bytes => {
      if (this.length + bytes.length > this.maxBuffered) return this.fail(new Error('socket buffer bound exceeded'))
      this.parts.push(bytes); this.length += bytes.length; this.fulfil()
      // Original NE begins copying the upload immediately after NewFlow. Apply
      // readable backpressure while identity/SOCKS work is pending, retaining
      // only a bounded prefix instead of treating a large upload as malformed.
      if (this.length >= this.highWaterMark && (!this.pending || this.length >= this.pending.length)) {
        this.bufferPause = true; this.socket.pause()
      }
    }
    this.onError = () => this.fail(new Error('socket transport failed'))
    this.ended = false
    this.onEnd = () => { this.ended = true; if (this.pending && this.length < this.pending.length) this.fail(new Error('socket ended before handshake completed')) }
    socket.on('data', this.onData); socket.on('error', this.onError); socket.on('end', this.onEnd); socket.on('close', this.onEnd)
  }
  fail(error) {
    if (!this.failure) this.failure = error
    if (this.pending) { const pending = this.pending; this.pending = null; pending.reject(this.failure) }
  }
  fulfil() {
    if (!this.pending || this.length < this.pending.length) return
    const pending = this.pending; this.pending = null; const bytes = Buffer.concat(this.parts, this.length)
    const result = bytes.subarray(0, pending.length); const rest = bytes.subarray(pending.length)
    this.parts = rest.length ? [rest] : []; this.length = rest.length; pending.resolve(result)
    if (this.bufferPause && this.length < this.highWaterMark) { this.bufferPause = false; this.socket.resume() }
  }
  read(length) {
    if (!Number.isInteger(length) || length < 0 || length > this.maxBuffered || this.pending) return Promise.reject(new Error('invalid socket read'))
    if (this.failure) return Promise.reject(this.failure)
    if (this.ended && this.length < length) return Promise.reject(new Error('socket ended before handshake completed'))
    return new Promise((resolve, reject) => {
      this.pending = { length, resolve, reject }; this.fulfil()
      if (this.bufferPause && this.pending && this.length < length) { this.bufferPause = false; this.socket.resume() }
    })
  }
  release() {
    if (this.pending) throw new Error('socket read still pending')
    this.socket.pause()
    this.socket.removeListener('data', this.onData); this.socket.removeListener('error', this.onError); this.socket.removeListener('end', this.onEnd); this.socket.removeListener('close', this.onEnd)
    const bytes = Buffer.concat(this.parts, this.length); this.parts = []; this.length = 0
    return bytes
  }
}

function targetBytes(host, port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535 || port === 53) throw new Error('DNS requires a verified resolver adapter')
  const suffix = Buffer.alloc(2); suffix.writeUInt16BE(port)
  if (net.isIP(host) === 4) return Buffer.concat([Buffer.from([1, ...host.split('.').map(Number)]), suffix])
  if (net.isIP(host) === 6) {
    if (host.includes('%')) throw new Error('scoped destination unsupported')
    // URL canonicalisation produces a valid compressed IPv6 address without DNS.
    const canonical = new URL(`http://[${host}]/`).hostname.slice(1, -1)
    const [left, right] = canonical.split('::'); const first = left ? left.split(':') : []; const last = right ? right.split(':') : []
    const groups = canonical.includes('::') ? [...first, ...Array(8 - first.length - last.length).fill('0'), ...last] : first
    if (groups.length !== 8) throw new Error('invalid IPv6 destination')
    const address = Buffer.alloc(16); groups.forEach((group, i) => address.writeUInt16BE(parseInt(group, 16), i * 2))
    return Buffer.concat([Buffer.from([4]), address, suffix])
  }
  const domain = domainToASCII(host)
  if (!domain || domain.length > 253 || domain.includes('\0') || !/^[a-zA-Z0-9.-]+$/.test(domain)) throw new Error('invalid destination')
  return Buffer.concat([Buffer.from([3, Buffer.byteLength(domain)]), Buffer.from(domain), suffix])
}
function waitConnected(socket) {
  return new Promise((resolve, reject) => {
    const connected = () => { cleanup(); resolve() }; const failed = () => { cleanup(); reject(new Error('managed proxy unavailable')) }
    const cleanup = () => { socket.removeListener('connect', connected); socket.removeListener('error', failed); socket.removeListener('close', failed); socket.removeListener('end', failed) }
    socket.once('connect', connected); socket.once('error', failed); socket.once('close', failed); socket.once('end', failed)
    if (socket.destroyed) failed()
  })
}
export async function openSocksStream(proxyInput, destination, timeoutMs = 5000, { signal } = {}) {
  const proxy = validateManagedProxy(proxyInput); const target = targetBytes(destination.host, destination.port)
  if (signal?.aborted) throw new Error('route revoked')
  const socket = net.createConnection({ host: proxy.host, port: proxy.port, allowHalfOpen: true })
  socket.on('error', () => {}) // Error may arrive between handshake and caller piping.
  const reader = new SocketReader(socket); const timer = setTimeout(() => socket.destroy(new Error('proxy handshake deadline')), timeoutMs)
  const abort = () => socket.destroy(new Error('route revoked'))
  signal?.addEventListener('abort', abort, { once: true })
  try {
    await waitConnected(socket)
    socket.write(Buffer.from([5, 1, 2]))
    if (!(await reader.read(2)).equals(Buffer.from([5, 2]))) throw new Error('proxy refused required authentication')
    const username = Buffer.from(proxy.username); const password = Buffer.from(proxy.password)
    socket.write(Buffer.concat([Buffer.from([1, username.length]), username, Buffer.from([password.length]), password]))
    if (!(await reader.read(2)).equals(Buffer.from([1, 0]))) throw new Error('proxy authentication failed')
    socket.write(Buffer.concat([Buffer.from([5, 1, 0]), target]))
    const reply = await reader.read(4)
    if (reply[0] !== 5 || reply[1] !== 0 || reply[2] !== 0) throw new Error('proxy connect failed')
    if (reply[3] === 1) await reader.read(6)
    else if (reply[3] === 4) await reader.read(18)
    else if (reply[3] === 3) { const length = (await reader.read(1))[0]; if (!length) throw new Error('invalid proxy reply'); await reader.read(length + 2) }
    else throw new Error('invalid proxy reply address')
    const buffered = reader.release(); if (reader.failure) throw new Error('proxy transport failed'); clearTimeout(timer); signal?.removeEventListener('abort', abort)
    return { socket, buffered, ended: reader.ended }
  } catch (error) {
    clearTimeout(timer); signal?.removeEventListener('abort', abort); if (reader.pending) reader.fail(new Error('handshake aborted'))
    try { reader.release() } catch {}
    socket.destroy(); throw error
  }
}

export async function authenticateManagedProxy(proxyInput, timeoutMs = 5000) {
  const proxy = validateManagedProxy(proxyInput)
  const socket = net.createConnection({ host: proxy.host, port: proxy.port })
  socket.on('error', () => {})
  const reader = new SocketReader(socket); const timer = setTimeout(() => socket.destroy(new Error('proxy authentication deadline')), timeoutMs)
  try {
    await waitConnected(socket); socket.write(Buffer.from([5, 1, 2]))
    if (!(await reader.read(2)).equals(Buffer.from([5, 2]))) throw new Error('proxy refused required authentication')
    const username = Buffer.from(proxy.username); const password = Buffer.from(proxy.password)
    socket.write(Buffer.concat([Buffer.from([1, username.length]), username, Buffer.from([password.length]), password]))
    if (!(await reader.read(2)).equals(Buffer.from([1, 0]))) throw new Error('proxy authentication failed')
    return true
  } finally {
    clearTimeout(timer); if (reader.pending) reader.fail(new Error('handshake aborted'))
    try { reader.release() } catch {}
    socket.destroy()
  }
}
