// DNS transport uses only the selected route's authenticated SOCKS stream.
// A bootstrap IP avoids resolving the DoH endpoint through the host resolver.
import net from 'node:net'
import tls from 'node:tls'
import https from 'node:https'
import { openSocksStream } from './socks-stream.mjs'
import { validateDnsQuery, validateDnsResponse } from './dns-wire.mjs'

const failure = code => Object.assign(new Error('managed DNS request did not complete'), { code })
const tlsErrors = new Set(['DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_TLS_CERT_ALTNAME_INVALID', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'CERT_SIGNATURE_FAILURE'])
export const DNS_FAILURE_CODES = Object.freeze(['DNS_QUERY_INVALID', 'DNS_RESPONSE_INVALID', 'DNS_PROXY_FAILED', 'DNS_TLS_FAILED',
  'DNS_TLS_VERIFY_FAILED', 'DNS_HTTP_INVALID', 'DNS_HTTP_FAILED', 'DNS_RESPONSE_TOO_LARGE', 'DNS_DEADLINE', 'DNS_ABORTED', 'DNS_CAPACITY_EXCEEDED'])
const codes = new Set(DNS_FAILURE_CODES)

export class DnsOverHttpsResolver {
  constructor(options = {}) {
    const allowed = ['bootstrapIP', 'port', 'servername', 'path', 'testCa', 'timeoutMs', 'maxConcurrent']
    if (!options || Object.keys(options).some(key => !allowed.includes(key))) throw failure('DNS_QUERY_INVALID')
    const endpoint = { bootstrapIP: options.bootstrapIP ?? '1.1.1.1', port: options.port ?? 443,
      servername: options.servername ?? 'cloudflare-dns.com', path: options.path ?? '/dns-query' }
    if (!net.isIP(endpoint.bootstrapIP) || endpoint.bootstrapIP.includes('%') || !Number.isInteger(endpoint.port) || endpoint.port < 1 || endpoint.port > 65535 || endpoint.port === 53 ||
        typeof endpoint.servername !== 'string' || endpoint.servername.length > 253 || !/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(endpoint.servername) || net.isIP(endpoint.servername) ||
        typeof endpoint.path !== 'string' || !/^\/[A-Za-z0-9/_-]{1,128}$/.test(endpoint.path)) throw failure('DNS_QUERY_INVALID')
    if (options.testCa !== undefined && !(typeof options.testCa === 'string' || Buffer.isBuffer(options.testCa))) throw failure('DNS_QUERY_INVALID')
    this.endpoint = Object.freeze(endpoint)
    // This constructor is the sole fixture CA injection boundary. No RPC or
    // route parameter can set it, and TLS verification cannot be disabled.
    this.testCa = options.testCa === undefined ? undefined : Buffer.from(options.testCa)
    this.timeoutMs = options.timeoutMs ?? 5000; this.maxConcurrent = options.maxConcurrent ?? 32; this.inFlight = 0
    if (!Number.isInteger(this.timeoutMs) || this.timeoutMs < 50 || this.timeoutMs > 15000 ||
        !Number.isInteger(this.maxConcurrent) || this.maxConcurrent < 1 || this.maxConcurrent > 64) throw failure('DNS_QUERY_INVALID')
  }
  async resolve(proxy, input, { signal } = {}) {
    if (!Buffer.isBuffer(input) || input.length < 12 || input.length > 4096) throw failure('DNS_QUERY_INVALID')
    const query = Buffer.from(input)
    let expected
    try { expected = validateDnsQuery(query) } catch { throw failure('DNS_QUERY_INVALID') }
    if (signal?.aborted) throw failure('DNS_ABORTED')
    if (this.inFlight >= this.maxConcurrent) throw failure('DNS_CAPACITY_EXCEEDED')
    this.inFlight++
    try {
      return await new Promise((resolve, reject) => {
        const aborter = new AbortController(); const sockets = new Set(); let request, response, settled = false, agent
        const finish = (error, data) => {
          if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener('abort', cancelled)
          aborter.abort(); response?.destroy(); request?.destroy(); for (const socket of sockets) socket.destroy(); agent?.destroy()
          if (error) reject(error); else resolve(data)
        }
        const cancelled = () => finish(failure('DNS_ABORTED'))
        const timer = setTimeout(() => finish(failure('DNS_DEADLINE')), this.timeoutMs)
        signal?.addEventListener('abort', cancelled, { once: true })
        if (signal?.aborted) { cancelled(); return }
        agent = new https.Agent({ keepAlive: false, maxSockets: 1, maxCachedSessions: 0 })
        // The agent never calls the default DNS/TCP connector. The SOCKS
        // destination is always the fixed numeric bootstrap address.
        agent.createConnection = (_options, callback) => {
          let callbackSent = false
          const connected = (error, socket) => { if (callbackSent) return; callbackSent = true; callback(error, socket) }
          ;(async () => {
            let stream
            try { stream = await openSocksStream(proxy, { host: this.endpoint.bootstrapIP, port: this.endpoint.port }, this.timeoutMs, { signal: aborter.signal }) }
            catch { throw failure(aborter.signal.aborted ? 'DNS_ABORTED' : 'DNS_PROXY_FAILED') }
            sockets.add(stream.socket)
            if (settled || aborter.signal.aborted || stream.ended || stream.buffered.length) { stream.socket.destroy(); throw failure('DNS_PROXY_FAILED') }
            const secure = tls.connect({ socket: stream.socket, servername: this.endpoint.servername, rejectUnauthorized: true,
              minVersion: 'TLSv1.2', ALPNProtocols: ['http/1.1'], ...(this.testCa === undefined ? {} : { ca: this.testCa }) })
            sockets.add(secure); secure.on('error', () => {})
            await new Promise((accept, refuse) => {
              const cleanup = () => { secure.removeListener('secureConnect', ready); secure.removeListener('error', errored); secure.removeListener('close', closed) }
              const ready = () => { cleanup(); secure.authorized ? accept() : refuse(failure('DNS_TLS_VERIFY_FAILED')) }
              const errored = error => { cleanup(); refuse(failure(tlsErrors.has(error.code) ? 'DNS_TLS_VERIFY_FAILED' : 'DNS_TLS_FAILED')) }
              const closed = () => { cleanup(); refuse(failure(aborter.signal.aborted ? 'DNS_ABORTED' : 'DNS_TLS_FAILED')) }
              secure.once('secureConnect', ready); secure.once('error', errored); secure.once('close', closed); stream.socket.resume()
            })
            if (settled || aborter.signal.aborted) { secure.destroy(); throw failure('DNS_ABORTED') }
            connected(null, secure)
          })().catch(error => { connected(codes.has(error.code) ? error : failure('DNS_TLS_FAILED')); if (!settled) finish(codes.has(error.code) ? error : failure('DNS_TLS_FAILED')) })
        }
        request = https.request({ hostname: this.endpoint.servername, port: this.endpoint.port, servername: this.endpoint.servername,
          path: this.endpoint.path, method: 'POST', agent, maxHeaderSize: 8192,
          headers: { 'Content-Type': 'application/dns-message', Accept: 'application/dns-message', 'Content-Length': query.length, Connection: 'close' } }, incoming => {
          response = incoming
          if (settled) { incoming.destroy(); return }
          const length = incoming.headers['content-length']; const encoding = incoming.headers['content-encoding']
          if (incoming.statusCode !== 200 || incoming.headers['content-type']?.split(';', 1)[0].trim().toLowerCase() !== 'application/dns-message' ||
              (encoding !== undefined && encoding !== 'identity') || (length !== undefined && (!/^\d+$/.test(length) || Number(length) > 65535))) return finish(failure('DNS_HTTP_INVALID'))
          let total = 0; const chunks = []
          incoming.on('data', bytes => { if (settled) return; total += bytes.length; if (total > 65535) finish(failure('DNS_RESPONSE_TOO_LARGE')); else chunks.push(bytes) })
          incoming.once('aborted', () => finish(failure('DNS_HTTP_FAILED'))); incoming.once('error', () => finish(failure('DNS_HTTP_FAILED')))
          incoming.once('end', () => {
            if (settled) return
            const data = Buffer.concat(chunks, total)
            try { validateDnsResponse(data, expected) } catch { return finish(failure('DNS_RESPONSE_INVALID')) }
            finish(null, data)
          })
        })
        request.once('error', error => finish(codes.has(error.code) ? error : failure('DNS_HTTP_FAILED')))
        request.end(query)
      })
    } finally { this.inFlight-- }
  }
}
