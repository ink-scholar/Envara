import { spawn } from 'node:child_process'
import { lstat, realpath } from 'node:fs/promises'
import { notionSOCKSError } from './notion-socks-reader.mjs'

// Own-fixture authorizer only. No default registry; native tuple snapshots are
// useful evidence but deliberately do not qualify a production controller.
export async function createNotionOwnedFixtureAuthorizer({ binaryPath, routeContext, identities, timeoutMs = 500 } = {}) {
  if (process.platform !== 'darwin' || process.getuid?.() === 0 || !Array.isArray(identities) || !identities.length || identities.length > 16 ||
      !routeContext?.routeId || !Number.isSafeInteger(routeContext.registryEpoch) || !Number.isInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 2000) throw notionSOCKSError('ATTESTOR_OPTIONS')
  const binary = await realpath(binaryPath), stat = await lstat(binary)
  if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o022)) throw notionSOCKSError('ATTESTOR_RESOURCE')
  const registry = identities.map(identity => {
    if (!Number.isInteger(identity.pid) || identity.pid < 2 || identity.uid !== process.getuid() || !Number.isInteger(identity.gid) ||
        !Number.isSafeInteger(identity.birthSec) || identity.birthSec < 1 || !Number.isInteger(identity.birthUsec) || identity.birthUsec < 0 || identity.birthUsec > 999999) throw notionSOCKSError('ATTESTOR_REGISTRY')
    return Object.freeze({ ...identity })
  })
  if (new Set(registry.map(identity => identity.pid)).size !== registry.length) throw notionSOCKSError('ATTESTOR_AMBIGUOUS_REGISTRY')
  async function inspect(identity, tuple, signal) {
    if (signal.aborted) throw notionSOCKSError('REVOKED')
    return new Promise((resolve, reject) => {
      const child = spawn(binary, ['witness', identity.pid, identity.birthSec, identity.birthUsec, identity.uid, identity.gid,
        tuple.clientPort, tuple.frontPort].map(String), { stdio: ['ignore', 'pipe', 'pipe'] })
      let output = '', excessive = false, timedOut = false
      const onAbort = () => child.kill('SIGTERM')
      signal.addEventListener('abort', onAbort, { once: true })
      const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL') }, timeoutMs)
      child.stdout.on('data', bytes => { output += bytes.toString('utf8'); if (output.length > 4096) { excessive = true; child.kill('SIGKILL') } })
      child.stderr.on('data', () => {})
      child.once('error', () => { clearTimeout(timer); signal.removeEventListener('abort', onAbort); reject(notionSOCKSError('ATTESTOR_FAILED')) })
      child.once('close', (exitCode, killed) => {
        clearTimeout(timer); signal.removeEventListener('abort', onAbort)
        if (signal.aborted || timedOut || excessive || exitCode !== 0 || killed) { reject(notionSOCKSError('ATTESTOR_UNREADABLE')); return }
        try { resolve(JSON.parse(output)) } catch { reject(notionSOCKSError('ATTESTOR_UNREADABLE')) }
      })
    })
  }
  return async request => {
    if (request.routeContext.routeId !== routeContext.routeId || request.routeContext.environmentId !== routeContext.environmentId ||
        request.routeContext.registryEpoch !== routeContext.registryEpoch || request.tuple.clientHost !== '127.0.0.1' || request.tuple.frontHost !== '127.0.0.1') return { authorized: false }
    const results = await Promise.all(registry.map(identity => inspect(identity, request.tuple, request.signal)))
    // Unknown/ambiguous/changed/unreadable registrants never become authorization.
    if (results.some(result => !result.verified && result.reason !== 'TUPLE_UNMATCHED')) return { authorized: false }
    const matching = results.filter(result => result.verified)
    if (matching.length !== 1) return { authorized: false }
    const result = matching[0]
    return { authorized: true, registered: true, routeId: routeContext.routeId, registryEpoch: routeContext.registryEpoch,
      identity: result.identity, witness: result.witness }
  }
}
