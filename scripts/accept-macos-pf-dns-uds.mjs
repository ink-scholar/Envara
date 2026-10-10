import { spawn } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import net from 'node:net'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const dnsDenyProfile = `(version 1)
(allow default)
(deny network-outbound
  (literal "/private/var/run/mDNSResponder")
  (literal "/var/run/mDNSResponder")
  (remote tcp "*:53")
  (remote udp "*:53"))
(deny mach-lookup (global-name "com.apple.dnssd.service"))`

function run(command, args, env = process.env, timeoutMs = 12000) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env, stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = '', stderr = ''
    child.stdout.on('data', data => { stdout += data })
    child.stderr.on('data', data => { stderr += data })
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs)
    child.once('error', error => { clearTimeout(timer); reject(error) })
    child.once('close', (exitCode, signal) => {
      clearTimeout(timer)
      const output = stdout.trim()
      let result = null
      try { result = output ? JSON.parse(output) : null } catch {}
      resolve({ exitCode, signal, result, stderr, ...(result ? {} : { stdout: output }) })
    })
  })
}

async function dnsFingerprint() {
  const result = await run('/usr/sbin/scutil', ['--dns'])
  if (result.exitCode !== 0) throw new Error('Cannot read system resolver configuration')
  return createHash('sha256').update(result.stdout ?? '').digest('hex')
}

export async function probeOwnedDNSUDS() {
  if (process.platform !== 'darwin') throw new Error('This diagnostic requires macOS')
  if (process.getuid() === 0) throw new Error('Run this owned fixture without root')
  const temporary = await mkdtemp('/private/tmp/envara-dns-uds-')
  const binary = path.join(temporary, 'dns-fixture')
  const socketPath = path.join(temporary, 'owned.sock')
  const missingSocketPath = path.join(temporary, 'missing.sock')
  const activeSockets = new Set()
  let requests = []
  const server = net.createServer(socket => {
    activeSockets.add(socket)
    requests.push({ kind: 'connection' })
    socket.on('data', data => {
      requests.push({ kind: 'request', bytes: data.length, op: data.length >= 16 ? data.readUInt32BE(12) : null })
      socket.destroy()
    })
    socket.on('error', () => {})
    socket.once('close', () => activeSockets.delete(socket))
  })
  let before
  try {
    before = await dnsFingerprint()
    const build = await run('clang', [path.join(root, 'native/macos-pf-routing/dns-fixture.c'), '-o', binary, '-framework', 'Network', '-fblocks'])
    if (build.exitCode !== 0) throw new Error(`Owned fixture build failed: ${build.stderr}`)
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socketPath, resolve) })
    const observations = []
    const baseEnv = { ...process.env }
    delete baseEnv.DNSSD_UDS_PATH
    async function observe(name, mode, env, sandboxed = false) {
      requests = []
      // Reserved, random fixture names only; no user destination enters the probe.
      const hostname = `envara-${randomUUID()}.invalid`
      const command = sandboxed ? '/usr/bin/sandbox-exec' : binary
      const args = sandboxed ? ['-p', dnsDenyProfile, binary, mode, hostname] : [mode, hostname]
      const execution = await run(command, args, env)
      observations.push({ name, mode, sandboxed, requests: [...requests], ...execution })
      return observations.at(-1)
    }
    const ordinary = await observe('ordinary-dnssd-control', 'dnssd', baseEnv)
    const ownedDNS = await observe('owned-dnssd', 'dnssd', { ...baseEnv, DNSSD_UDS_PATH: socketPath })
    const ownedGetaddrinfo = await observe('owned-getaddrinfo', 'getaddrinfo', { ...baseEnv, DNSSD_UDS_PATH: socketPath })
    const ownedNetwork = await observe('owned-network-framework', 'network-framework', { ...baseEnv, DNSSD_UDS_PATH: socketPath })
    const missingDNS = await observe('missing-owned-dnssd', 'dnssd', { ...baseEnv, DNSSD_UDS_PATH: missingSocketPath })
    const deniedDNS = await observe('sandbox-dnssd', 'dnssd', baseEnv, true)
    await observe('sandbox-getaddrinfo', 'getaddrinfo', baseEnv, true)
    await observe('sandbox-network-framework', 'network-framework', baseEnv, true)
    const raw = []
    for (const mode of ['dns-udp4', 'dns-tcp4', 'dns-udp6', 'dns-tcp6']) raw.push(await observe(`sandbox-${mode}`, mode, baseEnv, true))
    const after = await dnsFingerprint()
    return {
      checkedAt: new Date().toISOString(), uid: process.getuid(),
      source: 'native/macos-pf-routing/dns-fixture.c', ready: false,
      observationsCompleted: observations.every(item => item.exitCode === 0 && item.signal === null && item.result !== null),
      systemDNSUnchanged: before === after,
      ownedEndpointUsed: ownedDNS.requests.some(event => event.kind === 'connection') && ownedGetaddrinfo.requests.some(event => event.kind === 'connection'),
      missingEndpointRejected: missingDNS.exitCode === 0 && Number.isInteger(missingDNS.result?.status) && missingDNS.result.status !== 0,
      resolverIPCBlocked: ordinary.exitCode === 0 && deniedDNS.exitCode === 0 && ordinary.result?.status === 0 && Number.isInteger(deniedDNS.result?.status) && deniedDNS.result.status !== 0,
      rawPort53Blocked: raw.every(item => item.result?.status === -1 && [1, 13].includes(item.result?.errno)),
      observations,
      limitations: [
        'No user app was launched; this does not qualify original signed Notion.',
        'A private UDS listener accepts and closes fixture requests; it is not a DNS broker.',
        'getaddrinfo failure for an invalid name alone does not prove zero DNS packets.',
        'This probes process sandbox denial, not PF/GID attribution or utun capture.',
        'No packet capture was enabled; no claim of full application or delegated-helper coverage.'
      ]
    }
  } finally {
    for (const socket of activeSockets) socket.destroy()
    if (server.listening) await new Promise(resolve => server.close(resolve))
    await rm(temporary, { recursive: true, force: true })
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await probeOwnedDNSUDS()
  const output = process.argv.find(value => value.startsWith('--output='))?.slice('--output='.length)
  if (output) {
    const destination = path.resolve(output)
    await mkdir(path.dirname(destination), { recursive: true })
    await writeFile(destination, `${JSON.stringify(result, null, 2)}\n`)
  }
  console.log(JSON.stringify(result, null, 2))
  if (!result.observationsCompleted || !result.systemDNSUnchanged || !result.resolverIPCBlocked || !result.rawPort53Blocked) process.exitCode = 1
}
