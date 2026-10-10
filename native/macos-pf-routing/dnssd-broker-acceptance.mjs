import { spawn } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { chmod, mkdtemp, rm, lstat, mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createOwnedDNSSDBroker } from './dnssd-broker.mjs'
import { DNSSD_ERROR, DNSSD_PROTOCOL_SOURCE } from './dnssd-broker-protocol.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(here, '../..')
// Existing daemon IPC and direct port 53 are denied only in each owned child.
// This does not alter the host sandbox, resolver configuration, or PF rules.
const dnsDenyProfile = `(version 1)
(allow default)
(deny network-outbound
  (literal "/private/var/run/mDNSResponder")
  (literal "/var/run/mDNSResponder")
  (remote tcp "*:53")
  (remote udp "*:53"))`

function run(command, args, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = '', stderr = ''
    child.stdout.on('data', data => { stdout += data; if (stdout.length > 1000000) child.kill('SIGKILL') })
    child.stderr.on('data', data => { stderr += data; if (stderr.length > 1000000) child.kill('SIGKILL') })
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs)
    child.once('error', error => { clearTimeout(timer); reject(error) })
    child.once('close', (exitCode, signal) => { clearTimeout(timer); resolve({ exitCode, signal, stdout, stderr }) })
  })
}
async function dnsFingerprint() {
  const result = await run('/usr/sbin/scutil', ['--dns'])
  if (result.exitCode !== 0) throw new Error('DNS_STATUS_UNAVAILABLE')
  return createHash('sha256').update(result.stdout).digest('hex')
}
function beginFixture(binary, broker, mode, name, processes, sandboxed = false) {
  let readyResolve, readyReject, doneResolve
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject })
  const done = new Promise(resolve => { doneResolve = resolve })
  const env = { ...process.env, DNSSD_UDS_PATH: broker.socketPath }
  const child = spawn(sandboxed ? '/usr/bin/sandbox-exec' : binary,
    sandboxed ? ['-p', dnsDenyProfile, binary, mode, name] : [mode, name], { env, stdio: ['pipe', 'pipe', 'pipe'] })
  processes.add(child)
  let buffer = '', result = null, outputInvalid = false
  child.stdout.on('data', data => {
    buffer += data.toString('utf8')
    if (buffer.length > 8192) { outputInvalid = true; child.kill('SIGKILL'); return }
    let index
    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index); buffer = buffer.slice(index + 1)
      let event
      try { event = JSON.parse(line) } catch { outputInvalid = true; child.kill('SIGKILL'); return }
      if (event.kind === 'ready') readyResolve(event)
      else if (event.kind === 'result') result = event
      else outputInvalid = true
    }
  })
  child.stderr.on('data', () => {})
  child.stdin.on('error', () => {})
  const timer = setTimeout(() => child.kill('SIGKILL'), 10000)
  child.once('error', () => readyReject(new Error('FIXTURE_START_FAILED')))
  child.once('close', (exitCode, signal) => {
    clearTimeout(timer); processes.delete(child); readyReject(new Error('FIXTURE_EXITED'))
    doneResolve({ exitCode, signal, outputInvalid, result })
  })
  return { child, ready, done, async go(register = true) {
    const identity = await ready
    if (register) await broker.registerPeer(identity)
    child.stdin.end('GO\n')
    return done
  } }
}
const complete = result => result.exitCode === 0 && result.signal === null && !result.outputInvalid && result.result !== null
const hasAnswers = (result, answers) => complete(result) && result.result.status === 0 && result.result.callbackError === 0 &&
  JSON.stringify([...result.result.addresses].sort()) === JSON.stringify([...answers].sort())

export async function probeOwnedDNSSDBroker({ onCheck = () => {} } = {}) {
  if (process.platform !== 'darwin' || process.getuid() === 0) throw new Error('UNPRIVILEGED_MAC_REQUIRED')
  const temporary = await mkdtemp('/private/tmp/envara-dnssd-broker-'); await chmod(temporary, 0o700)
  const frontPath = path.join(temporary, 'dnssd-front'), fixturePath = path.join(temporary, 'dnssd-fixture')
  const processes = new Set(), brokers = [], checks = [], observations = []
  const beforeEnvironment = process.env.DNSSD_UDS_PATH, beforeDNS = await dnsFingerprint()
  let cleanup = null
  const check = (name, passed, details = {}) => { const item = { name, passed: Boolean(passed), ...details }; checks.push(item); onCheck(item) }
  async function broker(label, resolver, timeoutMs = 400) {
    let instance
    try { instance = await createOwnedDNSSDBroker({ frontPath, fixturePath, socketPath: path.join(temporary, `${label}.sock`),
      routeContext: { routeId: randomUUID(), environmentId: randomUUID() }, resolver, timeoutMs }) }
    catch (error) { throw new Error(`${label}: ${error.code ?? 'BROKER_FAILURE'}`) }
    brokers.push(instance); return instance
  }
  const A = Buffer.from([192, 0, 2, 10]), B = Buffer.from([198, 51, 100, 20])
  const AAAA = Buffer.from('20010db8000000000000000000000010', 'hex'), BBBB = Buffer.from('20010db8000000000000000000000020', 'hex')
  const syntheticName = `envara-${randomUUID()}.invalid`
  try {
    for (const [source, binary] of [['dnssd-broker-front.c', frontPath], ['dnssd-broker-fixture.c', fixturePath]]) {
      const build = await run('/usr/bin/clang', ['-Wall', '-Wextra', '-Werror', path.join(here, source), '-o', binary])
      if (build.exitCode !== 0) throw new Error(`OWNED_FIXTURE_BUILD_FAILED: ${build.stderr.slice(0, 1000)}`)
      await chmod(binary, 0o700)
    }
    let callsA = 0, callsB = 0, routeProofsValid = true
    const routeA = await broker('realm-a', async query => { callsA++; routeProofsValid &&= query.peer.nativePeerVerified && query.peer.routeId === routeA.routeContext.routeId; return { A: [A], AAAA: [AAAA] } })
    const routeB = await broker('realm-b', async query => { callsB++; routeProofsValid &&= query.peer.nativePeerVerified && query.peer.routeId === routeB.routeContext.routeId; return { A: [B], AAAA: [BBBB] } })
    for (const [mode, expected] of [['wire-query', ['192.0.2.10']], ['wire-query6', ['2001:db8::10']], ['wire-shared-query', ['192.0.2.10']],
      ['wire-addrinfo', ['192.0.2.10', '2001:db8::10']]]) {
      const result = await beginFixture(fixturePath, routeA, mode, syntheticName, processes).go()
      check(`native-${mode}`, hasAnswers(result, expected) && result.result.ownedEndpoint === 1, { status: result.result?.status ?? null, callbackError: result.result?.callbackError ?? null,
        answerCount: result.result?.addresses.length ?? 0, sandboxedDefaultDNSUDSAndPort53Denied: false })
    }
    const [first, second] = await Promise.all([
      beginFixture(fixturePath, routeA, 'wire-addrinfo', syntheticName, processes).go(),
      beginFixture(fixturePath, routeB, 'wire-addrinfo', syntheticName, processes).go(),
    ])
    check('concurrent-same-name-two-realms', hasAnswers(first, ['192.0.2.10', '2001:db8::10']) && hasAnswers(second, ['198.51.100.20', '2001:db8::20']),
      { sameName: true, independentUDS: routeA.socketPath !== routeB.socketPath, distinctRouteContext: routeA.routeContext.routeId !== routeB.routeContext.routeId })
    const callsBeforeRefusal = callsA
    for (const mode of ['wire-unsupported', 'wire-multicast-flags']) {
      const result = await beginFixture(fixturePath, routeA, mode, syntheticName, processes).go()
      check(`refuse-${mode}`, complete(result) && result.result.status === DNSSD_ERROR.unsupported && callsA === callsBeforeRefusal)
    }
    const unregistered = await beginFixture(fixturePath, routeA, 'wire-query', syntheticName, processes).go(false)
    check('native-reject-unregistered-peer', complete(unregistered) && unregistered.result.status !== 0 && routeA.snapshot().peerRejected > 0 && callsA === callsBeforeRefusal)
    const invalidHeader = await beginFixture(fixturePath, routeA, 'wire-invalid-header', syntheticName, processes).go()
    check('native-refuse-oversized-frame-before-resolver', complete(invalidHeader) && invalidHeader.result.status !== 0 && callsA === callsBeforeRefusal)
    const crossRoute = beginFixture(fixturePath, routeB, 'wire-query', syntheticName, processes)
    await routeA.registerPeer(await crossRoute.ready)
    const crossRouteResult = await crossRoute.go(false)
    check('native-route-bound-peer-cannot-use-other-realm', complete(crossRouteResult) && crossRouteResult.result.status !== 0 && routeB.snapshot().peerRejected > 0 && callsA === callsBeforeRefusal)
    const wrongBirth = beginFixture(fixturePath, routeA, 'wire-query', syntheticName, processes)
    const identity = await wrongBirth.ready
    let rejectedBirth = false
    try { await routeA.registerPeer({ ...identity, birthUsec: (identity.birthUsec + 1) % 1000000 }) } catch (error) { rejectedBirth = error.code === 'PEER_REGISTRATION_REFUSED' }
    wrongBirth.child.stdin.end('GO\n'); const wrongBirthResult = await wrongBirth.done
    check('native-reject-wrong-birth', rejectedBirth && complete(wrongBirthResult) && wrongBirthResult.result.status !== 0)
    const missing = await broker('missing', async () => ({ A: [], AAAA: [] }))
    const missingResult = await beginFixture(fixturePath, missing, 'wire-query', syntheticName, processes).go()
    check('native-wire-negative-answer', complete(missingResult) && missingResult.result.callbackError === DNSSD_ERROR.noSuchRecord && missingResult.result.addresses.length === 0)
    const dead = await broker('dead', async () => { throw new Error('FIXTURE_RESOLVER_DEAD') })
    const deadResult = await beginFixture(fixturePath, dead, 'wire-query', syntheticName, processes).go()
    check('dead-resolver-no-fallback', complete(deadResult) && deadResult.result.status === DNSSD_ERROR.unsupported && dead.snapshot().resolverFailed === 1 && dead.snapshot().activeRequests === 0)
    let timeoutAborted = false
    const stalled = await broker('stalled', query => new Promise(() => { query.signal.addEventListener('abort', () => { timeoutAborted = true }, { once: true }) }), 150)
    const stalledResult = await beginFixture(fixturePath, stalled, 'wire-query', syntheticName, processes).go()
    check('stalled-resolver-bounded-no-fallback', complete(stalledResult) && stalledResult.result.status === DNSSD_ERROR.timeout && timeoutAborted && stalled.snapshot().activeRequests === 0)
    let closeAborted = false, enteredResolve
    const entered = new Promise(resolve => { enteredResolve = resolve })
    const closing = await broker('closing', query => new Promise(() => { enteredResolve(); query.signal.addEventListener('abort', () => { closeAborted = true }, { once: true }) }), 1000)
    const pendingFixture = beginFixture(fixturePath, closing, 'wire-query', syntheticName, processes)
    const pendingResult = pendingFixture.go()
    let enterTimer
    const resolverEntered = await Promise.race([entered.then(() => true), pendingResult.then(() => false),
      new Promise(resolve => { enterTimer = setTimeout(() => resolve(false), 2000) })])
    clearTimeout(enterTimer)
    const closeReceipt = await closing.close(), closedResult = await pendingResult
    check('close-in-flight-cleans-owned-clients', resolverEntered && closeAborted && closeReceipt.ownedFrontExited && closeReceipt.activeRequests === 0 && complete(closedResult) && closedResult.result.status !== 0)
    check('authoritative-native-route-context-proof', routeProofsValid && callsA > 0 && callsB > 0)
    const requestsBeforeSystemProbe = routeA.snapshot().requests
    const systemConnection = await beginFixture(fixturePath, routeA, 'connection', syntheticName, processes).go()
    check('stock-libdns-custom-UDS-unsupported', complete(systemConnection) && systemConnection.result.status === 0 &&
      systemConnection.result.ownedEndpoint === 0 && routeA.snapshot().requests === requestsBeforeSystemProbe,
      { supported: false, stockLibraryReturnedSuccess: systemConnection.result?.status === 0,
        ownedEndpointUsed: systemConnection.result?.ownedEndpoint === 1, reason: 'SYSTEM_LIBRARY_DOES_NOT_USE_DNSSD_UDS_PATH' })
    const systemGetaddrinfo = await beginFixture(fixturePath, routeA, 'getaddrinfo', syntheticName, processes, true).go()
    check('stock-getaddrinfo-positive-remains-unverified', complete(systemGetaddrinfo) && systemGetaddrinfo.result.status !== 0 &&
      routeA.snapshot().requests === requestsBeforeSystemProbe, { supported: false, status: systemGetaddrinfo.result?.status ?? null,
        sandboxedDefaultDNSUDSAndPort53Denied: true, ownedEndpointUsed: false })
    const sandboxResult = await beginFixture(fixturePath, routeA, 'query', syntheticName, processes, true).go()
    check('sandbox-denial-boundary-is-explicit', complete(sandboxResult) && sandboxResult.result.status === -65563,
      { supported: false, reason: 'LIBDNS_POLICY_DENIES_CUSTOM_UDS_WHEN_DEFAULT_DNS_ACCESS_DENIED' })
    for (const instance of brokers) observations.push({ context: instance.routeContext, ...instance.snapshot() })
  } finally {
    const exits = await Promise.all(brokers.map(instance => instance.close()))
    for (const child of processes) { child.stdin.end(); child.kill('SIGTERM') }
    await Promise.all([...processes].map(child => new Promise(resolve => { child.once('close', resolve); setTimeout(() => child.kill('SIGKILL'), 500).unref() })))
    const pathsRemoved = await Promise.all(brokers.map(instance => lstat(instance.socketPath).then(() => false, error => error.code === 'ENOENT')))
    cleanup = { ownedFrontsExited: exits.every(item => item.ownedFrontExited && item.exitCode === 0 && !item.signal),
      activeRequests: exits.reduce((sum, item) => sum + item.activeRequests, 0), ownedFixturesRemaining: processes.size, socketPathsRemoved: pathsRemoved.every(Boolean) }
    await rm(temporary, { recursive: true, force: true })
  }
  check('owned-process-and-socket-cleanup', cleanup.ownedFrontsExited && cleanup.activeRequests === 0 && cleanup.ownedFixturesRemaining === 0 && cleanup.socketPathsRemoved)
  check('system-DNS-and-parent-environment-unchanged', beforeDNS === await dnsFingerprint() && beforeEnvironment === process.env.DNSSD_UDS_PATH)
  return { checkedAt: new Date().toISOString(), acceptanceOnly: true, ready: false, productionReady: false,
    networkFrameworkCovered: false, hostResolverFallback: false, systemDNSRouteSupported: false, stockGetaddrinfoPositivePassed: false,
    supportedScope: 'independent native DNS-SD IPC fixtures; not stock libdns_sd/getaddrinfo routing',
    protocolSource: DNSSD_PROTOCOL_SOURCE, passed: checks.every(item => item.passed), checks, cleanup, observations,
    limitations: ['The stock macOS library did not use DNSSD_UDS_PATH. System DNS routing is unsupported; production bindings/gates remain closed.',
      'No Network.framework, user app, delegated helper, PF/GID, utun, or production launch acceptance.',
      'Only injected deterministic A/AAAA answers were tested; no upstream proxy DNS transport is implemented here.',
      'Unsupported opcodes/flags/TLVs are refused; no multicast, resolver override, DNSSEC, or privacy guarantee.',
      'Positive native wire fixtures bypass the system resolver by design; they are protocol tests, not libdns/getaddrinfo success.',
      'No packet capture was enabled; delegated resolver traffic coverage is not claimed.'] }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await probeOwnedDNSSDBroker()
  const output = process.argv.find(value => value.startsWith('--output='))?.slice('--output='.length)
  if (output) {
    const destination = path.resolve(output), artifactRoot = path.join(root, 'test-artifacts/mac-routing')
    if (!destination.startsWith(`${artifactRoot}${path.sep}`)) throw new Error('OWNED_ARTIFACT_PATH_REQUIRED')
    await mkdir(path.dirname(destination), { recursive: true }); await writeFile(destination, JSON.stringify(result, null, 2) + '\n')
  }
  console.log(JSON.stringify(result, null, 2))
  if (!result.passed) process.exitCode = 1
}
