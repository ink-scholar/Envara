import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn } from 'node:child_process'
import { constants as fsConstants, fstatSync } from 'node:fs'
import * as fs from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { verifyPFInstallation, PF_INSTALL_ROOT, PF_RUNTIME_ROOT } from './controller.mjs'
import { isPFRoutingRunId } from './policy.mjs'
import { createNotionSOCKSFront } from './notion-socks-front.mjs'

export const NOTION_FRONT_PROTOCOL = 'envara.macos-pf-notion-front/v1'
export const NOTION_ADMISSION_PROTOCOL = 'envara.macos-pf-notion-admission/v1'
const native = `${PF_INSTALL_ROOT}/envara-pf-native`, node = `${PF_INSTALL_ROOT}/node`
const clockSchema = 'envara.macos-pf-app-context-clock/v1', leaseSchema = 'envara.macos-pf-app-bound-lease/v1'
const idKeys = ['runId', 'environmentId', 'leaseId', 'generation']
const leaseKeys = ['schema', 'runId', 'environmentId', 'realmId', 'leaseId', 'generation', 'registrationId', 'versionId', 'consoleUID', 'gid', 'cwd', 'timezone', 'locale', 'issuedMonotonicMs', 'expiresMonotonicMs', 'bootTimeSeconds', 'controllerPid', 'controllerBirth', 'ipv4Address', 'rootHookLease']
const admissionKeys = ['schema', 'operation', ...idKeys, 'leaseSHA256', 'keeperPID', 'keeperBirth', 'frontPID', 'frontBirth', 'frontPort', 'gid', 'filterRevision', 'writerPid', 'profile', 'rulesVerified', 'poolsVerified', 'lo0FilteringVerified', 'originalListenerHeld', 'originalUTunHeld', 'expiresMonotonicMs', 'bootTimeSeconds', 'ready', 'protected']
const proofKeys = ['rulesVerified', 'poolsVerified', 'lo0FilteringVerified', 'originalListenerHeld', 'originalUTunHeld']
const birth = value => typeof value === 'string' && /^[1-9][0-9]{0,19}:[0-9]{6}$/.test(value)
const uint = value => Number.isSafeInteger(value) && value >= 0
const pid = value => Number.isInteger(value) && value >= 2 && value <= 2147483647
const port = value => Number.isInteger(value) && value >= 1 && value <= 65535
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const exact = (value, keys) => object(value) && Object.keys(value).sort().join('|') === [...keys].sort().join('|')
const hash = value => createHash('sha256').update(value).digest('hex')
const fileIdentityKeys = ['device', 'inode', 'size', 'mtimeMs', 'ctimeMs']
const reasons = new Set(['PRIVATE_NATIVE_FRONT_REFUSED', 'BOOTSTRAP_REFUSED', 'INSTALLATION_REFUSED', 'EXECUTION_REFUSED', 'LEASE_REFUSED',
  'NATIVE_IDENTITY_REFUSED', 'NATIVE_CLOCK_REFUSED', 'LISTENER_REFUSED', 'ACTIVATION_REFUSED', 'LEASE_EXPIRED', 'PRIVATE_CHANNEL_LOST'])
const refused = (reason = 'PRIVATE_NATIVE_FRONT_REFUSED') => Object.assign(new Error('Private native front refused'), { code: 'NOTION_FRONT_REFUSED', reason: reasons.has(reason) ? reason : 'PRIVATE_NATIVE_FRONT_REFUSED' })
const fail = reason => { throw refused(reason) }

// These commands are read-only. Arguments, executable, environment, output and
// lifetime are fixed; raw stderr and upstream credentials are never emitted.
async function nativeRead(args) {
  return new Promise((resolve, reject) => {
    let child, bytes = Buffer.alloc(0), settled = false
    const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); bytes.fill(0); error ? reject(refused()) : resolve(value) }
    const timer = setTimeout(() => { try { child?.kill('SIGTERM') } catch {} finish(true) }, 1000)
    try { child = spawn(native, args, { shell: false, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' }, stdio: ['ignore', 'pipe', 'pipe'] }) }
    catch { finish(true); return }
    child.stderr.on('data', () => {})
    child.stdout.on('data', value => { if (settled) return; bytes = Buffer.concat([bytes, value]); if (bytes.length > 4096) { child.kill('SIGTERM'); finish(true) } })
    child.once('error', () => finish(true))
    child.once('close', (code, signal) => {
      if (settled) return
      try { if (code !== 0 || signal) fail(); const value = JSON.parse(bytes.toString('utf8')); finish(null, value) } catch { finish(true) }
    })
  })
}
const nativeIdentity = processId => { if (!pid(processId)) fail(); return nativeRead(['identity', '--pid', String(processId)]) }
const nativeClock = () => nativeRead(['app-context-clock'])

async function executionIdentity() {
  if (process.platform !== 'darwin' || process.getuid?.() !== 0 || process.geteuid?.() !== 0 ||
      process.argv.length !== 3 || process.argv[2] !== '--native-fd3' || process.execArgv.join('|') !== '--no-addons|--disable-proto=throw' ||
      fileURLToPath(import.meta.url) !== `${PF_INSTALL_ROOT}/notion-front-service.mjs` || await fs.realpath(process.execPath) !== node ||
      !fstatSync(0).isFIFO() || !fstatSync(1).isFIFO() || !fstatSync(3).isSocket()) fail('EXECUTION_REFUSED')
  return { pid: process.pid, parentPid: process.ppid }
}

async function privateLease(runId) {
  if (!isPFRoutingRunId(runId) || !fsConstants.O_NOFOLLOW) fail('LEASE_REFUSED')
  const run = path.join(PF_RUNTIME_ROOT, runId), target = path.join(run, 'app-bound-lease.json')
  // Fixed path only, no symlink ancestors or user-writable root objects.
  for (let current = run; ; current = path.dirname(current)) {
    const info = await fs.lstat(current)
    if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o022) || await fs.realpath(current) !== current ||
        ([run, PF_RUNTIME_ROOT].includes(current) && (info.mode & 0o777) !== 0o700)) fail('LEASE_REFUSED')
    if (current === '/') break
  }
  const handle = await fs.open(target, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
  let bytes
  try {
    const before = await handle.stat(), linked = await fs.lstat(target)
    const safe = info => info.isFile() && !info.isSymbolicLink?.() && info.uid === 0 && (info.mode & 0o777) === 0o600 && info.nlink === 1 && info.size > 0 && info.size <= 65536
    if (!safe(before) || !safe(linked) || before.dev !== linked.dev || before.ino !== linked.ino) fail('LEASE_REFUSED')
    bytes = await handle.readFile()
    const after = await handle.stat(), again = await fs.lstat(target)
    if (!safe(after) || !safe(again) || [after, again].some(info => info.dev !== before.dev || info.ino !== before.ino || info.size !== before.size || info.mtimeMs !== before.mtimeMs || info.ctimeMs !== before.ctimeMs) || bytes.length !== before.size) fail('LEASE_REFUSED')
    return { lease: JSON.parse(bytes.toString('utf8')), sha256: hash(bytes), fileIdentity: {
      device: before.dev, inode: before.ino, size: before.size, mtimeMs: before.mtimeMs, ctimeMs: before.ctimeMs,
    } }
  } finally { bytes?.fill(0); await handle.close() }
}

function validateLease(record, context) {
  const value = record?.lease
  if (!exact(value, leaseKeys) || value.schema !== leaseSchema || !/^[0-9a-f]{64}$/.test(record.sha256 ?? '') ||
      !exact(record.fileIdentity, fileIdentityKeys) || fileIdentityKeys.some(key => !Number.isFinite(record.fileIdentity[key]) || record.fileIdentity[key] < 0) ||
      !uint(record.fileIdentity.device) || !uint(record.fileIdentity.inode) || !uint(record.fileIdentity.size) || record.fileIdentity.size < 1 || record.fileIdentity.size > 65536 ||
      [...idKeys, 'realmId', 'registrationId', 'versionId'].some(key => !isPFRoutingRunId(value[key])) || idKeys.some(key => value[key] !== context[key]) ||
      !uint(value.consoleUID) || value.consoleUID < 1 || !Number.isInteger(value.gid) || value.gid < 7100 || value.gid > 7999 || !pid(value.controllerPid) || !birth(value.controllerBirth) ||
      ['issuedMonotonicMs', 'expiresMonotonicMs', 'bootTimeSeconds'].some(key => !uint(value[key])) || value.bootTimeSeconds < 1 ||
      value.expiresMonotonicMs <= value.issuedMonotonicMs || value.expiresMonotonicMs - value.issuedMonotonicMs > 180000 ||
      typeof value.cwd !== 'string' || !value.cwd.startsWith('/') || /[\0\r\n]/.test(value.cwd) ||
      ['timezone', 'locale'].some(key => typeof value[key] !== 'string' || !value[key] || /[\0\r\n]/.test(value[key])) ||
      !['198.18.1.1', '198.18.2.1'].includes(value.ipv4Address) || value.rootHookLease?.runId !== context.runId) fail('LEASE_REFUSED')
  return Object.freeze({ lease: Object.freeze({ ...value }), sha256: record.sha256, fileIdentity: Object.freeze({ ...record.fileIdentity }) })
}
function validateIdentity(value, expectedPid, expectedParent, expectedPath, expectedBirth) {
  if (!object(value) || value.schema !== 'envara.macos-pf-native/v1' || value.ok !== true || value.protected !== false || value.pid !== expectedPid ||
      (expectedParent !== null && value.parentPid !== expectedParent) || value.path !== expectedPath || !birth(value.birth) ||
      (expectedBirth !== null && value.birth !== expectedBirth) || ['uid', 'realUID', 'savedUID'].some(key => value[key] !== 0) ||
      ['gid', 'realGID', 'savedGID'].some(key => !uint(value[key])) || value.gid !== value.realGID || value.gid !== value.savedGID) fail('NATIVE_IDENTITY_REFUSED')
  return Object.freeze({ ...value })
}
function validateClock(value, lease) {
  if (!exact(value, ['schema', 'ok', 'bootTimeSeconds', 'nowMonotonicMilliseconds']) || value.schema !== clockSchema || value.ok !== true ||
      !uint(value.nowMonotonicMilliseconds) || value.bootTimeSeconds !== lease.bootTimeSeconds ||
      value.nowMonotonicMilliseconds < lease.issuedMonotonicMs || value.nowMonotonicMilliseconds >= lease.expiresMonotonicMs) fail('NATIVE_CLOCK_REFUSED')
  return value
}
function bootstrap(line) {
  let value
  try { value = JSON.parse(line) } catch { fail('BOOTSTRAP_REFUSED') }
  if (!exact(value, ['schema', ...idKeys, 'upstream']) || JSON.stringify(value) !== line || value.schema !== NOTION_FRONT_PROTOCOL || idKeys.some(key => !isPFRoutingRunId(value[key])) ||
      !exact(value.upstream, ['host', 'port', 'username', 'password', 'udpPolicy']) || !['127.0.0.1', '::1'].includes(value.upstream.host) || !port(value.upstream.port) ||
      !['block', 'proxy'].includes(value.upstream.udpPolicy) || ['username', 'password'].some(key => typeof value.upstream[key] !== 'string' ||
        Buffer.byteLength(value.upstream[key]) < 1 || Buffer.byteLength(value.upstream[key]) > 255 || /[\0\r\n]/.test(value.upstream[key]))) fail('BOOTSTRAP_REFUSED')
  return value
}

/* Private service entry. Constructor dependencies are for trusted source tests,
 * never parsed from native stdin or renderer RPC. Production has no env/argv
 * override for executable, FD, manifest, identity, clock or lease paths. */
export async function runNotionFrontService({ input = process.stdin, output = process.stdout, inspectInstallation = verifyPFInstallation,
  inspectExecution = executionIdentity, readNativeIdentity = nativeIdentity, readNativeClock = nativeClock, readBoundLease = privateLease,
  createFront = createNotionSOCKSFront, recheckMs = 500 } = {}) {
  if ([inspectInstallation, inspectExecution, readNativeIdentity, readNativeClock, readBoundLease, createFront].some(value => typeof value !== 'function') ||
      !Number.isInteger(recheckMs) || recheckMs < 50 || recheckMs > 500) fail()
  let front, timer, expiryTimer, pending = Buffer.alloc(0), initialized = false, ended = false, failed = false, admission = null, lease, context, own, keeper, execution, launchBootstrap
  let checking = null, cached = null, fixedDeadline = null, phase = 'bootstrap', reason = null, queue = Promise.resolve(), resolveDone
  const monotonic = () => process.hrtime.bigint()
  const safeState = () => ({ ready: false, protected: false, admitted: !!admission && !ended, failed, phase, reason })
  const done = new Promise(resolve => { resolveDone = resolve })
  const stop = async () => {
    if (ended) return; ended = true; admission = null; cached = null; clearInterval(timer); clearTimeout(expiryTimer); pending.fill(0); pending = Buffer.alloc(0)
    if (!failed) { phase = 'closed'; reason = null }
    input.off('data', onData); input.off('end', onEnd); input.off('error', onError); output.off('error', onError)
    input.destroy() // Close only this private duplicate; the native keeper retains original sockets.
    front?.revoke(); await front?.close(); resolveDone(Object.freeze(safeState()))
  }
  const reject = (error, at = 'liveness') => { failed = true; phase = at; reason = reasons.has(error?.reason) ? error.reason : 'PRIVATE_NATIVE_FRONT_REFUSED'
    void stop().catch(() => resolveDone(Object.freeze(safeState()))) }
  const fresh = async (force = false) => {
    if (ended || !initialized) fail()
    const started = monotonic()
    if (fixedDeadline !== null && started >= fixedDeadline) fail('LEASE_EXPIRED')
    if (!force && cached && started - cached.started < BigInt(recheckMs) * 1000000n) return cached.clock
    if (checking) return checking
    checking = (async () => {
      const [parent, self, controller, clock, record, intermediate] = await Promise.all([
        readNativeIdentity(execution.parentPid), readNativeIdentity(execution.pid), readNativeIdentity(lease.lease.controllerPid),
        readNativeClock(), readBoundLease(context.runId), launchBootstrap ? readNativeIdentity(launchBootstrap.pid) : null,
      ])
      validateIdentity(parent, execution.parentPid, keeper.parentPid, native, keeper.birth)
      validateIdentity(self, execution.pid, execution.parentPid, node, own.birth)
      validateIdentity(controller, lease.lease.controllerPid, null, node, lease.lease.controllerBirth)
      if (launchBootstrap) validateIdentity(intermediate, launchBootstrap.pid, lease.lease.controllerPid, '/bin/launchctl', launchBootstrap.birth)
      validateClock(clock, lease.lease)
      const observed = validateLease(record, context)
      if (observed.sha256 !== lease.sha256 || fileIdentityKeys.some(key => observed.fileIdentity[key] !== lease.fileIdentity[key]) || ended) fail('LEASE_REFUSED')
      // Subtract elapsed time from the native clock observation conservatively.
      // Later checks may shorten this deadline, never renew the sealed lease.
      const deadline = started + BigInt(lease.lease.expiresMonotonicMs - clock.nowMonotonicMilliseconds) * 1000000n
      fixedDeadline = fixedDeadline === null || deadline < fixedDeadline ? deadline : fixedDeadline
      const remaining = Number((fixedDeadline - monotonic()) / 1000000n)
      if (remaining <= 0) fail('LEASE_EXPIRED')
      clearTimeout(expiryTimer); expiryTimer = setTimeout(() => reject(refused('LEASE_EXPIRED')), remaining)
      cached = { clock, started }
      return clock
    })().finally(() => { checking = null })
    return checking
  }
  const authorize = async () => {
    if (ended || !admission) return { authorized: false }
    try { await fresh(); if (ended || !admission) fail(); return { authorized: true, kind: 'native-kernel-gid', admission } }
    catch (error) { reject(error); return { authorized: false } }
  }
  async function first(line) {
    const start = bootstrap(line), installation = await inspectInstallation()
    if (installation?.verified !== true || installation.runtimeVerified !== true || ended) fail('INSTALLATION_REFUSED')
    execution = await inspectExecution()
    if (!pid(execution?.pid) || !pid(execution?.parentPid)) fail('EXECUTION_REFUSED')
    context = Object.freeze(Object.fromEntries(idKeys.map(key => [key, start[key]])))
    lease = validateLease(await readBoundLease(context.runId), context)
    const [parent, self] = await Promise.all([readNativeIdentity(execution.parentPid), readNativeIdentity(execution.pid)])
    keeper = validateIdentity(parent, execution.parentPid, null, native, null)
    if (keeper.parentPid !== lease.lease.controllerPid) {
      // launchctl may fork rather than exec. Permit only this fixed, observed
      // root executable directly under the sealed controller, not an arbitrary
      // ancestor chain, and recheck its exact birth throughout this lease.
      if (!pid(keeper.parentPid) || [execution.pid, execution.parentPid].includes(keeper.parentPid)) fail('NATIVE_IDENTITY_REFUSED')
      launchBootstrap = validateIdentity(await readNativeIdentity(keeper.parentPid), keeper.parentPid, lease.lease.controllerPid, '/bin/launchctl', null)
    }
    own = validateIdentity(self, execution.pid, execution.parentPid, node, null)
    initialized = true; await fresh()
    if (ended) fail()
    phase = 'listener'
    try { front = await createFront({ routeContext: context, upstream: start.upstream, authorizeOwnership: authorize, admissionMode: 'native-kernel-gid', listenFD: 3, timeoutMs: 2000, recheckMs }) }
    finally { start.upstream.username = ''; start.upstream.password = '' }
    if (ended || !port(front?.port) || front.host !== '127.0.0.1') { await front?.close(); fail('LISTENER_REFUSED') }
    await fresh()
    const ack = { schema: NOTION_FRONT_PROTOCOL, operation: 'front-started', ...context, pid: execution.pid, host: '127.0.0.1', port: front.port, ready: false, protected: false }
    output.write(`${JSON.stringify(ack)}\n`)
    phase = 'admission'
    timer = setInterval(() => { void fresh(true).catch(error => reject(error)) }, recheckMs)
  }
  async function activate(line) {
    let value
    try { value = JSON.parse(line) } catch { fail('ACTIVATION_REFUSED') }
    // One native admission only. No renewal, alternate authority, heartbeat,
    // proof field from renderer, or prototype tuple may extend the fixed lease.
    if (admission || !front || !exact(value, admissionKeys) || JSON.stringify(value) !== line || value.schema !== NOTION_ADMISSION_PROTOCOL || value.operation !== 'activate' ||
        idKeys.some(key => value[key] !== context[key]) || value.leaseSHA256 !== lease.sha256 || value.keeperPID !== keeper.pid || value.keeperBirth !== keeper.birth ||
        value.frontPID !== own.pid || value.frontBirth !== own.birth || value.frontPort !== front.port || value.gid !== lease.lease.gid ||
        !Number.isInteger(value.filterRevision) || value.filterRevision < 0 || value.filterRevision > 4294967295 || !pid(value.writerPid) || value.writerPid !== keeper.pid ||
        value.profile !== 'seatbelt-front-only' || proofKeys.some(key => value[key] !== true) || value.expiresMonotonicMs !== lease.lease.expiresMonotonicMs ||
        value.bootTimeSeconds !== lease.lease.bootTimeSeconds || value.ready !== false || value.protected !== false) fail('ACTIVATION_REFUSED')
    await fresh(true); if (ended) fail(); admission = Object.freeze({ ...value }); phase = 'liveness'
  }
  const onData = chunk => {
    if (ended) return
    const frameRefused = () => reject(refused(initialized ? 'ACTIVATION_REFUSED' : 'BOOTSTRAP_REFUSED'), initialized ? 'admission' : 'bootstrap')
    pending = Buffer.concat([pending, chunk]); if (pending.length > 16384) { frameRefused(); return }
    let newline
    while ((newline = pending.indexOf(10)) >= 0) {
      const bytes = pending.subarray(0, newline), line = bytes.toString('utf8'); pending = Buffer.from(pending.subarray(newline + 1))
      if (!line || bytes.length > 8192 || line.includes('\r')) { frameRefused(); return }
      queue = queue.then(async () => { if (ended) return; initialized ? await activate(line) : await first(line) }).catch(error => reject(error, initialized && front ? 'admission' : phase))
    }
  }
  const onEnd = () => { void stop() }, onError = () => reject(refused('PRIVATE_CHANNEL_LOST'))
  input.on('data', onData); input.once('end', onEnd); input.once('error', onError); output.once('error', onError)
  return Object.freeze({ done, close: stop, snapshot: () => ({ ...safeState(), closed: ended }) })
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] !== '--native-fd3') process.exitCode = 1
  else {
    const service = await runNotionFrontService()
    const result = await service.done
    if (result.failed) { process.stderr.write(`${JSON.stringify({ schema: 'envara.macos-pf-notion-front-failure/v1', phase: result.phase, reason: result.reason, ready: false, protected: false })}\n`); process.exitCode = 1 }
  }
}
