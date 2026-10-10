import fs from 'node:fs/promises'
import path from 'node:path'
import { randomUUID } from 'node:crypto'
import { spawn } from 'node:child_process'
import { inspectDependency, hasOriginalExtensionAuthorization, lock } from './dependency.mjs'
import { createNativeInspector } from './native-identity.mjs'
import { RedirectorFlowBridge } from './flow-bridge.mjs'
import { validateManagedProxy, authenticateManagedProxy } from './socks-stream.mjs'
import { RoutingDiagnostics } from './diagnostics.mjs'
import { DnsOverHttpsResolver } from './dns-doh.mjs'

const fail = (code, message) => Object.assign(new Error(message), { code })
const emptyChecks = () => ({ tcp: false, udp: false, dns: false, childProcesses: false, failClosed: false })
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(value)

export class MacOSLocalRoutingAdapter {
  constructor({ peerVerifierPath, appPath = lock.installedAppPath, bundledAppPath, onEvent = () => {}, activationTimeoutMs = 120000, dnsResolverOptions } = {}) {
    this.peerVerifierPath = peerVerifierPath; this.appPath = appPath; this.bundledAppPath = bundledAppPath; this.onEvent = onEvent; this.activationTimeoutMs = activationTimeoutMs
    this.native = peerVerifierPath ? createNativeInspector(peerVerifierPath) : null
    this.routes = new Map(); this.bindings = new Map(); this.seenPids = new Set(); this.bridge = null; this.directory = null
    this.starting = false; this.closed = false; this.fault = null; this.lockHandle = null; this.lockPath = null; this.helper = null
    this.queue = Promise.resolve()
    this.identityTimer = null; this.identityRefreshPending = false
    this.dnsResolver = new DnsOverHttpsResolver(dnsResolverOptions)
    this.diagnostics = new RoutingDiagnostics((pid, sessionId) => pid == null ? [...this.bindings.values()].find(binding => binding.sessionId === sessionId) : this.bindings.get(pid))
  }
  serialized(operation) {
    const result = this.queue.then(operation); this.queue = result.catch(() => {}); return result
  }
  notify(type, detail = {}) { try { this.onEvent({ type, ...detail }) } catch {} }
  async status() {
    const installedDependency = await inspectDependency({ appPath: this.appPath })
    const bundledDependency = !installedDependency.present && typeof this.bundledAppPath === 'string' && path.isAbsolute(this.bundledAppPath)
      ? await inspectDependency({ appPath: this.bundledAppPath }) : null
    const dependency = bundledDependency?.binaryVerified ? bundledDependency : installedDependency
    let nativeVerifierAvailable = false
    try { nativeVerifierAvailable = !!this.native && (await fs.stat(this.peerVerifierPath)).isFile() } catch {}
    const controlConnected = !!this.bridge?.control && !this.bridge.control.destroyed && !this.bridge.faulted
    const authorized = hasOriginalExtensionAuthorization(installedDependency.systemExtensions)
    const nativeTcpObserved = (this.bridge?.metrics.tcpConnected ?? 0) > 0
    const checks = emptyChecks()
    return {
      platform: process.platform, installed: installedDependency.binaryVerified && nativeVerifierAvailable,
      dependencyVerified: dependency.binaryVerified, externalOriginal: dependency.binaryVerified,
      authorized, ready: false, protectedLaunchAllowed: false,
      mode: 'signed-external-experimental', sourceVersion: lock.version, sourceCommit: lock.sourceCommit,
      capabilities: { ...checks, tcp: controlConnected && nativeTcpObserved, streamBridge: true, capture: controlConnected, udpBlocking: true,
        dnsTransport: true, diagnosticDnsForwarding: controlConnected && this.bridge?.diagnosticDnsForwarding === true },
      verification: { passed: false, version: `mitmproxy-macos/${lock.version}`, checks, nativeTcpObserved, controlAcknowledged: false, compatibilityVerified: false },
      capture: { controlConnected, starting: this.starting, metrics: this.bridge ? { ...this.bridge.metrics } : null, fault: this.fault },
      component: { name: 'mitmproxy-redirector', version: lock.version, available: installedDependency.present || !!bundledDependency?.present,
        verified: dependency.binaryVerified, installed: installedDependency.binaryVerified },
      dependency, installedDependency, nativeVerifierAvailable,
      sessions: [...this.bindings.values()].map(binding => ({ sessionId: binding.sessionId, routeId: binding.routeId, pid: binding.pid, birth: binding.birth, status: binding.active ? 'capture-test' : 'revoked' })),
      reason: this.fault ?? 'Production launch awaits application-family acceptance, resolver-cache compatibility, a scope barrier and persistent failure blocking',
    }
  }
  async setup() { return this.status() }
  prepareRoute(params) {
    return this.serialized(async () => {
      if (this.closed) throw fail('APPLICATION_ROUTING_CLOSED', 'adapter is closed')
      if (!params || !identifier(params.application?.id) || !identifier(params.application?.profileId) ||
          typeof params.application.executablePath !== 'string' || !path.isAbsolute(params.application.executablePath) ||
          typeof params.workspace?.cwd !== 'string' || !path.isAbsolute(params.workspace.cwd)) throw fail('APPLICATION_ROUTING_PROTOCOL_ERROR', 'invalid route context')
      if (params.route?.udpPolicy !== 'block') throw fail('APPLICATION_ROUTING_NOT_READY', 'UDP proxy routing is not implemented')
      let proxy
      try { proxy = validateManagedProxy(params.route); await authenticateManagedProxy(proxy) } catch { throw fail('APPLICATION_PROXY_UNAVAILABLE', 'managed authenticated route is unavailable') }
      const routeId = `mac_${randomUUID().replaceAll('-', '')}`
      this.routes.set(routeId, { routeId, application: { ...params.application }, workspace: { ...params.workspace }, proxy, active: true })
      return { routeId, prepared: true, ready: false, failClosed: false, capabilities: { ...emptyChecks(), streamBridge: true, udpBlocking: true }, verification: { passed: false, version: `mitmproxy-macos/${lock.version}`, checks: emptyChecks() } }
    })
  }
  async launch() {
    throw fail('APPLICATION_ROUTING_NOT_READY', 'protected launch awaits DNS origin, child routing, persistent blocking and native acceptance')
  }
  startCapture({ activationAuthorized = false } = {}) {
    return this.serialized(async () => {
      if (!activationAuthorized) throw fail('APPLICATION_ROUTING_AUTHORIZATION_REQUIRED', 'explicit system activation authorization required')
      if (this.closed || this.bridge || this.starting || this.fault) throw fail('APPLICATION_ROUTING_NOT_READY', 'capture cannot start in this instance')
      if (process.platform !== 'darwin' || this.appPath !== lock.installedAppPath || !this.native) throw fail('APPLICATION_ROUTING_UNAVAILABLE', 'original installed dependency and native verifier required')
      const dependency = await inspectDependency()
      if (!dependency.binaryVerified || !dependency.gatekeeperAccepted) throw fail('APPLICATION_ROUTING_UNAVAILABLE', 'original dependency trust is not verified')
      await this.native.identity(process.pid)
      this.starting = true
      try {
        // Never remove a stale/shared lock automatically: another user's
        // mitmproxy/Envara instance must not be taken over silently.
        this.lockPath = `/tmp/envara-macos-routing-${process.getuid()}.lock`
        this.lockHandle = await fs.open(this.lockPath, 'wx', 0o600)
        await this.lockHandle.writeFile(`${process.pid}\n`)
        this.directory = await fs.mkdtemp('/tmp/envara-mac-'); await fs.chmod(this.directory, 0o700)
        this.bridge = new RedirectorFlowBridge({ socketPath: path.join(this.directory, 'ipc.sock'), verifyPeer: socket => this.native.peer(socket),
          resolveBinding: (flow, previous) => this.resolveBinding(flow, previous), selectedPids: () => [...this.bindings.keys()], dnsResolver: this.dnsResolver })
        this.bridge.on('fault', reason => { this.fault = reason; this.notify('routing-fault', { reason, failClosed: false }) })
        this.bridge.on('flow', flow => this.notify('captured-flow', flow))
        this.bridge.on('peer-rejected', detail => this.notify('capture-peer-rejected', detail))
        this.bridge.on('flow-rejected', event => { const observed = this.diagnostics.recordRejection(event); if (observed) this.notify('capture-flow-rejected', observed) })
        this.bridge.on('diagnostic', event => { const observed = this.diagnostics.record(event); if (observed) this.notify('capture-diagnostic', observed) })
        await this.bridge.listen()
        const connected = new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(fail('APPLICATION_ROUTING_TIMEOUT', 'system approval or control connection did not complete')), this.activationTimeoutMs)
          this.bridge.once('control', () => { clearTimeout(timer); resolve() })
          this.bridge.once('fault', () => { clearTimeout(timer); reject(fail('APPLICATION_ROUTING_NOT_READY', 'system extension control failed')) })
        })
        this.helper = spawn(path.join(lock.installedAppPath, 'Contents/MacOS/Mitmproxy Redirector'), [this.bridge.socketPath], {
          stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' }, shell: false,
        })
        // Original app exits after startVPNTunnel. That exit is expected; the
        // signed extension owns the control connection thereafter.
        this.helper.stdout.resume(); this.helper.stderr.resume()
        this.helper.once('error', () => this.bridge?.fault('Original helper could not start'))
        this.helper.once('exit', code => { if (code !== 0 && this.starting) this.bridge?.fault('Original helper rejected activation') })
        await connected
        this.starting = false; return this.status()
      } catch (error) {
        this.starting = false; await this.closeCapture(); throw error
      }
    })
  }
  bindPid({ routeId, pid, birth } = {}) {
    return this.serialized(async () => {
      const binding = await this.validateDiagnosticBinding({ routeId, pid, birth })
      this.installDiagnosticBindings([binding])
      return { sessionId: binding.sessionId, routeId, pid, birth: binding.birth, captureTest: true, protected: false }
    })
  }
  async validateDiagnosticBinding({ routeId, pid, birth }) {
    const route = this.routes.get(routeId)
    if (!route?.active || !this.bridge?.control || this.bridge.faulted || !this.native) throw fail('APPLICATION_ROUTING_NOT_READY', 'active route and capture required')
    if (this.seenPids.has(pid) || this.bindings.size >= 256) throw fail('APPLICATION_ROUTING_NOT_READY', 'PID cannot be rebound in this capture epoch')
    let identity
    try { identity = await this.native.identity(pid) } catch { throw fail('APPLICATION_ROUTING_NOT_READY', 'actual process identity unavailable') }
    if (identity.alive !== true || identity.uid !== process.getuid() || (birth != null && identity.birth !== birth)) throw fail('APPLICATION_ROUTING_NOT_READY', 'process identity mismatch')
    const expected = await fs.realpath(route.application.executablePath)
    if (identity.path !== expected) throw fail('APPLICATION_ROUTING_NOT_READY', 'explicit PID executable does not match selected application')
    return { sessionId: `mac_session_${randomUUID().replaceAll('-', '')}`, routeId, pid, birth: identity.birth, processPath: identity.path, parentPid: identity.parentPid, active: true }
  }
  installDiagnosticBindings(bindings) {
    for (const binding of bindings) { this.bindings.set(binding.pid, binding); this.seenPids.add(binding.pid) }
    this.bridge.sendScope(); this.startIdentityMonitor()
  }
  bindDiagnosticFamily({ routeId, ownerPid, processes } = {}) {
    return this.serialized(async () => {
      if (ownerPid !== process.pid || !Array.isArray(processes) || processes.length < 1 || processes.length > 32 ||
          this.bindings.size + processes.length > 256 || new Set(processes.map(entry => entry?.pid)).size !== processes.length) throw fail('APPLICATION_ROUTING_PROTOCOL_ERROR', 'explicit owned fixture family required')
      const bindings = []
      for (const entry of processes) bindings.push(await this.validateDiagnosticBinding({ routeId, pid: entry?.pid, birth: entry?.birth }))
      const family = new Map(bindings.map(binding => [binding.pid, binding]))
      for (const binding of bindings) {
        let ancestor = binding.parentPid; const visited = new Set([binding.pid])
        while (ancestor !== ownerPid) {
          if (visited.has(ancestor) || !family.has(ancestor)) throw fail('APPLICATION_ROUTING_NOT_READY', 'fixture PID is not in the explicit owned family')
          visited.add(ancestor); ancestor = family.get(ancestor).parentPid
        }
        const actual = await this.native.identity(binding.pid)
        if (actual.alive !== true || actual.birth !== binding.birth || actual.path !== binding.processPath || actual.parentPid !== binding.parentPid || actual.uid !== process.getuid()) throw fail('APPLICATION_ROUTING_NOT_READY', 'fixture family identity changed')
      }
      this.installDiagnosticBindings(bindings)
      return { sessions: bindings.map(binding => ({ sessionId: binding.sessionId, pid: binding.pid, birth: binding.birth, routeId })),
        diagnostic: true, explicitFamilyBound: true, automaticChildren: false, atomic: false, protected: false }
    })
  }
  setDiagnosticOptions(options = {}) {
    return this.serialized(async () => {
      if (!options || Object.keys(options).some(key => !['sampleUdp', 'dnsForwarding'].includes(key)) || !Object.keys(options).length ||
          (options.sampleUdp !== undefined && typeof options.sampleUdp !== 'boolean') || (options.dnsForwarding !== undefined && typeof options.dnsForwarding !== 'boolean')) throw fail('APPLICATION_ROUTING_PROTOCOL_ERROR', 'explicit diagnostic option required')
      if (!this.bridge?.control || this.bridge.faulted) throw fail('APPLICATION_ROUTING_NOT_READY', 'capture required')
      if (options.sampleUdp !== undefined) this.bridge.diagnosticUdpSampling = options.sampleUdp
      if (options.dnsForwarding !== undefined) this.bridge.diagnosticDnsForwarding = options.dnsForwarding
      return { diagnostic: true, sampleUdp: this.bridge.diagnosticUdpSampling, dnsForwarding: this.bridge.diagnosticDnsForwarding, udpRouting: false, productionReady: false }
    })
  }
  diagnosticSnapshot() { return this.diagnostics.snapshot() }
  waitForDiagnosticEvent(params) { return this.diagnostics.wait(params) }
  async resolveBinding(flow, previous) {
    const binding = this.bindings.get(flow.pid); const route = binding && this.routes.get(binding.routeId)
    if (!binding?.active || !route?.active || (previous && (previous.routeId !== binding.routeId || previous.birth !== binding.birth))) return null
    let actual
    try { actual = await this.native.identity(flow.pid) } catch { return null }
    if (actual.birth !== binding.birth || actual.uid !== process.getuid() || actual.path !== binding.processPath ||
        (flow.processPath !== null && flow.processPath !== actual.path)) return null
    // Revocation can occur while native process inspection was awaiting a child.
    if (!binding.active || !route.active || this.bindings.get(flow.pid) !== binding) return null
    return { routeId: binding.routeId, birth: binding.birth, proxy: route.proxy }
  }
  startIdentityMonitor() {
    if (this.identityTimer) return
    this.identityTimer = setInterval(() => {
      if (this.identityRefreshPending) return
      this.identityRefreshPending = true
      this.refreshBindings().catch(() => {}).finally(() => { this.identityRefreshPending = false })
    }, 1000)
    this.identityTimer.unref()
  }
  refreshBindings() {
    return this.serialized(async () => {
      let changed = false
      for (const [pid, binding] of this.bindings) {
        let current
        try { current = await this.native.identity(pid) } catch {
          // A timeout, permission change, or verifier failure is not exit proof.
          if (!binding.identityUncertain) this.notify('process-identity-unavailable', { sessionId: binding.sessionId, pid })
          binding.identityUncertain = true; continue
        }
        binding.identityUncertain = false
        if (current.alive === false || (current.alive === true && current.birth !== binding.birth)) {
          binding.active = false; this.bridge?.closePid(pid); this.bindings.delete(pid); changed = true
          this.notify('capture-process-exited', { sessionId: binding.sessionId, pid, identityChanged: current.alive === true })
        }
      }
      if (changed && this.bridge?.control && !this.bridge.faulted) {
        try { this.bridge.sendScope() } catch { this.bridge.fault('Could not remove exited PID from interception scope') }
      }
      if (!this.bindings.size && this.identityTimer) { clearInterval(this.identityTimer); this.identityTimer = null }
      return { removedExitedIdentities: changed, activeBindings: this.bindings.size }
    })
  }
  stop({ sessionId, routeId } = {}) {
    return this.serialized(async () => {
      let found = false
      for (const binding of this.bindings.values()) if ((sessionId && binding.sessionId === sessionId) || (routeId && binding.routeId === routeId)) {
        binding.active = false; this.bridge?.closePid(binding.pid); found = true
      }
      if (!found) throw fail('APPLICATION_ROUTING_PROTOCOL_ERROR', 'owned capture-test session unavailable')
      // Keep PID interception active while that exact process lives. Revoking a
      // binding must not silently restore direct traffic to that process.
      return { stopped: false, captureStopped: true, processTerminated: false, interceptionRetained: true }
    })
  }
  revoke({ routeId } = {}) {
    return this.serialized(async () => {
      const route = this.routes.get(routeId)
      if (!route) throw fail('APPLICATION_ROUTING_PROTOCOL_ERROR', 'route unavailable')
      route.active = false
      for (const binding of this.bindings.values()) if (binding.routeId === routeId) { binding.active = false; this.bridge?.closePid(binding.pid) }
      route.proxy = null; return { revoked: true, interceptionRetained: true }
    })
  }
  async closeCapture() {
    this.diagnostics.close()
    if (this.identityTimer) { clearInterval(this.identityTimer); this.identityTimer = null }
    await this.bridge?.close(); this.bridge = null
    if (this.helper && this.helper.exitCode === null) this.helper.kill()
    this.helper = null
    if (this.directory) { await fs.rm(this.directory, { recursive: true, force: true }); this.directory = null }
    if (this.lockHandle) { await this.lockHandle.close(); this.lockHandle = null; await fs.unlink(this.lockPath); this.lockPath = null }
  }
  shutdown() {
    return this.serialized(async () => {
      for (const binding of this.bindings.values()) {
        let current
        try { current = await this.native.identity(binding.pid) } catch {
          throw fail('APPLICATION_ROUTING_NOT_READY', 'selected process exit could not be verified; capture retained')
        }
        if (current.alive !== false && (current.alive !== true || current.birth === binding.birth)) throw fail('APPLICATION_ROUTING_NOT_READY', 'selected process must exit before capture shutdown')
      }
      this.closed = true; await this.closeCapture()
      for (const route of this.routes.values()) route.proxy = null
      this.routes.clear(); this.bindings.clear()
    })
  }
}
