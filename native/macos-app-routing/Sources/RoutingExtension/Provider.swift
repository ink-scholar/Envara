import Foundation
import Darwin
import Network
import NetworkExtension
import RoutingShared

@objc(EnvaraAppProxyProvider)
final class EnvaraAppProxyProvider: NEAppProxyProvider {
    private var route: Route?
    private var runtime: RuntimeStore?
    private var previousLease: GuardianLease?
    private var ownership: FlowProcessOwnership?
    private var blockedRouteId: String?
    private var leaseTimer: DispatchSourceTimer?
    private var sessions: [UUID: FlowSession] = [:]
    private var draining = false
    private var lifecycleEpoch = UUID()
    private var drainEpoch: UUID?
    private let lock = NSLock()

    private struct GuardianAdmission {
        let routeId: String
        let vpnUUID: String
        let sessionId: String
        let guardian: ProcessIdentity
        let ownership: FlowProcessOwnership
    }

    // Must hold lock. An ownership instance is the route epoch; heartbeats may
    // renew a lease but revoke/rebind must never reuse an earlier admission.
    private func matches(_ admission: GuardianAdmission) -> Bool {
        !draining && route?.routeId == admission.routeId && route?.vpnUUID == admission.vpnUUID &&
            previousLease?.sessionId == admission.sessionId && previousLease?.guardian == admission.guardian &&
            ownership === admission.ownership
    }

    private struct Drain {
        let epoch: UUID
        let sessions: [UUID: FlowSession]
        let cancellations: [() -> Void]
    }

    // Must hold lock. Late cleanup removes only its own sessions and cannot
    // clear a later drain or erase flows admitted after a new start/rebind.
    private func blockRoute(_ routeId: String?) -> Drain {
        let epoch = UUID()
        let active = sessions
        route = nil; ownership = nil; blockedRouteId = routeId; draining = true; drainEpoch = epoch
        // Seal while admission is locked, but run resource/completion callbacks
        // outside this lock. A pending session start then sees a closed lifetime.
        let cancellations = active.values.compactMap { $0.prepareCancellation() }
        return Drain(epoch: epoch, sessions: active, cancellations: cancellations)
    }

    private func finishDraining(_ active: Drain) {
        active.cancellations.forEach { $0() }
        lock.lock()
        for (id, session) in active.sessions where sessions[id] === session { sessions.removeValue(forKey: id) }
        if drainEpoch == active.epoch { drainEpoch = nil; draining = false }
        lock.unlock()
    }

    /// A prepared route accepts no traffic until its guardian establishes a
    /// live lease. Once observed, any uncertainty permanently closes this route;
    /// a late heartbeat can never reopen it.
    @discardableResult private func refreshGuardianLease(expectedLifecycle: UUID? = nil) -> GuardianAdmission? {
        lock.lock()
        guard expectedLifecycle == nil || expectedLifecycle == lifecycleEpoch,
              let selected = route, let runtime = runtime, !draining else { lock.unlock(); return nil }
        do {
            let file = try runtime.url(selected.routeId, suffix: "lease")
            var info = stat()
            if lstat(file.path, &info) != 0, errno == ENOENT, previousLease == nil {
                lock.unlock(); return nil
            }
            let lease = try runtime.readGuardianLease(selected.routeId)
            let baseline = previousLease ?? lease
            let decision = lease.evaluate(expectedRouteId: selected.routeId, expectedVPNUUID: selected.vpnUUID,
                expectedSessionId: baseline.sessionId, expectedGuardian: baseline.guardian,
                now: try GuardianLeaseClock.sample(), previous: previousLease,
                probe: { ProcessIdentity.inspect($0, $1, authorizedUID: runtime.ownerUID) })
            guard decision == .ready else { throw RoutingError.refused }
            let currentOwnership = ownership ?? FlowProcessOwnership(guardian: lease.guardian,
                applicationExecutablePath: selected.executablePath)
            ownership = currentOwnership; previousLease = lease
            let admission = GuardianAdmission(routeId: selected.routeId, vpnUUID: selected.vpnUUID,
                sessionId: lease.sessionId, guardian: lease.guardian, ownership: currentOwnership)
            lock.unlock(); return admission
        } catch {
            let active = blockRoute(selected.routeId)
            lock.unlock(); finishDraining(active); return nil
        }
    }

    private func startLeaseMonitor(expectedLifecycle: UUID, routeId: String) {
        lock.lock()
        guard lifecycleEpoch == expectedLifecycle, route?.routeId == routeId, !draining else { lock.unlock(); return }
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "io.envara.routing.lease"))
        timer.schedule(deadline: .now(), repeating: .milliseconds(250), leeway: .milliseconds(25))
        timer.setEventHandler { [weak self] in _ = self?.refreshGuardianLease(expectedLifecycle: expectedLifecycle) }
        leaseTimer?.cancel(); leaseTimer = timer; lock.unlock()
        timer.resume()
    }

    override func startProxy(options: [String : Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        let startEpoch = UUID()
        lock.lock()
        lifecycleEpoch = startEpoch
        leaseTimer?.cancel(); leaseTimer = nil
        let old = blockRoute(route?.routeId)
        runtime = nil; previousLease = nil
        lock.unlock(); finishDraining(old)
        do {
            guard let group = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: RuntimeStore.groupIdentifier),
                  let configuration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
                  configuration[RealmBindingSelection.versionKey] as? Int == 1,
                  let namespaceValue = configuration[RoutingRuntimeNamespace.configurationKey] as? String,
                  let namespace = RoutingRuntimeNamespace(rawValue: namespaceValue),
                  let configuredRealm = configuration[RealmBindingSelection.configurationKey] as? String,
                  let realm = RealmValidation.canonicalUUID(configuredRealm),
                  let id = (options?["routeId"] as? String) ?? (configuration["routeId"] as? String) else {
                throw RoutingError.notReady("Missing private route configuration")
            }
            let store = try RuntimeStore(directory: group, create: false, namespace: namespace)
            let selected = try store.read(id)
            guard selected.vpnUUID == realm,
                  options?["vpnUUID"] == nil || (options?["vpnUUID"] as? String).flatMap(RealmValidation.canonicalUUID) == realm else {
                throw RoutingError.notReady("private-route-does-not-match-provider-realm")
            }
            lock.lock()
            guard lifecycleEpoch == startEpoch, !draining else { lock.unlock(); throw RoutingError.refused }
            route = selected; runtime = store; previousLease = nil; ownership = nil; blockedRouteId = nil
            lock.unlock()
            _ = refreshGuardianLease(expectedLifecycle: startEpoch)
            lock.lock(); let viable = lifecycleEpoch == startEpoch && route?.routeId == selected.routeId; lock.unlock()
            guard viable else { throw RoutingError.notReady("guardian-lease-invalid") }
            let settings = NETunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
            settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "1.0.0.1"])
            setTunnelNetworkSettings(settings) { [weak self] error in
                guard let self = self else { completionHandler(RoutingError.refused); return }
                self.lock.lock()
                let current = self.lifecycleEpoch == startEpoch && self.route?.routeId == selected.routeId
                let failed = current && error != nil ? self.blockRoute(selected.routeId) : nil
                self.lock.unlock()
                if let failed = failed { self.finishDraining(failed) }
                if current && error == nil { self.startLeaseMonitor(expectedLifecycle: startEpoch, routeId: selected.routeId) }
                completionHandler(current ? error : RoutingError.refused)
            }
        } catch {
            lock.lock()
            let failed = lifecycleEpoch == startEpoch ? blockRoute(route?.routeId) : nil
            lock.unlock()
            if let failed = failed { finishDraining(failed) }
            completionHandler(error)
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lock.lock()
        lifecycleEpoch = UUID()
        let active = blockRoute(route?.routeId ?? blockedRouteId)
        leaseTimer?.cancel(); leaseTimer = nil; lock.unlock()
        finishDraining(active); completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // Ownership remains true on every refusal, including a missing guardian.
        guard let admission = refreshGuardianLease() else { close(flow, RoutingError.refused); return true }
        lock.lock()
        guard matches(admission), let selected = route, let runtime = runtime else {
            lock.unlock(); close(flow, RoutingError.refused); return true
        }
        // The OS mapping selects a realm, but only this guardian's fresh target
        // and proved descendants may consume it. Attribute each first flow from
        // its kernel audit token rather than waiting for a periodic PID scan.
        do {
            guard let token = flow.metaData.sourceAppAuditToken else { throw RoutingError.refused }
            let caller = try FlowAuditCaller.inspect(token, authorizedUID: runtime.ownerUID)
            guard admission.ownership.validate(caller: caller.identity, generation: caller.pidVersion,
                currentGeneration: { caller.isCurrent(authorizedUID: runtime.ownerUID) }, probe: {
                    ProcessIdentity.inspect($0, $1, authorizedUID: runtime.ownerUID)
                }) else { throw RoutingError.refused }
        } catch { lock.unlock(); close(flow, RoutingError.refused); return true }

        // The process walk may take time. Re-read expiry, guardian and lease
        // sequence under the same route lock before installing any transport.
        do {
            let lease = try runtime.readGuardianLease(admission.routeId)
            let decision = lease.evaluate(expectedRouteId: admission.routeId, expectedVPNUUID: admission.vpnUUID,
                expectedSessionId: admission.sessionId, expectedGuardian: admission.guardian,
                now: try GuardianLeaseClock.sample(), previous: previousLease,
                probe: { ProcessIdentity.inspect($0, $1, authorizedUID: runtime.ownerUID) })
            guard matches(admission), decision == .ready else { throw RoutingError.refused }
            previousLease = lease
        } catch {
            let active = blockRoute(admission.routeId)
            lock.unlock(); finishDraining(active); close(flow, RoutingError.refused); return true
        }
        let id = UUID()
        let session: FlowSession
        if let tcp = flow as? NEAppProxyTCPFlow {
            if let peer = try? endpoint(tcp.remoteEndpoint), peer.port == 53 {
                session = DNSTCPFlowSession(flow: tcp, route: selected)
            } else { session = TCPFlowSession(flow: tcp, route: selected) }
        }
        else if let udp = flow as? NEAppProxyUDPFlow {
            session = selected.udp ? UDPFlowSession(flow: udp, route: selected) : DNSFlowSession(flow: udp, route: selected)
        } else { lock.unlock(); close(flow, RoutingError.refused); return true }
        sessions[id] = session
        lock.unlock()
        // Starting after unlock avoids a synchronous failure callback acquiring
        // this same lock. Revocation first closes the lifetime, so a racing
        // start cannot create a new socket after its admission was withdrawn.
        session.start { [weak self] in
            guard let self = self else { return }
            self.lock.lock(); self.sessions.removeValue(forKey: id); self.lock.unlock()
        }
        return true
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        let request = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any]
        let admission = refreshGuardianLease()
        lock.lock()
        let selected = route
        let leaseReady = admission.map { matches($0) } ?? false
        let sessionId = leaseReady ? admission?.sessionId ?? "" : ""
        lock.unlock()
        let response: [String: Any] = ["routeId": selected?.routeId ?? "", "active": selected != nil,
            "vpnUUID": selected?.vpnUUID ?? "", "runtimeNamespace": selected?.runtimeNamespace.rawValue ?? "",
            "guardianLeaseReady": leaseReady, "sessionId": sessionId,
            "protocol": "socks5", "udpPolicy": selected?.udp == true ? "proxy" : "block", "providerVersion": "1"]
        if request?["method"] as? String == "revoke" {
            lock.lock()
            guard let requestedID = request?["routeId"] as? String, !draining,
                  route?.routeId == requestedID || (route == nil && blockedRouteId == requestedID && sessions.isEmpty) else {
                lock.unlock(); completionHandler?(try? JSONSerialization.data(withJSONObject: ["revoked": false])); return
            }
            let activeSessions = blockRoute(requestedID); lock.unlock()
            finishDraining(activeSessions)
            completionHandler?(try? JSONSerialization.data(withJSONObject: ["revoked": true])); return
        }
        if request?["method"] as? String == "rebind" {
            do {
                guard let configuration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
                      configuration[RealmBindingSelection.versionKey] as? Int == 1,
                      let configuredRealm = configuration[RealmBindingSelection.configurationKey] as? String,
                      let requestedRealm = request?["vpnUUID"] as? String,
                      let id = request?["routeId"] as? String else { throw RoutingError.refused }
                lock.lock()
                guard let store = runtime, !draining else { lock.unlock(); throw RoutingError.refused }
                let rebindEpoch = lifecycleEpoch
                lock.unlock()
                let replacement = try store.read(id)
                guard RealmValidation.canonicalUUID(requestedRealm) == replacement.vpnUUID else { throw RoutingError.refused }
                lock.lock()
                do {
                    guard lifecycleEpoch == rebindEpoch else { throw RoutingError.refused }
                    try RealmRebindValidation.validate(routeRealm: replacement.vpnUUID, configuredRealm: configuredRealm,
                        hasRoute: route != nil, activeFlows: sessions.count, draining: draining)
                    guard id != blockedRouteId else { throw RoutingError.refused }
                    route = replacement; previousLease = nil; ownership = nil; blockedRouteId = nil
                    lock.unlock()
                } catch { lock.unlock(); throw error }
                _ = refreshGuardianLease(expectedLifecycle: rebindEpoch)
                lock.lock(); let valid = lifecycleEpoch == rebindEpoch && route?.routeId == id; lock.unlock()
                guard valid else { throw RoutingError.refused }
                completionHandler?(try? JSONSerialization.data(withJSONObject: ["rebound": true, "routeId": replacement.routeId,
                    "vpnUUID": replacement.vpnUUID])); return
            } catch { completionHandler?(try? JSONSerialization.data(withJSONObject: ["rebound": false])); return }
        }
        guard request?["method"] as? String == "health" else { completionHandler?(nil); return }
        completionHandler?(try? JSONSerialization.data(withJSONObject: response))
    }
}

private func close(_ flow: NEAppProxyFlow, _ error: Error?) {
    flow.closeReadWithError(error); flow.closeWriteWithError(error)
}

private protocol FlowSession: AnyObject {
    func start(_ completion: @escaping () -> Void)
    func cancel()
    func prepareCancellation() -> (() -> Void)?
}

private func flowOperation<T>(lifetime: FlowResourceLifetime, onCancel: @escaping () -> Void,
                              _ operation: (CheckedContinuation<T, Error>) -> Void) async throws -> T {
    try Task.checkCancellation()
    let result: T = try await withTaskCancellationHandler {
        return try await withCheckedThrowingContinuation { continuation in
            do { try lifetime.whileOpen { operation(continuation) } }
            catch { continuation.resume(throwing: error) }
        }
    } onCancel: { onCancel() }
    try Task.checkCancellation()
    try lifetime.whileOpen {}
    return result
}

private func endpoint(_ value: AnyObject) throws -> SOCKSEndpoint {
    guard let host = value as? NWHostEndpoint, let port = UInt16(host.port), port > 0 else { throw RoutingError.invalidSOCKS }
    return SOCKSEndpoint(host: host.hostname, port: port)
}

private final class TCPFlowSession: FlowSession {
    private let flow: NEAppProxyTCPFlow
    private let route: Route
    private let lifetime = FlowResourceLifetime()
    private var completion: (() -> Void)?
    init(flow: NEAppProxyTCPFlow, route: Route) { self.flow = flow; self.route = route }

    func start(_ completion: @escaping () -> Void) {
        do {
            try lifetime.whileOpen { self.completion = completion }
            _ = try lifetime.install(make: { Task { [self] in
                do {
                    try Task.checkCancellation()
                    let peer = try endpoint(flow.remoteEndpoint)
                    guard !PrivacyPolicy.blocks(peer.host, mode: route.privacyMode) else { throw RoutingError.refused }
                    let socket = try lifetime.install(make: { try SOCKSTransport(route: route) }, cancel: { $0.cancel() }).resource
                    _ = try await socket.connect(route: route, endpoint: peer)
                    try await flowOperation(lifetime: lifetime, onCancel: { self.cancel() }) { (continuation: CheckedContinuation<Void, Error>) in
                        flow.open(withLocalEndpoint: nil) { error in
                            if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                        }
                    }
                    try await withThrowingTaskGroup(of: Void.self) { group in
                        group.addTask {
                            while !Task.isCancelled {
                                let data: Data = try await flowOperation(lifetime: self.lifetime, onCancel: { self.cancel() }) { continuation in
                                    self.flow.readData { data, error in
                                        if let error = error { continuation.resume(throwing: error) }
                                        else { continuation.resume(returning: data ?? Data()) }
                                    }
                                }
                                if data.isEmpty { socket.closeWrite(); return }
                                try await socket.write(data)
                            }
                        }
                        group.addTask {
                            while !Task.isCancelled {
                                let data = try await socket.read()
                                if data.isEmpty { self.flow.closeWriteWithError(nil); return }
                                try await flowOperation(lifetime: self.lifetime, onCancel: { self.cancel() }) { (continuation: CheckedContinuation<Void, Error>) in
                                    self.flow.write(data) { error in
                                        if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                                    }
                                }
                            }
                        }
                        do { for _ in 0..<2 { _ = try await group.next() } }
                        catch { group.cancelAll(); finish(error); throw error }
                    }
                    finish(nil)
                } catch { finish(error) }
            } }, cancel: { $0.cancel() })
        } catch { finish(error) }
    }

    private func prepareFinish(_ error: Error?) -> (() -> Void)? {
        guard let cancelResources = lifetime.closeDeferred() else { return nil }
        let callback = completion; completion = nil
        return { [self] in cancelResources(); close(flow, error); callback?() }
    }
    private func finish(_ error: Error?) { prepareFinish(error)?() }
    func prepareCancellation() -> (() -> Void)? { prepareFinish(RoutingError.refused) }
    func cancel() { prepareCancellation()?() }
}

// TC replies from UDP retry through this same admitted route. Generic TCP
// relaying would skip the DNS transaction/question checks and tracker policy.
private final class DNSTCPFlowSession: FlowSession {
    private let flow: NEAppProxyTCPFlow
    private let route: Route
    private let lifetime = FlowResourceLifetime()
    private var completion: (() -> Void)?
    private var frames = DNSWire.TCPFrameBuffer()
    init(flow: NEAppProxyTCPFlow, route: Route) { self.flow = flow; self.route = route }

    func start(_ completion: @escaping () -> Void) {
        do {
            try lifetime.whileOpen { self.completion = completion }
            _ = try lifetime.install(make: { Task { [self] in
                do {
                    let peer = try endpoint(flow.remoteEndpoint)
                    guard peer.port == 53 else { throw RoutingError.invalidSOCKS }
                    try await DNSDeadline.run(milliseconds: 8000, cancel: { self.cancel() }) {
                        try await flowOperation(lifetime: self.lifetime, onCancel: { self.cancel() }) { (continuation: CheckedContinuation<Void, Error>) in
                            self.flow.open(withLocalEndpoint: nil) { error in
                                if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                            }
                        }
                    }
                    for _ in 0..<16 {
                        guard let packet = try await nextQuery() else { finish(nil); return }
                        let question = try DNSWire.validateQuery(packet)
                        let answer: Data
                        if PrivacyPolicy.blocks(question.dnsName, mode: route.privacyMode) {
                            answer = DNSWire.blockedResponse(query: question)
                        } else {
                            answer = try await DNSExchange.response(for: packet, route: route, endpoint: peer)
                        }
                        let framed = Data([UInt8(answer.count >> 8), UInt8(answer.count & 255)]) + answer
                        try await DNSDeadline.run(milliseconds: 8000, cancel: { self.cancel() }) {
                            try await flowOperation(lifetime: self.lifetime, onCancel: { self.cancel() }) { (continuation: CheckedContinuation<Void, Error>) in
                                self.flow.write(framed) { error in
                                    if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                                }
                            }
                        }
                    }
                    finish(nil)
                } catch { finish(error) }
            } }, cancel: { $0.cancel() })
        } catch { finish(error) }
    }

    private func nextQuery() async throws -> Data? {
        try await DNSDeadline.run(milliseconds: 8000, cancel: { self.cancel() }) {
            while true {
                if let packet = try self.frames.nextQuery() { return packet }
                if try await self.readMore() == false {
                    try self.frames.validateEOF()
                    return nil
                }
            }
        }
    }

    private func readMore() async throws -> Bool {
        let data: Data = try await flowOperation(lifetime: lifetime, onCancel: { self.cancel() }) { continuation in
            flow.readData { data, error in
                if let error = error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: data ?? Data()) }
            }
        }
        guard !data.isEmpty else { return false }
        try frames.append(data); return true
    }

    private func prepareFinish(_ error: Error?) -> (() -> Void)? {
        guard let cancelResources = lifetime.closeDeferred() else { return nil }
        let callback = completion; completion = nil
        return { [self] in cancelResources(); close(flow, error); callback?() }
    }
    private func finish(_ error: Error?) { prepareFinish(error)?() }
    func prepareCancellation() -> (() -> Void)? { prepareFinish(RoutingError.refused) }
    func cancel() { prepareCancellation()?() }
}

private final class UDPFlowSession: FlowSession {
    private let flow: NEAppProxyUDPFlow
    private let route: Route
    private let lifetime = FlowResourceLifetime()
    private var completion: (() -> Void)?
    init(flow: NEAppProxyUDPFlow, route: Route) { self.flow = flow; self.route = route }

    func start(_ completion: @escaping () -> Void) {
        do {
            try lifetime.whileOpen { self.completion = completion }
            _ = try lifetime.install(make: { Task { [self] in
                do {
                    try Task.checkCancellation()
                    let control = try lifetime.install(make: { try SOCKSTransport(route: route) }, cancel: { $0.cancel() }).resource
                    let bound = try await control.connect(route: route, endpoint: SOCKSEndpoint(host: "127.0.0.1", port: 1), udp: true)
                    // A managed core must advertise a loopback relay. Refuse remote relays;
                    // they could bypass Envara's authenticated node and expose datagrams.
                    let host = ["0.0.0.0", "::"].contains(bound.host) ? route.host : bound.host
                    guard ["127.0.0.1", "::1"].contains(host), bound.port > 0 else { throw RoutingError.refused }
                    let connection = try lifetime.install(make: {
                        NWConnection(host: Network.NWEndpoint.Host(host), port: Network.NWEndpoint.Port(rawValue: bound.port)!, using: .udp)
                    }, cancel: { $0.cancel() }).resource
                    try await flowOperation(lifetime: lifetime, onCancel: { self.cancel() }) { (continuation: CheckedContinuation<Void, Error>) in
                        flow.open(withLocalEndpoint: nil) { error in
                            if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                        }
                    }
                    try lifetime.whileOpen { connection.start(queue: DispatchQueue(label: "io.envara.app-routing.udp")) }
                    try await withThrowingTaskGroup(of: Void.self) { group in
                        group.addTask {
                            while !Task.isCancelled {
                                let batch: ([Data], [AnyObject]) = try await flowOperation(lifetime: self.lifetime, onCancel: { self.cancel() }) { continuation in
                                    self.flow.readDatagrams { packets, endpoints, error in
                                        if let error = error { continuation.resume(throwing: error) }
                                        else { continuation.resume(returning: (packets ?? [], (endpoints ?? []).map { $0 as AnyObject })) }
                                    }
                                }
                                if batch.0.isEmpty { return }
                                guard batch.0.count == batch.1.count else { throw RoutingError.invalidSOCKS }
                                for (packet, destination) in zip(batch.0, batch.1) {
                                    let peer = try endpoint(destination)
                                    guard !PrivacyPolicy.blocks(peer.host, mode: self.route.privacyMode) else { throw RoutingError.refused }
                                    if peer.port == 53 {
                                        let question = try DNSWire.validateQuery(packet)
                                        let fullAnswer: Data
                                        if PrivacyPolicy.blocks(question.dnsName, mode: self.route.privacyMode) {
                                            fullAnswer = DNSWire.blockedResponse(query: question)
                                        } else {
                                            fullAnswer = try await DNSExchange.response(for: packet, route: self.route, endpoint: peer)
                                        }
                                        let answer = try DNSWire.udpResponse(fullAnswer, query: question)
                                        try await DNSDeadline.run(milliseconds: 8000, cancel: { self.cancel() }) {
                                            try await flowOperation(lifetime: self.lifetime, onCancel: { self.cancel() }) { (continuation: CheckedContinuation<Void, Error>) in
                                                self.flow.writeDatagrams([answer], sentBy: [NWHostEndpoint(hostname: peer.host, port: String(peer.port))]) { error in
                                                    if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                                                }
                                            }
                                        }
                                        continue
                                    }
                                    let data = try SOCKSCodec.udpPacket(packet, endpoint: peer)
                                    try await flowOperation(lifetime: self.lifetime, onCancel: { self.cancel() }) { (continuation: CheckedContinuation<Void, Error>) in
                                        connection.send(content: data, completion: .contentProcessed { error in
                                            if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                                        })
                                    }
                                }
                            }
                        }
                        group.addTask {
                            while !Task.isCancelled {
                                let data: Data = try await flowOperation(lifetime: self.lifetime, onCancel: { self.cancel() }) { continuation in
                                    connection.receiveMessage { data, _, _, error in
                                        if let error = error { continuation.resume(throwing: error) }
                                        else if let data = data { continuation.resume(returning: data) }
                                        else { continuation.resume(throwing: RoutingError.refused) }
                                    }
                                }
                                let (peer, packet) = try SOCKSCodec.decodeUDP(data)
                                guard DNSExchange.permitsRawDatagramSource(peer) else { throw RoutingError.refused }
                                let source = NWHostEndpoint(hostname: peer.host, port: String(peer.port))
                                try await flowOperation(lifetime: self.lifetime, onCancel: { self.cancel() }) { (continuation: CheckedContinuation<Void, Error>) in
                                    self.flow.writeDatagrams([packet], sentBy: [source]) { error in
                                        if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                                    }
                                }
                            }
                        }
                        // SOCKS UDP lifetime follows the authenticated TCP control channel.
                        group.addTask { _ = try await control.read(); throw RoutingError.refused }
                        do { try await group.next(); group.cancelAll(); finish(nil) }
                        catch { group.cancelAll(); finish(error); throw error }
                    }
                    finish(nil)
                } catch { finish(error) }
            } }, cancel: { $0.cancel() })
        } catch { finish(error) }
    }

    private func prepareFinish(_ error: Error?) -> (() -> Void)? {
        guard let cancelResources = lifetime.closeDeferred() else { return nil }
        let callback = completion; completion = nil
        return { [self] in cancelResources(); close(flow, error); callback?() }
    }
    private func finish(_ error: Error?) { prepareFinish(error)?() }
    func prepareCancellation() -> (() -> Void)? { prepareFinish(RoutingError.refused) }
    func cancel() { prepareCancellation()?() }
}

// With UDP disabled, DNS remains available over authenticated SOCKS TCP. Other
// datagrams are explicitly closed instead of returned for direct communication.
private final class DNSFlowSession: FlowSession {
    private let flow: NEAppProxyUDPFlow
    private let route: Route
    private let lifetime = FlowResourceLifetime()
    private var completion: (() -> Void)?
    init(flow: NEAppProxyUDPFlow, route: Route) { self.flow = flow; self.route = route }

    func start(_ completion: @escaping () -> Void) {
        do {
            try lifetime.whileOpen { self.completion = completion }
            _ = try lifetime.install(make: { Task { [self] in
                do {
                    try Task.checkCancellation()
                    try await DNSDeadline.run(milliseconds: 8000, cancel: { self.cancel() }) {
                        try await flowOperation(lifetime: self.lifetime, onCancel: { self.cancel() }) { (continuation: CheckedContinuation<Void, Error>) in
                            self.flow.open(withLocalEndpoint: nil) { error in
                                if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                            }
                        }
                    }
                    while !Task.isCancelled {
                        let batch: ([Data], [AnyObject]) = try await flowOperation(lifetime: lifetime, onCancel: { self.cancel() }) { continuation in
                            flow.readDatagrams { packets, endpoints, error in
                                if let error = error { continuation.resume(throwing: error) }
                                else { continuation.resume(returning: (packets ?? [], (endpoints ?? []).map { $0 as AnyObject })) }
                            }
                        }
                        if batch.0.isEmpty { break }
                        guard batch.0.count == batch.1.count else { throw RoutingError.invalidSOCKS }
                        for (packet, original) in zip(batch.0, batch.1) {
                            let peer = try endpoint(original)
                            guard peer.port == 53 else { throw RoutingError.unsupportedUDP }
                            let question = try DNSWire.validateQuery(packet)
                            let fullAnswer: Data
                            if PrivacyPolicy.blocks(question.dnsName, mode: route.privacyMode) {
                                fullAnswer = DNSWire.blockedResponse(query: question)
                            } else { fullAnswer = try await DNSExchange.response(for: packet, route: route, endpoint: peer) }
                            let answer = try DNSWire.udpResponse(fullAnswer, query: question)
                            try await DNSDeadline.run(milliseconds: 8000, cancel: { self.cancel() }) {
                                try await flowOperation(lifetime: self.lifetime, onCancel: { self.cancel() }) { (continuation: CheckedContinuation<Void, Error>) in
                                    self.flow.writeDatagrams([answer], sentBy: [NWHostEndpoint(hostname: peer.host, port: String(peer.port))]) { error in
                                        if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                                    }
                                }
                            }
                        }
                    }
                    finish(nil)
                } catch { finish(error) }
            } }, cancel: { $0.cancel() })
        } catch { finish(error) }
    }
    private func prepareFinish(_ error: Error?) -> (() -> Void)? {
        guard let cancelResources = lifetime.closeDeferred() else { return nil }
        let callback = completion; completion = nil
        return { [self] in cancelResources(); close(flow, error); callback?() }
    }
    private func finish(_ error: Error?) { prepareFinish(error)?() }
    func prepareCancellation() -> (() -> Void)? { prepareFinish(RoutingError.refused) }
    func cancel() { prepareCancellation()?() }
}
