import Foundation
import Network
import NetworkExtension
import RoutingShared

@objc(EnvaraAppProxyProvider)
final class EnvaraAppProxyProvider: NEAppProxyProvider {
    private var route: Route?
    private var sessions: [UUID: FlowSession] = [:]
    private let lock = NSLock()

    override func startProxy(options: [String : Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        do {
            guard let group = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: RuntimeStore.groupIdentifier),
                  let configuration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
                  let id = (options?["routeId"] as? String) ?? (configuration["routeId"] as? String) else {
                throw RoutingError.notReady("Missing private route configuration")
            }
            let selected = try RuntimeStore(directory: group).read(id)
            lock.lock(); route = selected; lock.unlock()
            let settings = NETunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
            // Low-level resolver packets arrive as UDP flows and are either SOCKS relayed
            // or blocked. High-level name endpoints remain names in SOCKS requests.
            // This resolver setting applies to the app proxy, not the global system.
            settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "1.0.0.1"])
            setTunnelNetworkSettings(settings, completionHandler: completionHandler)
        } catch { lock.lock(); route = nil; lock.unlock(); completionHandler(error) }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lock.lock(); let active = Array(sessions.values); sessions.removeAll(); route = nil; lock.unlock()
        active.forEach { $0.cancel() }; completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // True means ownership. Even a malformed flow or missing route is closed,
        // never returned to the system for direct communication.
        lock.lock()
        guard let route = route else { lock.unlock(); close(flow, RoutingError.refused); return true }
        let id = UUID()
        let session: FlowSession
        if let tcp = flow as? NEAppProxyTCPFlow { session = TCPFlowSession(flow: tcp, route: route) }
        else if let udp = flow as? NEAppProxyUDPFlow {
            session = route.udp ? UDPFlowSession(flow: udp, route: route) : DNSFlowSession(flow: udp, route: route)
        } else { lock.unlock(); close(flow, RoutingError.refused); return true }
        sessions[id] = session
        session.start { [weak self] in
            guard let self = self else { return }
            self.lock.lock(); self.sessions.removeValue(forKey: id); self.lock.unlock()
        }
        lock.unlock()
        return true
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        // Never send route credentials or destinations over the health endpoint.
        let request = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any]
        lock.lock(); let selected = route; lock.unlock()
        let active = selected?.routeId
        let response: [String: Any] = ["routeId": active ?? "", "active": active != nil,
                                      "protocol": "socks5", "udpPolicy": selected?.udp == true ? "proxy" : "block",
                                      "providerVersion": "1"]
        if request?["method"] as? String == "revoke", request?["routeId"] as? String == active {
            lock.lock(); let activeSessions = Array(sessions.values); sessions.removeAll(); route = nil; lock.unlock()
            activeSessions.forEach { $0.cancel() }
            completionHandler?(try? JSONSerialization.data(withJSONObject: ["revoked": true])); return
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
}

private func endpoint(_ value: AnyObject) throws -> SOCKSEndpoint {
    guard let host = value as? NWHostEndpoint, let port = UInt16(host.port), port > 0 else { throw RoutingError.invalidSOCKS }
    return SOCKSEndpoint(host: host.hostname, port: port)
}

private final class TCPFlowSession: FlowSession {
    private let flow: NEAppProxyTCPFlow
    private let route: Route
    private var transport: SOCKSTransport?
    private var task: Task<Void, Never>?
    private var completion: (() -> Void)?
    private let lock = NSLock()
    init(flow: NEAppProxyTCPFlow, route: Route) { self.flow = flow; self.route = route }

    func start(_ completion: @escaping () -> Void) {
        self.completion = completion
        task = Task {
            do {
                try Task.checkCancellation()
                let peer = try endpoint(flow.remoteEndpoint)
                guard !PrivacyPolicy.blocks(peer.host, mode: route.privacyMode) else { throw RoutingError.refused }
                let socket = try SOCKSTransport(route: route); transport = socket
                _ = try await socket.connect(route: route, endpoint: peer)
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    flow.open(withLocalEndpoint: nil) { error in
                        if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                    }
                }
                try await withThrowingTaskGroup(of: Void.self) { group in
                    group.addTask {
                        while !Task.isCancelled {
                            let data: Data = try await withCheckedThrowingContinuation { continuation in
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
                            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                                self.flow.write(data) { error in
                                    if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                                }
                            }
                        }
                    }
                    do { for _ in 0..<2 { _ = try await group.next() } }
                    catch { group.cancelAll(); socket.cancel(); close(self.flow, error); throw error }
                }
                finish(nil)
            } catch { finish(error) }
        }
    }

    private func finish(_ error: Error?) {
        lock.lock(); let callback = completion; completion = nil; lock.unlock()
        transport?.cancel(); close(flow, error); callback?()
    }
    func cancel() { task?.cancel(); finish(RoutingError.refused) }
}

private final class UDPFlowSession: FlowSession {
    private let flow: NEAppProxyUDPFlow
    private let route: Route
    private var transport: SOCKSTransport?
    private var relay: NWConnection?
    private var task: Task<Void, Never>?
    private var completion: (() -> Void)?
    private let lock = NSLock()
    init(flow: NEAppProxyUDPFlow, route: Route) { self.flow = flow; self.route = route }

    func start(_ completion: @escaping () -> Void) {
        self.completion = completion
        task = Task {
            do {
                try Task.checkCancellation()
                let control = try SOCKSTransport(route: route); transport = control
                let bound = try await control.connect(route: route, endpoint: SOCKSEndpoint(host: "127.0.0.1", port: 1), udp: true)
                // A managed core must advertise a loopback relay. Refuse remote relays;
                // they could bypass Envara's authenticated node and expose datagrams.
                let host = ["0.0.0.0", "::"].contains(bound.host) ? route.host : bound.host
                guard ["127.0.0.1", "::1"].contains(host), bound.port > 0 else { throw RoutingError.refused }
                let connection = NWConnection(host: Network.NWEndpoint.Host(host), port: Network.NWEndpoint.Port(rawValue: bound.port)!, using: .udp)
                relay = connection
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    flow.open(withLocalEndpoint: nil) { error in
                        if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                    }
                }
                connection.start(queue: DispatchQueue(label: "io.envara.app-routing.udp"))
                try await withThrowingTaskGroup(of: Void.self) { group in
                    group.addTask {
                        while !Task.isCancelled {
                            let batch: ([Data], [AnyObject]) = try await withCheckedThrowingContinuation { continuation in
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
                                if peer.port == 53, let blocked = try PrivacyPolicy.blockedDNSResponse(packet, mode: self.route.privacyMode) {
                                    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                                        self.flow.writeDatagrams([blocked], sentBy: [NWHostEndpoint(hostname: peer.host, port: String(peer.port))]) { error in
                                            if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                                        }
                                    }
                                    continue
                                }
                                let data = try SOCKSCodec.udpPacket(packet, endpoint: peer)
                                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                                    connection.send(content: data, completion: .contentProcessed { error in
                                        if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                                    })
                                }
                            }
                        }
                    }
                    group.addTask {
                        while !Task.isCancelled {
                            let data: Data = try await withCheckedThrowingContinuation { continuation in
                                connection.receiveMessage { data, _, _, error in
                                    if let error = error { continuation.resume(throwing: error) }
                                    else if let data = data { continuation.resume(returning: data) }
                                    else { continuation.resume(throwing: RoutingError.refused) }
                                }
                            }
                            let (peer, packet) = try SOCKSCodec.decodeUDP(data)
                            let source = NWHostEndpoint(hostname: peer.host, port: String(peer.port))
                            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                                self.flow.writeDatagrams([packet], sentBy: [source]) { error in
                                    if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                                }
                            }
                        }
                    }
                    // SOCKS UDP lifetime follows the authenticated TCP control channel.
                    group.addTask { _ = try await control.read(); throw RoutingError.refused }
                    do { try await group.next(); group.cancelAll(); self.relay?.cancel(); self.transport?.cancel(); close(self.flow, nil) }
                    catch { group.cancelAll(); self.relay?.cancel(); self.transport?.cancel(); close(self.flow, error); throw error }
                }
                finish(nil)
            } catch { finish(error) }
        }
    }

    private func finish(_ error: Error?) {
        lock.lock(); let callback = completion; completion = nil; lock.unlock()
        relay?.cancel(); transport?.cancel(); close(flow, error); callback?()
    }
    func cancel() { task?.cancel(); finish(RoutingError.refused) }
}

// With UDP disabled, DNS remains available over authenticated SOCKS TCP. Other
// datagrams are explicitly closed instead of returned for direct communication.
private final class DNSFlowSession: FlowSession {
    private let flow: NEAppProxyUDPFlow
    private let route: Route
    private var task: Task<Void, Never>?
    private var transport: SOCKSTransport?
    private var completion: (() -> Void)?
    private let lock = NSLock()
    init(flow: NEAppProxyUDPFlow, route: Route) { self.flow = flow; self.route = route }

    func start(_ completion: @escaping () -> Void) {
        self.completion = completion
        task = Task {
            do {
                try Task.checkCancellation()
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    flow.open(withLocalEndpoint: nil) { error in
                        if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                    }
                }
                while !Task.isCancelled {
                    let batch: ([Data], [AnyObject]) = try await withCheckedThrowingContinuation { continuation in
                        flow.readDatagrams { packets, endpoints, error in
                            if let error = error { continuation.resume(throwing: error) }
                            else { continuation.resume(returning: (packets ?? [], (endpoints ?? []).map { $0 as AnyObject })) }
                        }
                    }
                    if batch.0.isEmpty { break }
                    guard batch.0.count == batch.1.count else { throw RoutingError.invalidSOCKS }
                    for (packet, original) in zip(batch.0, batch.1) {
                        let peer = try endpoint(original)
                        guard peer.port == 53, packet.count >= 12, packet.count <= 65535 else { throw RoutingError.unsupportedUDP }
                        if let blocked = try PrivacyPolicy.blockedDNSResponse(packet, mode: route.privacyMode) {
                            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                                flow.writeDatagrams([blocked], sentBy: [NWHostEndpoint(hostname: peer.host, port: String(peer.port))]) { error in
                                    if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                                }
                            }
                            continue
                        }
                        let socket = try SOCKSTransport(route: route); transport = socket
                        _ = try await socket.connect(route: route, endpoint: peer)
                        try await socket.write(Data([UInt8(packet.count >> 8), UInt8(packet.count & 255)]) + packet)
                        let size = try await socket.readExactly(2)
                        let count = Int(size[0]) << 8 | Int(size[1])
                        guard count >= 12 else { throw RoutingError.invalidSOCKS }
                        let answer = try await socket.readExactly(count)
                        guard answer.prefix(2) == packet.prefix(2) else { throw RoutingError.invalidSOCKS }
                        socket.cancel(); transport = nil
                        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                            flow.writeDatagrams([answer], sentBy: [NWHostEndpoint(hostname: peer.host, port: String(peer.port))]) { error in
                                if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                            }
                        }
                    }
                }
                finish(nil)
            } catch { finish(error) }
        }
    }
    private func finish(_ error: Error?) {
        lock.lock(); let callback = completion; completion = nil; lock.unlock()
        transport?.cancel(); close(flow, error); callback?()
    }
    func cancel() { task?.cancel(); finish(RoutingError.refused) }
}
