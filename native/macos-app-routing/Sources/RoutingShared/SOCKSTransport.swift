import Foundation
import Network

private actor ReadGate {
    private var held = false
    private var waiters = [CheckedContinuation<Void, Never>]()
    func acquire() async {
        if !held { held = true; return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func release() {
        if waiters.isEmpty { held = false } else { waiters.removeFirst().resume() }
    }
}

// Every connection in this transport is to the authenticated Envara loopback core.
// No remote socket is opened when authentication, negotiation, or the core fails.
public final class SOCKSTransport: @unchecked Sendable {
    public let connection: NWConnection
    private let queue = DispatchQueue(label: "io.envara.app-routing.socks")
    private var buffer = Data()
    private var readyContinuation: CheckedContinuation<Void, Error>?
    private var readyTimeout: DispatchWorkItem?
    // Negotiation state lives on queue; the byte buffer has one async reader.
    private let readGate = ReadGate()

    public init(route: Route) throws {
        try route.validate()
        connection = NWConnection(host: NWEndpoint.Host(route.host), port: NWEndpoint.Port(rawValue: route.port)!, using: .tcp)
    }

    public func connect(route: Route, endpoint: SOCKSEndpoint, udp: Bool = false) async throws -> SOCKSEndpoint {
        if udp && !route.udp { throw RoutingError.unsupportedUDP }
        let deadline = DispatchWorkItem { self.connection.cancel() }
        queue.asyncAfter(deadline: .now() + 15, execute: deadline)
        defer { deadline.cancel() }
        try await ready()
        try await write(SOCKSCodec.greeting)
        guard try await readExactly(2) == Data([5, 2]) else { throw RoutingError.invalidSOCKS }
        try await write(SOCKSCodec.authentication(username: route.username, password: route.password))
        guard try await readExactly(2) == Data([1, 0]) else { throw RoutingError.refused }
        // Port zero is permitted only for SOCKS UDP ASSOCIATE's unspecified client address.
        let request = udp ? Data([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]) : try SOCKSCodec.command(1, endpoint: endpoint)
        try await write(request)
        let header = try await readExactly(4)
        guard header[0] == 5, header[1] == 0, header[2] == 0 else { throw RoutingError.refused }
        var reply = Data([header[3]])
        switch header[3] {
        case 1: reply += try await readExactly(6)
        case 4: reply += try await readExactly(18)
        case 3:
            let length = try await readExactly(1); reply += length
            reply += try await readExactly(Int(length[0]) + 2)
        default: throw RoutingError.invalidSOCKS
        }
        return try SOCKSCodec.decodeAddress(reply).0
    }

    private func ready() async throws {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                self.readyContinuation = continuation
                let timeout = DispatchWorkItem { self.finishReady(RoutingError.refused); self.connection.cancel() }
                self.readyTimeout = timeout
                self.queue.asyncAfter(deadline: .now() + 10, execute: timeout)
                self.connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready: self.finishReady(nil)
                    case .failed(let error): self.finishReady(error)
                    case .cancelled: self.finishReady(RoutingError.refused)
                    default: break
                    }
                }
                self.connection.start(queue: self.queue)
            }
        }
    }

    private func finishReady(_ error: Error?) {
        guard let continuation = readyContinuation else { return }
        readyContinuation = nil; readyTimeout?.cancel(); readyTimeout = nil
        if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
    }

    public func readExactly(_ count: Int) async throws -> Data {
        await readGate.acquire()
        defer { Task { await readGate.release() } }
        guard count > 0 else { return Data() }
        while buffer.count < count {
            let data = try await readNetwork(maximum: max(4096, count - buffer.count))
            guard !data.isEmpty else { throw RoutingError.refused }
            buffer += data
        }
        let result = buffer.prefix(count); buffer.removeFirst(count); return Data(result)
    }

    public func read(maximum: Int = 65536) async throws -> Data {
        await readGate.acquire()
        defer { Task { await readGate.release() } }
        if !buffer.isEmpty { let result = buffer; buffer.removeAll(); return result }
        return try await readNetwork(maximum: maximum)
    }

    private func readNetwork(maximum: Int) async throws -> Data {
        return try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) { data, _, complete, error in
                if let error = error { continuation.resume(throwing: error) }
                else if let data = data { continuation.resume(returning: data) }
                else if complete { continuation.resume(returning: Data()) }
                else { continuation.resume(throwing: RoutingError.refused) }
            }
        }
    }

    public func write(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
            })
        }
    }

    public func closeWrite() { connection.send(content: nil, isComplete: true, completion: .idempotent) }
    public func cancel() { connection.cancel() }
}
