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
    // Read terminal state follows buffered bytes and is owned by readGate.
    private var readFinished = false
    private var pendingReadError: Error?
    // Send registration and the write-half latch share lifetime's lock, so no
    // payload can be registered after the one final TCP message.
    private var writeFinished = false
    private var readyContinuation: CheckedContinuation<Void, Error>?
    private var readyTimeout: DispatchWorkItem?
    private let lifetime = FlowResourceLifetime()
    // Negotiation state lives on queue; the byte buffer has one async reader.
    private let readGate = ReadGate()

    public init(route: Route) throws {
        try route.validate()
        let connection = NWConnection(host: NWEndpoint.Host(route.host), port: NWEndpoint.Port(rawValue: route.port)!, using: .tcp)
        self.connection = connection
        _ = try lifetime.install(make: { connection }, cancel: { $0.cancel() })
    }

    public func connect(route: Route, endpoint: SOCKSEndpoint, udp: Bool = false) async throws -> SOCKSEndpoint {
        if udp && !route.udp { throw RoutingError.unsupportedUDP }
        return try await withTaskCancellationHandler {
            try await negotiate(route: route, endpoint: endpoint, udp: udp)
        } onCancel: { self.cancel() }
    }

    private func negotiate(route: Route, endpoint: SOCKSEndpoint, udp: Bool) async throws -> SOCKSEndpoint {
        try Task.checkCancellation()
        try lifetime.whileOpen {}
        let deadline = DispatchWorkItem { self.cancel() }
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
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                queue.async {
                    do {
                        try self.lifetime.whileOpen {
                            guard self.readyContinuation == nil else { throw RoutingError.refused }
                            self.readyContinuation = continuation
                            let timeout = DispatchWorkItem { self.finishReady(RoutingError.refused); self.cancel() }
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
                    } catch { continuation.resume(throwing: error) }
                }
            }
        } onCancel: { self.cancel() }
        try Task.checkCancellation()
        try lifetime.whileOpen {}
    }

    private func operation<T>(_ register: (CheckedContinuation<T, Error>) -> Void) async throws -> T {
        let result: T = try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                do { try lifetime.whileOpen { register(continuation) } }
                catch { continuation.resume(throwing: error) }
            }
        } onCancel: { self.cancel() }
        try Task.checkCancellation()
        try lifetime.whileOpen {}
        return result
    }

    private func finishReady(_ error: Error?) {
        let continuation = readyContinuation
        readyContinuation = nil; readyTimeout?.cancel(); readyTimeout = nil
        connection.stateUpdateHandler = nil
        guard let continuation = continuation else { return }
        if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
    }

    public func readExactly(_ count: Int) async throws -> Data {
        try await withTaskCancellationHandler {
            try await readExactlyValue(count)
        } onCancel: { self.cancel() }
    }

    private func readExactlyValue(_ count: Int) async throws -> Data {
        try Task.checkCancellation()
        await readGate.acquire()
        defer { Task { await readGate.release() } }
        try Task.checkCancellation()
        try lifetime.whileOpen {}
        guard count > 0 else { return Data() }
        while buffer.count < count {
            let data = try await readNetwork(maximum: max(4096, count - buffer.count))
            guard !data.isEmpty else { throw RoutingError.refused }
            buffer += data
        }
        let result = buffer.prefix(count); buffer.removeFirst(count); return Data(result)
    }

    public func read(maximum: Int = 65536) async throws -> Data {
        try await withTaskCancellationHandler {
            try await readValue(maximum: maximum)
        } onCancel: { self.cancel() }
    }

    private func readValue(maximum: Int) async throws -> Data {
        try Task.checkCancellation()
        await readGate.acquire()
        defer { Task { await readGate.release() } }
        try Task.checkCancellation()
        try lifetime.whileOpen {}
        if !buffer.isEmpty { let result = buffer; buffer.removeAll(); return result }
        return try await readNetwork(maximum: maximum)
    }

    private func readNetwork(maximum: Int) async throws -> Data {
        if let error = pendingReadError { throw error }
        if readFinished { return Data() }
        let result: (Data, Bool, Error?) = try await operation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) { data, _, complete, error in
                // Network may deliver final bytes together with EOF or an
                // error. Preserve those bytes before surfacing terminal state.
                continuation.resume(returning: (data ?? Data(), complete, error))
            }
        }
        readFinished = result.1
        pendingReadError = result.2
        if !result.0.isEmpty { return result.0 }
        if let error = result.2 { throw error }
        if result.1 { return Data() }
        throw RoutingError.refused
    }

    public func write(_ data: Data) async throws {
        try await operation { (continuation: CheckedContinuation<Void, Error>) in
            guard !writeFinished else { continuation.resume(throwing: RoutingError.refused); return }
            connection.send(content: data, completion: .contentProcessed { error in
                if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
            })
        }
    }

    public func closeWrite() {
        try? lifetime.whileOpen {
            guard !writeFinished else { return }
            writeFinished = true
            // isComplete alone finishes the default content message, not TCP.
            // A final context emits FIN while keeping the read half available.
            connection.send(content: nil, contentContext: .finalMessage, isComplete: true,
                            completion: .contentProcessed { [weak self] error in
                if error != nil { self?.cancel() }
            })
        }
    }

    public func cancel() {
        guard lifetime.close() else { return }
        queue.async { self.finishReady(RoutingError.refused) }
    }
}
