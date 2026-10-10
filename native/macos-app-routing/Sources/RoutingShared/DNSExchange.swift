import Foundation

public enum DNSExchangeError: Error, Equatable {
    case deadline
    case invalidDeadline
}

private final class DNSDeadlineState: @unchecked Sendable {
    private let lock = NSLock()
    private var timedOut = false
    func expire() { lock.lock(); timedOut = true; lock.unlock() }
    var expired: Bool { lock.lock(); defer { lock.unlock() }; return timedOut }
}

/// Timeout closes the exact owned operation's resources before cancelling its
/// tasks. A timer alone would leave an NW receive continuation outstanding.
public enum DNSDeadline {
    public static func run<T: Sendable>(milliseconds: Int, cancel: @escaping @Sendable () -> Void,
                                       operation: @escaping @Sendable () async throws -> T) async throws -> T {
        guard milliseconds > 0 && milliseconds <= 30000 else { throw DNSExchangeError.invalidDeadline }
        let deadline = DNSDeadlineState()
        return try await withTaskCancellationHandler {
            try await withThrowingTaskGroup(of: T.self) { group in
                group.addTask { try await operation() }
                group.addTask {
                    try await Task.sleep(nanoseconds: UInt64(milliseconds) * 1_000_000)
                    deadline.expire()
                    cancel()
                    throw DNSExchangeError.deadline
                }
                defer { group.cancelAll() }
                do {
                    guard let value = try await group.next() else { throw CancellationError() }
                    guard !deadline.expired else { throw DNSExchangeError.deadline }
                    return value
                } catch {
                    if deadline.expired { throw DNSExchangeError.deadline }
                    throw error
                }
            }
        } onCancel: { cancel() }
    }
}

public enum DNSExchange {
    /// Outbound DNS uses the validated TCP exchange, so an unsolicited raw
    /// SOCKS UDP reply from port 53 cannot inject an unchecked DNS response.
    public static func permitsRawDatagramSource(_ endpoint: SOCKSEndpoint) -> Bool {
        endpoint.port != 53
    }

    /// Raw DNS-over-TCP is carried solely over this route's authenticated local
    /// SOCKS transport. No host resolver, direct socket or credential output.
    public static func response(for packet: Data, route: Route, endpoint: SOCKSEndpoint,
                                timeoutMilliseconds: Int = 8000) async throws -> Data {
        let question = try DNSWire.validateQuery(packet)
        guard endpoint.port == 53 else { throw RoutingError.invalidSOCKS }
        let socket = try SOCKSTransport(route: route)
        defer { socket.cancel() }
        return try await DNSDeadline.run(milliseconds: timeoutMilliseconds, cancel: { socket.cancel() }) {
            _ = try await socket.connect(route: route, endpoint: endpoint)
            try await socket.write(Data([UInt8(packet.count >> 8), UInt8(packet.count & 255)]) + packet)
            let prefix = try await socket.readExactly(2)
            let count = Int(prefix[0]) << 8 | Int(prefix[1])
            guard count >= 12 else { throw DNSWireError.sizeInvalid }
            let answer = try await socket.readExactly(count)
            return try DNSWire.validateResponse(answer, query: question)
        }
    }
}
