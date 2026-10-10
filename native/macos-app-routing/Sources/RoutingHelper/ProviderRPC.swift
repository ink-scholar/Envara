import Foundation
import NetworkExtension
import RoutingShared

private final class ProviderReply {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data?, Error>?
    init(_ continuation: CheckedContinuation<Data?, Error>) { self.continuation = continuation }
    func finish(_ result: Result<Data?, Error>) {
        lock.lock(); let pending = continuation; continuation = nil; lock.unlock()
        pending?.resume(with: result)
    }
}

/// A timeout is uncertainty, never an acknowledgement of routing or revocation.
func boundedProviderReply(_ session: NETunnelProviderSession, request: Data) async throws -> Data? {
    try await withCheckedThrowingContinuation { continuation in
        let pending = ProviderReply(continuation)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 3) {
            pending.finish(.failure(RoutingError.notReady("provider-reply-deadline")))
        }
        do { try session.sendProviderMessage(request) { pending.finish(.success($0)) } }
        catch { pending.finish(.failure(error)) }
    }
}
