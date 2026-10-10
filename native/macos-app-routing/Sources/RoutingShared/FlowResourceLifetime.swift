import Foundation

/// A monotonic close latch for one provider-owned flow. Resource construction
/// and cancellation registration are atomic relative to close. Callbacks run
/// after unlocking; they may reenter without deadlocking the lifetime.
public final class FlowResourceLifetime: @unchecked Sendable {
    private final class DeferredCancellation: @unchecked Sendable {
        private let lock = NSLock()
        private var callbacks: [() -> Void]?

        init(_ callbacks: [() -> Void]) { self.callbacks = callbacks }

        func run() {
            lock.lock()
            let pending = callbacks
            callbacks = nil
            lock.unlock()
            pending?.forEach { $0() }
        }
    }

    private let lock = NSLock()
    private var closed = false
    private var resources: [UUID: () -> Void] = [:]

    public init() {}

    public var isClosed: Bool {
        lock.lock(); defer { lock.unlock() }
        return closed
    }

    /// The synchronous operation must not reenter this lifetime. This gate is
    /// also used around start/send/receive registration so close cannot precede
    /// a newly registered network operation.
    public func whileOpen<T>(_ operation: () throws -> T) throws -> T {
        lock.lock(); defer { lock.unlock() }
        guard !closed else { throw CancellationError() }
        return try operation()
    }

    /// Constructors must not open traffic themselves. Starting a connection is
    /// a separate whileOpen operation. Nothing can be constructed after close.
    public func install<T>(make: () throws -> T, cancel: @escaping (T) -> Void) throws -> (resource: T, token: UUID) {
        lock.lock(); defer { lock.unlock() }
        guard !closed else { throw CancellationError() }
        let resource = try make(), token = UUID()
        resources[token] = { cancel(resource) }
        return (resource, token)
    }

    /// A completed per-query resource can leave the lifetime. Closing the whole
    /// lifetime and releasing an individual handle both cancel it at most once.
    public func release(_ token: UUID) {
        lock.lock(); let cancellation = resources.removeValue(forKey: token); lock.unlock()
        cancellation?()
    }

    /// Seal the lifetime without executing callbacks, allowing an owner to
    /// withdraw admission under its own lock before cancelling after unlock.
    /// Only the first close returns work; repeated or concurrent calls to that
    /// work execute the detached callbacks once, outside either lock.
    public func closeDeferred() -> (() -> Void)? {
        lock.lock()
        guard !closed else { lock.unlock(); return nil }
        closed = true
        let cancellations = Array(resources.values); resources.removeAll()
        lock.unlock()
        let work = DeferredCancellation(cancellations)
        return { work.run() }
    }

    /// Returns true exactly once, allowing the flow and completion callback to
    /// be closed once by the caller. The latch is set before resource callbacks.
    @discardableResult public func close() -> Bool {
        guard let cancel = closeDeferred() else { return false }
        cancel()
        return true
    }
}
