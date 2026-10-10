import Foundation

/// Per-route process ownership, proved synchronously when a flow arrives.
/// The provider must serialize calls and supply a probe restricted to the
/// authorized runtime owner. A foreign owner must return `.unknown(.foreignUser)`.
public final class FlowProcessOwnership {
    private static let maximumParentDepth = 64
    private static let maximumRetainedIdentities = 4096

    private struct AuditedProcess {
        let identity: ProcessIdentity
        let generation: Int32
        let isCurrent: () -> Bool
    }

    private let guardian: ProcessIdentity
    private let applicationExecutablePath: String
    private var owned = [Int32: AuditedProcess]()

    public init(guardian: ProcessIdentity, applicationExecutablePath: String) {
        self.guardian = guardian
        self.applicationExecutablePath = applicationExecutablePath
    }

    /// The generation closure must revalidate the caller's immutable kernel
    /// audit token. Birth/path alone cannot prove that the process has not exec'd.
    /// Process groups never establish caller ownership.
    public func validate(caller: ProcessIdentity, generation: Int32,
                         currentGeneration: @escaping () -> Bool, probe: ProcessProbe) -> Bool {
        guard Self.valid(guardian), Self.valid(caller), caller.pid != guardian.pid,
              applicationExecutablePath.hasPrefix("/") else { return false }
        // A queued stale flow cannot invalidate a separately proved newer token.
        // Any retained token will still be revalidated before it can authorize.
        guard currentGeneration() else { return false }
        guard currentGuardian(probe: probe) != nil,
              let liveCaller = current(caller, probe: probe) else { return false }

        if let cached = owned[caller.pid] {
            // A previously proved child may have been naturally reparented.
            // A reused PID or an executable change cannot inherit this proof.
            if Self.sameIdentity(liveCaller, cached.identity), generation == cached.generation, cached.isCurrent() {
                guard current(cached.identity, probe: probe) != nil,
                      currentGuardian(probe: probe) != nil, currentGeneration() else {
                    owned.removeValue(forKey: caller.pid)
                    return false
                }
                return true
            }
            // A fresh audited generation or executable needs a new live-chain
            // proof; the earlier identity cannot authorize it from the cache.
            owned.removeValue(forKey: caller.pid)
        }

        var chain = [ProcessIdentity]()
        var seen = Set<Int32>()
        var item = liveCaller
        var reachedOwnedAncestor = false
        var auditedAnchor: AuditedProcess?

        for _ in 0..<Self.maximumParentDepth {
            guard seen.insert(item.pid).inserted, item.pid != guardian.pid else { return false }
            chain.append(item)

            if let cached = owned[item.pid] {
                // New children of an already proved, still-live orphan are
                // allowed only through this newly observed parent chain.
                if Self.sameIdentity(item, cached.identity), cached.isCurrent() {
                    reachedOwnedAncestor = true
                    auditedAnchor = cached
                    break
                }
                owned.removeValue(forKey: item.pid)
            }

            if item.parent == guardian.pid {
                guard item.path == applicationExecutablePath else { return false }
                reachedOwnedAncestor = true
                break
            }

            guard chain.count < Self.maximumParentDepth,
                  item.parent > 0, !seen.contains(item.parent),
                  let parent = currentPID(item.parent, probe: probe) else { return false }
            item = parent
        }

        guard reachedOwnedAncestor else { return false }

        // Recheck root-to-caller before retaining any proof. A birth, path or
        // parent change during the walk leaves ownership unproved.
        for observed in chain.reversed() {
            guard let latest = current(observed, probe: probe),
                  latest.parent == observed.parent else { return false }
            if let cached = owned[observed.pid], !Self.sameIdentity(latest, cached.identity) { return false }
        }
        if let anchor = auditedAnchor, !anchor.isCurrent() {
            owned.removeValue(forKey: anchor.identity.pid)
            return false
        }
        guard currentGuardian(probe: probe) != nil, currentGeneration() else { return false }

        // Only the actual audited caller receives a retained generation proof.
        // Merely inspecting ancestors cannot grant them future orphan access.
        // If full, fresh chains may pass but uncached orphans cannot use a cache.
        if owned[caller.pid] != nil || owned.count < Self.maximumRetainedIdentities {
            owned[caller.pid] = AuditedProcess(identity: liveCaller, generation: generation, isCurrent: currentGeneration)
        }
        return true
    }

    private func current(_ expected: ProcessIdentity, probe: ProcessProbe) -> ProcessIdentity? {
        guard Self.valid(expected), case .found(let identity) = probe(expected.pid, expected),
              Self.valid(identity), Self.sameIdentity(identity, expected) else { return nil }
        return identity
    }

    private func currentGuardian(probe: ProcessProbe) -> ProcessIdentity? {
        guard let identity = current(guardian, probe: probe), identity.group == guardian.group else { return nil }
        return identity
    }

    private func currentPID(_ pid: Int32, probe: ProcessProbe) -> ProcessIdentity? {
        guard pid > 0, case .found(let identity) = probe(pid, nil),
              identity.pid == pid, Self.valid(identity) else { return nil }
        return identity
    }

    private static func valid(_ identity: ProcessIdentity) -> Bool {
        identity.pid > 0 && identity.startedSeconds > 0 &&
            identity.startedMicroseconds < 1_000_000 && identity.path.hasPrefix("/")
    }

    private static func sameIdentity(_ current: ProcessIdentity, _ expected: ProcessIdentity) -> Bool {
        current.pid == expected.pid && current.startedSeconds == expected.startedSeconds &&
            current.startedMicroseconds == expected.startedMicroseconds && current.path == expected.path
    }
}
