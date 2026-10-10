import Foundation
import Darwin

public enum ProcessProbeFailure: Error, Equatable {
    case system(Int32), truncated, foreignUser, identityChanged, invalidPID, enumerationFailed, scopeChanged
}

public enum ProcessProbeResult: Equatable {
    case found(ProcessIdentity), gone, unknown(ProcessProbeFailure)
}

public enum ProcessPresence: Equatable {
    case alive, gone, unknown(ProcessProbeFailure)
}

public typealias ProcessProbe = (Int32, ProcessIdentity?) -> ProcessProbeResult

public enum ProcessPIDListResult: Equatable {
    case listed([Int32]), unknown(ProcessProbeFailure)
}

public struct ProcessIdentity: Codable, Equatable {
    public let pid: Int32
    public let parent: Int32
    public let group: Int32
    public let startedSeconds: UInt64
    public let startedMicroseconds: UInt64
    public let path: String

    public init(pid: Int32, parent: Int32, group: Int32, startedSeconds: UInt64,
                startedMicroseconds: UInt64, path: String) {
        self.pid = pid; self.parent = parent; self.group = group
        self.startedSeconds = startedSeconds; self.startedMicroseconds = startedMicroseconds; self.path = path
    }

    public static func inspect(_ pid: Int32, _ expected: ProcessIdentity? = nil) -> ProcessProbeResult {
        inspect(pid, expected, authorizedUID: getuid())
    }

    /// A system provider may inspect only its protected runtime directory's owner.
    /// Ordinary cleanup retains the original caller-UID-only overload.
    public static func inspect(_ pid: Int32, _ expected: ProcessIdentity?, authorizedUID: uid_t) -> ProcessProbeResult {
        guard authorizedUID == getuid() || getuid() == 0 else { return .unknown(.foreignUser) }
        guard pid > 0 else { return .unknown(.invalidPID) }
        var info = proc_bsdinfo()
        errno = 0
        let bytes = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        guard bytes == MemoryLayout<proc_bsdinfo>.size else {
            if errno == ESRCH { return .gone }
            return .unknown(bytes > 0 ? .truncated : .system(errno == 0 ? EIO : errno))
        }
        // A birth generation change proves the original identity is gone, even
        // when the replacement PID belongs to another user.
        if let expected = expected,
           (info.pbi_start_tvsec != expected.startedSeconds || info.pbi_start_tvusec != expected.startedMicroseconds) { return .gone }
        guard info.pbi_uid == authorizedUID else { return .unknown(.foreignUser) }
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        errno = 0
        let pathBytes = proc_pidpath(pid, &path, UInt32(path.count))
        guard pathBytes > 0 else {
            if errno == ESRCH { return .gone }
            return .unknown(.system(errno == 0 ? EIO : errno))
        }
        guard pathBytes < path.count, path.contains(0) else { return .unknown(.truncated) }
        // Recheck birth after reading the path, so a PID replacement between
        // the two libproc calls cannot combine old birth data with a new path.
        var finalInfo = proc_bsdinfo()
        errno = 0
        let finalBytes = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &finalInfo, Int32(MemoryLayout<proc_bsdinfo>.size))
        guard finalBytes == MemoryLayout<proc_bsdinfo>.size else {
            if errno == ESRCH { return .gone }
            return .unknown(finalBytes > 0 ? .truncated : .system(errno == 0 ? EIO : errno))
        }
        if finalInfo.pbi_start_tvsec != info.pbi_start_tvsec || finalInfo.pbi_start_tvusec != info.pbi_start_tvusec {
            return expected == nil ? .unknown(.identityChanged) : .gone
        }
        guard finalInfo.pbi_uid == authorizedUID else { return .unknown(.foreignUser) }
        return .found(ProcessIdentity(pid: pid, parent: Int32(finalInfo.pbi_ppid), group: Int32(finalInfo.pbi_pgid),
                                      startedSeconds: finalInfo.pbi_start_tvsec, startedMicroseconds: finalInfo.pbi_start_tvusec,
                                      path: String(cString: path)))
    }

    /// Compatibility lookup for initial capture. Cleanup must use the typed
    /// presence/exitConfirmed APIs, never infer exit from a nil lookup.
    public static func read(_ pid: Int32) -> ProcessIdentity? {
        if case .found(let identity) = inspect(pid) { return identity }
        return nil
    }

    public func presence(using probe: ProcessProbe = ProcessIdentity.inspect) -> ProcessPresence {
        switch probe(pid, self) {
        case .gone: return .gone
        case .unknown(let reason): return .unknown(reason)
        case .found(let current):
            guard current.pid == pid else { return .unknown(.invalidPID) }
            if current.startedSeconds != startedSeconds || current.startedMicroseconds != startedMicroseconds { return .gone }
            guard current.path == path else { return .unknown(.identityChanged) }
            return .alive
        }
    }

    public var alive: Bool { presence() == .alive }
    public var exitConfirmed: Bool { isExitConfirmed() }
    public func isExitConfirmed(using probe: ProcessProbe = ProcessIdentity.inspect) -> Bool { presence(using: probe) == .gone }

    public func signal(_ value: Int32, probe: ProcessProbe = ProcessIdentity.inspect,
                       send: (Int32, Int32) -> Int32 = Darwin.kill) -> Bool {
        guard presence(using: probe) == .alive else { return false }
        return send(pid, value) == 0
    }

    public static func listGroup(_ group: Int32) -> ProcessPIDListResult {
        list(capacity: 16384) { buffer, bytes in proc_listpgrppids(group, buffer, bytes) }
    }

    public static func listChildren(_ pid: Int32) -> ProcessPIDListResult {
        list(capacity: 4096) { buffer, bytes in proc_listchildpids(pid, buffer, bytes) }
    }

    private static func list(capacity: Int, call: (UnsafeMutableRawPointer?, Int32) -> Int32) -> ProcessPIDListResult {
        var pids = [Int32](repeating: 0, count: capacity)
        errno = 0
        let byteCapacity = capacity * MemoryLayout<Int32>.size
        let bytes = pids.withUnsafeMutableBytes { call($0.baseAddress, Int32(byteCapacity)) }
        guard bytes >= 0, errno == 0 else { return .unknown(.system(errno == 0 ? EIO : errno)) }
        guard bytes < byteCapacity, Int(bytes) % MemoryLayout<Int32>.size == 0 else { return .unknown(.truncated) }
        return .listed(Array(pids.prefix(Int(bytes) / MemoryLayout<Int32>.size)))
    }
}

public final class ProcessFamily {
    private let group: Int32
    private let guardianPID: Int32
    private let probe: ProcessProbe
    private let listGroup: (Int32) -> ProcessPIDListResult
    private let listChildren: (Int32) -> ProcessPIDListResult
    private var observed = [Int32: ProcessIdentity]()
    private var pending = Set<Int32>()
    private var unverifiedEnumeration: ProcessProbeFailure?

    public init(group: Int32, guardianPID: Int32, initial: [ProcessIdentity] = [],
                probe: @escaping ProcessProbe = ProcessIdentity.inspect,
                listGroup: @escaping (Int32) -> ProcessPIDListResult = ProcessIdentity.listGroup,
                listChildren: @escaping (Int32) -> ProcessPIDListResult = ProcessIdentity.listChildren) {
        self.group = group; self.guardianPID = guardianPID; self.probe = probe
        self.listGroup = listGroup; self.listChildren = listChildren
        initial.forEach { observed[$0.pid] = $0 }
    }

    public var retainedIdentities: [ProcessIdentity] { observed.values.sorted { $0.pid < $1.pid } }
    public var unknownPIDs: [Int32] { pending.sorted() }

    public func refresh() throws -> [ProcessIdentity] {
        var failure = unverifiedEnumeration
        func capture(_ pid: Int32, parent: Int32? = nil) {
            guard pid != guardianPID, pid != 0 else { return }
            switch probe(pid, nil) {
            case .gone: observed.removeValue(forKey: pid); pending.remove(pid)
            case .unknown(let reason): pending.insert(pid); failure = failure ?? reason
            case .found(let item):
                guard item.pid == pid, pid > 0 else { pending.insert(pid); failure = failure ?? .invalidPID; return }
                let known = observed[pid]
                let sameKnownBirth = known?.startedSeconds == item.startedSeconds && known?.startedMicroseconds == item.startedMicroseconds
                if sameKnownBirth, known?.path != item.path { failure = failure ?? .identityChanged; return }
                guard item.group == group || (parent != nil && item.parent == parent) || sameKnownBirth else {
                    pending.insert(pid); failure = failure ?? .scopeChanged; return
                }
                observed[pid] = item; pending.remove(pid)
            }
        }
        func captureList(_ result: ProcessPIDListResult, parent: Int32? = nil) {
            switch result {
            case .unknown(let reason):
                // A failed/truncated list may hide an unobserved detached child.
                // A later empty list cannot retrospectively prove that scope
                // exited. Retain the uncertainty instead of granting cleanup.
                unverifiedEnumeration = unverifiedEnumeration ?? reason
                failure = failure ?? reason
            case .listed(let pids): pids.forEach { capture($0, parent: parent) }
            }
        }
        captureList(listGroup(group))
        // An unidentifiable PID remains uncertainty even when a later group list
        // omits it. Only a definite exit, or proved current scope, clears it.
        for pid in Array(pending) { capture(pid) }
        for identity in Array(observed.values) {
            switch identity.presence(using: probe) {
            case .gone: observed.removeValue(forKey: identity.pid)
            case .unknown(let reason): failure = failure ?? reason
            case .alive: captureList(listChildren(identity.pid), parent: identity.pid)
            }
        }
        for identity in Array(observed.values) {
            switch identity.presence(using: probe) {
            case .gone: observed.removeValue(forKey: identity.pid)
            case .unknown(let reason): failure = failure ?? reason
            case .alive: break
            }
        }
        if let failure = failure { throw failure }
        guard pending.isEmpty else { throw ProcessProbeFailure.scopeChanged }
        return retainedIdentities
    }
}
