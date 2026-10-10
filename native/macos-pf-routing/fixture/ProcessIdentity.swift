// Standalone PF fixture identity reader, copied without a NE or RoutingShared module dependency.
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

