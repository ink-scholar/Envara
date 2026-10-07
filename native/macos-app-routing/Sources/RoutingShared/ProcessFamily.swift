import Foundation
import Darwin

public struct ProcessIdentity: Codable, Equatable {
    public let pid: Int32
    public let parent: Int32
    public let group: Int32
    public let startedSeconds: UInt64
    public let startedMicroseconds: UInt64
    public let path: String

    public static func read(_ pid: Int32) -> ProcessIdentity? {
        var info = proc_bsdinfo()
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) == MemoryLayout<proc_bsdinfo>.size,
              info.pbi_uid == getuid() else { return nil }
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
        return ProcessIdentity(pid: pid, parent: Int32(info.pbi_ppid), group: Int32(info.pbi_pgid),
                               startedSeconds: info.pbi_start_tvsec, startedMicroseconds: info.pbi_start_tvusec,
                               path: String(cString: path))
    }

    public var alive: Bool {
        guard let current = Self.read(pid) else { return false }
        return current.startedSeconds == startedSeconds && current.startedMicroseconds == startedMicroseconds && current.path == path
    }

    public func signal(_ value: Int32) -> Bool {
        guard alive else { return false }
        return kill(pid, value) == 0
    }
}

public final class ProcessFamily {
    private let group: Int32
    private let guardianPID: Int32
    private var observed = [Int32: ProcessIdentity]()
    public init(group: Int32, guardianPID: Int32) { self.group = group; self.guardianPID = guardianPID }

    public func refresh() -> [ProcessIdentity] {
        var pids = [Int32](repeating: 0, count: 16384)
        let bytes = proc_listpgrppids(group, &pids, Int32(pids.count * MemoryLayout<Int32>.size))
        if bytes > 0 {
            for pid in pids.prefix(Int(bytes) / MemoryLayout<Int32>.size) where pid > 0 && pid != guardianPID {
                if let item = ProcessIdentity.read(pid) { observed[pid] = item }
            }
        }
        // Retain helpers after they leave the process group if they were observed
        // while attached. Unknown/shared system services are outside this contract.
        for parent in Array(observed.values) where parent.alive {
            var children = [Int32](repeating: 0, count: 4096)
            let count = proc_listchildpids(parent.pid, &children, Int32(children.count * MemoryLayout<Int32>.size))
            if count > 0 {
                for pid in children.prefix(Int(count) / MemoryLayout<Int32>.size) where pid > 0 && pid != guardianPID {
                    if let item = ProcessIdentity.read(pid) { observed[pid] = item }
                }
            }
        }
        return observed.values.filter { $0.alive }
    }
}
