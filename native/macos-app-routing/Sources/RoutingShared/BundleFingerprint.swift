import CryptoKit
import Darwin
import Foundation

public enum RoutingBundleFingerprintError: Error, Equatable {
    case unsafeBundle, budgetExceeded, changedWhileReading, ioFailure
}

/// Version 1 of the provider bundle digest shared with provider-reuse.mjs.
/// The digest binds all relative paths, directories, permissions and file bytes;
/// timestamps, ownership and extended attributes are not digest input.
public enum RoutingBundleFingerprint {
    public static let version = 1
    static let maximumEntries = 4096
    static let maximumPathBytes = 1024
    static let maximumFileBytes: Int64 = 64 * 1024 * 1024
    static let maximumTotalBytes: Int64 = 64 * 1024 * 1024
    private static let executablePath = "Contents/MacOS/EnvaraAppProxy"

    private struct Entry {
        let path: String
        let directory: Bool
        let snapshot: stat
        var mode: UInt16 { UInt16(snapshot.st_mode & 0o777) }
    }

    public static func sha256(_ bundle: URL) throws -> String {
        let path = bundle.path
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        guard bundle.isFileURL, path.hasPrefix("/"), !path.contains("\0"),
              components.count > 1, components.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
              let resolved = Darwin.realpath(path, nil) else {
            throw RoutingBundleFingerprintError.unsafeBundle
        }
        // NSURL display normalization rewrites an existing /private/tmp path to
        // /tmp on macOS. POSIX realpath is the same canonical spelling used by
        // the JS builder and preserves the actual /private directory identity.
        defer { free(resolved) }
        guard let canonical = String(validatingUTF8: resolved), canonical.utf8.elementsEqual(path.utf8) else {
            throw RoutingBundleFingerprintError.unsafeBundle
        }
        var original = stat()
        guard lstat(bundle.path, &original) == 0, isDirectory(original) else { throw RoutingBundleFingerprintError.unsafeBundle }
        let root = open(bundle.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw RoutingBundleFingerprintError.ioFailure }
        defer { Darwin.close(root) }
        guard try snapshot(root).st_ino == original.st_ino, sameSnapshot(original, try snapshot(root)) else {
            throw RoutingBundleFingerprintError.changedWhileReading
        }
        var entries = [Entry](), total: Int64 = 0
        try inventory(root, path: "", original: original, entries: &entries, total: &total)
        guard let executable = entries.first(where: { $0.path == executablePath }),
              !executable.directory, executable.mode & 0o111 != 0 else { throw RoutingBundleFingerprintError.unsafeBundle }
        var directories: [Data: stat] = [:]
        for entry in entries where entry.directory {
            let key = Data(entry.path.utf8)
            guard directories[key] == nil else { throw RoutingBundleFingerprintError.unsafeBundle }
            directories[key] = entry.snapshot
        }
        let sorted = entries.sorted { $0.path.utf8.lexicographicallyPrecedes($1.path.utf8) }
        var digest = SHA256()
        digest.update(data: Data("envara-routing-provider-bundle-v1\0".utf8))
        for entry in sorted {
            let mode = String(format: "%03o", Int(entry.mode))
            digest.update(data: Data("\(entry.path)\0\(entry.directory ? "directory" : "file")\0\(mode)\0".utf8))
            if !entry.directory {
                let file = try openEntry(entry, root: root, directories: directories)
                defer { Darwin.close(file) }
                guard sameSnapshot(entry.snapshot, try snapshot(file)) else { throw RoutingBundleFingerprintError.changedWhileReading }
                let fileDigest = try hashFile(file, expectedBytes: entry.snapshot.st_size)
                guard sameSnapshot(entry.snapshot, try snapshot(file)) else { throw RoutingBundleFingerprintError.changedWhileReading }
                digest.update(data: Data("\(entry.snapshot.st_size)\0\(fileDigest)\0".utf8))
            }
        }
        // Reopening each directory without following any path component catches
        // resource additions, removals and replaced ancestors during inspection.
        for entry in entries where entry.directory {
            let directory = try openEntry(entry, root: root, directories: directories)
            defer { Darwin.close(directory) }
            guard sameSnapshot(entry.snapshot, try snapshot(directory)) else { throw RoutingBundleFingerprintError.changedWhileReading }
        }
        var final = stat()
        guard lstat(bundle.path, &final) == 0, sameSnapshot(original, final) else { throw RoutingBundleFingerprintError.changedWhileReading }
        return hexadecimal(digest.finalize())
    }

    private static func isDirectory(_ info: stat) -> Bool { info.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) }
    private static func isFile(_ info: stat) -> Bool { info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) && info.st_nlink == 1 }

    private static func snapshot(_ fd: Int32) throws -> stat {
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw RoutingBundleFingerprintError.ioFailure }
        return info
    }

    private static func sameSnapshot(_ left: stat, _ right: stat) -> Bool {
        left.st_dev == right.st_dev && left.st_ino == right.st_ino && left.st_mode == right.st_mode &&
        left.st_nlink == right.st_nlink && left.st_size == right.st_size && left.st_uid == right.st_uid && left.st_gid == right.st_gid &&
        left.st_mtimespec.tv_sec == right.st_mtimespec.tv_sec && left.st_mtimespec.tv_nsec == right.st_mtimespec.tv_nsec &&
        left.st_ctimespec.tv_sec == right.st_ctimespec.tv_sec && left.st_ctimespec.tv_nsec == right.st_ctimespec.tv_nsec
    }

    private static func inventory(_ fd: Int32, path: String, original: stat, entries: inout [Entry], total: inout Int64) throws {
        guard entries.count < maximumEntries, path.utf8.count <= maximumPathBytes else { throw RoutingBundleFingerprintError.budgetExceeded }
        guard isDirectory(original), sameSnapshot(original, try snapshot(fd)) else { throw RoutingBundleFingerprintError.changedWhileReading }
        entries.append(Entry(path: path, directory: true, snapshot: original))
        let directoryFD = dup(fd)
        guard directoryFD >= 0 else { throw RoutingBundleFingerprintError.ioFailure }
        guard let stream = fdopendir(directoryFD) else { Darwin.close(directoryFD); throw RoutingBundleFingerprintError.ioFailure }
        defer { closedir(stream) }
        errno = 0
        while let item = readdir(stream) {
            let length = Int(item.pointee.d_namlen)
            let name = withUnsafePointer(to: &item.pointee.d_name) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: length + 1) { String(validatingUTF8: $0) }
            }
            guard let name = name, name.utf8.count == length, !name.contains("/"), !name.contains("\\"),
                  !name.utf8.contains(where: { $0 < 32 || $0 == 127 }) else {
                throw RoutingBundleFingerprintError.unsafeBundle
            }
            if name == "." || name == ".." { continue }
            let relative = path.isEmpty ? name : path + "/" + name
            guard entries.count < maximumEntries, relative.utf8.count <= maximumPathBytes else { throw RoutingBundleFingerprintError.budgetExceeded }
            var info = stat()
            guard fstatat(fd, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else { throw RoutingBundleFingerprintError.changedWhileReading }
            if isDirectory(info) {
                let child = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { throw RoutingBundleFingerprintError.changedWhileReading }
                defer { Darwin.close(child) }
                try inventory(child, path: relative, original: info, entries: &entries, total: &total)
            } else if isFile(info) {
                guard info.st_size >= 0, info.st_size <= maximumFileBytes, info.st_size <= maximumTotalBytes - total else {
                    throw RoutingBundleFingerprintError.budgetExceeded
                }
                total += info.st_size
                entries.append(Entry(path: relative, directory: false, snapshot: info))
            } else { throw RoutingBundleFingerprintError.unsafeBundle }
            errno = 0
        }
        guard errno == 0 else { throw RoutingBundleFingerprintError.ioFailure }
        guard sameSnapshot(original, try snapshot(fd)) else { throw RoutingBundleFingerprintError.changedWhileReading }
    }

    private static func openEntry(_ entry: Entry, root: Int32, directories: [Data: stat]) throws -> Int32 {
        var current = dup(root)
        guard current >= 0 else { throw RoutingBundleFingerprintError.ioFailure }
        var prefix = ""
        do {
            guard let rootInfo = directories[Data()], sameSnapshot(rootInfo, try snapshot(current)) else { throw RoutingBundleFingerprintError.changedWhileReading }
            if entry.path.isEmpty { return current }
            let parts = entry.path.split(separator: "/", omittingEmptySubsequences: false)
            for (index, part) in parts.enumerated() {
                let final = index == parts.count - 1
                guard !part.isEmpty, part != ".", part != ".." else { throw RoutingBundleFingerprintError.unsafeBundle }
                prefix = prefix.isEmpty ? String(part) : prefix + "/" + part
                let directory = !final || entry.directory
                let next = openat(current, String(part), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (directory ? O_DIRECTORY : 0))
                guard next >= 0 else { throw RoutingBundleFingerprintError.changedWhileReading }
                Darwin.close(current); current = next
                if directory {
                    guard let expected = directories[Data(prefix.utf8)], sameSnapshot(expected, try snapshot(current)) else {
                        throw RoutingBundleFingerprintError.changedWhileReading
                    }
                } else { guard isFile(try snapshot(current)) else { throw RoutingBundleFingerprintError.unsafeBundle } }
            }
            return current
        } catch { Darwin.close(current); throw error }
    }

    private static func hashFile(_ fd: Int32, expectedBytes: Int64) throws -> String {
        var digest = SHA256(), buffer = [UInt8](repeating: 0, count: 64 * 1024), count: Int64 = 0
        while true {
            let bytes = Darwin.read(fd, &buffer, buffer.count)
            if bytes < 0 { if errno == EINTR { continue }; throw RoutingBundleFingerprintError.ioFailure }
            if bytes == 0 { break }
            count += Int64(bytes)
            guard count <= expectedBytes, count <= maximumFileBytes else { throw RoutingBundleFingerprintError.changedWhileReading }
            digest.update(data: Data(buffer.prefix(bytes)))
        }
        guard count == expectedBytes else { throw RoutingBundleFingerprintError.changedWhileReading }
        return hexadecimal(digest.finalize())
    }

    private static func hexadecimal<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
        bytes.map { String(format: "%02x", Int($0)) }.joined()
    }
}
