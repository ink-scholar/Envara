// No network, credentials, privilege escalation or user-data operations.
// The main process verifies the official release download before invoking this
// helper. Ad-hoc codesign below checks integrity, not independent provenance.
import Foundation
import Darwin

let schema = "envara.mac-update/v1"
let manager = FileManager.default
struct Refusal: Error { let code: String }
func require(_ value: @autoclosure () throws -> Bool, _ code: String) throws {
    if try !value() { throw Refusal(code: code) }
}
func emit(_ value: [String: Any]) {
    guard var data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return }
    data.append(10)
    data.withUnsafeBytes { bytes in _ = Darwin.write(STDOUT_FILENO, bytes.baseAddress, bytes.count) }
}
func info(_ path: String) throws -> stat {
    var value = stat()
    try require(lstat(path, &value) == 0, "APP_UPDATE_PATH")
    return value
}
func canonical(_ path: String) throws {
    try require(path.hasPrefix("/") && !path.contains("\0") && !path.contains("\n") && !path.contains("\r") && path.utf8.count < 4096,
                "APP_UPDATE_PATH")
    var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    try require(realpath(path, &buffer) != nil && String(cString: buffer) == path, "APP_UPDATE_PATH")
    var current = ""
    for segment in path.split(separator: "/") {
        current += "/" + segment
        let item = try info(current)
        try require((item.st_mode & S_IFMT) != S_IFLNK, "APP_UPDATE_PATH")
    }
}
func directory(_ path: String, privateOnly: Bool = false) throws -> Int32 {
    try canonical(path)
    let item = try info(path)
    try require((item.st_mode & S_IFMT) == S_IFDIR, "APP_UPDATE_PATH")
    if privateOnly { try require(item.st_uid == getuid() && item.st_mode & 0o077 == 0, "APP_UPDATE_PATH") }
    let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    try require(descriptor >= 0, "APP_UPDATE_PATH")
    var actual = stat()
    if fstat(descriptor, &actual) != 0 || actual.st_dev != item.st_dev || actual.st_ino != item.st_ino {
        close(descriptor); throw Refusal(code: "APP_UPDATE_PATH")
    }
    return descriptor
}
func same(_ fd: Int32, _ path: String) -> Bool {
    var actual = stat(), current = stat()
    return fstat(fd, &actual) == 0 && lstat(path, &current) == 0 && actual.st_dev == current.st_dev && actual.st_ino == current.st_ino
        && (current.st_mode & S_IFMT) == S_IFDIR
}
func identityAt(_ parent: Int32, _ name: String) throws -> stat {
    var value = stat()
    try require(fstatat(parent, name, &value, AT_SYMLINK_NOFOLLOW) == 0 && value.st_mode & S_IFMT == S_IFDIR,
                "APP_UPDATE_PATH")
    return value
}
func matches(_ left: stat, _ right: stat) -> Bool { left.st_dev == right.st_dev && left.st_ino == right.st_ino }
func within(_ root: String, _ path: String) -> Bool { path == root || path.hasPrefix(root + "/") }

// Fixed system executables only. A timeout signals only the child we created;
// if termination is not confirmed the operation stays failed and no swap runs.
func command(_ executable: String, _ arguments: [String], seconds: Double = 90) throws {
    let process = Process(), finished = DispatchSemaphore(value: 0)
    process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
    process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
    process.standardInput = FileHandle.nullDevice; process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
    process.terminationHandler = { _ in finished.signal() }
    do { try process.run() } catch { throw Refusal(code: "APP_UPDATE_TOOL_FAILED") }
    if finished.wait(timeout: .now() + seconds) == .timedOut {
        if process.isRunning { process.terminate() }
        _ = finished.wait(timeout: .now() + 5)
        throw Refusal(code: "APP_UPDATE_TOOL_TIMEOUT")
    }
    try require(process.terminationReason == .exit && process.terminationStatus == 0, "APP_UPDATE_VALIDATION")
}
func validateTree(_ app: String) throws {
    try canonical(app)
    let root = try info(app)
    try require(root.st_uid == getuid() && root.st_mode & S_IFMT == S_IFDIR && root.st_mode & 0o022 == 0, "APP_UPDATE_PATH")
    guard let entries = manager.enumerator(atPath: app) else { throw Refusal(code: "APP_UPDATE_PATH") }
    var count = 0
    for case let entry as String in entries {
        count += 1; try require(count <= 250000, "APP_UPDATE_PATH")
        let path = app + "/" + entry, value = try info(path), kind = value.st_mode & S_IFMT
        try require(value.st_uid == getuid(), "APP_UPDATE_PATH")
        if kind == S_IFLNK {
            let target = try manager.destinationOfSymbolicLink(atPath: path)
            let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
            try require(!target.hasPrefix("/") && within(app, resolved), "APP_UPDATE_PATH")
            entries.skipDescendants()
        } else {
            try require((kind == S_IFDIR || kind == S_IFREG) && value.st_mode & 0o022 == 0 && (kind != S_IFREG || value.st_nlink == 1), "APP_UPDATE_PATH")
        }
    }
}
func minimumSystemVersion(_ value: Any) throws -> [Int] {
    guard let text = value as? String,
          let matched = text.range(of: "^(0|[1-9][0-9]{0,3})(\\.(0|[1-9][0-9]{0,3})){0,2}$", options: .regularExpression),
          matched.lowerBound == text.startIndex, matched.upperBound == text.endIndex else {
        throw Refusal(code: "APP_UPDATE_SYSTEM_UNSUPPORTED")
    }
    let parts = text.split(separator: ".").compactMap { Int($0) }
    return parts + Array(repeating: 0, count: 3 - parts.count)
}
func validateSystemRequirement(_ plist: [String: Any]) throws {
    var minimum: [Int]?
    if let generic = plist["LSMinimumSystemVersion"] { minimum = try minimumSystemVersion(generic) }
    if let architectures = plist["LSMinimumSystemVersionByArchitecture"] {
        guard let values = architectures as? [String: Any] else { throw Refusal(code: "APP_UPDATE_SYSTEM_UNSUPPORTED") }
        if let arm64 = values["arm64"] { minimum = try minimumSystemVersion(arm64) }
    }
    guard let minimum = minimum else { return }
    let system = ProcessInfo.processInfo.operatingSystemVersion
    let current = [system.majorVersion, system.minorVersion, system.patchVersion]
    for index in 0..<3 {
        if current[index] > minimum[index] { return }
        try require(current[index] == minimum[index], "APP_UPDATE_SYSTEM_UNSUPPORTED")
    }
}
func validateBundle(_ app: String, version: String) throws {
    try validateTree(app)
    let plistURL = URL(fileURLWithPath: app + "/Contents/Info.plist")
    try require(try info(plistURL.path).st_size <= 1024 * 1024, "APP_UPDATE_VALIDATION")
    let bytes = try Data(contentsOf: plistURL)
    try require(bytes.count <= 1024 * 1024, "APP_UPDATE_VALIDATION")
    guard let plist = try PropertyListSerialization.propertyList(from: bytes, options: [], format: nil) as? [String: Any] else {
        throw Refusal(code: "APP_UPDATE_VALIDATION")
    }
    try require(plist["CFBundleIdentifier"] as? String == "io.envara.desktop"
        && plist["CFBundleExecutable"] as? String == "Envara"
        && plist["CFBundleShortVersionString"] as? String == version, "APP_UPDATE_VALIDATION")
    try validateSystemRequirement(plist)
    let executable = app + "/Contents/MacOS/Envara"
    let fd = open(executable, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    try require(fd >= 0, "APP_UPDATE_VALIDATION")
    defer { close(fd) }
    var header = [UInt32](repeating: 0, count: 2)
    let length = header.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
    try require(length == 8 && header[0] == 0xfeedfacf && header[1] == 0x0100000c, "APP_UPDATE_ARCHITECTURE")
    try command("/usr/bin/codesign", ["--verify", "--deep", "--strict", app])
}
struct Birth { let seconds: UInt64; let microseconds: UInt64 }
func processInfo(_ pid: Int32) throws -> proc_bsdinfo? {
    var value = proc_bsdinfo(); errno = 0
    let length = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &value, Int32(MemoryLayout<proc_bsdinfo>.size))
    if length == 0 && errno == ESRCH { return nil }
    try require(length == MemoryLayout<proc_bsdinfo>.size && value.pbi_pid == UInt32(pid) && value.pbi_start_tvsec > 0,
                "APP_UPDATE_PARENT_UNKNOWN")
    return value
}
func processPath(_ pid: Int32) throws -> String {
    var value = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    let length = proc_pidpath(pid, &value, UInt32(value.count))
    try require(length > 0 && length < value.count && value.contains(0), "APP_UPDATE_PARENT_UNKNOWN")
    return String(cString: value)
}
func bindParent(_ pid: Int32, executable: String) throws -> Birth {
    try require(pid > 1 && pid == getppid(), "APP_UPDATE_PARENT")
    guard let first = try processInfo(pid) else { throw Refusal(code: "APP_UPDATE_PARENT") }
    try require(first.pbi_uid == getuid() && first.pbi_ruid == getuid() && (try processPath(pid)) == executable, "APP_UPDATE_PARENT")
    guard let after = try processInfo(pid) else { throw Refusal(code: "APP_UPDATE_PARENT") }
    try require(first.pbi_start_tvsec == after.pbi_start_tvsec && first.pbi_start_tvusec == after.pbi_start_tvusec && after.pbi_uid == getuid(), "APP_UPDATE_PARENT")
    return Birth(seconds: first.pbi_start_tvsec, microseconds: first.pbi_start_tvusec)
}
func waitForParent(_ pid: Int32, birth: Birth, executable: String) throws {
    let deadline = ProcessInfo.processInfo.systemUptime + 120
    while ProcessInfo.processInfo.systemUptime < deadline {
        guard let current = try processInfo(pid) else { return }
        if current.pbi_start_tvsec != birth.seconds || current.pbi_start_tvusec != birth.microseconds { return }
        try require(current.pbi_uid == getuid(), "APP_UPDATE_PARENT_UNKNOWN")
        // Zombies retain no execution authority; still wait for the OS to reap
        // them rather than interpreting a failed executable-path query as exit.
        if current.pbi_status != UInt32(SZOMB) { try require(try processPath(pid) == executable, "APP_UPDATE_PARENT_UNKNOWN") }
        usleep(100000)
    }
    throw Refusal(code: "APP_UPDATE_PARENT_TIMEOUT")
}

func processName(_ value: proc_bsdinfo) -> String {
    var mutable = value
    return withUnsafePointer(to: &mutable.pbi_comm) {
        $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMLEN)) { String(cString: $0) }
    }
}
// The names are fixed by the two binaries we own. Prefiltering the kernel's
// executable name avoids treating unrelated, already-unlinked programs as an
// unreadable Envara instance. A relevant candidate still requires exact path,
// UID and stable birth checks; a missing path for that candidate fails closed.
func matchingOwnedProcess(executable: String, name: String) throws -> Bool {
    let needed = proc_listpids(UInt32(PROC_UID_ONLY), UInt32(getuid()), nil, 0)
    try require(needed > 0 && needed < 4 * 1024 * 1024, "APP_UPDATE_PARENT_UNKNOWN")
    var pids = [Int32](repeating: 0, count: Int(needed) / MemoryLayout<Int32>.size + 1024)
    let capacity = pids.count * MemoryLayout<Int32>.size
    let actual = pids.withUnsafeMutableBytes { proc_listpids(UInt32(PROC_UID_ONLY), UInt32(getuid()), $0.baseAddress, Int32($0.count)) }
    try require(actual > 0 && actual < capacity && actual % Int32(MemoryLayout<Int32>.size) == 0, "APP_UPDATE_PARENT_UNKNOWN")
    for pid in pids.prefix(Int(actual) / MemoryLayout<Int32>.size) where pid > 1 && pid != getpid() {
        guard let before = try processInfo(pid) else { continue }
        if before.pbi_uid != getuid() || before.pbi_status == UInt32(SZOMB) || processName(before) != name { continue }
        let actualPath: String
        do { actualPath = try processPath(pid) } catch {
            if try processInfo(pid) == nil { continue }
            throw Refusal(code: "APP_UPDATE_PARENT_UNKNOWN")
        }
        guard let after = try processInfo(pid) else { continue }
        try require(before.pbi_start_tvsec == after.pbi_start_tvsec && before.pbi_start_tvusec == after.pbi_start_tvusec,
                    "APP_UPDATE_PARENT_UNKNOWN")
        if actualPath == executable { return true }
    }
    return false
}
// The app startup gate prevents future launches from initializing resources.
// This last check also refuses another already-running main instance. Existing
// child-resource cleanup remains the main process's explicit commit condition.
func requireNoRunningBundle(_ app: String) throws {
    let deadline = ProcessInfo.processInfo.systemUptime + 3
    while try matchingOwnedProcess(executable: app + "/Contents/MacOS/Envara", name: "Envara") {
        try require(ProcessInfo.processInfo.systemUptime < deadline, "APP_UPDATE_APP_RUNNING")
        usleep(50000)
    }
}
func installerStatus() -> Int32 {
    do {
        try require(getuid() != 0 && geteuid() == getuid(), "APP_UPDATE_LOCATION")
        let root = CommandLine.arguments[2], app = CommandLine.arguments[4]
        guard let origin = Int32(CommandLine.arguments[3]), origin > 1 else { throw Refusal(code: "APP_UPDATE_PROTOCOL") }
        let descriptor = try directory(root, privateOnly: true); defer { close(descriptor) }
        try canonical(app)
        let helper = try info(root + "/EnvaraUpdater")
        try require(helper.st_uid == getuid() && helper.st_mode & S_IFMT == S_IFREG && helper.st_mode & 0o077 == 0 && helper.st_nlink == 1, "APP_UPDATE_PATH")
        var originAlive = false
        if let before = try processInfo(origin), before.pbi_uid == getuid(), before.pbi_status != UInt32(SZOMB) {
            let actual = try processPath(origin)
            if let after = try processInfo(origin) {
                try require(before.pbi_start_tvsec == after.pbi_start_tvsec && before.pbi_start_tvusec == after.pbi_start_tvusec, "APP_UPDATE_PARENT_UNKNOWN")
                originAlive = actual == app + "/Contents/MacOS/Envara"
            }
        }
        let updaterAlive = try matchingOwnedProcess(executable: root + "/EnvaraUpdater", name: "EnvaraUpdater")
        emit(["schema": schema, "type": "installer-status", "active": originAlive || updaterAlive])
        return 0
    } catch {
        emit(["schema": schema, "type": "failed", "code": (error as? Refusal)?.code ?? "APP_UPDATE_PARENT_UNKNOWN"])
        return 1
    }
}
func line(seconds: Double) throws -> [String: Any] {
    let deadline = ProcessInfo.processInfo.systemUptime + seconds
    var bytes = [UInt8]()
    while ProcessInfo.processInfo.systemUptime < deadline && bytes.count < 16384 {
        var event = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
        let remaining = max(1, min(1000, Int32((deadline - ProcessInfo.processInfo.systemUptime) * 1000)))
        let ready = poll(&event, 1, remaining)
        if ready < 0 && errno == EINTR { continue }
        try require(ready >= 0, "APP_UPDATE_PROTOCOL")
        if ready == 0 { continue }
        var byte: UInt8 = 0
        let length = Darwin.read(STDIN_FILENO, &byte, 1)
        try require(length == 1, "APP_UPDATE_CANCELLED")
        if byte == 10 {
            guard let object = try JSONSerialization.jsonObject(with: Data(bytes)) as? [String: Any] else { throw Refusal(code: "APP_UPDATE_PROTOCOL") }
            return object
        }
        bytes.append(byte)
    }
    throw Refusal(code: "APP_UPDATE_TIMEOUT")
}
func string(_ object: [String: Any], _ key: String) throws -> String {
    guard let value = object[key] as? String else { throw Refusal(code: "APP_UPDATE_PROTOCOL") }; return value
}
func receipt(_ descriptor: Int32, _ value: [String: Any]) {
    guard descriptor >= 0, var bytes = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return }
    bytes.append(10)
    let temporary = ".result-" + UUID().uuidString + ".tmp"
    let fd = openat(descriptor, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    if fd < 0 { return }; defer { close(fd) }
    let written = bytes.withUnsafeBytes { buffer in Darwin.write(fd, buffer.baseAddress, buffer.count) }
    if written == bytes.count && fsync(fd) == 0 {
        _ = renameatx_np(descriptor, temporary, descriptor, "result.json", UInt32(RENAME_EXCL))
        _ = fsync(descriptor)
    }
    _ = unlinkat(descriptor, temporary, 0)
}

// Deletion is restricted to descriptors for the exclusive prepared directory;
// symlinks are unlinked, never traversed. The old bundle is never cleaned here.
func removeChildren(_ descriptor: Int32) throws {
    let duplicate = dup(descriptor)
    try require(duplicate >= 0, "APP_UPDATE_CLEANUP_UNCERTAIN")
    guard let stream = fdopendir(duplicate) else { close(duplicate); throw Refusal(code: "APP_UPDATE_CLEANUP_UNCERTAIN") }
    defer { closedir(stream) }
    while let entry = readdir(stream) {
        let name = withUnsafePointer(to: &entry.pointee.d_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
        }
        if name == "." || name == ".." { continue }
        var before = stat()
        try require(fstatat(descriptor, name, &before, AT_SYMLINK_NOFOLLOW) == 0, "APP_UPDATE_CLEANUP_UNCERTAIN")
        if before.st_mode & S_IFMT == S_IFDIR {
            let child = openat(descriptor, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            try require(child >= 0, "APP_UPDATE_CLEANUP_UNCERTAIN")
            do {
                var opened = stat()
                try require(fstat(child, &opened) == 0 && matches(before, opened), "APP_UPDATE_CLEANUP_UNCERTAIN")
                try removeChildren(child)
                try require(matches(try identityAt(descriptor, name), opened), "APP_UPDATE_CLEANUP_UNCERTAIN")
                try require(unlinkat(descriptor, name, AT_REMOVEDIR) == 0, "APP_UPDATE_CLEANUP_UNCERTAIN")
                close(child)
            } catch { close(child); throw error }
        } else {
            try require(before.st_mode & S_IFMT == S_IFREG || before.st_mode & S_IFMT == S_IFLNK, "APP_UPDATE_CLEANUP_UNCERTAIN")
            try require(unlinkat(descriptor, name, 0) == 0, "APP_UPDATE_CLEANUP_UNCERTAIN")
        }
    }
}

func install() -> Int32 {
    var stageFD: Int32 = -1, parentFD: Int32 = -1, preparedFD: Int32 = -1
    defer { for fd in [stageFD, parentFD, preparedFD] where fd >= 0 { close(fd) } }
    var committed = false, swapped = false, prepared = false, parentExited = false, backupName: String? = nil
    var restartOriginal: (() throws -> Void)?
    do {
        try require(CommandLine.arguments.count == 1 && getuid() != 0 && geteuid() == getuid(), "APP_UPDATE_LOCATION")
        var input = stat()
        try require(fstat(STDIN_FILENO, &input) == 0 && [S_IFIFO, S_IFSOCK].contains(input.st_mode & S_IFMT), "APP_UPDATE_PROTOCOL")
        let request = try line(seconds: 10)
        try require(Set(request.keys) == Set(["schema", "currentApp", "stagedApp", "stageRoot", "expectedVersion", "expectedCurrentVersion", "parentPid", "capability"]), "APP_UPDATE_PROTOCOL")
        try require(try string(request, "schema") == schema, "APP_UPDATE_PROTOCOL")
        let currentApp = try string(request, "currentApp"), stagedApp = try string(request, "stagedApp"), stageRoot = try string(request, "stageRoot")
        let version = try string(request, "expectedVersion"), previous = try string(request, "expectedCurrentVersion"), capability = try string(request, "capability")
        try require(capability.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil, "APP_UPDATE_PROTOCOL")
        try require(version.range(of: "^[0-9]{1,6}\\.[0-9]{1,6}\\.[0-9]{1,6}$", options: .regularExpression) != nil
            && previous.range(of: "^[0-9]{1,6}\\.[0-9]{1,6}\\.[0-9]{1,6}$", options: .regularExpression) != nil
            && version.compare(previous, options: .numeric) == .orderedDescending, "APP_UPDATE_VERSION")
        guard let pidNumber = request["parentPid"] as? NSNumber, CFGetTypeID(pidNumber) != CFBooleanGetTypeID(),
              pidNumber.doubleValue == Double(pidNumber.int32Value) else { throw Refusal(code: "APP_UPDATE_PARENT") }
        let pid = pidNumber.int32Value
        try require(currentApp.hasSuffix(".app") && stagedApp == stageRoot + "/Envara.app"
            && !within(currentApp, stageRoot) && !within(stageRoot, currentApp)
            && !currentApp.hasPrefix("/Volumes/") && !currentApp.contains("/AppTranslocation/"), "APP_UPDATE_LOCATION")
        stageFD = try directory(stageRoot, privateOnly: true)
        try require(try processPath(getpid()) == stageRoot + "/EnvaraUpdater", "APP_UPDATE_PATH")
        let helper = try info(stageRoot + "/EnvaraUpdater")
        try require(helper.st_uid == getuid() && helper.st_mode & S_IFMT == S_IFREG && helper.st_mode & 0o077 == 0 && helper.st_nlink == 1, "APP_UPDATE_PATH")
        let parentPath = URL(fileURLWithPath: currentApp).deletingLastPathComponent().path
        let currentName = URL(fileURLWithPath: currentApp).lastPathComponent
        parentFD = try directory(parentPath)
        try require(access(parentPath, W_OK) == 0 && access(currentApp, W_OK) == 0, "APP_UPDATE_LOCATION")
        var volume = statfs()
        try require(fstatfs(parentFD, &volume) == 0 && volume.f_flags & UInt32(MNT_RDONLY) == 0, "APP_UPDATE_LOCATION")
        let parentBirth = try bindParent(pid, executable: currentApp + "/Contents/MacOS/Envara")
        try validateBundle(currentApp, version: previous)
        try validateBundle(stagedApp, version: version)
        let original = try identityAt(parentFD, currentName)
        restartOriginal = {
            try canonical(parentPath)
            try require(same(parentFD, parentPath) && matches(try identityAt(parentFD, currentName), original), "APP_UPDATE_PATH")
            try validateBundle(currentApp, version: previous)
            try requireNoRunningBundle(currentApp)
            try command("/usr/bin/open", ["-n", currentApp], seconds: 30)
        }
        let ownedName = ".envara-update-" + String(capability.prefix(16))
        try require(mkdirat(parentFD, ownedName, 0o700) == 0, "APP_UPDATE_PREPARATION")
        backupName = ownedName
        let preparedRoot = parentPath + "/" + ownedName, preparedApp = preparedRoot + "/Envara.app"
        preparedFD = try directory(preparedRoot, privateOnly: true)
        try command("/usr/bin/ditto", [stagedApp, preparedApp], seconds: 600)
        try validateBundle(preparedApp, version: version)
        let candidate = try identityAt(preparedFD, "Envara.app")
        try require(original.st_dev == candidate.st_dev && same(parentFD, parentPath) && same(stageFD, stageRoot), "APP_UPDATE_PATH")
        prepared = true
        emit(["schema": schema, "type": "ready", "parentBirth": "\(parentBirth.seconds):\(String(format: "%06llu", parentBirth.microseconds))"])
        let authorization = try line(seconds: 900)
        try require(Set(authorization.keys) == Set(["type", "capability"]) && authorization["type"] as? String == "commit"
            && authorization["capability"] as? String == capability, "APP_UPDATE_AUTHORIZATION")
        committed = true
        emit(["schema": schema, "type": "authorized"])
        try waitForParent(pid, birth: parentBirth, executable: currentApp + "/Contents/MacOS/Envara")
        parentExited = true
        try canonical(parentPath); try canonical(stageRoot); try canonical(preparedRoot)
        try require(same(parentFD, parentPath) && same(stageFD, stageRoot) && same(preparedFD, preparedRoot)
            && matches(try identityAt(parentFD, currentName), original) && matches(try identityAt(preparedFD, "Envara.app"), candidate), "APP_UPDATE_PATH")
        try validateBundle(currentApp, version: previous)
        try validateBundle(preparedApp, version: version)
        try canonical(parentPath); try canonical(preparedRoot)
        try require(same(parentFD, parentPath) && same(preparedFD, preparedRoot)
            && matches(try identityAt(parentFD, currentName), original) && matches(try identityAt(preparedFD, "Envara.app"), candidate), "APP_UPDATE_PATH")
        try requireNoRunningBundle(currentApp)
        try require(renameatx_np(parentFD, currentName, preparedFD, "Envara.app", UInt32(RENAME_SWAP)) == 0, "APP_UPDATE_REPLACE_FAILED")
        swapped = true
        do {
            try require(matches(try identityAt(parentFD, currentName), candidate) && matches(try identityAt(preparedFD, "Envara.app"), original), "APP_UPDATE_PATH")
            try validateBundle(currentApp, version: version)
        } catch {
            // Roll back only the exact two directory identities we swapped.
            // Never restore data or replace an unrecognized application.
            let rollbackSafe = same(parentFD, parentPath) && same(preparedFD, preparedRoot)
                && ((try? identityAt(parentFD, currentName)).map { matches($0, candidate) } ?? false)
                && ((try? identityAt(preparedFD, "Envara.app")).map { matches($0, original) } ?? false)
            if rollbackSafe && renameatx_np(parentFD, currentName, preparedFD, "Envara.app", UInt32(RENAME_SWAP)) == 0 {
                swapped = false
                do { try validateBundle(currentApp, version: previous) }
                catch { throw Refusal(code: "APP_UPDATE_ROLLBACK_UNCERTAIN") }
                throw Refusal(code: "APP_UPDATE_ROLLED_BACK")
            }
            throw Refusal(code: "APP_UPDATE_ROLLBACK_UNCERTAIN")
        }
        _ = fsync(parentFD); _ = fsync(preparedFD)
        // Once the new application may have started, never swap code back under
        // it or roll back its data. A launch failure leaves the installed app.
        var relaunch = "requested"
        do { try command("/usr/bin/open", ["-n", currentApp], seconds: 30) } catch { relaunch = "failed" }
        let result: [String: Any] = ["schema": schema, "type": "installed", "version": version, "relaunch": relaunch, "backupName": ownedName]
        receipt(stageFD, result); emit(result); return 0
    } catch {
        var result: [String: Any] = ["schema": schema, "type": "failed", "code": (error as? Refusal)?.code ?? "APP_UPDATE_FAILED",
                                     "committed": committed, "replaced": swapped]
        if prepared && !committed, let name = backupName {
            do {
                var owned = stat()
                try require(fstat(preparedFD, &owned) == 0 && matches(try identityAt(parentFD, name), owned), "APP_UPDATE_CLEANUP_UNCERTAIN")
                try removeChildren(preparedFD)
                try require(matches(try identityAt(parentFD, name), owned) && unlinkat(parentFD, name, AT_REMOVEDIR) == 0, "APP_UPDATE_CLEANUP_UNCERTAIN")
                backupName = nil
            } catch { result["cleanupCode"] = "APP_UPDATE_CLEANUP_UNCERTAIN" }
        }
        // Failed preparation and committed transactions retain their owned
        // directory for recovery. Never delete a previous installed bundle.
        if let backupName = backupName { result["backupName"] = backupName }
        if committed { receipt(stageFD, result) }
        // Publish refusal/rollback before asking the old version to restart,
        // so its startup gate can distinguish completed failure from a live
        // installation. This optional launch outcome is stdout-only.
        if parentExited && !swapped && result["code"] as? String != "APP_UPDATE_ROLLBACK_UNCERTAIN", let restart = restartOriginal {
            do { try restart(); result["relaunch"] = "requested" } catch { result["relaunch"] = "failed" }
        }
        emit(result); return 1
    }
}
signal(SIGPIPE, SIG_IGN)
if CommandLine.arguments.count == 5 && CommandLine.arguments[1] == "--installer-active" { exit(installerStatus()) }
exit(install())
