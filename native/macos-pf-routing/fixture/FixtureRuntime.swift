// PF-only fork of the existing sealed fixture; the NE fixture is unchanged.
import Foundation
import Darwin

final class FixtureSocket {
    let descriptor: Int32
    let path: String
    private let device: dev_t
    private let inode: ino_t

    static func validatePath(_ path: String) throws -> String {
        guard path.hasPrefix("/"), path.utf8.count < MemoryLayout<sockaddr_un>.size - MemoryLayout<sa_family_t>.size - 1,
              URL(fileURLWithPath: path).standardizedFileURL.path == path,
              URL(fileURLWithPath: path).resolvingSymlinksInPath().path == path else { throw FixtureFailure.invalidRequest }
        let url = URL(fileURLWithPath: path), name = url.lastPathComponent
        guard name.hasPrefix("acceptance-"), name.hasSuffix(".sock") else { throw FixtureFailure.invalidRequest }
        let text = String(name.dropFirst(11).dropLast(5))
        guard let uuid = UUID(uuidString: text), uuid.uuidString == text else { throw FixtureFailure.invalidRequest }
        var info = stat()
        guard lstat(url.deletingLastPathComponent().path, &info) == 0, info.st_uid == getuid(),
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR), info.st_mode & 0o777 == 0o700 else { throw FixtureFailure.invalidRequest }
        var existing = stat()
        guard lstat(path, &existing) != 0, errno == ENOENT else { throw FixtureFailure.invalidRequest }
        return path
    }

    init(path: String) throws {
        self.path = try Self.validatePath(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw FixtureFailure.transport }
        do {
            try FixtureIO.nonblocking(fd)
            var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
            address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
            withUnsafeMutableBytes(of: &address.sun_path) { bytes in
                path.utf8CString.withUnsafeBytes { source in bytes.copyBytes(from: source) }
            }
            let previousMask = umask(0o077)
            let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            } }
            umask(previousMask)
            guard bound == 0 else { throw FixtureFailure.transport }
            var info = stat()
            guard lstat(path, &info) == 0, info.st_uid == getuid(), info.st_mode & mode_t(S_IFMT) == mode_t(S_IFSOCK),
                  chmod(path, 0o600) == 0, listen(fd, 2) == 0 else {
                _ = unlink(path); throw FixtureFailure.transport
            }
            descriptor = fd; device = info.st_dev; inode = info.st_ino
        } catch { Darwin.close(fd); throw error }
    }

    func accept(deadline: UInt64) throws -> Int32 {
        while true {
            try FixtureIO.wait(descriptor, events: Int16(POLLIN), deadline: deadline)
            let fd = Darwin.accept(descriptor, nil, nil)
            if fd < 0 { if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }; throw FixtureFailure.transport }
            var uid: uid_t = 0, gid: gid_t = 0
            guard getpeereid(fd, &uid, &gid) == 0, uid == getuid() else { Darwin.close(fd); continue }
            do { try FixtureIO.nonblocking(fd); return fd } catch { Darwin.close(fd); throw error }
        }
    }

    @discardableResult func removeOwnedSocket() -> Bool {
        var info = stat()
        if lstat(path, &info) != 0 { return errno == ENOENT }
        guard info.st_dev == device, info.st_ino == inode, info.st_uid == getuid(),
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFSOCK) else { return false }
        return unlink(path) == 0
    }
    deinit { Darwin.close(descriptor); _ = removeOwnedSocket() }
}

final class FixtureRuntime {
    private struct Child {
        let process: Process
        let identity: ProcessIdentity
        let input: Pipe
        let output: Pipe
    }
    private struct UnverifiedChild {
        let process: Process
        let input: Pipe
        let output: Pipe
    }
    private let isChild: Bool
    private let selfIdentity: ProcessIdentity
    private let probes = FixtureProbe()
    private var children: [Int32: Child] = [:]
    private var unverifiedChildren: [UnverifiedChild] = []
    private(set) var stopping = false
    private let lifetimeDeadline: UInt64

    init(isChild: Bool = false) throws {
        guard let identity = ProcessIdentity.read(getpid()) else { throw FixtureFailure.transport }
        selfIdentity = identity; self.isChild = isChild
        lifetimeDeadline = FixtureClock.now + UInt64(FixtureProtocol.lifetimeSeconds * 1_000_000_000)
    }

    func status() -> [String: Any] {
        var result: [String: Any] = ["protocolVersion": FixtureProtocol.version, "fixtureIdentity": FixtureProtocol.identity,
         "bundleIdentifier": Bundle.main.bundleIdentifier ?? "unbundled", "pid": getpid(), "parentPID": getppid(),
         "child": isChild, "maximumLifetimeSeconds": Int(FixtureProtocol.lifetimeSeconds),
         "children": children.keys.sorted(), "unverifiedChildren": unverifiedChildren.map { $0.process.processIdentifier },
         "ownedChildScopeVerified": unverifiedChildren.isEmpty, "nativeRoutingAcceptance": false]
        for (key, value) in probes.reservationStatus { result[key] = value }
        return result
    }

    func handle(_ request: FixtureRequest) -> [String: Any] {
        var response: [String: Any] = ["id": request.id, "op": request.op, "pid": getpid()]
        do {
            guard FixtureClock.now < lifetimeDeadline, !stopping else { throw FixtureFailure.deadline }
            let result: [String: Any]
            switch request.op {
            case "status": result = status()
            case "resolve", "tcp", "udp", "reserve", "probe_reserved", "release_reservation": result = try probes.run(request.probe!, processDeadline: lifetimeDeadline)
            case "spawn_child": result = try spawnChild()
            case "child_probe":
                guard !isChild, let child = children[request.childPID!] else { throw FixtureFailure.childUnavailable }
                let inner = request.childProbe!
                var command = inner.json; command["id"] = request.id
                result = ["childResult": try transact(child, command: command, timeoutMs: inner.timeoutMs + 200)]
            case "close_child":
                guard !isChild, let child = children[request.childPID!] else { throw FixtureFailure.childUnavailable }
                guard close(child) else { throw FixtureFailure.cleanupUnverified }
                children.removeValue(forKey: child.identity.pid)
                result = ["childPID": child.identity.pid, "exitConfirmed": true]
            case "stop":
                stopping = true
                probes.closeReservations()
                let confirmed = cleanupChildren()
                result = ["childrenExitConfirmed": confirmed, "willExit": true]
                if !confirmed { throw FixtureFailure.cleanupUnverified }
            default: throw FixtureFailure.invalidRequest
            }
            response["ok"] = true
            for (key, value) in result { response[key] = value }
        } catch {
            response["ok"] = false; response["code"] = (error as? FixtureFailure ?? .transport).code
        }
        return response
    }

    private func spawnChild() throws -> [String: Any] {
        guard !isChild else { throw FixtureFailure.childUnavailable }
        guard children.count + unverifiedChildren.count < 2 else { throw FixtureFailure.childLimit }
        guard selfIdentity.presence() == .alive else { throw FixtureFailure.childUnavailable }
        let process = Process(), input = Pipe(), output = Pipe()
        process.executableURL = URL(fileURLWithPath: selfIdentity.path)
        process.arguments = ["--child"]
        process.environment = ["PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"]
        if let timezone = ProcessInfo.processInfo.environment["TZ"] { process.environment?["TZ"] = timezone }
        process.standardInput = input; process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run()
        // Record ownership immediately after successful spawn. Every subsequent
        // pipe or identity operation may throw; none may lose the owned child.
        unverifiedChildren.append(UnverifiedChild(process: process, input: input, output: output))
        do {
            try input.fileHandleForReading.close(); try output.fileHandleForWriting.close()
            try FixtureIO.nonblocking(input.fileHandleForWriting.fileDescriptor)
            try FixtureIO.nonblocking(output.fileHandleForReading.fileDescriptor)
            guard let identity = ProcessIdentity.read(process.processIdentifier), identity.parent == getpid(), identity.path == selfIdentity.path else {
                throw FixtureFailure.childUnavailable
            }
            let child = Child(process: process, identity: identity, input: input, output: output)
            children[identity.pid] = child
            unverifiedChildren.removeAll { $0.process === process }
            do {
                let result = try transact(child, command: ["id": "child-start", "op": "status"], timeoutMs: 1500)
                guard result["ok"] as? Bool == true, result["fixtureIdentity"] as? String == FixtureProtocol.identity,
                      result["protocolVersion"] as? Int == FixtureProtocol.version, result["pid"] as? Int32 == identity.pid,
                      result["child"] as? Bool == true else { throw FixtureFailure.childUnavailable }
                return ["childPID": identity.pid, "childStartedSeconds": identity.startedSeconds,
                        "childStartedMicroseconds": identity.startedMicroseconds]
            } catch {
                if close(child) { children.removeValue(forKey: identity.pid) }
                throw error
            }
        } catch {
            // A failed identity read must not turn into an unbounded wait or an
            // unverified PID signal. EOF asks our exact self-copy to exit;
            // unverified ownership remains until Process observes its exit.
            try? input.fileHandleForWriting.close()
            throw error
        }
    }

    private func transact(_ child: Child, command: [String: Any], timeoutMs: Int) throws -> [String: Any] {
        guard child.identity.presence() == .alive, child.process.isRunning else { throw FixtureFailure.childUnavailable }
        let deadline = min(FixtureClock.deadline(milliseconds: timeoutMs), lifetimeDeadline)
        let data = try JSONSerialization.data(withJSONObject: command, options: [.sortedKeys]) + Data([10])
        try FixtureIO.write(data, fd: child.input.fileHandleForWriting.fileDescriptor, deadline: deadline)
        guard let line = try FixtureIO.line(fd: child.output.fileHandleForReading.fileDescriptor, deadline: deadline),
              let result = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
              result["id"] as? String == command["id"] as? String else { throw FixtureFailure.childUnavailable }
        return result
    }

    private func close(_ child: Child) -> Bool {
        try? child.input.fileHandleForWriting.close()
        let graceful = FixtureClock.deadline(milliseconds: 300)
        while child.process.isRunning && FixtureClock.now < graceful { usleep(10_000) }
        if child.process.isRunning { _ = child.identity.signal(SIGTERM) }
        let terminated = FixtureClock.deadline(milliseconds: 300)
        while child.process.isRunning && FixtureClock.now < terminated { usleep(10_000) }
        if child.process.isRunning { _ = child.identity.signal(SIGKILL) }
        let killed = FixtureClock.deadline(milliseconds: 500)
        while child.process.isRunning && FixtureClock.now < killed { usleep(10_000) }
        try? child.output.fileHandleForReading.close()
        return !child.process.isRunning && child.identity.exitConfirmed
    }

    @discardableResult func cleanupChildren() -> Bool {
        var confirmed = true
        for (pid, child) in children {
            if close(child) { children.removeValue(forKey: pid) } else { confirmed = false }
        }
        for child in unverifiedChildren { try? child.input.fileHandleForWriting.close() }
        let deadline = FixtureClock.deadline(milliseconds: 100)
        while unverifiedChildren.contains(where: { $0.process.isRunning }) && FixtureClock.now < deadline { usleep(10_000) }
        unverifiedChildren.removeAll { child in
            if child.process.isRunning { return false }
            try? child.output.fileHandleForReading.close(); return true
        }
        confirmed = confirmed && unverifiedChildren.isEmpty
        return confirmed
    }

    private func serve(input: Int32, output: Int32) throws {
        try FixtureIO.nonblocking(input); try FixtureIO.nonblocking(output)
        while !stopping && FixtureClock.now < lifetimeDeadline {
            let deadline = min(lifetimeDeadline, FixtureClock.now + UInt64(FixtureProtocol.idleSeconds * 1_000_000_000))
            guard let line = try FixtureIO.line(fd: input, deadline: deadline) else { return }
            let response: [String: Any]
            do { response = handle(try FixtureRequest(line: line)) }
            catch {
                let id: Any = FixtureRequest.replyIdentifier(line: line).map { $0 as Any } ?? NSNull()
                response = ["id": id, "ok": false, "code": (error as? FixtureFailure ?? .invalidRequest).code, "pid": getpid()]
            }
            let data = try JSONSerialization.data(withJSONObject: response, options: [.sortedKeys]) + Data([10])
            guard data.count <= FixtureProtocol.maximumLineBytes else { throw FixtureFailure.tooLarge }
            try FixtureIO.write(data, fd: output, deadline: min(lifetimeDeadline, FixtureClock.deadline(milliseconds: 1000)))
        }
    }

    func run(socketPath: String? = nil) throws {
        defer { probes.closeReservations(); _ = cleanupChildren() }
        if let path = socketPath {
            guard !isChild else { throw FixtureFailure.invalidRequest }
            let socket = try FixtureSocket(path: path)
            defer { _ = socket.removeOwnedSocket() }
            while !stopping && FixtureClock.now < lifetimeDeadline {
                let deadline = min(lifetimeDeadline, FixtureClock.now + UInt64(FixtureProtocol.idleSeconds * 1_000_000_000))
                let peer = try socket.accept(deadline: deadline)
                do { try serve(input: peer, output: peer) }
                catch FixtureFailure.deadline { }
                catch FixtureFailure.tooLarge { }
                Darwin.close(peer)
            }
        } else { try serve(input: STDIN_FILENO, output: STDOUT_FILENO) }
    }
}
