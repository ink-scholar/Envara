import Foundation
import Dispatch
import Darwin
import RoutingShared

private enum AuditFixtureFailure: Error { case protocolViolation, timeout, transport, identity }

private func waitForParent() throws {
    let deadline = DispatchTime.now().uptimeNanoseconds + 10_000_000_000
    while DispatchTime.now().uptimeNanoseconds < deadline {
        var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
        let remaining = deadline - min(deadline, DispatchTime.now().uptimeNanoseconds)
        let milliseconds = Int32(max(1, (remaining + 999_999) / 1_000_000))
        let result = poll(&descriptor, 1, milliseconds)
        if result < 0 && errno == EINTR { continue }
        guard result >= 0 else { throw AuditFixtureFailure.transport }
        if result == 0 { continue }
        var byte: UInt8 = 0
        let count = Darwin.read(STDIN_FILENO, &byte, 1)
        if count < 0 && errno == EINTR { continue }
        guard count == 1, byte == 1 else { throw AuditFixtureFailure.protocolViolation }
        return
    }
    throw AuditFixtureFailure.timeout
}

private func sendToken() throws {
    let token = try FlowAuditCaller.currentToken()
    guard token.count == 32 else { throw AuditFixtureFailure.protocolViolation }
    try token.withUnsafeBytes { bytes in
        var written = 0
        while written < bytes.count {
            let count = Darwin.write(STDOUT_FILENO, bytes.baseAddress!.advanced(by: written), bytes.count - written)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw AuditFixtureFailure.transport }
            written += count
        }
    }
}

private func replaceOwnExecutable() throws {
    guard let identity = ProcessIdentity.read(getpid()), identity.path.hasPrefix("/") else {
        throw AuditFixtureFailure.identity
    }
    var arguments: [UnsafeMutablePointer<CChar>?] = [strdup(identity.path), strdup("--after-exec"), nil]
    defer { for argument in arguments { if let argument { free(argument) } } }
    guard arguments[0] != nil, arguments[1] != nil else { throw AuditFixtureFailure.transport }
    identity.path.withCString { executable in
        arguments.withUnsafeMutableBufferPointer { buffer in
            _ = execv(executable, buffer.baseAddress!)
        }
    }
    // A successful exec never returns. No token, path or environment is logged.
    throw AuditFixtureFailure.transport
}

do {
    let afterExec = CommandLine.arguments == [CommandLine.arguments[0], "--after-exec"]
    guard CommandLine.arguments.count == 1 || afterExec else { throw AuditFixtureFailure.protocolViolation }
    for descriptor in [STDIN_FILENO, STDOUT_FILENO] {
        var status = stat()
        guard fstat(descriptor, &status) == 0, status.st_mode & mode_t(S_IFMT) == mode_t(S_IFIFO) else {
            throw AuditFixtureFailure.protocolViolation
        }
        let flags = fcntl(descriptor, F_GETFD)
        guard flags >= 0, fcntl(descriptor, F_SETFD, flags & ~FD_CLOEXEC) == 0 else {
            throw AuditFixtureFailure.transport
        }
    }
    guard fcntl(STDOUT_FILENO, F_SETNOSIGPIPE, 1) == 0 else { throw AuditFixtureFailure.transport }
    try sendToken()
    try waitForParent()
    if !afterExec { try replaceOwnExecutable() }
    _exit(0)
} catch {
    _exit(1)
}
