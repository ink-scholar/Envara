import Foundation
import Dispatch
import Darwin
import XCTest
@testable import RoutingShared

final class FlowAuditExecTests: XCTestCase {
    private enum FixtureFailure: Error { case unavailable, timeout, transport, identity }

    private func fixtureExecutable() throws -> URL {
        let buildDirectory = Bundle(for: FlowAuditExecTests.self).bundleURL.deletingLastPathComponent()
        let executable = buildDirectory.appendingPathComponent("EnvaraRoutingAuditFixture").resolvingSymlinksInPath()
        guard FileManager.default.isExecutableFile(atPath: executable.path) else { throw FixtureFailure.unavailable }
        return executable
    }

    private func nonblocking(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else { throw FixtureFailure.transport }
    }

    private func ready(_ descriptor: Int32, events: Int16, deadline: UInt64) throws {
        while DispatchTime.now().uptimeNanoseconds < deadline {
            var request = pollfd(fd: descriptor, events: events, revents: 0)
            let remaining = deadline - min(deadline, DispatchTime.now().uptimeNanoseconds)
            let milliseconds = Int32(max(1, (remaining + 999_999) / 1_000_000))
            let result = poll(&request, 1, milliseconds)
            if result < 0 && errno == EINTR { continue }
            guard result >= 0 else { throw FixtureFailure.transport }
            if result == 0 { continue }
            guard request.revents & Int16(POLLERR | POLLNVAL) == 0 else { throw FixtureFailure.transport }
            if request.revents & (events | Int16(POLLHUP)) != 0 { return }
        }
        throw FixtureFailure.timeout
    }

    private func readToken(_ descriptor: Int32) throws -> Data {
        let deadline = DispatchTime.now().uptimeNanoseconds + 3_000_000_000
        var bytes = [UInt8](repeating: 0, count: 32), received = 0
        while received < bytes.count {
            try ready(descriptor, events: Int16(POLLIN), deadline: deadline)
            let count = bytes.withUnsafeMutableBytes { buffer in
                Darwin.read(descriptor, buffer.baseAddress!.advanced(by: received), buffer.count - received)
            }
            if count < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            guard count > 0 else { throw FixtureFailure.transport }
            received += count
        }
        return Data(bytes)
    }

    private func allowNextStage(_ descriptor: Int32) throws {
        let deadline = DispatchTime.now().uptimeNanoseconds + 3_000_000_000
        var byte: UInt8 = 1
        while true {
            try ready(descriptor, events: Int16(POLLOUT), deadline: deadline)
            let count = Darwin.write(descriptor, &byte, 1)
            if count < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            guard count == 1 else { throw FixtureFailure.transport }
            return
        }
    }

    private func waitForExit(_ process: Process, milliseconds: UInt64) -> Bool {
        let deadline = DispatchTime.now().uptimeNanoseconds + milliseconds * 1_000_000
        while process.isRunning && DispatchTime.now().uptimeNanoseconds < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        guard !process.isRunning else { return false }
        process.waitUntilExit()
        return true
    }

    func testSamePathExecInvalidatesTheRetainedKernelCallerGeneration() throws {
        let executable = try fixtureExecutable()
        let workspace = FileManager.default.temporaryDirectory.appendingPathComponent("envara-audit-exec-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: workspace) }
        let process = Process(), input = Pipe(), output = Pipe()
        process.executableURL = executable
        process.arguments = []
        process.environment = ["TMPDIR": workspace.path, "LC_ALL": "C"]
        process.currentDirectoryURL = workspace
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        var ownedIdentity: ProcessIdentity?
        var launched = false
        defer {
            try? input.fileHandleForWriting.close()
            try? input.fileHandleForReading.close()
            try? output.fileHandleForWriting.close()
            try? output.fileHandleForReading.close()
            if launched && process.isRunning && !waitForExit(process, milliseconds: 500), let identity = ownedIdentity {
                // No process group or name is signalled; birth/path are checked.
                _ = identity.signal(SIGKILL)
            }
            if launched {
                XCTAssertTrue(waitForExit(process, milliseconds: 2000), "Owned audit fixture cleanup must complete")
            }
        }
        try process.run()
        launched = true
        guard let initial = ProcessIdentity.read(process.processIdentifier), initial.parent == getpid(),
              initial.path == executable.path else { throw FixtureFailure.identity }
        ownedIdentity = initial
        try input.fileHandleForReading.close()
        try output.fileHandleForWriting.close()
        let inputDescriptor = input.fileHandleForWriting.fileDescriptor
        let outputDescriptor = output.fileHandleForReading.fileDescriptor
        try nonblocking(inputDescriptor)
        try nonblocking(outputDescriptor)
        guard fcntl(inputDescriptor, F_SETNOSIGPIPE, 1) == 0 else { throw FixtureFailure.transport }

        let before = try FlowAuditCaller.inspect(readToken(outputDescriptor), authorizedUID: getuid())
        XCTAssertEqual(before.identity.pid, initial.pid)
        XCTAssertEqual(before.identity, initial)
        XCTAssertTrue(before.isCurrent(authorizedUID: getuid()))
        try allowNextStage(inputDescriptor)
        let after = try FlowAuditCaller.inspect(readToken(outputDescriptor), authorizedUID: getuid())
        XCTAssertEqual(after.identity.pid, before.identity.pid)
        XCTAssertEqual(after.identity.startedSeconds, before.identity.startedSeconds)
        XCTAssertEqual(after.identity.startedMicroseconds, before.identity.startedMicroseconds)
        XCTAssertEqual(after.identity.path, before.identity.path)
        XCTAssertTrue(after.pidVersion != before.pidVersion, "exec must change the audit generation")
        XCTAssertFalse(before.isCurrent(authorizedUID: getuid()))
        XCTAssertTrue(after.isCurrent(authorizedUID: getuid()))

        try allowNextStage(inputDescriptor)
        XCTAssertTrue(waitForExit(process, milliseconds: 3000), "Owned audit fixture must exit after permission")
        if !process.isRunning {
            XCTAssertEqual(process.terminationReason, .exit)
            XCTAssertEqual(process.terminationStatus, 0)
        }
    }
}
