import Foundation
import Darwin
import RoutingShared

private final class ProfileInventoryOutput: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes = Data()
    private var invalid = false
    private var finished = false
    func drain(_ handle: FileHandle) {
        defer { lock.lock(); finished = true; lock.unlock() }
        do {
            while let chunk = try handle.read(upToCount: 8192), !chunk.isEmpty {
                lock.lock()
                if chunk.count > 2_097_152 - bytes.count { invalid = true }
                else if !invalid { bytes.append(chunk) }
                lock.unlock()
            }
        } catch { lock.lock(); invalid = true; lock.unlock() }
    }
    func snapshot() -> (Data, Bool, Bool) {
        lock.lock(); defer { lock.unlock() }
        return (bytes, invalid, finished)
    }
}

private func profileCommandPollDelay() async {
    // Cleanup must still yield if its caller is cancelled; swallowing a cancelled
    // Task.sleep error would turn the bounded polling loop into a busy spin.
    await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + .milliseconds(50)) {
            continuation.resume()
        }
    }
}

/// Fixed, non-interactive read-only command. The returned scope deliberately
/// excludes "all": without -all, root sees device profiles and other users see
/// their own profiles. Neither result attests global conflict freedom.
func validateInstalledProfileNamespace(runtime: RuntimeStore) async throws -> String {
    let process = Process(), output = Pipe(), collected = ProfileInventoryOutput()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/profiles")
    process.arguments = ["show", "-type", "configuration", "-output", "stdout-xml"]
    process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    do { try process.run() } catch { throw RoutingError.notReady("installed-profile-inventory-command-unavailable") }
    let identity = ProcessIdentity.read(process.processIdentifier)
    DispatchQueue.global(qos: .utility).async { collected.drain(output.fileHandleForReading) }
    let deadline = ProcessInfo.processInfo.systemUptime + 3
    var timedOut = false
    while process.isRunning || !collected.snapshot().2 {
        if collected.snapshot().1 || Task.isCancelled || ProcessInfo.processInfo.systemUptime >= deadline {
            timedOut = true; break
        }
        await profileCommandPollDelay()
    }
    if timedOut {
        // Never send a signal to a guessed/recycled PID. Both signals recheck the
        // exact executable and process birth of the command this function started.
        if process.isRunning, let identity = identity { _ = identity.signal(SIGTERM) }
        let termDeadline = ProcessInfo.processInfo.systemUptime + 0.5
        while process.isRunning && ProcessInfo.processInfo.systemUptime < termDeadline {
            await profileCommandPollDelay()
        }
        if process.isRunning, let identity = identity { _ = identity.signal(SIGKILL) }
        let killDeadline = ProcessInfo.processInfo.systemUptime + 0.5
        while process.isRunning && ProcessInfo.processInfo.systemUptime < killDeadline {
            await profileCommandPollDelay()
        }
        guard !process.isRunning else { throw RoutingError.notReady("installed-profile-inventory-command-exit-unconfirmed") }
        throw RoutingError.notReady("installed-profile-inventory-command-timed-out")
    }
    let (data, invalid, complete) = collected.snapshot()
    guard !process.isRunning, process.terminationStatus == 0, complete, !invalid, !data.isEmpty,
          let parsed = try? PropertyListSerialization.propertyList(from: data, format: nil) else {
        throw RoutingError.notReady("installed-profile-inventory-command-invalid")
    }
    _ = try InstalledProfileInventory.validate(parsed: parsed, ownedMappings: runtime.realmMappings(),
        ownerProfileIdentifier: runtime.namespace.profileIdentifier,
        mappingPayloadIdentifier: runtime.namespace.mappingIdentifier)
    return getuid() == 0 ? "computer-level" : "current-user"
}
