import Foundation
import Darwin
import RoutingShared

struct Session: Codable {
    let sessionId: String
    let routeId: String
    var pid: Int32
    let startedAt: Date
    let guardian: ProcessIdentity
    var application: ProcessIdentity
    var children: [ProcessIdentity]
    var state: String
    var scopeVerified: Bool = false
    var unknownPIDs: [Int32] = []
}

func runGuardian(_ params: [String: Any], acceptanceOnly: Bool = false) async throws {
    if acceptanceOnly {
        #if ENVARA_NATIVE_ROUTING_ACCEPTANCE
        try await requireAcceptanceReady()
        try validateAcceptanceLaunch(params)
        #else
        throw RoutingError.invalidRequest
        #endif
    } else { try await requireReady() }
    guard let routeId = params["routeId"] as? String, let sessionId = params["sessionId"] as? String,
          UUID(uuidString: sessionId) != nil else { throw RoutingError.invalidRequest }
    let runtime = try store(), route = try runtime.read(routeId)
    if acceptanceOnly {
        #if ENVARA_NATIVE_ROUTING_ACCEPTANCE
        _ = try acceptanceFixture(path: route.applicationPath, executable: route.executablePath)
        #else
        throw RoutingError.invalidRequest
        #endif
    } else { try requireTestedApplication(route.applicationIdentity) }
    _ = try validateApplication(path: route.applicationPath, executable: route.executablePath,
                                identity: route.applicationIdentity, requirement: route.applicationRequirement)
    let configuration = try await manager(for: routeId)
    try await health(configuration, routeId: routeId)
    // Give the owned application and its ordinary descendants their own group.
    guard setpgid(0, 0) == 0, let guardian = ProcessIdentity.read(getpid()) else { throw RoutingError.refused }
    // Handle stop before spawning the application, including startup failures.
    var stopRequested = false
    signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
    let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
    let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
    term.setEventHandler { stopRequested = true }; interrupt.setEventHandler { stopRequested = true }
    term.resume(); interrupt.resume()
    defer { term.cancel(); interrupt.cancel() }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: route.executablePath)
    process.arguments = params["args"] as? [String] ?? []
    if let cwd = params["cwd"] as? String {
        var directory: ObjCBool = false
        guard cwd.hasPrefix("/"), FileManager.default.fileExists(atPath: cwd, isDirectory: &directory), directory.boolValue else { throw RoutingError.invalidRequest }
        process.currentDirectoryURL = URL(fileURLWithPath: cwd, isDirectory: true)
    }
    var env = acceptanceOnly ? ["PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"] : ProcessInfo.processInfo.environment
    // Do not pass host proxy settings, login/API secrets, or host tool configuration.
    for key in Array(env.keys) where key.uppercased().contains("PROXY") || key.uppercased().contains("API_KEY") || key.uppercased().contains("TOKEN") || key.hasPrefix("CLAUDE_") || key.hasPrefix("XDG_") { env.removeValue(forKey: key) }
    let allowed = ["TZ", "LANG", "LC_ALL", "PATH", "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "CLAUDE_CONFIG_DIR", "TMPDIR", "NPM_CONFIG_USERCONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "DO_NOT_TRACK", "DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "ENVARA_PROFILE_ID", "ENVARA_ROUTE_ID"]
    for (key, value) in params["env"] as? [String: String] ?? [:] where allowed.contains(key) { env[key] = value }
    process.environment = env
    process.standardInput = FileHandle.nullDevice; process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
    // Persist uncertainty before launching. A failed identity read or journal
    // update must never leave a launched app looking like an absent session.
    let placeholder = ProcessIdentity(pid: 0, parent: getpid(), group: guardian.group,
                                      startedSeconds: 0, startedMicroseconds: 0, path: route.executablePath)
    var record = Session(sessionId: sessionId, routeId: routeId, pid: 0,
                         startedAt: Date(), guardian: guardian, application: placeholder,
                         children: [], state: "starting")
    let file = try runtime.url(sessionId, suffix: "session")
    try runtime.writePrivate(JSONEncoder().encode(record), to: file)
    let initialClock = try GuardianLeaseClock.sample()
    var lease = try GuardianLease(routeId: route.routeId, vpnUUID: route.vpnUUID, sessionId: sessionId,
                                  guardian: guardian, created: initialClock, renewed: initialClock)
    var leaseClosed = false
    func closeLease() {
        guard !leaseClosed else { return }
        leaseClosed = true
        if let closed = try? lease.closed(at: GuardianLeaseClock.sample()) {
            lease = closed
            try? runtime.writeGuardianLease(closed)
        }
    }
    defer { closeLease() }
    try runtime.writeGuardianLease(lease)
    try await health(configuration, routeId: routeId, guardianSession: sessionId)
    guard !stopRequested else { throw RoutingError.refused }
    do { try process.run() }
    catch {
        record.state = "error"
        try? runtime.writePrivate(JSONEncoder().encode(record), to: file)
        throw error
    }
    record.pid = process.processIdentifier
    record.unknownPIDs = [process.processIdentifier]; record.state = "error"
    guard case .found(let application) = ProcessIdentity.inspect(process.processIdentifier),
          application.parent == guardian.pid, application.group == guardian.group,
          application.path == route.executablePath else {
        // No uncertain kill(pid) and no claim that the application exited.
        try? runtime.writePrivate(JSONEncoder().encode(record), to: file)
        throw RoutingError.notReady("owned-application-identity-capture-unconfirmed")
    }
    let family = ProcessFamily(group: application.group, guardianPID: getpid(), initial: [application])
    defer {
        if record.state != "stopped" {
            _ = try? family.refresh()
            family.retainedIdentities.forEach { _ = $0.signal(SIGKILL) }
        }
    }
    // Install exact identity cleanup before any throwing post-spawn journal IO.
    record.application = application; record.children = [application]
    record.unknownPIDs = []; record.state = "running"
    try runtime.writePrivate(JSONEncoder().encode(record), to: file)
    var lastSaved = Date.distantPast
    while true {
        do {
            if !leaseClosed {
                let now = try GuardianLeaseClock.sample()
                guard now.bootSessionUUID == lease.renewed.bootSessionUUID,
                      now.continuousNanoseconds >= lease.renewed.continuousNanoseconds else { throw GuardianLeaseError.invalidClock }
                if now.continuousNanoseconds - lease.renewed.continuousNanoseconds >= 250_000_000 {
                    lease = try lease.renewed(at: now)
                    try runtime.writeGuardianLease(lease)
                }
            }
            let children = try family.refresh()
            record.scopeVerified = true; record.unknownPIDs = []
            if children.isEmpty { record.state = "stopped"; break }
            if stopRequested {
                closeLease()
                children.forEach { _ = $0.signal(SIGTERM) }
                for _ in 0..<30 {
                    if try family.refresh().isEmpty { break }
                    try await Task.sleep(nanoseconds: 100_000_000)
                }
                try family.refresh().forEach { _ = $0.signal(SIGKILL) }
                for _ in 0..<30 {
                    if try family.refresh().isEmpty { break }
                    try await Task.sleep(nanoseconds: 100_000_000)
                }
                record.children = try family.refresh()
                record.state = record.children.isEmpty ? "stopped" : "error"
                break
            }
            record.children = children
            record.state = "running"
            if Date().timeIntervalSince(lastSaved) > 0.5 {
                try runtime.writePrivate(JSONEncoder().encode(record), to: file); lastSaved = Date()
            }
            try await Task.sleep(nanoseconds: 50_000_000)
        } catch {
            closeLease(); stopRequested = true
            record.state = "error"; record.scopeVerified = false
            record.children = family.retainedIdentities; record.unknownPIDs = family.unknownPIDs
            if stopRequested { record.children.forEach { _ = $0.signal(SIGTERM) } }
            try runtime.writePrivate(JSONEncoder().encode(record), to: file)
            try await Task.sleep(nanoseconds: 100_000_000)
        }
    }
    closeLease()
    if record.state == "stopped" { record.children = []; record.unknownPIDs = []; record.scopeVerified = true }
    try runtime.writePrivate(JSONEncoder().encode(record), to: file)
}
