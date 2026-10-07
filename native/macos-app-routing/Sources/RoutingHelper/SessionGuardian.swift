import Foundation
import Darwin
import RoutingShared

struct Session: Codable {
    let sessionId: String
    let routeId: String
    let pid: Int32
    let startedAt: Date
    let guardian: ProcessIdentity
    let application: ProcessIdentity
    var children: [ProcessIdentity]
    var state: String
}

func runGuardian(_ params: [String: Any]) async throws {
    try await requireReady()
    guard let routeId = params["routeId"] as? String, let sessionId = params["sessionId"] as? String,
          UUID(uuidString: sessionId) != nil else { throw RoutingError.invalidRequest }
    let runtime = try store(), route = try runtime.read(routeId)
    _ = try validateApplication(path: route.applicationPath, executable: route.executablePath, identity: route.applicationIdentity)
    let configuration = try await manager(for: routeId)
    try await health(configuration, routeId: routeId)
    // Give the owned application and its ordinary descendants their own group.
    guard setpgid(0, 0) == 0, let guardian = ProcessIdentity.read(getpid()) else { throw RoutingError.refused }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: route.executablePath)
    process.arguments = params["args"] as? [String] ?? []
    if let cwd = params["cwd"] as? String {
        var directory: ObjCBool = false
        guard cwd.hasPrefix("/"), FileManager.default.fileExists(atPath: cwd, isDirectory: &directory), directory.boolValue else { throw RoutingError.invalidRequest }
        process.currentDirectoryURL = URL(fileURLWithPath: cwd, isDirectory: true)
    }
    var env = ProcessInfo.processInfo.environment
    // Do not pass host proxy settings, login/API secrets, or host tool configuration.
    for key in Array(env.keys) where key.uppercased().contains("PROXY") || key.uppercased().contains("API_KEY") || key.uppercased().contains("TOKEN") || key.hasPrefix("CLAUDE_") || key.hasPrefix("XDG_") { env.removeValue(forKey: key) }
    let allowed = ["TZ", "LANG", "LC_ALL", "PATH", "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "CLAUDE_CONFIG_DIR", "TMPDIR", "NPM_CONFIG_USERCONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "DO_NOT_TRACK", "DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "ENVARA_PROFILE_ID", "ENVARA_ROUTE_ID"]
    for (key, value) in params["env"] as? [String: String] ?? [:] where allowed.contains(key) { env[key] = value }
    process.environment = env
    process.standardInput = FileHandle.nullDevice; process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
    try process.run()
    guard let application = ProcessIdentity.read(process.processIdentifier) else { process.terminate(); throw RoutingError.refused }
    var record = Session(sessionId: sessionId, routeId: routeId, pid: process.processIdentifier,
                         startedAt: Date(), guardian: guardian, application: application,
                         children: [application], state: "running")
    let file = try runtime.url(sessionId, suffix: "session")
    let family = ProcessFamily(group: application.group, guardianPID: getpid())
    defer {
        if record.state != "stopped" { family.refresh().forEach { _ = $0.signal(SIGKILL) } }
    }
    try runtime.writePrivate(JSONEncoder().encode(record), to: file)
    var stopRequested = false
    signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
    let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
    let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
    term.setEventHandler { stopRequested = true }; interrupt.setEventHandler { stopRequested = true }
    term.resume(); interrupt.resume()
    defer { term.cancel(); interrupt.cancel() }
    var lastSaved = Date.distantPast
    while true {
        let children = family.refresh()
        if children.isEmpty { record.state = "stopped"; break }
        if stopRequested {
            children.forEach { _ = $0.signal(SIGTERM) }
            for _ in 0..<30 {
                if family.refresh().isEmpty { break }
                try await Task.sleep(nanoseconds: 100_000_000)
            }
            family.refresh().forEach { _ = $0.signal(SIGKILL) }
            for _ in 0..<30 {
                if family.refresh().isEmpty { break }
                try await Task.sleep(nanoseconds: 100_000_000)
            }
            record.children = family.refresh()
            record.state = record.children.isEmpty ? "stopped" : "error"
            break
        }
        record.children = children
        if Date().timeIntervalSince(lastSaved) > 0.5 {
            try runtime.writePrivate(JSONEncoder().encode(record), to: file); lastSaved = Date()
        }
        try await Task.sleep(nanoseconds: 50_000_000)
    }
    record.children = family.refresh()
    try runtime.writePrivate(JSONEncoder().encode(record), to: file)
}
