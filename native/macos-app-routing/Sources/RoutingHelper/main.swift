import AppKit
import Foundation
import NetworkExtension
import Security
import CryptoKit
import SystemExtensions
import RoutingShared

private let providerIdentifier = "io.envara.app-routing.proxy"
private let protocolIdentifier = "envara.application-routing"

// Development signing is an explicit, separately compiled local build. A
// release helper never changes its trust policy via environment or RPC input.
#if ENVARA_LOCAL_DEVELOPMENT_ROUTING
private let signingMode = RoutingSigningMode.development
#else
private let signingMode = RoutingSigningMode.developerID
#endif
private var authorizationReason: String { signingMode == .development
    ? "apple-development-and-network-extension-profiles-required"
    : "developer-id-and-network-extension-entitlement-required" }

private func codeIdentity(_ path: URL) throws -> (String, String) {
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(path as CFURL, [], &code) == errSecSuccess, let code = code,
          SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess else { throw RoutingError.notReady("Application has no valid code identity") }
    var information: CFDictionary?
    guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
          let values = information as? [String: Any], let identity = values[kSecCodeInfoIdentifier as String] as? String else {
        throw RoutingError.notReady("Application signing identity is unavailable")
    }
    var requirement: SecRequirement?, requirementText: CFString?
    guard SecCodeCopyDesignatedRequirement(code, [], &requirement) == errSecSuccess,
          let requirement = requirement, SecRequirementCopyString(requirement, [], &requirementText) == errSecSuccess,
          let text = requirementText as String? else { throw RoutingError.notReady("Application requirement is unavailable") }
    return (identity, text)
}

func validateApplication(path: String, executable: String, identity: String? = nil) throws -> (String, String) {
    let url = URL(fileURLWithPath: path).resolvingSymlinksInPath()
    guard path.hasSuffix(".app"), url.path == path, let bundle = Bundle(url: url),
          let actual = bundle.executableURL?.resolvingSymlinksInPath(),
          actual.path == URL(fileURLWithPath: executable).resolvingSymlinksInPath().path,
          actual.path.hasPrefix(url.appendingPathComponent("Contents/MacOS", isDirectory: true).path + "/") else {
        throw RoutingError.notReady("application-executable-does-not-match-signed-bundle")
    }
    let validated = try codeIdentity(url)
    if let expected = identity, expected != validated.0 { throw RoutingError.notReady("application-identity-changed") }
    return validated
}

private func hostAuthorized() -> Bool {
    do {
        let devices = signingMode == .development ? try RoutingSigningAuthorization.deviceIdentifiers() : []
        let bundle = Bundle.main.bundleURL
        let host = try RoutingSigningAuthorization.validateBundle(bundle,
            expectedIdentifier: RoutingSigningAuthorization.hostIdentifier, host: true, mode: signingMode, devices: devices)
        let provider = try RoutingSigningAuthorization.validateBundle(bundle.appendingPathComponent("Contents/Library/SystemExtensions/io.envara.app-routing.proxy.systemextension"),
            expectedIdentifier: providerIdentifier, host: false, mode: signingMode, devices: devices)
        return host.team == provider.team && host.certificateSHA256 == provider.certificateSHA256
    } catch { return false }
}

func store() throws -> RuntimeStore {
    guard hostAuthorized(), let group = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: RuntimeStore.groupIdentifier) else {
        throw RoutingError.notReady(authorizationReason)
    }
    return try RuntimeStore(directory: group)
}

private func managers() async throws -> [NEAppProxyProviderManager] {
    try await withCheckedThrowingContinuation { continuation in
        NEAppProxyProviderManager.loadAllFromPreferences { managers, error in
            if let error = error { continuation.resume(throwing: error) }
            else { continuation.resume(returning: (managers ?? []).filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerIdentifier
            }) }
        }
    }
}

private func verification() -> [String: Any] {
    let keys = ["tcp", "udp", "dns", "childProcesses", "failClosed"]
    let incomplete: [String: Any] = ["passed": false, "version": "1", "checks": Dictionary(uniqueKeysWithValues: keys.map { ($0, false) })]
    // A release acceptance receipt belongs to the signed resource seal. The source
    // build deliberately does not create one: transport tests cannot attest OS routing.
    guard hostAuthorized(), let url = Bundle.main.url(forResource: "routing-acceptance", withExtension: "plist"),
          let data = try? Data(contentsOf: url),
          let receipt = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
          receipt["providerVersion"] as? String == "1",
          let binary = try? Data(contentsOf: Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions/io.envara.app-routing.proxy.systemextension/Contents/MacOS/EnvaraAppProxy")),
          receipt["providerSHA256"] as? String == SHA256.hash(data: binary).map({ String(format: "%02x", $0) }).joined(),
          receipt["osMajor"] as? Int == ProcessInfo.processInfo.operatingSystemVersion.majorVersion,
          receipt["passed"] as? Bool == true,
          let checks = receipt["checks"] as? [String: Bool], keys.allSatisfy({ checks[$0] == true }),
          let version = receipt["version"] as? String, !version.isEmpty else { return incomplete }
    return ["passed": true, "version": version, "checks": checks]
}

private final class PropertiesDelegate: NSObject, OSSystemExtensionRequestDelegate {
    var completion: ((Bool) -> Void)?
    func finish(_ value: Bool) { let callback = completion; completion = nil; callback?(value) }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .cancel }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) { finish(false) }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) { }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { finish(false) }
    func request(_ request: OSSystemExtensionRequest, foundProperties properties: [OSSystemExtensionProperties]) {
        guard let bundled = try? Data(contentsOf: Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions/io.envara.app-routing.proxy.systemextension/Contents/MacOS/EnvaraAppProxy")) else { finish(false); return }
        let expected = SHA256.hash(data: bundled)
        finish(properties.contains { item in
            guard item.isEnabled, !item.isAwaitingUserApproval, !item.isUninstalling,
                  let active = try? Data(contentsOf: item.url.appendingPathComponent("Contents/MacOS/EnvaraAppProxy")) else { return false }
            return SHA256.hash(data: active) == expected
        })
    }
}
private var propertiesDelegate: PropertiesDelegate?

private func extensionEnabled() async -> Bool {
    await withCheckedContinuation { continuation in
        let delegate = PropertiesDelegate(); propertiesDelegate = delegate
        delegate.completion = { continuation.resume(returning: $0) }
        let request = OSSystemExtensionRequest.propertiesRequest(forExtensionWithIdentifier: providerIdentifier, queue: .main)
        request.delegate = delegate
        OSSystemExtensionManager.shared.submitRequest(request)
        let timeout = DispatchWorkItem { delegate.finish(false) }
        DispatchQueue.main.asyncAfter(deadline: .now() + 5, execute: timeout)
    }
}

private func status() async -> [String: Any] {
    let authorized = hostAuthorized()
    let configured = authorized ? ((try? await managers()) ?? []) : []
    let enabled = authorized ? await extensionEnabled() : false
    let assessment = verification()
    let ready = authorized && enabled && !configured.isEmpty && assessment["passed"] as? Bool == true
    var result: [String: Any] = ["platform": "darwin", "installed": enabled && !configured.isEmpty, "extensionEnabled": enabled,
        "authorized": authorized, "ready": ready, "signingMode": signingMode.rawValue,
        "capabilities": ["tcp": true, "udp": true, "dns": true, "childProcesses": true, "failClosed": true],
        "udpPolicies": ["proxy", "block"], "verification": assessment, "sessions": sessionStatuses()]
    if !ready { result["reason"] = !authorized ? authorizationReason : configured.isEmpty || !enabled ? "per-app-profile-and-extension-required" : "native-routing-acceptance-required" }
    return result
}

func requireReady() async throws {
    let state = await status()
    guard state["ready"] as? Bool == true else { throw RoutingError.notReady(state["reason"] as? String ?? "native-routing-not-ready") }
}

func manager(for routeId: String) async throws -> NEAppProxyProviderManager {
    let route = try store().read(routeId)
    guard let item = try await managers().first(where: {
        $0.appRules.count == 1 && $0.appRules.contains { $0.matchSigningIdentifier == route.applicationIdentity && ($0.matchPath == nil || $0.matchPath == route.executablePath) && $0.matchDomains == nil && $0.matchTools == nil }
    }) else { throw RoutingError.notReady("per-app-profile-required") }
    return item
}

func health(_ manager: NEAppProxyProviderManager, routeId: String) async throws {
    guard manager.connection.status == .connected, let session = manager.connection as? NETunnelProviderSession else {
        throw RoutingError.notReady("app-proxy-not-connected")
    }
    let request = try JSONSerialization.data(withJSONObject: ["method": "health"])
    let response: Data? = try await withCheckedThrowingContinuation { continuation in
        do { try session.sendProviderMessage(request) { continuation.resume(returning: $0) } }
        catch { continuation.resume(throwing: error) }
    }
    guard let response = response, let values = try JSONSerialization.jsonObject(with: response) as? [String: Any],
          values["active"] as? Bool == true, values["routeId"] as? String == routeId,
          values["providerVersion"] as? String == "1" else { throw RoutingError.notReady("route-not-confirmed-by-extension") }
}

private func prepare(_ params: [String: Any]) async throws -> [String: Any] {
    try await requireReady()
    guard let app = params["application"] as? [String: Any], let path = app["path"] as? String,
          let executable = app["executablePath"] as? String,
          let request = params["route"] as? [String: Any], let protocolName = request["protocol"] as? String,
          let host = request["host"] as? String, let port = request["port"] as? Int, port > 0, port <= 65535,
          let user = request["username"] as? String, let password = request["password"] as? String else { throw RoutingError.invalidRequest }
    let (identity, requirement) = try validateApplication(path: path, executable: executable)
    guard let receiptURL = Bundle.main.url(forResource: "routing-acceptance", withExtension: "plist"),
          let receiptData = try? Data(contentsOf: receiptURL),
          let receipt = try? PropertyListSerialization.propertyList(from: receiptData, format: nil) as? [String: Any],
          let tested = receipt["testedApplications"] as? [String], tested.contains(identity) else {
        throw RoutingError.notReady("selected-application-native-acceptance-required")
    }
    guard let manager = try await managers().first(where: { item in
        item.appRules.count == 1 && item.appRules.contains { $0.matchSigningIdentifier == identity && $0.matchDesignatedRequirement == requirement && ($0.matchPath == nil || $0.matchPath == executable) && $0.matchDomains == nil && $0.matchTools == nil }
    }) else { throw RoutingError.notReady("selected-application-profile-required") }
    let id = UUID().uuidString
    let udpPolicy = request["udpPolicy"] as? String ?? (request["udp"] as? Bool == true ? "proxy" : "block")
    guard ["proxy", "block"].contains(udpPolicy) else { throw RoutingError.invalidRequest }
    let route = try Route(routeId: id, applicationIdentity: identity, applicationPath: path, executablePath: executable,
                          protocolName: protocolName, host: host, port: UInt16(port), username: user, password: password,
                          udp: udpPolicy == "proxy" && request["udp"] as? Bool == true,
                          privacyMode: ((params["workspace"] as? [String: Any])?["privacy"] as? [String: Any])?["mode"] as? String ?? "standard")
    try store().write(route)
    var confirmed = false
    defer { if !confirmed { try? store().revoke(id) } }
    // Profiles are administrator-owned. Do not rewrite them. Our generated profile
    // must already enforce on-demand routing and contain no disconnect bypass rule.
    guard manager.isEnabled, manager.isOnDemandEnabled,
          !(manager.onDemandRules ?? []).contains(where: { $0 is NEOnDemandRuleDisconnect }),
          manager.excludedDomains.isEmpty,
          !sessions().contains(where: { $0.application.path == executable && ($0.application.alive || $0.children.contains { $0.alive }) }) else {
        throw RoutingError.notReady("application-profile-must-enforce-routing-without-bypass")
    }
    if manager.connection.status == .connected { manager.connection.stopVPNTunnel() }
    try manager.connection.startVPNTunnel(options: ["routeId": id as NSString])
    for _ in 0..<100 {
        if manager.connection.status == .connected { break }
        try await Task.sleep(nanoseconds: 100_000_000)
    }
    try await health(manager, routeId: id)
    confirmed = true
    return ["routeId": id, "ready": true, "failClosed": true, "udpPolicy": route.udp ? "proxy" : "block",
            "capabilities": ["tcp": true, "udp": true, "dns": true, "childProcesses": true, "failClosed": true], "verification": verification()]
}

private func sessions() -> [Session] {
    guard let store = try? store(), let files = try? FileManager.default.contentsOfDirectory(at: store.directory, includingPropertiesForKeys: nil) else { return [] }
    return files.filter { $0.pathExtension == "session" }.compactMap { url in
        guard let data = try? store.readPrivate(url) else { return nil }
        return try? JSONDecoder().decode(Session.self, from: data)
    }
}

private func sessionStatuses() -> [[String: Any]] {
    sessions().map {
        let running = $0.guardian.alive && ($0.application.alive || $0.children.contains { $0.alive })
        return ["sessionId": $0.sessionId, "pid": Int($0.pid), "routeId": $0.routeId,
                "status": running ? "running" : $0.state == "stopped" ? "stopped" : "error"]
    }
}

private func launch(_ params: [String: Any]) async throws -> [String: Any] {
    try await requireReady()
    guard let id = params["routeId"] as? String else { throw RoutingError.invalidRequest }
    let route = try store().read(id), manager = try await manager(for: id)
    try await health(manager, routeId: id)
    guard !NSWorkspace.shared.runningApplications.contains(where: { $0.bundleURL?.path == route.applicationPath }) else {
        throw RoutingError.notReady("application-already-running-close-it-before-binding")
    }
    let sessionId = UUID().uuidString
    var request = params; request["sessionId"] = sessionId
    let guardian = Process()
    guardian.executableURL = Bundle.main.executableURL
    guardian.arguments = ["--guardian"]
    let input = Pipe(); guardian.standardInput = input
    guardian.standardOutput = FileHandle.nullDevice; guardian.standardError = FileHandle.nullDevice
    try guardian.run()
    input.fileHandleForWriting.write(try JSONSerialization.data(withJSONObject: request)); try input.fileHandleForWriting.close()
    // The response is written atomically before launch is reported. A guardian owns
    // the process family after this short-lived RPC helper exits.
    for _ in 0..<100 {
        if let session = sessions().first(where: { $0.sessionId == sessionId }), session.application.alive, session.guardian.alive {
            return ["sessionId": session.sessionId, "pid": Int(session.pid), "startedAt": ISO8601DateFormatter().string(from: session.startedAt)]
        }
        if !guardian.isRunning { break }
        try await Task.sleep(nanoseconds: 100_000_000)
    }
    guardian.terminate(); throw RoutingError.notReady("owned-application-launch-unconfirmed")
}

private func stop(_ params: [String: Any]) async throws -> [String: Any] {
    let id = params["sessionId"] as? String, routeId = params["routeId"] as? String
    guard id != nil || routeId != nil else { throw RoutingError.invalidRequest }
    let matched = sessions().filter { id != nil ? $0.sessionId == id : $0.routeId == routeId }
    for session in matched { _ = session.guardian.signal(SIGTERM) }
    for _ in 0..<80 {
        let latest = sessions().filter { id != nil ? $0.sessionId == id : $0.routeId == routeId }
        if latest.allSatisfy({ $0.state == "stopped" && !$0.application.alive && $0.children.allSatisfy { !$0.alive } }) {
            return ["stopped": true]
        }
        try await Task.sleep(nanoseconds: 100_000_000)
    }
    // If a guardian crashed, kill only records whose PID, executable and start time
    // still match. Keep route mappings retained until all tracked children are gone.
    for session in matched {
        _ = session.application.signal(SIGKILL)
        session.children.forEach { _ = $0.signal(SIGKILL) }
    }
    return ["stopped": false, "reason": "child-process-exit-verification-required"]
}

private func revoke(_ params: [String: Any]) async throws -> [String: Any] {
    guard let id = params["routeId"] as? String else { throw RoutingError.invalidRequest }
    guard sessions().filter({ $0.routeId == id }).allSatisfy({ !$0.application.alive && $0.children.allSatisfy { !$0.alive } }) else {
        throw RoutingError.notReady("stop-owned-applications-before-revoking-route")
    }
    if let manager = try? await manager(for: id), manager.connection.status == .connected,
       let connection = manager.connection as? NETunnelProviderSession {
        let data = try JSONSerialization.data(withJSONObject: ["method": "revoke", "routeId": id])
        let response: Data? = try await withCheckedThrowingContinuation { continuation in
            do { try connection.sendProviderMessage(data) { continuation.resume(returning: $0) } }
            catch { continuation.resume(throwing: error) }
        }
        guard let response = response, let values = try JSONSerialization.jsonObject(with: response) as? [String: Any],
              values["revoked"] as? Bool == true else { throw RoutingError.notReady("route-revocation-unconfirmed") }
    }
    // Removing route secrets makes new/provider-restarted flows fail closed. Keep the
    // app mapping enabled rather than disabling the VPN and potentially enabling DIRECT.
    try store().revoke(id)
    return ["revoked": true, "mappingRetained": true]
}

private final class ActivationDelegate: NSObject, OSSystemExtensionRequestDelegate {
    var completion: (([String: Any]) -> Void)?
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) { completion?(["ready": false, "reason": "system-extension-user-approval-required"]); completion = nil }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) { completion?(["ready": false, "reason": result == .completed ? "per-app-profile-and-acceptance-required" : "system-restart-required"]); completion = nil }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { completion?(["ready": false, "reason": "system-extension-activation-failed"]); completion = nil }
}
private var activationDelegate: ActivationDelegate?

private func setup(_ params: [String: Any]) async throws -> [String: Any] {
    if let application = params["application"] as? [String: Any], let path = application["path"] as? String,
       let executable = application["executablePath"] as? String {
        guard hostAuthorized() else { throw RoutingError.notReady(authorizationReason) }
        let (identity, requirement) = try validateApplication(path: path, executable: executable)
        let provider = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions/io.envara.app-routing.proxy.systemextension")
        let (_, providerRequirement) = try codeIdentity(provider)
        guard let bundleIdentifier = Bundle(url: URL(fileURLWithPath: path))?.bundleIdentifier else { throw RoutingError.invalidRequest }
        let profile = try ConfigurationProfile.make(applicationIdentifier: bundleIdentifier,
                                                   signingIdentifier: identity, designatedRequirement: requirement,
                                                   executablePath: executable, providerRequirement: providerRequirement)
        let file = try store().directory.appendingPathComponent("Envara-\(UUID().uuidString).mobileconfig")
        try store().writePrivate(profile, to: file)
        // The desktop can present this local profile for explicit system approval.
        // Generating it does not install a profile, change routes, or register a VPN.
        return ["ready": false, "reason": "per-app-profile-user-installation-required", "profilePath": file.path, "requiresUserApproval": true]
    }
    guard params["activate"] as? Bool == true else { return ["ready": false, "reason": "signed-extension-and-per-app-profile-required", "requiresUserApproval": true] }
    guard hostAuthorized() else { throw RoutingError.notReady(authorizationReason) }
    return await withCheckedContinuation { continuation in
        let delegate = ActivationDelegate(); activationDelegate = delegate
        delegate.completion = { continuation.resume(returning: $0) }
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: providerIdentifier, queue: .main)
        request.delegate = delegate
        OSSystemExtensionManager.shared.submitRequest(request)
    }
}

private func handle(_ request: [String: Any]) async -> [String: Any] {
    let id = request["id"] ?? NSNull()
    var response: [String: Any] = ["protocol": protocolIdentifier, "version": 1, "id": id]
    do {
        guard request["protocol"] as? String == protocolIdentifier, request["version"] as? Int == 1,
              let method = request["method"] as? String else { throw RoutingError.invalidRequest }
        let params = request["params"] as? [String: Any] ?? [:]
        let result: [String: Any]
        switch method {
        case "status": result = await status()
        case "setup": result = try await setup(params)
        case "prepareRoute": result = try await prepare(params)
        case "launch": result = try await launch(params)
        case "stop": result = try await stop(params)
        case "revoke": result = try await revoke(params)
        default: throw RoutingError.invalidRequest
        }
        response["result"] = result
    } catch let RoutingError.notReady(reason) { response["error"] = ["code": "notReady", "message": reason] }
    catch { response["error"] = ["code": "routingFailed", "message": "Protected application routing could not complete"] }
    return response
}

guard CommandLine.arguments.contains("--rpc") || CommandLine.arguments.contains("--guardian") else {
    // The helper is not a general-purpose application launcher.
    FileHandle.standardError.write(Data("Use the Envara desktop application.\n".utf8)); exit(64)
}
let input = FileHandle.standardInput.readDataToEndOfFile()
guard input.count <= 1_048_576, let request = try? JSONSerialization.jsonObject(with: input) as? [String: Any] else {
    FileHandle.standardOutput.write(Data("{\"protocol\":\"envara.application-routing\",\"version\":1,\"id\":null,\"error\":{\"code\":\"invalidRequest\",\"message\":\"Invalid request\"}}\n".utf8)); exit(65)
}
Task {
    if CommandLine.arguments.contains("--guardian") {
        do { try await runGuardian(request); exit(0) } catch { exit(70) }
    }
    let response = await handle(request)
    if let output = try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys]) {
        FileHandle.standardOutput.write(output + Data([10]))
    }
    exit(0)
}
dispatchMain()
