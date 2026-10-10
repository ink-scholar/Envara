import AppKit
import Foundation
import NetworkExtension
import Security
import CryptoKit
import SystemExtensions
import RoutingShared

let providerIdentifier = RoutingSigningAuthorization.providerIdentifier
let providerBundleURL = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions/\(providerIdentifier).systemextension")
private let protocolIdentifier = "envara.application-routing"
#if ENVARA_NATIVE_ROUTING_ACCEPTANCE
let runtimeNamespace = RoutingRuntimeNamespace.fixtureAcceptance
#else
let runtimeNamespace = RoutingRuntimeNamespace.production
#endif

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

func validateApplication(path: String, executable: String, identity: String? = nil, requirement: String? = nil) throws -> (String, String) {
    let url = URL(fileURLWithPath: path).resolvingSymlinksInPath()
    guard RealmValidation.executablePath(path), RealmValidation.executablePath(executable),
          path.hasSuffix(".app"), url.path == path, let bundle = Bundle(url: url),
          let actual = bundle.executableURL?.resolvingSymlinksInPath(),
          RealmValidation.applicationExecutablePath(executable), actual.path == executable,
          actual.path.hasPrefix(url.appendingPathComponent("Contents/MacOS", isDirectory: true).path + "/") else {
        throw RoutingError.notReady("application-executable-does-not-match-signed-bundle")
    }
    let validated = try codeIdentity(url)
    if let expected = identity, expected != validated.0 { throw RoutingError.notReady("application-identity-changed") }
    if let expected = requirement, expected != validated.1 { throw RoutingError.notReady("application-requirement-changed") }
    return validated
}

func hostAuthorized() -> Bool {
    do {
        let devices = signingMode == .development ? try RoutingSigningAuthorization.deviceIdentifiers() : []
        let bundle = Bundle.main.bundleURL
        let host = try RoutingSigningAuthorization.validateBundle(bundle,
            expectedIdentifier: RoutingSigningAuthorization.hostIdentifier, host: true, mode: signingMode, devices: devices)
        let provider = try RoutingSigningAuthorization.validateBundle(providerBundleURL,
            expectedIdentifier: providerIdentifier, host: false, mode: signingMode, devices: devices)
        guard host.team == provider.team && host.certificateSHA256 == provider.certificateSHA256 else { return false }
        #if ENVARA_NATIVE_ROUTING_ACCEPTANCE
        guard let manifestURL = Bundle.main.url(forResource: "provider-reuse", withExtension: "json"),
              let bytes = try? Data(contentsOf: manifestURL), bytes.count <= 16_384,
              let manifest = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              manifest["version"] as? Int == 1, manifest["acceptanceOnly"] as? Bool == true,
              manifest["runtimeNamespace"] as? String == runtimeNamespace.rawValue,
              manifest["providerIdentifier"] as? String == providerIdentifier,
              let record = manifest["provider"] as? [String: Any], record["fingerprintVersion"] as? Int == 1,
              record["bundle"] as? String == "\(providerIdentifier).systemextension",
              record["bundleSHA256"] as? String == (try? RoutingBundleFingerprint.sha256(providerBundleURL)) else { return false }
        #endif
        return true
    } catch { return false }
}

func store(readOnly: Bool = false) throws -> RuntimeStore {
    guard hostAuthorized(), let group = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: RuntimeStore.groupIdentifier) else {
        throw RoutingError.notReady(authorizationReason)
    }
    return try RuntimeStore(directory: group, create: !readOnly, namespace: runtimeNamespace)
}

private func managers() async throws -> [NEAppProxyProviderManager] {
    try await withCheckedThrowingContinuation { continuation in
        NEAppProxyProviderManager.loadAllFromPreferences { managers, error in
            if let error = error { continuation.resume(throwing: error) }
            else { continuation.resume(returning: (managers ?? []).filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerIdentifier &&
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?[RoutingRuntimeNamespace.configurationKey] as? String == runtimeNamespace.rawValue
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
          let binary = try? Data(contentsOf: providerBundleURL.appendingPathComponent("Contents/MacOS/EnvaraAppProxy")),
          receipt["providerSHA256"] as? String == SHA256.hash(data: binary).map({ String(format: "%02x", $0) }).joined(),
          receipt["providerBundleSHA256"] as? String == (try? RoutingBundleFingerprint.sha256(providerBundleURL)),
          receipt["osMajor"] as? Int == ProcessInfo.processInfo.operatingSystemVersion.majorVersion,
          receipt["passed"] as? Bool == true,
          let checks = receipt["checks"] as? [String: Bool], keys.allSatisfy({ checks[$0] == true }),
          let version = receipt["version"] as? String, !version.isEmpty else { return incomplete }
    return ["passed": true, "version": version, "checks": checks]
}

private final class PropertiesDelegate: NSObject, OSSystemExtensionRequestDelegate {
    var completion: (([OSSystemExtensionProperties]?) -> Void)?
    func finish(_ value: [OSSystemExtensionProperties]?) { let callback = completion; completion = nil; callback?(value) }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .cancel }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) { finish(nil) }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) { }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { finish(nil) }
    func request(_ request: OSSystemExtensionRequest, foundProperties properties: [OSSystemExtensionProperties]) { finish(properties) }
}
private var propertiesDelegate: PropertiesDelegate?

private func extensionProperties() async -> [OSSystemExtensionProperties]? {
    await withCheckedContinuation { continuation in
        let delegate = PropertiesDelegate(); propertiesDelegate = delegate
        delegate.completion = { continuation.resume(returning: $0) }
        let request = OSSystemExtensionRequest.propertiesRequest(forExtensionWithIdentifier: providerIdentifier, queue: .main)
        request.delegate = delegate
        OSSystemExtensionManager.shared.submitRequest(request)
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { delegate.finish(nil) }
    }
}

func extensionEnabled() async -> Bool {
    guard let expected = try? RoutingBundleFingerprint.sha256(providerBundleURL),
          let properties = await extensionProperties() else { return false }
    return properties.contains { item in
        item.isEnabled && !item.isAwaitingUserApproval && !item.isUninstalling &&
        (try? RoutingBundleFingerprint.sha256(item.url)) == expected
    }
}

private func activationPreflight() async throws {
    let host = Bundle.main.bundleURL.resolvingSymlinksInPath()
    let roots = [URL(fileURLWithPath: "/Applications", isDirectory: true),
                 FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications", isDirectory: true)]
    guard roots.contains(where: { host.path.hasPrefix($0.path + "/") }),
          host.path.hasSuffix(".app"), hostAuthorized(),
          let properties = await extensionProperties() else { throw RoutingError.notReady("installed-authorized-activation-host-required") }
    let expected = try RoutingBundleFingerprint.sha256(providerBundleURL)
    for existing in properties {
        guard !existing.isAwaitingUserApproval, !existing.isUninstalling,
              (try? RoutingBundleFingerprint.sha256(existing.url)) == expected else {
            throw RoutingError.notReady("existing-provider-installation-conflicts-no-replacement-performed")
        }
    }
}

private func status() async -> [String: Any] {
    let authorized = hostAuthorized()
    let configured = authorized ? ((try? await managers()) ?? []) : []
    let enabled = authorized ? await extensionEnabled() : false
    let assessment = verification()
    let snapshot = authorized ? try? sessionSnapshot() : nil
    let journalReadable = snapshot != nil
    let scopeVerified = snapshot?.allSatisfy { session in
        guard session.scopeVerified, session.unknownPIDs.isEmpty else { return false }
        if session.state == "stopped" { return session.application.exitConfirmed && session.children.allSatisfy { $0.exitConfirmed } }
        return session.state == "running" && session.guardian.presence() == .alive &&
            ([session.application] + session.children).allSatisfy { identity in
                switch identity.presence() { case .alive, .gone: return true; case .unknown: return false }
            }
    } ?? false
    let ready = authorized && enabled && !configured.isEmpty && scopeVerified && assessment["passed"] as? Bool == true
    var result: [String: Any] = ["platform": "darwin", "installed": enabled && !configured.isEmpty, "extensionEnabled": enabled,
        "authorized": authorized, "ready": ready, "signingMode": signingMode.rawValue,
        "component": ["name": "envara-app-proxy", "version": "1", "available": true,
                      "verified": authorized, "installed": enabled && !configured.isEmpty],
        "capabilities": ["tcp": true, "udp": true, "dns": true, "childProcesses": true, "failClosed": true],
        "udpPolicies": ["proxy", "block"], "verification": assessment, "journalReadable": journalReadable,
        "processScopeVerified": scopeVerified, "sessions": sessionStatuses(snapshot ?? [])]
    if !ready { result["reason"] = !authorized ? authorizationReason : configured.isEmpty || !enabled ? "per-app-profile-and-extension-required" : !scopeVerified ? "owned-session-journal-unverified" : "native-routing-acceptance-required" }
    return result
}

func requireTestedApplication(_ identity: String) throws {
    guard let receiptURL = Bundle.main.url(forResource: "routing-acceptance", withExtension: "plist"),
          let receiptData = try? Data(contentsOf: receiptURL),
          let receipt = try? PropertyListSerialization.propertyList(from: receiptData, format: nil) as? [String: Any],
          let tested = receipt["testedApplications"] as? [String], tested.contains(identity) else {
        throw RoutingError.notReady("selected-application-native-acceptance-required")
    }
}

func requireReady() async throws {
    let state = await status()
    guard state["ready"] as? Bool == true else { throw RoutingError.notReady(state["reason"] as? String ?? "native-routing-not-ready") }
}

func manager(for routeId: String) async throws -> NEAppProxyProviderManager {
    let route = try store().read(routeId)
    return try exactManager(in: await managers(), vpnUUID: route.vpnUUID, identity: route.applicationIdentity,
                            requirement: route.applicationRequirement, executable: route.executablePath)
}

private func exactManager(in configured: [NEAppProxyProviderManager], vpnUUID: String, identity: String,
                          requirement: String, executable: String) throws -> NEAppProxyProviderManager {
    let bindings = configured.map { item -> RealmManagerBinding in
        let configuration = (item.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        let realm = configuration?[RealmBindingSelection.versionKey] as? Int == 1
            ? configuration?[RealmBindingSelection.configurationKey] as? String : nil
        return RealmManagerBinding(realmUUID: realm, rules: item.appRules.map {
            RealmRule(signingIdentifier: $0.matchSigningIdentifier, designatedRequirement: $0.matchDesignatedRequirement,
                      executablePath: $0.matchPath, domains: $0.matchDomains == nil ? nil : [],
                      toolsRestricted: $0.matchTools != nil)
        })
    }
    let index = try RealmBindingSelection.uniqueIndex(in: bindings, vpnUUID: vpnUUID, signingIdentifier: identity,
                                                     designatedRequirement: requirement, executablePath: executable)
    return configured[index]
}

func health(_ manager: NEAppProxyProviderManager, routeId: String, guardianSession: String? = nil) async throws {
    let route = try store().read(routeId)
    guard manager.connection.status == .connected, let session = manager.connection as? NETunnelProviderSession else {
        throw RoutingError.notReady("app-proxy-not-connected")
    }
    let request = try JSONSerialization.data(withJSONObject: ["method": "health"])
    let response = try await boundedProviderReply(session, request: request)
    guard let response = response, let values = try JSONSerialization.jsonObject(with: response) as? [String: Any],
          values["active"] as? Bool == true, values["routeId"] as? String == routeId,
          (values["vpnUUID"] as? String).flatMap(RealmValidation.canonicalUUID) == route.vpnUUID,
          values["runtimeNamespace"] as? String == runtimeNamespace.rawValue,
          guardianSession == nil || (values["guardianLeaseReady"] as? Bool == true && values["sessionId"] as? String == guardianSession),
          values["providerVersion"] as? String == "1" else { throw RoutingError.notReady("route-not-confirmed-by-extension") }
}

func prepare(_ params: [String: Any], acceptanceOnly: Bool = false) async throws -> [String: Any] {
    if acceptanceOnly {
        #if ENVARA_NATIVE_ROUTING_ACCEPTANCE
        try await requireAcceptanceReady()
        #else
        throw RoutingError.invalidRequest
        #endif
    } else { try await requireReady() }
    guard let app = params["application"] as? [String: Any], let path = app["path"] as? String,
          let executable = app["executablePath"] as? String,
          let requestedRealm = params["vpnUUID"] as? String, let vpnUUID = RealmValidation.canonicalUUID(requestedRealm),
          let request = params["route"] as? [String: Any], let protocolName = request["protocol"] as? String,
          let host = request["host"] as? String, let port = request["port"] as? Int, port > 0, port <= 65535,
          let user = request["username"] as? String, let password = request["password"] as? String else { throw RoutingError.invalidRequest }
    let (identity, requirement) = try validateApplication(path: path, executable: executable)
    if acceptanceOnly {
        #if ENVARA_NATIVE_ROUTING_ACCEPTANCE
        _ = try acceptanceFixture(path: path, executable: executable)
        #else
        throw RoutingError.invalidRequest
        #endif
    } else { try requireTestedApplication(identity) }
    let manager = try exactManager(in: await managers(), vpnUUID: vpnUUID, identity: identity,
                                   requirement: requirement, executable: executable)
    guard !NSWorkspace.shared.runningApplications.contains(where: { $0.bundleURL?.path == path }),
          !(try sessionSnapshot()).contains(where: { $0.application.path == executable &&
              (!$0.scopeVerified || !$0.unknownPIDs.isEmpty || !$0.application.exitConfirmed ||
               $0.children.contains { !$0.exitConfirmed }) }) else {
        throw RoutingError.notReady("application-already-running-close-it-before-binding")
    }
    let id = UUID().uuidString
    let udpPolicy = request["udpPolicy"] as? String ?? (request["udp"] as? Bool == true ? "proxy" : "block")
    guard ["proxy", "block"].contains(udpPolicy) else { throw RoutingError.invalidRequest }
    let route = try Route(routeId: id, vpnUUID: vpnUUID, applicationIdentity: identity, applicationRequirement: requirement,
                          applicationPath: path, executablePath: executable,
                          protocolName: protocolName, host: host, port: UInt16(port), username: user, password: password,
                          udp: udpPolicy == "proxy" && request["udp"] as? Bool == true,
                          privacyMode: ((params["workspace"] as? [String: Any])?["privacy"] as? [String: Any])?["mode"] as? String ?? "standard", runtimeNamespace: runtimeNamespace)
    // Profiles are administrator-owned. Do not rewrite them. Our generated profile
    // must already enforce on-demand routing and contain no disconnect bypass rule.
    guard manager.isEnabled, manager.isOnDemandEnabled,
          !(manager.onDemandRules ?? []).contains(where: { $0 is NEOnDemandRuleDisconnect }),
          manager.excludedDomains.isEmpty,
          [.disconnected, .connected].contains(manager.connection.status) else {
        throw RoutingError.notReady("application-profile-must-enforce-routing-without-bypass")
    }
    let wasDisconnected = manager.connection.status == .disconnected
    try store().write(route)
    var rebindRejected = false
    do {
        if wasDisconnected {
            try manager.connection.startVPNTunnel(options: ["routeId": id as NSString, "vpnUUID": vpnUUID as NSString])
            for _ in 0..<100 {
                if manager.connection.status == .connected { break }
                try await Task.sleep(nanoseconds: 100_000_000)
            }
        } else {
            // Only a revoked, empty provider in this exact realm can bind again.
            // This preserves its VPN mapping and never stops another manager.
            let response = try await providerMessage(manager, ["method": "rebind", "routeId": id, "vpnUUID": vpnUUID])
            if response["rebound"] as? Bool == false { rebindRejected = true }
            guard response["rebound"] as? Bool == true,
                  response["routeId"] as? String == id,
                  (response["vpnUUID"] as? String).flatMap(RealmValidation.canonicalUUID) == vpnUUID else {
                throw RoutingError.notReady("same-realm-provider-is-not-idle")
            }
        }
        try await health(manager, routeId: id)
    } catch {
        // Removing a file alone cannot revoke the provider's in-memory secrets.
        // Roll back only this attempted route, and keep records if unconfirmed.
        var rolledBack = rebindRejected
        if !rolledBack, manager.connection.status == .connected,
           let response = try? await providerMessage(manager, ["method": "revoke", "routeId": id]) {
            rolledBack = response["revoked"] as? Bool == true
        }
        if !rolledBack && wasDisconnected {
            // This manager was idle and started solely by this failed attempt.
            manager.connection.stopVPNTunnel()
            for _ in 0..<30 {
                if [.disconnected, .invalid].contains(manager.connection.status) { rolledBack = true; break }
                try? await Task.sleep(nanoseconds: 100_000_000)
            }
        }
        if rolledBack { try store().revoke(id) }
        else { throw RoutingError.notReady("prepare-rollback-unconfirmed-route-retained") }
        throw error
    }
    return ["routeId": id, "vpnUUID": vpnUUID, "ready": !acceptanceOnly, "acceptanceOnly": acceptanceOnly, "failClosed": !acceptanceOnly, "udpPolicy": route.udp ? "proxy" : "block",
            "capabilities": ["tcp": true, "udp": true, "dns": true, "childProcesses": true, "failClosed": true], "verification": verification()]
}

private func sessionSnapshot() throws -> [Session] {
    let runtime = try store(readOnly: true)
    let files = try FileManager.default.contentsOfDirectory(at: runtime.directory, includingPropertiesForKeys: nil)
    return try files.filter { $0.pathExtension == "session" }.map { url in
        let session = try JSONDecoder().decode(Session.self, from: runtime.readPrivate(url))
        guard let fileID = RealmValidation.canonicalUUID(url.deletingPathExtension().lastPathComponent),
              let sessionID = RealmValidation.canonicalUUID(session.sessionId), fileID == sessionID,
              RealmValidation.canonicalUUID(session.routeId) != nil,
              ["starting", "running", "stopped", "error"].contains(session.state),
              session.unknownPIDs.allSatisfy({ $0 > 0 }) else { throw RoutingError.unsafeFile }
        return session
    }
}


private func providerMessage(_ manager: NEAppProxyProviderManager, _ message: [String: Any]) async throws -> [String: Any] {
    guard manager.connection.status == .connected, let session = manager.connection as? NETunnelProviderSession else {
        throw RoutingError.notReady("app-proxy-not-connected")
    }
    let request = try JSONSerialization.data(withJSONObject: message)
    let response = try await boundedProviderReply(session, request: request)
    guard let response = response,
          let result = try JSONSerialization.jsonObject(with: response) as? [String: Any] else { throw RoutingError.refused }
    return result
}

private func sessionStatuses(_ records: [Session]) -> [[String: Any]] {
    records.map {
        let running = $0.guardian.alive && ($0.application.alive || $0.children.contains { $0.alive })
        let stopped = $0.state == "stopped" && $0.scopeVerified && $0.unknownPIDs.isEmpty &&
            $0.application.exitConfirmed && $0.children.allSatisfy { $0.exitConfirmed }
        return ["sessionId": $0.sessionId, "pid": Int($0.pid), "routeId": $0.routeId,
                "status": running ? "running" : stopped ? "stopped" : "error"]
    }
}

func launch(_ params: [String: Any], acceptanceOnly: Bool = false) async throws -> [String: Any] {
    if acceptanceOnly {
        #if ENVARA_NATIVE_ROUTING_ACCEPTANCE
        try await requireAcceptanceReady()
        #else
        throw RoutingError.invalidRequest
        #endif
    } else { try await requireReady() }
    guard let id = params["routeId"] as? String else { throw RoutingError.invalidRequest }
    let route = try store().read(id), manager = try await manager(for: id)
    if acceptanceOnly {
        #if ENVARA_NATIVE_ROUTING_ACCEPTANCE
        _ = try acceptanceFixture(path: route.applicationPath, executable: route.executablePath)
        try validateAcceptanceLaunch(params)
        #else
        throw RoutingError.invalidRequest
        #endif
    } else { try requireTestedApplication(route.applicationIdentity) }
    try await health(manager, routeId: id)
    guard !(try sessionSnapshot()).contains(where: { $0.routeId == id &&
              (!$0.scopeVerified || !$0.unknownPIDs.isEmpty || !$0.application.exitConfirmed || $0.children.contains { !$0.exitConfirmed }) }),
          !NSWorkspace.shared.runningApplications.contains(where: { $0.bundleURL?.path == route.applicationPath }) else {
        throw RoutingError.notReady("application-already-running-close-it-before-binding")
    }
    let sessionId = UUID().uuidString
    var request = params; request["sessionId"] = sessionId
    let requestBytes = try JSONSerialization.data(withJSONObject: request)
    let guardian = Process()
    guardian.executableURL = Bundle.main.executableURL
    #if ENVARA_NATIVE_ROUTING_ACCEPTANCE
    guardian.arguments = ["--acceptance-guardian"]
    #else
    guardian.arguments = ["--guardian"]
    #endif
    let input = Pipe(); guardian.standardInput = input
    guardian.standardOutput = FileHandle.nullDevice; guardian.standardError = FileHandle.nullDevice
    try guardian.run()
    // Capture the process generation now. A later error must not adopt a reused
    // PID, and every failure after spawn must attempt owned cleanup.
    let guardianIdentity = ProcessIdentity.read(guardian.processIdentifier).flatMap { identity in
        identity.parent == getpid() && identity.path == Bundle.main.executableURL?.resolvingSymlinksInPath().path ? identity : nil
    }
    var confirmed = false
    defer {
        try? input.fileHandleForWriting.close()
        if !confirmed, let identity = guardianIdentity { _ = identity.signal(SIGTERM) }
    }
    guard guardianIdentity != nil else { throw RoutingError.notReady("owned-guardian-identity-unconfirmed") }
    input.fileHandleForWriting.write(requestBytes); try input.fileHandleForWriting.close()
    // The response is written atomically before launch is reported. A guardian owns
    // the process family after this short-lived RPC helper exits.
    for _ in 0..<100 {
        if let session = try sessionSnapshot().first(where: { $0.sessionId == sessionId }), session.state == "running",
           session.scopeVerified, session.unknownPIDs.isEmpty, session.application.alive, session.guardian.alive {
            try await health(manager, routeId: id, guardianSession: sessionId)
            confirmed = true
            return ["sessionId": session.sessionId, "pid": Int(session.pid), "startedAt": ISO8601DateFormatter().string(from: session.startedAt)]
        }
        if !guardian.isRunning { break }
        try await Task.sleep(nanoseconds: 100_000_000)
    }
    throw RoutingError.notReady("owned-application-launch-unconfirmed")
}

func stop(_ params: [String: Any]) async throws -> [String: Any] {
    let id = params["sessionId"] as? String, routeId = params["routeId"] as? String
    guard id != nil || routeId != nil else { throw RoutingError.invalidRequest }
    let matched = try sessionSnapshot().filter { id != nil ? $0.sessionId == id : $0.routeId == routeId }
    guard !matched.isEmpty else { throw RoutingError.notReady("known-owned-session-required") }
    for session in matched { _ = session.guardian.signal(SIGTERM) }
    for _ in 0..<80 {
        let latest = try sessionSnapshot().filter { id != nil ? $0.sessionId == id : $0.routeId == routeId }
        guard latest.count == matched.count else { throw RoutingError.notReady("owned-session-journal-is-incomplete") }
        if latest.allSatisfy({ $0.state == "stopped" && $0.scopeVerified && $0.unknownPIDs.isEmpty &&
            $0.application.exitConfirmed && $0.children.allSatisfy { $0.exitConfirmed } }) {
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

func revoke(_ params: [String: Any]) async throws -> [String: Any] {
    guard let id = params["routeId"] as? String else { throw RoutingError.invalidRequest }
    guard try sessionSnapshot().filter({ $0.routeId == id }).allSatisfy({ $0.state == "stopped" &&
        $0.scopeVerified && $0.unknownPIDs.isEmpty && $0.application.exitConfirmed &&
        $0.children.allSatisfy { $0.exitConfirmed } }) else {
        throw RoutingError.notReady("stop-owned-applications-before-revoking-route")
    }
    let selected = try await manager(for: id)
    if selected.connection.status == .connected {
        let values = try await providerMessage(selected, ["method": "revoke", "routeId": id])
        guard values["revoked"] as? Bool == true else { throw RoutingError.notReady("route-revocation-unconfirmed") }
    } else {
        guard [.disconnected, .invalid].contains(selected.connection.status) else {
            throw RoutingError.notReady("route-revocation-unconfirmed")
        }
    }
    // Removing route secrets makes new/provider-restarted flows fail closed. Keep the
    // app mapping enabled rather than disabling the VPN and potentially enabling DIRECT.
    let runtime = try store()
    try runtime.revoke(id)
    let leaseFile = try runtime.url(id, suffix: "lease")
    var leaseInfo = stat()
    if lstat(leaseFile.path, &leaseInfo) == 0 { try runtime.removeGuardianLease(id) }
    else if errno != ENOENT { throw RoutingError.unsafeFile }
    return ["revoked": true, "mappingRetained": true]
}

private final class ActivationDelegate: NSObject, OSSystemExtensionRequestDelegate {
    var completion: (([String: Any]) -> Void)?
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        // Same-version installations also need the preceding full-bundle check.
        // Never replace existing bytes as a side effect of acceptance or setup.
        return .cancel
    }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) { completion?(["ready": false, "reason": "system-extension-user-approval-required"]); completion = nil }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) { completion?(["ready": false, "reason": result == .completed ? "per-app-profile-and-acceptance-required" : "system-restart-required"]); completion = nil }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { completion?(["ready": false, "reason": "system-extension-activation-failed"]); completion = nil }
}
private var activationDelegate: ActivationDelegate?

func resolveRealm(_ params: [String: Any]) throws -> [String: Any] {
    guard let application = params["application"] as? [String: Any], let path = application["path"] as? String,
          let executable = application["executablePath"] as? String else { throw RoutingError.invalidRequest }
    // Read-only means no generated profile, directory creation, chmod, manager
    // configuration or extension activation. A missing manifest is not setup.
    let runtime = try store(readOnly: true)
    let (identity, requirement) = try validateApplication(path: path, executable: executable)
    let matches = try runtime.realmMappings().filter { $0.executablePath == executable }
    guard matches.count == 1, let mapping = matches.first,
          mapping.signingIdentifier == identity, mapping.designatedRequirement == requirement,
          mapping.applicationIdentifier == Bundle(url: URL(fileURLWithPath: path))?.bundleIdentifier,
          let realm = RealmValidation.canonicalUUID(mapping.vpnUUID) else {
        throw RoutingError.notReady("unique-owned-application-realm-required")
    }
    return ["vpnUUID": realm]
}

func setup(_ params: [String: Any]) async throws -> [String: Any] {
    if params["application"] != nil || params["applications"] != nil {
        guard hostAuthorized() else { throw RoutingError.notReady(authorizationReason) }
        let applications: [[String: Any]]
        if let many = params["applications"] as? [[String: Any]], params["application"] == nil { applications = many }
        else if let one = params["application"] as? [String: Any], params["applications"] == nil { applications = [one] }
        else { throw RoutingError.invalidRequest }
        guard !applications.isEmpty else { throw RoutingError.invalidRequest }
        let runtime = try store()
        let profileScope = try await validateInstalledProfileNamespace(runtime: runtime)
        var mappings = try runtime.realmMappings()
        var requested: [RealmMapping] = []
        for application in applications {
            guard let path = application["path"] as? String, let executable = application["executablePath"] as? String else {
                throw RoutingError.invalidRequest
            }
            let (identity, requirement) = try validateApplication(path: path, executable: executable)
            guard let bundleIdentifier = Bundle(url: URL(fileURLWithPath: path))?.bundleIdentifier else { throw RoutingError.invalidRequest }
            let existing = mappings.first { $0.executablePath == executable }
            let realm = (application["vpnUUID"] as? String) ?? (applications.count == 1 ? params["vpnUUID"] as? String : nil)
                ?? existing?.vpnUUID ?? UUID().uuidString
            guard let canonical = RealmValidation.canonicalUUID(realm) else { throw RoutingError.invalidRequest }
            let mapping = RealmMapping(applicationIdentifier: bundleIdentifier, signingIdentifier: identity,
                                       designatedRequirement: requirement, executablePath: executable, vpnUUID: canonical)
            // Reusing the same exact owned entry is idempotent. Changing its realm
            // or code identity requires an explicit future migration, never a
            // silent replacement of an application's already installed mapping.
            if let existing = existing {
                guard existing == mapping else { throw RoutingError.notReady("existing-application-realm-conflicts-with-request") }
            } else { mappings.append(mapping) }
            requested.append(mapping)
        }
        // Validate the request itself as well: duplicate entries in one request
        // must not disappear just because the persisted manifest is idempotent.
        let provider = providerBundleURL
        let (_, providerRequirement) = try codeIdentity(provider)
        _ = try ConfigurationProfile.make(applications: requested, providerRequirement: providerRequirement, namespace: runtimeNamespace)
        let profile = try ConfigurationProfile.make(applications: mappings, providerRequirement: providerRequirement, namespace: runtimeNamespace)
        let file = runtime.directory.appendingPathComponent("Envara-owned-realms.mobileconfig")
        try runtime.writePrivate(profile, to: file)
        try runtime.writeRealmMappings(mappings)
        // The desktop can present this local profile for explicit system approval.
        // Generating it does not install a profile, change routes, or register a VPN.
        return ["ready": false, "reason": "per-app-profile-user-installation-required", "profilePath": file.path,
                "requiresUserApproval": true, "vpnUUID": requested.count == 1 ? requested[0].vpnUUID : "",
                "realmCount": mappings.count, "profileConflictScope": profileScope, "globalProfileInventoryVerified": profileScope == "all"]
    }
    guard params["activate"] as? Bool == true else { return ["ready": false, "reason": "signed-extension-and-per-app-profile-required", "requiresUserApproval": true] }
    guard hostAuthorized() else { throw RoutingError.notReady(authorizationReason) }
    try await activationPreflight()
    return await withCheckedContinuation { continuation in
        let delegate = ActivationDelegate(); activationDelegate = delegate
        delegate.completion = { continuation.resume(returning: $0) }
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: providerIdentifier, queue: .main)
        request.delegate = delegate
        OSSystemExtensionManager.shared.submitRequest(request)
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
            delegate.completion?(["ready": false, "reason": "system-extension-activation-deadline"])
            delegate.completion = nil
        }
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
        case "resolveRealm": result = try resolveRealm(params)
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

#if ENVARA_NATIVE_ROUTING_ACCEPTANCE
let rpcFlag = "--acceptance-rpc", guardianFlag = "--acceptance-guardian"
#else
let rpcFlag = "--rpc", guardianFlag = "--guardian"
#endif
guard CommandLine.arguments.count == 2,
      CommandLine.arguments[1] == rpcFlag || CommandLine.arguments[1] == guardianFlag else {
    FileHandle.standardError.write(Data("Use the Envara desktop application or its dedicated acceptance tool.\n".utf8)); exit(64)
}
let input = FileHandle.standardInput.readDataToEndOfFile()
guard input.count <= 1_048_576, let request = try? JSONSerialization.jsonObject(with: input) as? [String: Any] else { exit(65) }
Task {
    if CommandLine.arguments[1] == guardianFlag {
        do {
            #if ENVARA_NATIVE_ROUTING_ACCEPTANCE
            try await runGuardian(request, acceptanceOnly: true)
            #else
            try await runGuardian(request)
            #endif
            exit(0)
        } catch { exit(70) }
    }
    #if ENVARA_NATIVE_ROUTING_ACCEPTANCE
    let response = await handleAcceptance(request)
    #else
    let response = await handle(request)
    #endif
    if let output = try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys]) {
        FileHandle.standardOutput.write(output + Data([10]))
    }
    exit(0)
}
// Only the explicit, authorized activation operation starts the AppKit host
// lifecycle required for the OS authorization UI. Status never activates it.
let explicitActivation = CommandLine.arguments[1] == rpcFlag &&
    ((request["method"] as? String == "setup" || request["method"] as? String == "activateExtension") &&
     (request["params"] as? [String: Any])?["activate"] as? Bool == true) && hostAuthorized()
if explicitActivation {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    app.run()
} else { dispatchMain() }
