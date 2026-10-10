#if ENVARA_NATIVE_ROUTING_ACCEPTANCE
import CryptoKit
import Darwin
import Foundation
import Security
import RoutingShared

// This source is absent from the production dispatch. The helper uses a separate
// runtime namespace/profile IDs and the exact signed production provider. Results
// never create a production routing-acceptance receipt.
private let acceptanceProtocol = "envara.routing-acceptance"
private let fixtureNames = ["one": "EnvaraRoutingFixtureOne", "two": "EnvaraRoutingFixtureTwo"]

func acceptanceFixture(_ slot: String) throws -> [String: Any] {
    guard let name = fixtureNames[slot], hostAuthorized() else {
        throw RoutingError.notReady("authorized-owned-acceptance-fixtures-required")
    }
    let host = Bundle.main.bundleURL
    let devices = signingModeForAcceptance == .development ? try RoutingSigningAuthorization.deviceIdentifiers() : []
    let hostProof = try RoutingSigningAuthorization.validateBundle(host,
        expectedIdentifier: RoutingSigningAuthorization.hostIdentifier, host: true,
        mode: signingModeForAcceptance, devices: devices)
    let app = host.appendingPathComponent("Contents/Helpers/\(name).app")
    let executable = app.appendingPathComponent("Contents/MacOS/EnvaraRoutingAcceptanceFixture")
    guard app.resolvingSymlinksInPath().path == app.path,
          executable.resolvingSymlinksInPath().path == executable.path,
          let manifestURL = Bundle.main.url(forResource: "acceptance-fixtures", withExtension: "json"),
          let data = try? Data(contentsOf: manifestURL), data.count <= 16_384,
          let manifest = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          manifest["version"] as? Int == 1,
          let entries = manifest["fixtures"] as? [String: [String: String]],
          let entry = entries[slot], entry["identifier"] == "io.envara.routing.fixture.\(slot)",
          entry["bundle"] == "\(name).app",
          let bytes = try? Data(contentsOf: executable),
          entry["sha256"] == SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() else {
        throw RoutingError.notReady("sealed-acceptance-fixture-manifest-required")
    }
    var code: SecStaticCode?, info: CFDictionary?
    guard SecStaticCodeCreateWithPath(app as CFURL, [], &code) == errSecSuccess, let code = code,
          SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), nil) == errSecSuccess,
          SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let values = info as? [String: Any],
          values[kSecCodeInfoIdentifier as String] as? String == entry["identifier"],
          values[kSecCodeInfoTeamIdentifier as String] as? String == hostProof.team,
          let certificates = values[kSecCodeInfoCertificates as String] as? [SecCertificate], let certificate = certificates.first,
          SHA256.hash(data: SecCertificateCopyData(certificate) as Data).map({ String(format: "%02x", $0) }).joined() == hostProof.certificateSHA256 else {
        throw RoutingError.notReady("fixture-must-share-authorized-host-signature")
    }
    _ = try validateApplication(path: app.path, executable: executable.path, identity: entry["identifier"])
    return ["path": app.path, "executablePath": executable.path]
}

private var signingModeForAcceptance: RoutingSigningMode {
    #if ENVARA_LOCAL_DEVELOPMENT_ROUTING
    return .development
    #else
    return .developerID
    #endif
}

@discardableResult
func acceptanceFixture(path: String, executable: String) throws -> String {
    for slot in ["one", "two"] {
        let fixture = try acceptanceFixture(slot)
        if fixture["path"] as? String == path, fixture["executablePath"] as? String == executable { return slot }
    }
    throw RoutingError.notReady("only-sealed-acceptance-fixtures-may-launch")
}

func requireAcceptanceReady() async throws {
    guard hostAuthorized() else { throw RoutingError.notReady("apple-signed-acceptance-extension-required") }
    guard await extensionEnabled() else { throw RoutingError.notReady("acceptance-extension-user-authorization-required") }
    _ = try acceptanceFixture("one"); _ = try acceptanceFixture("two")
}

func validateAcceptanceLaunch(_ params: [String: Any]) throws {
    guard Set(params.keys).isSubset(of: ["routeId", "args", "sessionId"]),
          let id = params["routeId"] as? String, let canonical = RealmValidation.canonicalUUID(id),
          let arguments = params["args"] as? [String], arguments.count == 2, arguments[0] == "--socket" else {
        throw RoutingError.invalidRequest
    }
    let socket = URL(fileURLWithPath: arguments[1]), parent = socket.deletingLastPathComponent()
    var info = stat()
    guard socket.path.utf8.count < 104, socket.path == socket.resolvingSymlinksInPath().path,
          socket.lastPathComponent == "acceptance-\(canonical).sock",
          parent.deletingLastPathComponent().path == "/private/tmp", parent.lastPathComponent.hasPrefix("envara-ac-"),
          lstat(parent.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
          info.st_uid == getuid(), info.st_mode & 0o777 == 0o700 else { throw RoutingError.unsafeFile }
    if let session = params["sessionId"] as? String, RealmValidation.canonicalUUID(session) == nil { throw RoutingError.invalidRequest }
}

private func ownedFixtureRoute(_ params: [String: Any]) throws -> Route {
    guard Set(params.keys) == ["routeId"], let id = params["routeId"] as? String else { throw RoutingError.invalidRequest }
    let route = try store(readOnly: true).read(id)
    _ = try acceptanceFixture(path: route.applicationPath, executable: route.executablePath)
    return route
}

func handleAcceptance(_ request: [String: Any]) async -> [String: Any] {
    let id = request["id"] as? String ?? ""
    var response: [String: Any] = ["protocol": acceptanceProtocol, "version": 1, "id": id]
    do {
        guard Set(request.keys).isSubset(of: ["protocol", "version", "id", "method", "params"]),
              request["protocol"] as? String == acceptanceProtocol, request["version"] as? Int == 1,
              !id.isEmpty, id.utf8.count <= 64, let method = request["method"] as? String,
              let params = request["params"] as? [String: Any] else { throw RoutingError.invalidRequest }
        var result: [String: Any]
        switch method {
        case "status":
            guard params.isEmpty else { throw RoutingError.invalidRequest }
            let authorized = hostAuthorized(), enabled = authorized ? await extensionEnabled() : false
            result = ["ready": false, "acceptanceOnly": true, "productionReceiptAllowed": false,
                      "authorized": authorized, "extensionEnabled": enabled,
                      "hostIdentifier": RoutingSigningAuthorization.hostIdentifier,
                      "providerIdentifier": providerIdentifier, "applicationGroup": RuntimeStore.groupIdentifier,
                      "runtimeNamespace": runtimeNamespace.rawValue, "fixtures": ["one", "two"], "reason": authorized ? "native-fixture-acceptance-pending" : "apple-signed-acceptance-extension-required"]
        case "setupProfiles":
            guard params.isEmpty else { throw RoutingError.invalidRequest }
            result = try await setup(["applications": [acceptanceFixture("one"), acceptanceFixture("two")]])
        case "activateExtension":
            guard Set(params.keys) == ["activate"], params["activate"] as? Bool == true else { throw RoutingError.invalidRequest }
            _ = try acceptanceFixture("one"); _ = try acceptanceFixture("two")
            result = try await setup(["activate": true])
        case "prepareFixture":
            guard Set(params.keys) == ["fixture", "route"], let slot = params["fixture"] as? String,
                  let route = params["route"] as? [String: Any],
                  Set(route.keys).isSubset(of: ["protocol", "host", "port", "username", "password", "udp", "udpPolicy"]) else { throw RoutingError.invalidRequest }
            let fixture = try acceptanceFixture(slot)
            let realm = try resolveRealm(["application": fixture])
            result = try await prepare(["application": fixture, "vpnUUID": realm["vpnUUID"]!, "route": route], acceptanceOnly: true)
        case "launchFixture":
            let route = try ownedFixtureRoute(params)
            var template = Array("/private/tmp/envara-ac-XXXXXX".utf8CString)
            guard let directory = mkdtemp(&template) else { throw RoutingError.unsafeFile }
            let parent = URL(fileURLWithPath: String(cString: directory), isDirectory: true)
            let socket = parent.appendingPathComponent("acceptance-\(route.routeId).sock")
            do {
                result = try await launch(["routeId": route.routeId, "args": ["--socket", socket.path]], acceptanceOnly: true)
                result["socketPath"] = socket.path
            } catch {
                // rmdir only removes the directory if it is empty. Keep any live
                // socket/uncertain guardian state available for explicit cleanup.
                _ = rmdir(parent.path); throw error
            }
        case "stopFixture":
            let route = try ownedFixtureRoute(params)
            result = try await stop(["routeId": route.routeId])
        case "revokeFixture":
            let route = try ownedFixtureRoute(params)
            result = try await revoke(["routeId": route.routeId])
        default: throw RoutingError.invalidRequest
        }
        result["ready"] = false; result["acceptanceOnly"] = true
        result["productionReceiptAllowed"] = false
        response["result"] = result
    } catch let RoutingError.notReady(reason) { response["error"] = ["code": "notReady", "message": reason] }
    catch { response["error"] = ["code": "routingFailed", "message": "Owned fixture acceptance could not complete"] }
    return response
}
#endif
