import Foundation
import XCTest
@testable import RoutingShared

final class RuntimeNamespaceTests: XCTestCase {
    private func route(namespace: RoutingRuntimeNamespace) throws -> Route {
        try Route(routeId: UUID().uuidString, vpnUUID: UUID().uuidString,
                  applicationIdentity: "io.envara.test", applicationRequirement: "test-requirement",
                  applicationPath: "/Applications/Test.app", executablePath: "/Applications/Test.app/Contents/MacOS/Test",
                  protocolName: "socks5", host: "127.0.0.1", port: 1080, username: "test", password: "test",
                  udp: false, runtimeNamespace: namespace)
    }

    func testRuntimeNamespacesCannotReadOrOverwriteEachOthersRoutes() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let production = try RuntimeStore(directory: directory)
        let fixtures = try RuntimeStore(directory: directory, namespace: .fixtureAcceptance)
        let selected = try route(namespace: .fixtureAcceptance)
        try fixtures.write(selected)
        XCTAssertEqual(try fixtures.read(selected.routeId), selected)
        XCTAssertThrowsError(try production.read(selected.routeId))
        XCTAssertThrowsError(try production.write(selected))
        XCTAssertNotEqual(production.directory, fixtures.directory)
    }

    func testSerializedNamespaceMustBeExplicitAndKnown() throws {
        let selected = try route(namespace: .production)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(selected)) as? [String: Any])
        object.removeValue(forKey: "runtimeNamespace")
        XCTAssertThrowsError(try JSONDecoder().decode(Route.self, from: JSONSerialization.data(withJSONObject: object)))
        object["runtimeNamespace"] = "../../other"
        XCTAssertThrowsError(try JSONDecoder().decode(Route.self, from: JSONSerialization.data(withJSONObject: object)))
    }

    func testProfileNamespacesShareOnlyProviderIdentity() throws {
        let entry = RealmMapping(applicationIdentifier: "io.envara.test", signingIdentifier: "io.envara.test",
                                 designatedRequirement: "test-requirement", executablePath: "/Applications/Test.app/Contents/MacOS/Test")
        var identifiers = Set<String>()
        for namespace in [RoutingRuntimeNamespace.production, .fixtureAcceptance] {
            let data = try ConfigurationProfile.make(applications: [entry], providerRequirement: "provider", namespace: namespace)
            let profile = try XCTUnwrap(PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
            XCTAssertEqual(profile["PayloadIdentifier"] as? String, namespace.profileIdentifier)
            XCTAssertTrue(identifiers.insert(try XCTUnwrap(profile["PayloadIdentifier"] as? String)).inserted)
            let payloads = try XCTUnwrap(profile["PayloadContent"] as? [[String: Any]])
            let vpn = try XCTUnwrap(payloads.first { $0["PayloadType"] as? String == "com.apple.vpn.managed.applayer" })
            XCTAssertEqual((vpn["VendorConfig"] as? [String: Any])?[RoutingRuntimeNamespace.configurationKey] as? String, namespace.rawValue)
            XCTAssertEqual((vpn["VPN"] as? [String: Any])?["ProviderBundleIdentifier"] as? String, RoutingSigningAuthorization.providerIdentifier)
        }
    }
}
