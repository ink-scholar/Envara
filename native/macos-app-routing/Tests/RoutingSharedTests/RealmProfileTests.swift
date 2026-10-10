import XCTest
@testable import RoutingShared

// These tests verify serialization and rejection of ambiguous input only.
// They do not install profiles or verify macOS multi-VPNUUID/cached-flow routing.
final class RealmProfileTests: XCTestCase {
    private let firstUUID = "40D96A8D-82C6-442D-82FC-981903A85338"
    private let secondUUID = "A1B64DB3-2AC2-4B1C-BBA1-704B5E8E8016"
    private let requirement = "identifier io.envara.fixture"
    private let providerRequirement = "identifier io.envara.app-routing.proxy"

    private func realm(path: String = "/Applications/RealmA.app/Contents/MacOS/Fixture", uuid: String? = nil,
                       identifier: String = "io.envara.fixture", signingIdentifier: String = "io.envara.fixture",
                       designatedRequirement: String? = nil) -> RealmMapping {
        RealmMapping(applicationIdentifier: identifier, signingIdentifier: signingIdentifier,
                     designatedRequirement: designatedRequirement ?? requirement, executablePath: path,
                     vpnUUID: uuid ?? firstUUID)
    }

    private func profile(_ applications: [RealmMapping], provider: String? = nil) throws -> [String: Any] {
        let data = try ConfigurationProfile.make(applications: applications, providerRequirement: provider ?? providerRequirement)
        return try XCTUnwrap(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
    }

    func testDistinctPathsSharingSignatureAndBundleHaveSeparateRealms() throws {
        let applications = [realm(uuid: firstUUID.lowercased()),
                            realm(path: "/Applications/RealmB.app/Contents/MacOS/Fixture", uuid: secondUUID)]
        let root = try profile(applications)
        let payloads = try XCTUnwrap(root["PayloadContent"] as? [[String: Any]])
        let vpns = payloads.filter { $0["PayloadType"] as? String == "com.apple.vpn.managed.applayer" }
        let mappings = payloads.filter { $0["PayloadType"] as? String == "com.apple.vpn.managed.appmapping" }
        XCTAssertEqual(payloads.count, 3)
        XCTAssertEqual(vpns.count, 2)
        XCTAssertEqual(mappings.count, 1)
        let items = try XCTUnwrap(mappings[0]["AppLayerVPNMapping"] as? [[String: Any]])
        XCTAssertEqual(items.count, 2)
        XCTAssertEqual(items.map { $0["Identifier"] as? String }, applications.map { Optional($0.applicationIdentifier) })
        XCTAssertEqual(items.map { $0["Path"] as? String }, applications.map { Optional($0.executablePath) })
        XCTAssertEqual(items.map { $0["VPNUUID"] as? String }, [firstUUID, secondUUID])
        for (index, vpn) in vpns.enumerated() {
            let expectedUUID = [firstUUID, secondUUID][index]
            XCTAssertEqual(vpn["VPNUUID"] as? String, expectedUUID)
            XCTAssertEqual(vpn["OnDemandMatchAppEnabled"] as? Bool, true)
            let marker = try XCTUnwrap(vpn["VendorConfig"] as? [String: Any])
            XCTAssertEqual(marker["envaraVPNRealmUUID"] as? String, expectedUUID)
            XCTAssertEqual(marker["envaraRealmVersion"] as? Int, 1)
            let configuration = try XCTUnwrap(vpn["VPN"] as? [String: Any])
            XCTAssertEqual(configuration["ProviderDesignatedRequirement"] as? String, providerRequirement)
            XCTAssertNil(configuration["IncludeAllNetworks"])
            XCTAssertNil(configuration["AuthPassword"])
            XCTAssertNil(configuration["OnDemandRules"])
        }
        XCTAssertTrue(items.allSatisfy { $0["MatchTools"] == nil })
    }

    func testOwnedProfileAndMappingIdentifiersRemainStable() throws {
        let first = try profile([realm()])
        let second = try profile([realm(), realm(path: "/Applications/RealmB.app/Contents/MacOS/Fixture", uuid: secondUUID)])
        XCTAssertEqual(first["PayloadIdentifier"] as? String, "io.envara.app-routing.configuration")
        XCTAssertEqual(first["PayloadIdentifier"] as? String, second["PayloadIdentifier"] as? String)
        XCTAssertEqual(first["PayloadUUID"] as? String, second["PayloadUUID"] as? String)
        let firstPayloads = try XCTUnwrap(first["PayloadContent"] as? [[String: Any]])
        let secondPayloads = try XCTUnwrap(second["PayloadContent"] as? [[String: Any]])
        let firstMapping = try XCTUnwrap(firstPayloads.last)
        let secondMapping = try XCTUnwrap(secondPayloads.last)
        XCTAssertEqual(firstMapping["PayloadIdentifier"] as? String, "io.envara.app-routing.mapping")
        XCTAssertEqual(firstMapping["PayloadIdentifier"] as? String, secondMapping["PayloadIdentifier"] as? String)
        XCTAssertEqual(firstMapping["PayloadUUID"] as? String, secondMapping["PayloadUUID"] as? String)
    }

    func testRejectsRepeatedExecutablePathRegardlessOfIdentity() {
        XCTAssertThrowsError(try profile([realm(), realm(uuid: secondUUID, identifier: "io.envara.other", signingIdentifier: "io.envara.other")]))
    }

    func testRejectsRepeatedVPNUUIDRegardlessOfCaseOrPath() {
        XCTAssertThrowsError(try profile([realm(), realm(path: "/Applications/RealmB.app/Contents/MacOS/Fixture", uuid: firstUUID.lowercased())]))
    }

    func testRejectsCompletelyRepeatedMapping() {
        XCTAssertThrowsError(try profile([realm(), realm()]))
    }

    func testRejectsNonCanonicalOrBroadExecutablePaths() {
        for path in ["", "/", "/Applications", "/Applications/", "Applications/Fixture", "./Fixture", "../Fixture",
                     "/Applications/./Fixture", "/Applications/../Fixture", "/Applications//Fixture",
                     "/Applications/Fixture.app/Contents/MacOS/Fixture/", "/Applications/Fixture\u{0}binary"] {
            XCTAssertThrowsError(try profile([realm(path: path)]), "Accepted invalid executable path: \(path)")
        }
    }

    func testRejectsMissingOrInvalidRealmFields() {
        XCTAssertThrowsError(try profile([]))
        XCTAssertThrowsError(try profile([realm()], provider: " "))
        XCTAssertThrowsError(try profile([realm(identifier: " ")]))
        XCTAssertThrowsError(try profile([realm(signingIdentifier: "")]))
        XCTAssertThrowsError(try profile([realm(designatedRequirement: "\n")]))
        XCTAssertThrowsError(try profile([realm(uuid: "invalid-uuid")]))
        XCTAssertThrowsError(try profile([realm(uuid: " \(firstUUID)")]))
    }

    func testRealmMappingSupportsManifestRoundTrip() throws {
        let expected = [realm(), realm(path: "/Applications/RealmB.app/Contents/MacOS/Fixture", uuid: secondUUID)]
        XCTAssertEqual(try JSONDecoder().decode([RealmMapping].self, from: JSONEncoder().encode(expected)), expected)
    }

    func testSingleApplicationAPIUsesAggregateStructure() throws {
        let data = try ConfigurationProfile.make(applicationIdentifier: "io.envara.fixture", signingIdentifier: "io.envara.fixture",
                                                 designatedRequirement: requirement, executablePath: realm().executablePath,
                                                 providerRequirement: providerRequirement, vpnUUID: firstUUID)
        let root = try XCTUnwrap(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        let payloads = try XCTUnwrap(root["PayloadContent"] as? [[String: Any]])
        XCTAssertEqual(payloads.count, 2)
        XCTAssertEqual(payloads[0]["PayloadType"] as? String, "com.apple.vpn.managed.applayer")
        XCTAssertEqual(payloads[1]["PayloadType"] as? String, "com.apple.vpn.managed.appmapping")
    }
}
