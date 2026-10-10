import Foundation
import XCTest
@testable import RoutingShared

final class InstalledProfileInventoryTests: XCTestCase {
    private let realm = RealmMapping(applicationIdentifier: "io.envara.inventory-fixture",
        signingIdentifier: "io.envara.inventory-fixture", designatedRequirement: "identifier io.envara.inventory-fixture",
        executablePath: "/Applications/InventoryFixture.app/Contents/MacOS/Fixture",
        vpnUUID: "E55C39C6-6401-461F-AC02-019820FBE58B")
    private var owner: String { RoutingRuntimeNamespace.production.profileIdentifier }
    private var mappingID: String { RoutingRuntimeNamespace.production.mappingIdentifier }
    private func entry(_ item: RealmMapping) -> [String: Any] {
        ["Identifier": item.applicationIdentifier, "SigningIdentifier": item.signingIdentifier,
         "DesignatedRequirement": item.designatedRequirement, "Path": item.executablePath, "VPNUUID": item.vpnUUID]
    }
    private func payload(_ entries: [[String: Any]]? = nil) -> [String: Any] {
        ["PayloadType": "com.apple.vpn.managed.appmapping", "PayloadIdentifier": mappingID,
         "AppLayerVPNMapping": entries ?? [entry(realm)]]
    }
    private func profile(_ payloads: [Any], identifier: String? = nil) -> [String: Any] {
        ["PayloadType": "Configuration", "PayloadIdentifier": identifier ?? owner, "PayloadContent": payloads]
    }
    private func validate(_ tree: Any, known: [RealmMapping]? = nil) throws -> InstalledProfileInventory.Summary {
        try InstalledProfileInventory.validate(parsed: tree, ownedMappings: known ?? [realm])
    }

    func testEmptyScopedInventoryDoesNotClaimGlobalCoverage() throws {
        let result = try validate([String: Any]())
        XCTAssertFalse(result.ownedProfileFound)
        XCTAssertFalse(result.globalVerified)
        XCTAssertEqual(result.mappingPayloadCount, 0)
    }
    func testProfileToolWrapperAndDirectConfigurationFindOwnedSingleton() throws {
        let trees: [Any] = [profile([payload()]), ["_computerLevel": [["ProfileIdentifier": owner, "ProfileItems": [payload()]]]],
                            ["fixture-user": [["ProfileIdentifier": owner, "ProfileContent": [profile([payload()])]]]]]
        for tree in trees {
            let result = try validate(tree)
            XCTAssertTrue(result.ownedProfileFound)
            XCTAssertEqual(result.mappingPayloadCount, 1)
            XCTAssertEqual(result.installedMappingCount, 1)
        }
    }
    func testInstalledSubsetIsAllowedButUnknownOrChangedEntriesAreNot() throws {
        let extra = RealmMapping(applicationIdentifier: realm.applicationIdentifier, signingIdentifier: realm.signingIdentifier,
            designatedRequirement: realm.designatedRequirement, executablePath: "/Applications/OtherFixture.app/Contents/MacOS/Fixture",
            vpnUUID: "C2E8E500-D5DE-4D30-83F4-2B404D7D631D")
        XCTAssertEqual(try validate(profile([payload()]), known: [realm, extra]).installedMappingCount, 1)
        XCTAssertThrowsError(try validate(profile([payload()]), known: []))
        for field in ["Identifier", "SigningIdentifier", "DesignatedRequirement", "Path", "VPNUUID"] {
            var changed = entry(realm); changed[field] = "unknown"
            XCTAssertThrowsError(try validate(profile([payload([changed])])))
        }
    }
    func testForeignUnknownAndNestedConflictingOwnersAreRefused() {
        XCTAssertThrowsError(try validate(profile([payload()], identifier: "com.foreign.profile")))
        XCTAssertThrowsError(try validate(["unknown-wrapper": [payload()]]))
        XCTAssertThrowsError(try validate(profile([profile([payload()], identifier: "com.foreign.profile")])))
        XCTAssertThrowsError(try validate(["ProfileIdentifier": owner, "Arbitrary": [payload()]]))
    }
    func testDuplicatePayloadsOwnersAndEntriesAreRefused() {
        XCTAssertThrowsError(try validate(profile([payload(), payload()])))
        XCTAssertThrowsError(try validate(["fixture-user": [profile([payload()]), profile([payload()])]]))
        XCTAssertThrowsError(try validate(profile([payload([entry(realm), entry(realm)])])))
        XCTAssertThrowsError(try validate(profile([])))
    }
    func testMalformedPayloadCannotDisappearDuringRecursiveTraversal() {
        var missingType = payload(); missingType.removeValue(forKey: "PayloadType")
        var unknownKeys = entry(realm); unknownKeys["MatchTools"] = []
        let trees: [Any] = ["not-a-tree", ["PayloadType": 1], profile([missingType]),
                            profile([payload([])]), profile([payload([unknownKeys])]),
                            ["unexpected-type-key": "com.apple.vpn.managed.appmapping"],
                            ["ProfileIdentifier": owner, "ProfileItems": "not-an-array"], ["unsupported": NSNull()]]
        for tree in trees {
            XCTAssertThrowsError(try validate(tree))
        }
    }
    func testBoundedDepthNodeAndByteBudgetsRejectOversizedTrees() {
        var nested: Any = payload()
        for _ in 0..<40 { nested = ["nested": nested] }
        XCTAssertThrowsError(try validate(nested))
        XCTAssertThrowsError(try validate(["large": String(repeating: "x", count: 2_097_153)]))
        XCTAssertThrowsError(try validate(["many": Array(repeating: "x", count: 16_385)]))
    }
    func testExactNamespaceIncludesFixtureIsolationAndPreservesProductionNames() throws {
        let namespace = RoutingRuntimeNamespace.fixtureAcceptance
        var fixturePayload = payload()
        fixturePayload["PayloadIdentifier"] = "io.envara.app-routing.\(namespace.rawValue).mapping"
        let fixtureTree = profile([fixturePayload], identifier: namespace.profileIdentifier)
        XCTAssertThrowsError(try validate(fixtureTree))
        XCTAssertEqual(try InstalledProfileInventory.validate(parsed: fixtureTree, ownedMappings: [realm],
            ownerProfileIdentifier: namespace.profileIdentifier,
            mappingPayloadIdentifier: "io.envara.app-routing.\(namespace.rawValue).mapping").installedMappingCount, 1)
        XCTAssertThrowsError(try validate(profile([payload()], identifier: "io.envara.app-routing.production.configuration")))
    }
}
