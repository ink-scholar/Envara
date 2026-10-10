import Foundation
import XCTest
@testable import RoutingShared

final class RealmRouteTests: XCTestCase {
    private let signingIdentifier = "io.envara.realm-fixture"
    private let requirement = "identifier \"io.envara.realm-fixture\" and anchor apple generic"
    private let applicationA = "/Applications/EnvaraRealmA.app"
    private let applicationB = "/Applications/EnvaraRealmB.app"

    private func executable(_ application: String) -> String {
        application + "/Contents/MacOS/RealmFixture"
    }

    private func route(routeId: String = UUID().uuidString, vpnUUID: String = UUID().uuidString,
                       applicationPath: String = "/Applications/EnvaraRealmA.app",
                       executablePath: String = "/Applications/EnvaraRealmA.app/Contents/MacOS/RealmFixture",
                       applicationRequirement: String = "identifier \"io.envara.realm-fixture\" and anchor apple generic") throws -> Route {
        try Route(routeId: routeId, vpnUUID: vpnUUID, applicationIdentity: signingIdentifier,
                  applicationRequirement: applicationRequirement, applicationPath: applicationPath,
                  executablePath: executablePath, protocolName: "socks5", host: "127.0.0.1",
                  port: 12345, username: "realm-fixture", password: "ephemeral-realm-fixture-secret", udp: true)
    }

    private func binding(_ vpnUUID: String?, path: String?, designatedRequirement: String? = nil) -> RealmManagerBinding {
        RealmManagerBinding(realmUUID: vpnUUID, rules: [
            RealmRule(signingIdentifier: signingIdentifier,
                      designatedRequirement: designatedRequirement ?? requirement,
                      executablePath: path)
        ])
    }

    private func select(_ bindings: [RealmManagerBinding], vpnUUID: String, path: String) throws -> Int {
        try RealmBindingSelection.uniqueIndex(in: bindings, vpnUUID: vpnUUID,
            signingIdentifier: signingIdentifier, designatedRequirement: requirement, executablePath: path)
    }

    func testSameSigningIdentityUsesItsOwnUUIDAndExecutablePath() throws {
        let realmA = UUID().uuidString, realmB = UUID().uuidString
        let bindings = [binding(realmA, path: executable(applicationA)),
                        binding(realmB, path: executable(applicationB))]
        XCTAssertEqual(try select(bindings, vpnUUID: realmA, path: executable(applicationA)), 0)
        XCTAssertEqual(try select(bindings, vpnUUID: realmB, path: executable(applicationB)), 1)
        XCTAssertThrowsError(try select(bindings, vpnUUID: realmA, path: executable(applicationB)))
        XCTAssertThrowsError(try select(bindings, vpnUUID: realmB, path: executable(applicationA)))
    }

    func testExactApplicationCannotSelectAnotherRealmOrAnUnscopedManager() {
        let realm = UUID().uuidString, otherRealm = UUID().uuidString
        XCTAssertThrowsError(try select([binding(otherRealm, path: executable(applicationA))],
                                       vpnUUID: realm, path: executable(applicationA)))
        XCTAssertThrowsError(try select([binding(nil, path: executable(applicationA))],
                                       vpnUUID: realm, path: executable(applicationA)))
    }

    func testUnrestrictedPathDoesNotAuthorizeAnEnvironmentInstance() {
        let realm = UUID().uuidString
        XCTAssertThrowsError(try select([binding(realm, path: nil)],
                                       vpnUUID: realm, path: executable(applicationA)))
    }

    func testMatchingUUIDAndPathDoNotAcceptAnotherSigningRequirement() {
        let realm = UUID().uuidString
        let wrongRequirement = "identifier \"io.envara.realm-fixture\" and anchor trusted"
        XCTAssertThrowsError(try select([binding(realm, path: executable(applicationA),
                                                designatedRequirement: wrongRequirement)],
                                       vpnUUID: realm, path: executable(applicationA)))
        let wrongIdentity = RealmManagerBinding(realmUUID: realm, rules: [
            RealmRule(signingIdentifier: "io.envara.other-fixture", designatedRequirement: requirement,
                      executablePath: executable(applicationA))
        ])
        XCTAssertThrowsError(try select([wrongIdentity], vpnUUID: realm, path: executable(applicationA)))
    }

    func testDuplicateManagerBindingsAreAmbiguous() {
        let realm = UUID().uuidString
        let matching = binding(realm, path: executable(applicationA))
        XCTAssertThrowsError(try select([matching, matching], vpnUUID: realm, path: executable(applicationA)))
    }

    func testBroadOrCompetingMappingsCannotStealTheSelectedRealm() {
        let realm = UUID().uuidString, other = UUID().uuidString
        let selected = binding(realm, path: executable(applicationA))
        XCTAssertThrowsError(try select([selected, binding(other, path: nil)],
                                       vpnUUID: realm, path: executable(applicationA)))
        XCTAssertThrowsError(try select([selected, binding(other, path: executable(applicationA))],
                                       vpnUUID: realm, path: executable(applicationA)))
        XCTAssertThrowsError(try select([selected, binding(realm, path: executable(applicationB))],
                                       vpnUUID: realm, path: executable(applicationA)))
        for broad in ["/Applications", applicationA, applicationA + "/Contents", applicationA + "/Contents/MacOS"] {
            XCTAssertThrowsError(try select([selected, binding(other, path: broad)],
                                           vpnUUID: realm, path: executable(applicationA)))
        }
    }

    func testRestrictedDomainsAndToolsDoNotAuthorizeWholeApplicationRouting() {
        let realm = UUID().uuidString
        for rule in [RealmRule(signingIdentifier: signingIdentifier, designatedRequirement: requirement,
                               executablePath: executable(applicationA), domains: ["example.test"]),
                     RealmRule(signingIdentifier: signingIdentifier, designatedRequirement: requirement,
                               executablePath: executable(applicationA), toolsRestricted: true)] {
            XCTAssertThrowsError(try select([RealmManagerBinding(realmUUID: realm, rules: [rule])],
                                           vpnUUID: realm, path: executable(applicationA)))
        }
    }

    func testMissingLegacyRealmFieldsFailDecoding() throws {
        let valid = try route()
        let encoded = try JSONEncoder().encode(valid)
        XCTAssertEqual(try JSONDecoder().decode(Route.self, from: encoded), valid)
        let original = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        for field in ["vpnUUID", "applicationRequirement"] {
            var legacy = original
            legacy.removeValue(forKey: field)
            let data = try JSONSerialization.data(withJSONObject: legacy)
            XCTAssertThrowsError(try JSONDecoder().decode(Route.self, from: data)) { error in
                guard case DecodingError.keyNotFound(let key, _) = error else {
                    return XCTFail("Missing \(field) must fail as a required field, got \(error)")
                }
                XCTAssertEqual(key.stringValue, field)
            }
        }
    }

    func testRealmUUIDRequirementAndPathsMustBeValidAndCanonical() {
        XCTAssertThrowsError(try route(vpnUUID: "not-a-vpn-uuid"))
        XCTAssertThrowsError(try route(applicationRequirement: ""))
        XCTAssertThrowsError(try route(applicationRequirement: " \n"))
        for path in ["Applications/EnvaraRealmA.app", "/Applications/./EnvaraRealmA.app",
                     "/Applications/Unused/../EnvaraRealmA.app", "/Applications/EnvaraRealmA.app/"] {
            XCTAssertThrowsError(try route(applicationPath: path), "Rejected application path: \(path)")
        }
        for path in ["RealmFixture", "/Applications/EnvaraRealmA.app/Contents/MacOS/./RealmFixture",
                     "/Applications/EnvaraRealmA.app/Contents/Unused/../MacOS/RealmFixture",
                     "/Applications/EnvaraRealmA.app/Contents/MacOS/RealmFixture/"] {
            XCTAssertThrowsError(try route(executablePath: path), "Rejected executable path: \(path)")
        }
    }

    func testRuntimeFileCannotClaimAnotherRouteID() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try RuntimeStore(directory: root), record = try route()
        let requestedID = UUID().uuidString
        try store.writePrivate(JSONEncoder().encode(record), to: store.url(requestedID))
        XCTAssertThrowsError(try store.read(requestedID))
    }

    func testRuntimeRouteIDComparisonUsesCanonicalUUIDIdentity() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try RuntimeStore(directory: root)
        let id = UUID().uuidString, record = try route(routeId: id)
        try store.writePrivate(JSONEncoder().encode(record), to: store.url(id.lowercased()))
        XCTAssertEqual(try store.read(id.lowercased()), record)
    }

    func testOwnedManifestRoundTripAndConflictingPersistedMappingsFail() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try RuntimeStore(directory: root)
        XCTAssertTrue(try store.realmMappings().isEmpty)
        let first = RealmMapping(applicationIdentifier: signingIdentifier, signingIdentifier: signingIdentifier,
                                 designatedRequirement: requirement, executablePath: executable(applicationA), vpnUUID: UUID().uuidString)
        let second = RealmMapping(applicationIdentifier: signingIdentifier, signingIdentifier: signingIdentifier,
                                  designatedRequirement: requirement, executablePath: executable(applicationB), vpnUUID: UUID().uuidString)
        try store.writeRealmMappings([first, second])
        XCTAssertEqual(try store.realmMappings(), [first, second])
        XCTAssertThrowsError(try store.writeRealmMappings([first, first]))
        try store.writePrivate(JSONEncoder().encode([first, first]),
                               to: store.directory.appendingPathComponent("owned-realms.json"))
        XCTAssertThrowsError(try store.realmMappings())
    }

    func testReadOnlyStoreDoesNotCreateOrRepairPermissions() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        XCTAssertThrowsError(try RuntimeStore(directory: root, create: false))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.path))
        let created = try RuntimeStore(directory: root)
        let record = try route()
        try created.write(record)
        XCTAssertEqual(try RuntimeStore(directory: root, create: false).read(record.routeId), record)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: created.directory.path)
        XCTAssertThrowsError(try RuntimeStore(directory: root, create: false))
        XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: created.directory.path)[.posixPermissions] as? NSNumber)?.intValue,
                       0o755)
    }

    func testRebindRequiresSameRealmAndFullyRevokedFlowState() throws {
        let realm = UUID().uuidString, other = UUID().uuidString
        XCTAssertNoThrow(try RealmRebindValidation.validate(routeRealm: realm, configuredRealm: realm.lowercased(),
                                                            hasRoute: false, activeFlows: 0, draining: false))
        XCTAssertThrowsError(try RealmRebindValidation.validate(routeRealm: other, configuredRealm: realm,
                                                               hasRoute: false, activeFlows: 0, draining: false))
        XCTAssertThrowsError(try RealmRebindValidation.validate(routeRealm: realm, configuredRealm: realm,
                                                               hasRoute: true, activeFlows: 0, draining: false))
        XCTAssertThrowsError(try RealmRebindValidation.validate(routeRealm: realm, configuredRealm: realm,
                                                               hasRoute: false, activeFlows: 1, draining: false))
        XCTAssertThrowsError(try RealmRebindValidation.validate(routeRealm: realm, configuredRealm: realm,
                                                               hasRoute: false, activeFlows: 0, draining: true))
    }
}
