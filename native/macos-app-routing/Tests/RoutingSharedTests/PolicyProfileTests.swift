import XCTest
@testable import RoutingShared

final class PolicyProfileTests: XCTestCase {
    private func query(_ host: String) -> Data {
        var data = Data([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        for label in host.split(separator: ".") { data.append(UInt8(label.utf8.count)); data.append(contentsOf: label.utf8) }
        data.append(contentsOf: [0, 0, 1, 0, 1]); return data
    }

    func testTrackerDNSIsAnsweredWithoutProxyOrHostResolution() throws {
        let request = query("stats.google-analytics.com")
        let response = try XCTUnwrap(PrivacyPolicy.blockedDNSResponse(request, mode: "standard"))
        XCTAssertEqual(response.prefix(2), request.prefix(2))
        XCTAssertEqual(response[3] & 0x0f, 3)
        XCTAssertEqual(response.subdata(in: 12..<response.count), request.subdata(in: 12..<request.count))
        XCTAssertNil(try PrivacyPolicy.blockedDNSResponse(query("example.test"), mode: "strict"))
        XCTAssertNil(try PrivacyPolicy.blockedDNSResponse(request, mode: "off"))
    }

    func testTrackerHostBoundariesAndModes() {
        XCTAssertTrue(PrivacyPolicy.blocks("stats.google-analytics.com.", mode: "standard"))
        XCTAssertFalse(PrivacyPolicy.blocks("notgoogle-analytics.com", mode: "strict"))
        XCTAssertFalse(PrivacyPolicy.blocks("api.mixpanel.com", mode: "standard"))
        XCTAssertTrue(PrivacyPolicy.blocks("api.mixpanel.com", mode: "strict"))
    }

    func testProfileTargetsOnlySelectedIdentityAndContainsNoSecrets() throws {
        let data = try ConfigurationProfile.make(applicationIdentifier: "io.envara.fixture", signingIdentifier: "io.envara.fixture",
                                                 designatedRequirement: "identifier io.envara.fixture", executablePath: "/Applications/Fixture.app/Contents/MacOS/Fixture",
                                                 providerRequirement: "identifier io.envara.app-routing.proxy")
        let profile = try XCTUnwrap(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        let payloads = try XCTUnwrap(profile["PayloadContent"] as? [[String: Any]])
        XCTAssertEqual(payloads.count, 2)
        XCTAssertEqual(payloads[0]["PayloadType"] as? String, "com.apple.vpn.managed.applayer")
        let vpn = try XCTUnwrap(payloads[0]["VPN"] as? [String: Any])
        XCTAssertEqual(vpn["ProviderType"] as? String, "app-proxy")
        XCTAssertNil(vpn["IncludeAllNetworks"]); XCTAssertNil(vpn["AuthPassword"])
        let mapping = try XCTUnwrap(payloads[1]["AppLayerVPNMapping"] as? [[String: Any]])
        XCTAssertEqual(mapping.count, 1); XCTAssertNil(mapping[0]["MatchTools"])
        XCTAssertEqual(mapping[0]["Path"] as? String, "/Applications/Fixture.app/Contents/MacOS/Fixture")
    }
}
