import Foundation
import Security
import XCTest
@testable import RoutingShared

final class SigningAuthorizationTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let team = "TEAM123456"
    private let certificate = Data("synthetic-unit-test-certificate-not-signing-material".utf8)
    private let device = "LOCAL-PROVISIONING-UDID"

    private func profile(_ mode: RoutingSigningMode, host: Bool = true) -> [String: Any] {
        let identifier = host ? RoutingSigningAuthorization.hostIdentifier : RoutingSigningAuthorization.providerIdentifier
        var entitlements: [String: Any] = ["com.apple.application-identifier": "PREFIX1234." + identifier,
            "com.apple.developer.team-identifier": team,
            "com.apple.developer.networking.networkextension": [mode.networkEntitlement],
            "com.apple.security.application-groups": [RuntimeStore.groupIdentifier]]
        if host { entitlements["com.apple.developer.system-extension.install"] = true }
        var result: [String: Any] = ["CreationDate": now.addingTimeInterval(-100), "ExpirationDate": now.addingTimeInterval(100),
            "Platform": ["OSX"], "TeamIdentifier": [team], "ApplicationIdentifierPrefix": ["PREFIX1234"],
            "DeveloperCertificates": [certificate], "Entitlements": entitlements]
        if mode == .development {
            result["ProvisionedDevices"] = [device]
            entitlements["com.apple.security.get-task-allow"] = true; result["Entitlements"] = entitlements
        } else { result["ProvisionsAllDevices"] = true }
        return result
    }

    private func validate(_ profile: [String: Any], _ mode: RoutingSigningMode, host: Bool = true) throws -> String {
        try RoutingSigningAuthorization.validateConstraints(profile, certificateData: certificate, team: team,
            bundleIdentifier: host ? RoutingSigningAuthorization.hostIdentifier : RoutingSigningAuthorization.providerIdentifier,
            host: host, mode: mode, devices: [device], now: now)
    }

    func testDevelopmentConstraintsBindCertificateTeamAppAndProvisioningDevice() throws {
        XCTAssertEqual(try validate(profile(.development), .development), "PREFIX1234.io.envara.app-routing")
        XCTAssertEqual(try validate(profile(.development, host: false), .development, host: false), "PREFIX1234.io.envara.app-routing.proxy")
        // These are pure parser tests; no fixture is an authenticated CMS profile.
        XCTAssertThrowsError(try validate(profile(.development), .developerID))
    }

    func testDevelopmentConstraintsRejectMissingOrMismatchedAuthorization() {
        let changes: [(inout [String: Any]) -> Void] = [
            { $0["ExpirationDate"] = self.now.addingTimeInterval(-1) },
            { $0["CreationDate"] = self.now.addingTimeInterval(1) },
            { $0["TeamIdentifier"] = ["OTHER12345"] },
            { $0["DeveloperCertificates"] = [Data("wrong".utf8)] },
            { $0["ProvisionedDevices"] = ["UNRELATED-DEVICE"] },
            { $0["ProvisionsAllDevices"] = true },
            { $0["ApplicationIdentifierPrefix"] = ["WRONGPREFIX"] },
            { $0["Platform"] = ["iOS"] },
        ]
        for change in changes { var value = profile(.development); change(&value); XCTAssertThrowsError(try validate(value, .development)) }
        for key in ["com.apple.developer.team-identifier", "com.apple.application-identifier",
                    "com.apple.developer.networking.networkextension", "com.apple.security.application-groups",
                    "com.apple.developer.system-extension.install", "com.apple.security.get-task-allow"] {
            var value = profile(.development), entitlements = value["Entitlements"] as! [String: Any]
            entitlements.removeValue(forKey: key); value["Entitlements"] = entitlements
            XCTAssertThrowsError(try validate(value, .development))
        }
    }

    func testDeveloperIDModeCannotAcceptDevelopmentOrMixedEntitlements() throws {
        XCTAssertEqual(try validate(profile(.developerID), .developerID), "PREFIX1234.io.envara.app-routing")
        XCTAssertThrowsError(try validate(profile(.developerID), .development))
        var value = profile(.developerID), entitlements = value["Entitlements"] as! [String: Any]
        entitlements["com.apple.developer.networking.networkextension"] = ["app-proxy-provider", "app-proxy-provider-systemextension"]
        value["Entitlements"] = entitlements; XCTAssertThrowsError(try validate(value, .developerID))
        value = profile(.developerID); value.removeValue(forKey: "ProvisionsAllDevices")
        XCTAssertThrowsError(try validate(value, .developerID))
        value = profile(.developerID); value["ProvisionedDevices"] = [device]
        XCTAssertThrowsError(try validate(value, .developerID))
    }

    func testUntrustedPlistAndUnsignedCMSCannotAuthorizeProfiles() throws {
        let data = try PropertyListSerialization.data(fromPropertyList: profile(.development), format: .xml, options: 0)
        XCTAssertThrowsError(try RoutingSigningAuthorization.verifiedProfile(data))
        func der(_ tag: UInt8, _ value: Data) -> Data {
            var length = value.count, bytes: [UInt8] = []
            repeat { bytes.insert(UInt8(length & 255), at: 0); length >>= 8 } while length > 0
            let encodedLength: [UInt8] = value.count < 128 ? [UInt8(value.count)] : [0x80 | UInt8(bytes.count)] + bytes
            return Data([tag] + encodedLength) + value
        }
        // Valid SignedData encoding with zero signerInfos; no keychain identity
        // or private key is needed to verify this negative authorization case.
        let dataOID = Data([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01])
        let signedOID = Data([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02])
        let body = Data([0x02, 0x01, 0x01, 0x31, 0x00]) + der(0x30, dataOID + der(0xa0, der(0x04, data))) + Data([0x31, 0x00])
        let unsigned = der(0x30, signedOID + der(0xa0, der(0x30, body)))
        var decoder: CMSDecoder?
        XCTAssertEqual(CMSDecoderCreate(&decoder), errSecSuccess)
        let decoded = try XCTUnwrap(decoder)
        XCTAssertEqual(unsigned.withUnsafeBytes { CMSDecoderUpdateMessage(decoded, $0.baseAddress!, $0.count) }, errSecSuccess)
        XCTAssertEqual(CMSDecoderFinalizeMessage(decoded), errSecSuccess)
        var signers = 1
        XCTAssertEqual(CMSDecoderGetNumSigners(decoded, &signers), errSecSuccess); XCTAssertEqual(signers, 0)
        XCTAssertThrowsError(try RoutingSigningAuthorization.verifiedProfile(unsigned))
        XCTAssertThrowsError(try RoutingSigningAuthorization.verifiedProfile(Data()))
    }

    func testAbsentCertificateMarkersAreNotTreatedAsAuthorization() throws {
        let process = Process(), output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        process.arguments = ["find-certificate", "-c", "Apple Root CA", "-p", "/System/Library/Keychains/SystemRootCertificates.keychain"]
        process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run(); let pem = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        let text = try XCTUnwrap(String(data: pem, encoding: .utf8))
        let base64 = text.components(separatedBy: .newlines).filter { !$0.hasPrefix("-----") }.joined()
        let der = try XCTUnwrap(Data(base64Encoded: base64)), root = try XCTUnwrap(SecCertificateCreateWithData(nil, der as CFData))
        XCTAssertFalse(RoutingSigningAuthorization.certificateHasMarker(root, RoutingSigningMode.development.certificateMarker))
        XCTAssertFalse(RoutingSigningAuthorization.certificateHasMarker(root, RoutingSigningMode.developerID.certificateMarker))
        XCTAssertThrowsError(try RoutingSigningAuthorization.validateSigningCertificate(root, mode: .development))
    }
}
