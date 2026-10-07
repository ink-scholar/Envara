import CryptoKit
import Foundation
import Security

public enum RoutingSigningMode: String {
    case developerID = "developer-id"
    case development

    public var networkEntitlement: String {
        self == .development ? "app-proxy-provider" : "app-proxy-provider-systemextension"
    }
    public var certificateMarker: String {
        self == .development ? "1.2.840.113635.100.6.1.12" : "1.2.840.113635.100.6.1.13"
    }
}

public struct RoutingSigningProof {
    public let team: String
    public let applicationIdentifier: String
    public let profileSHA256: String
    public let certificateSHA256: String
    public let certificateSHA1: String

    public var dictionary: [String: Any] {
        ["teamIdentifier": team, "applicationIdentifier": applicationIdentifier,
         "profileSHA256": profileSHA256, "certificateSHA256": certificateSHA256,
         "certificateSHA1": certificateSHA1]
    }
}

/// Validation uses public Security APIs. Decoding a CMS payload alone is never
/// evidence of Apple authorization. No profile/device identifiers are logged.
public enum RoutingSigningAuthorization {
    public static let hostIdentifier = "io.envara.app-routing"
    public static let providerIdentifier = "io.envara.app-routing.proxy"
    private static let profileMarker = "1.2.840.113635.100.4.11"
    private static let wwdrMarker = "1.2.840.113635.100.6.2.1"

    private static func reject(_ reason: String) -> RoutingError { .notReady(reason) }

    private static func appleAnchors() throws -> [SecCertificate] {
        // Use the OS root keychain explicitly, not user-added trust anchors.
        var keychain: SecKeychain?
        guard SecKeychainOpen("/System/Library/Keychains/SystemRootCertificates.keychain", &keychain) == errSecSuccess,
              let keychain = keychain else { throw reject("apple-system-root-keychain-unavailable") }
        let query: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                  kSecMatchSearchList as String: [keychain],
                                  kSecMatchLimit as String: kSecMatchLimitAll,
                                  kSecReturnRef as String: true]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let certificates = result as? [SecCertificate] else { throw reject("apple-system-roots-unavailable") }
        let names: Set<String> = ["Apple Root CA", "Apple Root CA - G2", "Apple Root CA - G3"]
        let anchors = certificates.filter { names.contains((SecCertificateCopySubjectSummary($0) as String?) ?? "") }
        guard !anchors.isEmpty else { throw reject("apple-system-roots-unavailable") }
        return anchors
    }

    private static func evaluateAppleTrust(_ trust: SecTrust) throws {
        let anchors = try appleAnchors()
        guard SecTrustSetAnchorCertificates(trust, anchors as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil) else { throw reject("apple-certificate-trust-required") }
    }

    public static func certificateHasMarker(_ certificate: SecCertificate, _ oid: String) -> Bool {
        guard let values = SecCertificateCopyValues(certificate, [oid] as CFArray, nil) as? [String: Any],
              let property = values[oid] as? [String: Any], property[kSecPropertyKeyValue as String] != nil,
              property[kSecPropertyKeyType as String] as? String != kSecPropertyTypeError as String else { return false }
        return true
    }

    private static func propertyStrings(_ value: Any) -> [String] {
        if let string = value as? String { return [string] }
        if let array = value as? [Any] { return array.flatMap(propertyStrings) }
        if let dictionary = value as? [String: Any], let nested = dictionary[kSecPropertyKeyValue as String] {
            return propertyStrings(nested)
        }
        return []
    }

    public static func certificateTeam(_ certificate: SecCertificate) throws -> String {
        let oid = kSecOIDOrganizationalUnitName as String
        guard let values = SecCertificateCopyValues(certificate, [oid] as CFArray, nil) as? [String: Any],
              let value = values[oid] else { throw reject("signing-certificate-team-required") }
        let candidates = propertyStrings(value).filter { $0.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil }
        guard Set(candidates).count == 1, let team = candidates.first else { throw reject("signing-certificate-team-required") }
        return team
    }

    public static func validateSigningCertificate(_ certificate: SecCertificate, mode: RoutingSigningMode) throws -> String {
        guard certificateHasMarker(certificate, mode.certificateMarker) else { throw reject("signing-certificate-type-mismatch") }
        var trust: SecTrust?
        guard let policy = SecPolicyCreateWithProperties(kSecPolicyAppleCodeSigning, nil),
              SecTrustCreateWithCertificates(certificate, policy, &trust) == errSecSuccess,
              let trust = trust else { throw reject("signing-certificate-trust-unavailable") }
        try evaluateAppleTrust(trust)
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], chain.count >= 3,
              certificateHasMarker(chain[1], mode == .development ? wwdrMarker : "1.2.840.113635.100.6.2.6") else {
            throw reject("signing-certificate-issuer-required")
        }
        return try certificateTeam(certificate)
    }

    public static func signingIdentity(named name: String, mode: RoutingSigningMode) throws -> SecCertificate {
        let prefix = mode == .development ? "Apple Development:" : "Developer ID Application:"
        guard name.hasPrefix(prefix) else { throw reject("explicit-signing-identity-type-required") }
        var result: CFTypeRef?
        let query: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                  kSecMatchLimit as String: kSecMatchLimitAll,
                                  kSecReturnRef as String: true]
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let identities = result as? [SecIdentity] else { throw reject("signing-identity-unavailable") }
        let matches: [SecCertificate] = identities.compactMap { identity in
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate = certificate,
                  (SecCertificateCopySubjectSummary(certificate) as String?) == name else { return nil }
            return certificate
        }
        guard matches.count == 1, let certificate = matches.first else { throw reject("unique-signing-identity-required") }
        _ = try validateSigningCertificate(certificate, mode: mode)
        return certificate
    }

    public static func verifiedProfile(_ data: Data) throws -> [String: Any] {
        guard data.count > 0, data.count <= 2_000_000 else { throw reject("provisioning-profile-size-invalid") }
        var decoder: CMSDecoder?
        guard CMSDecoderCreate(&decoder) == errSecSuccess, let decoder = decoder,
              data.withUnsafeBytes({ buffer in
                  guard let base = buffer.baseAddress else { return errSecParam }
                  return CMSDecoderUpdateMessage(decoder, base, buffer.count)
              }) == errSecSuccess,
              CMSDecoderFinalizeMessage(decoder) == errSecSuccess else { throw reject("apple-signed-provisioning-profile-required") }
        var count = 0
        guard CMSDecoderGetNumSigners(decoder, &count) == errSecSuccess, count == 1 else { throw reject("unique-apple-profile-signer-required") }
        var signerStatus = CMSSignerStatus(rawValue: 0)!, trust: SecTrust?, certificate: SecCertificate?
        guard CMSDecoderCopySignerStatus(decoder, 0, SecPolicyCreateBasicX509(), false, &signerStatus, &trust, nil) == errSecSuccess,
              signerStatus == CMSSignerStatus(rawValue: 1), let trust = trust,
              CMSDecoderCopySignerCert(decoder, 0, &certificate) == errSecSuccess, let certificate = certificate,
              certificateHasMarker(certificate, profileMarker) else { throw reject("apple-profile-signature-required") }
        try evaluateAppleTrust(trust)
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], chain.count >= 3,
              SecCertificateCopyData(chain[0]) as Data == SecCertificateCopyData(certificate) as Data,
              certificateHasMarker(chain[1], wwdrMarker) else { throw reject("apple-profile-issuer-required") }
        guard let properties = SecCertificateCopyValues(certificate, [kSecOIDKeyUsage] as CFArray, nil) as? [String: Any],
              let usage = properties[kSecOIDKeyUsage as String] as? [String: Any],
              let mask = usage[kSecPropertyKeyValue as String] as? NSNumber,
              mask.intValue & Int(SecKeyUsage.digitalSignature.rawValue) != 0 else { throw reject("apple-profile-signing-usage-required") }
        var content: CFData?
        guard CMSDecoderCopyContent(decoder, &content) == errSecSuccess, let content = content,
              let profile = try PropertyListSerialization.propertyList(from: content as Data, format: nil) as? [String: Any] else {
            throw reject("provisioning-profile-content-invalid")
        }
        return profile
    }

    public static func deviceIdentifiers() throws -> Set<String> {
        // Apple silicon uses Provisioning UDID; older Macs use Hardware UUID.
        // Read only this section; neither value is returned in diagnostics.
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/system_profiler")
        process.arguments = ["SPHardwareDataType", "-json"]
        process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        try process.run()
        let bytes = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0,
              let value = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              let sections = value["SPHardwareDataType"] as? [[String: Any]] else { throw reject("development-device-identity-unavailable") }
        let values = sections.compactMap { section in
            (section["provisioning_UDID"] as? String) ?? (section["platform_UUID"] as? String)
        }
        guard !values.isEmpty else { throw reject("development-device-identity-unavailable") }
        return Set(values.map { $0.uppercased() })
    }

    /// Pure constraints are separately testable. Callers must first authenticate
    /// the CMS profile and signing certificate; this function alone grants nothing.
    public static func validateConstraints(_ profile: [String: Any], certificateData: Data, team: String,
                                           bundleIdentifier: String, host: Bool, mode: RoutingSigningMode,
                                           devices: Set<String>, now: Date = Date()) throws -> String {
        guard let expiration = profile["ExpirationDate"] as? Date, expiration > now,
              let creation = profile["CreationDate"] as? Date, creation <= now,
              let platforms = profile["Platform"] as? [String], platforms.contains(where: { $0 == "OSX" || $0 == "macOS" }),
              let teams = profile["TeamIdentifier"] as? [String], teams == [team],
              let certificates = profile["DeveloperCertificates"] as? [Data], certificates.contains(certificateData),
              let entitlements = profile["Entitlements"] as? [String: Any],
              entitlements["com.apple.developer.team-identifier"] as? String == team,
              let application = entitlements["com.apple.application-identifier"] as? String,
              let prefixes = profile["ApplicationIdentifierPrefix"] as? [String],
              prefixes.contains(where: { application == $0 + "." + bundleIdentifier }),
              let network = entitlements["com.apple.developer.networking.networkextension"] as? [String],
              network.contains(mode.networkEntitlement),
              !network.contains(mode == .development ? RoutingSigningMode.developerID.networkEntitlement : RoutingSigningMode.development.networkEntitlement),
              (entitlements["com.apple.security.application-groups"] as? [String])?.contains(RuntimeStore.groupIdentifier) == true else {
            throw reject("provisioning-profile-authorization-mismatch")
        }
        if host && entitlements["com.apple.developer.system-extension.install"] as? Bool != true {
            throw reject("system-extension-install-authorization-required")
        }
        if mode == .development {
            guard profile["ProvisionsAllDevices"] as? Bool != true,
                  let allowed = profile["ProvisionedDevices"] as? [String],
                  !devices.isDisjoint(with: Set(allowed.map { $0.uppercased() })),
                  entitlements["com.apple.security.get-task-allow"] as? Bool == true else { throw reject("local-development-profile-required") }
        } else {
            guard profile["ProvisionsAllDevices"] as? Bool == true,
                  profile["ProvisionedDevices"] == nil,
                  entitlements["com.apple.security.get-task-allow"] as? Bool != true else { throw reject("developer-id-profile-required") }
        }
        return application
    }

    public static func validateProfile(_ data: Data, certificate: SecCertificate, bundleIdentifier: String,
                                       host: Bool, mode: RoutingSigningMode, devices: Set<String>) throws -> RoutingSigningProof {
        let team = try validateSigningCertificate(certificate, mode: mode)
        let certificateData = SecCertificateCopyData(certificate) as Data
        let profile = try verifiedProfile(data)
        let application = try validateConstraints(profile, certificateData: certificateData, team: team,
                                                 bundleIdentifier: bundleIdentifier, host: host, mode: mode, devices: devices)
        return RoutingSigningProof(team: team, applicationIdentifier: application,
                                   profileSHA256: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(),
                                   certificateSHA256: SHA256.hash(data: certificateData).map { String(format: "%02x", $0) }.joined(),
                                   certificateSHA1: Insecure.SHA1.hash(data: certificateData).map { String(format: "%02X", $0) }.joined())
    }

    public static func validateBundle(_ bundle: URL, expectedIdentifier: String, host: Bool,
                                      mode: RoutingSigningMode, devices: Set<String>) throws -> RoutingSigningProof {
        var code: SecStaticCode?, requirement: SecRequirement?, information: CFDictionary?
        let expression = "anchor apple generic and identifier \"\(expectedIdentifier)\" and certificate leaf[field.\(mode.certificateMarker)] exists"
        guard SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess,
              let requirement = requirement,
              SecStaticCodeCreateWithPath(bundle as CFURL, [], &code) == errSecSuccess, let code = code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), requirement) == errSecSuccess,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any], let team = info[kSecCodeInfoTeamIdentifier as String] as? String,
              let certificates = info[kSecCodeInfoCertificates as String] as? [SecCertificate], let certificate = certificates.first,
              let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              (entitlements["com.apple.developer.networking.networkextension"] as? [String])?.contains(mode.networkEntitlement) == true,
              (entitlements["com.apple.security.application-groups"] as? [String])?.contains(RuntimeStore.groupIdentifier) == true,
              !host || entitlements["com.apple.developer.system-extension.install"] as? Bool == true,
              let profile = try? Data(contentsOf: bundle.appendingPathComponent("Contents/embedded.provisionprofile")) else {
            throw reject("apple-signed-network-extension-authorization-required")
        }
        let proof = try validateProfile(profile, certificate: certificate, bundleIdentifier: expectedIdentifier, host: host, mode: mode, devices: devices)
        guard team == proof.team, entitlements["com.apple.developer.team-identifier"] as? String == team,
              entitlements["com.apple.application-identifier"] as? String == proof.applicationIdentifier else {
            throw reject("signed-profile-identity-mismatch")
        }
        return proof
    }
}
