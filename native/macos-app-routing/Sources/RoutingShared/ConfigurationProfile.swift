import Foundation

public struct RealmMapping: Codable, Equatable {
    public let applicationIdentifier: String
    public let signingIdentifier: String
    public let designatedRequirement: String
    public let executablePath: String
    public let vpnUUID: String

    public init(applicationIdentifier: String, signingIdentifier: String, designatedRequirement: String,
                executablePath: String, vpnUUID: String = UUID().uuidString) {
        self.applicationIdentifier = applicationIdentifier
        self.signingIdentifier = signingIdentifier
        self.designatedRequirement = designatedRequirement
        self.executablePath = executablePath
        self.vpnUUID = vpnUUID
    }
}

public enum ConfigurationProfile {
    public static func make(applicationIdentifier: String, signingIdentifier: String, designatedRequirement: String,
                            executablePath: String, providerRequirement: String, vpnUUID: String = UUID().uuidString, namespace: RoutingRuntimeNamespace = .production) throws -> Data {
        try make(applications: [RealmMapping(applicationIdentifier: applicationIdentifier, signingIdentifier: signingIdentifier,
                                            designatedRequirement: designatedRequirement, executablePath: executablePath,
                                            vpnUUID: vpnUUID)], providerRequirement: providerRequirement, namespace: namespace)
    }

    public static func make(applications: [RealmMapping], providerRequirement: String, namespace: RoutingRuntimeNamespace = .production) throws -> Data {
        func hasValue(_ value: String) -> Bool { !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        guard !applications.isEmpty, hasValue(providerRequirement) else {
            throw RoutingError.invalidRequest
        }

        var paths = Set<String>()
        var vpnUUIDs = Set<String>()
        let realms = try applications.map { application -> RealmMapping in
            guard hasValue(application.applicationIdentifier), hasValue(application.signingIdentifier),
                  hasValue(application.designatedRequirement), RealmValidation.applicationExecutablePath(application.executablePath),
                  let vpnUUID = RealmValidation.canonicalUUID(application.vpnUUID),
                  paths.insert(application.executablePath).inserted, vpnUUIDs.insert(vpnUUID).inserted else {
                throw RoutingError.invalidRequest
            }
            // A shared bundle/signing identity at a different complete executable path
            // is a distinct realm. Only a repeated path or VPN UUID conflicts here.
            return RealmMapping(applicationIdentifier: application.applicationIdentifier, signingIdentifier: application.signingIdentifier,
                                designatedRequirement: application.designatedRequirement, executablePath: application.executablePath,
                                vpnUUID: vpnUUID)
        }

        func payload(_ type: String, identifier: String, uuid: String = UUID().uuidString) -> [String: Any] {
            ["PayloadType": type, "PayloadVersion": 1, "PayloadUUID": uuid,
             "PayloadIdentifier": identifier, "PayloadDisplayName": "Envara"]
        }
        let vpns = realms.map { realm -> [String: Any] in
            var vpn = payload("com.apple.vpn.managed.applayer", identifier: "\(RoutingSigningAuthorization.hostIdentifier).vpn.\(realm.vpnUUID)", uuid: realm.vpnUUID)
            vpn["VPNType"] = "VPN"; vpn["VPNSubType"] = RoutingSigningAuthorization.hostIdentifier
            vpn["UserDefinedName"] = "Envara · \(realm.applicationIdentifier)"
            vpn["VPNUUID"] = realm.vpnUUID; vpn["OnDemandMatchAppEnabled"] = true
            vpn["VendorConfig"] = ["envaraVPNRealmUUID": realm.vpnUUID, "envaraRealmVersion": 1, RoutingRuntimeNamespace.configurationKey: namespace.rawValue]
            vpn["VPN"] = ["RemoteAddress": "127.0.0.1", "ProviderType": "app-proxy",
                          "ProviderBundleIdentifier": RoutingSigningAuthorization.providerIdentifier,
                          "ProviderDesignatedRequirement": providerRequirement,
                          "OnDemandEnabled": 1, "DisconnectOnIdle": 0]
            return vpn
        }
        // No disconnect/bypass rules, global routes, system proxy, or credentials.
        var mapping = payload("com.apple.vpn.managed.appmapping", identifier: namespace.mappingIdentifier, uuid: namespace.mappingUUID)
        mapping["AppLayerVPNMapping"] = realms.map { realm in
            ["Identifier": realm.applicationIdentifier, "VPNUUID": realm.vpnUUID,
             "SigningIdentifier": realm.signingIdentifier, "DesignatedRequirement": realm.designatedRequirement,
             "Path": realm.executablePath]
        }
        // Omitting MatchTools includes the selected app and spawned helper tools.
        // Apple specifies one appmapping payload containing an array of mappings:
        // https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/profiles/com.apple.vpn.managed.appmapping.yaml
        // This serialized structure does not establish native multi-VPNUUID or
        // cached-flow isolation; those remain separate macOS acceptance gates.
        var profile = payload("Configuration", identifier: namespace.profileIdentifier, uuid: namespace.configurationUUID)
        profile["PayloadContent"] = vpns + [mapping]
        return try PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0)
    }
}
