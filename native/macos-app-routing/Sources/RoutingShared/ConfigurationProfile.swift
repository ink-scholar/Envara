import Foundation

public enum ConfigurationProfile {
    public static func make(applicationIdentifier: String, signingIdentifier: String, designatedRequirement: String,
                            executablePath: String, providerRequirement: String, vpnUUID: String = UUID().uuidString) throws -> Data {
        guard !applicationIdentifier.isEmpty, !signingIdentifier.isEmpty, !designatedRequirement.isEmpty,
              executablePath.hasPrefix("/"), !providerRequirement.isEmpty, UUID(uuidString: vpnUUID) != nil else {
            throw RoutingError.invalidRequest
        }
        func payload(_ type: String, suffix: String) -> [String: Any] {
            ["PayloadType": type, "PayloadVersion": 1, "PayloadUUID": UUID().uuidString,
             "PayloadIdentifier": "io.envara.app-routing.\(suffix).\(vpnUUID)", "PayloadDisplayName": "Envara"]
        }
        var vpn = payload("com.apple.vpn.managed.applayer", suffix: "vpn")
        vpn["VPNType"] = "VPN"; vpn["VPNSubType"] = "io.envara.app-routing"
        vpn["UserDefinedName"] = "Envara · \(applicationIdentifier)"
        vpn["VPNUUID"] = vpnUUID; vpn["OnDemandMatchAppEnabled"] = true
        vpn["VPN"] = ["RemoteAddress": "127.0.0.1", "ProviderType": "app-proxy",
                      "ProviderBundleIdentifier": "io.envara.app-routing.proxy",
                      "ProviderDesignatedRequirement": providerRequirement,
                      "OnDemandEnabled": 1, "DisconnectOnIdle": 0]
        // No disconnect/bypass rules, global routes, system proxy, or credentials.
        var mapping = payload("com.apple.vpn.managed.appmapping", suffix: "mapping")
        mapping["AppLayerVPNMapping"] = [["Identifier": applicationIdentifier, "VPNUUID": vpnUUID,
                                         "SigningIdentifier": signingIdentifier, "DesignatedRequirement": designatedRequirement,
                                         "Path": executablePath]]
        // Omitting MatchTools includes the selected app and spawned helper tools.
        var profile = payload("Configuration", suffix: "configuration")
        profile["PayloadContent"] = [vpn, mapping]
        return try PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0)
    }
}
