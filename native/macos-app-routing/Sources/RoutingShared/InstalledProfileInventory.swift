import Foundation

/// Inspects an already parsed `profiles show ... -output stdout-xml` plist.
/// This is a scoped, read-only conflict check, never evidence of installation,
/// system-wide inventory coverage, or native routing acceptance.
public enum InstalledProfileInventory {
    public struct Summary: Equatable {
        public let ownedProfileFound: Bool
        public let mappingPayloadCount: Int
        public let installedMappingCount: Int
        public let globalVerified = false
    }

    private static let mappingType = "com.apple.vpn.managed.appmapping"
    private static let maximumNodes = 16_384
    private static let maximumBytes = 2_097_152
    private static let maximumDepth = 32

    public static func validate(parsed: Any, ownedMappings: [RealmMapping],
                                ownerProfileIdentifier: String = RoutingRuntimeNamespace.production.profileIdentifier,
                                mappingPayloadIdentifier: String = RoutingRuntimeNamespace.production.mappingIdentifier) throws -> Summary {
        func reject(_ reason: String) -> RoutingError { .notReady(reason) }
        func text(_ value: Any?) -> String? {
            guard let string = value as? String, !string.isEmpty,
                  string == string.trimmingCharacters(in: .whitespacesAndNewlines) else { return nil }
            return string
        }
        guard text(ownerProfileIdentifier) != nil, text(mappingPayloadIdentifier) != nil,
              parsed is [String: Any] || parsed is [Any] else { throw RoutingError.invalidRequest }
        if !ownedMappings.isEmpty {
            _ = try ConfigurationProfile.make(applications: ownedMappings,
                                               providerRequirement: "inventory-validation")
        }
        let expected = Dictionary(uniqueKeysWithValues: ownedMappings.map { ($0.executablePath, $0) })
        var nodes = 0, bytes = 0, ownedProfiles = 0, payloads = 0, installedCount = 0
        var installedPaths = Set<String>(), installedRealms = Set<String>()

        func budget(_ count: Int) throws {
            guard count >= 0, count <= maximumBytes - bytes else { throw reject("installed-profile-inventory-too-large") }
            bytes += count
        }
        func walk(_ value: Any, owner: String?, depth: Int) throws {
            nodes += 1
            guard nodes <= maximumNodes, depth <= maximumDepth else { throw reject("installed-profile-inventory-too-large") }
            if let dictionary = value as? [String: Any] {
                var localOwner = owner
                if dictionary["PayloadType"] != nil && text(dictionary["PayloadType"]) == nil {
                    throw reject("installed-profile-inventory-malformed")
                }
                let type = dictionary["PayloadType"] as? String
                var declaredOwner: String?
                if type == "Configuration" {
                    guard let identifier = text(dictionary["PayloadIdentifier"]),
                          dictionary["PayloadContent"] is [Any] || dictionary["PayloadContent"] is [String: Any] else {
                        throw reject("installed-profile-inventory-malformed")
                    }
                    declaredOwner = identifier
                }
                // The official tool wraps a profile using ProfileIdentifier and
                // ProfileItems/ProfileContent instead of exposing Configuration.
                if dictionary["ProfileIdentifier"] != nil {
                    guard let identifier = text(dictionary["ProfileIdentifier"]),
                          dictionary["ProfileItems"] is [Any] || dictionary["ProfileItems"] is [String: Any] ||
                          dictionary["ProfileContent"] is [Any] || dictionary["ProfileContent"] is [String: Any],
                          declaredOwner == nil || declaredOwner == identifier else {
                        throw reject("installed-profile-inventory-malformed")
                    }
                    declaredOwner = identifier
                }
                if let identifier = declaredOwner {
                    guard owner == nil || owner == identifier else { throw reject("installed-profile-inventory-ambiguous-owner") }
                    if owner == nil && identifier == ownerProfileIdentifier {
                        ownedProfiles += 1
                        guard ownedProfiles == 1 else { throw reject("installed-profile-inventory-duplicate-owner") }
                    }
                    localOwner = identifier
                }
                if dictionary["AppLayerVPNMapping"] != nil && type != mappingType {
                    throw reject("installed-profile-inventory-malformed")
                }
                if type == mappingType {
                    payloads += 1
                    guard payloads == 1 else { throw reject("installed-appmapping-singleton-conflict") }
                    guard localOwner == ownerProfileIdentifier,
                          text(dictionary["PayloadIdentifier"]) == mappingPayloadIdentifier else {
                        throw reject("installed-appmapping-foreign-or-unknown-owner")
                    }
                    guard let mappings = dictionary["AppLayerVPNMapping"] as? [[String: Any]], !mappings.isEmpty else {
                        throw reject("installed-profile-inventory-malformed")
                    }
                    let allowedKeys: Set<String> = ["Identifier", "VPNUUID", "SigningIdentifier", "DesignatedRequirement", "Path"]
                    for mapping in mappings {
                        guard Set(mapping.keys) == allowedKeys,
                              let path = text(mapping["Path"]), let known = expected[path],
                              text(mapping["Identifier"]) == known.applicationIdentifier,
                              text(mapping["SigningIdentifier"]) == known.signingIdentifier,
                              text(mapping["DesignatedRequirement"]) == known.designatedRequirement,
                              let realm = text(mapping["VPNUUID"]).flatMap(RealmValidation.canonicalUUID),
                              realm == RealmValidation.canonicalUUID(known.vpnUUID),
                              installedPaths.insert(path).inserted, installedRealms.insert(realm).inserted else {
                            throw reject("installed-appmapping-unknown-or-conflicting-entry")
                        }
                        installedCount += 1
                    }
                }
                for (key, child) in dictionary {
                    try budget(key.utf8.count)
                    if key != "PayloadType", child as? String == mappingType {
                        throw reject("installed-profile-inventory-malformed")
                    }
                    try walk(child, owner: localOwner, depth: depth + 1)
                }
            } else if let array = value as? [Any] {
                for child in array { try walk(child, owner: owner, depth: depth + 1) }
            } else if let string = value as? String { try budget(string.utf8.count) }
            else if let data = value as? Data { try budget(data.count) }
            else if value is Date || value is NSNumber { try budget(16) }
            else { throw reject("installed-profile-inventory-malformed") }
        }
        try walk(parsed, owner: nil, depth: 0)
        guard ownedProfiles == 0 || payloads == 1 else { throw reject("installed-profile-owner-without-appmapping") }
        return Summary(ownedProfileFound: ownedProfiles == 1, mappingPayloadCount: payloads,
                       installedMappingCount: installedCount)
    }
}
