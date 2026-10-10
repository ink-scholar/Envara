import Foundation

/// Validation is lexical; the helper separately verifies the signed bundle and
/// resolves symlinks before accepting an application. Never broaden a rule.
public enum RealmValidation {
    public static func canonicalUUID(_ value: String) -> String? {
        guard value.utf8.count == 36, value == value.trimmingCharacters(in: .whitespacesAndNewlines) else { return nil }
        return UUID(uuidString: value)?.uuidString
    }

    public static func executablePath(_ value: String) -> Bool {
        guard value.hasPrefix("/"), value != "/", !value.hasSuffix("/"),
              !value.contains("\0"), !value.contains("*"), !value.contains("?"),
              !value.contains("//") else { return false }
        let components = value.split(separator: "/", omittingEmptySubsequences: false)
        return !components.dropFirst().contains { $0.isEmpty || $0 == "." || $0 == ".." }
    }

    public static func applicationExecutablePath(_ value: String) -> Bool {
        executablePath(value) && value.contains(".app/Contents/MacOS/")
    }
}

public struct RealmRule: Equatable {
    public let signingIdentifier: String
    public let designatedRequirement: String
    public let executablePath: String?
    public let domains: [String]?
    public let toolsRestricted: Bool

    public init(signingIdentifier: String, designatedRequirement: String, executablePath: String?,
                domains: [String]? = nil, toolsRestricted: Bool = false) {
        self.signingIdentifier = signingIdentifier
        self.designatedRequirement = designatedRequirement
        self.executablePath = executablePath
        self.domains = domains
        self.toolsRestricted = toolsRestricted
    }
}

public struct RealmManagerBinding: Equatable {
    public let realmUUID: String?
    public let rules: [RealmRule]
    public init(realmUUID: String?, rules: [RealmRule]) {
        self.realmUUID = realmUUID
        self.rules = rules
    }
}

public enum RealmBindingSelection {
    public static let configurationKey = "envaraVPNRealmUUID"
    public static let versionKey = "envaraRealmVersion"

    /// Fail on an absent, broad, conflicting or ambiguous manager. A manager is
    /// identified by the profile's persistent realm marker AND its exact rule.
    public static func uniqueIndex(in managers: [RealmManagerBinding], vpnUUID: String,
                                   signingIdentifier: String, designatedRequirement: String,
                                   executablePath: String) throws -> Int {
        guard let uuid = RealmValidation.canonicalUUID(vpnUUID),
              !signingIdentifier.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !designatedRequirement.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              RealmValidation.applicationExecutablePath(executablePath) else { throw RoutingError.invalidRequest }
        let realmManagers = managers.indices.filter {
            managers[$0].realmUUID.flatMap(RealmValidation.canonicalUUID) == uuid
        }
        // Two managers claiming one realm is an error even if only one has the
        // expected rule. Selecting the first would conceal conflicting profiles.
        guard realmManagers.count == 1, let index = realmManagers.first,
              managers[index].rules.count == 1, let rule = managers[index].rules.first,
              rule.signingIdentifier == signingIdentifier,
              rule.designatedRequirement == designatedRequirement,
              rule.executablePath == executablePath, rule.domains == nil,
              !rule.toolsRestricted else { throw RoutingError.notReady("unique-exact-application-realm-required") }
        // A second, broader rule could steal this application's traffic before
        // the intended realm is reached. Refuse such a configuration.
        guard !managers.indices.contains(where: { other in
            other != index && managers[other].rules.contains(where: { candidate in
                candidate.signingIdentifier == signingIdentifier &&
                candidate.designatedRequirement == designatedRequirement &&
                pathScopesOverlap(candidate.executablePath, executablePath)
            })
        }) else { throw RoutingError.notReady("application-has-conflicting-realm-mappings") }
        return index
    }

    private static func pathScopesOverlap(_ candidate: String?, _ executable: String) -> Bool {
        guard let candidate = candidate else { return true }
        // Refuse broad directory scopes conservatively, including malformed
        // paths whose actual system matching semantics cannot be established.
        guard RealmValidation.executablePath(candidate) else { return true }
        return candidate == executable || executable.hasPrefix(candidate + "/")
    }
}

public enum RealmRebindValidation {
    public static func validate(routeRealm: String, configuredRealm: String, hasRoute: Bool,
                                activeFlows: Int, draining: Bool) throws {
        guard let selected = RealmValidation.canonicalUUID(routeRealm),
              let configured = RealmValidation.canonicalUUID(configuredRealm), selected == configured,
              !hasRoute, activeFlows == 0, !draining else {
            throw RoutingError.notReady("same-realm-provider-is-not-idle")
        }
    }
}
