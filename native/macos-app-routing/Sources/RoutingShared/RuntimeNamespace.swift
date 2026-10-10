import Foundation

/// These fixed namespaces share the same signed provider while keeping owned
/// diagnostic routes and journals separate from application routes.
public enum RoutingRuntimeNamespace: String, Codable {
    case production
    case fixtureAcceptance = "owned-fixture-acceptance"

    public static let configurationKey = "envaraRuntimeNamespace"
    public var directoryName: String { self == .production ? "EnvaraRouting" : "EnvaraFixtureAcceptance" }
    public var configurationUUID: String { self == .production ? "972BB8F6-0CA1-4CD7-AF55-6062F6E37DFE" : "B3664E94-7C11-4FC4-8BE7-02197655DA6E" }
    public var mappingUUID: String { self == .production ? "FC107DD7-5089-4C33-913E-A645C047EA71" : "F30501AB-ED8B-4873-854E-D518F3C0B7B3" }
    public var profileIdentifier: String { self == .production ? "io.envara.app-routing.configuration" : "\(RoutingSigningAuthorization.hostIdentifier).\(rawValue).configuration" }
    public var mappingIdentifier: String { self == .production ? "io.envara.app-routing.mapping" : "\(RoutingSigningAuthorization.hostIdentifier).\(rawValue).mapping" }
}
