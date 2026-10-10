import Foundation
import Darwin

public enum RoutingError: Error, LocalizedError {
    case invalidRequest, invalidRoute, unsafeFile, unsupportedUDP, invalidSOCKS, refused, notReady(String)
    public var errorDescription: String? {
        switch self {
        case .notReady(let reason): return reason
        case .invalidRequest: return "Invalid routing request"
        case .invalidRoute: return "A protected authenticated loopback SOCKS5 route is required"
        case .unsafeFile: return "Runtime route file is not private"
        case .unsupportedUDP: return "The selected route does not support UDP"
        case .invalidSOCKS: return "Invalid SOCKS5 response"
        case .refused: return "The selected route refused the connection"
        }
    }
}

public struct Route: Codable, Equatable {
    public let runtimeNamespace: RoutingRuntimeNamespace
    public let routeId: String
    public let vpnUUID: String
    public let applicationIdentity: String
    public let applicationRequirement: String
    public let applicationPath: String
    public let executablePath: String
    public let protocolName: String
    public let host: String
    public let port: UInt16
    public let username: String
    public let password: String
    public let udp: Bool
    public let privacyMode: String
    public let createdAt: Date

    public init(routeId: String, vpnUUID: String, applicationIdentity: String, applicationRequirement: String,
                applicationPath: String, executablePath: String,
                protocolName: String, host: String, port: UInt16, username: String, password: String, udp: Bool, privacyMode: String = "standard", runtimeNamespace: RoutingRuntimeNamespace = .production) throws {
        guard let canonicalRoute = RealmValidation.canonicalUUID(routeId),
              let canonicalRealm = RealmValidation.canonicalUUID(vpnUUID),
              !applicationIdentity.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !applicationRequirement.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              RealmValidation.executablePath(applicationPath),
              applicationPath.hasSuffix(".app"), RealmValidation.applicationExecutablePath(executablePath),
              executablePath.hasPrefix(applicationPath + "/Contents/MacOS/"),
              ["socks5", "socks"].contains(protocolName.lowercased()),
              ["127.0.0.1", "::1"].contains(host), port > 0,
              !username.isEmpty, !password.isEmpty,
              username.utf8.count <= 255, password.utf8.count <= 255,
              ["off", "standard", "strict"].contains(privacyMode) else { throw RoutingError.invalidRoute }
        self.runtimeNamespace = runtimeNamespace
        self.routeId = canonicalRoute
        self.vpnUUID = canonicalRealm
        self.applicationIdentity = applicationIdentity
        self.applicationRequirement = applicationRequirement
        self.applicationPath = applicationPath
        self.executablePath = executablePath
        self.protocolName = "socks5"
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.udp = udp
        self.privacyMode = privacyMode
        self.createdAt = Date()
    }

    public func validate() throws {
        _ = try Route(routeId: routeId, vpnUUID: vpnUUID, applicationIdentity: applicationIdentity,
                      applicationRequirement: applicationRequirement, applicationPath: applicationPath,
                      executablePath: executablePath, protocolName: protocolName, host: host, port: port,
                      username: username, password: password, udp: udp, privacyMode: privacyMode, runtimeNamespace: runtimeNamespace)
    }
}

public struct RuntimeStore {
    public static let groupIdentifier = "group.io.envara.app-routing"
    public let directory: URL
    public let namespace: RoutingRuntimeNamespace
    public let ownerUID: uid_t

    public init(directory: URL, create: Bool = true, namespace: RoutingRuntimeNamespace = .production) throws {
        self.namespace = namespace
        self.directory = directory.appendingPathComponent(namespace.directoryName, isDirectory: true)
        if create {
            try FileManager.default.createDirectory(at: self.directory, withIntermediateDirectories: true,
                                                   attributes: [.posixPermissions: 0o700])
        }
        var info = stat()
        guard lstat(self.directory.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == getuid() || getuid() == 0 else { throw RoutingError.unsafeFile }
        self.ownerUID = info.st_uid
        if create { guard chmod(self.directory.path, 0o700) == 0 else { throw RoutingError.unsafeFile } }
        else { guard info.st_mode & 0o777 == 0o700 else { throw RoutingError.unsafeFile } }
    }

    public func url(_ id: String, suffix: String = "json") throws -> URL {
        guard let canonical = RealmValidation.canonicalUUID(id), ["json", "session", "lease"].contains(suffix) else { throw RoutingError.invalidRequest }
        return directory.appendingPathComponent("\(canonical).\(suffix)")
    }

    public func write(_ route: Route) throws {
        try route.validate()
        guard route.runtimeNamespace == namespace else { throw RoutingError.invalidRoute }
        try writePrivate(JSONEncoder().encode(route), to: url(route.routeId))
    }

    public func writePrivate(_ data: Data, to url: URL) throws {
        guard url.deletingLastPathComponent().standardizedFileURL == directory.standardizedFileURL else {
            throw RoutingError.unsafeFile
        }
        let temporary = directory.appendingPathComponent(".\(UUID().uuidString).tmp")
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw RoutingError.unsafeFile }
        defer { close(descriptor); try? FileManager.default.removeItem(at: temporary) }
        var offset = 0
        try data.withUnsafeBytes { bytes in
            while offset < bytes.count {
                let count = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard count > 0 else { throw RoutingError.unsafeFile }
                offset += count
            }
        }
        guard fsync(descriptor) == 0, rename(temporary.path, url.path) == 0 else { throw RoutingError.unsafeFile }
    }

    public func readPrivate(_ url: URL) throws -> Data {
        guard url.deletingLastPathComponent().standardizedFileURL == directory.standardizedFileURL else {
            throw RoutingError.unsafeFile
        }
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW)
        guard descriptor >= 0 else { throw RoutingError.unsafeFile }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              (info.st_mode & 0o777) == 0o600, info.st_uid == ownerUID,
              info.st_size <= 1_048_576 else { throw RoutingError.unsafeFile }
        var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes { buffer in
                Darwin.read(descriptor, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
            }
            guard count > 0 else { throw RoutingError.unsafeFile }
            offset += count
        }
        return Data(bytes)
    }

    public func read(_ id: String) throws -> Route {
        let route = try JSONDecoder().decode(Route.self, from: readPrivate(url(id)))
        try route.validate()
        guard route.runtimeNamespace == namespace, RealmValidation.canonicalUUID(route.routeId) == RealmValidation.canonicalUUID(id) else {
            throw RoutingError.invalidRoute
        }
        return route
    }

    /// This is an owned profile-generation manifest, not proof of installation.
    /// Legacy route records lacking vpnUUID or the code requirement are rejected
    /// by Codable; guessing a realm could redirect another application's route.
    public func realmMappings() throws -> [RealmMapping] {
        let file = directory.appendingPathComponent("owned-realms.json")
        var info = stat()
        if lstat(file.path, &info) != 0 {
            guard errno == ENOENT else { throw RoutingError.unsafeFile }
            return []
        }
        let mappings = try JSONDecoder().decode([RealmMapping].self, from: readPrivate(file))
        if !mappings.isEmpty { _ = try ConfigurationProfile.make(applications: mappings, providerRequirement: "manifest-validation", namespace: namespace) }
        return mappings
    }

    public func writeRealmMappings(_ mappings: [RealmMapping]) throws {
        _ = try ConfigurationProfile.make(applications: mappings, providerRequirement: "manifest-validation", namespace: namespace)
        try writePrivate(JSONEncoder().encode(mappings), to: directory.appendingPathComponent("owned-realms.json"))
    }

    public func revoke(_ id: String) throws { try FileManager.default.removeItem(at: url(id)) }
}
