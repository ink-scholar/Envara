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
    public let routeId: String
    public let applicationIdentity: String
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

    public init(routeId: String, applicationIdentity: String, applicationPath: String, executablePath: String,
                protocolName: String, host: String, port: UInt16, username: String, password: String, udp: Bool, privacyMode: String = "standard") throws {
        guard UUID(uuidString: routeId) != nil, !applicationIdentity.isEmpty,
              applicationPath.hasPrefix("/"), executablePath.hasPrefix("/"),
              ["socks5", "socks"].contains(protocolName.lowercased()),
              ["127.0.0.1", "::1"].contains(host), port > 0,
              !username.isEmpty, !password.isEmpty,
              username.utf8.count <= 255, password.utf8.count <= 255,
              ["off", "standard", "strict"].contains(privacyMode) else { throw RoutingError.invalidRoute }
        self.routeId = routeId
        self.applicationIdentity = applicationIdentity
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
        _ = try Route(routeId: routeId, applicationIdentity: applicationIdentity, applicationPath: applicationPath,
                      executablePath: executablePath, protocolName: protocolName, host: host, port: port,
                      username: username, password: password, udp: udp, privacyMode: privacyMode)
    }
}

public struct RuntimeStore {
    public static let groupIdentifier = "group.io.envara.app-routing"
    public let directory: URL

    public init(directory: URL) throws {
        self.directory = directory.appendingPathComponent("EnvaraRouting", isDirectory: true)
        try FileManager.default.createDirectory(at: self.directory, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        var info = stat()
        guard lstat(self.directory.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == getuid() || getuid() == 0 else { throw RoutingError.unsafeFile }
        guard chmod(self.directory.path, 0o700) == 0 else { throw RoutingError.unsafeFile }
    }

    public func url(_ id: String, suffix: String = "json") throws -> URL {
        guard UUID(uuidString: id) != nil, ["json", "session"].contains(suffix) else { throw RoutingError.invalidRequest }
        return directory.appendingPathComponent("\(id).\(suffix)")
    }

    public func write(_ route: Route) throws {
        try route.validate()
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
              (info.st_mode & 0o777) == 0o600, info.st_uid == getuid() || getuid() == 0,
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
        return route
    }

    public func revoke(_ id: String) throws { try FileManager.default.removeItem(at: url(id)) }
}
