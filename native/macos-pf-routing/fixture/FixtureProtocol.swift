// PF-only fork of the existing sealed fixture; the NE fixture is unchanged.
import Foundation
import CoreFoundation
import Darwin

/// A deliberately limited probe protocol, never a general application launcher.
enum FixtureProtocol {
    static let version = 1
    static let identity = "envara-routing-acceptance-fixture"
    static let executableName = "EnvaraRoutingAcceptanceFixture"
    static let bundleIdentifiers: Set<String> = ["io.envara.routing.fixture.one", "io.envara.routing.fixture.two"]
    static let maximumLineBytes = 8192
    static let maximumPayloadBytes = 4096
    static let lifetimeSeconds: TimeInterval = 120
    static let idleSeconds: TimeInterval = 30
    static let reservationSeconds: TimeInterval = 60
    static let maximumReservations = 16
    static let reservationProtocol = "envara-pf-socket-reservation/v1"
}

enum FixtureFailure: Error, Equatable {
    case invalidRequest, forbiddenEndpoint, deadline, transport, tooLarge, childUnavailable, childLimit, cleanupUnverified, reservationRequired, reservationUnavailable, reservationLimit
    var code: String {
        switch self {
        case .invalidRequest: return "INVALID_REQUEST"
        case .forbiddenEndpoint: return "FORBIDDEN_ENDPOINT"
        case .deadline: return "PROBE_TIMEOUT"
        case .transport: return "PROBE_TRANSPORT_FAILED"
        case .tooLarge: return "PROBE_SIZE_LIMIT"
        case .childUnavailable: return "CHILD_UNAVAILABLE"
        case .childLimit: return "CHILD_LIMIT"
        case .cleanupUnverified: return "CLEANUP_UNVERIFIED"
        case .reservationRequired: return "RESERVATION_REQUIRED"
        case .reservationUnavailable: return "RESERVATION_UNAVAILABLE"
        case .reservationLimit: return "RESERVATION_LIMIT"
        }
    }
}

struct FixtureProbeRequest {
    let op: String
    private(set) var host: String?
    private(set) var port: UInt16?
    private(set) var transport: String?
    private(set) var reservationID: String?
    let payload: Data
    let halfClose: Bool
    let timeoutMs: Int

    init(_ object: [String: Any]) throws {
        let known: Set<String> = ["id", "op", "host", "port", "protocol", "reservationId", "payloadBase64", "halfClose", "timeoutMs"]
        guard Set(object.keys).isSubset(of: known), let op = object["op"] as? String,
              ["status", "resolve", "tcp", "udp", "reserve", "probe_reserved", "release_reservation"].contains(op) else { throw FixtureFailure.invalidRequest }
        self.op = op
        let timeout = try Self.integer(object["timeoutMs"], default: 3000)
        guard (200...5000).contains(timeout) else { throw FixtureFailure.invalidRequest }
        timeoutMs = timeout
        if let value = object["halfClose"] {
            guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { throw FixtureFailure.invalidRequest }
        }
        halfClose = object["halfClose"] as? Bool ?? false
        if let value = object["payloadBase64"] {
            guard let encoded = value as? String, encoded.utf8.count <= 5464,
                  let decoded = Data(base64Encoded: encoded), (1...FixtureProtocol.maximumPayloadBytes).contains(decoded.count) else { throw FixtureFailure.invalidRequest }
            payload = decoded
        } else { payload = Data("envara-routing-fixture-v1".utf8) }
        host = nil; port = nil; transport = nil; reservationID = nil
        switch op {
        case "status":
            guard object.keys.allSatisfy({ ["id", "op", "timeoutMs"].contains($0) }) else { throw FixtureFailure.invalidRequest }
        case "resolve":
            guard object.keys.allSatisfy({ ["id", "op", "host", "timeoutMs"].contains($0) }),
                  let name = object["host"] as? String, Self.isSyntheticHostname(name) else { throw FixtureFailure.forbiddenEndpoint }
            self.host = name
        case "reserve":
            guard object.keys.allSatisfy({ ["id", "op", "host", "port", "protocol", "timeoutMs"].contains($0) }),
                  let address = object["host"] as? String, let proto = object["protocol"] as? String,
                  ["tcp", "udp"].contains(proto) else { throw FixtureFailure.invalidRequest }
            let value = try Self.integer(object["port"])
            guard Self.isReservedEndpoint(address, port: value) else { throw FixtureFailure.forbiddenEndpoint }
            self.host = address; self.port = UInt16(value); self.transport = proto
        case "probe_reserved", "release_reservation":
            let keys = op == "probe_reserved" ? ["id", "op", "reservationId", "payloadBase64", "halfClose", "timeoutMs"] : ["id", "op", "reservationId", "timeoutMs"]
            guard object.keys.allSatisfy({ keys.contains($0) }), let token = object["reservationId"] as? String,
                  let uuid = UUID(uuidString: token), uuid.uuidString.lowercased() == token.lowercased() else { throw FixtureFailure.invalidRequest }
            self.reservationID = uuid.uuidString.lowercased()
        default:
            // Preserve parsing of the old operations only to return an explicit
            // refusal. They must never create or connect a replacement socket.
            guard let address = object["host"] as? String, Self.isProbeAddress(address) else { throw FixtureFailure.forbiddenEndpoint }
            let value = try Self.integer(object["port"])
            guard (1024...65535).contains(value), op == "tcp" || !halfClose else { throw FixtureFailure.invalidRequest }
            self.host = address; self.port = UInt16(value); self.transport = op
        }
    }

    static func integer(_ value: Any?, default fallback: Int? = nil) throws -> Int {
        guard let value = value else { if let fallback = fallback { return fallback }; throw FixtureFailure.invalidRequest }
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue.isFinite,
              number.doubleValue.rounded() == number.doubleValue,
              number.doubleValue >= Double(Int32.min), number.doubleValue <= Double(Int32.max) else { throw FixtureFailure.invalidRequest }
        return number.intValue
    }

    static func isSyntheticHostname(_ name: String) -> Bool {
        if name == "localhost" { return true }
        guard name.utf8.count <= 253, name == name.lowercased(), name.hasSuffix(".envara-fixture.test") else { return false }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        return labels.count >= 3 && labels.allSatisfy { label in
            (1...63).contains(label.utf8.count) && label.first != "-" && label.last != "-" &&
            label.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
        }
    }

    static func isReservedEndpoint(_ host: String, port: Int) -> Bool {
        // External tests are sealed to the controller's four synthetic targets
        // and two explicit DNS destinations. Loopback exists for unprivileged
        // build tests. There is no hostname resolution or arbitrary remote peer.
        if host == "198.51.100.42" { return (44441...44444).contains(port) }
        if host == "1.1.1.1" || host == "1.0.0.1" { return port == 53 }
        return host == "127.0.0.1" && (1024...65535).contains(port)
    }

    static func isProbeAddress(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        if parts.count == 4 {
            guard parts.allSatisfy({ !$0.isEmpty && $0.count <= 3 && $0.utf8.allSatisfy({ (48...57).contains($0) }) &&
                ($0 == "0" || $0.first != "0") }),
                let a = UInt8(parts[0]), let b = UInt8(parts[1]), let c = UInt8(parts[2]), UInt8(parts[3]) != nil else { return false }
            return a == 127 || (a == 198 && (b == 18 || b == 19)) ||
                (a == 192 && b == 0 && c == 2) || (a == 198 && b == 51 && c == 100) || (a == 203 && b == 0 && c == 113)
        }
        var address = in6_addr()
        guard host.utf8.count <= 45, inet_pton(AF_INET6, host, &address) == 1 else { return false }
        let bytes = withUnsafeBytes(of: address) { Array($0) }
        return bytes == Array(repeating: UInt8(0), count: 15) + [1] || Array(bytes.prefix(4)) == [0x20, 0x01, 0x0d, 0xb8]
    }

    var json: [String: Any] {
        var result: [String: Any] = ["op": op, "timeoutMs": timeoutMs]
        if let host = host { result["host"] = host }
        if let port = port { result["port"] = Int(port) }
        if let transport = transport, op == "reserve" { result["protocol"] = transport }
        if let reservationID = reservationID { result["reservationId"] = reservationID }
        if ["tcp", "udp", "probe_reserved"].contains(op) { result["payloadBase64"] = payload.base64EncodedString(); result["halfClose"] = halfClose }
        return result
    }
}

struct FixtureRequest {
    let id: String
    let op: String
    let probe: FixtureProbeRequest?
    let childPID: Int32?
    let childProbe: FixtureProbeRequest?

    private static func identifier(_ value: Any?) -> String? {
        guard let id = value as? String, (1...64).contains(id.utf8.count),
              id.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }) else { return nil }
        return id
    }

    /// Semantic refusals retain only the safe request identifier. Malformed
    /// JSON, oversized input or arbitrary strings never reach diagnostic output.
    static func replyIdentifier(line: Data) -> String? {
        guard line.count <= FixtureProtocol.maximumLineBytes,
              let object = try? JSONSerialization.jsonObject(with: line) as? [String: Any] else { return nil }
        return identifier(object["id"])
    }

    init(line: Data) throws {
        guard line.count <= FixtureProtocol.maximumLineBytes,
              let object = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
              let id = Self.identifier(object["id"]),
              let op = object["op"] as? String else { throw FixtureFailure.invalidRequest }
        self.id = id; self.op = op
        if ["status", "resolve", "tcp", "udp", "reserve", "probe_reserved", "release_reservation"].contains(op) {
            probe = try FixtureProbeRequest(object); childPID = nil; childProbe = nil
        } else {
            probe = nil
            switch op {
            case "spawn_child", "stop":
                guard Set(object.keys) == ["id", "op"] else { throw FixtureFailure.invalidRequest }
                childPID = nil; childProbe = nil
            case "close_child", "child_probe":
                let keys: Set<String> = op == "close_child" ? ["id", "op", "pid"] : ["id", "op", "pid", "request"]
                guard Set(object.keys) == keys else { throw FixtureFailure.invalidRequest }
                let pid = try FixtureProbeRequest.integer(object["pid"])
                guard pid > 0 else { throw FixtureFailure.invalidRequest }
                childPID = Int32(pid)
                if op == "child_probe" {
                    guard let inner = object["request"] as? [String: Any], inner["id"] == nil else { throw FixtureFailure.invalidRequest }
                    childProbe = try FixtureProbeRequest(inner)
                } else { childProbe = nil }
            default: throw FixtureFailure.invalidRequest
            }
        }
    }
}
