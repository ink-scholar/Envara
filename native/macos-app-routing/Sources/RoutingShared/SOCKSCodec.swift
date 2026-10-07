import Foundation
import Darwin

public struct SOCKSEndpoint: Equatable {
    public let host: String
    public let port: UInt16
    public init(host: String, port: UInt16) { self.host = host; self.port = port }
}

public enum SOCKSCodec {
    // Authentication is mandatory. No unauthenticated/no-proxy alternative is offered.
    public static let greeting = Data([5, 1, 2])

    public static func authentication(username: String, password: String) throws -> Data {
        let user = Array(username.utf8), secret = Array(password.utf8)
        guard !user.isEmpty, !secret.isEmpty, user.count <= 255, secret.count <= 255 else { throw RoutingError.invalidRoute }
        return Data([1, UInt8(user.count)] + user + [UInt8(secret.count)] + secret)
    }

    public static func address(_ endpoint: SOCKSEndpoint) throws -> Data {
        guard endpoint.port > 0, !endpoint.host.isEmpty else { throw RoutingError.invalidSOCKS }
        var ipv4 = in_addr(), ipv6 = in6_addr()
        var output = Data()
        if inet_pton(AF_INET, endpoint.host, &ipv4) == 1 {
            output.append(1); withUnsafeBytes(of: &ipv4) { output.append(contentsOf: $0) }
        } else if inet_pton(AF_INET6, endpoint.host, &ipv6) == 1 {
            output.append(4); withUnsafeBytes(of: &ipv6) { output.append(contentsOf: $0) }
        } else {
            let host = Array(endpoint.host.utf8)
            guard host.count <= 255, !host.contains(0) else { throw RoutingError.invalidSOCKS }
            output.append(contentsOf: [3, UInt8(host.count)]); output.append(contentsOf: host)
        }
        output.append(contentsOf: [UInt8(endpoint.port >> 8), UInt8(endpoint.port & 255)])
        return output
    }

    public static func command(_ command: UInt8, endpoint: SOCKSEndpoint) throws -> Data {
        guard command == 1 || command == 3 else { throw RoutingError.invalidSOCKS }
        return Data([5, command, 0]) + (try address(endpoint))
    }

    public static func udpPacket(_ payload: Data, endpoint: SOCKSEndpoint) throws -> Data {
        Data([0, 0, 0]) + (try address(endpoint)) + payload
    }

    public static func decodeAddress(_ data: Data, offset: Int = 0) throws -> (SOCKSEndpoint, Int) {
        let bytes = Array(data)
        guard offset >= 0, bytes.count > offset else { throw RoutingError.invalidSOCKS }
        var cursor = offset + 1
        let host: String
        switch bytes[offset] {
        case 1, 4:
            let count = bytes[offset] == 1 ? 4 : 16
            guard bytes.count >= cursor + count + 2 else { throw RoutingError.invalidSOCKS }
            var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let address = Array(bytes[cursor..<(cursor + count)])
            let valid = address.withUnsafeBytes { raw in
                inet_ntop(count == 4 ? AF_INET : AF_INET6, raw.baseAddress!, &output, socklen_t(output.count)) != nil
            }
            guard valid else { throw RoutingError.invalidSOCKS }
            host = String(cString: output); cursor += count
        case 3:
            guard bytes.count > cursor else { throw RoutingError.invalidSOCKS }
            let count = Int(bytes[cursor]); cursor += 1
            guard count > 0, bytes.count >= cursor + count + 2,
                  let value = String(bytes: bytes[cursor..<(cursor + count)], encoding: .utf8) else { throw RoutingError.invalidSOCKS }
            host = value; cursor += count
        default: throw RoutingError.invalidSOCKS
        }
        let port = UInt16(bytes[cursor]) << 8 | UInt16(bytes[cursor + 1]); cursor += 2
        return (SOCKSEndpoint(host: host, port: port), cursor)
    }

    public static func decodeUDP(_ data: Data) throws -> (SOCKSEndpoint, Data) {
        guard data.count >= 4, data[0] == 0, data[1] == 0, data[2] == 0 else { throw RoutingError.invalidSOCKS }
        let (endpoint, offset) = try decodeAddress(data, offset: 3)
        return (endpoint, data.subdata(in: offset..<data.count))
    }
}
