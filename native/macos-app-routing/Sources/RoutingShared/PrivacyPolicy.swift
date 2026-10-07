import Foundation

public enum PrivacyPolicy {
    public static let standard = ["google-analytics.com", "doubleclick.net", "api.segment.io", "api.segment.com", "cdn.segment.com"]
    public static let strict = standard + ["googletagmanager.com", "api.mixpanel.com", "api-js.mixpanel.com", "api.amplitude.com", "api2.amplitude.com", "cdn.amplitude.com", "hotjar.com", "hotjar.io", "sessions.bugsnag.com", "notify.bugsnag.com", "browser-intake-datadoghq.com", "browser-intake-datadoghq.eu", "ingest.sentry.io", "ingest.us.sentry.io", "ingest.de.sentry.io"]

    public static func blocks(_ host: String, mode: String) -> Bool {
        if mode == "off" { return false }
        let host = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return (mode == "strict" ? strict : standard).contains { host == $0 || host.hasSuffix(".\($0)") }
    }

    // Parse one ordinary DNS question without resolving it on the host. Compressed
    // question names and malformed packets are not guessed or passed to DIRECT.
    public static func dnsQuestion(_ packet: Data) throws -> (String, Int) {
        let bytes = Array(packet)
        guard bytes.count >= 17, bytes[2] & 0x80 == 0, bytes[4] == 0, bytes[5] == 1 else { throw RoutingError.invalidSOCKS }
        var cursor = 12, labels = [String]()
        while true {
            guard cursor < bytes.count else { throw RoutingError.invalidSOCKS }
            let length = Int(bytes[cursor]); cursor += 1
            if length == 0 { break }
            guard length <= 63, cursor + length <= bytes.count,
                  bytes[cursor..<(cursor + length)].allSatisfy({ $0 > 0 && $0 < 128 }),
                  let label = String(bytes: bytes[cursor..<(cursor + length)], encoding: .ascii) else { throw RoutingError.invalidSOCKS }
            labels.append(label); cursor += length
            guard labels.joined(separator: ".").utf8.count <= 253 else { throw RoutingError.invalidSOCKS }
        }
        guard !labels.isEmpty, cursor + 4 <= bytes.count else { throw RoutingError.invalidSOCKS }
        return (labels.joined(separator: ".").lowercased(), cursor + 4)
    }

    public static func blockedDNSResponse(_ packet: Data, mode: String) throws -> Data? {
        if mode == "off" { return nil }
        let (name, end) = try dnsQuestion(packet)
        guard blocks(name, mode: mode) else { return nil }
        var response = packet.subdata(in: 0..<end)
        response[2] = (response[2] & 1) | 0x80 // QR + request's RD
        response[3] = 0x83 // recursion available + NXDOMAIN
        for index in 6..<12 { response[index] = 0 }
        return response
    }
}
