import Foundation

/// Safe failure categories. Neither errors nor this codec log DNS contents.
public enum DNSWireError: String, Error, Equatable, Sendable {
    case sizeInvalid = "DNS_SIZE_INVALID"
    case headerInvalid = "DNS_HEADER_INVALID"
    case queryUnsupported = "DNS_QUERY_UNSUPPORTED"
    case questionMismatch = "DNS_QUESTION_MISMATCH"
    case transactionMismatch = "DNS_TRANSACTION_MISMATCH"
    case messageTruncated = "DNS_MESSAGE_TRUNCATED"
    case trailingBytes = "DNS_TRAILING_BYTES"
    case nameInvalid = "DNS_NAME_INVALID"
    case compressionInvalid = "DNS_COMPRESSION_INVALID"
    case compressionDepth = "DNS_COMPRESSION_DEPTH"
    case recordInvalid = "DNS_RR_INVALID"
    case recordUnsupported = "DNS_RR_UNSUPPORTED"
    case ednsInvalid = "DNS_EDNS_INVALID"
    case ednsUnsupported = "DNS_EDNS_UNSUPPORTED"
}

/// Bounded unsigned standard QUERY framing, not a resolver or DNSSEC verifier.
public enum DNSWire {
    /// One provider-owned DNS TCP stream. Data slices retain their original
    /// indices, so every frame offset is relative to storage.startIndex.
    public struct TCPFrameBuffer: Sendable {
        private var storage = Data()
        public init() {}

        public mutating func append(_ data: Data) throws {
            guard data.count <= 65536 - storage.count else { throw DNSWireError.sizeInvalid }
            storage.append(data)
        }

        public mutating func nextQuery() throws -> Data? {
            guard storage.count >= 2 else { return nil }
            let start = storage.startIndex
            let size = Int(storage[start]) << 8 | Int(storage[storage.index(after: start)])
            guard size >= 12, size <= 4096 else { throw DNSWireError.sizeInvalid }
            guard storage.count >= size + 2 else { return nil }
            let payloadStart = storage.index(start, offsetBy: 2)
            let end = storage.index(payloadStart, offsetBy: size)
            let packet = Data(storage[payloadStart..<end])
            storage.removeFirst(size + 2)
            if storage.isEmpty { storage = Data() }
            return packet
        }

        public func validateEOF() throws {
            guard storage.isEmpty else { throw DNSWireError.messageTruncated }
        }
    }

    public struct Query: Sendable {
        public let wire: Data
        public let dnsName: String
        public let udpPayloadSize: Int
        fileprivate let id: UInt16
        fileprivate let flags: UInt16
        fileprivate let name: [UInt8]
        fileprivate let type: UInt16
        fileprivate let rrclass: UInt16
        fileprivate let question: [UInt8]
        fileprivate let edns: Bool
        fileprivate let ednsDO: Bool
    }

    private struct Header {
        let id: UInt16
        let flags: UInt16
        let counts: [Int]
    }
    private struct ParsedQuestion {
        let name: [UInt8]
        let type: UInt16
        let rrclass: UInt16
        let end: Int
    }
    private struct OPT {
        let payloadSize: Int
        let ttl: UInt32
    }
    private enum Section: Equatable { case answer, authority, additional }
    private static let unsupportedTypes: Set<UInt16> = [0, 24, 41, 249, 250, 251, 252, 253, 254, 255]

    public static func validateQuery(_ data: Data) throws -> Query {
        let bytes = try message(data, maximum: 4096)
        let header = try readHeader(bytes, response: false)
        guard header.counts[1] == 0, header.counts[2] == 0, header.counts[3] <= 1 else { throw DNSWireError.queryUnsupported }
        let parser = Parser(bytes)
        let asked = try question(parser, compression: false)
        guard asked.rrclass == 1, !unsupportedTypes.contains(asked.type) else { throw DNSWireError.queryUnsupported }
        var offset = asked.end
        var udpPayloadSize = 512
        var ednsDO = false
        let edns = header.counts[3] == 1
        if edns {
            let record = try parser.record(at: offset, section: .additional, query: true, ednsAllowed: true, seenOPT: false)
            guard let opt = record.opt else { throw DNSWireError.ednsInvalid }
            offset = record.end; udpPayloadSize = opt.payloadSize; ednsDO = opt.ttl & 0x8000 != 0
        }
        guard offset == bytes.count else { throw DNSWireError.trailingBytes }
        return Query(wire: Data(bytes), dnsName: printableName(asked.name), udpPayloadSize: udpPayloadSize,
                     id: header.id, flags: header.flags, name: asked.name, type: asked.type, rrclass: asked.rrclass,
                     question: Array(bytes[12..<asked.end]), edns: edns, ednsDO: ednsDO)
    }

    /// Local privacy refusal. Keep RD/CD and EDNS DO, but never claim DNSSEC
    /// authentication (AD) for this locally generated NXDOMAIN response.
    public static func blockedResponse(query: Query) -> Data {
        var bytes = [UInt8](repeating: 0, count: 12)
        put16(query.id, in: &bytes, at: 0)
        put16(0x8083 | (query.flags & 0x0110), in: &bytes, at: 2)
        put16(1, in: &bytes, at: 4)
        put16(query.edns ? 1 : 0, in: &bytes, at: 10)
        bytes += query.question
        if query.edns {
            bytes += [0, 0, 41, UInt8(query.udpPayloadSize >> 8), UInt8(query.udpPayloadSize & 255),
                      0, 0, query.ednsDO ? 0x80 : 0, 0, 0, 0]
        }
        return Data(bytes)
    }

    @discardableResult public static func validateResponse(_ data: Data, query: Query) throws -> Data {
        _ = try response(data, query: query)
        return data
    }

    /// Validate first, then emit a whole question-only TC answer if UDP is too
    /// small. No RR or EDNS option is sliced into an invalid partial message.
    public static func udpResponse(_ data: Data, query: Query) throws -> Data {
        let parsed = try response(data, query: query)
        guard data.count > query.udpPayloadSize else { return data }
        var bytes = Array(parsed.bytes.prefix(12))
        put16(parsed.header.flags | 0x0200, in: &bytes, at: 2)
        put16(1, in: &bytes, at: 4)
        put16(0, in: &bytes, at: 6); put16(0, in: &bytes, at: 8)
        put16(parsed.opt == nil ? 0 : 1, in: &bytes, at: 10)
        bytes += query.question
        if let opt = parsed.opt {
            bytes += [0, 0, 41, UInt8(opt.payloadSize >> 8), UInt8(opt.payloadSize & 255)]
            // Preserve extended RCODE and DO, version zero, no option payload,
            // and no unassigned flags in this newly generated OPT record.
            let ttl = opt.ttl & 0xffff8000
            bytes += [UInt8((ttl >> 24) & 255), UInt8((ttl >> 16) & 255), UInt8((ttl >> 8) & 255), UInt8(ttl & 255), 0, 0]
        }
        return Data(bytes)
    }

    private static func message(_ data: Data, maximum: Int) throws -> [UInt8] {
        guard data.count >= 12, data.count <= maximum else { throw DNSWireError.sizeInvalid }
        return Array(data)
    }
    private static func readHeader(_ bytes: [UInt8], response: Bool) throws -> Header {
        let flags = word(bytes, 2)
        guard (flags & 0x8000 != 0) == response, flags & 0x7800 == 0, flags & 0x0040 == 0,
              response || flags & ~UInt16(0x0130) == 0 else { throw DNSWireError.headerInvalid }
        let counts = [4, 6, 8, 10].map { Int(word(bytes, $0)) }
        guard counts[0] == 1 else { throw DNSWireError.headerInvalid }
        return Header(id: word(bytes, 0), flags: flags, counts: counts)
    }
    private static func question(_ parser: Parser, compression: Bool) throws -> ParsedQuestion {
        let name = try parser.name(at: 12, compression: compression)
        try parser.require(name.end, 4)
        return ParsedQuestion(name: name.wire, type: word(parser.bytes, name.end),
                              rrclass: word(parser.bytes, name.end + 2), end: name.end + 4)
    }
    private static func response(_ data: Data, query: Query) throws -> (bytes: [UInt8], header: Header, opt: OPT?) {
        let bytes = try message(data, maximum: 65535)
        let header = try readHeader(bytes, response: true)
        guard header.id == query.id else { throw DNSWireError.transactionMismatch }
        let parser = Parser(bytes)
        let asked = try question(parser, compression: true)
        guard asked.name == query.name, asked.type == query.type, asked.rrclass == query.rrclass else { throw DNSWireError.questionMismatch }
        var offset = asked.end
        guard header.counts[1...3].reduce(0, +) <= (bytes.count - offset) / 11 else { throw DNSWireError.recordInvalid }
        var opt: OPT?
        for (index, section) in [Section.answer, .authority, .additional].enumerated() {
            for _ in 0..<header.counts[index + 1] {
                let record = try parser.record(at: offset, section: section, query: false, ednsAllowed: query.edns, seenOPT: opt != nil)
                offset = record.end
                if let found = record.opt { opt = found }
            }
        }
        guard offset == bytes.count else { throw DNSWireError.trailingBytes }
        let legacyFORMERR = header.flags & 0x000f == 1 && header.flags & 0x0200 == 0 &&
            header.counts[1...3].allSatisfy { $0 == 0 }
        guard !query.edns || opt != nil || legacyFORMERR else { throw DNSWireError.ednsInvalid }
        return (bytes, header, opt)
    }
    private static func word(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }
    private static func longWord(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(word(bytes, offset)) << 16 | UInt32(word(bytes, offset + 2))
    }
    private static func put16(_ value: UInt16, in bytes: inout [UInt8], at offset: Int) {
        bytes[offset] = UInt8(value >> 8); bytes[offset + 1] = UInt8(value & 255)
    }
    private static func printableName(_ name: [UInt8]) -> String {
        var labels = [String](), offset = 0
        while name[offset] != 0 {
            let count = Int(name[offset]); offset += 1
            let label = name[offset..<(offset + count)].map { byte -> String in
                if byte >= 33 && byte <= 126 && byte != 46 && byte != 92 { return String(UnicodeScalar(byte)) }
                return String(format: "\\%03d", Int(byte))
            }.joined()
            labels.append(label); offset += count
        }
        return labels.isEmpty ? "." : labels.joined(separator: ".")
    }

    private final class Parser {
        struct Name { let wire: [UInt8]; let end: Int }
        private struct Suffix { let wire: [UInt8]; let depth: Int }
        let bytes: [UInt8]
        private var names = [Int: Suffix]()
        init(_ bytes: [UInt8]) { self.bytes = bytes }

        func require(_ offset: Int, _ count: Int, end: Int? = nil) throws {
            let limit = end ?? bytes.count
            guard offset >= 0, count >= 0, limit <= bytes.count, offset <= limit, count <= limit - offset else { throw DNSWireError.messageTruncated }
        }
        /// Only completed prior name boundaries may be compression targets.
        /// Opaque RDATA and unfinished names never register target offsets.
        func name(at offset: Int, end: Int? = nil, compression: Bool = true) throws -> Name {
            let limit = end ?? bytes.count
            var cursor = offset, wire = [UInt8](), boundaries = [(Int, Int)](), depth = 0
            while true {
                try require(cursor, 1, end: limit)
                let length = Int(bytes[cursor])
                if length & 0xc0 == 0xc0 {
                    guard compression else { throw DNSWireError.compressionInvalid }
                    try require(cursor, 2, end: limit)
                    let target = (length & 0x3f) << 8 | Int(bytes[cursor + 1])
                    guard target >= 12, target < cursor, let previous = names[target] else { throw DNSWireError.compressionInvalid }
                    depth = previous.depth + 1
                    guard depth <= 32 else { throw DNSWireError.compressionDepth }
                    boundaries.append((cursor, wire.count)); wire += previous.wire; cursor += 2
                    break
                }
                guard length & 0xc0 == 0 else { throw DNSWireError.nameInvalid }
                boundaries.append((cursor, wire.count)); cursor += 1; wire.append(UInt8(length))
                if length == 0 { break }
                try require(cursor, length, end: limit)
                wire += bytes[cursor..<(cursor + length)].map { byte in byte >= 65 && byte <= 90 ? byte + 32 : byte }
                cursor += length
                guard wire.count < 255 else { throw DNSWireError.nameInvalid }
            }
            guard wire.count <= 255 else { throw DNSWireError.nameInvalid }
            for (position, start) in boundaries { names[position] = Suffix(wire: Array(wire.dropFirst(start)), depth: depth) }
            return Name(wire: wire, end: cursor)
        }
        func record(at start: Int, section: Section, query: Bool, ednsAllowed: Bool, seenOPT: Bool) throws -> (end: Int, opt: OPT?) {
            let owner = try name(at: start, compression: !query)
            try require(owner.end, 10)
            let type = DNSWire.word(bytes, owner.end), rrclass = DNSWire.word(bytes, owner.end + 2)
            let ttl = DNSWire.longWord(bytes, owner.end + 4)
            let dataStart = owner.end + 10, length = Int(DNSWire.word(bytes, owner.end + 8))
            try require(dataStart, length)
            let end = dataStart + length
            if type == 41 {
                guard section == .additional, ednsAllowed, !seenOPT, bytes[start] == 0, owner.end == start + 1 else { throw DNSWireError.ednsInvalid }
                guard (ttl >> 16) & 255 == 0 else { throw DNSWireError.ednsUnsupported }
                guard !query || ttl >> 24 == 0 else { throw DNSWireError.ednsInvalid }
                var offset = dataStart
                while offset < end {
                    try require(offset, 4, end: end)
                    let count = Int(DNSWire.word(bytes, offset + 2)); offset += 4
                    try require(offset, count, end: end); offset += count
                }
                return (end, OPT(payloadSize: max(512, min(4096, Int(rrclass))), ttl: ttl))
            }
            guard !query, !DNSWire.unsupportedTypes.contains(type), rrclass == 1 else { throw DNSWireError.recordUnsupported }
            try rdata(type: type, start: dataStart, end: end)
            return (end, nil)
        }
        private func characterString(at offset: Int, end: Int) throws -> Int {
            try require(offset, 1, end: end)
            let count = Int(bytes[offset]); try require(offset + 1, count, end: end)
            return offset + 1 + count
        }
        private func bitmap(at start: Int, end: Int, allowEmpty: Bool = false) throws -> Int {
            var offset = start, previous = -1
            guard allowEmpty || offset < end else { throw DNSWireError.recordInvalid }
            while offset < end {
                try require(offset, 2, end: end)
                let window = Int(bytes[offset]), count = Int(bytes[offset + 1]); offset += 2
                guard window > previous, count >= 1, count <= 32 else { throw DNSWireError.recordInvalid }
                try require(offset, count, end: end)
                guard bytes[offset + count - 1] != 0 else { throw DNSWireError.recordInvalid }
                offset += count; previous = window
            }
            return offset
        }
        private func rdata(type: UInt16, start: Int, end: Int) throws {
            var offset = start
            let length = end - start
            switch type {
            case 1, 28, 108, 109:
                let expected = type == 1 ? 4 : type == 28 ? 16 : type == 108 ? 6 : 8
                guard length == expected else { throw DNSWireError.recordInvalid }; return
            case 2, 3, 4, 5, 7, 8, 9, 12, 39:
                offset = try name(at: offset, end: end, compression: type != 39).end
            case 6:
                offset = try name(at: offset, end: end).end
                offset = try name(at: offset, end: end).end
                try require(offset, 20, end: end); offset += 20
            case 14, 17:
                offset = try name(at: offset, end: end).end
                offset = try name(at: offset, end: end).end
            case 15, 18, 21, 36:
                try require(offset, 2, end: end); offset += 2
                offset = try name(at: offset, end: end, compression: type != 36).end
            case 13:
                offset = try characterString(at: offset, end: end)
                offset = try characterString(at: offset, end: end)
            case 16, 99:
                guard length > 0 else { throw DNSWireError.recordInvalid }
                while offset < end { offset = try characterString(at: offset, end: end) }
            case 33:
                try require(offset, 6, end: end); offset += 6
                offset = try name(at: offset, end: end, compression: false).end
            case 35:
                try require(offset, 4, end: end); offset += 4
                for _ in 0..<3 { offset = try characterString(at: offset, end: end) }
                offset = try name(at: offset, end: end, compression: false).end
            case 46:
                try require(offset, 18, end: end); offset += 18
                offset = try name(at: offset, end: end, compression: false).end
                guard offset < end else { throw DNSWireError.recordInvalid }; return
            case 47:
                offset = try name(at: offset, end: end, compression: false).end
                offset = try bitmap(at: offset, end: end)
            case 50:
                try require(offset, 5, end: end)
                let saltLength = Int(bytes[offset + 4]); offset += 5
                try require(offset, saltLength + 1, end: end); offset += saltLength
                let hashLength = Int(bytes[offset]); offset += 1
                guard hashLength > 0 else { throw DNSWireError.recordInvalid }
                try require(offset, hashLength, end: end); offset += hashLength
                offset = try bitmap(at: offset, end: end, allowEmpty: true)
            case 51:
                try require(offset, 5, end: end)
                let saltLength = Int(bytes[offset + 4]); offset += 5
                try require(offset, saltLength, end: end); offset += saltLength
            case 64, 65:
                try require(offset, 2, end: end); offset += 2
                offset = try name(at: offset, end: end, compression: false).end
                var previous = -1
                while offset < end {
                    try require(offset, 4, end: end)
                    let key = Int(DNSWire.word(bytes, offset)), count = Int(DNSWire.word(bytes, offset + 2))
                    guard key > previous else { throw DNSWireError.recordInvalid }
                    offset += 4; try require(offset, count, end: end); offset += count; previous = key
                }
            case 257:
                guard length >= 3, bytes[start + 1] > 0, Int(bytes[start + 1]) <= length - 2 else { throw DNSWireError.recordInvalid }; return
            case 11, 37, 43, 59, 44, 48, 60, 52, 53, 256:
                let minimum: Int
                switch type { case 11, 43, 59, 256: minimum = 5; case 37: minimum = 6; case 44: minimum = 3; default: minimum = 4 }
                guard length >= minimum else { throw DNSWireError.recordInvalid }; return
            default:
                // RFC 3597: unknown data stays opaque and publishes no names.
                return
            }
            guard offset == end else { throw DNSWireError.recordInvalid }
        }
    }
}
