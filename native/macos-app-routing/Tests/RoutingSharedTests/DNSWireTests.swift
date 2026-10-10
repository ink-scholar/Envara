import Foundation
import XCTest
@testable import RoutingShared

final class DNSWireTests: XCTestCase {
    private func u16(_ value: Int) -> [UInt8] { [UInt8((value >> 8) & 255), UInt8(value & 255)] }
    private func u32(_ value: UInt32) -> [UInt8] {
        [UInt8((value >> 24) & 255), UInt8((value >> 16) & 255), UInt8((value >> 8) & 255), UInt8(value & 255)]
    }
    private func name(_ value: String) -> [UInt8] {
        var bytes: [UInt8] = []
        for label in value.split(separator: ".") {
            bytes.append(UInt8(label.utf8.count))
            bytes.append(contentsOf: label.utf8)
        }
        bytes.append(0)
        return bytes
    }
    private func question(_ value: String = "Fixture.Example", type: Int = 1, rrclass: Int = 1) -> [UInt8] {
        var bytes: [UInt8] = name(value)
        bytes.append(contentsOf: u16(type))
        bytes.append(contentsOf: u16(rrclass))
        return bytes
    }
    private func header(id: Int = 0x4a2b, flags: Int, answers: Int = 0, authority: Int = 0, additional: Int = 0) -> [UInt8] {
        var bytes: [UInt8] = u16(id)
        bytes.append(contentsOf: u16(flags))
        bytes.append(contentsOf: u16(1))
        bytes.append(contentsOf: u16(answers))
        bytes.append(contentsOf: u16(authority))
        bytes.append(contentsOf: u16(additional))
        return bytes
    }
    private func rr(type: Int, data: [UInt8], owner: [UInt8] = [0xc0, 12], rrclass: Int = 1) -> [UInt8] {
        var bytes: [UInt8] = owner
        bytes.append(contentsOf: u16(type))
        bytes.append(contentsOf: u16(rrclass))
        bytes.append(contentsOf: u32(30))
        bytes.append(contentsOf: u16(data.count))
        bytes.append(contentsOf: data)
        return bytes
    }
    private func opt(size: Int = 1232, ttl: UInt32 = 0x8000, data: [UInt8] = []) -> [UInt8] {
        var bytes: [UInt8] = [0]
        bytes.append(contentsOf: u16(41))
        bytes.append(contentsOf: u16(size))
        bytes.append(contentsOf: u32(ttl))
        bytes.append(contentsOf: u16(data.count))
        bytes.append(contentsOf: data)
        return bytes
    }
    private func query(type: Int = 1, size: Int? = nil) -> Data {
        var bytes: [UInt8] = header(flags: 0x0130, additional: size == nil ? 0 : 1)
        bytes.append(contentsOf: question(type: type))
        if let size { bytes.append(contentsOf: opt(size: size)) }
        return Data(bytes)
    }
    private func response(answers: [[UInt8]] = [], authority: [[UInt8]] = [], additional: [[UInt8]] = [],
                          asked: [UInt8]? = nil, id: Int = 0x4a2b, flags: Int = 0x81b0) -> Data {
        var bytes: [UInt8] = header(id: id, flags: flags, answers: answers.count, authority: authority.count, additional: additional.count)
        bytes.append(contentsOf: asked ?? question("fixture.example"))
        for record in answers { bytes.append(contentsOf: record) }
        for record in authority { bytes.append(contentsOf: record) }
        for record in additional { bytes.append(contentsOf: record) }
        return Data(bytes)
    }
    private func rejected(_ expected: DNSWireError? = nil, _ operation: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            XCTAssertTrue(error is DNSWireError, file: file, line: line)
            if let expected { XCTAssertEqual(error as? DNSWireError, expected, file: file, line: line) }
        }
    }

    func testQueryDescriptorIsBoundedAndPreservesOnlyReadOnlyWireAndPrivacyName() throws {
        let raw = query(), parsed = try DNSWire.validateQuery(raw)
        XCTAssertEqual(parsed.wire, raw); XCTAssertEqual(parsed.dnsName, "fixture.example"); XCTAssertEqual(parsed.udpPayloadSize, 512)
        for (advertised, bounded) in [(0, 512), (511, 512), (512, 512), (1232, 1232), (65535, 4096)] {
            XCTAssertEqual(try DNSWire.validateQuery(query(size: advertised)).udpPayloadSize, bounded)
        }
        rejected(.sizeInvalid) { _ = try DNSWire.validateQuery(Data(repeating: 0, count: 4097)) }
        for flags in [0x8100, 0x0900, 0x0140, 0x0500, 0x0101] {
            rejected(.headerInvalid) { _ = try DNSWire.validateQuery(Data(self.header(flags: flags) + self.question())) }
        }
        rejected(.queryUnsupported) { _ = try DNSWire.validateQuery(Data(self.header(flags: 0x100, answers: 1) + self.question())) }
        for type in [0, 41, 249, 250, 251, 252, 255] {
            rejected(.queryUnsupported) { _ = try DNSWire.validateQuery(self.query(type: type)) }
        }
        rejected(.queryUnsupported) { _ = try DNSWire.validateQuery(Data(self.header(flags: 0x100) + self.question(rrclass: 3))) }
        rejected(.compressionInvalid) { _ = try DNSWire.validateQuery(Data(self.header(flags: 0x100) + [0xc0, 12, 0, 1, 0, 1])) }
        rejected(.trailingBytes) { _ = try DNSWire.validateQuery(raw + Data([0])) }
    }

    func testResponseRequiresTransactionAndCompleteQuestionIdentity() throws {
        let asked = try DNSWire.validateQuery(query())
        let valid = response(answers: [rr(type: 1, data: [203, 0, 113, 42])])
        XCTAssertEqual(try DNSWire.validateResponse(valid, query: asked), valid)
        for mismatch in [response(asked: question("other.example")), response(asked: question(type: 28)), response(asked: question(rrclass: 3))] {
            rejected(.questionMismatch) { _ = try DNSWire.validateResponse(mismatch, query: asked) }
        }
        rejected(.transactionMismatch) { _ = try DNSWire.validateResponse(self.response(id: 0x4a2c), query: asked) }
        for flags in [0x0100, 0x8900, 0x8140] {
            rejected(.headerInvalid) { _ = try DNSWire.validateResponse(self.response(flags: flags), query: asked) }
        }
        rejected(.trailingBytes) { _ = try DNSWire.validateResponse(valid + Data([0]), query: asked) }
        var shortened = valid; shortened.removeLast()
        rejected(.messageTruncated) { _ = try DNSWire.validateResponse(shortened, query: asked) }
    }

    func testCompressionTargetsOnlyPriorCompletedNamesAndNeverOpaqueData() throws {
        let asked = try DNSWire.validateQuery(query())
        let good = response(answers: [rr(type: 5, data: [0xc0, 12]), rr(type: 1, data: [203, 0, 113, 42])])
        XCTAssertEqual(try DNSWire.validateResponse(good, query: asked), good)
        let answerStart = 12 + question().count
        for owner in [[UInt8(0xc0), 0], [0xc0, 13], [0xc0, UInt8(answerStart)], [0xc0, UInt8(answerStart + 2)], [0xc0, 255], [0xc0]] {
            rejected { _ = try DNSWire.validateResponse(self.response(answers: [self.rr(type: 1, data: [203, 0, 113, 42], owner: owner)]), query: asked) }
        }
        // An unknown RR may legally contain pointer-looking bytes, but those
        // bytes cannot become the owner-name target of a later record.
        let opaque = rr(type: 65000, data: [0, 0xc0, 12])
        XCTAssertNoThrow(try DNSWire.validateResponse(response(answers: [opaque]), query: asked))
        let opaqueStart = answerStart + 12
        rejected(.compressionInvalid) {
            _ = try DNSWire.validateResponse(self.response(answers: [opaque, self.rr(type: 1, data: [203, 0, 113, 42], owner: [0xc0, UInt8(opaqueStart)])]), query: asked)
        }
        var records = [[UInt8]](), previous = 12, offset = answerStart
        for _ in 0..<34 {
            let record = rr(type: 1, data: [203, 0, 113, 42], owner: [UInt8(0xc0 | (previous >> 8)), UInt8(previous & 255)])
            records.append(record); previous = offset; offset += record.count
        }
        rejected(.compressionDepth) { _ = try DNSWire.validateResponse(self.response(answers: records), query: asked) }
    }

    func testKnownResourceDataUsesExactLengthsAndNamesWhileUnknownTypesRemainOpaque() throws {
        let asked = try DNSWire.validateQuery(query())
        let cname = rr(type: 5, data: [0xc0, 12])
        let soa = rr(type: 6, data: [0xc0, 12, 0xc0, 12] + Array(repeating: 0, count: 20))
        let mx = rr(type: 15, data: [0, 10, 0xc0, 12])
        let srv = rr(type: 33, data: [0, 0, 0, 0, 1, 187] + name("target.example"))
        XCTAssertNoThrow(try DNSWire.validateResponse(response(answers: [cname, soa, mx, srv, rr(type: 28, data: Array(repeating: 0, count: 16)),
                                                                      rr(type: 65000, data: [0xff, 0xc0, 0xff])]), query: asked))
        for record in [rr(type: 1, data: [203, 0, 113]), rr(type: 28, data: Array(repeating: 0, count: 15)),
                       rr(type: 5, data: [0xc0, 12, 0]), rr(type: 6, data: [0xc0, 12, 0xc0, 12] + Array(repeating: 0, count: 19)),
                       rr(type: 15, data: [0, 10]), rr(type: 33, data: [0, 0, 0, 0, 1, 187, 0xc0, 12])] {
            rejected { _ = try DNSWire.validateResponse(self.response(answers: [record]), query: asked) }
        }
    }

    func testEDNSMustBeUniqueVersionZeroAdditionalRootWithCompleteOptions() throws {
        let raw = query(size: 512), asked = try DNSWire.validateQuery(raw)
        let valid = response(additional: [opt(size: 1232)])
        XCTAssertNoThrow(try DNSWire.validateResponse(valid, query: asked))
        rejected(.ednsInvalid) { _ = try DNSWire.validateResponse(self.response(additional: [self.opt(), self.opt()]), query: asked) }
        rejected(.ednsInvalid) { _ = try DNSWire.validateResponse(self.response(answers: [self.opt()]), query: asked) }
        rejected(.ednsUnsupported) { _ = try DNSWire.validateResponse(self.response(additional: [self.opt(ttl: 0x10000)]), query: asked) }
        rejected(.messageTruncated) { _ = try DNSWire.validateResponse(self.response(additional: [self.opt(data: [0, 1, 0, 2, 1])]), query: asked) }
        rejected(.ednsInvalid) { _ = try DNSWire.validateResponse(self.response(), query: asked) }
        XCTAssertNoThrow(try DNSWire.validateResponse(response(flags: 0x8101), query: asked))
        rejected(.ednsInvalid) { _ = try DNSWire.validateResponse(self.response(flags: 0x8301), query: asked) }
        let plain = try DNSWire.validateQuery(query())
        rejected(.ednsInvalid) { _ = try DNSWire.validateResponse(valid, query: plain) }
        rejected(.ednsInvalid) { _ = try DNSWire.validateQuery(Data(self.header(flags: 0x100, additional: 1) + self.question() + self.opt(ttl: 0x01000000))) }
        rejected(.queryUnsupported) { _ = try DNSWire.validateQuery(Data(self.header(flags: 0x100, additional: 2) + self.question() + self.opt() + self.opt())) }
        let nonroot = rr(type: 41, data: [], owner: name("fixture.example"), rrclass: 512)
        rejected(.ednsInvalid) { _ = try DNSWire.validateResponse(self.response(additional: [nonroot]), query: asked) }
    }

    func testOversizedUDPProducesWholeQuestionAndOPTAndPreservesStatusWithoutSlicingRecords() throws {
        let asked = try DNSWire.validateQuery(query(size: 512))
        let large = response(answers: [rr(type: 65000, data: Array(repeating: 0xaa, count: 600))],
                             additional: [opt(size: 1232, ttl: 0x02008001, data: [0, 15, 0, 2, 0, 1])], flags: 0x85b3)
        let truncated = try DNSWire.udpResponse(large, query: asked)
        let expected = Data(header(flags: 0x87b3, additional: 1) + question() + opt(size: 1232, ttl: 0x02008000))
        XCTAssertEqual(truncated, expected); XCTAssertLessThanOrEqual(truncated.count, asked.udpPayloadSize)
        XCTAssertEqual(try DNSWire.validateResponse(truncated, query: asked), truncated)
        let small = response(additional: [opt(size: 1232)])
        XCTAssertEqual(try DNSWire.udpResponse(small, query: asked), small)
        let plain = try DNSWire.validateQuery(query())
        let plainBig = response(answers: [rr(type: 65000, data: Array(repeating: 0xbb, count: 600))])
        XCTAssertEqual(try DNSWire.udpResponse(plainBig, query: plain), Data(header(flags: 0x83b0) + question()))
        // Validation cannot be bypassed merely because the result will be TC.
        rejected(.transactionMismatch) { _ = try DNSWire.udpResponse(self.response(answers: [self.rr(type: 65000, data: Array(repeating: 0, count: 600))],
                                                                                    additional: [self.opt()], id: 0x4a2c), query: asked) }
    }

    func testLocalBlockedResponseKeepsWholeQuestionAndEDNSDOWithoutClaimingAuthentication() throws {
        let plain = try DNSWire.validateQuery(query())
        let blocked = DNSWire.blockedResponse(query: plain)
        XCTAssertEqual(blocked, Data(header(flags: 0x8193) + question()))
        XCTAssertEqual(try DNSWire.validateResponse(blocked, query: plain), blocked)
        for ttl in [UInt32(0), UInt32(0x8000)] {
            let raw = Data(header(flags: 0x0130, additional: 1) + question() + opt(size: 1232, ttl: ttl, data: [0, 15, 0, 1, 0]))
            let asked = try DNSWire.validateQuery(raw)
            let reply = DNSWire.blockedResponse(query: asked)
            XCTAssertEqual(reply, Data(header(flags: 0x8193, additional: 1) + question() + opt(size: 1232, ttl: ttl)))
            XCTAssertEqual(try DNSWire.validateResponse(reply, query: asked), reply)
            XCTAssertEqual(try DNSWire.udpResponse(reply, query: asked), reply)
        }
    }
}
