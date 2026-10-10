import Foundation
import XCTest
@testable import RoutingShared

final class DNSTCPFrameBufferTests: XCTestCase {
    private func packet(_ marker: UInt8, count: Int = 12) -> Data {
        Data(repeating: marker, count: count)
    }
    private func framed(_ data: Data) -> Data {
        Data([UInt8(data.count >> 8), UInt8(data.count & 255)]) + data
    }

    func testConsecutiveFramesUseRelativeIndicesAfterConsumption() throws {
        let first = packet(0x31, count: 33), second = packet(0x72, count: 44)
        let input = framed(first) + framed(second)
        // This is the Foundation behavior that broke the old Provider's
        // absolute subdata(in: 2..<size+2) on the second frame.
        var observed = input
        observed.removeFirst(framed(first).count)
        XCTAssertGreaterThan(observed.startIndex, 0)
        XCTAssertEqual(Data(observed), framed(second))

        var buffer = DNSWire.TCPFrameBuffer()
        try buffer.append(input)
        XCTAssertEqual(try buffer.nextQuery(), first)
        XCTAssertEqual(try buffer.nextQuery(), second)
        XCTAssertNil(try buffer.nextQuery())
        XCTAssertNoThrow(try buffer.validateEOF())
    }

    func testFramesSpanFragmentedReadsAndPreserveTheFollowingPrefix() throws {
        let first = packet(0x42, count: 28), second = packet(0xa9, count: 19)
        let input = framed(first) + framed(second)
        var buffer = DNSWire.TCPFrameBuffer()
        try buffer.append(input.prefix(1))
        XCTAssertNil(try buffer.nextQuery())
        try buffer.append(input.subdata(in: 1..<8))
        XCTAssertNil(try buffer.nextQuery())
        let firstEnd = framed(first).count
        try buffer.append(input.subdata(in: 8..<(firstEnd + 1)))
        XCTAssertEqual(try buffer.nextQuery(), first)
        XCTAssertNil(try buffer.nextQuery())
        try buffer.append(input.subdata(in: (firstEnd + 1)..<input.count))
        XCTAssertEqual(try buffer.nextQuery(), second)
        XCTAssertNoThrow(try buffer.validateEOF())
    }

    func testInputWithNonzeroStartIndexIsAcceptedWithoutRequiringRebasing() throws {
        let expected = packet(0x67, count: 23)
        let source = Data(repeating: 0xee, count: 80) + framed(expected)
        let sliced = source.dropFirst(80)
        XCTAssertEqual(sliced.startIndex, 80)
        var buffer = DNSWire.TCPFrameBuffer()
        try buffer.append(sliced)
        XCTAssertEqual(try buffer.nextQuery(), expected)
        XCTAssertNoThrow(try buffer.validateEOF())
    }

    func testInvalidLengthsAndIncompleteEOFNeverProduceAQuery() throws {
        for length in [0, 1, 11, 4097, 65535] {
            var buffer = DNSWire.TCPFrameBuffer()
            try buffer.append(Data([UInt8(length >> 8), UInt8(length & 255)]))
            XCTAssertThrowsError(try buffer.nextQuery()) { error in
                XCTAssertEqual(error as? DNSWireError, .sizeInvalid)
            }
        }
        for bytes in [Data([0]), Data([0, 12]), Data([0, 12, 1, 2])] {
            var buffer = DNSWire.TCPFrameBuffer()
            try buffer.append(bytes)
            XCTAssertNil(try buffer.nextQuery())
            XCTAssertThrowsError(try buffer.validateEOF()) { error in
                XCTAssertEqual(error as? DNSWireError, .messageTruncated)
            }
        }
        var boundary = DNSWire.TCPFrameBuffer()
        let maximum = packet(0x51, count: 4096)
        try boundary.append(framed(maximum))
        XCTAssertEqual(try boundary.nextQuery(), maximum)
    }

    func testCapacityUsesUnconsumedBytesAndRejectedAppendKeepsEarlierFrames() throws {
        let first = packet(0x10), second = packet(0x20)
        let firstFrame = framed(first), secondFrame = framed(second)
        var input = firstFrame + secondFrame
        input.append(Data(repeating: 0, count: 65536 - input.count))
        var buffer = DNSWire.TCPFrameBuffer()
        try buffer.append(input)
        XCTAssertThrowsError(try buffer.append(Data([0xff]))) { error in
            XCTAssertEqual(error as? DNSWireError, .sizeInvalid)
        }
        XCTAssertEqual(try buffer.nextQuery(), first)
        // Consuming a frame frees precisely its byte count even though the
        // backing Data now has a nonzero starting index.
        XCTAssertNoThrow(try buffer.append(Data(repeating: 0, count: firstFrame.count)))
        XCTAssertThrowsError(try buffer.append(Data([0xff])))
        XCTAssertEqual(try buffer.nextQuery(), second)

        var empty = DNSWire.TCPFrameBuffer()
        XCTAssertThrowsError(try empty.append(Data(repeating: 0, count: 65537)))
        XCTAssertNil(try empty.nextQuery())
        XCTAssertNoThrow(try empty.validateEOF())
    }
}
