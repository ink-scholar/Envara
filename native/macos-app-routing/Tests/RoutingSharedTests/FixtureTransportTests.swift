import Foundation
import Darwin
import XCTest
@testable import RoutingAcceptanceFixture

final class FixtureTransportTests: XCTestCase {
    private func localSocket(_ type: Int32) throws -> (Int32, Int) {
        let fd = socket(AF_INET, type, 0)
        guard fd >= 0 else { throw FixtureFailure.transport }
        do {
            var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_addr.s_addr = inet_addr("127.0.0.1")
            let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            } }
            guard bound == 0 else { throw FixtureFailure.transport }
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            let named = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }
            guard named == 0 else { throw FixtureFailure.transport }
            try FixtureIO.nonblocking(fd)
            return (fd, Int(UInt16(bigEndian: address.sin_port)))
        } catch { Darwin.close(fd); throw error }
    }

    func testTCPRetainsEchoAfterOwnedHalfClose() throws {
        let (listener, port) = try localSocket(SOCK_STREAM); defer { Darwin.close(listener) }
        guard listen(listener, 1) == 0 else { throw FixtureFailure.transport }
        let payload = Data(repeating: 0x51, count: 2048), finished = expectation(description: "local TCP fixture closed")
        DispatchQueue.global(qos: .utility).async {
            defer { finished.fulfill() }
            do {
                let deadline = FixtureClock.deadline(milliseconds: 3000)
                try FixtureIO.wait(listener, events: Int16(POLLIN), deadline: deadline)
                let client = Darwin.accept(listener, nil, nil)
                guard client >= 0 else { throw FixtureFailure.transport }; defer { Darwin.close(client) }
                try FixtureIO.nonblocking(client)
                var received = Data()
                while true {
                    try FixtureIO.wait(client, events: Int16(POLLIN), deadline: deadline)
                    var bytes = [UInt8](repeating: 0, count: 4096)
                    let count = recv(client, &bytes, bytes.count, 0)
                    if count == 0 { break }; guard count > 0 else { throw FixtureFailure.transport }
                    received.append(contentsOf: bytes.prefix(count)); guard received.count <= 4096 else { throw FixtureFailure.tooLarge }
                }
                XCTAssertEqual(received, payload)
                try FixtureIO.write(received, fd: client, deadline: deadline)
                XCTAssertEqual(shutdown(client, SHUT_WR), 0)
            } catch { XCTFail("Owned local half-close fixture failed") }
        }
        let request = try FixtureProbeRequest(["op": "tcp", "host": "127.0.0.1", "port": port,
                                             "payloadBase64": payload.base64EncodedString(), "halfClose": true, "timeoutMs": 2000])
        let result = try FixtureProbe().run(request)
        XCTAssertEqual(result["matches"] as? Bool, true)
        XCTAssertEqual(result["receivedBytes"] as? Int, payload.count)
        XCTAssertEqual(result["eof"] as? Bool, true)
        wait(for: [finished], timeout: 3)
    }

    func testUDPUsesBoundedOwnedDatagram() throws {
        let (server, port) = try localSocket(SOCK_DGRAM); defer { Darwin.close(server) }
        let payload = Data(repeating: 0x52, count: 32), finished = expectation(description: "local UDP fixture completed")
        DispatchQueue.global(qos: .utility).async {
            defer { finished.fulfill() }
            do {
                try FixtureIO.wait(server, events: Int16(POLLIN), deadline: FixtureClock.deadline(milliseconds: 3000))
                var address = sockaddr_storage(), length = socklen_t(MemoryLayout<sockaddr_storage>.size)
                var bytes = [UInt8](repeating: 0, count: 4096)
                let count = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    recvfrom(server, &bytes, bytes.count, 0, $0, &length)
                } }
                guard count == payload.count else { throw FixtureFailure.transport }
                let response = Data(bytes.prefix(count)); XCTAssertEqual(response, payload)
                let sent = response.withUnsafeBytes { data in withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(server, data.baseAddress, data.count, 0, $0, length)
                } } }
                XCTAssertEqual(sent, count)
            } catch { XCTFail("Owned local UDP fixture failed") }
        }
        let request = try FixtureProbeRequest(["op": "udp", "host": "127.0.0.1", "port": port, "payloadBase64": payload.base64EncodedString()])
        let result = try FixtureProbe().run(request)
        XCTAssertEqual(result["matches"] as? Bool, true)
        XCTAssertEqual(result["receivedBytes"] as? Int, payload.count)
        wait(for: [finished], timeout: 3)
    }

    func testUnansweredUDPHasARealDeadline() throws {
        let (server, port) = try localSocket(SOCK_DGRAM); defer { Darwin.close(server) }
        let request = try FixtureProbeRequest(["op": "udp", "host": "127.0.0.1", "port": port, "timeoutMs": 200])
        let started = FixtureClock.now
        XCTAssertThrowsError(try FixtureProbe().run(request)) { XCTAssertEqual($0 as? FixtureFailure, .deadline) }
        let elapsed = Double(FixtureClock.now - started) / 1_000_000_000
        XCTAssertGreaterThanOrEqual(elapsed, 0.15); XCTAssertLessThan(elapsed, 1.5)
    }
}
