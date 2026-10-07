import XCTest
@testable import RoutingShared

final class RoutingTests: XCTestCase {
    private func route(host: String = "127.0.0.1", password: String = "ephemeral-test-secret", udp: Bool = false) throws -> Route {
        try Route(routeId: UUID().uuidString, applicationIdentity: "io.envara.test", applicationPath: "/Applications/Test.app",
                  executablePath: "/Applications/Test.app/Contents/MacOS/Test", protocolName: "socks5",
                  host: host, port: 12345, username: "test", password: password, udp: udp)
    }

    func testRemoteCoreAndEmptyAuthRejected() {
        XCTAssertThrowsError(try route(host: "198.51.100.1"))
        XCTAssertThrowsError(try route(password: ""))
        XCTAssertEqual(SOCKSCodec.greeting, Data([5, 1, 2]))
    }

    func testAddressRoundTripsPreserveRemoteDNSName() throws {
        for endpoint in [SOCKSEndpoint(host: "example.test", port: 443), SOCKSEndpoint(host: "192.0.2.3", port: 53), SOCKSEndpoint(host: "2001:db8::1", port: 5353)] {
            let encoded = try SOCKSCodec.address(endpoint)
            let (decoded, size) = try SOCKSCodec.decodeAddress(encoded)
            XCTAssertEqual(decoded, endpoint); XCTAssertEqual(size, encoded.count)
        }
        XCTAssertEqual(try SOCKSCodec.command(1, endpoint: .init(host: "example.test", port: 443))[3], 3)
    }

    func testUDPAndDNSPayloadRemainUnchanged() throws {
        let dns = Data([0x01, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00])
        let peer = SOCKSEndpoint(host: "192.0.2.53", port: 53)
        let encoded = try SOCKSCodec.udpPacket(dns, endpoint: peer)
        let (decoded, payload) = try SOCKSCodec.decodeUDP(encoded)
        XCTAssertEqual(decoded, peer); XCTAssertEqual(payload, dns)
        var fragmented = encoded; fragmented[2] = 1
        XCTAssertThrowsError(try SOCKSCodec.decodeUDP(fragmented))
    }

    func testMalformedResponsesRejected() {
        for data in [Data(), Data([1]), Data([3, 255]), Data([4, 0, 0]), Data([7, 0])] {
            XCTAssertThrowsError(try SOCKSCodec.decodeAddress(data))
        }
        XCTAssertThrowsError(try SOCKSCodec.authentication(username: "", password: "value"))
    }

    func testPrivateRuntimePermissionsAndTampering() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: folder) }
        let store = try RuntimeStore(directory: folder), record = try route()
        try store.write(record)
        XCTAssertEqual(try store.read(record.routeId), record)
        let file = try store.url(record.routeId)
        XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        XCTAssertThrowsError(try store.read(record.routeId))
        XCTAssertThrowsError(try store.url("../../outside"))
    }

    func testSymlinkRuntimeReadAndDirectoryRejected() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try RuntimeStore(directory: root)
        let target = root.appendingPathComponent("outside")
        try Data("{}".utf8).write(to: target)
        let id = UUID().uuidString
        try FileManager.default.createSymbolicLink(at: store.url(id), withDestinationURL: target)
        XCTAssertThrowsError(try store.read(id))
    }

    func testPIDReuseCannotSignalUnrelatedProcess() throws {
        let own = try XCTUnwrap(ProcessIdentity.read(getpid()))
        XCTAssertTrue(own.alive)
        let reused = ProcessIdentity(pid: own.pid, parent: own.parent, group: own.group,
                                     startedSeconds: own.startedSeconds + 1, startedMicroseconds: own.startedMicroseconds, path: own.path)
        XCTAssertFalse(reused.alive)
        XCTAssertFalse(reused.signal(0))
    }
}
