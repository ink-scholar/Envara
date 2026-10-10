import Foundation
import Darwin
import XCTest
@testable import RoutingAcceptanceFixture

final class FixtureProtocolTests: XCTestCase {
    private func request(_ value: [String: Any]) throws -> FixtureRequest {
        try FixtureRequest(line: JSONSerialization.data(withJSONObject: value))
    }

    func testOnlySyntheticResolverNamesAreAccepted() throws {
        for host in ["localhost", "realm-one.envara-fixture.test", "same-name.envara-fixture.test"] {
            XCTAssertEqual(try request(["id": "resolve", "op": "resolve", "host": host]).probe?.host, host)
        }
        for host in ["example.com", "envara-fixture.test", "a.envara-fixture.test.evil", "A.envara-fixture.test",
                     "-a.envara-fixture.test", "a..envara-fixture.test", "a.envara-fixture.test.", "127.0.0.1"] {
            XCTAssertThrowsError(try request(["id": "resolve", "op": "resolve", "host": host]))
        }
    }

    func testNumericProbeAddressesStayWithinOwnedFixtureRanges() throws {
        for host in ["127.0.0.1", "127.0.0.2", "198.18.0.1", "198.19.255.254", "192.0.2.42", "198.51.100.42",
                     "203.0.113.42", "::1", "2001:db8::42"] {
            XCTAssertTrue(FixtureProbeRequest.isProbeAddress(host), host)
            XCTAssertNoThrow(try request(["id": "probe", "op": "tcp", "host": host, "port": 40443]))
        }
        for host in ["example.com", "0.0.0.0", "10.0.0.1", "192.168.1.1", "1.1.1.1", "198.17.0.1",
                     "198.20.0.1", "127.00.0.1", "127.0.0.256", "::", "::ffff:127.0.0.1", "2001:db9::1", "fe80::1%lo0"] {
            XCTAssertFalse(FixtureProbeRequest.isProbeAddress(host), host)
        }
    }

    func testRequestSizeTypesDeadlinesAndOperationsAreBounded() throws {
        XCTAssertNoThrow(try request(["id": "bounded", "op": "tcp", "host": "127.0.0.1", "port": 65535,
                                     "payloadBase64": Data(repeating: 1, count: 4096).base64EncodedString(), "timeoutMs": 5000, "halfClose": true]))
        for value: [String: Any] in [
            ["id": "command", "op": "run", "command": "/bin/sh"],
            ["id": "command", "op": "status", "environment": ["secret": "unused"]],
            ["id": "probe", "op": "tcp", "host": "127.0.0.1", "port": 80],
            ["id": "probe", "op": "tcp", "host": "127.0.0.1", "port": true],
            ["id": "probe", "op": "tcp", "host": "127.0.0.1", "port": 40443.5],
            ["id": "probe", "op": "tcp", "host": "127.0.0.1", "port": 40443, "halfClose": 1],
            ["id": "probe", "op": "udp", "host": "127.0.0.1", "port": 40443, "halfClose": true],
            ["id": "probe", "op": "tcp", "host": "127.0.0.1", "port": 40443, "timeoutMs": 100],
            ["id": "probe", "op": "tcp", "host": "127.0.0.1", "port": 40443, "timeoutMs": 5001],
            ["id": "probe", "op": "tcp", "host": "127.0.0.1", "port": 40443, "payloadBase64": "***"],
            ["id": "probe", "op": "tcp", "host": "127.0.0.1", "port": 40443, "payloadBase64": Data(repeating: 1, count: 4097).base64EncodedString()],
        ] { XCTAssertThrowsError(try request(value)) }
        XCTAssertThrowsError(try FixtureRequest(line: Data(repeating: 32, count: 8193)))
        XCTAssertThrowsError(try request(["id": "line\nbreak", "op": "status"]))
        XCTAssertEqual(FixtureRequest.replyIdentifier(line: try JSONSerialization.data(withJSONObject: ["id": "refuse", "op": "resolve", "host": "example.com"])), "refuse")
        XCTAssertNil(FixtureRequest.replyIdentifier(line: Data("broken-json".utf8)))
        XCTAssertNil(FixtureRequest.replyIdentifier(line: try JSONSerialization.data(withJSONObject: ["id": "secret\ncontent", "op": "status"])))
    }

    func testChildProtocolCannotLaunchOtherExecutablesOrNestChildren() throws {
        XCTAssertNoThrow(try request(["id": "spawn", "op": "spawn_child"]))
        XCTAssertThrowsError(try request(["id": "spawn", "op": "spawn_child", "executablePath": "/bin/sh"]))
        XCTAssertThrowsError(try request(["id": "nested", "op": "child_probe", "pid": 1234, "request": ["op": "spawn_child"]]))
        XCTAssertThrowsError(try request(["id": "nested", "op": "child_probe", "pid": 1234,
                                           "request": ["id": "unexpected", "op": "status"]]))
        let runtime = try FixtureRuntime(isChild: true)
        XCTAssertEqual(runtime.handle(try request(["id": "spawn", "op": "spawn_child"]))["code"] as? String, "CHILD_UNAVAILABLE")
    }

    func testSocketRequiresPrivateCanonicalDirectoryAndNeverOverwrites() throws {
        let directory = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("envara-f-" + String(UUID().uuidString.prefix(8)))
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let canonicalDirectory = directory.resolvingSymlinksInPath()
        let path = canonicalDirectory.appendingPathComponent("acceptance-" + UUID().uuidString + ".sock").path
        XCTAssertEqual(try FixtureSocket.validatePath(path), path)
        let socket = try FixtureSocket(path: path)
        XCTAssertThrowsError(try FixtureSocket(path: path))
        var info = stat(); XCTAssertEqual(lstat(path, &info), 0); XCTAssertEqual(info.st_mode & 0o777, 0o600)
        XCTAssertTrue(socket.removeOwnedSocket())
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: canonicalDirectory.path)
        XCTAssertThrowsError(try FixtureSocket.validatePath(path))
        XCTAssertThrowsError(try FixtureSocket.validatePath(canonicalDirectory.appendingPathComponent("other.sock").path))
        XCTAssertThrowsError(try FixtureSocket.validatePath("/tmp" + path.dropFirst("/private/tmp".count)))
        XCTAssertThrowsError(try FixtureSocket.validatePath(canonicalDirectory.appendingPathComponent("acceptance-" + UUID().uuidString.lowercased() + ".sock").path))
    }

    func testRealSystemResolverProbeUsesOnlyLocalhostOffline() throws {
        let probe = FixtureProbe(), value = try FixtureProbeRequest(["op": "resolve", "host": "localhost", "timeoutMs": 1000])
        let result = try probe.run(value)
        XCTAssertEqual(result["systemGetaddrinfo"] as? Bool, true)
        let addresses = try XCTUnwrap(result["addresses"] as? [String])
        XCTAssertFalse(addresses.isEmpty)
        XCTAssertTrue(addresses.allSatisfy { $0 == "127.0.0.1" || $0 == "::1" })
    }
}
