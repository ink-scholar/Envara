import Foundation
import Network
import XCTest
@testable import RoutingShared

final class SOCKSTransportTests: XCTestCase {
    private final class Core {
        let listener: NWListener
        let queue = DispatchQueue(label: "envara.test.socks")
        var connections = [NWConnection]()
        var task: Task<Void, Never>?
        var startCompleted = false
        init() throws {
            let parameters = NWParameters.tcp
            parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
            listener = try NWListener(using: parameters)
        }
        func start(_ handler: @escaping (NWConnection) async -> Void) async throws -> UInt16 {
            listener.newConnectionHandler = { connection in
                self.connections.append(connection); connection.start(queue: self.queue)
                self.task = Task { await handler(connection) }
            }
            return try await withCheckedThrowingContinuation { continuation in
                listener.stateUpdateHandler = { state in
                    guard !self.startCompleted else { return }
                    switch state {
                    case .ready: self.startCompleted = true; continuation.resume(returning: self.listener.port!.rawValue)
                    case .failed(let error): self.startCompleted = true; continuation.resume(throwing: error)
                    default: break
                    }
                }
                listener.start(queue: queue)
            }
        }
        func stop() { connections.forEach { $0.cancel() }; task?.cancel(); listener.cancel() }
    }

    private func read(_ connection: NWConnection, _ count: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
                if let error = error { continuation.resume(throwing: error) }
                else if let data = data, data.count == count { continuation.resume(returning: data) }
                else { continuation.resume(throwing: RoutingError.refused) }
            }
        }
    }
    private func write(_ connection: NWConnection, _ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
            })
        }
    }
    private func route(_ port: UInt16) throws -> Route {
        try Route(routeId: UUID().uuidString, applicationIdentity: "io.envara.test", applicationPath: "/Test.app",
                  executablePath: "/Test.app/Contents/MacOS/Test", protocolName: "socks5", host: "127.0.0.1",
                  port: port, username: "user", password: "ephemeral-local-test", udp: true)
    }

    func testAuthenticatedSOCKSNameForwardingWithCoalescedPayload() async throws {
        let core = try Core(); defer { core.stop() }
        let serverCompleted = expectation(description: "SOCKS server completed")
        let destination = SOCKSEndpoint(host: "example.test", port: 443)
        let command = try SOCKSCodec.command(1, endpoint: destination)
        let auth = try SOCKSCodec.authentication(username: "user", password: "ephemeral-local-test")
        let port = try await core.start { connection in
            defer { serverCompleted.fulfill() }
            do {
                let greeting = try await self.read(connection, 3)
                XCTAssertEqual(greeting, SOCKSCodec.greeting)
                try await self.write(connection, Data([5, 2]))
                let authentication = try await self.read(connection, auth.count)
                XCTAssertEqual(authentication, auth)
                try await self.write(connection, Data([1, 0]))
                let receivedCommand = try await self.read(connection, command.count)
                XCTAssertEqual(receivedCommand, command)
                // The payload arrives in the same TCP receive as the reply; it must
                // survive exact-size negotiation reads and appear once to the app.
                try await self.write(connection, Data([5, 0, 0, 1, 127, 0, 0, 1, 0, 1]) + Data("response".utf8))
            } catch { XCTFail("Local SOCKS fixture failed") }
        }
        let route = try route(port), socket = try SOCKSTransport(route: route)
        defer { socket.cancel() }
        _ = try await socket.connect(route: route, endpoint: destination)
        let payload = try await socket.readExactly(8)
        XCTAssertEqual(payload, Data("response".utf8))
        await fulfillment(of: [serverCompleted], timeout: 5)
    }

    func testAuthenticationRejectionDoesNotTryUnauthenticatedConnect() async throws {
        let core = try Core(); defer { core.stop() }
        let port = try await core.start { connection in
            do {
                _ = try await self.read(connection, 3)
                try await self.write(connection, Data([5, 0]))
            } catch { }
        }
        let route = try route(port), socket = try SOCKSTransport(route: route)
        defer { socket.cancel() }
        do { _ = try await socket.connect(route: route, endpoint: .init(host: "example.test", port: 443)); XCTFail("Authentication downgrade was accepted") }
        catch { XCTAssertTrue(error is RoutingError) }
    }

    func testUDPDisabledRejectsBeforeOpeningTransport() async throws {
        let route = try Route(routeId: UUID().uuidString, applicationIdentity: "io.envara.test", applicationPath: "/Test.app",
                              executablePath: "/Test.app/Contents/MacOS/Test", protocolName: "socks5", host: "127.0.0.1",
                              port: 1, username: "user", password: "ephemeral-local-test", udp: false)
        let socket = try SOCKSTransport(route: route); defer { socket.cancel() }
        do { _ = try await socket.connect(route: route, endpoint: .init(host: "example.test", port: 53), udp: true); XCTFail("UDP should be blocked") }
        catch { XCTAssertTrue(error is RoutingError) }
    }
}
