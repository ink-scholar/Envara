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
        func stop() { queue.sync { connections.forEach { $0.cancel() }; task?.cancel(); listener.cancel() } }
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
    private func finishWrite(_ connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: nil, contentContext: .finalMessage, isComplete: true,
                            completion: .contentProcessed { error in
                if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
            })
        }
    }
    private func readUntilFIN(_ connection: NWConnection, maximumBytes: Int) async throws -> Data {
        var received = Data()
        while true {
            let result: (Data, Bool) = try await withCheckedThrowingContinuation { continuation in
                connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, complete, error in
                    if let error = error { continuation.resume(throwing: error) }
                    else { continuation.resume(returning: (data ?? Data(), complete)) }
                }
            }
            received += result.0
            guard received.count <= maximumBytes else { throw RoutingError.refused }
            if result.1 { return received }
        }
    }
    private func acceptSOCKS(_ connection: NWConnection, destination: SOCKSEndpoint) async throws {
        let authentication = try SOCKSCodec.authentication(username: "user", password: "ephemeral-local-test")
        let command = try SOCKSCodec.command(1, endpoint: destination)
        let greeting = try await read(connection, 3)
        XCTAssertEqual(greeting, SOCKSCodec.greeting)
        try await write(connection, Data([5, 2]))
        let auth = try await read(connection, authentication.count)
        XCTAssertEqual(auth, authentication)
        try await write(connection, Data([1, 0]))
        let receivedCommand = try await read(connection, command.count)
        XCTAssertEqual(receivedCommand, command)
        try await write(connection, Data([5, 0, 0, 1, 127, 0, 0, 1, 0, 1]))
    }
    private func route(_ port: UInt16) throws -> Route {
        try Route(routeId: UUID().uuidString, vpnUUID: UUID().uuidString, applicationIdentity: "io.envara.test",
                  applicationRequirement: "identifier io.envara.test", applicationPath: "/Test.app",
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
        let route = try Route(routeId: UUID().uuidString, vpnUUID: UUID().uuidString, applicationIdentity: "io.envara.test",
                              applicationRequirement: "identifier io.envara.test", applicationPath: "/Test.app",
                              executablePath: "/Test.app/Contents/MacOS/Test", protocolName: "socks5", host: "127.0.0.1",
                              port: 1, username: "user", password: "ephemeral-local-test", udp: false)
        let socket = try SOCKSTransport(route: route); defer { socket.cancel() }
        do { _ = try await socket.connect(route: route, endpoint: .init(host: "example.test", port: 53), udp: true); XCTFail("UDP should be blocked") }
        catch { XCTAssertTrue(error is RoutingError) }
    }

    func testCancelledTransportCannotStartOrSendAfterClose() async throws {
        let core = try Core(); defer { core.stop() }
        let unexpected = expectation(description: "closed transport opened a socket")
        unexpected.isInverted = true
        let port = try await core.start { _ in unexpected.fulfill() }
        let route = try route(port), socket = try SOCKSTransport(route: route)
        socket.cancel()
        do { _ = try await socket.connect(route: route, endpoint: .init(host: "example.test", port: 443)); XCTFail("Closed transport connected") }
        catch { XCTAssertTrue(error is CancellationError) }
        do { try await socket.write(Data("after-close".utf8)); XCTFail("Closed transport sent data") }
        catch { XCTAssertTrue(error is CancellationError) }
        do { _ = try await socket.readExactly(1); XCTFail("Closed transport registered a read") }
        catch { XCTAssertTrue(error is CancellationError) }
        await fulfillment(of: [unexpected], timeout: 0.15)
    }

    func testTaskCancellationDrainsPendingSOCKSNegotiation() async throws {
        let core = try Core(); defer { core.stop() }
        let greeting = expectation(description: "owned local core received greeting")
        let drained = expectation(description: "cancelled negotiation completed")
        let port = try await core.start { connection in
            do { _ = try await self.read(connection, 3); greeting.fulfill() }
            catch { }
            // Deliberately withhold the server greeting while retaining TCP.
        }
        let route = try route(port), socket = try SOCKSTransport(route: route)
        defer { socket.cancel() }
        let task = Task {
            defer { drained.fulfill() }
            do { _ = try await socket.connect(route: route, endpoint: .init(host: "example.test", port: 443)); XCTFail("Cancelled negotiation completed successfully") }
            catch { }
        }
        await fulfillment(of: [greeting], timeout: 2)
        task.cancel()
        await fulfillment(of: [drained], timeout: 1)
        socket.cancel(); core.stop()
        await task.value
    }

    func testTaskCancellationDrainsActiveAndQueuedTransportReaders() async throws {
        let core = try Core(); defer { core.stop() }
        let destination = SOCKSEndpoint(host: "example.test", port: 443)
        let authentication = try SOCKSCodec.authentication(username: "user", password: "ephemeral-local-test")
        let command = try SOCKSCodec.command(1, endpoint: destination)
        let port = try await core.start { connection in
            do {
                _ = try await self.read(connection, 3); try await self.write(connection, Data([5, 2]))
                _ = try await self.read(connection, authentication.count); try await self.write(connection, Data([1, 0]))
                _ = try await self.read(connection, command.count)
                try await self.write(connection, Data([5, 0, 0, 1, 127, 0, 0, 1, 0, 1]))
            } catch { }
            // No payload: one client reader holds the gate and one awaits it.
        }
        let route = try route(port), socket = try SOCKSTransport(route: route)
        defer { socket.cancel() }
        _ = try await socket.connect(route: route, endpoint: destination)
        let started = expectation(description: "readers started"), drained = expectation(description: "readers drained")
        started.expectedFulfillmentCount = 2; drained.expectedFulfillmentCount = 2
        let readers = (0..<2).map { _ in Task {
            started.fulfill()
            defer { drained.fulfill() }
            do { _ = try await socket.read(); XCTFail("Closed transport returned payload") }
            catch { }
        } }
        await fulfillment(of: [started], timeout: 1)
        readers[1].cancel()
        await fulfillment(of: [drained], timeout: 1)
        core.stop()
        for reader in readers { await reader.value }
    }

    func testWriteFINPreservesEntireResponseSentOnlyAfterFIN() async throws {
        let core = try Core(); defer { core.stop() }
        let destination = SOCKSEndpoint(host: "example.test", port: 443)
        let prefix = Data(repeating: 0x31, count: 1024), captured = Data(repeating: 0x32, count: 64)
        let requestTail = Data((0..<(256 * 1024)).map { UInt8($0 % 251) })
        let responseTail = Data((0..<(512 * 1024)).map { UInt8(($0 + 17) % 253) })
        let finObserved = expectation(description: "real loopback SOCKS peer received client FIN")
        let serverCompleted = expectation(description: "tail sent after client FIN")
        let port = try await core.start { connection in
            defer { serverCompleted.fulfill() }
            do {
                try await self.acceptSOCKS(connection, destination: destination)
                let initial = try await self.read(connection, prefix.count)
                XCTAssertEqual(initial, prefix)
                // This response confirms a real authenticated stream before FIN.
                try await self.write(connection, captured)
                let upload = try await self.readUntilFIN(connection, maximumBytes: requestTail.count)
                XCTAssertEqual(upload, requestTail)
                finObserved.fulfill()
                try await Task.sleep(nanoseconds: 100_000_000)
                // Retain the whole response until EOF; an early echo could hide
                // a missing FIN or an implementation cancelling both directions.
                for offset in stride(from: 0, to: responseTail.count, by: 32768) {
                    try await self.write(connection, responseTail.subdata(in: offset..<(offset + 32768)))
                }
                try await self.finishWrite(connection)
            } catch { XCTFail("Local half-close fixture failed") }
        }
        let route = try route(port), socket = try SOCKSTransport(route: route)
        defer { socket.cancel() }
        let deadline = Task {
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            if !Task.isCancelled { socket.cancel(); core.stop() }
        }
        defer { deadline.cancel() }
        _ = try await socket.connect(route: route, endpoint: destination)
        try await socket.write(prefix)
        let witness = try await socket.readExactly(captured.count)
        XCTAssertEqual(witness, captured)
        for offset in stride(from: 0, to: requestTail.count, by: 32768) {
            try await socket.write(requestTail.subdata(in: offset..<(offset + 32768)))
        }
        socket.closeWrite(); socket.closeWrite()
        var received = Data()
        while true {
            let bytes = try await socket.read(maximum: 16384)
            if bytes.isEmpty { break }
            received += bytes
        }
        XCTAssertEqual(received, responseTail)
        await fulfillment(of: [finObserved, serverCompleted], timeout: 1)
        do { try await socket.write(Data([0x99])); XCTFail("Write after FIN was accepted") }
        catch { XCTAssertTrue(error is RoutingError) }
        let repeatedEOF = try await socket.read()
        XCTAssertTrue(repeatedEOF.isEmpty)
    }

    func testPeerFINPreservesLocalWriteDirection() async throws {
        let core = try Core(); defer { core.stop() }
        let destination = SOCKSEndpoint(host: "example.test", port: 443)
        let response = Data("peer-response-before-FIN".utf8), upload = Data(repeating: 0x47, count: 65536)
        let serverCompleted = expectation(description: "peer read upload after closing its write direction")
        let port = try await core.start { connection in
            defer { serverCompleted.fulfill() }
            do {
                try await self.acceptSOCKS(connection, destination: destination)
                try await self.write(connection, response)
                try await self.finishWrite(connection)
                let bytes = try await self.readUntilFIN(connection, maximumBytes: upload.count)
                XCTAssertEqual(bytes, upload)
            } catch { XCTFail("Reverse half-close fixture failed") }
        }
        let route = try route(port), socket = try SOCKSTransport(route: route)
        defer { socket.cancel() }
        let deadline = Task {
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            if !Task.isCancelled { socket.cancel(); core.stop() }
        }
        defer { deadline.cancel() }
        _ = try await socket.connect(route: route, endpoint: destination)
        let payload = try await socket.readExactly(response.count)
        XCTAssertEqual(payload, response)
        let eof = try await socket.read()
        XCTAssertTrue(eof.isEmpty)
        try await socket.write(upload)
        socket.closeWrite()
        await fulfillment(of: [serverCompleted], timeout: 2)
    }

    func testCancelAfterWriteFINDrainsPendingRead() async throws {
        let core = try Core(); defer { core.stop() }
        let destination = SOCKSEndpoint(host: "example.test", port: 443)
        let port = try await core.start { connection in
            do { try await self.acceptSOCKS(connection, destination: destination) }
            catch { }
            // Keep the peer's read direction alive without a response.
        }
        let route = try route(port), socket = try SOCKSTransport(route: route)
        defer { socket.cancel() }
        _ = try await socket.connect(route: route, endpoint: destination)
        let started = expectation(description: "pending read started"), drained = expectation(description: "pending read cancelled")
        let reader = Task {
            started.fulfill()
            defer { drained.fulfill() }
            do { _ = try await socket.read(); XCTFail("Cancelled half-closed transport returned data") }
            catch { }
        }
        await fulfillment(of: [started], timeout: 1)
        socket.closeWrite(); socket.cancel(); socket.closeWrite(); socket.cancel()
        await fulfillment(of: [drained], timeout: 1)
        core.stop()
        await reader.value
    }
}
