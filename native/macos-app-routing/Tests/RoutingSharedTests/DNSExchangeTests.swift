import Foundation
import Network
import XCTest
@testable import RoutingShared

final class DNSExchangeTests: XCTestCase {
    private final class Core {
        let listener: NWListener
        let queue = DispatchQueue(label: "envara.test.dns-core")
        var connections = [NWConnection]()
        var tasks = [Task<Void, Never>]()
        var ready = false
        init() throws {
            let parameters = NWParameters.tcp
            parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
            listener = try NWListener(using: parameters)
        }
        func start(_ handle: @escaping (NWConnection) async -> Void) async throws -> UInt16 {
            listener.newConnectionHandler = { connection in
                self.connections.append(connection); connection.start(queue: self.queue)
                self.tasks.append(Task { await handle(connection) })
            }
            return try await withCheckedThrowingContinuation { continuation in
                listener.stateUpdateHandler = { state in
                    guard !self.ready else { return }
                    switch state {
                    case .ready: self.ready = true; continuation.resume(returning: self.listener.port!.rawValue)
                    case .failed(let error): self.ready = true; continuation.resume(throwing: error)
                    default: break
                    }
                }
                listener.start(queue: queue)
            }
        }
        func stop() { queue.sync { connections.forEach { $0.cancel() }; tasks.forEach { $0.cancel() }; listener.cancel() } }
    }
    private let destination = SOCKSEndpoint(host: "198.51.100.53", port: 53)
    private func read(_ connection: NWConnection, _ count: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
                if let data = data, data.count == count { continuation.resume(returning: data) }
                else { continuation.resume(throwing: error ?? RoutingError.refused) }
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
    private func accept(_ connection: NWConnection) async throws -> Data {
        let greeting = try await read(connection, 3); XCTAssertEqual(greeting, SOCKSCodec.greeting)
        try await write(connection, Data([5, 2]))
        let expected = try SOCKSCodec.authentication(username: "fixture", password: "ephemeral-owned-test")
        let authentication = try await read(connection, expected.count); XCTAssertEqual(authentication, expected)
        try await write(connection, Data([1, 0]))
        let command = try SOCKSCodec.command(1, endpoint: destination)
        let actualCommand = try await read(connection, command.count); XCTAssertEqual(actualCommand, command)
        try await write(connection, Data([5, 0, 0, 1, 127, 0, 0, 1, 0, 1]))
        let size = try await read(connection, 2)
        return try await read(connection, Int(size[0]) << 8 | Int(size[1]))
    }
    private func route(_ port: UInt16) throws -> Route {
        try Route(routeId: UUID().uuidString, vpnUUID: UUID().uuidString, applicationIdentity: "io.envara.dns-test",
                  applicationRequirement: "identifier io.envara.dns-test", applicationPath: "/Test.app",
                  executablePath: "/Test.app/Contents/MacOS/Test", protocolName: "socks5", host: "127.0.0.1",
                  port: port, username: "fixture", password: "ephemeral-owned-test", udp: false)
    }
    private func query() -> Data {
        var data = Data([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        for label in ["fixture", "envara", "test"] { data.append(UInt8(label.count)); data.append(contentsOf: label.utf8) }
        data.append(contentsOf: [0, 0, 1, 0, 1]); return data
    }
    private func response(_ question: Data) -> Data {
        var data = question; data[2] = 0x81; data[3] = 0x80; data[7] = 1
        data.append(contentsOf: [0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 203, 0, 113, 42]); return data
    }
    private func framed(_ data: Data) -> Data { Data([UInt8(data.count >> 8), UInt8(data.count & 255)]) + data }

    func testRawUDPSourceCannotBypassValidatedDNSExchange() {
        XCTAssertFalse(DNSExchange.permitsRawDatagramSource(.init(host: "198.51.100.53", port: 53)))
        XCTAssertFalse(DNSExchange.permitsRawDatagramSource(.init(host: "resolver.example.test", port: 53)))
        XCTAssertTrue(DNSExchange.permitsRawDatagramSource(.init(host: "198.51.100.44", port: 443)))
        XCTAssertTrue(DNSExchange.permitsRawDatagramSource(.init(host: "2001:db8::42", port: 5353)))
    }

    func testAuthenticatedLocalExchangePreservesFragmentedResponse() async throws {
        let core = try Core(); defer { core.stop() }
        let question = query(), answer = response(query()), completed = expectation(description: "owned DNS core replied")
        let port = try await core.start { connection in
            defer { completed.fulfill() }
            do {
                let received = try await self.accept(connection); XCTAssertEqual(received, question)
                let bytes = self.framed(answer)
                try await self.write(connection, bytes.prefix(1))
                try await self.write(connection, bytes.subdata(in: 1..<9))
                try await self.write(connection, bytes.subdata(in: 9..<bytes.count))
            } catch { XCTFail("Owned DNS core fixture failed") }
        }
        let actual = try await DNSExchange.response(for: question, route: route(port), endpoint: destination, timeoutMilliseconds: 1000)
        XCTAssertEqual(actual, answer)
        await fulfillment(of: [completed], timeout: 2)
    }

    func testMatchingTransactionCannotAcceptDifferentQuestionType() async throws {
        let core = try Core(); defer { core.stop() }
        let question = query(), completed = expectation(description: "wrong question reply sent")
        let port = try await core.start { connection in
            defer { completed.fulfill() }
            do {
                _ = try await self.accept(connection)
                var answer = self.response(question); answer[question.count - 3] = 28
                try await self.write(connection, self.framed(answer))
            } catch { XCTFail("Owned DNS mismatch fixture failed") }
        }
        do { _ = try await DNSExchange.response(for: question, route: route(port), endpoint: destination, timeoutMilliseconds: 1000); XCTFail("Wrong question was accepted") }
        catch { XCTAssertEqual(error as? DNSWireError, .questionMismatch) }
        await fulfillment(of: [completed], timeout: 2)
    }

    func testDeadlineCancelsARealPartialDNSBodyAndClosesOwnedTransport() async throws {
        let core = try Core(); defer { core.stop() }
        let question = query(), received = expectation(description: "partial response sent"), closed = expectation(description: "deadline closed owned DNS socket")
        let port = try await core.start { connection in
            do {
                _ = try await self.accept(connection)
                let bytes = self.framed(self.response(question))
                try await self.write(connection, bytes.prefix(7)); received.fulfill()
                let eof: Bool = try await withCheckedThrowingContinuation { continuation in
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 1) { _, _, complete, error in
                        continuation.resume(returning: complete || error != nil)
                    }
                }
                XCTAssertTrue(eof); closed.fulfill()
            } catch { XCTFail("Owned stalled DNS fixture failed") }
        }
        let started = Date()
        do { _ = try await DNSExchange.response(for: question, route: route(port), endpoint: destination, timeoutMilliseconds: 200); XCTFail("Stalled DNS reply completed") }
        catch { XCTAssertEqual(error as? DNSExchangeError, .deadline) }
        XCTAssertLessThan(Date().timeIntervalSince(started), 1.5)
        await fulfillment(of: [received, closed], timeout: 2)
    }
}
