import Foundation
import Darwin

enum FixtureClock {
    static var now: UInt64 { DispatchTime.now().uptimeNanoseconds }
    static func deadline(milliseconds: Int) -> UInt64 { now + UInt64(milliseconds) * 1_000_000 }
}

enum FixtureIO {
    static func wait(_ fd: Int32, events: Int16, deadline: UInt64) throws {
        while true {
            let now = FixtureClock.now
            guard now < deadline else { throw FixtureFailure.deadline }
            let remaining: Int64 = max(1, min(Int64(Int32.max), Int64((deadline - now + 999_999) / 1_000_000)))
            var descriptor = pollfd(fd: fd, events: events, revents: 0)
            let count = poll(&descriptor, 1, Int32(remaining))
            if count == 0 { throw FixtureFailure.deadline }
            if count < 0 { if errno == EINTR { continue }; throw FixtureFailure.transport }
            if descriptor.revents & Int16(POLLNVAL) != 0 { throw FixtureFailure.transport }
            if descriptor.revents & events != 0 || descriptor.revents & Int16(POLLHUP | POLLERR) != 0 { return }
        }
    }

    static func nonblocking(_ fd: Int32) throws {
        let current = fcntl(fd, F_GETFL)
        guard current >= 0, fcntl(fd, F_SETFL, current | O_NONBLOCK) == 0 else { throw FixtureFailure.transport }
        var enabled: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
    }

    static func write(_ data: Data, fd: Int32, deadline: UInt64) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count > 0 { offset += count; continue }
                if count < 0 && errno == EINTR { continue }
                guard count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) else { throw FixtureFailure.transport }
                try wait(fd, events: Int16(POLLOUT), deadline: deadline)
            }
        }
    }

    /// Reads one bounded line without consuming the next request from a pipe.
    static func line(fd: Int32, deadline: UInt64) throws -> Data? {
        var result = Data()
        while true {
            try wait(fd, events: Int16(POLLIN), deadline: deadline)
            var byte: UInt8 = 0
            let count = Darwin.read(fd, &byte, 1)
            if count == 0 { return nil }
            if count < 0 { if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }; throw FixtureFailure.transport }
            if byte == 10 { return result }
            guard result.count < FixtureProtocol.maximumLineBytes else { throw FixtureFailure.tooLarge }
            result.append(byte)
        }
    }
}

final class FixtureProbe {
    private let resolverCapacity = DispatchSemaphore(value: 2)

    func run(_ request: FixtureProbeRequest, processDeadline: UInt64 = UInt64.max) throws -> [String: Any] {
        let deadline = min(FixtureClock.deadline(milliseconds: request.timeoutMs), processDeadline)
        guard FixtureClock.now < deadline else { throw FixtureFailure.deadline }
        switch request.op {
        case "resolve": return try resolve(request.host!, deadline: deadline)
        case "tcp", "udp": return try socketProbe(request, deadline: deadline)
        default: throw FixtureFailure.invalidRequest
        }
    }

    private final class ResolverResult {
        private let lock = NSLock()
        private var storage: Result<[String], FixtureFailure>?
        func save(_ value: Result<[String], FixtureFailure>) { lock.lock(); defer { lock.unlock() }; storage = value }
        func read() -> Result<[String], FixtureFailure>? { lock.lock(); defer { lock.unlock() }; return storage }
    }

    private func resolve(_ host: String, deadline: UInt64) throws -> [String: Any] {
        guard resolverCapacity.wait(timeout: .now()) == .success else { throw FixtureFailure.deadline }
        let finished = DispatchSemaphore(value: 0), result = ResolverResult(), capacity = resolverCapacity
        // getaddrinfo has no cancellation API. Timed-out workers retain their
        // capacity slot, and the fixture has a hard 120-second process lifetime.
        // Late results are never emitted or mistaken for a successful probe.
        DispatchQueue.global(qos: .utility).async {
            defer { capacity.signal(); finished.signal() }
            var hints = addrinfo(); hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM
            var list: UnsafeMutablePointer<addrinfo>?
            let code = getaddrinfo(host, nil, &hints, &list)
            guard code == 0, let first = list else { result.save(.failure(.transport)); return }
            defer { freeaddrinfo(first) }
            var addresses = Set<String>(), cursor: UnsafeMutablePointer<addrinfo>? = first, inspected = 0
            while let item = cursor, inspected < 64 {
                inspected += 1
                var text = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(item.pointee.ai_addr, item.pointee.ai_addrlen, &text, socklen_t(text.count), nil, 0, NI_NUMERICHOST) == 0 {
                    addresses.insert(String(cString: text))
                    if addresses.count > 16 { result.save(.failure(.tooLarge)); return }
                }
                cursor = item.pointee.ai_next
            }
            guard cursor == nil, !addresses.isEmpty else { result.save(.failure(.tooLarge)); return }
            result.save(.success(addresses.sorted()))
        }
        guard finished.wait(timeout: DispatchTime(uptimeNanoseconds: deadline)) == .success, let value = result.read() else { throw FixtureFailure.deadline }
        return ["systemGetaddrinfo": true, "resolved": true, "addresses": try value.get()]
    }

    private func socketProbe(_ request: FixtureProbeRequest, deadline: UInt64) throws -> [String: Any] {
        var hints = addrinfo(); hints.ai_family = AF_UNSPEC
        hints.ai_socktype = request.op == "udp" ? SOCK_DGRAM : SOCK_STREAM; hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(request.host!, String(request.port!), &hints, &list) == 0, let address = list else { throw FixtureFailure.transport }
        defer { freeaddrinfo(address) }
        let fd = socket(address.pointee.ai_family, address.pointee.ai_socktype, address.pointee.ai_protocol)
        guard fd >= 0 else { throw FixtureFailure.transport }; defer { Darwin.close(fd) }
        try FixtureIO.nonblocking(fd)
        if connect(fd, address.pointee.ai_addr, address.pointee.ai_addrlen) != 0 {
            guard errno == EINPROGRESS || errno == EWOULDBLOCK else { throw FixtureFailure.transport }
            try FixtureIO.wait(fd, events: Int16(POLLOUT), deadline: deadline)
            var error: Int32 = 0, length = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0, error == 0 else { throw FixtureFailure.transport }
        }
        if request.op == "udp" {
            let sent = request.payload.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, $0.count, 0) }
            guard sent == request.payload.count else { throw FixtureFailure.transport }
            try FixtureIO.wait(fd, events: Int16(POLLIN), deadline: deadline)
            var bytes = [UInt8](repeating: 0, count: FixtureProtocol.maximumPayloadBytes + 1)
            let count = recv(fd, &bytes, bytes.count, 0)
            guard count > 0 else { throw FixtureFailure.transport }
            guard count <= FixtureProtocol.maximumPayloadBytes else { throw FixtureFailure.tooLarge }
            let response = Data(bytes.prefix(count))
            return ["sentBytes": sent, "receivedBytes": count, "matches": response == request.payload,
                    "payloadBase64": response.base64EncodedString()]
        }
        try FixtureIO.write(request.payload, fd: fd, deadline: deadline)
        if request.halfClose { guard shutdown(fd, SHUT_WR) == 0 else { throw FixtureFailure.transport } }
        var received = Data(), eof = false
        while request.halfClose || received.count < request.payload.count {
            try FixtureIO.wait(fd, events: Int16(POLLIN), deadline: deadline)
            var bytes = [UInt8](repeating: 0, count: FixtureProtocol.maximumPayloadBytes + 1 - received.count)
            let count = recv(fd, &bytes, bytes.count, 0)
            if count == 0 { eof = true; break }
            if count < 0 { if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }; throw FixtureFailure.transport }
            received.append(contentsOf: bytes.prefix(count))
            guard received.count <= FixtureProtocol.maximumPayloadBytes else { throw FixtureFailure.tooLarge }
        }
        return ["sentBytes": request.payload.count, "receivedBytes": received.count, "matches": received == request.payload,
                "eof": eof, "halfClose": request.halfClose, "payloadBase64": received.base64EncodedString()]
    }
}
