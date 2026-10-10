// PF-only fork of the existing sealed fixture; the NE fixture is unchanged.
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

    /// An unconnected, exclusively bound socket. The map owns this exact FD
    /// until one probe consumes it or it expires/is explicitly released.
    private final class Reservation {
        let id = UUID().uuidString.lowercased()
        let fd: Int32
        let transport: String
        let host: String
        let port: UInt16
        let address: Data
        let localPort: UInt16
        let expires: UInt64
        private var closed = false
        init(fd: Int32, transport: String, host: String, port: UInt16, address: Data, localPort: UInt16, expires: UInt64) {
            self.fd = fd; self.transport = transport; self.host = host; self.port = port
            self.address = address; self.localPort = localPort; self.expires = expires
        }
        func close() { if !closed { closed = true; Darwin.close(fd) } }
        deinit { close() }
    }
    private var reservations: [String: Reservation] = [:]

    func closeReservations() { for reservation in reservations.values { reservation.close() }; reservations.removeAll() }
    private func expireReservations() {
        let expired = reservations.filter { $0.value.expires <= FixtureClock.now }.map { $0.key }
        for key in expired { reservations.removeValue(forKey: key)?.close() }
    }
    var reservationStatus: [String: Any] {
        expireReservations()
        return ["socketReservationProtocol": FixtureProtocol.reservationProtocol,
                "twoPhaseSocketReservations": true, "activeReservations": reservations.count,
                "maximumReservations": FixtureProtocol.maximumReservations,
                "maximumReservationSeconds": Int(FixtureProtocol.reservationSeconds)]
    }
    deinit { closeReservations() }

    func run(_ request: FixtureProbeRequest, processDeadline: UInt64 = UInt64.max) throws -> [String: Any] {
        expireReservations()
        let deadline = min(FixtureClock.deadline(milliseconds: request.timeoutMs), processDeadline)
        guard FixtureClock.now < deadline else { throw FixtureFailure.deadline }
        switch request.op {
        case "resolve": return try resolve(request.host!, deadline: deadline)
        case "tcp", "udp": throw FixtureFailure.reservationRequired
        case "reserve": return try reserve(request, processDeadline: processDeadline)
        case "release_reservation":
            guard let reservation = reservations.removeValue(forKey: request.reservationID!) else { throw FixtureFailure.reservationUnavailable }
            reservation.close()
            return ["reservationId": reservation.id, "released": true, "connected": false, "packetsSent": 0]
        case "probe_reserved":
            guard let reservation = reservations.removeValue(forKey: request.reservationID!) else { throw FixtureFailure.reservationUnavailable }
            defer { reservation.close() }
            guard FixtureClock.now < reservation.expires, reservation.transport == "tcp" || !request.halfClose else { throw FixtureFailure.invalidRequest }
            let started = FixtureClock.now
            var result = try socketProbe(request, reservation: reservation, deadline: min(deadline, reservation.expires))
            let local = try socketTuple(reservation.fd)
            guard local.port == reservation.localPort else { throw FixtureFailure.transport }
            result["reservationId"] = reservation.id; result["consumed"] = true; result["usedReservedSocket"] = true
            result["protocol"] = reservation.transport; result["localHost"] = local.host; result["localPort"] = Int(local.port)
            result["remoteHost"] = reservation.host; result["remotePort"] = Int(reservation.port)
            result["sourceWildcard"] = false; result["sourceAddressResolved"] = true
            result["startedAtNanoseconds"] = String(started); result["finishedAtNanoseconds"] = String(FixtureClock.now)
            return result
        default: throw FixtureFailure.invalidRequest
        }
    }

    private func socketTuple(_ fd: Int32) throws -> (host: String, port: UInt16) {
        var local = sockaddr_storage(), length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let code = withUnsafeMutablePointer(to: &local) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        guard code == 0 else { throw FixtureFailure.transport }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST)), service = [CChar](repeating: 0, count: Int(NI_MAXSERV))
        let named = withUnsafePointer(to: &local) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getnameinfo($0, length, &host, socklen_t(host.count), &service, socklen_t(service.count), NI_NUMERICHOST | NI_NUMERICSERV)
            }
        }
        guard named == 0, let port = UInt16(String(cString: service)), port > 0 else { throw FixtureFailure.transport }
        return (String(cString: host), port)
    }

    private func reserve(_ request: FixtureProbeRequest, processDeadline: UInt64) throws -> [String: Any] {
        guard reservations.count < FixtureProtocol.maximumReservations else { throw FixtureFailure.reservationLimit }
        var hints = addrinfo(); hints.ai_family = AF_INET
        hints.ai_socktype = request.transport! == "udp" ? SOCK_DGRAM : SOCK_STREAM
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(request.host!, String(request.port!), &hints, &list) == 0, let address = list else { throw FixtureFailure.transport }
        defer { freeaddrinfo(address) }
        let fd = socket(AF_INET, hints.ai_socktype, address.pointee.ai_protocol)
        guard fd >= 0 else { throw FixtureFailure.transport }
        var transferred = false
        defer { if !transferred { Darwin.close(fd) } }
        let flags = fcntl(fd, F_GETFD)
        guard flags >= 0, fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0 else { throw FixtureFailure.transport }
        try FixtureIO.nonblocking(fd)
        var local = sockaddr_in(); local.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        local.sin_family = sa_family_t(AF_INET); local.sin_port = 0; local.sin_addr.s_addr = INADDR_ANY
        let bound = withUnsafePointer(to: &local) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0 else { throw FixtureFailure.transport }
        let tuple = try socketTuple(fd)
        guard tuple.host == "0.0.0.0" else { throw FixtureFailure.transport }
        let expires = min(processDeadline, FixtureClock.now + UInt64(FixtureProtocol.reservationSeconds * 1_000_000_000))
        let reservation = Reservation(fd: fd, transport: request.transport!, host: request.host!, port: request.port!,
            address: Data(bytes: address.pointee.ai_addr, count: Int(address.pointee.ai_addrlen)), localPort: tuple.port, expires: expires)
        reservations[reservation.id] = reservation; transferred = true
        // No connect, send, DNS resolution, route mutation or SO_REUSE* occurs.
        // Wildcard source is intentionally unresolved until the eventual connect.
        return ["reservationId": reservation.id, "protocol": reservation.transport,
                "localHost": tuple.host, "localPort": Int(tuple.port), "remoteHost": reservation.host, "remotePort": Int(reservation.port),
                "bound": true, "connected": false, "packetsSent": 0, "sourceWildcard": true, "sourceAddressResolved": false,
                "expiresAtNanoseconds": String(expires), "socketReservationProtocol": FixtureProtocol.reservationProtocol]
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

    private func socketProbe(_ request: FixtureProbeRequest, reservation: Reservation, deadline: UInt64) throws -> [String: Any] {
        let fd = reservation.fd
        let connected = reservation.address.withUnsafeBytes { bytes in
            Darwin.connect(fd, bytes.baseAddress!.assumingMemoryBound(to: sockaddr.self), socklen_t(bytes.count))
        }
        if connected != 0 {
            guard errno == EINPROGRESS || errno == EWOULDBLOCK else { throw FixtureFailure.transport }
            try FixtureIO.wait(fd, events: Int16(POLLOUT), deadline: deadline)
            var error: Int32 = 0, length = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0, error == 0 else { throw FixtureFailure.transport }
        }
        if reservation.transport == "udp" {
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
