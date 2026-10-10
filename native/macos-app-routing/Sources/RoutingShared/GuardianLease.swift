import Foundation
import Darwin

public enum GuardianLeaseError: Error, Equatable {
    case invalidClock, invalidLease, sequenceExhausted, system(Int32)
}

/// A boot-specific clock shared by the helper and provider. Continuous time
/// includes sleep, so an old heartbeat cannot become fresh after wake.
public struct GuardianLeaseClock: Codable, Equatable {
    public let bootSessionUUID: String
    public let continuousNanoseconds: UInt64

    public init(bootSessionUUID: String, continuousNanoseconds: UInt64) throws {
        guard let boot = RealmValidation.canonicalUUID(bootSessionUUID) else { throw GuardianLeaseError.invalidClock }
        self.bootSessionUUID = boot
        self.continuousNanoseconds = continuousNanoseconds
    }

    public func validate() throws {
        guard RealmValidation.canonicalUUID(bootSessionUUID) == bootSessionUUID else { throw GuardianLeaseError.invalidClock }
    }

    public static func sample() throws -> GuardianLeaseClock {
        var length = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &length, nil, 0) == 0,
              length > 1, length <= 128 else { throw GuardianLeaseError.system(errno == 0 ? EIO : errno) }
        var bytes = [CChar](repeating: 0, count: length)
        let result = bytes.withUnsafeMutableBytes { sysctlbyname("kern.bootsessionuuid", $0.baseAddress, &length, nil, 0) }
        guard result == 0, length > 1, length <= bytes.count,
              bytes[Int(length) - 1] == 0 else { throw GuardianLeaseError.system(errno == 0 ? EIO : errno) }
        var timebase = mach_timebase_info_data_t()
        guard mach_timebase_info(&timebase) == KERN_SUCCESS, timebase.numer > 0, timebase.denom > 0 else {
            throw GuardianLeaseError.invalidClock
        }
        let ticks = mach_continuous_time(), numerator = UInt64(timebase.numer), denominator = UInt64(timebase.denom)
        let (whole, wholeOverflow) = (ticks / denominator).multipliedReportingOverflow(by: numerator)
        let fractional = (ticks % denominator) * numerator / denominator
        let (nanoseconds, sumOverflow) = whole.addingReportingOverflow(fractional)
        guard !wholeOverflow, !sumOverflow else { throw GuardianLeaseError.invalidClock }
        return try GuardianLeaseClock(bootSessionUUID: String(cString: bytes), continuousNanoseconds: nanoseconds)
    }
}

public enum GuardianLeaseState: String, Codable {
    case active, closed
}

public enum GuardianLeaseInvalidity: Equatable {
    case malformed, mismatchedRoute, mismatchedRealm, mismatchedSession, mismatchedGuardian
    case bootChanged, clockAhead, replayed
}

public enum GuardianLeaseDecision: Equatable {
    case ready, expired, closed, guardianGone
    case invalid(GuardianLeaseInvalidity)
    case unknown(ProcessProbeFailure)
}

/// A lease is a bounded authorization for an already bound route/session. It is
/// not proof of platform acceptance, process-family coverage or an OS sandbox.
/// There is deliberately no startup/prepared state that permits traffic.
public struct GuardianLease: Codable, Equatable {
    public static let maximumTTLNanoseconds: UInt64 = 3_000_000_000

    public let routeId: String
    public let vpnUUID: String
    public let sessionId: String
    public let guardian: ProcessIdentity
    public let state: GuardianLeaseState
    public let sequence: UInt64
    public let created: GuardianLeaseClock
    public let renewed: GuardianLeaseClock
    public let ttlNanoseconds: UInt64

    public init(routeId: String, vpnUUID: String, sessionId: String, guardian: ProcessIdentity,
                state: GuardianLeaseState = .active, sequence: UInt64 = 0,
                created: GuardianLeaseClock, renewed: GuardianLeaseClock,
                ttlNanoseconds: UInt64 = maximumTTLNanoseconds) throws {
        guard let route = RealmValidation.canonicalUUID(routeId),
              let realm = RealmValidation.canonicalUUID(vpnUUID),
              let session = RealmValidation.canonicalUUID(sessionId) else { throw GuardianLeaseError.invalidLease }
        self.routeId = route; self.vpnUUID = realm; self.sessionId = session
        self.guardian = guardian; self.state = state; self.sequence = sequence
        self.created = created; self.renewed = renewed; self.ttlNanoseconds = ttlNanoseconds
        try validate()
    }

    public func validate() throws {
        try created.validate(); try renewed.validate()
        guard RealmValidation.canonicalUUID(routeId) == routeId,
              RealmValidation.canonicalUUID(vpnUUID) == vpnUUID,
              RealmValidation.canonicalUUID(sessionId) == sessionId,
              guardian.pid > 0, guardian.parent >= 0, guardian.group > 0,
              guardian.startedSeconds > 0, guardian.startedMicroseconds < 1_000_000,
              RealmValidation.executablePath(guardian.path),
              created.bootSessionUUID == renewed.bootSessionUUID,
              renewed.continuousNanoseconds >= created.continuousNanoseconds,
              ttlNanoseconds > 0, ttlNanoseconds <= Self.maximumTTLNanoseconds else {
            throw GuardianLeaseError.invalidLease
        }
    }

    public func renewed(at clock: GuardianLeaseClock) throws -> GuardianLease {
        guard state == .active, clock.continuousNanoseconds >= renewed.continuousNanoseconds,
              clock.continuousNanoseconds - renewed.continuousNanoseconds < ttlNanoseconds else {
            throw GuardianLeaseError.invalidLease
        }
        return try successor(state: .active, at: clock)
    }

    public func closed(at clock: GuardianLeaseClock) throws -> GuardianLease {
        guard state == .active else { throw GuardianLeaseError.invalidLease }
        return try successor(state: .closed, at: clock)
    }

    private func successor(state: GuardianLeaseState, at clock: GuardianLeaseClock) throws -> GuardianLease {
        try validate(); try clock.validate()
        guard clock.bootSessionUUID == renewed.bootSessionUUID,
              clock.continuousNanoseconds >= renewed.continuousNanoseconds else { throw GuardianLeaseError.invalidClock }
        let (next, overflow) = sequence.addingReportingOverflow(1)
        guard !overflow else { throw GuardianLeaseError.sequenceExhausted }
        return try GuardianLease(routeId: routeId, vpnUUID: vpnUUID, sessionId: sessionId, guardian: guardian,
                                 state: state, sequence: next, created: created, renewed: clock,
                                 ttlNanoseconds: ttlNanoseconds)
    }

    /// Only .ready permits traffic. Every other result is a reason to close
    /// owned flows, while retaining the exact OS application mapping.
    /// `previous` is the provider's last accepted lease, not a caller baseline.
    /// Reading the identical sequence is allowed until its original expiration;
    /// a changed record with that sequence, a lower sequence, or reopening a
    /// closed session never extends the authorization.
    public func evaluate(expectedRouteId: String, expectedVPNUUID: String, expectedSessionId: String,
                         expectedGuardian: ProcessIdentity, now: GuardianLeaseClock,
                         previous: GuardianLease? = nil, probe: ProcessProbe = ProcessIdentity.inspect) -> GuardianLeaseDecision {
        guard (try? validate()) != nil, (try? now.validate()) != nil else { return .invalid(.malformed) }
        guard routeId == RealmValidation.canonicalUUID(expectedRouteId) else { return .invalid(.mismatchedRoute) }
        guard vpnUUID == RealmValidation.canonicalUUID(expectedVPNUUID) else { return .invalid(.mismatchedRealm) }
        guard sessionId == RealmValidation.canonicalUUID(expectedSessionId) else { return .invalid(.mismatchedSession) }
        guard guardian == expectedGuardian else { return .invalid(.mismatchedGuardian) }
        guard now.bootSessionUUID == created.bootSessionUUID else { return .invalid(.bootChanged) }
        guard renewed.continuousNanoseconds <= now.continuousNanoseconds else { return .invalid(.clockAhead) }
        if let previous = previous {
            guard (try? previous.validate()) != nil,
                  previous.routeId == routeId, previous.vpnUUID == vpnUUID,
                  previous.sessionId == sessionId, previous.guardian == guardian,
                  previous.created == created, previous.ttlNanoseconds == ttlNanoseconds,
                  sequence >= previous.sequence,
                  renewed.continuousNanoseconds >= previous.renewed.continuousNanoseconds,
                  (sequence != previous.sequence || self == previous),
                  (previous.state != .closed || self == previous) else { return .invalid(.replayed) }
        }
        if state == .closed { return .closed }
        // Subtraction after the clock order check avoids unsigned wraparound.
        if now.continuousNanoseconds - renewed.continuousNanoseconds >= ttlNanoseconds { return .expired }
        switch probe(guardian.pid, guardian) {
        case .gone: return .guardianGone
        case .unknown(let reason): return .unknown(reason)
        case .found(let actual):
            guard actual.pid == guardian.pid else { return .unknown(.invalidPID) }
            if actual.startedSeconds != guardian.startedSeconds || actual.startedMicroseconds != guardian.startedMicroseconds {
                return .guardianGone
            }
            // A moved group or executable with unchanged birth is uncertainty,
            // never a reusable guardian identity or proof that it exited.
            guard actual.group == guardian.group, actual.path == guardian.path else { return .unknown(.identityChanged) }
            return .ready
        }
    }
}

public extension RuntimeStore {
    func writeGuardianLease(_ lease: GuardianLease) throws {
        try lease.validate()
        try writePrivate(JSONEncoder().encode(lease), to: url(lease.routeId, suffix: "lease"))
    }

    func readGuardianLease(_ routeId: String) throws -> GuardianLease {
        let lease = try JSONDecoder().decode(GuardianLease.self, from: readPrivate(url(routeId, suffix: "lease")))
        try lease.validate()
        guard lease.routeId == RealmValidation.canonicalUUID(routeId) else { throw GuardianLeaseError.invalidLease }
        return lease
    }

    func removeGuardianLease(_ routeId: String) throws {
        try FileManager.default.removeItem(at: url(routeId, suffix: "lease"))
    }
}
