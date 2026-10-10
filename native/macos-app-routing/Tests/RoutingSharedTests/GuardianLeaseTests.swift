import Foundation
import XCTest
import Darwin
@testable import RoutingShared

final class GuardianLeaseTests: XCTestCase {
    private let boot = "11111111-1111-4111-8111-111111111111"
    private let otherBoot = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
    private let route = "22222222-2222-4222-8222-222222222222"
    private let realm = "33333333-3333-4333-8333-333333333333"
    private let session = "44444444-4444-4444-8444-444444444444"
    private let anotherID = "55555555-5555-4555-8555-555555555555"
    private let second: UInt64 = 1_000_000_000

    private func clock(_ nanoseconds: UInt64, boot: String? = nil) throws -> GuardianLeaseClock {
        try GuardianLeaseClock(bootSessionUUID: boot ?? self.boot, continuousNanoseconds: nanoseconds)
    }

    private func guardian(pid: Int32 = 900, group: Int32 = 900, seconds: UInt64 = 1_800_000_000,
                          microseconds: UInt64 = 7, path: String = "/Applications/EnvaraAppRouting.app/Contents/MacOS/EnvaraAppRoutingHelper") -> ProcessIdentity {
        ProcessIdentity(pid: pid, parent: 700, group: group, startedSeconds: seconds,
                        startedMicroseconds: microseconds, path: path)
    }

    private func lease(renewed: UInt64 = 100_000_000_000, sequence: UInt64 = 0,
                       state: GuardianLeaseState = .active, ttl: UInt64 = GuardianLease.maximumTTLNanoseconds,
                       sessionId: String? = nil) throws -> GuardianLease {
        try GuardianLease(routeId: route, vpnUUID: realm, sessionId: sessionId ?? session, guardian: guardian(),
                          state: state, sequence: sequence, created: clock(100 * second),
                          renewed: clock(renewed), ttlNanoseconds: ttl)
    }

    private func decision(_ lease: GuardianLease, at nanoseconds: UInt64, previous: GuardianLease? = nil,
                          boot: String? = nil, result: ProcessProbeResult? = nil) throws -> GuardianLeaseDecision {
        let actual = result ?? .found(guardian())
        return lease.evaluate(expectedRouteId: route, expectedVPNUUID: realm, expectedSessionId: session,
                              expectedGuardian: guardian(), now: try clock(nanoseconds, boot: boot),
                              previous: previous, probe: { pid, baseline in
                                  XCTAssertEqual(pid, 900)
                                  XCTAssertEqual(baseline, self.guardian())
                                  return actual
                              })
    }

    // All liveness results here are injected. No scoped application is launched,
    // signaled or routed, and these tests do not establish native crash safety.
    func testFreshLeaseRequiresExactGuardianProbe() throws {
        let initial = try lease()
        XCTAssertEqual(try decision(initial, at: 100 * second), .ready)
        XCTAssertEqual(try decision(initial, at: 103 * second - 1), .ready)
        XCTAssertEqual(try JSONDecoder().decode(GuardianLease.self, from: JSONEncoder().encode(initial)), initial)
    }

    func testExpiryAtExactTTLDoesNotProbeOrExtendLease() throws {
        let initial = try lease()
        var probes = 0
        let result = initial.evaluate(expectedRouteId: route, expectedVPNUUID: realm, expectedSessionId: session,
                                      expectedGuardian: guardian(), now: try clock(103 * second),
                                      previous: initial, probe: { _, _ in probes += 1; return .found(self.guardian()) })
        XCTAssertEqual(result, .expired)
        XCTAssertEqual(probes, 0)
        XCTAssertEqual(try decision(initial, at: 1_000 * second, previous: initial), .expired)
    }

    func testSleepSizedContinuousClockJumpExpiresLease() throws {
        XCTAssertEqual(try decision(lease(), at: 3_700 * second), .expired)
    }

    func testConfirmedExitAndReusedBirthRejectBeforeTraffic() throws {
        let initial = try lease()
        XCTAssertEqual(try decision(initial, at: 101 * second, result: .gone), .guardianGone)
        XCTAssertEqual(try decision(initial, at: 101 * second, result: .found(guardian(seconds: 1_800_000_001))), .guardianGone)
        XCTAssertEqual(try decision(initial, at: 101 * second, result: .found(guardian(microseconds: 8))), .guardianGone)
    }

    func testUnknownIdentityCannotBecomeFreshAuthorization() throws {
        for reason in [ProcessProbeFailure.system(EACCES), .system(ETIMEDOUT), .truncated, .foreignUser, .identityChanged] {
            XCTAssertEqual(try decision(lease(), at: 101 * second, result: .unknown(reason)), .unknown(reason))
        }
    }

    func testUnchangedBirthWithDifferentGroupOrExecutableStaysUnknown() throws {
        XCTAssertEqual(try decision(lease(), at: 101 * second, result: .found(guardian(group: 901))), .unknown(.identityChanged))
        XCTAssertEqual(try decision(lease(), at: 101 * second,
                                    result: .found(guardian(path: "/Applications/Other.app/Contents/MacOS/Other"))), .unknown(.identityChanged))
        XCTAssertEqual(try decision(lease(), at: 101 * second, result: .found(guardian(pid: 901))), .unknown(.invalidPID))
    }

    func testBootMismatchAndFutureHeartbeatNeverProbe() throws {
        let initial = try lease()
        XCTAssertEqual(try decision(initial, at: 101 * second, boot: otherBoot), .invalid(.bootChanged))
        XCTAssertEqual(try decision(initial, at: 100 * second - 1), .invalid(.clockAhead))
        let futureRenewal = try initial.renewed(at: clock(101 * second))
        XCTAssertEqual(try decision(futureRenewal, at: 101 * second - 1), .invalid(.clockAhead))
    }

    func testRouteRealmSessionAndGuardianMustMatchBinding() throws {
        let initial = try lease(), now = try clock(101 * second)
        let probe: ProcessProbe = { _, _ in XCTFail("Rejected binding must not inspect a process"); return .gone }
        XCTAssertEqual(initial.evaluate(expectedRouteId: anotherID, expectedVPNUUID: realm, expectedSessionId: session,
                                        expectedGuardian: guardian(), now: now, probe: probe), .invalid(.mismatchedRoute))
        XCTAssertEqual(initial.evaluate(expectedRouteId: route, expectedVPNUUID: anotherID, expectedSessionId: session,
                                        expectedGuardian: guardian(), now: now, probe: probe), .invalid(.mismatchedRealm))
        XCTAssertEqual(initial.evaluate(expectedRouteId: route, expectedVPNUUID: realm, expectedSessionId: anotherID,
                                        expectedGuardian: guardian(), now: now, probe: probe), .invalid(.mismatchedSession))
        XCTAssertEqual(initial.evaluate(expectedRouteId: route, expectedVPNUUID: realm, expectedSessionId: session,
                                        expectedGuardian: guardian(microseconds: 8), now: now, probe: probe), .invalid(.mismatchedGuardian))
    }

    func testUnchangedRecordMayBeRereadButCannotExtendExpiry() throws {
        let initial = try lease()
        XCTAssertEqual(try decision(initial, at: 102 * second, previous: initial), .ready)
        XCTAssertEqual(try decision(initial, at: 103 * second, previous: initial), .expired)
    }

    func testReplayCannotAlterTimestampAtSameSequence() throws {
        let initial = try lease(), altered = try lease(renewed: 101 * second)
        XCTAssertEqual(try decision(altered, at: 102 * second, previous: initial), .invalid(.replayed))
        let future = try lease(renewed: 102 * second, sequence: 2)
        XCTAssertEqual(try decision(initial, at: 102 * second, previous: future), .invalid(.replayed))
    }

    func testValidRenewalAcceptsSequenceGapsButNotTimestampRegression() throws {
        let initial = try lease()
        let next = try initial.renewed(at: clock(101 * second))
        XCTAssertEqual(next.sequence, 1)
        XCTAssertEqual(next.created, initial.created)
        XCTAssertEqual(try decision(next, at: 102 * second, previous: initial), .ready)
        let later = try lease(renewed: 102 * second, sequence: 8)
        XCTAssertEqual(try decision(later, at: 102 * second, previous: initial), .ready)
        let reversed = try lease(renewed: 101 * second, sequence: 9)
        XCTAssertEqual(try decision(reversed, at: 102 * second, previous: later), .invalid(.replayed))
    }

    func testLateRenewalAndSequenceOverflowCannotReviveAuthorization() throws {
        let initial = try lease()
        XCTAssertThrowsError(try initial.renewed(at: clock(103 * second)))
        XCTAssertThrowsError(try initial.renewed(at: clock(104 * second)))
        XCTAssertThrowsError(try initial.renewed(at: clock(100 * second - 1)))
        XCTAssertThrowsError(try initial.renewed(at: clock(101 * second, boot: otherBoot)))
        let exhausted = try lease(sequence: UInt64.max)
        XCTAssertThrowsError(try exhausted.renewed(at: clock(101 * second))) {
            XCTAssertEqual($0 as? GuardianLeaseError, .sequenceExhausted)
        }
    }

    func testClosedLeaseRemainsTerminalAndNeverProbes() throws {
        let initial = try lease(), closed = try initial.closed(at: clock(104 * second))
        XCTAssertEqual(closed.state, .closed)
        XCTAssertEqual(closed.sequence, 1)
        XCTAssertEqual(try decision(closed, at: 104 * second, previous: initial, result: .unknown(.system(EACCES))), .closed)
        XCTAssertEqual(try decision(closed, at: 105 * second, previous: closed), .closed)
        XCTAssertThrowsError(try closed.renewed(at: clock(105 * second)))
        let reopened = try lease(renewed: 105 * second, sequence: 2)
        XCTAssertEqual(try decision(reopened, at: 105 * second, previous: closed), .invalid(.replayed))
    }

    func testChangingCreatedGenerationOrTTLIsAReplay() throws {
        let initial = try lease()
        let differentCreated = try GuardianLease(routeId: route, vpnUUID: realm, sessionId: session, guardian: guardian(),
                                                 sequence: 1, created: clock(101 * second), renewed: clock(102 * second))
        XCTAssertEqual(try decision(differentCreated, at: 102 * second, previous: initial), .invalid(.replayed))
        let shorter = try lease(renewed: 101 * second, sequence: 1, ttl: second)
        XCTAssertEqual(try decision(shorter, at: 101 * second, previous: initial), .invalid(.replayed))
    }

    func testNewSessionCannotInheritPreviouslyAcceptedLease() throws {
        let initial = try lease(), newSession = try lease(sessionId: anotherID)
        XCTAssertEqual(newSession.evaluate(expectedRouteId: route, expectedVPNUUID: realm, expectedSessionId: anotherID,
                                          expectedGuardian: guardian(), now: try clock(101 * second),
                                          previous: initial, probe: { _, _ in .found(self.guardian()) }), .invalid(.replayed))
    }

    func testClockAndLeaseBoundsRejectMalformedValues() throws {
        XCTAssertThrowsError(try clock(second, boot: "not-a-uuid"))
        XCTAssertThrowsError(try clock(second, boot: " " + boot))
        XCTAssertThrowsError(try lease(ttl: 0))
        XCTAssertThrowsError(try lease(ttl: GuardianLease.maximumTTLNanoseconds + 1))
        XCTAssertThrowsError(try lease(renewed: 100 * second - 1))
        for invalid in [guardian(pid: 0), guardian(group: 0), guardian(seconds: 0), guardian(microseconds: 1_000_000),
                        guardian(path: "/Applications/../Other.app/Contents/MacOS/Other")] {
            XCTAssertThrowsError(try GuardianLease(routeId: route, vpnUUID: realm, sessionId: session, guardian: invalid,
                                                   created: clock(100 * second), renewed: clock(100 * second)))
        }
    }

    func testDecodedNoncanonicalAndCorruptStateCannotGrantAuthorization() throws {
        let original = try lease()
        let encoded = try JSONEncoder().encode(original)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        object["routeId"] = anotherID.lowercased()
        let wrongRoute = try JSONDecoder().decode(GuardianLease.self, from: JSONSerialization.data(withJSONObject: object))
        XCTAssertEqual(try decision(wrongRoute, at: 101 * second), .invalid(.mismatchedRoute))
        object["routeId"] = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA".lowercased()
        let noncanonical = try JSONDecoder().decode(GuardianLease.self, from: JSONSerialization.data(withJSONObject: object))
        XCTAssertEqual(try decision(noncanonical, at: 101 * second), .invalid(.malformed))
        object["routeId"] = route
        object["state"] = "prepared"
        XCTAssertThrowsError(try JSONDecoder().decode(GuardianLease.self, from: JSONSerialization.data(withJSONObject: object)))
        object["state"] = "active"; object["sequence"] = -1
        XCTAssertThrowsError(try JSONDecoder().decode(GuardianLease.self, from: JSONSerialization.data(withJSONObject: object)))
    }

    func testPrivateLeaseRoundTripRejectsUnsafePermissionsAndSymlink() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("envara-lease-" + UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try RuntimeStore(directory: directory)
        let initial = try lease()
        try store.writeGuardianLease(initial)
        XCTAssertEqual(try store.readGuardianLease(route), initial)
        let file = try store.url(route, suffix: "lease")
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertEqual(chmod(file.path, 0o644), 0)
        XCTAssertThrowsError(try store.readGuardianLease(route))
        XCTAssertEqual(chmod(file.path, 0o600), 0)
        let alternate = try store.url(anotherID, suffix: "lease")
        try FileManager.default.createSymbolicLink(at: alternate, withDestinationURL: file)
        XCTAssertThrowsError(try store.readGuardianLease(anotherID))
        try store.removeGuardianLease(route)
        XCTAssertThrowsError(try store.readGuardianLease(route))
    }
}
