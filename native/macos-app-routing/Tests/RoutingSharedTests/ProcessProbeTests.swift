import Foundation
import XCTest
@testable import RoutingShared

final class ProcessProbeTests: XCTestCase {
    private let group: Int32 = 700
    private let guardian: Int32 = 900

    private func identity(_ pid: Int32 = 1101, parent: Int32 = 900, group: Int32 = 700,
                          seconds: UInt64 = 1_800_000_000, microseconds: UInt64 = 7,
                          path: String = "/Applications/EnvaraFixture.app/Contents/MacOS/Fixture") -> ProcessIdentity {
        ProcessIdentity(pid: pid, parent: parent, group: group, startedSeconds: seconds,
                        startedMicroseconds: microseconds, path: path)
    }

    // These closures model probe and enumeration results. They never inspect or
    // signal a process, enumerate a real process group, or launch a subprocess.
    private final class Fixture {
        var results: [Int32: ProcessProbeResult] = [:]
        var groupResult: ProcessPIDListResult = .listed([])
        var children: [Int32: ProcessPIDListResult] = [:]
        var probeCounts: [Int32: Int] = [:]
        var baselines: [Int32: ProcessIdentity] = [:]
        var signals: [(pid: Int32, value: Int32)] = []

        var probe: ProcessProbe {
            { [self] pid, baseline in
                probeCounts[pid, default: 0] += 1
                if let baseline { baselines[pid] = baseline }
                return results[pid] ?? .gone
            }
        }

        func makeFamily(group: Int32, guardian: Int32, initial: [ProcessIdentity] = []) -> ProcessFamily {
            ProcessFamily(group: group, guardianPID: guardian, initial: initial, probe: probe,
                listGroup: { [self] _ in groupResult },
                listChildren: { [self] pid in children[pid] ?? .listed([]) })
        }

        func send(_ pid: Int32, _ value: Int32) -> Int32 {
            signals.append((pid: pid, value: value))
            return 0
        }
    }

    func testSameBirthAndExecutableRemainAlive() {
        let original = identity(), fixture = Fixture()
        fixture.results[original.pid] = .found(original)
        XCTAssertEqual(original.presence(using: fixture.probe), .alive)
        XCTAssertFalse(original.isExitConfirmed(using: fixture.probe))
        XCTAssertEqual(fixture.baselines[original.pid], original)
    }

    func testReusedPIDWithDifferentBirthConfirmsOriginalIdentityGone() {
        let original = identity(), fixture = Fixture()
        fixture.results[original.pid] = .found(identity(seconds: original.startedSeconds + 1))
        XCTAssertEqual(original.presence(using: fixture.probe), .gone)
        XCTAssertTrue(original.isExitConfirmed(using: fixture.probe))
        fixture.results[original.pid] = .found(identity(microseconds: original.startedMicroseconds + 1))
        XCTAssertEqual(original.presence(using: fixture.probe), .gone)
    }

    func testSameBirthWithChangedExecutableIsUnknown() {
        let original = identity(), fixture = Fixture()
        fixture.results[original.pid] = .found(identity(path: "/Applications/OtherFixture.app/Contents/MacOS/Other"))
        XCTAssertEqual(original.presence(using: fixture.probe), .unknown(.identityChanged))
        XCTAssertFalse(original.isExitConfirmed(using: fixture.probe))
    }

    func testInjectedESRCHOutcomeConfirmsGone() {
        let original = identity(), fixture = Fixture()
        // .gone models an identity probe that positively reported ESRCH.
        fixture.results[original.pid] = .gone
        XCTAssertEqual(original.presence(using: fixture.probe), .gone)
        XCTAssertTrue(original.isExitConfirmed(using: fixture.probe))
    }

    func testAccessDeniedAndTimeoutRemainUnknown() {
        let original = identity(), fixture = Fixture()
        // macOS errno values: EACCES = 13, ETIMEDOUT = 60.
        for failure in [ProcessProbeFailure.system(13), .system(60), .truncated, .foreignUser] {
            fixture.results[original.pid] = .unknown(failure)
            XCTAssertEqual(original.presence(using: fixture.probe), .unknown(failure))
            XCTAssertFalse(original.isExitConfirmed(using: fixture.probe))
        }
    }

    func testUnknownOrGoneIdentityNeverInvokesSignalSender() {
        let original = identity(), fixture = Fixture()
        for result in [ProcessProbeResult.unknown(.system(13)), .unknown(.system(60)),
                       .unknown(.truncated), .unknown(.foreignUser), .unknown(.identityChanged), .gone] {
            fixture.results[original.pid] = result
            XCTAssertFalse(original.signal(9, probe: fixture.probe, send: fixture.send))
            XCTAssertTrue(fixture.signals.isEmpty)
        }
    }

    func testReusedPIDNeverInvokesSignalSender() {
        let original = identity(), fixture = Fixture()
        fixture.results[original.pid] = .found(identity(seconds: original.startedSeconds + 1))
        XCTAssertFalse(original.signal(9, probe: fixture.probe, send: fixture.send))
        XCTAssertTrue(fixture.signals.isEmpty)
    }

    func testAliveIdentityInvokesOnlyInjectedSignalSender() {
        let original = identity(), fixture = Fixture()
        fixture.results[original.pid] = .found(original)
        XCTAssertTrue(original.signal(9, probe: fixture.probe, send: fixture.send))
        XCTAssertEqual(fixture.signals.count, 1)
        XCTAssertEqual(fixture.signals.first?.pid, original.pid)
        XCTAssertEqual(fixture.signals.first?.value, 9)
    }

    func testGroupEnumerationFailureRetainsKnownIdentities() {
        let known = identity()
        // Even ESRCH from an enumeration is not proof that each scoped identity
        // exited; scope enumeration and identity inspection have different roles.
        for failure in [ProcessProbeFailure.enumerationFailed, .truncated, .system(3)] {
            let fixture = Fixture()
            fixture.results[known.pid] = .found(known)
            fixture.groupResult = .unknown(failure)
            let family = fixture.makeFamily(group: group, guardian: guardian, initial: [known])
            XCTAssertThrowsError(try family.refresh())
            XCTAssertEqual(family.retainedIdentities, [known])
        }
    }

    func testChildEnumerationFailureRetainsKnownIdentities() {
        let known = identity()
        for failure in [ProcessProbeFailure.enumerationFailed, .truncated] {
            let fixture = Fixture()
            fixture.results[known.pid] = .found(known)
            fixture.groupResult = .listed([known.pid])
            fixture.children[known.pid] = .unknown(failure)
            let family = fixture.makeFamily(group: group, guardian: guardian, initial: [known])
            XCTAssertThrowsError(try family.refresh())
            XCTAssertEqual(family.retainedIdentities, [known])
        }
    }

    func testNewUnknownPIDRemainsPendingWhenNextEnumerationIsEmpty() {
        let known = identity(), pendingPID: Int32 = 1102, fixture = Fixture()
        fixture.results[known.pid] = .found(known)
        fixture.results[pendingPID] = .unknown(.system(13))
        fixture.groupResult = .listed([known.pid, pendingPID])
        let family = fixture.makeFamily(group: group, guardian: guardian, initial: [known])
        XCTAssertThrowsError(try family.refresh())
        XCTAssertEqual(family.unknownPIDs.sorted(), [pendingPID])
        XCTAssertEqual(family.retainedIdentities, [known])

        fixture.groupResult = .listed([])
        let previousProbeCount = fixture.probeCounts[pendingPID, default: 0]
        XCTAssertThrowsError(try family.refresh())
        XCTAssertEqual(family.unknownPIDs.sorted(), [pendingPID])
        XCTAssertGreaterThan(fixture.probeCounts[pendingPID, default: 0], previousProbeCount)
        XCTAssertEqual(family.retainedIdentities, [known])
    }

    func testPendingPIDConfirmedGoneResolvesUnknownScope() throws {
        let pendingPID: Int32 = 1102, fixture = Fixture()
        fixture.results[pendingPID] = .unknown(.system(60))
        fixture.groupResult = .listed([pendingPID])
        let family = fixture.makeFamily(group: group, guardian: guardian)
        XCTAssertThrowsError(try family.refresh())
        XCTAssertEqual(family.unknownPIDs, [pendingPID])

        fixture.groupResult = .listed([])
        fixture.results[pendingPID] = .gone
        XCTAssertTrue(try family.refresh().isEmpty)
        XCTAssertTrue(family.unknownPIDs.isEmpty)
        XCTAssertTrue(family.retainedIdentities.isEmpty)
    }

    func testUnknownKnownIdentityCannotDisappearFromRetainedScope() {
        let known = identity(), fixture = Fixture()
        fixture.results[known.pid] = .unknown(.truncated)
        fixture.groupResult = .listed([])
        let family = fixture.makeFamily(group: group, guardian: guardian, initial: [known])
        XCTAssertThrowsError(try family.refresh())
        XCTAssertEqual(family.retainedIdentities, [known])
        XCTAssertEqual(fixture.baselines[known.pid], known)
    }

    func testOwnedGroupAndChildIdentitiesProduceNormalRefreshOutput() throws {
        let owned = identity(), child = identity(1102, parent: 1101), fixture = Fixture()
        fixture.results[owned.pid] = .found(owned)
        fixture.results[child.pid] = .found(child)
        fixture.groupResult = .listed([guardian, owned.pid])
        fixture.children[owned.pid] = .listed([guardian, child.pid])
        let family = fixture.makeFamily(group: group, guardian: guardian)
        XCTAssertEqual(try family.refresh().sorted { $0.pid < $1.pid }, [owned, child])
        XCTAssertEqual(family.retainedIdentities.sorted { $0.pid < $1.pid }, [owned, child])
        XCTAssertTrue(family.unknownPIDs.isEmpty)
        XCTAssertNil(fixture.probeCounts[guardian])
        XCTAssertTrue(fixture.signals.isEmpty)
    }

    func testFailedEnumerationCannotBeClearedByLaterEmptyList() {
        let known = identity(), fixture = Fixture()
        fixture.results[known.pid] = .found(known)
        fixture.groupResult = .unknown(.truncated)
        let family = fixture.makeFamily(group: group, guardian: guardian, initial: [known])
        XCTAssertThrowsError(try family.refresh())
        fixture.groupResult = .listed([])
        fixture.results[known.pid] = .gone
        XCTAssertThrowsError(try family.refresh(), "An unseen detached child cannot be disproved by an empty later list")
    }

    func testRealOwnProbeAndOwnedSleepNaturalExit() throws {
        guard case .found(let own) = ProcessIdentity.inspect(getpid()) else { return XCTFail("Own process identity must be readable") }
        XCTAssertEqual(own.presence(), .alive)
        XCTAssertFalse(own.exitConfirmed)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["0.2"]
        try process.run()
        guard case .found(let child) = ProcessIdentity.inspect(process.processIdentifier) else {
            process.waitUntilExit()
            return XCTFail("Owned sleep child identity must be readable")
        }
        XCTAssertEqual(child.presence(), .alive)
        process.waitUntilExit()
        XCTAssertEqual(ProcessIdentity.inspect(child.pid, child), .gone)
        XCTAssertEqual(child.presence(), .gone)
        XCTAssertTrue(child.exitConfirmed)
    }
}
