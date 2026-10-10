import Foundation
import Dispatch
import Darwin
import XCTest
@testable import RoutingShared

final class FlowProcessOwnershipTests: XCTestCase {
    private let applicationPath = "/Applications/OwnedFixture.app/Contents/MacOS/Fixture"
    private let guardianPath = "/Applications/Envara.app/Contents/MacOS/RoutingHelper"
    private let childPath = "/Applications/OwnedFixture.app/Contents/MacOS/FixtureChild"

    private func identity(_ pid: Int32, parent: Int32, group: Int32 = 700,
                          seconds: UInt64 = 1_800_000_000, microseconds: UInt64 = 7,
                          path: String) -> ProcessIdentity {
        ProcessIdentity(pid: pid, parent: parent, group: group, startedSeconds: seconds,
                        startedMicroseconds: microseconds, path: path)
    }

    /// Only injected snapshots are used: no real process, token, enumeration,
    /// network capture, polling timer or user application is touched.
    private final class KernelFixture {
        var results = [Int32: ProcessProbeResult]()
        var counts = [Int32: Int]()
        var expectations = [Int32: ProcessIdentity]()
        var override: ((Int32, ProcessIdentity?, Int) -> ProcessProbeResult?)?
        var generations = [Int32: Int32]()
        var generationCounts = [Int32: Int]()
        var generationOverride: ((Int32, Int32, Int) -> Bool?)?

        init(_ identities: [ProcessIdentity]) {
            for item in identities { results[item.pid] = .found(item) }
        }

        var probe: ProcessProbe {
            { [self] pid, expected in
                counts[pid, default: 0] += 1
                if let expected { expectations[pid] = expected }
                if let replacement = override?(pid, expected, counts[pid, default: 0]) { return replacement }
                return results[pid] ?? .gone
            }
        }

        func validate(_ ownership: FlowProcessOwnership, caller: ProcessIdentity, generation: Int32? = nil) -> Bool {
            let version = generation ?? generations[caller.pid, default: 1]
            return ownership.validate(caller: caller, generation: version, currentGeneration: { [self] in
                generationCounts[caller.pid, default: 0] += 1
                if let replacement = generationOverride?(caller.pid, version, generationCounts[caller.pid, default: 0]) {
                    return replacement
                }
                guard generations[caller.pid, default: 1] == version,
                      let result = results[caller.pid], case .found(let current) = result else { return false }
                // This closure models token revalidation, including its immutable
                // pid/exec version. Parent/group changes are not exec changes.
                return current.pid == caller.pid && current.path == caller.path &&
                    current.startedSeconds == caller.startedSeconds &&
                    current.startedMicroseconds == caller.startedMicroseconds
            }, probe: probe)
        }
    }

    private func scene() -> (FlowProcessOwnership, KernelFixture, ProcessIdentity, ProcessIdentity, ProcessIdentity) {
        let guardian = identity(900, parent: 1, path: guardianPath)
        let application = identity(1000, parent: guardian.pid, path: applicationPath)
        let child = identity(1001, parent: application.pid, path: childPath)
        return (FlowProcessOwnership(guardian: guardian, applicationExecutablePath: applicationPath),
                KernelFixture([guardian, application, child]), guardian, application, child)
    }

    func testFirstApplicationFlowIsProvedImmediatelyWithoutEnumerationOrPolling() {
        let (ownership, kernel, guardian, application, _) = scene()
        XCTAssertTrue(kernel.validate(ownership, caller: application))
        XCTAssertEqual(kernel.expectations[guardian.pid], guardian)
        XCTAssertEqual(kernel.expectations[application.pid], application)
        XCTAssertEqual(kernel.counts[application.pid], 2)
        XCTAssertEqual(kernel.counts[guardian.pid], 2)
    }

    func testFirstChildFlowWalksLiveParentsEvenWithDifferentProcessGroups() {
        let (ownership, kernel, _, application, child) = scene()
        let detached = identity(child.pid, parent: application.pid, group: 8123, path: childPath)
        kernel.results[detached.pid] = .found(detached)
        XCTAssertTrue(kernel.validate(ownership, caller: detached))
        XCTAssertEqual(kernel.counts[application.pid], 2)
        XCTAssertEqual(kernel.counts[detached.pid], 2)
    }

    func testUnrelatedSameGroupAndSameExecutableDoesNotEstablishOwnership() {
        let (ownership, kernel, _, _, child) = scene()
        XCTAssertTrue(kernel.validate(ownership, caller: child))
        let unrelated = identity(4000, parent: 1, path: childPath)
        kernel.results[unrelated.pid] = .found(unrelated)
        XCTAssertFalse(kernel.validate(ownership, caller: unrelated))
    }

    func testGuardianCannotRouteItsOwnFlows() {
        let (ownership, kernel, guardian, _, _) = scene()
        XCTAssertFalse(kernel.validate(ownership, caller: guardian))
        XCTAssertTrue(kernel.counts.isEmpty)
    }

    func testDirectChildMustMatchCompleteConfiguredApplicationPath() {
        let (ownership, kernel, guardian, application, _) = scene()
        for path in [applicationPath + "Helper", "/tmp/Fixture", childPath] {
            let imposter = identity(application.pid, parent: guardian.pid, path: path)
            kernel.results[imposter.pid] = .found(imposter)
            XCTAssertFalse(kernel.validate(ownership, caller: imposter))
        }
    }

    func testChildOfWrongApplicationCannotUseGuardianAncestryAlone() {
        let (ownership, kernel, guardian, application, child) = scene()
        kernel.results[application.pid] = .found(identity(application.pid, parent: guardian.pid,
                                                        path: "/Applications/Other.app/Contents/MacOS/Other"))
        XCTAssertFalse(kernel.validate(ownership, caller: child))
    }

    func testRouteInstancesDoNotShareProofAcrossRealms() {
        let (first, kernel, guardian, application, child) = scene()
        let otherGuardian = identity(901, parent: 1, path: guardianPath)
        let otherApplication = identity(2000, parent: otherGuardian.pid, path: applicationPath)
        let otherChild = identity(2001, parent: otherApplication.pid, path: childPath)
        for item in [otherGuardian, otherApplication, otherChild] { kernel.results[item.pid] = .found(item) }
        let second = FlowProcessOwnership(guardian: otherGuardian, applicationExecutablePath: applicationPath)

        XCTAssertTrue(kernel.validate(first, caller: child))
        XCTAssertTrue(kernel.validate(second, caller: otherChild))
        XCTAssertFalse(kernel.validate(first, caller: otherChild))
        XCTAssertFalse(kernel.validate(second, caller: child))
        XCTAssertEqual(kernel.expectations[guardian.pid], guardian)
        XCTAssertEqual(kernel.expectations[application.pid], application)

        let orphan = identity(otherChild.pid, parent: 1, path: childPath)
        kernel.results[otherApplication.pid] = .gone
        kernel.results[orphan.pid] = .found(orphan)
        XCTAssertTrue(kernel.validate(second, caller: orphan))
        XCTAssertFalse(kernel.validate(first, caller: orphan))
    }

    func testCallerBirthAndPathMustMatchAuditedIdentity() {
        let (ownership, kernel, _, application, child) = scene()
        let replacements = [
            identity(child.pid, parent: application.pid, seconds: child.startedSeconds + 1, path: childPath),
            identity(child.pid, parent: application.pid, microseconds: child.startedMicroseconds + 1, path: childPath),
            identity(child.pid, parent: application.pid, path: "/tmp/ChangedExecutable"),
            identity(7000, parent: application.pid, path: childPath)
        ]
        for replacement in replacements {
            kernel.results[child.pid] = .found(replacement)
            XCTAssertFalse(kernel.validate(ownership, caller: child))
        }
    }

    func testEveryFlowStillRequiresTheCurrentGuardianIdentity() {
        let (ownership, kernel, guardian, _, child) = scene()
        XCTAssertTrue(kernel.validate(ownership, caller: child))
        let failures: [ProcessProbeResult] = [
            .gone, .unknown(.foreignUser), .unknown(.truncated), .unknown(.system(13)),
            .found(identity(guardian.pid, parent: 1, seconds: guardian.startedSeconds + 1, path: guardianPath)),
            .found(identity(guardian.pid, parent: 1, path: "/tmp/ChangedGuardian")),
            .found(identity(guardian.pid, parent: 1, group: guardian.group + 1, path: guardianPath))
        ]
        for failure in failures {
            kernel.results[guardian.pid] = failure
            XCTAssertFalse(kernel.validate(ownership, caller: child))
        }
    }

    func testUnknownGoneOrForeignCallerAndParentAreNeverAccepted() {
        let failures: [ProcessProbeResult] = [
            .gone, .unknown(.foreignUser), .unknown(.truncated), .unknown(.system(13)),
            .unknown(.system(60)), .unknown(.identityChanged), .unknown(.scopeChanged)
        ]
        for failure in failures {
            let (ownership, kernel, _, application, child) = scene()
            kernel.results[child.pid] = failure
            XCTAssertFalse(kernel.validate(ownership, caller: child))
            kernel.results[child.pid] = .found(child)
            kernel.results[application.pid] = failure
            XCTAssertFalse(kernel.validate(ownership, caller: child))
        }
    }

    func testProvedChildMayKeepRoutingAfterItsParentNaturallyExits() {
        let (ownership, kernel, _, application, child) = scene()
        XCTAssertTrue(kernel.validate(ownership, caller: child))
        let orphan = identity(child.pid, parent: 1, group: 9999, path: childPath)
        kernel.results[application.pid] = .gone
        kernel.results[orphan.pid] = .found(orphan)
        kernel.counts.removeAll()
        XCTAssertTrue(kernel.validate(ownership, caller: orphan))
        XCTAssertNil(kernel.counts[application.pid])
        XCTAssertEqual(kernel.counts[child.pid], 2, "A cache hit must still recheck the owned identity")
    }

    func testFreshChildOfLiveProvedOrphanHasItsOwnRealParentChain() {
        let (ownership, kernel, _, application, child) = scene()
        XCTAssertTrue(kernel.validate(ownership, caller: child))
        let orphan = identity(child.pid, parent: 1, path: childPath)
        let fresh = identity(4000, parent: orphan.pid, group: 4444, path: "/tmp/OwnedChild")
        kernel.results[application.pid] = .gone
        kernel.results[orphan.pid] = .found(orphan)
        kernel.results[fresh.pid] = .found(fresh)
        kernel.counts.removeAll()
        XCTAssertTrue(kernel.validate(ownership, caller: fresh))
        XCTAssertEqual(kernel.counts[orphan.pid], 2)
        XCTAssertEqual(kernel.counts[fresh.pid], 2)

        let freshOrphan = identity(fresh.pid, parent: 1, group: 4444, path: fresh.path)
        kernel.results[orphan.pid] = .gone
        kernel.results[fresh.pid] = .found(freshOrphan)
        XCTAssertTrue(kernel.validate(ownership, caller: freshOrphan))
    }

    func testUnprovedOrphanCannotAcquireOwnershipFromItsProcessGroup() {
        let (ownership, kernel, _, application, child) = scene()
        let orphan = identity(child.pid, parent: 1, path: childPath)
        kernel.results[application.pid] = .gone
        kernel.results[child.pid] = .found(orphan)
        XCTAssertFalse(kernel.validate(ownership, caller: orphan))
    }

    func testCachedCallerPIDReuseCannotInheritEarlierProof() {
        let (ownership, kernel, _, _, child) = scene()
        XCTAssertTrue(kernel.validate(ownership, caller: child))
        let replacement = identity(child.pid, parent: 1, seconds: child.startedSeconds + 1, path: childPath)
        kernel.results[child.pid] = .found(replacement)
        XCTAssertFalse(kernel.validate(ownership, caller: replacement))
    }

    func testSameBirthButChangedCachedCallerPathCannotInheritProof() {
        let (ownership, kernel, _, _, child) = scene()
        XCTAssertTrue(kernel.validate(ownership, caller: child))
        let replacement = identity(child.pid, parent: 1, path: "/tmp/ChangedExecutable")
        kernel.results[child.pid] = .found(replacement)
        XCTAssertFalse(kernel.validate(ownership, caller: replacement))
    }

    func testFreshAuditedIdentityCanReplaceCacheOnlyWithANewOwnedChain() {
        for changedPath in [false, true] {
            let (ownership, kernel, _, application, child) = scene()
            XCTAssertTrue(kernel.validate(ownership, caller: child))
            let replacement = identity(child.pid, parent: application.pid,
                                       seconds: changedPath ? child.startedSeconds : child.startedSeconds + 1,
                                       path: changedPath ? "/tmp/NewOwnedExecutable" : childPath)
            kernel.results[replacement.pid] = .found(replacement)
            kernel.counts.removeAll()
            XCTAssertTrue(kernel.validate(ownership, caller: replacement))
            XCTAssertEqual(kernel.counts[application.pid], 2, "The old caller proof must not suffice")

            let orphan = identity(replacement.pid, parent: 1, seconds: replacement.startedSeconds, path: replacement.path)
            kernel.results[application.pid] = .gone
            kernel.results[replacement.pid] = .found(orphan)
            XCTAssertTrue(kernel.validate(ownership, caller: orphan))
        }
    }

    func testCachedCallerIsStillSubjectToOwnerAndUncertaintyChecks() {
        let (ownership, kernel, _, _, child) = scene()
        XCTAssertTrue(kernel.validate(ownership, caller: child))
        for failure in [ProcessProbeFailure.foreignUser, .truncated, .system(13), .system(60)] {
            kernel.results[child.pid] = .unknown(failure)
            XCTAssertFalse(kernel.validate(ownership, caller: child))
        }
        kernel.results[child.pid] = .found(child)
        XCTAssertTrue(kernel.validate(ownership, caller: child))
    }

    func testCachedAncestorReuseOrPathChangeCannotAdmitANewChild() {
        for changedPath in [false, true] {
            let (ownership, kernel, _, application, child) = scene()
            XCTAssertTrue(kernel.validate(ownership, caller: child))
            let replacement = identity(child.pid, parent: 1,
                                       seconds: changedPath ? child.startedSeconds : child.startedSeconds + 1,
                                       path: changedPath ? "/tmp/ChangedExecutable" : childPath)
            let fresh = identity(4000, parent: replacement.pid, path: "/tmp/OwnedChild")
            kernel.results[application.pid] = .gone
            kernel.results[child.pid] = .found(replacement)
            kernel.results[fresh.pid] = .found(fresh)
            XCTAssertFalse(kernel.validate(ownership, caller: fresh))
        }
    }

    func testReusedCachedAncestorCanBeReprovedThroughItsNewOwnedParentChain() {
        let (ownership, kernel, _, application, child) = scene()
        XCTAssertTrue(kernel.validate(ownership, caller: child))
        let replacement = identity(child.pid, parent: application.pid,
                                   seconds: child.startedSeconds + 1, path: "/tmp/NewOwnedParent")
        let fresh = identity(4000, parent: replacement.pid, path: "/tmp/NewOwnedChild")
        kernel.results[replacement.pid] = .found(replacement)
        kernel.results[fresh.pid] = .found(fresh)
        kernel.counts.removeAll()
        XCTAssertTrue(kernel.validate(ownership, caller: fresh))
        XCTAssertEqual(kernel.counts[application.pid], 2, "A reused ancestor must reach a current owned parent")
        XCTAssertEqual(kernel.counts[replacement.pid], 2)
        XCTAssertEqual(kernel.counts[fresh.pid], 2)
    }

    func testCachedAncestorMustRemainReadableForNewChildren() {
        let (ownership, kernel, _, _, child) = scene()
        XCTAssertTrue(kernel.validate(ownership, caller: child))
        let fresh = identity(4000, parent: child.pid, path: "/tmp/OwnedChild")
        kernel.results[fresh.pid] = .found(fresh)
        for failure in [ProcessProbeResult.gone, .unknown(.foreignUser), .unknown(.truncated), .unknown(.system(13))] {
            kernel.results[child.pid] = failure
            XCTAssertFalse(kernel.validate(ownership, caller: fresh))
        }
    }

    func testParentIdentityChangingDuringTheWalkRejectsWithoutCaching() {
        let (ownership, kernel, _, application, child) = scene()
        let replacement = identity(application.pid, parent: application.parent,
                                   seconds: application.startedSeconds + 1, path: applicationPath)
        kernel.override = { pid, _, count in pid == application.pid && count == 2 ? .found(replacement) : nil }
        XCTAssertFalse(kernel.validate(ownership, caller: child))
        kernel.override = nil
        let orphan = identity(child.pid, parent: 1, path: childPath)
        kernel.results[child.pid] = .found(orphan)
        kernel.results[application.pid] = .gone
        XCTAssertFalse(kernel.validate(ownership, caller: orphan))
    }

    func testReparentingDuringInitialProofRejectsWithoutCaching() {
        let (ownership, kernel, _, application, child) = scene()
        let orphan = identity(child.pid, parent: 1, path: childPath)
        kernel.override = { pid, _, count in pid == child.pid && count == 2 ? .found(orphan) : nil }
        XCTAssertFalse(kernel.validate(ownership, caller: child))
        kernel.override = nil
        kernel.results[application.pid] = .gone
        kernel.results[child.pid] = .found(orphan)
        XCTAssertFalse(kernel.validate(ownership, caller: orphan))
    }

    func testGuardianExitBeforeCommittingProofDoesNotPopulateCache() {
        let (ownership, kernel, guardian, application, _) = scene()
        kernel.override = { pid, _, count in pid == guardian.pid && count == 2 ? .gone : nil }
        XCTAssertFalse(kernel.validate(ownership, caller: application))
        kernel.override = nil
        let orphan = identity(application.pid, parent: 1, path: application.path)
        kernel.results[application.pid] = .found(orphan)
        XCTAssertFalse(kernel.validate(ownership, caller: orphan))
    }

    func testMaximum64ProcessesBelowGuardianAreAccepted() {
        let guardian = identity(900, parent: 1, path: guardianPath)
        var processes = [identity(1000, parent: guardian.pid, path: applicationPath)]
        for offset in 1..<64 {
            processes.append(identity(1000 + Int32(offset), parent: 999 + Int32(offset), path: childPath))
        }
        let kernel = KernelFixture([guardian] + processes)
        let ownership = FlowProcessOwnership(guardian: guardian, applicationExecutablePath: applicationPath)
        XCTAssertTrue(kernel.validate(ownership, caller: processes.last!))
        XCTAssertEqual(kernel.counts[processes.first!.pid], 2)
    }

    func test65ProcessChainIsRejectedBeforeReadingBeyondLimit() {
        let guardian = identity(900, parent: 1, path: guardianPath)
        var processes = [identity(1000, parent: guardian.pid, path: applicationPath)]
        for offset in 1...64 {
            processes.append(identity(1000 + Int32(offset), parent: 999 + Int32(offset), path: childPath))
        }
        let kernel = KernelFixture([guardian] + processes)
        let ownership = FlowProcessOwnership(guardian: guardian, applicationExecutablePath: applicationPath)
        XCTAssertFalse(kernel.validate(ownership, caller: processes.last!))
        XCTAssertNil(kernel.counts[processes.first!.pid], "The 65th node must not even be probed")
    }

    func testCyclesAndSelfParentNeverEstablishOwnership() {
        let (ownership, kernel, _, _, child) = scene()
        let cycleChild = identity(child.pid, parent: 4000, path: childPath)
        let cycleParent = identity(4000, parent: child.pid, path: "/tmp/CycleParent")
        kernel.results[cycleChild.pid] = .found(cycleChild)
        kernel.results[cycleParent.pid] = .found(cycleParent)
        XCTAssertFalse(kernel.validate(ownership, caller: cycleChild))

        let selfParent = identity(child.pid, parent: child.pid, path: childPath)
        kernel.results[selfParent.pid] = .found(selfParent)
        XCTAssertFalse(kernel.validate(ownership, caller: selfParent))
    }

    func testMalformedOrWrongPIDProbeCannotEstablishOwnership() {
        let (ownership, kernel, _, application, child) = scene()
        kernel.results[application.pid] = .found(identity(4444, parent: application.parent, path: applicationPath))
        XCTAssertFalse(kernel.validate(ownership, caller: child))

        for invalid in [
            identity(0, parent: application.pid, path: childPath),
            identity(child.pid, parent: application.pid, seconds: 0, path: childPath),
            identity(child.pid, parent: application.pid, microseconds: 1_000_000, path: childPath),
            identity(child.pid, parent: application.pid, path: "relative/path")
        ] {
            kernel.results[invalid.pid] = .found(invalid)
            XCTAssertFalse(kernel.validate(ownership, caller: invalid))
        }
    }

    func testObservedButUnauditedAncestorCannotAuthorizeOrphans() {
        let (ownership, kernel, _, application, _) = scene()
        let middle = identity(1100, parent: application.pid, path: "/tmp/OwnedMiddle")
        let leaf = identity(1101, parent: middle.pid, path: "/tmp/OwnedLeaf")
        kernel.results[middle.pid] = .found(middle)
        kernel.results[leaf.pid] = .found(leaf)
        XCTAssertTrue(kernel.validate(ownership, caller: leaf))

        let orphanMiddle = identity(middle.pid, parent: 1, path: middle.path)
        let newLeaf = identity(1102, parent: middle.pid, path: "/tmp/NewLeaf")
        kernel.results[application.pid] = .gone
        kernel.results[middle.pid] = .found(orphanMiddle)
        kernel.results[newLeaf.pid] = .found(newLeaf)
        XCTAssertTrue(kernel.validate(ownership, caller: leaf), "The audited leaf retains only its own proof")
        XCTAssertFalse(kernel.validate(ownership, caller: orphanMiddle), "Walking an ancestor did not audit its exec generation")
        XCTAssertFalse(kernel.validate(ownership, caller: newLeaf), "A fresh child cannot borrow an unaudited orphan ancestor")
    }

    func testSamePathExecGenerationChangeInvalidatesCachedOrphan() {
        let (ownership, kernel, _, application, child) = scene()
        XCTAssertTrue(kernel.validate(ownership, caller: child, generation: 1))
        let orphan = identity(child.pid, parent: 1, path: childPath)
        kernel.results[application.pid] = .gone
        kernel.results[child.pid] = .found(orphan)
        kernel.generations[child.pid] = 2

        XCTAssertEqual(orphan.startedSeconds, child.startedSeconds)
        XCTAssertEqual(orphan.startedMicroseconds, child.startedMicroseconds)
        XCTAssertEqual(orphan.path, child.path)
        XCTAssertFalse(kernel.validate(ownership, caller: orphan, generation: 2), "A new same-path exec cannot inherit the old orphan proof")
        XCTAssertFalse(kernel.validate(ownership, caller: orphan, generation: 1), "The original kernel token is now stale")
    }

    func testActiveSamePathNewExecGenerationRequiresAndRetainsANewChainProof() {
        let (ownership, kernel, _, application, child) = scene()
        XCTAssertTrue(kernel.validate(ownership, caller: child, generation: 1))
        kernel.generations[child.pid] = 2
        kernel.counts.removeAll()
        XCTAssertTrue(kernel.validate(ownership, caller: child, generation: 2))
        XCTAssertEqual(kernel.counts[application.pid], 2, "A version change must reach the current application chain")

        let orphan = identity(child.pid, parent: 1, path: childPath)
        kernel.results[application.pid] = .gone
        kernel.results[child.pid] = .found(orphan)
        XCTAssertTrue(kernel.validate(ownership, caller: orphan, generation: 2))
        XCTAssertFalse(kernel.validate(ownership, caller: orphan, generation: 1))
        XCTAssertTrue(kernel.validate(ownership, caller: orphan, generation: 2), "A queued stale flow cannot poison the newer retained proof")
    }

    func testCachedAncestorWithStaleExecTokenCannotAdmitAFreshChild() {
        let (ownership, kernel, _, application, child) = scene()
        XCTAssertTrue(kernel.validate(ownership, caller: child, generation: 1))
        let orphan = identity(child.pid, parent: 1, path: childPath)
        let fresh = identity(4000, parent: orphan.pid, path: "/tmp/FreshChild")
        kernel.results[application.pid] = .gone
        kernel.results[orphan.pid] = .found(orphan)
        kernel.results[fresh.pid] = .found(fresh)
        kernel.generations[orphan.pid] = 2
        XCTAssertFalse(kernel.validate(ownership, caller: fresh), "Birth/path agreement cannot rescue an old ancestor token")
    }

    func testCallerAuditGenerationBecomingInvalidBeforeCommitDoesNotPopulateCache() {
        let (ownership, kernel, _, application, child) = scene()
        kernel.generationOverride = { pid, _, count in pid == child.pid ? count == 1 : nil }
        XCTAssertFalse(kernel.validate(ownership, caller: child))
        kernel.generationOverride = nil
        let orphan = identity(child.pid, parent: 1, path: childPath)
        kernel.results[application.pid] = .gone
        kernel.results[child.pid] = .found(orphan)
        XCTAssertFalse(kernel.validate(ownership, caller: orphan))
    }

    func testCachedAncestorTokenInvalidatingDuringNewChainIsRemoved() {
        let (ownership, kernel, _, application, child) = scene()
        XCTAssertTrue(kernel.validate(ownership, caller: child))
        let orphan = identity(child.pid, parent: 1, path: childPath)
        let fresh = identity(4000, parent: child.pid, path: "/tmp/FreshChild")
        kernel.results[application.pid] = .gone
        kernel.results[child.pid] = .found(orphan)
        kernel.results[fresh.pid] = .found(fresh)
        kernel.generationCounts.removeAll()
        kernel.generationOverride = { pid, _, count in pid == child.pid ? count == 1 : nil }
        XCTAssertFalse(kernel.validate(ownership, caller: fresh))

        kernel.generationOverride = nil
        XCTAssertFalse(kernel.validate(ownership, caller: fresh), "An invalidated ancestor cache was not retained")
        XCTAssertFalse(kernel.validate(ownership, caller: orphan))
    }

    func testInvalidInitialAuditGenerationStopsBeforeAnyProcessProbe() {
        let (ownership, kernel, _, _, child) = scene()
        XCTAssertFalse(kernel.validate(ownership, caller: child, generation: 99))
        XCTAssertTrue(kernel.counts.isEmpty, "Unverified audit metadata must not seed a parent walk")
    }

    func testRealDarwinDirectApplicationAndUnrelatedOwnedControl() throws {
        guard case .found(let guardian) = ProcessIdentity.inspect(getpid()) else {
            return XCTFail("The test process must have a current libproc identity")
        }
        let target = Process()
        target.executableURL = URL(fileURLWithPath: "/bin/sleep")
        target.arguments = ["5"]
        target.environment = ["PATH": "/usr/bin:/bin"]
        var targetIdentity: ProcessIdentity?
        defer { stopOwned(target, identity: targetIdentity) }
        try target.run()
        guard case .found(let application) = ProcessIdentity.inspect(target.processIdentifier) else {
            return XCTFail("The owned sleep application must be readable")
        }
        targetIdentity = application

        let controlInput = Pipe()
        let control = Process()
        control.executableURL = URL(fileURLWithPath: "/bin/sh")
        control.arguments = ["-c", "read envara_fixture_input"]
        control.environment = ["PATH": "/usr/bin:/bin"]
        control.standardInput = controlInput
        control.standardOutput = FileHandle.nullDevice
        control.standardError = FileHandle.nullDevice
        var controlIdentity: ProcessIdentity?
        defer {
            try? controlInput.fileHandleForWriting.close()
            stopOwned(control, identity: controlIdentity)
        }
        try control.run()
        guard case .found(let unrelated) = ProcessIdentity.inspect(control.processIdentifier) else {
            return XCTFail("The owned control shell must be readable")
        }
        controlIdentity = unrelated

        XCTAssertEqual(application.parent, guardian.pid)
        XCTAssertEqual(application.path, "/bin/sleep")
        XCTAssertNotEqual(unrelated.path, application.path)
        let ownership = FlowProcessOwnership(guardian: guardian, applicationExecutablePath: application.path)
        // Token callbacks are injected here. This test proves the real libproc
        // parent/birth/path policy, not native audit-token exec revalidation.
        XCTAssertTrue(ownership.validate(caller: application, generation: 1, currentGeneration: { true },
                                         probe: ProcessIdentity.inspect))
        XCTAssertFalse(ownership.validate(caller: unrelated, generation: 1, currentGeneration: { true },
                                          probe: ProcessIdentity.inspect))
    }

    func testRealDarwinChildFirstFlowAndUnrelatedSleepControl() throws {
        guard case .found(let guardian) = ProcessIdentity.inspect(getpid()) else {
            return XCTFail("The test process must have a current libproc identity")
        }
        let output = Pipe()
        let applicationProcess = Process()
        applicationProcess.executableURL = URL(fileURLWithPath: "/bin/sh")
        applicationProcess.arguments = ["-c", "/bin/sleep 5 & envara_fixture_child=$!; printf '%s\\n' \"$envara_fixture_child\"; wait \"$envara_fixture_child\""]
        applicationProcess.environment = ["PATH": "/usr/bin:/bin"]
        applicationProcess.standardOutput = output
        applicationProcess.standardError = FileHandle.nullDevice
        var applicationIdentity: ProcessIdentity?
        var childIdentity: ProcessIdentity?
        defer {
            if let childIdentity { _ = childIdentity.signal(SIGTERM) }
            stopOwned(applicationProcess, identity: applicationIdentity)
            try? output.fileHandleForReading.close()
            try? output.fileHandleForWriting.close()
        }
        try applicationProcess.run()
        guard case .found(let application) = ProcessIdentity.inspect(applicationProcess.processIdentifier) else {
            return XCTFail("The owned application shell must be readable")
        }
        applicationIdentity = application
        // FileHandle's length-oriented read may wait until the child exits.
        // Read only the owned PID line, without requiring pipe EOF.
        let descriptor = output.fileHandleForReading.fileDescriptor
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            return XCTFail("The owned fixture pipe could not be made nonblocking")
        }
        defer { _ = fcntl(descriptor, F_SETFL, flags) }
        let lineDeadline = DispatchTime.now().uptimeNanoseconds + 3_000_000_000
        var line = Data()
        var bytes = [UInt8](repeating: 0, count: 64)
        while !line.contains(10), DispatchTime.now().uptimeNanoseconds < lineDeadline {
            let remaining = lineDeadline - min(lineDeadline, DispatchTime.now().uptimeNanoseconds)
            let milliseconds = Int32(max(1, min(50, (remaining + 999_999) / 1_000_000)))
            var request = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            let ready = Darwin.poll(&request, 1, milliseconds)
            if ready < 0 && errno == EINTR { continue }
            guard ready >= 0, request.revents & Int16(POLLERR | POLLNVAL) == 0 else {
                return XCTFail("The owned fixture pipe could not be polled")
            }
            if ready == 0 { continue }
            if request.revents & Int16(POLLIN | POLLHUP) == 0 { continue }
            let count = bytes.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
            if count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { continue }
            guard count > 0, line.count + count <= 64 else {
                return XCTFail("The owned fixture closed its pipe or exceeded the PID line limit")
            }
            line.append(contentsOf: bytes.prefix(count))
        }
        guard let newline = line.firstIndex(of: 10),
              let childPID = Int32(String(decoding: line.prefix(upTo: newline), as: UTF8.self)), childPID > 0 else {
            return XCTFail("The owned fixture must print its child PID within three seconds")
        }

        // The shell can print $! before the forked child finishes exec. Retain
        // only its exact owned birth, then briefly wait for the requested path.
        let execDeadline = DispatchTime.now().uptimeNanoseconds + 1_000_000_000
        var readyChild: ProcessIdentity?
        while DispatchTime.now().uptimeNanoseconds < execDeadline {
            guard case .found(let observed) = ProcessIdentity.inspect(childPID, childIdentity),
                  observed.parent == application.pid else {
                return XCTFail("The printed PID must remain the owned shell's current child")
            }
            childIdentity = observed
            if observed.path == "/bin/sleep" {
                readyChild = observed
                break
            }
            // The path reported while this exclusively owned child is being
            // spawned is not itself an exec-completion handshake. Keep the
            // same birth/parent bound, and require the final requested path.
            usleep(5_000)
        }
        guard let child = readyChild else {
            return XCTFail("The owned child must exec /bin/sleep within one second")
        }
        // The child's PID line also proves the parent entered its shell.
        // macOS /bin/sh can exec its selected shell image (here /bin/bash);
        // use this exclusively owned process's current full image path.
        guard case .found(let runningApplication) = ProcessIdentity.inspect(application.pid, application),
              runningApplication.parent == guardian.pid, runningApplication.path.hasPrefix("/") else {
            return XCTFail("The owned parent must have completed its requested shell exec")
        }
        applicationIdentity = runningApplication

        let control = Process()
        control.executableURL = URL(fileURLWithPath: "/bin/sleep")
        control.arguments = ["5"]
        control.environment = ["PATH": "/usr/bin:/bin"]
        var controlIdentity: ProcessIdentity?
        defer { stopOwned(control, identity: controlIdentity) }
        try control.run()
        guard case .found(let unrelated) = ProcessIdentity.inspect(control.processIdentifier) else {
            return XCTFail("The owned sleep control must be readable")
        }
        controlIdentity = unrelated

        XCTAssertEqual(application.parent, guardian.pid)
        XCTAssertEqual(child.parent, application.pid)
        XCTAssertEqual(child.path, "/bin/sleep")
        XCTAssertEqual(unrelated.parent, guardian.pid)
        let ownership = FlowProcessOwnership(guardian: guardian, applicationExecutablePath: runningApplication.path)
        // No earlier application flow or polling pass seeded the child proof.
        // Token callbacks are injected; actual exec-version evidence belongs to
        // the separate native FlowAuditCaller tests.
        XCTAssertTrue(ownership.validate(caller: child, generation: 1, currentGeneration: { true },
                                         probe: ProcessIdentity.inspect))
        XCTAssertFalse(ownership.validate(caller: unrelated, generation: 1, currentGeneration: { true },
                                          probe: ProcessIdentity.inspect))
    }

    private func stopOwned(_ process: Process, identity: ProcessIdentity?) {
        guard process.processIdentifier > 0 else { return }
        if process.isRunning {
            if let identity {
                _ = identity.signal(SIGTERM)
            } else {
                // This Foundation Process is exclusively created by the test.
                process.terminate()
            }
        }
        process.waitUntilExit()
    }
}
