import Foundation
import XCTest
@testable import RoutingShared

final class FlowResourceLifetimeTests: XCTestCase {
    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var stored = 0
        var value: Int { lock.lock(); defer { lock.unlock() }; return stored }
        func increment() { lock.lock(); stored += 1; lock.unlock() }
    }

    func testClosedLifetimeRejectsNewResourcesAndNetworkRegistrations() throws {
        let lifetime = FlowResourceLifetime(), constructions = Counter(), operations = Counter()
        XCTAssertTrue(lifetime.close())
        XCTAssertThrowsError(try lifetime.install(make: { constructions.increment(); return 1 }, cancel: { _ in }))
        XCTAssertThrowsError(try lifetime.whileOpen { operations.increment() })
        XCTAssertEqual(constructions.value, 0)
        XCTAssertEqual(operations.value, 0)
        XCTAssertFalse(lifetime.close())
    }

    func testCloseCancelsEveryRegisteredResourceExactlyOnce() throws {
        let lifetime = FlowResourceLifetime(), cancellations = Counter()
        let first = try lifetime.install(make: { 1 }, cancel: { _ in cancellations.increment() })
        _ = try lifetime.install(make: { 2 }, cancel: { _ in cancellations.increment() })
        XCTAssertFalse(lifetime.isClosed)
        XCTAssertTrue(lifetime.close())
        XCTAssertTrue(lifetime.isClosed)
        XCTAssertEqual(cancellations.value, 2)
        lifetime.release(first.token)
        XCTAssertFalse(lifetime.close())
        XCTAssertEqual(cancellations.value, 2)
    }

    func testCompletedQueryCanReleaseWithoutClosingRemainingFlow() throws {
        let lifetime = FlowResourceLifetime(), first = Counter(), second = Counter()
        let handle = try lifetime.install(make: { 1 }, cancel: { _ in first.increment() })
        _ = try lifetime.install(make: { 2 }, cancel: { _ in second.increment() })
        lifetime.release(handle.token); lifetime.release(handle.token)
        XCTAssertEqual(first.value, 1)
        XCTAssertEqual(second.value, 0)
        XCTAssertFalse(lifetime.isClosed)
        XCTAssertTrue(lifetime.close())
        XCTAssertEqual(first.value, 1)
        XCTAssertEqual(second.value, 1)
    }

    func testCancellationCallbackCannotReopenLifetimeAndMayReenter() throws {
        let lifetime = FlowResourceLifetime(), constructions = Counter()
        _ = try lifetime.install(make: { 1 }, cancel: { (_: Int) in
            XCTAssertTrue(lifetime.isClosed)
            XCTAssertFalse(lifetime.close())
            do {
                _ = try lifetime.install(make: { constructions.increment(); return 2 }, cancel: { (_: Int) in })
                XCTFail("A cancellation callback must not reopen the lifetime")
            } catch { XCTAssertTrue(error is CancellationError) }
        })
        XCTAssertTrue(lifetime.close())
        XCTAssertEqual(constructions.value, 0)
    }

    func testDeferredCloseSealsBeforeRunningCancellation() throws {
        let lifetime = FlowResourceLifetime(), cancelled = Counter(), made = Counter(), operations = Counter()
        let handle = try lifetime.install(make: { 1 }, cancel: { _ in cancelled.increment() })
        let cancel = try XCTUnwrap(lifetime.closeDeferred())

        XCTAssertTrue(lifetime.isClosed)
        XCTAssertEqual(cancelled.value, 0)
        XCTAssertThrowsError(try lifetime.install(make: { made.increment(); return 2 }, cancel: { _ in }))
        XCTAssertThrowsError(try lifetime.whileOpen { operations.increment() })
        XCTAssertEqual(made.value, 0)
        XCTAssertEqual(operations.value, 0)
        XCTAssertNil(lifetime.closeDeferred())
        XCTAssertFalse(lifetime.close())
        lifetime.release(handle.token)
        XCTAssertEqual(cancelled.value, 0)

        cancel()
        XCTAssertEqual(cancelled.value, 1)
    }

    func testDeferredCancellationRunsOnceWhenRepeatedConcurrentlyAndMayReenter() throws {
        let lifetime = FlowResourceLifetime(), cancelled = Counter(), reentries = Counter()
        for value in 0..<2 {
            _ = try lifetime.install(make: { value }, cancel: { _ in
                cancelled.increment()
                XCTAssertTrue(lifetime.isClosed)
                XCTAssertFalse(lifetime.close())
                XCTAssertNil(lifetime.closeDeferred())
                reentries.increment()
            })
        }
        let cancel = try XCTUnwrap(lifetime.closeDeferred())
        let group = DispatchGroup()
        for _ in 0..<32 {
            group.enter()
            DispatchQueue.global().async {
                cancel(); cancel()
                group.leave()
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 2), .success)
        cancel()
        XCTAssertEqual(cancelled.value, 2)
        XCTAssertEqual(reentries.value, 2)
    }

    func testCancellationRaceWaitsForAtomicPublicationAndCancelsResource() throws {
        let lifetime = FlowResourceLifetime(), made = Counter(), cancelled = Counter()
        let entered = DispatchSemaphore(value: 0), proceed = DispatchSemaphore(value: 0)
        let installed = expectation(description: "resource publication finished")
        let closed = expectation(description: "raced close finished")
        DispatchQueue.global().async {
            do {
                _ = try lifetime.install(make: {
                    entered.signal()
                    _ = proceed.wait(timeout: .now() + 2)
                    made.increment()
                    return 1
                }, cancel: { _ in cancelled.increment() })
            } catch { XCTFail("Publication should precede the raced close") }
            installed.fulfill()
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 2), .success)
        DispatchQueue.global().async { lifetime.close(); closed.fulfill() }
        proceed.signal()
        wait(for: [installed, closed], timeout: 2)
        XCTAssertEqual(made.value, 1)
        XCTAssertEqual(cancelled.value, 1)
        XCTAssertTrue(lifetime.isClosed)
    }

    func testConcurrentPublicationAndCloseNeverLoseCancellation() {
        let lifetime = FlowResourceLifetime(), made = Counter(), cancelled = Counter(), rejected = Counter()
        let group = DispatchGroup()
        for value in 0..<32 {
            group.enter()
            DispatchQueue.global().async {
                do {
                    _ = try lifetime.install(make: { made.increment(); return value }, cancel: { _ in cancelled.increment() })
                } catch { rejected.increment() }
                group.leave()
            }
        }
        group.enter()
        DispatchQueue.global().async { lifetime.close(); group.leave() }
        XCTAssertEqual(group.wait(timeout: .now() + 2), .success)
        XCTAssertTrue(lifetime.isClosed)
        XCTAssertEqual(made.value + rejected.value, 32)
        XCTAssertEqual(cancelled.value, made.value)
    }
}
