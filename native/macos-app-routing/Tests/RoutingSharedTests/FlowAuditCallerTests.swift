import XCTest
import Darwin
@testable import RoutingShared

final class FlowAuditCallerTests: XCTestCase {
    func testCurrentKernelTokenResolvesItsActualProcessAndExecutable() throws {
        let caller = try FlowAuditCaller.inspect(FlowAuditCaller.currentToken(), authorizedUID: getuid())
        XCTAssertEqual(caller.identity.pid, getpid())
        XCTAssertEqual(caller.identity, ProcessIdentity.read(getpid()))
    }

    func testMissingTruncatedAndOversizedTokensAreRefused() {
        for count in [0, 1, MemoryLayout<audit_token_t>.size - 1, MemoryLayout<audit_token_t>.size + 1, 4096] {
            XCTAssertThrowsError(try FlowAuditCaller.inspect(Data(repeating: 0, count: count), authorizedUID: getuid())) { error in
                XCTAssertEqual(error as? FlowAuditCallerError, .malformed)
            }
        }
    }

    func testEmptyIdentityCannotBecomeAFlowCaller() {
        XCTAssertThrowsError(try FlowAuditCaller.inspect(Data(repeating: 0, count: MemoryLayout<audit_token_t>.size), authorizedUID: getuid())) { error in
            XCTAssertEqual(error as? FlowAuditCallerError, .malformed)
        }
    }

    func testEvenALiveKernelTokenIsRefusedForAnotherWorkspaceOwner() throws {
        let token = try FlowAuditCaller.currentToken()
        let other = getuid() == 0 ? uid_t(501) : uid_t(0)
        XCTAssertThrowsError(try FlowAuditCaller.inspect(token, authorizedUID: other)) { error in
            XCTAssertEqual(error as? FlowAuditCallerError, .foreignUser)
        }
    }
}
