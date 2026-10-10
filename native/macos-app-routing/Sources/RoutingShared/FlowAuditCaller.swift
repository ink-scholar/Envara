import Foundation
import Darwin
import RoutingAudit

public enum FlowAuditCallerError: Error, Equatable {
    case system(Int32), malformed, foreignUser, identityChanged, unavailable(ProcessProbeFailure)
}

/// NE supplies a nullable source-application kernel token. Delegated DNS
/// attribution requires native acceptance; missing/unknown callers are refused.
/// No flow may substitute an IPC PID or an executable-name match.
public struct FlowAuditCaller {
    public let identity: ProcessIdentity
    public let pidVersion: Int32
    private let tokenData: Data

    private static func decode(_ data: Data) throws -> (envara_audit_caller, String) {
        var caller = envara_audit_caller()
        var executable = [CChar](repeating: 0, count: envara_audit_path_capacity())
        let error = data.withUnsafeBytes { bytes in
            executable.withUnsafeMutableBufferPointer { buffer in
                envara_audit_copy_caller(bytes.baseAddress, bytes.count, &caller, buffer.baseAddress, buffer.count)
            }
        }
        guard error == 0 else {
            if error == EINVAL { throw FlowAuditCallerError.malformed }
            throw FlowAuditCallerError.system(error)
        }
        return (caller, String(cString: executable))
    }

    public static func inspect(_ data: Data, authorizedUID: uid_t) throws -> FlowAuditCaller {
        let (token, executable) = try decode(data)
        guard token.effective_uid == authorizedUID, token.real_uid == authorizedUID else {
            throw FlowAuditCallerError.foreignUser
        }
        let current: ProcessIdentity
        switch ProcessIdentity.inspect(token.pid, nil, authorizedUID: authorizedUID) {
        case .found(let identity): current = identity
        case .gone: throw FlowAuditCallerError.identityChanged
        case .unknown(let failure): throw FlowAuditCallerError.unavailable(failure)
        }
        guard current.path == executable else { throw FlowAuditCallerError.identityChanged }
        // Reading libproc state must not combine an old flow token with a reused
        // PID or exec. Revalidate against the same kernel generation afterwards.
        let (final, finalExecutable) = try decode(data)
        guard final.pid == token.pid, final.pid_version == token.pid_version,
              final.effective_uid == token.effective_uid, final.real_uid == token.real_uid,
              finalExecutable == executable else { throw FlowAuditCallerError.identityChanged }
        return FlowAuditCaller(identity: current, pidVersion: token.pid_version, tokenData: data)
    }

    /// Recheck a retained kernel token after reparenting. An exec, including
    /// the same executable path, or PID reuse invalidates the old generation.
    public func isCurrent(authorizedUID: uid_t) -> Bool {
        guard let actual = try? Self.inspect(tokenData, authorizedUID: authorizedUID) else { return false }
        return actual.pidVersion == pidVersion && actual.identity.pid == identity.pid &&
            actual.identity.startedSeconds == identity.startedSeconds &&
            actual.identity.startedMicroseconds == identity.startedMicroseconds && actual.identity.path == identity.path
    }

    public static func currentToken() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: MemoryLayout<audit_token_t>.size)
        var length = 0
        let error = bytes.withUnsafeMutableBytes { envara_audit_copy_current_token($0.baseAddress, $0.count, &length) }
        guard error == 0, length == bytes.count else { throw FlowAuditCallerError.system(error == 0 ? EIO : error) }
        return Data(bytes)
    }
}
