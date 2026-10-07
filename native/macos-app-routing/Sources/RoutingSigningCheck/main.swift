import Foundation
import RoutingShared

// Build-time authorization check. This does not install or activate anything.
// Output is deliberately limited to hashes, team and App IDs, never profile data.
do {
    let bytes = FileHandle.standardInput.readDataToEndOfFile()
    guard bytes.count <= 16_384,
          let request = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
          let modeValue = request["mode"] as? String, let mode = RoutingSigningMode(rawValue: modeValue),
          let identity = request["identity"] as? String,
          let hostPath = request["hostProfile"] as? String,
          let extensionPath = request["extensionProfile"] as? String else { throw RoutingError.invalidRequest }
    let certificate = try RoutingSigningAuthorization.signingIdentity(named: identity, mode: mode)
    let devices = mode == .development ? try RoutingSigningAuthorization.deviceIdentifiers() : []
    let host = try RoutingSigningAuthorization.validateProfile(Data(contentsOf: URL(fileURLWithPath: hostPath)), certificate: certificate,
                       bundleIdentifier: RoutingSigningAuthorization.hostIdentifier, host: true, mode: mode, devices: devices)
    let provider = try RoutingSigningAuthorization.validateProfile(Data(contentsOf: URL(fileURLWithPath: extensionPath)), certificate: certificate,
                       bundleIdentifier: RoutingSigningAuthorization.providerIdentifier, host: false, mode: mode, devices: devices)
    guard host.team == provider.team, host.certificateSHA256 == provider.certificateSHA256 else { throw RoutingError.notReady("host-provider-signing-team-mismatch") }
    let result: [String: Any] = ["verified": true, "mode": mode.rawValue, "networkEntitlement": mode.networkEntitlement,
                               "host": host.dictionary, "provider": provider.dictionary]
    FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]))
} catch {
    // Avoid Foundation errors containing private provisioning-profile paths.
    let reason = (error as? RoutingError)?.errorDescription ?? "signing-profile-validation-failed"
    FileHandle.standardError.write(Data((reason + "\n").utf8))
    exit(1)
}
