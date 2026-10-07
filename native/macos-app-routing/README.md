# macOS application routing

This is a native source implementation for Envara's attached applications. It is
not a global TUN, system proxy, or a wrapper that relies on `HTTP_PROXY`.

The Swift package builds a host/controller app and an `NEAppProxyProvider` system
extension. A per-app configuration profile matches the chosen software's code
identity and includes its spawned helpers by omitting `MatchTools`. Unmatched
software is not added to a global route.

## Implemented source

- Mandatory-authentication SOCKS5 TCP forwarding through Envara's loopback core.
  Hostname endpoints remain hostnames; the helper never resolves them directly.
- SOCKS5 UDP ASSOCIATE forwarding with a loopback-only relay and authenticated
  TCP control-channel lifetime. Fragmented SOCKS datagrams are rejected.
- UDP blocking when the node does not support it. Low-level DNS requests can
  still use DNS-over-TCP through the same SOCKS route. DNS resolver settings are
  scoped to the per-app provider.
- Domain and DNS-question blocking for Envara's standard/strict tracker sets.
  There is no TLS interception, arbitrary app binary patching, or claim that
  hardcoded IP telemetry and encrypted DNS can all be identified.
- Private, atomic `0600` runtime route/session records in the entitled App Group.
  Listener credentials are absent from argv, profiles and RPC output.
- A launch guardian sets the selected working directory and process-only TZ and
  tool configuration. It tracks process groups/observed descendants with PID,
  executable and start-time checks to avoid killing a reused PID.
- Route revocation closes captured flows and keeps the application's VPN mapping
  enabled. It never disables the mapping as a cleanup shortcut to DIRECT.
- Read-only status inspects signature entitlements, App Proxy configurations and
  the actual enabled extension's binary hash. Missing authorization or acceptance
  causes `notReady` before an application can launch.

`ProcessFamily` covers ordinary descendants and observed detached helpers. A
shared system/XPC daemon and a helper that escapes before it can be observed need
app-specific acceptance. The system extension and guardian must be fault-tested;
these source/transport tests do not demonstrate OS-level crash leak protection.
macOS GUI apps can also choose to ignore `TZ`, or read location and credentials
through OS services. Routing does not change the OS timezone, Core Location,
Keychain, device identifiers, or existing accounts.

## Build and validate source

From the repository root:

```sh
swift test --package-path native/macos-app-routing
node scripts/build-macos-app-routing.mjs
```

This compiles both binaries and creates
`build/app-routing/macos/EnvaraAppRouting.app`. It does not install a profile,
activate an extension, request a VPN connection, change system routes or connect
to a real proxy node. An unsigned source build correctly returns `ready:false`.

The desktop adapter invokes
`EnvaraAppRouting.app/Contents/MacOS/EnvaraAppRoutingHelper --rpc`, writes one
`envara.application-routing` version 1 JSON request to stdin and reads one response
from stdout. Methods are `status`, `setup`, `prepareRoute`, `launch`, `stop` and
`revoke`. `stop` accepts `sessionId` or `routeId`; it reports `stopped:true` only
after the guardian confirms the tracked family has exited. If confirmation fails,
keep the route/mapping retained and report incomplete cleanup.

## Signed deployment and acceptance

1. Register the host `io.envara.app-routing`, provider
   `io.envara.app-routing.proxy`, shared group `group.io.envara.app-routing` and
   Network Extension capability and host System Extension capability in the developer account. Use the provided
   entitlement templates and provisioning profiles that actually grant them.
2. Build with `--sign` and explicit `ENVARA_MAC_SIGN_IDENTITY`,
   `ENVARA_MAC_HOST_PROFILE` and `ENVARA_MAC_EXTENSION_PROFILE`. The identity must
   be Developer ID Application. Notarize/staple the signed containing app as part
   of distribution. None of these are done by the unsigned build command.
3. The explicit `setup({activate:true})` RPC requests extension activation. macOS
   may require user approval/reboot. It must run from the signed installed host
   bundle, not a loose Swift executable.
4. `setup({application:{path,executablePath,identity}})` generates a private
   `.mobileconfig` containing the per-app VPN and code-identity mapping. Present
   that file for the user's macOS configuration-profile installation. Generation
   does not install anything. Do not use undocumented PF/SIP workarounds.
5. On a signed native test installation, verify TCP, UDP forwarding/blocking, both
   DNS API paths, spawned helpers, core outage, extension restart/crash and normal
   VPN coexistence. Test each supported app. Only actual successful native
   acceptance can produce `routing-acceptance.plist`: `passed`, `version`,
   `providerVersion`, `providerSHA256`, `osMajor`, `testedApplications`, and
   `checks.{tcp,udp,dns,childProcesses,failClosed}`. A transport/unit test report
   must never be converted into this receipt. Embed it with
   `ENVARA_MAC_ACCEPTANCE_RECEIPT` before signing; the helper checks the signed
   resource seal, exact provider hash, OS version and selected app's identity.

No Apple signing identity, provisioning profile or OS-level acceptance receipt is included in this
repository. The current implementation intentionally cannot become ready through
an environment variable, UI checkbox, fake profile or unsigned helper.

### Local Apple Development signing

This requires an Apple Developer Program team with Network Extension and System
Extension capabilities. A free Personal Team cannot provision either capability;
having an Apple Development certificate alone is insufficient.

Use `node scripts/build-macos-app-routing.mjs --development-sign` (or explicit
`ENVARA_MAC_SIGN_MODE=development`) with `ENVARA_MAC_SIGN_IDENTITY` set to the exact
`Apple Development:` identity and the two `ENVARA_MAC_*_PROFILE` paths. Each must
be a valid Apple-signed Mac App Development profile for its explicit App ID,
the same certificate/team, and this Mac's Provisioning UDID. The host profile
must grant `com.apple.developer.system-extension.install`; both must grant
standard `app-proxy-provider` and the shared App Group. The script derives
`com.apple.application-identifier` and `com.apple.developer.team-identifier`
from verified profiles instead of guessing App ID prefixes.

The development helper is separately compiled with
`ENVARA_LOCAL_DEVELOPMENT_ROUTING`, uses an independent scratch directory and
outputs to `build/development-app-routing/macos`, outside production packaged
resources. The default helper continues to require Developer ID and the
`app-proxy-provider-systemextension` value; a runtime environment variable cannot
change this policy. `--sign` retains the production Developer ID path. Mixing
CLI/environment modes, profiles, certificates or development/distribution
entitlements is rejected.

Build-time and runtime validation authenticate CMS signatures with public
Security APIs, restrict the chain to OS-supplied Apple production roots and
check the dedicated Mac profile signer, certificate class, Team, App ID,
entitlements, validity and device scope. Network trust fetching is disabled;
this checks locally available trust, not current online revocation status. A
decoded plist or successful `security cms -D` is not authorization evidence.
Unsigned rebuilds remove embedded profiles, signature metadata and acceptance
receipts from both host and provider. None of these commands installs a profile,
activates a system extension or marks native routing ready. The exact same
OS/profile/provider and per-application acceptance gates remain mandatory.

No positive Apple signing/profile or system activation test has been run without
real signing assets. Compilation, parser/CMS rejection tests and unsigned RPC
refusals do not establish an operational per-app route.

## Primary API references

- [App Proxy flow and DNS handling](https://developer.apple.com/documentation/networkextension/neappproxyprovider)
- [Helper-process matching](https://developer.apple.com/documentation/networkextension/neapprule/matchtools)
- [Provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
- [Per-app mapping schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.vpn.managed.appmapping.yaml)
- [App Proxy manager profile configuration](https://developer.apple.com/documentation/networkextension/neappproxyprovidermanager)
- [Membership and macOS capability matrix](https://developer.apple.com/help/account/reference/supported-capabilities-macos/)
- [Development versus Developer ID entitlements](https://developer.apple.com/forums/thread/737894)
- [Provisioning profile binding](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
- [Register this Mac's Provisioning UDID](https://developer.apple.com/help/account/devices/register-a-single-device)
