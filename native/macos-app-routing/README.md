# macOS application routing

This is a native source implementation for Envara's attached applications. It is
not a global TUN, system proxy, or a wrapper that relies on `HTTP_PROXY`.

The Swift package builds a host/controller app and an `NEAppProxyProvider` system
extension. A per-app configuration profile matches the chosen software's code
identity and includes its spawned helpers by omitting `MatchTools`. Unmatched
software is not added to a global route.

## Application realms and DNS acceptance

Each owned executable path has a persistent `vpnUUID`. A route also records its
exact code signing identifier and designated requirement. Manager selection
requires one matching realm marker, one exact executable rule and the matching
signature conditions. A nil/broad path, missing marker, duplicate manager,
conflicting rule (including a broad directory prefix) or wrong realm is refused.
The selected application's existing GUI instance and live owned session are
checked before preparing a route; executable symlink aliases are rejected.
A revoked connected provider can bind a new private route only in the same realm,
with no old route, active flows or cancellation in progress. Other managers are
never stopped. Failed preparation requires a provider revocation acknowledgement
or confirmation that its newly started, previously idle manager disconnected;
unconfirmed cleanup retains the record and fails. Old route files without the new UUID/requirement fields
are rejected; no realm is guessed during migration.

Profile generation maintains a private owned manifest and emits one stable
`com.apple.vpn.managed.appmapping` payload containing all its mappings, with a
separate app-layer payload per UUID. Repeated full paths or UUIDs are rejected.
Two unchanged copies with the same bundle/signing identity at different full
executable paths may be represented by different realms. Two instances at the
same full path cannot select different realms. The helper does not copy, patch
or re-sign user applications. Generating a profile does not install it, alter an
administrator's existing mapping or prove concurrent per-app VPN operation.

`NEAppRule` conditions are combined with AND; `matchPath` is the executable path.
Apple documents that omitted `MatchTools` includes the matching application's
spawned helper tools. This is not an acceptance result for shared system/XPC
services or every process that an application might trigger. The current Apple
[mapping schema](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/profiles/com.apple.vpn.managed.appmapping.yaml)
allows manual macOS installation and only one mapping payload. The
[payload multiplicity definition](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/docs/schema.md#L55)
applies to installed copies, including the user/device scope. Current developer
schema and the older Apple deployment page disagree about multiple app-layer
payloads, so serialization tests do not establish multiple active UUIDs.

Unlike a transparent proxy, an App Proxy can provide per-app resolver settings
for low-level `getaddrinfo` and receive hostname endpoints from higher-level
network APIs. Apple's
[transparent-proxy documentation](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider)
explicitly says DNS settings are ignored there; Envara's original signed external
Redirector remains a diagnostic component, not a substitute for this provider.
Apple's published older QUERIER source distinguishes outstanding questions by
[DNS service](https://github.com/apple-oss-distributions/mDNSResponder/blob/d89f8d1d0e001b810d6c055aa2a57b768bcf9aa2/mDNSCore/mDNS.c#L13909-L13942)
and also scopes
[cached answers](https://github.com/apple-oss-distributions/mDNSResponder/blob/d89f8d1d0e001b810d6c055aa2a57b768bcf9aa2/mDNSCore/DNSCommon.c#L2136-L2140)
to that service. This supports testing independent resolver realms; it does not
prove that this provider's configurations produce independent services on the
current OS. The newer portable OSS omits Apple's QUERIER implementation.

Native acceptance must demonstrate two same-signature executables at different
paths using different UUIDs simultaneously, fresh and cached same-name A/AAAA
queries (both launch orders and concurrent queries), ordinary spawned helpers,
unmatched applications and existing VPN coexistence. Core/provider/guardian
failure must also be tested. No cache flushing, ignored second answer or relaxed
DNS gate can substitute for those results. All production readiness and signed
acceptance-receipt checks remain mandatory and false for an unsigned build.
A dedicated fixture entry uses the compile-time
`ENVARA_NATIVE_ROUTING_ACCEPTANCE` flag in the helper only. It copies the complete
production provider without recompiling or re-signing it, while using a separate
runtime namespace, profile identifiers and output host. Production
`prepareRoute`/`launch` still require a successful sealed receipt. A fixture result
may establish behavior of those exact provider bytes; it cannot attest Notion or
any other application that was not actually tested. Neither an unsigned fixture
run nor the read-only plan creates a production acceptance receipt.
Process exit attribution, whole-provider crash handling and same-realm restart
still require real macOS acceptance; shared logic tests cannot establish them.
Process probes now distinguish confirmed alive, confirmed gone and unknown.
Only ESRCH or a different birth generation confirms the original process exited;
permission, timeout, short reads and changed executable identities stay unknown
and cannot be signalled or used to release a route. Failed/truncated family
enumeration retains uncertainty even if a later list is empty. A guardian writes
an unverified error journal and keeps the mapping; it cannot label that scope
stopped. A private starting journal is written before launching. Old journals
without explicit scope/unknown-PID fields fail closed rather than inventing exit
proof. Mock fault tests and an owned sleep process's natural exit check cover
these wrappers; complete application/Network Extension acceptance remains open.

## Implemented source

- Mandatory-authentication SOCKS5 TCP forwarding through Envara's loopback core.
  Hostname endpoints remain hostnames; the helper never resolves them directly.
  Write EOF sends a real TCP FIN while keeping the read direction available;
  duplicate EOF is idempotent and writes after EOF are refused. Local transport tests include
  a 512 KiB response held until FIN. System flow half-close remains a native
  acceptance requirement, including whether the OS keeps that flow writable.
- SOCKS5 UDP ASSOCIATE forwarding with a loopback-only relay and authenticated
  TCP control-channel lifetime. Fragmented SOCKS datagrams are rejected.
- UDP blocking when the node does not support it. Low-level DNS requests can
  still use DNS-over-TCP through the same SOCKS route. DNS resolver settings are
  scoped to the per-app provider.
  UDP53 and framed TCP53 use the same authenticated TCP DNS exchange, validate
  the transaction, question and complete wire message, and close owned resources
  on an eight-second deadline. Large UDP answers return a complete question with
  TC; subsequent TCP exchanges remain validated. Raw UDP53 replies are refused.
  Provider stream framing uses the tested bounded buffer and relative Data
  indices, preserving consecutive and fragmented queries without index traps.
  These checks do not establish separate OS resolver/cache realms.
- Domain and DNS-question blocking for Envara's standard/strict tracker sets.
  There is no TLS interception, arbitrary app binary patching, or claim that
  hardcoded IP telemetry and encrypted DNS can all be identified.
- Private, atomic `0600` runtime route/session records in the entitled App Group.
  Listener credentials are absent from argv, profiles and RPC output.
- A launch guardian sets the selected working directory and process-only TZ and
  tool configuration. It tracks process groups/observed descendants with PID,
  executable and start-time checks to avoid killing a reused PID.
- Each new flow requires its system-supplied source audit token, the authorized
  user and a live parent chain to the configured application's full path.
  A process group or matching executable name alone grants no access. Retained
  orphan proofs apply only to callers that previously supplied a valid token;
  the token is rechecked against the same kernel exec generation before reuse.
  Missing tokens and unproved delegated callers are refused. Actual delegated
  DNS attribution and descendant coverage still require native acceptance.
- Route revocation closes captured flows and keeps the application's VPN mapping
  enabled. It never disables the mapping as a cleanup shortcut to DIRECT.
- A guardian renews its boot-scoped continuous-clock lease every 250 ms. The
  provider checks it on new flows and every 250 ms, with a maximum three-second
  lifetime. A missing initial lease permits no traffic; an expired, malformed,
  closed, replayed or uncertain lease closes captured flows and cannot reopen
  the same route through a late heartbeat. This source mechanism does not prove
  whole-guardian/provider crash isolation on macOS; those native tests remain
  required.
- Flow admission retains the exact route, VPN realm, guardian session and
  ownership instance under one lock, then rechecks the lease immediately before
  creating a session. A rebind or revoke invalidates earlier admission results.
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

The test-only `EnvaraRoutingAuditFixture` uses private pipes to expose its own
kernel token, then execs the same image for a generation-change check. It makes
no network requests and is not copied into the desktop bundle or native
acceptance host. Token bytes are not printed to terminal or diagnostic logs.

The desktop adapter invokes
`EnvaraAppRouting.app/Contents/MacOS/EnvaraAppRoutingHelper --rpc`, writes one
`envara.application-routing` version 1 JSON request to stdin and reads one response
from stdout. Methods are `status`, `setup`, `resolveRealm`, `prepareRoute`, `launch`,
`stop` and `revoke`. `status.component` identifies this helper as
`envara-app-proxy`; component availability is separate from verified signing and
production readiness. `resolveRealm({application:{path,executablePath}})` reads
only the owned manifest, checks the application's current signed identity and
returns only `vpnUUID`. It never creates directories/profiles, changes permissions
or activates a provider. Missing or ambiguous entries fail. `prepareRoute`
requires that UUID and rechecks the exact installed manager binding. `stop`
accepts `sessionId` or `routeId`; it reports `stopped:true` only
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
   `.mobileconfig` containing all owned per-app VPN and code-identity mappings.
   `applications:[...]` can request several entries together; each may supply
   its `vpnUUID`, while repeating an identical existing entry reuses its UUID.
   Conflicting or duplicate requests are rejected. Present
   that file for the user's macOS configuration-profile installation. Generation
   does not install anything. Do not use undocumented PF/SIP workarounds.
5. On a signed native test installation, verify TCP, UDP forwarding/blocking, both
   DNS API paths, spawned helpers, core outage, extension restart/crash and normal
   VPN coexistence. Test each supported app. Only actual successful native
   acceptance can produce `routing-acceptance.plist`: `passed`, `version`,
   `providerVersion`, `providerSHA256`, `providerBundleSHA256`, `osMajor`, `testedApplications`, and
   `checks.{tcp,udp,dns,childProcesses,failClosed}`. A transport/unit test report
   must never be converted into this receipt. Embed it with
   `ENVARA_MAC_ACCEPTANCE_RECEIPT` with explicit `--reuse-provider` pointing to
   the tested production manifest before signing the final host. That build
   reuses the complete signed provider unchanged; it must not create a new
   timestamp/signature and invalidate the tested Mach-O hash. The helper checks
   the signed resource seal, exact binary and complete bundle hashes, OS version
   and selected app's identity.

No Apple signing identity, provisioning profile or OS-level acceptance receipt is included in this
repository. The current implementation intentionally cannot become ready through
an environment variable, UI checkbox, fake profile or unsigned helper.

The current [TN3134 deployment table](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
does not restrict macOS App Proxy system extensions to MDM-managed devices and
supports direct Developer ID distribution. A personal Mac can use the documented
manual profile workflow; Envara's complete signing, installation, multi-realm
and native acceptance workflow has not been exercised here. The publisher needs
Apple-authorized signing/provisioning assets; recipients use the signed product
and macOS approval flow rather than obtaining their own developer membership.

This requirement applies to the owned or modified extension, not to running an
existing unmodified third-party signed component. Envara also retains the
original signed mitmproxy Redirector diagnostic route, which does not require
the user to enroll in the Apple Developer Program. Its same-hostname system DNS
realm isolation still failed after the user reported TUN disabled; it has not
passed the complete attached-application acceptance gates.

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


## Isolated native fixture tooling

First build the production provider with `npm run routing:build:mac` (or its
explicit signing mode). `npm run routing:build:mac:acceptance` then builds a
non-activated fixture host at
`build/acceptance-app-routing/macos/EnvaraRoutingAcceptance.app`. The acceptance
build requires the corresponding production `manifest.json`; its default source
is `build/app-routing/macos/manifest.json`, or
`build/development-app-routing/macos/manifest.json` for local development signing.
`--reuse-provider /absolute/path/to/manifest.json` explicitly chooses another
matching production build. Its
`--acceptance-rpc` protocol accepts only status, fixture profile generation,
explicit extension activation, and prepare/launch/stop/revoke of the sealed
`one` and `two` fixtures. The production helper rejects this entry and the
renderer/REST/MCP desktop dispatcher does not expose its methods.

The host, provider and App Group use the production identifiers:
`io.envara.app-routing`, `io.envara.app-routing.proxy`, and
`group.io.envara.app-routing`. The earlier diagnostic design with distinct
`.acceptance` App IDs tested a different provider and is historical; it cannot
be reused as a production provider proof. The current build compiles only the
helper, signing checker and fixtures. It copies the entire provider bundle from
the selected manifest verbatim, including its embedded profile and signature,
and checks its complete fingerprint before copying and after sealing the host.
For a signed source, the native Security checker also validates the actual
provider bundle against the exact compatible profiles, certificate and Team.
A manifest alone is byte provenance, not Apple authorization. An unsigned source
can be copied for development refusal tests, but cannot issue a receipt.

Both bundles use the fixed Mach service
`group.io.envara.app-routing.service`, prefixed by the actual shared App Group.
The provider supports only the fixed `production` and
`owned-fixture-acceptance` VendorConfig namespaces. Their private files live in
`EnvaraRouting` and `EnvaraFixtureAcceptance` respectively; managers must match
the selected namespace and exact realm. The fixture helper never reads or edits
the production owned manifest or journals.

Sign with `--acceptance --development-sign` or `--acceptance --sign` only when
the corresponding production assets exist. Installation into an appropriate
Applications directory remains a separate explicit operation; do not overwrite
an existing user installation. Activation requires the user's OS interaction.
The acceptance activation delegate refuses replacement, and existing provider
properties must match the complete expected bundle before activation is
requested. A different installed provider, including one with the same version
number, must be retained and reported as a conflict. Do not delete an installed
acceptance host while macOS still associates the active extension with it.
No account is enrolled or purchased.

Profile identifiers and payload UUIDs are separate from production. This does
not bypass Apple's one-appmapping limit. Read-only profile assessment must
distinguish the applicable user and device channels; it must not treat a limited
user-channel view as proof that no device mapping exists. Unknown scope or an
existing applicable mapping blocks fixture installation unless a separately
reviewed, user-approved migration has been planned. The fixture tools must not
remove or silently merge production or third-party mappings. A clean test user
or host is the appropriate first native acceptance environment.

`npm run routing:accept:mac:plan` reads status and writes a local pending matrix.
It launches no fixture and changes no VPN/TUN setting. The separately explicit
`--setup-profiles` operation generates a profile; installation still needs the
user's OS interaction. `--activate-extension` explicitly requests system
activation, never starts capture as a side effect of status.

`node scripts/accept-macos-app-proxy.mjs --run-fixtures` explicitly runs the
owned native subset only after build-byte and native authorization checks.
The work and cleanup budget is 115 seconds, with at most two additional seconds
for unconfirmed helper teardown; uncertainty prevents later mutations. It
cannot launch user software or generate a production receipt. The current
unsigned build was actually refused at authorization before opening fixture
listeners or starting fixture processes; all native checks remain false.
Current source verification is 157 Swift tests and 281 Node tests (279 pass and
two explicit Chromium skips). The earlier lease snapshot also verified 12
rebuilt native refusal gates; the latest default plan remains read-only. These do not
prove first-packet, whole guardian/provider crash, unrelated desktop software,
or Notion routing.

Fixtures have bounded JSON commands for synthetic DNS names, reserved numeric
TCP/UDP endpoints and at most two copies of their own executable. Control uses a
private directory and UID-checked 0600 Unix socket. Request, payload, deadline,
idle and whole-process lifetime limits are enforced. They cannot execute arbitrary
commands or launch user apps. The helper rejects caller app paths, arguments,
environment and working directory. Same cert/Team, strict bundle validity and a
resource-sealed executable SHA manifest are required even in diagnostic mode.

Readable journals are distinct from verified process scope. Unknown/corrupted
scope keeps production readiness false. Guardian identities and app identities
must match exact parent, executable and process group before cleanup signals are
allowed. Cleanup is installed before throwing post-spawn journal IO; an uncertain
identity retains the route rather than claiming exit.

Offline fixture transport/process tests and unsigned refusal tests do **not**
prove native AppProxy routing. Only a real successful matrix against the copied
signed provider can support a provider receipt; this tooling currently creates
no production receipt or Notion acceptance. Multiple-active-realm DNS/cache
isolation, unaffected-application compatibility and whole-guard crash behavior
remain explicit native gates. Even a successful owned-fixture matrix may list
only the tested fixture identities, never Notion or arbitrary software.
