# Windows application routing

This is the native Windows module for the desktop application's `envara.application-routing` version 1 RPC. It does not change networking on macOS and does not install or activate anything as part of a build.

## Current acceptance boundary

**The full arbitrary-application routing feature is not ready. The native helper reports `ready:false`, `verification.passed:false`, and `dns:false`, and refuses `prepareRoute` and `launch`.** A build or a loaded driver is not treated as a passed networking test. There is no environment variable, editable acceptance file, command-line switch, or RPC that overrides this gate.

Implemented native source:

- WFP ALE connect redirection for owned TCP flows, IPv4 and IPv6, with original-destination context and redirect-record propagation.
- A local authenticated SOCKS5 relay into the existing application-owned proxy core. The relay never connects directly to the original destination and does not fall back to no-auth SOCKS5.
- Owned UDP and non-TCP flow blocking. `udpPolicy:block` is explicit; this module does not advertise datagram proxying. Inbound physical-interface flows to attached applications are blocked so replies cannot create a direct path; local TCP IPC remains possible. Attachment is intended for outbound client applications, not local server publishing. Unattached processes continue through their existing networking policies.
- A suspended root process registered by process object and creation time, kernel process-create inheritance, exit cleanup, and process-table overflow rejection before an owned child executes. Executable-path-wide rules are not used.
- Creation under the named-pipe caller's interactive user token, never the privileged service token. A non-breakaway Job Object is assigned before the initial thread resumes; closing the service's job handle kills that owned process tree.
- Route revocation retains living process entries as blocked tombstones. Driver heartbeat expiry blocks new owned connections. Revocation closes relay sockets and terminates the job, and `stop` confirms zero active job processes before reporting success.
- BFE state subscription is established before the initial state read. The source invalidates route generations before stopping owned processes, denies subsequent owned child creation, drains referenced process objects outside the table lock, and rebuilds the six FWPM filters on BFE recovery. Kernel callouts register once; recovered filtering never revives an old route. Status, registration, and heartbeat check both BFE state and the actual filter objects. The native stop/crash timing remains unaccepted.
- A per-route DNS broker for a future owned resolver adapter: authenticated SOCKS5 to a fixed literal DoH endpoint, verified TLS, bounded DNS message validation, private TTL cache, HTTP `Age` deduction, and cancellation on route revocation. There is no system-resolver, ambient-proxy, HTTP-redirect, or direct-network fallback. Its private service boundary checks the pipe caller's actual PID, creation time and SID against the kernel-owned route. It is not exposed as a desktop RPC or claimed as interception of Win32 resolver calls; the public launch gate remains closed.
- Kernel device ACL restricted to SYSTEM/Administrators; local-only named-pipe ACL; client SID obtained by named-pipe impersonation; native client verifies the server PID against the installed SCM service before sending credentials; per-SID route and session ownership; bounded stdin and pipe frames; credentials held in memory only.

Not implemented or accepted:

- Safe attribution of an application's `DnsQuery`/`getaddrinfo` calls that are sent by the shared Windows DNS Client service. Capturing all `svchost.exe` DNS traffic would change other applications' network and is deliberately not done.
- A complete resolver adapter or OS isolation boundary for arbitrary attached executables. WFP's shared-service socket PID does not identify the original DNS caller; ETW observations after a request, a standalone DoH broker, or `DnsQueryEx` settings for one caller do not establish that coverage. An application must not be launched with this gap. The broker currently accepts ASCII DNS names; IDN normalization also belongs in the future adapter.
- Arbitrary software's requests handed to an existing system broker, an unrelated service, an already-running single-instance app, WSL, or an elevated launcher. These cannot be presented as ordinary owned descendants without explicit integration and tests.
- Windows kernel-driver build, Driver Verifier/HLK, driver signing, installation, and live networking acceptance. BFE restart/stop behavior also remains unaccepted: even the new source callbacks, filter checks and portable transition tests do not prove that owned processes always exit before filtering disappears during a real BFE stop or abrupt crash. The absence of a direct-connection window needs native fault testing. This checkout is being developed on macOS; Go cross-compilation does not exercise WFP.
- Windows OS geolocation spoofing or timezone changes. `TZ` is scoped to launched processes; applications that ignore it continue to use their own OS APIs.

Microsoft documents a separate connected-UDP limitation for local ALE redirection. This implementation avoids claiming a generic UDP relay and blocks UDP rather than routing it directly.

## Build and integration

`node scripts/build-windows-app-routing.mjs` cross-compiles the Go helper to:

```
build/app-routing/win32/x64/EnvaraAppRouting.exe
build/app-routing/win32/arm64/EnvaraAppRouting.exe
```

The desktop packages these as `resources/app-routing/win32/<arch>/EnvaraAppRouting.exe` and invokes `--rpc`. Each invocation accepts one JSON request on stdin and emits one JSON response on stdout. Requests and secrets must never be put in argv. The helper connects to `\\.\pipe\EnvaraApplicationRouting-v1`. The installed SCM service runs the same executable with `--service`. `status` and `setup` return capabilities and readiness; `setup` does not perform an implicit privileged install.

The driver project `driver/EnvaraAppRouting.vcxproj` targets Visual Studio 2022 + Windows 11 SDK/WDK, x64 and ARM64, with `/INTEGRITYCHECK`, SHA-256 catalog generation, Spectre mitigation, and signing disabled at build time. A production installer must use a legitimately Microsoft-signed driver package and a signed helper, grant user consent, install service `EnvaraAppRouting` as LocalSystem with a binary directory writable only by administrators, and use SCM dependencies on `BFE` and driver service `EnvaraAppRoutingDriver`. No third-party signatures or downloaded drivers are reused. Driver removal/replacement requires a reboot after stopping managed jobs; the production driver deliberately cannot unload while running.

The production-ready gate must be completed with **real** TCP/IPv6, UDP blocking, shared-DNS isolation, child-process/reuse, service/core failure, unaffected-app, VPN-coexistence, and cleanup tests. The `verification` response must only report a versioned pass after those platform tests actually succeed. Modifying a boolean is not an acceptable implementation of acceptance.

Microsoft Hardware Developer Program onboarding requires organization verification, an authorized legal contact and a purchased EV code-signing certificate. A personal Microsoft or Store developer account does not replace this process; the project has not completed enrollment or purchased a certificate. This requirement applies to publishing the custom kernel-driver route above, not every Windows desktop application. See [Microsoft's Hardware Developer Program registration requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/hardware-program-register).

## Local source checks

`node scripts/test-windows-app-routing.mjs` runs Go race tests, Go vet, and builds the helper for Windows x64 and ARM64. It compiles and executes the production lifecycle transition header and driver ABI assertions as portable C, checks the source's closed launch gate, and confirms the local unsupported-platform helper cannot spawn an application. DNS fixtures use loopback sockets only: they exercise authenticated SOCKS5 → verified TLS → a local DoH server, certificate refusal, fixed literal CONNECT, HTTP `Age`/cache expiry, redirect refusal, and cancellation. It does not activate a driver, require administrator rights, contact a real node or resolver, or read user credentials.

## Primary sources

- [WFP bind/connect redirection and proxy redirect-record tracking](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)
- [ALE authorization applies to TCP, the first UDP packet to a tuple, and raw ICMP](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers)
- [Microsoft's connected-UDP local-redirection limitation](https://learn.microsoft.com/en-us/troubleshoot/windows-hardware/drivers/redirection-connected-udp-traffic-local-proxy-fail)
- [Process-create callbacks and integrity requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [Windows Job Objects and kill-on-close process tree ownership](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [Kernel driver signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)
- [BFE state subscription, initial-read ordering and callback cleanup](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpmk/nf-fwpmk-fwpmbfestatesubscribechanges0)
- [WFP filtering conditions available at each layer](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer)
- [Cloudflare DoH wire-format endpoint](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/)
- [DoH HTTP cache age and DNS TTL requirements](https://www.rfc-editor.org/rfc/rfc8484.html#section-5.1)

The Go helper uses Go standard libraries and `golang.org/x/sys v0.30.0` (BSD-3-Clause), pinned by `go.sum`. The driver and helper implementation are original project source under Envara's MIT license; no WFPSampler code is copied.
