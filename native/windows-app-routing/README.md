# Windows application routing

The default Windows capture source uses the unmodified, officially signed **WinDivert 2.2.2-A x64** driver and a separate Envara user-mode DLL/Go service. The old custom WFP kernel driver remains under `driver/` as an inactive alternative; it is not built, installed or required by this route. This avoids applying for our own kernel-driver signing certificate merely to build this candidate. Administrator permission and native driver-trust checks are still necessary for eventual installation.

## Current acceptance boundary

**Application routing is not ready for arbitrary software.** `ready`, `dns`, `failClosed` and `verification.passed` remain false. `prepareRoute` and `launch` refuse to run. There is no command, RPC, environment variable or editable acceptance file that overrides this gate. Status/setup inspect protected files and hashes; they do not load a DLL, install a service or open a driver. Cross-compilation on this Mac is source/build evidence only.

## Implemented source

- SOCKET events and packet-triggered owner lookup, actual process handles, PID plus creation time and membership in retained non-breakaway Jobs. A root is created suspended under the named-pipe caller's interactive token, assigned to its Job and registered before resume. The LocalSystem service does not launch the application under its own token.
- Separate opaque route/session generations and a portable ownership registry, including confirmed-unowned decisions, bounded capacity and irreversible revocation. The same executable path can have different process identities; path-wide proxy rules are not the capture boundary.
- Complete IPv4/IPv6 TCP tuple NAT into Windows' own TCP stack at the local relay, unique aliases, original destination recovery and single-use lookup. The relay uses only the selected authenticated loopback SOCKS route; it has no direct fallback. The old WFP redirect-record API is not used on WinDivert connections.
- Explicit owned UDP and TCP/UDP DNS-port blocking. This prototype does not advertise UDP proxying or shared-system DNS interception. Unknown ownership is held briefly then dropped. These behaviors are not a substitute for complete routing or proof that all unrelated applications are unaffected.
- Revocation blocks retained owned identities, closes relay connections and terminates Jobs; stop waits for zero active Job processes. The guard owns capture handles separately from relay workers. Failures in the guard itself remain an unresolved boundary.
- Administrator-protected installation directory/ancestor/file ACL checks, no reparse points, retained non-write-share file handles, strict SHA-256 ABI provenance, absolute-path DLL loading with constrained search flags and x64-only capture. Hash provenance does not establish Authenticode trust or native networking acceptance.
- Local-only named-pipe RPC with actual caller PID/SID/creation time; the client checks the installed SCM server identity before sending credentials. Secrets stay in bounded private stdin/pipe frames and memory, not argv or export files.
- A separate per-route authenticated SOCKS → verified TLS → literal DoH broker with private TTL/Age-aware cache and cancellation. It is a foundation for a future resolver adapter, not proof that Win32 DNS requests were intercepted.

## Remaining work

1. Attribute and intercept arbitrary Win32 `DnsQuery`/`getaddrinfo` calls sent through the shared DNS Client service, without routing unrelated `svchost.exe` traffic. A packet PID, ETW event or controller's own `DnsSetApplicationSettings` call cannot by itself do this. Per-route DoH is not the missing resolver adapter.
2. Preserve blocking if the whole guard process or driver fails. The stock WinDivert driver removes its filters on handle cleanup and may reinject pending original packets. Job kill-on-close and worker cancellation do not prove there is no direct-connection window. A persistent protection or stronger OS isolation boundary is required.
3. Native Windows acceptance for PID/socket reuse, actual child processes, IPv4/IPv6 TCP, UDP/DNS blocking, both environments concurrently, unchanged unrelated applications, resource exhaustion, abrupt guard/core failures, Windows firewall/VPN coexistence and cleanup. Windows x64 is the first capture target. ARM64 has only a helper cross-build, because this pinned release has no ARM64 driver.
4. Privileged per-machine installation with protected ACLs, user consent, service lifecycle and native Authenticode/Secure Boot/HVCI verification. No component was installed or activated on this Mac. A controller must not silently reuse a user's existing WinDivert/mitmproxy installation.

A [candidate PowerShell component installer](installer/README.md) now implements read-only Validate/Plan, explicit protected per-machine installation, manual SCM registration and service-only uninstall with files retained. Its grammar/schema have been checked on macOS; UAC, ACLs, driver trust and SCM operations still require Windows testing. It never activates capture or changes the launch gate. Build output includes the exact `install-manifest.json` and prints its review digest.

Software using an already-running single-instance process, an existing system service, WSL or an external elevated broker needs specific integration. GUI timezone/location APIs, device identity and encrypted application telemetry are not spoofed by this route.

## Build

`npm run routing:build:win` builds Go x64/ARM64 helpers and the x64 capture DLL. On macOS/Linux it requires `x86_64-w64-mingw32-gcc`; on Windows use a current Visual Studio x64 Developer Command Prompt or set `ENVARA_WINDOWS_CC` to an x64 MinGW compiler. Go is also a build prerequisite. These compilers are developer tools, not runtime dependencies.

`prepare-windivert.mjs` downloads only pinned official archive/source bytes, checks fixed SHA-256 digests and preserves the original DLL and signed driver without patching or re-signing. Generated resources live in ignored `build/app-routing/win32/`:

- `x64/EnvaraAppRouting.exe`, `EnvaraCapture.dll`, `WinDivert.dll`, `WinDivert64.sys`, `capture-provenance.json`, full WinDivert corresponding source, licenses and provenance.
- `arm64/EnvaraAppRouting.exe` and an explicit `CAPTURE-UNAVAILABLE.txt`; there are no falsely labelled ARM64 driver resources.

The Electron application packages these under `resources/app-routing/win32/<arch>/`. RPC version 1 uses stdin/stdout and the installed local named pipe. `setup` does not implicitly install or activate a privileged component. Build artifacts cannot create a passing acceptance record. Publication is paused.

## Source checks and primary sources

`npm run routing:test:win` runs Go race/vet, Windows helper cross-builds, portable production C lifecycle/ABI and capture tuple/identity/lease checks, and unsupported-platform launch rejection. Local DNS tests exercise real loopback authenticated SOCKS/TLS/DoH fixtures without user nodes or credentials. None of these tests prove native Windows routing.

- [WinDivert official binary download, signatures and administrator requirement](https://reqrypt.org/windivert.html)
- [Pinned WinDivert source](https://github.com/basil00/WinDivert/tree/1789526ecfb9ff5397c94f9f54c1a3dc2fb60440)
- [WinDivert cleanup releases pending packets](https://github.com/basil00/WinDivert/blob/1789526ecfb9ff5397c94f9f54c1a3dc2fb60440/sys/windivert.c#L1949-L2035)
- [Capture provenance, original MIT technique and detailed limits](capture/PROVENANCE.md)
- [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [DNS application settings apply to the current process, Windows 11+](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnssetapplicationsettings)
- [DoH cache age and DNS TTL](https://www.rfc-editor.org/rfc/rfc8484.html#section-5.1)

Envara's own source is MIT; ProxyBridge's retained MIT attribution and WinDivert's original LGPLv3/GPLv2 licensing apply to their respective components. The Go helper retains Go/x/sys BSD notices. The MIT application license does not replace third-party licenses. The custom driver source under `driver/` would still require its own Microsoft-signing/deployment process if selected later; it is not the default implemented route.
