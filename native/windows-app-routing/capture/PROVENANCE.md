# Envara capture source and acceptance boundary

The fixed TCP address-swap/local listener technique is adapted from ProxyBridge,
commit `02703a0672a8b94011a4698368a392f7734c10dc` (MIT), specifically
`Windows/src/ProxyBridge.c` TCP packet rewrite and `Windows/src/pb_relay.c`
Winsock listener. The upstream copyright and MIT license are retained in LICENSE.
Executable-name rules, source-port-only caches, DNS snooping and proxy credentials
are not used. Identity, tuple, alias, generation and ABI code is Envara source.

`vendor/windivert.h` is the unchanged header from official
`https://www.reqrypt.org/download/WinDivert-2.2.2-A.zip`; its license is preserved
as `vendor/WinDivert-LICENSE` (LGPLv3/GPLv2 choice). The DLL dynamically links
the official x64 WinDivert import library. Obtain its runtime DLL and signed
WinDivert64.sys using the repository's verified SDK preparation workflow. This
directory contains no modified kernel driver, node password or subscription token.

## Implemented experimental boundary

SOCKET SNIFF events supply PID and endpoint IDs. The DLL opens the actual process,
reads creation time, retains its handle and asks the service to prove membership
in its retained Jobs. The callback is outside capture locks. Only a confirmed
UNOWNED decision re-injects original outbound TCP/UDP packets. UNKNOWN waits
10–250 ms (one userspace packet; bounded kernel queue), then drops. OWNED UDP,
including UDP/53, and owned TCP/53 are blocked. New owned TCP SYNs receive unique
never-reused aliases during one run; Windows' own TCP stack terminates them at
the Go listener. Lookup requires the entire accepted peer/local tuple and is a
single-use claim. Revoke keeps blocked process tombstones and session generations.
Existing owned TCP connections are rejected instead of being migrated.

For every new TCP SYN and every proposed UNOWNED direct packet, packet-triggered
GetExtendedTcp/UdpTable verification must agree with the retained PID/birth and
a SOCKET event whose timestamp precedes the captured packet. A table snapshot
alone never authorizes direct traffic. The callback can run concurrently on the
SOCKET and NETWORK threads. New SYNs do not inherit old NAT identity; a different
identity, sequence number or closed lease retires the old alias. Both FIN
directions, RST and process exit close two-minute flow leases; half-closed live
streams are not evicted. The alias range is finite and is never recycled per run.

Bind the service relay to IPv4 0.0.0.0 and separate IPv6-only [::], same port;
reject every accepted socket without a successful LookupRelay. Unsolicited
inbound relay packets are dropped. Do not retain the old WFP redirect-record API
on this path. Terminate and wait all owned Jobs before CaptureStop. The DLL
explicitly drops its queued packets during planned cleanup rather than sending
unknown packets back from userspace.

## Remaining failures and honest status

`ready`, `dns`, `fail_closed`, `verification_passed` are always false. Start means
only that capture setup completed. No configuration or environment flag overrides
these fields. Windows networking acceptance has not been performed on macOS.

Shared DNS Client request callers are not identified. A separate DNS broker is
not a resolver adapter. WinDivert socket PID/event-to-creation-time attribution,
Job callback ordering, port/flow reuse, queue pressure, VPN coexistence, Windows
IPv4/IPv6 and listener reachability still require native tests. A timestamp check
rejects obvious PID reuse and near-birth ambiguity; wall-clock correction and OS
event delivery races are not proven solved. Socket owner-table checks are
packet-driven rather than child polling. Pre-capture sockets lack SOCKET event
evidence and their outbound traffic is dropped until they open a new socket.
This would interrupt unrelated preexisting connections; preserving them needs
a proven kernel socket-epoch/queue barrier before system activation. No stale
synthetic endpoint snapshot is accepted as a direct-traffic authorization.

Fragments cannot be attributed safely: unsupported outbound fragments are dropped
and counted, potentially affecting unrelated fragmented traffic; inbound fragments
retain their original path. Owned multicast/link-local IPv6 targets are rejected.
Other IP protocols are outside this TCP/UDP prototype. These limits prevent
unaffected-application or complete-routing acceptance. Maps are bounded; capacity
failure drops or terminates capture, never silently authorizes owned traffic.

The unchanged WinDivert driver releases filters on service/DLL failure and may
re-inject its driver work queues during handle cleanup. Even explicit planned
queue draining does not establish a persistent fail-closed boundary. Fatal worker
failure disables capture and must cause the service to stop its Jobs. An
independent persistent block/OS isolation boundary and native fault tests remain
required before any protected launch. The user has paused publication.

## Builds

Portable: `clang -std=c11 -Wall -Wextra -Werror -I. capture_core.c tests/core_test.c -o /tmp/envara-capture-core-test`.
Run the test executable; this does not open a driver or touch network settings.

MinGW: compile capture_windows.c and capture_core.c with
`-shared -DENVARA_CAPTURE_BUILD -D_WIN32_WINNT=0x0A00`, include EnvaraCapture.def,
link the SDK's x64/WinDivert.lib, ws2_32 and iphlpapi. CMake accepts
`-DWINDIVERT_ROOT=/path/to/verified/sdk`; use a Windows x64 toolchain and disable
cross-platform test execution. Visual Studio: CMake with `-A x64` and the same
WINDIVERT_ROOT. A build does not confirm signatures load or routing works.
