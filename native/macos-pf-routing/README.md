# macOS PF native primitives

This is an implementation branch for per-environment PF group routing. It
does not require a Network Extension entitlement. It is not yet an accepted
attached-application adapter. `ready` and `protected` remain false.

`make test` builds with the local Apple SDK and runs only unprivileged fixtures.
It does not use sudo, install a helper, create groups or a utun, load PF rules,
activate a packet engine, alter DNS, or change a route. It uses the existing
hash-verified Mihomo `-t` branch only to parse a dummy transport configuration;
the fixed upstream source exits that branch before applying listeners/TUN.
The tests verify cold execution,
stopping before target execution, ordinary child identity inheritance, closing
an inherited live socket, JSON validation, and utun packet framing. They do
not verify a transition to a new GID or real routed traffic.

## Read-only CLI

The build output is `build/envara-pf-native`.

- `status`: diagnostic availability and the `7100..7999` GID contract. Every
  installation, policy, transport, DNS and native-acceptance gate remains false.
- `plan --uid UID --gid GID --cwd ABS --exec ABS`: a non-activating plan.
- `identity --pid PID`: actual real/effective/saved UID/GID, parent PID,
  executable path, and birth generation. A second identity read follows the
  path read; ambiguous identity returns an error.
- `fixture`: unprivileged tests, with no externally connected socket.
- `transport-config-fixture --output ABS`: writes only dummy listener credentials
  into a new mode-0600 fixture file; never reads real route credentials.

## Privileged fixture boundary

`launch-fixture --uid UID --gid GID --cwd ABS --executable ABS` is private
acceptance machinery. It requires a real root caller, the current console UID,
and an existing dedicated group named exactly `_envara_pf_<GID>`. It accepts
only a root-owned executable under a directory chain owned by root and not
writable by group/other. No target arguments or shell are accepted.

The child uses the console user's real/effective/saved UID and the realm's
real/effective/saved GID. Supplementary groups contain only the realm GID;
preserving ordinary supplementary groups would allow `setegid()` to bypass
group routing. UID-based file access remains; group-only file access may be
restricted. Changes affect only this child. No user account is modified.

The process stops before executing the target and reports `phase:suspended`.
The authenticated root controller must commit its deny rule, scoped pass rule,
owned transport, route authentication and guard before sending `RESUME\n` to
the native guardian's stdin. `TERMINATE\n`, EOF, malformed input, SIGTERM,
SIGINT, SIGHUP or loss of the output pipe cancels the original birth's process
group. The guardian never reports `protected:true` or `scopeQuiescent:true`.
A SIGKILL, detached process, XPC delegate or an application changing its
credential/session can escape this process-group cleanup; persistent PF denial
and complete process/DNS accounting must be verified by the controller.

Fixture stdin/stdout are dedicated pipes; stderr is `/dev/null`. The root
controller can send `PROBE <base64-encoded-single-JSON-line>\n` after RESUME.
The guardian decodes at most 16 KiB, rejects NUL/multiple lines/noncanonical
padding, and bounds the child response to a 16 KiB line and 15 seconds.
It watches the lease pipe for EOF during the response wait. The response is
wrapped as `{operation:"fixture-response",payload:"escaped JSON string"}`;
the controller still validates the sealed fixture's request nonce and evidence.
Child output cannot supply guardian metadata. There are no user-chosen target
arguments or shell commands.

The exec uses
`POSIX_SPAWN_SETEXEC | POSIX_SPAWN_CLOEXEC_DEFAULT` and explicitly inherits
only stdio. Inherited sockets cannot silently retain an earlier direct route.
The fixture target environment has only console HOME/USER/LOGNAME, a fixed
system PATH and LANG=C. Node passwords and route credentials are not arguments
or child environment variables.

The library's `envara_spawn_suspended()` can support the eventual cold GUI
launch, but the CLI intentionally exposes only the installed fixture. A helper
running in the system bootstrap must enter the console user's bootstrap/security
session through the fixed system `launchctl asuser` entry before invoking the
native launcher. UID/GID correctness alone does not prove GUI, TCC, keychain,
Notion helpers or XPC work in that session. Existing applications must not be
reused by LaunchServices; the production controller must reject an already
running target and verify its executable identity separately.

## Owned packet transport

Reuse Envara's original bundled Mihomo v1.19.32 as a separate packet-engine
process, rather than introducing a second downloaded tun2socks dependency.
Its immutable source is commit `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`;
the corresponding vendored source is already included in
`build/proxy-core/mihomo-corresponding-source.tar.gz` with provenance hashes.

Fixed source facts:

- `listener/sing_tun/server.go:152..165` reads the real tunnel name for a
  nonzero `tun.file-descriptor`; it need not select an unreserved name.
- `vendor/github.com/metacubex/sing-tun/tun_darwin.go:113..118` uses the passed
  descriptor. This path skips the interface-address/route creation routine.
- That routine configures the interface address even with `auto-route:false`.
  Explicit route additions are inside the `AutoRoute` condition at line 311.
  Address assignment may create a connected route; compare the real routing
  table before/after instead of claiming the false option has no side effects.
- `config/config.go:1686..1704` derives the global TUN IPv4 address from DNS's
  fake-IP range and forces `/30`. Multiple realms must not independently use
  the same automatic address. An owned FD plus separately allocated owned
  address is preferable.
- Darwin `NativeTun.Close()` at line 168 unconditionally flushes the host DNS
  cache. It does not change the DNS server setting. This lifecycle side effect
  must remain explicit in acceptance.

The planned root controller creates and retains a new utun descriptor, assigns
only its own address/MTU, passes a duplicate as FD 3 to Mihomo, sets
`file-descriptor:3`, `stack:gvisor`, `auto-route:false`, `auto-redirect:false`
and `auto-detect-interface:false`, and routes only PF's UID+GID scope into it.
The outbound must be the existing authenticated loopback SOCKS route to the
owned AnyTLS core, with no DIRECT fallback. Do not apply upstream tutorials'
default routes, host DNS changes, global PF flushes or global proxy settings.

The experimental privileged entry is:

```
tunnel-core --core ROOT_OWNED_MIHOMO --state-dir ROOT_OWNED_PRIVATE_DIR --ipv4 OWNED_BENCHMARK_ADDRESS
```

The first stdin line is private JSON with exactly `host`, `port`, `username`,
`password`, and `udpPolicy` (`proxy` or `block`). Only numeric `127.0.0.1` and
`::1` are accepted. RFC 1929 username/password authentication must succeed;
there is no no-auth downgrade and no outbound CONNECT during preflight. Runtime
listener credentials are not CLI arguments, diagnostic output or application
environment values. A generated config exists only under the validated root
directory in a mode-0600 file; it is removed when the core is stopped/exits.

`envara_utun_open()` requests `sc_unit=0` (a new free interface); the helper
sets only that interface's address to an available address in 198.18.0.0/15,
with a /32 mask and MTU 9000, matching the private gvisor configuration.
This keeps the controlled UDP payloads (up to 4096 bytes plus IPv4/UDP headers)
below the owned tunnel MTU; traffic larger than that MTU and general fragment
reassembly remain unverified. No other interface's MTU is changed.
It does not add a default route, change host DNS,
load PF or activate another VPN. Interface address assignment can create its
own connected host route and must be included in before/after acceptance.
The original FD remains in the C guardian and FD 3 is explicitly passed to the
separate Mihomo process. The report has the actual `interfaceName`, `ipv4Address`,
core PID/birth, guardian PID and a fresh instance ID. `core-spawned` is not an
engine-ready or protected attestation.

`KEEP\n` retains the lease. Core exit retains the original FD, preventing that
name from disappearing merely because the engine died. EOF, malformed input,
SIGTERM/SIGINT/SIGHUP or loss of output kills the owned core with SIGKILL and
then holds the original FD. SIGKILL avoids Mihomo's graceful Close DNS-cache
flush branch; a startup error inside Mihomo can still call Close, so absence
of a host cache flush is not an accepted guarantee. The held FD does not expire
automatically while an orphaned PF route may still name it.

Only a live controller's `RELEASE\n`, or a separate administrator's explicit
SIGUSR1 to the original guardian, releases it. The controller must first cancel
the fixture, verify its scope is quiescent, and remove/verify the owned pass
rule. SIGUSR1 is private fixture cleanup, not an ordinary user's UI operation.
Killing the whole guardian with SIGKILL can still allow interface-name reuse;
that failure remains a false acceptance gate. Core death, guardian death,
process cleanup and unrelated-application behavior need real native acceptance
before attached applications can use this branch.

Ordinary macOS resolver requests may be delegated to mDNSResponder outside the
target GID. Encrypted application telemetry is not automatically identifiable.
The adapter must keep DNS attribution, delegated traffic, tracker rules and
failure denial as separate gates; neither a compiled helper nor an HTTP 200 is
proof of those properties.

Sources: [Mihomo fixed source](https://github.com/MetaCubeX/mihomo/tree/88dcbf7f1614a67c3b36b848ee3592dfa92ada36),
[Apple PF maintenance contract](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api).
The existing Mihomo third-party license/provenance must remain bundled. No
source or signature of a third-party Network Extension is modified.

## PF-only two-phase acceptance fixture

`make test-pf-fixture` compiles the five standalone Swift files under `fixture/` using the same arm64/macOS 13 flags as the resource builder. This copy does not modify or rebuild the Network Extension fixture. Its unprivileged tests use loopback only; the TCP DNS test reserves and releases a socket without connecting to the external destination.

`reserve` accepts a sealed numeric IPv4 target and `protocol: tcp|udp`. It exclusively binds port zero without `SO_REUSEADDR`/`SO_REUSEPORT`, reports the actual `getsockname` port and an opaque reservation token, and does not connect or send. Its local address is **wildcard**, not the eventual flow source address. The privileged controller must conservatively inspect PF states for every local address using that source port and exact destination before permitting a probe. A reserve response alone is not fresh-state or routing acceptance.

`probe_reserved` consumes the token once and connects/sends on that exact held FD, then closes it on success or failure. It reports the actual post-connect address/port and monotonic start/end times. UDP, TCP, TCP port 53 and TCP half-close use this same path. Old direct `tcp`/`udp` operations refuse with `RESERVATION_REQUIRED`. Child requests use the existing `child_probe` envelope. `release_reservation`, child shutdown, stdin EOF and process exit close held sockets; descriptor `FD_CLOEXEC` prevents parent reservations being inherited into an exec'd child.

Each process permits at most 16 reservations with a 60-second expiry bounded by its existing 120-second lifetime and 30-second idle cutoff. Expired reservations are removed before subsequent requests; an idle process exits and closes all descriptors. This fixture does not activate PF, allocate groups, create a TUN, alter routes or DNS, or claim native routing acceptance.
