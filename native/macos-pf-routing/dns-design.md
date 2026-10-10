# PF/GID/owned-utun DNS boundary

Checked on 2026-10-08. This document describes a diagnostic and a restricted
launch candidate. It does not qualify the attached-application adapter.

## What PF can identify

Apple's PF `pf_socket_lookup()` obtains UID/GID by looking up the packet's
TCP/UDP PCB. The IPv4 lookup reads the credentials of `inp_socket->so_cred`.
It does not read the DNS requester's IPC credentials:

- [pf.c:4136](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf.c#L4136)
- [in_pcb.c:2475](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/in_pcb.c#L2475)

Therefore a GID rule can identify a selected application's own DNS socket.
It cannot automatically identify that application's question inside a shared
system resolver socket. Blocking the shared daemon's DNS sockets would also
affect unrelated applications.

## Scoped resolver and UID are different from process selection

Public Libinfo's ordinary `getaddrinfo()` passes a NULL interface to its
internal resolver. Its mDNS module sends DNSServiceQueryRecord requests.
mDNSResponder preserves the request's effective PID/UUID and UID, but its
ordinary scoped-server selection matches interface ID or service ID. A new
GID, UID, exec session or owned utun does not by itself supply one of those
resolver scope keys.

- [libinfo.c:2505](https://github.com/apple-oss-distributions/Libinfo/blob/main/lookup.subproj/libinfo.c#L2505)
- [mdns_module.c:1329](https://github.com/apple-oss-distributions/Libinfo/blob/main/lookup.subproj/mdns_module.c#L1329)
- [uds_daemon.c:4387](https://github.com/apple-oss-distributions/mDNSResponder/blob/main/mDNSShared/uds_daemon.c#L4387)
- [mDNS.c:11951](https://github.com/apple-oss-distributions/mDNSResponder/blob/main/mDNSCore/mDNS.c#L11951)

Interface-scoped resolution is useful for an application that explicitly
requests that interface. It has not been shown to redirect an unchanged,
signed application's ordinary getaddrinfo calls. A dedicated UID also does
not establish an independent DNS cache or supply a UID-to-resolver mapping.

## Private Unix-socket candidate: rejected by the installed runtime

Apple's public DNS-SD client defines `DNSSD_UDS_PATH` and reads it before
connecting to its Unix server. That suggested a private broker for each owned
exec family, preserving the original app signature and host DNS configuration.
The public client falls back to the system socket if the path is too long, so
any future implementation must reject invalid paths before launch.

- [dnssd_ipc.h:90](https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSShared/dnssd_ipc.h#L90)
- [dnssd_clientstub.c:802](https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSShared/dnssd_clientstub.c#L802)

The native fixture was compiled against the installed system libraries and
run as UID 501. A short, private, listening UDS received zero connections from
DNSServiceCreateConnection, getaddrinfo, and the Network.framework connection
probe. DNSServiceCreateConnection returned success even with an absent private
socket. Thus the installed system library did not select this endpoint. The
source implementation cannot be treated as a working runtime feature.

Network.framework reached a waiting state without a useful error code in this
probe; it did not connect to the private socket. This does not identify its
actual resolver transport or qualify all Network.framework DNS behavior.
No complete DNS-SD broker was implemented after its required entry point failed.

## Implementable restricted launch candidate

A fresh owned child process can receive a Seatbelt profile before exec that
denies its system resolver Unix socket, the `com.apple.dnssd.service` Mach
lookup, and outbound TCP/UDP port 53. This changes the launched process policy,
not the original application binary, host resolver configuration, or SIP.
The actual profile is retained in `scripts/accept-macos-pf-dns-uds.mjs`.

The installed Apple profile `/System/Library/Sandbox/Profiles/cmioextension.sb`
also uses a deny rule for `/private/var/run/mDNSResponder` at line 216.

The owned fixture established these local acceptance results:

| Probe | Ordinary or private endpoint | With child DNS-deny profile |
| --- | --- | --- |
| DNSServiceCreateConnection | success, status 0 | status -65563 |
| getaddrinfo of random .invalid name | status 8; no private UDS connection | status 8 |
| IPv4 UDP/TCP loopback port 53 | no ordinary send required | syscall rejected, EPERM |
| IPv6 UDP/TCP loopback port 53 | no ordinary send required | syscall rejected, EPERM |
| System DNS configuration | read-only SHA-256 snapshot | identical after probe |

This provides an explicit DNS failure mode for the tested resolver IPC and raw
port-53 operations. It does not provide working independent getaddrinfo answers.
An application with a verified built-in remote SOCKS resolver or application
private DNS implementation may remain usable; that is an application-specific
mode and must not be presented as generic attached-application coverage.

The profile must apply before all owned helpers are created. Existing running
apps, inherited resolver connections, system-delegated networking helpers,
alternative DNS IPC, DoH/DoT, and application compatibility remain acceptance
boundaries. No original Notion process was started in this diagnostic. No
packet capture or PF activation was performed, and failing to resolve an
invalid name alone is not proof that no DNS packet left the host.

## Reproducible diagnostic

Run `node scripts/accept-macos-pf-dns-uds.mjs` without root. It builds only the
owned native fixture, uses random reserved `.invalid` names and loopback
port-53 operations, compares read-only system DNS snapshots, closes its own
children and listener, and removes its temporary directory. It can save the
JSON result with `--output=<path>`.

Recorded result: `test-artifacts/mac-routing/pf-dns-uds-2026-10-08.json`.
`ready` stays false. Passing the restricted-denial diagnostic does not enable
the production protection gate.

## Broker contract for a future caller that really selects a private endpoint

Resolve requests must carry an immutable route identity as well as qname and
qtype. A broker must use the route's authenticated SOCKS transport, keep caches
and in-flight requests keyed by route identity, reject unsupported operations,
and never retry via the host resolver or a direct path. Two routes resolving
the same qname concurrently must receive their respective synthetic answers;
an unrelated ordinary fixture must retain its normal result. Broker death
must leave the launched family's DNS denied, rather than restoring host DNS.

The public DNS-SD IPC uses a 28-byte big-endian header, opaque 8-byte context,
connection request 1, query request 8 and addrinfo request 15. Shared requests
carry their synchronous error channel with SCM_RIGHTS, so a Node-only stream
parser that drops ancillary data is insufficient. These details apply only
to that public client; replacing the installed client or injecting a library
into a signed app is outside this candidate.

[Public IPC definition](https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSShared/dnssd_ipc.h#L142)
