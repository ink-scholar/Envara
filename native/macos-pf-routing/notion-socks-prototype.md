## Prototype scope

This unintegrated Notion-specific candidate accepts loopback SOCKS5 no-auth **CONNECT** and bridges to an independent, authenticated loopback SOCKS5 upstream. It offers only RFC1929 username/password authentication upstream, refuses downgrade/auth failure, and preserves DOMAIN ATYP bytes exactly. It never calls a host DNS resolver, opens a destination directly, retries via DIRECT, modifies the managed core's authentication, or logs/persists upstream credentials. BIND and UDP ASSOCIATE are unsupported.

The front requires an injected ownership authorizer; there is no permissive default. Each authorization checks immutable route ID/registry epoch, registered PID/birth/UID/GID, and a native connected TCP tuple witness before any method/CONNECT success and before upstream connection. It rechecks during upstream setup and streaming. Revocation/timeout cancels pending operations and closes both sockets. TCP half-close preserves the opposite read direction and buffered tail.

`notion-socks-attestor.c` uses unprivileged Darwin `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` on registered owned processes, with two bounded descriptor scans, process birth/UID/GID rechecks, an exact held-open IPv4 loopback tuple, unique FD match and stable nonzero PCB generation. Unknown, ambiguous, stale, unstable, unreadable, or revoked observations refuse access. The test authorizer is expressly **not a sealed production controller**.

**Every snapshot remains `ready:false`, `productionReady:false`, `raceFreeOwnership:false`, and `automaticChildren:false`.** Tuple snapshots cannot prevent every concurrent FD transfer/inheritance/reuse or guarantee atomic kernel authorization. No production resource map, controller, installer, launcher, PF/tunnel gate, app binary/signature, VPN, system resolver, or host setting is changed.

## Required production gates

- Sealed controller/attestor resource identity and authenticated immutable registry lifecycle.
- Inherited and transferred descriptor handling, PID/FD/port/interface reuse and race protection.
- Verified PF/process-group enforcement and application-scoped Seatbelt DNS/other-stack denial before target exec.
- Original signed Notion acceptance, helpers/update/Node/native networking, unrelated applications, DNS observations and complete failure cleanup.

Chromium's SOCKS5 URL stack alone does not cover Node networking, external helpers, delegated Network.framework DNS, QUIC/UDP or all app traffic. This code does not launch Notion, provide generic unchanged-app DNS routing, or claim tracking/ban prevention.

## Primary sources

- [RFC1928 framing](https://www.rfc-editor.org/rfc/rfc1928) and [RFC1929 authentication](https://www.rfc-editor.org/rfc/rfc1929).
- [Chromium SOCKS proxy scope](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/docs/proxy.md), verified 2026-10-08; this upstream URL is mutable.
- [Apple XNU proc_info ABI](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info.h), fixed commit **f6217f891ac0bb64f3d375211650a4c1ff8ca1ea**. The native fixture uses the installed SDK ABI; successful observation is host-specific, not race-free authorization.

## Local validation

`node --test tests/macos-pf-notion-socks.test.mjs` builds only the two new C files in a private temporary directory. It uses owned native clients and independent local authenticated SOCKS fixtures; no remote destination is resolved or contacted. Tests cover domain/auth preservation, client FIN followed by a complete 262 KiB tail, two realms, unknown/cross-realm ownership, real duplicate-FD ambiguity, malformed/incomplete requests, authentication refusal/downgrade, pending-operation and live revocation, and cleanup. Temporary executables and all owned sockets/processes are removed.
