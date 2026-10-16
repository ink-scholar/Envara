## Scope

This is a bounded, unprivileged **independent DNS-SD IPC prototype**. It is not connected to the production PF helper, installer, adapter, or launch gates. `ready`, `productionReady`, and `systemDNSRouteSupported` remain false.

The native Unix front accepts only registered owned fixture processes. It checks kernel Unix peer PID/UID, process birth time, fixture executable path, and the owning Node process as parent, then rechecks identity before each request/reply. Each private socket has one immutable route/environment context. The JavaScript resolver is injected; this implementation contains no host DNS resolver or direct network fallback.

The protocol supports connection (1), QueryRecord A/AAAA (8), GetAddrInfo (15), and cancellation (63), including the shared-connection `SCM_RIGHTS` error socket. Headers, body lengths, flags, record types, names, and TLVs are bounded. Unsupported semantics are refused. Resolver timeout/failure closes the owned request; front EOF closes sockets and removes only its own socket inode.

## Source

The independent framing implementation is grounded in Apple **mDNSResponder-2881.0.25**, peeled commit **d4658af3f5f291311c6aee4210aa6d39bda82bbe**:

- [IPC ABI](https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSShared/dnssd_ipc.h)
- [client stub](https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSShared/dnssd_clientstub.c)
- [daemon/error socket](https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSShared/uds_daemon.c)
- [Libinfo lookup path](https://github.com/apple-oss-distributions/Libinfo/blob/39b70c515baee5b609e7e91693edbd934b6845a1/lookup.subproj/mdns_module.c), commit **39b70c515baee5b609e7e91693edbd934b6845a1**.

No upstream client stub is substituted into the system or user applications. Apple's source headers retain their upstream license; these new files implement the protocol independently.

## Observed boundary

In the tested macOS system-library path, the stock `DNSServiceCreateConnection` returns success but **does not connect to the supplied `DNSSD_UDS_PATH`**. The fixture records `ownedEndpointUsed:false` and `missingEndpointRejected:false`. Source code containing `getenv` does not establish that the current system dynamic library uses that transport.

Sandbox denial of default DNS access makes the stock library return PolicyDenied before using the custom socket. The actual sandboxed `getaddrinfo` fixture fails. Therefore **stock getaddrinfo positive routing is unsupported/unverified**, and UDS alone gives no Network.framework, original Notion, delegated-helper, packet-leak, or production protection guarantee.

Positive checks use a clearly named native `wire-*` fixture with no system resolver calls. They validate two concurrent independent realms returning different reserved A/AAAA answers for the same synthetic `.invalid` name, shared error-FD framing, negative records, rejected peers/births/cross-realm access, oversized packets, resolver failures/timeouts, and exact owned cleanup. Deterministic injected responses do not prove upstream proxy DNS transport.

## Validation

`node --test tests/macos-pf-dnssd-broker.test.mjs` compiles only the two new native files and runs the protocol and real system-library refusal tests. `node native/macos-pf-routing/dnssd-broker-acceptance.mjs --output=test-artifacts/mac-routing/dnssd-broker-prototype.json` writes a structured prototype report. Neither command requests administration or alters PF, system DNS, VPN/TUN, application binaries/signatures, SIP, or user data.
