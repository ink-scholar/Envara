# TCP owner observation probe

This standalone probe never loads WinDivert, installs a service, changes routing
or DNS, or authorizes a captured packet. With no arguments it creates no traffic.
`--run-local` creates only its own IPv4 loopback listener and client sockets.
`--enable-own-estats` additionally requests EStats collection on that temporary
connection; Windows may require elevation. No unrelated connection is changed.

It records `TCP_TABLE_OWNER_MODULE_ALL`, the real PID and process creation time,
the link's `liCreateTimestamp`, query QPC intervals and readable EStats. It then
closes its sockets with RST and attempts a controlled reuse of the same tuple.
A refused rebind or unavailable statistic remains an error/unavailable result.
Neither a timestamp nor matching TCP sequence state is a kernel endpoint token.
The marker is a userspace marker, **not a captured packet timestamp**. All
readiness, DNS, fail-closed and packet-generation-proof fields remain false.

Build with MinGW x64:

```sh
x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -O2 probe_windows.c observation.c -lws2_32 -liphlpapi -o tcp-owner-probe.exe
```

The buffer and undefined-EStats-data tests can run without Windows:

```sh
cc -std=c11 -Wall -Wextra -Werror observation.c observation_test.c -o observation-test
./observation-test
```

Official evidence:

- [WinDivert 2.2 layers and event metadata](https://reqrypt.org/windivert-doc.html#divert_layer): NETWORK has no PID/endpoint ID; FLOW and SOCKET cannot recover events that happened before their handles opened.
- [MIB_TCPROW_OWNER_MODULE](https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_module): the timestamp is FILETIME for a context bind; module information is opaque.
- [GetPerTcpConnectionEStats](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getpertcpconnectionestats): dynamic statistics must be ignored when `EnableCollection` is false.
- [TCP_ESTATS_DATA_ROD_v0](https://learn.microsoft.com/en-us/windows/win32/api/tcpestats/ns-tcpestats-tcp_estats_data_rod_v0): TCP state and statistics, with no packet-linked endpoint generation.

No production host path consumes this probe's output. A successful observation
does not establish WinDivert compatibility or authorize application launch.
