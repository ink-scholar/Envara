# Windows application DNS probe (driver-free, x64)

独立的受控实验程序，只研究 Windows DNS API 的实际行为。它不依赖 Envara、WinDivert 或服务，不改接口 DNS、注册表、hosts 或 NRPT，不注入第三方进程。当前只支持 Windows x64，应用 DNS API 的官方最低版本为 **build 22000**。它不是保护适配器，JSON 中所有 `ready`、`coverage`、`fail_closed` 始终为 `false`。

## 编译与运行

在此目录使用 MinGW x64 编译（不需要链接 dnsapi.lib）：

```sh
x86_64-w64-mingw32-g++ -std=c++17 -O2 -Wall -Wextra -Werror \
  -static -static-libgcc -static-libstdc++ \
  -o /tmp/envara-dns-application-probe.exe main.cpp -lws2_32 -lbcrypt
```

交叉编译不等于 Windows 行为验收。Windows 上可在普通控制台执行：

```powershell
.\envara-dns-application-probe.exe
.\envara-dns-application-probe.exe --run-local
```

无参数默认只读：读取真实 OS build、动态检查 dnsapi 导出、调用当前进程的 `DnsGetApplicationSettings`，并正确释放返回的服务器数组；不调用 Set、不查询 DNS、不建立监听。

只有显式 `--run-local` 才会在随机私有回环地址 `127.77.x.y:53` 建立自持 UDP DNS responder，并对**当前进程**调用 `DnsSetApplicationSettings`，设置一个 UDP 服务器和 `DNS_APP_SETTINGS_EXCLUSIVE_SERVERS`。若绑定冲突、快照失败、版本不足或读回不符，则不继续查询。没有提权逻辑，也不抢占已有监听。

Responder 不转发；只回答本次随机 token 下的 `.invalid.` 名称，A 答案为 `198.18.0.42`、TTL=0，其他类型返回空答案。程序不会连接该答案地址。随机后缀和完整域名用于区分各 case，不是通用缓存隔离保证。某 API 可能在本地拒绝 `.invalid`，这会被记录为未到达服务器，不算通过。

## 实际 case 与 JSON 含义

| case | 请求方式 | 缓存选项 |
| --- | --- | --- |
| `DnsQuery_A` / `DnsQuery_W` | 同步 A 查询，未指定每次查询服务器 | `DNS_QUERY_BYPASS_CACHE \| DNS_QUERY_NO_HOSTS_FILE`，值 72 |
| `DnsQueryEx_v1_sync` | v1 请求、回调 NULL、显式服务器列表 NULL | 同上；导出缺失则记录错误 |
| `getaddrinfo_AF_INET` | AF_INET、SOCK_STREAM、独立随机名称 | 此 API 没有使用 DNS bypass 选项，记录 `cache_bypass=false`、`query_options=null` |
| `inherit_child` | 同一个 exe 的受控 `--inherit-child <qname> <address>` 模式 | 子进程只 Get 和 DnsQuery_A，**绝不 Set** |

每个 case 的 `server_seen` / `server_requests` 来自本进程 responder 收到对应独立名称的实际计数；`result.status` 和 `expected_answer` 分别记录调用状态与预期答案。两者需分别检查：调用成功不代表到达指定 DNS。收到名称属于受控查询关联，**不是网络数据包原始客户端 PID 的证明**。JSON 的 responder `owner_pid` 只表示本次服务器的进程。

父进程 case 的 `inherit_child.result.child_json_text` 是完整子进程 JSON 字符串，包含子 PID、Get 返回的数量/flags、`settings_match_parent_exclusive` 和查询结果。父进程记录实际服务器计数；子进程没有 responder，因此它自己的 `server_seen=false` 不用来判断继承。子进程最多等待 20 秒，超时只结束本程序新建的该子进程；不会终止第三方程序。

如果子进程没有继承设置，或某 API 未采用应用 DNS 设置，该调用**可能使用系统解析路径**。这个实验不提供阻断或静默直连防护。`fail_closed=false` 表示未验证阻断，不能从 EXCLUSIVE 读回成功推导所有解析路径均被阻断。

执行前保存原服务器数组及 Version/Flags；每次尝试 Set 后都恢复原值，Get 读回按服务器类型、地址、端口和模板比较，最后通过 `DnsFreeCustomServers(DWORD*, DNS_CUSTOM_SERVER**)` 释放原数组及读回数组。正常退出和 C++ 异常展开走同一恢复逻辑；强制结束/崩溃不是恢复验收。退出码 0 仅表示只读检查结束，或设置/读回/恢复流程成功，**不表示每个查询通过，更不表示可启动受保护应用**。

## 官方契约与明确缺口

- [DnsSetApplicationSettings](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnssetapplicationsettings)：per-application、EXCLUSIVE、最低 build 22000；函数没有目标 PID/进程句柄参数。文档没有保证线程范围、父子继承、共享缓存隔离或全部解析 API 覆盖。
- [DNS_APPLICATION_SETTINGS](https://learn.microsoft.com/en-us/windows/win32/api/windns/ns-windns-dns_application_settings)：Version=1、Flags=ULONG64、EXCLUSIVE=1。
- [DnsGetApplicationSettings](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsgetapplicationsettings) 与 [DnsFreeCustomServers](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsfreecustomservers)：Get 的数组输出是 `DNS_CUSTOM_SERVER**`；Free 的两个参数均为指针。代码不把结构体本身当作待释放数组。
- [DNS_CUSTOM_SERVER](https://learn.microsoft.com/en-us/windows/win32/api/windnsdef/ns-windnsdef-dns_custom_server)：本实验仅用文档支持的 UDP 类型，flags=0、模板 NULL、SOCKADDR_INET。只用端口 53；不声称非 53 端口已验证。
- [DnsQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsqueryex) / [DNS_QUERY_REQUEST](https://learn.microsoft.com/en-us/windows/win32/api/windns/ns-windns-dns_query_request)：本实验仅实现同步 v1、A 查询、无显式服务器列表。
- [DNS_QUERY_REQUEST3](https://learn.microsoft.com/en-us/windows/win32/api/windns/ns-windns-dns_query_request3)：文档明确匹配 **NRPT** 时会忽略该请求中的 custom servers，使用 NRPT 服务器。应用设置与 NRPT 的优先级未由本 probe 验证；不把 `EXCLUSIVE` 当作绕过 NRPT 的证明。
- [GetAddrInfoW](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfow)：解析可包含 hosts 和其他 NS_DNS 名称空间提供程序，不能据此声称所有 Win32 名称解析路径覆盖。

ABI 固定来自微软 [win32metadata 的 WinDNS.h，commit 75ec935a4f1ac56345daa9f7f0bc21db3e68ac68](https://github.com/microsoft/win32metadata/blob/75ec935a4f1ac56345daa9f7f0bc21db3e68ac68/generation/WinSDK/RecompiledIdlHeaders/um/WinDNS.h#L851-L908) 和 [windnsdef.h](https://github.com/microsoft/win32metadata/blob/75ec935a4f1ac56345daa9f7f0bc21db3e68ac68/generation/WinSDK/RecompiledIdlHeaders/shared/windnsdef.h#L1624-L1673)。probe-local 声明保留自然布局，用 static_assert 验证 x64 大小/偏移，并从 System32 动态加载 API；不复制整份 SDK、不把 SDK 头文件宣称为该仓库的 MIT 授权。应用 Get/Set/Free 声明没有 WINAPI，QueryEx 有 WINAPI；本实验限定 x64，未验证 x86 ABI。

尚未实现/验收：NRPT、DnsCache 共享解析/缓存归属、不同环境同名与热缓存隔离、线程作用范围、UDP→TCP 重试、完整 IPv6、DnsQueryEx v3/异步/取消/显式服务器、DnsQueryRaw、GetAddrInfoW/Ex、缺省/多名称空间提供程序、第三方目标 bootstrap、第三方子进程、PPL/反注入、32 位、已存在单实例、全 guard 崩溃保护及不相关应用网络对照。即使本实验所有正向 case 收到正确答案，也不能声称“所有 Win32 DNS”或“全协议保护”已完成。
