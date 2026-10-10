# macOS attached-application routing: independent failure guard research

> 2026-10-08 实现状态更新：PF 已从研究转入真实原生后端开发，桌面默认选择 PF／专用进程组／独立 utun，出站复用 Envara 管理的认证节点。本文较早的“只研究、不实施规则”“生产路径只交给 AppProxy”段落保留为调查过程，当前状态以 [PF 后端说明](../native/macos-pf-routing/README.md) 和 [验证记录](verification.md) 为准。管理员安装和系统实验须单独明确授权；不需要先购买 Apple Developer 账号。完整保护尚未验收。

调查日期：2026-10-08。首个实机目标应用：Notion。本文是只读源码调查与实施路线，不是路由验收报告。

本轮没有执行 `pfctl`，没有创建用户或组，没有改变账号、PF 规则、DNS、路由、TUN、系统扩展或应用身份，也没有读取 Notion 账号数据。用户现有 TUN 保持运行；发布继续暂停。

## 结论

“保持 console UID、给目标应用及直接子进程专用 GID；原版已签名 transparent proxy/helper 和 Envara relay 使用另一个 GID；用持久 PF anchor 阻断目标 GID 的普通 TCP/UDP 出站”有值得做受控实机验证的内核时序依据。它与正常 NE 流捕获没有已确认的必然冲突，不能因此宣称可靠、完整或适合产品部署。

只修改 effective GID 不构成稳定身份：普通进程可以恢复其 real/saved GID。即使修正为专用 real/effective/saved GID，PF 只匹配实际 socket 创建者的凭据，不会自动按系统 DNS 请求的原始调用者 GID 阻断 mDNSResponder。它也无法凭 group 规则覆盖所有 IP 协议、授权既有网络 FD、LaunchServices/XPC 代发和既有 PF pass state。

Apple [TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api) 将 PF 归为系统实现细节与高级用户/管理员功能，而非稳定产品 API，并建议面向广泛用户分发的软件迁移到 Network Extension。这是兼容性与维护风险，不能扩大成“非 NE 实现不存在”或“Apple 禁止所有 PF 产品”。当前 PF 路线尚未通过 Envara 的系统验收，不能据此承诺正式保护。后续补充检索确认 VPNonly 与 LianYaoHu 的真实非 NE 实现，详见 [替代路线与 X 原帖核对](mac-routing-component-review.md#不依赖自有-ne-签名的替代路线2026-10-08-补充检索)。原版 signed helper 的复用仍不能补出一个新的 content-filter/DNS-proxy entitlement；这一限制仅针对自有 NE 部署。

## 固定来源与适用范围

| 来源 | 固定版本 | 适用边界 |
| --- | --- | --- |
| Apple XNU | `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`，Apple commit 标注 `xnu-12377.1.9`，2025-10-16 | 公开内核源码的时序与凭据实现；不是本机内核的运行证明 |
| Apple mDNSResponder | `d4658af3f5f291311c6aee4210aa6d39bda82bbe`，`mDNSResponder-2881.0.25`，2025-10-16 | 有请求 PID/UUID 保留与按 question 配置 socket 的证据；该公开树缺 Mac 平台 socket-option 实现 |
| mitmproxy_rs 发布版 | `40f1dfb5dca7b03ff7793d3c90f23b8bdf873889`，v0.12.11 | 当前候选原版 signed helper 的源码基线；签名、安装及实际审批另行核验 |
| 本机 Apple man pages | `/usr/share/man/man5/pf.conf.5`、`/usr/share/man/man8/pfctl.8` | 本机 PF 语法说明，未加载任何规则 |

本机只读 `uname` 返回 Darwin 27.0.0，内核标注 `xnu-13432.0.94.501.4`。这比上述公开 XNU 导入版本新；不能把源码推导冒充本机 PF/NE 次序已经通过实测。

## NE 与 PF 的执行顺序

1. TCP `tcp_usr_connect` 在 `necp_socket_should_use_flow_divert` 为真时，初始化 flow-divert，调用 `flow_divert_connect_out` 并直接返回；普通 `tcp_usr_connect_common` 在后面。这支持“成功接管的流先进入 NE，而不是先产生待 PF 放行的普通 SYN”。[XNU tcp_usrreq.c:660-676](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/tcp_usrreq.c#L660-L676)
2. UDP 显式 connect 也优先进入 flow-divert；未连接 UDP 的 send 同样先检查并返回 `flow_divert_implicit_data_out`。[udp_usrreq.c:2370-2383](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/udp_usrreq.c#L2370-L2383)、[udp_usrreq.c:2604-2624](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/udp_usrreq.c#L2604-L2624)
3. 普通 IP 输出的后段才调用 outbound `pf_af_hook`，IPv4、IPv6 都有对应调用。[ip_output.c:1122-1134](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/ip_output.c#L1122-L1134)、[ip6_output.c:1519-1542](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet6/ip6_output.c#L1519-L1542)

据此推导：NE 接管目标应用流、通过 Unix socket 交给 Envara relay 后，由另一个 GID 的 relay 建立真正 TCP/UDP 连接，针对应用 GID 的 PF block 理论上不会阻断 relay 的出站。NE 未接管而退回普通协议时，原应用自己创建的 socket 仍可被 PF 按原凭据检查。此推导需要在实际 Darwin 27、当前 TUN/VPN 和目标 Notion 上验证。

[Apple NETransparentProxyProvider 文档](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider) 特别说明：返回 false 会让流继续访问最终目标；不能套用其父类 NEAppProxyProvider 的“false 关闭流”语义。原版 helper 在 audit-token 缺失、spec 缺失、不匹配或 IPC handshake 无法构造时返回 false。[TransparentProxyProvider.swift:88-110](https://github.com/mitmproxy/mitmproxy_rs/blob/40f1dfb5dca7b03ff7793d3c90f23b8bdf873889/mitmproxy-macos/redirector/network-extension/TransparentProxyProvider.swift#L88-L110)

XNU 在 transparent flow-divert 服务全部拒绝后有恢复原协议、重连并发送缓冲数据的路径。[flow_divert.c:2224-2296](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/flow_divert.c#L2224-L2296)、[flow_divert.c:2667-2673](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/flow_divert.c#L2667-L2673)。而 group 控制连接消失时，现有 group flows 被关闭并设置 `ECONNABORTED`。[flow_divert.c:3351-3384](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/flow_divert.c#L3351-L3384)、[flow_divert.c:4599-4604](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/flow_divert.c#L4599-L4604)。这不证明 helper/controller 整体崩溃后所有新流也永远被系统阻断；独立屏障须覆盖未接管/退回普通路径。

## GID 身份不能只设 effective 值

本机 `pf.conf(5)` 说明 user/group 匹配 socket 创建时保存的 effective IDs，且只支持 TCP/UDP。XNU 的 PF socket lookup 根据 TCP/UDP tuple 找到 PCB；真正读取的 UID/GID 来自 `socket.so_cred`。[pf.c:4136-4186](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/pf.c#L4136-L4186)、[in_pcb.c:2474-2478](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/in_pcb.c#L2474-L2478)

只用 `setegid(dedicated_gid)` 而保留 console real/saved GID 时，目标无需 root 即可调用 `setegid(real_gid)` 或恢复 saved GID。这是官方 API 和内核明确允许的行为。[Apple setegid(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setegid.2.html)、[kern_prot.c:1020-1047](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_prot.c#L1020-L1047)

受控实验应由特权 launcher 在 drop console UID 前，将 real/effective/saved GID 全设为专用值。特权 `setgid` 有设置全部三者的实现；之后再设置最终 console UID。顺序、保存身份与 supplementary groups 都必须检查。[kern_prot.c:974-994](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_prot.c#L974-L994)

同 console UID 是 GUI 兼容候选条件，不能证明 WindowServer、Keychain、Notion sandbox、更新程序或其 helpers 都支持专用 GID。应保持 console bootstrap/session 并直接启动已知 executable，验证实际 UID/GID 和所有直接子进程；不能假定 `open`/LaunchServices 重新启动的进程继承调用者 GID。不能给现有 Notion 实例贴“受保护”标签，也不能继续使用身份变化前继承的网络 socket FD。IPC/XPC 委托给普通用户服务、setgid executable 和外部提权流程是另外的身份边界。

## anchor、state、接口与现有配置

- 只把规则写入一个命名 anchor 不等于它已参与过滤。主 ruleset 必须引用对应 anchor；quick 匹配和 anchor 顺序也决定是否到达它。本机 `pf.conf(5)` 的 anchor 段明确说明此行为。
- 本机 `/etc/pf.conf` 只读检查显示：默认 `com.apple/*` anchor 引用被注释，文件现有 `com.sangfor.atrust`、`com.sangfor.vpn`、`com.sangfor.byod` 等第三方 anchor。没有查询它们的运行规则，也没有修改这些文件。不能假定存在可用 Apple 通配挂接点，不能通过加载默认 pf.conf、flush 或覆盖第三方配置实现 Envara guard。
- PF 先查 TCP/UDP state，已有 pass state 命中后不再进入普通规则扫描；晚加 block 不是已有连接的可靠屏障。[pf.c:9883-9903](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/pf.c#L9883-L9903)、[pf.c:9934-9954](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/pf.c#L9934-L9954)。应在 fresh target 创建任何网络 socket 前建立屏障；不能全局清 state 来掩盖此问题。
- `set skip on` 接口上的包完全不经过 PF；只挡物理接口也可能漏掉 utun/loopback 路径。应以实际接口和规则证明覆盖，不能据“TUN ON”推导隔离通过。
- `pfctl -E`/`-X token` 是启用引用计数机制，不能直接使用全局 disable 来清理 Envara。kernel anchor 并非一个普通 app 句柄；但它是否在外部 VPN 重载、系统服务变更、重启与卸载中保持所需顺序，仍需验证。
- group/uid 只能归属 TCP/UDP。不能声称 ICMP、所有非首片或其他 IP 协议都已按应用强制阻断；也不能用忽略 group 的广泛协议规则误伤其他应用。

## 系统 DNS：有 origin 元数据机制，但尚未证明完整可用

不能把“网络 socket 由 mDNSResponder 创建”直接推成“macOS 永远无法识别原调用者”。公开源码存在正向证据链：

1. mDNSResponder 通过 `LOCAL_PEEREPID` 得到 Unix DNS 请求连接的 effective peer PID。[uds_daemon.c:1232-1245](https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSShared/uds_daemon.c#L1232-L1245)
2. GetAddrInfo 请求把 effectivePID/effectiveUUID 传入 client-request 层；question 保留 pid/uuid/euid。[uds_daemon.c:4394-4397](https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSShared/uds_daemon.c#L4394-L4397)、[ClientRequests.c:428-435](https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSShared/ClientRequests.c#L428-L435)
3. unicast question 的 LocalSocket 被传给 `mDNSPlatformSetSocktOpt`，并把 question 一起传入；旧注释明确关联 delegate socket option。[uDNS.c:4738-4751](https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSCore/uDNS.c#L4738-L4751)、[uds_daemon.c:2815-2834](https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSShared/uds_daemon.c#L2815-L2834)
4. XNU 遇到 `SOF_DELEGATED` 会根据 `e_pid/e_uuid` 选择 effective source process；flow-divert 把选中进程的 task audit token 写入 APP_AUDIT_TOKEN。[flow_divert.c:1147-1191](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/flow_divert.c#L1147-L1191)、[flow_divert.c:1105-1113](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/flow_divert.c#L1105-L1113)

因此，如果实际 DNS socket 正确设置 delegate，NE 的 `sourceAppAuditToken` 可能已经代表源应用，stock Swift helper 不需要再自行恢复一个 DNS caller。其 ProcessInfoCache 确实从这个 token 提取 PID，并用于拦截 spec。[ProcessInfoCache.swift:14-31](https://github.com/mitmproxy/mitmproxy_rs/blob/40f1dfb5dca7b03ff7793d3c90f23b8bdf873889/mitmproxy-macos/redirector/network-extension/ProcessInfoCache.swift#L14-L31)

但该 mDNSResponder 公开树没有 Mac 平台 `mDNSPlatformSetSocktOpt` 的实现；不能证明所有 `getaddrinfo`、Network.framework、缓存/共享 question、TCP DNS、DoH/DoT、多环境同域名请求都实际设置 delegate 并被这一原版 provider 捕获。Apple 也明确：TransparentProxyProvider 忽略指定的 DNS settings，connect-by-name 不跳过系统 DNS；`includedNetworkRules` 不能直接指定目的 port 53，而要求使用域名规则。[NETransparentProxyProvider](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider)、[includedNetworkRules](https://developer.apple.com/documentation/networkextension/netransparentproxynetworksettings/includednetworkrules)

更重要的是，**delegate attribution 不会把 PF 的实际 socket 凭据变为源 App GID**。socket 创建保存的是创建进程的 `so_cred`；delegate setter 更新 e_pid/e_uuid/flags，普通 PCB owner-update 只更新进程名称统计，不重写 so_cred。[uipc_socket.c:561-585](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_socket.c#L561-L585)、[uipc_socket.c:7925-7955](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_socket.c#L7925-L7955)、[in_pcb.c:4318-4340](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/in_pcb.c#L4318-L4340)

由此可推导：即便 NE 活着时拿到 DNS 原调用者，若 NE 缺席而 daemon 发出的 DNS 进入普通 IP 路径，仅按目标 App GID 的 PF block 仍不会命中 daemon 自己创建的 socket。不能为了解决它而全局阻断 mDNSResponder、换 host DNS 或影响其他软件。独立的 DNS attribution、路由和失败屏障仍是验收项；`dns` 和完整 `failClosed` 必须保持 false。

原版 helper 的 IPC TunnelInfo 只传 pid/process_name，没有把原 audit token、pidversion、creation-time 或单个 DNS request identity 传给 controller。[mitmproxy_ipc.proto:15-18](https://github.com/mitmproxy/mitmproxy_rs/blob/40f1dfb5dca7b03ff7793d3c90f23b8bdf873889/src/ipc/mitmproxy_ipc.proto#L15-L18)。进程退出/PID 复用和同应用两个环境仍需处理，不能把 IPC PID 当持久身份。

## 可执行的下一阶段及明确门槛

2026-10-08 的原版 transparent-provider 实测确认：不同随机域名可分别通过各境舱的认证路由返回 A/AAAA；两个境舱并发查询同一域名时，第二个境舱解析成功，但答案集合不匹配自身 route 的预期，且没有该 PID/route 的桥接 DNS 回复事件。完整报告为 `test-artifacts/mac-routing/native-dns-2026-10-07T16-31-03.126Z.json`。fixture 没有保存实际答案，也未获取系统 resolver trace；系统合并查询或共享缓存是候选解释，尚未确证具体根因或第二境舱收到的地址。这是当前原版适配器未通过独立 DNS 验收的证据，不是“Apple 系统 DNS 永远无法按应用隔离”或“借用组件无法按软件分流”的证明。

公开源码还要区分 portable OSS 与 Apple QUERIER 实现。固定 parent `d89f8d1d0e001b810d6c055aa2a57b768bcf9aa2` 的 [FindDuplicateQuestion](https://github.com/apple-oss-distributions/mDNSResponder/blob/d89f8d1d0e001b810d6c055aa2a57b768bcf9aa2/mDNSCore/mDNS.c#L13909-L13942) 在 Apple QUERIER 开启时拒绝合并不同 `dnsservice` 的问题；[RRMatchesQuestionService](https://github.com/apple-oss-distributions/mDNSResponder/blob/d89f8d1d0e001b810d6c055aa2a57b768bcf9aa2/mDNSCore/DNSCommon.c#L2136-L2140) 也按同一 service 匹配缓存。后续 portable 源码去掉了这些 Apple 条件分支，不能用它推出当前 macOS 没有 resolver realm。

因此当前实现优先修正自有 `NEAppProxyProvider`：每条路由持久保存独立 VPN UUID，严格匹配完整可执行文件路径、签名身份和 realm；多个路由的 mapping 合并到一个 payload。Apple [App Proxy DNS 文档](https://developer.apple.com/documentation/networkextension/neappproxyprovider) 提供按应用 resolver 配置与 DNS flow 的 API；[TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment) 允许 macOS system-extension 采用 Developer ID 直接分发。这里是有官方依据的候选方案，仍需要正确 entitlement、签名和当前 Darwin 27 的同域并发、缓存及崩溃实测。相同 executable path 的多个 PID 无法靠公开 `NEAppRule` 选择不同 realm，必须拒绝这种绑定。

桌面生产生命周期只交给自有 AppProxy。原版 signed Redirector 的已安装/已授权状态只作为独立诊断信息；不填补自有 provider 的安装、签名、DNS 或故障门槛，也不接收生产 launch。PF 方案保留为研究，不实施系统规则。

第一阶段可完成代码、测试工具、signed helper 文件/版本/签名校验和原版 IPC 的无 MITM stream relay，不改 helper 签名、不装 CA、不向 helper 发送节点凭据。PF 仍只保持研究文件，不实施规则。DNS origin 的原始 audit-token 与实际 caller 对照应成为实验观测项。

受控实机实验需要另外落实特权 launcher、保留 console bootstrap 的三 GID 启动、已授权原版扩展、与当前第三方网络共存的 PF anchor 挂接方案。Notion 必须 fresh launch；既有 Notion 实例、更新程序、提权程序和不受控 LaunchServices 子应用都不得计入受保护会话。

| Notion 验收项 | 必须观察的证据 |
| --- | --- |
| GUI 与进程身份 | 实际 console UID、三种 GID、保存身份、bootstrap、全部 helpers；能正常显示并读写所选 workspace |
| TCP/UDP IPv4/IPv6 | 原始 flow caller、环境 route tag、实际 authenticated proxy egress；未附加 Notion 和其他软件继续原网络 |
| 系统 DNS | `getaddrinfo`、DNSService、应用自带 resolver、冷/热缓存、同域名并发请求的 caller；helper 停止期间查询不能直出 |
| 多环境 | 两个 fresh Notion 实例用不同 GID/会话；同域名及同目的地址不串 route/DNS |
| 故障 | relay/controller/helper 分别 kill，helper 整体停止/取消 NE，反复重连；抓包与 guard counter 证明零目标 direct packet |
| PF/VPN/TUN 共存 | IPv4/IPv6、utun/loopback、现有 pass states、第三方规则重载、睡眠唤醒及接口切换；没有全局 flush/disable |

单次 stream 成功、源码顺序、signed helper 安装或 PF counter 增加都不能代替上述通过证据。PF 本机实验成功后仍需处理 TN3165 指出的系统升级与共存风险；当前自有 NE 生产路线不变。完整保护需要正确签名/授权并通过验收的 NE 组合，或另一个通过同等系统验收的隔离边界，不能仅凭签名或候选项目存在判定完成。
