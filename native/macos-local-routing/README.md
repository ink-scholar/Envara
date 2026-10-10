# 原版 macOS Redirector 外部组件候选

本目录实现 `mitmproxy-macos 0.12.11` 原版签名组件的依赖核验、真实 Unix peer 核验、精确 PID 流转发和私有控制协议。`launch()` 仍拒绝生产保护启动；`ready`、`protectedLaunchAllowed`、`verification.passed` 和全部验收 `verification.checks` 保持 false。

原版组件保持 `Mitmproxy Redirector.app` 名称、bundle ID、签名和 Team `S8XHQB96PW`。Envara 不把它的系统扩展重新嵌入自有签名 app，也不安装 CA 或解密 TLS。TLS 字节通过认证 SOCKS CONNECT 原样转发，证书验证由被接入的软件执行。原版 app 的独立安装和系统许可是另外的显式步骤；本目录的 `setup()` 只读核验。

## 依赖与真实 ABI

`dependency-lock.json` 锁定 PyPI wheel、内嵌 app archive、两个通用 Mach-O 文件的 SHA-256、arm64/x86_64 的 CDHash、Team、bundle 版本和 protobuf SHA-256。源码对应 [v0.12.11 的不可变 commit](https://github.com/mitmproxy/mitmproxy_rs/tree/40f1dfb5dca7b03ff7793d3c90f23b8bdf873889)。包版本为 0.12.11，原版 app bundle 版本为 2.0/1；不可混用。

- [原版 app 生命周期](https://github.com/mitmproxy/mitmproxy_rs/blob/40f1dfb5dca7b03ff7793d3c90f23b8bdf873889/mitmproxy-macos/redirector/macos-redirector/app.swift#L91)：保存/加载自己的 NETransparentProxyManager、启动 tunnel，然后 app 主进程退出。原版系统扩展继续运行。
- [原版 provider 的 control 与 flow](https://github.com/mitmproxy/mitmproxy_rs/blob/40f1dfb5dca7b03ff7793d3c90f23b8bdf873889/mitmproxy-macos/redirector/network-extension/TransparentProxyProvider.swift#L18)：先连接 control Unix socket，再应用网络设置；每条 flow 另开一个 Unix socket。
- [protobuf schema](https://github.com/mitmproxy/mitmproxy_rs/blob/40f1dfb5dca7b03ff7793d3c90f23b8bdf873889/src/ipc/mitmproxy_ipc.proto#L33)：4 字节大端长度加 protobuf。TCP NewFlow 之后是原样 TCP 字节；控制方向发送 InterceptConf。
- [精确 PID scope](https://github.com/mitmproxy/mitmproxy_rs/blob/40f1dfb5dca7b03ff7793d3c90f23b8bdf873889/mitmproxy-macos/redirector/network-extension/InterceptConf.swift#L54)：上游索引 `actions[0]`，空集合用仅包含 PID 0 的 scope，不发送空数组，也不使用进程名通配。
- [上游进程信息](https://github.com/mitmproxy/mitmproxy_rs/blob/40f1dfb5dca7b03ff7793d3c90f23b8bdf873889/mitmproxy-macos/redirector/network-extension/ProcessInfoCache.swift#L29)：flow audit token 转 PID/path，IPC 没有 birth token。Envara 对每条 flow 两次读取真实进程 birth/UID/path，并禁止同一 capture epoch 重新绑定曾用 PID。

上游 MIT 许可证保存在 `Mitmproxy-LICENSE`。分发原版组件时必须保留该许可证；本模块不暗示上游对 Envara 的担保。

## 接口

```js
import { MacOSLocalRoutingAdapter } from './controller.mjs'
const adapter = new MacOSLocalRoutingAdapter({
  peerVerifierPath: '/absolute/build/app-routing/macos-local/EnvaraPeerVerifier',
  bundledAppPath: '/absolute/build/app-routing/macos-local/Resources/Mitmproxy Redirector.app',
  onEvent: event => { /* 事件无 SOCKS 密码 */ },
})
```

| 方法 | 行为 |
| --- | --- |
| `status()` / `setup()` | 只读依赖、签名、Gatekeeper 与扩展 inventory；安装路径缺失时可核验 bundled。`component` 区分 available/verified/installed。 |
| `prepareRoute({application,workspace,route})` | 要求 application.id/profileId/executablePath、workspace.cwd、route.udpPolicy=`block`；实际核验本地 SOCKS 用户名密码，凭据仅存内存，返回 opaque routeId。 |
| `launch()` | 始终抛 `APPLICATION_ROUTING_NOT_READY`；不启动任何应用。 |
| `startCapture({activationAuthorized:true})` | 仅诊断接口：安装的固定原版路径、可信签名和 native verifier 全部通过后才运行原版 helper。bundled 路径不授权 activation。默认不调用。 |
| `bindPid({routeId,pid,birth?})` | 仅诊断接口：实际 UID、birth 和 executablePath 必须匹配。返回 captureTest=true/protected=false。原版 scope 没有 ACK，不能将控制连接等同于保护生效。 |
| `bindDiagnosticFamily({routeId,ownerPid,processes})` | 仅诊断接口：ownerPid 必须是 controller 自身；显式 PID 集合的实际父子链、UID、path、birth 经两次读取后单次更新 scope。返回 automaticChildren=false/atomic=false；不发现或自动绑定未知后代。 |
| `setDiagnosticOptions({sampleUdp:true})` | 仅进程内诊断接口：取已捕获 UDP flow 的第一个小 datagram，仅记录 host/port/bytes，然后关闭 flow；不转发一般 UDP。 |
| `setDiagnosticOptions({dnsForwarding:true})` | 仅进程内诊断接口：开启已核验 PID 的 UDP/TCP 53→该 route 的认证 SOCKS→严格证书验证的 HTTPS DNS；不更改系统 DNS、不开一般 UDP、不授予生产启动。默认关闭。 |
| `diagnosticSnapshot()` / `waitForDiagnosticEvent({sessionId,kind,afterSequence,timeoutMs})` | 观察严格验签流的 tcp-connected/tcp-response/udp-blocked/upstream-closed/upstream-error/dns-response/dns-error。事件历史有 256 条上限；DNS 事件仅含归属、transport、bytes/code，不存查询名、DNS 服务器、raw payload、密码或应用路径。返回 scopeAcknowledged=false/productionReady=false。 |
| `stop({sessionId})` / `revoke({routeId})` | 关闭已捕获连接并拒绝该 PID 后续流。保留仍活着的原 birth 的拦截 scope。`stop` 返回 stopped=false/captureStopped=true/processTerminated=false，不能当应用已退出。 |
| `refreshBindings()` | 真实 identity 确认退出或不同 birth 后才移除旧 PID scope。暂时无法检查时保留 scope。seenPids 的 epoch 防重绑定集合继续保留。正常 capture 自动每秒执行。 |
| `shutdown()` | 仅当所有绑定的原 birth 已确认退出才清理自有 IPC/lock/内存路由；检查失败时拒绝 shutdown 并保留 capture。不会杀被绑定应用，不删除系统 NE preferences。 |

`native-identity.mjs` 调用本地 `process-peer.c` 工具。`identity <PID>` 输出 `alive:true,pid,uid,parentPid,birth,path`；只有 `proc_pidinfo` 明确 ESRCH 才输出 `alive:false,reason:"not-found"`。权限/超时/读取不一致都不是退出证明。`peer` 从 fd 3 的真实 Unix socket 取得 `LOCAL_PEERPID`，检查 Apple anchor、原版系统扩展 ID/Team 和锁定 CDHash；不会信任 IPC 内发送的 peer PID。

私有 `main.mjs` 提供 JSON-lines RPC，envelope 为 `{protocol:"envara.application-routing",version:1,id,method,params}`。白名单仅包含 status/setup/prepareRoute/launch/stop/revoke/shutdown；activation、PID 绑定、诊断开关和诊断历史均不接受 RPC 请求，`--allow-activation` 也不会开放这些方法。原版 activation 必须由明确授权的进程内验收程序调用；renderer 不获得该接口。SOCKS 凭据不出现在响应、诊断事件或持久化文件。

## DNS 转发

`dns-doh.mjs` 只通过 route 的内存 SOCKS 凭据发起 CONNECT；生产默认为数字 bootstrap `1.1.1.1:443`、TLS SNI/HTTP Host `cloudflare-dns.com`、POST `/dns-query`。HTTPS connector 不调用系统 resolver，也不会退回直连。严格使用系统 CA、TLS 1.2 及以上和 hostname 验证，不安装 CA、不解密附加软件的 TLS、不跟随 HTTP 重定向。`dnsResolverOptions` 仅是可信 controller constructor 的本地 fixture 注入点，允许 documentation bootstrap、临时端口与临时 fixture CA；route 参数和 RPC 均不能控制该配置，任何 `rejectUnauthorized:false` 参数会被拒绝。

`dns-wire.mjs` 校验单个无压缩 IN question、transaction ID、完整 RR 边界、已解出名称边界上的向后压缩指针及 EDNS0 OPT。支持常用 query type、A/AAAA/CNAME 等记录；未知 RR 的 RDATA 按 [RFC 3597](https://www.rfc-editor.org/rfc/rfc3597.html) 保持 opaque，不能成为压缩指针目标。拒绝 UPDATE/AXFR/IXFR/TSIG 等不支持的事务。超出 UDP payload 上限的回答改为完整最小 TC response；保留 OPT 的 extended RCODE 和 DO，不切断 RR。后续 TCP 53 用两字节长度前缀传回完整 DoH answer。协议依据为 [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html)、[RFC 6891](https://www.rfc-editor.org/rfc/rfc6891.html) 和 [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html)。这只是 wire/TLS 校验，不表示自行验证 DNSSEC。

请求最多 4096 字节，回答最多 65535 字节；DoH 默认 5 秒 deadline、32 个并发请求。UDP/TCP DNS stream 每条最多 16 个请求，读取与写回分别有 deadline。每次交换前后重新核验原 PID/birth/path 与 route；关闭、撤销、上游失败或身份变化会取消待处理查询并关闭该捕获 flow。没有全局 DNS answer cache。系统自身的 cache/coalescing、其他 resolver 以及 Notion 的完整行为仍须 native 验收。

## 分项状态与验收边界

| 分项 | 当前候选 |
| --- | --- |
| 签名组件识别 | SHA、双架构签名、Gatekeeper 实际核验；bundled 准备不代表已安装。 |
| TCP stream bridge | 两个独立 PID 路由、SOCKS username/password、原样 TLS、背压、半关闭的真实 loopback 测试通过。native NE 捕获另测。 |
| UDP | 一般 UDP 被 bridge 关闭；不支持 SOCKS UDP 路由。诊断 DNS 模式仅处理端口 53。 |
| DNS | 已实现按 route 的 UDP/TCP 53→认证 SOCKS→严格 TLS DoH；22 组本地测试包含转发、TLS 拒绝、撤销及 UDP TC/TCP fallback。真实不同域名回包已通过；新增同域并发/串行来源对照观察到跨 route 答案与未绑定测试进程获得合成答案。系统 DNS 隔离与 Notion 验收未通过；不能直接用共享 Fake-IP 修补并称无关软件不受影响。 |
| 子进程 | 没有原子进程族创建/阻断。Notion/Electron helper 必须作为各自明确 PID/executable 诊断绑定；只绑定主进程不能覆盖它们。 |
| 持续 fail closed | 原版 provider 在 scope 尚未设置、metadata 无法识别或控制失联时存在 direct 路径。单独的持久 guard 未完成；普通 controller 退出不能保护应用继续联网。 |
| 其他路由兼容 | 只读报告已启用的 Proxifier/端点组件，不关闭它们，也不因为它们存在就禁止所有测试。互相优先级和未选中软件不受影响仍需 native 实测。 |

## 本地测试

`node scripts/test-macos-local-routing.mjs` 创建并清理自己的 Unix/TCP/SOCKS/TLS fixture，不运行原版 app，不激活扩展，不访问用户代理凭据。当前在 Mac 包含 22 组检查：原有 stream/身份/生命周期检查，以及 DNS wire/EDNS/compression/RDATA 边界、固定 IP bootstrap 不调用 host resolver、两个独立认证 route、证书/hostname 拒绝、错误 response/重定向/deadline/取消、UDP/TCP DNS、撤销中止和 TC→TCP 完整回包。suite 结果仍明确标记 nativeCaptureTested=false、正式 dns/children/failClosed=false。

这些结果证明候选转发与核验代码的本地行为。它们不构成 Notion 或真实 Network Extension 的完整应用路由验收。

`diagnostic-child.mjs` 仅通过私有 Node IPC 驱动 owned fixture。首次消息 `{type:"ready",pid,parentPid}`，此前不联网。命令必须含短 `id`；TCP/UDP 目标只允许 documentation IP 和 loopback 字面量。`spawn-children` 的全部新 child 先 ready，`forward-child` 将 child 的进度/终态包裹为 child-progress/child-result。TCP 的 normal 模式完整收到 fixture payload 后退出连接，hold 模式先返回 tcp-progress 保持连接以测上游断线，half-close 模式保留原版 provider EOF 限制的实测入口。UDP send callback 标记 `sendIsNotCaptureProof:true`，必须另有严格签名 flow 的 udp-blocked 观察才算捕获证据。`exit` 仅释放 fixture 自身及其子进程。

系统 DNS 诊断命令为 `{id,type:"dns",hostname:"<16..63 hex>.example.com",family:4}`，也可通过 `forward-child` 发送。单标签 64 字节被明确拒绝。`family` 可明确为 4 或 6；省略时沿用系统默认。它使用 `node:dns.lookup(...,{all:true,family})` 的系统 getaddrinfo，不手动选择 resolver。明确族只允许对应 expectedAddress4（仅 `203.0.113.42`/`.43`）或 expectedAddress6（仅 `2001:db8::42`/`::43`），避免 IPv4-only 系统默认查询被误判为缺少 AAAA。`otherFixtureAddresses` 也仅接受这四个文档地址，且与 own 不重叠。

结果只包含固定错误码、明确地址族、resolved、matchedExpectedAddresses 与 own/other/unexpected 答案分类；不返回查询名、原始答案、DNS 服务器或系统设置。默认 15 秒内返回结果或 `FIXTURE_DNS_TIMEOUT`，可设置 100..15000ms；getaddrinfo 本身不可取消，超时后由验收脚本结束自己的 fixture。lookup 成功或失败都不证明捕获，必须另外观察与该 session 对应的严格签名 UDP/TCP flow。同 phase 的合法热缓存仅在该 route 先有正确答案与真实 native reply 时允许零新增事件；另一 route 的答案、未知来源或缺少地址族证据不能继承通过。

另有 `actualAddressFamilies`（从地址文本计算）、`canonicalFixtureAnswerObserved`（IPv6 正规化等值）与 `fixtureIpv4TailObserved`（IPv6 最低 32 位匹配配置的合成 IPv4）脱敏格式观测。`diagnosticFixtureAddresses` 仅允许同一四地址白名单，不能给 caller 添加真实地址。格式观测不改变严格 source/matched，也不推断 DNS64/NAT64；未绑定进程命中这些特征或缺少格式证据时不通过，避免变形答案被误判为未受影响。当前 23 项私有 IPC/分类/矩阵反例测试通过。

`accept-macos-dns-routing.mjs --activate` 按 IPv4、IPv6 分别运行四个父/子独立域名基线及五种同域并发/串行/未绑定进程对照，每 phase 使用新随机域名，任一族失败仍如实失败。`accept-macos-route-isolation.mjs --activate` 独立验证两条认证路由的四进程并发、单路撤销和未绑定本地 TCP。两者默认只读；不会填充生产 gates。真实测试范围和保留的失败证据见 [验证记录](../../docs/verification.md)。

`diagnosticSnapshot().rejections` 保存最多 64 条 `flow-rejected` 分类记录；`onEvent` 对应 `capture-flow-rejected`。记录只含阶段、固定原因码、固定 address context、signedPeer、是否已解出 metadata、时间/序号。只有完成真实 identity 归属检查才加 session 的 PID/birth/route；header 解码失败仅是签名组件送来无法解码的 flow，不能当作该应用 DNS 的捕获证明。记录不含原 frame、payload、查询名、DNS 地址或代理凭据。
