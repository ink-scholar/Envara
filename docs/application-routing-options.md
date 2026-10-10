# 附加软件分流：实现与备选路线

2026-10-08 核对。目标是「选择境舱 → 添加本地软件 → 启动」，所属进程使用该境舱的节点，其余软件保持原网络。用户指定 Notion 为首个附加软件验收目标，当前优先完成 Mac；因本机仿真卡顿停止 Windows QEMU，Windows 测试条件由用户另行安排。GitHub 发布继续暂停。

## Windows 当前实现

默认路线改为 **WinDivert 2.2.2-A 官方已签名 x64 驱动 + EnvaraCapture.dll + Go guard service**。没有修改或重新签署上游驱动。固定完整源码、许可、官方二进制 SHA-256 与组件 ABI manifest 随构建资源保留。自己的 WFP 内核源码保留为未启用备选，不再是这条路线的签名先决条件。[官方签名与管理员要求](https://reqrypt.org/windivert.html)、[原生实现](../native/windows-app-routing/README.md)。

已落入源码：实际 PID/创建时间/Job 归属、不同境舱的独立 route、TCP IPv4/IPv6 NAT/认证 SOCKS relay、一次性目的地领取、UDP 阻断、撤销/进程退出、受保护 DLL 文件链，以及独立认证 DoH broker。x64 捕获 DLL 与 x64/ARM64 Go helper 可以在此 Mac 交叉构建；ARM64 没有对应的 WinDivert 驱动，不表示其捕获已支持。

完整功能仍未完成，正式启动门槛保持关闭：

- **共享 DNS**：系统 DNS Client 的连接 PID 不等于原调用软件，DoH broker 还不是任意 Win32 调用的适配器。
- **整个 guard 崩溃**：WinDivert 关闭句柄会撤除过滤，并可能重注入队列中的原包；Job kill-on-close 不能证明关闭过程没有直连窗口。
- **无关应用**：捕获前已经建立的 socket 没有可信事件代次，当前保守丢包会打断这些连接。不能恢复旧端口快照来伪造可信归属。累计身份容量也有服务生命周期上限，必须完成受控退出与实机验收。
- **Windows 实机**：驱动信任/加载、管理员安装、双境舱/子进程/端口与 PID 复用、核心与服务故障、UDP/DNS、无关软件、VPN/TUN 共存均未验收。

因此「源码与二进制构建成功」不能写成「Windows 附加软件功能已经可用」。本机没有启用 Windows 驱动、安装服务或改动 VPN/TUN。

## Mac 并非没有方案

当前桌面默认后端已改为 Envara 自有 **PF + 专用进程 GID + 自有 utun + 固定 Mihomo** 实现。Mihomo 的出站使用境舱现有认证 SOCKS 节点，保留 AnyTLS 的管理与身份校验。无需购买 Apple Developer 账号；系统安装与受控分流实验仍需要本机管理员明确授权。普通检查不会提权、创建组、启用 PF 或启动软件。源码、构建和受控夹具通过均不等于完整应用保护；DNS、整个守护进程失效、旧连接、接口复用、GUI／XPC 和无关应用行为继续作为验收项。实现与协议见 [PF 原生后端](../native/macos-pf-routing/README.md)。自有 AppProxy 和原版 signed Redirector 保留为备选及诊断路线。

| 项目或产品 | 做法 | 对 Envara 的意义与限制 |
| --- | --- | --- |
| [Proxifier Mac](https://www.proxifier.com/new/mac.html) | 自带已签名 Network Extension，按软件代理 TCP 与远程 DNS | 最终用户使用它不需要苹果开发者账号；是商业外部产品，不能据此直接把其组件装进开源 Envara；UDP 和同软件多实例需另行验证 |
| [Surge Mac](https://manual.nssurge.com/rules/process.html) | Enhanced Mode 配合进程名称/完整路径/App bundle 规则 | 现成产品可按软件分流；官方明确 DNS 查询阶段无法判定来源进程，不能等同境舱独立 DNS；商业许可并非再分发许可 |
| [mitmproxy_rs / mitmproxy-macos](https://github.com/mitmproxy/mitmproxy_rs) | 上游独立 Redirector.app 承载 Network Extension；PID 选择与原始 TCP/UDP stream callbacks | MIT 开源、可研究外部依赖集成。保留原组件身份和签名可能无需先申请 Envara 自己的开发者账号；子进程、DNS、断线阻断与多境舱仍需补齐 |
| [VPNonly app-engine](https://github.com/kanishkdan/vpnonly) | 专用 GID、PF、用户态隧道；不使用自有 Network Extension | 非 NE 架构参考。Envara 使用自己的启动、隧道与认证代理实现；上游完整商业 GUI 不在可再分发范围内 |
| [ProxyBridge](https://github.com/InterceptSuite/ProxyBridge) | Mac Transparent Proxy / DNS Proxy 源码 | MIT 架构参考；自己改名、构建与分发扩展仍需要自己的合法签名材料，不能复制上游签名来签修改后的代码 |

对没有账号的 Envara，当前已实现 **原版 mitmproxy Redirector 作为独立外部组件** 的控制与流桥接：单一 capture broker 按可信 PID/出生标记把原始连接交给境舱各自的认证 SOCKS 入口，不解密 TLS，不安装 mitmproxy CA。本地传输检查已经通过；实际内核、Notion、DNS、子进程与完整故障保护仍是验收门槛。正式自行维护扩展、改 bundle ID 或发布修改后的扩展，仍需项目维护者的 Apple Developer 签名/profile、公证；使用原版外部组件的最终用户不需要自己的开发者账号。

版本、双架构签名/Team、二进制、archive 与 protobuf 已锁定至实际 `v0.12.11` 提交 `40f1dfb5dca7b03ff7793d3c90f23b8bdf873889`。安装器只接受验证后的原版资源，用 macOS 原子 no-replace 操作保留任何现有安装；默认只读计划。诊断 capture / bindPid 不暴露给渲染页面，正式 launch 在完整验收前拒绝。

开发机已安装原版组件。用户已完成系统授权，`systemextensionsctl` 显示 `activated enabled`。正常原生 TCP fixture 已通过真实签名控制/flow 校验和认证 SOCKS 转发，完整收回 2048 字节；测试子进程与 capture 已清理。scope 写入后使用 2 秒诊断等待，没有 ACK，不能作为生产安全启动屏障。半关闭 fixture 暴露了原版上游在应用写 EOF 后取消整条流的限制；这个失败不代表正常流签名校验失效。Notion 7.34.0 的应用元数据已检查，尚未启动其用户会话，完整软件分流仍待验收。

`routing:test:mac:local` 最新 22 组通过，覆盖真实 Unix framing、认证 SOCKS、双向 TCP、原样 TLS、背压、撤销、PID 复用、严格 peer，以及 UDP/TCP53→严格 TLS DoH、EDNS/响应匹配/TC fallback。它们不启动 NE。

真实系统 DNS 验收已完成不同随机域名的双境舱父/子 A/AAAA 回包，但同域并发对照失败：第二境舱解析成功，答案集合不匹配自身 route 的预期，且没有该 PID/route 的桥接 DNS 回复事件。fixture 仅保存匹配布尔值，不保存实际答案；这份记录不能确证它收到了第一境舱的具体地址，也没有系统 resolver trace 来确认根因。系统 cache/coalescing 是符合现象的候选解释。该结果证明当前接入未通过跨境舱独立 DNS 验收，不能推出原版组件无法按软件分流，或所有替代路线都不可行；完整 DNS 门槛继续关闭，仍需验证 resolver realm 或其他满足出口、DNS 与无关软件要求的设计。精确报告与范围见 [验证记录](verification.md)。上游控制协议没有 ACK，真实 captured payload 才能作为 scope 生效证据。此前 PF 仅作研究；当前开发与验收进度见本节开头，维护边界见 [Mac guard 调查](mac-routing-guard-research.md)。当前 VPN/TUN、Proxifier/aTrust 设置未修改。

最新重新实测进一步区分了两件事：两境舱四个显式绑定进程的 TCP 并发、单路撤销与另一条路继续，共 9 项通过，原版组件并不只限一个软件或一个出口。新增 DNS 答案来源分类则直接观察到另一境舱的测试答案，并在未绑定第三个自有进程中观察到合成答案；只记录分类，不保存原始答案。后者反证了直接加入共享 Fake-IP 表就能保持未选软件网络的假设；扩大为全机 capture 也不符合当前要求。另一个已确认限制是先完成捕获再写 EOF 后，原版扩展截断应用收到的回复。当前可用源码及桥接测试不能修复扩展已经取消的流。最终复测范围与报告见 [当前验证结果](verification.md#原版签名组件重新实测2026-10-08-当前结果)。

此前桌面路径使用自有 AppProxy；当前默认 PF 后端见本节开头。原版 Redirector 仅提供独立的只读诊断状态，不能借其授权开放正式启动。每条 route 需要自有 manifest 中的唯一 VPN UUID、签名身份、完整可执行文件路径与对应 manager。桌面通过只读 `resolveRealm` 查绑定并覆盖 caller 的 UUID，不生成 profile 或激活组件。多境舱 DNS、缓存及既有 VPN 共存仍需要自有扩展的合法签名与原生验收；当前没有可用的 Envara NE 签名/profile 和合格的验收 receipt。

最新源码在每条新 flow 到达时验证系统 audit token、实际用户、执行世代和实时父链，拒绝仅凭进程组或程序名推定归属。已经审计的孤儿进程可保留授权，但必须再次验证原 token；同路径重新执行不能沿用旧世代。路线、guardian 会话和生命周期在准入与清理时统一核对，撤销先封闭会话再执行取消。这些源码检查与真实自有 exec 测试已通过，仍不代表系统 DNS 代发、所有子进程、扩展崩溃或 Notion 分流已验收。

### 非 NE 替代路线的补充核对（2026-10-08）

GitHub 固定源码确认 VPNonly 使用每应用 GID、PF 和用户态 WireGuard，LianYaoHu 使用 GID、sandbox 与 PF；这两条技术路线不以自有 NE 签名为运行前提。也已用内置浏览器读取 VPNonly、Tunless 作者的 X 原帖。此前“PF 不作为产品故障保护替代”描述的是当前未通过验收、未启用的状态，不表示非 NE 方案不可能。AnyTLS 多境舱、系统 DNS、全部相关进程、接口重用、崩溃和无关应用仍需验收，生产保护门槛不变。固定来源、许可与边界见 [组件研究](mac-routing-component-review.md#不依赖自有-ne-签名的替代路线2026-10-08-补充检索)。

## 原版 Mac 组件最初的只读实测（后续部署见上文）

下载的是 [mitmproxy-macos 0.12.11 官方 wheel](https://pypi.org/project/mitmproxy-macos/0.12.11/)，SHA-256：`63349d9b46514ca679547651f7c0548f9222892edfbcba087b82b3244fbae859`。只解压到 `/tmp/envara-mac-redirector-inspection/`。

- `codesign --verify --deep --strict`：valid on disk / satisfies Designated Requirement。
- app 与 system extension：Developer ID Application: Maximilian Hils，Team ID `S8XHQB96PW`；x86_64/arm64 universal。
- app 附带公证票据；`spctl --assess --type execute`：accepted，source=Notarized Developer ID。
- 没有运行 app，没有安装到 Applications，没有授权/激活扩展，没有改动本机路由或证书信任。这些结果不证明 Envara 与此组件的流量集成已通过。

源码接口参考固定提交 `51fe2b7c5aa8439c162abb665db61c6669d146d6`：[local redirector API](https://github.com/mitmproxy/mitmproxy_rs/blob/51fe2b7c5aa8439c162abb665db61c6669d146d6/mitmproxy-rs/mitmproxy_rs/local.pyi)、[安装生命周期](https://github.com/mitmproxy/mitmproxy_rs/blob/51fe2b7c5aa8439c162abb665db61c6669d146d6/mitmproxy-rs/src/server/local_redirector.rs)。该源码提交与已发布 0.12.11 二进制不是同一版本，后续集成必须按实际版本核对 ABI，不应把接口研究当成二进制兼容实测。
