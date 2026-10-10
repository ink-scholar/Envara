# macOS 应用路由组件审查

审查日期：2026-10-08。范围为官方发布元数据与固定源码；没有安装、启动组件或改变系统网络。这里记录候选组件的限制，不代表 Envara 的 macOS 保护功能已完成原生验收。

## 固定来源

| 组件 | 审查基线 | 公开发行状态 |
| --- | --- | --- |
| ProxyBridge macOS v4.0.0 | Mac v4 合并提交 [`5dc49f8ce5853f7b4de783a4d6000f86bf8c6c6a`](https://github.com/InterceptSuite/ProxyBridge/commit/5dc49f8ce5853f7b4de783a4d6000f86bf8c6c6a) | 官方 `ProxyBridge-v4.0.0-Universal-Installer.pkg` 于 2026-07-05 上传；发布元数据 SHA-256：`df64a77b9bd1a6f9d41b4c7e2169dbf86c23441c6751b65a0a55c016a6253d0a`。本次没有验证安装包与该提交的二进制对应关系。[发行页](https://github.com/InterceptSuite/ProxyBridge/releases/tag/v4.0.0) |
| tunless v0.4.1 | 标签指向 [`6be3e12da9e3b589b149e686193c0233a8225555`](https://github.com/bojieli/tunless/commit/6be3e12da9e3b589b149e686193c0233a8225555) | 官方 v0.4.1 Release 的 assets 列表为空，没有该版本的公开 macOS 签名安装资产。源码中的开发构建记录不能代替可取得、可核验的发行包。[发行页](https://github.com/bojieli/tunless/releases/tag/v0.4.1) |

ProxyBridge 的 `v4.0.0` 标签实际指向 2026-06-25 的 `22e53445e44481fad0f63c2a088aa91c0deda3af`，早于 Mac v4 发布，不能用该标签中的旧 Mac 实现代替上表基线；后续 master 的新增 DNS 组件也不能视为 7 月安装包已具备的能力。

## 原版 ProxyBridge 无法在外围补齐的行为

- **没有按 PID／完整路径区分境舱的规则。** 扩展从 audit token 取得 PID，调用 `proc_pidpath` 后只保留文件名；匹配输入是签名标识或文件名。GUI 增加规则、代理配置无法让同一软件的不同实例或通用子进程自动继承不同境舱路线。[身份处理与匹配源码](https://github.com/InterceptSuite/ProxyBridge/blob/5dc49f8ce5853f7b4de783a4d6000f86bf8c6c6a/MacOS/ProxyBridge/extension/AppProxyProvider.swift#L284)
- **TCP 半关闭丢失。** 客户端单向 EOF 会取消整个上游连接；上游 EOF 会同时关闭客户端读写。外置 SOCKS／HTTP 服务不能恢复已经被扩展取消的另一方向。[转发源码](https://github.com/InterceptSuite/ProxyBridge/blob/5dc49f8ce5853f7b4de783a4d6000f86bf8c6c6a/MacOS/ProxyBridge/extension/AppProxyProvider.swift#L1312)
- **域名转发不等于 DNS 按境舱隔离。** SOCKS 请求仅在原端点为域名时使用域名类型；应用已经通过系统 DNS 得到 IP 时发送 IP。GUI 规则无法追回系统代发查询的原应用归属，也不能为并发的同域查询建立独立解析路线。[SOCKS 请求源码](https://github.com/InterceptSuite/ProxyBridge/blob/5dc49f8ce5853f7b4de783a4d6000f86bf8c6c6a/MacOS/ProxyBridge/extension/AppProxyProvider.swift#L1180)
- **存在明确直连分支及非原子配置窗口。** TCP 无配置或配置 UUID 失效时放行；UDP 没有任何 SOCKS5 配置时，在 BLOCK 规则之前放行。启动后异步加载配置和规则，重同步先清规则再逐条添加。GUI 自动化无法把这些步骤变成内核层的原子保护边界。[流量决策](https://github.com/InterceptSuite/ProxyBridge/blob/5dc49f8ce5853f7b4de783a4d6000f86bf8c6c6a/MacOS/ProxyBridge/extension/AppProxyProvider.swift#L533)、[规则重同步](https://github.com/InterceptSuite/ProxyBridge/blob/5dc49f8ce5853f7b4de783a4d6000f86bf8c6c6a/MacOS/ProxyBridge/ProxyBridge/RuleManager.swift#L75)

原版可经 GUI 添加代理和规则；内部也有 `sendProviderMessage` JSON 协议，但未发现供外部应用使用的控制服务。Apple 的透明代理配置加载关联于调用应用，不能把内部消息协议认定为 Envara 可直接调用的公开 API。[Apple 会话范围](https://developer.apple.com/documentation/networkextension/netransparentproxymanager/loadallfrompreferences%28completionhandler%3A%29?language=objc)

Profile 导入会切换整套配置，不能直接用于保留无关软件原有路由；规则导入仅追加，但代理动作须引用配置 UUID。代理凭据会随 Profile 持久化／导出，不能直接把 Envara 临时监听凭据放进这种长期配置。[Profile 实现](https://github.com/InterceptSuite/ProxyBridge/blob/5dc49f8ce5853f7b4de783a4d6000f86bf8c6c6a/MacOS/ProxyBridge/ProxyBridge/ProxyBridgeViewModel.swift#L289)

## tunless 的可复用进展与边界

v0.4.1 源码已经实现应用 EOF 后关闭 SOCKS 写方向，并继续排空对端，最长 30 秒；不能把它描述为没有半关闭处理。但上游同时记录：某些客户端 `shutdown(SHUT_WR)` 会使 Apple 的 `NEAppProxyTCPFlow` 断开，随后写回失败。修好 SOCKS 生命周期仍不能让已断开的 Apple flow 接受回应；这类 FIN 作为消息分隔符的协议可能需要能保留该语义的捕获层。[固定源码](https://github.com/bojieli/tunless/blob/6be3e12da9e3b589b149e686193c0233a8225555/macos/Sources/TunlessExtension/TransparentProxyProvider.swift#L760)、[上游限制记录](https://github.com/bojieli/tunless/blob/6be3e12da9e3b589b149e686193c0233a8225555/docs/MACOS.md#L943)

上游明确区分两类故障：provider 存活时的代理故障可保持拒绝流量；整个扩展退出、卸载或会话停止后，macOS 无 provider 接管新流量，普通路由恢复。v0.4.1 默认还会在持续降级 300 秒后回滚 capture；设置 `--degraded-timeout 0` 只能去掉该时限，不能解决整个扩展消失后的直连。独立的系统阻断机制仍是完整失败保护的必要验收项。[扩展退出行为](https://github.com/bojieli/tunless/blob/6be3e12da9e3b589b149e686193c0233a8225555/docs/MACOS.md#L648)、[v0.4.1 降级策略](https://github.com/bojieli/tunless/releases/tag/v0.4.1)

## 自有系统扩展的两条部署路线

1. **项目方维护并签署修订组件。** 使用项目自己的组件身份，对捕获归属、DNS 按境舱路由、原子启停与系统故障阻断作可审计实现；修订代码不套用原作者签名，也不覆盖用户现有组件。如果目标 flow API 本身不能保留客户端 FIN，必须选择能满足语义的捕获层。
2. **接入原作者公开发布的修订版。** 保留原版身份和许可，要求可取得的固定签名资产、对应源码，以及可验证的控制协议和保护语义；不能仅凭开发记录或 GUI 可操作就标记为已保护。

两条路线都必须在 macOS 原生环境验证：同软件多实例及子进程归属、两个境舱并发查询同一域名、TCP 两方向半关闭、TCP／UDP／DNS 出口、启动与配置切换窗口、代理／控制器／整个扩展退出后的拒绝直连，以及无关应用和既有 VPN／TUN 行为保持。源码检查、单测和构建通过均不能替代这些验收；当前没有据此宣称完成，GitHub 发布继续暂停。

## 不依赖自有 NE 签名的替代路线（2026-10-08 补充检索）

“当前自有 Network Extension 的正常部署需要签名”不能扩大为“所有按应用分流方法都需要 Apple 开发者资格”。以下项目提供真实的非 NE 实现；本轮只读核对固定源码，没有安装、运行、创建用户／组、写 PF、改路由、启用 TUN 或关闭 SIP。它们目前是候选，尚未满足 Envara 的正式附加软件保护门槛。

| 路线 | 已确认的实现 | 对 Envara 的具体边界 |
| --- | --- | --- |
| VPNonly 的进程组与 PF | `v1.9.26` 对应 `5f4a12c84f2ee9f575ae045e116a74c85edb7f31`。公开 app-engine 为每个应用创建独立 Unix group；root launcher 先设置组再降到原用户，PF 将该组的 TCP／UDP 送到用户态 WireGuard。没有 NE entitlement／开发者证书这项运行前提 | 需要管理员安装授权；固定公开 app-engine 对同一用户管理一个 WireGuard 接口，没有每组 AnyTLS／境舱出口映射；私有 GUI 的完整功能未实测。系统 DNS、外部 XPC／LaunchServices 服务、继承网络 FD、接口重用及 state 清理仍有具体缺口 |
| LianYaoHu 的 CLI guard | 固定 `767c9d7ba7624f4ff52ed26293a57f3cd1d6ac99`。root helper、专用 GID、`launchctl asuser`、sandbox-exec 和 PF；还提供只允许经本地代理出站的候选模式 | 面向命令行 agent，当前每用户共用组／anchor。默认 VPN 模式要求所选接口承载全 IPv4；不能直接替代多境舱、原版 GUI Notion 和独立系统 DNS 的验收 |
| Electron 参数代理 | `codex-gui-proxy` 固定 `6f54c0089393d0c193e0cd4d9dfd29eb9b999a60`。以 `--proxy-server` 冷启动原版 Electron 应用，无需注入或 NE | Electron 官方只承诺 HTTP／HTTPS／WebSocket 范围；Node socket、原生更新器、外部子进程及其他 UDP 不由此强制接管。只能单独标注兼容模式，不能授予“整个应用已保护”状态 |
| NE 的本机开发设置 | Apple 的开发测试文档提供放宽部分验证的路径；developer mode 放宽安装位置，放宽签名／公证涉及另外的开发设置 | 没有证明当前 Envara 在无 profile 的 ad-hoc 模式可激活；不能把 `developer on` 当成绕过全部 entitlement／profile 检查，也不能把降低本机安全设置作为普通用户安装方案 |

VPNonly 的 [launcher](https://github.com/kanishkdan/vpnonly/blob/5f4a12c84f2ee9f575ae045e116a74c85edb7f31/app-engine/vpnrun.c#L69) 在 root 下 `setgroups → setgid → setuid`，再 `posix_spawn(SETEXEC)`；[分组实现](https://github.com/kanishkdan/vpnonly/blob/5f4a12c84f2ee9f575ae045e116a74c85edb7f31/app-engine/group.sh#L28) 使用每应用 GID。它未关闭全部继承 FD；直接 fork/exec 子进程可以继承组，系统另起的服务不能据此获得该身份。固定公开 [路由实现](https://github.com/kanishkdan/vpnonly/blob/5f4a12c84f2ee9f575ae045e116a74c85edb7f31/app-engine/route.sh#L197) 从该用户唯一状态目录读取其自有 WireGuard 接口，对所属 group 使用同一接口，不接受任意已有 utun。这个限制不能扩大为私有 GUI 产品绝不支持作者所称的 multi-VPN。可借鉴的是“境舱→专用组→自有接口”的架构；改为独立认证 SOCKS／AnyTLS 传输属于待开发方案，而非公开引擎已实现能力。

断线保护有真实基础，也有必须测试的反例。固定 Apple XNU 的 [pf_route](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/pf.c#L9254) 在路由目标接口缺失时释放包，不改走默认路由。然而 [kif 管理](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/pf_if.c#L143) 按接口名保存对象；旧规则／state 保留引用时，同名 utun 再出现可重新指向新接口。旧规则因此可能把包送入无关 VPN，不能只凭规则仍存在保证整个核心／helper 崩溃后永久拒绝直连。这是固定公开内核源码推导，不是当前 Darwin 27 的实测结果。

上游 [state 清理](https://github.com/kanishkdan/vpnonly/blob/5f4a12c84f2ee9f575ae045e116a74c85edb7f31/app-engine/route.sh#L668) 也需重做：按路由接口清 state 不一定命中 floating state，按地址清理则可能打断其他 PF policy 的连接；源码明确承认后一种误伤。其 [VPN 冲突检查](https://github.com/kanishkdan/vpnonly/blob/5f4a12c84f2ee9f575ae045e116a74c85edb7f31/app-engine/up.sh#L588) 会拒绝当前端点经 utun／ppp／ipsec 的情况。[README](https://github.com/kanishkdan/vpnonly/blob/5f4a12c84f2ee9f575ae045e116a74c85edb7f31/README.md) 明确承认 mDNSResponder 查询不随应用组路由。不能原样集成后声称 DNS 隔离及现有 VPN 共存已解决。

VPNonly 的 CLI 与 app-engine 为 MIT，可按其 [许可证](https://github.com/kanishkdan/vpnonly/blob/5f4a12c84f2ee9f575ae045e116a74c85edb7f31/LICENSE) 复用；发行 GUI 是付费保留版权产品，禁止直接再分发，WireGuard 等组件仍须遵守各自许可。LianYaoHu 的 [PF 实现](https://github.com/madeye/LianYaoHu/blob/767c9d7ba7624f4ff52ed26293a57f3cd1d6ac99/crates/lianyaohu-core/src/pf.rs#L203) 与 [helper 启动设计](https://github.com/madeye/LianYaoHu/blob/767c9d7ba7624f4ff52ed26293a57f3cd1d6ac99/README.md#L138) 可供 CLI 身份／安全会话研究，不代表已核验 Notion GUI。

参数代理项目有两处不能照搬的文档说法：`<-loopback>` 是取消隐式 localhost／link-local 绕过，使其也走代理；代理 URL 里加入用户名密码也不能为 Chromium 配置认证。后者见 [Electron 43.6 固定文档](https://raw.githubusercontent.com/electron/electron/3333109a2998815e64ffc0a0a54d9a82899fe512/docs/api/command-line-switches.md)，前者见 [Chromium 固定测试](https://chromium.googlesource.com/chromium/src/+/d387f092f963cdceb9568d3a589686f7cf0e5986/net/proxy_resolution/proxy_bypass_rules_unittest.cc)。当前境舱认证监听不能直接套无认证 SOCKS 参数；原版应用是否支持认证回调或需额外局部前端，必须另行验收。

Apple [TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api) 将 PF 定位为系统实现细节和高级用户／管理员机制，不视为稳定产品 API，并建议面向广泛用户的产品迁移 NE；这是系统升级与共存维护的实际风险，不能当成技术上不存在替代的证明。[开发测试说明](https://developer.apple.com/documentation/DriverKit/debugging-and-testing-system-extensions) 则区分 developer mode 与签名／公证验证，不支持“只执行 developer on 即可正常分发”的说法。

建议下一项实验先使用自有 GUI／父子 fixture，而非 Notion 账号会话，证明独立组与独立 AnyTLS 传输、同域系统解析及缓存、IPv4／IPv6／UDP、FIN 尾部、核心/helper 崩溃与同名接口重用、严格所属 state 清理及未绑定应用网络保持。系统实验要使用独立所属规则，保留当前 VPN/TUN 与其他软件规则，不全局 flush，不更换主机 DNS。当前阶段仅更新研究记录，没有切换生产 adapter 或开启保护启动。

## X 原帖核对（内置浏览器，2026-10-08）

使用 Codex 内置浏览器的现有登录状态，实际读取项目搜索结果、作者原帖及可见回复；没有发帖、回复、关注或安装软件。页面读取接口恢复后，以下两条均取得正文，不能再描述为只有搜索引擎索引或第三方镜像。

- **VPNonly：** [作者发布帖](https://x.com/kanishkrazdan/status/2097663813441187936)，页面显示 2026-09-09 20:30。作者在 [同一串的说明](https://x.com/kanishkrazdan/status/2097663813990617151) 中介绍按应用选择 VPN，其他应用保留原网络；[提供商与源码说明](https://x.com/kanishkrazdan/status/2097663814586261766) 将 NordVPN、Mullvad、Proton、WireGuard 配置和免费 CLI 分开说明。“multi-vpn” 的发布措辞不能直接证明多条隧道同时按境舱独立运行，更不能证明公开引擎已有 AnyTLS；具体实现及限制以上述固定源码为准。
- **Tunless：** [作者原帖](https://x.com/bojie_li/status/2105665492228931874)，页面显示 2026-10-01 22:25，正文介绍 socket 层 TCP／UDP 转发并链接 `bojieli/tunless`。这是已确认的真实项目线索；其 macOS 源码仍是 Network Extension，不是免 NE 签名的 PF 替代路线。回复中的代理工具建议也必须核对平台，不能直接迁移到 Mac。

Tunless 帖子中的 [graftcp／mgraftcp 建议](https://x.com/fsysky/status/2105920512115495376) 经 [官方 README](https://github.com/hmgle/graftcp) 核对为 Linux-only，`mgraftcp` 当前为兼容别名，不能替代完整 SIP、原版签名 Notion 的 macOS 捕获层。其他回复对 DNS、PAC 和 ICMP 的讨论只作检索线索，不作为系统验收或签名要求的权威证据。
