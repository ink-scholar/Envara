# 附加软件分流：实现与备选路线

2026-10-07 核对。目标是「选择境舱 → 添加本地软件 → 启动」，所属进程使用该境舱的节点，其余软件保持原网络。项目发布暂停，Mac 软件接管部署继续暂停。

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

| 项目或产品 | 做法 | 对 Envara 的意义与限制 |
| --- | --- | --- |
| [Proxifier Mac](https://www.proxifier.com/new/mac.html) | 自带已签名 Network Extension，按软件代理 TCP 与远程 DNS | 最终用户使用它不需要苹果开发者账号；是商业外部产品，不能据此直接把其组件装进开源 Envara；UDP 和同软件多实例需另行验证 |
| [Surge Mac](https://manual.nssurge.com/rules/process.html) | Enhanced Mode 配合进程名称/完整路径/App bundle 规则 | 现成产品可按软件分流；官方明确 DNS 查询阶段无法判定来源进程，不能等同境舱独立 DNS；商业许可并非再分发许可 |
| [mitmproxy_rs / mitmproxy-macos](https://github.com/mitmproxy/mitmproxy_rs) | 上游独立 Redirector.app 承载 Network Extension；PID 选择与原始 TCP/UDP stream callbacks | MIT 开源、可研究外部依赖集成。保留原组件身份和签名可能无需先申请 Envara 自己的开发者账号；子进程、DNS、断线阻断与多境舱仍需补齐 |
| [ProxyBridge](https://github.com/InterceptSuite/ProxyBridge) | Mac Transparent Proxy / DNS Proxy 源码 | MIT 架构参考；自己改名、构建与分发扩展仍需要自己的合法签名材料，不能复制上游签名来签修改后的代码 |

对没有账号的 Envara，我建议先验证 **原版 mitmproxy Redirector 作为独立外部组件**：单一 capture broker 按可信进程身份把原始连接交给境舱各自的认证 SOCKS 入口，不解密 TLS，不安装 mitmproxy CA。这个建议是根据源码接口作出的工程判断，尚不是已集成的功能。正式自行维护扩展、改 bundle ID 或发布修改后的扩展，仍需项目维护者的 Apple Developer 签名/profile、公证；最终用户不需要自己的开发者账号。

保留上游组件时还要锁定版本、签名/Team ID、IPC 与安装归属，不能覆盖用户原有 `/Applications/Mitmproxy Redirector.app`，不能把 Python/Rust 控制接口直接暴露给渲染页面。Mac 部署暂停，所以这轮只做资料与只读签名检查。

## 原版 Mac 组件的只读实测

下载的是 [mitmproxy-macos 0.12.11 官方 wheel](https://pypi.org/project/mitmproxy-macos/0.12.11/)，SHA-256：`63349d9b46514ca679547651f7c0548f9222892edfbcba087b82b3244fbae859`。只解压到 `/tmp/envara-mac-redirector-inspection/`。

- `codesign --verify --deep --strict`：valid on disk / satisfies Designated Requirement。
- app 与 system extension：Developer ID Application: Maximilian Hils，Team ID `S8XHQB96PW`；x86_64/arm64 universal。
- app 附带公证票据；`spctl --assess --type execute`：accepted，source=Notarized Developer ID。
- 没有运行 app，没有安装到 Applications，没有授权/激活扩展，没有改动本机路由或证书信任。这些结果不证明 Envara 与此组件的流量集成已通过。

源码接口参考固定提交 `51fe2b7c5aa8439c162abb665db61c6669d146d6`：[local redirector API](https://github.com/mitmproxy/mitmproxy_rs/blob/51fe2b7c5aa8439c162abb665db61c6669d146d6/mitmproxy-rs/mitmproxy_rs/local.pyi)、[安装生命周期](https://github.com/mitmproxy/mitmproxy_rs/blob/51fe2b7c5aa8439c162abb665db61c6669d146d6/mitmproxy-rs/src/server/local_redirector.rs)。该源码提交与已发布 0.12.11 二进制不是同一版本，后续集成必须按实际版本核对 ABI，不应把接口研究当成二进制兼容实测。
