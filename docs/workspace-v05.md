# Envara 0.5 工作区与实现边界

0.5.0 是本地开发候选版，发布暂停。此文区分已落地的界面、环境与服务代码，以及尚未完成系统部署和验收的应用网络接管。历史版本的测试数字不能替代本轮结果，完整检查以 [验证记录](verification.md) 为准。

**English:** The 0.5.0 workspace provides dedicated environment, network, browser, terminal, application and monitoring pages, Chinese/English UI, detected egress context and scoped privacy settings. Application bindings and guarded native adapters are implemented. Windows defaults to the unmodified officially signed WinDivert x64 driver and an Envara user-mode guard; macOS activation/deployment is deferred. Windows shared-DNS adaptation, whole-guard crash blocking, preservation of existing unrelated connections, installation and native acceptance remain incomplete; routing must not be presented as production-ready.

## 工作区

导航依次为 **环境 → 网络出口 → 浏览器 → 终端 → 附加软件 → 运行监控**，设置置底。环境管理共用网络和工作目录；浏览器、终端与软件分别操作，监控汇总真实状态。

新建环境只显示名称、网络出口；默认自动匹配出口资料。浏览器内核、指纹、分组、隐私和手动语言/时区放在折叠的高级设置中。原有配置保持兼容，既有固定语言与时区不会因新版默认值而被改写。

中文/英文切换保存到应用设置，540 项词条覆盖界面、表单、终端、独立窗口与状态提示。用户输入的名称、路径、分组、程序名与终端输出不翻译。

## 共用网络与隐私

- 经认证的实际 HTTPS 出口查询提供公网 IP、IANA 时区、国家/城市估算与可用的区域坐标。代理服务器入口地址不会冒充出口地址。
- 未指定固定语言时，浏览器语言按出口国家匹配；未指定固定时区时，按出口检测结果解析。有代理时自动检测失败会拒绝启动；无代理的本地回退明确标注来源。
- 浏览器定位使用 IP 地理估算，当前精度为区域范围（约 50 km）。无可用坐标时不把本机定位当代理位置。它不能产生可靠的住宅街道地址。
- 标准/严格隐私模式按已知域名拦截第三方 HTTP(S) 追踪请求。严格模式扩大规则；拦截模式下阻止 service worker 绕过该请求层。关闭模式不执行这些追踪域名规则。
- 终端传入 `DO_NOT_TRACK`、`DISABLE_TELEMETRY`、`DISABLE_ERROR_REPORTING`；严格模式另传 `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`。这些是所属进程的退出选项，工具必须支持它们才会生效。

此实现不识别全部收集器，不拦截所有硬编码 IP、加密 DNS 或共享系统服务的请求；不解密 TLS，也不修改任意软件二进制。配置隔离不等于操作系统沙箱；网络出口、时区或配置分离不保证账号不会被关联或封禁。

## 终端

独立终端工作页沿用真实 PTY 与 xterm。支持拖动/键盘调高、放大与恢复、独立窗口、本地工作目录，以及同一境舱的多个独立会话。

复制会话创建新的进程，共享原启动目录、代理、时区、工具配置和历史，不复制运行中的命令、输出或临时进程状态。关闭视图不结束进程；明确关闭会话才结束所属进程。工具使用本机安装位置，但配置与历史保存在各境舱自己的目录中。

代理变量仍只约束支持它们的 CLI，不能替代按软件的系统网络接管。`TZ` 与工具设置只传给拥有的子进程，不修改宿主系统；任意 GUI 软件仍可能忽略这些变量，使用自己的操作系统 API。

## 附加软件

Windows 默认改用官方已签名 WinDivert x64 驱动与 Envara capture/guard 服务，避免先申请自己的内核驱动签名；原自写 WFP 源码保留为未启用备选。Mac 自有 App Proxy 源码继续保留，另研究原版已签名 mitmproxy 外部组件路线，详见 [方案与实测](application-routing-options.md)。这些选择尚未满足完整系统验收，尤其 Windows 的共享 DNS、guard 崩溃保护与无关应用既有连接仍未完成。没有启用全局 TUN 或改写宿主路由。

macOS 扩展由项目维护者使用 Apple Developer Program 的有效签名材料构建、签名和公证。最终用户安装已签名的正式版本时不需要开发者账号，只需系统要求的网络扩展授权。**当前 macOS 软件接管部署暂停，优先 Windows；不需要为本轮候选版申请苹果账号。** 已有 Mac 模块源码保留，未激活或接管网络，浏览器与终端继续提供。参考 [Apple 网络扩展权限](https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.developer.networking.networkextension) 与 [系统扩展分发要求](https://developer.apple.com/documentation/systemextensions)。

已落地「选择境舱 → 添加本地软件 → 启动」界面、`.app` / 可执行文件检查、绑定持久化、状态订阅、原生 helper RPC 适配和清理流程。首版一个软件身份只绑定一个境舱，不提供同一软件多实例分流保证。

服务同时检查组件安装、授权、TCP/UDP/DNS/子进程/断线阻断能力与完整验收记录。缺任何一项都拒绝启动；界面显示真实未就绪原因。凭据不进入应用绑定文件、公开诊断或启动参数。普通浏览器/终端路由成功不构成此模块已验收的证据。

| 平台 | 已实现的源码与本地检查 | 尚未完成 |
| --- | --- | --- |
| macOS（暂停部署） | App Proxy System Extension、按应用身份映射、认证 SOCKS TCP/UDP、按应用 DNS、启动 guardian 与撤销规则；Swift 构建、18 项源码测试、helper RPC 门槛；开发签名输出隔离，unsigned 清除签名材料残留 | 有效 Apple 签名/profile 的正向验证、签名/公证、用户安装配置及扩展激活；TCP/UDP/DNS、子进程、核心/扩展故障、既有 VPN 共存和逐应用实机验收 |
| Windows（优先） | WinDivert x64 捕获 DLL、TCP IPv4/IPv6 NAT/认证 SOCKS relay、真实进程/Job、UDP 阻断、撤销与受保护 DLL 文件链；每 route 认证 SOCKS→TLS DoH 与独立缓存；源码检查与组件交叉构建 | 任意软件共享 DNS Client 适配、整个 guard 故障后的持续阻断、无关应用既有连接保留、管理员安装/驱动信任与 Windows 实机验收；ARM64 无 capture 驱动 |

当前两个平台均不能据此宣布任意软件的全部访问已强制走境舱网络。Windows 明确保持 `ready:false`；macOS 未签名、未激活或无有效系统验收记录时同样保持未就绪。构建不能生成假的验收记录，布尔开关不能绕过启动门槛。

原生路由不会改变系统时区、Core Location / Windows 定位、钥匙串、设备标识或软件已有账号。共享系统服务、已有单实例后台软件、已脱离的辅助进程等需要逐应用验证，不按普通子进程直接承诺覆盖。

平台细节与独立检查方式见 [macOS 原生模块](../native/macos-app-routing/README.md) 和 [Windows 原生模块](../native/windows-app-routing/README.md)。浏览器供应商的功能差异及与 BrowseForge 的比较仍见 [能力矩阵](capability-matrix.md)。
