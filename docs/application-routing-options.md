# 附加软件路由

适用于 Envara 0.5.23。当前发布目标为 macOS arm64。识别出受支持引擎只说明软件具备适配条件，**不等于任意软件、扩展、登录流程和故障场景均已通过保护验收**。

## 使用与数据

添加时依次选择网络组、本地软件和链接浏览器。同一软件身份绑定一个环境，并由 Envara 管理一个实例。启动前重新校验签名、实际引擎和目标身份；发现原版或其他实例时要求用户先关闭，不接管或终止无关会话。

软件运行期间复用已确认网络环境。切换网络必须先停止并确认清理；关闭软件窗口不代表进程已结束，可重新打开窗口。软件自然退出结束观察，退出 Envara 会结束其管理的实例。

每个环境/软件分别保存 UserData、Home、Cache、Temp 和 Extensions。VS Code 另指定共享数据与扩展路径。停止、解绑和退出保留登录资料；删除只通过明确清除数据或删除环境完成。缓存回收只处理命名的可再生缓存，不删除离线文档。

## macOS：PF、进程身份与自有隧道

默认原生路线使用专用 GID、作用域内 PF 规则、自有 utun 和固定 Mihomo 传输，经环境的认证节点入口出网。安装与激活通过显式操作和 macOS 授权提示完成，不要求先购买 Apple Developer 账号。只读状态与计划不创建组、启用 PF、改路由/DNS或启动目标。

原生启动器根据签名 Electron/Chromium 引擎识别适配能力，并复核原应用、密封副本和运行目标。无法识别或不满足条件的软件拒绝启动，不退回普通冷启动。清理需核对进程、入口、规则、隧道和租约；清理未确认时保留归属和失败状态，不显示为已停止。

Chromium/Electron 软件在外层 Seatbelt 网络围栏内以 `--no-sandbox` 运行，因为 macOS 不能嵌套该沙箱。代价是关闭应用自身的 Chromium 内层沙箱；外层围栏不是相同的内部进程隔离机制。DNS、子进程、继承描述符、外部系统服务、IPv6、整个守护进程故障及无关应用网络仍需各自验收。

保留的 Network Extension/原版 Redirector 接入为独立路线，不借用其存在或授权提升默认 PF 路线的验收状态。不覆盖用户已有的第三方安装。

实现依据：[桌面路由适配器](../electron/macos-pf-application-routing.mjs)、[原生 GUI 合同](../native/macos-pf-routing/gui-contract.md)、[身份与策略](../native/macos-pf-routing/policy.mjs)、[引擎启动器](../native/macos-pf-routing/gui-launch.m)。

## Windows：未完成原生验收

源码默认使用未修改、官方签名的 **WinDivert 2.2.2-A x64**，配合 Envara capture DLL 与 Go guard；旧自定义 WFP 驱动保留为非默认备选。不得修改或重新签署上游驱动。

已实现的构件包括进程创建时间/Job 归属、独立 route、TCP relay、撤销、UDP 阻断及独立认证 DoH broker。以下仍是阻断项：

- 共享系统 DNS Client 代发请求的可靠归属与拦截。
- 整个 guard/驱动失效时不出现直接连接窗口。
- 无关应用既有连接、IPv6、进程/端口复用、资源耗尽及 VPN 共存。
- Windows 实机安装、驱动信任、GUI 生命周期与退出清理。

Windows 不能因交叉构建或包校验而开放保护启动。ARM64 helper 构建不代表 ARM64 capture 支持；不使用虚拟机替代原生验收。参见[Windows 原生说明](../native/windows-app-routing/README.md)及[桌面打包](windows-desktop-packaging.md)。

## 定位、链接与边界

应用复用环境的时区、有效 locale 和路由上下文；软件是否采用这些提示取决于其实现。目录隔离不是另一个 macOS 用户、Keychain、硬件身份或系统定位服务，也不代表任意加密遥测被过滤。

受管理的网页链接默认打开同环境浏览器；其他保存选择须在同一网络，系统浏览器是明确的环境外选项。系统链接路由需要用户接受 macOS 可撤销的默认浏览器变更，无关应用链接仍交给原默认浏览器。

不承诺住宅地址、消除全部追踪、通过所有检测器或规避服务端账户限制。当前能力与未测覆盖见[能力矩阵](capability-matrix.md)。
