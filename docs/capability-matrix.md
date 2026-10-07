# Envara 境舱能力与验收矩阵

记录日期：2026-10-07。当前为 **0.5.0 本地开发候选版**，新增独立工作页、界面语言、浏览器隐私/出口定位与附加软件接管门禁。BrowseForge 固定版本源码纳入 `third_party/browseforge/`，由 Envara 桌面应用自动管理本地服务；终端、出口解析、受管 AnyTLS 与附加软件是 Envara 扩展，不代表上游已有相同产品入口。

状态含义：**源码已接入**表示实现或适配代码已纳入仓库；**Mac 后端已验证**表示所注明版本在 macOS Apple Silicon 上有真实执行证据；**待验证**表示当前路径还需测试；**计划中**表示尚未形成可验收的产品能力。中间阶段测试不代表冻结源码已通过，后端测试不代表 Electron 界面已验收，历史版本结果不自动转移到新增代码。

## 0.5.0 当前能力范围

| 能力 | 实现范围 | 验收边界 |
| --- | --- | --- |
| 六个工作页与简化配置 | 环境、网络出口、浏览器、终端、附加软件、运行监控依次排列，设置置底；保留暗色三栏，详细指纹放高级配置 | 新界面已接入；冻结源码的本轮桌面与浏览器证据见 [验证记录](verification.md) |
| 中文/英文界面 | 540 项静态界面翻译，设置保存语言；用户命名、路径和终端输出保留原文 | 界面语言与境舱浏览器 locale 分开，不自动翻译软件输出 |
| 共享出口上下文 | 浏览器、终端与附加软件私有上下文共用实际出口、时区、语言及粗略定位 | 固定时区/语言也检测出口定位；失败保留手动字段、geolocation=null，代理自动时区失败拒启动，不伪造出口或住宅地址 |
| Cloak 区域语言 | 原生语言参数结合 persistent context 的 opts.Locale，对齐 en-PH 等语言与 native Intl 默认地区 | 新增补丁需本轮实际浏览器证据；历史 provider 验收不自动转移 |
| 浏览器定位边界 | 使用 IP 地理服务返回的粗略经纬度/精度；缺少定位时拒绝宿主位置来源 | CDP 仅使用 Target.getBrowserContexts 清单内的有效 ID，默认 persistent context 省略无效 ID，拒绝策略维持到页面关闭；不修改系统定位 |
| 标准/严格隐私 | context route 阻断规则中的第三方 HTTP(S) 域名，Service Worker 阻止绕过；严格模式扩大列表 | 第一方请求保留；不代表消除所有追踪、加密软件遥测或账号关联 |
| 终端与 CLI 隐私 | 原有真实 PTY、目录/配置/历史、拖高、放大恢复、独立窗口与独立进程复制保留；提供 CLI opt-out 变量 | 网络范围仍为 proxy-aware-cli，不能强制全部 TCP/UDP；工具是否尊重 opt-out 需分别验证 |
| 附加软件绑定 | 原生选择本地软件，按身份绑定境舱，白名单原子存储，运行时状态不持久化 | 添加与管理绑定已接入；应用网络接管未就绪时启动明确拒绝，不以代理变量替代 |
| 附加软件启动与失败清理 | 私有 launch context、严格原生能力/验收门禁、主进程串行活跃配置锁；状态缺失转 error 并尝试清理 | 未确认停止/撤销时保留 route/session 归属及修改锁，不假报 stopped，不释放保护后继续运行 |
| macOS 应用接管 | Network Extension App Proxy 与 helper RPC 源码已接入 | 缺 Developer ID/provisioning、安装授权/扩展激活和系统验收，ready=false；源码编译/测试不代表原生可用 |
| Windows 应用接管 | WFP TCP/UDP 策略、受管 relay、进程/Job、BFE 代次撤销/过滤恢复与独立认证 DoH broker 源码已接入 | 共享 DNS 调用适配、WDK 构建/签名及实机故障验收未完成，ready=false；broker 不等于任意软件 DNS 已截获 |

0.5.0 的实际测试与桌面证据单独记录，以上不预填最终通过计数。终端代理、浏览器隐私与原生软件接管是不同范围；源码纳入完整上游不等于全部 BrowseForge 工作流均已在桌面逐项验收。以下为历史基线。

## 0.4.0 AnyTLS 历史基线

| 能力 | 实现范围 | 当前验收状态 |
| --- | --- | --- |
| 软件内置 AnyTLS | 固定 Mihomo v1.19.32 独立进程处理原始节点，不依赖用户另开 Clash | 19 项真实原生链、20 项包内链及一条真实供应商节点通过 |
| 每节点私有入口 | 127.0.0.1 随机认证 mixed 监听，MATCH 仅指向选定节点，无直连回退、无系统代理/TUN写入 | 私有入口认证、错误证书/密码、不可达与服务停止的拒绝回退通过；17 个所属进程清理通过 |
| 浏览器/终端共享路由 | 真实 HTTPS 经受管入口；临时 session proxy 不改原节点绑定，终端使用同一上下文 | 真实可见 Cloak/PTY与合成 Geo 时区联动通过；原始绑定重启保留，缺少入口的直接 REST/MCP 拒启动通过 |
| 核心意外退出与恢复 | 旧 Geo 失效，恢复保持原入口端口/认证 | 原有浏览器与 PTY再次HTTPS通过，不需重建这两个会话 |
| AnyTLS TLS 设置 | 密码、SNI默认host、严格证书默认开、chrome、ALPN数组与默认UDP true | 受控/真实节点严格HTTPS通过；源码原生 UI 的 ALPN/UDP/SNI保存回读、默认TLS/密码掩码与不可达失败通过。HTTP 入口不表示通用 UDP |
| 许可与源码分发 | 独立 Mihomo 保留 GPLv3、对应源码/vendor 及来源，原创应用保留 MIT | 9 资源测试、GOPROXY=off 离线重建及最终包内副本 SHA 一致通过 |
| 外部节点与 TUN | 单节点严格HTTPS与真实出口，Mac只读物理接口供节点/AliDNS IPDoH | 一条节点在 TUN 开启和用户主动关闭后均 example.com200、PH/Manila/Asia/Manila；无系统写入、环境覆盖或外部 Clash，不覆盖其他供应商/平台 |
| Mac arm64 最终本地包 | .app、DMG、ZIP，保留所有核心/source/license资源 | 30 文件SHA及元数据一致、包内真实AnyTLS/PTY、归档完整性通过；未签名/未公证，完整新包 GUI未逐项验收 |

0.4.0 的 npm test **193/193** 通过。原生链为 `test-artifacts/anytls-smoke/run-SIdTv5/proof.json`；包内链与终端分别为 `test-artifacts/anytls-packaged/run-HIooJP/proof.json`、`test-artifacts/packaged-terminal/run-EWQLtE/proof.json`。真实节点为 `test-artifacts/anytls-private-node/run-dWdWBT/proof.json` 与 `run-v2ajQf/proof.json`，资源为 `test-artifacts/package-verification/0.4.0-mac-arm64.json`，源码原生 UI 为 `test-artifacts/native-ui-0.4/run-NN5VHj/proof.json`。完整 GUI、Claude 登录/远端请求、其他供应商与平台未扩大结论。

## 0.3.0 工作区历史基线

| 能力 | 实现范围 | 当前验收状态 |
| --- | --- | --- |
| 多内核浏览器后端 | 三 provider 的能力目录与桌面安装入口保留 | 0.3.0 Cloak 原生回归 11 项通过；Camoufox 与 Alpha 本轮未执行，不能把目录读取当可见会话测试。两家族和 Alpha 的 0.2.0 证据保留在下一节 |
| 认证代理真实出口与地域检测 | 通过 HTTP、HTTPS 或 SOCKS5 代理访问固定 HTTPS 服务，校验公网 IP、粗略城市和 IANA 时区；按有效代理配置缓存，修改配置使缓存失效 | 实际 ipwho.is 直连 HTTPS 出口检查通过，IP 已脱敏；用户代理供应商结果待验收。代理入口地址、预设时区或失败结果不算检测成功 |
| 自动时区与浏览器/终端解析 | 同一环境使用有效代理与时区解析规则；自动结果只作为临时会话参数，不改保存的手动值。有代理检测失败拒绝启动，无代理可明确回退本地时区 | 3 项真实 Cloak 临时时区检查，以及直连出口→默认 PTY TZ/Intl 和旧指纹字段兼容共 7 项通过；保存的配置未改。代理供应商完整联动待验收 |
| 每环境原生终端与工作目录 | 真实 node-pty、原生目录选择与会话标签；默认 360 px 底部面板支持拖动、键盘调节、放大恢复和独立窗口；Web 预览禁用原生操作 | Electron 44.6.0 预检、12 项真实 PTY 和最终候选包 3 项终端检查通过。原生 pwd/date、放大恢复、复制新 PTY 与独立窗口命令通过；Web 高度/键盘/8 标签交互通过 |
| 同境舱复制会话 | 创建独立 PTY 与代理桥，共用所属境舱配置/历史；使用原选启动 cwd，不追踪 shell 手动 cd，不复制命令或临时环境变量 | 真实 PTY 副本独立输入输出、代理路由及关闭源后副本继续运行通过；全境舱会话停止前目录保持锁定 |
| 终端视图与会话分离 | 折叠面板或关闭独立窗口保留会话；明确关闭会话、自然退出或退出应用清理所属进程 | 原生关闭副本 B 后 A 继续运行；关闭独立视图返回主窗后 A 与输出保留。原位已有会话复用仅有服务/单元证据，尚未单独 GUI 验收 |
| 独立工具配置与历史 | 每环境 HOME、XDG、Claude 配置、shell 历史和临时目录分开；从白名单构建环境变量，不直接继承宿主 API 密钥或启动钩子 | 真实 PTY 分离、0700/0600 权限与 6 项历史校验通过，重开保留；仍使用同一 OS 用户权限，不是文件或进程沙箱 |
| SOCKS5 命令行代理桥 | 私有随机认证的本机 HTTP 桥与远程 SOCKS DNS；HTTP/HTTPS 代理使用子进程代理变量，localhost 明确直连 | 冻结源码中代理感知 PTY 客户端的认证 SOCKS5 请求通过，凭据不进入目标站点或快照；不强制路由所有程序 |
| 终端退出清理 | 明确关闭会话、shell 自行退出与应用关闭时清理已记录归属的进程和桥连接 | 真实 PTY 关闭/重开/后台子进程清理通过，源与副本互不误杀，所属剩余为 0，不影响无关进程；不保证捕获提前完全脱离且未记录的守护进程 |
| Claude CLI | 设置独立 CLAUDE_CONFIG_DIR，并提供代理变量与 HTTP 桥 | 配置接口已接入；Claude 安装、登录、远端请求尚未执行 |

0.3.0 npm test **145/145** 通过；其中终端 Service 18 项、Process 6 项、Bridge 12 项共 36 项单元及本地进程/网络测试。Go 全包及 API/browser/profile race 检查通过；原生 PTY 预检和 15 份许可证准备通过。真实 PTY 记录为 `test-artifacts/terminal-smoke/run-j1qwoT/proof.json`，会话时区记录为 `test-artifacts/sidecar-prototype/session-timezone-9ylq6ufu/proof.json`，Cloak 回归为 `test-artifacts/sidecar-smoke/run-NwBoJB/proof.json`。列出的原生多窗口核心操作已通过，全部 GUI 未逐项验收。IP 地理定位只估算地域，不提供住宅街道地址；环境和账号隔离不保证免于服务封禁。

直连出口与旧字段兼容链为 `test-artifacts/auto-egress-terminal/run-nAADv9/proof.json`，最终候选包终端为 `test-artifacts/packaged-terminal/run-blswCc/proof.json`。当前包 19 份源码/前端/许可证文件 SHA 匹配、package.json 语义匹配、Node 可执行、15 份许可证完整、DMG/ZIP 完整性通过；后端与上述原生记录相同。包证据为 `test-artifacts/package-verification/0.3.0-mac-arm64.json`；该包终端检查不覆盖远端 CLI、代理路由或完整 GUI。

## 0.2.0 多内核历史基线

以下记录对应 0.2.0：macOS Apple Silicon 两家族原生回归 12 项通过，另有 6 轮、12 个新 Cloak 环境的并行单标签页回归；Alpha 为独立单项启动验证。.app、DMG、ZIP 的打包一致性、归档完整性、启动和基本 UI 只读验收通过；全部 GUI 操作未逐项验收。这些结果保留作回归对照，不能作为新增 0.3.0 功能已通过的证明。

| 能力 | 本地 BrowseForge 服务路径 | 已有证据与剩余工作 |
| --- | --- | --- |
| 桌面界面与本地服务 | Mac 后端与基本 UI 已验证 | 零内核工作区可启动受保护服务，重启保留环境；打包 UI 的三栏、新建表单、迁移预览/取消只读验收通过。没有对真实用户环境执行迁移、新增或启停，全部 GUI 操作未逐项验收 |
| 三个 provider 与真实截图 | Mac 后端已验证 | CloakBrowser、Camoufox 和 BrowseForge Chromium Alpha 均实际启动；Alpha 完成独立截图/停止检查，不代表发布级稳定性 |
| 创建、编辑、克隆、删除环境 | 部分 Mac 后端已验证 | 实际创建、编辑、克隆与配置导入已执行；克隆生成新种子。删除及完整失败恢复仍需独立原生/UI 验收 |
| 启动、停止、聚焦与关闭会话 | Mac 后端已验证 | 同时启动两 Cloak 环境和 Firefox；聚焦不新增标签页；关闭最后标签页后回收会话；关闭测试工作区后没有残留所属浏览器或后端进程 |
| 并行启动与正常启动标签页 | Mac 后端已验证 | 冻结源码 6 轮并行启动共 12 个新 Cloak 环境，每个只有一个本地测试标签页；结果不替代所有网站和既有环境的标签页恢复验收 |
| 每环境平台、种子、语言、时区、屏幕 | 部分 Mac 后端已验证 | 手动参数补丁后，上海/纽约两 Cloak 环境分别展示正确语言、Intl、时区和屏幕，Mac 上 Windows 身份为 Win32/Windows UA；Firefox 与 Alpha 的手动 Mac 身份亦通过。种子已验证克隆重新生成，完整指纹稳定性未验收 |
| 语言、时区自动匹配出口 | 源码与适配测试已验证；外部出口待验证 | 支持清空手动设置并恢复自动模式；尚未对真实外部 GeoIP、代理地域回退及自动原生结果做端到端验证 |
| Cookie、localStorage 隔离与重启保留 | Mac 后端已验证 | 两个 Cloak 环境的 Cookie/localStorage 隔离且停止重启后保留；Firefox 跨内核隔离及 localStorage 持久化通过 |
| HTTP、HTTPS、SOCKS5 代理 | HTTP 认证 Mac 后端已验证；其余待验证 | 真实浏览器请求通过本地认证 HTTP 代理。认证 SOCKS5 relay、HTTPS、外部代理出口与泄漏检测尚未验收 |
| 代理检查 | 历史实现 | 0.2.0 桌面检查只证明 TCP 端口可达；0.3.0 替换为上方的认证 HTTPS 实际出口检测，最终验收单独记录 |
| 分组、标签与分组代理策略 | 源码及适配测试已接入；原生待验证 | 原生测试保存了分组；默认/强制代理继承、运行中修改和完整标签流程仍需验证 |
| 配置导入导出、备份与恢复 | 配置交换 Mac 后端已验证；完整备份待验证 | v2 配置导出脱敏代理凭据，导入必须显式映射代理且保留绑定。配置导出不含完整浏览数据，不等于 Cookie/浏览器目录备份 |
| 旧工作区迁移 | Mac 后端已验证 | 自愿迁移复制真实浏览器目录与本地代理凭据；迁移后 Cookie/localStorage 可读取，备份摘要正确，原配置摘要不变且源目录保留 |
| CPU、内存与资料大小 | 源码及适配测试已接入；显示待验证 | 已接系统采样并校验运行状态和未知数值规则；实际统计准确性与桌面展示还需独立验收 |
| REST、MCP、Playwright 连接、YAML 工作流 | 部分 Mac 后端已验证 | 受保护 REST 和 MCP 初始化通过，工具目录为 43 项；evaluate、get_content、list_tabs 实际操作浏览器。Playwright 外部连接、YAML 工作流及其余全部工具未逐项验收 |
| WebRTC、字体、硬件、Canvas/WebGL 等完整指纹 | 上游源码具备；检测待验证 | 手动可见字段测试未覆盖这些表面的完整一致性、UA-CH 与物理内核版本一致性，亦未证明通过全部第三方检测器 |
| 多用户与权限管理 | 计划中 | 当前面向本机工作区；尚无已验收的多人协作与权限流程 |

## 多内核历史范围

| Provider | 上游固定基线 | Envara 0.2.0 实际状态 |
| --- | --- | --- |
| `cloakbrowser` | macOS `145.0.7632.109.2`；Linux/Windows `146.0.7680.177.4` | macOS Apple Silicon 的双环境手动参数、截图、HTTP 认证代理、隔离、重启与迁移已验证；其他平台未实测 |
| `camoufox` | `v135.0.1-beta.24` | macOS Apple Silicon 官方安装、与 Chromium 同时运行、手动语言/Intl/时区/屏幕、跨内核隔离与 localStorage 持久化已验证；Intl 的 zh-Hans-CN 与请求 zh-CN 语义一致 |
| `browseforge-chromium` | `v0.1.6-alpha.0` | macOS Apple Silicon 官方单 provider 安装、可执行探测、实际 Chromium `150.0.7871.101`、手动参数、截图和停止已验证；仍为实验性未签名 Alpha |

BrowseForge Chromium 上游有 macOS、Linux 与 Windows 的 Alpha 产物，但其 macOS Intel 产物明确仅打包，未完成启动与检测验证；上游仍声明 `release_grade_ready=false`。这些产物和能力声明不能替代 Envara 的平台验收。[固定版本 runtime README](https://github.com/nczz/browseforge-runtime-chromium/blob/92cfe89356ef0e7fb22979f5ee8d95a0a832d69b/README.md#L43)、[发布验收状态](https://github.com/nczz/browseforge-runtime-chromium/blob/92cfe89356ef0e7fb22979f5ee8d95a0a832d69b/knowledge/manifests/release-status.json)。

## 平台与许可

- **macOS Apple Silicon：**0.2.0/0.3.0/0.4.0 结果保留为历史；0.5.0 的冻结源码证据见 [验证记录](verification.md)。附加软件 App Proxy 部署暂停，源码保留；尚无签名扩展激活或系统接管验收，拒绝启动附加软件。
- **Windows：**附加软件当前优先；源码交叉编译、BFE 生命周期与 DNS broker 本地测试不代表内核驱动已运行。共享 DNS 调用适配、WDK 构建/签名与真实机器验收未完成，原生 ready=false。Envara 浏览器、终端与安装包亦未完成 Windows 实机验收。
- **macOS Intel、Linux：**Envara 本地服务、终端与安装包未完成实机验收。上游的平台矩阵与 CI 构建目标分别说明源码/产物范围，不能作为 Envara 已可用的证明。
- **源码许可：**Envara 原创应用与纳入的 BrowseForge 代码保留 MIT；独立 Mihomo 核心保留 GPLv3 及对应源码/vendor 和来源记录，应用 MIT 不替代核心许可。见 [第三方声明](../THIRD_PARTY_NOTICES.md) 与 [固定版本 BrowseForge License](https://github.com/nczz/BrowseForge/blob/fa9e0bb670e749706a9c8f2d4095333347d6c521/LICENSE)。
- **CloakBrowser：**包装层为 MIT，编译浏览器适用独立专有许可。Envara 不把该内核打入安装包；用户须从官方渠道获取，版本与订阅条件以其条款为准。[包装层 License](https://github.com/CloakHQ/CloakBrowser/blob/5fa65172f0612b3ea3efbee719be0cb618594285/LICENSE)、[Binary License](https://github.com/CloakHQ/CloakBrowser/blob/5fa65172f0612b3ea3efbee719be0cb618594285/BINARY-LICENSE.md)。

上游对照基线为 BrowseForge `fa9e0bb670e749706a9c8f2d4095333347d6c521`（v2.1.15）：[provider registry](https://github.com/nczz/BrowseForge/blob/fa9e0bb670e749706a9c8f2d4095333347d6c521/internal/runtime/runtime.go)、[平台与版本定义](https://github.com/nczz/BrowseForge/blob/fa9e0bb670e749706a9c8f2d4095333347d6c521/internal/runtime/support.go)、[Chromium 启动逻辑](https://github.com/nczz/BrowseForge/blob/fa9e0bb670e749706a9c8f2d4095333347d6c521/internal/browser/launch_chromium.go)。后续只有补丁后的实际验证通过，才更新对应状态。

0.2.0 历史验证计数为 npm test **65/65**、资源准备辅助测试 **7 项**；Go 全包及 browser/API/MCP race 检查通过。该轮冻结源码原生记录为 `test-artifacts/sidecar-smoke/run-Wed9Ik/proof.json`，并行专项为 `test-artifacts/sidecar-smoke/parallel-fixed-S4ov8I/proof.json`；Alpha 独立记录为 `test-artifacts/alpha-smoke/run-jcUD6L/proof.json`，仍为实验性，且未验证其归档的官方发布摘要。latest-proof 别名可能被新测试覆盖，复核历史时以该轮路径为准。

0.2.0 服务 SHA-256 为 `915faddfe43506aa2cc4887e2b1b7e386d1399a1e1847c08ecfb085cb52d8acd`，源码树 SHA-256 为 `ddde9f2114ccef3e7f7a2c4cea1fb583e0b4f617483cc6bdb05c0fed073ccdc3`，对应该轮最终资源构建记录。隔离测试产物不提交至公开仓库，不构成浏览器包签名或发布完整性认证。构建资源包含匹配的 Node/Playwright 驱动与许可证；0.3.0 还准备原生 PTY 资源，目标是桌面用户无需系统 Go 或 Node。

发布继续暂停，新代码尚未推送，当前没有公开的 0.5.0 正式下载版。附加软件原生接管、其他系统、全部 MCP、完整指纹、其他地理服务与未测试供应商、全部代理协议完整流程及完整浏览资料备份保持未验收。
