# 验证记录

记录日期：2026-10-07。当前开发 0.3.0 本地候选版，发布暂停。结果按版本与运行路径区分，旧结果不自动代表新增代码已验收。状态见 [能力矩阵](capability-matrix.md)。

## 0.3.0：出口时区与每环境终端

| 检查 | 当前证据 |
| --- | --- |
| 功能实现 | 认证代理 HTTPS 出口检测、自动时区解析、原生工作目录选择、每环境 PTY 与独立工具配置已接入 |
| JavaScript 测试 | npm test 145/145 项通过；终端 36 项包含在总数中 |
| 原生模块准备 | node-pty 1.1.0 在 Electron 44.6.0 / Node-API 10 上通过实际 PTY 预检；15 份依赖许可证已准备 |
| Cloak 本轮原生回归 | 11 项通过，包括空服务、43 项 MCP 目录及 3 个真实工具、双可见会话手动身份、隔离与持久化、认证 HTTP、克隆/导入、真实资料迁移及退出 |
| Camoufox 与 Alpha 本轮执行 | 当前 0.3.0 记录未安装或执行这两个内核；三 provider 的目录能力读取不算运行验收，历史结果保留在下一节 |
| 冻结源码真实终端 | Electron 44.6.0 / Node 24.21.0 的 12 项真实 PTY 验收通过；跨境舱分离、代理桥请求、同境舱复制、源/副本独立退出及目录锁定通过 |
| 终端测试 | Service 18 项、Process 6 项、Bridge 12 项，共 36 项单元及本地进程/网络测试通过，包含复制/取消竞态 |
| 独立历史与退出 | 6 项历史布尔校验全为 true：各自标记保留且不交叉、0600 权限、重开保留；最终剩余所属进程为 0 |
| Go 后端 | 本轮全包测试及 API/browser/profile race 检查通过 |
| 会话临时时区原生参数 | 3 项检查通过：拒绝非法字段而不启动浏览器、Cloak 原生身份使用本次时区但不改保存配置、下一次无临时参数仍使用保存的手动时区 |
| 直连真实出口到终端与旧字段兼容 | 7 项真实检查通过：实际 ipwho.is HTTPS 公网出口返回 America/Los_Angeles，默认 node-pty 中的打包 Node 同时报告一致 TZ/Intl；自动配置不改。旧指纹语言/时区保持固定，明确切自动才清除并重新识别；0 个浏览器会话，正常退出 |
| 外部代理供应商自动时区 | 本轮直连证据不代表用户代理供应商已验证；代理出口到浏览器/终端的完整实际链路单独验收 |
| 最终候选包真实终端 | 3 项通过：从 app.asar 使用完整展开的 node-pty，输入输出/尺寸/打包 Node/私有 cwd 与配置/时区、自然退出/重开/关闭/应用退出；剩余所属进程为 0 |
| 包资源与归档 | 19 份源码/前端/许可证文件 SHA 匹配，package.json 语义匹配，当前入口/控制器/前端/终端代码已冻结；后端与原生证据一致，Node 可执行，15 份许可证完整，DMG/ZIP 完整性通过；个人旧配置保持原样 |
| Web 构建界面 | 当前 JS/CSS 构建的高度拖动、键盘调节、放大恢复与复制到 8 标签测试通过；不是原生 PTY 界面验收 |
| 原生终端 UI 核心操作 | 实际 Tokyo 会话 A 的 pwd/date 输出、放大/恢复持续运行、复制 B 为新 PTY、B 独立窗口 pwd 通过；明确关闭 B 后 A 仍运行，独立窗口再次输出 JST。关闭独立视图后返回主窗，A 继续运行且输出保留 |
| 原位已有会话复用与其他 GUI | 复用由服务/单元测试覆盖，未单独执行该原位 GUI 路径；全部 GUI 按钮未逐项验收 |
| Claude CLI | 未执行安装、登录或真实远端请求 |
| 其他操作系统 | 原生模块、终端、出口时区和安装包尚未实机验收 |

本轮成功出口检测必须来自通过指定网络发出的 HTTPS 请求，包含有效公网 IP 和 IANA 时区。代理入口地址、预设时区或地理服务失败均不算成功。自动模式下有代理且检测失败时阻止启动；无代理时允许明确标记为本地来源的时区回退。

配置与时区仅作用于 Envara 拥有的子进程；真实 PTY 测试使用独立资料和本地认证代理，直连出口测试使用真实 HTTPS 地理服务。它们证明配置分离、已测自动时区链与代理感知客户端路由，不证明操作系统沙箱、所有程序强制代理、住宅地址或账号不会被封禁。退出证据覆盖已记录归属的 shell 与后台子进程，不保证捕获提前完全脱离的守护进程；macOS 进程出生标记使用秒精度。关闭视图保留会话已在原生桌面观察，明确结束会话或退出应用才清理所属进程。以下 0.2.0 的计数与哈希只作历史基线。

终端记录为 `test-artifacts/terminal-smoke/run-j1qwoT/proof.json`，会话时区记录为 `test-artifacts/sidecar-prototype/session-timezone-9ylq6ufu/proof.json`，Cloak 回归为 `test-artifacts/sidecar-smoke/run-NwBoJB/proof.json`。后两项的后端 SHA-256 均为 `1ba3ab54ebc038a68f978ab364344aebcf6c9b62f9c7be15179eb871cd5f0ff7`；回归记录的后端源码树 SHA-256 为 `bec6c2c836b4e58b1af6efa89659886d19e9216a0f35fbf2d00deb949e44807b`。npm 总数见 `test-artifacts/final-0.3-tests.log`。这些是本机隔离验收资料，不是公开浏览器归档、应用签名或发布认证。

直连与旧字段兼容记录为 `test-artifacts/auto-egress-terminal/run-nAADv9/proof.json`，公网 IP 已脱敏；它使用上述后端，不下载或启动浏览器，也不调用 CLI 账号。最终候选包终端记录为 `test-artifacts/packaged-terminal/run-blswCc/proof.json`，只证明包内终端加载与生命周期，不覆盖 GUI、远端 CLI 或代理路由。Web 界面验证使用当前 `index-8k7Db2PH.js` 与 `index-lJzzvbOD.css`；演示适配器的 8 标签检查不替代真实多窗口验收。

包核验记录为 `test-artifacts/package-verification/0.3.0-mac-arm64.json`。原生核心操作由完整截图 `test-artifacts/terminal-qa/18-native-independent-shell.png`（2200×1520）与 `19-native-expanded-surviving-shell.png`（3000×1880）复核，测试与截图保持在本机隔离目录。截图证明所列操作，不扩大到全部桌面流程；这轮没有推送或发布。

## 0.2.0：多内核本地服务历史基线

固定 BrowseForge v2.1.15、提交 fa9e0bb670e749706a9c8f2d4095333347d6c521，加入桌面补丁。上游能力、适配源码和旧版结果不能直接等同于新路径验收。

| 检查 | 当前证据 |
| --- | --- |
| JavaScript 测试 | npm test 65/65 项通过 |
| Go 后端 | 全包测试通过，browser、API、MCP 的 race 检查通过 |
| 固定后端与 REST 适配 | 新服务原生回归通过；基本打包 UI 只读验收通过，全部 GUI 操作未逐项验收 |
| macOS arm64 后端资源 | 已生成 sidecar、完整官方 Playwright driver 1.61.1 与 Node 24.18.0；7 项资源准备辅助测试通过 |
| 冻结源码原生回归 | 新服务两家族完整回归 12 项通过 |
| 并行启动专项 | 6 轮并行启动共 12 个新 Cloak 环境，每个仅一个测试标签页，未出现额外启动页 |
| 空工作区 | 零内核时本机服务正常启动，私有 REST 需认证 |
| MCP | 初始化与 43 个工具枚举通过；evaluate、get_content、list_tabs 已操作真实浏览器 |
| CloakBrowser 145.0.7632.109.2 | 两个可见窗口并行运行，独立手动语言、Intl、时区、屏幕及系统画像通过 |
| Camoufox 135 | 官方安装及可见 Firefox 与 Chromium 同时运行通过；手动身份匹配，Firefox 的 zh-Hans-CN 与请求 zh-CN 语义一致 |
| 数据隔离与重启 | CloakBrowser 两环境 Cookie/localStorage 隔离与持久化通过；Firefox 跨内核隔离和 localStorage 重启保留通过 |
| 认证 HTTP 代理 | 新服务实际浏览器请求经过本地认证代理，通过认证 |
| 克隆与配置导入导出 | 克隆更新种子，导出移除凭据，导入保持明确映射的代理 |
| 旧资料迁移 | 复制真实 Cookie/localStorage、本机代理凭据并校验备份，原配置字节不变 |
| 会话生命周期 | 聚焦复用当前页，最后原生标签页关闭后回收会话；服务重启保留环境与元数据 |
| 退出 | 本轮托管浏览器与后端进程已全部关闭，剩余数量为 0 |
| BrowseForge Chromium Alpha | 官方安装和可见会话、手动身份、真实截图、停止及关闭通过；版本标记 v0.1.6-alpha.0，实际 Chromium 150.0.7871.101 |
| 分组代理与批量操作 | 适配源码已接入，完整桌面流程尚待验收 |
| 打包代码与后端一致性 | app.asar 中的入口、服务管理/客户端/适配代码和前端构建文件与冻结版本逐字匹配；后端 SHA-256 与最终原生回归相同 |
| 打包运行资源 | Node 可执行文件、provenance 和许可证资源完整 |
| 新版本 .app、DMG、ZIP | macOS arm64 已构建；hdiutil verify 确认 DMG 有效，unzip -tq 确认 ZIP 无错误 |
| 打包应用启动与布局 | 本机启动通过，原生三栏完整，显示真实空环境、已安装内核和旧环境提示 |
| 迁移预览与取消 | 显示真实旧环境，未确认时迁移按钮禁用；取消后新环境仍为空，内核目录保留 |
| 新建表单 | 默认已安装 CloakBrowser、about:blank，语言/时区、高级折叠与固定操作区完整；未提交新环境 |
| Windows、Linux、macOS Intel | 新版本尚未完成实机验收 |

以上原生证据来自 macOS Apple Silicon 的独立工作区、真实可见浏览器和本地测试站点/代理。冻结源码的手动身份和并行启动补丁已重新完成回归。Alpha 是单独的实验性内核测试，不并入两家族的完整回归结论。

该轮冻结源码记录为 `test-artifacts/sidecar-smoke/run-Wed9Ik/proof.json`，并行专项为 `test-artifacts/sidecar-smoke/parallel-fixed-S4ov8I/proof.json`；Alpha 独立记录为 `test-artifacts/alpha-smoke/run-jcUD6L/proof.json`。latest-proof 别名可能随新测试更新，历史复核应使用该轮路径。这些隔离产物不提交至公开仓库，也不是安装包签名或浏览器归档摘要验证。

该轮后端二进制 SHA-256 为 `915faddfe43506aa2cc4887e2b1b7e386d1399a1e1847c08ecfb085cb52d8acd`，源码树 SHA-256 为 `ddde9f2114ccef3e7f7a2c4cea1fb583e0b4f617483cc6bdb05c0fed073ccdc3`；它们与最终资源构建记录及打包后端一致。本机包资源记录为 `test-artifacts/package-verification/0.2.0-mac-arm64.json`。最终原生界面截图经完整 3000×1880 图像检查，覆盖主页、迁移预览和新建表单；截图留在隔离验收目录，不作为公开演示数据。

## 0.1.x：旧直接驱动路径的历史证据

0.1.0 功能验收在 macOS Apple Silicon 完成，0.1.1 补充 Linux 发布元数据。该路径使用 cloakbrowser@0.5.12 和 Chromium 145.0.7632.109.2。

| 检查 | 历史结果 |
| --- | --- |
| 核心测试 | 24 项通过：15 项后端、9 项运行适配器 |
| Sites 构建与路由 | 4 项通过 |
| 打包 .app | 原生界面创建、启动和停止通过，从 app.asar 加载 |
| macOS arm64 DMG、ZIP | 已构建，DMG 完整性校验通过 |
| 设置页安装 | 打包应用从实际设置界面主动安装官方内核 |
| 两个可见会话 | zh-CN / en-US、上海 / 纽约时区、各自屏幕尺寸通过 |
| 语言一致性 | navigator.language、navigator.languages 和 Intl 默认语言匹配 |
| Cookie 与 localStorage | 环境隔离和停止/重启后的持久化通过 |
| 认证 HTTP 代理 | 浏览器请求经过本地测试代理并通过认证 |
| 克隆、导出、重载 | 通过，新环境只有一个正常启动标签页 |

旧测试使用独立工作区和本地站点、代理，不使用个人登录环境。历史结果用于回归对照，不自动覆盖新 sidecar。

## 范围与复核

0.1.x/0.2.0 的代理原生证据覆盖本地认证 HTTP 代理，不能据此宣称 HTTPS、SOCKS5 relay 或外部供应商出口已通过。0.2.0 的界面检查只验证 TCP 连通性；0.3.0 替换为实际 HTTPS 出口检测，并为终端增加 SOCKS5 桥。冻结终端的真实 PTY 已覆盖本地认证 SOCKS5 请求及独立副本的路由；外部供应商验证仍单独记录。

0.2.0 打包 UI 验收为只读：未迁移、新增或启停真实用户环境。0.3.0 的终端写操作使用独立测试资料，包内真实终端与列出的原生核心操作已通过；原位会话复用及全部 GUI 未逐项验收。外部代理供应商结果、其他地理服务、全部 MCP 工具、完整指纹、检测网站、字体/WebGL/硬件组合、异常恢复和完整浏览资料备份仍未验收。Alpha 历史单项未验证归档的官方发布摘要。Web 演示配置不作为原生证据，也没有无法检测或自动通过验证码的保证。

基础检查先生成构建文件：

~~~bash
npm test
npm run build
npm run test:sites
npm run test:sidecar -- --install-camoufox
~~~

sidecar 检查需要已准备后端、联网与可显示窗口的桌面环境，使用独立测试工作区；启用 Camoufox 选项后才覆盖两家族。旧 test:smoke 覆盖直接驱动路径，Alpha 单项证据单独记录。更新结果时应注明后端、内核版本、系统以及是否运行打包应用。

GitHub 安装发行版处于草稿，自动发布暂停；本轮新代码未推送，不提供公开正式 0.3.0 版本。0.3.0 验收结果需使用新的冻结源码与原生/包证据更新。
