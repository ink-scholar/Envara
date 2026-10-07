# 验证记录

记录日期：2026-10-07。当前开发 0.2.0 多内核本地候选版，发布暂停。结果按运行路径区分；详细状态见 [能力矩阵](capability-matrix.md)。

## 0.2.0 候选版：新本地服务

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

本机冻结源码记录为 `test-artifacts/sidecar-smoke/run-Wed9Ik/proof.json`（更新后的 `latest-proof.json`），并行专项为 `test-artifacts/sidecar-smoke/parallel-fixed-S4ov8I/proof.json`；Alpha 独立记录为 `test-artifacts/alpha-smoke/run-jcUD6L/proof.json`。这些隔离产物不提交至公开仓库，也不是安装包签名或浏览器归档摘要验证。

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

新旧路径的代理原生证据覆盖本地认证 HTTP 代理。HTTPS、SOCKS5 relay 和外部供应商出口尚未因此通过验收；界面检查只验证 TCP 连通性。

打包 UI 验收为只读：未迁移、新增或启停真实用户环境。功能写流程的证据来自后端与独立测试资料，全部 GUI 按钮及完整桌面交互未逐项验收。外部自动 GeoIP、全部 MCP 工具、完整指纹、检测网站、字体/WebGL/硬件组合、异常恢复和完整浏览资料备份仍未验收。Alpha 本轮未验证归档的官方发布摘要。Web 演示配置不作为原生证据，也没有无法检测或自动通过验证码的保证。

基础检查先生成构建文件：

~~~bash
npm test
npm run build
npm run test:sites
~~~

旧 test:smoke 覆盖直接驱动路径；本轮新的两家族原生验收使用：

~~~bash
npm run backend:prepare
npm run test:sidecar -- --install-camoufox
~~~

该命令需要联网和可显示窗口的桌面环境，使用独立测试工作区。Alpha 单项证据单独记录。更新结果时应注明后端、内核版本、系统以及是否运行打包应用。

GitHub 两个 0.1.x 发行版处于草稿，自动发布暂停。新路径与平台包未验收前，不对外提供 0.2.0 可用性声明。
