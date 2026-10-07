# Envara 境舱能力与验收矩阵

记录日期：2026-10-07。本轮将 BrowseForge 固定版本源码纳入 `third_party/browseforge/`，由 Envara 桌面应用自动管理本地服务。macOS Apple Silicon 冻结源码的两家族原生回归 12 项通过，另有 6 轮、12 个新 Cloak 环境的并行单标签页回归；Alpha 仅为独立单项启动验证。macOS arm64 .app、DMG、ZIP 已构建，打包一致性、归档完整性、启动和基本 UI 只读验收通过；全部 GUI 操作未逐项验收。

状态含义：**源码已接入**表示实现或适配代码已纳入仓库；**Mac 后端已验证**表示 macOS Apple Silicon 上的新服务与真实浏览器有执行证据；**待验证**表示当前路径还需测试；**计划中**表示尚未形成可验收的产品能力。后端测试不代表 Electron 界面已验收，旧版直接运行 CloakBrowser 的验证也不自动转移到新后端。

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
| 代理检查 | 源码已接入 | 桌面检查只证明 TCP 端口可达；代理认证、实际请求及出口地域需要独立证据 |
| 分组、标签与分组代理策略 | 源码及适配测试已接入；原生待验证 | 原生测试保存了分组；默认/强制代理继承、运行中修改和完整标签流程仍需验证 |
| 配置导入导出、备份与恢复 | 配置交换 Mac 后端已验证；完整备份待验证 | v2 配置导出脱敏代理凭据，导入必须显式映射代理且保留绑定。配置导出不含完整浏览数据，不等于 Cookie/浏览器目录备份 |
| 旧工作区迁移 | Mac 后端已验证 | 自愿迁移复制真实浏览器目录与本地代理凭据；迁移后 Cookie/localStorage 可读取，备份摘要正确，原配置摘要不变且源目录保留 |
| CPU、内存与资料大小 | 源码及适配测试已接入；显示待验证 | 已接系统采样并校验运行状态和未知数值规则；实际统计准确性与桌面展示还需独立验收 |
| REST、MCP、Playwright 连接、YAML 工作流 | 部分 Mac 后端已验证 | 受保护 REST 和 MCP 初始化通过，工具目录为 43 项；evaluate、get_content、list_tabs 实际操作浏览器。Playwright 外部连接、YAML 工作流及其余全部工具未逐项验收 |
| WebRTC、字体、硬件、Canvas/WebGL 等完整指纹 | 上游源码具备；检测待验证 | 手动可见字段测试未覆盖这些表面的完整一致性、UA-CH 与物理内核版本一致性，亦未证明通过全部第三方检测器 |
| 多用户与权限管理 | 计划中 | 当前面向本机工作区；尚无已验收的多人协作与权限流程 |

## 内核范围

| Provider | 上游固定基线 | Envara 新路径的实际状态 |
| --- | --- | --- |
| `cloakbrowser` | macOS `145.0.7632.109.2`；Linux/Windows `146.0.7680.177.4` | macOS Apple Silicon 的双环境手动参数、截图、HTTP 认证代理、隔离、重启与迁移已验证；其他平台未实测 |
| `camoufox` | `v135.0.1-beta.24` | macOS Apple Silicon 官方安装、与 Chromium 同时运行、手动语言/Intl/时区/屏幕、跨内核隔离与 localStorage 持久化已验证；Intl 的 zh-Hans-CN 与请求 zh-CN 语义一致 |
| `browseforge-chromium` | `v0.1.6-alpha.0` | macOS Apple Silicon 官方单 provider 安装、可执行探测、实际 Chromium `150.0.7871.101`、手动参数、截图和停止已验证；仍为实验性未签名 Alpha |

BrowseForge Chromium 上游有 macOS、Linux 与 Windows 的 Alpha 产物，但其 macOS Intel 产物明确仅打包，未完成启动与检测验证；上游仍声明 `release_grade_ready=false`。这些产物和能力声明不能替代 Envara 的平台验收。[固定版本 runtime README](https://github.com/nczz/browseforge-runtime-chromium/blob/92cfe89356ef0e7fb22979f5ee8d95a0a832d69b/README.md#L43)、[发布验收状态](https://github.com/nczz/browseforge-runtime-chromium/blob/92cfe89356ef0e7fb22979f5ee8d95a0a832d69b/knowledge/manifests/release-status.json)。

## 平台与许可

- **macOS Apple Silicon：**新服务真实浏览器验收通过，范围见上表；.app、DMG、ZIP 已构建，打包代码与验收后端相同，Node、provenance、许可证完整，DMG/ZIP 完整性通过。启动与基本 UI 只读验收完成，迁移预览取消保留空列表和内核目录；真实用户写操作及全部 GUI 操作未逐项验收。旧版与当前证据见 [验证记录](verification.md)。
- **macOS Intel、Windows、Linux：**本轮 Envara 新服务与安装包均未完成实机验收。上游的平台矩阵与 CI 构建目标分别说明源码/产物范围，不能作为 Envara 已可用的证明。
- **源码许可：**Envara 与纳入的 BrowseForge 代码采用 MIT，保留上游归属和许可证。[固定版本 BrowseForge License](https://github.com/nczz/BrowseForge/blob/fa9e0bb670e749706a9c8f2d4095333347d6c521/LICENSE)。
- **CloakBrowser：**包装层为 MIT，编译浏览器适用独立专有许可。Envara 不把该内核打入安装包；用户须从官方渠道获取，版本与订阅条件以其条款为准。[包装层 License](https://github.com/CloakHQ/CloakBrowser/blob/5fa65172f0612b3ea3efbee719be0cb618594285/LICENSE)、[Binary License](https://github.com/CloakHQ/CloakBrowser/blob/5fa65172f0612b3ea3efbee719be0cb618594285/BINARY-LICENSE.md)。

上游对照基线为 BrowseForge `fa9e0bb670e749706a9c8f2d4095333347d6c521`（v2.1.15）：[provider registry](https://github.com/nczz/BrowseForge/blob/fa9e0bb670e749706a9c8f2d4095333347d6c521/internal/runtime/runtime.go)、[平台与版本定义](https://github.com/nczz/BrowseForge/blob/fa9e0bb670e749706a9c8f2d4095333347d6c521/internal/runtime/support.go)、[Chromium 启动逻辑](https://github.com/nczz/BrowseForge/blob/fa9e0bb670e749706a9c8f2d4095333347d6c521/internal/browser/launch_chromium.go)。后续只有补丁后的实际验证通过，才更新对应状态。

当前验证计数为 npm test **65/65**、资源准备辅助测试 **7 项**；Go 全包及 browser/API/MCP race 检查通过。本机冻结源码原生记录为 `test-artifacts/sidecar-smoke/run-Wed9Ik/proof.json`（更新后的 `latest-proof.json`），并行专项为 `test-artifacts/sidecar-smoke/parallel-fixed-S4ov8I/proof.json`；Alpha 独立记录为 `test-artifacts/alpha-smoke/run-jcUD6L/proof.json`，仍为实验性，且未验证其归档的官方发布摘要。

当前服务 SHA-256 为 `915faddfe43506aa2cc4887e2b1b7e386d1399a1e1847c08ecfb085cb52d8acd`，源码树 SHA-256 为 `ddde9f2114ccef3e7f7a2c4cea1fb583e0b4f617483cc6bdb05c0fed073ccdc3`，对应最终资源构建记录。隔离测试产物不提交至公开仓库，不构成浏览器包签名或发布完整性认证。构建资源包含匹配的 Node/Playwright 驱动和许可证，桌面用户无需系统 Go 或 Node。

发布继续暂停，新代码尚未推送，当前没有公开的 0.2.0 正式下载版。其他系统、全部 MCP、完整指纹、外部自动 GeoIP、非 HTTP 代理及完整浏览资料备份保持未验收。
