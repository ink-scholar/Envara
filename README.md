<p align="center">
  <img src="build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>给每一套工作，一个独立的境舱。</strong><br />One environment. Your browser, terminal and apps.</p>
<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="原创代码许可证：MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-1.1.0-475569" alt="Envara 1.1.0" /></a>
</p>
<p align="center">
  <strong>简体中文</strong> · <a href="docs/readme/zh-TW.md">繁體中文</a> · <a href="docs/readme/en.md">English</a> · <a href="docs/readme/ja.md">日本語</a> · <a href="docs/readme/ko.md">한국어</a> · <a href="docs/readme/es.md">Español</a> · <a href="docs/readme/fr.md">Français</a> · <a href="docs/readme/de.md">Deutsch</a> · <a href="docs/readme/pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">下载 macOS 版</a> · <a href="docs/user-guide.md">使用指南</a> · <a href="docs/capability-matrix.md">全部功能</a> · <a href="docs/SUPPORT.md">支持项目</a>
</p>

**不止是 Claude Code 的隐私隔离工具，更是浏览器、终端和桌面应用的一站式独立工作区。**

Envara 境舱是开源的本地桌面工作台。为不同项目、账号或地区保存各自的网络、浏览资料和工具配置；选好环境，从查资料、写代码到打开应用，接着上次的工作继续。

![Envara 工作区，使用合成示例数据](docs/media/workspace-zh-CN.png)

## 1.1.0：更顺手的工作台

- **精简界面与可折叠导航**：收起左侧导航，为浏览器、终端和应用内容留出更多空间，常用操作保持集中。
- **保存常用终端**：普通终端和 Claude 终端都有可命名的持久入口；选择运行中的会话，或按已保存上下文重新打开空闲 shell，不重放命令。
- **找回自定义 MCP 与插件**：官方 Claude CLI 可读取境舱内用户、项目与本地配置，同时保留 Envara 的固定浏览器工具与会话网络约束。
- **按目标选择 SSH 路线**：macOS 已保存主机使用本机出口，未保存目标使用境舱代理；认证或连接失败不切换路线。

## Claude Code「防封」与环境隔离

把**选定网络路线、独立账号目录、持久浏览器身份和受支持的设备读取限制**放进同一套会话流程，减少网络与账号配置混用。每个环境独立安装**原样的官方 CLI**，登录档案分别保存；模型、恢复会话与权限由你决定。

隔离有助于减少配置混用，不承诺账号免封或完整匿名。具体方法与适用范围见 [Claude Code 指南](docs/claude-code-sessions.md)。

## 一张工作台，覆盖日常流程

| 功能 | 你可以做什么 |
| --- | --- |
| 🌐 网络环境 | HTTP / HTTPS / SOCKS5 / AnyTLS；检测认证出口，确认地区与时区，AnyTLS 无需外装 Clash |
| 🧭 独立浏览器 | CloakBrowser、Camoufox 与实验性 BrowseForge Chromium；分开保存资料，重开沿用身份 |
| 🤖 Claude Code | 环境内安装与更新、命名登录档案、绑定环境浏览器，账号资料按档案保存 |
| ⌨️ 原生终端 | 选择项目目录，多会话、可伸缩面板与独立窗口，配置和历史按环境保留；macOS [SSH 连接](docs/claude-code-sessions.md#ssh-through-the-environment-route)按保存目标选路线：保存主机走本机出口，未保存地址走境舱代理 |
| 🧩 附加应用 | 为受支持的 Chromium / Electron 软件绑定环境，管理独立资料与启动、停止 |
| 🔗 链接与自动化 | 链接交给指定浏览器，提供 REST / MCP / Playwright 浏览器接口 |
| 📦 加密迁移 | 分别导出浏览器、所选终端档案或单个应用；密码加密，导入新环境 |
| 🗂️ 工作区管理 | 环境分组、搜索、复制与运行状态；三栏布局与可折叠左侧导航、九种语言、浅色 / 深色 / 跟随系统 |

**终端里的 SSH 按保存目标选择路线。** macOS 普通会话、Claude 会话和复制会话均支持：保存主机走本机网络出口，服从已有 VPN / TUN，服务器可见该出口 IP；未保存的主机与端口可用 `ssh user@host` 经境舱代理连接。已保存目标未解锁、未载入或用户名冲突时拒绝连接，不改走代理。用 `envara-ssh list` 查看本会话已载入的授权；密码和私钥授权在本次 Envara 运行期间不定时到期，密码仅在应用内存保留至退出，私钥保留本机。

1.1.0 的新建终端使用双路线，现有终端保留创建时的上下文。支持的参数仍限于端口、用户、TTY 和日志选项，未集成 `scp` / `sftp`、`-i`、跳板或端口转发。主机信任、可达性与认证要求见 [SSH 指南](docs/claude-code-sessions.md#ssh-through-the-environment-route)。

附加应用的系统授权、沙箱取舍与支持范围见[功能与边界](docs/capability-matrix.md)。停止或解绑会保留登录资料。

## 开始使用

从 [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest) 下载 **macOS Apple Silicon（arm64）** 的 DMG 或 ZIP 安装包，附 SHA-256 校验文件。当前制品未使用 Apple Developer ID 签名，也未公证；安装步骤见指南。其他平台暂不提供已验证制品。

**第一次使用，建议从一个项目开始。** 先添加并检测网络出口，再创建环境、选择浏览器；需要终端时选好工作目录，需要桌面软件时绑定受支持的应用。以后回到同一环境，可以沿用已保存的浏览资料、终端配置和应用数据，减少切换工具时的重复配置。

[使用指南](docs/user-guide.md) · [全部功能](docs/capability-matrix.md) · [验证范围](docs/verification.md) · [从源码开发与贡献](CONTRIBUTING.md) · [反馈问题](https://github.com/ink-scholar/Envara/issues)

## 支持境舱

开发中投入了大量 AI 调用成本。如果 Envara 对你有帮助，欢迎自愿支持；Star、反馈、翻译和代码贡献同样重要。

**所有功能均不以打赏为前提。** 转出时请确认币种与网络均和下表一致。

### USDT

| 网络 | 收款地址 |
| --- | --- |
| <img src="docs/assets/chains/tron.png" width="24" height="24" alt="TRON" /> TRON（TRC20） | `TFnUooSKx1Joe6i8vkbsiQpiMVqiNq5c1r` |
| <img src="docs/assets/chains/ethereum.png" width="24" height="24" alt="Ethereum" /> Ethereum（ERC20） | `0x71dead57a9d0047349329fecb914f2b2a069a869` |
| <img src="docs/assets/chains/solana.png" width="24" height="24" alt="Solana" /> Solana（SOL） | `6ACRnyNUHDuf7HeovVgxqBS8jgLsWrvbNTMuQnZdwr1V` |
| <img src="docs/assets/chains/arbitrum.png" width="24" height="24" alt="Arbitrum" /> Arbitrum | `0x71dead57a9d0047349329fecb914f2b2a069a869` |
| <img src="docs/assets/chains/plasma.png" width="24" height="24" alt="Plasma" /> Plasma | `0x71dead57a9d0047349329fecb914f2b2a069a869` |

### USDC

| 网络 | 收款地址 |
| --- | --- |
| <img src="docs/assets/chains/ethereum.png" width="24" height="24" alt="Ethereum" /> Ethereum（ERC20） | `0x71dead57a9d0047349329fecb914f2b2a069a869` |
| <img src="docs/assets/chains/solana.png" width="24" height="24" alt="Solana" /> Solana（SOL） | `6ACRnyNUHDuf7HeovVgxqBS8jgLsWrvbNTMuQnZdwr1V` |
| <img src="docs/assets/chains/arbitrum.png" width="24" height="24" alt="Arbitrum" /> Arbitrum | `0x71dead57a9d0047349329fecb914f2b2a069a869` |

### 币安

币安 ID：`820140284`

[支持说明与图标来源](docs/SUPPORT.md)

---

原创代码采用 [MIT](LICENSE)；BrowseForge、Mihomo 与其他依赖保留各自许可及对应源码义务，见[第三方声明](THIRD_PARTY_NOTICES.md)。
