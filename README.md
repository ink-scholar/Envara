<p align="center">
  <img src="build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>多个环境，一个工作台。</strong><br />A local workspace for browsers, terminals and network contexts.</p>
<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="原创代码许可证：MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-0.5.23-475569" alt="Envara 0.5.23" /></a>
  <a href="docs/readme/en.md"><img src="https://img.shields.io/badge/README-9_languages-6366f1" alt="9 种 README 语言" /></a>
</p>
<p align="center">
  <strong>简体中文</strong> · <a href="docs/readme/zh-TW.md">繁體中文</a> · <a href="docs/readme/en.md">English</a> · <a href="docs/readme/ja.md">日本語</a> · <a href="docs/readme/ko.md">한국어</a> · <a href="docs/readme/es.md">Español</a> · <a href="docs/readme/fr.md">Français</a> · <a href="docs/readme/de.md">Deutsch</a> · <a href="docs/readme/pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">下载 macOS 版</a> · <a href="docs/capability-matrix.md">功能与边界</a> · <a href="CONTRIBUTING.md">参与贡献</a> · <a href="docs/SUPPORT.md">支持项目</a>
</p>

![Envara 中文原生工作区](docs/media/workspace-zh-CN.png)

<p align="center"><sub>原生 Electron 工作区，截图使用合成示例数据。</sub></p>

## 一个环境，一套工作上下文

Envara 把浏览器、网络出口、工作目录和命令行工具放在同一个本地工作台中。每个环境保留自己的浏览资料、工具配置与历史；不同环境可以选择不同网络。

| 工作区 | 能力 |
| --- | --- |
| 环境 | 创建、克隆、分组和搜索，保存工作目录与网络上下文 |
| 网络出口 | HTTP、HTTPS、SOCKS5 和内置 AnyTLS，检测实际出口、粗略地域与时区 |
| 浏览器 | CloakBrowser / Chromium、Camoufox / Firefox、实验性的 BrowseForge Chromium；自动配置与高级设置 |
| 终端 | 真实 PTY、目录选择、多会话、可调整大小的面板与独立窗口 |
| Claude Code | 每环境独立官方 CLI 安装、命名登录档案、绑定环境浏览器的 MCP 工具 |
| 附加软件 | 为支持的 Chromium/Electron 应用绑定环境、管理运行实例与独立应用数据 |
| 数据迁移 | 分别导出浏览器、选定终端登录档案或附加应用资料，使用密码加密 |

内置 AnyTLS 核心由 Envara 管理，无需另行配置 Clash。浏览器、终端与附加软件复用已确认的网络位置与时区。位置设置不会修改系统时区；IP 定位只表示大致地域。

终端复制会创建新的独立进程，不重放命令。Claude Code 会话先进入 shell，由你输入 `claude`；可以下载独立的官方安装，或用已有本机原生程序初始化。Envara 不修改官方 CLI、不复制宿主账号，也不默认开启权限绕过。[了解 Claude Code 会话](docs/claude-code-sessions.md)。

附加软件启动前检查兼容性、现有实例及路由组件状态。不满足条件时明确拒绝启动。停止、移除绑定和退出应用保留登录数据；只有明确删除登录数据或环境时才清除。详见[附加软件](docs/application-routing-options.md)。

## 下载与安装

在 [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest) 下载 **macOS Apple Silicon（arm64）** 的 DMG 或 ZIP。DMG 打开后，将 Envara 拖入“应用程序”。校验文件与版本说明随 Release 提供。

**当前 macOS 制品未使用 Apple Developer ID 签名，也未公证。** 首次打开可能受到 macOS 安全检查；请确认下载来自本仓库并核对校验值。Envara 不会自动关闭系统安全检查。附加软件的系统路由组件需要单独的管理员授权，浏览器与普通工作区启动不会自动安装它。

| 平台 | 发布范围 |
| --- | --- |
| macOS Apple Silicon | 本次提供 DMG、ZIP 和 SHA-256 校验文件 |
| macOS Intel | 保留源码路径，未提供已验证制品 |
| Windows / Linux | 保留相关源码；本次不发布制品，实机验证范围见功能矩阵 |

浏览器内核由用户通过应用内入口安装，适用各自许可证。应用内置桌面运行依赖，无需另行安装 Node.js 或 Go。

## 用自己的语言开始

支持 **简体中文、繁體中文、English、日本語、한국어、Español、Français、Deutsch、Português (Brasil)**。首次启动推荐系统语言并由你确认，之后可在设置中切换。

![首次启动语言选择](docs/media/first-launch.png)

<p align="center"><sub>原生首次启动语言选择界面。</sub></p>

界面语言与浏览器环境语言分开，切换菜单语言不会修改已有网络、时区或工作目录。

## 能力边界

- 配置与数据隔离不是独立操作系统用户、Keychain 或虚拟硬件。浏览器指纹配置不改变原生应用的硬件身份。
- 支持的 macOS 终端路由使用网络围栏；尚未具备该边界的平台和路由不能视为强制隔离。详细范围见[功能矩阵](docs/capability-matrix.md)。
- 附加应用使用外层网络围栏时，Chromium/Electron 的内部沙箱被关闭。原生组件状态、支持引擎及实际验证范围分别说明，不把“可识别”当作“所有软件均已验证”。
- 导出不含 Keychain、程序本体、缓存或临时文件。换机后部分账号仍需重新登录；同机恢复成功不保证跨机器登录有效。
- 跟踪拦截只能覆盖已实现规则及内核支持的控制。网络、账号与配置隔离不保证避免服务限制，也不会消除所有追踪。

[验证说明](docs/verification.md) · [架构](docs/architecture.md) · [网络上下文](docs/network-context.md) · [浏览器设备与语言](docs/browser-device-profiles.md)

## 从源码开发

需要 Node.js 24 LTS（或 22.12+）、npm、Go 1.25，以及目标平台的编译工具。macOS 原生组件需要 Xcode Command Line Tools。

```bash
npm ci
npm run desktop
```

首次准备会下载固定版本的构建依赖。开发预览和检查：

```bash
npm run dev
npm test
npm run build
npm run test:sites
```

Web 预览只用于界面开发；真实浏览器、PTY 和系统路由需要桌面应用。构建与发布说明见[贡献指南](CONTRIBUTING.md)和[发布流程](docs/releasing.md)。GitHub 自动编译和发布工作流保持禁用，源码推送不会触发构建。

## 开源与支持

Envara 原创代码使用 [MIT](LICENSE)。BrowseForge 保留其 [MIT 许可证](third_party/browseforge/LICENSE)及[固定版本记录](third_party/browseforge/ENVARA_UPSTREAM.md)。独立 Mihomo 核心保留 [GPLv3](third_party/proxy-core/LICENSE)和[对应源码](third_party/proxy-core/SOURCE.md)。浏览器二进制适用各自许可，不包含在应用的 MIT 授权内。完整归属见[第三方声明](THIRD_PARTY_NOTICES.md)。

欢迎 [反馈问题](https://github.com/ink-scholar/Envara/issues)、提交代码、改进翻译或 Star。支持均为自愿；捐赠渠道尚未启用。[支持项目](docs/SUPPORT.md)
