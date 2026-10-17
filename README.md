<p align="center">
  <img src="build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>给每一套工作，一个独立的境舱。</strong><br />One environment. Your browser, terminal and apps.</p>
<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="原创代码许可证：MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-0.5.25-475569" alt="Envara 0.5.25" /></a>
  <a href="docs/readme/en.md"><img src="https://img.shields.io/badge/README-9_languages-6366f1" alt="9 种 README 语言" /></a>
</p>
<p align="center">
  <strong>简体中文</strong> · <a href="docs/readme/zh-TW.md">繁體中文</a> · <a href="docs/readme/en.md">English</a> · <a href="docs/readme/ja.md">日本語</a> · <a href="docs/readme/ko.md">한국어</a> · <a href="docs/readme/es.md">Español</a> · <a href="docs/readme/fr.md">Français</a> · <a href="docs/readme/de.md">Deutsch</a> · <a href="docs/readme/pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">下载 macOS 版</a> · <a href="docs/capability-matrix.md">功能与边界</a> · <a href="CONTRIBUTING.md">参与贡献</a> · <a href="docs/SUPPORT.md">支持项目</a>
</p>

**打开浏览器、运行命令、接入桌面应用，让一套工作环境贯穿整个流程。**

境舱是一个开源的本地桌面工作台：把网络出口、浏览器档案、终端工具和支持的桌面应用组织在一起。每个环境保存自己的设置与资料，你可以为不同项目、账号或地区建立不同的工作上下文，在同一个界面里管理。

![Envara 中文原生工作区](docs/media/workspace-zh-CN.png)

<p align="center"><sub>原生 Electron 工作区，截图使用合成示例数据。</sub></p>

## 境舱的特点：把整条工作流连起来

浏览器里查资料，终端里写代码，桌面应用里处理工作——这些动作往往属于同一个项目。境舱让它们复用同一套已确认的网络上下文，并分别保留需要延续的浏览资料、工具配置和应用数据。

**选好一次网络，接上需要的工具，下次回来继续工作。** 这是境舱的核心：让独立环境成为日常工作方式。

### 🌐 每个环境，都有自己的浏览器

在 **CloakBrowser / Chromium、Camoufox / Firefox** 与实验性的 **BrowseForge Chromium** 之间选择。独立浏览资料、持久会话、环境分组、搜索与配置克隆，让多个工作上下文各归其位。克隆配置会创建新环境，原有登录资料留在原环境。

指纹配置默认由所选内核管理，也提供高级设备、语言与时区设置；结合可审计的跟踪拦截规则，让隐私控制有据可查。具体支持范围随内核而异。[浏览器与设备设置](docs/browser-device-profiles.md)

### 🧭 网络、位置和时区，一次设定，贯穿使用

支持 **HTTP、HTTPS、SOCKS5 和 AnyTLS**。AnyTLS 使用随应用提供、由境舱管理的代理核心，无需另外配置 Clash。

创建网络环境时检测**实际认证出口**，再确认地区与时区；浏览器、终端和受支持的附加应用复用这套上下文。需要模拟位置时，可借助 Google Maps 选择坐标，测得出口与模拟位置分别展示。环境设置不会修改宿主系统时区。[网络环境](docs/network-context.md)

### ⌨️ 终端，也有自己的工作环境

新建会话时选择**网络、链接浏览器和项目文件夹**，配置与历史按环境保存。真实 PTY、多会话、拖动高度、展开工作区、独立窗口，让命令行成为工作台里顺手的一部分。

复制终端会在同一上下文中开启一个新的空闲进程；关闭面板后可以回来继续。支持的 macOS 托管回环路由使用网络围栏，不支持代理的程序会连接失败，避免悄悄走直连。项目文件夹仍在原位置，适合继续使用你已有的工具链。

### 🧩 让桌面应用加入同一套工作流

为支持的 **Chromium / Electron 应用**选择环境和链接浏览器，统一管理启动、停止与应用数据。境舱会检查目标身份、兼容性、已有实例及原生路由组件；满足条件后才允许启动。

停止、解绑或退出境舱会保留登录与离线资料，方便下次接着用；需要清理时，再明确选择删除。原生路由需要系统授权，支持引擎不等于所有应用都已完成验收。[附加软件的支持范围](docs/application-routing-options.md)

### 🔗 从命令行到登录页面，上下文接得上

为环境指定链接浏览器，让终端打开的网页进入对应环境；macOS 系统链接路由还可处理受管应用交给系统的链接。与环境无关的链接仍交给原来的默认浏览器。

系统链接路由需你在 macOS 对话框中确认，可随时关闭。主动选择系统浏览器时，界面会说明链接将离开环境。

### 🤖 给 AI 与自动化工具一个有序的工作台

浏览器后台提供 **REST、MCP 和 Playwright** 接口，可用于页面操作、表单、Cookie 与截图等自动化场景；接口支持范围见[功能矩阵](docs/capability-matrix.md)。

Claude Code 是其中一个集成场景：每环境独立安装**原样的官方 CLI**，保存命名登录档案，并通过会话级 MCP broker 绑定所选环境浏览器。先进入 shell，再由你启动 `claude`；模型、恢复会话和权限选项由你决定。[Claude Code 会话](docs/claude-code-sessions.md)

### 📦 需要迁移时，把选中的资料带走

浏览器、终端和附加应用提供各自的**密码加密导出**入口，按需选择资料。终端导出包含选定的 Claude 登录档案及共享 shell 配置、历史；导入会创建新环境，保留已有工作区。

程序本体、缓存、临时文件和 Keychain 不随包带走；部分账号换机后仍需重新登录。

### 🗂️ 日常管理，尽量少一点打断

三栏工作区支持浅色、深色和跟随系统外观，把环境、网络、浏览器、终端、附加软件和运行状态放在清晰的位置。外观设置仅影响境舱，不会更改主机外观。常用操作直接可达，细节配置收进高级选项；九种界面语言，让你用熟悉的语言开始。

## 可以用境舱做什么？

| 场景 | 境舱帮你组织的内容 |
| --- | --- |
| 多项目开发 | 项目目录、终端配置与历史、浏览器资料和指定网络 |
| 多账号工作 | 按环境分开保存浏览资料与应用数据，减少上下文混用 |
| 跨地区网页验证 | 选择网络出口，检查实际出口，再配置浏览器地区、语言与时区 |
| AI 辅助开发与浏览器自动化 | 在选定环境中运行工具，连接浏览器接口；使用专用 Claude 会话 |
| 工作环境备份与迁移 | 按浏览器、终端档案或单个应用导出加密资料，在新环境恢复 |

**本地桌面、一套工作上下文、多种工具入口。** 你负责工作，境舱帮你把环境安排好。

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

## 关于隔离与隐私

境舱重视可控的网络、分开的数据与可审计的隐私机制。下面几条边界，帮助你按实际能力使用它：

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
