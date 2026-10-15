<p align="center">
  <img src="build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>多个环境，一个工作台。</strong><br />A local workspace for browsers, terminals and network contexts.</p>
<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="原创代码许可证：MIT" /></a>
  <a href="docs/verification.md"><img src="https://img.shields.io/badge/0.5.3-local_candidate-475569" alt="0.5.3 本地候选版" /></a>
  <a href="docs/readme/en.md"><img src="https://img.shields.io/badge/README-9_languages-6366f1" alt="9 种 README 语言" /></a>
</p>
<p align="center">
  <strong>简体中文</strong> · <a href="docs/readme/zh-TW.md">繁體中文</a> · <a href="docs/readme/en.md">English</a> · <a href="docs/readme/ja.md">日本語</a> · <a href="docs/readme/ko.md">한국어</a> · <a href="docs/readme/es.md">Español</a> · <a href="docs/readme/fr.md">Français</a> · <a href="docs/readme/de.md">Deutsch</a> · <a href="docs/readme/pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="docs/capability-matrix.md">功能与边界</a> · <a href="docs/verification.md">验证记录</a> · <a href="CONTRIBUTING.md">参与贡献</a> · <a href="docs/SUPPORT.md">支持项目</a>
</p>

![Envara 中文原生工作区](docs/media/workspace-zh-CN.png)

<p align="center"><sub>原生 Electron 候选界面，网络为隔离测试夹具中的合成数据；不是实际出口或附加软件分流的证明。<a href="docs/envara-workspace-0.5.png">此前的原生 Electron 截图</a>也使用合成出口数据。</sub></p>

## 境舱能做什么

Envara 将 BrowseForge 的浏览器环境能力带进本地桌面工作台。按「环境 → 网络出口 → 浏览器 → 终端 → 附加软件 → 运行监控」安排工作，常用操作保持简洁，详细配置放在高级设置。

| 工作区 | 能力 |
| --- | --- |
| 环境 | 独立浏览资料、分组与标签；创建、克隆、搜索和配置导入导出 |
| 网络出口 | HTTP、HTTPS、SOCKS5 与内置 AnyTLS；通过认证请求检测实际出口、粗略地域和时区 |
| 浏览器 | CloakBrowser / Chromium、Camoufox / Firefox，以及实验性的 BrowseForge Chromium |
| 终端 | 真实本机 PTY、选择工作目录、调整大小、独立窗口与同环境多会话 |
| 附加软件 | 绑定本地程序和境舱；系统接管仍在验收，未就绪时拒绝受保护启动 |

浏览器和终端共用境舱的网络与时区上下文。每个境舱有独立工具配置和历史；复制终端会创建新的进程，不重放正在执行的命令。内置 AnyTLS 使用应用管理的核心，无需另外配置 Clash。

本地 0.5.7 候选版提供 [Claude Code 专用会话](docs/claude-code-sessions.md)：先打开命令行，由用户运行 `claude` 并自行添加参数；每个境舱维护独立原生安装，首次可选择从本机程序初始化，或通过所选境舱网络下载独立安装（默认），可选择独立登录档案，手动更新后下次调用采用新版。沿用境舱配置与登录信息，通过 MCP / Playwright 操作创建会话时选定的浏览器，并提供[浏览器设备档案与独立语言设置](docs/browser-device-profiles.md)。账号配置检查、官方隐私选项与网络故障处理的取舍见 [参考项目分析](docs/claude-reference-analysis.md)。

## 用自己的语言开始

候选界面支持 **简体中文、繁體中文、English、日本語、한국어、Español、Français、Deutsch、Português (Brasil)**。首次打开提供语言选择，之后可以在设置中修改。

![原生首次启动语言选择](docs/media/first-launch.png)

<p align="center"><sub>英文界面的原生 Electron 首次启动截图；语言选择、确认保存、重启保留与独立终端窗口同步已单独验证。</sub></p>

界面语言与浏览器环境语言分开。切换菜单语言不会修改既有浏览器语言、时区、节点、工作目录或终端输出。

## 安装与当前状态

**0.5.7 为本地开发候选版，当前没有公开正式下载。** 本轮 Claude Code 会话与设备档案功能尚未发布到 GitHub，自动发行保持禁用。历史 Notion 诊断见 [诊断交接](docs/notion-launch-handoff-20261010.md)，该历史记录不代表本轮功能的验收状态。

GitHub 自动编译、打包工作流已移除；上传源码不会触发构建，需要时在本地手动构建。

| 平台 | 当前范围 |
| --- | --- |
| macOS Apple Silicon | 当前优先验证平台；浏览器、AnyTLS、真实终端有分版本原生证据。本地候选包未签名、未公证 |
| Windows | 已有源码与构建候选；浏览器、终端和驱动接管的真实机器验收待完成 |
| macOS Intel / Linux | 有开发或构建路径，尚未完成本项目实机验收 |

**附加软件的完整强制分流在 Mac 和 Windows 上均未就绪。** Mac 当前接入不依赖自有 Network Extension 的 PF／进程分组／独立 utun 后端，使用 Envara 管理的认证节点；系统安装需要本机管理员授权。独立 DNS、故障保护及真实应用分流仍在验收，Notion 尚未以受保护模式运行。Windows 原生接管保留独立验证门槛。进展见 [附加软件方案](docs/application-routing-options.md) 和 [验证记录](docs/verification.md)。

追踪保护使用可审计的域名规则和内核支持的隐私控制，不能消除全部追踪。配置隔离使用同一操作系统用户权限，不是 OS 沙箱；IP 定位仅估算地域，不提供住宅地址，也不保证避免账号封禁。

## 从源码开发

需要 Node.js 24 LTS 或 22.12+、npm、Go 1.25+，以及必要的目标平台编译工具。

```bash
npm ci
npm run desktop
```

该命令准备本地服务、原生终端模块与固定代理核心，再启动桌面开发界面。首次准备需要联网；浏览器内核由用户主动从对应官方渠道安装。准备好的桌面包包含运行依赖，用户无需自行安装 Go 或 Node.js。

```bash
npm test
npm run build
npm run test:sites
```

Web 预览用于界面开发；真实浏览器、PTY 与系统路由需要桌面模式。更多开发与原生验证要求见 [贡献指南](CONTRIBUTING.md)。

## 了解更多与支持

- [功能矩阵与 BrowseForge 固定版本对照](docs/capability-matrix.md)
- [工作区设计](docs/workspace-v05.md) · [架构说明](docs/architecture.md)
- [验证范围和剩余门槛](docs/verification.md)
- [反馈问题](https://github.com/ink-scholar/Envara/issues) · [参与贡献](CONTRIBUTING.md)
- [支持 Envara](docs/SUPPORT.md)：Star、反馈、翻译和代码贡献都很有帮助；自愿打赏渠道尚未启用

## 开源与许可

Envara 原创应用代码采用 [MIT](LICENSE)，纳入的 BrowseForge 保留其 [MIT 许可证](third_party/browseforge/LICENSE) 和 [固定版本记录](third_party/browseforge/ENVARA_UPSTREAM.md)。独立 Mihomo 核心保留 [GPLv3](third_party/proxy-core/LICENSE) 及 [对应源码来源](third_party/proxy-core/SOURCE.md)。浏览器内核适用各自许可，CloakBrowser 编译内核的 [Binary License](https://github.com/CloakHQ/CloakBrowser/blob/main/BINARY-LICENSE.md) 不属于应用 MIT 授权。

完整归属见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
