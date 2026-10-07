<p align="center">
  <img src="build/icon.png" width="96" alt="Envara icon" />
</p>

# Envara · 境舱

一个中文优先的浏览器环境桌面管理器。用独立的持久化环境管理浏览器数据、指纹配置和代理，从创建到打开会话都在应用内完成。

**Envara is an open-source desktop manager for isolated, persistent browser environments.** It brings profile, fingerprint configuration, and proxy management into a simple native desktop workspace.

[下载发布版本](https://github.com/ink-scholar/Envara/releases) · [问题反馈](https://github.com/ink-scholar/Envara/issues) · [架构说明](docs/architecture.md) · [验证记录](docs/verification.md) · [参与贡献](CONTRIBUTING.md)

![Envara 三栏界面预览](docs/envara-preview.png)

上图为明确标记的界面预览，使用演示配置；桌面应用首次运行为空工作区。

## 当前版本

**0.1.1 Alpha**。界面采用左侧导航、中央环境列表、右侧详情的三栏布局，提供真实的桌面浏览器启动流程。第一次打开为空工作区。

| 平台 | 构建目标 | 验证状态 |
| --- | --- | --- |
| macOS Apple Silicon | `.dmg`、`.zip` | 已验证原生会话、安装包启动与内核安装 |
| Windows x64 | `.exe` 安装包 | 已配置 CI 构建，未实机验证 |
| Linux x64 | `.AppImage`、`.deb` | 已配置 CI 构建，未实机验证 |

## 首版功能

- 创建、编辑、分组、搜索、克隆和删除浏览器环境。
- 每个环境使用独立的持久化数据目录；Cookie、网站存储和登录状态在关闭后保留。
- 配置指纹种子、系统画像、语言、时区和分辨率；使用代理时限制 WebRTC 的非代理 UDP 连接。
- 启动、停止和重新打开真实的浏览器会话；查看会话状态与可用的本地资源信息。
- 管理 HTTP、HTTPS、SOCKS5 代理；检查代理主机端口是否能建立 TCP 连接。
- 导入和导出环境配置；导出不包含代理记录、Cookie、登录数据或内核许可密钥，导入后需重新选择代理。
- 在设置中查看和安装独立浏览器内核。

指纹配置的实际效果取决于内核版本、操作系统和访问的网站。Envara 不承诺“无法检测”、通过所有检测站点或完整模拟任意设备。TCP 可用性检查也不代表代理认证、出口 IP 或目标网站访问成功。

首版不含团队权限、云同步、托管浏览器或内置 VLESS 客户端。VLESS 等协议需先由外部客户端提供本地 HTTP/SOCKS5 端口，再添加到 Envara。

## 安装与第一次使用

1. 从 [Releases](https://github.com/ink-scholar/Envara/releases) 下载对应平台的安装包。
2. macOS 打开 DMG，将 Envara 拖入「应用程序」。当前 Alpha 未经过 Apple 公证；如系统阻止打开，可在 Finder 中右键应用并选择「打开」，或在「系统设置 → 隐私与安全性」中按系统提示允许这一次打开。
3. 打开 Envara，在「设置」中阅读内核许可说明，并主动安装浏览器内核。下载由官方 CloakHQ 渠道提供，需联网。
4. 创建环境，选择语言、时区、窗口尺寸和代理，然后打开会话。

浏览器内核不包含在 Envara 安装包中。首版采用 CloakBrowser 的官方免密钥基线；最新内核版本的获取可能需要上游许可或订阅，首版尚未集成 Pro 密钥管理。以 [CloakBrowser 当前条款](https://github.com/CloakHQ/CloakBrowser/blob/main/BINARY-LICENSE.md) 为准。

## 本地开发

需要 Node.js **24 LTS** 或 **22.12+**，以及 npm。开发浏览器会话仍需在桌面应用设置中安装独立内核。

```bash
npm ci
npm run desktop
```

构建后运行桌面应用：

```bash
npm run build
npm start
```

开发者可以运行 `npm run dev` 查看 Web 界面。Web 预览不启动本机浏览器；实际会话功能在 Electron 应用内使用。

```bash
npm test
npm run build
npm run test:sites
npm run dist:mac    # Apple Silicon
npm run dist:win    # Windows x64
npm run dist:linux  # Linux x64
```

`test:sites` 会检查生成的构建文件，因此应先运行 `npm run build`。建议在目标操作系统上打包。发布流水线会分别使用 macOS、Windows 和 Linux runner。

## 本地数据

环境配置与浏览器数据存放于 Electron 的 `userData` 目录。macOS 默认路径是 `~/Library/Application Support/Envara/`：`workspace.json` 保存配置，`profiles/<环境 ID>/` 保存各环境的浏览数据，`engines/` 缓存独立内核。不要将该目录提交到 Git，也不要将配置导出视为完整浏览器备份。

克隆只复制环境配置，并创建新的指纹种子与空白浏览器数据目录。清空浏览数据或删除环境需要在界面确认；运行中的环境应先停止。

## 技术与许可

Electron + React + Vite + Phosphor Icons，使用 CloakBrowser / Playwright 驱动独立持久化浏览器上下文。

Envara 自有源码采用 [MIT License](LICENSE)。CloakBrowser 的 JavaScript 包装层采用 MIT；其编译后的 Chromium 内核适用独立的 [Binary License](https://github.com/CloakHQ/CloakBrowser/blob/main/BINARY-LICENSE.md)，并非 Envara 的 MIT 许可内容。Envara 不重新分发该内核。依赖归属和许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

产品方向参考了 [BrowseForge](https://github.com/nczz/BrowseForge) 的浏览器环境管理理念；Envara 采用独立的桌面界面和本地实现。应用图标由 OpenAI 内置图像生成工具生成。
