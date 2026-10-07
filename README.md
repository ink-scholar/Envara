<p align="center"><img src="build/icon.png" width="96" alt="Envara icon" /></p>

# Envara · 境舱

一个中文优先的浏览器环境桌面管理器。用独立的持久化环境管理浏览器资料、指纹配置和代理，在桌面应用内完成环境管理与会话操作。

**Envara is an open-source desktop workspace for isolated browser environments.** The current 0.2.0 development candidate integrates a locally managed BrowseForge backend and a multi-engine catalog.

[项目源码](https://github.com/ink-scholar/Envara) · [问题反馈](https://github.com/ink-scholar/Envara/issues) · [能力矩阵](docs/capability-matrix.md) · [架构说明](docs/architecture.md) · [验证记录](docs/verification.md) · [参与贡献](CONTRIBUTING.md)

![Envara 三栏界面预览](docs/envara-preview.png)

上图为当前界面的 Web 预览，带有「界面预览」标识并使用演示配置。真实浏览器与打包桌面的验收分别记录。

## 当前状态

**0.2.0 本地开发候选版，尚未发布。** 源码仓库已公开；0.1.x 的两个 GitHub 发行版保留为草稿，自动发布已暂停。当前优先完善实际功能、布局和多内核支持。

新的本地后端固定于 BrowseForge v2.1.15（提交 fa9e0bb670e749706a9c8f2d4095333347d6c521），源码纳入 third_party/browseforge/。Envara 管理服务启动、私有本机连接和退出；桌面包包含编译后的 Go sidecar 和官方 Playwright driver/Node，用户无需另行安装 Go 或 Node.js。macOS arm64 的 .app、DMG 与 ZIP 已构建，打包一致性、归档完整性、本机启动、基本界面与迁移预览/取消已通过验收。

| 内核 | 当前证据 |
| --- | --- |
| CloakBrowser / Chromium | macOS arm64 新服务原生回归通过：手动身份、多环境隔离、Cookie/localStorage 持久化和认证 HTTP 代理 |
| Camoufox / Firefox | macOS arm64 官方安装及可见会话通过，可与 Chromium 同时运行；手动身份、跨内核隔离和 localStorage 重启保留通过 |
| BrowseForge Chromium | macOS arm64 Alpha 0.1.6 单项安装、可见会话、手动身份、截图与停止通过；仍为实验性内核 |

macOS Apple Silicon 是当前本地验证平台。冻结源码的原生回归 12 项通过，并通过 6 轮、12 个新 Cloak 环境的并行启动检查，每个仅打开一个测试标签页。新服务已通过重启、代理映射、脱敏导出和旧 Cookie/localStorage 复制迁移，备份与原配置不变均有实际证据。JavaScript 测试 65/65、Go 全包和 browser/API/MCP race 检查通过。桌面 UI 只读验收覆盖布局、表单与迁移预览/取消；真实用户资料的迁移、新增和启停未执行，全部 GUI 按钮也未逐项验收。macOS Intel、Windows 与 Linux 尚未实机验收。范围见 [能力矩阵](docs/capability-matrix.md)。

## 本轮接入范围

- 环境创建、编辑、克隆、删除，分组、标签、搜索和批量操作。
- 独立持久化浏览器目录，会话启动、停止、聚焦和真实截图。
- 按内核能力配置种子或结构化指纹，手动指定系统画像、语言、时区和屏幕尺寸。
- HTTP、HTTPS、SOCKS5 代理，以及分组代理策略。
- 配置导入导出、旧工作区备份与复制迁移。
- 上游的本机 REST、MCP、Playwright 连接与工作流能力；桌面入口和完整联动仍在验证。

原生后端的已通过项目见上表；分组、批量操作及其他桌面联动仍按 [验证记录](docs/verification.md) 分项验收。当前不能宣称已实现 BrowseForge 的完整功能对等。

代理检查只确认 TCP 端口可达。内置 VLESS 客户端、多人协作和云同步尚未实现；VLESS 等协议可由外部客户端提供 HTTP/SOCKS5 端口。指纹效果取决于内核、系统、字体、硬件和目标网站，Envara 不承诺通过所有检测站点。

## 本地开发

需要 Node.js **24 LTS** 或 **22.12+**、npm 和 Go **1.25+**。Go 仅用于从源码构建 sidecar；桌面运行使用准备好的 sidecar 和官方 Playwright driver 1.61.1 / Node。

~~~bash
npm ci
npm run desktop
~~~

desktop 会先运行 backend:prepare，编译固定版本 Go 后端并准备配套 driver，再打开桌面开发界面。首次准备所需资源需要联网；浏览器内核另由用户主动安装。

构建后运行桌面应用：

~~~bash
npm run backend:prepare
npm run build
npm start
~~~

开发者可用 npm run dev 查看 Web 界面，Web 预览不能启动本机浏览器。基础检查：

~~~bash
npm test
npm run build
npm run test:sites
~~~

test:sites 检查生成的文件，所以先运行 build。旧 test:smoke 覆盖直接驱动 CloakBrowser 的路径；test:sidecar 是新服务原生验收入口，其结果见验证记录。候选安装包构建命令仍需最终闭环验收，当前没有正式 0.2.0 下载版。

## 旧工作区与配置导出

0.1.x 的 `workspace.json` 和 `profiles/<ID>/` 按**先备份、再复制**的方式迁移。源配置和浏览资料保持原样；默认复制选定环境的完整浏览资料，并记录旧 ID 到新 ID 的对应关系。迁移前需要停止旧会话；代理绑定和凭据在本机迁移中保留。本机原生测试已验证真实 Cookie/localStorage 复制、备份及原配置字节不变；其他机器、系统或个人环境仍需分别确认。

v2 配置导出包含指纹配置和脱敏后的代理描述与引用，不包含代理用户名、密码、Cookie 或浏览资料。导入有代理绑定的环境时必须明确映射到现有本地代理；缺少映射会取消导入，不会自动变成直接连接。配置导出不是浏览器备份。

运行资料保存在 Electron userData 下，新后端使用 browseforge/，迁移备份放在 migration-backups/。不要将用户目录、凭据或浏览资料提交到 Git。

## 技术与许可

Electron + React + Vite + Phosphor Icons，配合由应用管理的 BrowseForge Go 本地服务和 Playwright driver。浏览器二进制由用户主动从对应官方渠道安装，不随应用重新分发。

Envara 源码采用 [MIT](LICENSE)。纳入的 BrowseForge 源码采用 MIT，保留 [原始许可证](third_party/browseforge/LICENSE) 和 [固定版本记录](third_party/browseforge/ENVARA_UPSTREAM.md)。CloakBrowser 编译内核适用独立 [Binary License](https://github.com/CloakHQ/CloakBrowser/blob/main/BINARY-LICENSE.md)，最新版本访问可能需要上游订阅，不属于 Envara 的 MIT 授权。归属见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
