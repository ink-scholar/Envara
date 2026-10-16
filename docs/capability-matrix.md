# Envara 0.5.23 能力矩阵

当前发布目标为 **macOS Apple Silicon（arm64）**。下表区分源码能力、桌面入口和验收边界，不表示所有 provider、网站或原生软件都已逐项通过。

## 与固定 BrowseForge 基线的关系

Envara 纳入 BrowseForge **v2.1.15 / `fa9e0bb670e749706a9c8f2d4095333347d6c521`**，记录见 [ENVARA_UPSTREAM](../third_party/browseforge/ENVARA_UPSTREAM.md)。纳入目录还包含 Envara 补丁；上游原始基线可按[固定提交](https://github.com/nczz/BrowseForge/tree/fa9e0bb670e749706a9c8f2d4095333347d6c521)复核，不能把桌面补丁反向归为上游原有能力。

| 能力 | BrowseForge 固定基线 | Envara 当前实现与边界 |
| --- | --- | --- |
| 产品入口 | Web Dashboard、CLI、本地/服务器部署 | Electron 本机工作区；先显示窗口再初始化服务。网页预览不提供原生 PTY 或路由 |
| 浏览器内核 | Camoufox/Firefox、CloakBrowser/Chromium、BrowseForge Chromium Alpha | 保留三个 provider 的选择、探测和安装；不是任意已安装 Chrome/Edge 的管理器 |
| 环境管理 | 创建、编辑、复制、删除、分组、标签、独立资料目录 | 桌面操作、批量管理、预览、旧配置迁移；克隆不复制原浏览资料 |
| 指纹与地区 | provider 各自的结构化配置、种子、语言/时区映射 | 默认交给 provider；保留保存的设置，高级固定设备档案目前仅映射 CloakBrowser |
| 代理与分组 | 认证代理、环境代理及分组默认/强制策略 | HTTP/HTTPS/SOCKS5 与托管 AnyTLS；分组和 provider 的协议/地域限制仍适用 |
| AnyTLS | 无原始节点与内置核心管理流程 | 独立自有核心、节点身份分路由、认证回环入口；保留 SNI/ALPN/TLS 指纹/UDP，不是通用订阅客户端 |
| 网络位置 | 浏览器 GeoIP 与启动时地区调整 | 测量认证出口后确认位置/时区，消费者共用；模拟位置与真实出口分开 |
| 追踪保护 | provider 提供的浏览器机制 | 补丁增加可审计的规则匹配与标准/严格模式；不覆盖所有遥测或服务端关联 |
| REST / MCP / Playwright | 浏览器、页面、标签、表单、Cookie、截图等自动化接口 | 保留本机后台接口；专用终端另用会话级 broker，全部工具未宣称逐项验收 |
| YAML 工作流 | CLI/REST/MCP 的工作流执行 | 固定后端保留；没有等价的桌面可视化工作流编辑器 |
| 备份与数据交换 | 配置 ZIP、Cookie 备份与 CLI 文件系统备份 | 增加密码加密的浏览器/终端/单软件导出；导入新环境，不覆盖已有资料，旧整环境文件兼容 |
| 原生终端 | 无应用内 PTY 产品流程 | 目录选择、独立配置/历史、拖高/放大/独立窗、独立进程复制 |
| Claude Code | 通用浏览器 MCP，无专用安装与登录档案流程 | 官方原样 native CLI、环境内安装、命名档案、手动启动/更新及固定浏览器 broker |
| 附加软件 | 无桌面应用强制路由生命周期 | 身份绑定、引擎识别、独立资料、启动/停止与原生适配器；识别引擎不代表任意应用保护验收 |
| 链接 | 自动化导航接口 | 终端私有 IPC、macOS 系统链接路由；系统默认处理器变更需用户 OS 确认 |
| 多语言 | Dashboard 的英语/繁体中文 | 简中、繁中、英、日、韩、西、法、德、巴西葡语；界面选择与浏览器 locale 独立 |
| 团队/云同步 | 本地档案/分组与服务令牌；团队用途描述不是账号权限实现 | 当前为本机单用户工作区，没有云同步、成员邀请、RBAC 或多租户授权产品流程 |

对应实现来源：

- Provider 与平台：[registry](../third_party/browseforge/internal/runtime/runtime.go)、[support](../third_party/browseforge/internal/runtime/support.go)、[桌面内核生命周期](../electron/sidecar-manager.mjs)。
- 档案、代理与指纹：[profile store](../third_party/browseforge/internal/profile/store.go)、[groups](../third_party/browseforge/internal/groups/store.go)、[Chromium](../third_party/browseforge/internal/browser/launch_chromium.go)、[Firefox](../third_party/browseforge/internal/browser/launch_firefox.go)、[桌面服务](../electron/browseforge-service.mjs)。
- API 与工作流：[REST 路由](../third_party/browseforge/internal/api/router.go)、[MCP schema](../third_party/browseforge/internal/mcp/tool_schema.go)、[workflow engine](../third_party/browseforge/internal/workflow/engine.go)、[backup](../third_party/browseforge/internal/api/backup.go)。
- Envara 扩展：[代理核心](../electron/proxy-core-manager.mjs)、[终端](../electron/terminal-service.mjs)、[浏览器 broker](../electron/terminal-browser-broker.mjs)、[附加软件](../electron/application-service.mjs)、[加密导出](../electron/environment-export.mjs)、[数据恢复](../electron/environment-transfer.mjs)。
- 隐私与语言：[浏览器规则](../third_party/browseforge/internal/browser/trackerlist.go)、[隐私接入](../third_party/browseforge/internal/browser/privacy.go)、[界面语言目录](../shared/interface-languages.mjs)。

## 平台与验收边界

| 范围 | 当前边界 |
| --- | --- |
| macOS arm64 浏览器与数据 | 当前发布目标；受控回环验收覆盖真实浏览器持久 Cookie/HttpOnly、localStorage、IndexedDB、加密独立导出/恢复及原档案保留。不是全部网站或跨 Mac 登录验收 |
| macOS 终端与 Claude | 托管回环路线使用 Seatbelt 围栏；受控夹具可验证 PTY、浏览器绑定和清理。真实认证、token 刷新、模型推理及模型主动调用工具需独立验收 |
| macOS 附加软件 | PF/进程身份/自有 utun 路线及独立 NE 路线；按实际安装、目标身份和运行条件决定准入。任意软件、DNS代发、外部 helper、整个 guard 故障与无关应用仍需对应验收 |
| Windows x64 | 有桌面准备、WinDivert capture 与 helper 源码；未完成实机 GUI/PTY/浏览器/驱动与路由验收，不能当作已支持发布平台 |
| macOS Intel、Linux、Windows ARM64 | provider 或 helper 的构建目标不等于 Envara 原生验收；不在当前发布承诺内 |

GPU、字体、硬件身份、所有 UA/Client Hints 表面和完整网站检测不是一个统一的已通过项目。选择坐标不证明住宅地址；隔离配置或网络不保证避免服务端限制。详见[设备边界](browser-device-profiles.md)、[网络环境](network-context.md)、[附加软件路由](application-routing-options.md)和[Claude 会话](claude-code-sessions.md)。

## 复核与许可

公共文档只保留可维护的功能边界；受控脚本和测试给出复核方式，不把历史计数或某台机器的状态当作产品属性。真实浏览器数据验收入口为[受控迁移脚本](../scripts/verify-scoped-browser-transfer.mjs)，Windows 准备边界见[打包说明](windows-desktop-packaging.md)。

Envara 与 BrowseForge 保留各自 MIT 声明。Mihomo、WinDivert、运行库及浏览器二进制遵循各自许可；CloakBrowser 包装层许可不替代其浏览器二进制条款。参见[第三方声明](../THIRD_PARTY_NOTICES.md)和[代理核心来源](../third_party/proxy-core/SOURCE.md)。
