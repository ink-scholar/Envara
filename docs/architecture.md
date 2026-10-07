# Envara 0.2.0 候选版架构

当前架构面向本机单用户桌面工作区。Electron 管理窗口和本地 BrowseForge Go 服务，React 负责管理界面，浏览器在独立可见窗口运行。源码接入与实际验收分别记录，状态见 [能力矩阵](capability-matrix.md)。

~~~mermaid
flowchart LR
  UI[React 管理界面] --> Bridge[限定 IPC 桥接]
  Bridge --> Main[Electron 主进程]
  Main --> Adapter[桌面服务适配器]
  Main --> Manager[本地服务生命周期]
  Adapter --> Client[带令牌的本机 REST]
  Manager --> Sidecar[BrowseForge Go 服务]
  Client --> Sidecar
  Sidecar --> Driver[配套 Playwright driver]
  Driver --> Firefox[Camoufox Firefox]
  Driver --> Cloak[CloakBrowser Chromium]
  Driver --> Alpha[BrowseForge Chromium Alpha]
  Sidecar --> Profiles[独立环境数据目录]
~~~

## 固定上游与资源

BrowseForge v2.1.15、提交 fa9e0bb670e749706a9c8f2d4095333347d6c521 纳入 third_party/browseforge/，原 MIT 许可保留。本轮添加桌面生命周期、空内核工作区和手动身份优先级等补丁。

Playwright Go 模块固定于 v0.6100.0，配套官方 driver 1.61.1 及 Node.js 24.18.0。backend:prepare 编译 Go sidecar 并准备资源；桌面包用户无需系统 Go、Node.js 或独立命令行服务器。macOS arm64 的 .app、DMG 与 ZIP 已构建，打包代码、原生验收后端、Node 可执行文件、provenance 与许可证资源均已核对；DMG 与 ZIP 完整性、本机启动及基本界面只读验收通过。

## 代码边界

| 位置 | 职责 |
| --- | --- |
| src/ | 环境、详情、表单、分组、代理、监控和设置 |
| electron/main.mjs | 窗口、限定 IPC、文件对话框与服务接线 |
| electron/preload.cjs | contextBridge 调用与状态订阅 |
| electron/sidecar-manager.mjs | 本机端口、令牌、子进程生命周期、内核探测及安装 |
| electron/browseforge-client.mjs | 限制本机地址的 REST 请求、超时与错误脱敏 |
| electron/browseforge-service.mjs | 环境/会话映射、分组策略、迁移及配置导入导出 |
| electron/store.mjs | 本地元数据校验与原子写入 |
| third_party/browseforge/ | 固定 Go 后端与 Envara 桌面补丁 |
| scripts/build-sidecar.mjs、scripts/prepare-playwright-driver.mjs | 后端和官方 driver/Node 资源构建准备 |
| electron/service.mjs、electron/runtime.mjs | 旧直接驱动路径及旧内核缓存兼容 |
| worker/、.openai/ | Sites 构建适配 |

渲染进程没有直接 Node.js 权限，也不能发起任意 sidecar 请求。主进程只路由限定的方法，普通状态快照不包含服务令牌。

## 本机服务与内核

服务仅监听 127.0.0.1，优先复用已保存的端口，端口占用时分配空闲端口。使用私有 bearer token，令牌以 0600 权限保存。REST 客户端拒绝跳转。应用负责服务启动与退出。

上游提供 REST、MCP、Playwright endpoint 和 YAML workflow；本机 MCP 已枚举 43 个工具，并执行验证其中三个。桌面导出连接配置包含本地令牌，应作为凭据文件保存，不进入公开仓库或截图。

没有已安装内核时仍应能进入空工作区。内核由用户主动安装，后台更新关闭；安装重启服务前要求先停止会话。provider 描述、平台支持和本机安装状态分别管理。

## 数据与迁移

Electron `userData` 是数据根目录，新服务使用 `browseforge/`，环境浏览资料位于 `profiles/<id>/browser-data/`。同一环境复用自己的目录，不同环境分开；克隆产生新身份且不复制原浏览资料。

旧根目录的 `workspace.json` 与 `profiles/<旧ID>/` 采用以下迁移方式：

1. 确认旧会话停止，校验配置和代理绑定。
2. 将旧配置和选定环境完整目录复制到 `migration-backups/<记录>/`。
3. 创建新环境，默认从备份复制浏览资料，排除运行时锁文件。
4. 保留指纹、代理关系和本机凭据，记录旧/新 ID 与结果。
5. 保留原文件与备份；失败时尝试移除本轮新建环境，报告未完成的回滚。

本机真实 Chromium Cookie 与 localStorage 复制迁移、备份和原配置字节保持已验证；失败回滚另有服务测试。跨机器或操作系统的 Cookie 加密兼容性不能仅凭文件复制判定成功。

## v2 配置导入导出

配置格式为 schema=envara.profiles、version=2，包含 profiles 和脱敏 proxies。完整结构化指纹与代理引用保留；代理描述包含名称、协议、主机、端口、地域及是否需要凭据，不含用户名和密码。

有代理绑定的环境必须明确映射到本地代理。缺少映射时取消导入，不自动切为直接连接。导入创建新环境 ID，不含 Cookie、登录状态和浏览资料。完整备份/恢复是上游另一种能力，不能与桌面的脱敏配置导出混用。

## 手动身份、代理与观测

Camoufox 使用结构化指纹；两种 Chromium provider 使用各自支持的种子和原生参数。profile.launch_overrides 的 timezone、locale、target_os 优先于 GeoIP/全局默认。未指定或留空时使用自动策略；语言和时区都固定时跳过相关 GeoIP 查询。目标系统使用每个环境自己的运行配置副本，避免跨环境污染。

Camoufox 补丁对齐语言、Intl、时区、Accept-Language 与对应系统字段。macOS CloakBrowser 145 补丁结合原生 accept-language 参数和只用于该进程的 Cocoa 语言参数；并行启动补丁通过了 6 轮、12 个新环境的单测试标签页回归。三 provider 的手动语言、时区、屏幕与平台已有原生验证；Cloak 的 Windows 目标身份也在 Mac 上验证。字体、WebGL 和所有检测器的一致性需另行验证。

代理支持 HTTP、HTTPS、SOCKS5 及分组策略。TCP 检查只证明端口可达，认证、真实请求、SOCKS5 relay 和外部出口须分别验证。VLESS 经外部客户端转换为 HTTP/SOCKS5。

截图由真实浏览器返回。CPU 和内存来自系统进程采样；RSS 合计可能重复计入共享页，当前 Windows 没有该采样。无法取得的数值保持不可用。

## 当前边界

旧版 CloakBrowser 的 macOS 验收保留为历史证据。冻结源码的新服务已通过 12 项两家族原生回归，涵盖隔离、持久化、认证 HTTP 代理、生命周期和迁移；Alpha 为独立单项启动验证，保留实验性标记，不并入完整回归结论。打包应用的启动、三栏布局、新建表单、旧环境迁移预览与取消已只读验收；没有执行真实用户环境的迁移、新增或启停，全部 GUI 操作仍未逐项验收。其他系统、全部 MCP 工具、外部 GeoIP、非 HTTP 代理及完整浏览资料备份未验收。

Web 预览不启动本机浏览器。build 保留 dist/client/index.html、dist/server/index.js 与 dist/.openai/hosting.json 的 Sites 契约。发布暂停，当前不能宣称正式多平台可用。
