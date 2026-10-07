# Envara 0.3.0 候选版架构

当前架构面向本机单用户桌面工作区。Electron 管理窗口、本地 BrowseForge Go 服务与真实 PTY；React 管理三栏界面、可调高度底部 xterm 与独立终端视图。浏览器与终端从同一环境解析网络与时区，终端使用用户选择的本地工作目录。会话与视图独立：一个境舱可有多个 PTY，一个会话可在底部或独立窗口查看。实现与验收分开记录，状态见 [能力矩阵](capability-matrix.md)。

~~~mermaid
flowchart LR
  UI[React 管理界面] --> Bridge[限定 IPC 桥接]
  Bridge --> Main[Electron 主进程]
  Main --> Adapter[桌面服务适配器]
  Main --> Manager[本地服务生命周期]
  Adapter --> Client[带令牌的本机 REST]
  Adapter --> Network[认证代理 HTTPS 出口检测]
  Adapter --> Context[环境网络与时区解析]
  Context --> Terminal[每环境 node-pty]
  UI --> Xterm[可折叠 xterm 面板]
  Xterm --> Bridge
  Terminal --> CWD[用户选择的工作目录]
  Terminal --> Config[独立 HOME XDG Claude 历史]
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

Playwright Go 模块固定于 v0.6100.0，配套官方 driver 1.61.1 及 Node.js 24.18.0。backend:prepare 编译 Go sidecar 并准备资源；native:prepare 在 Electron 44.6.0 上实际验证 node-pty，失败才从源码重建该模块。完整 node-pty 目录在 app.asar 外展开。桌面用户无需系统 Go 或 Node.js；当前 0.3.0 包内真实 PTY、资源匹配、DMG/ZIP 完整性与桌面终端核心操作已验证，范围见验证记录；0.2.0 包结果保留为历史基线。

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
| electron/proxy-network.mjs | 固定 HTTPS 地理服务、认证代理请求、公网 IP/IANA 时区校验和缓存 |
| electron/terminal-controller.mjs | 原生目录选择与终端 IPC，阻止活跃终端的冲突配置修改 |
| electron/terminal-service.mjs、terminal-process.mjs | 真实 PTY、独立配置目录、输入输出和所属进程退出清理 |
| electron/terminal-proxy-bridge.mjs | SOCKS5 到本机随机认证 HTTP 代理桥 |
| electron/terminal-view.mjs | 独立窗口的环境/会话归属与脱敏视图快照 |
| src/TerminalPane.jsx、TerminalWindowApp.jsx | 底部面板、拖动/键盘尺寸、放大恢复、多会话与独立窗口视图 |
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

代理支持 HTTP、HTTPS、SOCKS5 及分组策略；分组代理受上游协议范围限制。0.3.0 的检查通过认证代理访问主进程固定允许的 ipwho.is 或 ipapi.co HTTPS 地址，不接受渲染进程传入查询网址，不跟随跳转，并限制时限与响应体。结果必须包含有效公网 IP 与 IANA 时区，城市只是 IP 地理估算；不使用代理入口地址代替出口。缓存按包含认证信息的代理配置签名管理，修改配置使其失效。失败不降级为直接请求。VLESS 经外部客户端转换为 HTTP/SOCKS5。

### 自动时区与共享解析

固定时区保持手动配置。自动时区由同一 workspace resolver 根据环境及分组的有效代理解析；有代理时检测失败拒绝启动，无代理时可回退本机 IANA 时区并显示 local 来源。解析结果临时传入 Go sessions 的 launch_overrides，不把自动解析值写回永久手动配置。

旧环境只在结构化指纹中保存语言/时区时，仍按固定值解析而不重写存储。用户明确切换自动模式后，才清除这些固定字段并重新检测；此兼容路径已通过真实本机服务与终端检查。

浏览器启动与终端创建共用环境解析规则。终端 TZ、代理变量以及 HOME 配置只传给拥有的子进程，不修改系统、宿主 shell 或无关环境；已运行会话的上下文更新需遵守服务的活跃会话约束。

### 原生终端与配置隔离

TerminalController 用原生文件夹对话框选择可访问的绝对目录，保存在终端元数据中；运行中的终端更换目录或相关网络配置前，需要关闭该境舱的全部终端会话。TerminalService 以会话 ID 管理真实 node-pty，xterm 提供输出、输入、尺寸与标签。默认底部高度 360 px，支持拖动、键盘调整、放大/恢复与独立 BrowserWindow。独立视图只允许操作所属境舱的终端，不向它提供管理界面的特权连接配置。

复制运行中的终端创建新 PTY，并复制原始启动上下文与尺寸。同境舱的会话共享 HOME、工具配置和历史，各自拥有输入输出、进程树及 SOCKS 代理桥。复制使用原先选择的启动 cwd，不追踪 shell 手动 cd 后的当前目录，不复制运行中的命令、临时环境变量或已有输出。源会话关闭后，副本仍可继续工作。

折叠底部面板、放大恢复或关闭独立窗口只改变视图，不结束 PTY。明确「关闭会话」、shell 自然退出或退出应用才清理已记录归属的进程与代理桥。提前完全脱离且未被记录的守护进程不在该退出证明内，macOS 进程出生标记使用秒精度。Web 预览禁用这些原生操作。

`userData/terminal/profiles/<id>/` 内提供 0700 的独立 HOME、XDG 配置/缓存/数据、Claude 配置目录与临时目录，配置和历史文件为 0600。终端使用私有非登录 shell 配置，环境变量从白名单重新构造，只保留已知命令路径与本地 CLI 安装搜索位置，不继承宿主 API 密钥、SSH agent、Git 用户身份、shell 配置或 Node 启动钩子。选定工作目录用于 shell 的 cwd，不被复制成浏览器资料目录；删除环境只清理所属终端配置，保留用户选择的工作目录。

HTTP/HTTPS 代理直接写入该 PTY 的代理变量；SOCKS5 使用只绑定 127.0.0.1 随机端口、随机认证的 HTTP 桥，便于支持 HTTP 代理的 CLI 使用，桥负责远程 SOCKS DNS。NO_PROXY 明确允许 localhost、127.0.0.1 和 ::1 直连。只有尊重代理变量的程序会经过该路由，不能视为系统网络强制规则。

配置隔离是同一操作系统用户下的目录与变量分离，不是文件系统或进程沙箱。Claude 配置目录并不表示已安装或登录 Claude；真实账号和远端请求需另行验证。IP 地理估算不能提供住宅街道地址，账号隔离不保证免于服务封禁。

截图由真实浏览器返回。CPU 和内存来自系统进程采样；RSS 合计可能重复计入共享页，当前 Windows 没有该采样。无法取得的数值保持不可用。

## 当前边界

0.1.x 与 0.2.0 的多内核与包验收保留为历史。0.3.0 的 npm test 145/145 项、终端 12 项真实 PTY、原生模块预检与 15 份许可证准备通过；总测试包含 36 项终端单元/本地测试。Cloak 11 项原生回归和 3 项临时会话时区检查通过，Camoufox/Alpha 本轮尚未执行。实际 ipwho.is 直连出口到默认 PTY 的 TZ/Intl、旧指纹字段兼容共 7 项，以及最终包真实终端 3 项通过；19 份资源 SHA 与 package.json 语义已核对。Web 拖动/键盘高度/8 标签交互通过；原生桌面真实命令、放大恢复、复制、独立窗口、关闭副本与关闭视图保留原会话通过。原位已有会话复用尚未独立 GUI 验收。外部代理供应商、其他地理服务、全部 GUI、其他系统、Claude 登录/远端请求、全部 MCP、完整指纹和完整浏览资料备份未验收。Alpha 的历史单项结果保持实验性范围。

Web 预览不启动本机浏览器。build 保留 dist/client/index.html、dist/server/index.js 与 dist/.openai/hosting.json 的 Sites 契约。发布暂停，当前不能宣称正式多平台可用。
