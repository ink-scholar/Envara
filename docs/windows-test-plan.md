# Windows x64 适配测试计划

本文件给在 Windows 实机上编译、测试 `windows` 分支的同学使用。测试结果是 Windows 行为的唯一证据：macOS 上的单元测试与交叉编译不能代替。每一轮测试后交回**测试报告**（见文末模板）和**日志压缩包**。

> 范围：Windows 10 22H2 / Windows 11，x64。Windows ARM64、虚拟机、Wine 不在本轮范围；如果只有虚拟机，请在报告中写明。
> 不要使用自己的日常浏览器资料、真实账号或生产代理节点做破坏性测试。请使用一次性测试账号和测试代理。

## 1. 准备环境

1. 安装 **Node.js 24 LTS x64**（或 22.12+）、**Go 1.25**、**Git for Windows**。使用 Node 自带的 npm；第 1 轮发现另装的 npm 12 默认拒绝锁文件中的部分地址，锁文件已统一为 registry.npmjs.org，如仍报 `EALLOWREMOTE` 请在报告中注明 npm 版本。
2. 开启 Windows「开发者模式」（设置 → 系统 → 开发者选项），否则普通权限不能创建符号链接，约 80 项测试会因 `EPERM` 失败。不开也可以继续，在报告中注明即可。
3. 如果需要代理才能访问 GitHub / npm：除 `HTTPS_PROXY` 外再设置 `$env:ELECTRON_GET_USE_PROXY = "true"`，否则 Electron 首次下载不走代理。不要设置 `NODE_TLS_REJECT_UNAUTHORIZED=0`。
4. 普通权限打开 PowerShell（不需要管理员）：

   ```powershell
   git clone https://github.com/ink-scholar/Envara.git
   cd Envara
   git checkout windows
   git pull
   ```

   仓库已加入 `.gitattributes`，文本文件统一以 LF 检出。第 1 轮之前克隆、且系统 `core.autocrlf=true` 的工作区，请在没有本地修改时执行一次 `git rm -r --cached -q . ; git reset --hard` 重新检出，否则内置列表哈希校验会失败。

5. 运行日志收集脚本。第一次运行会安装依赖并准备后端、终端和代理核心：

   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\windows-test-collect.ps1 -Desktop
   ```

   - 脚本依次执行 `npm ci`、`native:prepare`、`backend:prepare`、`proxy:prepare`、全部单元测试、`npm run build`、`npm run test:sites`，然后执行 `npm run desktop` 打开应用。
   - 每一步都有时间限制（默认安装/构建 30 分钟、单元测试整体 60 分钟、单个测试 180 秒、桌面会话 240 分钟），超时会结束该步骤启动的整个进程树并记为 `timeout`；任何一步失败或超时，脚本最后以退出码 1 结束。可用 `-StepTimeoutMinutes`、`-TestTimeoutMinutes`、`-PerTestTimeoutSeconds` 调整。
   - 应用打开后按第 2 节逐项测试，测试结束后退出 Envara，脚本会继续收集日志。
   - 已经安装过依赖时可以加 `-SkipInstall`；只想重新做桌面测试可以加 `-SkipInstall -SkipTests -Desktop`。
   - 输出位于 `test-artifacts\windows\<时间>\` 和同名 `.zip`。脚本会把 Windows 用户名和计算机名替换为占位符，**发送前请再打开检查一遍**，不要包含代理密码、令牌或私人路径。

6. 应用内导出：「设置」中的「导出支持诊断」，把导出的文件一起放进压缩包。
7. 每个失败项请截图（使用测试数据），并记下发生时间，便于和日志对照。

如果某一步编译失败，后面的步骤可以不做，直接交回 `summary.json` 和对应步骤的 `.log`。

## 2. 测试用例

结果填写：✅ 通过 / ❌ 失败 / ⚠️ 部分可用 / ⏭️ 未测。**“预期拒绝”项看到明确的错误提示即为通过**；如果它没有报错、静默改走本机直连，请记为 ❌ 并重点说明。

### A. 编译与自动检查

| 编号 | 操作 | 预期 |
| --- | --- | --- |
| A1 | `npm ci` | 成功；`node-pty` 使用自带的 Windows 预编译文件 |
| A2 | `native:prepare` / `backend:prepare` / `proxy:prepare` | 各自成功；`build\backend\BrowseForge-sidecar.exe`、`build\backend\playwright-driver\node.exe`、`build\proxy-core\mihomo.exe` 存在 |
| A3 | `npm test` | 记录通过/失败/跳过数量；失败的测试名称写进报告 |
| A4 | `npm run build`、`npm run test:sites` | 成功 |

### B. 首次启动与界面

| 编号 | 操作 | 预期 |
| --- | --- | --- |
| B1 | 首次启动 | 先出现工作区窗口，再完成后台初始化；没有长时间白屏或崩溃 |
| B2 | 语言 | 推荐系统语言并要求确认；切换九种语言后文字不溢出、不被截断 |
| B3 | 外观 | 浅色 / 深色 / 跟随系统都正常，Windows 系统设置不被修改 |
| B4 | 布局 | 三栏布局、导航顺序、设置位于底部；窗口缩放、最大化、高 DPI（125%/150%）下显示正常 |
| B5 | 重启 | 退出后再打开，语言、外观、环境列表都保留 |

### C. 网络环境

| 编号 | 操作 | 预期 |
| --- | --- | --- |
| C1 | 添加 HTTP / HTTPS / SOCKS5 代理（带认证） | 能检测到实际出口 IP、地区，并推荐时区 |
| C2 | 添加 AnyTLS 节点 | 不需要外装 Clash；`mihomo.exe` 由 Envara 启动，检测出口成功 |
| C3 | 代理断开或密码错误 | 显示失败，不显示本机直连的 IP |
| C4 | 确认或手动选择位置 | 保存成功；Windows 系统时区不被修改 |

### D. 浏览器

每种内核（CloakBrowser、Camoufox、BrowseForge Chromium）各测一遍：

| 编号 | 操作 | 预期 |
| --- | --- | --- |
| D1 | 安装内核 | 下载与安装完成，进度和错误提示正常 |
| D2 | 启动浏览器 | 窗口打开；访问 IP 检测网站，显示的是代理出口而不是本机 IP |
| D3 | 登录测试网站后关闭再打开 | 登录状态保留，指纹信息（UA、时区、语言）和第一次一致 |
| D4 | 克隆环境 | 新环境的指纹与原环境不同 |
| D5 | 两个环境同时运行 | 互不影响，出口各自正确 |

### E. 终端

| 编号 | 操作 | 预期 |
| --- | --- | --- |
| E1 | 新建终端，选择网络和工作目录 | 使用 `cmd.exe` 启动，提示符为 `envara <目录>>`，当前目录正确 |
| E2 | 输入英文、中文、粘贴、Ctrl+C | 回显正常，无乱码，中断有效 |
| E3 | 拖动面板、展开工作区、独立窗口 | 内容随尺寸重排（`mode con` 显示的列数随之变化） |
| E4 | 复制终端 | 新建一个空闲 shell，目录和网络相同，之前的命令不会重放 |
| E5 | 关闭终端视图后重新打开 | 会话仍在，之前的输出还在 |
| E6 | 结束会话 | 进程结束；任务管理器中没有残留的 `cmd.exe` / `conhost.exe` / `OpenConsole.exe` |
| E7 | 使用代理的终端里执行 `set HTTP_PROXY` 和 `curl https://api.ipify.org` | 变量指向本机回环端口，返回代理出口 IP。**注意**：Windows 目前没有网络围栏，不读取代理变量的程序仍可能直连，终端网络说明应为“…代理，仅支持代理配置的命令行工具生效…”，不能显示“围栏阻止直接公网连接”。请记录界面上的实际描述 |
| E8 | 每个环境的终端执行 `echo %USERPROFILE%` | 指向 Envara 数据目录内该环境自己的 HOME，不是本机用户目录 |

### F. 预期拒绝（未实现部分应明确失败）

| 编号 | 操作 | 预期 |
| --- | --- | --- |
| F1 | 新建 Claude Code 专用终端 | 明确报错（需要网络围栏 / 平台不支持），不启动 CLI，也不使用本机安装的 `claude` |
| F2 | 添加 SSH 连接 | 提示“SSH 连接目前仅支持 macOS” |
| F3 | 附加应用：选择一个 `.exe` 并尝试启动 | 无法激活或启动，并说明原因；不安装驱动或服务，不弹出 UAC |
| F4 | 设置中的系统链接路由 | 显示不可用，不修改 Windows 默认浏览器 |

### G. 导出、导入与退出清理

| 编号 | 操作 | 预期 |
| --- | --- | --- |
| G1 | 从浏览器详情页导出（设置密码） | 生成加密文件 |
| G2 | 导入到新环境 | 资料恢复，原有环境不受影响；错误密码时拒绝 |
| G3 | 退出 Envara | 任务管理器中没有残留的 `BrowseForge-sidecar.exe`、`mihomo.exe`、Envara 启动的 `node.exe` 或浏览器进程 |
| G4 | 强制结束 Envara（任务管理器结束进程树）后重新打开 | 能正常启动；记录是否有残留进程或报错 |

## 3. 测试报告模板

复制以下内容填写，与日志压缩包一起交回：

```markdown
# Envara Windows 测试报告

- 测试人 / 日期：
- 分支与提交：windows @ <git rev-parse --short HEAD>
- 系统：Windows <10/11> <版本号> x64，实机/虚拟机：
- 显示缩放：  界面语言：  系统区域：
- Node / npm / Go 版本：
- 代理类型（不要写地址和密码）：

## 结果汇总
| 编号 | 结果 | 说明（现象、错误码、截图文件名、发生时间） |
| --- | --- | --- |
| A1 | | |
| ... | | |

## npm test
通过 X / 失败 Y / 跳过 Z；失败测试名称：

## 主要问题（按严重程度排序）
1. 现象 / 复现步骤 / 预期 / 实际 / 对应日志文件与时间

## 附件
- test-artifacts\windows\<时间>.zip
- 应用内导出的支持诊断文件
- 截图
```

## 4. 开发侧待办（Windows 适配）

由开发者维护，每轮根据测试报告更新。

- [x] Windows 上 POSIX 权限位和 uid 检查误判（Node 在 Windows 上把可写文件报告为 `0o666`、uid 为 0），终端配置、工作组合、缓存维护和诊断存储因此拒绝工作。已改用 `electron/file-trust.mjs`，保留文件类型、符号链接、硬链接和 realpath 检查。Windows 依赖 `%APPDATA%` 默认 ACL，尚未检查 NTFS ACL。
- [x] 第 1 轮：`check-native-pty.cjs` 成功后因 ConPTY 句柄不退出，`npm ci` / `native:prepare` 超时转源码编译。改为显式退出，并打印预编译检查失败的原因。
- [x] 第 1 轮：`proxy:prepare` 在 `create-source-archive.mjs` 因 POSIX 权限位检查失败，缺 `mihomo.exe`。Windows 上没有可保留的权限位，跳过该检查。
- [x] 第 1 轮：锁文件 283 条 `registry.npmmirror.com` 地址统一为 `registry.npmjs.org`（完整性哈希不变；使用镜像的用户由 npm 自动替换）。
- [x] 第 1 轮：新增 `.gitattributes`，统一 LF 检出，避免 CRLF 使内置列表哈希校验失败。
- [x] 第 1 轮：`terminal-browser-broker.mjs` 浏览器会话清理的 uid 比较在 Windows 恒为不一致，改用 `file-trust.mjs`。
- [x] 第 1 轮：PF 控制器和 Notion 前置服务向上遍历目录只在 `/` 停止，Windows 路径下死循环（`component-versions` 测试 100% CPU）。改为到根目录即停止。
- [x] 第 1 轮：收集脚本加入超时与进程树结束、失败时退出码 1、按路径和词边界脱敏，记录开发者模式、换行与环境变量是否存在（不记录值）。
- [x] 第 2 轮（基于 650fc1e，Windows 11 22631 实机）：B–G 桌面实测已完成。A1/A2 的 PTY 检查、`proxy:prepare`、`component-versions` 挂起和浏览器会话清理已在 8625d34 修复，下一轮需在新提交上复测。
- [x] 第 2 轮：关闭终端会话 4 次中 3 次卡在 `closing`，并拖住应用退出（E6/G3）。原因：Windows 每次进程快照都新起 `powershell.exe`（约 0.3–1 s），1.5 s 预算在发出 `pty.kill()` 之前就耗尽；之后最终核验只给 100 ms 超时，PowerShell 必然超时，结果永远是“元数据不可用”，重试也无法完成。已改为常驻一个只读元数据进程（空闲 15 s 自动退出，失败时回退单次查询）、Windows 关闭预算 6 s、最终核验至少 3 s、先走 ConPTY 正常关闭再对已核验 PID `taskkill /T /F`；多个终端的周期跟踪共享同一快照（1 s 间隔）。
- [x] 第 2 轮：`backend:prepare` 每次都从 `raw.githubusercontent.com` 下载 playwright-go LICENSE。现在依次复用 `GOMODCACHE`、仓库内 Go 模块缓存和上一次驱动产物中的同一文件，最后才下载。
- [x] 第 2 轮：Windows 引擎下载不读系统代理。侧车现在读取 `HKCU\…\Internet Settings` 中已启用的静态代理（不解析 PAC），与 macOS 读取 `scutil --proxy` 的行为一致。
- [x] 第 2 轮：终端缺少 `APPDATA`/`LOCALAPPDATA`，现指向该环境自己的配置/数据目录；Windows 上不再给 node-pty 传 `encoding`（消除每次启动的警告）；搜索框快捷键在非 macOS 显示 `Ctrl K`。
- [x] 第 3 轮（基于 e821ae0，两台 Windows 11 实机，说明见 `docs/windows-test-round3.md`）：原样安装通过（同事乙那台机器直连 GitHub 不通，需要设代理环境变量，属于网络环境）；`npm test` 约 14.5 分钟跑完，不再挂起；终端关闭 6 种方式共 30 次全部在预算内完成、无残留；常驻 `powershell.exe` 0/1/1 个，空闲约 15 s 退出；只靠系统代理下载内核成功；BrowseForge Chromium 停用提示、APPDATA 隔离、编码警告、`Ctrl K`、简短回归和导入密码错误提示都通过。
- [x] 第 3 轮：开着终端时关闭最后一个窗口，Envara 留在后台（macOS 的设计，Windows 上没有 Dock 可回到它），两台机器都观察到进程长时间不退出。现在 Windows/Linux 上关闭最后一个窗口时，如仍有运行中的终端或附加软件，弹窗确认“结束并退出”或“取消”（默认取消，九种语言），确认后走统一退出清理；没有运行中的任务就直接退出。macOS 不变。
- [x] 第 3 轮：HTTP/HTTPS 代理密码错误显示通用“无法完成 HTTPS 验证”。原因：这两种代理经内置 Mihomo 检测，Mihomo 先回应 CONNECT 再连上游，上游的 407 被吞掉。检测失败后，现在对上游代理单独发一次 CONNECT，只读状态行（隧道不发送任何数据并立即关闭）；返回 407 时改报“代理认证失败，请检查凭据”。
- [x] 第 3 轮：`npm run desktop` 按 Ctrl+C 后 Windows 上残留 Vite 的 `esbuild.exe`；开发启动器现在用 `taskkill /T /F` 结束 Vite 与 Electron 的整个进程树。
- [x] 第 3 轮：收集脚本对 JSON 转义路径（`C:\\Users\\<用户名>`）脱敏遗漏；`crlfFiles` 把 `attr/-text` 文件误报为 CRLF。均已修正。
- [ ] 第 4 轮（说明见 `docs/windows-test-round4.md`）：复测关闭最后一个窗口的确认与退出、HTTP 代理认证失败文案；记录 Envara 主进程下来源不明的 `cmd.exe` + `conhost.exe`（同事甲观察到一对，不随关闭次数累积）的命令行和创建时间。
- [ ] node-pty 在关闭会话时启动的 `conpty_console_list_agent` 偶发 `AttachConsole failed` 并打印完整堆栈（shell 已退出时）。不影响关闭结果，属于日志噪音，待评估是否能避免。
- [ ] 启动初期偶发 `Unable to refresh workspace: Unable to reach the local BrowseForge service.`（侧车尚未就绪时的刷新），之后恢复；可在侧车就绪前跳过刷新。
- [ ] `npm test` 在 `%TEMP%` 留下 `envara*` 临时目录（一次约 65 个）；`backend:prepare` 重命名旧 `playwright-driver` 偶发 EPERM（文件被扫描占用），可加短暂重试。
- [ ] npm 12 默认拦截 `electron-winstaller`、`esbuild`、`node-pty` 的安装脚本（allowScripts），当前未造成影响；升级到 npm 12 前需要在 `package.json` 中声明允许。
- [x] BrowseForge Chromium Windows 运行时（上游 `nczz/browseforge-runtime-chromium` v0.1.6-alpha.0）缺少 `150.0.7871.101.manifest`，`chrome.exe` 因 SxS 配置错误无法启动；补齐后页面时区与 Intl locale 仍取宿主值。已在 Windows 上停用该内核（`electron/engine-platform-hold.mjs`）：内核列表显示不可用及原因，安装、新建和启动都给出明确提示，且不会成为默认内核。
- [ ] 上游发布修复上述两项的 Windows 运行时后，更新固定版本、在 Windows 上验收，再移除停用。
- [ ] 引擎下载进度：侧车给出字符串进度，界面只显示“安装中…”；失败文案重复大量进度行。
- [ ] 待在 macOS 上复现后判断：Camoufox canvas 哈希重开后变化（D3）。（导入密码错误的提示已在第 3 轮确认正常；HTTP 407 已修正。）
- [ ] 界面：Windows 上仍显示 macOS 专属的“SSH 连接”导航；系统链接路由控件被隐藏而非显示不可用；设置中“终端链接使用所选浏览器”在链接通道不可用时不成立；Windows 附加软件目录未过滤安装器与系统辅助程序；Claude 拒绝文案应说明“Windows 暂不支持”而非“安装无效”。
- [ ] 单元测试在 Windows 上的可移植性：约 570 项失败来自测试本身的 POSIX 假设（`/usr/bin/true`、`/tmp`、Unix socket、`process.getuid`、`openssl`、gzip 夹具等）和 macOS 专属测试文件。需要为 macOS 专属测试加平台跳过，并把通用测试改为可移植夹具，以便区分真实的 Windows 缺陷。
- [ ] `realpath` 与原路径逐字比较：如果出现大小写、8.3 短路径或 `\\?\` 前缀差异导致 `UNSAFE_PATH`，需要改为 Windows 规范化比较。
- [ ] 终端链接通道使用 Unix socket 路径；Windows 需要改为命名管道（`\\.\pipe\…`），否则终端里打开的链接无法交给环境浏览器。
- [ ] 终端默认 shell 为 `cmd.exe`，终端附件仅支持 PowerShell；评估是否改为默认 PowerShell 或让用户选择。
- [ ] Windows 终端网络围栏：没有经过验证的边界之前，界面继续显示“仅支持代理配置的命令行工具生效”；Claude 专用会话继续拒绝。
- [ ] Claude Code：官方 Windows 原生安装的下载校验（`claude-code-download.mjs` 目前仅支持 darwin）与 PE 识别（`claude-code-installation.mjs`）；依赖终端围栏，暂不启用。
- [ ] SSH、系统链接路由：目前仅限 macOS，Windows 上保持明确提示。
- [ ] 附加应用：WinDivert 路由的 DNS 归属与守护进程故障阻断两项缺口完成前保持关闭（见 `native/windows-app-routing/README.md`）。
- [ ] 打包：`npm run dist:win` 安装包的安装、卸载和干净首次启动验收。
