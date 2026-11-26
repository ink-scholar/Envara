# Envara Windows 第 3 轮测试说明

本轮只验证第 2 轮之后的修复，并做一次简短的回归检查。完整用例与准备步骤仍以 `docs/windows-test-plan.md` 为准；本文说明本轮**测什么、谁来测、怎么判定、交回什么**。

- 分支：`windows`，请测最新提交（`git log -1 --oneline` 的结果写进报告）。
- 机器：Windows 10/11 x64 实机，不用虚拟机。
- 不需要管理员权限；不要修改系统代理、默认浏览器、时区、驱动、防火墙等主机设置。

## 0. 开始前（两位都要做）

1. 更新代码：`git checkout windows`，然后 `git pull`。
2. 如果上一轮之前克隆、且 `git config core.autocrlf` 为 `true`，在**没有本地修改**时按 LF 重新检出一次：
   ```powershell
   git rm -r --cached -q . ; git reset --hard
   ```
3. **撤掉上一轮的所有绕过手段**，本轮要验证原样命令：
   - 删除或清空 `NODE_OPTIONS` 里的预加载脚本；
   - 删除上一轮手工放入 `build\proxy-core` 的补丁产物（`npm run proxy:prepare` 会重新生成）；
   - 删除手工补的 `%APPDATA%\Envara\browseforge\browsers\browseforge-chromium\150.0.7871.101.manifest`（如果有）；
   - 不要设置 `NODE_TLS_REJECT_UNAUTHORIZED=0`。
4. 打开 Windows“开发者模式”（设置 → 系统 → 开发者选项），否则约 100 项符号链接测试会失败。
5. 记录：系统版本、Node/npm/Go 版本、是否设置了 `HTTP_PROXY`/`HTTPS_PROXY`（只写“有/无”，不写地址）、系统代理是否开启（只写“开/关”）。

## 1. 本轮改了什么（测试时对照）

| 改动 | 预期现象 |
| --- | --- |
| `npm ci` 后的终端模块检查会自行退出；`proxy:prepare` 不再检查 Windows 没有的权限位；锁文件改为 npmjs 地址；仓库统一 LF | 原样 `npm ci`、`npm run desktop` 一次通过，不需要任何夹具 |
| `npm test` 中的死循环已修复 | `npm test` 能跑完（仍会有几百项失败，见 R2） |
| 关闭终端：Windows 上改为常驻一个只读进程查询进程列表，关闭时限 6 秒 | 关闭会话在几秒内变为“已关闭”，不再停在“关闭中”；有终端时也能正常退出应用 |
| 不再每 0.75 秒新起一个 `powershell.exe` | 开着终端时 Envara 名下最多只有 1 个长期存在的 `powershell.exe`；全部终端关闭约 15 秒后它也退出 |
| `backend:prepare` 复用已有的 playwright-go 许可文件 | 第二次起不再访问 `raw.githubusercontent.com` |
| 浏览器内核下载读取 Windows 系统代理（只读“已启用的固定代理”，不读 PAC 自动配置脚本） | 只开系统代理、不设代理环境变量时也能下载内核 |
| **BrowseForge Chromium 在 Windows 上停用** | 内核列表显示“当前平台不可用”和原因；不能安装、不能新建、已有环境不能启动，都有明确提示 |
| 终端设置 `APPDATA`/`LOCALAPPDATA`；去掉 node-pty 的编码警告；搜索框显示 `Ctrl K` | 见 R7、R8 |

## 2. 分工

| 编号 | 内容 | 同事甲（第 1 轮的机器，应用之前没能启动） | 同事乙（第 2 轮的机器，已有环境和内核数据） |
| --- | --- | --- | --- |
| R1 | 原样安装与准备 | ✅ 主测 | ✅ 复测 |
| R2 | `npm test` 能否跑完 | ✅ | — |
| R3 | 终端关闭与应用退出 | ✅ | ✅ 主测（重复次数多一些） |
| R4 | `powershell.exe` 进程数量 | — | ✅ |
| R5 | 只靠系统代理下载内核 | ✅（内核尚未安装） | — |
| R6 | BrowseForge Chromium 停用提示 | ✅ 新建/安装 | ✅ 已有环境启动 |
| R7 | 终端环境变量与警告 | ✅ | — |
| R8 | 搜索框快捷键 | ✅ | — |
| R9 | 简短回归 | ✅ | ✅ |
| R10 | 两个待复现问题 | — | ✅ |

## 3. 用例

每项记录 ✅ / ⚠️ / ❌ / 未测，并写明时间点，失败时附截图和日志位置。

### R1 原样安装与准备

在仓库根目录运行收集脚本（它依次执行 `npm ci`、`native:prepare`、`backend:prepare`、`proxy:prepare`、`npm test`、构建，并打包日志）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\windows-test-collect.ps1
```

- 预期：01–04 四步退出码都是 0；`build\proxy-core\mihomo.exe` 存在；`02-native-prepare.log` 里有 `PTY ready (win32/x64…)`，**没有** `Could not find any Visual Studio installation`。
- 补充（同事甲）：准备步骤完成后，**在不设置代理环境变量的终端**里再运行一次 `npm run backend:prepare`，预期成功（许可文件已复用，不需要访问 GitHub）。
- 下载 Electron 被代理切断属于网络问题，可设置 `ELECTRON_GET_USE_PROXY=1` 后重试，并在报告里注明。

### R2 `npm test` 能否跑完

- 收集脚本的 `10-npm-test` 步骤应在时限内结束，不再无限挂起。
- 记录总数、通过、失败、跳过（日志末尾 `ℹ tests / pass / fail`）。失败仍会有几百项，主要是测试本身假设了 macOS，这部分下一步整理，本轮只记录数字，不需要逐项分析。
- 如果有单个测试超过 3 分钟被取消，记下测试名。

### R3 终端关闭与应用退出（重点）

用以下命令启动应用，测完后正常退出（日志会被收集）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\windows-test-collect.ps1 -SkipInstall -SkipTests -Desktop
```

逐个点“关闭会话”，每种至少 2 次（同事乙每种 3 次以上）：

1. 新建后不输入任何命令就关闭；
2. 运行过 `dir`、`echo` 后关闭；
3. 运行 `ping -t 127.0.0.1`，按 Ctrl+C 中断后关闭；
4. 运行 `ping -t 127.0.0.1` **不中断**直接关闭；
5. “复制会话”产生的会话；
6. 在独立窗口里打开过的会话。

预期：

- 约 6 秒内状态变为已关闭，不出现“终端进程清理未完成”；
- 对应的 `cmd.exe`、`conhost.exe`（或 `OpenConsole.exe`）和 `PING.EXE` 都消失。

检查残留时只看 Envara 启动的进程，不要把自己的 PowerShell 窗口算进去：

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.Name -in 'cmd.exe','conhost.exe','OpenConsole.exe','PING.EXE','powershell.exe' } |
  Select-Object ProcessId, ParentProcessId, Name, CreationDate | Format-Table
```

对照 `ParentProcessId` 判断是否属于 Envara（开发模式下 Envara 主进程是 `electron.exe`）。

**退出测试：**

- 保持 2 个终端会话开着（其中 1 个正在 `ping -t`），直接关闭 Envara 最后一个窗口。
- 预期：约 10 秒内 Envara 全部退出，`electron.exe`、`BrowseForge-sidecar.exe`、`mihomo.exe`、以及上面这些终端进程都没有残留。
- **更正（第 3 轮之后）**：此预期写错了。e821ae0 上关闭最后一个窗口时，只要还有终端在运行，Envara 会留在后台（沿用 macOS 行为），直到终端结束才退出。之后的提交在 Windows 上改为弹窗确认，见 `docs/windows-test-round4.md`。
- 退出后再打开一次，确认能正常启动、旧终端会话没有被复活。

### R4 `powershell.exe` 进程数量

分别在三种状态下观察 20 秒，记录 Envara 名下 `powershell.exe` 的**不同 PID 数量**：

- 不开终端；
- 开 1 个终端；
- 开 3 个终端。

```powershell
$seen = @{}; 1..20 | ForEach-Object {
  Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | ForEach-Object {
    $parent = Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue
    if ($parent.ProcessName -eq 'electron') { $seen[$_.ProcessId] = $true } }
  Start-Sleep 1 }
"distinct powershell.exe under Envara: $($seen.Count)"
```

- 预期：开着终端时为 1；不开终端时为 0。
- 关闭全部终端约 15 秒后，这个 `powershell.exe` 也退出。
- 上一轮开 1 个终端时，20 秒内出现过 26 个。

### R5 只靠系统代理下载内核（同事甲）

前提：本机网络必须经代理才能访问 GitHub，并且系统代理已开启。

1. 在**没有** `HTTP_PROXY`/`HTTPS_PROXY` 环境变量的终端里启动应用（用 R3 的命令）。
2. 安装 CloakBrowser 和 Camoufox。

- 预期：都能下载并安装成功，记录耗时。
- 如果系统代理是 PAC 自动配置脚本，本轮不支持，请注明“PAC”后改为设置代理环境变量再测。

### R6 BrowseForge Chromium 停用提示

- **内核列表**（浏览器页 → 内核）：BrowseForge Chromium 显示“当前平台不可用”，按钮为“不可用”且不能点击。下方显示原因：“BrowseForge Chromium 暂不支持 Windows：其运行时缺少启动组件，且无法应用环境时区。请改用 CloakBrowser 或 Camoufox。”
- **新建环境**（同事甲）：内核下拉里该项带“· 不可用”且不能选；默认内核不是它。
- **已有环境**（同事乙，例如上一轮的 T-bf-A）：点“启动”，预期立即显示上面的原因，没有新进程。不能再出现 `spawn UNKNOWN` 或一长串 Playwright 命令行。已有环境的配置和数据不受影响，可以正常导出和删除。
- **语言**：把界面切到 English 和 日本語，各看一次这条提示是否已翻译。

### R7 终端环境变量与警告（同事甲）

在 Envara 终端里执行：

```bat
echo %APPDATA%
echo %LOCALAPPDATA%
echo %USERPROFILE%
```

- 预期：三个路径都在 `%APPDATA%\Envara\terminal\profiles\<环境ID>\` 下，不是本机用户目录；两个不同环境的路径也不同。
- 打开 `20-desktop-session.log`，确认不再出现 `Setting encoding on Windows is not supported`。
- `AttachConsole failed` 这类来自 node-pty 的输出如果仍在，只需记录出现次数。

### R8 搜索框快捷键（同事甲）

- 环境页搜索框右侧应显示 `Ctrl K`，不是 `⌘ K`。
- 按 Ctrl+K，焦点应跳到搜索框。

### R9 简短回归（两位都做）

不必重复全部 B–G，确认以下各项仍正常即可：

- 首次启动和语言选择（同事甲是干净数据，正好覆盖）；
- 添加 1 个 HTTP 或 SOCKS5 出口并检测成功；
- 用 CloakBrowser 和 Camoufox 各启动 1 个环境，出口正确；
- 新建终端，`curl.exe https://api.ipify.org` 返回代理出口；
- 导出 1 个浏览器环境，再导入；
- 应用内“设置”中“导出支持诊断”能成功生成文件。

### R10 两个待复现问题（同事乙）

1. **导入时输错密码：**
   - 输入错误密码后点“导入”，**等待至少 10 秒**，观察是否出现红色提示“密码不正确，或文件已损坏。”（提示可能在窗口右下角）；
   - 再输入正确密码确认可以导入。
2. **HTTP 代理认证失败：**
   - 添加一个带错误密码的 HTTP 代理并检测，记录界面上的完整文案；
   - 用 SOCKS5 错误密码做一次对比。

## 4. 交回内容

- 每次运行收集脚本都会生成 `test-artifacts\windows\<时间>.zip`。请全部交回，同时交回按下面模板写的报告（Markdown 即可）。
- 发送前请打开压缩包检查：不应包含账号名、密码、代理地址或私人文件。截图里如有出口 IP 或本机路径，请打码。
- 放到仓库根目录或直接发给我，文件名带上“甲/乙”和日期。

### 报告模板

```markdown
# Envara Windows 第 3 轮测试报告（同事甲/乙）

- 测试人 / 日期 / 用时：
- 提交（git log -1 --oneline）：
- 系统版本 / 实机型号 / 显示缩放：
- Node / npm / Go 版本：
- 代理：系统代理 开/关（PAC 是/否）；HTTP(S)_PROXY 环境变量 有/无
- 已撤掉上一轮的绕过手段：是/否（如否，写明保留了哪些）

| 编号 | 结果 | 说明（现象、次数、耗时、截图/日志位置） |
| --- | --- | --- |
| R1 | | |
| R2 | | 总数 / 通过 / 失败 / 跳过 / 取消： |
| R3 | | 每种关闭方式：成功次数/总次数；退出耗时；有无残留 |
| R4 | | 0 / 1 / 3 个终端时的数量；关闭后多久退出 |
| R5 | | |
| R6 | | |
| R7 | | |
| R8 | | |
| R9 | | |
| R10 | | |

## 新发现的问题（按严重程度）

1. 现象 / 复现步骤 / 预期 / 实际 / 日志与截图

## 未测与原因
```
