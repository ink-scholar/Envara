# Envara Windows 第 4 轮测试说明

本轮只验证第 3 轮之后的修复，范围比上一轮小很多，预计每人 1 小时左右。准备步骤、收集脚本和报告格式与第 3 轮相同（见 `docs/windows-test-round3.md` 第 0 节与第 4 节）。

- 分支：`windows`，测最新提交（`git log -1 --oneline` 的结果写进报告）。
- 机器：沿用第 3 轮的两台实机。
- 不需要管理员权限；不要修改系统代理、默认浏览器、时区、驱动、防火墙等主机设置。

## 0. 开始前

1. `git checkout windows`，然后 `git pull`。
2. 运行一次收集脚本的准备部分（会重新生成产物，`npm test` 可以跳过）：
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\windows-test-collect.ps1 -SkipTests
   ```
3. 之后每次启动应用都用：
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\windows-test-collect.ps1 -SkipInstall -SkipTests -Desktop
   ```
   测完**在应用里正常退出**，不要在这个窗口按 Ctrl+C（Q4 除外），这样日志才会被完整收集。

## 1. 本轮改了什么

| 改动 | 预期现象 |
| --- | --- |
| 关闭最后一个窗口时，如果还有终端或附加软件在运行，弹窗确认 | 出现“仍有任务在运行”对话框，按钮为“结束并退出”和“取消”，默认是“取消”；选“结束并退出”后应用完整退出 |
| 没有运行中的任务时关闭最后一个窗口 | 不弹窗，直接退出（与上一轮相同） |
| HTTP/HTTPS 代理密码错误时，检测改报认证失败 | 显示“代理认证失败，请检查凭据。”，不再是“无法经指定网络出口完成 HTTPS 验证…” |
| `npm run desktop` 按 Ctrl+C 时结束整个进程树 | 不再残留 `esbuild.exe` 或 Electron 进程 |
| 收集脚本脱敏也覆盖 JSON 中的双反斜杠路径；CRLF 统计不再误报 | `10-npm-test.log` 等文件里没有你的用户名；`summary.json` 的 `crlfFiles` 为 0 |

说明：第 3 轮说明里“开着终端关闭最后一个窗口，约 10 秒内退出”的预期写错了，这正是本轮要验证的新行为。

## 2. 分工

| 编号 | 内容 | 同事甲 | 同事乙 |
| --- | --- | --- | --- |
| Q1 | 关闭最后一个窗口的确认与退出 | ✅ | ✅ 主测（重复次数多一些） |
| Q2 | HTTP 代理认证失败文案 | — | ✅ |
| Q3 | 来源不明的 `cmd.exe` + `conhost.exe` | ✅ | ✅（如果也观察到） |
| Q4 | 开发启动器 Ctrl+C 后无残留 | ✅ | — |
| Q5 | 收集脚本脱敏 | ✅ | — |
| Q6 | 简短回归 | ✅ | ✅ |

## 3. 用例

每项记录 ✅ / ⚠️ / ❌ / 未测，并写明时间点，失败时附截图和日志位置。

### Q1 关闭最后一个窗口（重点）

查看 Envara 相关进程的命令（开发模式下主进程是 `electron.exe`）：

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.Name -in 'electron.exe','BrowseForge-sidecar.exe','mihomo.exe','cmd.exe','conhost.exe','PING.EXE','powershell.exe','node.exe' } |
  Select-Object ProcessId, ParentProcessId, Name, CreationDate | Format-Table
```

逐项操作（同事乙每项 3 次，同事甲每项 1 次）：

1. **取消**：开 2 个终端会话（其中 1 个运行 `ping -t 127.0.0.1`），关闭主窗口。
   - 预期：弹出“仍有任务在运行 / 仍有 2 个终端或附加软件在运行”；按 Enter 或 Esc（默认取消）后窗口保留，两个终端都还在运行，`ping` 输出不中断。
2. **结束并退出**：同样的状态下关闭主窗口，选“结束并退出”。
   - 预期：约 15 秒内所有 Envara 进程（`electron.exe`、`BrowseForge-sidecar.exe`、`mihomo.exe`、终端的 `cmd.exe`/`conhost.exe`/`PING.EXE`、常驻 `powershell.exe`）都消失。请记录从点击到最后一个进程消失的秒数。
   - 之后重新启动，预期正常打开、旧终端没有被恢复为运行中。
3. **没有任务**：所有终端都关闭（状态为“已关闭”）后关闭主窗口。
   - 预期：不弹窗，几秒内退出。
4. **多个窗口**：开 1 个终端并在“独立窗口”中打开它，此时有主窗口 + 终端窗口。
   - 先关主窗口：预期**不弹窗**（还剩终端窗口）。
   - 再关终端窗口：预期弹窗，选“结束并退出”后完整退出。
5. **语言**：把界面切到 English，重复第 1 步。预期对话框为英文（“Work is still running”，按钮“End and Quit” / “Cancel”）。
6. **浏览器**：只开着 1 个浏览器环境（无终端）时关闭主窗口，记录实际行为（是否弹窗、浏览器是否一起关闭、耗时）。本项只记录，不判定。

### Q2 HTTP 代理认证失败文案（同事乙）

使用第 3 轮 R10 的 HTTP 测试代理：

1. 添加网络出口：协议 HTTP、正确地址和端口、**错误密码** → “检测并继续”。
   - 预期：显示“代理认证失败，请检查凭据。”
2. 同一代理、**正确密码** → 检测成功（不受影响）。
3. 同一地址、**错误端口**（没有服务监听） → 仍显示通用的“无法经指定网络出口完成 HTTPS 验证…”（不能误报为认证失败）。
4. 如果有 HTTPS 协议的测试代理，重复第 1 步；没有则写“未测”。
5. SOCKS5 错误密码仍显示“代理认证失败，请检查凭据。”（与上一轮相同）。

### Q3 来源不明的 `cmd.exe` + `conhost.exe`

第 3 轮同事甲观察到：Envara 主进程下一直挂着一对 `cmd.exe` + `conhost.exe`，不属于正在测试的会话，也不随关闭次数累积。本轮请记录它的来源：

1. 启动应用后**先不开任何终端**，运行下面的命令；然后开 1 个终端、再全部关闭，各运行一次。
   ```powershell
   $main = Get-CimInstance Win32_Process -Filter "Name='electron.exe'" | Where-Object { $_.CommandLine -notmatch '--type=' } | Select-Object -First 1
   Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $main.ProcessId } |
     Select-Object ProcessId, Name, CreationDate, CommandLine | Format-List
   ```
2. 记录每次输出中 `cmd.exe` 的命令行和创建时间，以及它出现在哪一步（启动后、开终端后还是关闭后）。
3. 同时在应用里查看所有环境的终端列表，记录有没有状态为“错误”或“关闭中”的旧会话。
4. 命令行中如果包含本机用户名或私人目录，请打码后再贴到报告里。

### Q4 开发启动器 Ctrl+C（同事甲）

1. 运行 `npm run desktop`（不用收集脚本），等应用窗口出现。
2. 在这个 PowerShell 窗口按一次 Ctrl+C。
3. 10 秒后运行 Q1 的进程查看命令，并单独检查 `esbuild.exe`：
   ```powershell
   Get-Process esbuild, electron -ErrorAction SilentlyContinue
   ```
   - 预期：没有残留。

### Q5 收集脚本脱敏（同事甲）

用收集脚本完整跑一次，包括 `npm test`：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\windows-test-collect.ps1
```

之后在生成的目录里搜索你的用户名，预期 0 处：

```powershell
Select-String -Path test-artifacts\windows\<时间>\* -Pattern $env:USERNAME -SimpleMatch | Measure-Object
```

同时确认 `summary.json` 里的 `crlfFiles` 为 0，并记下 `npm test` 的总数、通过、失败、跳过数字。

### Q6 简短回归（两位都做）

- 关闭会话：运行 `ping -t 127.0.0.1` 不中断直接关闭，以及“复制会话”产生的会话，各 1 次。预期约 6 秒内变为“已关闭”，无残留。
- CloakBrowser 与 Camoufox 各启动 1 个环境，确认出口 IP 与时区正确。
- 导出 1 个环境再导入。
- BrowseForge Chromium 仍显示“当前平台不可用”。

## 4. 交回内容

与第 3 轮相同：每次收集运行生成的 `test-artifacts\windows\<时间>.zip`，加按下面模板写的报告。发送前检查没有账号名、密码、代理地址或私人文件，截图中的出口 IP 和本机路径请打码。文件名带上“甲/乙”和日期。

### 报告模板

```markdown
# Envara Windows 第 4 轮测试报告（同事甲/乙）

- 测试人 / 日期 / 用时：
- 提交（git log -1 --oneline）：
- 系统版本 / 实机型号 / 显示缩放：
- Node / npm / Go 版本：
- 代理：系统代理 开/关（PAC 是/否）；HTTP(S)_PROXY 环境变量 有/无

| 编号 | 结果 | 说明（现象、次数、耗时、截图/日志位置） |
| --- | --- | --- |
| Q1 | | 1 取消 / 2 结束并退出（耗时、残留）/ 3 无任务 / 4 多窗口 / 5 英文 / 6 浏览器（仅记录） |
| Q2 | | 错误密码 / 正确密码 / 错误端口 / HTTPS / SOCKS5 |
| Q3 | | cmd.exe 的命令行、创建时间、出现时机；有无“错误”或“关闭中”的旧会话 |
| Q4 | | |
| Q5 | | 用户名命中数；crlfFiles；npm test 总数 / 通过 / 失败 / 跳过 / 取消 |
| Q6 | | |

## 新发现的问题（按严重程度）

1. 现象 / 复现步骤 / 预期 / 实际 / 日志与截图

## 未测与原因
```
