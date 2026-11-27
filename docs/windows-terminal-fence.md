# Windows 终端网络隔离：可行性验证与方案

状态：可行性验证（2026-11-27，Windows 11 Pro 10.0.28000 实机）。**尚未实现**，Windows 终端仍按“仅支持代理配置的命令行工具生效”显示，Claude 会话继续拒绝。

## 1. 要达到什么（对照 macOS）

macOS 用 Seatbelt 把终端整个进程树放进沙箱（`electron/terminal-network-fence.mjs`）：

1. 除 loopback 外的出站连接全部拒绝；环境自己的认证路由就在 loopback 上。
2. loopback 里再拒绝宿主常见代理客户端端口（Clash 7890/7897 等）和本地 DNS，防止绕到宿主代理。
3. 系统 DNS 解析不可用，外部域名只在路由远端解析。
4. 可选：拒绝读取设备序列号、平台 UUID。
5. SSH 私钥不可读写，只放行指定 agent。
6. 其余文件照常读写，项目和已安装工具都可用。
7. 不需要管理员，不改系统；子进程全部继承限制。

## 2. 验证的方案：AppContainer

验证程序在 `native/windows-terminal-fence/spike/`（Go，无第三方依赖）：创建一个**不带任何能力**的 AppContainer，在里面运行命令；另外可以起一个命名管道，ACL 只放行该容器的 SID。验证时用的容器、目录授权和回环豁免都已清理。

| 需求 | 结果 | 说明 |
|---|---|---|
| 1. 断开外网 | ✅ | `https://example.com`、`http://1.1.1.1` 都连不上 |
| 1. 连到环境路由（宿主 loopback） | ⚠️ 默认不行 | 容器连不上宿主进程监听的 127.0.0.1 端口；加管理员回环豁免（`CheckNetIsolation LoopbackExempt`）后能连，但见第 2 行 |
| 2. 封宿主代理端口 | ✅ 不豁免时 / ❌ 豁免后 | 不豁免时 Clash 7897 连不上；豁免后整个 loopback 放开，7897 也能连（返回 200），无法按端口细分 |
| 同一容器内的 loopback | ✅ | 容器内进程监听 127.0.0.1，同容器的另一个进程能连；**其他容器和宿主都连不上** |
| 容器 → 宿主的命名管道 | ✅ | ACL 只放行该容器 SID 的管道：本容器能双向通信，另一个容器被拒绝；**不需要管理员** |
| 3. 系统 DNS | ✅ | `[Net.Dns]` 解析失败，`nslookup` 超时 |
| 4. 设备标识 | 部分 | WMI/CIM（主板 UUID、BIOS 序列号）被拒绝；注册表 `MachineGuid` 仍可读 |
| 5. 私钥和用户文件 | ✅ | 未授权的用户文件、`Documents` 都读不到 |
| 6. 项目目录 | 需授权 | 默认不可写；用 `icacls` 给该目录加容器 SID 的修改权限后可读写 |
| 6. 常用工具 | ⚠️ 部分 | cmd、PowerShell 5.1、curl、tar、便携 node 可用；**Git for Windows / Git Bash / 所有 MSYS2 程序不可用**（MSYS2 运行时要在 `\BaseNamedObjects` 建对象，被拒绝 0xC0000022；`git.exe` 报 `open /dev/null or dup failed`）；**`NUL` 设备不可访问**（`> nul`、`2>nul` 失败） |
| 7. 不需要管理员 | ✅（按下面的架构） | 创建容器、目录授权、命名管道都不需要管理员 |

注意：验证进程是以管理员（高完整性，UAC 关闭）启动的。普通用户、开启 UAC 的机器上需要复测，文件和设备访问的结果可能不同。

## 3. 不需要管理员的架构（AppContainer + 容器内中继）

```
终端进程树（AppContainer，无网络能力）
  └─ 工具通过 HTTP_PROXY=127.0.0.1:<端口> 连接
        └─ 容器内中继（同一 AppContainer，监听 loopback）
              └─ 命名管道（ACL 只放行该容器 SID）
                    └─ Envara 主进程 → 该环境已有的认证路由 → 远端出口
```

- 每个环境一个 AppContainer（名称由环境 ID 派生），环境之间互不可达。
- 外网、系统 DNS、宿主代理端口、其他环境的容器全部不可达，不依赖防火墙规则，失败时就是断网。
- 终端需要用自己的启动器创建进程（node-pty 不支持 AppContainer 属性）：在 `CreateProcess` 时同时带上 `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` 和 `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`。

## 4. 主要障碍

1. **Git for Windows 与 MSYS2 不可用**。对开发终端来说这一条最严重，可能使 AppContainer 不适合作为默认终端。
2. **`NUL` 设备不可访问**，大量批处理和工具的输出重定向会失败。
3. 项目目录要给容器 SID 加访问权限，相当于修改用户文件的 ACL；用户级安装的工具（`%LOCALAPPDATA%\Programs` 下的 Python、Node 等）也要授权才能用。
4. 设备标识只限制了一部分（`MachineGuid` 可读）。

## 5. 交互终端复测（ConPTY）

验证程序的 `conpty` 模式通过伪控制台交互运行 `cmd.exe`（与 Envara 终端相同），同一组命令先在容器外跑一遍作对照：

| 命令 | 容器外 | AppContainer 内 |
|---|---|---|
| `echo x> nul`、`type nul` | ✅ | ❌ 拒绝访问 |
| `git --version`、`git init` | ✅ | ❌ `CreateNamedPipe failed: Permission denied` |
| Git Bash | ✅ | ❌ MSYS2 `NtCreateDirectoryObject` 0xC0000022 |
| curl 外网 | ✅ 200 | ✅ 被阻断（000） |

结论：Git 和 `NUL` 的问题与 stdio 方式无关，是 AppContainer 本身造成的。Claude Code 在 Windows 上依赖 Git for Windows 的 bash，所以 **AppContainer 不能承载 Claude 会话**。

## 6. 备选：专用本地账户（实测）

临时建了一个本地账户，以它的身份运行终端（测完已删除账户、配置文件目录和规则）：

- **兼容性**：✅ Git、Git Bash、`NUL` 都正常（就是普通用户会话）。
- **启动方式**：❌ `CreateProcessWithLogonW` 和 `LogonUser` + `CreateProcessWithTokenW` 都不接受伪控制台属性（“参数错误”），不带伪控制台时可以启动。能带伪控制台的 `CreateProcessAsUser` 需要通常只有 SYSTEM 服务才有的特权。可行的做法是先以该账户启动 Envara 自己的小助手（不带伪控制台），由助手在自己的身份下创建伪控制台和 shell，再通过限定该账户的命名管道和 Envara 交换输入输出。
- **网络**：Windows 防火墙规则（`New-NetFirewallRule -LocalUser`）在这台机器上**完全不生效**，因为它的专用和公用防火墙配置文件是关着的。基于防火墙规则的隔离会在用户关闭防火墙后悄悄失效，所以只能直接用 WFP 过滤器（不受防火墙开关影响，需要原生代码和管理员安装）。
- **DNS**：系统 DNS 解析由 Windows 的 DNS Client 服务以它自己的身份完成，按用户过滤的规则拦不到，查询的域名会走宿主网络泄漏出去。要堵住还需要额外设计。
- **本地代理端口**：Windows 防火墙不过滤 loopback；要拦宿主的 Clash 等端口，必须用 WFP 的 loopback 条件。

## 7. 结论与选项

Windows 上没有像 macOS Seatbelt 那样“不要管理员、兼容性好、一次满足全部要求”的机制：

| 方案 | 网络要求 | 兼容性 | 管理员 | 能否承载 Claude |
|---|---|---|---|---|
| 维持现状（不隔离） | ❌ 只有遵守代理变量的工具走环境网络 | ✅ | 不需要 | 否（继续拒绝） |
| AppContainer + 容器内中继 | ✅ 全部满足（设备标识部分） | ❌ 无 Git、MSYS2、`NUL` | 不需要 | 否 |
| 专用账户 + 自有 WFP 过滤器 + 账户内助手 | ⚠️ 外网和 loopback 端口可控，DNS 泄漏待解决 | ✅ | 安装时需要（建账户、WFP、凭据保管） | 有可能，工作量大 |

可选路线：

1. 维持现状，在文档和界面里写清楚。
2. 把 AppContainer 做成环境可选的“严格隔离（不含 Git）”模式，适合只跑 curl、node、PowerShell 的环境；不解决 Claude。
3. 投入“专用账户 + WFP”路线（独立设计和安装器、DNS 泄漏方案、卸载清理），这是 Windows 上运行 Claude 的前提。
