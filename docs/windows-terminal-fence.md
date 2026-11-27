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

## 5. 备选：专用本地账户 + WFP

终端以一个专用的 Windows 本地账户运行，用 WFP 按该账户的 SID 过滤：只允许连 Envara 的中继端口，其余出站和 DNS 一律拒绝。

- 优点：普通用户会话，Git、MSYS2、`NUL` 都正常；规则可以精确到端口。
- 代价：需要管理员创建账户和 WFP 规则（持久规则也要在卸载时清理）；用另一账户启动进程要保存它的凭据；项目目录同样要给该账户授权；宿主 GUI 交互受限。

## 6. 建议的下一步

1. 用 ConPTY 在 AppContainer 里跑一个真正的交互终端，复测 git、`NUL` 和输入输出。如果 `NUL` 和 git 的问题只出在管道式 stdio 上，结论会大不相同。
2. 在普通用户、开启 UAC 的环境下复测第 2 节。
3. 对“专用账户 + WFP”做同样的验证，对比兼容性和权限代价。
4. 根据结果再决定：默认方案、是否作为每个环境可选的“严格隔离”，或两者结合。
