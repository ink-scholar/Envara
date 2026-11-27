# Windows 终端网络隔离：可行性验证与方案

状态：可行性验证（2026-11-27，Windows 11 Pro 10.0.28000 实机）。**尚未实现**，Windows 终端仍按“仅支持代理配置的命令行工具生效”显示，Claude 会话继续拒绝。

目标（2026-11-27 确认）：在 Windows 上，让 Claude Code 在独立环境中运行，全部流量走远程代理，不出现 DNS、WebRTC 等泄漏。**选定方向：WSL2 + 每个环境一个 Linux 网络命名空间 + Mihomo TUN（见第 8 节）。**

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

## 8. 选定方案：WSL2 + 网络命名空间 + Mihomo TUN（实测）

Claude Code 官方支持 Linux。在 Envara 自己的 WSL2 发行版里，每个环境一个网络命名空间，其中只有 loopback 和一张 TUN 网卡；Mihomo 以 TUN 模式接管全部流量，转发到该环境的路由。命名空间里没有任何直连出口。

```
Envara 终端 ──wsl.exe──▶ Envara 专用发行版（关闭 Windows interop）
   命名空间（只有 lo + envtun0）
     ├─ Mihomo TUN：TCP → 路由；UDP → 拒绝；DNS → fake-ip，由远端解析
     ├─ 127.0.0.1:1080 中继 ──Unix 套接字（跨命名空间）──▶ 宿主侧路由
     └─ Claude Code、git、curl……
```

验证脚本在 `native/windows-terminal-fence/wsl-spike/`（`setup.sh` 准备 Alpine 3.24.4 + Mihomo v1.19.32，两者都校验了 SHA-256；`spike.sh` 建立命名空间并逐项测试）。测试用的发行版事后已注销。

| 检查 | 结果 |
|---|---|
| 不设任何代理变量时的出口 IP | 与路由出口一致 |
| 直接连 IP（1.1.1.1） | 仍经路由（Mihomo：`match Match using route`） |
| 直接向 8.8.8.8 发 DNS（UDP、TCP）、系统解析器 | 全部由 Mihomo 返回 fake-ip（198.18.x）；命名空间外**没有任何 53 端口报文**，测试用的唯一域名在外部抓包中出现 0 次 |
| 命名空间用过的域名（api.ipify.org、github.com、claude.ai、downloads.claude.ai、api.anthropic.com）出现在外部 DNS 中 | 0 次 |
| UDP / STUN（WebRTC 的探测方式） | 显式拒绝（`Network(udp) using REJECT`） |
| IPv6 | 不通 |
| 调用 Windows 程序（interop） | 失败，没有执行 |
| git clone | ✅ 经路由 |
| Claude Code 安装和运行 | ✅ `2.1.332 (Claude Code)`；下载与 API 都经路由 |

实测中发现的要点：

- WSL 的 `.wslconfig` 若开启“继承 Windows 代理”，会给所有 WSL 进程注入 `http_proxy=127.0.0.1:…`。命名空间里这个地址不存在，工具会直接失败（不泄漏，但不可用）。Envara 必须自己控制终端的环境变量。
- 没有显式拒绝时，Mihomo 对 HTTP 上游无法转发的 UDP 会回落到 DIRECT（因为没有路由才失败）。规则里必须写 `NETWORK,udp,REJECT`，不能依赖“没有路由”。如果节点支持 UDP，可以改为经节点转发。
- WSL2 的所有发行版共用一个虚拟机网络。命名空间可以与用户已有的发行版完全隔离，但宿主侧的中继只能绑定在 Unix 套接字上，不能监听 TCP 端口。

### 实测二：Windows 文件夹与 Windows↔发行版通道（2026-11-27，yyb）

脚本：`setup2.sh`、`files-spike.sh` + `files-inner.sh` + `bench_fs.py`、`channel-host.mjs` + `channel-agent.py` + `channel-spike.sh`、`rtt-host.mjs` + `rtt-agent.py`。测试发行版 `EnvaraSpike2`（Alpine，关闭 automount 和 interop）事后已注销。yyb 为 mirrored 网络模式。

**Windows 文件夹**：发行版关闭 automount 后没有任何 drvfs 挂载。root 在环境的网络 + 挂载命名空间里执行 `mount -t drvfs 'C:\…\work 空格 中文' /work -o metadata,uid=1000,gid=1000,umask=022`，shell 以非 root 的 `env` 账户运行。

| 检查 | 结果 |
|---|---|
| interop 关闭时挂载 drvfs（路径含空格和中文） | ✅ |
| 读 Windows 写的文件、写 UTF-8 文件后 Windows 读取 | ✅ 双向正常 |
| 可执行位（`metadata`），重新挂载后 | ✅ 755 保留，脚本可运行 |
| 挂载是否泄漏到发行版根命名空间 | 没有 |
| `env` 自己挂载 `C:\` | 拒绝（permission denied） |
| `env` 在新的用户命名空间里挂载 `C:\` | 拒绝（No such device，9p 不允许用户命名空间挂载） |
| `env` 经 `/proc/1/root` 读发行版根 | 拒绝 |
| 命名空间内的网络 | 无（文件走 9P，不经网络栈，不影响隔离） |
| inotify：Linux 侧写入 | ✅ 有事件 |
| inotify：Windows 侧写入 | ❌ 没有事件（watch 和热更新需改用轮询） |
| 大小写 | 不区分：`Case.txt` 与 `case.txt` 是同一个文件，Linux 新建的目录也一样（`case=dir` 选项未测） |
| 符号链接 | Linux 侧可用；Windows 侧看到的是 WSL 重解析点，Windows 程序不能跟随 |
| 1000 个小文件：创建 / 遍历 / git add+commit / git status | drvfs 2775 / 1396 / 7716 / 684 ms；ext4 99 / 5 / 42 / 17 ms |

结论：挂载用户选定的 Windows 文件夹可行，隔离成立，前提是 shell 不是 root。性能比 ext4 慢 30–40 倍，Windows 侧改动不触发 inotify。默认把项目放在环境家目录（ext4），Windows 文件夹作为显式选项并提示这两点。Windows 侧通过 `\\wsl.localhost\<发行版>\…` 访问家目录。

**Windows↔发行版通道**：WSL2 不支持跨 Windows/Linux 的 AF_UNIX；验证一用的是 mirrored 模式下的 Windows 回环 TCP，NAT 模式下不成立，也需要在宿主侧监听端口。改为由 Envara 主进程以管道启动 `wsl.exe -d <发行版> -- <agent>`，在它的 stdin/stdout 上做多路复用：发行版内的 agent 在 `/run/envara/*.sock` 上接受连接，以 OPEN（带套接字名）/ DATA / CLOSE 帧转给 Windows 侧，由 Windows 侧决定每个名字能连到哪里。全程不监听任何 TCP 端口，与 WSL 网络模式无关。

| 检查 | 结果 |
|---|---|
| wsl.exe 管道往返延迟（1 B–64 KB） | 中位数 0.3–0.7 ms |
| wsl.exe 管道吞吐（100 MB 往返回显） | 477 MB/s |
| 多路复用后单向吞吐（200 MB） | 164 MB/s |
| 命名空间 → Mihomo TUN → 通道 → Windows → 路由：出口 IP | 与路由一致 |
| HTTPS 延迟、8 路并发、20 MB 下载、5 MB 上传、git clone | ✅ 与直连路由相同（瓶颈在路由本身：下载 612 KB/s，直连 618 KB/s） |
| Windows 侧结束 wsl.exe 后，发行版里的进程 | 随之退出 |
| agent 的 stdin 结束（Envara 退出） | agent 退出，环境失去唯一出口，天然断网 |

同一条通道可以承载路由中继、MCP 浏览器 broker、SSH broker 和链接通道，各自用一个套接字名。验证用的多路复用没有逐流流控，一条慢流会拖住其他流；产品实现需要逐流窗口。

### 落地需要的工作

1. 发行版：随 Envara 提供一个最小 rootfs（带校验），首次使用时 `wsl --import` 为 Envara 专用发行版；关闭 interop 和 Windows PATH；卸载时注销。用户需要先装好 WSL2（首次需要管理员，可能要重启）。
2. 命名空间管理：每个环境一个命名空间，启动或关闭终端时创建和清理；`/etc/netns/<ns>/resolv.conf` 指向 fake-ip；所有进程不继承代理变量。
3. 路由：命名空间内的中继经 Unix 套接字和 wsl.exe stdio 通道（见实测二）接到该环境已有的认证路由（Mihomo 节点），不经过用户自己的代理客户端。通道需要逐流流控。
4. 文件：用挂载命名空间只暴露该环境的家目录和用户显式选择的 Windows 文件夹（drvfs，`metadata`），不暴露 Windows 用户目录和 SSH 私钥；shell 不能以 root 运行。界面提示 Windows 文件夹较慢、Windows 侧改动不触发文件监听。
4a. SSH：命名空间里的 OpenSSH 沿用 macOS 的 broker 模型（ProxyCommand / askpass 经通道交给主进程），凭据留在 Windows 主进程。
5. 终端：Envara 终端通过 `wsl.exe -d <发行版> --` 启动命名空间内的 shell（node-pty 可以直接运行 wsl.exe）；Claude Code 安装在环境自己的家目录。
6. 链接和浏览器：Claude 的登录和浏览器操作经已有的 MCP broker 交给 Envara 浏览器，需要一条从命名空间到宿主的专用通道（同样可以用 Unix 套接字）。浏览器侧的 WebRTC 由 Envara 浏览器内核的策略负责，需要单独核实。
7. 失败处理：Mihomo、中继或命名空间任何一个缺失时都必须断网（命名空间里没有其他出口，所以天然断网），并在终端里明确提示。
