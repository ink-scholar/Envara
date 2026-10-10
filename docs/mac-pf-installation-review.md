# macOS PF 组件安装与受控测试

日期：2026-10-08。当前为本地开发组件，已按用户明确授权安装，网络未激活，附加软件保护启动仍关闭。

非 Network Extension 路线使用独立进程 GID、Envara 自有 utun 和 PF anchor，将所选进程连接到 Envara 管理的认证 SOCKS 路线。该路线不要求 Apple Developer 身份；系统安装及 PF 操作需要本机管理员授权。

## 已准备资源

- 固定目标：`/Library/PrivilegedHelperTools/io.envara.pf-routing`。
- 资源约 189 MiB（198,198,551 bytes），13 个运行资源及 manifest；包括官方 Node 24.18.0、未修改的 Mihomo v1.19.32、对应源码与许可、自有原生组件和专用验收程序。
- 已安装 manifest SHA-256：`f8fce1d14566fdf822d220ef1a3469cbb815a37924c7ed709a1098729b8bed8b`。
- 对应安装器 SHA-256：`f0966e23979e8a6ef45b4cb0594d46030de19e19d2d6f3e6b3fc7a02efe4c108`。
- 此安装快照的资源、编译输入和专用验收程序核验通过；完整本地 App 包为 54 项 archive 文件、199 项资源文件、56 个目录、无 symlink。后续源码修复不自动改变这个已安装快照。

## 授权操作范围

安装仅复制这些固定资源为 root 所有，验证哈希并原子提交；不会加载 PF、创建组或隧道、启动后台常驻服务、运行用户软件。

另外一次有界测试通过原生管理员授权入口启动，最多 180 秒、2 个专用组和 2 个自有 utun，仅写入 `com.apple/envara.pf.v1`。使用两个本地认证 SOCKS 测试端点和自有验收进程，测试进程身份、并行 TCP、TCP 半关闭、并行 UDP、TCP 53。不会启动 Notion、改主机 DNS、默认路由、时区或现有 VPN 设置。测试后检查所属进程、隧道、组及 anchor 清理，并比较主机 PF、IPv4/IPv6 路由与 DNS 配置。

安装器使用已弃用的系统 Authorization API，本地引导程序由用户目录启动，API 不提供现代签名 helper 的身份绑定保证；这不是可发布的长期后台服务部署方案。详细边界见 [安装协议](../native/macos-pf-routing/INSTALLATION_CONTRACT.md)。

## 已实际执行

用户确认“允许安装并测试”。开发资源路径中的安装器在 `AuthorizationCreate` 返回 `-60008`；完整 App 包内的逐字节相同程序完成原生授权，`AuthorizationExecuteWithPrivileges` 返回 0，安装报告 `installed=true`、`changed=true`。具体路径差异的系统原因尚未确认，不能归因于缺少 Apple 账号。

安装后 root 所有权及 13 个资源哈希均通过。独立原生授权的持续 RPC 确认 root runtime、console UID 和授权有效；但五项试验在系统前置检查被拒绝，`nativeRoutingAttempted=false`。实际 root 状态中 `stockAppleAnchorHookVerified=false`，其他受控前置满足；没有创建系统组、utun、PF 规则或启动用户软件。通道正常关闭且清理未标记不确定。

本机 `/etc/pf.conf` 注释 Apple anchors，并配置 Sangfor anchors；实际 root 检查也确认缺少 Apple 入口。不能通过重载系统规则或借用 Sangfor 命名空间掩盖该前置。独立只读 ABI 检查已实际通过：读取与原版 `pfctl` 的 7 条 root 规则全部匹配，revision 稳定。随后按补充授权，在 PF 已禁用时添加、核对并精确删除一个空的 `io.envara.pf.root.v1` 自有入口，实验通过；原有规则、DNS、路由、NAT 和配置文件前后哈希一致。见 [单个空入口验证](mac-pf-root-canary-review.md)。这仍不证明流量分流通过，也不授权直接启动 Notion。

## 尚未通过的生产门槛

上述五项实验即使通过，也不代表普通桌面软件已具备完整保护。系统 DNS 的独立归属、外部辅助进程、IPv6／原始协议、整个守护进程崩溃、utun 名称复用和已有 PF 状态处理仍需实现及真实验证。未经这些验证不会开放受保护软件启动。GitHub 推送及发布继续暂停。
