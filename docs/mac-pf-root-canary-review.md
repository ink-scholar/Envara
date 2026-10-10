# 单个空 PF 入口验证

日期：2026-10-08。本页只审阅一个独立实验，不开放附加软件启动。

此前授权允许安装固定网络资源并在 `com.apple/envara.pf.v1` 子 anchor 内测试。本机生效 root 规则没有 Apple anchor 调用，单独填充该子 anchor 无法接入。此实验增加一次新的 root 入口操作，需要补充授权。

## 固定操作

仅在本机 PF 已禁用、当前 macOS 和系统工具哈希匹配、原有 7 条规则全部匹配，以及 `io.envara.pf.root.v1` 自有名称不存在时继续：

1. 在原有规则末尾添加一个调用 `io.envara.pf.root.v1` 的空入口。固定 owner、每次唯一 label、`priority=UINT32_MAX`、`keep_state=0`；不往该入口填入规则。
2. 读取并验证本次添加返回的非零 64 位 ticket，以及对应 owner、label 和原有规则顺序。
3. 仅按本次 ticket、owner 和 label 删除这个入口，再检查原有规则、PF 禁用状态、IPv4/IPv6 路由、DNS、NAT 和配置文件保持一致。

不会启用或禁用 PF、重载或清空全局规则、调用状态清除接口、创建组或隧道、启动应用，或修改 VPN、DNS、默认路由及系统时区。管理员密码仅输入 macOS 原生授权弹窗。

## 边界

当前系统的只读读取已实际匹配 7 条 root 规则。当前 Apple `pfctl` 和 `pfd` 二进制为 label、owner、priority、ticket 及 INSERT/DELETE 请求提供了字段证据；这不能代替写入与回滚的实机验证。

独立候选已原生编译及严格签名结构校验，默认仅运行只读 plan；**6/6** 非提权检查通过，包含票据不匹配、外来 label、并发第 9 条规则保留、删除失败、读回失败、超时和信号后的精确清理反例。候选记录为 `test-artifacts/mac-pf-routing/root-canary-candidate.json`，二进制 SHA-256 为 `ffebcb9271b45621c00c5e89ecec1a7f9cdcf05f616bfbe37523422fb8e884e7`。

## 实际结果

用户补充确认“允许继续验证”后，2026-10-08 通过原生授权执行成功：INSERT 读回、精确 ticket DELETE、原有 root 规则恢复和主机配置检查均为 true，`cleanupPending=false`。PF 保持禁用，未创建组、隧道或运行应用。原有 7 条规则、DNS、IPv4/IPv6 路由、NAT 及 `/etc/pf.conf` 的前后哈希一致。完整回执在 `test-artifacts/mac-pf-routing/root-canary-native-20261008.json`。

如果返回 ticket 为零、读回不匹配或发生并发变化，程序不会按名称删除未知规则，会报告清理未确认。SIGKILL、系统崩溃或断电可能留下一个空的自有入口；它不会被此程序填入路由规则。测试不会声称保证所有现存 PF 状态不受内核内部维护影响：DELETE 的系统实现包含关联规则状态处理，程序只保证不发状态控制调用。

本实验通过也只证明本机空入口添加和精确删除，不证明流量分流、DNS 隔离、故障保护或 Notion 可用。完整应用保护继续保持 `ready=false`。GitHub 发布继续暂停。
