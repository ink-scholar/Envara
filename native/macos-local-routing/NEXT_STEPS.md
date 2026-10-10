# 可以实际落地的三个补齐方向

本目录的诊断接口已经可供既有、唯一的 capture 使用。先把明确 PID、UDP 与上游失联矩阵验收做好，再扩大到 Notion。该步骤不需要重新安装、申请签名或开启第二个 capture。

## 冷启动：同 PID 预 exec 探针

原版 control 没有 ACK，写 scope 后不能立即启动应用。可在应用尚未执行前使用 owned launcher seed：

1. controller 创建仅等待私有 IPC 的 seed，读真实 PID/birth，把这个精确 PID 写入 scope。seed 此时没有应用状态或用户网络请求。
2. seed 重试连接一个 controller 所有的、无外网副作用的探针端点。只有通过真实原版 signed peer、正确 PID/birth 到达 bridge 的探针，才给带 nonce 的响应。仅由 seed 实际收到 nonce 回包和 controller 同时观察到对应 signed flow 形成 witness；timer、control write 和普通 TCP connect 均不能形成 witness。
3. witness 之后在同一 PID 执行 `execve` 到用户明确选择的应用，并验证 PID/birth 未变、实际路径已变为预选 executable。scope 的 PID 匹配继续有效；controller 需增加只允许 owned seed→预选路径的单向交接状态，不能让任意 caller 改绑定路径。
4. 在 kernel guard 未到位前仍不能转为 production launch。guard 必须从 seed 创建前覆盖该 owned 家族，挡住探针期间或 exec 后 provider/control 失效的 direct 路径；新增 child 也要先被 guard 拦住再绑定。

本机 Node v23.11.0 已提供 `process.execve`。对 owned Node→`/bin/sleep` 的实际试验确认 PID 和 proc start birth 保持相同、路径实际改变、没有网络操作。生产发行可把这一原语放入本项目自己的小型原生 launcher，避免依赖 Electron 是否暴露 Node execve。该 seed witness 是可实测的替代启动屏障；它没有给原版 wire protocol 增加 ACK，也不表示所有未覆盖的后代已经受保护。

原版 provider 缓存 source process path。exec 之后必须实际验证其报告的路径是否更新；若 audit token 未变而缓存仍是 seed 路径，只能为这条已核验的 owned seed→预选 executable 交接使用 native PID/birth/实际路径作为依据，不能泛化为忽略其他 flow 的路径匹配。该交接目前仍是方案，尚未实现或完成原生验收。

探针端点应由 bridge 内部仅在 seed/probing 状态识别，并要求 nonce 与该 birth/route 匹配。它不能成为普通应用绕过 managed SOCKS 的通道。若选用 documentation IP，应在 bridge 内部响应、不给实际代理 core 转发该 IP；未捕获的 SYN 没有探针服务响应，也不能继续 exec。

## 半关闭：源端修复并由原签名发行者重新签名

v0.12.11 的 `FlowExtensions.swift` 在 outbound EOF 后立即 `conn.cancel()` 并关闭应用的读写两侧。当前 upstream main 仍保留该逻辑；截至本次读取，最新 release tag 仍是 v0.12.11。Node bridge 自身保留半关闭的测试已经通过，但不能在 Unix peer 已被原版 provider 取消后恢复应用的 flow。

可落地的源端修复是为每条 TCP flow 保存两个方向的完成状态：outbound EOF 仅关闭该方向、继续接收入站；inbound EOF 关闭写方向；只有两侧结束或致命错误才 cancel。同步加入 control/settings/scope 序号 ACK：setTunnelNetworkSettings 成功且 scope 已应用后发 ACK，controller 按该 capture epoch+scope sequence 匹配。

这些 Swift 改动需要原版发行者用已有 Team 签名发布更新版本，或者 Envara 在有自己的 Apple 分发身份后发行自有 provider。可先准备源补丁和本地测试，不修改现有 app、不伪造签名。获得实际签名 artifact 后更新 dependency lock 的 commit、版本、双架构 hash/CDHash，再跑现有 normal/half-close/native matrix。该路线复用已有系统扩展技术与实际可编译代码；今天仍保留 half-close 未验收状态。

## DNS：已实现受认证转发，继续系统 resolver 与双环境验收

`native-matrix.json` 的真实 Mac 观察已确认 owned 父、子进程的系统 getaddrinfo 分别产生可归属其 PID/birth/path 的 signed UDP53 flow；当时仅采样并关闭，所以两个 resolver 均超时。这一步没有把整个 mDNSResponder 统一代理，也没有读取用户 DNS 设置或修改现有 TUN。

现有 `dns-wire.mjs`、`dns-doh.mjs` 和 bridge 已实现端口53的 UDP IPC/TCP 长度前缀→独立 route 认证 SOCKS→固定 numeric bootstrap 严格 TLS DoH→匹配 transaction/question 完整回答。UDP 超限时产生完整 TC reply，TCP fallback 保留完整 answer；EDNS truncated reply 保留 OPT/extended RCODE/DO。DoH 不解密应用 TLS、不安装 CA、不更改 host DNS，也不修改原版 provider。默认 diagnosticDnsForwarding=false，trusted in-process 验收可用 setDiagnosticOptions 开启；RPC 不开放诊断/activation。

22 组当前本地测试已包括两环境 DNS 回答、UDP/TCP、TC→TCP fallback、类型/压缩/EDNS 边界、严格证书与 hostname、拒绝重定向/错 ID、deadline、取消与撤销。下一步由唯一 capture 的 native 验收使用两个独立认证 SOCKS 和本地 DoH fixture，父、子进程分别 system lookup 同一个随机无用户数据域名，确认 route A/B 得到各自 reserved answer，signed event 与本地 DoH fixture 均匹配。`diagnostic-child` 提供 expectedAddress4/6 的布尔全集匹配；禁止把查询名和答案写入报告。

必须继续验收系统 cache/coalescing、IPv4/IPv6、A/AAAA、TCP fallback、并发 query、退出与 route 撤销。即便该 native fixture 通过，也不能自动把正式 DNS gate 标绿；Notion/Electron 整个进程族、未知后代、cold-start scope barrier、整个 broker 崩溃和未选中应用仍须完成。若系统 lookup 的 originating identity 不完整或系统缓存跨 route 混合，应保留 DNS 门槛并修复实际平台边界；仅让 TCP 应用流经过代理不能替代这项证据。
