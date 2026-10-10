# Notion 启动失败交接 · 2026-10-10

Envara 的 macOS Notion 试运行仍未通过真实启动、网络出口及清理验收。当前采用 PF、专用凭据组及自有 utun 的非 Network Extension 路径，执行范围为 `seatbelt-front-only`。`ready`、`protected`、`productionReady`、`genericApplicationRouting`、`udpSupported` 均为 `false`；请勿把已编译、安装或诊断测试通过解释为实际接管成功。

本文只包含经核对的安全诊断和源码指针；不包含节点、凭据、个人路径或现场运行标识。行号对应本次交接时的源码，后续修改需重新核对。

## 本次已确认的失败

导出的安全诊断显示：

```json
{
  "initialFailure": {
    "stage": "cold-stage",
    "code": "APPLICATION_APP_NATIVE_REFUSED",
    "native": {
      "stage": "guardian",
      "reason": "NATIVE_NOTION_STAGE_REFUSED",
      "error": 13
    }
  },
  "phase": "cleanup-required",
  "staged": false,
  "resumed": false,
  "cleanupComplete": false,
  "cleanupUncertain": true
}
```

事件为 `verifying → authorizing → preparing → failed → stopping → cleanup-required`。没有成功的 `staged`、`resuming` 或 `running` 事件，尚无 Notion 成功执行或专用出口证据。

| RPC | 实际耗时 | 结果 |
| --- | ---: | --- |
| `status` | 7,091 ms | result |
| `prepareRoute` | 38 ms | result |
| `prepareNotionApplication` | 36,379 ms | error |
| `stopNotionApplication` | 15,782 ms | error |
| `applicationSnapshot` | 2 ms | result |

导出中的 `stdoutEOF=false`、`terminalExitCode=null`、`terminalExitSignal=null` 表示这份记录没有取得完整通道终态；不能据此认定进程已退出，也不能认定它必然仍在运行。

## 首次错误已细化，内部拒绝条件还没有证据

1. [`app-native-factory.m:609–614`](../native/macos-pf-routing/app-native-factory.m#L609) 在 `envara_notion_stage()` 返回时立即保存错误数值，给出 `NATIVE_NOTION_STAGE_REFUSED`。
2. [`app-transport.c:933–940`](../native/macos-pf-routing/app-transport.c#L933) 在 supervisor 返回后、结束 relay 前保留首次 reason/error，将外层阶段标为 `guardian`。
3. [`notion-launch.m:231–263`](../native/macos-pf-routing/notion-launch.m#L231) 是下一步定位入口。它包含权限/authority 条件、固定执行路径及 root chain、GUI/audit session、原实例检查、账户、数据目录、manifest、已提交 DENY 校验、挂起启动和停止阶段确认；其中多个不同条件会返回或映射到 `EACCES`。

目前仅确认失败落在这一层，没有记录是哪一个内部 predicate、系统调用或 spawn 返回值首先失败。`13` 是本次错误数值，不足以推断需要 Apple Developer 身份、重新签名，或再次授予管理员权限；也不能直接归因于代理节点。

## 清理独立原因仍被原始错误覆盖

导出里的 `cleanupFailure` 为 `stage=cleanup`、`code=APPLICATION_APP_NATIVE_REFUSED`，并重复上述 guardian reason/13；停止事件却显示 `APPLICATION_APP_CLEANUP_UNCONFIRMED`。末次 controller 快照也保存同一重复值，说明缺口在控制层，不仅在页面。

- [`controller.mjs:876–879`](../native/macos-pf-routing/controller.mjs#L876)：`transportError()` 选择 `entry.cleanupFailure ?? entry.failure`。没有新的清理 native 帧时，等待超时或通道污染仍可能包装为首次启动拒绝。
- [`controller.mjs:992–996`](../native/macos-pf-routing/controller.mjs#L992)：等待计时器写入 `entry.waitFailure` 后进入 `poison()`；上面的优先级会掩盖等待原因。
- [`controller.mjs:1063–1069`](../native/macos-pf-routing/controller.mjs#L1063)：S/R 清理 ACK 等待为 15 秒，且独立 timeout code 为 `null`。本次 stop 的 15,782 ms 接近这一期限，但现有记录无法证明具体是 S、R、验证拒绝还是新的 native 清理错误。
- [`controller.mjs:1973–1977`](../native/macos-pf-routing/controller.mjs#L1973)：catch 将这个包装后的错误记为 `cleanupFailure`。
- [`controller.mjs:247–252`](../native/macos-pf-routing/controller.mjs#L247)：清理 RPC 外抛仍附首次错误的 `failureStage/nativeFailure`；[`macos-pf-notion-trial.mjs:168–171`](../electron/macos-pf-notion-trial.mjs#L168) 从顶层 native 数据生成停止事件，可能混合“清理未确认”分类与首次启动原因。

不能把重复错误当作第二次相同原生拒绝的证明。应分别保存：首次启动失败、清理操作及独立失败、ACK 等待/验证结果、EOF/退出/协议污染原因。缺少证据的字段保持 unknown，不补推成功或失败。

## 建议修复顺序及验收边界

1. 为 `envara_notion_stage()` 内部检查增加固定枚举诊断，区分主动拒绝、即时 syscall errno 和函数直接返回码；保留首次失败，禁止记录任意文本、账户、私有路径或节点配置。
2. 修正上述清理错误优先级，明确记录 S/R、ACK deadline、ACK validation、EOF、进程退出和协议污染。同步 helper、session、trial、持久化及 UI 的严格白名单；不要用宽松正则接收未知 reason。
3. 核验合法拒绝后原 keeper 的 cleanup-only 链：S 停止、R 释放、自有 FILTER/journal、原 FD、child/后代、core/front、专属组、自有 PF reference/hook、lease/锁。只凭新鲜所有权证据继续未完成步骤，不重放未知 PF 事务，不靠接口名或 PID 单独认领资源。
4. 在安全投影内保存逐项结果，清理错误不可覆盖首次错误。诊断历史只能解释问题，不能授权清理、恢复启动或开启通用 protection；不要向被完整 stat 固定的 run 目录临时添加日志。
5. 通过有意义的失败注入和协议测试后，编译匹配的组件和桌面 App，保留现有网络配置及软件绑定，由用户手动附加 Notion 验收。测试应证明实际启动、专用出口、退出清理及节点断开后的阻断，并证明其他应用和主机 DNS/默认路由未被改变。

产品操作仍是“选择境舱/网络组 → 添加本地软件 → 启动”。浏览器、终端、附加软件复用建立网络环境时确认的位置和时区。不要为通过测试改成全局代理、代理环境变量、放宽权限、关闭安全门，或自动操作个人浏览器。不要在没有新的明确请求时启动 Windows 虚拟机；源码检查不代表 Windows 验收。

相关诊断链文件：`native/macos-pf-routing/helper.mjs`、`electron/macos-pf-notion-session.mjs`、`electron/macos-pf-notion-trial.mjs`、`electron/notion-diagnostics-store.mjs`、`src/notion-trial-state.mjs`、`src/workspace-pages.jsx`。现有无系统激活的组件/协议测试与真实原生接管验收必须分别报告。
