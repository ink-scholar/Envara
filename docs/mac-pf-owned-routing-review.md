# 自有 PF 入口与受控流量测试

当前实际安装为 `46ae6acddd4f…`。最新 Notion 运行 `90401ced-5d54-4422-b80c-c7c4485a037b` 通过受管 AnyTLS 的真实出口检查和签名应用登记，但在 factory-open 阶段拒绝，未进入应用规则写入、冷启动或恢复运行，Notion 没有启动。`cleanupConfirmed=false`；精确自有入口、PF 引用、组及私有记录的恢复仍需原生管理员检查。普通用户进程清单没有相关测试进程，不能据此确认完整系统清理。

实际解析器回归已验证 JSON 中斜杠转义造成 lease 拒绝；另外发现验证函数以 0 表示成功，调用方把成功当成失败。两项源码修复与停止流程传参修复已通过针对性检查，但没有替换当前系统安装。独立恢复工具只针对固定 46ae 组件和上述运行，未知状态必须拒绝；非交互请求入口直接返回不可用，不调用授权 API。用户已离开，本轮不再触发管理员弹窗，也不调用恢复的 root 入口。完整清理仍未确认，Notion 启动与断线保护仍未验收，附加软件生产启动继续关闭。

历史 6f8 夹具运行通过双环境身份、并发 TCP、TCP 半关闭、TCP 53 DNS、四进程各 2048 字节 UDP，以及未绑定 loopback 对照，并确认自有 namespace absent、进程／组／隧道／入口退出、原 PF／DNS／路由恢复。记录为 `owned-hook-retry-1791459449353-09535066-e5ee-45e5-b4ac-f06c2cb99497.json`。它不能证明最新 Notion 路径已通过。详细证据见 [验证记录](verification.md)。以下旧组件记录保留为历史。

此前启动前回收候选 `957e4157e491…` 已真实编译并完成包内资源核验，未系统安装或激活。factory-open 失败现在具备独立的 `prestage-aborted` 原生回执和 `prestage-cleaned` 控制器回收分支；只有精确原始资源、子进程、完整原生 GID 检查及实际退出均确认后才进入该分支。客户端要求绑定请求环境、停止回执及随后独立状态复查。7 项原生非提权夹具、126 项控制器／客户端／驱动回归及独立审阅通过；它不证明 Notion 成功启动，也没有清理已有 904 运行。

最新离线候选为 `c37c49f9ca94…`，位于 `release/mac-listenerfix-20261008/`。固定的一次性原生子进程在自有 realm GID 下创建监听 socket，再经绑定 nonce／lease／父进程出生身份的私有 FD 传递交给 keeper；keeper 本身的凭据保持不变。factory 再次检查实际内核 socket UID 0／realm GID，PF FRONT 在 lo0 入站新增精确凭据放行及其余凭据拒绝规则，同一事务共 5 条规则。发现并修复了真实 Darwin 控制消息截断造成的 FD 泄漏：11 种传递场景的实际 FD 数均为 4→4。冻结源码严格编译、243 项针对性检查和独立审阅通过。包内 73 项归档文件、205 项资源文件、56 个目录、18 项运行资源和 65 项原生源码输入核验通过，DMG／ZIP 完整性通过；构建、传递、包证据分别为 `notion-listener-identity-offline-build-20261008.json`、`notion-listener-transfer-fixture-20261008.json`、`notion-listener-package-hashes-and-resources-20261008.json`。尚未系统安装或激活，原生 root 正向凭据、实际 PF loopback、整个 guard 故障／同端口复用及 Notion 生命周期未验收；没有追溯清理旧 904 运行。

整个 guard 故障与同端口复用曾存在数值端口放行缺口；c37 已实现内核 socket 凭据保护的源码与固定规则模板，但尚未验证本机 PF_IN 查询／实际 loopback 行为。控制器报告 uncertain 不能等同内核撤销放行。后续先用自有客户端验证一次性 creator 的 root 正向凭据、原 socket 身份、keeper／front 故障与同端口复用，再考虑用户应用。现保持 protected=false，旧运行完整清理仍未确认。

## 已完成的实现

使用固定 `io.envara.pf.root.v1` 名称，根调用和子规则都由 Envara 管理，不依赖 Apple wildcard，也不借用 Sangfor 名称。只读状态报告入口是否具备创建条件；原有 `stockAppleAnchorHookVerified` 保留真实结果。

受控会话在私有锁和基线检查后添加入口，保存本次 INSERT 返回的精确 ticket、随机 label 和基线，再创建专用组、加载自有规则及打开自有 utun。执行前先安装组的拒绝规则，测试软件冷启动后只预约新 socket，再验证没有旧状态，最后通过认证 SOCKS 测试端点验证流量。

清理先让测试软件退出、关闭所属传输并清空自有规则，然后释放本次 PF 启用引用，按精确票据删除自有入口，并检查原有规则与网络配置。任何未确认的所有权、票据、状态或清理都报告失败并保留必要拒绝状态，不通过全局清空恢复。

## e940 历史测试结果

e940 更新成功，安装后全部 13 项运行资源的哈希与 root 所有权再次核验通过。真实受控请求在 0.218 秒内于 prepare 阶段返回 `APPLICATION_ROUTING_NOT_READY`，没有进入五项流量用例。旧版错误转换丢失了原生失败阶段，因此不能把候选源码问题直接认定为此次失败的已确认根因。

私有测试通道已关闭且未报告清理不确定。后续 root 只读状态显示未准备、未激活，自有入口不存在、原有入口兼容；非特权检查未发现自有组、测试程序或隧道进程。私有运行目录仍为 root `0700`，当前用户无法读取其内容，不能据目录大小或权限拒绝认定目录为空。旧实验的完整状态检查证据缺失，清理的完整验收判据未通过。

记录：`installed-owned-hook-final-20261008.json`、`owned-hook-native-1791430929646-41499c39-5c7a-4c0e-a623-c2bbfc1f1faf.json`、`post-owned-hook-status-20261008.json`，均位于 `test-artifacts/mac-pf-routing/`。

## e940 之后的修复与已批准复测范围

固定 Apple 源码的 `pf_anchor_setup` 将单组件、无前导斜线的根调用读回为 `anchor_relative=1`。候选修复将写入模板的 `0` 和读回校验的 `1` 分开，仍严格验证名称、所有权、票据和其余规则语义；DELETE 重新构造固定写入模板。8 项原生惰性 ioctl 测试通过，不是修复后系统分流通过的证据。[固定 Apple 源码](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/pf_ruleset.c#L466-L475)

失败诊断现在只映射固定原生错误白名单，并在清理结果中保存固定阶段；不会输出私有票据、凭据、请求或原始日志。安装器新增精确 e940 快照；私有运行目录无法读取时，计划明确要求管理员核查。root 安装器仍必须实际确认目录为空并在排他锁下重查，才允许写入。

最多 180 秒、两个专用组和两个自有 utun，仅运行 Envara 验收软件及本机认证 SOCKS 测试端点。五项为进程身份、并行 TCP、TCP 半关闭、并行 UDP、TCP 53。不启动 Notion，不修改现有 VPN、主机 DNS、默认路由或时区。PF 若原本禁用，只申请本次启用引用，结束时释放该引用；不直接禁用他人的 PF。

e940 测试在 prepare 阶段失败后，用户另行批准精确 e940 → 518 更新及一次复测；这一授权已经执行。后续网络激活不包含在该次批准内。

## e940 历史安装快照

当时已安装的 `e940e171…` 固定资源没有被后台替换；随后通过用户批准的原生授权升级到 518。518 安装器只允许精确已知 f8 和 e940 快照升级，核对全部旧文件和 root 元数据；未知安装、活动会话、未确认备份或冲突一律拒绝。新固定资源通过校验后原子交换，失败时仅回滚属于本次操作的对象。资源升级不激活网络或启动应用。

已安装 e940 manifest SHA-256：`e940e171ac39624cd3cfeaea09234f4e8e035bfba141a843950cb0209e00db04`。此前安装器 SHA-256：`a3725f403800797b51c805e6b085546c243a02d2fb55805949801812469fec53`。该版本 13 项运行资源、18 项原生编译输入、官方依赖哈希、平台架构及源码许可核验通过。修复候选还需重新核验 20 项编译输入和新的固定哈希。

e940 构建时相关源码回归 244/244 通过，包含原生接口、精确旧版本升级、控制器、验收流程、托管代理、多语言和授权载体；这不是五项实际分流通过的证据。记录见 `test-artifacts/mac-pf-routing/owned-hook-regression-final-20261008.log` 和 `owned-hook-build-final-verification-20261008.json`。

此前用于 e940 更新的原生授权入口：`build/local-authorization/EnvaraPFAuthorization-e940e171ac39.app/Contents/Resources/app-routing/macos-pf/EnvaraPFInstall`。独立载体只对其新 launcher 和外 App 作 ad-hoc 签名，不重签安装器或官方运行资源；严格签名验证和全部 15 个 payload 叶文件核对通过。更新前的历史只读计划为 `sourceVerified=true`、`existingInstallation=known-prior`、`requiresUpgradeApproval=true`、`canRequestInstall=true`、`controlledRuntimeAbsent=true`、`needsManualReview=false`、`ready=false`，不能代替本次实验后的运行目录核查。此前 967 候选计划错误地把 stock `/private/var/run` 的 0775 权限当作活动记录，未安装；e940 的当前运行记录改到独立的 `/Library/PrivilegedHelperTools/io.envara.pf-runtime`，旧路径仅检查存在性，任何旧条目或未知残留都拒绝，通用 root 目录权限检查没有放宽。历史载体证据为 `test-artifacts/mac-pf-routing/authorization-bundle-e940e171ac39.json`。

## 验收边界

五项通过仍不代表 Notion、系统 DNS、外部辅助进程、IPv6／原始协议、整个守护进程崩溃或 utun 名称复用已验收。不以模拟结果或安装成功替代真实流量证据。GitHub 发布继续暂停。

## 518a75d94bac 更新前核验

以下为更新前保存的核验记录。manifest SHA-256：`518a75d94bac4f17d9e1ce60e842648ba6ff657a68cc62e95ce13718abda6d5a`；安装器 SHA-256：`56ce6416e99042dba757b5138cc23f5276a2a4fae9e12015cdf133ca3c4c413c`。相关回归 **252/252** 通过，13 项运行资源、20 项编译输入、官方依赖和许可核验通过。

原生授权入口：`build/local-authorization/EnvaraPFAuthorization-518a75d94bac.app/Contents/Resources/app-routing/macos-pf/EnvaraPFInstall`。独立载体的严格签名及 15 项 payload 叶文件核对通过，安装器和官方运行二进制没有重签。实际只读计划识别精确 e940 旧安装：`sourceVerified=true`、`requiresUpgradeApproval=true`、`privateRuntimeInspectionRequired=true`、`canRequestAuthorizationForInspection=true`、`controlledRuntimeAbsent=false`、`needsManualReview=false`、`ready=false`。

批准范围为通过原生管理员授权检查私有目录，确认没有运行证据后将精确 e940 替换为本候选，再进行一次最多 180 秒的五项受控测试。仍只运行 Envara 自有验收程序，最多两组和两条自有隧道；不启动 Notion，不改 VPN、主机 DNS、默认路由或时区。若管理员检查发现任何残留，更新必须拒绝，不能自动删除证据。用户随后明确批准，实际结果记录如下。

核验记录：`owned-hook-normalization-build-verification-20261008.json`、`owned-hook-normalization-regression-20261008.log`、`authorization-bundle-518a75d94bac.json`，均位于 `test-artifacts/mac-pf-routing/`。

## 518a75d94bac 实际复测与清理核查

更新实际成功，13 项资源和 root 所有权再次验证通过。原生 prepare 已通过入口插入、专用组、隧道、测试进程和 socket 准备，在 `stateless-rules` 阶段 3.840 秒内被拒绝；五项流量用例未开始。失败阶段和完整清理回执已保存。

回执为 `cleanupUncertain=true`：进程、隧道和子规则报告已清理、PF 引用报告已释放，但根入口删除及原根恢复未确认。传输关闭返回的 `cleanupUncertain=false` 只是传输结果，不能覆盖实际清理回执。旧票据可能使状态检查看不到删除已提交后的原根，不能由失败默认值认定入口仍在。

非特权检查未发现自有进程和组，DNS 与网卡列表匹配测试前记录；完整路由表摘要不同，不能宣称无关路由已恢复。新通道请求不带旧票据的只读状态超时（`PF_HELPER_DEADLINE`），未获得新的 root 证明。当前暂停进一步激活，优先准备从受保护记录读取本次精确票据的专用只读检查器。未知记录不得自动删除，不按入口名称重新取得票据。

实际记录：`installed-normalization-20261008.json`、`installed-normalization-proof-20261008.json`、`owned-hook-retry-1791432070242-ce66bad5-d202-4024-a31d-dfa08e93cf5f.json`、`normalization-after-native-network-20261008.json`、`post-normalization-fresh-status-refused-20261008.json`，均位于 `test-artifacts/mac-pf-routing/`。Notion 与生产启动仍未验收，GitHub 发布继续暂停。

专用只读检查器已经实际编译，通过惰性解析与输出脱敏测试、严格签名检查；固定 MF、13 文件哈希、本次 run ID 和基线，不接受 caller 提供路径或命令。请求仅读取受保护记录、进程身份，以及不带票据和带私有票据的两次 `hook-status`。授权等待期间曾停在 `AuthorizationCopyRights`，随后用户完成系统授权，实际 root 检查成功。无旧票据证明确认 PF 禁用、原有 7 条 root 双指纹一致、旧入口不在、原有入口兼容；11 个记录 PID 双读不存在。固定密封登记仍为 `cleanup-required`，PF 引用记为已释放。`canCreate=false` 尚不能区分自有命名空间残留和读取错误，需六类 active／ghost tables／children 的只读诊断，不得再次 DELETE 旧票据。没有新的删除、激活或完整清理结论。核验、等待和实际报告分别为 `readonly-recovery-518-build.json`、`readonly-recovery-518-authorization-wait.json`、`readonly-recovery-518-native.json`。

后续 stateless 源码修复比较 PF 展开后的完整规则及顺序，替代原始行数与 label 计数。本机固定 `pfctl -n -v` 只解析样本确认四端口和双协议的展开输出；68 项控制器与校验器测试通过。当前安装仍是 518，修复未部署，实际流量验收仍未通过。

验收通道另已修复结果覆盖：成功 RPC 的不确定清理状态永久保留，关闭须匹配全部已观察 run 的完整原生清理证据。50 项验收及重试调用方回归通过。原生外层 relay 尚不提供完整 root 子进程终止回执；源码修复不等于本次清理成功。

下一版已经本机实际构建与核验，MF 为 `1decd2bd777ef4324a46ef0c71978bb0f52b55777346b02bf1649a98834b4c93`，安装器 SHA 为 `6dfa89cdc161f41fdf12b52fd66c5c6399d04446c8ea38456eb313ecead67680`。14 项运行资源、22 项编译输入、依赖来源／许可与平台核验通过；授权载体严格签名和 16 项 payload 核验通过，官方运行资源没有重签。实际 read-only plan 识别精确 518，仍要求管理员检查私有目录，未宣称其为空。安装器 21 项、资源 18 项、载体 8 项回归通过。当前 root 安装再次读取仍为 518；新候选没有安装、激活或发布，上一轮清理核查继续优先。记录为 `stateless-fix-build-verification-20261008.json`、`stateless-fix-authorization-bundle-20261008.json`、`next-source-authorizer-regression-20261008.log`。
