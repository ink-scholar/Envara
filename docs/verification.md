# 验证记录

## 当前状态（2026-10-10）

最新 macOS ARM64 桌面候选为 `release/local-notion-diagnostic-recovery-r2-20261010/mac-arm64/Envara.app`，已编译并由用户手动测试。已安装组件的 manifest SHA-256 为 `4b9f859585a10e31eb98d43682595a9e152b3f93439ebea6ef1de0a4659ba557`。候选包资源和针对性回归有独立检查；以下历史构建记录不能代替最新实机结果。

用户导出的最新诊断仍为失败：首次错误 `APPLICATION_APP_NATIVE_REFUSED`，原生原因 `NATIVE_NOTION_STAGE_REFUSED`、`errno=13`，发生在 `cold-stage`。尚未记录内部具体失败检查；清理错误仍重复首次启动错误，`cleanupComplete=false`、`cleanupUncertain=true`。Notion 尚未成功进入 staged／resumed，受保护启动和通用应用接管均未验收。具体证据、代码路径和下一步见 [当前诊断交接](notion-launch-handoff-20261010.md)。

用户本次明确授权上传最新源码进展；不创建新 tag 或公开安装发行版，自动发行保持禁用。旧包和重复生成物可移出工作目录，原始诊断、配置及最新有用证据保留在本机。

本次上传前的本地检查：Node 回归共 1,580 项，1,578 通过、2 项真实浏览器检查按其开关跳过、0 失败；前端构建和 Sites 4 项检查通过；BrowseForge 的 `go test ./...` 通过。旧固定恢复草稿的测试改为独立检测真实源码漂移，并确认旧配方精确拒绝，未修改固定配方或历史哈希。CI 的完整套件改在 macOS 上执行，以匹配 Apple 原生夹具；这些检查不激活 PF，也不证明受保护应用验收。

## 2026-10-08 历史记录

2026-10-08 当前已安装系统组件为 `46ae6acddd4f…`。最新 Notion 验收在传输准备时失败，Notion 没有启动，完整清理未确认；自有 PF 引用、入口、组及私有运行记录需要下一次原生管理员检查，不能把测试进程已退出当作系统清理完成。配置 JSON 转义、成功返回值和停止流程传参错误已在源码修复并通过针对性回归，修复源码尚未安装。附加软件生产启动继续关闭。[具体系统状态](mac-pf-owned-routing-review.md)

本地 `release/mac-notion-run-20261008/` 的 macOS ARM64 0.5.0 DMG／ZIP 已完成打包与资源检查，包含 46ae 组件，不包含其后修复。验证记录为 `notion-package-hashes-and-resources-20261008.json`，证明包内容、固定资源与许可匹配，不证明 Notion 可用。以开发专用 workspace smoke 环境变量启动正式包的尝试超时：正式包明确禁用该入口并排除 smoke 模块，因此没有生成报告；本次不能算包内工作区验收通过。浏览器、终端与九语言的独立历史检查继续保留。GitHub 推送与发布仍暂停。

其后修复候选 `0d9209b17809…` 已完成真实编译、65 项固定源码输入、18 项运行资源及独立授权载体检查，未安装或激活。该次历史本地包为 `release/mac-factoryfix-20261008/`，打包内容检查通过：73 项归档文件、205 项资源文件、56 个目录、无符号链接。DMG SHA-256 为 `c521f9f8bf0eb430ecf87f5ab1f62acd98bdfebd0f974b38893211691f63026b`，ZIP 为 `76ec0d0bf54ad9545e815b96ccaaddd6b85acdf68f6d5298fdfcf9ed84cf6188`。对应 `notion-factoryfix-offline-carrier-20261008.json`、`notion-factoryfix-package-hashes-and-resources-20261008.json`；42 项停止／客户端／驱动和 26 项资源／载体回归通过。以上只证明修复与打包，真实 Notion 接管及最新失败运行的系统清理仍未确认。

此前启动前回收候选为 `957e4157e491…`，包位于 `release/mac-prestagefix-20261008/`，独立核验 73 项归档文件、205 项资源文件、56 个目录、18 项运行资源和 65 项原生源码输入通过。新增仅适用于 factory-open、任何规则或应用启动尝试之前的原生失败回执：精确核验原始 lease、utun／监听 socket、子进程回收、完整原生 GID 检查和退出状态，然后执行精确自有资源回收。客户端还要求绑定原请求的环境及 stop 后新取得的 snapshot。原生严格编译与 7 项非提权夹具、126 项控制器／客户端／驱动回归及独立审阅通过。`prestage-cleaned` 明确保留应用未启动和生命周期失败，不能替代普通 Notion 生命周期证据；它没有追溯清理已安装 46ae 的失败运行。构建与包证据为 `notion-prestage-abort-offline-build-20261008.json`、`notion-prestage-package-hashes-and-resources-20261008.json`，均未安装、激活或发布。

最新离线候选为 `c37c49f9ca94…`，位于 `release/mac-listenerfix-20261008/`。固定的一次性原生子进程在自有 realm GID 下创建监听 socket，再经绑定 nonce／lease／父进程出生身份的私有 FD 传递交给 keeper；keeper 本身的凭据保持不变。factory 再次检查实际内核 socket UID 0／realm GID，PF FRONT 在 lo0 入站新增精确凭据放行及其余凭据拒绝规则，同一事务共 5 条规则。发现并修复了真实 Darwin 控制消息截断造成的 FD 泄漏：11 种传递场景的实际 FD 数均为 4→4。冻结源码严格编译、243 项针对性检查和独立审阅通过。包内 73 项归档文件、205 项资源文件、56 个目录、18 项运行资源和 65 项原生源码输入核验通过，DMG／ZIP 完整性通过；构建、传递、包证据分别为 `notion-listener-identity-offline-build-20261008.json`、`notion-listener-transfer-fixture-20261008.json`、`notion-listener-package-hashes-and-resources-20261008.json`。尚未系统安装或激活，原生 root 正向凭据、实际 PF loopback、整个 guard 故障／同端口复用及 Notion 生命周期未验收；没有追溯清理旧 904 运行。

此前源码审阅发现全部原监听 FD 消失而 FRONT 规则仍在时，数值端口放行不能阻止其他进程复用端口。以上 c37 候选加入了监听身份保护，但惰性规则检查与非提权 FD 测试不能证明本机 PF 内核已实现该保护。SIGKILL 不执行普通退出清理，已有状态、IPv6／原始协议和整个 guard 故障仍需受控原生验证。`wholeGuardCrashProtectionAccepted=false`，附加软件生产保护继续关闭。

用户随后已手动打开原始 `/Applications/Notion.app`，观察到实际主进程和辅助进程为普通用户组，当时无 Envara 受管传输进程。未结束用户软件、未改其网络设置。此前恢复工具对原始 Notion 一概拒绝；最新独立源码候选改为只有完整 BSD／KERN_PROC_PID 凭据、全部 UID/GID、完整补充组及两轮路径／出生身份均稳定，才能判定原始会话与境舱无关。自有 Snapshot、native／Node／Mihomo 及全进程 GID、PF／lease／journal 门槛保留。3 项测试、46 项凭据用例、真实非提权自有进程读取、Werror 独立构建和审阅通过；原生 root 恢复仍未执行，用户当前明确不方便操作管理员弹窗。恢复方案与限制见 [固定运行恢复范围](mac-pf-application-recovery-46ae-run904.md)。

用于用户在场操作的独立恢复授权载体现已严格编译、以本地 hardened runtime 签名，并实际执行惰性 `--plan`，动态及静态自签名核验通过；5 项针对性检查通过。仅显式“安装恢复组件并只读检查”入口允许通过内嵌固定字节排他新建 root 文件；普通只读／清理入口缺件会在授权之前拒绝，不暗中安装。授权、root 文件创建、清理及 Notion 启动均未执行。证据为 `application-recovery-46ae-run904-authorization-build-20261008.json`。这不改变仍为 46ae 的当前系统组件、c37 候选包或生产未就绪状态。

历史 6f8 受控测试已通过双环境进程身份、并发 TCP、TCP 半关闭、TCP 53 DNS 和四个进程各 2048 字节 UDP，并确认该运行的完整清理、原 PF／DNS／路由恢复。这是自有夹具的证据，不能转移为最新 Notion 运行通过。最新失败记录为 `notion-linkfix-acceptance-1791464074257-90401ced-5d54-4422-b80c-c7c4485a037b.json`；本次运行未保存完整清理基线，之后的稳定性检查不能补充为起点一致性证明。

## 历史 macOS 编译交付与边界（2026-10-08，以下 6f8 及更早记录）

用户当前提供的 AGENTS.md 保持 GitHub 发布暂停；自动发布保持禁用。当前没有上传、推送或正式发布。用户已恢复操作管理员弹窗，本轮已实际完成组件升级和受控流量／清理复测。非 NE 路线不要求 Apple Developer 账号；系统操作仍要求原生管理员授权，不能用缓存授权保证不出现弹窗。

只读复测实际发现并修复两项接口问题：系统容量与 SDK 均为 16，旧检查器误拒完整的 16 项；`PROC_PIDTBSDINFO` 的原参数排除了系统列表中的僵尸进程。修复要求精确容量证明，固定使用包含僵尸的读取选项，并保留全部组、三种 GID、进程出生身份和双轮检查；72 项惰性边界测试、严格编译及独立审阅通过，未知进程和读取失败仍拒绝。随后原生只读复测通过 1,135 个进程的双轮完整检查；实际封存又独立复核了 1,140 个进程，核验后原子移动旧记录，保留登记、锁文件及两个空 realm 目录，没有删除或重发旧 PF DELETE。封存回执 `archiveVerified/runtimeRetired/sourceAbsentVerified=true`；`namespaceReclaimed/cleanupConfirmed/productionReady=false`。

原生升级安装回执确认 `2a7f4ad63504…` 已安装，随后独立逐项核对 manifest、14 项资源哈希及 root 所有权通过；仅复制固定组件，没有启用 PF、创建组／隧道或启动应用。实际记录为 `runtime-retirement-518-live-zombie-20261008.json`、`runtime-retirement-518-archive-20261008.json`、`fresh-namespace-install-20261008.json`，均位于 `test-artifacts/mac-pf-routing/`；完整流量验收仍待完成。

新版空入口已实际完成创建、读回、精确一次删除与只读恢复核验。新一次性 UUID `06d57c81-373e-49ab-9b07-27563497293a` 已永久消费；其命名空间核验为 absent，入口原规则恢复、回执退休、主机 DNS／路由／PF 配置摘要一致，`cleanupUncertain/cleanupPending=false`。本次没有启用 PF、创建组／隧道或启动应用。这只证明这个空入口循环；旧 518 命名空间、完整流量、整个 guardian 崩溃和生产启动仍不能据此认定通过。最终独立载体源码 `f0c0295c…`，8 项惰性测试与 15 个模拟生命周期场景通过；实际记录为 `v2-empty-run-canary-2a7-native-20261008.json`。

随后的 2a7 五项流量测试在 `socket-reservation` 阶段失败，尚未执行任何流量用例。实际失败运行 `01d1e669-bc58-4a10-ae2d-709e7fedd7f6` 的入口已删除、独立 PF 引用已释放；重复清理回执错误重置了已完成步骤。独立原生只读复查确认 11 个记录进程全部退出、两个记录 utun 名称已不存在、专用组不存在、1,137 个进程的双轮完整 GID 检查通过；原规则恢复、PF 禁用、六类活动规则和 anchor／ghost table 清单为空。该运行的内核命名空间仍为 present，私有记录当时保持 `cleanup-required`。随后实际原生封存成功，登记与锁文件、两个空 realm 保持原始字节及身份，原路径消失；没有删除内核命名空间或重发 DELETE。封存记录为 `runtime-retirement-2a7-run01d1-native-20261008.json`，`archiveVerified/runtimeRetired/sourceAbsentVerified=true`，完整清理仍为 false。复查期间 DNS／路由／PF 配置稳定，但失败运行的 baseline 未持久化，不能用这次稳定性替代与失败运行起点的比较。记录为 `owned-hook-retry-1791452000571-f51f9a93-bef6-4610-85d5-63b3d7d58c76.json` 和 `readonly-2a7-run01d1-native-retry-20261008.json`。

修复版源码统一 Swift reservation UUID 的小写生成与查找，不放宽运行 ID／PF lease；重复清理保留明确标注的历史步骤并重新检查 GID 进程缺席。69 项控制器／重试检查、真实非 root Swift 本地 socket／父子进程检查通过；新的精确 2a7 升级表及 53 项构建／授权／资源检查通过。新组件 manifest 为 `83256899dc6d…`，原生升级安装实际成功，独立核对 14 个运行文件、manifest、root 所有权、单硬链接及精确权限通过，安装步骤没有激活网络。记录为 `reservation-cleanup-install-832-native-20261008.json` 和 `reservation-cleanup-install-832-leaf-verification-20261008.json`。应用登记与 GUI 准备的两个原生测试集也已通过；它们仍是尚未接入生产 helper 的库，没有生产 resume。

832 实际五项重试运行 `95c92c49-063e-4595-b28f-232f558d6f6e` 在 25,978 ms 内结束：准备、进程身份、并发 TCP、TCP 半关闭及对应未绑定 loopback 控制均通过；UDP 5,044 ms 超时，DNS 用例未执行。清理保留真实已完成步骤，不再错误重置；原 PF 与根规则、主机 DNS 和路由核验恢复，命名空间仍为空但 present，回执退休，`cleanup-required`、`cleanupUncertain=true`。非 root 进程清单未发现任何测试 helper／fixture 或 QEMU；该清单不替代完整 root GID 检查。实际记录为 `owned-hook-retry-1791454103320-b0395cf6-818f-4d1d-8b70-4a83252385f2.json`；正式启动保持关闭。

随后 832 的大小对照运行 `3f419119-19e1-46d5-847e-fcd2d1ec1ed1` 通过身份、TCP、半关闭及 TCP 53 DNS，UDP 仍超时。每个父进程使用 1200 字节、子进程使用 2048 字节；两条认证 SOCKS 夹具均收到完整两包并发出回复，无拒绝或 socket 错误。这些计数只定位传输链路，不证明应用收到回复。两个 832 运行的实际原生封存均成功，源路径消失、两份文件和两个空 realm 保留；内核命名空间未回收。记录为 `runtime-retirement-832-run95c92-native-20261008.json` 和 `runtime-retirement-832-run3f419-native-20261008.json`。

UDP 修复仅将自有 utun 和其 Mihomo gvisor MTU 从 1500 统一为 9000，不修改主机接口、默认路由或 DNS，不放宽 UDP 端口规则。111 项针对性源码检查及独立审阅通过。精确 832 升级表与 53 项构建／授权／资源检查通过；新组件 `ff9f6a77bb8e…` 原生升级实际成功，14 个运行文件、manifest、root 所有权、单硬链接及精确权限核验通过，包含 28 项固定编译输入。安装回执为 `owned-utun-mtu9000-install-ff9-native-20261008.json`，独立文件核验为 `owned-utun-mtu9000-install-ff9-leaf-verification-20261008.json`。

ff9 实际重试运行 `4fe07677-cbdb-4273-9b45-a1ecae8e6444` 在 28,838 ms 内结束，身份、TCP、TCP 半关闭、TCP 53 DNS、UDP 及全部未绑定 loopback 对照均通过。四个父／子进程全部使用原来的 2048 字节 UDP，UDP 用例 79 ms 完成；该结果不代表大于 9000 字节的任意 UDP 分片也通过。正式流程沿用旧 pfctl 多类事务，空命名空间仍为 present，完整清理和生产验收仍为 false。随后实际原生封存成功：11 个记录进程双重缺席、1,194 个进程的两轮完整凭据检查通过、组与隧道消失；两份文件与两个空 realm 保留，原路径消失，未重发 DELETE 或修改 PF。记录为 `owned-hook-retry-1791456949779-3580cd54-7255-423a-b57a-00235609ac73.json` 和 `runtime-retirement-ff9-run4fe-native-20261008.json`；摘要与字节绑定见 `ff9-five-flow-archive-single-filter-progress-20261008.json`。

独立单 FILTER 事务载体已实际完成 EMPTY → 固定 TEST-NET 拒绝规则 → EMPTY，再精确删除自有根入口；命名空间 absent，原 PF 规则／DNS／路由恢复，PF 全程禁用，无软件、隧道或流量运行。一次性 UUID `a85314b8-5b24-4784-95ec-47b739c2e841` 已永久消费；57 项惰性检查、严格编译和独立审阅通过。记录为 `single-filter-canary-832-native-20261008.json`。它证明这个填入／清空循环，不替代完整分流、整个 guardian 崩溃或生产验收；生成式分流规则仍需接入该事务实现。

随后单 FILTER 事务实际接入受控控制器，生成、读回、清空采用同一精确私有 lease，不使用旧多类 `pfctl -f` 路径。157 项针对性惰性检查、原生严格编译及独立审阅通过；48 项编译输入核验通过。新组件 manifest 为 `6f8386e1586af12775c9aadd1de339568d29cf93dc4135d8de00b8661407026f`，原生升级实际成功，14 个运行文件、manifest、root 所有权、单硬链接及精确权限逐项核验通过。记录为 `single-filter-install-6f8-native-20261008.json` 和 `single-filter-install-6f8-leaf-verification-20261008.json`。

新组件第一次重试在启动状态读取的 60 秒期限结束，尚未创建 run、准备或执行流量用例，不能据此判断分流失败。用户随后完成原生授权，运行 `8a624a59-aff2-49b7-ada5-d7d13ae869ad` 在 22,910 ms 内完成：身份、并发 TCP、半关闭、TCP 53 DNS、全部四进程各 2048 字节 UDP，以及每项未绑定 loopback 对照均通过。完整清理回执确认自有 namespace absent、回执退休、进程／组／隧道／入口退出、原根与 PF 恢复、DNS／路由未改变，无自有 PF 状态创建或残留，`cleanupConfirmed=true`、`cleanupUncertain=false`。实际 lo0 受 PF 覆盖的只读检查通过，没有更改主机 skip 设置。记录为 `owned-hook-retry-1791459449353-09535066-e5ee-45e5-b4ac-f06c2cb99497.json`。本次使用自有测试程序，未启动 Notion；完整应用矩阵与生产就绪仍为 false。

正式附加软件启动仍有实现缺口：控制器的 `launch()` 当前固定拒绝。应用快照登记、私有一次性 ticket、GUI 执行前挂起和真实 guardian 生命周期已有原生源码与自有临时进程检查；它们尚未完整接入已安装 helper 的生产启动。原生网络权限来源、utun 文件描述符持有、DNS、前端及辅助进程归属和整个 guardian 故障保护仍需接通及验收，不能把剩余工作描述为只差授权或测试。

| 检查 | 当前结果 |
| --- | --- |
| 全量 JavaScript 源码 | 564 项，562 通过、2 个原生 Chromium 夹具明确跳过、0 失败；并发限制为 2 |
| 随后重试入口修复 | 真实控制器／矩阵共用候选 run ID；当前值精确绑定已安装的 6f8 授权载体、manifest 和安装器哈希；20 项重试检查与 5 项数据包大小对照检查通过。缺失／非法批准参数在任何安装检查或 helper 创建前拒绝。当前原生重试使用全部 2048 字节 UDP；该入口脚本不在应用安装包内 |
| 前端与 Sites | 构建和 4 项 Sites 检查通过，保留三个 Sites 交付文件 |
| 当前系统 PF 组件 | manifest `6f8386e1586af12775c9aadd1de339568d29cf93dc4135d8de00b8661407026f`，安装器 `da4b12697ad6561b86adc1754851c149ac4889b837d912f24c49a907060731ee`；14 项运行资源、48 项原生输入及依赖／许可核验通过。五项真实受控流量／身份用例与完整清理通过；Notion 和生产验收仍未通过 |
| 真实桌面 | 11 项工作区检查通过，含九语言、六页、真实 PTY、复制、展开恢复、独立窗口和未就绪软件启动拒绝；出口来自离线合成夹具 |
| 包内资源 | 62 个 archive 文件、200 个资源文件和 56 个目录核对通过 |
| 包内终端 | 真实加载打包 PTY，输入输出、尺寸、选定目录、私有配置、时区、自然退出和关闭清理通过 |
| 包内 AnyTLS | 应用自带核心经自有 TLS 夹具完成认证、证书拒绝、真实有头 CloakBrowser 和 PTY 共用路线与时区、核心恢复、断线无直连回退及清理。未使用用户节点、账号或真实公网地理数据 |
| 旧记录封存工具 | 严格编译、四组非提权夹具（含 72 项 GID 边界检查）、独立源码审阅及原生只读检查通过；实际系统封存和源路径消失核验通过，完整保留原记录。未删除 PF 命名空间；文件封存不等于内核命名空间回收 |

本地应用为 `release/mac-pf-run-20261008/mac-arm64/Envara.app`，安装文件为同目录下的 `Envara-0.5.0-mac-arm64.dmg` 和 `.zip`。没有 Developer ID 签名或公证；尚未验证 Intel Mac。安装包中的附加软件启动门禁继续关闭，不以编译、便携测试或浏览器通过代替 Notion／系统分流验收。

固定记录包括 `test-artifacts/mac-pf-routing/fresh-namespace-full-source-tests-20261008.log`、`fresh-namespace-build-verification-20261008.json`、`runtime-retirement-518-14001cc0908c-build.json`，以及 `test-artifacts/workspace-smoke/workspace-smoke-fresh-namespace-20261008.json`、`test-artifacts/package-verification/0.5.0-darwin-arm64-fresh-namespace-20261008.json`、`test-artifacts/packaged-terminal/run-gJUQjH/proof.json` 和 `test-artifacts/anytls-packaged/run-ZTfEfz/proof.json`。DMG 与 ZIP 的完整性均通过；最终字节数、SHA-256、app.asar 摘要和剩余门槛见 `test-artifacts/mac-pf-routing/fresh-namespace-macos-delivery-20261008.json`，用户可读编译说明及摘要保存在安装文件旁的 `BUILD-NOTES.md` 和 `SHA256SUMS`。

## 非 NE Mac 后端实现（2026-10-08 当前工作）

桌面默认后端改为 PF／独立进程 GID／自有 utun，通过固定 Mihomo 连接 Envara 管理的认证 SOCKS 节点。AnyTLS 核心的路由及执行代次有独立私有身份；退出或重启后旧身份失效。自有 NE 与原版 Redirector 的历史结果仍保留，不能借其授权或便携测试提升 PF 为已通过。

当前完成：真实 C 冷启动、执行前挂起、三种进程身份和子进程继承、继承网络 FD 关闭、私有探针通道、utun 和 Mihomo FD3 传输实现；原生非提权测试通过。PF 固定资源构建通过，官方 Node 与 Mihomo 的固定哈希、源码和许可被保留；6f8 固定资源已安装，五项受控流量与完整清理通过，最新重试为 `cleaned`。桌面 PF 准备状态已实际显示，未授权／未验收正式软件启动仍被拒绝。

本轮 Electron 工作区 11 项真实检查通过，包括九语言首启与设置、六页面、真实 PTY、复制会话、放大恢复、独立窗口及拒绝未就绪软件启动。网络出口是离线夹具合成数据，不代表 AnyTLS 或附加软件真实出口验收。前端构建通过。

独立 DNS 探索已实际运行：当前系统库没有连接 `DNSSD_UDS_PATH` 指定的私有入口；子进程 Seatbelt 可拒绝 DNS-SD 和 UDP／TCP 53，主机 DNS 配置指纹保持相同。拒绝泄漏不等于正常独立解析，详见 [DNS 设计与实测](../native/macos-pf-routing/dns-design.md)。完整 `dns`、`failClosed` 与受保护启动仍关闭。

受控无状态 PF 夹具、原生管理员授权入口和桌面明确安装按钮已接入。初次聚合回归 **193/193 通过**；前端构建通过。13 项资源及编译输入核验通过；用户明确批准后的首次安装 manifest 为 `f8fce1d14566fdf822d220ef1a3469cbb815a37924c7ed709a1098729b8bed8b`，资源约 189 MiB，后续先后升级至下文 e940 与 518a 快照。完整本地包核对 54 项 archive 文件、199 项资源文件、56 个目录通过。具体操作范围见 [安装与受控测试审阅](mac-pf-installation-review.md)。

真实工作区复查曾在首启确认后出现语言保存超时：保存通知先于 IPC 完成，选择器仍 disabled，测试立即发第二次切换被拒。修正测试等待可交互完成，未放宽保存／翻译断言，15 项语言检查和重跑的 **11 项真实工作区检查通过**。安装后的聚合检查暴露异常编译清单计数导致的原生只读 plan 越界（SIGSEGV）；已改为先验证清单并使用实际数组长度。原生反例通过，重跑聚合检查 **205/205 通过**，日志见 `test-artifacts/mac-pf-routing/source-regression-205-20261008.log`。源码修复没有自动替换已安装的旧快照。

首次包内安装器实际完成系统授权、固定资源安装；root 所有权和 13 文件哈希再核验通过。持续原生 RPC 的 root／console／授权门槛已过，当时受控五项测试因实际 Apple PF 入口缺失在前置检查拒绝，`nativeRoutingAttempted=false`。本机同时保留 Sangfor PF 配置，未重载或调整它。该次前置拒绝没有创建系统组、打开 utun、加载 PF 或运行 Notion；没有 Windows/QEMU、主机 DNS／默认路由／时区更改或 GitHub 发布。较早“需要先取得 Envara NE 签名”的阻塞结论仅适用于 NE 路线，当前非 NE 路线需管理员授权及完整实机验收。

独立只读 ABI 检查已通过原生授权实际执行：`O_RDONLY` 打开 PF，使用 `PF_GET_NONE` 读取规则，与原版 `pfctl` 的 7 条 root 规则全部匹配，读取期间 ruleset revision 保持一致。检查器另有 **5/5** 非提权测试通过；观测回执在 `test-artifacts/mac-pf-routing/readonly-abi-20261008.json`。

独立空 root 入口候选的 **6/6** 非提权检查和源码审查通过。用户补充授权后，实际 INSERT／读回／精确 DELETE／恢复检查全部成功，`cleanupPending=false`；PF 保持禁用，原有 7 条规则、DNS、IPv4/IPv6 路由、NAT 和配置文件前后哈希一致。回执见 `test-artifacts/mac-pf-routing/root-canary-native-20261008.json`。此结果只证明本机空入口操作；尚未验证填入分流规则、启用 PF、路由流量或用户软件。

自有入口已接入受控夹具。此前已实际升级安装的资源 manifest 为 `e940e171ac39624cd3cfeaea09234f4e8e035bfba141a843950cb0209e00db04`；安装前 13 项运行资源、18 项原生编译输入、平台／依赖／许可核验通过，安装后 root 所有权及 13 项文件哈希再次核验通过。安装器支持已知旧快照的原子升级和并发互斥。独立授权 App 的严格签名和资源核验通过；安装回执为 `test-artifacts/mac-pf-routing/installed-owned-hook-final-20261008.json`。当前记录使用独立的安全 root 路径，旧记录及未知残留只检查并拒绝，不自动删除。相关聚合检查 **244/244 通过**，日志见 `test-artifacts/mac-pf-routing/owned-hook-regression-final-20261008.log`。具体操作范围见 [自有入口与受控流量测试](mac-pf-owned-routing-review.md)。

在该 e940 安装快照上已进行一次有界真实受控测试，选定进程身份、并发 TCP、TCP 半关闭、并发 UDP 和 TCP53 五项，但测试在 prepare 阶段约 **0.218 秒**即以 `APPLICATION_ROUTING_NOT_READY` 中止。报告记录 `nativeRoutingAttempted=true`，同时 `nativeRoutingAcceptance=false`、`fixtureMatrixPassed=false`；这不是五项流量验收通过，也没有测试 Notion 或整个 guard 崩溃保护。私有安全通道已关闭，本地测试端点已关闭；最初报告未确认完整清理，后续 root 只读复查确认 `activated=false`、`prepared=false`、`ownedRootHookVerified=false`，所属临时组和测试进程已不存在。私有 runtime 目录的内部内容未从外部直接观测，不能声称目录已完全清空。真实报告和复查分别为 `test-artifacts/mac-pf-routing/owned-hook-native-1791430929646-41499c39-5c7a-4c0e-a623-c2bbfc1f1faf.json` 与 `post-owned-hook-status-20261008.json`。

在后续批准安装与重试前，源码候选分开处理 root 单层入口的写入模板 `anchor_relative=0` 与内核规范化读回 `anchor_relative=1`，删除仍重建固定写入模板并要求精确私有 lease。**8/8** 非提权惰性 ioctl 测试及编译检查通过；当时尚未安装或系统复测。旧真实失败仅返回通用错误，尚未确认执行到 INSERT，也未确认该规范化差异就是实际失败根因。源码复核见 `test-artifacts/mac-pf-routing/owned-hook-normalization-source-review.json`，后续安装与真实重试结果单独记录如下。

用户明确批准后，规范化候选已实际从 e940 升级安装至 manifest `518a75d94bac4f17d9e1ce60e842648ba6ff657a68cc62e95ce13718abda6d5a`，root 所有权及 13 项运行文件核验通过；安装及核验记录为 `test-artifacts/mac-pf-routing/installed-normalization-20261008.json` 与 `installed-normalization-proof-20261008.json`。这确认安装快照，不确认应用分流能力。

批准后的有界重试在 prepare 的 `stateless-rules` 阶段用时 **3.840 秒**后失败，`nativeFixtureCasesAttempted=false`、`selectedCasesPassed=false`、`nativeRoutingAcceptance=false`，五项流量用例没有开始。报告的 `diagnosticsComplete=true` 只表示诊断记录完整；有效清理回执明确 `cleanupUncertain=true`、`cleanupConfirmed=false`，所属运行仍为 `cleanup-required`。安全通道关闭或 transport 的 `cleanupUncertain=false` 不能覆盖该清理回执。报告见 `test-artifacts/mac-pf-routing/owned-hook-retry-1791432070242-ce66bad5-d202-4024-a31d-dfa08e93cf5f.json`。

清理回执报告所属进程退出、自有 utun 移除和子规则移除；后续非提权检查未发现所属 PID/GID，接口清单和主机 DNS 配置指纹保持一致。但路由的语义 SHA 与测试前不同，原因及归属尚未确认，不能声称无关路由已全部恢复。root 自有入口的删除和原 root 恢复均未确认；旧 lease 已失效或 `ownedRootHookVerified=false` 不证明入口不存在，删除也可能已提交而确认失败。另一次新通道 root 只读状态请求以 `PF_HELPER_DEADLINE` 超时，`statusAvailable=false`、`cleanupConfirmed=false`，见 `test-artifacts/mac-pf-routing/post-normalization-fresh-status-refused-20261008.json`。该超时结果不能用于证明当前已无激活、准备状态或残留入口。

专用 518 只读检查器已通过实际编译、惰性解析测试与严格签名检查，固定读取本次登记和两种入口证明，不删除或激活任何对象。授权等待期间的进程采样曾停在 `AuthorizationCopyRights`；用户完成系统授权后，实际检查成功，见 `readonly-recovery-518-native.json`。518 安装和密封固定登记核验通过，登记仍为 `cleanup-required`，PF 引用记为已释放；11 个记录 PID 双读均不存在，未见 live／unknown／birth mismatch。

新的无旧票据原生证明确认 `pfDisabled=true`、原有 7 条 root 的规则与文本指纹一致、`hookInstalled=false`、原有入口兼容。旧根入口当前已不存在；不能继续按旧票据 DELETE。`canCreateOwnedHook=false` 的剩余条件是 `leaf_absent` 未通过，现有报告不能区分空命名空间存在和读取错误。六类 active 规则、ghost tables、children 及私有目录内容仍待专门只读核查；inactive／open／refcnt 没有已确认的只读接口，不能推断为空。完整清理仍未确认，不删除登记、不进行新激活。后续非提权检查 DNS 与接口仍一致，完整路由语义摘要仍不同，见 `post-readonly-518-native-network-20261008.json`。

后续扩展只读检查已经实际完成。六类 active 规则的稳定双读均为 0；自有命名空间仍存在。固定系统 `pfctl`（实际权限 `0555`）和 SHA 核验后，子入口与包括 ghost 的 tables 稳定双读均为 0。私有目录仅有精确登记、锁和本次 run，run 内有两个已知空 realm 目录，未知／缺失条目均为 0，身份及清单摘要稳定；11 个记录 PID 仍全部不存在。原根两指纹和 PF 禁用状态在检查前后均匹配。记录为 `readonly-recovery-518-complete-public-inventory-native.json`；此前 `75652d84e31f` 版本因错误要求系统工具为 `0755` 而未执行 listings，保留其原始拒绝回执。inactive／open／refcnt 仍未验证，完整清理与生产就绪仍为 false。当前未删除登记或旧入口，正在准备保留原始数据的精确文件归档方案，并将后续入口改为每次 run 独立名称；尚未授权或执行该文件归档及新的网络激活。

后续源码已将 stateless 校验改为 PF 列表展开后的完整语义与顺序比较；本机 `pfctl -n -v` 只解析样本确认四端口展开成四条、协议列表展开成两条，**68/68** 控制器和校验器测试通过。该源码尚未安装，不能认定是此次实际拒绝的完整根因，更不代表原生流量或清理已通过。

验收通道源码同时保存控制器给出的清理不确定性：正常外层 EOF 不能覆盖 `cleanup-required`／`cleanupUncertain=true`，完整清理必须匹配全部观察到的 run ID 与 11 项原生证据。验收及重试调用方 **50/50** 回归通过。这修复本次结果丢失，不产生新的原生清理证明；后续原生 relay 已补充 root 子进程非零／信号／未知退出的清理不确定通知，6 项反例与 4 项既有门禁检查通过；整个 guardian 被 SIGKILL 时的通知及系统保护仍未验收。

较早 stateless 修复组件已在本机实际构建，manifest 为 `1decd2bd777ef4324a46ef0c71978bb0f52b55777346b02bf1649a98834b4c93`。14 项运行资源、22 项编译输入、依赖哈希／源码／许可和平台核验通过；独立授权载体 16 个 payload 叶文件与严格签名核验通过，安装器和官方运行资源未重签。载体仅读取 `--plan`，识别精确 518 旧安装并明确 `privateRuntimeInspectionRequired=true`、`controlledRuntimeAbsent=false`，没有请求安装授权。实际已安装 manifest 再读仍为 518。新增升级表的完整原生惰性回归 **21/21** 通过；资源 **18/18**、载体 **8/8** 通过。新组件尚未安装或激活，生产门禁继续关闭。证据为 `stateless-fix-build-verification-20261008.json`、`stateless-fix-authorization-bundle-20261008.json` 和 `next-source-authorizer-regression-20261008.log`。

生产保护、原版 Notion、通用系统 DNS、外部辅助进程、整个 guard 故障及完整不影响无关应用的验收仍未完成，`ready`、`dns`、`failClosed` 与 `productionReady` 继续 false。Windows 测试主机由用户另行安排，本机不运行或重启 Windows/QEMU；macOS GitHub 上传已获完成后授权，系统验收条件尚未满足，自动发布仍禁用。

记录日期：2026-10-08。当前开发 0.5.0 本地候选版；完成 macOS 后的上传已获授权，当前尚未正式发布。结果按版本与运行路径区分，旧结果不自动代表新增代码已验收。状态见 [能力矩阵](capability-matrix.md)。

## 自有 Mac TCP 与 DNS 修复（2026-10-08 最新源码）

针对原版组件复测暴露的问题，本轮修订 Envara 自有 AppProxy 的实际传输代码，而不是修改原版签名组件或放宽保护启动条件。原版组件的失败结果仍保留在下一节。

| 修复与检查 | 本轮实际结果与范围 |
| --- | --- |
| TCP 写方向 EOF | `SOCKSTransport.closeWrite` 现在使用 `NWConnection` 的 final message 与完成回调发送 FIN；重复关闭只发送一次，关闭后拒绝继续写入。读方向保留末段数据，然后稳定返回 EOF／错误。真实本地认证 SOCKS 测试中，对端等到 FIN 才返回的 512 KiB 数据全部收回；SOCKSTransport 9 项通过。这是传输层结果，尚未证明系统 `NEAppProxyTCPFlow` 保留相同的半关闭语义 |
| DNS 响应校验 | UDP53 与 TCP53 都使用该境舱的认证 SOCKS TCP DNS 交换；校验查询 ID、名称、类型、class 和完整报文结构。拒绝同 ID 的另一查询答案、异常压缩指针与截断记录；过大 UDP 答案返回完整问题与 TC，后续 TCP 查询继续校验。原始 SOCKS UDP53 回包不能绕过该路径 |
| DNS 等待与取消 | 查询、TCP DNS 读写及连接具有 8 秒上限，超时关闭所属连接。原有 DNS 11 项通过，包括真实本地连接中的分片响应、错误问题拒绝，以及只收到半包后 200 ms 测试超时并确认连接关闭。测试仅使用临时本地认证端点，不读取用户节点凭据 |
| 连续 TCP DNS 查询 | 复核发现 Foundation `Data.removeFirst` 后可保留非零 `startIndex`，原分帧代码的绝对索引会越界。Provider 现在直接使用按实际索引偏移的共用 `TCPFrameBuffer`。新增 5 项回归通过：连续帧、跨读取分片、非零索引、非法长度／EOF、容量限制；拒绝过量 append 不破坏已有帧。合计 DNS **16/16 通过** |
| 全量 Swift | **176/176 通过**；包含真实本地 transport、DNS exchange、内核 token 和已有租约／进程归属检查。没有激活自有 NE |
| 生产与验收构建 | 两个 unsigned release 构建通过；验收 host 逐字节复用本轮生产 provider，bundle SHA-256 为 `a1fd535867b8b748f91f836a7b9da3c52019a1038b2f9eea95784b031485e818`。首次一致性检查正确拒绝了残留旧 provider；重建验收 host 后，8 项启动门槛检查全过，未改变断言或授权门槛 |
| 系统状态 | 最新只读 plan 的 `authorized=false`、`extensionEnabled=false`、`productionReady=false`，全部十项自有原生门槛仍 false。没有启动 Notion、系统路由 fixture 或新扩展，没有改动 VPN/TUN、主机 DNS/时区、原版组件及无关软件，也没有运行 Windows/QEMU 或发布 |

源码与日志清单保存在 `test-artifacts/mac-routing/network-fixes-20261008.json`；全量日志为 `swift-network-fixes-20261008.log`，最终构建与门槛日志为 `build-network-fixes-20261008.log`、`build-network-fixes-acceptance-20261008.log` 和 `gates-network-fixes-20261008.log`，只读状态为 `plan-network-fixes-20261008.json`。这些位于同一 artifact 目录；首次旧 provider 不匹配的日志单独保留。先前桌面安装包快照尚未包含本轮 provider，不能用于证明这次系统行为。

**完整附加软件保护仍未完成。** 修改后的自有扩展不能继承原作者签名，当前没有其部署所需的合法 NE 签名/profile 与系统授权；同域双境舱的系统解析／缓存隔离、原生 TCP 半关闭、启动屏障、整个 guardian/provider 崩溃保护、无关软件及 Notion 还必须实测。签名也不自动证明这些能力。替代组件的固定源码与发行资产边界见 [组件审查](mac-routing-component-review.md)。

## 原版签名组件重新实测（2026-10-08 当前结果）

本轮重新使用已经授权的、未修改的 mitmproxy-macos 0.12.11 Redirector。只启动自有 Node 测试进程与私有认证 SOCKS/严格 TLS DoH 回显端点；未启动 Notion 或用户账号会话。原版组件可运行，不需要用户再申请 Apple 开发者账号。测试成功不为自有 AppProxy 生成授权或生产验收 receipt。

| 检查 | 当前实际结果与边界 |
| --- | --- |
| 两境舱 TCP 分流 | 9 项通过：两组父/子四个进程、相同执行文件和目标、两条独立认证代理并发回包。撤销 A 后它的两条旧流关闭、新流被拒绝；B 的旧流保持、新流成功。代理按各组随机 payload 白名单核对，未观察跨 route payload。只覆盖这些显式绑定的进程与 TCP 流 |
| 父/子、UDP 与代理断线 | 5 项通过：父/子 TCP 完整回包，所属 UDP 阻断，已有流的上游断开与代理不可用后的新流拒绝。不是自动子进程覆盖或整个 guard 崩溃验收 |
| TCP 半关闭 | 失败。修正测试为先收到首段回显、确认已捕获，再发送剩余内容与写 EOF。桥接完整接收并返回 2048 字节，应用只收到前 1024 字节；无 peer 拒绝。固定上游源码在应用输出 EOF 时取消整条连接，不能通过外部桥接恢复已关闭的应用流 |
| DNS 答案归属 | 修正默认系统查询只发 A，却同时要求 A/AAAA 的误判，改为显式 family4/family6 共 36 次查询。IPv4 四个父/子不同域名基线全过；同域并发及双向串行仍直接记录 `otherFixtureAnswerObserved=true`，未绑定进程也取得合成答案。IPv6 实际文本为 IPv6、低 32 位匹配合成 IPv4，却不匹配预期 IPv6；私有 DoH 查询只有 A，没有 AAAA。该族不通过，未确定由哪个系统或第三方组件转换，不能直接断言 DNS64/NAT64 原因。未保存原始域名或答案 |
| 未绑定进程 | 旧/新本地 TCP 回显通过；DNS 对照出现合成答案污染，因此不能称无关软件全部保持原网络，也不能直接采用共享 Fake-IP 修补 |
| 生产状态与清理 | 原版授权保持；全部诊断进程、capture 和私有端点清理通过。`productionReady=false`，启动屏障、完整 DNS、自动子进程、整个 guard/provider 崩溃保护与 Notion 尚未通过 |

原生报告位于 `test-artifacts/mac-routing/route-isolation-2026-10-08T00-44-46.114Z.json`、`native-matrix-2026-10-08T00-39-35.934Z.json`、`native-capture-2026-10-08T00-38-22.888Z.json` 与最终格式增强后的 `native-dns-2026-10-08T00-53-01.673Z.json`（schema 3）。前两项分别有 9 项与 5 项通过；半关闭报告明确记录 `captureWitnessObserved=true` 与上下游字节数。最终 DNS 36 次查询全部完成：IPv4 18 项有 11 项通过、IPv6 18 项 0 通过，完整 DNS 与不影响未绑定软件的门槛均失败。较早 `native-dns-2026-10-08T00-49-06.534Z.json` 的两个未绑定 IPv6 对照曾因只做文本全等检查而被判通过；新增正规化及低 32 位检查后，发现它们均匹配合成 IPv4 尾部，已纠正为失败。更早 `native-dns-2026-10-08T00-43-27.995Z.json` 包含默认地址族判定误差，两份旧报告保留但不作为最终聚合结果。

便携桥接 22 项、DNS 真实私有 IPC/分类/矩阵反例 23 项、生产启动门槛 8 项检查通过；这些不激活 NE。格式检查覆盖展开 IPv6、IPv4 嵌入及未知前缀尾部、无关 IPv6、尾部 `::` 和缺证据反例，保持严格匹配语义；尾部匹配仅是诊断现象，不推断转换协议。现成原版组件的最新只读 plan 仍 `authorized=true`、`verified=true`、`productionReady=false`，本地预览 HTTP 200。没有改动原版二进制、现有 VPN/TUN、主机 DNS/时区或无关软件配置，没有启动 Windows/QEMU 或推送发布。原版 EOF 行为见 [固定发行源码](https://github.com/mitmproxy/mitmproxy_rs/blob/40f1dfb5dca7b03ff7793d3c90f23b8bdf873889/mitmproxy-macos/redirector/network-extension/FlowExtensions.swift#L23)。

## 自有路径系统验收条件（2026-10-08 较早快照）

最新只读核对显示，自有 Mac 扩展仍 `authorized=false`、`extensionEnabled=false`、`productionReady=false`。当前 keychain 未找到有效 Developer ID Application 签名身份，已检查的路由构建/资源及用户 profile 目录未找到授权 profile；这不是任意私有存储的全盘搜索。62 项已验证源码与上一轮快照一致，无所属原生测试或 Windows 进程运行。

Windows 仍缺任意 Win32 共享 DNS 请求归属、整 guard 崩溃后的持久阻断，以及无关既有连接保持；这些是实现边界，不能只补一个验收文件或放开启动开关解决。没有可用 Windows 实机条件，本机 Windows 仿真保持禁止。默认签名 WinDivert 依赖保持不变；需在隔离 Windows x64 环境中确定并验证上述 OS 保护与解析边界。

这两项系统条件已连续三轮未具备。前两轮源码与语言工作有实质进展，本轮确认不能用更多便携测试替代缺失的原生条件。下一步需要项目方的合法 Mac NE 签名/profile 资产及 OS 授权，以及用户另行安排的 Windows x64 测试环境。完整目标未完成；浏览器、终端和九语言本地候选保持，附加软件保护启动继续关闭。当前只读计划及阻塞审计在 `test-artifacts/mac-routing/goal-blocker-current-plan.json` 和 `goal-blocker-audit.json`。没有运行用户软件、修改 VPN/TUN、购买开发者资产或发布 GitHub 内容。

## 九种界面语言与首次启动选择（2026-10-08）

新增简体中文、繁體中文、English、日本語、한국어、Español、Français、Deutsch 和 Português (Brasil)。每种语言覆盖相同的 562 个界面条目，插值变量和次数一致。桌面服务、BrowseForge 服务、Web 预览及安装包共用语言白名单；界面语言不修改境舱的浏览器语言、时区或网络配置。

首次启动根据系统语言推荐，选择时仅预览，确认保存成功后进入工作区；读取或保存失败保留明确重试入口。已保存有效语言的用户不重复初始化，独立终端窗口不显示首启对话框。

| 检查 | 本轮结果与范围 |
| --- | --- |
| JavaScript | 281 项：279 通过、2 项原生 Chromium fixture 明确跳过、0 失败；覆盖九语言词条、系统推荐、异步初始化、失败重试、双服务持久化与原有功能回归 |
| 前端与 Sites | `npm run build` 通过；构建后 `npm run test:sites` 4 项通过，保留三个 Sites 交付文件。构建有大块体积提示，不是错误 |
| 实际 Electron 工作区 | 11 项通过：九语言首启和设置、预览不提前写入、真实 IPC 确认、重载保留、六个工作页、实际 PTY/复制/放大恢复/独立窗口语言同步，以及拒绝未就绪的软件接管 |
| 视觉检查 | 当前原生首启和中文三栏截图已复核并放入 `docs/media/`。Web 首启在 390×740 下显示九种语言且无横向溢出；德语和法语设置与导航已检查 |
| Mac 本地包 | `release/mac-languages-20261008/mac-arm64/Envara.app`：47 个 archive 文件、184 个资源文件、54 个目录逐项核对通过，包含共用语言目录及当前前端；根应用仍未签名/公证 |
| 包内真实终端 | 3 项通过：加载完整展开的 node-pty、输入/输出/resize、私有目录与时区、自然退出/重开/明确关闭/shutdown；剩余所属进程 0 |

源码清单、日志和对应快照在 `test-artifacts/localization/languages-20261008.json`。原生界面报告为 `test-artifacts/workspace-smoke/workspace-smoke-languages-20261008.json`，包资源报告为 `test-artifacts/package-verification/0.5.0-darwin-arm64-20261008-languages.json`，包内 PTY 为 `test-artifacts/packaged-terminal/run-77xJmk/proof.json`。本轮 app.asar SHA-256 为 `6da9be5cc216240d18fc0f17d5e39fb0546cf5638a10461893694f78f09dbd28`。

原生界面验收在独立的开发 Electron 窗口加载当前生产前端，使用真实设置 IPC 和合成出口；包资源逐字节核对不是系统安装向导测试。截图中的出口数据不代表真实代理检测。此次未激活网络扩展、运行 Notion 或 Windows、修改 TUN，也未发布 GitHub 内容。附加软件完整分流仍未就绪，后续原生门槛见下文。

## Mac 每条流的进程归属与撤销检查（2026-10-08 当前快照）

自有 AppProxy 现在从系统提供的 `sourceAppAuditToken` 核对用户、PID、完整执行路径与执行世代，再即时检查属于当前 guardian 的父子链。仅同进程组、程序名或出生时间不能取得授权。只缓存曾真正提供审计 token 的 caller；父进程退出后复用授权须重新验证该 token，未审计的祖先不会自动获得孤儿授权。缺少 token、身份未知或首次流已无法证明父链时拒绝连接。

准入绑定不可变的 route、VPN realm、guardian 会话及 ownership 实例，安装 flow 前在同一锁内重读租约与时钟。撤销在锁内先封闭每条会话的资源注册，锁外执行单次取消；迟到清理仅删除自己的旧 session，settings 回调、重绑定和 timer 都检查所属生命周期，避免旧工作清除新路线。实际扩展调度、首包、整个 guardian/provider 崩溃仍须原生验证。

| 检查 | 本轮实际结果与范围 |
| --- | --- |
| Swift | **157/157 通过**。含执行世代、父链/孤儿/PID 复用、未知身份、延迟取消、租约、profile、指纹及本地 SOCKS transport；未激活自有 NE |
| 真实内核 token | 自有 pipe fixture 在相同 PID、出生时间、路径下执行同一路径；新世代变化，旧 token 拒绝、新 token 通过。另有两项真实 libproc 父/子与无关进程对照；其 generation callback 是注入 fixture，不冒充系统流验收 |
| 测试夹具修复 | 首轮有一项 PID 管道读取等待 EOF，第二轮暴露 `/bin/sh` 切换至实际 shell 映像的假设。改成有界逐行读取及同 birth/parent 的执行就绪核对，最终 focused 与全套通过；失败日志保留 |
| JavaScript | 281 项：279 通过、2 项原生 Chromium fixture 明确跳过、0 失败。界面及服务源码未在本轮改变 |
| 生产与诊断构建 | unsigned release 构建通过；诊断 host 逐字节复用当前完整生产 provider bundle，无第二份诊断 provider |
| 只读 plan | `authorized=false`、`extensionEnabled=false`、`productionReady=false`；全部自有原生检查 false。没有启动系统路由 fixture、Notion，安装 profile 或请求激活 |
| Mac 候选包 | `release/mac-flow-ownership-20261008/mac-arm64/Envara.app`：47 archive 文件、184 资源文件、54 目录、0 symlink 核对通过；原版 Redirector 签名/公证保留。自有 AppProxy 未就绪，根应用未签名/公证 |
| 包内终端 | 3 项真实 PTY 通过，私有目录/TZ、输入/输出/resize、自然退出/重开/明确关闭/shutdown；剩余所属进程 0 |

62 项源码/资源/构建/诊断文件的集合 SHA-256 为 `ed4d69c128d031252887e9ec09b85cdc0f43ce71d50f374a3e62d7172d66c8d4`；逐项清单、日志与范围在 `test-artifacts/mac-routing/flow-ownership-source-tests.json`。包资源报告为 `test-artifacts/package-verification/0.5.0-darwin-arm64-20261008-flow-ownership.json`；终端报告为 `test-artifacts/packaged-terminal/run-TYtikG/proof.json`。本轮测试专用 audit fixture 不进入桌面安装包。

当前仍没有 Envara 自有 NE 签名/profile 与原生验收 receipt。同域双 realm 的系统 DNS/缓存、子进程覆盖、故障保护、无关软件及 Notion 仍未验收；Windows 实机条件也未具备。没有运行 Windows/QEMU、改变 VPN/TUN、购买开发者资产或推送/发布 GitHub 内容。九语言首启及多语言 GitHub 文档的本地准备保持，上一个界面快照的范围见上文。

## 目标模式：双平台后续验收（待系统条件）

用户指定 Notion 为首个附加软件测试目标；开发机已只读核对其 7.34.0 版本、`notion.id` 和原版签名，未读取账号资料或启动用户会话。

| 检查 | 当前实际结果与边界 |
| --- | --- |
| Mac 原版资源 | 固定官方 mitmproxy-macos 0.12.11 / tag commit `40f1dfb5dca7b03ff7793d3c90f23b8bdf873889`，archive/双架构 Mach-O/Team/CDHash 核对；构建与安装前后原版签名、Gatekeeper 通过，无 CA truster |
| Mac 安装与授权 | 以原子 no-replace 安装至原版 Applications 路径，用户在系统中授权；`activated enabled`。不需要 Envara 开发者账号来运行这个未修改的外部组件 |
| Mac 本地桥接 | `routing:test:mac:local` 最新 22 组通过，新增两路认证 SOCKS→严格 TLS DoH、UDP/TCP53、EDNS/压缩/响应匹配与 TC→TCP fallback；不启动 NE，不等于 Notion或完整故障保护通过 |
| Mac 实际 NE | 正常 TCP fixture 已通过：真实原版签名控制与 flow peer 核验，认证 SOCKS 指定 `198.51.100.42:40443`，完整 2048 字节回包，1 条实际代理连接，0 次 peer 拒绝；测试子进程退出与 capture 清理通过。fixture 代理只在本地回显，没有连接这个保留地址。scope 写入后仅诊断等待 2 秒，未收到 ACK，不作为安全启动屏障。半关闭 fixture 失败：上游应用写 EOF 后取消整条流，不能以此代表正常流签名失效；Notion/DNS/子进程/故障仍待测 |
| 桌面回归 | 最新限并发 JavaScript 回归 262 项：260 通过、2 项明确原生 Chromium fixture 跳过、0 失败。前一快照的真实 workspace recovery smoke 9 项通过，含语言、六页、PTY/复制/独立窗口和拒绝未验收软件启动，出口为离线 fixture；本轮新增原生代码另行验证，范围见下文 |
| Windows 原生入口 | 添加隔离 VM 专用真实 capture test：认证 SOCKS、实际 root/child Job、UDP sensor、断线/撤销、不相关旧/新 TCP 对照。完整 `routing:test:win` 的便携 Go race、C/UBSan、amd64/arm64 vet/交叉构建通过，最新 amd64 lab SHA `c3d2e3105ba20fff6fc49688ba712482d3bc28772fdb0d8d5b443cab8cad64a2`；尚未 Windows 执行。独立 TCP owner / Win11 DNS API probes 同样仅编译 |
| Windows VM | 官方 Server2022 Eval ISO 下载并本地 rehash，4.70 GiB；本地 hash 不当作微软公布 hash。独立 TCG x64 VM 无 NIC/共享/转发；用户在许可页面同意仅用于离线测试，曾观察安装 79%，未取得完成或原生验收证据。因用户报告卡顿并要求停止，已确认 QEMU/测试进程不存在，禁止再启动；用户另安排 Windows 条件。Server2022 不是 Win11 DNS API 验证平台 |

随后 2026-10-08 的原生 Mac matrix 五项通过：owned 父/子各完整收回 2048 字节、真实签名 UDP datagram 阻断、已有流的上游 EOF、代理不可用后的新流拒绝且 0 字节回包。观察到实际系统 DNS UDP.local.port=0 由 proto3 省略后，修正只在 local context 默认 0，remote 非零端口规则保留；父/子各两条真实签名 DNS flow 归属通过，该阶段查询因阻断策略超时，不能算 DNS 解析通过。peer 拒绝、malformed 和 unknown 均为 0，owned fixture 与 capture 已清理。

新增 `scripts/accept-macos-dns-routing.mjs` 的真实系统 getaddrinfo 验收使用两组 owned 父/子、各自认证 SOCKS、本地严格 TLS DoH fixture，以及不同的 documentation IPv4/IPv6 答案。无用户数据、公共 DNS 请求、CA 安装或 VPN/TUN 设置变化。四个进程查询不同随机域名时，均收到本 route 的 A/AAAA；8 条 signed DNS reply、两 route 各4条认证 CONNECT，0 peer/decode/DNS error，未绑定控制进程的既有/新 TCP 回显也通过。首轮证据 `test-artifacts/mac-routing/native-dns-2026-10-07T16-28-30.534Z.json`。

更严格的同域并发对照 **失败**：两个 route 同时 system lookup 同一个随机域名，route one 有2条 A/AAAA signed reply；route two 返回已解析，却不是它自己的 reserved answer，并且没有自己的 signed reply。该阶段仅记录是否符合本 route 的答案，不能据此独立证明它取得哪一方的答案，也不能确认系统 resolver 合并查询这一具体根因。报告 `native-dns-2026-10-07T16-31-03.126Z.json` 明确 `isolatedQueriesPassed:true`、`systemResolverIsolationPassed:false`、`nativeDNSComponentPassed:false`。后续答案来源对照见本文最新复测。不能把不同域名回包成功升级为完整境舱 DNS 隔离。自动子进程、同 PID pre-exec 启动屏障、half-close、整个 guard 崩溃仍需修复与验收；正式 DNS/children/failClosed/ready 全部保持 false。

Windows 完整 x64 NSIS 候选实际构建于独立 stage，184,136,914 字节，SHA-256 `a15a28081034e10f0eb42ba47e568d9583e9d0c22c1def7f3f37ea3a14825e9a`。158 项资源和 PE x64、原 npm PTY 文件核对通过；不是 Windows 运行结果。新建交叉构建入口 `dist:win:cross` 保留主机输出，细节和 snapshot 证据见 [Windows 打包说明](windows-desktop-packaging.md)。

完整 DNS/子进程/故障/无关软件验收仍未完成；`ready:false`。GitHub 发布保持暂停。

用户报告系统中断后，已复查无 QEMU、Wine、MinGW 或所属 Windows 测试进程残留，源码、原版系统扩展授权和本地预览均可用。所有后续编译使用低优先级，Swift 限制为2个 jobs；没有重启 Windows VM、修改当前 TUN 或读取 Notion 账号数据。新 Electron 恢复报告保存在 `test-artifacts/workspace-smoke/workspace-smoke-mac-recovery-20261008.json`。

本轮先前 Mac `.app` 快照通过45个 archive文件、184个资源文件核对，以及包内3项真实 PTY检查；其资源报告已独立保存为 `test-artifacts/package-verification/0.5.0-darwin-arm64-20261008-pre-realm.json`，PTY证据为 `test-artifacts/packaged-terminal/run-QG46dY/proof.json`。这个快照先于自有 AppProxy realm修复，不能当作最后源码包的证据。

先前 realm 阶段的自有 AppProxy 源码检查 **57/57** 通过：精确 path/requirement/realm、聚合 profile、只读查绑定、重绑定、失败回滚，以及进程 alive/gone/unknown、故障/截断枚举、保留未知 scope。包含真实自身 libproc 和唯一 owned sleep 子进程自然退出；4项 unsigned RPC拒绝/状态检查通过，无 NE 或用户软件启动。21文件源码 SHA-256 `e49f9787a51a40b6467a4a8f79f5fd4b38fcef2d591a3f407f9aee66f6e8dcd5`，独立报告 `test-artifacts/mac-routing/app-proxy-realms-source-tests.json`。这些检查不能变成系统验收 receipt；该阶段尚未有专用签名 fixture 入口；后续独立诊断入口见下文，真正多个 active realm、DNS/缓存、Notion及完整故障验收仍未执行。

新 `.app` 位于 `release/mac-goal-20261008-realm/mac-arm64/Envara.app`，自有源码release编译限制2 jobs并完成。46个 archive文件、184个资源文件、54目录、0symlink核对通过；原版嵌套 Redirector签名/Gatekeeper仍通过。实际包内生产状态来自自有 AppProxy：installed/authorized/ready=false，原版组件的installed/authorized=true只进入diagnosticComponent。证据 `test-artifacts/package-verification/0.5.0-darwin-arm64-20261008-realm.json`，app.asar SHA-256 `c2e83d4cfd25e5cae148098e671bf0a10a415c2977f024f1b0d13624a1d8c96d`。包内真实PTY 3项再次通过、剩余owned进程0，证据 `test-artifacts/packaged-terminal/run-9pz6jB/proof.json`。根应用仍未签名/公证；没有生成DMG/ZIP或发布。

## Mac 独立 fixture 入口与启动清理（2026-10-08 较早快照）

新增受编译标志隔离的原生诊断入口，host/provider/group/profile 标识与生产路径分开，输出为 `build/acceptance-app-routing/macos/EnvaraRoutingAcceptance.app`。只选择两个签名封存的自有 fixture；拒绝用户软件路径、命令、环境和目录。严格验证同证书/Team、完整 bundle 路径和封存后的 binary SHA。只读计划不激活；生成 profile 与提交 OS 激活是分别明确的操作，激活不替换既有扩展。未签名的实际工具已验证拒绝这些操作及启动。

普通软件的生产门槛不变。新增会话日志可读性与进程范围确认分离；损坏/未知范围保持未就绪。`launch` 固定原始 guardian 的父进程、路径和出生身份，并在全部启动后失败路径限定清理；guardian 在可能抛错的日志 IO 前核对子进程路径/父进程/进程组并安装清理，停止信号在启动前接好。未知身份不误杀、不释放路由。

| 检查 | 实际结果与范围 |
| --- | --- |
| 自有 Swift | 66/66 通过：原 57 项加 9 项 fixture 协议/私有 socket/系统 localhost resolver/真实 TCP 半关闭、UDP 和超时；未启动 NE |
| 自有 fixture 二进制 | 7/7 本机离线检查：UID 校验的0600 Unix socket、拒绝公共域名和覆盖 socket、2独立自有子进程及 localhost resolver、父 TCP2048 半关闭、子 UDP、200ms超时、明确关闭/停止及 socket 清理；剩余 fixture 进程0 |
| JavaScript | 232 项：230通过、2项原生 Chromium fixture 按既有规则跳过、0失败；重新编译后6项签名/生产RPC隔离/unsigned拒绝测试再次通过 |
| 真实桌面 | 新9项 Electron workspace smoke通过；离线合成出口，不启动 Notion/NE/浏览器内核。报告 `test-artifacts/workspace-smoke/workspace-smoke-mac-fixtures-20261008.json` |
| 新 Mac 包 | `release/mac-goal-20261008-fixtures/mac-arm64/Envara.app`，46 archive文件/184资源/54目录/0symlink核对通过；原版嵌套签名与Gatekeeper保留，生产 AppProxy 的 ready=false |
| 包内终端 | 3项真实PTY通过，退出/重开/明确关闭/shutdown后剩余owned进程0；`test-artifacts/packaged-terminal/run-4rHDJa/proof.json` |

31项源文件集合 SHA-256 `1384d79c40466a062e4c50822e0b121033f657163ee81c450e5a9fae451bf427`，明细、日志摘要与离线范围保存在 `test-artifacts/mac-routing/fixture-source-tests.json`；离线二进制报告为 `fixture-offline-proof.json`。包独立核对报告 `test-artifacts/package-verification/0.5.0-darwin-arm64-20261008-fixtures.json`，app.asar SHA-256 `c5f6d50b0c759f8328a367dca256e25c9760c5847ae218c4cee3ae0fb7be777d`。

只读 `routing:accept:mac:plan` 实际返回 authorized=false/extensionEnabled=false，全部原生检查false。没有自有Apple网络扩展签名/profile，也未激活这个扩展。诊断 provider 的标识与字节不同于生产 provider，不能据此创建生产 receipt；实际生产 provider、多个 active realm 的同名DNS/缓存、首包、整个guardian/provider崩溃、无关软件及Notion仍待验收。新根app仍未签名/公证，没有DMG/ZIP或发布；没有运行Windows/QEMU，也没有改变当前TUN。

## Mac 租约、原版组件复测与生产字节复用（2026-10-08 先前快照）

**不需要先申请 Apple 开发者账号才能继续使用现成原版签名组件。** 自研或修改网络扩展后签名分发才需要发行方的合法 Apple 授权资产；使用者无需自己申请账号。原版 Redirector 路线保留，完整隔离尚未通过，不能借它已有的授权启用未签名自有 AppProxy。

用户报告已关闭 TUN 后，重新执行原版已授权组件的 owned fixture 系统 getaddrinfo 测试。本工具未独立验证系统 TUN 配置，也没有改动网络设置。两个境舱的四个父/子进程查询不同域名均取得各自 A/AAAA；同域并发时第二境舱返回已解析但不符合本 route 的答案，自己的 signed reply 为0。该阶段没有记录答案来源，不能直接称其收到另一境舱的具体答案；后续来源对照见本文最新复测。结果仍为 `systemResolverIsolationPassed:false`、`nativeDNSComponentPassed:false`，不能将问题仅归因于 TUN。两个未绑定诊断控制连接通过，仅覆盖这两个本地连接；所有 fixture、capture 和私有工作区清理完成。报告 `test-artifacts/mac-routing/native-dns-2026-10-07T17-58-53.194Z.json`。

自有路径新增基于进程身份、boot UUID 和连续时钟的 guardian 租约；启动前要求 provider 确认同一会话，准备但未取得租约时拒绝流。过期、关闭、身份未知或回放租约会使路由失效并取消所属连接，不释放未知进程范围。连接资源注册和异步取消共享单次关闭状态；RPC 超时不视为撤销成功。这些行为目前由源码及本地 transport 测试验证，不能替代 OS 调度、扩展崩溃或真实断线时序验收。

诊断 host 现在沿用生产 host/provider/group 标识，并**逐字节复用完整生产 provider bundle**；运行目录、profile 和 realm UUID 仍用独立 `owned-fixture-acceptance` namespace。这修正了上一个快照中诊断与生产 provider 字节不同的问题。完整 bundle 指纹包含相对路径、类型、权限和内容，receipt 同时绑定该指纹与可执行文件 SHA；原生 gate 未通过时不生成生产 receipt。只读安装配置检查只确认当前命令可见的 user/computer 范围，明确不代表全系统扫描。

| 检查 | 当前实际结果与范围 |
| --- | --- |
| Swift | 114/114 通过，含租约、资源取消、身份、profile 范围、完整 bundle 指纹及真实本地 SOCKS transport；未激活自有 NE |
| JavaScript | 262 项：260通过、2项原生 Chromium fixture 明确跳过、0失败；限制并发为2 |
| 重编译后的原生门槛 | 12/12 通过；unsigned helper 拒绝受保护启动/激活，诊断 RPC 隔离，复用的生产 provider 完整字节一致 |
| 诊断 CLI | 默认只读 plan 返回 authorized=false/extensionEnabled=false；明确 `--run-fixtures` 在授权门槛拒绝，未启动 fixture/监听器或原生路由。独立快照 `lease-cli-plan.json` 与 `lease-cli-native-fixtures.json`；全部自有原生 gate 仍false |
| Mac 候选包 | `release/mac-goal-20261008-lease/mac-arm64/Envara.app`：46 archive文件、184资源文件、54目录、0symlink核对通过；原版嵌套签名/Gatekeeper保留，根应用未签名/公证，自有接管仍未就绪 |
| 包内终端 | 3项真实 PTY 通过，输入/输出/resize、私有目录/TZ、退出/重开/明确关闭/shutdown，剩余owned进程0；不代表本轮 UI、远端账号或代理网络验证 |

54项原生源码、资源、构建与诊断测试文件的集合 SHA-256 为 `9ac4df3d0b7e4ec35846a6cc50d7f12775ec4a37450d0e299d10d8419369a5c7`，算法及逐项清单在 `test-artifacts/mac-routing/lease-source-tests.json`；日志分别封存为 `lease-source-*.log`。生产 provider 完整 bundle SHA-256 为 `242ab59a42e8f17f6fa41ee4f9403153dd5589e88ad7cec76247836703327852`，binary SHA-256 为 `f371c74c4ef001967e5987bbffc08b5ea10af0fa220b002cbd926a50777d9e3f`。

包资源快照为 `test-artifacts/package-verification/0.5.0-darwin-arm64-20261008-lease.json`，真实终端报告为 `test-artifacts/packaged-terminal/run-mw6XHU/proof.json`。app.asar SHA-256 仍为 `c5f6d50b0c759f8328a367dca256e25c9760c5847ae218c4cee3ae0fb7be777d`：本轮 Electron/前端归档未变，更改位于单独核对的原生资源。

没有启动 Notion、安装 profile、激活自有扩展或生成正式 receipt；多个 active realm、同域 DNS/缓存、首包、整个 guardian/provider 崩溃及无关桌面软件仍待原生验收。没有运行 Windows/QEMU、购买开发者资产或发布 GitHub 内容。

## Windows WinDivert 后续源码候选（先前阶段）

默认路由由自写 WFP 驱动改为 WinDivert 2.2.2-A 原版签名 x64 依赖、Envara capture DLL 与 Go guard。原 WFP 源码保留为未启用备选。这轮是组件源码与二进制检查，**没有完成 Windows 软件分流**，没有发布。此前 Mac 安装包没有包含这轮新增的 capture/installer，不能以它的旧包验证结果代表新源码。

| 检查 | 实际结果与范围 |
| --- | --- |
| Windows Go | `routing:test:win` 的全包 race、host vet、amd64/arm64 Windows vet 与 PE 交叉构建通过；Windows host 测试二进制仅编译，没有执行 |
| 原生 C | 生产 capture core 的完整 IPv4/IPv6 tuple NAT、socket 事件时间、单次 claim、PID 复用、撤销、FIN/进程退出 lease、容量检查，在本机实际编译并运行通过；UBSan 通过。保留旧驱动的便携生命周期/ABI 检查通过 |
| 捕获 DLL | MinGW 实际构建 x64 PE32+ DLL；恰好 5 个 ABI 导出，依赖 WinDivert、Windows IPHLPAPI/WS2_32/Kernel32/UCRT，没有外部 OpenSSL/TCP 栈。没有加载 DLL 或驱动 |
| 资源与来源 | 固定官方 ZIP `63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`，完整源码归档 `2955621df8f6ef32ad65170f0c0f11bd2f261cf5a960624f416d0b9c6343e99c`；原 SYS/DLL 哈希核对，SYS 原证书表保留，尚未 Windows 信任/加载验收 |
| ARM64 | Go helper/test 二进制可交叉构建；原版依赖没有 ARM64 驱动，构建明确生成 capture unavailable 说明，不能称 ARM64 接管支持 |
| 安装脚本 | 默认只读 Validate/Plan；显式 Install 创建受保护目录、SCM 服务；显式 Uninstall 仅卸载所属服务、保留文件。PowerShell grammar/schema 静态检查，不是 Windows UAC/ACL/SCM 执行结果 |
| JavaScript 回归 | `npm test` 共 223 项，221 通过、2 个显式原生 Chromium 测试跳过、0 失败。本轮未再启用浏览器 fixture；下方 0.5.0 的 223/223 是先前实际 Chromium 环境的记录 |
| Mac 外部组件 | 官方 mitmproxy-macos 0.12.11 wheel 固定 SHA；`codesign --verify --deep --strict` 通过，Redirector/app extension Team ID=S8XHQB96PW，Gatekeeper accepted / Notarized Developer ID。只在 /tmp 检查，未安装/运行/授权扩展或 CA |

独立源码复核修正了旧 socket 快照放行、身份数组槽复用、relay 同端口误拦、TCP 关闭后 NAT lease 未回收问题。Go 在累计身份达到 960 时撤销路由、终止并确认全部 Job 停止，再停止捕获；终止失败保留 capture/Job 并重试。同一已排空的服务实例不自动重启捕获。这些机制尚需 Windows 压力/故障实测。

仍有实质实现门槛：共享系统 DNS 未适配；stock WinDivert 在整个 guard 崩溃时不能保证持续阻断；捕获前旧 socket 与无法归属的 fragments 会影响无关软件；系统驱动加载、管理员安装、真实进程/socket 复用、双境舱、VPN/TUN 共存与清理未实机验收。`ready/dns/failClosed/verification` 始终 false，普通用户启动拒绝。没有接触用户节点或凭据，没有修改 TUN。详见 [实现与备选路线](application-routing-options.md)。

## 0.5.0：专用工作页、语言与隐私

| 检查 | 本轮证据与范围 |
| --- | --- |
| JavaScript | 223/223 通过、0 跳过；包含指定已有 Chromium 可执行文件的真实请求拦截/定位及顶层导航测试 |
| Go 服务 | 全包 go test ./... 通过；保留 BrowseForge Chromium 原生身份参数，仅 Mac Cloak 添加已实测的 Intl locale 兼容选项 |
| 构建 | Vite/桌面渲染产物生成，Sites 4 项通过；未发布站点或 GitHub 发行版 |
| 原生桌面 | 9 项通过：六页中文导航、英语保存及重载、自动地域上下文、真 PTY、复制新进程、放大/还原、独立窗口、权限范围与关闭清理 |
| 桌面视觉 | 10 张原生 PNG；截图等待实际 compositor presentation 后再次目视检查，环境、浏览器、软件与放大终端均为对应页面 |
| 两种真实浏览器 | 8 项通过：headed CloakBrowser 145 / Camoufox 135 的标准/严格/关闭模式，正常 HTTP 200、追踪请求中止与实际计数差异 |
| 自动语言与区域定位 | 两内核 navigator.language 与 Intl locale=en-PH、时区 Asia/Manila；定位 14.6,121、精度 50000m。出口由离线合成 PH 数据提供，不是公网节点证明 |
| 无坐标保护 | Cloak 原标签及 2 个新标签均权限 denied、getCurrentPosition 错误码 1；Camoufox 3 个标签均禁用定位 API。两机制分开验证，不把本机位置用作回退 |
| 真实终端 | Electron PTY 验收通过：本地工具、私有 HOME/Claude/历史、代理感知 CLI、本地 SOCKS 认证/远端 DNS、同境舱复制及进程清理；网络范围仍为 proxy-aware-cli |
| 包内终端 | 3 项通过：app.asar 内 TerminalService/原生 node-pty、打包 Node、输入输出/resize、自然退出/重开/关闭；所属进程剩余 0 |
| 最终包资源 | 27 份 archive 文件、155 份资源文件及 41 个目录全量清单/SHA/权限一致；含完整后端、Playwright、核心对应源码/许可证与各原生候选组件，开发 harness/开发签名输出不进入包；原生 helper 真实 ready=false |
| 浏览器误拦回归 | 同服务兄弟域 API 保留，外站仍拦；顶层导航按目标站点识别，不按旧页面误拦。真实 Chromium 仅访问 loopback proxy，验证导航可到 fixture、前后第三方 fetch 均被中止 |
| Mac 原生模块（暂停部署） | 默认/开发宏 release 编译、18 项 Swift、3 项 Node、两个 helper 共 6 项真实 RPC 拒启动检查通过；开发输出隔离，unsigned 清签名/profile/receipt 残留。未签名、未激活、无正向 Apple profile 验收，ready=false；不是系统分流验收 |
| Windows 原生模块（优先） | race/host/Windows vet、便携 C 生产生命周期/ABI、x64/ARM64 PE 交叉编译通过；BFE 撤销/过滤重建、认证 SOCKS→TLS→DoH 成功/证书拒绝/TTL Age 已本地检查。共享 DNS 适配、WDK 构建、签名及 Windows 网络/BFE 故障时序未完成，ready=false |
| 软件绑定与启动保护 | 原生桌面绑定本机 TextEdit，组件未就绪时真实拒绝启动，无 PID/会话或直连回退；组件丢失会话时标异常并清理，未确认清理时保留配置修改锁 |

桌面报告为 `test-artifacts/workspace-smoke/workspace-smoke.json`，最终浏览器报告为 `test-artifacts/privacy-sidecar-smoke/run-Dbl8JJ/proof.json`，终端为 `test-artifacts/terminal-smoke/run-jyL5ev/proof.json`，包内终端为 `test-artifacts/packaged-terminal/latest-proof.json`。测试数据与进程均为隔离工作区；没有使用用户节点、Claude 登录或远端账号，没有要求关闭 TUN。

全包 JavaScript 检查曾发现旧核心测试以固定 10ms 等待异步目录删除，在并行编译期间误报。断线状态立即失效的断言保留，目录清理改为等待真实 cleanupPromise；223 项最终全部通过。这个修正没有更改生产核心的停止策略。

最终全量包核验为 `test-artifacts/package-verification/0.5.0-darwin-arm64.json`；复核命令为 `npm run test:package:resources -- /absolute/path/Envara.app`。它核对当前源码与所有配置资源；权限按已核对的 electron-builder 规则记录两端原始值与规范化后的预期值，ASAR 只验证可执行标志，不伪称完整 POSIX mode 或 Windows ACL 验收。最终包内 PTY 记录为 `test-artifacts/packaged-terminal/run-iCjJLY/proof.json`，3 项通过且所属进程剩余 0。

本地 DMG `Envara-0.5.0-mac-arm64.dmg` 为 230332478 字节，SHA-256 `d4d849d6a9bea38067e5a7b25701ab08b8901047f450574a6bfa062f509eb8a0`，hdiutil verify 有效；ZIP `Envara-0.5.0-mac-arm64.zip` 为 228193560 字节，SHA-256 `39f4556fd341fbb5eabc4a22d8135d3817f1cec8cd4fcaa43d4bf535a4a4c426`，unzip -tq 通过。候选包未签名、未公证；Mac 附加软件未启用，Windows 组件不可用。没有推送或公开发行版。

本轮没有重新验证真实节点出口、Alpha 内核、全部检测器、Windows GUI、签名后 Mac 扩展的进程/DNS/断线行为或所有应用的系统定位。已知域名拦截及工具遥测退出变量不能保证消除全部追踪，也不能保证账号不会被关联。附加软件强制分流仍是未完成模块，不能用浏览器与终端的成功结果替代。

## 0.4.0：内置 AnyTLS

| 检查 | 当前证据 |
| --- | --- |
| JavaScript 测试 | npm test 193/193 项通过，记录见 test-artifacts/runtime-0.4-full-tests.log |
| 独立代理核心资源 | 固定 Mihomo v1.19.32 / commit 88dcbf7f1614a67c3b36b848ee3592dfa92ada36，官方 Mac arm64 二进制摘要与原生版本执行已核对 |
| 许可与对应源码 | 完整 GPLv3、固定源码/vendor 与 provenance 已准备；9 项资源测试、GOPROXY=off / -mod=vendor 实际离线重建与最终包内副本 SHA 核对通过 |
| AnyTLS 原生链 | 19/19 项通过：真实 Mihomo/TLS认证、默认拒绝不可信证书、私有入口认证、错误密码/节点不可达/服务停止均无 DIRECT 回退 |
| 浏览器/终端联动 | 真实 Cloak 可见会话与 Electron PTY 经同一路由访问 HTTPS，使用明确合成 Geo JSON 的一致时区；目标站点不收到节点或桥凭据 |
| 受管绑定与恢复 | 直接 REST/MCP 缺少临时入口时拒绝启动；后端重启保留原节点/分组绑定而无动态凭据。杀掉核心后使旧 Geo 失效，聚焦恢复相同端口/认证，原浏览器与 PTY再次HTTPS成功 |
| 清理 | 17 个观测到的所属进程全部退出，端口关闭、synthetic credential文件清理；不影响无关进程 |
| 一条真实外部节点 | 原始域名、产品默认行为、严格证书和 SNI/ALPN/chrome/UDP 下，example.com 200、ipwho.is 检测 PH / Philippines / Manila / Asia/Manila。本机 TUN 开启与用户主动关闭后均通过；没有外部 Clash 本地代理，凭据未保存到工作区 |
| TUN 兼容范围 | Mac 只读识别物理接口并仅用于节点与 AliDNS IP DoH，未改系统网络设置。测试者关闭 TUN 后仍使用默认管理器/no override，经 en0 成功；其他平台接口适配与原生运行未验证 |
| 包内 AnyTLS 链 | 20/20 项通过，实际 App Electron 从 app.asar 加载 5 个运行模块，使用打包核心/后端/Node/PTY；浏览器与终端、恢复及拒绝回退通过，17 个所属进程全退出 |
| 包内终端 | 3/3 项通过：真实输入输出/resize、私有目录/时区、自然退出/重开/关闭/应用退出；剩余所属进程为 0 |
| 原生高级字段 UI | 源码运行的 Electron 保存 ALPN h2,http/1.1 与 UDP false 后编辑回读一致；SNI 恢复、TLS 默认开、密码掩码、不可达节点显示失败通过。不覆盖全部 GUI 或新包 GUI |
| 最终包资源 | 30 份源码/前端/许可证/核心及完整对应源码/provenance/后端文件 SHA 逐字匹配，package 元数据匹配、Node 可执行；DMG/ZIP 完整性通过。本地 Mac arm64 包未签名且未公证，发布仍暂停 |

新增链路只控制所属本机进程，原始节点密码、域名和随机桥认证不进入公开文档。原生 fixture 的地理 JSON 明确为合成数据，不是公网出口证明；真实供应商节点的出口另有独立 HTTPS 证据。该单节点结果不代表所有供应商、远端账号或所有 CLI 已验证。ALPN 是数组、UDP 默认 true，但私有 HTTP 入口不等于通用 UDP 转发。

原生链为 `test-artifacts/anytls-smoke/run-SIdTv5/proof.json`，真实节点/TUN 开启与关闭分别为 `test-artifacts/anytls-private-node/run-dWdWBT/proof.json`、`run-v2ajQf/proof.json`，资源为 `test-artifacts/proxy-core-preparation/proof.json`。官方 Mihomo SHA-256 为 `94a386ec0149080deadd86b1f667363bde3c70f7489dba3258e52c56fc9a6d66`；对应源码归档为 `6859f30fa7ef47eea24a535e52711d91026adeac905768443aaf1d6f5955dddb`，包含 9007 条目、7754 vendor 条目及 152 份许可/归属文件。源码重建不宣称与官方二进制字节一致。

包内链为 `test-artifacts/anytls-packaged/run-HIooJP/proof.json`，PTY 为 `test-artifacts/packaged-terminal/run-EWQLtE/proof.json`，资源为 `test-artifacts/package-verification/0.4.0-mac-arm64.json`。最终 Go 后端 SHA-256 为 `7e89f026d2d220068bc2f1bbc49f446904aee06d3c3c3621e38a9beec9c33191`，源码树为 `04a48b6ebb0badf76f6f370920722ad3d25e3a3f6ee564bc7a541baec0866759`。原生 UI 证据为 `test-artifacts/native-ui-0.4/run-NN5VHj/proof.json`、`anytls-advanced.png` 与 `anytls-roundtrip.png`。这些资料留在本机，不含公开节点凭据。

本地 DMG `Envara-0.4.0-mac-arm64.dmg` 为 225250056 字节，SHA-256 `c3b129e7237a1c0bfef9f1cdb48843d234a85874f685f8474c6f811a1e8f616a`，hdiutil verify 有效；ZIP `Envara-0.4.0-mac-arm64.zip` 为 223119351 字节，SHA-256 `5d68d044619ae5a73720b8615406d2da775f20945303ef8c0a17e112155ddd38`，unzip -tq 通过。它们不是公开发行版，也没有应用签名或公证。

## 0.3.0：出口时区与每环境终端历史基线

| 检查 | 当前证据 |
| --- | --- |
| 功能实现 | 认证代理 HTTPS 出口检测、自动时区解析、原生工作目录选择、每环境 PTY 与独立工具配置已接入 |
| JavaScript 测试 | npm test 145/145 项通过；终端 36 项包含在总数中 |
| 原生模块准备 | node-pty 1.1.0 在 Electron 44.6.0 / Node-API 10 上通过实际 PTY 预检；15 份依赖许可证已准备 |
| Cloak 本轮原生回归 | 11 项通过，包括空服务、43 项 MCP 目录及 3 个真实工具、双可见会话手动身份、隔离与持久化、认证 HTTP、克隆/导入、真实资料迁移及退出 |
| Camoufox 与 Alpha 本轮执行 | 当前 0.3.0 记录未安装或执行这两个内核；三 provider 的目录能力读取不算运行验收，历史结果保留在下一节 |
| 冻结源码真实终端 | Electron 44.6.0 / Node 24.21.0 的 12 项真实 PTY 验收通过；跨境舱分离、代理桥请求、同境舱复制、源/副本独立退出及目录锁定通过 |
| 终端测试 | Service 18 项、Process 6 项、Bridge 12 项，共 36 项单元及本地进程/网络测试通过，包含复制/取消竞态 |
| 独立历史与退出 | 6 项历史布尔校验全为 true：各自标记保留且不交叉、0600 权限、重开保留；最终剩余所属进程为 0 |
| Go 后端 | 本轮全包测试及 API/browser/profile race 检查通过 |
| 会话临时时区原生参数 | 3 项检查通过：拒绝非法字段而不启动浏览器、Cloak 原生身份使用本次时区但不改保存配置、下一次无临时参数仍使用保存的手动时区 |
| 直连真实出口到终端与旧字段兼容 | 7 项真实检查通过：实际 ipwho.is HTTPS 公网出口返回 America/Los_Angeles，默认 node-pty 中的打包 Node 同时报告一致 TZ/Intl；自动配置不改。旧指纹语言/时区保持固定，明确切自动才清除并重新识别；0 个浏览器会话，正常退出 |
| 外部代理供应商自动时区 | 本轮直连证据不代表用户代理供应商已验证；代理出口到浏览器/终端的完整实际链路单独验收 |
| 最终候选包真实终端 | 3 项通过：从 app.asar 使用完整展开的 node-pty，输入输出/尺寸/打包 Node/私有 cwd 与配置/时区、自然退出/重开/关闭/应用退出；剩余所属进程为 0 |
| 包资源与归档 | 19 份源码/前端/许可证文件 SHA 匹配，package.json 语义匹配，当前入口/控制器/前端/终端代码已冻结；后端与原生证据一致，Node 可执行，15 份许可证完整，DMG/ZIP 完整性通过；个人旧配置保持原样 |
| Web 构建界面 | 当前 JS/CSS 构建的高度拖动、键盘调节、放大恢复与复制到 8 标签测试通过；不是原生 PTY 界面验收 |
| 原生终端 UI 核心操作 | 实际 Tokyo 会话 A 的 pwd/date 输出、放大/恢复持续运行、复制 B 为新 PTY、B 独立窗口 pwd 通过；明确关闭 B 后 A 仍运行，独立窗口再次输出 JST。关闭独立视图后返回主窗，A 继续运行且输出保留 |
| 原位已有会话复用与其他 GUI | 复用由服务/单元测试覆盖，未单独执行该原位 GUI 路径；全部 GUI 按钮未逐项验收 |
| Claude CLI | 未执行安装、登录或真实远端请求 |
| 其他操作系统 | 原生模块、终端、出口时区和安装包尚未实机验收 |

本轮成功出口检测必须来自通过指定网络发出的 HTTPS 请求，包含有效公网 IP 和 IANA 时区。代理入口地址、预设时区或地理服务失败均不算成功。自动模式下有代理且检测失败时阻止启动；无代理时允许明确标记为本地来源的时区回退。

配置与时区仅作用于 Envara 拥有的子进程；真实 PTY 测试使用独立资料和本地认证代理，直连出口测试使用真实 HTTPS 地理服务。它们证明配置分离、已测自动时区链与代理感知客户端路由，不证明操作系统沙箱、所有程序强制代理、住宅地址或账号不会被封禁。退出证据覆盖已记录归属的 shell 与后台子进程，不保证捕获提前完全脱离的守护进程；macOS 进程出生标记使用秒精度。关闭视图保留会话已在原生桌面观察，明确结束会话或退出应用才清理所属进程。以下 0.2.0 的计数与哈希只作历史基线。

终端记录为 `test-artifacts/terminal-smoke/run-j1qwoT/proof.json`，会话时区记录为 `test-artifacts/sidecar-prototype/session-timezone-9ylq6ufu/proof.json`，Cloak 回归为 `test-artifacts/sidecar-smoke/run-NwBoJB/proof.json`。后两项的后端 SHA-256 均为 `1ba3ab54ebc038a68f978ab364344aebcf6c9b62f9c7be15179eb871cd5f0ff7`；回归记录的后端源码树 SHA-256 为 `bec6c2c836b4e58b1af6efa89659886d19e9216a0f35fbf2d00deb949e44807b`。npm 总数见 `test-artifacts/final-0.3-tests.log`。这些是本机隔离验收资料，不是公开浏览器归档、应用签名或发布认证。

直连与旧字段兼容记录为 `test-artifacts/auto-egress-terminal/run-nAADv9/proof.json`，公网 IP 已脱敏；它使用上述后端，不下载或启动浏览器，也不调用 CLI 账号。最终候选包终端记录为 `test-artifacts/packaged-terminal/run-blswCc/proof.json`，只证明包内终端加载与生命周期，不覆盖 GUI、远端 CLI 或代理路由。Web 界面验证使用当前 `index-8k7Db2PH.js` 与 `index-lJzzvbOD.css`；演示适配器的 8 标签检查不替代真实多窗口验收。

包核验记录为 `test-artifacts/package-verification/0.3.0-mac-arm64.json`。原生核心操作由完整截图 `test-artifacts/terminal-qa/18-native-independent-shell.png`（2200×1520）与 `19-native-expanded-surviving-shell.png`（3000×1880）复核，测试与截图保持在本机隔离目录。截图证明所列操作，不扩大到全部桌面流程；这轮没有推送或发布。

## 0.2.0：多内核本地服务历史基线

固定 BrowseForge v2.1.15、提交 fa9e0bb670e749706a9c8f2d4095333347d6c521，加入桌面补丁。上游能力、适配源码和旧版结果不能直接等同于新路径验收。

| 检查 | 当前证据 |
| --- | --- |
| JavaScript 测试 | npm test 65/65 项通过 |
| Go 后端 | 全包测试通过，browser、API、MCP 的 race 检查通过 |
| 固定后端与 REST 适配 | 新服务原生回归通过；基本打包 UI 只读验收通过，全部 GUI 操作未逐项验收 |
| macOS arm64 后端资源 | 已生成 sidecar、完整官方 Playwright driver 1.61.1 与 Node 24.18.0；7 项资源准备辅助测试通过 |
| 冻结源码原生回归 | 新服务两家族完整回归 12 项通过 |
| 并行启动专项 | 6 轮并行启动共 12 个新 Cloak 环境，每个仅一个测试标签页，未出现额外启动页 |
| 空工作区 | 零内核时本机服务正常启动，私有 REST 需认证 |
| MCP | 初始化与 43 个工具枚举通过；evaluate、get_content、list_tabs 已操作真实浏览器 |
| CloakBrowser 145.0.7632.109.2 | 两个可见窗口并行运行，独立手动语言、Intl、时区、屏幕及系统画像通过 |
| Camoufox 135 | 官方安装及可见 Firefox 与 Chromium 同时运行通过；手动身份匹配，Firefox 的 zh-Hans-CN 与请求 zh-CN 语义一致 |
| 数据隔离与重启 | CloakBrowser 两环境 Cookie/localStorage 隔离与持久化通过；Firefox 跨内核隔离和 localStorage 重启保留通过 |
| 认证 HTTP 代理 | 新服务实际浏览器请求经过本地认证代理，通过认证 |
| 克隆与配置导入导出 | 克隆更新种子，导出移除凭据，导入保持明确映射的代理 |
| 旧资料迁移 | 复制真实 Cookie/localStorage、本机代理凭据并校验备份，原配置字节不变 |
| 会话生命周期 | 聚焦复用当前页，最后原生标签页关闭后回收会话；服务重启保留环境与元数据 |
| 退出 | 本轮托管浏览器与后端进程已全部关闭，剩余数量为 0 |
| BrowseForge Chromium Alpha | 官方安装和可见会话、手动身份、真实截图、停止及关闭通过；版本标记 v0.1.6-alpha.0，实际 Chromium 150.0.7871.101 |
| 分组代理与批量操作 | 适配源码已接入，完整桌面流程尚待验收 |
| 打包代码与后端一致性 | app.asar 中的入口、服务管理/客户端/适配代码和前端构建文件与冻结版本逐字匹配；后端 SHA-256 与最终原生回归相同 |
| 打包运行资源 | Node 可执行文件、provenance 和许可证资源完整 |
| 新版本 .app、DMG、ZIP | macOS arm64 已构建；hdiutil verify 确认 DMG 有效，unzip -tq 确认 ZIP 无错误 |
| 打包应用启动与布局 | 本机启动通过，原生三栏完整，显示真实空环境、已安装内核和旧环境提示 |
| 迁移预览与取消 | 显示真实旧环境，未确认时迁移按钮禁用；取消后新环境仍为空，内核目录保留 |
| 新建表单 | 默认已安装 CloakBrowser、about:blank，语言/时区、高级折叠与固定操作区完整；未提交新环境 |
| Windows、Linux、macOS Intel | 新版本尚未完成实机验收 |

以上原生证据来自 macOS Apple Silicon 的独立工作区、真实可见浏览器和本地测试站点/代理。冻结源码的手动身份和并行启动补丁已重新完成回归。Alpha 是单独的实验性内核测试，不并入两家族的完整回归结论。

该轮冻结源码记录为 `test-artifacts/sidecar-smoke/run-Wed9Ik/proof.json`，并行专项为 `test-artifacts/sidecar-smoke/parallel-fixed-S4ov8I/proof.json`；Alpha 独立记录为 `test-artifacts/alpha-smoke/run-jcUD6L/proof.json`。latest-proof 别名可能随新测试更新，历史复核应使用该轮路径。这些隔离产物不提交至公开仓库，也不是安装包签名或浏览器归档摘要验证。

该轮后端二进制 SHA-256 为 `915faddfe43506aa2cc4887e2b1b7e386d1399a1e1847c08ecfb085cb52d8acd`，源码树 SHA-256 为 `ddde9f2114ccef3e7f7a2c4cea1fb583e0b4f617483cc6bdb05c0fed073ccdc3`；它们与最终资源构建记录及打包后端一致。本机包资源记录为 `test-artifacts/package-verification/0.2.0-mac-arm64.json`。最终原生界面截图经完整 3000×1880 图像检查，覆盖主页、迁移预览和新建表单；截图留在隔离验收目录，不作为公开演示数据。

## 0.1.x：旧直接驱动路径的历史证据

0.1.0 功能验收在 macOS Apple Silicon 完成，0.1.1 补充 Linux 发布元数据。该路径使用 cloakbrowser@0.5.12 和 Chromium 145.0.7632.109.2。

| 检查 | 历史结果 |
| --- | --- |
| 核心测试 | 24 项通过：15 项后端、9 项运行适配器 |
| Sites 构建与路由 | 4 项通过 |
| 打包 .app | 原生界面创建、启动和停止通过，从 app.asar 加载 |
| macOS arm64 DMG、ZIP | 已构建，DMG 完整性校验通过 |
| 设置页安装 | 打包应用从实际设置界面主动安装官方内核 |
| 两个可见会话 | zh-CN / en-US、上海 / 纽约时区、各自屏幕尺寸通过 |
| 语言一致性 | navigator.language、navigator.languages 和 Intl 默认语言匹配 |
| Cookie 与 localStorage | 环境隔离和停止/重启后的持久化通过 |
| 认证 HTTP 代理 | 浏览器请求经过本地测试代理并通过认证 |
| 克隆、导出、重载 | 通过，新环境只有一个正常启动标签页 |

旧测试使用独立工作区和本地站点、代理，不使用个人登录环境。历史结果用于回归对照，不自动覆盖新 sidecar。

## 范围与复核

0.1.x/0.2.0 的代理原生证据覆盖本地认证 HTTP 代理，不能据此宣称 HTTPS、SOCKS5 relay 或外部供应商出口已通过。0.2.0 的界面检查只验证 TCP 连通性；0.3.0 替换为实际 HTTPS 出口检测，并为终端增加 SOCKS5 桥。冻结终端的真实 PTY 已覆盖本地认证 SOCKS5 请求及独立副本的路由；外部供应商验证仍单独记录。

0.2.0 打包 UI 验收为只读：未迁移、新增或启停真实用户环境。0.3.0 的终端写操作使用独立测试资料，包内真实终端与列出的原生核心操作已通过；原位会话复用及全部 GUI 未逐项验收。0.4.0 的真实供应商节点单独记录，未测供应商、其他地理服务、全部 MCP 工具、完整指纹、检测网站、字体/WebGL/硬件组合、一般异常恢复和完整浏览资料备份仍未验收。Alpha 历史单项未验证归档的官方发布摘要。Web 演示配置不作为原生证据，也没有无法检测或自动通过验证码的保证。

基础检查先生成构建文件：

~~~bash
npm test
npm run build
npm run test:sites
npm run test:anytls
~~~

AnyTLS 检查需要已准备后端/核心与可显示窗口的桌面环境，使用独立测试工作区。浏览器服务由 test:sidecar 检查，启用 Camoufox 选项后才覆盖两家族；旧 test:smoke 覆盖直接驱动，Alpha 单项单独记录。更新结果应注明后端、内核、系统以及是否运行打包应用。

GitHub 安装发行版处于草稿，自动发布暂停；本轮新代码未推送，不提供公开正式 0.5.0 版本。新增能力的结果需使用对应冻结源码与原生/包证据更新。
