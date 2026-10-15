# Claude Code 专用会话：参考项目取舍

核对日期：2026-10-15。用途是运行本机安装的官方 Claude Code，由用户正常登录 Claude 账号；Envara 不转换订阅为 API，不接管 OAuth 刷新，也不导入浏览器 Cookie。

核对的源码版本：

- [CCBaga · e5df9fa](https://github.com/liseami/CCBaga/tree/e5df9fa18cd78bc105e4176fc9ee514b25cb437b)
- [vm2api · 556b9c5](https://github.com/dofastted/vm2api/tree/556b9c58a32c346a26dce855d236a7679c003d84)

## 适合境舱的部分

| 做法 | 源码证据 | 境舱的处理 |
| --- | --- | --- |
| 独立、持久的工具配置 | CCBaga 的[身份目录范围](https://github.com/liseami/CCBaga/blob/e5df9fa18cd78bc105e4176fc9ee514b25cb437b/README.md#claude-identities)，vm2api 的[独立槽配置](https://github.com/dofastted/vm2api/blob/556b9c58a32c346a26dce855d236a7679c003d84/src/lib/vm/slot-seed.mjs#L22-L54) | 复用现有每境舱 HOME、CLAUDE_CONFIG_DIR 和历史；关闭、复制会话不重置登录状态。配置目录隔离不是整机沙箱。 |
| 明确凭据边界 | CCBaga [分项处理凭据](https://github.com/liseami/CCBaga/blob/e5df9fa18cd78bc105e4176fc9ee514b25cb437b/src-tauri/src/identities/credentials.rs#L22-L68) | 让官方 CLI 自己登录；界面不读取或展示 OAuth 凭据，不复制宿主账号；专用会话检查与账号登录冲突的 API 设置。 |
| 固定路线、失败阻断 | vm2api [代理不可用时拒绝](https://github.com/dofastted/vm2api/blob/556b9c58a32c346a26dce855d236a7679c003d84/src/lib/vm/proxy-resolve.mjs#L45-L79) | CLI 复用境舱网络围栏，MCP 和登录链接绑定创建会话时选择的浏览器；受管代理核心退出时结束相关 Claude 会话。不会自动换节点或账号。 |
| 出口和地区用实际检测结果 | CCBaga [浏览器网络对照](https://github.com/liseami/CCBaga/blob/e5df9fa18cd78bc105e4176fc9ee514b25cb437b/src-tauri/src/browser/network.rs#L161-L284)，vm2api [代理时区检测](https://github.com/dofastted/vm2api/blob/556b9c58a32c346a26dce855d236a7679c003d84/src/lib/vm/proxy-timezone.mjs#L20-L77) | 复用网络环境已保存的出口证据和时区，保留手动位置与实测出口的区别。绑定节点不保证提供商永远返回同一个公网 IP。 |
| 可解释的隐私开关 | 以 [Claude 官方数据说明](https://code.claude.com/docs/en/data-usage#telemetry-services)为依据 | 标准模式关闭官方遥测和错误上报；严格模式再关闭官方非必要流量。只影响境舱子进程，不修改宿主设置。 |

这些是独立实现的隔离、隐私和故障处理措施；参考项目没有提供足以证明其“防封”效果的对照证据。

## 不移植的部分

- vm2api 的[修改版 CLI、订阅转 API 数据面](https://github.com/dofastted/vm2api/blob/556b9c58a32c346a26dce855d236a7679c003d84/docs/INFERENCE.md#L4-L35)、账号池、凭据转换不属于本功能。
- vm2api 的[合成遥测](https://github.com/dofastted/vm2api/blob/556b9c58a32c346a26dce855d236a7679c003d84/src/lib/identity/telemetry-env.mjs#L130-L186)不是官方隐私选项。境舱不伪造设备身份、TLS、使用记录或模型请求。
- CCBaga 的[本地清理](https://github.com/liseami/CCBaga/blob/e5df9fa18cd78bc105e4176fc9ee514b25cb437b/src-tauri/src/cleaner_targets.rs#L94-L113)不等于清除服务端记录。其[测试保留已有遥测设置](https://github.com/liseami/CCBaga/blob/e5df9fa18cd78bc105e4176fc9ee514b25cb437b/src-tauri/src/cleaner_tests.rs#L304-L310)，不能据此说它自动禁用了上传。
- 不照搬修改整机时区、语言或定位的做法，也不轮换本地身份来规避账号限制。

## 使用边界

官方隐私开关不阻止正常登录、模型请求和服务端必要处理，也不改变账号的数据训练偏好。严格模式会影响 Remote Control、部分技能/插件同步等功能，具体以 [Claude 官方环境变量说明](https://code.claude.com/docs/en/env-vars)为准。Claude 的组织管理策略优先于启动参数，Envara 不绕过组织策略。

已验证的本地行为与需要用户登录验收的部分，见 [Claude Code 会话说明](claude-code-sessions.md)。

## 飞书文档复核（2026-10-15）

按用户要求，通过 Wi-Fi 接口直接读取[《Claude Code 封号机制逆向探查》](https://bytedance.larkoffice.com/docx/E2JudVzf7oCNfhxyxaQcZIW1n0g)的正文及分页建议表；请求禁用代理，未使用 7897。页面标注 4 月 2 日修改。本文将其客户端逆向描述视为待核验线索，不将其风险评级等同于 Anthropic 的服务端规则。

有价值的提醒是：可选遥测与正常账号请求是不同的数据路径；保留稳定配置、使用完整的原生客户端、明确本地数据边界比承诺匿名更可靠。Envara 已保留登录档案并固定会话网络/浏览器，不修改 Claude 请求头、设备标识或客户端证明。终端环境从白名单构造，Git 全局配置独立，但所选项目中的 Git 配置、作者信息及文件仍可被工具读取。

官方[数据说明](https://code.claude.com/docs/en/data-usage#telemetry-services)确认可以关闭遥测，同时说明这会关闭特性开关评估，可能影响 Remote Control。0.5.7 因此在折叠会话设置中补充兼容性提示，保留用户原有隐私选择。文档关于隐私开关增加封禁概率的推论没有给出可验证的服务端证据，不能据此替用户启用更多上报。其硬编码指纹算法及付费功能判断也不作为当前版本的接口约定。

删除本地设备标识和缓存不等于更换真实设备或清除服务端关联；不据此自动删除登录数据、生成虚假身份或实施账号轮换。网络传输代理与文档所述改写模型请求的 AI Gateway 亦应区分。后续可独立评估的改进包括：本机导入程序的发布者签名检查、出口变化的清晰提示，以及版本更新后的隐私选项兼容性复验；这些尚不是本轮新增的已验收能力。
