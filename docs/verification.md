# 验证范围与方法

本次发布目标为 **macOS Apple Silicon**。测试结果描述指定源码和制品的实际覆盖；编译成功、组件状态或可见窗口均不单独证明完整网络隔离。

## 0.5.23 发布检查

| 检查 | 结果 |
| --- | --- |
| Node 完整回归 | 2,099 通过，2 项平台跳过，0 失败 |
| 前端与 Sites | 构建及 4 项 Sites 检查通过 |
| Go 后端 | 常规包及 API/browser/MCP race 检查通过；未运行 6 项需要外部内核安装的 spike 实验，1 项字体依赖检查跳过 |
| 完整应用资源 | 归档源码、原生资源、manifest/carrier、许可证与对应源码一致 |
| 发布隐私检查 | 源码与完整应用扫描均无规则命中；本机编译目录已从自有原生产物移除 |
| 合成资料真实验收 | 浏览器迁移 5/5、最终包 PTY 28/28 通过；所属测试进程与临时目录已清理 |
| 桌面启动与退出 | 首窗显示加载状态并进入工作区，正常退出后所属进程清零；首次后台服务准备仍可能较慢 |

## 可复现检查

```bash
npm test
npm run build
npm run test:sites
node scripts/verify-public-release.mjs
node scripts/verify-package-resources.mjs "$PWD/release/mac-arm64/Envara.app"
node scripts/verify-public-release.mjs --app "$PWD/release/mac-arm64/Envara.app"
```

完整 Node 测试覆盖桌面启动门、IPC 权限、服务退出、终端生命周期、路由拒绝回退、加密资料迁移、配置持久化及原生协议的受控夹具。资源检查核对归档源码、后端来源、原生 payload/manifest/carrier、许可证、对应源码与平台一致性。隐私检查针对本机路径、高置信机密材料及禁止发布的本地数据，不代表能够识别所有敏感信息，仍需人工审阅。

Go 后端改动使用对应包测试和并发 race 检查。原生 C/Objective-C/Swift 组件的编译与无特权夹具不安装系统组件。

## 真实工作流

| 范围 | 验证方式与结论边界 |
| --- | --- |
| 启动 | 在服务初始化前显示加载窗口；初始化完成后进入工作区。慢初始化、失败和加载中退出分别检查。冷启动后端耗时仍会受系统和运行环境影响 |
| 浏览器资料迁移 | 使用真实浏览器和合成 Cookie、HttpOnly、localStorage、IndexedDB 数据，验证导出/恢复及源环境再次打开；同机结果不保证跨机器 Keychain 或登录有效 |
| Claude 专用终端 | 使用真实 PTY、官方 CLI 的非登录调用及合成账号目录，检查隔离、选择浏览器的 MCP/Playwright 接口、取消和进程清理；不据此宣称真实账号登录、刷新或模型推理已通过 |
| 网络 | 认证代理和 AnyTLS 受控夹具验证选定路由、失败阻断、REST/MCP拒绝缺失路由和所属资源清理；合成 Geo 不作为公网地域证据 |
| 附加应用 | 引擎识别、原生资源、授权和运行会话分别检查；新版本资源检查不自动继承旧版本的实机路由验收，不宣称所有 Electron 应用均已验证 |

脚本入口包括 `scripts/verify-scoped-browser-transfer.mjs`、`scripts/verify-claude-terminal.mjs`、`scripts/anytls-smoke.mjs` 与 `scripts/verify-application-front-isolation.mjs`。按脚本的运行条件使用独立测试数据；不要操作个人账号或无关应用。完整发布顺序见[发布流程](releasing.md)。

## 明确限制

- Windows、macOS Intel 和 Linux 的本次实机验收尚未完成，本次只提供 macOS arm64 制品。
- 通用附加应用的系统 DNS 委托、外部辅助进程、所有故障情形和无关应用共存仍需逐项验证；缺少有效路由授权时必须拒绝启动。
- Network Extension 备选路线需要相应签名、系统授权和独立验收。组件可读取状态不表示它已经激活。
- 系统默认浏览器变更需要用户接受 macOS 自身提示；路由资料与配置隔离不建立独立系统用户、Keychain 或硬件身份。
- 当前应用无 Developer ID 签名和公证。第三方原始签名和许可证按组件保留。

[功能矩阵](capability-matrix.md) · [附加软件](application-routing-options.md) · [第三方声明](../THIRD_PARTY_NOTICES.md)
