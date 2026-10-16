# 参与 Envara

欢迎通过 [Issues](https://github.com/ink-scholar/Envara/issues) 提交可复现的问题，或用 Pull Request 改进境舱。贡献遵循所在文件的原有许可证。

## 开发环境

需要 Node.js 24 LTS（或 22.12+）、npm、Go 1.25 和目标平台编译工具。macOS 原生组件需要 Xcode Command Line Tools。

```bash
npm ci
npm run desktop
```

桌面启动脚本准备 PTY、固定版本的 Go 后端、官方 Playwright driver/Node 和独立 Mihomo 核心。最终用户无需安装这些开发工具。只开发界面时可以运行 `npm run dev`。

修改前阅读 [AGENTS.md](AGENTS.md)、[架构](docs/architecture.md) 和 [功能矩阵](docs/capability-matrix.md)。界面位于 `src/`，桌面服务位于 `electron/`，平台组件位于 `native/`，固定 BrowseForge 源码位于 `third_party/browseforge/`。

## 修改与验证

```bash
npm test
npm run build
npm run test:sites
```

让改动围绕一个明确问题，复用已有规则，保留失败处理与资源归属检查。使用合成数据和可复现的测试，不提交浏览资料、Cookie、账号、代理凭据、私人路径、生成的内核或安装包。

- 浏览器改动需验证真实启动、隔离、关闭、重开及退出清理；参数正确不等于实际页面行为正确。
- 终端改动需验证真实 PTY、目录、输入输出、独立复制和进程清理；关闭视图与结束会话分别测试。
- 网络改动需验证认证路由、断线拒绝回退和无关流量不受影响；合成 Geo 数据不作为公网出口证据。
- 数据迁移需验证恢复内容、失败回滚与原资料保留。配置交换与包含资料的加密导出是不同入口。
- 原生路由改动需核对包内资源、安装授权、进程归属与清理。状态查询不得安装或激活系统组件。

真实工作流与单元检查的范围见[验证说明](docs/verification.md)。未完成的交互授权或平台验证应明确记录。

## 依赖与发布

保留第三方许可、固定来源与修改记录。Mihomo 的独立 GPLv3 许可和完整对应源码随核心分发，应用的 MIT 许可不替代它。不要修改或重新签署官方供应的路由驱动、浏览器或 CLI。

反馈应提供系统、架构、版本、内核、复现步骤与实际结果，并移除日志中的个人信息。截图使用合成示例数据。维护者按[发布流程](docs/releasing.md)手动验证和上传；GitHub 自动编译与发布工作流保持禁用。
