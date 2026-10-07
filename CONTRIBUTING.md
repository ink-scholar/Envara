# 参与 Envara

欢迎通过 [Issues](https://github.com/ink-scholar/Envara/issues) 提交可复现的问题，或用 Pull Request 改进境舱。贡献按所在文件的原许可发布；原创代码与纳入的 BrowseForge 源码均采用 MIT。

## 当前开发阶段

本轮本地开发 0.4.0 内置 AnyTLS 候选版，公开发布暂停。源码接入、受控测试、真实浏览器/PTY 测试和打包验收分别记录，不用上游清单推断产品已经可用。

开发需要 Node.js 24 LTS 或 22.12+、npm 和 Go 1.25+：

~~~bash
npm ci
npm run desktop
~~~

desktop 自动执行 native:prepare、backend:prepare 与 proxy:prepare，准备 node-pty、固定 Go 后端、官方 driver/Node 和 Mihomo/对应源码。原生模块需要重建时须有目标平台编译工具；最终桌面用户无需安装这些开发工具。

界面位于 src/，服务管理与适配位于 electron/，固定上游及补丁位于 third_party/browseforge/。修改前阅读 [AGENTS.md](AGENTS.md)、[架构说明](docs/architecture.md) 和 [能力矩阵](docs/capability-matrix.md)。

## 修改与验证

~~~bash
npm test
npm run build
npm run test:sites
~~~

涉及新后端或某内核时，验证真实创建、启动、停止、手动关窗、再次启动和应用退出。隔离、代理、语言、Intl、时区和目标系统应在实际页面观察，不能只核对传入参数。报告写明旧直接驱动或新 sidecar 路径，以及源代码运行或打包运行。

终端改动验证真实 PTY 输入输出、尺寸、选定 cwd、跨境舱配置分离与同境舱历史共用。复制必须生成独立 PTY/代理桥，不复制命令、临时环境变量或 shell 手动 cd 后的目录；关闭源不影响副本。分别验证拖动/键盘高度、放大恢复、独立窗口，以及关闭视图保留会话和明确结束会话清理所属进程。出口检测验证认证 HTTPS 路由、公网 IP、IANA 时区及失败路径，不用代理入口或默认值代替成功。旧指纹固定字段切自动必须由用户明确操作。不要把配置隔离描述为 OS 沙箱，也不要声称全部程序强制代理、住宅地址或防封效果。

旧资料迁移先备份再复制，保留原文件；验证代理绑定、指纹、浏览资料与失败回滚。v2 导入要求明确代理映射，不允许把缺失代理静默改为直接连接。配置导出不携带凭据或浏览资料。

AnyTLS 修改用 test:anytls 验证真实 TLS/auth fixture、Cloak/PTY、REST/MCP 缺少入口拒启动、节点故障无直连回退、核心恢复与清理；合成 Geo 不能作为公网地域证据，外部节点单独记录。Mac 接口选择只读，不关闭已有 TUN 或改系统网络；HTTP 桥不代表通用 UDP。准备/打包 Mihomo 时保留独立 GPLv3、固定对应源码/vendor、原有归属和 provenance，不能只附二进制；遵循 [来源记录](third_party/proxy-core/SOURCE.md)，不改用应用 MIT 覆盖核心许可。

改动限定在具体问题。修改上游时保留归属与许可，更新固定版本和补丁记录。界面截图清楚标记演示数据。不要提交个人浏览资料、Cookie、登录信息、代理凭据、本机令牌、浏览器内核或生成的安装包。

## 反馈与发布

反馈提供系统、架构、应用版本、后端路径、内核版本、复现步骤与实际行为。移除日志或截图中的个人账号、凭据和私密路径；代理问题注明 TCP 检查或实际浏览器请求。

两个 0.1.x GitHub 发行版保留为草稿，自动发布暂停。本轮不推送公开发布标签，也不把候选包当成正式下载版。恢复发布前，维护者结合新路径和目标平台的实际验收更新 README、验证记录与说明。上游专有内核的重新分发限制仍须保留。
