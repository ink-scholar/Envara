# macOS 发布流程

维护者在本地准备并验证制品，再手动上传 GitHub。源码推送不会触发自动编译或自动发布。当前发布目标为 macOS Apple Silicon；其他平台的源码不代表已有经过实机验证的安装包。

## 冻结源码

1. 更新 `package.json` 与 `package-lock.json` 的同一版本，以及九语言 README 的下载说明。
2. 检查改动、依赖来源与许可证。公共源码只包含可复现的实现、测试和文档；排除用户资料、私密配置、本机诊断与生成制品。
3. 运行检查；并发受限的机器可用 `node --test --test-concurrency=4 tests/*.test.mjs` 完整执行同一套测试。

```bash
npm ci
npm test
npm run build
npm run test:sites
node scripts/verify-public-release.mjs
```

后端改动还需在 `third_party/browseforge/` 运行对应 Go 测试；生命周期和并发改动需增加相关 race 检查。浏览器及原生测试的运行条件见[验证说明](verification.md)。

## 准备平台资源

```bash
npm run native:prepare
npm run backend:prepare
npm run proxy:prepare
npm run routing:build:mac
npm run routing:build:mac:local
npm run routing:build:mac:acceptance
npm run routing:build:mac:pf
npm run routing:test:mac:pf
npm run routing:prepare:mac:package
npm run routing:build:mac:link-router
```

PF 资源有固定 manifest、安装器和授权载体校验。更改其源文件后，先保留需要支持的旧安装精确快照，再审核新 manifest 和安装器摘要；按 `scripts/build-macos-pf-authorization-app.mjs` 构建匹配的载体，并同步 `electron/macos-pf-notion-trial.mjs` 的候选 pin。不要用动态信任当前文件、跳过校验或提升 readiness 来绕过不一致。`routing:prepare:mac:package` 严格核验审核 pin、源资源和载体原始构建记录，仅将选中的完整载体放入 `build/package-resources/local-authorization`，保留历史载体。缺少选中载体时调用既有构建器；已有 staging 若属于旧候选或含未知内容则拒绝覆盖，先将其移至独立归档再重新准备。该步骤不会自动更新 pin。构建操作本身不安装或激活系统组件。

原生 fixture 命令运行测试源码及已准备的原生二进制；也可用 `npm run routing:test:mac:pf -- --resources /absolute/prepared/macos-pf` 选择独立资源。它不会安装、激活或自动构建资源。

保留全部许可证及 Mihomo 对应源码。Electron 的原版 `LICENSE` 和 `LICENSES.chromium.html` 必须随安装包放入 `licenses/electron/`，资源核验会检查它们与当前 Electron 分发文件一致。供应商原版二进制和签名保持原样；Envara 自有构建去除编译机绝对路径。

## 构建并核对制品

```bash
npm run build
npx electron-builder --mac --arm64
node scripts/verify-package-resources.mjs "$PWD/release/mac-arm64/Envara.app"
node scripts/verify-public-release.mjs --app "$PWD/release/mac-arm64/Envara.app"
shasum -a 256 release/Envara-*-mac-arm64.dmg release/Envara-*-mac-arm64.zip
```

资源核对必须针对最后准备上传的应用。检查 DMG 挂载和 ZIP 解压后的应用与该候选一致，并为上传文件生成 `SHA256SUMS.txt`。确认归档不包含私人资料、临时证据、无关平台资源或重复载体。

使用独立测试资料验证首次启动可见窗口、服务准备期间操作限制、正常退出与所属进程清理，以及改动影响的真实浏览器/PTY流程。附加软件的安装授权、路由、DNS、子进程、故障阻断和清理需分别验收，未经验证的范围写入说明。

当前发行包没有 Apple Developer ID 签名和公证；发布说明必须明示。不要通过关闭系统安全检查、修改第三方签名或自动接受授权提示来使验证通过。

## 手动发布

核对最终源代码提交、版本标签、DMG、ZIP 和校验文件对应同一版本，再手动创建 GitHub Release。说明应包含支持架构、安装方式、主要变化、已验证范围和已知限制。运行日志保留在本地；公开说明只使用脱敏汇总。

推送前确认没有自动编译/发布工作流被重新启用。发布后核对远端提交、标签、下载资产名称、大小和 SHA-256。历史草稿或历史提交需要另行处理，不通过重写历史隐式删除。
