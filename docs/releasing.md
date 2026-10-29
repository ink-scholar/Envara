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
npm run claude:keychain:prepare
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

macOS 发布统一使用下列入口。默认模式为 `developer-id`，须明确选用钥匙串中**已有且有效的 Developer ID Application 证书**的 SHA-1 和 Team ID。维护者也可明确选择 `ENVARA_MAC_SIGNING_MODE=adhoc`，生成不带开发者证书的 ad-hoc 签名制品；未找到 Developer ID 时不会自动降级。模式与身份在任何资源准备或打包之前检查，未知模式、矛盾的证书变量和 `CSC_*` 证书导入或替代选择均会被拒绝。流程不会创建或导入证书，不会购买或注册开发者账号。

```bash
/usr/bin/security find-identity -v -p codesigning
# 在当前终端中设置审核选定的 ENVARA_MAC_SIGNING_IDENTITY 与 ENVARA_MAC_SIGNING_TEAM_ID
npm run dist:mac -- --check
npm run dist:mac
shasum -a 256 release/Envara-*-mac-arm64.dmg release/Envara-*-mac-arm64.zip
```

若维护者选择 ad-hoc 模式，使用以下显式命令；`env -u` 只移除这次命令的证书选择变量，不改当前 shell 或系统设置：

```bash
env -u ENVARA_MAC_SIGNING_IDENTITY -u ENVARA_MAC_SIGNING_TEAM_ID ENVARA_MAC_SIGNING_MODE=adhoc npm run dist:mac -- --check
env -u ENVARA_MAC_SIGNING_IDENTITY -u ENVARA_MAC_SIGNING_TEAM_ID ENVARA_MAC_SIGNING_MODE=adhoc npm run dist:mac
```

不要直接运行 `electron-builder --mac` 绕过发布入口。内部目录构建有意关闭 electron-builder 自动签名，随后只给固定的九个 Electron 主程序、辅助程序和框架目标签名；不会递归重签被 pin 的 PF 载体、第三方程序或资源。Developer ID 模式核对最终包标识、实际证书 SHA-1、Team ID 和含 Apple 证书链约束的稳定 designated requirement，拒绝自动降级或弱化要求。ad-hoc 模式使用 `--sign - --timestamp=none`，核对标识、`Signature=adhoc`、无 Team ID/证书，以及与实际 CDHash 匹配的指定要求；不宣称稳定开发者身份。

两种模式都核对完整资源字节未变、严格签名和候选验收，并保留现有 entitlements 和运行时策略。除重新签名时移除 linker-signed 标志并按模式设置 ad-hoc 标志外，不改变原标志；若以后启用 hardened runtime，须另外审核 Electron JIT、原生模块所需权限并完成实际启动验收。签名不等于公证；当前入口不提交公证。Keychain 兼容性修复不依赖 Developer ID，签名模式也不能替代真实账号或安装包验收。

临时应用固定存放于 `~/Library/Caches/io.envara.release/mac-arm64/` 下的候选、归档 payload、ZIP 核对和 DMG 挂载四个位置，不在桌面、文稿目录或版本编号目录创建一批应用副本。`beforePack` 守卫在提取 Electron 之前拒绝绕过统一入口的 macOS 构建，核对固定输出、该次目录锁、明确的签名模式及其身份条件和仅目录构建模式。私有工作目录带归属记录、排他锁和操作日志；遇到未知文件、路径替换、遗留锁或未完成清理会拒绝重用，需先审核日志，不能用删除锁或改新路径绕过。命令超时且退出情况不确定时同样保留目录。非应用证据按运行保留。

历史本地 `test-artifacts/` 下按版本冻结的打包、签名和归档 helper 已封存，仅用于审计原始回执，不得复用执行；保留其原始内容以核对旧制品。现有源码中的 `verify-*` 包验证脚本接受明确的包路径，其随机目录只用作测试资料和回执。后续包验证须复用受控固定工作目录；不要手工复制同标识的应用来绕过入口。上述守卫不能阻止任意外部工具或手工复制应用。

归档前后核对 DMG、ZIP 中的完整应用与已签候选一致，并检查最终资源和源码。临时应用清理先确认没有进程占用，精确注销该次工作目录的 LaunchServices 路径，再重新读取注册表确认路径消失，随后删除所属副本或正常卸载所属只读卷。注销、占用检查或卸载不确定时，保留日志和固定目录并使发布失败。不得对 LaunchServices 进行全局重建，也不得重置 TCC、修改默认浏览器或清理 `/Applications/Envara.app`。检查成功且所属临时副本清理完成后，`release/` 才得到 DMG、ZIP 和 `SHA256SUMS.txt`，不覆盖已有制品。

签名及静态资源检查后，入口必须在固定候选应用路径运行源码提交中的 `scripts/verify-macos-release-candidate.mjs`，通过独立参数传入应用路径、固定 runtime 目录、证据目录、回执路径、源码提交、该次工作目录 nonce 和签名后完整包清单的 SHA-256。runner 不能从环境变量或任意外部路径替换；缺少已跟踪的普通源码文件时，在创建打包工作目录前停止。`--check` 仍只检查签名条件，不代表候选验收已完成。

runner 使用不含宿主凭据变量的最小环境，HOME 和临时目录位于固定 runtime。它须实际完成可见窗口的干净首次启动、桌面服务就绪、真实终端 PTY、Claude 钥匙串持久化和所属进程清理，分别返回 `clean-first-launch`、`desktop-service-ready`、`terminal-pty`、`claude-keychain-persistence`、`owned-process-cleanup` 检查。只有全部检查通过、确实启动了应用、清理完成且剩余所属进程为零的回执才可进入归档。合成凭据持久化不能写成真实账户 OAuth 已验收；后者需另行如实记录。

回执为 `envara.macos-release-acceptance/v1` JSON，必须以 `0600` 权限新建在该次证据目录，普通文件、单链接、大小不超过 64 KiB，并精确绑定源码提交、应用/runtime 路径、nonce 和候选清单摘要。发布入口独立核对验收前后整个包树未变，用进程清单和打开文件检查确认候选应用及 runtime 无占用，随后才创建归档。验收失败不生成发布制品；清理或进程检查不确定时保留固定工作目录和证据。原有归档等值、签名、LaunchServices 精确注销与卸载核查仍全部执行。

附加软件的安装授权、路由、DNS、子进程、故障阻断和清理需分别验收，未经验证的范围写入说明。源码单测或伪造测试 runner 的回执只验证发布控制逻辑，不代表真实 GUI、钥匙串登录或精确包验收通过。

已发布的 v1.1.3 使用 ad-hoc 签名且未公证；新入口不会修改已安装副本或其资料、授权。ad-hoc 签名绑定具体代码版本，更新后的代码哈希可能导致系统再次请求授权；它不提供 Developer ID 的稳定开发者身份。首次从 ad-hoc 迁移到正式证书后，旧 TCC 授权也不保证自动继承。正式签名不保证免除所有系统授权。不得通过关闭系统安全检查、修改第三方签名或自动接受授权提示来使验证通过。

## 手动发布

核对最终源代码提交、版本标签、DMG、ZIP 和校验文件对应同一版本，再手动创建 GitHub Release。说明应包含支持架构、安装方式、主要变化、已验证范围和已知限制。运行日志保留在本地；公开说明只使用脱敏汇总。

推送前确认没有自动编译/发布工作流被重新启用。发布后核对远端提交、标签、下载资产名称、大小和 SHA-256。历史草稿或历史提交需要另行处理，不通过重写历史隐式删除。
