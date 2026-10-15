# Claude Code sessions

In **Terminal → New session**, choose **Claude Code**, then the network, its environment browser, a login profile and a working folder. Envara opens an isolated shell prompt. Run `claude` when ready; the session-local command invokes this environment's independent native CLI installation with the selected browser connection. An existing valid environment installation is reused. For a new installation, choose the default **Download independent installation** or **Initialize from local Claude**. The download uses the selected environment's route; the local option copies only a native executable into the environment, without importing host account data or sharing its writable installation. No Claude binary is bundled in the Envara app.

在 **终端 → 新建会话** 中选择 **Claude Code**，再选择网络、境舱浏览器、登录档案和工作目录。先进入命令行，由你输入 `claude`，也可自行添加参数，例如 `claude --permission-mode bypassPermissions`；Envara 不会默认开启该权限模式。退出 Claude 后仍回到这个终端。新登录档案首次使用时，在会话里完成 Claude 的登录；不会自动复制本机其他终端的账号。

同一境舱内可创建多个命名登录档案，登录信息由 Claude 自动保存，无需手动导出。新建终端时选用已有档案，即复用它的配置和登录存储；复制会话继承原档案。关闭终端、更新程序或重启 Envara 不会主动删除它；退出账号、凭据过期或服务端撤销可能要求重新登录。[Claude 官方说明](https://code.claude.com/docs/en/authentication#log-in-with-multiple-accounts)支持用独立 `CLAUDE_CONFIG_DIR` 分开保存 claude.ai 登录、设置和会话历史，macOS Keychain 也按配置目录区分。Console 的无 API key 登录不在此隔离承诺范围内。

默认档案继续使用旧版 Claude 配置目录，不搬迁或复制凭据。新增档案只创建自己的配置目录；Envara 只管理名称和标识，不读取 token、猜测账号邮箱或将其标成“已登录”。不同境舱不能选择彼此的档案。所有档案仍使用本境舱同一份 Claude 程序，程序更新不切换账号。绑定浏览器的网页登录与 CLI 登录档案不同：新档案登录时浏览器可能已有网页账号，需要由用户在官方登录流程中选择。

## Installation and updates

每个境舱使用自己 `HOME/.local/bin/claude` 指向的原生安装。已有有效安装（包括此前在境舱里执行 `claude update` 下载的版本）优先复用，界面不再显示安装来源选择。首次默认“下载独立安装”，也可选择“从本机 Claude 初始化”：后者只复制本机原生程序，不复制账号、配置或历史。程序文件独立存储，不使用会让更新影响本机的共享硬链接。同一境舱的多个终端共用这份安装，不同境舱分别维护。

选择下载时，首次创建 Claude 会话会从官方源下载适配当前平台与架构的原生版本，即使本机已经安装也不改用本机程序。版本清单和程序请求均显式绑定到该境舱的本地代理入口；不会使用系统代理或直连作为备用。下载完成后核对大小和 SHA-256，macOS 另外验证 Apple 签名及 Anthropic 开发者身份，通过后才原子发布为境舱安装。界面显示安装阶段和下载进度；取消或失败保留已有配置，清理本次临时下载，下次可重试。选择本机初始化但没有可用原生安装时明确报错，由用户改选下载，不会自动切换来源。这里的程序下载不执行远程 shell 安装脚本，也不修改本机 Claude 或主机 shell 配置。

在 Claude 专用终端里执行 `claude update`，更新位置与启动位置保持一致。每次手动调用 `claude` 都重新检查该境舱的安装入口，因此更新完成后，同一个终端里的下一次调用即可使用新版；已运行中的 CLI 继续使用其当前版本，退出后再启动才切换。登录目录、网络变量、浏览器/MCP 绑定和用户显式选择的权限参数保持原有处理。损坏、越界或缺失的既有安装会明确报错，不悄悄回到本机旧版。

Envara 的临时包装命令继续优先位于 PATH，以注入此会话绑定；它不覆盖原生安装的持久入口。官方说明自定义 launcher 不会被更新程序替换，所以包装器必须动态解析原生安装入口。[Claude 更新机制](https://code.claude.com/docs/en/setup#auto-updates)

从旧版 Envara 升级到 0.5.5 后，需要新建一次 Claude 专用终端以使用新的包装命令。此前已在境舱中下载的有效原生安装会直接复用；以后在该终端里执行 `claude update`，无需重建会话即可在下一次调用时使用新版。已打开的旧版终端不会被后台改写或中断。

独立安装主要减少版本更新相互影响，并配合既有配置隔离。共用一个官方可执行文件本身不代表共用账号；反过来，独立程序目录也不是文件系统或硬件沙箱。本地 CLI 及其命令仍可能读取真实系统信息，只有绑定浏览器中的网页使用浏览器设备档案。

## Configuration and browser tools

- The environment's `HOME` contains its native installation and shell configuration; the selected login profile supplies `CLAUDE_CONFIG_DIR` for Claude configuration, login state and history. Sessions selecting the same login profile share it; named profiles and separate environments have separate Claude directories. The selected project directory is the actual local directory, not a copy or filesystem sandbox.
- The dedicated session loads the `envara_browser` MCP server. Its Playwright-backed tools navigate, inspect visible content, click, fill, press keys, select options, check boxes, scroll, wait, capture screenshots and manage tabs in the selected environment browser.
- A private session token gives access only to that browser. The desktop keeps the broad sidecar credential and raw Playwright endpoint. Unavailable or changed bindings return errors; neither another browser nor the system default is substituted.
- The session-local `claude` command excludes Chrome integration and other MCP configurations. Arguments that replace the managed browser/settings binding are refused with an explanation. Model, resume and permission-mode arguments are passed to the CLI unchanged; ordinary permission prompts remain the default unless the user chooses otherwise. Project files remain readable, but project-level Claude settings and MCP servers are not loaded. Normal shell sessions keep their existing behavior.
- Duplicating a Claude session creates an idle shell and separate browser connection, retaining its selected login profile and environment configuration. It does not replay commands or resume an in-memory conversation. Closing a session revokes its automation connection without closing the environment browser or deleting login state.

## Account sessions and privacy

The dedicated session is intended for normal Claude account login. Before launching it, Envara checks the selected login profile's `settings.json` for API credentials, gateway/provider selection, credential helpers, and conflicting proxy or configuration paths. A conflict produces an explanatory error without displaying its value or modifying the file. The local CLI and its login storage remain under the user's control. `forceLoginMethod: "claudeai"` selects the account-login path; it is not proof of authentication or enforcement of a billing plan.

Session-only settings pin non-secret configuration paths and privacy choices. Proxy credentials and private browser tokens remain in the child environment, outside the settings JSON. Existing environment-local model and permission settings continue to load. Startup validation does not turn live-reloaded user settings or organization-managed policies into an Envara security boundary; the existing network fence and browser broker still enforce their own controls.

The selected environment's privacy mode is reused:

| Mode | Official CLI options |
| --- | --- |
| Off | No added telemetry or error-reporting opt-out |
| Standard | `DO_NOT_TRACK=1`, `DISABLE_TELEMETRY=1`, `DISABLE_ERROR_REPORTING=1` |
| Strict | Standard options plus `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` |

All dedicated sessions disable background CLI auto-updates with `DISABLE_AUTOUPDATER=1`; an explicit `claude update` remains available for the environment installation. Updating the host installation outside Envara is separate. These are [official documented options](https://code.claude.com/docs/en/env-vars), not fabricated telemetry. Privacy options can also disable feature-flag-dependent functionality, including Remote Control and some account skill/plugin synchronization. They do not disable normal account/model traffic or change account training preferences. Organization-managed settings remain authoritative.

When the owned managed proxy core reports that it exited, Envara revokes matching Claude browser capabilities and ends those Claude processes. Other nodes and ordinary terminal sessions keep their existing lifecycle. The primary route error remains visible after the session tab disappears; a cleanup error is stored separately. This reacts to the owned core's failure event, not every upstream service error: a provider refusing a request while the core remains alive is still reported by Claude itself. No account or node is automatically rotated.

The source-grounded [CCBaga/vm2api comparison](claude-reference-analysis.md) explains which ideas were used and which were excluded. No subscription-to-API service, token conversion, modified Claude binary or identity-spoofing mechanism is included.

## Current platform boundary

Dedicated sessions currently require the macOS terminal network fence and a verified proxy with an application-owned loopback front (including managed AnyTLS and bridged SOCKS5). A direct connection, unsupported platform or unfenced remote HTTP(S) proxy is refused. Envara reuses its existing network fence around the shell and its children; Claude's own nested macOS sandbox is disabled for this session because Seatbelt profiles cannot nest. Envara does not automatically disable Claude's permission prompts.

Use the supplied `envara_browser` tools for browser work. Launching unrelated browser automation from arbitrary project scripts is not a supported binding mechanism. The fence is not a filesystem sandbox and does not hide every local device characteristic.

此功能的账号登录、服务端可用性和账户限制仍由 Claude 决定；网络与配置隔离不等于“防封”。本地验证使用独立测试数据，不代表已经替用户登录或完成真实模型请求。

Browser locale is separate from website display language and installed fonts. For example, the automatic Malaysia locale is `ms-MY`, and `Asia/Kuala_Lumpur` uses UTC+8. A site can still serve its Chinese page, and the browser can still have access to Chinese fonts on the host. Envara does not currently isolate all system fonts for this browser configuration. A third-party browser environment score is neither a measurement of the terminal CLI's complete environment nor a prediction of account restrictions.

## Local verification

The macOS Apple Silicon candidate was exercised with local Claude Code 2.1.296 and the actual BrowseForge/CloakBrowser runtime. Two authenticated offline proxy fixtures distinguished the selected route from the unused route; real MCP navigation, inputs, clicks, tabs and screenshots used the chosen browser. A direct external socket was denied by Seatbelt. Changing the selected network refused the old browser capability, and cleanup left no owned Claude PTY processes.

The CLI and complete browser-tool chain are tested separately: the offline fixture deliberately refuses Anthropic API traffic, so the CLI's connectivity check can end the session. This does not demonstrate a logged-in Claude model choosing and invoking these tools. That final account-dependent step remains for user testing. `scripts/verify-claude-terminal.mjs` can also import the packaged modules with `--packaged /absolute/path/Envara.app`, exercising the physical bundled Node and MCP script outside ASAR.

The 0.5.2 packaged Apple Silicon build additionally passed all three privacy-mode launch checks, refusal of a synthetic API-key conflict without modifying its settings file, and an injected owned-core failure using real Claude PTYs and a live browser capability. The matching session exited and lost browser access while the other route's Claude process and the same route's ordinary shell remained responsive. This is a lifecycle fault-injection check against authenticated local proxy fixtures, not a real AnyTLS crash or public-egress measurement. Cleanup left no owned PTYs. A filesystem-permission regression separately verifies that failed browser-channel cleanup can be retried.

The 0.5.3 packaged build passed 15 native acceptance checks with the manual-start flow: the dedicated terminal initially contained only a shell; manually running `claude --version` and `claude --permission-mode bypassPermissions --version` returned to that shell; manually running `claude` opened the installed 2.1.296 CLI. Its offline connectivity failure returned to the shell without discarding the browser binding. The terminal's own MCP capability completed the selected-browser interactions, binding-change refusal and route-loss checks, and cleanup left zero owned PTYs. Separately, 141 terminal/broker/Claude regression tests and four Sites checks passed. Synthetic login markers verified that closure and reopening preserve environment-local files; this is not a real account-login or token-refresh acceptance test.

The 0.5.5 Apple Silicon package passed 20 native acceptance checks. In one existing PTY, replacing the environment's version entry between real Claude Code 2.1.296 and 2.1.300 binaries made the next invocation use 2.1.300; fresh sessions and reopening after closure retained it. The host binary and another environment stayed at 2.1.296, with their file hashes unchanged. A broken environment entry exited with code 126 rather than using the host. The same browser capability, MCP configuration, network fence and synthetic login-storage marker survived the switch; subsequent real MCP/Playwright interactions and route-loss checks passed. Cleanup left zero owned PTYs and removed the fixture directory. This simulates the updater's final native installation switch, not the official network download, a real account login, or token refresh. The package resource verifier also passed, including the physical bundled Node used by the dynamic resolver.

The final 0.5.5 source regression run passed 1,766 tests with two platform skips (`node --test --test-concurrency=4 tests/*.test.mjs`); the four Sites checks and frontend build passed. An earlier unrestricted parallel run during packaging missed the existing proxy test's 100 ms target-hit assertion. That test passed in isolation and the complete suite passed with bounded concurrency; its source and timeout were not changed.

The 0.5.6 source regression run passed 1,835 tests with two platform skips; the four Sites checks, frontend build and Apple Silicon package resource verifier passed. Renderer interaction checks at Chinese 1440 px and German 1200 px covered account creation failure/retry, environment switching, cancellation during installation, and reopening with the already-created login profile and remembered working directory. Button hover, pressed, focus, disabled and reduced-motion states were exercised in Electron. These renderer fixtures do not authenticate a real Claude account.

The final 0.5.6 Apple Silicon package passed 22 native checks (`build/local-verification/claude-terminal/run-xmLzd4/proof.json`). With the host CLI resolver intentionally unavailable, its production installer downloaded official Claude Code 2.1.300 (249,556,880 bytes, SHA-256 `475517caa611e3318a2f298fa071287ec98955538df78c58f709ecc01e5ae2d3`) through selected authenticated fixture A, verified the Apple/Anthropic signature and started the PTY only after installation. Fixture B received no official download connections. A used the execution environment's HTTPS proxy as its explicit external leg; this verifies downloader route binding, not a real AnyTLS node or public egress. Cancellation and retry used a separate local HTTPS fixture serving the same signed binary.

The same packaged run verified named-profile configuration separation, unchanged default storage, shared environment installation, duplicate/reopen behavior and cross-environment refusal using synthetic markers. The real CLI, UTF-8 PTYs, selected-browser MCP/Playwright interactions, binding-change refusal and route-failure lifecycle checks passed. Cleanup left zero owned PTYs and removed the temporary fixture. Real account login, credential refresh and model-directed tool use remain user acceptance steps.

The 0.5.7 candidate passed 191 focused regression tests, four Sites checks and 29 packaged native acceptance checks (`build/local-verification/claude-terminal/run-LrgOrJ/proof.json`). The installation-source checks exercised explicit download and local initialization, refusal without source fallback, reuse of an existing installation, and read-only status checks. The production downloader used an authenticated local HTTPS fixture serving the previously verified official 2.1.300 binary; this run did not repeat the public download or establish real proxy egress. Login-profile persistence, real PTYs, selected-browser MCP/Playwright and cleanup checks passed, leaving zero owned PTYs and removing the temporary fixture.

Chinese and German renderer checks covered the installation-source selector and retry flow. Six additional UI/translation checks and real renderer interaction confirmed that the collapsed privacy compatibility note appears for enabled privacy modes and is absent when privacy mode is off. The final 0.5.7 package resource verification passed, and all seven backend module hashes match the 29-check native acceptance run. Real account authentication, credential refresh and model-directed browser use remain unverified.
