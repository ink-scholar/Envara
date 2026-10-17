# Claude Code sessions

Applies to Envara 0.5.25. The current release target is macOS arm64. Envara launches the **unchanged official native Claude Code CLI**; it does not bundle a Claude program, convert subscriptions to an API, or infer whether an account is signed in.

## Start and installation

In **Terminal → New session**, choose Claude Code, the network, environment browser, named login profile and working directory. The session opens at a shell prompt. Enter `claude` when ready; leaving Claude returns to that shell. Model, resume and permission arguments remain user choices. Envara never enables permission bypass automatically.

Each environment owns its native installation. Reuse a valid existing installation, or choose:

- **Download independent installation:** fetch the official platform build through the selected environment route, verify size/checksum and applicable macOS signature identity, then install atomically.
- **Initialize from local Claude:** copy a supported native program into independent environment storage. No host credentials, configuration or history are copied, and the writable installation is not shared.

Cancellation or failure preserves account data and existing installation state. A missing or invalid source is reported; Envara does not silently use a host executable or another route. Background auto-updates are disabled. An explicit `claude update` affects that environment's next invocation; already-running programs keep their current version.

Implementation: [installer](../electron/claude-code-installation.mjs), [downloader](../electron/claude-code-download.mjs), [session launcher](../electron/claude-code-session.mjs).

## Login profiles and data

Named profiles use separate Claude configuration directories within one environment. Profiles share that environment's program but retain separate configuration/history storage. The default profile retains its existing directory. Duplication preserves the selected profile and creates an idle shell; it neither replays commands nor clones live process state.

Each selected profile pins both `CLAUDE_CONFIG_DIR` and `ANTHROPIC_CONFIG_DIR`; the latter is an owned subdirectory of the former. This also separates newer Console profile files that `CLAUDE_CONFIG_DIR` alone does not scope. An old environment-wide `HOME/.config/anthropic` directory is preserved without assigning it to a named profile or copying its credentials. If it exists, the session asks the user to sign in again within the selected profile.

Envara displays profile names, not inferred authentication status. Closing a terminal, stopping the program or updating Envara does not delete profile data. Official sign-in, token refresh, account policies and remote model availability remain the service's responsibility. Browser website sign-in and CLI sign-in are distinct.

Terminal export includes only the chosen Claude profile, including its scoped Anthropic directory, plus shared shell configuration/history. It excludes other profiles, the old shared Anthropic directory, program files, caches and host credentials. Encrypted import creates a new environment and requires explicit proxy mapping. macOS Keychain entries are not exported; copied files do not guarantee cross-machine sign-in.

## Browser and network binding

A dedicated session pins its selected environment browser. A private session-scoped `envara_browser` MCP broker exposes supported page navigation, inspection, inputs, clicks, screenshots and tab operations. The desktop retains the broad backend token and raw Playwright endpoint.

Missing, changed or unverified bindings fail closed. Neither another browser nor the system browser is substituted. Arguments replacing the managed MCP/settings binding are refused. Environment-local user settings remain available; project MCP/settings and Chrome integration are excluded from this dedicated launch. Ordinary terminals retain their own workflow.

Dedicated sessions require a verified managed loopback route and the macOS Seatbelt network fence. Direct public-network connections, external DNS, detected host proxy ports, unsupported platforms and unfenced remote HTTP(S) upstreams are refused. Other loopback development services and local IPC remain reachable; the fence does not control those services' onward connections. Claude's nested sandbox is disabled because it cannot nest inside this fence; ordinary permission prompts remain under user control. The working directory is still a real user directory, not a filesystem sandbox.

The ordinary link-routing switch does not replace a dedicated Claude session's pinned browser. Its links and browser tools keep that binding, including when the ordinary switch is off.

When the owned route core exits, matching Claude processes and browser capabilities are revoked. Other nodes retain their lifecycle. Provider/API errors with the core still alive are reported by the official CLI; Envara does not rotate accounts or nodes.

Implementation: [browser broker](../electron/terminal-browser-broker.mjs), [network fence](../electron/terminal-network-fence.mjs), [terminal lifecycle](../electron/terminal-service.mjs).

## Privacy and verification boundaries

| Mode | Added CLI opt-outs |
| --- | --- |
| Off | None |
| Standard | `DO_NOT_TRACK=1`, `DISABLE_TELEMETRY=1`, `DISABLE_ERROR_REPORTING=1` |
| Strict | Standard plus `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` |

These options depend on the CLI respecting them and can affect optional features. They do not remove normal model/account traffic, change training preferences, hide all device signals or guarantee avoidance of account restrictions. Device-identifier restrictions cover tested interfaces in dedicated process trees, not replacement hardware or a virtual Mac.

Terminal and CLI processes receive the verified native locale and timezone. The saved geographic coordinates do not replace macOS location APIs or give a command-line program a virtual street address. WebRTC and browser tracker rules apply to the selected browser's own implementation; the terminal itself has neither a WebRTC engine nor a general tracker-blocking layer.

The selected profile's settings are checked for conflicting authentication/provider or routing inputs without printing their values or rewriting that file. This is startup validation, not enforcement over every organization policy or later settings reload.

[Controlled acceptance](../scripts/verify-claude-terminal.mjs) exercises real PTYs, the official program, authenticated local fixture routes, selected-browser tools and cleanup. Such fixtures do not establish real account login, credential refresh, inference, or a model deciding to invoke a tool. These account-dependent steps require separate acceptance. Browser fonts, GPU and website language have their own [device boundaries](browser-device-profiles.md).
