# Claude Code sessions

This document describes Envara 1.0.3. Controlled SSH and package checks are recorded in [1.0.3 verification](verification.md#103-发布验证); terminal input checks remain in [1.0.2 verification](verification.md#102-发布验证). The release target is macOS arm64; published 1.0.1 package verification and the maintainer's confirmed payment-flow result are recorded in [release verification](verification.md#101-发布验证). Historical measurements retain their original package scope; they do not establish final-package Claude account or model-call acceptance. Envara launches the **unchanged official native Claude Code CLI**; it does not bundle a Claude program, convert subscriptions to an API, or infer whether an account is signed in.

## Start and installation

In **Terminal → New session**, choose Claude Code, the network, environment browser, named login profile and working directory. The session opens at a shell prompt. Enter `claude` when ready; leaving Claude returns to that shell. Model, resume and permission arguments remain user choices. Envara never enables permission bypass automatically.

Each environment owns its native installation. Reuse a valid existing installation, or choose:

- **Download independent installation:** fetch the official platform build through the selected environment route, verify size/checksum and applicable macOS signature identity, then install atomically.
- **Initialize from local Claude:** copy a supported native program into independent environment storage. No host credentials, configuration or history are copied, and the writable installation is not shared.

Cancellation or failure preserves account data and existing installation state. A missing or invalid source is reported; Envara does not silently use a host executable or another route. Background auto-updates are disabled. An explicit `claude update` affects that environment's next invocation; already-running programs keep their current version.

Implementation: [installer](../electron/claude-code-installation.mjs), [downloader](../electron/claude-code-download.mjs), [session launcher](../electron/claude-code-session.mjs).

## Terminal input

From 1.0.2, **Shift+Enter** sends the same multiline sequence as Option+Enter; plain Enter keeps its normal submit behavior. Confirming an input-method candidate with Enter does not also submit the terminal line. These rules apply to both the workspace panel and independent terminal window.

On macOS, the terminal waits for the input method's confirmed character on the backslash key, so Chinese `、` and English `\` or `|` retain their intended text. Screen-reader support follows the system accessibility state without restarting the session. These input changes preserve the official CLI, network fence, device restrictions and account directories.

The refreshed 1.0.2 package also keeps IME preedit after a complete wide character and moves it to the next visible row at a pending line wrap. At the bottom edge or when the text is too long, a bounded preedit popup uses an adjacent row; it can temporarily cover nearby output but keeps the current input line readable. The native candidate anchor follows the preedit, and returns to the terminal cursor when composition ends. This changes display positioning only, without rewriting terminal output or the committed input sequence.

## Login profiles and data

Named profiles use separate Claude configuration directories within one environment. Profiles share that environment's program but retain separate configuration/history storage. The default profile retains its existing directory. Duplication preserves the selected profile and creates an idle shell; it neither replays commands nor clones live process state.

Each selected profile pins both `CLAUDE_CONFIG_DIR` and `ANTHROPIC_CONFIG_DIR`; the latter is an owned subdirectory of the former. This also separates newer Console profile files that `CLAUDE_CONFIG_DIR` alone does not scope. An old environment-wide `HOME/.config/anthropic` directory is preserved without assigning it to a named profile or copying its credentials. If it exists, the session asks the user to sign in again within the selected profile.

Envara displays profile names, not inferred authentication status. Closing a terminal, stopping the program or updating Envara does not delete profile data. Official sign-in, token refresh, account policies and remote model availability remain the service's responsibility. Browser website sign-in and CLI sign-in are distinct.

Terminal export includes only the chosen Claude profile, including its scoped Anthropic directory, plus shared shell configuration/history. It excludes other profiles, the old shared Anthropic directory, program files, caches and host credentials. Encrypted import creates a new environment and requires explicit proxy mapping. macOS Keychain entries are not exported; copied files do not guarantee cross-machine sign-in.

### Profile management

The new-session dialog can create a named profile without starting Claude, and **Manage profile** can rename or delete the selected profile. Renaming changes its display name while retaining its directory and data. The default profile can be renamed but cannot be deleted individually.

Deletion requires confirmation for the selected profile and removes only that profile's configuration and history. Other profiles, the environment's Claude installation and shared shell data are retained. If removal of remaining files is incomplete, the dialog reports pending cleanup and offers a retry rather than claiming that cleanup finished.

Renaming and deletion are refused while a dedicated terminal using that profile is starting, running or closing. End the relevant terminal session first; closing its view alone retains the session. This use check describes process ownership, not account authentication. Deletion also prevents a new session or duplicate from starting with the same profile during the operation.

## Browser and network binding

A dedicated session pins its selected environment browser. A private session-scoped `envara_browser` MCP broker exposes supported page navigation, inspection, inputs, clicks, screenshots and tab operations. The desktop retains the broad backend token and raw Playwright endpoint.

Missing, changed or unverified bindings fail closed. Neither another browser nor the system browser is substituted. Arguments replacing the managed MCP/settings binding are refused. Environment-local user settings remain available; project MCP/settings and Chrome integration are excluded from this dedicated launch. Ordinary terminals retain their own workflow.

Dedicated sessions require a verified managed loopback route and the macOS Seatbelt network fence. Direct public-network connections, external DNS, detected host proxy ports, unsupported platforms and unfenced remote HTTP(S) upstreams are refused. Other loopback development services and local IPC remain reachable; the fence does not control those services' onward connections. Claude's nested sandbox is disabled because it cannot nest inside this fence; ordinary permission prompts remain under user control. The working directory is still a real user directory, not a filesystem sandbox.

The ordinary link-routing switch does not replace a dedicated Claude session's pinned browser. Its links and browser tools keep that binding, including when the ordinary switch is off.

When the owned route core exits, matching Claude processes and browser capabilities are revoked. Other nodes retain their lifecycle. Provider/API errors with the core still alive are reported by the official CLI; Envara does not rotate accounts or nodes.

Implementation: [browser broker](../electron/terminal-browser-broker.mjs), [network fence](../electron/terminal-network-fence.mjs), [terminal lifecycle](../electron/terminal-service.mjs).

## SSH through the environment route

From 1.0.3, in **Terminal → SSH connections**, enter a connection name, server, port and user, then select a private key with the native file picker. The key must have its matching `.pub` file, permissions exactly `0600` and an existing trusted host entry in the host's `known_hosts`. Confirm the displayed public fingerprints and save. End active sessions before changing connections, then start a new ordinary or Claude terminal and use the displayed `ssh envara-…` command. Do not pass a host private-key path with `-i`.

Saved aliases support interactive SSH and remote commands, with optional `-T`, `-t`, `-v`, `-vv` or `-vvv`. This entry point does not integrate `scp`, `sftp`, `ProxyJump`, port forwarding or arbitrary OpenSSH configuration arguments such as `-i`, `-p`, `-F` and `-o`.

The native SSH client uses an authenticated CONNECT helper through the selected loopback route, without local destination DNS or direct fallback. Each terminal owns a separate OpenSSH agent containing only the selected identities, constrained to the saved server host keys and usernames. Agent forwarding, password fallback and host-key auto-acceptance are disabled. Agent authorization lasts one hour; start a new terminal to renew it. An established SSH connection is not immediately disconnected when that authorization expires.

Private keys remain in their original location. Only native `ssh-add` loads them; the application stores references and public identity information outside exported profile data. New fenced terminals cannot read the registered private-key paths or the host `.ssh` directory, modify their generated SSH configuration, or use other managed sessions' agents. Encrypted keys requiring an interactive passphrase are currently refused. Removing a connection or closing a terminal preserves the original key and account data.

These protections apply to new macOS fenced process trees and require OpenSSH 8.9 or later. Existing processes cannot receive a new Seatbelt profile. The boundary does not isolate unrelated applications running as the same macOS user, copies of keys at unknown locations, or an agent's destination host key reused on another server. The agent constraint identifies host keys and usernames; the connection helper additionally checks the configured hostname and port. Existing device restrictions and privacy opt-outs remain in place, with no guarantee against account restrictions.

A local proxy's HTTP 200 is only a transport acknowledgement. SSH success requires host-key verification, authentication and a server response. An upstream 502, missing banner or timeout leaves the connection failed; changing the client helper cannot make an unreachable server or an unsupported upstream route reachable.

Implementation: [SSH manager](../electron/terminal-ssh-manager.mjs), [CONNECT helper](../electron/terminal-ssh-proxy.mjs). The [owned local acceptance](../scripts/verify-terminal-ssh-fixture.mjs) uses disposable keys and a loopback server; [opt-in server acceptance](../scripts/verify-terminal-ssh.mjs) uses an explicitly selected existing route and checks a read-only remote command. Neither substitutes for a model-directed tool invocation or general SSH/server compatibility testing.

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
