# Claude Code sessions

This document describes Envara 1.0.4 for macOS arm64. Release-specific SSH and package checks are recorded in [release verification](verification.md); terminal input checks retain their [1.0.2 scope](verification.md#102-发布验证). Historical measurements do not establish real Claude account login or model-directed tool use. Envara launches the **unchanged official native Claude Code CLI**; it does not bundle a Claude program, convert subscriptions to an API, or infer whether an account is signed in.

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

Envara 1.0.4 supports password and public-key SSH with per-session connection discovery. Controlled checks cover common SSH command forms, protected terminal discovery, real MCP stdio discovery and native authentication against disposable local servers. Password checks include interactive input, normal and abrupt exits, cancellation, wrong-password and changed-host-key rejection, authorization state and cleanup. This section does not establish authentication through Envara to a production server or a model-directed Claude invocation.

If no connections are available, open **Terminal → SSH connections**. Enter a connection name, server, port and user, then choose the authentication method. Both methods require an existing trusted host entry for the server and port in the host's `known_hosts`; confirm the displayed host fingerprints before saving. End active sessions before changing connections; saved changes take effect in a **new ordinary or Claude terminal session**.

For public-key authentication, select a private key with the native file picker. The key must have its matching `.pub` file and permissions exactly `0600`. Confirm its displayed public fingerprint. Starting a terminal revalidates the key and saved host identity before loading its environment-owned agent.

For password authentication, the saved `authType: password` record contains the connection metadata and trusted host keys, never the password. Enter the password in Envara's SSH connection interface to unlock it for the current Envara application run. The grant stays in application memory until Envara quits or the authorization is explicitly revoked; enter it again after restarting Envara. New or duplicated terminal sessions load only grants that are currently unlocked and ready. Each session retains its original authorization binding: a later unlock cannot reactivate a session whose grant was revoked. JavaScript strings can leave immutable copies in memory, so discarding password references is not a guarantee of complete memory zeroing.

Use `envara-ssh list` (or `envara-ssh list --json`) to discover the authorizations loaded into the current session, and `envara-ssh help` for usage. Ordinary terminals and Claude terminals use the same restricted SSH command entry point. Claude can discover the same authorizations through the session MCP broker's read-only `envara_ssh_connections` tool. These discovery commands and the tool never return passwords, open a connection or grant additional access. An empty result directs you to **Terminal → SSH connections**; a `ready` result means authorization is available, not that the server is reachable or authentication has succeeded. A saved connection is not usable through a session whose authority has been closed or revoked.

Connect with the displayed saved alias, such as `ssh envara-0123456789ab`, or common syntax such as `ssh -p 2222 operator@server.example` and `ssh -p 2222 -l operator server.example`. Host, port and user must uniquely match an already saved connection loaded into the session; missing, conflicting or ambiguous matches are refused. This syntax selects an existing authorization and cannot add a destination or key. Interactive SSH and remote commands support optional `-T`, `-t`, `-v`, `-vv` or `-vvv`. Connection options can also follow the destination until the first remote command argument; subsequent command arguments are preserved. Use `--` to end connection options explicitly. Arbitrary `-i`, `-o` and `-F` arguments, forwarding and jump hosts are refused; `scp` and `sftp` are not integrated.

The native SSH client uses an authenticated CONNECT helper through the selected loopback route, without local destination DNS or direct fallback. Public-key connections use a separate OpenSSH agent for each terminal, containing only the selected identities and constrained to the saved server host keys and usernames. Agent forwarding, password fallback for public-key connections and host-key auto-acceptance remain disabled. Password and public-key authorizations have no scheduled expiry during the current Envara run; elapsed time alone does not revoke them or disconnect an established connection. Ending a terminal or quitting Envara closes its owned agent and session authority. Connection and authentication setup can still fail or time out.

Password connections are started by the main process using the native SSH client, fixed password-only authentication settings and a forced askpass helper over a private, protected channel. Caller-supplied environment values cannot select the client, helper or credentials, and the terminal cannot retrieve the password through this channel. The SSH process retains the saved destination, trusted host keys and selected route, with no direct fallback. Ending the terminal, quitting Envara or revoking its authorization or route still closes its owned SSH connections. This feature does not send the password to terminal output, discovery tools or the model. A user can still disclose a password in a command, chat message or remote output; this boundary does not promise secrecy for those actions. Keyboard-interactive authentication and MFA prompts are not supported. After restarting Envara or revoking a grant, unlock it in Envara and load it into a new terminal session.

Private keys remain in their original location. Only native `ssh-add` loads them; the application stores references and public identity information outside exported profile data. New fenced terminals cannot read the registered private-key paths or the host `.ssh` directory, modify their generated SSH configuration, or use other managed sessions' agents. Encrypted keys requiring an interactive passphrase are currently refused. Removing a connection or closing a terminal preserves the original key and account data.

These protections apply to new macOS fenced process trees and require OpenSSH 8.9 or later. Existing processes cannot receive a new Seatbelt profile. The boundary does not isolate unrelated applications running as the same macOS user, copies of keys at unknown locations, or an agent's destination host key reused on another server. The agent constraint identifies host keys and usernames; the connection helper additionally checks the configured hostname and port. Existing device restrictions and privacy opt-outs remain in place, with no guarantee against account restrictions.

Commands executed on the remote server use that server's network; their onward connections are outside the local terminal's network fence. When Claude runs a remote command, its output may enter Claude's context. Choose commands and output accordingly; the SSH boundary does not guarantee freedom from account restrictions.

A local proxy's HTTP 200 is only a transport acknowledgement. SSH success requires host-key verification, authentication and a server response. An upstream 502, missing banner or timeout leaves the connection failed; changing the client helper cannot make an unreachable server or an unsupported upstream route reachable. A successful direct-host probe tests a different route and does not establish that the selected environment proxy can reach the same server.

Implementation: [SSH manager](../electron/terminal-ssh-manager.mjs), [password broker](../electron/terminal-ssh-broker.mjs), [CONNECT helper](../electron/terminal-ssh-proxy.mjs). The [public-key acceptance](../scripts/verify-terminal-ssh-fixture.mjs) and [password acceptance](../scripts/verify-terminal-ssh-password-fixture.mjs) use disposable credentials and loopback servers; [opt-in server acceptance](../scripts/verify-terminal-ssh.mjs) uses an explicitly selected existing route and checks a read-only remote command. These checks do not substitute for a model-directed tool invocation or general SSH/server compatibility testing.

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
