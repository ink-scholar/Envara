# Claude Code sessions

This document describes Envara 1.1.1 for macOS arm64. Release-specific SSH and package checks are recorded in [release verification](verification.md); terminal input checks retain their [1.0.2 scope](verification.md#102-发布验证). Historical measurements do not establish real Claude account login or model-directed tool use. Envara launches the **unchanged official native Claude Code CLI**; it does not bundle a Claude program, convert subscriptions to an API, or infer whether an account is signed in.

## Start and installation

In **Terminal → New session**, choose Claude Code, the network, environment browser, named login profile and working directory. The session opens at a shell prompt. Enter `claude` when ready; leaving Claude returns to that shell. Model, resume and permission arguments remain user choices. Envara never enables permission bypass automatically.

Each environment owns its native installation. Reuse a valid existing installation, or choose:

- **Download independent installation:** fetch the official platform build through the selected environment route, verify size/checksum and applicable macOS signature identity, then install atomically.
- **Initialize from local Claude:** copy a supported native program into independent environment storage. No host credentials, configuration or history are copied, and the writable installation is not shared.

Cancellation or failure preserves account data and existing installation state. A missing or invalid source is reported; Envara does not silently use a host executable or another route. Background auto-updates are disabled. An explicit `claude update` affects that environment's next invocation; already-running programs keep their current version.

Implementation: [installer](../electron/claude-code-installation.mjs), [downloader](../electron/claude-code-download.mjs), [session launcher](../electron/claude-code-session.mjs).

## Saved terminals

Successfully created ordinary and Claude terminals automatically add an entry under **Saved terminals**. Give each entry a recognizable name. Clicking a running entry selects its existing session; if duplicates are running, it selects the latest one. Clicking an ended entry opens an idle shell with the saved context. Enter `claude` yourself when needed; commands and live process state are never replayed.

An entry stores its name, terminal type, selected login profile and browser, working directory and network reference. It does not store credentials or terminal output. Changed network/browser settings, missing login profiles or unavailable directories require a new confirmed selection rather than a silent fallback.

Ending a session retains its entry. Renaming or removing an entry changes only that shortcut, preserving login data, terminal data and any running process. Sessions created before recording was introduced cannot be reconstructed as saved entries; recording starts with the next newly created session.

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

Envara’s built-in browser tools pin the selected environment browser. A private session-scoped `envara_browser` MCP broker exposes supported page navigation, inspection, inputs, clicks, screenshots and tab operations. The desktop retains the broad backend token and raw Playwright endpoint. Missing, changed or unverified Envara bindings fail closed, without substituting another browser or the system browser. The session-provided `envara_browser` entry takes precedence over a saved entry with the same name. This binding does not automatically apply to third-party browser MCP servers or plugins.

Custom MCP servers and enabled plugins can load from this environment’s user, local and project configuration alongside Envara’s built-in tools. Settings sources are `user,project,local`; arguments replacing Envara’s managed MCP/settings binding remain refused, and Chrome integration remains disabled. Ordinary terminals retain their own workflow.

Run `claude mcp add ...` inside the intended environment and selected login profile. The default `local` scope is tied to the current working directory: use the same directory when starting Claude again. Use `claude mcp add --scope user ...` to make a server available across working directories within that login profile. Project-scoped MCP entries follow the official CLI’s project trust flow; Envara does not approve trust prompts automatically or import all MCP definitions from the host’s Claude configuration.

After adding or changing MCP servers or plugins, exit Claude and invoke `claude` again to load the updated configuration. An already-running Claude process is not reconfigured by Envara. Terminals created before this compatibility change need a new Envara terminal to receive the updated launcher; closing a view alone retains its old session.

Dedicated sessions require a verified managed loopback route and the macOS Seatbelt network fence. Direct public-network connections, external DNS, detected host proxy ports, unsupported platforms and unfenced remote HTTP(S) upstreams are refused. Other loopback development services and local IPC remain reachable; the fence does not control those services' onward connections. Claude's nested sandbox is disabled because it cannot nest inside this fence; ordinary permission prompts remain under user control. The working directory is still a real user directory, not a filesystem sandbox.

The ordinary link-routing switch does not replace a dedicated Claude session's pinned browser. Its managed links and built-in browser tools keep that binding, including when the ordinary switch is off.

When the owned route core exits, matching Claude processes and browser capabilities are revoked. Other nodes retain their lifecycle. Provider/API errors with the core still alive are reported by the official CLI; Envara does not rotate accounts or nodes.

Implementation: [browser broker](../electron/terminal-browser-broker.mjs), [network fence](../electron/terminal-network-fence.mjs), [terminal lifecycle](../electron/terminal-service.mjs).

<a id="ssh-through-the-environment-route"></a>

## SSH routing and authorization

The current implementation chooses the SSH route from the saved destination. **Saved hosts use the host machine’s network exit; unsaved hosts use the selected environment proxy.** The saved route may use an existing system VPN or TUN; Envara does not change or bypass those host settings. A server reached through the host exit can see that exit’s public IP. This is an explicit exception for the saved destination, not general direct network access from the terminal.

In 1.1.0, a **new ordinary or Claude terminal session** receives these routing rules. Existing terminals retain the launcher and authorization created with that session. Controlled verification uses disposable local servers; production-server connectivity and model-directed Claude use require separate acceptance. See the [versioned verification record](verification.md#110-发布验证) for the final package scope.

To save a host for the host-machine route, open the **SSH connections** page in the sidebar. Enter a connection name, server, port and user, then choose the authentication method. Both methods require an existing trusted host entry for the server and port in the host's `known_hosts`; confirm the displayed host fingerprints before saving. End active sessions before changing connections; saved changes take effect in a **new ordinary or Claude terminal session**.

For public-key authentication, select a private key with the native file picker. The key must have its matching `.pub` file and permissions exactly `0600`. Confirm its displayed public fingerprint. Starting a terminal revalidates the key and saved host identity before loading its environment-owned agent.

For password authentication, the saved `authType: password` record contains the connection metadata and trusted host keys, never the password. Enter the password in Envara's SSH connection interface to unlock it for the current Envara application run. The grant stays in application memory until Envara quits or the authorization is explicitly revoked; enter it again after restarting Envara. New or duplicated terminal sessions load only grants that are currently unlocked and ready. Each session retains its original authorization binding: a later unlock cannot reactivate a session whose grant was revoked. JavaScript strings can leave immutable copies in memory, so discarding password references is not a guarantee of complete memory zeroing.

Use `envara-ssh list` (or `envara-ssh list --json`) to discover the authorizations loaded into the current session, and `envara-ssh help` for usage. Ordinary terminals and Claude terminals use the same restricted SSH command entry point. Claude can discover the same authorizations through the session MCP broker's read-only `envara_ssh_connections` tool. These discovery commands and the tool never return passwords, open a connection or grant additional access. An empty result means no saved authorizations are loaded; it does not disable proxy SSH to an unsaved destination. A `ready` result means authorization is available, not that the server is reachable or authentication has succeeded. A saved connection that is locked, unloaded or revoked is refused rather than retried through the environment proxy. Unlock it on the **SSH connections** page, then create a new terminal.

Connect with the displayed saved alias, such as `ssh envara-0123456789ab`, or common syntax such as `ssh -p 2222 operator@server.example` and `ssh -p 2222 -l operator server.example`. The command first matches the saved destination and port. Numerically equivalent IP literals, including IPv6 spellings and IPv4-mapped IPv6, match the same destination without rewriting the stored host. Hostname matching does not use DNS to infer equivalent destinations. A saved address/port requires the saved username and a unique, loaded authorization; changing the username cannot select the proxy route. A missing saved alias, conflicting or ambiguous match is refused. Interactive SSH and remote commands support optional `-T`, `-t`, `-v`, `-vv` or `-vvv`. Connection options can also follow the destination until the first remote command argument; subsequent command arguments are preserved. Use `--` to end connection options explicitly. Arbitrary `-i`, `-o` and `-F` arguments, forwarding and jump hosts are refused; `scp` and `sftp` are not integrated.

For an unsaved address/port, use explicit `user@host` or `-l user` with the usual port syntax. Its native SSH connection uses an authenticated CONNECT helper through the environment proxy, without local destination DNS or direct fallback. It does not borrow saved passwords or agents. Host-key verification and any password entry remain native SSH interactions in a real TTY, with no automatic trust approval or password supply. Without a TTY, a required trust or password interaction fails rather than being approved automatically.

For a saved destination, the main process supplies a session-bound TCP relay limited to that saved alias and destination. All native SSH processes retain the original Seatbelt fence; the terminal is not given arbitrary direct TCP access. Host DNS and the existing host network determine the saved destination’s host-exit route. Failed connection or authentication never switches routes. Saved public-key connections use a separate OpenSSH agent for each terminal, containing only the selected identities and constrained to the saved server host keys and usernames. Agent forwarding, password fallback for saved public-key connections and host-key auto-acceptance remain disabled. Password and public-key authorizations have no scheduled expiry during the current Envara run; elapsed time alone does not revoke them or disconnect an established connection. Ending a terminal or quitting Envara closes its owned agent and session authority. Connection and authentication setup can still fail or time out.

Native SSH uses Envara’s fixed `-F` configuration rather than the host’s SSH configuration. Its environment is allowlisted: a fixed `PATH`, an Envara-owned `HOME`, `LANG=C`, `LC_ALL=C`, `TERM=xterm-256color` and the required session transport/authentication capabilities. It does not inherit `USER`, `LOGNAME`, `HOSTNAME`, `PWD`, `TZ` or API credential variables, and does not automatically send the local account name, hostname, working directory or timezone. Agent, X11 and port forwarding remain disabled.

These controls do not hide the selected remote username, SSH protocol version, negotiation or requested terminal type, dimensions and modes. The server can still observe the connection’s exit IP; Envara does not make SSH metadata anonymous.

Password connections are started by the main process using the native SSH client, fixed password-only authentication settings and a forced askpass helper over a private, protected channel. Caller-supplied environment values cannot select the client, helper or credentials, and the terminal cannot retrieve the password through this channel. The SSH process retains the saved destination, trusted host keys and fixed host-exit route, without switching to the proxy on failure. Ending the terminal, quitting Envara or revoking its authorization or route still closes its owned SSH connections. This feature does not send the password to terminal output, discovery tools or the model. A user can still disclose a password in a command, chat message or remote output; this boundary does not promise secrecy for those actions. The saved-password helper does not support keyboard-interactive authentication or MFA prompts. After restarting Envara or revoking a grant, unlock it in Envara and load it into a new terminal session.

Private keys remain in their original location. Only native `ssh-add` loads them; the application stores references and public identity information outside exported profile data. New fenced terminals cannot read the registered private-key paths or the host `.ssh` directory, modify their generated SSH configuration, or use other managed sessions' agents. Encrypted keys requiring an interactive passphrase are currently refused. Removing a connection or closing a terminal preserves the original key and account data.

These protections apply to new macOS fenced process trees and require OpenSSH 8.9 or later. Existing processes cannot receive a new Seatbelt profile. The boundary does not isolate unrelated applications running as the same macOS user, copies of keys at unknown locations, or an agent's destination host key reused on another server. The saved agent constraint identifies host keys and usernames; the session relay additionally checks the fixed saved destination. Existing device restrictions and privacy opt-outs remain in place, with no guarantee against account restrictions.

Commands executed on the remote server use that server's network; their onward connections are outside the local terminal's network fence. When Claude runs a remote command, its output may enter Claude's context. A remote server or command can print the client exit IP; Envara does not automatically redact arbitrary remote output. The SSH boundary does not guarantee anonymity or freedom from account restrictions.

A local proxy's HTTP 200 is only a transport acknowledgement. SSH success requires host-key verification, authentication and a server response. An upstream 502, missing banner or timeout leaves the connection failed; changing the client helper cannot make an unreachable server or an unsupported upstream route reachable. A host-exit check and an environment-proxy check exercise different routes; success on one does not establish reachability or authentication on the other.

Implementation: [SSH manager](../electron/terminal-ssh-manager.mjs), [password broker](../electron/terminal-ssh-broker.mjs), [saved-destination relay](../electron/terminal-ssh-direct.mjs), [CONNECT helper](../electron/terminal-ssh-proxy.mjs). The [two-route verifier](../scripts/verify-terminal-ssh-routing.mjs) is the verification entry point for the new routing behavior. The [public-key fixture](../scripts/verify-terminal-ssh-fixture.mjs) and [password fixture](../scripts/verify-terminal-ssh-password-fixture.mjs) provide complementary authentication and lifecycle regressions with disposable credentials and loopback servers; [opt-in server acceptance](../scripts/verify-terminal-ssh.mjs) checks a read-only command against the explicitly selected saved server through the host exit. These links do not establish passing results for a new source build or package, model-directed tool use, or general SSH/server compatibility.

## Privacy and verification boundaries

| Mode | Added CLI opt-outs |
| --- | --- |
| Off | None |
| Standard | `DO_NOT_TRACK=1`, `DISABLE_TELEMETRY=1`, `DISABLE_ERROR_REPORTING=1` |
| Strict | Standard plus `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` |

These options depend on the CLI respecting them and can affect optional features. They do not remove normal model/account traffic, change training preferences, hide all device signals or guarantee avoidance of account restrictions. Device-identifier restrictions cover tested interfaces in dedicated process trees, not replacement hardware or a virtual Mac.

Terminal and CLI processes receive the verified native locale and timezone. The saved geographic coordinates do not replace macOS location APIs or give a command-line program a virtual street address. WebRTC and browser tracker rules apply to the selected browser's own implementation; the terminal itself has neither a WebRTC engine nor a general tracker-blocking layer.

Before each manual `claude` invocation, Envara checks the selected profile and applicable project/local settings for conflicting authentication/provider or routing inputs. Conflicts are refused without printing their values or rewriting those files. The official CLI still handles project trust and permission prompts. These checks do not enforce every organization policy or later settings reload, and third-party MCP service connectivity requires its own verification.

[Controlled acceptance](../scripts/verify-claude-terminal.mjs) exercises real PTYs, the official program, authenticated local fixture routes, selected-browser tools and cleanup. Such fixtures do not establish real account login, credential refresh, inference, or a model deciding to invoke a tool. These account-dependent steps require separate acceptance. Browser fonts, GPU and website language have their own [device boundaries](browser-device-profiles.md).
