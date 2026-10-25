<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Give each workflow a place of its own.</strong><br />One environment. Your browser, terminal and apps.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="MIT license for original code" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-1.1.3-475569" alt="Envara 1.1.3" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <strong>English</strong> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">Download for macOS</a> · <a href="../user-guide.md">User guide</a> · <a href="../capability-matrix.md">All features</a> · <a href="../SUPPORT.md">Support</a>
</p>

**Bring your browser, terminal and desktop apps into separate working environments.**

Envara is an open-source local desktop workspace. Keep separate networks, browser data and tool settings for different projects, accounts or regions. Choose an environment, research in the browser, write code or open an app, and pick up where you left off.

![Envara workspace with synthetic example data](../media/workspace-zh-CN.png)

## New in 1.1.3

- **Keep terminal queries working when a view is hidden.** Fixes a missing-response bug that could leave command-line programs waiting and typed input without an echo after switching pages or closing a terminal view.
- **Use several views of the same session.** Each session handles terminal queries once, so opening another window or restoring output does not send duplicate replies.
- **Diagnose slow operations.** Local stage records help investigate delays and failures without recording commands, conversations or credentials. Existing environment settings and sign-in data are retained.

## Concerned about account and environment linking in Claude Code?

Keep a **chosen network route, separate account directories, persistent browser identities and supported device-read restrictions** in the same session workflow to reduce configuration mix-ups. Each environment installs the **unchanged official CLI** and keeps named login profiles separate. You choose the model, session-resume and permission options.

Isolation helps reduce configuration mix-ups; it does not guarantee freedom from account restrictions or complete anonymity. See the [Claude Code guide](../claude-code-sessions.md) for methods and scope.

## One workspace for the whole workflow

| Feature | What you can do |
| --- | --- |
| 🌐 Network environments | Use HTTP / HTTPS / SOCKS5 / AnyTLS, verify authenticated egress, and confirm region and timezone; AnyTLS needs no separate Clash installation |
| 🧭 Separate browsers | Choose CloakBrowser, Camoufox or experimental BrowseForge Chromium; keep data separate and reuse saved identities when reopening |
| 🤖 Claude Code | Install and update within an environment, manage named login profiles, and bind the selected environment browser |
| ⌨️ Native terminals | Choose a project folder, open multiple sessions, resize the panel or use a separate window; retain environment configuration and history. Each saved macOS [SSH connection](../claude-code-sessions.md#ssh-through-the-environment-route) can use the host network or a configured environment’s route |
| 🧩 Attached apps | Bind supported Chromium / Electron applications to an environment, with separate data and managed start/stop controls |
| 🔗 Links and automation | Open links in the chosen browser and use REST / MCP / Playwright browser interfaces |
| 📦 Encrypted migration | Export a browser, selected terminal profile or individual app with password encryption; import into a new environment |
| 🗂️ Workspace management | Group, search and duplicate environments; inspect runtime status in a three-column layout with nine languages and light, dark or system appearance |

**In 1.1.2, each SSH connection keeps its chosen route.** When adding a connection, select the host network or a configured environment, fetch the server fingerprint through that route, then verify and confirm it. New trust pins stay in Envara; it does not write them to the host’s `known_hosts`. Ordinary, Claude and duplicated terminal sessions use the saved route. Older records without a route retain the host network, including any active system VPN/TUN; the server sees the actual exit IP.

Missing authorization, an unavailable or changed selected environment route, and connection failures are refused without switching routes. Unsaved `user@host` destinations use the terminal’s own environment proxy, without borrowing a saved connection’s authorization or another environment’s route. Use `envara-ssh list` to inspect loaded authorizations. Passwords stay in application memory until exit; private keys remain on your Mac.

Existing sessions retain their original context; connection changes require a new session. See the [SSH guide](../claude-code-sessions.md#ssh-through-the-environment-route) for trust, authentication and supported command options.

See [capabilities and limits](../capability-matrix.md) for attached-app system authorization, sandbox trade-offs and support. Stopping or unbinding preserves sign-in data.

## Get started

Download the DMG or ZIP package for **macOS Apple Silicon (arm64)** from [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest), with SHA-256 checksums. Current artifacts are not signed with an Apple Developer ID or notarized; see the guide for installation steps. Verified builds for other platforms are not available yet.

**For your first session, start with one project.** Add and check a network route, then create an environment and choose a browser. Select a working directory when opening a terminal, or attach a supported desktop app as needed. Return to the same environment to reuse your saved browser data, terminal settings and app data, with less setup when switching between tools.

[User guide](../user-guide.md) · [All features](../capability-matrix.md) · [Verification scope](../verification.md) · [Develop and contribute](../../CONTRIBUTING.md) · [Report an issue](https://github.com/ink-scholar/Envara/issues)

## Support Envara

Development has involved substantial AI usage costs. If Envara helps you, voluntary support is welcome. Stars, feedback, translations and code contributions help too.

**All features remain available without a donation.** Please match both the asset and network shown below.

### USDT

| Network | Address |
| --- | --- |
| <img src="../assets/chains/tron.png" width="24" height="24" alt="TRON" /> TRON（TRC20） | `TFnUooSKx1Joe6i8vkbsiQpiMVqiNq5c1r` |
| <img src="../assets/chains/ethereum.png" width="24" height="24" alt="Ethereum" /> Ethereum（ERC20） | `0x71dead57a9d0047349329fecb914f2b2a069a869` |
| <img src="../assets/chains/solana.png" width="24" height="24" alt="Solana" /> Solana（SOL） | `6ACRnyNUHDuf7HeovVgxqBS8jgLsWrvbNTMuQnZdwr1V` |
| <img src="../assets/chains/arbitrum.png" width="24" height="24" alt="Arbitrum" /> Arbitrum | `0x71dead57a9d0047349329fecb914f2b2a069a869` |
| <img src="../assets/chains/plasma.png" width="24" height="24" alt="Plasma" /> Plasma | `0x71dead57a9d0047349329fecb914f2b2a069a869` |

### USDC

| Network | Address |
| --- | --- |
| <img src="../assets/chains/ethereum.png" width="24" height="24" alt="Ethereum" /> Ethereum（ERC20） | `0x71dead57a9d0047349329fecb914f2b2a069a869` |
| <img src="../assets/chains/solana.png" width="24" height="24" alt="Solana" /> Solana（SOL） | `6ACRnyNUHDuf7HeovVgxqBS8jgLsWrvbNTMuQnZdwr1V` |
| <img src="../assets/chains/arbitrum.png" width="24" height="24" alt="Arbitrum" /> Arbitrum | `0x71dead57a9d0047349329fecb914f2b2a069a869` |

### Binance

Binance ID: `820140284`

[Support details and icon sources](../SUPPORT.md)

---

Original code uses [MIT](../../LICENSE). BrowseForge, Mihomo and other dependencies retain their own licenses and corresponding-source obligations. See [third-party notices](../../THIRD_PARTY_NOTICES.md).
