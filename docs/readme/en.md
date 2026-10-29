<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Give each workflow a place of its own.</strong><br />One environment. Your browser, terminal and apps.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="MIT license for original code" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/github/v/release/ink-scholar/Envara?color=475569" alt="Latest release" /></a>
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

## One workspace for the whole workflow

| Feature | What you can do |
| --- | --- |
| 🌐 Network environments | Use HTTP / HTTPS / SOCKS5 / AnyTLS, check authenticated egress, and confirm region and timezone; AnyTLS needs no separate Clash installation |
| 🧭 Separate browsers | Choose CloakBrowser, Camoufox or experimental BrowseForge Chromium; keep data separate and reuse saved identities when reopening |
| ⌨️ Native terminals | Choose a project folder, open multiple sessions, resize the panel or use a separate window; retain environment configuration and history. Each saved macOS SSH connection can use the host network or a configured environment’s route |
| 🧩 Attached apps | Bind supported Chromium / Electron applications to an environment, with separate data and managed start/stop controls |
| 🤖 Claude Code | Install and update within an environment, manage named login profiles, and bind the selected environment browser |
| 🔗 Links and automation | Open links in the chosen browser and use REST / MCP / Playwright browser interfaces |
| 📦 Encrypted migration | Export a browser, selected terminal profile or individual app with password encryption; import into a new environment |
| 🗂️ Workspace management | Group, search and duplicate environments; inspect runtime status in a three-column layout with collapsible navigation, nine languages and light, dark or system appearance |

## Keep working with familiar tools

Research in the browser, write code in a terminal and open the desktop apps you need. Your environment keeps the network settings and data for that work together. Connect to remote servers from the terminal, with a chosen route for each saved SSH connection. See the [SSH guide](../claude-code-sessions.md#ssh-through-the-environment-route) for setup.

Claude Code is one integration within the terminal workflow. Each environment installs the **unchanged official CLI**, keeps named login profiles separate and binds the chosen environment browser. Start at a shell prompt and type `claude` when you want to use it. You choose the model, session-resume and permission options. See the [Claude Code guide](../claude-code-sessions.md).

Environment isolation helps reduce network and account configuration mix-ups; it does not guarantee freedom from account restrictions or complete anonymity. See [capabilities and limits](../capability-matrix.md) for attached-app support, system authorization and sandbox trade-offs. Stopping or unbinding preserves sign-in data.

## Get started

Download the **macOS Apple Silicon (arm64)** DMG or ZIP and SHA-256 checksums from [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest). See the [user guide](../user-guide.md) for installation steps and signing information.

1. **Choose a network.** Add a network configuration, check its actual egress, then confirm the region and timezone.
2. **Create an environment.** Choose a browser and give your project or account its own workspace.
3. **Start working.** Open the browser, choose a terminal working directory or attach a supported desktop app.

Return to the same environment to reuse your saved browser data, terminal settings and app data, with less setup each time.

[User guide](../user-guide.md) · [All features](../capability-matrix.md) · [Release notes](https://github.com/ink-scholar/Envara/releases) · [Develop and contribute](../../CONTRIBUTING.md) · [Report an issue](https://github.com/ink-scholar/Envara/issues)

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
