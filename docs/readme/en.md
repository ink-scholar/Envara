<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Give each workflow a place of its own.</strong><br />One environment. Your browser, terminal and apps.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="MIT license for original code" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-1.0.0-475569" alt="Envara 1.0.0" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <strong>English</strong> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">Download for macOS</a> · <a href="../user-guide.md">User guide</a> · <a href="../capability-matrix.md">All features</a> · <a href="../SUPPORT.md">Support</a>
</p>

**More than a privacy workspace for Claude Code: one independent environment for your browser, terminal and desktop apps.**

Envara is an open-source local desktop workspace. Keep separate networks, browser data and tool settings for different projects, accounts or regions. Choose an environment, research in the browser, write code or open an app, and pick up where you left off.

![Envara workspace with synthetic example data](../media/workspace-zh-CN.png)

## Concerned about account and environment linking in Claude Code?

Keep a **chosen network route, separate account directories, persistent browser identities and supported device-read restrictions** in the same session workflow to reduce configuration mix-ups. Each environment installs the **unchanged official CLI** and keeps named login profiles separate. You choose the model, session-resume and permission options.

Isolation helps reduce configuration mix-ups; it does not guarantee freedom from account restrictions or complete anonymity. See the [Claude Code guide](../claude-code-sessions.md) for methods and scope.

## One workspace for the whole workflow

| Feature | What you can do |
| --- | --- |
| 🌐 Network environments | Use HTTP / HTTPS / SOCKS5 / AnyTLS, verify authenticated egress, and confirm region and timezone; AnyTLS needs no separate Clash installation |
| 🧭 Separate browsers | Choose CloakBrowser, Camoufox or experimental BrowseForge Chromium; keep data separate and reuse saved identities when reopening |
| 🤖 Claude Code | Install and update within an environment, manage named login profiles, and bind the selected environment browser |
| ⌨️ Native terminals | Choose a project folder, open multiple sessions, resize the panel or use a separate window; retain environment configuration and history |
| 🧩 Attached apps | Bind supported Chromium / Electron applications to an environment, with separate data and managed start/stop controls |
| 🔗 Links and automation | Open links in the chosen browser and use REST / MCP / Playwright browser interfaces |
| 📦 Encrypted migration | Export a browser, selected terminal profile or individual app with password encryption; import into a new environment |
| 🗂️ Workspace management | Group, search and duplicate environments; inspect runtime status in a three-column layout with nine languages and light, dark or system appearance |

See [capabilities and limits](../capability-matrix.md) for attached-app system authorization, sandbox trade-offs and support. Stopping or unbinding preserves sign-in data.

## Get started

Download the **macOS Apple Silicon (arm64)** DMG or ZIP from [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest), with SHA-256 checksums. Current artifacts are not signed with an Apple Developer ID or notarized; see the guide for installation steps. Verified builds for other platforms are not available yet.

[User guide](../user-guide.md) · [All features](../capability-matrix.md) · [Verification scope](../verification.md) · [Develop and contribute](../../CONTRIBUTING.md) · [Report an issue](https://github.com/ink-scholar/Envara/issues)

## Support Envara

Development has involved substantial AI usage costs. If Envara helps you, voluntary support is welcome: [USDT](../SUPPORT.md#usdt) · [USDC](../SUPPORT.md#usdc) · [Binance](../SUPPORT.md#binance). Stars, feedback, translations and code contributions help too.

Original code uses [MIT](../../LICENSE). BrowseForge, Mihomo and other dependencies retain their own licenses and corresponding-source obligations. See [third-party notices](../../THIRD_PARTY_NOTICES.md).
