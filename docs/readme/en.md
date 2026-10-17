<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Give each workflow a place of its own.</strong><br />One environment. Your browser, terminal and apps.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="MIT license for original code" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-1.0.0-475569" alt="Envara 1.0.0" /></a>
  <a href="en.md"><img src="https://img.shields.io/badge/README-9_languages-6366f1" alt="README in 9 languages" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <strong>English</strong> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">Download for macOS</a> · <a href="../capability-matrix.md">Capabilities and limits</a> · <a href="../../CONTRIBUTING.md">Contribute</a> · <a href="../SUPPORT.md">Support the project</a>
</p>

**Browse, run commands and connect desktop apps with one working context from start to finish.**

Envara is an open-source local desktop workspace that brings network egress, browser profiles, terminal tools and supported desktop applications together. Each environment keeps its own settings and data. Create separate contexts for projects, accounts or regions, and manage them in one place.

![Envara native workspace in Chinese](../media/workspace-zh-CN.png)

<p align="center"><sub>Native Electron workspace, shown with synthetic example data.</sub></p>

## Bring the whole workflow together

Research in the browser, write code in the terminal, finish a task in a desktop app: these often belong to the same project. Envara lets them reuse one confirmed network context while keeping the browser data, tool settings and application data you need for next time.

**Choose your network once, connect the tools you need, and pick up where you left off.** Envara makes separate environments part of everyday work.

### 🌐 A browser of its own, in every environment

Choose **CloakBrowser / Chromium, Camoufox / Firefox** or experimental **BrowseForge Chromium**. Separate browser data, persistent sessions, environment groups, search and configuration cloning keep your work organized. Cloning a configuration creates a new environment; existing sign-in data stays in the original.

The selected engine manages fingerprint configuration by default, with advanced device, language and timezone settings available. Auditable tracker-blocking rules make the privacy controls inspectable. Support varies by engine. [Browser and device settings](../browser-device-profiles.md)

### 🧭 Set the network once, use the context throughout

Use **HTTP, HTTPS, SOCKS5 or AnyTLS**. AnyTLS runs through Envara's bundled, app-managed proxy core, with no separate Clash configuration needed.

When creating a network environment, Envara checks the **actual egress using an authenticated request**, then lets you confirm the region and timezone. Browsers, terminals and supported attached applications reuse that context. For a simulated location, use Google Maps to choose coordinates; measured egress and simulated location are displayed separately. Environment settings do not change the host system's timezone. [Network contexts](../network-context.md)

### ⌨️ A working environment for your terminal, too

Choose the **network, link browser and project folder** when starting a session. Configuration and history stay with the environment. Real PTYs, multiple sessions, a panel with draggable height, workspace expansion and independent windows keep the command line close at hand.

Duplicating a terminal opens a new idle process in the same context. Close the panel and return to the session later. Supported macOS managed loopback routes use a network fence: tools that cannot use the proxy fail to connect, preventing a silent fallback to direct traffic. Your project folder stays where it is, so you can keep using your existing toolchain.

### 🧩 Bring desktop apps into the workflow

Choose an environment and link browser for supported **Chromium / Electron applications**, then manage their launch, stop and application data in one place. Envara checks the target's identity, compatibility, existing instances and native routing components before allowing it to start.

Stopping an app, removing its binding or quitting Envara preserves sign-in and offline data for next time. Delete that data explicitly when you need to clear it. Native routing requires system authorization; support for an engine does not mean that every application has passed acceptance testing. [Attached application support](../application-routing-options.md)

### 🔗 Keep context from the command line to the sign-in page

Assign a link browser to an environment so pages opened from its terminal reach the corresponding environment. On macOS, system link routing can also handle links that managed applications hand to the system. Unrelated links still go to the previous default browser.

System link routing requires your confirmation in a macOS dialog and can be turned off at any time. When you explicitly choose the system browser, Envara explains that the link will leave the environment.

### 🤖 A workspace for AI and automation tools

The browser backend provides **REST, MCP and Playwright** interfaces for tasks such as page operations, forms, cookies and screenshots. See the [capability matrix](../capability-matrix.md) for interface coverage.

Claude Code is one integration: each environment has its own installation of the **unchanged official CLI**, named login profiles and a session-scoped MCP broker bound to the selected environment browser. Start at a shell prompt, then enter `claude` yourself. You choose the model, session-resume and permission options. [Claude Code sessions](../claude-code-sessions.md)

### 📦 Take the data you choose when it's time to move

Browsers, terminals and attached applications each offer **password-encrypted exports**, so you can choose the data you need. Terminal exports include the selected Claude login profile plus shared shell configuration and history. Imports create a new environment, preserving your existing workspace.

Application executables, caches, temporary files and Keychain are excluded. Some accounts may still need a fresh sign-in on another machine.

### 🗂️ Keep everyday work close at hand

The three-column workspace supports light, dark and system appearance, giving environments, networks, browsers, terminals, attached applications and runtime status a clear place. Appearance settings apply only to Envara and do not change your computer’s appearance. Common actions are within reach; detailed settings stay under Advanced. Nine interface languages let you start in a language you know.

## What can you do with Envara?

| Use case | What Envara helps you organize |
| --- | --- |
| Development across projects | Project folders, terminal configuration and history, browser data and the chosen network |
| Work across accounts | Browser and application data kept separately by environment, reducing context mix-ups |
| Regional web checks | Choose a network, verify actual egress, then configure the browser's region, language and timezone |
| AI-assisted development and browser automation | Run tools in the selected environment, connect to browser interfaces and use dedicated Claude sessions |
| Workspace backup and migration | Export encrypted data for a browser, terminal profile or individual application, then restore it in a new environment |

**A local desktop, one working context, and a choice of tools.** Focus on your work; Envara helps keep the environment organized.

## Download and install

Download the **macOS Apple Silicon (arm64)** DMG or ZIP from [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest). Open the DMG and drag Envara into Applications. Checksums and release notes accompany each release.

**The current macOS artifacts are not signed with an Apple Developer ID and are not notarized.** macOS security checks may prevent the first launch; confirm that the download came from this repository and verify its checksum. Envara does not automatically disable system security checks. The system routing component for attached applications requires separate administrator approval; starting the browser or ordinary workspace does not install it automatically.

| Platform | Release scope |
| --- | --- |
| macOS Apple Silicon | DMG, ZIP and SHA-256 checksum files in this release |
| macOS Intel | Source paths retained; no verified artifact provided |
| Windows / Linux | Related source retained; no artifacts in this release. See the capability matrix for real-machine validation scope |

Users install browser engines through the app, under each engine's own license. The app includes its desktop runtime dependencies; no separate Node.js or Go installation is needed.

## Start in your language

The interface supports **简体中文、繁體中文、English、日本語、한국어、Español、Français、Deutsch、Português (Brasil)**. First launch recommends the system language for you to confirm; you can change it later in Settings.

![First-launch language selection](../media/first-launch.png)

<p align="center"><sub>Native first-launch language selection.</sub></p>

Interface language is separate from browser locale. Changing the menu language does not change existing networks, timezones or working directories.

## About isolation and privacy

Envara focuses on controlled networks, separate data and auditable privacy mechanisms. These boundaries help you use it according to its actual capabilities:

- Configuration and data isolation do not provide a separate OS user, Keychain or virtual hardware. Browser fingerprint settings do not change native applications' hardware identity.
- Supported macOS terminal routes use a network fence. Platforms and routes without that boundary must not be treated as forcibly isolated. See the [capability matrix](../capability-matrix.md).
- When attached applications use the outer network fence, Chromium/Electron's internal sandbox is disabled. Native component status, supported engines and actual validation scope are documented separately; recognizing an application does not mean that every application has been verified.
- Exports exclude Keychain, application executables, caches and temporary files. Some accounts may need to sign in again on another machine; a successful same-machine restore does not guarantee that login state works across machines.
- Tracker blocking covers only implemented rules and engine-supported controls. Network, account and configuration isolation does not guarantee freedom from service restrictions or remove all tracking.

[Verification](../verification.md) · [Architecture](../architecture.md) · [Network contexts](../network-context.md) · [Browser devices and languages](../browser-device-profiles.md)

## Develop from source

Requires Node.js 24 LTS (or 22.12+), npm, Go 1.25 and build tools for the target platform. macOS native components require Xcode Command Line Tools.

```bash
npm ci
npm run desktop
```

Initial preparation downloads pinned build dependencies. Development preview and checks:

```bash
npm run dev
npm test
npm run build
npm run test:sites
```

The web preview is for interface development; real browsers, PTYs and system routing require the desktop app. See the [contribution guide](../../CONTRIBUTING.md) and [release process](../releasing.md) for building and releasing. GitHub's automatic build and release workflows remain disabled; source pushes do not trigger builds.

## Open source and support

Original Envara code uses [MIT](../../LICENSE). BrowseForge retains its [MIT license](../../third_party/browseforge/LICENSE) and [pinned upstream record](../../third_party/browseforge/ENVARA_UPSTREAM.md). The independent Mihomo core retains [GPLv3](../../third_party/proxy-core/LICENSE) and its [corresponding source](../../third_party/proxy-core/SOURCE.md). Browser binaries have their own licenses and are not covered by the app's MIT license. Full attribution is in [third-party notices](../../THIRD_PARTY_NOTICES.md).

[Report an issue](https://github.com/ink-scholar/Envara/issues), contribute code, improve translations or leave a Star. All support is voluntary; donations are not enabled. [Support the project](../SUPPORT.md)
