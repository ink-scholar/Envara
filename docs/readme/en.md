<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Many environments. One workspace.</strong><br />A local workspace for browsers, terminals and network contexts.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="MIT license for original code" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-0.5.23-475569" alt="Envara 0.5.23" /></a>
  <a href="en.md"><img src="https://img.shields.io/badge/README-9_languages-6366f1" alt="README in 9 languages" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <strong>English</strong> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">Download for macOS</a> · <a href="../capability-matrix.md">Capabilities and limits</a> · <a href="../../CONTRIBUTING.md">Contribute</a> · <a href="../SUPPORT.md">Support the project</a>
</p>

![Envara native workspace in Chinese](../media/workspace-zh-CN.png)

<p align="center"><sub>Native Electron workspace, shown with synthetic example data.</sub></p>

## One environment, one working context

Envara brings browsers, network egress, working directories and command-line tools into one local workspace. Each environment keeps its own browser data, tool configuration and history; different environments can use different networks.

| Workspace | Capabilities |
| --- | --- |
| Environments | Create, clone, group and search; save working directories and network contexts |
| Network egress | HTTP, HTTPS, SOCKS5 and built-in AnyTLS; detect actual egress, approximate region and timezone |
| Browsers | CloakBrowser / Chromium, Camoufox / Firefox and experimental BrowseForge Chromium; automatic configuration and advanced settings |
| Terminals | Real PTYs, directory selection, multiple sessions, resizable panels and independent windows |
| Claude Code | A separate official CLI installation per environment, named login profiles and MCP tools bound to the environment's browser |
| Attached applications | Bind supported Chromium/Electron applications to an environment; manage their running instances and separate application data |
| Data transfer | Export browser data, a selected terminal login profile or attached-application data separately, encrypted with a password |

Envara manages its built-in AnyTLS core, so no separate Clash configuration is needed. Browsers, terminals and attached applications reuse the confirmed network location and timezone. Location settings do not change the system timezone; IP geolocation only estimates a region.

Duplicating a terminal creates a new independent process without replaying commands. A Claude Code session opens a shell where you enter `claude`; you can download a separate official installation or initialize it from an existing local native executable. Envara does not modify the official CLI, copy the host account or enable permission bypass by default. [About Claude Code sessions](../claude-code-sessions.md).

Before launching an attached application, Envara checks compatibility, existing instances and the routing component's status. It refuses to launch if the requirements are not met. Stopping an application, removing its binding or quitting Envara preserves login data; that data is cleared only when you explicitly delete it or its environment. See [attached applications](../application-routing-options.md).

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

## Capability boundaries

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
