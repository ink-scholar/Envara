<p align="center"><img src="../../build/icon.png" width="88" alt="Envara" /></p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Many environments. One workspace.</strong></p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="MIT license for original app code" /></a>
  <a href="../verification.md"><img src="https://img.shields.io/badge/0.5.0-local_candidate-475569" alt="0.5.0 local candidate" /></a>
</p>
<p align="center"><a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <strong>English</strong> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a></p>

![Envara native workspace in Chinese](../media/workspace-zh-CN.png)

*Native Electron candidate, shown in Chinese with synthetic network data. It is not egress or application-routing proof. [Earlier native screenshot](../envara-workspace-0.5.png).*

## Your local workspace

Envara brings BrowseForge browser environments into a desktop app. Navigation follows **Environments → Network egress → Browser → Terminal → Attached applications → Runtime monitor**. Detailed controls live under Advanced.

- **Environments:** separate browser data, groups, tags, cloning and configuration exchange.
- **Networks:** HTTP, HTTPS, SOCKS5 and app-managed AnyTLS; detect authenticated egress, approximate region and timezone without a separately configured Clash client.
- **Browsers:** CloakBrowser / Chromium, Camoufox / Firefox and experimental BrowseForge Chromium.
- **Terminals:** real local PTYs, a chosen directory, resizing, independent windows and multiple sessions. Duplicating creates a new process without replaying commands.
- **Attached applications:** bind local software to an environment. Protected launch is refused until the system adapter is authorized and verified.

Browsers and terminals share their environment's network and timezone. Tool configuration and history are separate between environments.

## Start in your language

The candidate UI supports Simplified Chinese, Traditional Chinese, English, Japanese, Korean, Spanish, French, German and Brazilian Portuguese. Choose a language at first launch and change it later in Settings. Interface language does not change browser locale, network, timezone, directory or terminal output.

![Native first-launch language selection](../media/first-launch.png)

*Native Electron first launch, shown in English. Selection, persistence and terminal-window synchronization were checked separately.*

## Availability and limits

**0.5.0 is a development candidate with no public final download.** The latest source progress is being shared; installation releases remain drafts and automatic releases remain disabled. Notion launch and cleanup are not accepted. See the [current diagnostic handoff](../notion-launch-handoff-20261010.md).

macOS Apple Silicon is the primary validation platform, with version-specific browser, AnyTLS and PTY evidence. The candidate is unsigned and unnotarized. Windows has source/build candidates but needs real-machine acceptance; macOS Intel and Linux are also unverified.

**Complete forced routing for attached applications is not ready on either platform.** Mac now defaults to a PF, process-group and owned-utun backend using Envara’s managed authenticated node. This path needs local administrator approval, without requiring an Apple Developer account. Independent DNS, failure protection and real-application acceptance remain pending; Notion has not run protected. See [routing boundaries](../application-routing-options.md) and [verification](../verification.md).

Tracker rules cannot remove all tracking. Configuration separation is not an OS sandbox. IP location estimates a region, not a residential address, and does not guarantee protection from account suspension.

## Development

Requires Node.js 24 LTS or 22.12+, npm, Go 1.25+ and platform build tools.

```bash
npm ci
npm run desktop
```

Initial preparation needs internet access. Users install browser engines from their official sources. Prepared desktop packages include runtime dependencies; end users do not need Go or Node.js.

```bash
npm test
npm run build
npm run test:sites
```

Web preview is for UI work; native operations need desktop mode. Read the [contribution guide](../../CONTRIBUTING.md).

## Learn more and support

[Capabilities and BrowseForge comparison](../capability-matrix.md) · [Architecture](../architecture.md) · [Verification](../verification.md) · [Issues](https://github.com/ink-scholar/Envara/issues)

Stars, feedback, translations and contributions help. [Financial support](../SUPPORT.md) will be optional; no payment channel is enabled.

## License

Original Envara code and included BrowseForge source retain their separate MIT licenses. The independent Mihomo core remains GPLv3 with corresponding source. Browser binaries have their own licenses; CloakBrowser's Binary License is not the app's MIT license. See [LICENSE](../../LICENSE), [BrowseForge provenance](../../third_party/browseforge/ENVARA_UPSTREAM.md), [proxy source](../../third_party/proxy-core/SOURCE.md) and [third-party notices](../../THIRD_PARTY_NOTICES.md).
