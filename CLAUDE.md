# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Read `AGENTS.md` first.** It holds the binding product, privacy, routing, UI and release rules (fail-closed networking, no host changes, nine interface languages, three-column layout, publication only on explicit request). This file does not repeat them.

## Commands

Requires Node.js 24 LTS (or 22.12+), npm, and Go 1.25. macOS native pieces need Xcode Command Line Tools.

```bash
npm ci                      # postinstall runs scripts/prepare-native.mjs (node-pty rebuild for Electron)
npm run dev                 # Vite UI only (no Electron services)
npm run desktop             # full desktop: prepares PTY, Keychain helper, Go sidecar, Playwright driver, Mihomo core, then Vite + Electron
npm test                    # node --test tests/*.test.mjs (~3k tests; some skip conditionally per platform)
node --test tests/terminal-process.test.mjs        # single test file
node --test --test-name-pattern="duplicate" tests/terminal-service.test.mjs   # single test by name
npm run build               # vite build + scripts/prepare-sites-build.mjs
npm run test:sites          # worker/hosting checks; must keep passing
```

Required before packaging: `npm test`, `npm run build`, `npm run test:sites`, plus relevant native checks. The build must preserve `dist/client/index.html`, `dist/server/index.js` and `dist/.openai/hosting.json`. Do not modify `.openai/hosting.json`, `worker/index.js`, `scripts/prepare-sites-build.mjs` or `tests/sites-worker.test.mjs`.

Resource preparation (outputs go to ignored `build/*` dirs): `backend:prepare` (Go BrowseForge sidecar + pinned Playwright driver/Node), `proxy:prepare` (Mihomo core), `native:prepare`, `routing:build:mac*` / `routing:build:win`. Platform smoke/acceptance scripts live in `scripts/` (`verify-*`, `accept-*`, `test-*`) and are wired as `npm run test:*` / `routing:*` entries in `package.json`.

## Architecture

Electron app, ESM throughout (`"type": "module"`); only `electron/preload.cjs` is CommonJS.

- **`src/`** — React 19 renderer. `App.jsx` owns workspace state and page switching; feature components are separate files. `src/i18n.mjs` + `src/locales/` hold base strings; feature translations live in `*-translations.mjs` files next to their component and are merged in. Every new string needs all nine languages.
- **`electron/`** — main process. `main.mjs` wires windows and services; `desktop-startup.mjs` initializes services asynchronously after the first window appears; `desktop-ipc.mjs` is the single allowlisted IPC surface (caller-window checks, method whitelist, per-environment data locks). The renderer never touches Node, arbitrary paths or backend tokens.
  - Browser: `browseforge-service.mjs` + `sidecar-manager.mjs` drive the local Go sidecar (`third_party/browseforge/`, pinned upstream with Envara patches — see `ENVARA_UPSTREAM.md`) over a private token; it launches CloakBrowser/Camoufox/BrowseForge Chromium through a bundled read-only Playwright driver.
  - Network: `proxy-network.mjs` (authenticated egress measurement), `proxy-core-manager.mjs` (per-node Mihomo listeners with ephemeral credentials), `shared/network-location.mjs` (confirmed location rules). Browser, terminal and apps all consume the same saved network context.
  - Terminal: `terminal-service.mjs` (sessions/lifecycle), `terminal-process.mjs` (PTY spawn/kill trees, has win32 branches), `terminal-launch-config.mjs` (pure env/launch builder), `terminal-network-fence.mjs` (macOS Seatbelt), `terminal-browser-broker.mjs`/`terminal-browser-mcp.mjs` (session-scoped MCP), `terminal-ssh-*.mjs`, `claude-code-*.mjs` (per-environment official CLI install/profiles).
  - Attached apps: `application-service.mjs`, `application-compatibility.mjs`, `application-routing.mjs` (spawns the platform routing helper and speaks its RPC), `macos-pf-*.mjs` for the macOS PF path.
  - Transfer: `environment-export.mjs` (encrypted format), `environment-transfer.mjs`, `environment-import-lifecycle.mjs`.
  - Pure policy/config modules are separated from services that own processes and async lifecycle; tests target both.
- **`shared/`** — modules used by both renderer and main (protocol, appearance, languages, fingerprint profiles).
- **`native/`** — platform components: macOS Swift helpers (PF routing, link router, Keychain, updater, authorization app) and `windows-app-routing/` (Go helper + WinDivert capture DLL + PowerShell installer; its launch gate is intentionally hard-coded closed — see its README).
- **`tests/`** — `node:test` files, one per module, synthetic fixtures only.
- **`docs/`** — `architecture.md`, `capability-matrix.md` (what is and isn't supported/verified), `verification.md` (per-release verification records), `releasing.md`, `windows-desktop-packaging.md`. Docs are mostly Simplified Chinese.

## Platform status

The only released and accepted target is **macOS arm64**. Windows x64 has build/packaging paths (`npm run dist:win` on a Windows host; `node scripts/prepare-windows-desktop.mjs [--build|--verify <stage>]` for an isolated cross-host stage under `.cache/windows-desktop/`) and `win32` branches in the main process, but no native GUI/PTY/browser/driver/routing acceptance. Package checks and cross-compilation are not proof of Windows behavior; record unverified coverage explicitly rather than claiming support.

## Windows port (branch `windows`)

Work happens on the `windows` branch. The running record is `docs/windows-test-plan.md` §4: checked items are done, with the round and commit noted. Tester guides are `docs/windows-test-round3.md` and `docs/windows-test-round4.md`. Rounds 1–4 accepted on real Windows 11 hardware:
- the stock install path: prebuilt node-pty without Visual Studio, Mihomo prep, system-proxy engine downloads;
- terminal close and app exit (Windows/Linux confirm before the last window closes while terminals or apps run);
- Camoufox via authenticated HTTP exits;
- the BrowseForge Chromium hold (`electron/engine-platform-hold.mjs`).

Windows facts learned so far:
- The sidecar build pins `GOTOOLCHAIN=go1.25.0`. Install exactly Go 1.25.0, or Go downloads that toolchain through `proxy.golang.org`.
- Node reports synthetic mode/uid values on Windows; use `electron/file-trust.mjs`, never raw POSIX permission checks.
- Process snapshots use one long-lived PowerShell reader (`electron/terminal-process.mjs`); never start a new `powershell.exe` per poll.
- HTTP/HTTPS proxies are checked through the managed Mihomo route, which hides upstream 407s; `ProxyNetworkProbe.explainFailure` reclassifies them.
- Native folder/save dialogs block automation; drive them with UI Automation and Win32 messages when testing remotely.

Next work, in order (keep §4 of the test plan updated as items land):
1. **Make `npm test` portable on Windows.** About 680 tests fail there, mostly from POSIX/macOS assumptions in the tests themselves: `/usr/bin/true`, `/tmp`, Unix sockets, `process.getuid`, `openssl`, gzip fixtures, and Seatbelt/Keychain/PF files.
   - Skip macOS-only tests by platform, and give the general tests portable fixtures.
   - Re-run on a Windows machine and triage what is left as real Windows defects.
   - Watch for `realpath` literal comparisons (case, 8.3 short names, the `\\?\` prefix) and temp-directory leaks (`envara*` under `%TEMP%`).
2. **Windows UI mismatches**, all small:
   - hide or disable the macOS-only "SSH 连接" nav item;
   - show the system link-router control as unavailable instead of hiding it;
   - drop or explain the "terminal links use the selected browser" setting while the link channel is unavailable;
   - filter installers and system helpers out of the attached-app catalog;
   - make the Claude refusal say "Windows not supported yet" rather than "invalid installation";
   - show engine download progress, and stop the failure text from repeating progress lines.

   Every new string needs all nine languages.
3. **Terminal link channel on Windows.** `electron/terminal-link-channel.mjs` uses a Unix socket path, and its uid check always fails on Windows (startup logs "终端链接通道目录不安全"). Move it to a named pipe (`\\.\pipe\…`) with an equivalent ownership/ACL check, so terminal-opened links and OAuth handoffs reach the environment browser.
4. **Packaging acceptance:** `npm run dist:win` installer install, first launch, uninstall and data retention on a clean Windows machine.
5. **Low priority / noise:**
   - node-pty `AttachConsole failed` stack traces on session close;
   - the early "Unable to reach the local BrowseForge service" refresh before the sidecar is ready;
   - retry `playwright-driver` directory renames on transient EPERM;
   - declare `allowScripts` before moving to npm 12.
6. **Blocked or large; keep the explicit refusals until then:**
   - lift the BrowseForge Chromium hold once upstream ships a Windows runtime with the SxS manifest and working timezone/locale;
   - Windows terminal network fence;
   - Claude Code native Windows install;
   - WinDivert attached-app routing (see `native/windows-app-routing/README.md`);
   - SSH and system link routing.
