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
- Tests: macOS-only files use `macOSOnly` from `tests/support/platform-test.mjs`, and Unix-socket transports use `unixSocketOnly`; skips always carry a reason.
- Windows does not paint hidden windows, so Electron UI fixtures show a frameless window off-screen on win32.
- `electron.exe` gets no console TTY under ConPTY, and ConPTY itself answers or swallows terminal queries.
- WSL mirrored networking can hold loopback ports that no listener reports, so tests must bind port 0, not fixed ports.

Next work, in order (keep §4 of the test plan updated as items land):
1. **`npm test` on Windows: done (round 5).** 1 failure remains, `browseforge-service` legacy migration, which fails on macOS too and is unrelated to Windows; the full run takes about 45 s.
   - Open decision: cache maintenance stays read-only on Windows until an NTFS ACL check exists.
2. **Windows UI mismatches: done (round 5).**
   - Follow-up: build the Windows attached-app catalog from Start Menu shortcuts (`.lnk`). The bounded Program Files scan still truncates and lists some vendor helpers.
3. **Terminal link channel on Windows: done (round 5).** A per-run named pipe; `BROWSER` is a PowerShell command line running `electron/terminal-link-shim.ps1`, never a `.cmd`, because batch files re-parse `&`/`|` in URLs.
   - Limit: only `BROWSER`-honouring tools reach the environment browser; `start <url>` uses the Windows default browser.
4. **Packaging acceptance: done (round 5).** Unsigned NSIS from `npm run dist:win` on Windows.
   - Accepted: silent install to the default and to a custom (space plus CJK) directory, installed launch, terminal, Camoufox, quit-all, and uninstall that keeps `%APPDATA%\Envara`.
   - Build prerequisites: Go 1.25.0, network, and an x64 C compiler. Without MSVC, use portable llvm-mingw via `ENVARA_WINDOWS_CC`.
   - Open: code signing (SmartScreen), upgrade-over-install, and a never-used user profile.
5. **Low priority / noise: done.**
   - node-pty's console-list agent runs silently (`quietConsoleListAgent`).
   - The workspace refresh skips the sidecar restart after an engine install.
   - Windows prepare renames retry transient EPERM.
   - `allowScripts` in package.json is pinned to `node-pty@1.1.0`, `esbuild@0.25.12` and `electron-winstaller@5.4.0` (denied); update the versions with dependency bumps.
6. **Blocked or large; keep the explicit refusals until then:**
   - lift the BrowseForge Chromium hold once upstream ships a Windows runtime with the SxS manifest and working timezone/locale;
   - Windows terminal network fence;
   - Claude Code native Windows install;
   - WinDivert attached-app routing (see `native/windows-app-routing/README.md`);
   - SSH and system link routing.
