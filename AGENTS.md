# Contributor instructions

## Project and workflow

Envara is a lightweight desktop workspace for browser environments, terminals and attached applications. Preserve existing configuration and application data.

- Present Envara as a complete environment workspace for browsers, terminals and supported desktop applications. Product writing should be distinctive, benefit-led and approachable; Claude Code is one integration, not the product's primary identity. Describe implemented privacy mechanisms accurately without promising immunity from account restrictions or unsupported market exclusivity.

- Read the implementation and existing tests before changing behavior. Prefer focused changes and shared rules over broad rewrites.
- Keep UI in `src/`. Preserve `.openai/hosting.json`, `worker/index.js`, `scripts/prepare-sites-build.mjs` and `tests/sites-worker.test.mjs`. Start previews yourself when needed.
- Run relevant checks and verify real desktop/browser behavior. A successful build or unit test does not establish routing, authentication or release acceptance. Distinguish measured behavior, known failures and untested coverage.
- Use disposable test data. Never operate unrelated applications, personal browsers or extensions, terminate user sessions, or change host settings to make a test pass. Clean only owned resources.
- Virtual machines are outside the current product scope. Do not start a VM, buy signing credentials or enroll a developer account without an explicit request. Authorization uses the OS prompt; never collect administrator passwords.

## Interface

- Preserve the dark three-column workspace. Navigation order: Environment, Network egress, Browser, Terminal, Attached applications, Runtime monitor. Settings stays at the bottom.
- Keep primary actions concise and unique. Put detailed network, fingerprint and diagnostic controls under Advanced or collapsible sections.
- Support Simplified Chinese, Traditional Chinese, English, Japanese, Korean, Spanish, French, German and Brazilian Portuguese. First launch recommends the system language and asks for confirmation. Preserve saved language choices.
- Interface language is separate from browser locale. Never apply environment locale/timezone changes to the host.
- Establish a current Product Design reference before a substantial redesign. A selected mockup defines layout, density, spacing and visual hierarchy.

## Network and browsers

- Confirm network context when creating or updating an environment: configure proxy, measure authenticated egress, recommend IP-region/timezone, then confirm or choose a manual location. Google Maps may assist selection. Consumers reuse this saved context; preserve older configurations until explicitly updated.
- Keep measured egress separate from simulated location. A proxy entry address is not egress evidence. GeoIP estimates a region; a map coordinate does not prove a residential IP or address.
- AnyTLS uses an application-owned bundled core, without an external Clash prerequisite. Preserve SNI, ALPN, TLS fingerprint and UDP settings; verify certificates by default.
- Managed browser, terminal and application traffic must use its selected route, including REST/MCP callers. Never silently fall back to direct traffic. Scope listeners and credentials to owned processes; do not persist runtime listener credentials in browser profiles or exports.
- Let the selected provider manage automatic fingerprints. Keep explicit device overrides under Advanced; preserve saved seeds and settings. Only describe behavior verified against the actual engine. A browser profile is not native hardware virtualization.
- On 2026-10-16 the user required CloakBrowser, Camoufox and BrowseForge Chromium to generate a mutually consistent random fingerprint once for each new environment and persist it. Reopening keeps that identity; cloning creates a new identity, while importing preserves the exported identity. Never implicitly reshuffle existing fixed, custom or imported configurations.
- Tracker protection requires auditable rules and supported controls. Do not claim it removes all tracking, encrypted telemetry or service-side account checks.

## Terminals and Claude Code

- New terminals choose network, link browser and working directory. Directory selection uses main-process authority, not renderer paths. Keep configuration and history separate per environment.
- Support a resizable collapsible panel, workspace expansion and an independent window. Duplication creates an independent idle process with the same context, not replayed commands or process state. Closing a view retains its session; ending a session ends its process.
- A macOS terminal using a managed loopback route must use the existing Seatbelt network fence. Unsupported clients fail rather than connect directly. Remote HTTP(S) upstreams and other platforms are not fenced without an implemented and verified boundary.
- Dedicated Claude sessions remain within the terminal workflow. Start at a shell prompt and invoke the unchanged official CLI only when the user enters `claude`. Keep model, resume and permission arguments under user control; never enable permission bypass automatically.
- Each environment owns its native Claude installation. Reuse a valid installation; otherwise default to download through its route or offer copying a supported local native program. Copy no host credentials and never fall back silently to a host executable.
- Verify official downloads before atomic installation. Cancellation and failures preserve account data. Manual updates affect the next invocation in that environment, never the host installation. Background updates remain disabled.
- Named login profiles are separate directories within an environment. Show names, not inferred authentication state. Duplication preserves the chosen profile; environments do not share profiles.
- Pin the selected environment browser for each dedicated session and duplicate. Use a session-scoped MCP broker; keep the broad backend token and raw browser endpoint in the main process. Missing, changed or unverified routes fail closed.
- Device-identifier restrictions cover tested interfaces in dedicated Claude process trees. They do not create replacement hardware, a virtual Mac or complete anonymity. Never modify the official CLI, expose actual identifiers in diagnostics or change host settings.

## Attached applications

- One software identity binds to one environment and has one managed instance. Detect an existing original or managed instance before launch and explain that it must be closed. Never terminate, adopt or relabel an unrelated user session.
- Attach flow: choose network group, local application from a searchable list, then link browser. Derive compatibility from the signed engine and revalidate the bound target at launch. Reject unsupported software before activation.
- Scope UserData, Home, Cache, Temp and Extensions per environment/application, including VS Code shared-data and extension directories. Preserve existing sign-in data.
- Require a real routing adapter: macOS PF/process-group/owned-utun or the separate signed Network Extension path; Windows original signed WinDivert x64 dependency with Envara capture DLL/guard. An ARM64 helper build is not ARM64 capture support.
- Read-only status/setup inspection must not install, enable PF, change routing/DNS or launch applications. Installation and activation are explicit operations. Preserve unrelated traffic and host network configuration.
- Keep pinned resources, manifests and known prior installation snapshots consistent. They are trust and upgrade inputs. Never patch/re-sign upstream supplied drivers or overwrite an unrelated third-party installation.
- Preserve DNS, child-process attribution, inherited-descriptor, IPv6, whole-guard-failure and unaffected-application checks. Proxy environment variables alone do not establish routing.
- Chromium/Electron applications use the supported outer Seatbelt profile with `--no-sandbox`; disclose the internal sandbox trade-off. Scoped data is not a separate macOS user, Keychain, hardware identity or system location service.
- Start launches inside the environment; Stop ends the managed process family. Closing a window does not end the run. Support reopening a running window. Network changes require confirmed cleanup before restarting.
- Reuse authorization across sequential applications. Refusal before resource creation is not uncertain cleanup. Preserve first operation failure separately from cleanup failures, including retained diagnostic history.
- Natural application exit ends observation. A revoked keeper may answer cleanup with its buffered stop frame, never renewed launch authority. Malformed channels and uncertain kernel state remain fail closed.
- Stop, unbind and quit preserve sign-in data. Delete it only on explicit request or environment deletion. Never prune offline content as generic cache. Reclaim only named regenerable caches and confirmed-unused sealed copies.

## Links, data and privacy

- Default managed links to the environment's own browser; allow another saved browser on the same network. Missing selections fall back to the environment's browser. The system browser is an explicit outside-environment choice and must be described as such.
- Terminal shims use private authenticated IPC and never open a host browser after refusal. System link routing requires macOS confirmation of the reversible default-browser change. Unrelated links retain the previous default browser without environment notifications.
- Preserve the previous-browser record when retaining/resetting application data; restore the default before removing that record while the router is active.
- Export a selected browser, terminal or application from its focused page, encrypted with a user password. Terminal exports contain only the chosen Claude profile and shared shell configuration/history. Keep older bundled imports compatible.
- Exclude host credentials, Keychain entries, programs, caches and temporary files. Preserve relevant offline browser/application data. Import into a new environment, never merge over unrelated existing data.
- Copied data does not guarantee cross-machine sign-in or Keychain portability. Never expose node passwords, tokens, private endpoints or device identifiers in public logs, examples or screenshots. Account isolation does not guarantee avoidance of service restrictions.

## Validation and publication

- Keep source free of developer-specific paths, personal configuration, incident diaries and generated artifacts. Use synthetic fixtures and portable commands. Preserve copyright, licenses, attribution and corresponding-source obligations.
- Before packaging, run `npm test`, `npm run build`, `npm run test:sites` and relevant backend/native checks. Preserve `dist/client/index.html`, `dist/server/index.js` and `dist/.openai/hosting.json`.
- Verify the exact package, clean first launch, owned-process cleanup and affected real workflows. Keep interactive authorization and unverified platform coverage explicit.
- Publish only on an explicit maintainer request, using a reviewed source commit and verified local artifacts. Automatic GitHub compilation/release workflows stay removed or disabled; source pushes must not trigger packaging.
- Donation support is voluntary. Do not invent or activate a funding destination without a real public destination supplied by the maintainer.
