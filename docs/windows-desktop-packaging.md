# Windows x64 desktop packaging

Envara 0.5.25 targets macOS arm64 artifacts. Windows x64 has a development packaging path, **not completed native acceptance or a supported Windows release**. No VM is required or started by these preparation commands.

## Commands

On a Windows build host, `npm run dist:win` prepares host-native resources and runs electron-builder. Running that command on macOS does not turn the previously prepared Mac resources into Windows resources.

For an isolated cross-host preparation:

```sh
node scripts/prepare-windows-desktop.mjs --build
```

Omit `--build` to prepare without building an installer. Output is a disposable staged project under the ignored `.cache/windows-desktop/` directory, separate from existing platform resources. The stage's `preparation.json` records exact builder inputs/arguments and disables automatic publication.

Recheck a stage without installing it:

```sh
node scripts/prepare-windows-desktop.mjs --verify /path/to/prepared-stage
```

Preparation downloads pinned build dependencies and compiles helpers. It does not install or activate a driver, system service, certificate or application.

## Target resources

The [preparation script](../scripts/prepare-windows-desktop.mjs) selects Windows x64 resources explicitly:

- Pinned Go toolchain and a `GOOS=windows GOARCH=amd64 CGO_ENABLED=0` BrowseForge build.
- Matching Playwright driver and official Windows Node archive, with integrity checks.
- Official Windows Electron archive selected through `electronDist`, not the host distribution.
- Original npm node-pty Windows N-API prebuilds, ConPTY components and worker layout, excluding host build overrides.
- Unmodified Windows Mihomo plus its license, provenance and corresponding-source bundle.
- Original signed WinDivert x64 dependency, Envara capture DLL and Go helper with their manifests and licenses.

Versions and digests live in the [driver preparation](../scripts/prepare-playwright-driver.mjs), [sidecar build](../scripts/build-sidecar.mjs), [proxy preparation](../scripts/prepare-proxy-core.mjs) and [WinDivert preparation](../scripts/prepare-windivert.mjs) sources. An ARM64 helper cross-build is not ARM64 capture support.

The cross-host candidate disables Envara signing and branding-resource editing. Electron branding can remain in embedded executable metadata; the original signed WinDivert driver is never patched or re-signed. This path does not produce a signed Windows release.

## Verification boundary

The verifier checks staged and packaged inventories/hashes, owned ASAR contents, unpacked PTY resources and PE x64 architecture. Wrong-platform resources are rejected. These are package checks, not proof that Windows loaded a native module or routed traffic.

Native acceptance still requires installer/uninstaller behavior, GUI startup, browser launch, PTY input/resize/duplicate/cleanup, authenticated AnyTLS traffic, driver trust/loading, DNS attribution, guard failure behavior and unaffected applications. The native adapter stays unavailable/fail-closed where those gates are incomplete. Cross-compilation, Wine and VM results cannot replace the missing host acceptance.

See [Windows routing](../native/windows-app-routing/README.md), [installer contract](../native/windows-app-routing/installer/README.md), [source checks](../scripts/test-windows-app-routing.mjs) and [capability matrix](capability-matrix.md). Preserve third-party licenses and corresponding-source obligations when distributing any candidate.
