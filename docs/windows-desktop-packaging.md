# Windows x64 desktop packaging

The current `npm run dist:win` is intended for a Windows runner. On a Mac its
host-native preparation selects Mac PTY, BrowseForge/Playwright Node and Mihomo
resources before `electron-builder --win` runs. Passing `--win` to the final
builder does not replace those resources. Do not treat that command as a valid
cross-host Windows build.

The separate preparation command creates a fresh isolated project under
`.cache/windows-desktop/run-*/project` and keeps existing Mac build outputs,
release artifacts and configuration intact:

```sh
node scripts/prepare-windows-desktop.mjs --build
```

Omit `--build` to prepare the complete Windows target without running the
installer builder. The generated `preparation.json` contains the exact builder
executable/arguments for that isolated stage. Publication is always `never`.
This operation creates files and compiles helpers only. It does not install or
activate any driver, system service, certificate or application.

An existing candidate can be rechecked without rebuilding or installing it:

```sh
node scripts/prepare-windows-desktop.mjs --verify /absolute/path/to/.cache/windows-desktop/run-directory
```

The script builds a fresh frontend from the isolated source snapshot and
cross-compiles BrowseForge with the pinned Go 1.25.0 toolchain,
`GOOS=windows GOARCH=amd64 CGO_ENABLED=0`. It prepares Playwright 1.61.1 with
Windows Node 24.18.0 from the original checksum-verified Node ZIP and the pinned
Playwright npm integrity. It uses the unmodified official Windows Mihomo
v1.19.32 x64 release, with GPL license, fixed-source/vendor archive and its
actual embedded CA build input. Windows routing is built inside the stage using
the existing pinned WinDivert preparation script. Only the x64 routing bundle
is packaged; an ARM64 helper does not imply ARM64 capture support.

`node-pty@1.1.0` is extracted from the original npm archive after its lockfile
SRI verification. Its Windows x64 N-API prebuilds, DLLs, ConPTY host and full
JavaScript worker layout are kept. Other platform prebuilds and host
`build/Release`/`build/Debug` overrides are excluded. This avoids a Mac source
rebuild deleting or replacing the Windows native files.

Fixed official Electron v44.6.0 Windows x64 archive SHA-256:
`04d6071f8deca081044e1398f96f65e4c1550ffdb3f882504cd78528d821d422`.
[Official release](https://github.com/electron/electron/releases/tag/v44.6.0)
provides that digest. A copy of the official Electron distribution is selected
explicitly with `electronDist`, so the builder cannot reuse the installed Mac
Electron distribution.

The cross-host local candidate disables branding resource editing and Envara
code signing. The original Electron distribution is used; electron-builder
adds its expected ASAR-integrity resource to `Envara.exe`. The verifier
reconstructs that exact update and compares the complete executable hash.
Embedded executable icon/version/copyright may still identify Electron.
The installer and application window use Envara's project
identity. This is an unsigned local candidate, not a signed Windows release.
The unmodified signed WinDivert driver is never patched or re-signed.

After packaging, `verification.json` compares complete resource inventories
and file hashes with the isolated Windows stage; checks owned Electron/frontend
files in ASAR; verifies all seven PTY native files in ASAR unpacked storage; and
checks PE x64 architecture for Electron, backend, Node and Mihomo. No Mac
sidecar, Node or Mihomo executable is accepted in the Windows resource folders.
All license/source bundles remain included.

These checks are **preparation and package checks**, not Windows runtime
acceptance. Windows installer execution/uninstall, Electron GUI, actual browser
launch, terminal input/output/resize/duplicate/cleanup, AnyTLS traffic, driver
trust/loading, DNS attribution, guard crash protection and unaffected-application
behavior remain separate native gates. Building an installer or running Wine
does not satisfy those gates. The app must retain unavailable/fail-closed
status whenever the real platform adapter is absent or unverified.

## Local build evidence, 2026-10-08

An end-to-end run of `node scripts/prepare-windows-desktop.mjs --build` completed
on the Mac arm64 host for Envara 0.5.0. Its owned source snapshot, official
artifact digests and build information are recorded in
`.cache/windows-desktop/run-2026-10-07T16-03-16-317Z-bfd57db5/preparation.json`.
The corresponding `verification.json` passed the comparison of 158 resource
files, owned ASAR files and the seven Windows PTY native files. Five additional
PE target checks confirmed that wrong-architecture, malformed, missing-N-API
and the existing Mac sidecar inputs are rejected.

The local NSIS candidate is
`release/Envara-0.5.0-win-x64.exe` under that run directory, 184,136,914 bytes,
SHA-256 `a15a28081034e10f0eb42ba47e568d9583e9d0c22c1def7f3f37ea3a14825e9a`.
It has not been installed or run on Windows, and it has not been published.
Its embedded program is Windows x64; the NSIS bootstrapper itself may be x86.
