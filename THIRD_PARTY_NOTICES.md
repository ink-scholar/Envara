# Third-party notices

Envara's original application code is licensed under the MIT License. Third-party software retains its own copyright and license. JavaScript versions are recorded in `package-lock.json`; the vendored Go backend and its dependencies are pinned in `third_party/browseforge/ENVARA_UPSTREAM.md`, `go.mod`, and `go.sum`. This document describes local development candidates; public releases are paused.

## Main dependencies

| Component | License | Copyright / source |
| --- | --- | --- |
| Electron | MIT | Electron contributors; 2013–2020 GitHub Inc. · [source](https://github.com/electron/electron) |
| React and React DOM | MIT | Meta Platforms, Inc. and affiliates · [source](https://github.com/facebook/react) |
| Vite | MIT | 2019–present VoidZero Inc. and Vite contributors · [source](https://github.com/vitejs/vite) |
| @vitejs/plugin-react | MIT | 2019–present Yuxi (Evan) You and Vite contributors · [source](https://github.com/vitejs/vite-plugin-react) |
| Phosphor Icons | MIT | 2020 Phosphor Icons · [source](https://github.com/phosphor-icons/react) |
| BrowseForge vendored backend | MIT | 2026 BrowseForge contributors · [preserved license](third_party/browseforge/LICENSE) |
| Mihomo v1.19.32 proxy core | GPLv3 | Upstream authors and contributors · [preserved license](third_party/proxy-core/LICENSE) · [fixed source record](third_party/proxy-core/SOURCE.md) |
| WinDivert 2.2.2-A x64 DLL / original signed driver | LGPLv3 / GPLv2 upstream choice | Basil and contributors · [retained full license](native/windows-app-routing/capture/vendor/WinDivert-LICENSE) · [pinned preparation](scripts/prepare-windivert.mjs) |
| ProxyBridge TCP NAT technique | MIT | 2025 Anof-cyber/InterceptSuite · [retained license](native/windows-app-routing/capture/LICENSE) · [fixed source attribution](native/windows-app-routing/capture/PROVENANCE.md) |
| Playwright Go binding | MIT | 2020 Max Schmitt · [license](https://github.com/mxschmitt/playwright-go/blob/main/LICENSE) |
| CloakBrowser JavaScript wrapper | MIT | 2026 CloakHQ · [license](https://github.com/CloakHQ/CloakBrowser/blob/main/LICENSE) |
| Playwright client and official driver | Apache-2.0 | Microsoft Corporation · [license](https://github.com/microsoft/playwright/blob/main/LICENSE) |
| electron-builder | MIT | 2015 Loopline Systems · [source](https://github.com/electron-userland/electron-builder) |
| node-pty 1.1.0 | MIT | 2012–2015 Christopher Jeffrey · [source](https://github.com/microsoft/node-pty/tree/v1.1.0) |
| @xterm/xterm 6.0.0 | MIT | xterm.js authors; SourceLair; Christopher Jeffrey · [source](https://github.com/xtermjs/xterm.js) |
| @xterm/addon-fit 0.11.0 | MIT | 2019 xterm.js authors · [source](https://github.com/xtermjs/xterm.js/tree/master/addons/addon-fit) |
| socks 2.8.10 | MIT | 2013 Josh Glazebrook · [source](https://github.com/JoshGlazebrook/socks) |
| https-proxy-agent 9.1.0 / socks-proxy-agent 10.1.0 | MIT | 2013 Nathan Rajlich · [source](https://github.com/TooTallNate/proxy-agents) |
| ipaddr.js 2.5.0 | MIT | 2011–2017 whitequark · [source](https://github.com/whitequark/ipaddr.js) |

Electron includes Chromium, Node.js and additional components with their own licenses. The Electron runtime distribution includes its `LICENSE` and `LICENSES.chromium.html` notices. Transitive dependencies and build tools may carry additional licenses; their notices are retained in their distributions.

## Vendored backend and prepared resources

BrowseForge v2.1.15 is incorporated at commit `fa9e0bb670e749706a9c8f2d4095333347d6c521`. Its original MIT copyright and license are preserved under `third_party/browseforge/`. Envara applies local desktop lifecycle, manual identity, and integration patches. The source baseline is recorded in [ENVARA_UPSTREAM.md](third_party/browseforge/ENVARA_UPSTREAM.md).

The prepared backend resources include a compiled Go sidecar, the official Playwright driver 1.61.1 and its Node.js runtime. The Go standard library uses the Go project's BSD-style license; Node.js carries its own MIT and third-party notices. The resource builders retain the Go runtime and module licenses in `build/backend/licenses/`, and the driver, binding, Node and bundled dependency notices beside the prepared driver. Build provenance records exact versions and checksums. These generated resources are excluded from the source repository and are separate from browser-engine binaries.

## Separately managed Mihomo proxy core

Envara 0.4.0 prepares the unmodified official Mihomo v1.19.32 executable at commit `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`, launched as an independent owned process. Its GPLv3 license and the licenses of its dependencies are retained; Envara's original application MIT notice does not replace them.

`build/proxy-core/` contains the executable, complete `LICENSE`, `SOURCE.md`, `provenance.json` and `mihomo-corresponding-source.tar.gz`. The latter contains the fixed full upstream source, original build scripts/copyright notices, checksum-verified Go `vendor/` dependencies and the release CA input. Its SHA-256 is `6859f30fa7ef47eea24a535e52711d91026adeac905768443aaf1d6f5955dddb`. An Envara helper has successfully built those sources with `GOPROXY=off` and `-mod=vendor`; it does not promise byte-identical release reproduction. Distribution retains this complete directory beside the core under `proxy-core/`; the actual local 0.4.0 package copy is verified separately in the verification record.

The source baseline, official archive/executable checksums and build details are recorded in [third_party/proxy-core/SOURCE.md](third_party/proxy-core/SOURCE.md) and generated provenance. No upstream source patches are applied to the supplied executable. These records describe component attribution and prepared distribution contents, not a legal conclusion about the combined application.

## Terminal and proxy dependency notices

The Windows routing component build preserves WinDivert's unmodified x64 DLL and signed driver at commit `1789526ecfb9ff5397c94f9f54c1a3dc2fb60440`, the complete pinned corresponding source archive, original license and artifact hashes. It dynamically loads the DLL without changing the driver signature. Envara's user-mode capture source and Go guard service are separate components; ProxyBridge's MIT address-swap technique retains its attribution. See [Windows source and acceptance boundary](native/windows-app-routing/README.md). No routing component has been installed or accepted on Windows during this Mac-hosted build. The ARM64 helper does not include or claim an ARM64 driver.

The native preparation step retains complete notices for the terminal renderer, node-pty and proxy dependencies in `build/native/licenses/`, with a manifest; application resources include them under `licenses/npm/`. The whole node-pty package is unpacked to preserve native modules and platform helpers. winpty and Microsoft Terminal ConPTY notices are retained separately. Development-only @electron/rebuild 4.2.1 is MIT and is not installed by the running application.

[third_party/npm-licenses/README.md](third_party/npm-licenses/README.md) records exact versions, official sources and two supplementary notices. The Microsoft Terminal notice comes from its official MIT license. The proxy-agent-negotiate notice explicitly records the npm tarball's missing standalone license, retaining the declared MIT attribution and the same maintainer's distributed MIT text; it is an Envara supplement, not a claimed file from that tarball. Optional Kerberos support is not installed or used by Envara's explicit Basic authentication path.

### MIT notice for the MIT components above

The copyrights listed above apply to their respective components.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Separately downloaded browser runtimes

The compiled CloakBrowser Chromium binary is **not included** in the Envara source tree or application installers. An end user initiates its download from official CloakHQ distribution channels within the application settings.

The wrapper's MIT license does not apply to that binary. It is governed by [CloakBrowser Binary License v1.3, July 2026](https://github.com/CloakHQ/CloakBrowser/blob/main/BINARY-LICENSE.md), including restrictions on redistribution and third-party hosted browser access. Version access can require an upstream subscription. The official license, as applicable to the version obtained, is authoritative; Envara does not grant an additional license to the binary.

The multi-engine catalog also includes Camoufox and BrowseForge Chromium Alpha. Camoufox source is under [MPL-2.0](https://github.com/daijro/camoufox/blob/main/LICENSE); the BrowseForge Chromium runtime repository uses [Apache-2.0](https://github.com/nczz/browseforge-runtime-chromium/blob/92cfe89356ef0e7fb22979f5ee8d95a0a832d69b/LICENSE), with Chromium and other upstream components retaining their own notices. Their browser binaries are obtained through the respective official channels, not redistributed by Envara. Catalog integration does not mean a binary has been installed or accepted on every platform; current evidence is recorded in the [capability matrix](docs/capability-matrix.md).

## Design references and assets

[BrowseForge](https://github.com/nczz/BrowseForge) began as a product reference and is now the pinned local backend. Envara supplies its desktop interface, terminal workspace and integration layer while retaining the vendored source's attribution and license.

`build/icon.png` was generated with OpenAI's built-in image generation tool for Envara. It contains no third-party browser logo or supplied reference artwork.
