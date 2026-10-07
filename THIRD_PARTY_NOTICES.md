# Third-party notices

Envara's original application code is licensed under the MIT License. Third-party software retains its own copyright and license. Versions used for a particular build are recorded in `package-lock.json`.

## Main dependencies

| Component | License | Copyright / source |
| --- | --- | --- |
| Electron | MIT | Electron contributors; 2013–2020 GitHub Inc. · [source](https://github.com/electron/electron) |
| React and React DOM | MIT | Meta Platforms, Inc. and affiliates · [source](https://github.com/facebook/react) |
| Vite | MIT | 2019–present VoidZero Inc. and Vite contributors · [source](https://github.com/vitejs/vite) |
| @vitejs/plugin-react | MIT | 2019–present Yuxi (Evan) You and Vite contributors · [source](https://github.com/vitejs/vite-plugin-react) |
| Phosphor Icons | MIT | 2020 Phosphor Icons · [source](https://github.com/phosphor-icons/react) |
| CloakBrowser JavaScript wrapper | MIT | 2026 CloakHQ · [license](https://github.com/CloakHQ/CloakBrowser/blob/main/LICENSE) |
| Playwright | Apache-2.0 | Microsoft Corporation · [license](https://github.com/microsoft/playwright/blob/main/LICENSE) |
| electron-builder | MIT | 2015 Loopline Systems · [source](https://github.com/electron-userland/electron-builder) |

Electron includes Chromium, Node.js and additional components with their own licenses. The Electron runtime distribution includes its `LICENSE` and `LICENSES.chromium.html` notices. Transitive dependencies and build tools may carry additional licenses; their notices are retained in their distributions.

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

## Separately downloaded browser runtime

The compiled CloakBrowser Chromium binary is **not included** in the Envara source tree or application installers. An end user initiates its download from official CloakHQ distribution channels within the application settings.

The wrapper's MIT license does not apply to that binary. It is governed by [CloakBrowser Binary License v1.3, July 2026](https://github.com/CloakHQ/CloakBrowser/blob/main/BINARY-LICENSE.md), including restrictions on redistribution and third-party hosted browser access. Version access can require an upstream subscription. The official license, as applicable to the version obtained, is authoritative; Envara does not grant an additional license to the binary.

## Design references and assets

[BrowseForge](https://github.com/nczz/BrowseForge) was a product-direction reference. Envara is a separate implementation; no BrowseForge source is incorporated in this initial release.

`build/icon.png` was generated with OpenAI's built-in image generation tool for Envara. It contains no third-party browser logo or supplied reference artwork.
