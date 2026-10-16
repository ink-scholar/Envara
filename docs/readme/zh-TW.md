<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>多個環境，一個工作台。</strong><br />整合瀏覽器、終端與網路環境的本機工作區。</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="原創程式碼授權：MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-0.5.23-475569" alt="Envara 0.5.23" /></a>
  <a href="en.md"><img src="https://img.shields.io/badge/README-9_languages-6366f1" alt="9 種 README 語言" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <strong>繁體中文</strong> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">下載 macOS 版</a> · <a href="../capability-matrix.md">功能與邊界</a> · <a href="../../CONTRIBUTING.md">參與貢獻</a> · <a href="../SUPPORT.md">支持專案</a>
</p>

![Envara 中文原生工作區](../media/workspace-zh-CN.png)

<p align="center"><sub>原生 Electron 工作區，截圖使用合成範例資料。</sub></p>

## 一個環境，一套工作脈絡

Envara 把瀏覽器、網路出口、工作目錄和命令列工具放在同一個本機工作台。每個環境保留自己的瀏覽資料、工具設定與歷史；不同環境可以選擇不同網路。

| 工作區 | 功能 |
| --- | --- |
| 環境 | 建立、複製、分組與搜尋，儲存工作目錄和網路環境 |
| 網路出口 | HTTP、HTTPS、SOCKS5 和內建 AnyTLS，偵測實際出口、概略地區與時區 |
| 瀏覽器 | CloakBrowser / Chromium、Camoufox / Firefox、實驗性的 BrowseForge Chromium；自動設定與進階設定 |
| 終端 | 真實 PTY、目錄選擇、多工作階段、可調整大小的面板與獨立視窗 |
| Claude Code | 每個環境獨立的官方 CLI 安裝、具名登入檔案、綁定環境瀏覽器的 MCP 工具 |
| 附加軟體 | 將支援的 Chromium/Electron 應用程式綁定到環境，管理執行個體與獨立應用資料 |
| 資料移轉 | 分別匯出瀏覽器、選定終端登入檔案或附加應用資料，並以密碼加密 |

內建 AnyTLS 核心由 Envara 管理，無需另外設定 Clash。瀏覽器、終端與附加軟體沿用已確認的網路位置與時區。位置設定不會修改系統時區；IP 定位僅表示大致地區。

複製終端會建立新的獨立程序，不會重播命令。Claude Code 工作階段先進入 shell，由你輸入 `claude`；可下載獨立的官方安裝，或使用現有本機原生程式初始化。Envara 不修改官方 CLI、不複製主機帳號，也不預設啟用權限略過。[了解 Claude Code 工作階段](../claude-code-sessions.md)。

附加軟體啟動前會檢查相容性、現有執行個體與路由元件狀態。不符合條件時會明確拒絕啟動。停止、移除綁定及退出 Envara 都會保留登入資料；只有明確刪除登入資料或環境時才會清除。詳見[附加軟體](../application-routing-options.md)。

## 下載與安裝

從 [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest) 下載 **macOS Apple Silicon（arm64）** 的 DMG 或 ZIP。開啟 DMG 後，將 Envara 拖入「應用程式」。校驗檔與版本說明隨 Release 提供。

**目前 macOS 成品未使用 Apple Developer ID 簽章，也未經公證。** 首次開啟可能受到 macOS 安全檢查；請確認下載來自本儲存庫並核對校驗值。Envara 不會自動關閉系統安全檢查。附加軟體的系統路由元件需要另外取得管理員授權，啟動瀏覽器或一般工作區不會自動安裝它。

| 平台 | 發布範圍 |
| --- | --- |
| macOS Apple Silicon | 本次提供 DMG、ZIP 與 SHA-256 校驗檔 |
| macOS Intel | 保留原始碼路徑，未提供已驗證成品 |
| Windows / Linux | 保留相關原始碼；本次不發布成品，實機驗證範圍請見功能矩陣 |

瀏覽器核心由使用者透過應用程式內的入口安裝，適用各自授權。應用程式內含桌面執行所需相依元件，無需另外安裝 Node.js 或 Go。

## 選擇介面語言

支援 **简体中文、繁體中文、English、日本語、한국어、Español、Français、Deutsch、Português (Brasil)**。首次啟動會推薦系統語言並由你確認，之後可在設定中切換。

![首次啟動語言選擇](../media/first-launch.png)

<p align="center"><sub>原生首次啟動語言選擇介面。</sub></p>

介面語言與瀏覽器環境語言分開，切換選單語言不會修改既有網路、時區或工作目錄。

## 能力邊界

- 設定與資料隔離並不提供獨立的作業系統使用者、Keychain 或虛擬硬體。瀏覽器指紋設定不會改變原生應用程式的硬體身分。
- 支援的 macOS 終端路由使用網路圍欄；尚未具備此邊界的平台和路由不能視為強制隔離。詳細範圍請見[功能矩陣](../capability-matrix.md)。
- 附加應用程式使用外層網路圍欄時，Chromium/Electron 的內部沙箱會關閉。原生元件狀態、支援引擎與實際驗證範圍分別說明，不把「可識別」當作「所有軟體均已驗證」。
- 匯出不含 Keychain、程式本體、快取或暫存檔。換機後部分帳號仍需重新登入；同機還原成功不保證跨機器登入有效。
- 追蹤攔截僅涵蓋已實作規則與核心支援的控制。網路、帳號與設定隔離不保證避免服務限制，也不會消除所有追蹤。

[驗證說明](../verification.md) · [架構](../architecture.md) · [網路環境](../network-context.md) · [瀏覽器裝置與語言](../browser-device-profiles.md)

## 從原始碼開發

需要 Node.js 24 LTS（或 22.12+）、npm、Go 1.25，以及目標平台的編譯工具。macOS 原生元件需要 Xcode Command Line Tools。

```bash
npm ci
npm run desktop
```

首次準備會下載固定版本的建置相依套件。開發預覽與檢查：

```bash
npm run dev
npm test
npm run build
npm run test:sites
```

Web 預覽僅用於介面開發；真實瀏覽器、PTY 和系統路由需要桌面應用程式。建置與發布說明請見[貢獻指南](../../CONTRIBUTING.md)與[發布流程](../releasing.md)。GitHub 自動編譯和發布工作流程維持停用，推送原始碼不會觸發建置。

## 開源與支持

Envara 原創程式碼採用 [MIT](../../LICENSE)。BrowseForge 保留其 [MIT 授權](../../third_party/browseforge/LICENSE)及[固定版本紀錄](../../third_party/browseforge/ENVARA_UPSTREAM.md)。獨立 Mihomo 核心保留 [GPLv3](../../third_party/proxy-core/LICENSE)及[對應原始碼](../../third_party/proxy-core/SOURCE.md)。瀏覽器二進位檔適用各自授權，不包含在應用程式的 MIT 授權內。完整歸屬請見[第三方聲明](../../THIRD_PARTY_NOTICES.md)。

歡迎[回報問題](https://github.com/ink-scholar/Envara/issues)、提交程式碼、改進翻譯或 Star。支持均為自願；捐贈管道尚未啟用。[支持專案](../SUPPORT.md)
