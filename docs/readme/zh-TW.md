<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>讓每一套工作，都有獨立的境艙。</strong><br />One environment. Your browser, terminal and apps.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="原創程式碼授權：MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-1.2.0-475569" alt="Envara 1.2.0" /></a>
  <a href="en.md"><img src="https://img.shields.io/badge/README-9_languages-6366f1" alt="9 種 README 語言" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <strong>繁體中文</strong> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">下載 macOS 1.2.0</a> · <a href="../capability-matrix.md">功能與邊界</a> · <a href="../../CONTRIBUTING.md">參與貢獻</a> · <a href="../SUPPORT.md">支持專案</a>
</p>

**開啟瀏覽器、執行命令、連接桌面應用程式，讓同一套工作環境串起整個流程。**

境艙是開源的本機桌面工作台，將網路出口、瀏覽器設定檔、終端工具與支援的桌面應用程式整合在一起。每個環境保存自己的設定與資料，你可以為不同專案、帳號或地區建立不同的工作脈絡，在同一個介面中管理。

![Envara 中文原生工作區](../media/workspace-zh-CN.png)

## 1.2.0：修正 macOS Keychain 相容性

- **補齊環境內的鑰匙圈選擇**：修正獨立 HOME 缺少預設鑰匙圈選擇時的憑證儲存相容問題；僅在建立 Claude 終端時準備環境內的選擇中繼資料。
- **沿用選定的登入設定檔**：重新開啟已儲存終端或複製工作階段時，保留所選設定檔；鑰匙圈無法使用時說明原因並保留既有資料。
- **保留既有工作區**：環境、網路、瀏覽器、終端設定與登入資料繼續保留；鑰匙圈準備不讀取或移轉主機憑證，也不變更主機的預設鑰匙圈與搜尋列表。

合成憑證情境已驗證；真實 Claude OAuth 登入及重新開啟後的帳號狀態仍未驗收，詳見[驗證範圍](../verification.md#120-验证范围)。

<p align="center"><sub>原生 Electron 工作區，截圖使用合成範例資料。</sub></p>

## 境艙的特色：把整條工作流程串起來

在瀏覽器查資料、在終端寫程式、在桌面應用程式處理工作，這些動作往往都屬於同一個專案。境艙讓它們沿用同一套已確認的網路環境，同時分別保留需要延續的瀏覽資料、工具設定與應用程式資料。

**選好一次網路，接上需要的工具，下次回來繼續工作。** 這就是境艙的核心：讓獨立環境成為日常工作的方式。

### 🌐 每個環境，都有自己的瀏覽器

在 **CloakBrowser / Chromium、Camoufox / Firefox** 與實驗性的 **BrowseForge Chromium** 之間選擇。獨立瀏覽資料、持續保留的工作階段、環境分組、搜尋與設定複製，讓不同的工作脈絡各就各位。複製設定會建立新環境，原有登入資料仍留在原環境。

指紋設定預設由所選核心管理，也提供進階裝置、語言與時區設定；搭配可稽核的追蹤攔截規則，讓隱私控制有據可查。實際支援範圍依核心而異。[瀏覽器與裝置設定](../browser-device-profiles.md)

### 🧭 網路、位置與時區，設定一次，持續沿用

支援 **HTTP、HTTPS、SOCKS5 和 AnyTLS**。AnyTLS 使用隨應用程式提供、由境艙管理的代理核心，無需另外設定 Clash。

建立網路環境時，先偵測**實際通過驗證的網路出口**，再確認地區與時區；瀏覽器、終端與支援的附加應用程式都沿用這套設定。需要模擬位置時，可透過 Google Maps 選擇座標，測得的出口與模擬位置會分別顯示。環境設定不會修改主機的系統時區。[網路環境](../network-context.md)

### ⌨️ 終端，也有自己的工作環境

建立工作階段時，選擇**網路、開啟連結用的瀏覽器與專案資料夾**，設定與歷史紀錄依環境保存。真實 PTY、多工作階段、拖曳調整高度、展開工作區、獨立視窗，讓命令列成為工作台中順手的一部分。

macOS 的[受控 SSH 連線](../claude-code-sessions.md)對已儲存的主機與連接埠組合使用本機目前的網路出口（包括既有系統 VPN/TUN），遠端可見該出口 IP；未儲存的組合可用 `ssh user@host` 經境艙代理連線。已儲存連線尚未授權時會拒絕，不會改走代理；私鑰保留在本機。1.1.0 的新建終端使用這些路線；既有工作階段保留原本的設定。

複製終端會在同一套環境設定中開啟新的閒置程序；關閉面板後，仍能回來繼續使用。支援的 macOS 受管回環路由使用網路圍欄，不支援代理的程式會連線失敗，避免悄悄改走直連。專案資料夾仍在原來的位置，方便繼續使用你熟悉的工具鏈。

### 🧩 讓桌面應用程式加入同一套工作流程

為支援的 **Chromium / Electron 應用程式**選擇環境與開啟連結用的瀏覽器，統一管理啟動、停止及應用程式資料。境艙會檢查目標身分、相容性、既有執行個體與原生路由元件，符合條件後才允許啟動。

停止、解除綁定或退出境艙，都會保留登入與離線資料，方便下次接著使用；需要清理時，再明確選擇刪除。原生路由需要系統授權，支援某個引擎不代表所有應用程式都已完成驗證。[附加軟體的支援範圍](../application-routing-options.md)

### 🔗 從命令列到登入頁面，延續同一套環境

為環境指定開啟連結用的瀏覽器，讓終端開啟的網頁進入對應環境；macOS 系統連結路由也能處理受管應用程式交給系統的連結。與環境無關的連結，仍交給原本的預設瀏覽器。

系統連結路由需要你在 macOS 對話框中確認，並可隨時關閉。主動選擇系統瀏覽器時，介面會說明連結將離開環境。

### 🤖 給 AI 與自動化工具，一個有條理的工作台

瀏覽器後端提供 **REST、MCP 和 Playwright** 介面，可用於頁面操作、表單、Cookie 與截圖等自動化情境；介面的支援範圍請見[功能矩陣](../capability-matrix.md)。

Claude Code 是其中一項整合：每個環境獨立安裝**未經修改的官方 CLI**，保存具名登入設定檔，並透過工作階段專用的 MCP broker 綁定所選環境瀏覽器。先進入 shell，再由你啟動 `claude`；模型、恢復工作階段與權限選項都由你決定。[Claude Code 工作階段](../claude-code-sessions.md)

### 📦 需要移轉時，帶走你選擇的資料

瀏覽器、終端與附加應用程式各有**密碼加密匯出**入口，依需求選擇資料。終端匯出包含選定的 Claude 登入設定檔，以及共用的 shell 設定與歷史紀錄；匯入時會建立新環境，保留既有工作區。

程式本體、快取、暫存檔與 Keychain 不會隨匯出檔帶走；部分帳號換機後仍需重新登入。

### 🗂️ 日常管理，盡量少一點打斷

三欄工作區支援淺色、深色與跟隨系統外觀，讓環境、網路、瀏覽器、終端、附加軟體與執行狀態都有清楚的位置。外觀設定僅影響 Envara，不會變更主機外觀。常用操作直接可達，細節設定收進進階選項；九種介面語言，讓你用熟悉的語言開始。

## 可以用境艙做什麼？

| 情境 | 境艙幫你整理的內容 |
| --- | --- |
| 多專案開發 | 專案目錄、終端設定與歷史紀錄、瀏覽器資料及指定網路 |
| 多帳號工作 | 依環境分開保存瀏覽資料與應用程式資料，減少不同工作脈絡混用 |
| 跨地區網頁驗證 | 選擇網路出口、檢查實際出口，再設定瀏覽器地區、語言與時區 |
| AI 輔助開發與瀏覽器自動化 | 在選定環境中執行工具、連接瀏覽器介面，並使用專用 Claude 工作階段 |
| 工作環境備份與移轉 | 依瀏覽器、終端設定檔或單一應用程式匯出加密資料，在新環境中還原 |

**本機桌面、一套工作脈絡、多種工具入口。** 你專心工作，境艙幫你把環境安排好。

## 下載與安裝

從 [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest) 下載 **1.2.0 macOS Apple Silicon（arm64）** 的 DMG、ZIP 與 SHA-256 校驗檔。開啟 DMG 後，可將 Envara 拖入「應用程式」。

**本版沿用 ad-hoc 臨時簽章，未使用 Apple Developer ID，也未經公證。** 首次開啟可能受到 macOS 安全檢查；請確認下載來自本儲存庫並核對校驗值。Envara 不會自動關閉系統安全檢查。附加軟體的系統路由元件需要另外取得管理員授權，啟動瀏覽器或一般工作區不會自動安裝它。

| 平台 | 1.2.0 提供範圍 |
| --- | --- |
| macOS Apple Silicon | 提供 DMG、ZIP 與 SHA-256 校驗檔 |
| macOS Intel | 保留原始碼路徑，未提供已驗證成品 |
| Windows / Linux | 保留相關原始碼；本次不發布成品，實機驗證範圍請見功能矩陣 |

瀏覽器核心由使用者透過應用程式內的入口安裝，適用各自授權。應用程式內含桌面執行所需相依元件，無需另外安裝 Node.js 或 Go。

## 用自己的語言開始

支援 **简体中文、繁體中文、English、日本語、한국어、Español、Français、Deutsch、Português (Brasil)**。首次啟動會推薦系統語言並由你確認，之後可在設定中切換。

![首次啟動語言選擇](../media/first-launch.png)

<p align="center"><sub>原生首次啟動語言選擇介面。</sub></p>

介面語言與瀏覽器環境語言分開，切換選單語言不會修改既有網路、時區或工作目錄。

## 關於隔離與隱私

境艙重視可控的網路、分開的資料，以及可稽核的隱私機制。以下幾項邊界，幫助你依照實際能力使用：

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

開發中投入了大量 AI 呼叫成本。如果 Envara 對你有幫助，歡迎自願支持：[USDT](../SUPPORT.md#usdt) · [USDC](../SUPPORT.md#usdc) · [Binance](../SUPPORT.md#binance)。Star、回報問題、翻譯與程式碼貢獻同樣重要。

[詳細使用指南（簡體中文）](../user-guide.md)
