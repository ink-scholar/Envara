<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>讓每一套工作，都有獨立的境艙。</strong><br />One environment. Your browser, terminal and apps.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="原創程式碼授權：MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/github/v/release/ink-scholar/Envara?color=475569" alt="最新版本" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <strong>繁體中文</strong> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">下載 macOS 版</a> · <a href="../user-guide.md">使用指南</a> · <a href="../capability-matrix.md">全部功能</a> · <a href="../SUPPORT.md">支持專案</a>
</p>

**將瀏覽器、終端與桌面應用程式，放進各自獨立的工作環境。**

Envara 境艙是開源的本機桌面工作台。為不同專案、帳號或地區分別保存網路、瀏覽資料與工具設定；選好環境，從查資料、寫程式到開啟應用程式，都能接著上次的工作繼續。

![Envara 工作區，使用合成範例資料](../media/workspace-zh-CN.png)

## 一張工作台，串起日常流程

| 功能 | 你可以做什麼 |
| --- | --- |
| 🌐 網路環境 | 支援 HTTP / HTTPS / SOCKS5 / AnyTLS；偵測通過認證的網路出口，確認地區與時區，AnyTLS 無需另外安裝 Clash |
| 🧭 獨立瀏覽器 | 選擇 CloakBrowser、Camoufox 或實驗性的 BrowseForge Chromium；分開保存資料，重新開啟時沿用已儲存的身分設定 |
| ⌨️ 原生終端 | 選擇專案資料夾，使用多工作階段、可調整大小的面板與獨立視窗；設定與歷史紀錄按環境保留，macOS 已儲存的 SSH 連線可選擇本機或已設定環境的網路路線 |
| 🧩 附加應用程式 | 為支援的 Chromium / Electron 應用程式綁定環境，管理獨立資料與啟動、停止 |
| 🤖 Claude Code | 在環境內安裝與更新，管理具名登入設定檔，並綁定所選的環境瀏覽器 |
| 🔗 連結與自動化 | 透過指定瀏覽器開啟連結，使用 REST / MCP / Playwright 瀏覽器介面 |
| 📦 加密移轉 | 分別匯出瀏覽器、所選終端設定檔或單一應用程式；以密碼加密，匯入新環境 |
| 🗂️ 工作區管理 | 將環境分組、搜尋、複製並查看執行狀態；三欄配置、可摺疊導覽、九種語言，支援淺色 / 深色 / 跟隨系統外觀 |

## 在熟悉的工具裡繼續工作

在瀏覽器查資料，在終端寫程式，再開啟需要的桌面應用程式，同一個環境保存這套工作的網路設定與資料。終端可以連線至遠端伺服器，每條已儲存的 SSH 連線都能選擇自己的路線；設定方式請見 [SSH 指南](../claude-code-sessions.md#ssh-through-the-environment-route)。

Claude Code 是終端工作流程中的一項整合。每個環境獨立安裝**未經修改的官方 CLI**，分別保存具名登入設定檔，並綁定所選的環境瀏覽器。進入 shell 後，由你輸入 `claude` 啟動；模型、恢復工作階段與權限選項都由你決定。詳見 [Claude Code 指南](../claude-code-sessions.md)。

環境隔離有助於減少網路與帳號設定混用，不保證避免帳號限制或提供完全匿名。附加應用程式的支援範圍、系統授權與沙箱取捨請見[功能與邊界](../capability-matrix.md)；停止或解除綁定會保留登入資料。

## 開始使用

從 [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest) 下載 **macOS Apple Silicon（arm64）** 的 DMG 或 ZIP，以及 SHA-256 校驗檔。安裝步驟與簽章說明請見[使用指南](../user-guide.md)。

1. **選擇網路。** 新增網路設定，偵測實際出口，再確認地區與時區。
2. **建立環境。** 選擇瀏覽器，為專案或帳號準備獨立的工作空間。
3. **開始工作。** 開啟瀏覽器、選擇終端工作目錄，或綁定支援的桌面應用程式。

下次回到同一個環境，繼續使用已儲存的瀏覽資料、終端設定與應用程式資料，減少重複設定。

[使用指南](../user-guide.md) · [全部功能](../capability-matrix.md) · [版本更新](https://github.com/ink-scholar/Envara/releases) · [從原始碼開發與貢獻](../../CONTRIBUTING.md) · [回報問題](https://github.com/ink-scholar/Envara/issues)

## 開源與支持

Envara 原創程式碼採用 [MIT](../../LICENSE)。BrowseForge 保留其 [MIT 授權](../../third_party/browseforge/LICENSE)及[固定版本紀錄](../../third_party/browseforge/ENVARA_UPSTREAM.md)。獨立 Mihomo 核心保留 [GPLv3](../../third_party/proxy-core/LICENSE)及[對應原始碼](../../third_party/proxy-core/SOURCE.md)。瀏覽器二進位檔適用各自授權，不包含在應用程式的 MIT 授權內。完整歸屬請見[第三方聲明](../../THIRD_PARTY_NOTICES.md)。

開發中投入了大量 AI 呼叫成本。如果 Envara 對你有幫助，歡迎自願支持：[USDT](../SUPPORT.md#usdt) · [USDC](../SUPPORT.md#usdc) · [Binance](../SUPPORT.md#binance)。Star、回報問題、翻譯與程式碼貢獻同樣重要。

[詳細使用指南（簡體中文）](../user-guide.md)
