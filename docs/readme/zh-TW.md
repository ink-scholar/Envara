<p align="center"><img src="../../build/icon.png" width="88" alt="Envara" /></p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>多個環境，一個工作臺。</strong></p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="原創應用程式碼：MIT" /></a>
  <a href="../verification.md"><img src="https://img.shields.io/badge/0.5.0-local_candidate-475569" alt="0.5.0 本機候選版" /></a>
</p>
<p align="center"><a href="../../README.md">简体中文</a> · <strong>繁體中文</strong> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a></p>

![Envara 中文原生工作區](../media/workspace-zh-CN.png)

*中文原生 Electron 候選介面，網路為隔離測試夾具中的合成資料，不是實際出口或附加軟體分流的證明。[先前的原生截圖](../envara-workspace-0.5.png)。*

## 本機工作區

Envara 將 BrowseForge 的瀏覽器環境功能帶進桌面應用程式。導覽依序為 **環境 → 網路出口 → 瀏覽器 → 終端機 → 附加應用程式 → 執行監控**；詳細設定集中於進階選項。

- **環境：**獨立瀏覽資料、群組、標籤、複製及設定匯入匯出。
- **網路：**HTTP、HTTPS、SOCKS5 與內建 AnyTLS；透過認證請求偵測真正出口、概略地區與時區，無須另外設定 Clash。
- **瀏覽器：**CloakBrowser / Chromium、Camoufox / Firefox，以及實驗性的 BrowseForge Chromium。
- **終端機：**真正的本機 PTY、自選目錄、調整尺寸、獨立視窗與多工作階段。複製會產生新行程，不重播指令。
- **附加應用程式：**將本機軟體綁定環境；系統網路接管元件未獲授權或尚未通過驗證時，不允許以受保護模式啟動。

瀏覽器和終端機共用境舱的網路與時區。不同環境的工具設定與紀錄彼此分開。

## 選擇介面語言

候選介面支援簡體中文、繁體中文、英語、日語、韓語、西班牙語、法語、德語與巴西葡萄牙語。首次開啟時可選擇語言，之後可在設定中更改。介面語言不會改變瀏覽器語系、時區、節點、工作目錄或終端機輸出。

![英文介面的原生首次啟動語言選擇](../media/first-launch.png)

*英文介面的原生 Electron 首次啟動截圖；語言選擇、儲存、重新啟動後保留，以及獨立終端機視窗同步均已單獨驗證。*

## 安裝狀態與限制

**0.5.0 是開發候選版，目前沒有公開正式下載。** 最新原始碼進展已獲授權上傳；安裝發行版仍為草稿，自動發行維持停用。Notion 啟動與清理尚未通過驗收，請見[目前診斷交接](../notion-launch-handoff-20261010.md)。

macOS Apple Silicon 是目前主要驗證平台，瀏覽器、AnyTLS 與真實 PTY 具有各版本的原生驗證紀錄；候選套件尚未簽章或公證。Windows 已有原始碼及建置候選，仍待實機驗收；macOS Intel 和 Linux 也未完成實機驗證。

**兩個平台的附加軟體完整強制分流都尚未就緒。** Mac 現在預設使用 PF、專用程序群組與自有 utun，透過 Envara 管理的已驗證節點連線。此路線需要本機管理員授權，不必先申請 Apple 開發者帳號。獨立 DNS、故障保護與實際應用程式仍待驗收；Notion 尚未以受保護模式執行。參閱[分流邊界](../application-routing-options.md)與[驗證紀錄](../verification.md)。

追蹤規則無法消除所有追蹤。設定隔離不是作業系統沙箱；IP 定位只估計地區，不提供住宅地址，也不保證避免帳號停權。

## 開發

需要 Node.js 24 LTS 或 22.12+、npm、Go 1.25+ 與目標平台建置工具。

```bash
npm ci
npm run desktop
```

首次準備需要連網。瀏覽器核心由使用者主動從官方來源安裝。準備好的桌面套件內含執行所需的相依元件，一般使用者不需要自行安裝 Go 或 Node.js。

```bash
npm test
npm run build
npm run test:sites
```

Web 預覽用於介面開發；原生操作需要桌面模式。參閱[貢獻指南](../../CONTRIBUTING.md)。

## 深入了解與支持

[功能與 BrowseForge 對照](../capability-matrix.md) · [架構](../architecture.md) · [驗證](../verification.md) · [問題回報](https://github.com/ink-scholar/Envara/issues)

歡迎 Star、回饋、翻譯和程式碼貢獻。[自願支持](../SUPPORT.md)的收款管道目前尚未啟用。

## 授權

Envara 原創程式碼與納入的 BrowseForge 分別保留 MIT 授權。獨立 Mihomo 核心保留 GPLv3 與對應原始碼。瀏覽器二進位檔案適用各自授權；CloakBrowser 的 Binary License 不屬於應用程式的 MIT。詳見 [LICENSE](../../LICENSE)、[BrowseForge 來源](../../third_party/browseforge/ENVARA_UPSTREAM.md)、[代理核心來源](../../third_party/proxy-core/SOURCE.md)與[第三方聲明](../../THIRD_PARTY_NOTICES.md)。
