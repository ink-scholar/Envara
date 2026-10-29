<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>作業ごとに、独立したひとつの環境を。</strong><br />ブラウザーも、ターミナルも、アプリも。同じ作業環境で。</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="独自コードのライセンス：MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/github/v/release/ink-scholar/Envara?color=475569" alt="最新リリース" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <strong>日本語</strong> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">macOS 版をダウンロード</a> · <a href="../user-guide.md">使い方</a> · <a href="../capability-matrix.md">すべての機能</a> · <a href="../SUPPORT.md">プロジェクトを支援</a>
</p>

**ブラウザー、ターミナル、デスクトップアプリを、それぞれ独立した作業環境に。**

Envara は、オープンソースのローカルデスクトップワークスペースです。プロジェクト、アカウント、地域ごとに、ネットワーク、ブラウザーデータ、ツールの設定を分けて保存できます。環境を選んだら、ブラウザーで調べ、コードを書き、アプリを開いて、前回の続きから作業を始められます。

![合成したサンプルデータを使った Envara ワークスペース](../media/workspace-zh-CN.png)

## 日々の作業を、ひとつのワークスペースで

| 機能 | できること |
| --- | --- |
| 🌐 ネットワーク環境 | HTTP / HTTPS / SOCKS5 / AnyTLS に対応。プロキシ認証を経た実際の出口を確認し、地域とタイムゾーンを設定。AnyTLS は Clash の別途インストール不要 |
| 🧭 独立したブラウザー | CloakBrowser、Camoufox、実験段階の BrowseForge Chromium から選択。データを分けて保存し、再び開くときも保存済みの識別設定を維持 |
| ⌨️ ネイティブターミナル | プロジェクトフォルダーの選択、複数セッション、サイズ調整できるパネル、独立ウィンドウに対応。設定と履歴を環境ごとに保存。macOS の保存済み SSH 接続では、本機のネットワークまたは設定済み環境の経路を選択可能 |
| 🧩 追加アプリ | 対応する Chromium / Electron アプリを環境に関連付け、独立したデータと起動・停止を管理 |
| 🤖 Claude Code | 環境内でインストール・更新し、名前付きログインプロファイルを管理。選択した環境ブラウザーを関連付け |
| 🔗 リンクと自動化 | 指定したブラウザーでリンクを開き、REST / MCP / Playwright のブラウザーインターフェースを利用 |
| 📦 暗号化して移行 | ブラウザー、選択したターミナルプロファイル、個別アプリをパスワードで暗号化してエクスポートし、新しい環境にインポート |
| 🗂️ ワークスペース管理 | 環境のグループ化、検索、複製、実行状況の確認。折りたたみ可能なナビゲーションを備えた 3 カラム画面、9 言語、ライト・ダーク・システム設定に合わせた外観に対応 |

## 使い慣れたツールで、作業を続ける

ブラウザーで調べ、ターミナルでコードを書き、必要なデスクトップアプリを開く。その作業に使うネットワーク設定とデータを、ひとつの環境にまとめられます。ターミナルからリモートサーバーに接続する際は、保存済みの SSH 接続ごとに経路を選べます。設定方法は [SSH ガイド](../claude-code-sessions.md#ssh-through-the-environment-route)をご覧ください。

Claude Code は、ターミナルの作業フローに組み込まれた機能のひとつです。環境ごとに**改変していない公式 CLI**をインストールし、名前付きログインプロファイルを分けて保存して、選択した環境ブラウザーを関連付けます。シェルのプロンプトから始め、使いたいときに `claude` を入力して起動します。モデル、セッション再開、権限のオプションは自分で選べます。詳しくは [Claude Code ガイド](../claude-code-sessions.md)をご覧ください。

環境の分離は、ネットワークやアカウントの設定が混在することを減らしますが、サービスによるアカウント制限の回避や完全な匿名性を保証するものではありません。追加アプリの対応範囲、システムの承認、サンドボックスの取扱いは[機能と制限](../capability-matrix.md)をご覧ください。停止や関連付けの解除後も、ログインデータは保持されます。

## はじめに

[GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest) から **macOS Apple Silicon（arm64）** 向けの DMG または ZIP と、SHA-256 チェックサムをダウンロードしてください。インストール手順と署名については[ユーザーガイド](../user-guide.md)をご覧ください。

1. **ネットワークを選ぶ。** ネットワーク設定を追加して実際の出口を確認し、地域とタイムゾーンを確定します。
2. **環境を作る。** ブラウザーを選び、プロジェクトやアカウント専用のワークスペースを用意します。
3. **作業を始める。** ブラウザーを開き、ターミナルの作業フォルダーを選ぶか、対応するデスクトップアプリを関連付けます。

次回も同じ環境に戻れば、保存済みのブラウザーデータ、ターミナル設定、アプリデータを使い、設定を繰り返す手間を減らせます。

[使い方](../user-guide.md) · [すべての機能](../capability-matrix.md) · [リリースノート](https://github.com/ink-scholar/Envara/releases) · [開発と貢献](../../CONTRIBUTING.md) · [問題を報告](https://github.com/ink-scholar/Envara/issues)

## オープンソースと支援

Envara の独自コードには [MIT](../../LICENSE) を適用します。BrowseForge は元の [MIT ライセンス](../../third_party/browseforge/LICENSE)と[固定バージョンの記録](../../third_party/browseforge/ENVARA_UPSTREAM.md)を保持しています。独立した Mihomo コアは [GPLv3](../../third_party/proxy-core/LICENSE)と[対応するソースコード](../../third_party/proxy-core/SOURCE.md)を維持しています。ブラウザーのバイナリにはそれぞれのライセンスが適用され、アプリの MIT ライセンスには含まれません。詳しい帰属は[第三者に関する通知](../../THIRD_PARTY_NOTICES.md)をご覧ください。

開発には多くの AI 利用費用がかかっています。Envara が役立った方は、任意でご支援いただけると幸いです：[USDT](../SUPPORT.md#usdt) · [USDC](../SUPPORT.md#usdc) · [Binance](../SUPPORT.md#binance)。Star、問題報告、翻訳やコードへの貢献も歓迎します。

[詳しい使い方（簡体字中国語）](../user-guide.md)
