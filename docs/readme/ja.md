<p align="center"><img src="../../build/icon.png" width="88" alt="Envara" /></p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>複数の環境を、ひとつのワークスペースに。</strong></p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="独自コードの MIT ライセンス" /></a>
  <a href="../verification.md"><img src="https://img.shields.io/badge/0.5.0-local_candidate-475569" alt="0.5.0 ローカル候補版" /></a>
</p>
<p align="center"><a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <strong>日本語</strong> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a></p>

![Envara 中国語版ネイティブワークスペース](../media/workspace-zh-CN.png)

*中国語版のネイティブ Electron 候補です。ネットワークはテスト用の合成データであり、実際の出口やアプリのルーティングの証拠ではありません。[以前のネイティブスクリーンショット](../envara-workspace-0.5.png)。*

## ローカルのワークスペース

Envara は BrowseForge のブラウザー環境をデスクトップアプリとして使いやすくまとめます。ナビゲーションは **環境 → ネットワーク出口 → ブラウザー → ターミナル → 追加アプリ → 実行状況** の順です。詳細な項目は「詳細設定」にあります。

- **環境：**独立したブラウザーデータ、グループ、タグ、複製、設定のインポートとエクスポート。
- **ネットワーク：**HTTP、HTTPS、SOCKS5、内蔵 AnyTLS。認証付き通信で実際の出口、概略の地域とタイムゾーンを確認します。別途 Clash を設定する必要はありません。
- **ブラウザー：**CloakBrowser / Chromium、Camoufox / Firefox、実験段階の BrowseForge Chromium。
- **ターミナル：**実際のローカル PTY、作業ディレクトリの選択、サイズ変更、独立ウィンドウと複数セッション。複製は新しいプロセスを作り、実行中のコマンドを再生しません。
- **追加アプリ：**ローカルソフトウェアを環境に関連付けます。システムアダプターの認可と検証が完了するまで、保護された起動を拒否します。

ブラウザーとターミナルは環境のネットワークとタイムゾーンを共有します。ツール設定と履歴は環境ごとに分かれます。

## 言語を選んで開始

候補版 UI は簡体字中国語、繁体字中国語、英語、日本語、韓国語、スペイン語、フランス語、ドイツ語、ブラジルポルトガル語に対応しています。初回起動で言語を選び、後から設定で変更できます。UI 言語を変更しても、ブラウザーのロケール、ネットワーク、タイムゾーン、ディレクトリ、ターミナル出力は変わりません。

![初回起動時の言語選択](../media/first-launch.png)

*ネイティブ Electron の英語 UI による初回起動画面です。言語選択、保存、再起動後の保持、独立ターミナルウィンドウの同期は個別に検証しました。*

## 提供状況と制限

**0.5.0 は開発候補版で、正式な公開ダウンロードはありません。** 最新ソースの進捗を公開します。インストーラーは下書きのまま、自動リリースも無効です。Notion の起動とクリーンアップは未検証です。[現在の診断引き継ぎ](../notion-launch-handoff-20261010.md)をご覧ください。

macOS Apple Silicon を優先して検証しています。ブラウザー、AnyTLS、実際の PTY にバージョン別のネイティブ検証記録があります。候補パッケージは未署名・未公証です。Windows はソースとビルド候補があり、実機検証が必要です。macOS Intel と Linux も実機検証を終えていません。

**macOS と Windows の両方で、追加アプリの完全な強制ルーティングはまだ利用できません。** Mac の既定方式は PF、専用プロセスグループ、専用 utun を使い、Envara が管理する認証付きノードに接続します。この方式にはローカル管理者の承認が必要ですが、Apple 開発者アカウントは不要です。独立 DNS、障害時の保護、実際のアプリでの検証は未完了です。Notion は保護された状態で実行していません。[ルーティングの制限](../application-routing-options.md)と[検証記録](../verification.md)をご覧ください。

追跡ルールですべての追跡を除去することはできません。設定の分離は OS サンドボックスではありません。IP 位置情報は地域の推定であり、住宅住所やアカウント停止の回避を保証しません。

## 開発

Node.js 24 LTS または 22.12+、npm、Go 1.25+ とプラットフォームのビルドツールが必要です。

```bash
npm ci
npm run desktop
```

最初の準備にはインターネット接続が必要です。ブラウザーエンジンは利用者が公式配布元からインストールします。準備済みのデスクトップパッケージには実行依存関係が含まれ、利用者による Go / Node.js のインストールは不要です。

```bash
npm test
npm run build
npm run test:sites
```

Web プレビューは UI 開発用です。ネイティブ操作にはデスクトップモードを使います。[貢献ガイド](../../CONTRIBUTING.md)を参照してください。

## 詳細と支援

[機能と BrowseForge 比較](../capability-matrix.md) · [アーキテクチャ](../architecture.md) · [検証](../verification.md) · [問題報告](https://github.com/ink-scholar/Envara/issues)

Star、フィードバック、翻訳、コードへの貢献を歓迎します。[任意の金銭的支援](../SUPPORT.md)は予定段階で、支払い窓口は未開設です。

## ライセンス

Envara の独自コードと組み込まれた BrowseForge ソースは、それぞれ MIT を維持します。独立して動作する Mihomo コアは GPLv3 に従い、対応するソースコードも提供します。ブラウザーのバイナリには独自のライセンスがあり、CloakBrowser の Binary License はアプリの MIT に含まれません。[LICENSE](../../LICENSE)、[BrowseForge の出典](../../third_party/browseforge/ENVARA_UPSTREAM.md)、[プロキシのソース](../../third_party/proxy-core/SOURCE.md)、[第三者ライセンス](../../THIRD_PARTY_NOTICES.md)を参照してください。
