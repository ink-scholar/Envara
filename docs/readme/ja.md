<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>複数の環境を、ひとつのワークスペースに。</strong><br />ブラウザー、ターミナル、ネットワーク設定をまとめるローカルワークスペース。</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="独自コードのライセンス：MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-0.5.23-475569" alt="Envara 0.5.23" /></a>
  <a href="en.md"><img src="https://img.shields.io/badge/README-9_languages-6366f1" alt="9 言語の README" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <strong>日本語</strong> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">macOS 版をダウンロード</a> · <a href="../capability-matrix.md">機能と制限</a> · <a href="../../CONTRIBUTING.md">貢献する</a> · <a href="../SUPPORT.md">プロジェクトを支援</a>
</p>

![Envara 中国語版のネイティブワークスペース](../media/workspace-zh-CN.png)

<p align="center"><sub>ネイティブ Electron ワークスペース。スクリーンショットには合成したサンプルデータを使用しています。</sub></p>

## ひとつの環境に、ひと揃いの作業設定

Envara は、ブラウザー、ネットワーク出口、作業ディレクトリ、コマンドラインツールをひとつのローカルワークスペースにまとめます。環境ごとにブラウザーデータ、ツール設定、履歴を保持し、それぞれ異なるネットワークを選べます。

| ワークスペース | 機能 |
| --- | --- |
| 環境 | 作成、複製、グループ化、検索。作業ディレクトリとネットワーク設定を保存 |
| ネットワーク出口 | HTTP、HTTPS、SOCKS5、内蔵 AnyTLS に対応。実際の出口、おおよその地域、タイムゾーンを検出 |
| ブラウザー | CloakBrowser / Chromium、Camoufox / Firefox、実験段階の BrowseForge Chromium。自動設定と詳細設定 |
| ターミナル | 実際の PTY、ディレクトリ選択、複数セッション、サイズ変更可能なパネル、独立ウィンドウ |
| Claude Code | 環境ごとに独立した公式 CLI のインストール、名前付きログインプロファイル、環境のブラウザーに紐づく MCP ツール |
| 追加アプリ | 対応する Chromium/Electron アプリを環境に関連付け、実行インスタンスと独立したアプリデータを管理 |
| データ移行 | ブラウザー、選択したターミナルのログインプロファイル、追加アプリのデータを個別にエクスポートし、パスワードで暗号化 |

内蔵 AnyTLS コアは Envara が管理するため、Clash を別途設定する必要はありません。ブラウザー、ターミナル、追加アプリは、確認済みのネットワーク位置とタイムゾーンを共用します。位置設定でシステムのタイムゾーンが変わることはありません。IP による位置情報は、おおよその地域を示すものです。

ターミナルの複製では新しい独立プロセスを作成し、コマンドを再実行しません。Claude Code セッションはまず shell を開き、利用者が `claude` を入力して起動します。環境専用に公式 CLI をダウンロードしてインストールするか、既存のローカルのネイティブプログラムを使って初期化できます。Envara は公式 CLI を改変せず、ホスト側のアカウント情報もコピーしません。権限確認の回避も既定では有効にしません。[Claude Code セッションについて](../claude-code-sessions.md)。

追加アプリの起動前には、互換性、既存の実行インスタンス、ルーティングコンポーネントの状態を確認します。条件を満たさない場合は、起動を明示的に拒否します。停止、関連付けの解除、Envara の終了ではログインデータを保持し、ログインデータまたは環境を明示的に削除した場合にのみ消去します。詳しくは[追加アプリ](../application-routing-options.md)をご覧ください。

## ダウンロードとインストール

[GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest) から **macOS Apple Silicon（arm64）** 向けの DMG または ZIP をダウンロードしてください。DMG を開いたら、Envara を「アプリケーション」にドラッグします。チェックサムファイルとリリースノートは Release に付属します。

**現在の macOS 配布物は、Apple Developer ID による署名も公証も受けていません。** 初回起動時に macOS のセキュリティ確認でブロックされる場合があります。このリポジトリからダウンロードしたことを確認し、チェックサムを照合してください。Envara がシステムのセキュリティ確認を自動で無効にすることはありません。追加アプリ用のシステムルーティングコンポーネントには別途管理者の承認が必要で、ブラウザーや通常のワークスペースの起動時に自動インストールされることはありません。

| プラットフォーム | 今回の提供範囲 |
| --- | --- |
| macOS Apple Silicon | DMG、ZIP、SHA-256 チェックサムファイルを提供 |
| macOS Intel | ソースコードは維持していますが、検証済みの配布物は提供していません |
| Windows / Linux | 関連ソースコードは維持していますが、今回は配布物を公開しません。実機での検証範囲は機能一覧をご覧ください |

ブラウザーエンジンは、利用者がアプリ内のインストール機能から導入します。それぞれのライセンスが適用されます。デスクトップ実行に必要な依存関係はアプリに同梱しているため、Node.js や Go を別途インストールする必要はありません。

## 自分の言語で始める

**简体中文、繁體中文、English、日本語、한국어、Español、Français、Deutsch、Português (Brasil)** に対応しています。初回起動時にはシステム言語を推奨し、利用者が確認して選択します。その後は設定から切り替えられます。

![初回起動時の言語選択](../media/first-launch.png)

<p align="center"><sub>ネイティブの初回起動時の言語選択画面。</sub></p>

インターフェースの言語とブラウザー環境の言語は別々です。メニューの言語を変えても、既存のネットワーク、タイムゾーン、作業ディレクトリは変わりません。

## 機能の限界

- 設定とデータの分離は、独立した OS ユーザー、Keychain、仮想ハードウェアを提供するものではありません。ブラウザーのフィンガープリント設定は、ネイティブアプリのハードウェア識別情報を変更しません。
- 対応する macOS ターミナルのルーティングにはネットワーク制限を使用します。この仕組みが未実装のプラットフォームや経路では、強制的に分離されているとはみなせません。詳しい範囲は[機能一覧](../capability-matrix.md)をご覧ください。
- 追加アプリで外側のネットワーク制限を使用する場合、Chromium/Electron の内部サンドボックスは無効になります。ネイティブコンポーネントの状態、対応エンジン、実際の検証範囲は区別して説明し、「識別できる」ことを「すべてのアプリを検証済み」とは扱いません。
- エクスポートには Keychain、プログラム本体、キャッシュ、一時ファイルは含まれません。別の端末では、一部のアカウントに再ログインが必要です。同じ端末で復元できても、別の端末でログイン状態を引き継げる保証はありません。
- 追跡のブロックは、実装済みのルールとエンジンが対応する制御に限られます。ネットワーク、アカウント、設定の分離はサービス側の制限の回避を保証せず、すべての追跡をなくすものでもありません。

[検証について](../verification.md) · [アーキテクチャ](../architecture.md) · [ネットワーク設定](../network-context.md) · [ブラウザーのデバイス設定と言語](../browser-device-profiles.md)

## ソースコードから開発する

Node.js 24 LTS（または 22.12+）、npm、Go 1.25、対象プラットフォームのビルドツールが必要です。macOS のネイティブコンポーネントには Xcode Command Line Tools が必要です。

```bash
npm ci
npm run desktop
```

初回の準備では、固定バージョンのビルド依存関係をダウンロードします。開発用プレビューとチェックは次のコマンドで実行できます。

```bash
npm run dev
npm test
npm run build
npm run test:sites
```

Web プレビューはインターフェース開発専用です。実際のブラウザー、PTY、システムルーティングにはデスクトップアプリが必要です。ビルドと公開については[貢献ガイド](../../CONTRIBUTING.md)と[リリース手順](../releasing.md)をご覧ください。GitHub の自動ビルド・リリースワークフローは無効のままで、ソースコードを push してもビルドは実行されません。

## オープンソースと支援

Envara の独自コードには [MIT](../../LICENSE) を適用します。BrowseForge は元の [MIT ライセンス](../../third_party/browseforge/LICENSE)と[固定バージョンの記録](../../third_party/browseforge/ENVARA_UPSTREAM.md)を保持しています。独立した Mihomo コアは [GPLv3](../../third_party/proxy-core/LICENSE)と[対応するソースコード](../../third_party/proxy-core/SOURCE.md)を維持しています。ブラウザーのバイナリにはそれぞれのライセンスが適用され、アプリの MIT ライセンスには含まれません。詳しい帰属は[第三者に関する通知](../../THIRD_PARTY_NOTICES.md)をご覧ください。

[問題報告](https://github.com/ink-scholar/Envara/issues)、コードや翻訳への貢献、Star を歓迎します。支援はすべて任意です。寄付窓口はまだ開設していません。[プロジェクトを支援](../SUPPORT.md)
