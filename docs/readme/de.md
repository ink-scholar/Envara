<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Eine eigene Umgebung für jeden Arbeitskontext.</strong><br />Dein Browser, dein Terminal und deine Apps in einer gemeinsamen Umgebung.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="Lizenz des Originalcodes: MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/github/v/release/ink-scholar/Envara?color=475569" alt="Neueste Version" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <strong>Deutsch</strong> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">Für macOS herunterladen</a> · <a href="../user-guide.md">Anleitung</a> · <a href="../capability-matrix.md">Alle Funktionen</a> · <a href="../SUPPORT.md">Projekt unterstützen</a>
</p>

**Browser, Terminal und Desktop-Apps in getrennten Arbeitsumgebungen organisieren.**

Envara ist ein lokaler Open-Source-Arbeitsplatz. Bewahre Netzwerkeinstellungen, Browserdaten und Werkzeugkonfigurationen für verschiedene Projekte, Konten oder Regionen getrennt auf. Wähle eine Umgebung, recherchiere im Browser, schreibe Code oder öffne eine App und mache dort weiter, wo du aufgehört hast.

![Envara-Arbeitsbereich mit synthetischen Beispieldaten](../media/workspace-zh-CN.png)

## Ein Arbeitsplatz für den gesamten Ablauf

| Funktion | Was du damit tun kannst |
| --- | --- |
| 🌐 Netzwerkumgebungen | HTTP / HTTPS / SOCKS5 / AnyTLS nutzen, den tatsächlichen Ausgang über den authentifizierten Proxy prüfen sowie Region und Zeitzone bestätigen; AnyTLS benötigt keine separate Clash-Installation |
| 🧭 Getrennte Browser | CloakBrowser, Camoufox oder das experimentelle BrowseForge Chromium wählen; Daten getrennt speichern und beim erneuten Öffnen die gespeicherte Identität weiterverwenden |
| ⌨️ Native Terminals | Einen Projektordner wählen, mehrere Sitzungen öffnen, das Panel anpassen oder ein separates Fenster nutzen; Konfiguration und Verlauf pro Umgebung behalten. Jede gespeicherte SSH-Verbindung unter macOS kann das Netzwerk des Rechners oder die Route einer konfigurierten Umgebung nutzen |
| 🧩 Angebundene Apps | Unterstützte Chromium-/Electron-Anwendungen einer Umgebung zuordnen, mit getrennten Daten und verwaltetem Start und Stopp |
| 🤖 Claude Code | Innerhalb einer Umgebung installieren und aktualisieren, benannte Anmeldeprofile verwalten und den gewählten Umgebungsbrowser zuordnen |
| 🔗 Links und Automatisierung | Links im gewählten Browser öffnen und REST-, MCP- und Playwright-Schnittstellen für den Browser nutzen |
| 📦 Verschlüsselte Übertragung | Einen Browser, ein ausgewähltes Terminalprofil oder eine einzelne App passwortverschlüsselt exportieren und in eine neue Umgebung importieren |
| 🗂️ Arbeitsbereich verwalten | Umgebungen gruppieren, suchen und duplizieren; den Laufzeitstatus in einer Oberfläche mit drei Spalten, einklappbarer Navigation, neun Sprachen sowie heller, dunkler oder systemabhängiger Darstellung prüfen |

## Mit vertrauten Werkzeugen weiterarbeiten

Recherchiere im Browser, schreibe Code im Terminal und öffne die Desktop-Apps, die du brauchst. Deine Umgebung hält die zugehörigen Netzwerkeinstellungen und Daten zusammen. Verbinde dich vom Terminal aus mit entfernten Servern und wähle für jede gespeicherte SSH-Verbindung eine eigene Route. Die Einrichtung beschreibt die [SSH-Anleitung](../claude-code-sessions.md#ssh-through-the-environment-route).

Claude Code ist eine Integration innerhalb des Terminalablaufs. Jede Umgebung installiert die **unveränderte offizielle CLI**, speichert benannte Anmeldeprofile getrennt und bindet den gewählten Umgebungsbrowser ein. Du beginnst an der Shell-Eingabeaufforderung und gibst `claude` ein, wenn du es nutzen möchtest. Modell, Sitzungsfortsetzung und Berechtigungsoptionen wählst du selbst. Mehr dazu in der [Claude-Code-Anleitung](../claude-code-sessions.md).

Getrennte Umgebungen helfen, Verwechslungen bei Netzwerk- und Kontoeinstellungen zu vermeiden; sie garantieren weder Schutz vor Kontoeinschränkungen noch vollständige Anonymität. Die [Funktionen und Grenzen](../capability-matrix.md) erläutern unterstützte angebundene Apps, Systemfreigaben und Abwägungen bei der Sandbox. Beim Stoppen oder Entfernen einer Zuordnung bleiben Anmeldedaten erhalten.

## Erste Schritte

Lade die DMG- oder ZIP-Datei für **macOS Apple Silicon (arm64)** und die SHA-256-Prüfsummen von [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest) herunter. Installationsschritte und Hinweise zur Signatur findest du in der [Anleitung](../user-guide.md).

1. **Netzwerk wählen.** Füge eine Netzwerkkonfiguration hinzu, prüfe den tatsächlichen Netzausgang und bestätige Region und Zeitzone.
2. **Umgebung erstellen.** Wähle einen Browser und gib deinem Projekt oder Konto einen eigenen Arbeitsbereich.
3. **Loslegen.** Öffne den Browser, wähle ein Arbeitsverzeichnis für das Terminal oder binde eine unterstützte Desktop-App ein.

Kehre in dieselbe Umgebung zurück, um gespeicherte Browserdaten, Terminaleinstellungen und App-Daten weiterzuverwenden und dir wiederholtes Einrichten zu sparen.

[Anleitung](../user-guide.md) · [Alle Funktionen](../capability-matrix.md) · [Versionshinweise](https://github.com/ink-scholar/Envara/releases) · [Entwickeln und beitragen](../../CONTRIBUTING.md) · [Problem melden](https://github.com/ink-scholar/Envara/issues)

## Open Source und Unterstützung

Der Originalcode von Envara steht unter [MIT](../../LICENSE). BrowseForge behält seine [MIT-Lizenz](../../third_party/browseforge/LICENSE) und die [Dokumentation der festgelegten Upstream-Version](../../third_party/browseforge/ENVARA_UPSTREAM.md). Der separate Mihomo-Kern behält [GPLv3](../../third_party/proxy-core/LICENSE) und seinen [zugehörigen Quellcode](../../third_party/proxy-core/SOURCE.md). Für Browser-Binärdateien gelten eigene Lizenzen; sie sind nicht von der MIT-Lizenz der App erfasst. Die vollständigen Angaben stehen in den [Drittanbieterhinweisen](../../THIRD_PARTY_NOTICES.md).

Die Entwicklung verursacht erhebliche Kosten für die KI-Nutzung. Wenn Envara dir hilft, kannst du das Projekt freiwillig unterstützen: [USDT](../SUPPORT.md#usdt) · [USDC](../SUPPORT.md#usdc) · [Binance](../SUPPORT.md#binance). Sterne, Fehlerberichte, Übersetzungen und Codebeiträge helfen ebenfalls.

[Ausführliche Anleitung (auf vereinfachtem Chinesisch)](../user-guide.md)
