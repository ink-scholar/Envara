<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Mehrere Umgebungen, ein Arbeitsplatz.</strong><br />Ein lokaler Arbeitsplatz für Browser, Terminals und Netzwerkkontexte.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="Lizenz des Originalcodes: MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-0.5.23-475569" alt="Envara 0.5.23" /></a>
  <a href="en.md"><img src="https://img.shields.io/badge/README-9_languages-6366f1" alt="README in 9 Sprachen" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <strong>Deutsch</strong> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">macOS-Version herunterladen</a> · <a href="../capability-matrix.md">Funktionen und Grenzen</a> · <a href="../../CONTRIBUTING.md">Mitwirken</a> · <a href="../SUPPORT.md">Projekt unterstützen</a>
</p>

![Nativer Envara-Arbeitsbereich auf Chinesisch](../media/workspace-zh-CN.png)

<p align="center"><sub>Nativer Electron-Arbeitsbereich mit synthetischen Beispieldaten.</sub></p>

## Eine Umgebung, ein gemeinsamer Arbeitskontext

Envara vereint Browser, Netzwerkausgang, Arbeitsverzeichnis und Kommandozeilenwerkzeuge in einem lokalen Arbeitsplatz. Jede Umgebung behält ihre eigenen Browserdaten, Werkzeugkonfigurationen und Verläufe; für unterschiedliche Umgebungen lassen sich unterschiedliche Netzwerke wählen.

| Bereich | Funktionen |
| --- | --- |
| Umgebungen | Erstellen, klonen, gruppieren und durchsuchen; Arbeitsverzeichnis und Netzwerkkontext speichern |
| Netzwerkausgang | HTTP, HTTPS, SOCKS5 und integriertes AnyTLS; tatsächlichen Ausgang, ungefähre Region und Zeitzone ermitteln |
| Browser | CloakBrowser / Chromium, Camoufox / Firefox und experimentelles BrowseForge Chromium; automatische Konfiguration und erweiterte Einstellungen |
| Terminal | Echte PTYs, Verzeichnisauswahl, mehrere Sitzungen, größenverstellbare Bereiche und separate Fenster |
| Claude Code | Separate Installation der offiziellen CLI pro Umgebung, benannte Anmeldeprofile und MCP-Werkzeuge mit fest zugeordnetem Umgebungsbrowser |
| Angebundene Anwendungen | Unterstützte Chromium-/Electron-Anwendungen einer Umgebung zuordnen, laufende Instanzen und separate Anwendungsdaten verwalten |
| Datenübertragung | Browserdaten, das ausgewählte Terminal-Anmeldeprofil oder Daten einer angebundenen Anwendung getrennt exportieren und mit einem Passwort verschlüsseln |

Envara verwaltet den integrierten AnyTLS-Kern; eine separate Clash-Konfiguration ist nicht erforderlich. Browser, Terminals und angebundene Anwendungen verwenden den bestätigten Netzwerkstandort und die Zeitzone gemeinsam. Die Standorteinstellung verändert nicht die Systemzeitzone; IP-Ortung liefert nur eine ungefähre Region.

Beim Duplizieren eines Terminals entsteht ein neuer, unabhängiger Prozess; Befehle werden nicht erneut ausgeführt. Claude-Code-Sitzungen beginnen an der Shell-Eingabeaufforderung, wo du selbst `claude` eingibst. Du kannst eine separate offizielle Installation herunterladen oder sie mit einem bereits vorhandenen nativen Programm auf deinem Rechner initialisieren. Envara verändert die offizielle CLI nicht, kopiert keine Kontodaten des Hostsystems und aktiviert standardmäßig keine Umgehung von Berechtigungsprüfungen. [Mehr zu Claude-Code-Sitzungen](../claude-code-sessions.md).

Vor dem Start einer angebundenen Anwendung prüft Envara ihre Kompatibilität, bereits laufende Instanzen und den Zustand der Routing-Komponenten. Sind die Voraussetzungen nicht erfüllt, wird der Start ausdrücklich verweigert. Stoppen, Entfernen der Zuordnung und Beenden der App erhalten die Anmeldedaten. Sie werden nur gelöscht, wenn du die Anmeldedaten oder die Umgebung ausdrücklich löschst. Weitere Informationen unter [Angebundene Anwendungen](../application-routing-options.md).

## Herunterladen und installieren

Lade auf [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest) die DMG- oder ZIP-Datei für **macOS Apple Silicon (arm64)** herunter. Öffne die DMG-Datei und ziehe Envara in den Ordner „Programme“. Prüfsummen und Versionshinweise werden mit dem Release bereitgestellt.

**Die aktuellen macOS-Artefakte sind weder mit einer Apple Developer ID signiert noch notarisiert.** Beim ersten Öffnen können die Sicherheitsprüfungen von macOS den Start verhindern. Vergewissere dich, dass der Download aus diesem Repository stammt, und prüfe die Prüfsumme. Envara schaltet die Sicherheitsprüfungen des Systems nicht automatisch aus. Die Systemkomponente für das Routing angebundener Anwendungen benötigt eine gesonderte Administratorfreigabe. Der Start eines Browsers oder des normalen Arbeitsbereichs installiert sie nicht automatisch.

| Plattform | Veröffentlichte Artefakte |
| --- | --- |
| macOS Apple Silicon | Für diese Version: DMG, ZIP und SHA-256-Prüfsummendatei |
| macOS Intel | Quellcode für diese Plattform bleibt erhalten; keine verifizierten Artefakte verfügbar |
| Windows / Linux | Zugehöriger Quellcode bleibt erhalten; für diese Version werden keine Artefakte veröffentlicht. Den Umfang der Tests auf echter Hardware beschreibt die Funktionsmatrix |

Browser-Engines installierst du über die entsprechende Funktion in der App; es gelten ihre jeweiligen Lizenzen. Die App enthält die Laufzeitabhängigkeiten für den Desktopbetrieb. Node.js und Go müssen nicht separat installiert werden.

## In deiner Sprache starten

Unterstützt werden **简体中文、繁體中文、English、日本語、한국어、Español、Français、Deutsch、Português (Brasil)**. Beim ersten Start empfiehlt Envara die Systemsprache und bittet dich um Bestätigung. Später lässt sich die Sprache in den Einstellungen ändern.

![Sprachauswahl beim ersten Start](../media/first-launch.png)

<p align="center"><sub>Native Sprachauswahl beim ersten Start.</sub></p>

Die Oberflächensprache ist von der Sprache der Browserumgebung getrennt. Ein Wechsel der Menüsprache verändert weder vorhandene Netzwerke noch Zeitzonen oder Arbeitsverzeichnisse.

## Grenzen der Funktionen

- Die Trennung von Konfiguration und Daten schafft weder einen eigenen Betriebssystembenutzer noch einen separaten Schlüsselbund oder virtuelle Hardware. Browser-Fingerabdruckeinstellungen verändern nicht die Hardwareidentität nativer Anwendungen.
- Unterstützte Terminalrouten unter macOS verwenden eine Netzwerkbegrenzung. Plattformen und Routen ohne diese Grenze gelten nicht als erzwungen isoliert. Einzelheiten stehen in der [Funktionsmatrix](../capability-matrix.md).
- Wenn angebundene Anwendungen die äußere Netzwerkbegrenzung verwenden, ist die interne Sandbox von Chromium/Electron deaktiviert. Der Zustand nativer Komponenten, unterstützte Engines und der tatsächlich geprüfte Umfang werden getrennt beschrieben. Die Erkennung einer Anwendung bedeutet nicht, dass alle Programme verifiziert wurden.
- Exporte enthalten weder Schlüsselbunddaten noch die Programme selbst, Caches oder temporäre Dateien. Nach einem Rechnerwechsel kann für manche Konten eine erneute Anmeldung erforderlich sein. Eine erfolgreiche Wiederherstellung auf demselben Rechner garantiert keine gültige Anmeldung auf einem anderen.
- Tracking-Schutz umfasst nur implementierte Regeln und von der Engine unterstützte Steuerungsmöglichkeiten. Die Trennung von Netzwerken, Konten und Konfigurationen garantiert weder die Vermeidung von Diensteinschränkungen noch die Beseitigung jeglichen Trackings.

[Hinweise zur Verifizierung](../verification.md) · [Architektur](../architecture.md) · [Netzwerkkontext](../network-context.md) · [Browsergeräte und Sprache](../browser-device-profiles.md)

## Aus dem Quellcode entwickeln

Benötigt werden Node.js 24 LTS (oder 22.12+), npm, Go 1.25 und die Build-Werkzeuge der Zielplattform. Die nativen macOS-Komponenten benötigen die Xcode Command Line Tools.

```bash
npm ci
npm run desktop
```

Bei der ersten Vorbereitung werden Build-Abhängigkeiten in festgelegten Versionen heruntergeladen. Entwicklungsvorschau und Prüfungen:

```bash
npm run dev
npm test
npm run build
npm run test:sites
```

Die Web-Vorschau dient ausschließlich der Oberflächenentwicklung. Echte Browser, PTYs und Systemrouting benötigen die Desktop-App. Hinweise zu Builds und Veröffentlichungen findest du im [Beitragsleitfaden](../../CONTRIBUTING.md) und im [Release-Ablauf](../releasing.md). Automatische Build- und Release-Workflows auf GitHub bleiben deaktiviert; das Pushen von Quellcode löst keinen Build aus.

## Open Source und Unterstützung

Der Originalcode von Envara steht unter [MIT](../../LICENSE). BrowseForge behält seine [MIT-Lizenz](../../third_party/browseforge/LICENSE) und die [Dokumentation der festgelegten Upstream-Version](../../third_party/browseforge/ENVARA_UPSTREAM.md). Der separate Mihomo-Kern behält [GPLv3](../../third_party/proxy-core/LICENSE) und seinen [zugehörigen Quellcode](../../third_party/proxy-core/SOURCE.md). Für Browser-Binärdateien gelten eigene Lizenzen; sie sind nicht von der MIT-Lizenz der App erfasst. Die vollständigen Angaben stehen in den [Drittanbieterhinweisen](../../THIRD_PARTY_NOTICES.md).

[Fehlerberichte](https://github.com/ink-scholar/Envara/issues), Codebeiträge, verbesserte Übersetzungen und Sterne sind willkommen. Jede Unterstützung ist freiwillig; ein Spendenkanal ist noch nicht aktiviert. [Projekt unterstützen](../SUPPORT.md)
