<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Eine eigene Umgebung für jeden Arbeitskontext.</strong><br />Dein Browser, dein Terminal und deine Apps in einer gemeinsamen Umgebung.</p>
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

**Im Browser recherchieren, Befehle ausführen und Desktop-Apps nutzen: Eine gemeinsame Arbeitsumgebung begleitet den gesamten Ablauf.**

Envara ist ein lokaler Open-Source-Arbeitsplatz, der Netzwerkausgänge, Browserprofile, Terminalwerkzeuge und unterstützte Desktop-Anwendungen zusammenführt. Jede Umgebung speichert ihre eigenen Einstellungen und Daten. So kannst du für verschiedene Projekte, Konten oder Regionen eigene Arbeitskontexte anlegen und sie in einer Oberfläche verwalten.

![Nativer Envara-Arbeitsbereich auf Chinesisch](../media/workspace-zh-CN.png)

<p align="center"><sub>Nativer Electron-Arbeitsbereich mit synthetischen Beispieldaten.</sub></p>

## Was Envara besonders macht: Der ganze Arbeitsablauf bleibt verbunden

Im Browser recherchieren, im Terminal programmieren und in einer Desktop-App weiterarbeiten: Oft gehört all das zum selben Projekt. Mit Envara nutzen diese Werkzeuge denselben bestätigten Netzwerkkontext. Browserdaten, Werkzeugkonfigurationen und Anwendungsdaten bleiben jeweils für die nächste Sitzung erhalten.

**Einmal das Netzwerk wählen, die passenden Werkzeuge hinzufügen und beim nächsten Mal weiterarbeiten.** Das ist die Idee hinter Envara: getrennte Umgebungen als selbstverständlicher Teil des Arbeitsalltags.

### 🌐 Jede Umgebung hat ihren eigenen Browser

Wähle zwischen **CloakBrowser / Chromium, Camoufox / Firefox** und dem experimentellen **BrowseForge Chromium**. Getrennte Browserdaten, dauerhafte Sitzungen, Gruppen, Suche und das Klonen von Konfigurationen helfen dir, mehrere Arbeitskontexte übersichtlich zu verwalten. Ein Konfigurationsklon erstellt eine neue Umgebung; vorhandene Anmeldedaten bleiben in der ursprünglichen Umgebung.

Die Fingerabdruckkonfiguration verwaltet standardmäßig die gewählte Engine. Erweiterte Einstellungen für Gerät, Sprache und Zeitzone ergänzen überprüfbare Regeln zum Blockieren von Trackern. Der genaue Funktionsumfang hängt von der Engine ab. [Browser- und Geräteeinstellungen](../browser-device-profiles.md)

### 🧭 Netzwerk, Standort und Zeitzone einmal festlegen

Unterstützt werden **HTTP, HTTPS, SOCKS5 und AnyTLS**. Den mitgelieferten AnyTLS-Proxy-Kern verwaltet Envara selbst; eine separate Clash-Konfiguration ist nicht nötig.

Beim Anlegen einer Netzwerkumgebung ermittelt Envara den **tatsächlichen Ausgang über den authentifizierten Proxy**. Anschließend bestätigst du Region und Zeitzone. Browser, Terminal und unterstützte angebundene Anwendungen verwenden diesen Kontext gemeinsam. Wenn du einen Standort simulieren möchtest, hilft Google Maps bei der Koordinatenauswahl. Gemessener Netzausgang und simulierter Standort werden getrennt angezeigt. Die Systemzeitzone des Hostrechners bleibt unverändert. [Netzwerkumgebungen](../network-context.md)

### ⌨️ Auch das Terminal bekommt eine eigene Arbeitsumgebung

Beim Anlegen einer Sitzung wählst du **Netzwerk, Browser für Links und Projektordner**. Konfiguration und Verlauf werden pro Umgebung gespeichert. Echte PTYs, mehrere Sitzungen, eine verstellbare Höhe, die Vergrößerung im Hauptbereich und separate Fenster machen die Kommandozeile zu einem praktischen Teil des Arbeitsplatzes.

Beim Duplizieren eines Terminals öffnet sich ein neuer Prozess im selben Kontext, der auf Eingaben wartet. Nach dem Schließen des Panels kannst du zur Sitzung zurückkehren. Unterstützte macOS-Routen mit einem verwalteten lokalen Relay nutzen eine Netzwerkbegrenzung: Programme ohne Proxy-Unterstützung können sich nicht verbinden, statt unbemerkt direkt ins Netz zu gehen. Deine Projektordner bleiben an ihrem ursprünglichen Ort, sodass du deine vorhandenen Werkzeuge weiterverwenden kannst.

### 🧩 Desktop-Apps in denselben Arbeitsablauf einbinden

Für unterstützte **Chromium-/Electron-Anwendungen** wählst du eine Umgebung und einen Browser für Links. Start, Stopp und Anwendungsdaten verwaltest du gemeinsam in Envara. Vor dem Start prüft Envara die Identität und Kompatibilität der Anwendung, bereits vorhandene Instanzen und die nativen Routing-Komponenten. Erst wenn die Voraussetzungen erfüllt sind, wird der Start freigegeben.

Stoppen, Entfernen der Zuordnung und Beenden von Envara erhalten Anmeldedaten und Offline-Inhalte für die nächste Sitzung. Wann sie gelöscht werden, entscheidest du ausdrücklich. Natives Routing benötigt eine Systemfreigabe; eine unterstützte Engine bedeutet nicht, dass jede darauf basierende Anwendung bereits verifiziert wurde. [Unterstützte angebundene Anwendungen](../application-routing-options.md)

### 🔗 Vom Terminal bis zur Anmeldung bleibt der Kontext erhalten

Lege für die Umgebung einen Browser fest, damit Links aus dem Terminal dort geöffnet werden. Das System-Link-Routing unter macOS kann auch Links übernehmen, die verwaltete Anwendungen an das System übergeben. Links ohne Bezug zu einer Umgebung öffnen sich weiterhin im bisherigen Standardbrowser.

Das System-Link-Routing erfordert deine Bestätigung im macOS-Dialog und lässt sich jederzeit ausschalten. Wenn du den Systembrowser wählst, weist die Oberfläche darauf hin, dass der Link die Umgebung verlässt.

### 🤖 Ein geordneter Arbeitsplatz für KI und Automatisierung

Der Browserdienst stellt **REST-, MCP- und Playwright-Schnittstellen** bereit, etwa für Seitenaktionen, Formulare, Cookies und Screenshots. Welche Funktionen unterstützt werden, zeigt die [Funktionsmatrix](../capability-matrix.md).

Claude Code ist eine dieser Integrationen: Jede Umgebung erhält eine eigene Installation der **unveränderten offiziellen CLI**, benannte Anmeldeprofile und einen MCP-Broker pro Sitzung, der die Werkzeuge an den gewählten Umgebungsbrowser bindet. Du gelangst zuerst in die Shell und startest dann selbst `claude`. Modell, Sitzungsfortsetzung und Berechtigungsoptionen wählst du selbst. [Claude-Code-Sitzungen](../claude-code-sessions.md)

### 📦 Bei einem Wechsel die gewünschten Daten mitnehmen

Browser, Terminal und angebundene Anwendungen haben jeweils einen eigenen **Export mit Passwortverschlüsselung**. Ein Terminalexport enthält das ausgewählte Claude-Anmeldeprofil sowie die gemeinsame Shell-Konfiguration und den Verlauf. Der Import legt eine neue Umgebung an und erhält deinen vorhandenen Arbeitsbereich.

Die Programme selbst, Caches, temporäre Dateien und Schlüsselbunddaten werden nicht mitgenommen. Nach einem Rechnerwechsel kann deshalb für manche Konten eine erneute Anmeldung nötig sein.

### 🗂️ Weniger Unterbrechungen bei der täglichen Verwaltung

Die dunkle Oberfläche mit drei Spalten ordnet Umgebungen, Netzwerke, Browser, Terminals, angebundene Anwendungen und Laufzeitstatus übersichtlich an. Häufige Aktionen sind direkt erreichbar, detaillierte Einstellungen stehen unter den erweiterten Optionen. Neun Oberflächensprachen erleichtern den Einstieg in deiner vertrauten Sprache.

## Wofür kannst du Envara nutzen?

| Einsatz | Was Envara für dich organisiert |
| --- | --- |
| Entwicklung mehrerer Projekte | Projektordner, Terminalkonfiguration und Verlauf, Browserdaten und das gewählte Netzwerk |
| Arbeit mit mehreren Konten | Getrennte Browser- und Anwendungsdaten pro Umgebung, damit Arbeitskontexte seltener vermischt werden |
| Prüfung von Websites für verschiedene Regionen | Netzwerkausgang auswählen und überprüfen, dann Region, Sprache und Zeitzone des Browsers einstellen |
| KI-gestützte Entwicklung und Browserautomatisierung | Werkzeuge in der gewählten Umgebung ausführen, Browserschnittstellen nutzen und dedizierte Claude-Sitzungen starten |
| Arbeitsumgebungen sichern und übertragen | Daten eines Browsers, eines Terminalprofils oder einer einzelnen Anwendung verschlüsselt exportieren und in einer neuen Umgebung wiederherstellen |

**Ein lokaler Arbeitsplatz, ein gemeinsamer Arbeitskontext und mehrere Zugänge zu deinen Werkzeugen.** Du kümmerst dich um deine Arbeit, Envara hilft dir beim Organisieren der Umgebung.

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

## Isolation und Datenschutz

Envara setzt auf kontrollierbare Netzwerkverbindungen, getrennte Daten und überprüfbare Datenschutzmechanismen. Die folgenden Grenzen helfen dir, das Produkt entsprechend seinen tatsächlichen Fähigkeiten einzusetzen:

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
