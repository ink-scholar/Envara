<p align="center"><img src="../../build/icon.png" width="88" alt="Envara" /></p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Mehrere Umgebungen. Ein Arbeitsplatz.</strong></p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="MIT-Lizenz des eigenen App-Codes" /></a>
  <a href="../verification.md"><img src="https://img.shields.io/badge/0.5.0-local_candidate-475569" alt="Lokaler Kandidat 0.5.0" /></a>
</p>
<p align="center"><a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <strong>Deutsch</strong> · <a href="pt-BR.md">Português (Brasil)</a></p>

![Envara nativ auf Chinesisch](../media/workspace-zh-CN.png)

*Nativer Electron-Kandidat auf Chinesisch mit synthetischen Netzwerkdaten; kein Nachweis für echten Ausgang oder Anwendungsrouting. [Früherer nativer Screenshot](../envara-workspace-0.5.png).*

## Dein lokaler Arbeitsplatz

Envara bringt BrowseForge-Browserumgebungen in eine Desktop-App. Die Navigation folgt **Umgebungen → Netzwerkausgang → Browser → Terminal → Zugeordnete Anwendungen → Laufzeitmonitor**. Detaillierte Einstellungen befinden sich unter Erweitert.

- **Umgebungen:** getrennte Browserdaten, Gruppen, Tags, Klonen und Konfigurationsaustausch.
- **Netzwerke:** HTTP, HTTPS, SOCKS5 und integriertes AnyTLS; authentifizierte Ermittlung des tatsächlichen Ausgangs, der ungefähren Region und Zeitzone ohne separate Clash-Konfiguration.
- **Browser:** CloakBrowser / Chromium, Camoufox / Firefox und experimentelles BrowseForge Chromium.
- **Terminals:** echte lokale PTYs, gewähltes Arbeitsverzeichnis, Größenanpassung, eigene Fenster und mehrere Sitzungen. Duplizieren erstellt einen neuen Prozess, ohne Befehle erneut auszuführen.
- **Anwendungen:** Zuordnung lokaler Programme. Geschützter Start wird verweigert, bis der Systemadapter autorisiert und überprüft ist.

Browser und Terminal teilen Netzwerk und Zeitzone ihrer Umgebung. Werkzeugkonfiguration und Verlauf bleiben zwischen Umgebungen getrennt.

## Sprache beim Start wählen

Die Kandidatenoberfläche unterstützt vereinfachtes und traditionelles Chinesisch, Englisch, Japanisch, Koreanisch, Spanisch, Französisch, Deutsch und brasilianisches Portugiesisch. Wähle deine Sprache beim ersten Start und ändere sie später in den Einstellungen. Die Oberflächensprache verändert weder Browsersprache noch Netzwerk, Zeitzone, Verzeichnis oder Terminalausgabe.

![Sprachauswahl beim ersten Start](../media/first-launch.png)

*Nativer Electron-Erststart auf Englisch. Sprachauswahl, Speicherung und Sprachsynchronisierung der Terminalfenster wurden gesondert geprüft.*

## Verfügbarkeit und Grenzen

**0.5.0 ist eine Entwicklungsversion ohne endgültigen öffentlichen Download.** Der aktuelle Quellcodefortschritt wird geteilt; Installationsversionen bleiben Entwürfe und automatische Releases bleiben deaktiviert. Start und Bereinigung von Notion sind noch nicht validiert. Siehe die [aktuelle Diagnoseübergabe](../notion-launch-handoff-20261010.md).

macOS Apple Silicon ist die vorrangige Testplattform, mit versionsbezogenen nativen Nachweisen für Browser, AnyTLS und PTY. Das Kandidatenpaket ist unsigniert und nicht notarisiert. Windows hat Quellcode und Build-Kandidaten, benötigt aber Tests auf echter Hardware; macOS Intel und Linux sind ebenfalls nicht abgenommen.

**Vollständiges erzwungenes Anwendungsrouting ist auf beiden Plattformen noch nicht bereit.** Mac verwendet jetzt ein PF-Backend mit eigenen Prozessgruppen und utun-Schnittstellen, verbunden mit dem von Envara verwalteten authentifizierten Knoten. Dieser Weg benötigt eine lokale Administratorfreigabe, aber keinen Apple-Entwickleraccount. Unabhängiges DNS, Schutz bei Ausfällen und Tests mit echten Anwendungen stehen noch aus; Notion wurde nicht geschützt gestartet. Siehe [Routing-Grenzen](../application-routing-options.md) und [Prüfprotokolle](../verification.md).

Regeln entfernen nicht jedes Tracking. Konfigurationstrennung ist keine OS-Sandbox. IP-Ortung schätzt eine Region, keine Wohnadresse, und garantiert keinen Schutz vor Kontosperren.

## Entwicklung

Erforderlich sind Node.js 24 LTS oder 22.12+, npm, Go 1.25+ und plattformspezifische Build-Werkzeuge.

```bash
npm ci
npm run desktop
```

Die erste Vorbereitung benötigt Internet. Browser-Engines werden aus offiziellen Quellen installiert. Vorbereitete Desktop-Pakete enthalten Laufzeitabhängigkeiten; Nutzer brauchen weder Go noch Node.js.

```bash
npm test
npm run build
npm run test:sites
```

Web-Vorschau dient der UI-Entwicklung; native Vorgänge benötigen den Desktop-Modus. [Beitragsleitfaden](../../CONTRIBUTING.md).

## Mehr erfahren und unterstützen

[Funktionen und BrowseForge-Vergleich](../capability-matrix.md) · [Architektur](../architecture.md) · [Prüfungen](../verification.md) · [Issues](https://github.com/ink-scholar/Envara/issues)

Sterne, Rückmeldungen, Übersetzungen und Beiträge helfen. [Finanzielle Unterstützung](../SUPPORT.md) wird freiwillig sein; kein Zahlungsweg ist aktiviert.

## Lizenz

Envara und BrowseForge behalten getrennte MIT-Lizenzen. Der unabhängige Mihomo-Kern bleibt GPLv3 mit entsprechendem Quellcode. Browser-Binärdateien haben eigene Lizenzen; CloakBrowsers Binary License fällt nicht unter die MIT-Lizenz der App. [LICENSE](../../LICENSE) · [BrowseForge-Herkunft](../../third_party/browseforge/ENVARA_UPSTREAM.md) · [Proxy-Quellcode](../../third_party/proxy-core/SOURCE.md) · [Drittanbieterhinweise](../../THIRD_PARTY_NOTICES.md).
