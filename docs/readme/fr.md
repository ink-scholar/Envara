<p align="center"><img src="../../build/icon.png" width="88" alt="Envara" /></p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Plusieurs environnements. Un seul espace de travail.</strong></p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="Licence MIT du code original" /></a>
  <a href="../verification.md"><img src="https://img.shields.io/badge/0.5.0-local_candidate-475569" alt="Version candidate locale 0.5.0" /></a>
</p>
<p align="center"><a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <strong>Français</strong> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a></p>

![Envara natif en chinois](../media/workspace-zh-CN.png)

*Electron natif en chinois avec un réseau synthétique : aucune preuve de sortie réelle ou de routage applicatif. [Capture native précédente](../envara-workspace-0.5.png).*

## Votre espace local

Envara rassemble BrowseForge dans une application de bureau : **Environnements → Sortie réseau → Navigateur → Terminal → Applications associées → Suivi d’exécution**. Réglages détaillés dans Avancé.

- **Environnements :** données de navigation séparées, groupes, étiquettes, clonage et échange de configurations.
- **Réseaux :** HTTP, HTTPS, SOCKS5 et AnyTLS intégré ; détection authentifiée de la sortie, de la région approximative et du fuseau horaire, sans configurer Clash séparément.
- **Navigateurs :** CloakBrowser / Chromium, Camoufox / Firefox et BrowseForge Chromium expérimental.
- **Terminaux :** vrais PTY locaux, dossier choisi, redimensionnement, fenêtres indépendantes et plusieurs sessions. Dupliquer crée un nouveau processus sans rejouer les commandes.
- **Applications :** association de logiciels locaux. Le lancement protégé est refusé tant que l’adaptateur système n’est pas autorisé et vérifié.

Navigateur et terminal partagent réseau et fuseau ; configurations et historiques des outils restent séparés entre environnements.

## Choisissez votre langue

L’interface candidate prend en charge le chinois simplifié et traditionnel, l’anglais, le japonais, le coréen, l’espagnol, le français, l’allemand et le portugais brésilien. Choisissez votre langue au premier lancement, puis changez-la dans les paramètres. La langue ne modifie ni langue du navigateur, réseau, fuseau, dossier, ni sortie du terminal.

![Choix de langue au premier lancement](../media/first-launch.png)

*Premier lancement natif en anglais. Choix, persistance et synchronisation de langue des fenêtres de terminal vérifiés séparément.*

## Disponibilité et limites

**0.5.0 est une version candidate de développement, sans téléchargement public définitif.** Les dernières avancées du code source sont partagées ; les installateurs restent en brouillon et les versions automatiques restent désactivées. Le démarrage et le nettoyage de Notion ne sont pas validés. Voir le [diagnostic actuel](../notion-launch-handoff-20261010.md).

macOS Apple Silicon est prioritaire, avec des preuves natives par version pour navigateurs, AnyTLS et PTY. Paquet non signé, non notarié. Les candidats Windows attendent des essais réels ; macOS Intel et Linux restent non validés.

**Le routage forcé complet des applications n’est prêt sur aucune plateforme.** Mac utilise désormais un backend PF avec des groupes de processus et des interfaces utun propres, relié au nœud authentifié géré par Envara. Cette solution exige l’accord de l’administrateur local, sans compte Apple Developer. Le DNS indépendant, la protection en cas de panne et la validation avec des applications réelles restent à vérifier ; Notion n’a pas été lancé en mode protégé. Consultez les [limites](../application-routing-options.md) et [vérifications](../verification.md).

Les règles ne suppriment pas tout suivi. La configuration n’est pas un bac à sable du système ; l’IP estime une région, pas une adresse, et ne garantit pas d’éviter une suspension de compte.

## Développement

Prérequis : Node.js 24 LTS ou 22.12+, npm, Go 1.25+ et outils de compilation adaptés.

```bash
npm ci
npm run desktop
```

La préparation nécessite internet ; les moteurs proviennent des sources officielles. Le paquet inclut les dépendances : aucun Go ou Node.js à installer pour l’utilisateur.

```bash
npm test
npm run build
npm run test:sites
```

Web sert à l’interface ; les opérations natives nécessitent le mode bureau. [Guide de contribution](../../CONTRIBUTING.md).

## Informations et soutien

[Fonctions et comparaison BrowseForge](../capability-matrix.md) · [Architecture](../architecture.md) · [Vérifications](../verification.md) · [Problèmes](https://github.com/ink-scholar/Envara/issues)

Étoiles, retours, traductions et contributions sont utiles. [Soutien financier](../SUPPORT.md) facultatif ; paiements désactivés.

## Licence

Envara et BrowseForge conservent leurs licences MIT distinctes. Le cœur indépendant Mihomo conserve GPLv3 et le code correspondant. Les navigateurs ont leurs licences propres ; la Binary License de CloakBrowser n’est pas incluse dans MIT. [LICENSE](../../LICENSE) · [Origine BrowseForge](../../third_party/browseforge/ENVARA_UPSTREAM.md) · [Source du proxy](../../third_party/proxy-core/SOURCE.md) · [Mentions tierces](../../THIRD_PARTY_NOTICES.md).
