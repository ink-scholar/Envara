<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Un environnement dédié à chaque contexte de travail.</strong><br />Votre navigateur, votre terminal et vos applications, dans un même environnement.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="Licence du code original : MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/github/v/release/ink-scholar/Envara?color=475569" alt="Dernière version" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <strong>Français</strong> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">Télécharger pour macOS</a> · <a href="../user-guide.md">Guide d’utilisation</a> · <a href="../capability-matrix.md">Toutes les fonctionnalités</a> · <a href="../SUPPORT.md">Soutenir le projet</a>
</p>

**Organisez votre navigateur, votre terminal et vos applications de bureau dans des environnements de travail distincts.**

Envara est un espace de travail local et open source. Conservez des réseaux, des données de navigation et des réglages d’outils distincts pour vos projets, comptes ou régions. Choisissez un environnement, faites vos recherches, écrivez du code ou ouvrez une application, puis reprenez là où vous en étiez.

![Espace de travail Envara avec des données d’exemple synthétiques](../media/workspace-zh-CN.png)

## Un espace pour tout votre travail

| Fonctionnalité | Ce que vous pouvez faire |
| --- | --- |
| 🌐 Environnements réseau | Utiliser HTTP / HTTPS / SOCKS5 / AnyTLS, vérifier la sortie via le proxy authentifié, puis confirmer la région et le fuseau horaire ; AnyTLS ne nécessite aucune installation séparée de Clash |
| 🧭 Navigateurs distincts | Choisir CloakBrowser, Camoufox ou BrowseForge Chromium, proposé à titre expérimental ; séparer les données et retrouver les identités enregistrées à la réouverture |
| ⌨️ Terminaux natifs | Choisir un dossier de projet, ouvrir plusieurs sessions, redimensionner le panneau ou utiliser une fenêtre séparée ; conserver la configuration et l’historique par environnement. Sur macOS, chaque connexion SSH enregistrée peut utiliser le réseau de l’hôte ou la route d’un environnement configuré |
| 🧩 Applications associées | Associer les applications Chromium / Electron prises en charge à un environnement, avec des données distinctes et des commandes de lancement et d’arrêt |
| 🤖 Claude Code | Installer et mettre à jour dans l’environnement, gérer des profils de connexion nommés et associer le navigateur choisi |
| 🔗 Liens et automatisation | Ouvrir les liens dans le navigateur choisi et utiliser les interfaces REST / MCP / Playwright du navigateur |
| 📦 Transfert chiffré | Exporter un navigateur, le profil de terminal choisi ou une application, avec un chiffrement par mot de passe ; importer dans un nouvel environnement |
| 🗂️ Gestion de l’espace de travail | Regrouper, rechercher et dupliquer les environnements ; consulter leur état d’exécution dans une interface à trois colonnes, avec navigation repliable, neuf langues et apparence claire, sombre ou adaptée au système |

## Continuez avec vos outils habituels

Faites vos recherches dans le navigateur, écrivez du code dans un terminal et ouvrez les applications de bureau dont vous avez besoin. Votre environnement réunit les réglages réseau et les données de ce travail. Connectez-vous à des serveurs distants depuis le terminal en choisissant une route pour chaque connexion SSH enregistrée. Consultez le [guide SSH](../claude-code-sessions.md#ssh-through-the-environment-route) pour la configuration.

Claude Code est une intégration du terminal. Chaque environnement installe la **CLI officielle, sans modification**, conserve séparément les profils de connexion nommés et leur associe le navigateur choisi. Vous arrivez d’abord à l’invite du shell et saisissez `claude` lorsque vous souhaitez l’utiliser. Vous choisissez le modèle, la reprise de session et les options d’autorisation. Consultez le [guide Claude Code](../claude-code-sessions.md).

L’isolation des environnements aide à limiter les mélanges de configurations réseau et de comptes ; elle ne garantit ni l’absence de restrictions sur les comptes ni un anonymat complet. Les [fonctionnalités et limites](../capability-matrix.md) détaillent la prise en charge des applications associées, les autorisations système et les compromis liés au sandbox. L’arrêt ou la suppression d’une association conserve les données de connexion.

## Premiers pas

Téléchargez le **DMG ou ZIP pour macOS Apple Silicon (arm64)** et les sommes de contrôle SHA-256 sur [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest). Consultez le [guide d’utilisation](../user-guide.md) pour l’installation et les informations sur la signature.

1. **Choisissez un réseau.** Ajoutez une configuration réseau, vérifiez sa sortie réelle, puis confirmez la région et le fuseau horaire.
2. **Créez un environnement.** Choisissez un navigateur et donnez à votre projet ou compte son propre espace de travail.
3. **Commencez à travailler.** Ouvrez le navigateur, choisissez le dossier de travail du terminal ou associez une application de bureau prise en charge.

Retrouvez le même environnement pour réutiliser vos données de navigation, réglages de terminal et données applicatives, avec moins de configuration à chaque fois.

[Guide d’utilisation](../user-guide.md) · [Toutes les fonctionnalités](../capability-matrix.md) · [Notes de version](https://github.com/ink-scholar/Envara/releases) · [Développer et contribuer](../../CONTRIBUTING.md) · [Signaler un problème](https://github.com/ink-scholar/Envara/issues)

## Open source et soutien

Le code original d’Envara est sous licence [MIT](../../LICENSE). BrowseForge conserve sa [licence MIT](../../third_party/browseforge/LICENSE) et la [référence de la version amont figée](../../third_party/browseforge/ENVARA_UPSTREAM.md). Le cœur Mihomo distinct conserve la licence [GPLv3](../../third_party/proxy-core/LICENSE) et son [code source correspondant](../../third_party/proxy-core/SOURCE.md). Les binaires des navigateurs sont soumis à leurs propres licences et ne relèvent pas de la licence MIT de l’application. Les attributions complètes figurent dans les [mentions relatives aux tiers](../../THIRD_PARTY_NOTICES.md).

Le développement a entraîné des coûts importants d’utilisation de l’IA. Si Envara vous est utile, vous pouvez le soutenir librement : [USDT](../SUPPORT.md#usdt) · [USDC](../SUPPORT.md#usdc) · [Binance](../SUPPORT.md#binance). Les étoiles, signalements de problèmes, traductions et contributions de code sont également les bienvenus.

[Guide d’utilisation détaillé (en chinois simplifié)](../user-guide.md)
