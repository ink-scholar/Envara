<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Plusieurs environnements, un seul espace de travail.</strong><br />Un espace local pour vos navigateurs, terminaux et contextes réseau.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="Licence du code original : MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-0.5.23-475569" alt="Envara 0.5.23" /></a>
  <a href="en.md"><img src="https://img.shields.io/badge/README-9_languages-6366f1" alt="README en 9 langues" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <strong>Français</strong> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">Télécharger pour macOS</a> · <a href="../capability-matrix.md">Fonctionnalités et limites</a> · <a href="../../CONTRIBUTING.md">Contribuer</a> · <a href="../SUPPORT.md">Soutenir le projet</a>
</p>

![Espace de travail natif Envara en chinois](../media/workspace-zh-CN.png)

<p align="center"><sub>Espace de travail Electron natif avec des données d’exemple synthétiques.</sub></p>

## Un environnement, un contexte de travail commun

Envara réunit navigateur, sortie réseau, dossier de travail et outils en ligne de commande dans un même espace local. Chaque environnement conserve ses propres données de navigation, configurations et historiques d’outils ; les environnements peuvent utiliser des réseaux différents.

| Espace | Fonctionnalités |
| --- | --- |
| Environnements | Création, clonage, regroupement et recherche ; conservation du dossier de travail et du contexte réseau |
| Sortie réseau | HTTP, HTTPS, SOCKS5 et AnyTLS intégré ; détection de la sortie réelle, de la région approximative et du fuseau horaire |
| Navigateurs | CloakBrowser / Chromium, Camoufox / Firefox et BrowseForge Chromium expérimental ; configuration automatique et paramètres avancés |
| Terminal | Vrais PTY, choix du dossier, sessions multiples, panneau redimensionnable et fenêtres indépendantes |
| Claude Code | Installation distincte de la CLI officielle par environnement, profils de connexion nommés et outils MCP associés au navigateur de l’environnement |
| Applications associées | Association d’un environnement aux applications Chromium/Electron prises en charge, gestion des instances en cours et de données applicatives distinctes |
| Migration des données | Export séparé des données d’un navigateur, du profil de connexion de terminal choisi ou d’une application associée, avec chiffrement par mot de passe |

Le cœur AnyTLS intégré est géré par Envara, sans configuration séparée de Clash. Navigateurs, terminaux et applications associées réutilisent la localisation réseau et le fuseau horaire confirmés. La localisation choisie ne modifie pas le fuseau horaire du système ; la géolocalisation IP indique seulement une région approximative.

Dupliquer un terminal crée un nouveau processus indépendant, sans rejouer les commandes. Une session Claude Code commence à l’invite du shell : vous saisissez vous-même `claude`. Vous pouvez télécharger une installation officielle distincte ou l’initialiser à partir d’un programme natif déjà présent sur votre ordinateur. Envara ne modifie pas la CLI officielle, ne copie pas les données de compte de l’hôte et n’active pas par défaut de contournement des autorisations. [En savoir plus sur les sessions Claude Code](../claude-code-sessions.md).

Avant de lancer une application associée, Envara vérifie sa compatibilité, les instances existantes et l’état des composants de routage. Si les conditions ne sont pas remplies, le lancement est explicitement refusé. Arrêter l’application, supprimer son association ou quitter Envara conserve les données de connexion ; elles ne sont effacées que si vous supprimez explicitement ces données ou l’environnement. Voir [Applications associées](../application-routing-options.md).

## Téléchargement et installation

Téléchargez le DMG ou le ZIP pour **macOS Apple Silicon (arm64)** sur [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest). Ouvrez le DMG, puis faites glisser Envara dans le dossier « Applications ». Les fichiers de sommes de contrôle et les notes de version accompagnent la publication.

**Les fichiers macOS actuels ne sont ni signés avec un Apple Developer ID ni notariés.** Les contrôles de sécurité de macOS peuvent bloquer la première ouverture. Vérifiez que le téléchargement provient de ce dépôt et contrôlez sa somme de contrôle. Envara ne désactive pas automatiquement les contrôles de sécurité du système. Le composant système de routage des applications associées nécessite une autorisation administrateur distincte ; le lancement d’un navigateur ou de l’espace de travail ordinaire ne l’installe pas automatiquement.

| Plateforme | Fichiers proposés |
| --- | --- |
| macOS Apple Silicon | Pour cette version : DMG, ZIP et fichier de sommes de contrôle SHA-256 |
| macOS Intel | Code source conservé ; aucun fichier compilé et vérifié proposé |
| Windows / Linux | Code source correspondant conservé ; aucun fichier compilé publié pour cette version. Le périmètre des essais sur matériel réel figure dans la matrice des fonctionnalités |

Les moteurs de navigateur s’installent depuis l’application à votre initiative et restent soumis à leurs licences respectives. L’application intègre les dépendances nécessaires à son exécution sur le bureau ; aucune installation séparée de Node.js ou de Go n’est requise.

## Commencer dans votre langue

L’interface prend en charge **简体中文、繁體中文、English、日本語、한국어、Español、Français、Deutsch、Português (Brasil)**. Au premier lancement, Envara recommande la langue du système et vous demande de la confirmer. Vous pouvez ensuite la modifier dans les paramètres.

![Choix de langue au premier lancement](../media/first-launch.png)

<p align="center"><sub>Écran natif de choix de langue au premier lancement.</sub></p>

La langue de l’interface est distincte de celle de l’environnement de navigation. Changer la langue des menus ne modifie ni les réseaux existants, ni les fuseaux horaires, ni les dossiers de travail.

## Limites des fonctionnalités

- La séparation des configurations et des données ne crée ni utilisateur distinct du système d’exploitation, ni trousseau séparé, ni matériel virtuel. Les réglages d’empreinte du navigateur ne modifient pas l’identité matérielle des applications natives.
- Les routes de terminal prises en charge sur macOS utilisent une barrière réseau. Les plateformes et routes dépourvues de cette frontière ne doivent pas être considérées comme soumises à une isolation forcée. Voir la [matrice des fonctionnalités](../capability-matrix.md) pour le périmètre détaillé.
- Lorsqu’une application associée utilise la barrière réseau externe, le bac à sable interne de Chromium/Electron est désactivé. L’état des composants natifs, les moteurs pris en charge et le périmètre réellement vérifié sont décrits séparément. Reconnaître une application ne signifie pas que tous les logiciels ont été validés.
- Les exports ne contiennent ni trousseau, ni programmes, ni caches, ni fichiers temporaires. Certains comptes peuvent nécessiter une nouvelle connexion après un changement d’ordinateur ; une restauration réussie sur la même machine ne garantit pas la validité de la connexion sur une autre.
- Le blocage du suivi couvre uniquement les règles implémentées et les contrôles pris en charge par le moteur. La séparation des réseaux, comptes et configurations ne garantit pas d’éviter les restrictions d’un service et ne supprime pas tout suivi.

[Vérification](../verification.md) · [Architecture](../architecture.md) · [Contexte réseau](../network-context.md) · [Appareils et langues du navigateur](../browser-device-profiles.md)

## Développer à partir du code source

Prérequis : Node.js 24 LTS (ou 22.12+), npm, Go 1.25 et les outils de compilation de la plateforme cible. Les composants natifs macOS nécessitent les Xcode Command Line Tools.

```bash
npm ci
npm run desktop
```

La première préparation télécharge les dépendances de compilation dans des versions fixes. Aperçu de développement et vérifications :

```bash
npm run dev
npm test
npm run build
npm run test:sites
```

L’aperçu Web sert uniquement au développement de l’interface ; les vrais navigateurs, PTY et le routage système nécessitent l’application de bureau. Consultez le [guide de contribution](../../CONTRIBUTING.md) et la [procédure de publication](../releasing.md) pour la compilation et les versions. Les workflows GitHub de compilation et de publication automatiques restent désactivés ; l’envoi du code source ne déclenche pas de compilation.

## Open source et soutien

Le code original d’Envara est sous licence [MIT](../../LICENSE). BrowseForge conserve sa [licence MIT](../../third_party/browseforge/LICENSE) et la [référence de la version amont figée](../../third_party/browseforge/ENVARA_UPSTREAM.md). Le cœur Mihomo distinct conserve la licence [GPLv3](../../third_party/proxy-core/LICENSE) et son [code source correspondant](../../third_party/proxy-core/SOURCE.md). Les binaires des navigateurs sont soumis à leurs propres licences et ne relèvent pas de la licence MIT de l’application. Les attributions complètes figurent dans les [mentions relatives aux tiers](../../THIRD_PARTY_NOTICES.md).

Les [signalements de problèmes](https://github.com/ink-scholar/Envara/issues), contributions de code, améliorations des traductions et étoiles sont les bienvenus. Tout soutien est volontaire ; aucun canal de don n’est encore activé. [Soutenir le projet](../SUPPORT.md)
