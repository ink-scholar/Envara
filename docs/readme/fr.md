<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Un environnement dédié à chaque contexte de travail.</strong><br />Votre navigateur, votre terminal et vos applications, dans un même environnement.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="Licence du code original : MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-1.1.0-475569" alt="Envara 1.1.0" /></a>
  <a href="en.md"><img src="https://img.shields.io/badge/README-9_languages-6366f1" alt="README en 9 langues" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <strong>Français</strong> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">Télécharger pour macOS</a> · <a href="../capability-matrix.md">Fonctionnalités et limites</a> · <a href="../../CONTRIBUTING.md">Contribuer</a> · <a href="../SUPPORT.md">Soutenir le projet</a>
</p>

**Naviguez, exécutez vos commandes et utilisez vos applications de bureau au sein d’un même environnement de travail.**

Envara est un espace de travail local et open source qui réunit sortie réseau, profils de navigateur, outils de terminal et applications de bureau prises en charge. Chaque environnement conserve ses propres réglages et données. Vous pouvez ainsi organiser vos projets, comptes ou activités par région, depuis une seule interface.

![Espace de travail natif Envara en chinois](../media/workspace-zh-CN.png)

## Nouveautés de la version 1.1.0

- **Une interface allégée et une navigation repliable.** Repliez le menu latéral pour laisser plus de place au navigateur, aux terminaux et aux applications.
- **Des terminaux enregistrés et nommés.** Retrouvez une session ordinaire ou Claude en cours, ou ouvrez un shell au repos avec son contexte enregistré. Aucune commande n’est rejouée.
- **MCP et plugins personnalisés.** La CLI officielle de Claude peut découvrir les configurations utilisateur, projet et locale de l’environnement, tout en conservant les outils du navigateur fixé et les contraintes réseau d’Envara.
- **Un trajet SSH selon la destination.** Sur macOS, les hôtes enregistrés utilisent la sortie réseau du Mac ; les autres passent par le proxy de l’environnement. Un échec ne change jamais ce trajet.

<p align="center"><sub>Espace de travail Electron natif avec des données d’exemple synthétiques.</sub></p>

## Ce qui fait la différence : relier tout votre flux de travail

Faire une recherche dans le navigateur, écrire du code dans le terminal, poursuivre dans une application de bureau : ces activités font souvent partie du même projet. Envara leur permet de réutiliser un contexte réseau confirmé, tout en conservant les données de navigation, configurations d’outils et données applicatives dont vous aurez besoin à votre retour.

**Choisissez votre réseau une fois, ajoutez vos outils et retrouvez votre travail la prochaine fois.** C’est le principe d’Envara : faire des environnements distincts une façon simple de travailler au quotidien.

### 🌐 À chaque environnement son navigateur

Choisissez entre **CloakBrowser / Chromium, Camoufox / Firefox** et **BrowseForge Chromium**, proposé à titre expérimental. Données de navigation distinctes, sessions persistantes, groupes, recherche et clonage des configurations vous aident à garder vos contextes bien organisés. Cloner une configuration crée un nouvel environnement ; les données de connexion restent dans l’original.

L’empreinte du navigateur est gérée par défaut par le moteur choisi. Des réglages avancés d’appareil, de langue et de fuseau horaire complètent les règles de blocage du suivi, qui peuvent être auditées. Les possibilités varient selon le moteur. [Navigateurs et paramètres d’appareil](../browser-device-profiles.md)

### 🧭 Réseau, localisation et fuseau horaire : un réglage commun

Envara prend en charge **HTTP, HTTPS, SOCKS5 et AnyTLS**. Le cœur de proxy AnyTLS est fourni avec l’application et géré par Envara ; aucune configuration séparée de Clash n’est nécessaire.

Lors de la création d’un environnement réseau, Envara détecte la **sortie réelle via le proxy authentifié**, puis vous laisse confirmer la région et le fuseau horaire. Le navigateur, le terminal et les applications associées prises en charge réutilisent ce contexte. Pour simuler une position, vous pouvez choisir des coordonnées avec Google Maps ; la sortie mesurée et la position simulée sont présentées séparément. Ces réglages ne modifient pas le fuseau horaire du système hôte. [Environnements réseau](../network-context.md)

### ⌨️ Un vrai environnement de travail pour le terminal

À la création d’une session, choisissez **le réseau, le navigateur pour les liens et le dossier du projet**. Configurations et historique sont conservés par environnement. Vrais PTY, sessions multiples, hauteur réglable, agrandissement dans l’espace principal et fenêtres indépendantes rendent la ligne de commande facile à intégrer à votre travail.

Sur macOS, les [connexions SSH contrôlées](../claude-code-sessions.md) utilisent la sortie réseau actuelle de cet appareil (y compris un VPN/TUN système actif) pour les couples hôte/port enregistrés ; l’hôte distant voit cette IP de sortie. Les couples non enregistrés peuvent utiliser `ssh user@host` via le proxy de l’environnement. Les connexions enregistrées sans autorisation valide sont bloquées et ne basculent pas vers le proxy ; les clés privées restent sur votre Mac. Ces trajets s’appliquent aux nouveaux terminaux de la version 1.1.0 ; les sessions existantes conservent leur contexte initial.

Dupliquer un terminal ouvre un nouveau processus au repos dans le même contexte. Fermer le panneau laisse la session disponible pour y revenir. Les routes gérées via un relais local prises en charge sur macOS utilisent une barrière réseau : les programmes incompatibles avec le proxy échouent à se connecter plutôt que de passer silencieusement en connexion directe. Vos dossiers de projet restent à leur emplacement d’origine, avec votre chaîne d’outils habituelle.

### 🧩 Intégrer les applications de bureau au même flux de travail

Pour les **applications Chromium / Electron prises en charge**, choisissez l’environnement et le navigateur pour les liens, puis gérez leur lancement, leur arrêt et leurs données applicatives. Envara vérifie l’identité de la cible, sa compatibilité, les instances déjà présentes et les composants natifs de routage avant d’autoriser le lancement.

Arrêter une application, supprimer son association ou quitter Envara conserve ses données de connexion et son contenu hors ligne pour la prochaine session. Vous choisissez explicitement quand les effacer. Le routage natif nécessite une autorisation du système ; la prise en charge d’un moteur ne signifie pas que toutes ses applications ont été validées. [Périmètre des applications associées](../application-routing-options.md)

### 🔗 Du terminal à la page de connexion, gardez le même contexte

Attribuez un navigateur à l’environnement pour y ouvrir les liens du terminal. Le routage des liens système de macOS peut également prendre en charge les liens que les applications gérées transmettent au système. Les liens sans rapport avec un environnement continuent de s’ouvrir dans le navigateur par défaut précédent.

Le routage système requiert votre confirmation dans une boîte de dialogue macOS et peut être désactivé à tout moment. Si vous choisissez le navigateur du système, l’interface précise que le lien quittera l’environnement.

### 🤖 Un espace organisé pour l’IA et l’automatisation

Le service du navigateur propose des interfaces **REST, MCP et Playwright** pour automatiser les pages, formulaires, cookies et captures d’écran, entre autres. Leur périmètre est précisé dans la [matrice des fonctionnalités](../capability-matrix.md).

Claude Code est l’une de ces intégrations : chaque environnement dispose d’une installation distincte de la **CLI officielle, sans modification**, de profils de connexion nommés et d’un broker MCP propre à la session qui lie les outils au navigateur choisi. Vous entrez d’abord dans le shell, puis lancez `claude` vous-même. Le modèle, la reprise d’une session et les options d’autorisation restent à votre choix. [Sessions Claude Code](../claude-code-sessions.md)

### 📦 Emporter uniquement les données dont vous avez besoin

Navigateurs, terminaux et applications associées disposent chacun de leur propre fonction d’**export chiffré par mot de passe**. L’export d’un terminal comprend le profil de connexion Claude sélectionné ainsi que la configuration et l’historique shell partagés. L’import crée un nouvel environnement et conserve votre espace de travail existant.

Les programmes eux-mêmes, caches, fichiers temporaires et données du trousseau ne sont pas exportés. Certains comptes nécessitent donc une nouvelle connexion après un changement d’ordinateur.

### 🗂️ Moins d’interruptions dans la gestion quotidienne

L’interface à trois colonnes propose un mode clair, sombre ou adapté au système, et donne une place claire aux environnements, réseaux, navigateurs, terminaux, applications associées et états d’exécution. Ce réglage s’applique uniquement à Envara et ne change pas l’apparence de votre ordinateur. Les actions courantes sont directement accessibles, les réglages détaillés se trouvent dans les options avancées et neuf langues d’interface vous permettent de commencer dans la vôtre.

## Que pouvez-vous faire avec Envara ?

| Usage | Ce qu’Envara vous aide à organiser |
| --- | --- |
| Développer plusieurs projets | Dossiers de projet, configuration et historique du terminal, données de navigation et réseau choisi |
| Travailler avec plusieurs comptes | Données de navigation et données applicatives distinctes par environnement pour limiter les mélanges de contextes |
| Tester des sites pour différentes régions | Choix et vérification de la sortie réseau, puis réglage de la région, de la langue et du fuseau horaire du navigateur |
| Développer avec l’IA et automatiser le navigateur | Outils exécutés dans l’environnement choisi, accès aux interfaces du navigateur et sessions Claude dédiées |
| Sauvegarder et transférer un environnement de travail | Export chiffré d’un navigateur, d’un profil de terminal ou d’une application, puis restauration dans un nouvel environnement |

**Un bureau local, un contexte de travail commun, plusieurs façons d’utiliser vos outils.** Vous avancez dans votre travail ; Envara vous aide à en organiser l’environnement.

## Téléchargement et installation

Téléchargez le paquet DMG ou ZIP pour **macOS Apple Silicon (arm64)** sur [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest). Ouvrez le DMG, puis faites glisser Envara dans le dossier « Applications ». Les fichiers de sommes de contrôle et les notes de version accompagnent la publication.

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

## Isolation et vie privée

Envara privilégie un réseau maîtrisé, des données distinctes et des mécanismes de confidentialité auditables. Ces quelques limites vous aident à l’utiliser en fonction de ses capacités réelles :

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

Le développement a entraîné des coûts importants d’utilisation de l’IA. Si Envara vous est utile, vous pouvez le soutenir librement : [USDT](../SUPPORT.md#usdt) · [USDC](../SUPPORT.md#usdc) · [Binance](../SUPPORT.md#binance). Les étoiles, signalements de problèmes, traductions et contributions de code sont également les bienvenus.

[Guide d’utilisation détaillé (en chinois simplifié)](../user-guide.md)
