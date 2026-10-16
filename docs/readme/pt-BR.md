<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Vários ambientes, um só espaço de trabalho.</strong><br />Um espaço de trabalho local para navegadores, terminais e contextos de rede.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="Licença do código original: MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-0.5.23-475569" alt="Envara 0.5.23" /></a>
  <a href="en.md"><img src="https://img.shields.io/badge/README-9_languages-6366f1" alt="README em 9 idiomas" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <strong>Português (Brasil)</strong>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">Baixar para macOS</a> · <a href="../capability-matrix.md">Recursos e limites</a> · <a href="../../CONTRIBUTING.md">Contribuir</a> · <a href="../SUPPORT.md">Apoiar o projeto</a>
</p>

![Espaço de trabalho nativo do Envara em chinês](../media/workspace-zh-CN.png)

<p align="center"><sub>Espaço de trabalho nativo em Electron. A captura usa dados de exemplo sintéticos.</sub></p>

## Um ambiente, um contexto de trabalho

O Envara reúne navegador, saída de rede, diretório de trabalho e ferramentas de linha de comando em um único espaço de trabalho local. Cada ambiente mantém seus próprios dados de navegação, configurações de ferramentas e histórico; ambientes diferentes podem usar redes diferentes.

| Área de trabalho | Recursos |
| --- | --- |
| Ambientes | Criação, clonagem, agrupamento e busca; diretório de trabalho e contexto de rede salvos |
| Saída de rede | HTTP, HTTPS, SOCKS5 e AnyTLS integrado; detecção da saída real, da região aproximada e do fuso horário |
| Navegadores | CloakBrowser / Chromium, Camoufox / Firefox e BrowseForge Chromium experimental; configuração automática e ajustes avançados |
| Terminais | PTYs reais, seleção de diretório, várias sessões, painel redimensionável e janelas independentes |
| Claude Code | Instalação independente da CLI oficial por ambiente, perfis de login com nome e ferramentas MCP vinculadas ao navegador do ambiente |
| Aplicativos vinculados | Vinculação de aplicativos Chromium/Electron compatíveis a um ambiente, gerenciamento das instâncias e dados de aplicativo separados |
| Migração de dados | Exportação separada dos dados do navegador, do perfil de login selecionado do terminal ou de um aplicativo vinculado, com criptografia por senha |

O Envara gerencia o núcleo AnyTLS integrado, sem precisar configurar o Clash separadamente. Navegadores, terminais e aplicativos vinculados reutilizam a localização e o fuso horário de rede já confirmados. As configurações de localização não alteram o fuso horário do sistema; a geolocalização por IP indica apenas uma região aproximada.

Duplicar um terminal cria um processo novo e independente, sem repetir comandos. As sessões do Claude Code começam em um shell, onde você digita `claude`; é possível baixar uma instalação oficial independente ou inicializá-la a partir de um programa nativo já disponível no computador. O Envara não modifica a CLI oficial, não copia as contas do sistema hospedeiro nem ativa por padrão o desvio de permissões. [Saiba mais sobre as sessões do Claude Code](../claude-code-sessions.md).

Antes de iniciar um aplicativo vinculado, o Envara verifica a compatibilidade, as instâncias existentes e o estado dos componentes de roteamento. Se os requisitos não forem atendidos, a inicialização é recusada explicitamente. Parar um aplicativo, remover seu vínculo ou sair do Envara preserva os dados de login; eles só são apagados quando você solicita explicitamente a exclusão desses dados ou do ambiente. Veja [Aplicativos vinculados](../application-routing-options.md).

## Download e instalação

Baixe o DMG ou ZIP para **macOS Apple Silicon (arm64)** em [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest). Abra o DMG e arraste o Envara para Aplicativos. Os arquivos de verificação e as notas da versão acompanham a publicação.

**Os pacotes atuais para macOS não têm assinatura Apple Developer ID nem notarização.** As verificações de segurança do macOS podem ser aplicadas na primeira abertura; confirme que o download veio deste repositório e confira a soma de verificação. O Envara não desativa automaticamente as verificações de segurança do sistema. O componente de roteamento do sistema para aplicativos vinculados exige autorização separada do administrador; iniciar o navegador ou o espaço de trabalho comum não o instala automaticamente.

| Plataforma | Escopo da publicação |
| --- | --- |
| macOS Apple Silicon | Esta publicação oferece DMG, ZIP e arquivos de somas de verificação SHA-256 |
| macOS Intel | O código-fonte para a plataforma é mantido; não há pacotes verificados disponíveis |
| Windows / Linux | O código-fonte correspondente é mantido; esta publicação não oferece pacotes. Consulte a matriz de recursos para conhecer o escopo dos testes em máquinas reais |

Os motores de navegador são instalados pelo usuário dentro do aplicativo e seguem suas próprias licenças. O aplicativo inclui as dependências de execução do desktop; não é preciso instalar Node.js ou Go separadamente.

## Comece no seu idioma

Há suporte a **简体中文、繁體中文、English、日本語、한국어、Español、Français、Deutsch、Português (Brasil)**. Na primeira abertura, o Envara recomenda o idioma do sistema e pede sua confirmação. Depois, você pode alterá-lo nas Configurações.

![Seleção de idioma na primeira abertura](../media/first-launch.png)

<p align="center"><sub>Seletor nativo de idioma da primeira abertura.</sub></p>

O idioma da interface é independente do idioma do ambiente do navegador. Alterar o idioma dos menus não modifica a rede, o fuso horário ou o diretório de trabalho existentes.

## Limites dos recursos

- O isolamento de configurações e dados não equivale a um usuário separado do sistema operacional, um Keychain separado ou hardware virtual. A configuração da impressão digital do navegador não altera a identidade de hardware dos aplicativos nativos.
- As rotas de terminal compatíveis no macOS usam uma barreira de rede; plataformas e rotas que ainda não têm essa barreira não devem ser consideradas isolamento forçado. Veja o escopo detalhado na [matriz de recursos](../capability-matrix.md).
- Quando os aplicativos vinculados usam a barreira de rede externa, o sandbox interno do Chromium/Electron é desativado. O estado dos componentes nativos, os motores compatíveis e o escopo dos testes reais são documentados separadamente; conseguir identificar um aplicativo não significa que todos os aplicativos tenham sido validados.
- As exportações não incluem Keychain, os programas, caches ou arquivos temporários. Algumas contas ainda podem exigir um novo login ao trocar de computador; uma restauração bem-sucedida na mesma máquina não garante que o login funcione em outra.
- O bloqueio de rastreamento cobre apenas as regras implementadas e os controles compatíveis com o motor. O isolamento de rede, contas e configurações não garante evitar restrições dos serviços nem elimina todo o rastreamento.

[Notas de verificação](../verification.md) · [Arquitetura](../architecture.md) · [Contexto de rede](../network-context.md) · [Dispositivo e idioma do navegador](../browser-device-profiles.md)

## Desenvolvimento a partir do código-fonte

São necessários Node.js 24 LTS (ou 22.12+), npm, Go 1.25 e as ferramentas de compilação da plataforma de destino. Os componentes nativos do macOS exigem Xcode Command Line Tools.

```bash
npm ci
npm run desktop
```

A preparação inicial baixa versões fixas das dependências de compilação. Para a prévia de desenvolvimento e as verificações:

```bash
npm run dev
npm test
npm run build
npm run test:sites
```

A prévia web serve apenas para desenvolver a interface; navegadores reais, PTYs e roteamento do sistema exigem o aplicativo desktop. Veja as instruções de compilação e publicação no [guia de contribuição](../../CONTRIBUTING.md) e no [processo de publicação](../releasing.md). Os fluxos automáticos de compilação e publicação do GitHub permanecem desativados; enviar código-fonte não dispara compilações.

## Código aberto e apoio

O código original do Envara usa a licença [MIT](../../LICENSE). O BrowseForge mantém sua [licença MIT](../../third_party/browseforge/LICENSE) e o [registro da versão fixada](../../third_party/browseforge/ENVARA_UPSTREAM.md). O núcleo independente Mihomo mantém a licença [GPLv3](../../third_party/proxy-core/LICENSE) e o [código-fonte correspondente](../../third_party/proxy-core/SOURCE.md). Os binários dos navegadores seguem suas próprias licenças e não estão incluídos na licença MIT do aplicativo. Veja todas as atribuições nos [avisos de terceiros](../../THIRD_PARTY_NOTICES.md).

Você pode [relatar problemas](https://github.com/ink-scholar/Envara/issues), contribuir com código, melhorar traduções ou dar uma estrela ao projeto. Todo apoio é voluntário; os canais de doação ainda não estão habilitados. [Apoiar o projeto](../SUPPORT.md)
