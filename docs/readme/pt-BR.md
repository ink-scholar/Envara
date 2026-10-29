<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Um espaço próprio para cada fluxo de trabalho.</strong><br />Um ambiente. Seu navegador, terminal e aplicativos.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="Licença do código original: MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/github/v/release/ink-scholar/Envara?color=475569" alt="Versão mais recente" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <strong>Português (Brasil)</strong>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">Baixar para macOS</a> · <a href="../user-guide.md">Guia de uso</a> · <a href="../capability-matrix.md">Todos os recursos</a> · <a href="../SUPPORT.md">Apoiar o projeto</a>
</p>

**Organize seu navegador, terminal e aplicativos desktop em ambientes de trabalho separados.**

O Envara é um espaço de trabalho desktop local e de código aberto. Mantenha redes, dados de navegação e configurações de ferramentas separados para cada projeto, conta ou região. Escolha um ambiente, pesquise no navegador, escreva código ou abra um aplicativo e continue de onde parou.

![Espaço de trabalho do Envara com dados de exemplo sintéticos](../media/workspace-zh-CN.png)

## Um espaço para todo o fluxo de trabalho

| Recurso | O que você pode fazer |
| --- | --- |
| 🌐 Ambientes de rede | Usar HTTP / HTTPS / SOCKS5 / AnyTLS, verificar a saída de rede com autenticação e confirmar região e fuso horário; o AnyTLS dispensa a instalação separada do Clash |
| 🧭 Navegadores separados | Escolher CloakBrowser, Camoufox ou o experimental BrowseForge Chromium; manter os dados separados e reutilizar as identidades salvas ao reabrir |
| ⌨️ Terminais nativos | Escolher uma pasta de projeto, abrir várias sessões, redimensionar o painel ou usar uma janela independente; preservar configurações e histórico por ambiente. Cada conexão SSH salva no macOS pode usar a rede do computador ou a rota de um ambiente configurado |
| 🧩 Aplicativos vinculados | Vincular aplicativos Chromium / Electron compatíveis a um ambiente, com dados separados e controles para iniciar e parar |
| 🤖 Claude Code | Instalar e atualizar dentro de um ambiente, gerenciar perfis de login nomeados e vincular o navegador selecionado para o ambiente |
| 🔗 Links e automação | Abrir links no navegador escolhido e usar interfaces REST / MCP / Playwright para o navegador |
| 📦 Migração criptografada | Exportar um navegador, o perfil de terminal selecionado ou um aplicativo individual com criptografia por senha; importar para um novo ambiente |
| 🗂️ Gestão do espaço de trabalho | Agrupar, pesquisar e duplicar ambientes; acompanhar o estado de execução em um layout de três colunas, com navegação recolhível, nove idiomas e aparência clara, escura ou conforme o sistema |

## Continue trabalhando com as ferramentas que você conhece

Pesquise no navegador, escreva código no terminal e abra os aplicativos desktop de que precisa. Seu ambiente reúne as configurações de rede e os dados desse trabalho. Conecte-se a servidores remotos pelo terminal, com uma rota escolhida para cada conexão SSH salva. Consulte o [guia de SSH](../claude-code-sessions.md#ssh-through-the-environment-route) para configurar.

O Claude Code é uma das integrações do fluxo de trabalho no terminal. Cada ambiente instala a **CLI oficial sem modificações**, mantém os perfis de login nomeados separados e vincula o navegador escolhido para o ambiente. Comece no prompt do shell e digite `claude` quando quiser usá-lo. Você escolhe o modelo, as opções de retomada de sessão e as permissões. Consulte o [guia do Claude Code](../claude-code-sessions.md).

O isolamento de ambientes ajuda a evitar a mistura de configurações de rede e contas; ele não garante proteção contra restrições de serviços nem anonimato completo. Consulte [recursos e limites](../capability-matrix.md) para entender a compatibilidade dos aplicativos vinculados, a autorização do sistema e as implicações do sandbox. Parar ou desvincular um aplicativo preserva os dados de login.

## Comece a usar

Baixe o DMG ou ZIP para **macOS Apple Silicon (arm64)** e as somas de verificação SHA-256 em [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest). Consulte o [guia de uso](../user-guide.md) para ver as etapas de instalação e informações sobre a assinatura.

1. **Escolha uma rede.** Adicione uma configuração de rede, verifique a saída real e confirme a região e o fuso horário.
2. **Crie um ambiente.** Escolha um navegador e dê ao seu projeto ou conta um espaço de trabalho próprio.
3. **Comece a trabalhar.** Abra o navegador, escolha o diretório de trabalho do terminal ou vincule um aplicativo desktop compatível.

Volte ao mesmo ambiente para reutilizar os dados de navegação, as configurações do terminal e os dados dos aplicativos salvos, com menos ajustes a cada vez.

[Guia de uso](../user-guide.md) · [Todos os recursos](../capability-matrix.md) · [Notas de versão](https://github.com/ink-scholar/Envara/releases) · [Desenvolver e contribuir](../../CONTRIBUTING.md) · [Relatar um problema](https://github.com/ink-scholar/Envara/issues)

## Código aberto e apoio

O código original do Envara usa a licença [MIT](../../LICENSE). O BrowseForge mantém sua [licença MIT](../../third_party/browseforge/LICENSE) e o [registro da versão fixada](../../third_party/browseforge/ENVARA_UPSTREAM.md). O núcleo independente Mihomo mantém a licença [GPLv3](../../third_party/proxy-core/LICENSE) e o [código-fonte correspondente](../../third_party/proxy-core/SOURCE.md). Os binários dos navegadores seguem suas próprias licenças e não estão incluídos na licença MIT do aplicativo. Veja todas as atribuições nos [avisos de terceiros](../../THIRD_PARTY_NOTICES.md).

O desenvolvimento envolveu custos elevados de uso de IA. Se o Envara for útil para você, contribuições voluntárias são bem-vindas: [USDT](../SUPPORT.md#usdt) · [USDC](../SUPPORT.md#usdc) · [Binance](../SUPPORT.md#binance). Estrelas, relatos de problemas, traduções e contribuições de código também ajudam.

[Guia de uso detalhado (em chinês simplificado)](../user-guide.md)
