<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Um espaço próprio para cada fluxo de trabalho.</strong><br />Um ambiente. Seu navegador, terminal e aplicativos.</p>
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

**Abra o navegador, execute comandos e conecte aplicativos desktop em um ambiente que acompanha todo o seu trabalho.**

O Envara é um espaço de trabalho desktop local e de código aberto que reúne saídas de rede, perfis de navegador, ferramentas de terminal e aplicativos desktop compatíveis. Cada ambiente mantém suas próprias configurações e dados. Crie contextos separados para projetos, contas ou regiões e gerencie todos pela mesma interface.

![Espaço de trabalho nativo do Envara em chinês](../media/workspace-zh-CN.png)

<p align="center"><sub>Espaço de trabalho nativo em Electron. A captura usa dados de exemplo sintéticos.</sub></p>

## O que torna o Envara diferente: um fluxo de trabalho conectado

Pesquisar no navegador, escrever código no terminal e trabalhar em aplicativos desktop costuma fazer parte do mesmo projeto. O Envara permite que essas ferramentas reutilizem um contexto de rede já confirmado, preservando separadamente os dados de navegação, as configurações das ferramentas e os dados dos aplicativos de que você precisa para continuar.

**Configure a rede uma vez, conecte as ferramentas de que precisa e retome o trabalho na próxima vez.** Essa é a ideia central do Envara: fazer dos ambientes independentes uma parte do seu dia a dia.

### 🌐 Cada ambiente tem seu próprio navegador

Escolha entre **CloakBrowser / Chromium, Camoufox / Firefox** e o **BrowseForge Chromium** experimental. Dados de navegação separados, sessões persistentes, grupos de ambientes, busca e clonagem de configurações ajudam a manter cada contexto de trabalho em seu lugar. Clonar uma configuração cria um novo ambiente; os dados de login permanecem no original.

A configuração da impressão digital fica, por padrão, a cargo do motor escolhido. Também há ajustes avançados de dispositivo, idioma e fuso horário. Com regras auditáveis de bloqueio de rastreamento, os controles de privacidade podem ser examinados. Os recursos disponíveis variam conforme o motor. [Navegador e configurações de dispositivo](../browser-device-profiles.md)

### 🧭 Rede, localização e fuso horário: configure uma vez e reutilize

Há suporte a **HTTP, HTTPS, SOCKS5 e AnyTLS**. O AnyTLS usa um núcleo de proxy incluído no aplicativo e gerenciado pelo Envara, sem precisar configurar o Clash separadamente.

Ao criar um ambiente de rede, o Envara verifica a **saída real com autenticação** antes de você confirmar a região e o fuso horário. O navegador, o terminal e os aplicativos vinculados compatíveis reutilizam esse contexto. Para simular uma localização, você pode escolher coordenadas com a ajuda do Google Maps; a saída medida e a localização simulada são exibidas separadamente. As configurações do ambiente não alteram o fuso horário do sistema hospedeiro. [Ambientes de rede](../network-context.md)

### ⌨️ O terminal também tem seu próprio ambiente de trabalho

Ao criar uma sessão, escolha a **rede, o navegador para abrir links e a pasta do projeto**. As configurações e o histórico são salvos por ambiente. PTYs reais, várias sessões, altura ajustável, expansão na área de trabalho e janelas independentes tornam a linha de comando uma parte prática do espaço de trabalho.

Duplicar um terminal abre um novo processo ocioso no mesmo contexto. Você pode fechar o painel e voltar à sessão depois. As rotas de loopback gerenciadas compatíveis no macOS usam uma barreira de rede: programas sem suporte a proxy não conseguem se conectar, evitando conexões diretas silenciosas. A pasta do projeto continua no local original, para que você possa seguir usando suas ferramentas habituais.

### 🧩 Integre aplicativos desktop ao mesmo fluxo de trabalho

Escolha um ambiente e um navegador para links para os **aplicativos Chromium / Electron compatíveis** e gerencie sua inicialização, parada e dados. O Envara verifica a identidade do aplicativo, a compatibilidade, as instâncias existentes e os componentes nativos de roteamento. A inicialização só é permitida quando os requisitos são atendidos.

Parar um aplicativo, remover seu vínculo ou sair do Envara preserva os dados de login e o conteúdo offline, para você continuar depois. Quando quiser limpar esses dados, escolha explicitamente a exclusão. O roteamento nativo exige autorização do sistema; a compatibilidade com um motor não significa que todos os aplicativos tenham sido validados. [Escopo dos aplicativos vinculados](../application-routing-options.md)

### 🔗 Da linha de comando à página de login, o contexto continua

Defina um navegador para os links do ambiente, para que as páginas abertas pelo terminal usem o ambiente correspondente. No macOS, o roteamento de links do sistema também pode tratar os links que aplicativos gerenciados enviam ao sistema. Links sem relação com os ambientes continuam no navegador padrão anterior.

O roteamento de links do sistema exige sua confirmação em uma caixa de diálogo do macOS e pode ser desativado a qualquer momento. Se você escolher o navegador do sistema, a interface informa que o link será aberto fora do ambiente.

### 🤖 Um espaço de trabalho organizado para IA e automação

O backend do navegador oferece interfaces **REST, MCP e Playwright** para automatizar operações de página, formulários, cookies e capturas de tela, entre outros cenários. Consulte o escopo das interfaces na [matriz de recursos](../capability-matrix.md).

O Claude Code é uma dessas integrações: cada ambiente tem sua própria instalação da **CLI oficial, sem modificações**, perfis de login com nome e um broker MCP por sessão vinculado ao navegador do ambiente selecionado. Você entra primeiro no shell e inicia `claude` quando quiser. As opções de modelo, retomada de sessão e permissões ficam sob seu controle. [Sessões do Claude Code](../claude-code-sessions.md)

### 📦 Leve os dados escolhidos quando precisar migrar

Navegadores, terminais e aplicativos vinculados têm opções separadas de **exportação criptografada por senha**, para você escolher os dados de que precisa. A exportação do terminal inclui o perfil de login do Claude selecionado e as configurações e o histórico compartilhados do shell. A importação cria um novo ambiente e preserva o espaço de trabalho existente.

Os programas, caches, arquivos temporários e o Keychain não acompanham o pacote. Algumas contas ainda podem exigir um novo login em outro computador.

### 🗂️ Menos interrupções no gerenciamento do dia a dia

O espaço de trabalho escuro com três colunas organiza ambientes, redes, navegadores, terminais, aplicativos vinculados e o estado de execução. As ações mais usadas ficam à mão, e os detalhes de configuração ficam nas opções avançadas. Com nove idiomas de interface, você pode começar no idioma que conhece.

## O que você pode fazer com o Envara?

| Cenário | O que o Envara ajuda a organizar |
| --- | --- |
| Desenvolvimento de vários projetos | Diretórios dos projetos, configurações e histórico do terminal, dados de navegação e a rede escolhida |
| Trabalho com várias contas | Dados de navegação e de aplicativos separados por ambiente, para reduzir a mistura de contextos |
| Testes de páginas em diferentes regiões | Escolha da rede, verificação da saída real e configuração de região, idioma e fuso horário do navegador |
| Desenvolvimento com IA e automação do navegador | Ferramentas no ambiente escolhido, acesso às interfaces do navegador e sessões dedicadas do Claude |
| Backup e migração do ambiente de trabalho | Exportação criptografada por navegador, perfil do terminal ou aplicativo, com restauração em um novo ambiente |

**Um desktop local, um contexto de trabalho e várias ferramentas.** Você cuida do trabalho; o Envara ajuda a organizar o ambiente.

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

## Sobre isolamento e privacidade

O Envara prioriza redes sob seu controle, dados separados e mecanismos de privacidade auditáveis. Estes limites ajudam você a usá-lo de acordo com suas capacidades reais:

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
