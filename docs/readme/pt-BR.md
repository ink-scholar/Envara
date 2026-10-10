<p align="center"><img src="../../build/icon.png" width="88" alt="Envara" /></p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Vários ambientes. Um espaço de trabalho.</strong></p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="Licença MIT do código original" /></a>
  <a href="../verification.md"><img src="https://img.shields.io/badge/0.5.0-local_candidate-475569" alt="Versão candidata local 0.5.0" /></a>
</p>
<p align="center"><a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <strong>Português (Brasil)</strong></p>

![Envara nativo em chinês](../media/workspace-zh-CN.png)

*Electron nativo em chinês com rede sintética; não comprova saída real ou roteamento de aplicativos. [Captura nativa anterior](../envara-workspace-0.5.png).*

## Seu espaço local

O Envara reúne ambientes do BrowseForge em um aplicativo desktop. A navegação segue **Ambientes → Saída de rede → Navegador → Terminal → Aplicativos vinculados → Monitor de execução**. Os controles detalhados ficam em Avançado.

- **Ambientes:** dados de navegação separados, grupos, etiquetas, clonagem e troca de configurações.
- **Redes:** HTTP, HTTPS, SOCKS5 e AnyTLS integrado; detecção autenticada da saída real, região aproximada e fuso horário, sem configurar o Clash separadamente.
- **Navegadores:** CloakBrowser / Chromium, Camoufox / Firefox e BrowseForge Chromium experimental.
- **Terminais:** PTYs locais reais, pasta escolhida, redimensionamento, janelas independentes e várias sessões. Duplicar cria um processo novo sem repetir comandos.
- **Aplicativos:** vínculo de software local ao ambiente. A inicialização protegida é recusada até autorizar e verificar o adaptador do sistema.

O navegador e o terminal compartilham rede e fuso do ambiente. Configurações de ferramentas e histórico são separados entre ambientes.

## Comece no seu idioma

A interface candidata oferece chinês simplificado e tradicional, inglês, japonês, coreano, espanhol, francês, alemão e português do Brasil. Escolha na primeira abertura e altere depois nas configurações. O idioma da interface não modifica idioma do navegador, rede, fuso, pasta nem saída do terminal.

![Escolha de idioma na primeira abertura](../media/first-launch.png)

*Primeira abertura nativa em inglês. Seleção, persistência e sincronização das janelas de terminal verificadas separadamente.*

## Disponibilidade e limites

**0.5.0 é uma versão candidata de desenvolvimento, sem download público definitivo.** O progresso mais recente do código é compartilhado; os instaladores permanecem como rascunhos e as versões automáticas continuam desativadas. A inicialização e a limpeza do Notion ainda não foram validadas. Consulte o [diagnóstico atual](../notion-launch-handoff-20261010.md).

macOS Apple Silicon é prioritário, com evidências nativas por versão para navegadores, AnyTLS e PTY. Pacote sem assinatura ou notarização. Windows oferece código e compilações pendentes de testes reais; macOS Intel e Linux também não foram validados.

**O roteamento forçado completo de aplicativos não está pronto em nenhuma plataforma.** O Mac agora usa um backend de PF com grupos de processos e interfaces utun próprios, conectado ao nó autenticado gerenciado pelo Envara. Essa opção exige autorização do administrador local, sem exigir uma conta Apple Developer. DNS independente, proteção contra falhas e validação com aplicativos reais ainda estão pendentes; o Notion não foi executado protegido. Veja [os limites](../application-routing-options.md) e [as verificações](../verification.md).

As regras não removem todo rastreamento. A configuração não é um sandbox; o IP estima uma região, não uma residência, nem garante evitar suspensões.

## Desenvolvimento

Requer Node.js 24 LTS ou 22.12+, npm, Go 1.25+ e ferramentas de compilação da plataforma.

```bash
npm ci
npm run desktop
```

A preparação inicial precisa de internet; os motores vêm de fontes oficiais. O pacote inclui dependências: usuários não precisam de Go ou Node.js.

```bash
npm test
npm run build
npm run test:sites
```

A prévia web mostra a interface; operações nativas exigem o app desktop. [Guia de contribuição](../../CONTRIBUTING.md).

## Saiba mais e apoie

[Recursos e comparação com BrowseForge](../capability-matrix.md) · [Arquitetura](../architecture.md) · [Verificações](../verification.md) · [Problemas](https://github.com/ink-scholar/Envara/issues)

Estrelas, comentários, traduções e contribuições ajudam. [Apoio financeiro](../SUPPORT.md) voluntário; pagamentos desativados.

## Licença

Envara e BrowseForge mantêm suas licenças MIT separadas. O núcleo independente Mihomo conserva GPLv3 e o código correspondente. Binários dos navegadores têm licenças próprias; a Binary License do CloakBrowser não é a MIT do aplicativo. [LICENSE](../../LICENSE) · [Origem BrowseForge](../../third_party/browseforge/ENVARA_UPSTREAM.md) · [Código do proxy](../../third_party/proxy-core/SOURCE.md) · [Avisos de terceiros](../../THIRD_PARTY_NOTICES.md).
