<p align="center"><img src="../../build/icon.png" width="88" alt="Envara" /></p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Varios entornos. Un espacio de trabajo.</strong></p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="Licencia MIT del código original" /></a>
  <a href="../verification.md"><img src="https://img.shields.io/badge/0.5.0-local_candidate-475569" alt="Versión candidata local 0.5.0" /></a>
</p>
<p align="center"><a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <strong>Español</strong> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a></p>

![Envara nativo en chino](../media/workspace-zh-CN.png)

*Electron nativo en chino con red sintética; no demuestra salida real ni enrutamiento de aplicaciones. [Captura nativa anterior](../envara-workspace-0.5.png).*

## Tu espacio local

Envara reúne entornos BrowseForge en una aplicación de escritorio: **Entornos → Salida de red → Navegador → Terminal → Aplicaciones vinculadas → Monitor de ejecución**. Los controles detallados están en Avanzado.

- **Entornos:** datos del navegador separados, grupos, etiquetas, clonación e intercambio de configuración.
- **Redes:** HTTP, HTTPS, SOCKS5 y AnyTLS integrado; detección autenticada de salida, región aproximada y zona horaria, sin configurar Clash por separado.
- **Navegadores:** CloakBrowser / Chromium, Camoufox / Firefox y BrowseForge Chromium experimental.
- **Terminales:** PTY locales reales, carpeta elegida, tamaño ajustable, ventanas independientes y varias sesiones. Duplicar crea un proceso nuevo sin repetir comandos.
- **Aplicaciones:** vinculación de software local. El inicio protegido se rechaza hasta autorizar y verificar el adaptador del sistema.

Navegador y terminal comparten red y zona horaria; configuración e historial de herramientas separados por entorno.

## Elige tu idioma

La interfaz candidata admite chino simplificado, chino tradicional, inglés, japonés, coreano, español, francés, alemán y portugués de Brasil. Elige el idioma al iniciar Envara y cámbialo después en Ajustes. El idioma de la interfaz no modifica el idioma del navegador, la red, la zona horaria, la carpeta ni la salida del terminal.

![Selección inicial de idioma](../media/first-launch.png)

*Primer inicio nativo en inglés. Selección, persistencia y sincronización de ventanas de terminal verificadas por separado.*

## Disponibilidad y límites

**0.5.0 es una versión candidata de desarrollo, sin descarga pública definitiva.** Se comparte el progreso del código fuente; los instaladores siguen en borrador y las versiones automáticas permanecen desactivadas. El inicio y la limpieza de Notion no están validados. Consulte el [informe de diagnóstico actual](../notion-launch-handoff-20261010.md).

macOS Apple Silicon es prioritario, con pruebas nativas por versión de navegadores, AnyTLS y PTY. Paquete sin firma ni notarización. Windows ofrece código y compilaciones pendientes de pruebas reales; macOS Intel y Linux también siguen sin validar.

**El enrutamiento forzado completo de aplicaciones no está listo en ninguna plataforma.** Mac usa ahora un backend de PF, grupos de procesos y utun propios, conectado al nodo autenticado que administra Envara. Esta vía requiere autorización del administrador local, sin exigir una cuenta Apple Developer. El DNS independiente, la protección ante fallos y la validación con aplicaciones reales siguen pendientes; Notion no se ha ejecutado protegido. Consulta [los límites](../application-routing-options.md) y [las pruebas](../verification.md).

Las reglas no eliminan todo seguimiento. La configuración no es un sandbox; la ubicación IP estima una región, no un domicilio, ni garantiza evitar suspensiones.

## Desarrollo

Necesitas Node.js 24 LTS o 22.12+, npm, Go 1.25+ y herramientas de compilación de la plataforma.

```bash
npm ci
npm run desktop
```

La preparación inicial requiere internet; los motores se instalan desde fuentes oficiales. El paquete incluye dependencias: el usuario no necesita Go ni Node.js.

```bash
npm test
npm run build
npm run test:sites
```

La vista web muestra la interfaz; las operaciones nativas requieren la aplicación de escritorio. [Guía de contribución](../../CONTRIBUTING.md).

## Información y apoyo

[Funciones y comparación con BrowseForge](../capability-matrix.md) · [Arquitectura](../architecture.md) · [Pruebas](../verification.md) · [Incidencias](https://github.com/ink-scholar/Envara/issues)

Estrellas, comentarios, traducciones y contribuciones ayudan. [Apoyo económico](../SUPPORT.md) voluntario; pagos todavía desactivados.

## Licencia

Envara y BrowseForge conservan sus licencias MIT separadas. El núcleo independiente Mihomo mantiene GPLv3 y el código correspondiente. Los navegadores tienen licencias propias; la Binary License de CloakBrowser no está incluida en MIT. [LICENSE](../../LICENSE) · [Origen BrowseForge](../../third_party/browseforge/ENVARA_UPSTREAM.md) · [Código del proxy](../../third_party/proxy-core/SOURCE.md) · [Avisos de terceros](../../THIRD_PARTY_NOTICES.md).
