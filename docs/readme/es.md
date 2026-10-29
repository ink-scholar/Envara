<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Un entorno propio para cada flujo de trabajo.</strong><br />Un entorno. Tu navegador, terminal y aplicaciones.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="Licencia del código original: MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/github/v/release/ink-scholar/Envara?color=475569" alt="Última versión" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <strong>Español</strong> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">Descargar para macOS</a> · <a href="../user-guide.md">Guía de uso</a> · <a href="../capability-matrix.md">Todas las funciones</a> · <a href="../SUPPORT.md">Apoyar el proyecto</a>
</p>

**Organiza tu navegador, terminal y aplicaciones de escritorio en entornos de trabajo separados.**

Envara es un espacio de trabajo local y de código abierto. Guarda por separado las redes, los datos del navegador y los ajustes de las herramientas para distintos proyectos, cuentas o regiones. Elige un entorno, investiga en el navegador, escribe código o abre una aplicación y retoma el trabajo donde lo dejaste.

![Espacio de trabajo de Envara con datos de ejemplo sintéticos](../media/workspace-zh-CN.png)

## Un espacio para todo tu flujo de trabajo

| Función | Qué puedes hacer |
| --- | --- |
| 🌐 Entornos de red | Usa HTTP / HTTPS / SOCKS5 / AnyTLS, comprueba la salida de red con autenticación y confirma la región y la zona horaria; AnyTLS no necesita una instalación aparte de Clash |
| 🧭 Navegadores separados | Elige CloakBrowser, Camoufox o BrowseForge Chromium, de carácter experimental; guarda los datos por separado y conserva la identidad guardada al volver a abrir el navegador |
| ⌨️ Terminales nativos | Elige una carpeta de proyecto, abre varias sesiones, ajusta el panel o usa una ventana independiente; conserva la configuración y el historial del entorno. Cada conexión SSH guardada en macOS puede usar la red del equipo o la ruta de un entorno configurado |
| 🧩 Aplicaciones vinculadas | Vincula aplicaciones Chromium / Electron compatibles a un entorno, con datos separados y controles para iniciarlas y detenerlas |
| 🤖 Claude Code | Instálalo y actualízalo dentro de un entorno, gestiona perfiles de inicio de sesión con nombre y vincula el navegador elegido para ese entorno |
| 🔗 Enlaces y automatización | Abre los enlaces en el navegador elegido y usa las interfaces REST / MCP / Playwright del navegador |
| 📦 Migración cifrada | Exporta un navegador, el perfil de terminal seleccionado o una aplicación individual con cifrado por contraseña; importa los datos en un entorno nuevo |
| 🗂️ Gestión del espacio de trabajo | Agrupa, busca y duplica entornos; consulta su estado de ejecución en una interfaz de tres columnas, con navegación plegable, nueve idiomas y apariencia clara, oscura o del sistema |

## Sigue trabajando con tus herramientas habituales

Investiga en el navegador, escribe código en un terminal y abre las aplicaciones de escritorio que necesites. Tu entorno reúne la configuración de red y los datos de ese trabajo. Conéctate a servidores remotos desde el terminal y elige una ruta para cada conexión SSH guardada. Consulta la [guía de SSH](../claude-code-sessions.md#ssh-through-the-environment-route) para configurarlas.

Claude Code es una de las integraciones del flujo de trabajo del terminal. Cada entorno instala la **CLI oficial sin modificaciones**, mantiene separados los perfiles de inicio de sesión con nombre y vincula el navegador elegido para ese entorno. Empieza en el shell y escribe `claude` cuando quieras usarlo. Tú decides el modelo, las opciones para reanudar sesiones y los permisos. Consulta la [guía de Claude Code](../claude-code-sessions.md).

El aislamiento de entornos ayuda a reducir las mezclas entre configuraciones de red y de cuentas; no garantiza evitar las restricciones de los servicios ni ofrece anonimato completo. Consulta las [funciones y límites](../capability-matrix.md) para conocer las aplicaciones compatibles, la autorización del sistema y las implicaciones del sandbox. Detener o desvincular una aplicación conserva sus datos de inicio de sesión.

## Primeros pasos

Descarga el DMG o ZIP para **macOS Apple Silicon (arm64)** y las sumas de verificación SHA-256 desde [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest). La [guía de uso](../user-guide.md) explica los pasos de instalación y la información sobre la firma.

1. **Elige una red.** Añade una configuración de red, comprueba su salida real y confirma la región y la zona horaria.
2. **Crea un entorno.** Elige un navegador y dale a tu proyecto o cuenta su propio espacio de trabajo.
3. **Empieza a trabajar.** Abre el navegador, elige el directorio de trabajo del terminal o vincula una aplicación de escritorio compatible.

Vuelve al mismo entorno para reutilizar los datos del navegador, los ajustes del terminal y los datos de las aplicaciones, sin tener que configurarlo todo de nuevo.

[Guía de uso](../user-guide.md) · [Todas las funciones](../capability-matrix.md) · [Notas de versión](https://github.com/ink-scholar/Envara/releases) · [Desarrollo y contribuciones](../../CONTRIBUTING.md) · [Informar de un problema](https://github.com/ink-scholar/Envara/issues)

## Código abierto y apoyo

El código original de Envara utiliza la licencia [MIT](../../LICENSE). BrowseForge conserva su [licencia MIT](../../third_party/browseforge/LICENSE) y el [registro de la versión fijada](../../third_party/browseforge/ENVARA_UPSTREAM.md). El núcleo independiente Mihomo conserva la licencia [GPLv3](../../third_party/proxy-core/LICENSE) y el [código fuente correspondiente](../../third_party/proxy-core/SOURCE.md). Los binarios de los navegadores están sujetos a sus propias licencias y no están incluidos en la licencia MIT de la aplicación. Consulta los [avisos de terceros](../../THIRD_PARTY_NOTICES.md) para conocer todas las atribuciones.

El desarrollo ha supuesto un gasto considerable en servicios de IA. Si Envara te resulta útil, puedes apoyarlo de forma voluntaria: [USDT](../SUPPORT.md#usdt) · [USDC](../SUPPORT.md#usdc) · [Binance](../SUPPORT.md#binance). Las estrellas, los informes de problemas, las traducciones y las contribuciones de código también ayudan.

[Guía de uso detallada (en chino simplificado)](../user-guide.md)
