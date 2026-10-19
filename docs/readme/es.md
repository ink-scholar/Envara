<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Un entorno propio para cada flujo de trabajo.</strong><br />Un entorno. Tu navegador, terminal y aplicaciones.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="Licencia del código original: MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-1.0.3-475569" alt="Envara 1.0.3" /></a>
  <a href="en.md"><img src="https://img.shields.io/badge/README-9_languages-6366f1" alt="README en 9 idiomas" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <strong>Español</strong> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">Descargar para macOS</a> · <a href="../capability-matrix.md">Funciones y límites</a> · <a href="../../CONTRIBUTING.md">Contribuir</a> · <a href="../SUPPORT.md">Apoyar el proyecto</a>
</p>

**Navega, ejecuta comandos y conecta aplicaciones de escritorio: un mismo entorno para todo tu flujo de trabajo.**

Envara es un espacio de trabajo local y de código abierto que reúne la salida de red, los perfiles del navegador, las herramientas de terminal y las aplicaciones de escritorio compatibles. Cada entorno conserva sus propios ajustes y datos. Crea contextos distintos para tus proyectos, cuentas o regiones y gestiónalos desde una sola interfaz.

![Espacio de trabajo nativo de Envara en chino](../media/workspace-zh-CN.png)

<p align="center"><sub>Espacio de trabajo nativo de Electron. La captura utiliza datos de ejemplo sintéticos.</sub></p>

## Lo que distingue a Envara: conectar todo el flujo de trabajo

Consultar información en el navegador, escribir código en el terminal y trabajar en una aplicación de escritorio suelen ser partes del mismo proyecto. Envara les permite reutilizar un contexto de red ya confirmado y conservar por separado los datos de navegación, la configuración de herramientas y los datos de aplicación que necesitas para continuar.

**Elige la red una vez, conecta tus herramientas y retoma el trabajo cuando vuelvas.** Esa es la idea de Envara: hacer de los entornos independientes una forma práctica de trabajar a diario.

### 🌐 Un navegador propio para cada entorno

Elige entre **CloakBrowser / Chromium, Camoufox / Firefox** y **BrowseForge Chromium**, de carácter experimental. Los datos de navegación independientes, las sesiones persistentes, los grupos, la búsqueda y la clonación de configuraciones ayudan a mantener cada contexto en su sitio. Clonar una configuración crea un entorno nuevo; los datos de inicio de sesión originales permanecen en el entorno de origen.

El motor elegido gestiona la huella del navegador de forma predeterminada. También hay ajustes avanzados de dispositivo, idioma y zona horaria, junto con reglas de bloqueo de seguimiento que se pueden auditar. El alcance concreto depende del motor. [Navegadores y ajustes de dispositivo](../browser-device-profiles.md)

### 🧭 Red, ubicación y zona horaria: configúralas una vez y reutilízalas

Se admiten **HTTP, HTTPS, SOCKS5 y AnyTLS**. AnyTLS utiliza un núcleo proxy incluido y administrado por Envara, sin necesidad de configurar Clash por separado.

Al crear un entorno de red, Envara mide la **salida real de la conexión autenticada** para que confirmes la región y la zona horaria. El navegador, el terminal y las aplicaciones vinculadas compatibles reutilizan ese contexto. Si necesitas simular una ubicación, puedes elegir coordenadas con ayuda de Google Maps; la salida medida y la ubicación simulada se muestran por separado. Los ajustes del entorno no cambian la zona horaria del sistema anfitrión. [Entornos de red](../network-context.md)

### ⌨️ Un contexto de trabajo también para el terminal

Al crear una sesión, elige la **red, el navegador para los enlaces y la carpeta del proyecto**. La configuración y el historial se guardan por entorno. Los PTY reales, las sesiones múltiples, la altura ajustable, la expansión al área de trabajo y las ventanas independientes integran la línea de comandos en tu día a día.

En macOS, puedes usar [conexiones SSH controladas](../claude-code-sessions.md) a través del proxy seleccionado, manteniendo las claves privadas en tu Mac.

Duplicar un terminal abre un nuevo proceso inactivo con el mismo contexto. Cerrar el panel no termina la sesión: puedes volver a ella después. Las rutas de bucle local administradas y compatibles con macOS utilizan una barrera de red; los programas que no admiten el proxy no podrán conectarse, evitando conexiones directas silenciosas. La carpeta del proyecto permanece en su ubicación original para que sigas usando tus herramientas habituales.

### 🧩 Incorpora aplicaciones de escritorio al mismo flujo

Elige un entorno y un navegador para los enlaces de las **aplicaciones Chromium / Electron compatibles**, y gestiona su inicio, detención y datos desde un mismo lugar. Antes de permitir el inicio, Envara comprueba la identidad del programa, su compatibilidad, las instancias existentes y el componente nativo de enrutamiento.

Detener una aplicación, desvincularla o salir de Envara conserva los datos de inicio de sesión y el contenido sin conexión para la próxima vez. Cuando quieras borrarlos, elige expresamente esa acción. El enrutamiento nativo requiere autorización del sistema; reconocer un motor compatible no significa que todas sus aplicaciones hayan sido validadas. [Alcance de las aplicaciones vinculadas](../application-routing-options.md)

### 🔗 De la línea de comandos a la página de inicio de sesión, sin perder el contexto

Asigna un navegador de enlaces al entorno para abrir en él las páginas solicitadas desde el terminal. En macOS, el enrutamiento de enlaces del sistema también puede gestionar los que una aplicación administrada entrega al sistema. Los enlaces ajenos al entorno siguen abriéndose en el navegador predeterminado anterior.

El enrutamiento de enlaces del sistema requiere tu confirmación en el diálogo de macOS y se puede desactivar cuando quieras. Si eliges expresamente el navegador del sistema, la interfaz indica que el enlace saldrá del entorno.

### 🤖 Un espacio organizado para la IA y la automatización

El servicio de navegador ofrece interfaces **REST, MCP y Playwright** para automatizar páginas, formularios, cookies y capturas, entre otras operaciones. Consulta su alcance en la [matriz de funciones](../capability-matrix.md).

Claude Code es una de las integraciones disponibles: cada entorno tiene su propia instalación de la **CLI oficial sin modificar**, perfiles de inicio de sesión con nombre y un broker MCP por sesión vinculado al navegador elegido. Primero entras en un shell y tú decides cuándo ejecutar `claude`; también eliges el modelo y las opciones de reanudación y permisos. [Sesiones de Claude Code](../claude-code-sessions.md)

### 📦 Llévate los datos que necesitas

El navegador, el terminal y las aplicaciones vinculadas tienen sus propias opciones de **exportación cifrada con contraseña**. Elige qué datos llevarte. La exportación del terminal incluye el perfil de Claude seleccionado y la configuración y el historial compartidos del shell. La importación crea un entorno nuevo y conserva el espacio de trabajo existente.

Los programas, las cachés, los archivos temporales y Keychain no se incluyen en el archivo. Algunas cuentas pueden requerir un nuevo inicio de sesión al cambiar de equipo.

### 🗂️ Menos interrupciones en la gestión diaria

La interfaz de tres columnas ofrece los modos claro, oscuro y según el sistema, y da un lugar claro a los entornos, las redes, el navegador, el terminal, las aplicaciones vinculadas y su estado de ejecución. El ajuste de apariencia solo se aplica a Envara, sin cambiar la apariencia del equipo. Las acciones habituales están a mano; los detalles se agrupan en opciones avanzadas. Con nueve idiomas de interfaz, puedes empezar en el que te resulte más familiar.

## ¿Qué puedes hacer con Envara?

| Escenario | Lo que Envara te ayuda a organizar |
| --- | --- |
| Desarrollo de varios proyectos | Directorios, configuración e historial del terminal, datos del navegador y la red elegida |
| Trabajo con varias cuentas | Datos de navegación y aplicaciones separados por entorno, para reducir la mezcla de contextos |
| Verificación web entre regiones | Elegir la salida de red, comprobar la salida real y configurar la región, el idioma y la zona horaria del navegador |
| Desarrollo con IA y automatización del navegador | Ejecutar herramientas en el entorno elegido, conectar las interfaces del navegador y usar sesiones dedicadas de Claude |
| Copia y traslado de entornos de trabajo | Exportar datos cifrados del navegador, un perfil de terminal o una aplicación y restaurarlos en un entorno nuevo |

**Un escritorio local, un contexto de trabajo y varias formas de usar tus herramientas.** Tú te encargas del trabajo; Envara te ayuda a mantener el entorno en orden.

## Descarga e instalación

Descarga el paquete DMG o ZIP para **macOS Apple Silicon (arm64)** desde [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest). Abre el DMG y arrastra Envara a Aplicaciones. Los archivos de sumas de verificación y las notas de la versión se incluyen en la publicación.

**Los paquetes actuales para macOS no están firmados con Apple Developer ID ni notarizados.** macOS puede aplicar sus comprobaciones de seguridad al abrir la aplicación por primera vez; confirma que la descarga procede de este repositorio y verifica la suma de comprobación. Envara no desactiva automáticamente las comprobaciones de seguridad del sistema. El componente de enrutamiento del sistema para las aplicaciones vinculadas requiere autorización independiente del administrador; iniciar el navegador o el espacio de trabajo habitual no lo instala automáticamente.

| Plataforma | Alcance de la publicación |
| --- | --- |
| macOS Apple Silicon | Esta publicación incluye DMG, ZIP y archivos de sumas de verificación SHA-256 |
| macOS Intel | Se conserva el código fuente para esta plataforma; no se ofrecen paquetes verificados |
| Windows / Linux | Se conserva el código fuente correspondiente; esta publicación no incluye paquetes. Consulta la matriz de funciones para conocer el alcance de las pruebas en equipos reales |

Los motores de navegador se instalan desde la aplicación por decisión del usuario y están sujetos a sus respectivas licencias. La aplicación incluye las dependencias de ejecución del escritorio; no es necesario instalar Node.js ni Go por separado.

## Empieza en tu idioma

Se admiten **简体中文、繁體中文、English、日本語、한국어、Español、Français、Deutsch、Português (Brasil)**. En el primer inicio, Envara recomienda el idioma del sistema y te pide confirmarlo. Después puedes cambiarlo en Ajustes.

![Selección de idioma en el primer inicio](../media/first-launch.png)

<p align="center"><sub>Selector de idioma nativo del primer inicio.</sub></p>

El idioma de la interfaz es independiente del idioma del entorno del navegador. Cambiar el idioma de los menús no modifica la red, la zona horaria ni el directorio de trabajo existentes.

## Sobre el aislamiento y la privacidad

Envara prioriza las redes controlables, los datos separados y los mecanismos de privacidad auditables. Estos límites te ayudan a utilizarlo según sus capacidades reales:

- El aislamiento de configuración y datos no equivale a un usuario independiente del sistema operativo, un Keychain separado ni hardware virtual. La configuración de la huella del navegador no cambia la identidad del hardware de las aplicaciones nativas.
- Las rutas de terminal compatibles en macOS utilizan una barrera de red; las plataformas y rutas que aún no cuentan con esa barrera no deben considerarse aislamiento forzado. Consulta el alcance detallado en la [matriz de funciones](../capability-matrix.md).
- Cuando las aplicaciones vinculadas utilizan la barrera de red externa, se desactiva el sandbox interno de Chromium/Electron. El estado de los componentes nativos, los motores compatibles y el alcance de las pruebas reales se documentan por separado; poder identificar una aplicación no significa que todas las aplicaciones se hayan validado.
- Las exportaciones no incluyen Keychain, los programas, las cachés ni los archivos temporales. Algunas cuentas pueden requerir un nuevo inicio de sesión al cambiar de equipo; una restauración correcta en el mismo equipo no garantiza que la sesión funcione en otro.
- El bloqueo del seguimiento solo cubre las reglas implementadas y los controles admitidos por el motor. El aislamiento de red, cuentas y configuración no garantiza evitar las restricciones de los servicios ni elimina todo el seguimiento.

[Notas de verificación](../verification.md) · [Arquitectura](../architecture.md) · [Contexto de red](../network-context.md) · [Dispositivo e idioma del navegador](../browser-device-profiles.md)

## Desarrollo desde el código fuente

Se requieren Node.js 24 LTS (o 22.12+), npm, Go 1.25 y las herramientas de compilación de la plataforma de destino. Los componentes nativos de macOS requieren Xcode Command Line Tools.

```bash
npm ci
npm run desktop
```

La preparación inicial descarga versiones fijas de las dependencias de compilación. Para la vista previa de desarrollo y las comprobaciones:

```bash
npm run dev
npm test
npm run build
npm run test:sites
```

La vista previa web solo sirve para desarrollar la interfaz; los navegadores reales, los PTY y el enrutamiento del sistema requieren la aplicación de escritorio. Consulta la [guía de contribución](../../CONTRIBUTING.md) y el [proceso de publicación](../releasing.md) para obtener instrucciones de compilación y publicación. Los flujos de compilación y publicación automáticas de GitHub permanecen desactivados; enviar código fuente no activa ninguna compilación.

## Código abierto y apoyo

El código original de Envara utiliza la licencia [MIT](../../LICENSE). BrowseForge conserva su [licencia MIT](../../third_party/browseforge/LICENSE) y el [registro de la versión fijada](../../third_party/browseforge/ENVARA_UPSTREAM.md). El núcleo independiente Mihomo conserva la licencia [GPLv3](../../third_party/proxy-core/LICENSE) y el [código fuente correspondiente](../../third_party/proxy-core/SOURCE.md). Los binarios de los navegadores están sujetos a sus propias licencias y no están incluidos en la licencia MIT de la aplicación. Consulta los [avisos de terceros](../../THIRD_PARTY_NOTICES.md) para conocer todas las atribuciones.

El desarrollo ha supuesto un gasto considerable en servicios de IA. Si Envara te resulta útil, puedes apoyarlo de forma voluntaria: [USDT](../SUPPORT.md#usdt) · [USDC](../SUPPORT.md#usdc) · [Binance](../SUPPORT.md#binance). Las estrellas, los informes de problemas, las traducciones y las contribuciones de código también ayudan.

[Guía de uso detallada (en chino simplificado)](../user-guide.md)
