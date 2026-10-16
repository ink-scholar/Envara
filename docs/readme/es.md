<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>Varios entornos, un solo espacio de trabajo.</strong><br />Un espacio de trabajo local para navegadores, terminales y contextos de red.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="Licencia del código original: MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-0.5.23-475569" alt="Envara 0.5.23" /></a>
  <a href="en.md"><img src="https://img.shields.io/badge/README-9_languages-6366f1" alt="README en 9 idiomas" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <a href="ko.md">한국어</a> · <strong>Español</strong> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">Descargar para macOS</a> · <a href="../capability-matrix.md">Funciones y límites</a> · <a href="../../CONTRIBUTING.md">Contribuir</a> · <a href="../SUPPORT.md">Apoyar el proyecto</a>
</p>

![Espacio de trabajo nativo de Envara en chino](../media/workspace-zh-CN.png)

<p align="center"><sub>Espacio de trabajo nativo de Electron. La captura utiliza datos de ejemplo sintéticos.</sub></p>

## Un entorno, un contexto de trabajo

Envara reúne el navegador, la salida de red, el directorio de trabajo y las herramientas de línea de comandos en un mismo espacio de trabajo local. Cada entorno conserva sus propios datos de navegación, configuración de herramientas e historial; los distintos entornos pueden utilizar redes diferentes.

| Área de trabajo | Funciones |
| --- | --- |
| Entornos | Creación, clonación, agrupación y búsqueda; directorio de trabajo y contexto de red guardados |
| Salida de red | HTTP, HTTPS, SOCKS5 y AnyTLS integrado; detección de la salida real, la región aproximada y la zona horaria |
| Navegadores | CloakBrowser / Chromium, Camoufox / Firefox y BrowseForge Chromium experimental; configuración automática y ajustes avanzados |
| Terminales | PTY reales, selección de directorio, varias sesiones, panel ajustable y ventanas independientes |
| Claude Code | Instalación independiente de la CLI oficial por entorno, perfiles de inicio de sesión con nombre y herramientas MCP vinculadas al navegador del entorno |
| Aplicaciones vinculadas | Vinculación de aplicaciones Chromium/Electron compatibles a un entorno, gestión de sus instancias y datos de aplicación independientes |
| Migración de datos | Exportación por separado de datos del navegador, del perfil de inicio de sesión seleccionado del terminal o de una aplicación vinculada, cifrada con contraseña |

Envara administra el núcleo AnyTLS integrado, sin necesidad de configurar Clash por separado. Los navegadores, terminales y aplicaciones vinculadas reutilizan la ubicación y la zona horaria de red confirmadas. Los ajustes de ubicación no modifican la zona horaria del sistema; la geolocalización por IP solo indica una región aproximada.

Duplicar un terminal crea un proceso nuevo e independiente, sin repetir comandos. Las sesiones de Claude Code empiezan en un shell, donde tú escribes `claude`; puedes descargar una instalación oficial independiente o inicializarla a partir de un programa nativo ya disponible en el equipo. Envara no modifica la CLI oficial, no copia las cuentas del sistema anfitrión ni activa por defecto la omisión de permisos. [Más sobre las sesiones de Claude Code](../claude-code-sessions.md).

Antes de iniciar una aplicación vinculada, Envara comprueba su compatibilidad, las instancias existentes y el estado de los componentes de enrutamiento. Si no se cumplen los requisitos, rechaza explícitamente el inicio. Detener una aplicación, eliminar su vínculo o salir de Envara conserva los datos de inicio de sesión; solo se borran cuando solicitas expresamente eliminar esos datos o el entorno. Consulta [Aplicaciones vinculadas](../application-routing-options.md).

## Descarga e instalación

Descarga el DMG o ZIP para **macOS Apple Silicon (arm64)** desde [GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest). Abre el DMG y arrastra Envara a Aplicaciones. Los archivos de sumas de verificación y las notas de la versión se incluyen en la publicación.

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

## Límites de las funciones

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

Puedes [informar de problemas](https://github.com/ink-scholar/Envara/issues), contribuir código, mejorar las traducciones o dar una estrella al proyecto. Todo apoyo es voluntario; los canales de donación aún no están habilitados. [Apoyar el proyecto](../SUPPORT.md)
