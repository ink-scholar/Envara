# 终端与原生附加软件：设备信息、语言隔离研究

研究日期：2026-10-15。本文核查 Apple、Microsoft、Docker、POSIX 与 OpenSSH 官方资料，只讨论一般隐私、可重复环境与兼容性。没有启动虚拟机、安装驱动、修改第三方应用或变更宿主设置。下列方案是研究结论，不能据此视为 Envara 已实现或通过实机验收。

## 结论与选择

**本机原生运行可以分开配置、限制资源和网络访问，并向支持它的程序提供独立语言设置；它不会因此获得另一台电脑的完整硬件视图。** 如果“软件看到独立操作系统和虚拟硬件”是硬要求，合适的边界是让软件真正运行在完整 VM 的 guest 内。VM 也不保证任意硬件字段可修改、无法识别虚拟化，或没有任何宿主关联。

对 Envara 最稳妥的路线是保留轻量的原生模式，准确列出其网络、配置及语言能力；把完整 VM 作为以后由用户主动选择的独立模式。不要以全局硬件修改、第三方应用注入或改签来让原生模式看似具有 VM 能力。当前不启动任何 VM，尤其不在这台 Mac 上重启 Windows 仿真测试。

## 不同边界能做到什么

| 方案 | 可提供的边界 | 明确限制与适用性 |
| --- | --- | --- |
| 本机终端＋独立配置目录＋网络围栏 | 工作目录、工具配置与历史、已验证的进程网络范围；部分运行时语言/时区 | 仍是宿主 OS 上的真实进程。`HOME`、代理变量或权限围栏不是虚拟硬件。最符合现有本机工具、真实本地目录的交互。 |
| macOS App Sandbox／Windows AppContainer | 限制指定文件、服务、网络及设备资源访问 | “拒绝读取”与“返回一套新硬件值”不同。不能仅据启用沙盒就声称 CPU、主板、磁盘、所有系统 API 都已隔离。[Apple](https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox)、[Microsoft](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) |
| macOS Virtualization／Windows Hyper-V 完整 VM | 独立 guest OS、虚拟设备与持久 guest 状态；guest 自己的语言及地区设置 | 应用必须真正装在 guest 中运行；宿主已安装应用不是自动搬入 VM。需独立计算资源、存储、网络和共享目录设计。[Apple VM 示例](https://developer.apple.com/documentation/virtualization/running-macos-in-a-virtual-machine-on-apple-silicon)、[Hyper-V 架构](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/architecture) |
| Linux 容器／WSL | Linux 用户空间、文件与进程命名空间；可为工具提供独立配置 | 普通容器共享所在 Linux 内核；Docker Desktop 在 Mac 上由 Linux VM 承载，不是任意 macOS GUI 应用容器。[Docker](https://docs.docker.com/desktop/setup/install/mac-permission-requirements/)、[容器隔离](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/hyperv-container) |
| Windows Sandbox | 硬件虚拟化支持的独立临时 Windows 桌面 | 关闭即丢弃状态，宿主软件不自动安装，官方文档当前不支持同时多实例；不适合作为多个持久境舱的默认后端。[官方说明](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/) |
| SSH 远程 runner | 命令与系统查询在远端执行，使用远端 OS 的环境 | 不是本机 CLI 的原地隔离；本地工具安装、文件路径、GUI 和凭据不能直接复用，需要单独设计文件与浏览器连接。运行远端官方 CLI 不要求转换为 API。[OpenSSH](https://man.openbsd.org/ssh) |

上述“适合/不适合”属于依据官方能力边界作出的工程判断，不是供应商对 Envara 的认证。

## macOS 设备信息边界

Apple 将 App Sandbox 描述为限制资源访问；公开的 `ProcessInfo` 仍定义物理内存、处理器数量、主机名及系统版本等查询，IOKit 也提供注册表属性查询。是否能读取某个敏感值还取决于系统版本、权限和具体 API；不能把少数探针被拒绝推广为所有本机特征都已隐藏。[App Sandbox](https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox)、[ProcessInfo.physicalMemory](https://developer.apple.com/documentation/foundation/processinfo/physicalmemory)、[系统版本](https://developer.apple.com/documentation/foundation/processinfo/operatingsystemversionstring)、[IOKit 属性查询](https://developer.apple.com/documentation/iokit/1514293-ioregistryentrycreatecfproperty/)

Apple 的 macOS VM 平台配置包括受恢复镜像支持的 `hardwareModel`、辅助存储与独立 `machineIdentifier`，可为 guest 配置 CPU 数量、内存和虚拟设备。它不是任意物理 Mac 型号及所有序列号的通用编辑器。macOS guest 的这条官方路线针对 Apple silicon；Linux guest 镜像也需要匹配 CPU 架构。[安装 macOS VM](https://developer.apple.com/documentation/virtualization/installing-macos-on-a-virtual-machine)、[Linux guest 架构要求](https://developer.apple.com/documentation/virtualization/creating-and-running-a-linux-virtual-machine)

VM 的隔离也应具体描述。例如 Apple 说明，支持 iCloud 的较新 macOS VM 身份会从宿主 Secure Enclave 安全信息派生，迁移宿主会改变身份。因此不能把“独立 VM 身份”宣传成“所有用途均与宿主完全无关”。[Apple iCloud 与 VM](https://developer.apple.com/documentation/virtualization/using-icloud-with-macos-virtual-machines)

## Windows 设备信息边界

Hyper-V 的子分区通过虚拟处理器、虚拟设备和 hypervisor 访问资源，具备独立 guest OS 的基础。Windows process container 主要隔离文件系统、注册表和命名空间，并共享宿主内核；Hyper-V container 则有自己的内核。这些模式不能混称为同一种硬件隔离。[Hyper-V](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/architecture)、[Windows 容器隔离模式](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/hyperv-container)

WSL 2 运行 Linux 内核，但从 WSL 启动 Windows `.exe`，该程序仍以当前 Windows 用户运行，如同从 CMD 启动，仍会出现在 Windows 任务管理器。因此“WSL 终端里启动 Windows Notion”不会自动让 Notion 变为 Linux guest 应用或获得独立 Windows 硬件视图。[WSL 架构](https://learn.microsoft.com/en-us/windows/wsl/wsl2-about)、[Windows 互操作](https://learn.microsoft.com/en-us/windows/wsl/filesystems#run-windows-tools-from-linux)

Windows Sandbox 可控制网络、虚拟 GPU、共享文件夹等；默认有网络不等于已经使用境舱节点。持久 VM 同样需要另做 guest 网络出口、DNS、断线阻断及宿主共享验收。[Sandbox 配置](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)

## 为什么不采用通用 API 注入作为默认方案

macOS Hardened Runtime 默认启用 library validation，只允许符合 Apple 签名或相同 Team ID 等条件的库。DYLD 注入相关行为需要目标应用允许对应例外；Envara 自身的签名不能替任意第三方目标增加权限。[Library validation](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.disable-library-validation)、[Hardened Runtime](https://developer.apple.com/documentation/xcode/configuring-the-hardened-runtime)

Windows 也有可限制可加载签名映像的进程策略，受保护进程限制内存和线程访问。因此，hook 少量 API 的实验不等于完整覆盖目标的多进程、不同架构、直接系统查询、外部服务及版本升级路径。[签名缓解策略](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_binary_signature_policy)、[受保护进程](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)

**工程判断：** 特定应用、特定版本、应用主动提供的插件/API 可以单独适配；不把注入、第三方 bundle 修改或全局硬件改写列为稳定通用能力。用户可选的拒绝访问策略仍可研究，但应显示为“访问被限制”，不显示为“硬件已虚拟化”。

## 语言隔离：应分别设置与验收

| 层次 | 可做的事 | 不能由此推断 |
| --- | --- | --- |
| Envara 界面 | 保存用户选择的界面语言 | 不应连带改浏览器、终端或宿主语言。 |
| 环境浏览器 | 使用 provider 支持的 locale、请求语言和页面可见语言设置 | 网站仍可按账户偏好、Cookie 或服务端规则选语言；字体、网页语言与浏览器 locale 是不同项。 |
| POSIX 终端工具 | 给自有子进程设置有效的 `LANG`、`LC_*`；`LC_ALL` 优先于分类变量和 `LANG` | 只有按这些规则初始化 locale、并自带对应翻译的工具才会响应；设置变量不等于虚拟化 OS 语言 API。[POSIX 环境规则](https://pubs.opengroup.org/onlinepubs/7908799/xbd/envvar.html)、[setlocale](https://pubs.opengroup.org/onlinepubs/009695399/functions/setlocale.html) |
| macOS 原生软件 | 对支持 Foundation 偏好的应用测试单次 `AppleLanguages`／`AppleLocale` 启动覆盖，优先使用软件自己的语言设置 | 不保证所有框架、帮助进程、系统服务、输入法和账户语言同步改变。[Apple 测试语言与地区](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPInternational/TestingYourInternationalApp/TestingYourInternationalApp.html) |
| Windows 原生软件 | 软件自己的语言/地区设置；遵循 CRT 或运行时配置的工具可独立设置 | 子进程环境块不能统一覆盖所有 Win32 语言/地区 API；必须逐软件验收。[进程环境](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)、[用户默认 locale](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getuserdefaultlocalename) |
| 完整 VM／远端 runner | guest/远端用户自己的系统语言与地区，另配每个应用 | 它改变执行位置；不会自动控制本地浏览器、输入法或远端账户服务的语言。 |

Apple 官方支持按应用选择语言，但系统设置里的选择作用于该应用身份；直接替用户改原应用的持久偏好可能影响其普通使用。Foundation 的命令行偏好域是临时覆盖，退出后丢弃，所以候选适配应优先测试自有启动实例的临时参数，避免写宿主全局偏好。[按应用选择语言](https://support.apple.com/guide/mac-help/change-the-system-language-mh26684/mac)、[临时参数域](https://developer.apple.com/documentation/foundation/userdefaults/argumentdomain)

时区同样不能一概而论：Microsoft CRT `_tzset` 可读 `TZ`，Win32 `GetTimeZoneInformation` 读系统时区。给进程加 `TZ` 不能宣传为任意 Windows 软件的系统时区都改变。IP 地区只用于推荐，语言应允许用户确认；一个国家可能有多种语言，不应由出口 IP 强制决定。[CRT 时区](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/tzset?view=msvc-170)、[系统时区 API](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-gettimezoneinformation)

## 建议的产品边界与后续验收

1. **原生模式继续优先兼容本地软件。** 保持官方 CLI 和软件原有二进制、独立配置及现有网络接管；只公布已测的语言控制项。网络接管不顺带获得硬件或系统定位虚拟化。
2. **强设备隔离作为单独 VM 模式。** 若用户接受资源开销及 guest 内安装软件，再评估 Mac 同架构 Virtualization guest、Windows 原生 Hyper-V guest；给 guest 明确的存储、共享目录、资源上限和独立网络规则。不是默认后台启动任务，也不承诺跨架构仿真性能。
3. **远端执行作为另一种模式。** 适合愿意把工具/代码工作区移到远端的用户；明确显示执行主机和文件位置，不能伪装成本地现有安装的 CLI。远端用户、VM 或专用机器的隔离强度也需分别说明。
4. **按可观察结果验收。** 检查父子进程的实际 locale、应用界面和格式、原生系统查询与帮助进程；核查应用支持的语言包。VM 另检查 guest OS/虚拟设备、实际出站/DNS、共享文件/剪贴板/设备范围及关闭后的状态。只导出必要的脱敏结果，不收集或公开真实硬件序列号。
5. **保持边界诚实。** 不保证所有硬件/字体/文件名/宿主标识都不可见；不保证选定地图位置替代系统定位；不保证 VM 不可识别、所有软件兼容或任何账户结果。原生与 VM 的验收结果应分开展示。

本轮只完成官方资料研究和文档，以上候选实现均未因此获得启动、系统授权或完成状态。
