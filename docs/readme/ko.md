<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>여러 환경을 하나의 작업 공간에서.</strong><br />브라우저, 터미널, 네트워크 설정을 한곳에 모은 로컬 작업 공간.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="자체 코드 라이선스: MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/badge/version-0.5.23-475569" alt="Envara 0.5.23" /></a>
  <a href="en.md"><img src="https://img.shields.io/badge/README-9_languages-6366f1" alt="9개 언어의 README" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <strong>한국어</strong> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">macOS 버전 다운로드</a> · <a href="../capability-matrix.md">기능과 한계</a> · <a href="../../CONTRIBUTING.md">기여하기</a> · <a href="../SUPPORT.md">프로젝트 지원</a>
</p>

![Envara 중국어 네이티브 작업 공간](../media/workspace-zh-CN.png)

<p align="center"><sub>네이티브 Electron 작업 공간입니다. 스크린샷에는 합성 예시 데이터를 사용했습니다.</sub></p>

## 환경마다 독립된 작업 설정

Envara는 브라우저, 네트워크 경로, 작업 폴더, 명령줄 도구를 하나의 로컬 작업 공간에 모읍니다. 각 환경은 자체 브라우저 데이터, 도구 설정과 기록을 보관하며, 환경마다 다른 네트워크를 선택할 수 있습니다.

| 작업 공간 | 기능 |
| --- | --- |
| 환경 | 생성, 복제, 그룹화, 검색 및 작업 폴더와 네트워크 설정 저장 |
| 네트워크 경로 | HTTP, HTTPS, SOCKS5와 내장 AnyTLS 지원, 실제 외부 IP와 대략적인 지역·시간대 확인 |
| 브라우저 | CloakBrowser / Chromium, Camoufox / Firefox, 실험 단계의 BrowseForge Chromium 및 자동·고급 설정 |
| 터미널 | 실제 PTY, 폴더 선택, 여러 세션, 크기 조절 패널과 독립 창 |
| Claude Code | 환경별 독립 공식 CLI 설치, 이름을 지정한 로그인 프로필, 환경 브라우저에 연결된 MCP 도구 |
| 연결된 앱 | 지원되는 Chromium/Electron 앱을 환경에 연결하고 실행 인스턴스와 독립 앱 데이터 관리 |
| 데이터 이동 | 브라우저, 선택한 터미널 로그인 프로필 또는 연결된 앱 데이터를 각각 내보내고 비밀번호로 암호화 |

내장 AnyTLS 코어는 Envara가 관리하므로 Clash를 따로 설정할 필요가 없습니다. 브라우저, 터미널과 연결된 앱은 확인된 네트워크 위치와 시간대를 함께 사용합니다. 위치 설정은 시스템 시간대를 바꾸지 않으며, IP 위치 정보는 대략적인 지역만 나타냅니다.

터미널을 복제하면 새로운 독립 프로세스가 생성되며 명령을 다시 실행하지 않습니다. Claude Code 세션은 먼저 shell 프롬프트에서 시작하며, 사용자가 `claude`를 입력해 실행합니다. 환경 전용 공식 CLI를 다운로드해 설치하거나, 기존 로컬 네이티브 프로그램으로 초기화할 수 있습니다. Envara는 공식 CLI를 수정하거나 호스트 계정 정보를 복사하지 않으며, 권한 확인 우회를 기본으로 활성화하지 않습니다. [Claude Code 세션 알아보기](../claude-code-sessions.md).

연결된 앱을 시작하기 전에 호환성, 기존 실행 인스턴스와 라우팅 구성 요소의 상태를 확인합니다. 조건이 충족되지 않으면 시작을 명확히 거부합니다. 앱 중지, 연결 해제와 Envara 종료 시에는 로그인 데이터를 보존하며, 로그인 데이터나 환경을 명시적으로 삭제할 때만 지웁니다. 자세한 내용은 [연결된 앱](../application-routing-options.md)을 참고하세요.

## 다운로드 및 설치

[GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest)에서 **macOS Apple Silicon(arm64)**용 DMG 또는 ZIP을 다운로드하세요. DMG를 열고 Envara를 ‘응용 프로그램’ 폴더로 드래그하면 됩니다. 체크섬 파일과 버전 설명은 Release에 함께 제공됩니다.

**현재 macOS 배포 파일은 Apple Developer ID 서명과 공증을 받지 않았습니다.** 처음 열 때 macOS 보안 검사로 실행이 차단될 수 있으므로 이 저장소에서 다운로드했는지 확인하고 체크섬을 대조하세요. Envara는 시스템 보안 검사를 자동으로 끄지 않습니다. 연결된 앱의 시스템 라우팅 구성 요소에는 별도의 관리자 승인이 필요하며, 브라우저나 일반 작업 공간을 시작할 때 자동으로 설치되지 않습니다.

| 플랫폼 | 이번 배포 범위 |
| --- | --- |
| macOS Apple Silicon | DMG, ZIP 및 SHA-256 체크섬 파일 제공 |
| macOS Intel | 소스 코드는 유지하지만 검증된 배포 파일은 제공하지 않음 |
| Windows / Linux | 관련 소스 코드는 유지하지만 이번에는 배포 파일을 공개하지 않음. 실제 기기 검증 범위는 기능 표 참고 |

브라우저 엔진은 사용자가 앱 내 설치 기능을 통해 설치하며, 각 엔진의 라이선스가 적용됩니다. 데스크톱 실행에 필요한 의존성은 앱에 포함되어 있어 Node.js나 Go를 별도로 설치할 필요가 없습니다.

## 원하는 언어로 시작

**简体中文, 繁體中文, English, 日本語, 한국어, Español, Français, Deutsch, Português (Brasil)**를 지원합니다. 처음 실행할 때 시스템 언어를 추천하고 사용자가 확인해 선택하며, 이후에는 설정에서 변경할 수 있습니다.

![첫 실행 시 언어 선택](../media/first-launch.png)

<p align="center"><sub>네이티브 첫 실행 언어 선택 화면입니다.</sub></p>

인터페이스 언어와 브라우저 환경의 언어는 별개입니다. 메뉴 언어를 바꿔도 기존 네트워크, 시간대나 작업 폴더는 바뀌지 않습니다.

## 기능의 한계

- 설정과 데이터 분리는 별도의 운영체제 사용자, Keychain이나 가상 하드웨어를 제공하지 않습니다. 브라우저 지문 설정은 네이티브 앱의 하드웨어 식별 정보를 바꾸지 않습니다.
- 지원되는 macOS 터미널 경로에는 네트워크 격리 경계를 적용합니다. 이 경계가 아직 구현되지 않은 플랫폼과 경로는 강제로 격리된 것으로 볼 수 없습니다. 자세한 범위는 [기능 표](../capability-matrix.md)를 참고하세요.
- 연결된 앱에 외부 네트워크 격리 경계를 적용할 때는 Chromium/Electron의 내부 샌드박스가 비활성화됩니다. 네이티브 구성 요소 상태, 지원 엔진과 실제 검증 범위를 구분해 설명하며, ‘인식 가능’을 ‘모든 앱 검증 완료’로 간주하지 않습니다.
- 내보내기에는 Keychain, 프로그램 본체, 캐시나 임시 파일이 포함되지 않습니다. 다른 기기에서는 일부 계정에 다시 로그인해야 할 수 있습니다. 같은 기기에서 복원에 성공해도 다른 기기에서 로그인 상태가 유지된다고 보장하지 않습니다.
- 추적 차단은 구현된 규칙과 엔진이 지원하는 제어 범위에 한정됩니다. 네트워크, 계정과 설정 분리는 서비스 제한 회피를 보장하지 않으며 모든 추적을 제거하지도 않습니다.

[검증 안내](../verification.md) · [아키텍처](../architecture.md) · [네트워크 설정](../network-context.md) · [브라우저 기기 설정과 언어](../browser-device-profiles.md)

## 소스 코드로 개발

Node.js 24 LTS(또는 22.12+), npm, Go 1.25와 대상 플랫폼의 빌드 도구가 필요합니다. macOS 네이티브 구성 요소에는 Xcode Command Line Tools가 필요합니다.

```bash
npm ci
npm run desktop
```

초기 준비 과정에서 고정 버전의 빌드 의존성을 다운로드합니다. 개발용 미리 보기와 검사는 다음 명령으로 실행할 수 있습니다.

```bash
npm run dev
npm test
npm run build
npm run test:sites
```

Web 미리 보기는 인터페이스 개발용입니다. 실제 브라우저, PTY와 시스템 라우팅에는 데스크톱 앱이 필요합니다. 빌드와 배포 방법은 [기여 안내](../../CONTRIBUTING.md)와 [릴리스 절차](../releasing.md)를 참고하세요. GitHub 자동 빌드·릴리스 워크플로는 비활성 상태를 유지하며, 소스를 push해도 빌드가 실행되지 않습니다.

## 오픈 소스와 지원

Envara의 자체 코드에는 [MIT](../../LICENSE)가 적용됩니다. BrowseForge는 기존 [MIT 라이선스](../../third_party/browseforge/LICENSE)와 [고정 버전 기록](../../third_party/browseforge/ENVARA_UPSTREAM.md)을 유지합니다. 독립 Mihomo 코어는 [GPLv3](../../third_party/proxy-core/LICENSE)와 [해당 소스 코드](../../third_party/proxy-core/SOURCE.md)를 유지합니다. 브라우저 바이너리에는 각자의 라이선스가 적용되며 앱의 MIT 라이선스에 포함되지 않습니다. 전체 출처 및 라이선스 정보는 [타사 고지](../../THIRD_PARTY_NOTICES.md)를 참고하세요.

[문제 보고](https://github.com/ink-scholar/Envara/issues), 코드 기여, 번역 개선과 Star를 환영합니다. 모든 지원은 자발적이며, 기부 채널은 아직 열려 있지 않습니다. [프로젝트 지원](../SUPPORT.md)
