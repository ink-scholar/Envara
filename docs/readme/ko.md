<p align="center"><img src="../../build/icon.png" width="88" alt="Envara" /></p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>여러 환경을 하나의 작업 공간에서.</strong></p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="자체 앱 코드의 MIT 라이선스" /></a>
  <a href="../verification.md"><img src="https://img.shields.io/badge/0.5.0-local_candidate-475569" alt="0.5.0 로컬 후보" /></a>
</p>
<p align="center"><a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <strong>한국어</strong> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a></p>

![Envara 중국어 네이티브 작업 공간](../media/workspace-zh-CN.png)

*중국어 네이티브 Electron 후보 화면입니다. 네트워크는 테스트용 합성 데이터이며 실제 네트워크 경로나 앱 라우팅의 증거가 아닙니다. [이전 네이티브 스크린샷](../envara-workspace-0.5.png).*

## 로컬 작업 공간

Envara는 BrowseForge의 브라우저 환경을 데스크톱 앱으로 제공합니다. 메뉴는 **환경 → 네트워크 경로 → 브라우저 → 터미널 → 연결된 앱 → 실행 모니터** 순서입니다. 자세한 설정은 고급 옵션에 모았습니다.

- **환경:** 독립 브라우저 데이터, 그룹, 태그, 복제와 설정 가져오기·내보내기.
- **네트워크:** HTTP, HTTPS, SOCKS5와 내장 AnyTLS. 인증된 요청으로 실제 외부 IP, 대략적인 지역과 시간대를 확인하며 별도의 Clash 설정은 필요하지 않습니다.
- **브라우저:** CloakBrowser / Chromium, Camoufox / Firefox와 실험 단계의 BrowseForge Chromium.
- **터미널:** 실제 로컬 PTY, 작업 폴더 선택, 크기 조절, 독립 창과 여러 세션. 복제는 새 프로세스를 만들며 실행 중인 명령을 다시 실행하지 않습니다.
- **연결된 앱:** 로컬 소프트웨어를 환경에 연결합니다. 시스템 어댑터의 승인과 검증이 끝나기 전에는 보호된 실행을 거부합니다.

브라우저와 터미널은 환경의 네트워크와 시간대를 공유합니다. 도구 설정과 기록은 환경별로 분리됩니다.

## 원하는 언어로 시작

후보 UI는 중국어 간체·번체, 영어, 일본어, 한국어, 스페인어, 프랑스어, 독일어와 브라질 포르투갈어를 지원합니다. 처음 실행할 때 언어를 선택하고 설정에서 바꿀 수 있습니다. UI 언어 변경은 브라우저 언어, 네트워크, 시간대, 작업 폴더 또는 터미널 출력에 영향을 주지 않습니다.

![네이티브 첫 실행 언어 선택](../media/first-launch.png)

*영어 UI로 표시된 네이티브 Electron 첫 실행 화면입니다. 언어 선택, 저장, 재시작 후 유지와 독립 터미널 창 동기화를 별도로 확인했습니다.*

## 설치 상태와 제한

**0.5.0은 개발 후보 버전이며 정식 공개 다운로드는 없습니다.** 최신 소스 진행 상황을 공유합니다. 설치 릴리스는 초안이며 자동 릴리스는 비활성화 상태입니다. Notion 실행 및 정리는 아직 검증되지 않았습니다. [현재 진단 인계](../notion-launch-handoff-20261010.md)를 확인하세요.

macOS Apple Silicon을 우선 검증합니다. 브라우저, AnyTLS와 실제 PTY의 버전별 네이티브 기록이 있습니다. 후보 패키지는 서명과 공증을 받지 않았습니다. Windows에는 소스와 빌드 후보가 있지만 실제 기기 검증이 필요합니다. macOS Intel과 Linux도 실기 검증을 마치지 않았습니다.

**연결된 앱의 완전한 강제 라우팅은 두 플랫폼 모두 준비되지 않았습니다.** Mac의 기본 방식은 PF, 전용 프로세스 그룹 및 자체 utun을 사용해 Envara가 관리하는 인증된 노드에 연결합니다. 이 방식은 로컬 관리자 승인이 필요하지만 Apple 개발자 계정은 필요하지 않습니다. 독립 DNS, 장애 보호 및 실제 앱 검증은 아직 완료되지 않았습니다. Notion은 보호된 상태로 실행하지 않았습니다. [라우팅 제한](../application-routing-options.md)과 [검증 기록](../verification.md)을 확인하세요.

추적 차단 규칙은 모든 추적을 제거하지 않습니다. 설정 분리는 OS 샌드박스가 아닙니다. IP 위치는 지역의 추정값이며 주택 주소나 계정 정지 방지를 보장하지 않습니다.

## 개발

Node.js 24 LTS 또는 22.12+, npm, Go 1.25+와 플랫폼 빌드 도구가 필요합니다.

```bash
npm ci
npm run desktop
```

초기 준비에는 인터넷 연결이 필요합니다. 브라우저 엔진은 사용자가 공식 출처에서 설치합니다. 준비된 데스크톱 패키지는 실행 의존성을 포함하므로 일반 사용자는 Go나 Node.js를 설치할 필요가 없습니다.

```bash
npm test
npm run build
npm run test:sites
```

Web 미리 보기는 UI 개발용입니다. 네이티브 작업은 데스크톱 모드에서 실행합니다. [기여 안내](../../CONTRIBUTING.md)를 참고하세요.

## 더 알아보기와 지원

[기능과 BrowseForge 비교](../capability-matrix.md) · [아키텍처](../architecture.md) · [검증](../verification.md) · [문제 보고](https://github.com/ink-scholar/Envara/issues)

Star, 의견, 번역과 코드 기여를 환영합니다. [자발적 후원](../SUPPORT.md)은 예정되어 있지만 현재 결제 채널은 열려 있지 않습니다.

## 라이선스

Envara의 자체 코드와 포함된 BrowseForge 소스는 각각 MIT 라이선스를 유지합니다. 독립적으로 실행되는 Mihomo 코어는 GPLv3 라이선스를 따르며 해당 소스도 제공됩니다. 브라우저 바이너리는 각자의 라이선스를 따르며 CloakBrowser의 Binary License는 앱의 MIT에 포함되지 않습니다. [LICENSE](../../LICENSE), [BrowseForge 출처](../../third_party/browseforge/ENVARA_UPSTREAM.md), [프록시 소스](../../third_party/proxy-core/SOURCE.md), [타사 고지](../../THIRD_PARTY_NOTICES.md)를 확인하세요.
