<p align="center">
  <img src="../../build/icon.png" width="88" alt="Envara 境舱" />
</p>
<h1 align="center">Envara · 境舱</h1>
<p align="center"><strong>작업마다, 하나의 독립된 환경을.</strong><br />브라우저도, 터미널도, 앱도. 하나의 작업 환경에서.</p>
<p align="center">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b9cff" alt="자체 코드 라이선스: MIT" /></a>
  <a href="https://github.com/ink-scholar/Envara/releases"><img src="https://img.shields.io/github/v/release/ink-scholar/Envara?color=475569" alt="최신 버전" /></a>
</p>
<p align="center">
  <a href="../../README.md">简体中文</a> · <a href="zh-TW.md">繁體中文</a> · <a href="en.md">English</a> · <a href="ja.md">日本語</a> · <strong>한국어</strong> · <a href="es.md">Español</a> · <a href="fr.md">Français</a> · <a href="de.md">Deutsch</a> · <a href="pt-BR.md">Português (Brasil)</a>
</p>
<p align="center">
  <a href="https://github.com/ink-scholar/Envara/releases/latest">macOS용 다운로드</a> · <a href="../user-guide.md">사용 안내</a> · <a href="../capability-matrix.md">전체 기능</a> · <a href="../SUPPORT.md">프로젝트 지원</a>
</p>

**브라우저, 터미널과 데스크톱 앱을 각각의 독립된 작업 환경에 모아 보세요.**

Envara는 오픈 소스 로컬 데스크톱 작업 공간입니다. 프로젝트, 계정이나 지역에 따라 네트워크, 브라우저 데이터와 도구 설정을 따로 보관할 수 있습니다. 환경을 선택하고 자료 조사, 코드 작성, 앱 사용까지 이전 작업을 이어 가세요.

![합성 예시 데이터를 사용한 Envara 작업 공간](../media/workspace-zh-CN.png)

## 일상의 작업을 하나의 작업 공간에서

| 기능 | 할 수 있는 일 |
| --- | --- |
| 🌐 네트워크 환경 | HTTP / HTTPS / SOCKS5 / AnyTLS를 사용하고, 프록시 인증을 거친 실제 네트워크 출구와 지역·시간대를 확인합니다. AnyTLS는 Clash를 별도로 설치할 필요가 없습니다 |
| 🧭 독립 브라우저 | CloakBrowser, Camoufox 또는 실험적 BrowseForge Chromium을 선택합니다. 데이터를 따로 보관하고 다시 열 때 저장된 식별 설정을 유지합니다 |
| ⌨️ 네이티브 터미널 | 프로젝트 폴더, 여러 세션, 크기 조절 패널과 독립 창을 사용합니다. 설정과 기록은 환경별로 보관하며, macOS에서는 저장된 SSH 연결마다 호스트 네트워크 또는 설정된 환경의 경로를 선택할 수 있습니다 |
| 🧩 연결된 앱 | 지원되는 Chromium / Electron 앱을 환경에 연결하고 별도 데이터와 시작·중지를 관리합니다 |
| 🤖 Claude Code | 환경 안에서 설치·업데이트하고, 이름을 붙인 로그인 프로필을 관리하며 선택한 환경 브라우저를 연결합니다 |
| 🔗 링크와 자동화 | 지정한 브라우저로 링크를 열고 REST / MCP / Playwright 브라우저 인터페이스를 사용합니다 |
| 📦 암호화된 데이터 이전 | 브라우저, 선택한 터미널 프로필 또는 개별 앱을 비밀번호로 암호화하여 내보내고 새 환경으로 가져옵니다 |
| 🗂️ 작업 공간 관리 | 환경을 그룹화·검색·복제하고 실행 상태를 확인합니다. 3열 구성, 접을 수 있는 탐색 영역, 9개 언어와 라이트·다크·시스템 테마를 지원합니다 |

## 익숙한 도구로 작업을 이어 가세요

브라우저에서 자료를 찾고, 터미널에서 코드를 작성하고, 필요한 데스크톱 앱을 여세요. 환경이 해당 작업의 네트워크 설정과 데이터를 함께 보관합니다. 터미널에서 원격 서버에 연결하고 저장된 SSH 연결마다 경로를 선택할 수 있습니다. 설정 방법은 [SSH 안내](../claude-code-sessions.md#ssh-through-the-environment-route)를 참고하세요.

Claude Code는 터미널 작업 흐름에 통합된 도구 중 하나입니다. 각 환경은 **수정하지 않은 공식 CLI**를 따로 설치하고, 이름을 붙인 로그인 프로필을 개별 보관하며 선택한 환경 브라우저를 연결합니다. 셸 프롬프트에서 필요할 때 직접 `claude`를 입력해 시작하세요. 모델, 세션 재개와 권한 옵션은 사용자가 선택합니다. 자세한 내용은 [Claude Code 안내](../claude-code-sessions.md)를 참고하세요.

환경 분리는 네트워크와 계정 설정이 섞이는 일을 줄여 주지만, 계정 제한 회피나 완전한 익명성을 보장하지는 않습니다. 연결된 앱의 지원 범위, 시스템 승인과 샌드박스 관련 고려 사항은 [기능과 한계](../capability-matrix.md)를 참고하세요. 앱을 중지하거나 연결을 해제해도 로그인 데이터는 보존됩니다.

## 시작하기

[GitHub Releases](https://github.com/ink-scholar/Envara/releases/latest)에서 **macOS Apple Silicon(arm64)**용 DMG 또는 ZIP과 SHA-256 체크섬 파일을 다운로드하세요. 설치 단계와 서명 정보는 [사용 안내](../user-guide.md)를 참고하세요.

1. **네트워크를 선택하세요.** 네트워크 설정을 추가하고 실제 출구를 확인한 뒤 지역과 시간대를 확인합니다.
2. **환경을 만드세요.** 브라우저를 선택하고 프로젝트나 계정에 맞는 독립된 작업 공간을 준비합니다.
3. **작업을 시작하세요.** 브라우저를 열거나, 터미널 작업 디렉터리를 선택하거나, 지원되는 데스크톱 앱을 연결합니다.

같은 환경으로 돌아오면 저장된 브라우저 데이터, 터미널 설정과 앱 데이터를 다시 사용할 수 있어 반복 설정이 줄어듭니다.

[사용 안내](../user-guide.md) · [전체 기능](../capability-matrix.md) · [릴리스 노트](https://github.com/ink-scholar/Envara/releases) · [소스 개발과 기여](../../CONTRIBUTING.md) · [문제 보고](https://github.com/ink-scholar/Envara/issues)

## 오픈 소스와 지원

Envara의 자체 코드에는 [MIT](../../LICENSE)가 적용됩니다. BrowseForge는 기존 [MIT 라이선스](../../third_party/browseforge/LICENSE)와 [고정 버전 기록](../../third_party/browseforge/ENVARA_UPSTREAM.md)을 유지합니다. 독립 Mihomo 코어는 [GPLv3](../../third_party/proxy-core/LICENSE)와 [해당 소스 코드](../../third_party/proxy-core/SOURCE.md)를 유지합니다. 브라우저 바이너리에는 각자의 라이선스가 적용되며 앱의 MIT 라이선스에 포함되지 않습니다. 전체 출처 및 라이선스 정보는 [타사 고지](../../THIRD_PARTY_NOTICES.md)를 참고하세요.

개발에는 많은 AI 사용 비용이 들었습니다. Envara가 도움이 되었다면 자발적인 후원을 환영합니다: [USDT](../SUPPORT.md#usdt) · [USDC](../SUPPORT.md#usdc) · [Binance](../SUPPORT.md#binance). Star, 문제 보고, 번역과 코드 기여도 큰 도움이 됩니다.

[자세한 사용 안내（중국어 간체）](../user-guide.md)
