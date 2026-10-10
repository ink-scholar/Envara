# Opt-in Windows capture component lab

The same-package Go test calls the actual installed capture DLL and official
signed WinDivert driver, with private authenticated SOCKS and loopback-only
traffic. It never sets product readiness and never exposes a launch override.
Ordinary Go/npm checks skip it. Run only in the explicit disposable Windows x64
evaluation VM designated for this task. No real account or node is needed.

Build the test executable:

```sh
GOOS=windows GOARCH=amd64 go test -c ./internal/host -o envara-native-capture-lab.test.exe
```

The executable must be alongside `EnvaraCapture.dll`, `WinDivert.dll`,
`WinDivert64.sys` and the matching `capture-provenance.json` in the same
administrator-protected installation directory. The normal DLL hash, owner,
ACL, architecture and reparse-point checks remain enforced. Run elevated so
Windows can activate its signed driver. Use an elevated interactive lab user,
not SYSTEM/LocalService/NetworkService or a session-0 setup script: the actual
caller-token fixture refuses a service-account launch. This does not register
an SCM service.

Inside the disposable guest, opt in explicitly:

```powershell
$env:ENVARA_WINDOWS_CAPTURE_LAB = 'isolated-vm'
$env:ENVARA_WINDOWS_CAPTURE_REPORT = 'C:\acceptance\capture-component-report.json'
.\envara-native-capture-lab.test.exe -test.v -test.run='^TestWinDivertCaptureLoopbackLab$' -test.timeout=3m
```

The report path must be absolute with an existing parent. Creation is exclusive;
an existing report is never overwritten. The same JSON is printed with the
`ENVARA_NATIVE_REPORT` prefix even if setup or a behavior test fails. There are no
node credentials in the report, child arguments or fixture files. SOCKS fixture
credentials exist only in the controller's memory and are generated per run.

Observed cases include:

- An unrelated TCP socket established before capture, followed by a new one.
  Both must actually echo. The known pre-capture compatibility gap is reported
  as **failed**, not turned into an expected-rejection test.
- A root test process launched through the real suspended caller-token/Job
  path, then a child it spawns normally. Both must echo through authenticated
  SOCKS with observed exact private destinations and role payloads.
- The same private UDP receiver must work before activation and with a new
  unrelated sender afterward. Root and child report successful own sends;
  neither datagram may arrive. The capture's global blocking counter must also
  advance, but it does not identify which protocol caused those increments.
- The relay's first actual native claim must match its original destination,
  PID/creation time, route, session and adapter tags. That exact tuple and flow
  token must change from a live host proxy binding to a blocked revoked binding.
  Native `LookupRelay` claims are one-shot, so a repeated rejection cannot prove
  native revocation and this lab does not present it as such evidence.
- Closing the managed core must close the existing owned stream. A subsequent
  owned attempt must not echo or create a new original-target connection.
- Another independently authenticated session must remain live immediately
  before Stop. Its exact native tuple/token must change from Proxy to Block
  while that session's core remains open, separating Stop from core failure.
- Session stop must confirm zero Job processes before closing borrowed handles.
  Production launch and DNS/fail-closed verification must remain disabled.

The child-only fixture flag can run only a validated loopback fixture; it cannot
activate capture or call a product launch RPC. This is component evidence, not a
Notion, DNS, generic-software or service-crash acceptance claim. No Windows run
has been performed on the macOS development host.
