<#
  Envara Windows test log collector (developer checkout, x64).

  Runs the automated checks and, optionally, one interactive desktop session,
  writing every command's output under test-artifacts\windows\<timestamp>\.
  It needs no administrator rights, installs nothing outside this checkout,
  never touches drivers/services/network settings, and does not upload
  anything. User/computer names are masked in copied logs; review the archive
  before sending it.

  Every step has a time limit; on expiry the step's whole process tree is
  ended (only processes this script started). The script exits 1 when any
  step failed or timed out.

  Usage (from the repository root, normal PowerShell):
    powershell -ExecutionPolicy Bypass -File scripts\windows-test-collect.ps1            # automated checks
    powershell -ExecutionPolicy Bypass -File scripts\windows-test-collect.ps1 -Desktop   # + desktop session
    powershell -ExecutionPolicy Bypass -File scripts\windows-test-collect.ps1 -SkipInstall -SkipTests -Desktop
#>
[CmdletBinding()]
param(
  [switch]$Desktop, [switch]$SkipInstall, [switch]$SkipTests,
  [int]$StepTimeoutMinutes = 30, [int]$TestTimeoutMinutes = 60, [int]$PerTestTimeoutSeconds = 180
)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = Join-Path $root "test-artifacts\windows\$stamp"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$summary = [ordered]@{ schema = 'envara.windows-test-run/v2'; startedAt = (Get-Date).ToString('o'); steps = @() }
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Mask([string]$text) {
  if (-not $text) { return $text }
  if ($env:USERPROFILE) {
    $text = $text.Replace($env:USERPROFILE, '%USERPROFILE%')
    # JSON and escaped strings double every backslash.
    $text = $text.Replace($env:USERPROFILE.Replace('\', '\\'), '%USERPROFILE%')
  }
  foreach ($pair in @(@($env:USERNAME, '<user>'), @($env:COMPUTERNAME, '<host>'))) {
    $name = $pair[0]; $label = $pair[1]
    if (-not $name) { continue }
    $escaped = [regex]::Escape($name)
    # Always mask profile paths; mask free-standing words only for names that
    # cannot be mistaken for ordinary numbers or short tokens in test output.
    $text = [regex]::Replace($text, "(?i)([\\/]+Users[\\/]+)$escaped(?=[\\/\s'`"]|$)", "`$1$label")
    if ($name.Length -ge 4 -and $name -notmatch '^\d+$') {
      $text = [regex]::Replace($text, "(?i)(?<![A-Za-z0-9_.-])$escaped(?![A-Za-z0-9_-])", $label)
    }
  }
  return $text
}

function Step([string]$name, [string]$command, [int]$timeoutMinutes) {
  Write-Host "==> $name : $command (limit $timeoutMinutes min)" -ForegroundColor Cyan
  $raw = Join-Path $out "$name.raw.log"
  $log = Join-Path $out "$name.log"
  New-Item -ItemType File -Force -Path $raw | Out-Null
  $started = Get-Date
  $process = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -NoNewWindow -PassThru `
    -ArgumentList "/d /s /c `"$command 1>`"$raw`" 2>&1`""
  $null = $process.Handle   # keep the handle so ExitCode stays readable
  $deadline = $started.AddMinutes($timeoutMinutes)
  $position = 0L
  $timedOut = $false
  while ($true) {
    $exited = $process.WaitForExit(2000)
    try {
      $stream = [IO.File]::Open($raw, 'Open', 'Read', 'ReadWrite')
      try {
        if ($stream.Length -gt $position) {
          $stream.Seek($position, 'Begin') | Out-Null
          $buffer = New-Object byte[] ($stream.Length - $position)
          $read = $stream.Read($buffer, 0, $buffer.Length)
          $position += $read
          Write-Host -NoNewline ($utf8.GetString($buffer, 0, $read))
        }
      } finally { $stream.Dispose() }
    } catch {}
    if ($exited) { break }
    if ((Get-Date) -gt $deadline) {
      $timedOut = $true
      Write-Host "`n!! $name exceeded $timeoutMinutes min; ending its process tree" -ForegroundColor Red
      & "$env:SystemRoot\System32\taskkill.exe" /PID $process.Id /T /F | Out-Null
      $process.WaitForExit(10000) | Out-Null
      break
    }
  }
  $code = if ($timedOut) { 'timeout' } else { $process.ExitCode }
  $seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
  [IO.File]::WriteAllText($log, (Mask ([IO.File]::ReadAllText($raw, $utf8))), $utf8)
  Remove-Item -LiteralPath $raw -Force
  $script:summary.steps += [ordered]@{ name = $name; command = $command; exitCode = $code; seconds = $seconds; timeoutMinutes = $timeoutMinutes }
  $color = 'Green'; if ($code -ne 0) { $color = 'Red' }
  Write-Host "<== $name exit $code ($seconds s)" -ForegroundColor $color
}

# Environment facts only: no account names, keys, addresses or proxy values.
$os = Get-CimInstance Win32_OperatingSystem
$summary.system = [ordered]@{
  caption = $os.Caption; version = $os.Version; build = $os.BuildNumber
  osArchitecture = $os.OSArchitecture; processArchitecture = $env:PROCESSOR_ARCHITECTURE
  locale = (Get-Culture).Name; uiLanguage = (Get-UICulture).Name; timeZone = (Get-TimeZone).Id
  is64BitProcess = [Environment]::Is64BitProcess
  developerMode = [bool]((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -ErrorAction SilentlyContinue).AllowDevelopmentWithoutDevLicense)
}
$tools = [ordered]@{}
foreach ($tool in @('node --version', 'npm --version', 'go version', 'git --version')) {
  $key = $tool.Split(' ')[0]
  $tools[$key] = (& cmd.exe /d /c "$tool 2>&1" | Select-Object -First 1)
  if (-not $tools[$key]) { $tools[$key] = 'missing' }
}
$summary.tools = $tools
# Presence only, never values.
$summary.environmentFlags = [ordered]@{}
foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'ELECTRON_GET_USE_PROXY', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_OPTIONS', 'npm_config_registry', 'NoDefaultCurrentDirectoryInExePath')) {
  $summary.environmentFlags[$name] = [bool][Environment]::GetEnvironmentVariable($name)
}
$summary.git = [ordered]@{
  branch = (& git rev-parse --abbrev-ref HEAD 2>$null); commit = (& git rev-parse HEAD 2>$null)
  dirty = [bool](& git status --porcelain 2>$null)
  autocrlf = (& git config --get core.autocrlf 2>$null)
  crlfFiles = @(& git ls-files --eol 2>$null | Where-Object { $_ -match '\sw/crlf\s' -and $_ -notmatch '[\s/]-text\s' }).Count
}

if (-not $SkipInstall) {
  Step '01-npm-ci' 'npm ci' $StepTimeoutMinutes
  Step '02-native-prepare' 'npm run native:prepare' $StepTimeoutMinutes
  Step '03-backend-prepare' 'npm run backend:prepare' $StepTimeoutMinutes
  Step '04-proxy-prepare' 'npm run proxy:prepare' $StepTimeoutMinutes
}
if (-not $SkipTests) {
  # Build first: tests/sites-worker.test.mjs checks the emitted dist/ files.
  Step '10-build' 'npm run build' $StepTimeoutMinutes
  Step '11-npm-test' "node --test --test-timeout=$($PerTestTimeoutSeconds * 1000) `"tests/*.test.mjs`"" $TestTimeoutMinutes
  Step '12-test-sites' 'npm run test:sites' $StepTimeoutMinutes
}
if ($Desktop) {
  Write-Host ''
  Write-Host 'Starting the desktop app. Work through docs\windows-test-plan.md, then quit Envara.' -ForegroundColor Yellow
  Write-Host 'Logs are captured until it exits (limit 240 min).' -ForegroundColor Yellow
  Step '20-desktop-session' 'npm run desktop' 240
}

# Copy only Envara's own diagnostics files (no browser profiles, cookies or terminal history).
$userData = Join-Path $env:APPDATA 'Envara'
$diag = Join-Path $out 'userdata-diagnostics'
if (Test-Path -LiteralPath $userData) {
  New-Item -ItemType Directory -Force -Path $diag | Out-Null
  Get-ChildItem -LiteralPath $userData -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\(diagnostics|runtime-diagnostics|startup-diagnostics)[^\\]*\\' -or $_.Name -match 'diagnostic' } |
    Where-Object { $_.Length -lt 2MB } |
    ForEach-Object {
      $relative = $_.FullName.Substring($userData.Length).TrimStart('\')
      $target = Join-Path $diag ($relative -replace '\\', '__')
      [IO.File]::WriteAllText($target, (Mask ([IO.File]::ReadAllText($_.FullName, $utf8))), $utf8)
    }
  $summary.userDataTopLevel = @(Get-ChildItem -LiteralPath $userData -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
}

$failed = @($summary.steps | Where-Object { $_.exitCode -ne 0 })
$summary.failedSteps = @($failed | ForEach-Object { $_.name })
$summary.finishedAt = (Get-Date).ToString('o')
[IO.File]::WriteAllText((Join-Path $out 'summary.json'), ($summary | ConvertTo-Json -Depth 6), $utf8)
$zip = "$out.zip"
Compress-Archive -Path (Join-Path $out '*') -DestinationPath $zip -Force
Write-Host ''
Write-Host "Logs: $out" -ForegroundColor Green
Write-Host "Archive to send back (review it first): $zip" -ForegroundColor Green
if ($failed.Count) {
  Write-Host ("Failed or timed out: " + ($summary.failedSteps -join ', ')) -ForegroundColor Red
  exit 1
}
exit 0
