<#
  Envara Windows test log collector (developer checkout, x64).

  Runs the automated checks and, optionally, one interactive desktop session,
  writing every command's output under test-artifacts\windows\<timestamp>\.
  It needs no administrator rights, installs nothing outside this checkout,
  never touches drivers/services/network settings, and does not upload
  anything. The Windows user name is masked in the copied logs; review the
  archive before sending it.

  Usage (from the repository root, normal PowerShell):
    powershell -ExecutionPolicy Bypass -File scripts\windows-test-collect.ps1            # automated checks
    powershell -ExecutionPolicy Bypass -File scripts\windows-test-collect.ps1 -Desktop   # + desktop session
    powershell -ExecutionPolicy Bypass -File scripts\windows-test-collect.ps1 -SkipInstall -Desktop
#>
[CmdletBinding()]
param([switch]$Desktop, [switch]$SkipInstall, [switch]$SkipTests)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = Join-Path $root "test-artifacts\windows\$stamp"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$summary = [ordered]@{ schema = 'envara.windows-test-run/v1'; startedAt = (Get-Date).ToString('o'); steps = @() }

function Mask([string]$text) {
  if (-not $text) { return $text }
  $text = $text.Replace($env:USERPROFILE, '%USERPROFILE%')
  if ($env:USERNAME) { $text = $text -replace [regex]::Escape($env:USERNAME), '<user>' }
  if ($env:COMPUTERNAME) { $text = $text -replace [regex]::Escape($env:COMPUTERNAME), '<host>' }
  return $text
}

function Step([string]$name, [string]$command) {
  Write-Host "==> $name : $command" -ForegroundColor Cyan
  $log = Join-Path $out "$name.log"
  $started = Get-Date
  & cmd.exe /d /s /c "$command 2>&1" | ForEach-Object { $_ } | Tee-Object -FilePath "$log.raw"
  $code = $LASTEXITCODE
  $seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
  Set-Content -LiteralPath $log -Value (Mask (Get-Content -LiteralPath "$log.raw" -Raw)) -Encoding UTF8
  Remove-Item -LiteralPath "$log.raw" -Force
  $script:summary.steps += [ordered]@{ name = $name; command = $command; exitCode = $code; seconds = $seconds }
  $color = 'Green'; if ($code -ne 0) { $color = 'Red' }
  Write-Host "<== $name exit $code ($seconds s)" -ForegroundColor $color
}

# Environment facts only: no account names, keys, network addresses or proxy settings.
$os = Get-CimInstance Win32_OperatingSystem
$summary.system = [ordered]@{
  caption = $os.Caption; version = $os.Version; build = $os.BuildNumber
  osArchitecture = $os.OSArchitecture; processArchitecture = $env:PROCESSOR_ARCHITECTURE
  locale = (Get-Culture).Name; uiLanguage = (Get-UICulture).Name; timeZone = (Get-TimeZone).Id
  is64BitProcess = [Environment]::Is64BitProcess
}
$tools = [ordered]@{}
foreach ($tool in @('node --version', 'npm --version', 'go version', 'git --version')) {
  try { $tools[$tool.Split(' ')[0]] = (& cmd.exe /d /c "$tool 2>&1" | Select-Object -First 1) } catch { $tools[$tool.Split(' ')[0]] = 'missing' }
}
$summary.tools = $tools
$summary.git = [ordered]@{
  branch = (& git rev-parse --abbrev-ref HEAD 2>$null); commit = (& git rev-parse HEAD 2>$null)
  dirty = [bool](& git status --porcelain 2>$null)
}

if (-not $SkipInstall) {
  Step '01-npm-ci' 'npm ci'
  Step '02-native-prepare' 'npm run native:prepare'
  Step '03-backend-prepare' 'npm run backend:prepare'
  Step '04-proxy-prepare' 'npm run proxy:prepare'
}
if (-not $SkipTests) {
  Step '10-npm-test' 'npm test'
  Step '11-build' 'npm run build'
  Step '12-test-sites' 'npm run test:sites'
}
if ($Desktop) {
  Write-Host ''
  Write-Host 'Starting the desktop app. Work through docs\windows-test-plan.md, then quit Envara' -ForegroundColor Yellow
  Write-Host '(tray/menu Quit or close the last window). Logs are captured until it exits.' -ForegroundColor Yellow
  Step '20-desktop-session' 'npm run desktop'
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
      Set-Content -LiteralPath $target -Value (Mask (Get-Content -LiteralPath $_.FullName -Raw)) -Encoding UTF8
    }
  $summary.userDataTopLevel = @(Get-ChildItem -LiteralPath $userData -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
}

$summary.finishedAt = (Get-Date).ToString('o')
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $out 'summary.json') -Encoding UTF8
$zip = "$out.zip"
Compress-Archive -Path (Join-Path $out '*') -DestinationPath $zip -Force
Write-Host ''
Write-Host "Logs: $out" -ForegroundColor Green
Write-Host "Archive to send back (review it first): $zip" -ForegroundColor Green
