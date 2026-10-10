<# Explicitly run only inside the task's disposable offline Windows x64 VM.
   This never marks the production adapter ready. The default is read-only. #>
[CmdletBinding()]
param([switch]$RunPty, [switch]$RunDriverLab, [switch]$ExportSerial)
$ErrorActionPreference = 'Stop'
$media = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $media 'PAYLOAD-SHA256.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.generation -ne 'v3' -or $manifest.guestArchitecture -ne 'x64') { throw 'Unexpected acceptance media' }
if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) { throw 'Windows x64 process required' }
foreach ($entry in $manifest.files) {
  if ($entry.name -match '(^|/)\.\.(/|$)|^[\\/]|:') { throw 'Unsafe payload entry' }
  $item = Get-Item -LiteralPath (Join-Path $media $entry.name)
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Regular payload file required' }
  if ($item.Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) {
    throw ('Changed acceptance payload: ' + $entry.name)
  }
}
if (-not $RunPty -and -not $RunDriverLab) {
  [pscustomobject]@{ plan = $true; payloadVerified = $true; fileCount = $manifest.files.Count; writesPerformed = $false;
    activatesDriver = $false; startsGUI = $false; productionReady = $false } | ConvertTo-Json
  return
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use an elevated interactive PowerShell in the disposable guest' }
if ([Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { throw 'An interactive guest session is required' }
$base = Join-Path $env:ProgramFiles 'Envara Acceptance Test'
if (-not (Test-Path -LiteralPath $base)) { New-Item -ItemType Directory -Path $base | Out-Null }
if ((Get-Item -LiteralPath $base).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Acceptance base cannot be a reparse point' }
$run = Join-Path $base ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $run | Out-Null
& "$env:SystemRoot\System32\icacls.exe" $run /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to protect the new acceptance directory' }
$summary = [ordered]@{ schema = 'envara.windows-offline-acceptance'; schemaVersion = 1; startedAt = [DateTime]::UtcNow.ToString('o');
  WindowsBuild = [Environment]::OSVersion.Version.ToString(); processSession = [Diagnostics.Process]::GetCurrentProcess().SessionId;
  isolatedGuest = $true; productionReady = $false; GUIAcceptance = $false; browserAcceptance = $false; testsUserAccounts = $false; results = @{} }
try {
  if ($RunPty) {
    Copy-Item -LiteralPath (Join-Path $media 'Desktop') -Destination $run -Recurse
    $desktop = Join-Path $run 'Desktop\win-unpacked'
    $report = Join-Path $run 'pty-report.json'
    $beforeRunAsNode = $env:ELECTRON_RUN_AS_NODE
    try {
      $env:ELECTRON_RUN_AS_NODE = '1'
      $fixture = Join-Path $PSScriptRoot 'accept-windows-pty.cjs'
      $arguments = @($fixture, $desktop, $report) | ForEach-Object {
        if ($_ -match '"') { throw 'Unsafe executable argument' }
        '"' + $_ + '"'
      }
      $ownedProcess = Start-Process -FilePath (Join-Path $desktop 'Envara.exe') -ArgumentList $arguments -PassThru
      if (-not $ownedProcess.WaitForExit(120000)) {
        $ownedProcess.Kill()
        $ownedProcess.WaitForExit()
        throw 'Packaged Electron PTY fixture timed out'
      }
      $exit = $ownedProcess.ExitCode
    } finally {
      if ($null -eq $beforeRunAsNode) { Remove-Item Env:ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue }
      else { $env:ELECTRON_RUN_AS_NODE = $beforeRunAsNode }
    }
    $summary.results.pty = @{ exitCode = $exit; report = $report; passed = $false }
    if (Test-Path -LiteralPath $report) { $summary.results.pty.passed = (Get-Content -LiteralPath $report -Raw | ConvertFrom-Json).passed -eq $true }
  }
  if ($RunDriverLab) {
    Copy-Item -LiteralPath (Join-Path $media 'Lab') -Destination $run -Recurse
    $lab = Join-Path $run 'Lab'
    $report = Join-Path $run 'capture-component-report.json'
    $beforeGate = $env:ENVARA_WINDOWS_CAPTURE_LAB
    $beforeReport = $env:ENVARA_WINDOWS_CAPTURE_REPORT
    try {
      $env:ENVARA_WINDOWS_CAPTURE_LAB = 'isolated-vm'
      $env:ENVARA_WINDOWS_CAPTURE_REPORT = $report
      & (Join-Path $lab 'envara-native-capture-lab.test.exe') -test.v '-test.run=^TestWinDivertCaptureLoopbackLab$' -test.timeout=3m
      $exit = $LASTEXITCODE
    } finally {
      if ($null -eq $beforeGate) { Remove-Item Env:ENVARA_WINDOWS_CAPTURE_LAB -ErrorAction SilentlyContinue } else { $env:ENVARA_WINDOWS_CAPTURE_LAB = $beforeGate }
      if ($null -eq $beforeReport) { Remove-Item Env:ENVARA_WINDOWS_CAPTURE_REPORT -ErrorAction SilentlyContinue } else { $env:ENVARA_WINDOWS_CAPTURE_REPORT = $beforeReport }
    }
    $summary.results.capture = @{ exitCode = $exit; report = $report; productionReady = $false }
  }
} finally {
  $summary.finishedAt = [DateTime]::UtcNow.ToString('o')
  $output = Join-Path $run 'acceptance-summary.json'
  $summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $output -Encoding UTF8
  Write-Output ('Evidence preserved at: ' + $output)
  if ($ExportSerial) {
    # Only test results cross the owned VM's serial device; no user files or network.
    $serial = New-Object IO.Ports.SerialPort('COM1', 115200, [IO.Ports.Parity]::None, 8, [IO.Ports.StopBits]::One)
    try {
      $serial.WriteTimeout = 5000
      $serial.Open()
      $serial.WriteLine('ENVARA_WINDOWS_SUMMARY ' + ($summary | ConvertTo-Json -Depth 12 -Compress))
      foreach ($name in @('pty-report.json', 'capture-component-report.json')) {
        $file = Join-Path $run $name
        if (Test-Path -LiteralPath $file) {
          $serial.WriteLine('ENVARA_WINDOWS_REPORT ' + ((Get-Content -LiteralPath $file -Raw | ConvertFrom-Json) | ConvertTo-Json -Depth 30 -Compress))
        }
      }
    } finally { $serial.Dispose() }
  }
}
