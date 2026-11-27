# Envara: open a web link in this environment's browser (Windows).
# $BROWSER runs this as a command line; the link arrives as its own argument and
# is never re-parsed by cmd.exe. Every outcome is said on the terminal, and a
# refusal never opens a browser on the host network instead.
$ErrorActionPreference = 'Stop'
function Say([string] $message) { [Console]::Error.WriteLine("envara: $message") }

# "%s" is a placeholder some callers pass through literally.
$targets = @($args | Where-Object { $_ -is [string] -and $_ -ne '' -and $_ -ne '%s' })
if ($targets.Count -eq 0) { Say '没有收到要打开的链接。'; exit 1 }
foreach ($target in $targets) {
  if ($target -notmatch '^https?://\S+$') { Say "只打开 http/https 链接；没有打开：$target"; exit 1 }
}

$prefix = '\\.\pipe\'
$socket = [string] $env:ENVARA_LINK_SOCKET
$pipeName = if ($socket.StartsWith($prefix)) { $socket.Substring($prefix.Length) } else { '' }
if (-not $env:ENVARA_LINK_TOKEN -or $pipeName -notmatch '^envara-link-[A-Za-z0-9-]+$') {
  Say '这个终端没有连上 Envara 的链接通道，链接没有打开。请新建一个终端再试。'; exit 1
}

$status = 0
foreach ($target in $targets) {
  $code = 0; $browser = $null
  try {
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
    try {
      $pipe.Connect(5000)
      $body = [Text.Encoding]::UTF8.GetBytes((@{ url = $target } | ConvertTo-Json -Compress))
      $head = [Text.Encoding]::ASCII.GetBytes("POST /link HTTP/1.1`r`nHost: localhost`r`nAuthorization: Bearer $($env:ENVARA_LINK_TOKEN)`r`nContent-Type: application/json`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n")
      $pipe.Write($head, 0, $head.Length); $pipe.Write($body, 0, $body.Length); $pipe.Flush()
      $buffer = New-Object byte[] 8192; $received = New-Object System.IO.MemoryStream
      while (($read = $pipe.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $received.Write($buffer, 0, $read)
        if ($received.Length -gt 65536) { break }
      }
      $reply = [Text.Encoding]::UTF8.GetString($received.ToArray())
      if ($reply -match '^HTTP/1\.1 (\d{3})') { $code = [int] $Matches[1] }
      $split = $reply.IndexOf("`r`n`r`n")
      if ($code -eq 200 -and $split -ge 0) { try { $browser = ($reply.Substring($split + 4) | ConvertFrom-Json).browser } catch { } }
    } finally { $pipe.Dispose() }
  } catch { $code = 0 }
  switch ($code) {
    200 { if ($browser) { Say "正在「$browser」中打开 $target" } else { Say "已交给系统默认浏览器打开，不经过境舱网络：$target" } }
    403 { Say '链接通道已更换（Envara 重启过）；请新建一个终端再打开链接。'; $status = 1 }
    400 { Say "这个链接无法打开：$target"; $status = 1 }
    0 { Say 'Envara 没有响应，链接没有打开。'; $status = 1 }
    default { Say "Envara 没有打开这个链接（$code）。"; $status = 1 }
  }
}
exit $status
