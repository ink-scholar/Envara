#Requires -Version 5.1
<#
.SYNOPSIS
Read-only validation by default; explicit candidate component install/uninstall.
.DESCRIPTION
Never opens WinDivert, starts packet capture, changes a network route, or changes
the application-launch gate. Install and Uninstall require an elevated process.
The service and EnvaraCapture.dll are source-built candidates, not a release.
#>
[CmdletBinding()]
param(
    [ValidateSet('Validate', 'Plan', 'Install', 'Status', 'Uninstall')]
    [string]$Command = 'Validate',
    [string]$SourceBundle,
    [ValidatePattern('^[a-f0-9]{64}$')]
    [string]$ManifestSHA256,
    [switch]$StartService
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ServiceName = 'EnvaraAppRouting'
$ManifestName = 'install-manifest.json'
$ReceiptName = 'install-receipt.json'
$UpstreamCommit = '1789526ecfb9ff5397c94f9f54c1a3dc2fb60440'
$PinnedDriverSHA256 = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
$PinnedDLLSHA256 = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
$PinnedSourceSHA256 = '2955621df8f6ef32ad65170f0c0f11bd2f261cf5a960624f416d0b9c6343e99c'
# Embedded signer metadata from the exact pinned official driver, not a claim
# that the Windows trust chain, Secure Boot, HVCI or driver loading passed here.
$PinnedDriverSigner = '043589F75FCE2795E7F2CC3E526D46784D5DDAB3'
$PayloadNames = @(
    'EnvaraAppRouting.exe', 'EnvaraCapture.dll', 'WinDivert.dll', 'WinDivert64.sys',
    'capture-provenance.json', 'WinDivert-LICENSE', 'WinDivert-README',
    'WinDivert-corresponding-source.tar.gz', 'WinDivert-provenance.json',
    'ProxyBridge-LICENSE', 'CAPTURE-SOURCE.md', 'THIRD-PARTY-NOTICES.txt'
)
$TrustedOwners = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')

function Assert-WindowsX64 {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
        -not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
        throw 'Native x64 Windows and 64-bit PowerShell are required. No changes were made.'
    }
    $processors = @(Get-CimInstance -ClassName Win32_Processor)
    if ($processors.Count -eq 0 -or @($processors | Where-Object { $_.Architecture -ne 9 }).Count -ne 0) {
        throw 'This bundle supports native AMD64 Windows only; ARM64 is unavailable.'
    }
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Install/Uninstall requires an elevated administrator PowerShell. Use Run as administrator (UAC) and rerun the reviewed command.'
        }
    } finally { $identity.Dispose() }
}

function Get-SafeLocalPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:\\' -or
        $Path -match '["<>|?*\x00-\x1f/]' -or $Path.Substring(2).Contains(':')) {
        throw 'Only an absolute local drive path without ADS, device paths, wildcards or unsafe characters is allowed.'
    }
    foreach ($part in $Path.Substring(3).Split('\')) {
        if ($part -eq '.' -or $part -eq '..' -or ($part.Length -ne 0 -and ($part -match '[ .]$' -or $part -match '^ '))) {
            throw 'Traversal, ambiguous path components and trailing spaces/dots are forbidden.'
        }
    }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($full.Length -le 3) { throw 'A drive root cannot be used as a component directory.' }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    if (-not $drive.IsReady -or @([IO.DriveType]::Fixed, [IO.DriveType]::Removable, [IO.DriveType]::CDRom) -notcontains $drive.DriveType) {
        throw 'Mapped network, unknown and unavailable drives are not local bundle locations.'
    }
    return $full
}

function Get-InstallDirectory {
    # Do not trust a caller-set ProgramFiles environment variable.
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion', $false)
        if ($null -eq $key) { throw 'Windows Program Files location is unavailable.' }
        try { $programFiles = [string]$key.GetValue('ProgramFilesDir', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
        finally { $key.Dispose() }
    } finally { $base.Dispose() }
    $directory = Get-SafeLocalPath ([IO.Path]::Combine((Get-SafeLocalPath $programFiles), 'Envara', 'AppRouting'))
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($directory))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -cne 'NTFS') { throw 'The fixed installation requires a local NTFS Program Files volume.' }
    return $directory
}

function Assert-NoReparseAncestors([string]$Path) {
    $current = $Path
    while (-not [string]::IsNullOrEmpty($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse point rejected: $current" }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
}

function Assert-ProtectedACL([string]$Path, [bool]$FullWriteCheck) {
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($TrustedOwners -cnotcontains $owner) { throw "Unprivileged installation owner rejected: $Path" }
    $writeMask = [int64]([Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles)
    # Generic rights can remain unexpanded in an ACE returned by Get-Acl.
    $writeMask = $writeMask -bor [int64]0x10000000 -bor [int64]0x40000000
    if ($FullWriteCheck) { $writeMask = $writeMask -bor [int64][Security.AccessControl.FileSystemRights]::Write }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $inheritOnly = ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0
        $safeCreatorRule = $inheritOnly -and $rule.IdentityReference.Value -ceq 'S-1-3-0'
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            -not $safeCreatorRule -and ($FullWriteCheck -or -not $inheritOnly) -and
            ([int64]$rule.FileSystemRights -band $writeMask) -ne 0 -and
            $TrustedOwners -cnotcontains $rule.IdentityReference.Value) {
            throw "Untrusted installation write/delete permission rejected: $Path"
        }
    }
}

function Assert-ProtectedAncestors([string]$Path) {
    Assert-NoReparseAncestors $Path
    $current = $Path
    while (-not [string]::IsNullOrEmpty($current)) {
        if (Test-Path -LiteralPath $current) {
            if (-not (Get-Item -LiteralPath $current -Force).PSIsContainer) { throw "Installation ancestor is not a directory: $current" }
            # The root may grant creation of unrelated children; it must not
            # grant replacement/deletion of the protected Program Files child.
            $isRoot = $current.TrimEnd('\') -eq [IO.Path]::GetPathRoot($current).TrimEnd('\')
            Assert-ProtectedACL $current (-not $isRoot)
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
}

function Set-ExactACL([string]$Path, [bool]$Directory) {
    $acl = if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = if ($Directory) { [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-32-545')) {
        $rights = if ($sid -eq 'S-1-5-32-545') { [Security.AccessControl.FileSystemRights]::ReadAndExecute } else { [Security.AccessControl.FileSystemRights]::FullControl }
        $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), $rights,
            $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-ProtectedACL $Path $true
}

function Assert-Properties($Object, [string[]]$Names) {
    if ($null -eq $Object) { throw 'Required JSON object is absent.' }
    $actual = @($Object.PSObject.Properties | ForEach-Object { $_.Name })
    if ($actual.Count -ne $Names.Count) { throw 'JSON schema has missing or extra properties.' }
    foreach ($name in $actual) { if ($Names -cnotcontains $name) { throw 'JSON property name does not match the exact schema.' } }
}

function Get-StreamHash([IO.Stream]$Stream) {
    $Stream.Position = 0
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $digest = $algorithm.ComputeHash($Stream) } finally { $algorithm.Dispose(); $Stream.Position = 0 }
    return [BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
}

function Read-StreamJSON([IO.Stream]$Stream, [int]$MaximumBytes = 32768) {
    if ($Stream.Length -eq 0 -or $Stream.Length -gt $MaximumBytes) { throw 'JSON file size is invalid.' }
    $Stream.Position = 0
    $reader = [IO.StreamReader]::new($Stream, [Text.UTF8Encoding]::new($false, $true), $true, 1024, $true)
    try { $json = $reader.ReadToEnd() } finally { $reader.Dispose(); $Stream.Position = 0 }
    return ConvertFrom-Json -InputObject $json
}

function Assert-PE([IO.Stream]$Stream, [string]$Name) {
    if ($Stream.Length -lt 512) { throw "PE image is too short: $Name" }
    $reader = [IO.BinaryReader]::new($Stream, [Text.Encoding]::ASCII, $true)
    try {
        $Stream.Position = 0
        if ($reader.ReadUInt16() -ne 0x5a4d) { throw "PE DOS signature invalid: $Name" }
        $Stream.Position = 0x3c
        $offset = $reader.ReadUInt32()
        if ($offset -lt 64 -or [uint64]$offset + 168 -gt [uint64]$Stream.Length) { throw "PE header bounds invalid: $Name" }
        $Stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) { throw "PE architecture must be x64: $Name" }
        $Stream.Position = $offset + 22
        $characteristics = $reader.ReadUInt16()
        if (($characteristics -band 2) -eq 0) { throw "PE executable characteristic is absent: $Name" }
        $isDLL = ($characteristics -band 0x2000) -ne 0
        if (($Name.EndsWith('.dll') -and -not $isDLL) -or ($Name -ceq 'EnvaraAppRouting.exe' -and $isDLL)) { throw "PE image type mismatch: $Name" }
        $Stream.Position = $offset + 24
        if ($reader.ReadUInt16() -ne 0x20b) { throw "PE32+ is required: $Name" }
    } finally { $reader.Dispose(); $Stream.Position = 0 }
}

function Close-Bundle($Bundle) {
    if ($null -ne $Bundle) { foreach ($stream in $Bundle.Streams.Values) { $stream.Dispose() } }
}

function Open-VerifiedBundle([string]$Path, [string]$ExpectedManifestHash, [bool]$Installed = $false) {
    if ($ExpectedManifestHash -cnotmatch '^[a-f0-9]{64}$') { throw 'A separately reviewed raw install-manifest.json SHA-256 is required.' }
    $Path = Get-SafeLocalPath $Path
    Assert-NoReparseAncestors $Path
    if (-not (Get-Item -LiteralPath $Path -Force).PSIsContainer) { throw 'Bundle source must be a directory.' }
    $expected = @($PayloadNames) + @($ManifestName)
    if ($Installed) { $expected += $ReceiptName; Assert-ProtectedAncestors $Path }
    $children = @(Get-ChildItem -LiteralPath $Path -Force)
    if ($children.Count -ne $expected.Count) { throw 'Bundle has missing or extra entries; nothing will be overwritten or removed.' }
    foreach ($child in $children) {
        if ($child.PSIsContainer -or ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $expected -cnotcontains $child.Name) {
            throw 'Bundle entries must be the exact approved regular-file names.'
        }
        if ($Installed) { Assert-ProtectedACL $child.FullName $true }
    }
    $bundle = [pscustomobject]@{ Path = $Path; Streams = @{}; Manifest = $null; ManifestSHA256 = $ExpectedManifestHash; ServiceSignature = $null }
    try {
        foreach ($name in $expected) {
            # Existing source files are only read. Fresh destination files are
            # created from these locked streams; no source hardlink gets an ACL.
            $stream = [IO.File]::Open([IO.Path]::Combine($Path, $name), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            $bundle.Streams.Add($name, $stream)
            if ($stream.Length -gt 67108864) { throw 'Bundle artifact exceeds the supported size limit.' }
        }
        if ((Get-StreamHash $bundle.Streams[$ManifestName]) -cne $ExpectedManifestHash) { throw 'Manifest differs from the separately reviewed SHA-256 anchor.' }
        $manifest = Read-StreamJSON $bundle.Streams[$ManifestName]
        Assert-Properties $manifest @('schema', 'platform', 'architecture', 'service', 'captureAbi', 'engine', 'upstream', 'files')
        Assert-Properties $manifest.upstream @('project', 'version', 'commit')
        if ($manifest.schema -ne 1 -or $manifest.platform -cne 'windows' -or $manifest.architecture -cne 'x64' -or
            $manifest.service -cne $ServiceName -or $manifest.captureAbi -ne 1 -or $manifest.engine -cne 'windivert' -or
            $manifest.upstream.project -cne 'basil00/WinDivert' -or $manifest.upstream.version -cne '2.2.2' -or
            $manifest.upstream.commit -cne $UpstreamCommit -or $manifest.files -isnot [Array] -or $manifest.files.Count -ne $PayloadNames.Count) {
            throw 'Package identity, ABI, architecture or pinned upstream contract is invalid.'
        }
        $hashes = @{}
        foreach ($artifact in $manifest.files) {
            Assert-Properties $artifact @('name', 'sha256')
            if ($artifact.name -isnot [string] -or $PayloadNames -cnotcontains $artifact.name -or $hashes.ContainsKey($artifact.name) -or $artifact.sha256 -cnotmatch '^[a-f0-9]{64}$') {
                throw 'Artifact names/digests must be exact, unique approved values, never paths.'
            }
            $hashes.Add($artifact.name, $artifact.sha256)
            if ((Get-StreamHash $bundle.Streams[$artifact.name]) -cne $artifact.sha256) { throw "Artifact SHA-256 mismatch: $($artifact.name)" }
        }
        if ($hashes['WinDivert.dll'] -cne $PinnedDLLSHA256 -or $hashes['WinDivert64.sys'] -cne $PinnedDriverSHA256 -or
            $hashes['WinDivert-corresponding-source.tar.gz'] -cne $PinnedSourceSHA256) { throw 'Pinned upstream DLL, driver or complete source archive changed.' }
        $capture = Read-StreamJSON $bundle.Streams['capture-provenance.json']
        Assert-Properties $capture @('schema', 'captureAbi', 'engine', 'architecture', 'upstream', 'files')
        Assert-Properties $capture.upstream @('project', 'version', 'commit')
        if ($capture.schema -ne 1 -or $capture.captureAbi -ne 1 -or $capture.engine -cne 'windivert' -or $capture.architecture -cne 'x64' -or
            $capture.upstream.project -cne 'basil00/WinDivert' -or $capture.upstream.version -cne '2.2.2' -or $capture.upstream.commit -cne $UpstreamCommit -or
            $capture.files -isnot [Array] -or $capture.files.Count -ne 3) { throw 'Capture ABI manifest is invalid.' }
        $captureNames = @{}
        foreach ($artifact in $capture.files) {
            Assert-Properties $artifact @('name', 'sha256')
            if (@('EnvaraCapture.dll', 'WinDivert.dll', 'WinDivert64.sys') -cnotcontains $artifact.name -or
                $captureNames.ContainsKey($artifact.name) -or $artifact.sha256 -cne $hashes[$artifact.name]) { throw 'Capture and installation provenance do not agree.' }
            $captureNames.Add($artifact.name, $true)
        }
        $upstream = Read-StreamJSON $bundle.Streams['WinDivert-provenance.json']
        if ($upstream.version -cne '2.2.2' -or $upstream.commit -cne $UpstreamCommit -or $upstream.architecture -cne 'x64' -or
            $upstream.dllSha256 -cne $PinnedDLLSHA256 -or $upstream.driverSha256 -cne $PinnedDriverSHA256 -or
            $upstream.sourceSha256 -cne $PinnedSourceSHA256 -or $upstream.correspondingSource -cne 'WinDivert-corresponding-source.tar.gz') { throw 'Upstream source provenance is inconsistent.' }
        foreach ($name in @('EnvaraAppRouting.exe', 'EnvaraCapture.dll', 'WinDivert.dll', 'WinDivert64.sys')) { Assert-PE $bundle.Streams[$name] $name }
        $signature = Get-AuthenticodeSignature -LiteralPath ([IO.Path]::Combine($Path, 'WinDivert64.sys'))
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or $null -eq $signature.SignerCertificate -or
            @('Authenticode', 'Catalog') -cnotcontains ([string]$signature.SignatureType)) { throw 'The exact pinned driver must pass Windows Authenticode/catalog trust. No driver is loaded.' }
        # Windows prefers a catalog signature when present. The fixed driver
        # hash above anchors the bytes in either case; an embedded signature
        # also has to match the approved original embedded leaf certificate.
        if ([string]$signature.SignatureType -ceq 'Authenticode' -and $signature.SignerCertificate.Thumbprint -cne $PinnedDriverSigner) {
            throw 'Pinned driver embedded signer metadata does not match.'
        }
        $serviceSignature = Get-AuthenticodeSignature -LiteralPath ([IO.Path]::Combine($Path, 'EnvaraAppRouting.exe'))
        if ($serviceSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -and $serviceSignature.Status -ne [Management.Automation.SignatureStatus]::NotSigned) {
            throw 'Service EXE has an invalid signature; only an unsigned candidate or a valid signature is accepted.'
        }
        $bundle.Manifest = $manifest
        $bundle.ServiceSignature = [string]$serviceSignature.Status
        return $bundle
    } catch { Close-Bundle $bundle; throw }
}

function Get-ServiceRegistration {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $base.OpenSubKey(('SYSTEM\CurrentControlSet\Services\' + $ServiceName), $false)
        if ($null -eq $key) { return $null }
        try {
            return [pscustomobject]@{ ImagePath = [string]$key.GetValue('ImagePath', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);
                Type = $key.GetValue('Type', 0); Start = $key.GetValue('Start', 0); Account = [string]$key.GetValue('ObjectName', '') }
        } finally { $key.Dispose() }
    } finally { $base.Dispose() }
}

function Assert-OwnedService($Registration, [string]$Directory) {
    $expected = '"' + [IO.Path]::Combine($Directory, 'EnvaraAppRouting.exe') + '" --service'
    if ($null -eq $Registration -or -not [string]::Equals($Registration.ImagePath, $expected, [StringComparison]::OrdinalIgnoreCase) -or
        $Registration.Type -ne 16 -or $Registration.Start -ne 3 -or $Registration.Account -cne 'LocalSystem') {
        throw 'Existing service does not exactly match this installation, LocalSystem, OwnProcess and manual start. It will not be changed.'
    }
}

function Open-InstalledBundle([string]$Directory) {
    Assert-ProtectedAncestors $Directory
    $receiptPath = [IO.Path]::Combine($Directory, $ReceiptName)
    Assert-NoReparseAncestors $receiptPath
    Assert-ProtectedACL $receiptPath $true
    $stream = [IO.File]::Open($receiptPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { $receipt = Read-StreamJSON $stream } finally { $stream.Dispose() }
    Assert-Properties $receipt @('schema', 'product', 'service', 'architecture', 'installDirectory', 'manifestSHA256', 'candidate', 'captureActivated', 'acceptanceVerified')
    if ($receipt.schema -ne 1 -or $receipt.product -cne 'Envara.AppRouting' -or $receipt.service -cne $ServiceName -or $receipt.architecture -cne 'x64' -or
        -not [string]::Equals($receipt.installDirectory, $Directory, [StringComparison]::OrdinalIgnoreCase) -or
        $receipt.candidate -ne $true -or $receipt.captureActivated -ne $false -or $receipt.acceptanceVerified -ne $false) { throw 'Installation ownership receipt is invalid.' }
    return Open-VerifiedBundle $Directory $receipt.manifestSHA256 $true
}

function Install-Candidate($Bundle, [string]$Directory) {
    Assert-Administrator
    Assert-ProtectedAncestors $Directory
    if ((Test-Path -LiteralPath $Directory) -or $null -ne (Get-ServiceRegistration)) { throw 'A directory or service already exists. No upgrade, adoption or overwrite is permitted.' }
    $parent = [IO.Path]::GetDirectoryName($Directory)
    if (-not (Test-Path -LiteralPath $parent)) { [void][IO.Directory]::CreateDirectory($parent); Set-ExactACL $parent $true }
    Assert-ProtectedAncestors $parent
    $stage = [IO.Path]::Combine($parent, ('.AppRouting-stage-' + [Guid]::NewGuid().ToString('N')))
    [void][IO.Directory]::CreateDirectory($stage)
    Set-ExactACL $stage $true
    try {
        foreach ($name in (@($PayloadNames) + @($ManifestName))) {
            $target = [IO.Path]::Combine($stage, $name)
            $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $Bundle.Streams[$name].Position = 0; $Bundle.Streams[$name].CopyTo($output); $output.Flush($true) } finally { $output.Dispose() }
            Set-ExactACL $target $false
        }
        $receipt = [ordered]@{ schema = 1; product = 'Envara.AppRouting'; service = $ServiceName; architecture = 'x64';
            installDirectory = $Directory; manifestSHA256 = $Bundle.ManifestSHA256; candidate = $true; captureActivated = $false; acceptanceVerified = $false }
        $receiptPath = [IO.Path]::Combine($stage, $ReceiptName)
        [IO.File]::WriteAllText($receiptPath, (($receipt | ConvertTo-Json -Depth 4) + "`n"), [Text.UTF8Encoding]::new($false))
        Set-ExactACL $receiptPath $false
        $staged = Open-VerifiedBundle $stage $Bundle.ManifestSHA256 $true
        try { $stagedSignature = $staged.ServiceSignature } finally { Close-Bundle $staged }
        if ((Test-Path -LiteralPath $Directory) -or $null -ne (Get-ServiceRegistration)) { throw 'Installation destination changed during validation.' }
        [IO.Directory]::Move($stage, $Directory)
        $installed = Open-InstalledBundle $Directory
        try {
            $binaryPath = '"' + [IO.Path]::Combine($Directory, 'EnvaraAppRouting.exe') + '" --service'
            New-Service -Name $ServiceName -BinaryPathName $binaryPath -StartupType Manual -DisplayName 'Envara App Routing (candidate)' -Description 'Candidate component. DNS/native acceptance incomplete; protected application launch remains disabled.' | Out-Null
            Assert-OwnedService (Get-ServiceRegistration) $Directory
            if ($StartService) {
                Start-Service -Name $ServiceName
                $controller = Get-Service -Name $ServiceName
                try { $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30)) } finally { $controller.Dispose() }
            }
        } finally { Close-Bundle $installed }
        return [pscustomobject]@{ command = 'Install'; installed = $true; serviceStarted = [bool]$StartService; directory = $Directory;
            serviceSignature = $stagedSignature; candidate = $true; captureActivated = $false; acceptanceVerified = $false; launchEnabled = $false }
    } catch {
        # No automatic recursive deletion or service rollback: preserve every
        # recoverable candidate byte and report the exact owned path to inspect.
        throw "Installation stopped; component files are retained at '$stage' or '$Directory'. No capture or launch gate was activated. $($_.Exception.Message)"
    }
}

function Uninstall-OwnedService([string]$Directory) {
    Assert-Administrator
    $bundle = Open-InstalledBundle $Directory
    try {
        Assert-OwnedService (Get-ServiceRegistration) $Directory
        $controller = Get-Service -Name $ServiceName
        try {
            if ($controller.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) { $controller.Stop() }
            $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
        } finally { $controller.Dispose() }
        Assert-OwnedService (Get-ServiceRegistration) $Directory
        $sc = [IO.Path]::Combine([Environment]::GetFolderPath('System'), 'sc.exe')
        $output = & $sc delete $ServiceName 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) { throw "Owned service deletion failed with exit code $exitCode; all component files are retained." }
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while ($null -ne (Get-ServiceRegistration) -and [DateTime]::UtcNow -lt $deadline) { [Threading.Thread]::Sleep(100) }
        if ($null -ne (Get-ServiceRegistration)) { throw 'Service deletion is still pending. All component files and the receipt are retained.' }
        return [pscustomobject]@{ command = 'Uninstall'; serviceRemoved = $true; filesRetained = $true; directory = $Directory;
            otherWinDivertComponentsChanged = $false; captureActivated = $false; acceptanceVerified = $false }
    } finally { Close-Bundle $bundle }
}

Assert-WindowsX64
if ($StartService -and $Command -ne 'Install') { throw '-StartService is only available with explicit Install.' }
$destination = Get-InstallDirectory
Assert-ProtectedAncestors $destination

switch ($Command) {
    { $_ -in @('Validate', 'Plan', 'Install') } {
        if ([string]::IsNullOrWhiteSpace($SourceBundle) -or [string]::IsNullOrWhiteSpace($ManifestSHA256)) { throw '-SourceBundle and the separately reviewed -ManifestSHA256 are required.' }
        $bundle = Open-VerifiedBundle $SourceBundle $ManifestSHA256
        try {
            if ($Command -eq 'Install') { Install-Candidate $bundle $destination }
            else {
                $registration = Get-ServiceRegistration
                if ($null -ne $registration) { Assert-OwnedService $registration $destination }
                [pscustomobject]@{ command = $Command; validated = $true; writesPerformed = $false; directory = $destination;
                    destinationExists = (Test-Path -LiteralPath $destination); serviceExists = ($null -ne $registration); serviceSignature = $bundle.ServiceSignature;
                    candidate = $true; captureActivated = $false; acceptanceVerified = $false; launchEnabled = $false;
                    plan = @('Refuse any existing service/destination; create protected stage and fresh files', 'Reverify staged hashes, ABI, driver trust and exact names', 'Move into fixed directory; register manual LocalSystem service', 'Start service only with explicit Install -StartService; routing acceptance remains incomplete') }
            }
        } finally { Close-Bundle $bundle }
    }
    'Status' {
        $bundle = Open-InstalledBundle $destination
        try {
            $registration = Get-ServiceRegistration
            if ($null -ne $registration) { Assert-OwnedService $registration $destination }
            [pscustomobject]@{ command = 'Status'; filesValidated = $true; serviceRegistered = ($null -ne $registration); directory = $destination;
                candidate = $true; captureActivated = $false; acceptanceVerified = $false; launchEnabled = $false; writesPerformed = $false }
        } finally { Close-Bundle $bundle }
    }
    'Uninstall' { Uninstall-OwnedService $destination }
}
