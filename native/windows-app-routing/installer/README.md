# Windows component installer candidate

`Install-AppRouting.ps1` is a reviewable Windows x64 component installer. Its default command is **Validate**, which reads the selected bundle, signatures, ACLs and service registration. `Plan` is also read-only. Neither command executes bundle code, loads a DLL/driver, starts capture, registers a service or changes network configuration.

This script and the source-built `EnvaraAppRouting.exe`/`EnvaraCapture.dll` are candidates. An unsigned service EXE is reported as `NotSigned`; it is not a production-signed release. Package validation and a running service do not establish DNS isolation, crash protection, Secure Boot/HVCI compatibility or Windows routing acceptance. All results keep `captureActivated`, `acceptanceVerified` and `launchEnabled` false. The service's existing acceptance gate remains authoritative.

## Input contract

Use native AMD64 Windows with 64-bit PowerShell 5.1 or later. ARM64 and 32-bit PowerShell are rejected. The source must be an absolute local path on an available fixed/removable/CD-ROM drive; mapped network drives are rejected. The install location is fixed to the OS's 64-bit Program Files directory plus `Envara\AppRouting`, normally `C:\Program Files\Envara\AppRouting`, on a local NTFS volume; it is read from the protected registry location, not a caller-controlled environment variable.

The source directory must contain exactly these 12 payload files and `install-manifest.json`, with no extra file or subdirectory:

```text
EnvaraAppRouting.exe
EnvaraCapture.dll
WinDivert.dll
WinDivert64.sys
capture-provenance.json
WinDivert-LICENSE
WinDivert-README
WinDivert-corresponding-source.tar.gz
WinDivert-provenance.json
ProxyBridge-LICENSE
CAPTURE-SOURCE.md
THIRD-PARTY-NOTICES.txt
install-manifest.json
```

The build produces `install-manifest.json` with this exact schema. Every payload filename occurs once, and each digest is lowercase SHA-256:

```json
{
  "schema": 1,
  "platform": "windows",
  "architecture": "x64",
  "service": "EnvaraAppRouting",
  "captureAbi": 1,
  "engine": "windivert",
  "upstream": {
    "project": "basil00/WinDivert",
    "version": "2.2.2",
    "commit": "1789526ecfb9ff5397c94f9f54c1a3dc2fb60440"
  },
  "files": [
    { "name": "EnvaraAppRouting.exe", "sha256": "<reviewed build digest>" }
  ]
}
```

The example's `files` array is abbreviated; the real manifest must contain all 12 payload entries. `-ManifestSHA256` must be the separately reviewed raw manifest digest from build/review output. Recomputing a digest from an untrusted package does not authenticate that package. There is no signed release-manifest trust anchor in this candidate workflow.

The script checks the fixed capture ABI, agreement with `capture-provenance.json`, x64 PE headers, every payload digest, and the pinned original WinDivert DLL, driver and complete corresponding-source archive. It verifies the driver through Windows `Get-AuthenticodeSignature`: status must be `Valid`. When Windows reports the embedded Authenticode signature, its leaf thumbprint must be `043589F75FCE2795E7F2CC3E526D46784D5DDAB3`; when Windows prefers a catalog signature, the valid catalog trust result is accepted with the same exact pinned driver hash. The embedded leaf belongs to the original pinned driver's Sectigo chain; it is not described as a Microsoft attestation. Certificate metadata read on another platform is not Windows trust validation. [Microsoft Authenticode command and catalog preference](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature).

## Read-only validation and plan

These examples are Windows commands, not instructions to run the installer on macOS. Replace the digest with the reviewed build's 64 lowercase hexadecimal characters.

```powershell
.\Install-AppRouting.ps1 -SourceBundle 'C:\ReviewedBuild\x64' -ManifestSHA256 '<reviewed-manifest-sha256>'
.\Install-AppRouting.ps1 -Command Plan -SourceBundle 'C:\ReviewedBuild\x64' -ManifestSHA256 '<reviewed-manifest-sha256>'
```

Validate/Plan do not request UAC and make no installer writes. Windows signature verification may perform the operating system's normal certificate checks. A conflicting same-name service causes refusal. An existing fixed directory is reported in the plan; Install will refuse it rather than adopt or overwrite it.

## Explicit installation

Open **64-bit Windows PowerShell → Run as administrator**, review the UAC prompt, then issue the explicit command. The script does not elevate itself, change execution policy or bypass organizational policy.

```powershell
.\Install-AppRouting.ps1 -Command Install -SourceBundle 'C:\ReviewedBuild\x64' -ManifestSHA256 '<reviewed-manifest-sha256>'
```

Installation first verifies the complete input. It refuses reparse points on every existing source/destination ancestor, path traversal, UNC/device/ADS paths, wrong names, unsafe installation ancestors, a preexisting fixed destination or any preexisting same-name service. Source files are held open without write/delete sharing and copied as fresh files, so source hardlinks are never modified or assigned installation ACLs.

A new stage under the protected `Envara` parent receives a fresh protected DACL: SYSTEM and Administrators FullControl, Users ReadAndExecute. No inherited or old explicit grants are retained. Payloads and the ownership receipt receive their own protected ACLs. Staged hashes, ABI and driver trust are checked again before moving into the fixed directory. The script leaves a complete `install-receipt.json` that records the owned path and raw manifest digest. Existing unrelated parent ACLs are audited rather than rewritten. [Microsoft ACL permissions](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls).

The only registered service is `EnvaraAppRouting`, OwnProcess, LocalSystem, manual startup, with the exact quoted binary path:

```text
"C:\Program Files\Envara\AppRouting\EnvaraAppRouting.exe" --service
```

The actual Program Files root may differ from `C:`. Service registration is queried again after creation. Add `-StartService` only when deliberately starting the candidate service. Starting it does not open WinDivert or authorize protected application launch. No WinDivert registry key or driver service is created, edited or deleted by this installer. Other applications' existing WinDivert installations remain untouched. [Microsoft service creation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create).

## Status and service uninstall

`Status` reads the protected receipt and revalidates the installed bundle and exact service identity. It does not execute the service EXE or activate capture:

```powershell
.\Install-AppRouting.ps1 -Command Status
```

From an elevated administrator PowerShell, explicit Uninstall verifies the owned receipt, complete package, ACLs and exact service path/account/type/manual-start configuration. It stops only that service, waits for confirmed `Stopped`, rechecks ownership, then deletes only that SCM registration:

```powershell
.\Install-AppRouting.ps1 -Command Uninstall
```

**All component files and the ownership receipt remain in the protected directory for recovery.** Uninstall does not delete files, terminate unrelated processes, remove shared WinDivert drivers or change other WinDivert services/registry entries. Any ownership mismatch, stop timeout, native command failure or pending service deletion preserves the files and reports failure. Install failures likewise retain the protected stage/final directory; there is no automatic recursive cleanup or upgrade path. An administrator must review retained files before any later manual cleanup or reinstall.

## Verification limits

The implementation was reviewed statically on macOS and parsed with the Tree-sitter PowerShell grammar. PowerShell itself was unavailable there, and no installer command, UAC flow, ACL mutation, SCM operation or Windows network test was executed. Grammar parsing is not validation by the PowerShell engine, Windows installation testing or routing acceptance.

`verify_installer.py` never runs PowerShell. It checks the script grammar and the actual candidate bundle's exact names, installer schema, externally supplied manifest digest, all payload digests, capture-manifest agreement, pinned upstream hashes and static x64 PE headers. It prints JSON by default; an explicit `--report` writes the requested evidence file. The parser dependencies used were `tree-sitter==0.25.2` and `tree-sitter-powershell==0.26.4` in a temporary directory. Use the manifest anchor printed by the reviewed component build; it changes between builds. The reproduction command from the repository root is:

```sh
PYTHONPATH=/tmp/envara-installer-psparse python3 native/windows-app-routing/installer/verify_installer.py \
  --bundle build/app-routing/win32/x64 \
  --expected-manifest-sha256 '<reviewed-manifest-sha256>' \
  --report test-artifacts/windows-routing/static-install.json
```

The ignored report records this check and explicitly marks PowerShell engine, Windows Authenticode, UAC/ACL/SCM installation and native routing acceptance as untested. A later build changes the manifest anchor and requires a new check; an artifact-specific report is not committed as a permanent acceptance record.

Before distributing or enabling attached-application launch, native Windows testing must cover wrong same-name services, unsafe ACLs, ancestor junctions, malformed/extra-name manifests, source replacement during copy, invalid driver trust, install interruption, service startup failure, stop timeout and pending SCM deletion. Confirm that service status never opens WinDivert and that other applications' network paths are preserved.
