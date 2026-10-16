# Signed Electron/Chromium launch capability

The `envara_notion_*` native names and diagnostic identifiers remain for private
protocol compatibility. They identify a capability-gated front adapter,
not a Notion application-name or exact-version allowlist.

## Current capability checks

The original and root-sealed registered copy must remain unchanged and retain
matching content digest, code-directory hash and designated signature
requirement. The main bundle and contained engine receive strict nested-code
and all-architecture signature validation against the original vendor identity;
the framework must have the same signing team. Ad-hoc/unsigned fixtures do not
receive launch authority.

The native classifier reads bounded bundle/framework metadata and inspects the
contained native Mach-O framework without loading its code:

- Electron requires `AtomApplication`, the `Electron Framework.framework`
  package metadata and a defined `_ElectronMain` entry.
- Chromium requires `BrowserCrApplication`, one matching framework whose bundle
  identifier is the application identifier plus `.framework`, and a defined
  `_ChromeMain` entry. Ambiguous matching frameworks refuse.
- Both require the expected application/framework package types, contained
  executable paths, and a numeric framework version with two to four components.
  Missing, escaped, damaged or unrecognized engine layouts refuse. This does not
  enable arbitrary native applications or fall back to an unfenced cold launch.

VS Code receives additional extension/shared-data flags only when its signed
stable or Insiders bundle identifier and bounded `product.json` fields agree.
Metadata eligibility is followed by native identity checks; it does not prove
that every application or extension honors every Chromium flag.

## Scoped state and process environment

The existing login path is preserved:

```text
/Library/PrivilegedHelperTools/io.envara.pf-app-data/<environment>/<registration>/UserData
```

`Home`, `Cache`, `Temp` and `Extensions` are fixed siblings. VS Code additionally
uses `Home/.vscode-shared`. Existing authorized data preparation creates and
checks these console-owned `0700` directories under nonwritable root-owned
ancestors; read-only inspection and plan do not allocate them. Held descriptors
and path identities are rechecked through suspended staging.

The adapter sets `--user-data-dir`, `--disk-cache-dir` and, for verified VS Code,
`--extensions-dir` and `--shared-data-dir`.

macOS limits a Unix socket path to 103 characters, and these paths are about
135. VS Code binds its main socket inside `--user-data-dir` and its IPC pipes in
`TMPDIR`, so it exited at start (`listen EINVAL`) before drawing a window.
Data preparation therefore also creates two root-owned symlinks in the
root-owned `0755` directory `/Library/PrivilegedHelperTools/io.envara.pf-s`,
named from both identifiers, that point to this registration's `UserData` and
`Temp`. VS Code receives the `UserData` alias as `--user-data-dir`; every engine
receives the `Temp` alias as `TMPDIR`/`TMP`/`TEMP`. The data stays where it was,
existing sign-in data is untouched, and the plan and the pre-spawn and stopped
rechecks require each alias to still name exactly its directory. Deleting an
environment's data removes its aliases. The same arguments, environment and
Seatbelt profile run an unprivileged VS Code through such aliases to a window,
with its update check refused by the unreachable proxy instead of going direct. It builds a fresh child environment
with scoped `HOME`, cache/config/temp paths, request timezone and browser locale.
`LANG`, `LC_CTYPE` and `LC_ALL` use an installed UTF-8 locale; an unavailable or
unrecognized requested language has an explicit `en_US.UTF-8` fallback in the
plan. Host `VSCODE_*`, proxy and loader variables are not inherited. These are
application/configuration paths, not a filesystem or hardware sandbox. The OS
Keychain encryption key may remain shared even when encrypted application
storage is separate; complete Keychain isolation is not claimed.

The outer Seatbelt profile allows outbound sockets only to the exact private
IPv4 TCP front. Direct DNS ports, DNS-SD IPC and the known `nsurlsessiond`
services are denied. Fixed SOCKS, resolver and `--no-sandbox` arguments remain;
`--no-sandbox` disables the application's internal Chromium sandbox because it
cannot nest inside the existing outer profile. This trade-off does not establish
coverage of every external broker, helper or native API.

## Verification boundary

Native fixtures cover read-only engine/signature inspection, malformed Mach-O inputs,
scoped path/UTF-8 construction and local Seatbelt socket/descendant denials.
These checks alone do not prove authorized application launch. Actual VS Code startup, extensions,
account flows, complete failure cleanup and unaffected-application behavior
remain application acceptance work. Generic `ready`/`protected` claims remain
closed; no full hardware, Keychain or tracking-elimination guarantee follows.

## Compatibility with the former Notion gate

The earlier native candidate accepted signed Notion **7.34.0** or **7.37.1**,
paired only with Electron **43.6.0**, identifier `notion.id` and vendor team
`LBQJ96FQ8D`. Other versions then refused. That former allowlist is historical;
The current adapter uses the capability and identity checks above.
