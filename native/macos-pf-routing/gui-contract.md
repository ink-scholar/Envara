# Cold GUI launch library preparation

`gui-launch.h` and `gui-launch.m` provide shared native inspection and
suspended-process lifecycle primitives. This document retains the original
standalone preparation and diagnostics. The production factory uses the
capability-gated `envara_notion_*` front adapter for recognized, signed
Electron/Chromium bundles. Its protocol names remain stable; they no longer mean
an exact Notion version allowlist. Unknown/native engine layouts refuse, with no
unfenced cold-launch fallback. The separate generic cold primitive remains for
fixtures and does not establish a production adapter.

`ENVARA_GUI_PRODUCTION_READY` and `ENVARA_NOTION_READY` remain `0`. Native staging
checks an installed sealed snapshot and leaves its child stopped before target
code; the surrounding authenticated supervisor controls the launch lifecycle.
Read-only inspection/plan does not install resources, activate PF, create groups
or utun, change routes/DNS or launch a user application. Metadata, signatures and
fixture checks do not establish full application acceptance. See
[the current front adapter and historical Notion inspection](notion-launch-versions.md).

## Implemented read-only inspection

`envara_gui_manifest_inspect()` accepts an original, canonical `.app` path and
parses its bounded `Contents/Info.plist` as an immutable property list. It
requires `CFBundlePackageType=APPL`, a bundle identifier and one basename for
`CFBundleExecutable`. The resulting executable must be a real, executable
Mach-O file at the original `Contents/MacOS` path; scripts and executable
symlinks are refused. Bundle aliases/translocated paths are not substituted.

The manifest records original paths, complete physical-tree SHA-256, normalized
complete-content SHA-256, executable SHA-256, file device/inode/size/owner/group/mode/mtime/ctime, code-directory hash
and designated signature requirement. Production inspection checks strict code
signature validity for all architectures and nested code. The tree walk permits
ordinary internal framework symlinks, rejects links resolving outside the
bundle, rejects special files and setid/group/world-writable real entries, and
hashes link text and metadata. It compares two complete scans and checks
individual regular-file identities before and after hashing. It never rewrites,
copies, re-signs or registers the app.

The normalized content digest includes relative paths, entry types, executable
permission bits, every regular file's bytes and internal symlink text. It binds
a separately installed snapshot to the original contents while allowing the
snapshot's owner/inode/timestamps to differ. Both manifests retain the separate
physical identity digest for mutation detection. Embedded NULs in plist string
metadata are rejected by UTF-8 byte-count parity, including binary plists.

This is an immutable **inspection result**, not filesystem sealing. Production
registration must put the expected manifest in the authenticated controller's
root-owned registry; a caller-supplied manifest/hash cannot authorize a launch.
App updates invalidate that registration and require fresh inspection.

### One verification per native operation

Native launch work is grouped into operations: ticket preparation, staging (from
ticket claim until the exact stopped child enters guardian custody) and resume.
The first check of an exact manifest in an operation is the full signed
inspection above: all bytes hashed in two scans around strict nested signature
validation. Later checks of that manifest in the same operation re-walk the
whole tree and require every entry's physical identity (relative path, device,
inode, size, modification and status-change times, owner, group, mode, link
count, link target) to equal the state the full inspection proved; they read
no bytes. The first registry resolve of an operation also validates the sealed
tree; later resolves in it rely on that identity re-proof. A witness never
crosses operations, threads or processes, and the outermost scope end clears
it. There is no time-based cache.

Without root, any write, truncate, chmod, chown, ACL, xattr, link or rename
changes at least one bound field, because the kernel stamps the status-change
time. The sealed snapshot is root-owned and read-only. For the user-owned
original, which is never executed, a change made through a shared writable
mapping may reach its times only at writeback; the next operation hashes its
bytes again. Root can bypass every one of these checks.

### Diagnostic step timing

After `L` is accepted, the keeper writes at most 16 `stage-progress` frames on
its own output: a fixed step name (`front-commit` … `stage-adopt`,
`resume-verify`), its monotonic milliseconds, the total since `L`, and how many
full inspections and identity re-proofs it ran. A frame is written whole only
when the output can take it now; otherwise it is dropped and never delays
staging. The controller keeps them with their receipt time and reports them
only as `applicationSnapshot().nativeStageTimings`. They are diagnostics, never
a receipt, readiness, protection or cleanup signal.

`envara_gui_original_running()` refuses a registered running app with the same
bundle identifier and any inspected executable under the original or sealed bundle for
the intended UID, including in-bundle helpers. An unreadable live process is
an error, not evidence of absence. The fixture version inspects only its own
direct children; it cannot establish a UID-wide production inventory.

## Strict request and fixed bootstrap route

The C request accepts only schema, lease/environment UUIDs, controller-derived
console UID, realm GID and kernel-derived requester GUI audit-session ID,
canonical existing workspace directory, a zoneinfo
timezone and a bounded language tag. It has no executable override, shell,
command arguments, arbitrary environment, proxy URL, node password, listener
credentials or bootstrap override. Malformed/unterminated values are rejected.
The console UID must still match `/dev/console`; the production GID must belong
to the realm allocation range. Existing `envara_spawn_suspended()` also verifies
the actual dedicated `_envara_pf_<gid>` group.

`envara_gui_bootstrap_plan()` is read-only. It requires an independently pinned
installed-native SHA-256, canonical fixed path, root ownership, safe Unix modes
and no extended ACL on the native file and its complete ancestor chain. It
constructs exactly this argument vector, with `ready=false`:

```text
/bin/launchctl asuser <verified-console-uid> \
  /Library/PrivilegedHelperTools/io.envara.pf-routing/envara-pf-native \
  gui-launch-lease <bounded-lease-uuid>
```

The plan stores strings without internal pointers; `envara_gui_bootstrap_argv()`
builds the pointer vector against the chosen plan instance, so copying the plan
does not leave dangling pointers. The production helper dispatches `gui-launch-lease`
through the fixed system `launchctl` with `shell:false`, a sanitized environment
and controlled stdio. Its UUID must resolve to an existing root-owned controller
lease; constructing this plan alone does not authorize execution. Public REST/MCP requests must never become an arbitrary root command,
launcher pathname, manifest/hash override or environment block.

The local `launchctl(1)` manual documents that `asuser` adopts the target user's
Mach bootstrap namespace, exception server and security audit session but does
**not** change UID/GID or adopt that user's environment. Starting with `setuid`
alone is insufficient. A `user/<uid>` domain can exist without a GUI login;
integration must require the actual `gui/<uid>` domain and a kernel-derived
authenticated requester session, then recheck the active console before resume.

`envara_gui_session_read()` obtains read-only native audit and public
`SessionGetInfo` evidence: audit user/session/flags and security-session graphics
access, rejecting initial/remote/root sessions for its graphics indicators. Its
`bootstrap_verified` is always false. These indicators alone do not attest the
Mach bootstrap namespace; GUI and user domains share registered names. No
`SessionCreate`, private `audit_session_join`, host timezone change or session
mutation is used. `asuser` success alone is not end-to-end GUI acceptance.

## Implemented self-owned lifecycle

Initialize fresh lifecycle storage with `envara_gui_lifecycle_init()`. Reusing a
completed lifecycle is refused while its scope remains unproved; initialization
must not erase a prior unresolved controller record. Fixture staging
requires an unprivileged, non-setuid caller; its own UID/GID and its own app
contents. It revalidates the manifest, validates the request and refuses an
already-running original before calling `envara_spawn_suspended_io()`. Supplied
fixture stdio must be caller-owned anonymous pipes with the appropriate
read/write direction; sockets, regular files, named FIFOs and arbitrary stdio
descriptors are refused.

Production staging takes distinct original and snapshot manifests. It rechecks
the unchanged original and strict original/snapshot content, identifier,
executable digest, code-directory hash and designated-requirement equality. The
snapshot must already exist below the fixed
`/Library/PrivilegedHelperTools/io.envara.pf-apps/objects` registry. Every real
snapshot file/directory and ancestor must be root-owned, free of extended ACLs,
setid/group/world-write permission, and regular-file hard links; symlinks must
remain internal. This function does not create or copy a snapshot. User-writable
original bundles cannot serve as the executable source.

It additionally requires real/effective root, execution from the fixed installed
native path with safe root-owned/ACL-free ancestors, only `/dev/null` target
stdio, the current console UID, and actual native audit/security graphics
evidence matching the authenticated requester's GUI session. It returns specific
preconditions such as `ROOT_SEALED_SIGNED_SNAPSHOT_REQUIRED`,
`FIXED_ROOT_NATIVE_ENTRY_REQUIRED` or
`AUTHENTICATED_CONSOLE_GUI_SESSION_REQUIRED`, rather than a universal stub.
Successful staging produces only a stopped native child and actual credential
evidence. It does not attest bootstrap routing or open protected launch.

Production staging also requires the fixed compiled root controller to supply
a read-only `verify_committed_deny` native function. It must independently verify
the already committed live realm deny lease before **any fork or UID change**;
the absence of that verifier returns `VERIFIED_COMMITTED_REALM_DENY_REQUIRED`.
Wire callers cannot supply a function pointer or its context, and the verifier
must not install rules as a side effect. Same-UID processes can send `SIGCONT`
to a console-owned child, so suspension is not an authorization barrier. A
future controller must retain denial even if target execution is continued
unexpectedly, and still verify bootstrap/DNS/guard/helper gates before claiming
protection. No verifier is integrated in the current runtime.

The existing native primitive creates a separate process group, applies the
production real/effective/saved UID and GID transition plus a sole realm
supplementary group, and stops before executing target code. Its production
stdio defaults to `/dev/null`. The target exec uses `POSIX_SPAWN_SETEXEC |
POSIX_SPAWN_CLOEXEC_DEFAULT` and explicitly inherits only stdio, closing inherited
network sockets even when the caller did not set `FD_CLOEXEC`. Fixtures retain
the caller's ordinary supplementary groups, and do not prove root credential
transition. The new library includes a read-only `KERN_PROC_PID` sole-group
predicate for future stopped-process integration.

The front adapter preserves the existing
`<environment>/<registration>/UserData` login path and prepares fixed `Home`,
`Cache`, `Temp` and `Extensions` siblings; VS Code shared data uses
`Home/.vscode-shared`. All are within Envara's own application-data layout.
Creation requires the existing authorized data-preparation operation, and the
console-owned `0700` directories are held and rechecked through suspended
staging. No plan or metadata inspection creates them.

Its child environment explicitly selects those home/cache/config/temp paths,
console USER/LOGNAME, fixed system PATH, request TZ and browser locale. LANG,
LC_CTYPE and LC_ALL use an installed UTF-8 locale with an explicit
`en_US.UTF-8` fallback recorded in the plan. The generic low-level fixture/cold
primitive still has its original console-HOME/`LANG=C` environment; the production
factory does not use it as a fallback for an unsupported application. Proxy,
`VSCODE_*` and loader variables are not inherited by the front adapter.

The supported engine receives fixed SOCKS/resolver/user-data/cache/locale flags;
verified VS Code also receives extension/shared-data directory flags. The outer
Seatbelt profile permits only the private IPv4 TCP front and denies direct DNS,
DNS-SD and known NSURLSession network-broker IPC. Its `--no-sandbox` flag keeps
the established Chromium internal-sandbox trade-off inside that outer fence.
Applications may ignore locale or storage conventions, and external helpers or
brokers require separate acceptance. These paths do not virtualize hardware,
fully isolate macOS Keychain or prove all native networking is covered. Actual
VS Code startup and extension behavior remain unverified.

Fixture resume rejects duplicate/out-of-order calls, re-inspects both manifests,
repeats running-instance refusal, checks exact PID/birth/credentials, and waits
for a bounded exec-error/EOF handshake. It then verifies the actual executable
path and manifest file identity separately from PID/birth, since PID/birth
survive `SETEXEC`. Timeout or bundle mutation cancels only the verified leader
and reaps it. Repeated stage cannot overwrite a live or reaped unresolved lifecycle. Natural leader
exit is reported separately from scope quiescence. `protected_ready` and
`scope_quiescent` remain false in all fixture states.
Wait status is cached and returned consistently on repeated terminal polls.

## Required integration gates

1. Authenticate the real requester and seal the app/environment lease in the
   root-owned registry, with strict wire key/type/size checking, duplicate-key
   rejection, nonce/lease freshness and only fixed native modes. Bind the lease
   to the installed-resource manifest and actual current console GUI session.
2. Invoke only the fixed `asuser` route, obtain native session evidence and
   attest its bootstrap entry. Apply UID/GID transition **after** entering that
   context. Verify real/effective/saved IDs and actual sole supplementary realm
   GID while the child is stopped. Do not initialize ordinary user groups.
3. Explicitly install a private root-sealed snapshot preserving the original's
   signature and complete contents, or establish an equivalent kernel-enforced
   no-credential-transition target invariant before target code executes. No
   snapshot installation has occurred. The original app may be user-writable; swapping
   it or changing it to setgid between inspection and exec can change credentials.
   A post-exec mismatch cannot protect the first packet. Double hashing alone
   does not close this race. Bind CWD by directory descriptor if mutable path
   replacement must be prevented. Preserve the original app's signed identity.
4. Commit and independently verify realm denial before creating a console-owned
   child, since another same-UID process can continue it. Commit verified pass
   ownership, live managed AnyTLS transport, DNS attribution and whole-guard
   crash protection before the authorized resume. Recheck
   console, bundle, singleton state and all runtime gates at the commit. Keep
   deny and resource leases until exact scope quiescence is proven on every
   error/EOF/timeout; this leader-only library does not authorize rule cleanup.
5. Verify first-packet routing and actual GUI cold startup using an owned GUI
   fixture before a specifically approved user-app test. Cover TCC/keychain,
   singleton IPC, helper/XPC/launchd delegation, app updates, detached children,
   IPv6/DNS, descriptor inheritance and unrelated apps. Descendant GID inheritance
   is not evidence that launchd/XPC helpers share the realm. Do not claim the
   application is protected when any gate remains unverified.

## Standalone tests

Run `node native/macos-pf-routing/gui-fixture.test.mjs`. This builds only these
new files plus the unchanged `launcher.c` in a task-owned temporary directory,
creates its own app bundle, uses an unconnected AF_INET descriptor and anonymous
pipes, and removes that directory afterward. It does not register the fixture
with LaunchServices or open a GUI. Checks include suspended-before-exec,
scoped environment and actual CWD, inherited descriptor closure and socket-as-stdio
refusal, original-child refusal, duplicate stage/resume and unresolved lifecycle
reuse refusal, cached wait status, mutation cancellation/reaping, malformed manifest and
request handling, canonical alias/script/external-link rejection, valid internal
links, binary-plist embedded-NUL rejection, pointer-free bootstrap-plan copy and
read-only strict inspection of Apple's signed Calculator bundle when
available. None of these checks opens production launch or proves root/GUI/PF
acceptance.
