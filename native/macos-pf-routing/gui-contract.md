# Cold GUI launch library preparation

`gui-launch.h` and `gui-launch.m` are an unintegrated native library. No current
controller, helper, installer, native CLI, resource map, or desktop action calls
them. `ENVARA_GUI_PRODUCTION_READY` is `0`. Production staging implements strict
preconditions for an already installed sealed snapshot and leaves its native
child stopped before app code; no production resume API exists. These files do
not install, activate PF, create groups or utun, change routes/DNS, or launch a
user application in their current disconnected state.

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

`envara_gui_original_running()` refuses a registered running app with the same
bundle identifier and any inspected executable under the original or sealed bundle for
the intended UID, including in-bundle helpers. An unreadable live process is
an error, not evidence of absence. The fixture version inspects only its own
direct children; it cannot establish a UID-wide production inventory. During
development on this Mac, a live unrelated extension-host process returned
`proc_pidpath` `ENOENT` while its process identity remained alive. Production
therefore currently fails closed on that inventory. No unrelated process was
stopped to make the test pass.

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
does not leave dangling pointers. There is no execution API for this plan. The installed native binary does not
currently expose `gui-launch-lease`. Future integration must execute the fixed
system `launchctl` with `shell:false`, a sanitized fixed environment and explicitly
controlled stdio; its UUID must resolve to one existing root-owned controller
lease. Public REST/MCP requests must never become an arbitrary root command,
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

The child's environment is built explicitly from console HOME/USER/LOGNAME,
fixed system PATH, `LANG=C`, request `TZ` and `ENVARA_BROWSER_LOCALE`. No proxy
environment variables substitute for network enforcement. CWD and TZ affect
only the owned child; `ENVARA_BROWSER_LOCALE` is a hint which generic GUI apps
may ignore, and does not attest actual browser locale support.

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
