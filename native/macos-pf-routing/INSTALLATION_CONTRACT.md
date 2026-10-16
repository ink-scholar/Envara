# Fixed PF helper resource installation

`EnvaraPFInstall` defaults to `--plan`. It reads the fixed payload, hashes each
file, inspects any existing destination, and reports `readOnly:true` and
`ready:false`. It never requests authorization in this mode.

The build supplies `installer-manifest.h` using this contract:

```c
#define ENVARA_PF_INSTALL_SOURCE "/absolute/build/app-routing/macos-pf"
#define ENVARA_PF_INSTALL_MANIFEST_SHA256 "64-lowercase-hex-digest"
typedef struct {
    const char *name;
    const char *sha256;
    unsigned int mode;
} EnvaraPFInstallFile;
static const EnvaraPFInstallFile ENVARA_PF_INSTALL_FILES[] = {
    /* Relative paths; modes are exactly 0644 or 0755. */
};
#define ENVARA_PF_INSTALL_FILE_COUNT \
    (sizeof(ENVARA_PF_INSTALL_FILES) / sizeof(ENVARA_PF_INSTALL_FILES[0]))
```

The table includes `manifest.json`, whose digest equals the manifest macro.
It excludes the installer itself to avoid a self-referential digest. The
runtime source is only the installer's canonical executable directory, so a
relocated bundle still needs every compiled digest to match. CLI arguments
cannot select source files, destinations or commands.

Only after the user explicitly approves this concrete installation may the
desktop invoke `--request-install`. It requests administrator authorization
through Security.framework; credentials stay in macOS's native UI. There is
no Apple Developer identity requirement, `osascript`, password input, shell,
SIP modification or alternate elevation mechanism.

Authorization launches this installer's fixed `--install-fixed-manifest`
operation. It checks its privileged authorization reference and performs only
file copying into `/Library/PrivilegedHelperTools/io.envara.pf-routing`:

* Fixed manifest files only; reads and copies use the same no-follow file FD.
* SHA-256, regular-file, single-link, bounds and mutation checks.
* Root-owned safe ancestors, without writable extended ACLs.
* Root-owned private staging; inherited ACLs are removed from new objects.
* Atomic exclusive directory rename for a new installation, with no overwrite
  of an unknown or conflicting installation. An exact existing installation is
  idempotent only when no staging evidence remains.
* Parent confirms the child's bounded completion and rechecks installed bytes.

This operation does **not** load PF rules, create groups or tunnels, change
DNS, register/start a daemon or launch an application. Installed resources
still report `ready:false`; separate native routing acceptance remains
required before protected application launch.

## Per-run hook receipts and retained recovery state

The runtime uses `io.envara.pf.run.<canonical-v4-UUID>` for each
new run. Its separate root-owned `io.envara.pf-run-ledger` burns each run identity
before INSERT and persists a delete intent before the first DELETE attempt.
Lost replies are resolved through read-only receipt checks; a stale or retired
receipt cannot authorize another DELETE. The bounded ledger never resets or
reuses an identity when storage, locking or capacity checks fail.

Resource installation and native routing acceptance are separate. Retained
runtime records must be inspected before replacement; an empty namespace is not
evidence that every lease was released. Recovery and installation use normal
macOS authorization and retain ownership evidence.

## Exact known prior version upgrade

The compile-time prior snapshot collection is defined in `authorize-install.c`
and `installer-upgrade-*.h`. Corresponding `known-installations/*.manifest.json`
files preserve each accepted version's exact public build metadata. These are
upgrade trust inputs and must retain their original bytes.

The installer never takes an allowlist from an installed or caller-provided
manifest. Every old byte, relative path, file type, link count, mode, root owner
and ACL must match its independent fixed table; extra or unknown files refuse
replacement. All prior snapshot source artifacts participate in the build
snapshot and package verification. Each prior version has its own exact file
count. Building an installer does not modify installed resources or retained
runtime evidence.

A read-only plan reports `existingInstallation:"known-prior"`, the exact
`priorManifestSHA256` and `requiresUpgradeApproval:true`. A new system update
requires approval of the concrete new payload; an earlier installation or
controlled-test approval is not permission to replace root resources. The
successful file-only upgrade retains the `installedResourcesOnly` action and
`installed-resources-only` reason, with `changed:true`, the new manifest digest
and the prior digest. It never asserts authorization, activation or readiness.

The root installer holds an exclusive nonblocking lock on the already verified
`PrivilegedHelperTools` directory FD from destination inspection through
staging, commit, post-checks, rollback and cleanup. It stages the complete new
fixed table first, flushes each file and directory, and checks both held
directory identities again before `RENAME_SWAP`. The old directory remains at
the invocation's staging name until the parent directory is flushed and both
snapshots and inode identities pass post-swap checks. Only that proven exact
old directory can then be removed; the parent is flushed after cleanup.

If a post-swap check fails, rollback exchanges only the same two held directory
identities and requires the old snapshot still to match. A replacement target
or corrupted prior snapshot is preserved and reported as unconfirmed. Any
pre-existing name beginning `.io.envara.pf-routing-stage-`, including a
symlink or incomplete crash backup, blocks installation and controlled launch
with `needsManualReview:true`; it is never automatically discarded. A crash
can therefore leave a new target and old staging evidence, or an intact old
target and incomplete new stage. The installer reports either situation for
manual review rather than interpreting a matching target as complete recovery.

The current runtime root is the separate fixed directory
`/Library/PrivilegedHelperTools/io.envara.pf-runtime`, with safe root-owned
ancestors and mode `0700`. The root installer accepts an absent or completely
empty safe runtime directory; any entry, including unknown evidence, blocks
updating. The unprivileged read-only plan can verify that directory's root
owner, exact mode, no-follow identity and absence of writable ACLs without being
allowed to read its contents. A permission refusal in that exact safe case
reports `privateRuntimeInspectionRequired:true`,
`canRequestAuthorizationForInspection:true` and
`controlledRuntimeAbsent:false`. `canRequestInstall:true` then permits only a
user-approved administrator precheck followed by a file-only update if the
strict root inspection succeeds. It does not assert that the directory is
empty. The root entry checks emptiness before any filesystem creation and
again under its exclusive installation lease; the private-inspection state is
never accepted as permission for a root write. Unknown ownership, ACLs, modes,
links, nonempty content or unverifiable metadata still refuse authorization.
It also checks the fixed legacy `/var/run/envara-pf-routing` name without
opening it. Stock macOS's canonical `/private/var/run` parent may be
root:daemon mode `0775` only for this read-only legacy presence probe and with
no writable extended ACL; generic privileged-path validation stays strict.
Any legacy entry, including a dangling symlink or empty directory, blocks
updating. No stale evidence is deleted and no software is stopped.
The new unprivileged relay
holds a shared installation-directory lease. The authorized root wrapper also
acquires its own independent shared lease before validating or loading the
installed helper, forks only that fixed helper, and waits for its known child
PID to exit. Client death, transport EOF or a relay deadline cannot release the
root lease while the helper is still starting or completing cleanup. Ordinary
termination signals do not end the guardian first. If child exit cannot be
confirmed, it reports uncertainty and retains its lease; a relay receipt is
still not proof of completed cleanup. The f8 bootstrap predates this lease;
absence of registry files cannot prove that an arbitrary previously launched
root process has exited. Deployment requires an independent check that the
earlier controlled session and all owned processes have closed. The root
guardian's lease is deliberately not inherited by the helper or attached
applications. Forced guardian termination such as SIGKILL, system failure and
an unconfirmed whole-component crash can release that kernel lock while the
child remains; those cases still require independent owned-process checks and
remain native acceptance gates. This is an offline, exact-version migration,
not a general concurrent service updater or whole-guard crash guarantee.

Tests exercise the production exchange, validation and exact cleanup functions
on unprivileged owned temporary directories, including mutation, path
replacement, bottom-up nested-directory fsync and retained recovery evidence.
An actual forked fixture kills the user relay and checks that the production
guardian keeps an exclusive updater blocked through EOF cleanup, releasing it
only after the helper exits. Production always requires root
metadata; those fixtures cannot satisfy it. System-root upgrade, crash
durability and the authorization/bootstrap boundaries require separate native
acceptance and are not established by temporary-directory tests.

## Separately approved controlled session

`--request-controlled-experiment` is a distinct native authorization operation.
It requires the exact already installed payload, the current console user and
private pipe/socket stdin and stdout. It does not install resources. This
operation may be invoked only after the user approves the concrete bounded
experiment: at most 180 seconds, two dedicated groups, two owned tunnels and
the component's owned PF anchor, with existing VPN settings preserved and
cleanup checked by the experiment runner. The helper separately enforces the
allowed plan; relaying bytes cannot establish routing readiness.

Security.framework launches only this same executable's fixed
`--run-controlled-experiment` entry. That entry rechecks its privileged
authorization reference and all installed hashes, ownership, ACLs and paths.
It derives the caller UID from the character device `/dev/console`, clears
supplementary groups and inherited environment, and starts only the fixed
installed `EnvaraPFHelper --controlled-experiment --caller-uid <derived UID>`
under the lease-holding root guardian.
No request parameters, credentials or caller-selected command enter its argv.

The SDK documents the Security communication FILE as bidirectional. The relay
also verifies that the actual FD is an AF_UNIX stream socket and refuses an
incompatible transport. It forwards bounded buffers without logging private
JSON. Closing the client's stdin sends a write-half close after pending input;
the read half stays open for the helper's final cleanup response. EOF and a
zero relay exit code alone do not prove cleanup, protection or acceptance.
The client must validate the helper's RPC status and cleanup receipts. There
is no launchd registration, setuid installation or permanent root daemon.

## Bootstrap boundary

`AuthorizationExecuteWithPrivileges` is deprecated. The current SDK still
declares it, but this implementation must report failure if the system refuses
it; there is no fallback. Its execute API accepts a pathname, not an already
verified executable FD, and does not provide modern helper identity binding.
A user-writable installer may be replaced between review and privileged
execution. Compiled payload digests protect copied resources, **not** that
bootstrap executable race. Approval therefore trusts the explicitly reviewed
installer build; it is not a claim of SMJobBless-style executable attestation.

The same bootstrap boundary applies to the separately approved controlled
session. Its privileged runtime is copied and hash checked first, but the
AuthorizationExecuteWithPrivileges entry executable is still the reviewed
user-owned build. This is an explicit development experiment boundary rather
than a production helper identity assertion. If Security.framework refuses
the deprecated API or provides a different communication transport, the
operation fails without an alternate elevation path.

The API also does not return a child PID. An incomplete pipe response is
reported as unconfirmed, never as readiness or a completed installation. No
unrelated process is killed to guess completion.
