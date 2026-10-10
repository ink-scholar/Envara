# Native launch guardian slice

`launch-guardian.c` is a linkable blocking C library for the **actual parent** of
a staged application. It is independent of the Node controller. It creates no
groups, PF rules, route, DNS settings or tunnel, and never resumes a child.
All reports keep `ready`, `protected_ready` and `whole_guard_crash_verified`
false. It is not installed or linked into the frozen 832 component.

The loop registers birth-bound `kqueue` watches for the controller, managed core
and owned front. Dependency exit or exec, identity change, nonrenewable monotonic
lease expiry, lease EOF, malformed input, and TERM/INT/HUP revoke the launch. The
supervisor sends SIGKILL only to its original, still unreaped direct child after
checking PID/birth/parent. It sends no group signal and does not assume external
helpers have stopped. Credential changes can trigger revocation without granting
authority to signal an unrelated PID.

The loop duplicates the held tunnel socket with CLOEXEC and holds that duplicate
across revocation. Production validation requires root, console UID, three realm
GIDs, and an actual held utun control socket matching its reported name/control
identity. Fixture custody uses only an own AF_UNIX socket. The original FD stays
the caller's responsibility. Anonymous lease/recovery read pipes are distinct,
read-only, CLOEXEC, and validated by held descriptor identity. Release byte `R`
is a request, not authority: the child must have been reaped and **both compiled
native callbacks** must freshly verify persistent denial and scope quiescence.
Missing checks refuse arming. Failed or absent recovery leaves FD custody held.
Observers/checkers must be bounded and run only in the isolated native process.

Concrete integration point: the future fixed native GUI launch entry must obtain
its sealed registration/lease, own the original utun FD or verified SCM_RIGHTS
duplicate, commit denial, stage with `envara_gui_stage`, and call
`envara_launch_guard_run` **in the same process that forked the GUI child**. The
root controller, authenticated managed core, and owned front supply its watched
identities. Connect the compiled checks to the sealed lease and live PF ownership
reader, and to complete owned-GID/descendant/helper inventory. The existing
`launch-fixture` and `tunnel-core` entries are not patched. The controller still
needs a fixed native entry, independent recovery channel, before-resume barrier,
durable revocation checks, installer/source inventory and readiness integration.

`envara_launch_guard_isolate_descriptors` is a child-side boundary for that
isolated entry: close descriptors >=3 except the explicit held set and mark the
held set CLOEXEC before creating the application. Actual descriptor-table
enumeration and a second inspection also close inherited descriptors above a
subsequently lowered RLIMIT_NOFILE. Do not invoke it in the GUI or
any multithreaded process. The normal application exec also needs the existing
POSIX_SPAWN_CLOEXEC_DEFAULT boundary.

Tests compile the native library with Clang `-Wall -Wextra -Werror` in an own
temporary directory and execute 18 real non-root scenarios. They cover abrupt
controller SIGKILL, dependency death and live same-birth exec, lease expiry despite
KEEP, signal/EOF/malformed revocation, FD closure/custody, premature release,
actual descendant-held scope, denial-check failure, wrong birth/parent, duplicate
peer, missing authority, unprivileged production, aliased pipes and wrong custody
type. FD tests include a descriptor above the lowered soft limit. The denial
callback is explicitly a fixture stub: no kernel policy exists.
Fixture scope proof is an anonymous pipe whose writer is held by every test child,
not a substitute for production process inventory. The own child exits on parent
death only to prevent orphan fixtures; arbitrary apps do not have that behavior.

SIGKILL of this guardian cannot be caught and releases its duplicate. This slice
does **not** prove whole-guardian crash protection or safe utun-name reuse. Actual
persistent denial, PF states, IPv6/raw traffic, DNS delegation, external helpers,
unaffected applications and real Notion routing remain acceptance gates. No
production protected launch may be opened from these tests.
