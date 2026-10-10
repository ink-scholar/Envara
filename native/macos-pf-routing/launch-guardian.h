#ifndef ENVARA_PF_LAUNCH_GUARDIAN_H
#define ENVARA_PF_LAUNCH_GUARDIAN_H

#include "native.h"
#include <stddef.h>

/* A linkable, blocking native parent supervisor. It does not install policy,
 * attest protected launch. The fixed native launch
 * entry must stage its direct child, verify persistent denial, and invoke this
 * loop in its own process (independent of the JavaScript controller). */
#define ENVARA_LAUNCH_GUARDIAN_READY 0
#define ENVARA_LAUNCH_GUARDIAN_MAX_PEERS 3

enum envara_launch_guard_reason {
    ENVARA_GUARD_NONE, ENVARA_GUARD_LEASE_CLOSED, ENVARA_GUARD_INVALID_COMMAND,
    ENVARA_GUARD_DEPENDENCY_EXITED, ENVARA_GUARD_DEPENDENCY_CHANGED,
    ENVARA_GUARD_LEASE_EXPIRED, ENVARA_GUARD_SIGNAL, ENVARA_GUARD_CHILD_EXITED,
    ENVARA_GUARD_DENY_UNCONFIRMED, ENVARA_GUARD_INSPECTION_UNAVAILABLE,
    ENVARA_GUARD_RESUME_REFUSED, ENVARA_GUARD_EXECUTION_UNVERIFIED
};
enum envara_launch_guard_event {
    ENVARA_GUARD_ARMED, ENVARA_GUARD_REVOKED, ENVARA_GUARD_CHILD_REAPED,
    ENVARA_GUARD_RELEASE_REFUSED, ENVARA_GUARD_RELEASED, ENVARA_GUARD_RESUMED
};
struct envara_launch_guard_report {
    enum envara_launch_guard_reason reason;
    int dependency_index, owns_retained_fd, child_reaped, child_signal_sent;
    int persistent_deny_observed, scope_quiescent_observed;
    int ready, protected_ready, whole_guard_crash_verified;
    int resume_sent, resumed;
};
struct envara_launch_guard_authority {
    /* Compiled fixed-controller callbacks only, never wire supplied pointers.
     * A boolean from the child/renderer is not an authority. These checks must
     * inspect sealed ownership plus already committed live kernel state.
     * Missing callbacks refuse arming/release, including in fixtures. */
    int (*verify_persistent_deny)(void *context);
    int (*verify_scope_quiescent)(void *context);
    void (*observe)(enum envara_launch_guard_event event,
                    const struct envara_launch_guard_report *report, void *context);
    void *context;
};
struct envara_launch_guard_request {
    int fixture_only;
    struct envara_child child; /* Must be an unreaped, same-birth direct child. */
    struct envara_identity dependencies[ENVARA_LAUNCH_GUARDIAN_MAX_PEERS];
    size_t dependency_count; /* controller, managed core, owned front */
    int lease_fd, recovery_fd; /* Distinct anonymous pipe read ends, CLOEXEC. */
    int retained_fd; /* Held original utun FD; fixture: own AF_UNIX socket. */
    char tunnel_name[16]; /* Production must agree with the held utun socket. */
    unsigned lease_milliseconds; /* Fixed nonrenewable 1..3,600,000 ms lease. */
    /* Optional compiled authority; never supplied over the command protocol.
     * B is once, only for the exact stopped native child. verify_resume must
     * freshly inspect the sealed target and live policy; verify_executed is
     * 1 for the exact executed target, 0 while native/wrapper, -1 to refuse.
     * Both are required. Missing authority keeps the generic route cold. */
    int (*verify_resume)(const struct envara_child *child, void *context);
    int (*verify_executed)(const struct envara_child *child, void *context);
    void *resume_context;
};

/* On successful arming this takes custody of a CLOEXEC duplicate, preserving
 * the caller's FD. Faults terminate only the unreaped direct child and retain
 * custody indefinitely. Recovery 'R' releases only after child reap plus BOTH
 * fixed native checks. Lease 'K' is a no-op; 'S', EOF, malformed bytes, watched
 * process exit/exec/identity changes, expiry, or TERM/INT/HUP revoke once.
 * Optional B sends SIGCONT once after fresh native checks, then waits at most
 * five seconds for exact execution proof before emitting RESUMED. SIGCONT
 * alone is not success. B without both callbacks or repeated B revokes.
 * No command extends expiry. Caller remains responsible for
 * its own original FD. SIGKILL cannot be handled: persistent denial and utun
 * name reuse remain separate, unverified production gates. No group signal.
 * Run only in the isolated, single-threaded fixed native entry. */
int envara_launch_guard_run(const struct envara_launch_guard_request *request,
                           const struct envara_launch_guard_authority *authority,
                           struct envara_launch_guard_report *out);

/* Child-side descriptor boundary for the isolated native entry BEFORE staging
 * its application. It closes every descriptor >=3 except the explicit held
 * set and marks those CLOEXEC. Never invoke in a multithreaded/UI process. */
int envara_launch_guard_isolate_descriptors(const int *held, size_t count);

#endif
