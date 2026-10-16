#ifndef ENVARA_PF_GUI_LAUNCH_H
#define ENVARA_PF_GUI_LAUNCH_H

#include "native.h"
#include <limits.h>

/* Library preparation only. No CLI, controller, installer, or resource map
 * invokes this code. Production stage requires an already installed root-sealed
 * snapshot and console session; protected resume remains unavailable. */
#define ENVARA_GUI_SCHEMA 1
#define ENVARA_GUI_NATIVE_PATH "/Library/PrivilegedHelperTools/io.envara.pf-routing/envara-pf-native"
#define ENVARA_GUI_SEALED_ROOT "/Library/PrivilegedHelperTools/io.envara.pf-apps/objects"
#define ENVARA_GUI_PRODUCTION_READY 0

struct envara_gui_file_identity {
    uint64_t device, inode, size;
    int64_t modified_seconds, modified_nanoseconds, changed_seconds, changed_nanoseconds;
    uint32_t owner, group, mode;
};

struct envara_gui_manifest {
    uint32_t schema;
    int fixture_only;
    char bundle[PATH_MAX], executable[PATH_MAX], identifier[256];
    char bundle_digest[65], content_digest[65], executable_digest[65], cdhash[65], requirement[2048];
    struct envara_gui_file_identity bundle_identity, executable_identity;
};

/* These values must be constructed by the authenticated controller from a
 * sealed, root-owned app registration and environment lease. Never deserialize
 * an untrusted struct, accept a caller's executable/argv/env, or trust a caller
 * to set the UID/GID. No route passwords belong in this request. */
struct envara_gui_request {
    uint32_t schema;
    char lease_id[37], environment_id[37];
    uid_t console_uid;
    gid_t realm_gid;
    uint32_t gui_audit_session;
    char cwd[PATH_MAX], timezone[128], browser_locale[64];
};

struct envara_gui_bootstrap_plan {
    int ready, activates_system;
    char uid_decimal[16], lease_id[37];
    char executable[PATH_MAX];
    char arguments[6][PATH_MAX];
};

struct envara_gui_session {
    uid_t console_uid;
    uint32_t audit_session, audit_flags;
    uint32_t security_session, security_flags;
    int audit_has_console_graphics;
    int security_has_graphics;
    /* Audit flags alone do not attest the Mach bootstrap namespace. */
    int bootstrap_verified;
};

enum envara_gui_phase {
    ENVARA_GUI_EMPTY, ENVARA_GUI_SUSPENDED, ENVARA_GUI_EXECUTING,
    ENVARA_GUI_EXITED, ENVARA_GUI_CANCELLED, ENVARA_GUI_UNCERTAIN
};
enum envara_gui_precondition {
    ENVARA_GUI_PRECONDITION_NONE, ENVARA_GUI_ROOT_HELPER_REQUIRED,
    ENVARA_GUI_SEALED_SNAPSHOT_REQUIRED, ENVARA_GUI_FIXED_NATIVE_ENTRY_REQUIRED,
    ENVARA_GUI_CONSOLE_SESSION_REQUIRED, ENVARA_GUI_INVALID_REQUEST,
    ENVARA_GUI_ORIGINAL_IDENTITY_CHANGED, ENVARA_GUI_ORIGINAL_ALREADY_RUNNING,
    ENVARA_GUI_PROCESS_INVENTORY_UNAVAILABLE, ENVARA_GUI_PRIVATE_PIPES_REQUIRED,
    ENVARA_GUI_COMMITTED_DENY_REQUIRED
};

/* Native function supplied only by the fixed, installed root-controller code;
 * never deserialize function pointers/context or permit a wire caller override.
 * Verification must be read-only and attest already committed live realm deny
 * ownership before the console-owned child exists. This library does not install
 * rules. SIGSTOP alone is not an authorization barrier against same-UID signals. */
struct envara_gui_stage_authority {
    int (*verify_committed_deny)(const struct envara_gui_request *request, void *context);
    void *context;
};

struct envara_gui_lifecycle {
    enum envara_gui_phase phase;
    enum envara_gui_precondition blocked_reason;
    int fixture_only, protected_ready, leader_reaped, scope_quiescent, wait_status;
    struct envara_child child;
    struct envara_gui_manifest original, manifest;
    struct envara_gui_request request;
    struct envara_gui_session session;
};

/* Read-only APIs. Fixture inspection accepts only caller-owned app contents;
 * production inspection requires strict, nested code-signature validity. Both
 * bind to the original canonical bundle and hash its complete physical tree. */
int envara_gui_manifest_inspect(const char *bundle, int fixture_only, struct envara_gui_manifest *out);
int envara_gui_manifest_unchanged(const struct envara_gui_manifest *expected);
/* Internal native operation scope, never a wire capability or launch receipt.
 * The first check of an exact manifest in a scope performs full signed
 * inspection: every byte hashed twice around strict nested signature
 * validation. Later checks of that manifest in the same scope re-walk the whole
 * tree and require every entry's exact physical identity (path, device, inode,
 * size, both times, owner, group, mode, links, link target) to equal the state
 * that inspection proved; they read no bytes. No time-based cache; a witness
 * never crosses threads, processes or scopes, and the outermost end clears it. */
uint64_t envara_gui_validation_scope_begin(void);
void envara_gui_validation_scope_end(void);
uint64_t envara_gui_validation_scope_current(void);
/* Whether the active scope holds a fully inspected witness for this exact
 * manifest. Information for callers that skip a check the witness subsumes;
 * it proves nothing until envara_gui_manifest_unchanged re-proves identity. */
int envara_gui_validation_witnessed(const struct envara_gui_manifest *manifest);
/* Diagnostic-only per-thread counts of full inspections and identity re-proofs. */
struct envara_gui_validation_counts { uint32_t full_inspections, identity_checks; };
void envara_gui_validation_counts(struct envara_gui_validation_counts *out);
/* Diagnostic-only launch step timing. One bounded series per accepted launch,
 * written as whole newline-delimited frames to the native keeper's own output
 * only when that output can take a frame now; a frame that cannot is dropped
 * and never blocks staging. Fixed step names, monotonic milliseconds and the
 * validation counts above: no path, PID, account, network or credential value.
 * Never a capability, receipt, acceptance or readiness signal. */
enum envara_gui_step {
    ENVARA_GUI_STEP_FRONT_COMMIT, ENVARA_GUI_STEP_FRONT_ADMISSION, ENVARA_GUI_STEP_TICKET_PREPARE,
    ENVARA_GUI_STEP_RELAY_FORK, ENVARA_GUI_STEP_TICKET_CLAIM, ENVARA_GUI_STEP_STAGE_FRESH,
    ENVARA_GUI_STEP_DATA_PREPARE, ENVARA_GUI_STEP_STAGE_PLAN, ENVARA_GUI_STEP_STAGE_RECHECK,
    ENVARA_GUI_STEP_STAGE_SPAWN, ENVARA_GUI_STEP_STAGE_STOPPED, ENVARA_GUI_STEP_STAGE_ADOPT,
    ENVARA_GUI_STEP_RESUME_VERIFY, ENVARA_GUI_STEP_COUNT
};
#define ENVARA_GUI_STEP_FRAME_LIMIT 16
int envara_gui_steps_begin(int fd, const char *schema, const char *run_id, const char *environment_id);
void envara_gui_step(enum envara_gui_step step);
void envara_gui_steps_end(void);
const char *envara_gui_step_name(enum envara_gui_step step);
/* Short root-owned aliases of scoped application directories. macOS limits a
 * Unix socket path to 103 characters, and applications such as VS Code bind
 * their main socket inside the user data directory; the scoped paths are far
 * longer. Each alias is a root-owned symlink in this root-owned 0755 directory
 * naming exactly one scoped directory, under a name derived from both
 * identifiers. The data itself never moves, and an alias is not a capability. */
#define ENVARA_GUI_ALIAS_ROOT "/Library/PrivilegedHelperTools/io.envara.pf-s"
int envara_gui_scoped_alias_id(const char *environment_id, const char *registration_id, char out[17]);
/* Read-only, nofollow ACL inspection with held-file and named-path identity.
 * Zero means verified no extended entries; an entry or unknown state refuses. */
int envara_gui_acl_free(const char *path);
int envara_gui_sealed_snapshot_validate(const struct envara_gui_manifest *manifest);
int envara_gui_request_validate(const struct envara_gui_manifest *manifest,
                               const struct envara_gui_request *request, int fixture_only);
int envara_gui_requirement_team(const char *requirement, char team[11]);
int envara_gui_original_running(const struct envara_gui_manifest *manifest, uid_t uid, pid_t *found_pid);
int envara_gui_session_read(struct envara_gui_session *out);
int envara_gui_bootstrap_plan(const struct envara_gui_request *request,
                              const char *pinned_native_sha256, struct envara_gui_bootstrap_plan *out);
int envara_gui_bootstrap_argv(const struct envara_gui_bootstrap_plan *plan, const char *argv[7]);

/* Production stage accepts only an already installed, signed root-sealed
 * snapshot beneath ENVARA_GUI_SEALED_ROOT matching the unchanged original's
 * content/signature. It also requires root, execution from the fixed native
 * path and current console graphic/audit context. It leaves the child stopped;
 * no production resume API or protected-ready attestation is provided here.
 * The fixed root controller must verify committed realm denial before fork:
 * same-UID code can SIGCONT the stopped child. It must attest the asuser
 * bootstrap and PF/DNS/engine/whole-guard/helper gates before authorized resume
 * or any protected-ready claim.
 * Unprivileged fixtures use only their own UID/GID, bundle and anonymous pipes.
 * Lifecycle storage is one-shot while scope quiescence remains unproved. */
void envara_gui_lifecycle_init(struct envara_gui_lifecycle *out);
int envara_gui_stage(const struct envara_gui_manifest *original,
                     const struct envara_gui_manifest *manifest,
                     const struct envara_gui_request *request, int fixture_only,
                     const struct envara_gui_stage_authority *authority,
                     int fixture_stdin, int fixture_stdout, struct envara_gui_lifecycle *out);
int envara_gui_resume_fixture(struct envara_gui_lifecycle *lifecycle, unsigned timeout_ms);
int envara_gui_cancel(struct envara_gui_lifecycle *lifecycle);
int envara_gui_poll(struct envara_gui_lifecycle *lifecycle, int *exit_status);
const char *envara_gui_precondition_name(enum envara_gui_precondition reason);

#endif
