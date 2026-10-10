#ifndef ENVARA_APP_NATIVE_FACTORY_H
#define ENVARA_APP_NATIVE_FACTORY_H
#include "app-supervisor.h"
#include "pf-production-filter.h"

#define ENVARA_APP_BOUND_LEASE_SCHEMA "envara.macos-pf-app-bound-lease/v1"
#define ENVARA_APP_BOUND_CLOCK_SCHEMA "envara.macos-pf-app-context-clock/v1"
#define ENVARA_APP_BOUND_MAX_LEASE_MS 180000U

/* Constructed ONLY by the same installed native transport process from its
 * original descriptors and direct child observations. No RPC decoder accepts
 * this struct or a proof boolean/FD number supplied by the desktop renderer. */
struct envara_app_native_owned_context {
    char run_id[37], environment_id[37], tunnel_name[16];
    int original_utun_fd, original_listener_fd, lease_read_fd, recovery_read_fd;
    struct envara_identity controller, core, frontend;
};
struct envara_app_native_preflight {
    char run_id[37], environment_id[37], realm_id[37], lease_id[37], generation[37];
    char registration_id[37], version_id[37], state_directory[PATH_MAX], ipv4[16];
    char lease_sha256[65], native_sha256[65];
    uid_t console_uid;
    gid_t realm_gid;
    unsigned remaining_milliseconds;
    struct envara_identity controller;
};
struct envara_app_native_admission {
    char run_id[37], environment_id[37], lease_id[37], generation[37], lease_sha256[65];
    struct envara_identity keeper, frontend;
    uint16_t front_port;
    gid_t gid;
    uint32_t filter_revision, writer_pid;
    uint64_t expires_monotonic_ms, boot_time_seconds;
};
typedef struct envara_app_native_factory envara_app_native_factory;
/* Fixed diagnostic enum represented by compile-time strings. No private
 * path, arbitrary exception text or credential is returned. Read immediately
 * with errno after a failed native operation, before doing other queries. */
const char *envara_app_native_failure_reason(void);
void envara_app_native_failure_begin(void);
int envara_app_native_failure_error(int fallback);

/* Read-only fixed paths derived from two canonical UUIDs; no store creation,
 * PF activation, app launch, arbitrary executable or caller-selected path. */
int envara_app_native_preflight(const char *run_id, const char *environment_id,
                                struct envara_app_native_preflight *out);
/* Read-only abort binding only: strict twenty-field private lease, registry,
 * live root controller, realm/console/clock/state and serialized root-hook
 * lease. It does NOT skip any full preflight gate, open routing or attest
 * cleanup. Output is zero on failure; the direct bootstrap must independently
 * pin raw bytes and prove no children/GID/PF resources before emitting abort. */
int envara_app_native_abort_plan(const char *run_id, const char *environment_id,
    struct envara_app_native_preflight *out, char *hook_json, size_t capacity, size_t *length);
int envara_app_native_context_clock(int argc, char **argv);
int envara_app_native_factory_open(const struct envara_app_native_owned_context *owned,
                                  envara_app_native_factory **out);
const struct envara_app_supervisor_provider *envara_app_native_factory_provider(envara_app_native_factory *factory);

/* Explicit owned single-class writes; preparation commits DENY before a cold
 * app child exists. UNKNOWN/lost mutation permanently poisons this factory.
 * No resume or production readiness follows from a successful receipt. */
int envara_app_native_factory_apply(envara_app_native_factory *factory,
                                   EnvaraPFProductionMode mode, EnvaraPFProductionResult *out);
int envara_app_native_factory_release_safe(envara_app_native_factory *factory);
/* Irreversible cleanup authority on the original custodian only. It never
 * restores a provider or FRONT admission. Unknown PF writes remain poisoned;
 * only a known result plus exact read-only reconciliation permits DENY/EMPTY. */
int envara_app_native_factory_cleanup_binding(envara_app_native_factory *factory);
int envara_app_native_factory_cleanup_deny(envara_app_native_factory *factory);
/* A private root-pipe receipt for the fixed front service. Values are derived
 * from fresh native FRONT readback/original sockets/births, never JSON booleans.
 * It is scoped admission, not protected launch or production readiness.
 * Returns 0 on verified receipt, -1 on refusal (output then remains zero). */
int envara_app_native_factory_admission(envara_app_native_factory *factory,
                                      struct envara_app_native_admission *out);
void envara_app_native_factory_close(envara_app_native_factory *factory);
#endif
