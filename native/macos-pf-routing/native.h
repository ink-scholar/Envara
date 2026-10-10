#ifndef ENVARA_MACOS_PF_NATIVE_H
#define ENVARA_MACOS_PF_NATIVE_H

#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>

#define ENVARA_REALM_GID_MIN 7100
#define ENVARA_REALM_GID_MAX 7999

/* Low-level primitives for a root-owned, authenticated controller. They do
 * not install PF rules and never attest that an application is protected. */
struct envara_identity {
    pid_t pid, parent_pid;
    uid_t uid, ruid, saved_uid;
    gid_t gid, rgid, saved_gid;
    uint64_t birth_seconds, birth_microseconds;
};
struct envara_child {
    struct envara_identity identity;
    int error_fd;
};

int envara_console_uid(uid_t *uid);
int envara_identity_read(pid_t pid, struct envara_identity *out);
int envara_identity_matches(const struct envara_identity *actual, uid_t uid, gid_t gid);
int envara_same_process(const struct envara_identity *expected);
int envara_root_owned_executable(const char *path);
/* Isolated native process only: close the actual descriptor table >=3 except
 * this compiled whitelist, including descriptors above a lowered soft limit.
 * Remaining whitelist entries are CLOEXEC; stdio is intentionally retained. */
int envara_close_inherited_descriptors(const int *held, size_t count);

/* Spawn stops after credential changes and before executing the target.
 * A controller must validate PF/engine/DNS/guard gates before resume. The
 * caller owns cleanup and must retain the deny rule until scope is quiescent.
 * fixture_mode is permitted only for an unprivileged caller's current IDs. */
int envara_spawn_suspended(uid_t uid, gid_t gid, const char *cwd,
                           const char *executable, char *const argv[],
                           char *const environment[], int fixture_mode,
                           struct envara_child *out);
int envara_spawn_suspended_io(uid_t uid, gid_t gid, const char *cwd,
                              const char *executable, char *const argv[],
                              char *const environment[], int fixture_mode,
                              int stdin_fd, int stdout_fd, struct envara_child *out);
int envara_child_resume(struct envara_child *child);
int envara_child_cancel(struct envara_child *child);

/* Optional raw utun primitive. Not called by status/plan/fixture or CLI.
 * The production packet engine should use the already bundled Mihomo. */
int envara_utun_open(char *name, size_t name_size);
int envara_utun_configure(const char *name, const char *ipv4_address, unsigned mtu);
int envara_utun_frame_family(const unsigned char *frame, size_t length);
int envara_transport_main(int argc, char **argv);
int envara_transport_fixture(void);
int envara_transport_config_fixture(const char *filename);

#endif
