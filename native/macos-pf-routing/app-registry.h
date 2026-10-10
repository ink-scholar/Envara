#ifndef ENVARA_APP_REGISTRY_H
#define ENVARA_APP_REGISTRY_H
#include "gui-launch.h"

#define ENVARA_APP_REGISTRY_ROOT "/Library/PrivilegedHelperTools/io.envara.pf-apps"
#define ENVARA_APP_REGISTRY_SCHEMA 1
#define ENVARA_APP_REGISTRY_MAX_APPS 32
#define ENVARA_APP_REGISTRY_MAX_VERSIONS 8
#define ENVARA_APP_REGISTRY_MAX_ENTRIES 20000
#define ENVARA_APP_REGISTRY_MAX_BYTES (UINT64_C(2) * 1024 * 1024 * 1024)

struct envara_app_registry {
    int fd, fixture_only;
    uid_t owner;
    char root[PATH_MAX];
};
struct envara_app_registration {
    uint32_t schema, sequence;
    int fixture_only, ready, protected_ready;
    char registration_id[37], version_id[37];
    struct envara_gui_manifest original, snapshot;
};
/* Fault callbacks are accepted ONLY in unprivileged self-owned fixture mode.
 * They have no production wire/CLI surface. A nonzero result injects EIO. */
struct envara_app_registry_fixture_hook {
    int (*observe)(const char *stage, void *context);
    void *context;
};

/* Production always uses the fixed sibling registry, real/effective root and
 * root-owned ACL-free ancestors. Fixture mode requires a canonical caller-owned
 * 0700 temporary parent outside the fixed system tree, never uid/euid root.
 * create=0 and resolve perform no writes. No API deletes a snapshot or record.
 * Strict copy preserves bounded relative internal bundle symlinks exactly;
 * external/absolute/dangling/cyclic links, regular hardlinks, extended ACLs,
 * app xattrs, special nodes and nonstandard execute bits refuse. Only bounded
 * macOS com.apple.provenance is permitted outside the app-content manifest;
 * it is never removed or rewritten. No original mutation or re-signing. */
int envara_app_registry_open(struct envara_app_registry *registry, const char *fixture_root, int fixture_only, int create);
void envara_app_registry_close(struct envara_app_registry *registry);
int envara_app_registry_register(struct envara_app_registry *registry, const char *registration_id,
                                const char *version_id, const char *original_bundle, const char *previous_version_id,
                                const struct envara_app_registry_fixture_hook *fixture_hook,
                                struct envara_app_registration *out);
/* Exact current version only. Durable newer intent, retirement, source update,
 * identity drift, unknown content or capacity ambiguity refuse; never fall back
 * to an older valid snapshot. Return is inspection, never a launch lease. */
int envara_app_registry_resolve(struct envara_app_registry *registry, const char *registration_id,
                               const char *version_id, struct envara_app_registration *out);
int envara_app_registry_retire(struct envara_app_registry *registry, const char *registration_id);
#endif
