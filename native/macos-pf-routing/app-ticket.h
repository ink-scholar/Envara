#ifndef ENVARA_APP_TICKET_H
#define ENVARA_APP_TICKET_H
#include "app-registry.h"

#define ENVARA_APP_TICKET_ROOT "/Library/PrivilegedHelperTools/io.envara.pf-app-tickets"
#define ENVARA_APP_TICKET_SCHEMA 1
#define ENVARA_APP_TICKET_MAX 64
/* Overridable only so a compiled fixture can observe expiry quickly. */
#ifndef ENVARA_APP_TICKET_LIFETIME_NS
#define ENVARA_APP_TICKET_LIFETIME_NS UINT64_C(60000000000)
#endif

struct envara_app_ticket_store { int fd, fixture_only; uid_t owner; char root[PATH_MAX]; };
struct envara_app_ticket {
    uint32_t schema;
    int fixture_only, ready, protected_ready;
    char ticket_id[37], environment_id[37], run_id[37], boot_id[64], environment_lease_sha256[65];
    uint64_t issued_ns, expires_ns;
    struct envara_app_registration app;
    struct envara_gui_request request;
};
/* Supplied by fixed compiled root controller code, never a wire override.
 * inspect derives UID/GID/workspace/TZ/locale from its private live environment
 * lease. verify re-attests the same lease, committed deny, owned route/front,
 * DNS and independent guardian before preparation/claim/fork. Missing native
 * implementations refuse. A ticket is not permission to resume or claim ready. */
struct envara_app_ticket_authority {
    int (*inspect)(const char *environment_id, const char *run_id,
                   const struct envara_app_registration *app,
                   struct envara_gui_request *request, char lease_sha256[65], void *context);
    int (*verify)(const struct envara_app_registration *app, const struct envara_gui_request *request, const char *run_id,
                  const char *lease_sha256, void *context);
    /* Fixed native guardian reservation is part of verify. After fork, adopt
     * must acknowledge custody of exact stopped PID/birth/error FD and durable
     * deny/lease before the caller can return. Missing custody refuses. */
    int (*adopt)(const struct envara_app_ticket *ticket, struct envara_gui_lifecycle *child, void *context);
    void *context;
};
int envara_app_ticket_store_open(struct envara_app_ticket_store *store, const char *fixture_root, int fixture_only, int create);
void envara_app_ticket_store_close(struct envara_app_ticket_store *store);
int envara_app_ticket_prepare(struct envara_app_ticket_store *store, struct envara_app_registry *registry,
    const char *ticket_id, const char *registration_id, const char *version_id,
    const char *environment_id, const char *run_id, const struct envara_app_ticket_authority *authority,
    struct envara_app_ticket *out);
/* Inspection has no writes and cannot retire/claim a ticket. Missing, pending,
 * consumed, expired, boot-changed and stale-registration tickets refuse. */
int envara_app_ticket_inspect(struct envara_app_ticket_store *store, struct envara_app_registry *registry,
    const char *ticket_id, struct envara_app_ticket *out);
/* Durable single use. Any uncertain claim consumes the ticket permanently;
 * claim/fork failure has no retry or deletion path. */
int envara_app_ticket_claim(struct envara_app_ticket_store *store, struct envara_app_registry *registry,
    const char *ticket_id, const struct envara_app_ticket_authority *authority, struct envara_app_ticket *out);
int envara_app_ticket_stage(struct envara_app_ticket_store *store, struct envara_app_registry *registry,
    const char *ticket_id, const struct envara_app_ticket_authority *authority, struct envara_gui_lifecycle *out);
#endif
