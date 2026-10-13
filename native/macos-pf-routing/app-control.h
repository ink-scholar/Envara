#ifndef ENVARA_APP_CONTROL_H
#define ENVARA_APP_CONTROL_H
#include "app-ticket.h"
/* Context originates in fixed native code only. Production root paths are
 * fixed; fixture roots/authority are unavailable through argv/env/JSON. */
struct envara_app_control_context {
    int fixture_only;
    const char *fixture_registry_root, *fixture_ticket_root;
    const struct envara_app_ticket_authority *authority;
    /* Last, so existing positional initializers keep their meaning. */
    const char *fixture_data_root;
};
/* Exact positional native commands; no shell, caller argv/env/executable,
 * UID/GID or manifest override. Returns 0 or -1/errno; emits bounded JSON with
 * ready/protected/activatesSystem false. No transient command stages a child. */
int envara_app_control_dispatch(const struct envara_app_control_context *context,
                               int argc, const char *const argv[], int output_fd);
#endif
