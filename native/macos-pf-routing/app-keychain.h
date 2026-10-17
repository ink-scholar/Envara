#ifndef ENVARA_APP_KEYCHAIN_H
#define ENVARA_APP_KEYCHAIN_H
#include "app-registry.h"

typedef struct envara_app_keychain_custody envara_app_keychain_custody;
/* Fixed internal child exits only: no paths, account data or OSStatus values.
 * A parent may diagnose one only after its own terminal wait and scope proof.
 * These values are never process, launch or cleanup authority. */
enum envara_app_keychain_helper_exit {
    ENVARA_KEYCHAIN_EXIT_ENTRY = 32, ENVARA_KEYCHAIN_EXIT_PIPES,
    ENVARA_KEYCHAIN_EXIT_REQUEST_READ, ENVARA_KEYCHAIN_EXIT_REQUEST_SHAPE,
    ENVARA_KEYCHAIN_EXIT_SELF_IDENTITY, ENVARA_KEYCHAIN_EXIT_PARENT_IDENTITY,
    ENVARA_KEYCHAIN_EXIT_EXECUTABLE, ENVARA_KEYCHAIN_EXIT_PIPE_BINDING,
    ENVARA_KEYCHAIN_EXIT_SESSION, ENVARA_KEYCHAIN_EXIT_HOME,
    ENVARA_KEYCHAIN_EXIT_HOLDS_OPEN, ENVARA_KEYCHAIN_EXIT_HOLDS_BINDING,
    ENVARA_KEYCHAIN_EXIT_SELECTOR, ENVARA_KEYCHAIN_EXIT_STAGE_LOAD,
    ENVARA_KEYCHAIN_EXIT_SANDBOX, ENVARA_KEYCHAIN_EXIT_INTERACTION,
    ENVARA_KEYCHAIN_EXIT_SELECT_RECHECK, ENVARA_KEYCHAIN_EXIT_KEYCHAIN_OPEN,
    ENVARA_KEYCHAIN_EXIT_SET_DEFAULT, ENVARA_KEYCHAIN_EXIT_SELECT_POSTCHECK,
    ENVARA_KEYCHAIN_EXIT_COPY_DEFAULT, ENVARA_KEYCHAIN_EXIT_DEFAULT_PATH,
    ENVARA_KEYCHAIN_EXIT_DEFAULT_OWNER, ENVARA_KEYCHAIN_EXIT_DEFAULT_STATUS,
    ENVARA_KEYCHAIN_EXIT_SEARCH_LIST, ENVARA_KEYCHAIN_EXIT_DOMAIN_SEARCH,
    ENVARA_KEYCHAIN_EXIT_SEARCH_DIGEST, ENVARA_KEYCHAIN_EXIT_SEARCH_MISSING,
    ENVARA_KEYCHAIN_EXIT_METADATA_POSTCHECK, ENVARA_KEYCHAIN_EXIT_REPLY_WRITE,
    ENVARA_KEYCHAIN_EXIT_TIMEOUT = 124
};
/* This opaque slot has no adopt/set-reaped interface. Only this module's own
 * launcher and exact terminal wait may change its process proof. One slot per
 * fixed keeper, bound to its birth, complete app/request and run. Private
 * selector staging descriptors remain in this same custody until safe cleanup. */
int envara_app_keychain_custody_create(const struct envara_app_registration *app,
    const struct envara_gui_request *request, const char *run_id,
    envara_app_keychain_custody **out);
/* 1 = pending, 0 = none, -1 = invalid binding. NULL means no preparation slot. */
int envara_app_keychain_custody_pending(envara_app_keychain_custody *slot,
    const struct envara_app_registration *app, const struct envara_gui_request *request,
    const char *run_id);
enum envara_app_keychain_child_state {
    ENVARA_APP_KEYCHAIN_LAUNCHER_CLEAR = 1, ENVARA_APP_KEYCHAIN_UNWAITED,
    ENVARA_APP_KEYCHAIN_REAPED, ENVARA_APP_KEYCHAIN_UNKNOWN
};
struct envara_app_keychain_snapshot {
    char slot_id[37]; uint64_t generation;
    enum envara_app_keychain_child_state child_state;
    int pending;
};
/* Diagnostic read only; no field is accepted back as process/release proof. */
int envara_app_keychain_custody_snapshot(envara_app_keychain_custody *slot,
    const struct envara_app_registration *app, const struct envara_gui_request *request,
    const char *run_id, struct envara_app_keychain_snapshot *out);
/* After independent network revocation: exact cancel/reap of our helper and
 * fresh realm absence. 1 = clear, 0 = pending, -1 = invalid binding. A retained
 * terminal wait is never repeated; later calls may re-prove scope alone. Only
 * after that proof may fixed owned staging entries be removed. */
int envara_app_keychain_custody_cleanup(envara_app_keychain_custody *slot,
    const struct envara_app_registration *app, const struct envara_gui_request *request,
    const char *run_id);
/* Refuses to destroy a pending slot or close its retained error reader. */
int envara_app_keychain_custody_destroy(envara_app_keychain_custody *slot);

/* Local selection metadata only. No item access, unlock, credential copying,
 * separate Keychain, host preference changes, or login-readiness claim. Only
 * the fixed root stage may call prepare, after committed realm denial. */
int envara_app_keychain_prepare(envara_app_keychain_custody *slot,
    const struct envara_app_registration *app, const struct envara_gui_request *request,
    const char *scoped_home, const struct envara_gui_stage_authority *authority);
/* Fixed internal cold-exec entry. No paths or modes in argv; requires private
 * root-created pipes and the exact installed root parent before Security APIs. */
int envara_app_keychain_command(int argc, char **argv);
#endif
