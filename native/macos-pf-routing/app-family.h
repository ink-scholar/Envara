#ifndef ENVARA_APP_FAMILY_H
#define ENVARA_APP_FAMILY_H
#include "native.h"
#include <stddef.h>

/* Private native custody. Membership comes from an observed parent/birth
 * chain, never a matching GID, command name or a caller-supplied PID list.
 * Tokens remain in this process and are never serialized or diagnosed. */
typedef struct envara_app_family envara_app_family;
enum envara_app_family_failure_reason {
    ENVARA_APP_FAMILY_FAILURE_NONE, ENVARA_APP_FAMILY_FAILURE_IDENTITY,
    ENVARA_APP_FAMILY_FAILURE_TOKEN, ENVARA_APP_FAMILY_FAILURE_INVENTORY,
    ENVARA_APP_FAMILY_FAILURE_CHURN, ENVARA_APP_FAMILY_FAILURE_CAPACITY,
    ENVARA_APP_FAMILY_FAILURE_SIGNAL, ENVARA_APP_FAMILY_FAILURE_STOP_TIMEOUT,
    ENVARA_APP_FAMILY_FAILURE_UNAVAILABLE
};
/* First refusal only; no process identifiers, paths or token contents. */
struct envara_app_family_failure {
    enum envara_app_family_failure_reason reason;
    int os_error, mach_error;
};
const char *envara_app_family_failure_name(enum envara_app_family_failure_reason reason);
void envara_app_family_first_failure(const envara_app_family *family, struct envara_app_family_failure *out);
/* Weak native symbol: older supported deployment targets refuse before app
 * launch instead of failing the helper's dyld load. No PID-only fallback. */
int envara_app_family_available(void);
envara_app_family *envara_app_family_create(const struct envara_identity *leader);
envara_app_family *envara_app_family_create_diagnosed(const struct envara_identity *leader,
    struct envara_app_family_failure *failure);
int envara_app_family_observe(envara_app_family *family);
/* Call only AFTER the fixed authority has revoked this run's network. Uses
 * kernel audit-token signals; missing/changed/unknown identity never falls
 * back to kill(pid), killpg or a group-wide signal. 1 = verified dispatch. */
int envara_app_family_stop(envara_app_family *family, int *leader_signal_sent);
/* Only the fixed guardian's fresh explicit Stop may advance a known,
 * complete vector-churn/freeze-timeout deferral. Permanent unknown never clears. */
int envara_app_family_retry_stop(envara_app_family *family, int *leader_signal_sent);
int envara_app_family_quiescent(envara_app_family *family);
size_t envara_app_family_count(const envara_app_family *family);
void envara_app_family_destroy(envara_app_family *family);
#endif
