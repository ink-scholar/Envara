#include "RoutingAudit.h"
#include <bsm/libbsm.h>
#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <string.h>

size_t envara_audit_path_capacity(void) { return PROC_PIDPATHINFO_MAXSIZE; }

int envara_audit_copy_caller(const void *bytes, size_t length,
                            envara_audit_caller *caller, char *path,
                            size_t path_capacity) {
    if (!bytes || !caller || !path || length != sizeof(audit_token_t) ||
        path_capacity < PROC_PIDPATHINFO_MAXSIZE || path_capacity > UINT32_MAX) {
        return EINVAL;
    }
    audit_token_t token;
    memcpy(&token, bytes, sizeof(token));
    envara_audit_caller value = {
        .pid = audit_token_to_pid(token),
        .effective_uid = audit_token_to_euid(token),
        .real_uid = audit_token_to_ruid(token),
        .pid_version = audit_token_to_pidversion(token)
    };
    if (value.pid <= 0) return EINVAL;
    memset(path, 0, path_capacity);
    errno = 0;
    int count = proc_pidpath_audittoken(&token, path, (uint32_t)path_capacity);
    if (count <= 0) return errno ? errno : EIO;
    if ((size_t)count >= path_capacity || !memchr(path, '\0', path_capacity)) {
        return EOVERFLOW;
    }
    *caller = value;
    return 0;
}

int envara_audit_copy_current_token(void *bytes, size_t capacity, size_t *length) {
    if (!bytes || !length || capacity < sizeof(audit_token_t)) return EINVAL;
    audit_token_t token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t status = task_info(mach_task_self(), TASK_AUDIT_TOKEN,
                                    (task_info_t)&token, &count);
    if (status != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT) return EIO;
    memcpy(bytes, &token, sizeof(token));
    *length = sizeof(token);
    return 0;
}
