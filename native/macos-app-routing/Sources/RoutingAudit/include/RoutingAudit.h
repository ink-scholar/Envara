#ifndef ENVARA_ROUTING_AUDIT_H
#define ENVARA_ROUTING_AUDIT_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int32_t pid;
    uint32_t effective_uid;
    uint32_t real_uid;
    int32_t pid_version;
} envara_audit_caller;

/* The input must be the immutable sourceAppAuditToken supplied by NE, never an
 * application-provided PID. Public libbsm functions decode the opaque token;
 * proc_pidpath_audittoken binds the live executable to its PID generation. */
int envara_audit_copy_caller(const void *bytes, size_t length,
                            envara_audit_caller *caller, char *path,
                            size_t path_capacity);
size_t envara_audit_path_capacity(void);

/* Read this process's kernel audit token for local validation; no task_for_pid
 * or access to another process's task port is used. */
int envara_audit_copy_current_token(void *bytes, size_t capacity, size_t *length);

#endif
