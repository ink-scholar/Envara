#ifndef ENVARA_TRANSPORT_SESSION_H
#define ENVARA_TRANSPORT_SESSION_H
#include "native.h"
#include <limits.h>
#include <sys/stat.h>

/* Native-only reuse of the original utun/core owner. Never serialized or
 * accepted as argv. Caller obtains fixed paths from the private native lease.
 * No PF, DNS or app launch occurs in these primitives. */
struct envara_transport_session {
    int original_utun_fd, state_fd, core_reaped;
    char interface_name[32], configuration[PATH_MAX];
    struct envara_identity core;
    struct stat state_identity, configuration_identity;
};
void envara_transport_session_init(struct envara_transport_session *session);
int envara_transport_session_start(const char *core, const char *state_directory,
    const char *ipv4_address, const char *private_route_json,
    struct envara_transport_session *session);
/* Stop the exact direct core child and remove only the exact configuration
 * inode created by start. The original socket remains held. No group signal. */
int envara_transport_session_stop(struct envara_transport_session *session);
/* Only the native owner calls this AFTER its fixed deny/scope release checks.
 * This is not a wire RELEASE command and cannot authorize app recovery. */
int envara_transport_session_release(struct envara_transport_session *session);
#endif
