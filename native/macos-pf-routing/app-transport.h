#ifndef ENVARA_APP_TRANSPORT_H
#define ENVARA_APP_TRANSPORT_H
#include "native.h"
#include <limits.h>

#define ENVARA_APP_TRANSPORT_PROTOCOL "envara.macos-pf-app-transport/v1"
#define ENVARA_APP_TRANSPORT_READY 0
struct envara_app_listener {
    int fd;
    pid_t owner;
    uint16_t port;
    uid_t credential_uid;
    gid_t credential_gid;
};
/* Native prebind, no SO_REUSEADDR/PORT, original FD stays in GUI parent even
 * when the inherited front duplicate disappears. No application admission. */
int envara_app_listener_open(struct envara_app_listener *out);
struct envara_app_native_preflight;
/* Fixed installed one-shot creator derives the owned realm from preflight.
 * Keeper credentials never change; success requires one authenticated FD and
 * actual direct creator exit 0 before any factory or front child is opened. */
int envara_app_listener_open_for_plan(const struct envara_app_native_preflight *plan,
    struct envara_app_listener *out);
int envara_app_listener_verify(const struct envara_app_listener *held);
int envara_app_listener_close(struct envara_app_listener *held);
/* One compiled fixed console entry. Only two canonical v4 UUIDs are accepted;
 * paths, IDs, front port, executable, argv and environment are never overrides.
 * bootstrap execs launchctl asuser with its UID derived by native preflight.
 * run creates the ORIGINAL utun and front listener and directly stages the
 * Notion child, then blocks in its own native guardian. No resume exists. */
int envara_app_transport_command(int argc, char *const argv[]);
/* Inert own-process fixture helper: translates only newline K/S/R into two
 * distinct anonymous pipes. Unknown input/EOF burns lease, never releases.
 * Caller creates pipe ends; production argv exposes no descriptor override. */
int envara_app_transport_relay(int input, int lease_writer, int recovery_writer,
    pid_t parent);
#endif
