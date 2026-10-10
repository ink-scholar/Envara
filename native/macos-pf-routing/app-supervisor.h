#ifndef ENVARA_APP_SUPERVISOR_H
#define ENVARA_APP_SUPERVISOR_H
#include "app-control.h"
#include "launch-guardian.h"

#define ENVARA_APP_KEEPER_PROTOCOL "envara.pf-app-keeper/v1"
#define ENVARA_APP_SUPERVISOR_READY 0

enum envara_app_execution_profile {
    ENVARA_APP_EXECUTION_COLD = 0,
    ENVARA_APP_EXECUTION_NOTION_FRONT_ONLY = 1
};

/* A compiled root-session factory, never RPC-provided pointers or FD numbers.
 * inspect/verify attest the exact live private lease and sealed app binding.
 * prepare_guard transfers the three original descriptors to this isolated
 * native process, before durable claim/fork: lease/recovery anonymous readers
 * and the held ORIGINAL owned utun socket. It supplies captured controller,
 * core and front births, a nonrenewable TTL and fixed native deny/scope checks.
 * No interface-name lookup, caller proof boolean or PID adoption substitutes
 * for the original socket or the direct cold child. The ticket.adopt member is
 * ignored: the supervisor itself enters the blocking guardian synchronously. */
struct envara_app_supervisor_provider {
    struct envara_app_ticket_authority ticket;
    int (*prepare_guard)(const struct envara_app_registration *app,
        const struct envara_gui_request *request, const char *run_id, const char *lease_sha256,
        struct envara_launch_guard_request *guard,
        struct envara_launch_guard_authority *authority, void *context);
    void *context;
    /* Optional compiled fixed adapter, called by this SAME native parent only
     * after durable claim and fresh lease/guard checks. It must use authority
     * immediately before fork and return its exact direct cold child, never
     * resume, delegate/adopt a PID, or assert readiness. NULL keeps generic GUI.
     * Failure with an owned partial child enters blocking quarantine. */
    int (*stage)(const struct envara_app_registration *app,
        const struct envara_gui_request *request,
        const struct envara_gui_stage_authority *authority,
        struct envara_gui_lifecycle *out, void *context);
    /* Set only by the compiled fixed native factory, never a caller field.
     * FRONT_ONLY describes its fixed sandbox-exec/observed sealed target
     * chain; it does not claim a public Seatbelt policy inspection result. */
    unsigned execution_profile;
};
struct envara_app_supervisor_context {
    int fixture_only;
    const char *fixture_registry_root, *fixture_ticket_root;
    const struct envara_app_supervisor_provider *provider;
};
struct envara_app_supervisor_report {
    int ready, protected_ready, resumed, armed, released, recovery_required;
    struct envara_gui_lifecycle child;
    struct envara_launch_guard_report guardian;
};

/* Fixed gui-launch-lease TICKET_UUID route. Missing compiled native authority
 * refuses before store creation or claim. A ticket cannot bypass fresh lease,
 * app, committed deny or session inspection. ARM/release JSON is emitted while
 * this same native parent holds guardian custody; no worker thread, transient
 * parent or independent PID adoption exists. Generic staging stays cold;
 * only optional compiled guardian authority can accept one B, with resumed
 * emitted after exact target execution proof. No frame attests readiness.
 * On arming failure after fork, the original utun FD remains held in a blocking
 * quarantine until exact child reap, fixed scope+deny checks and a recovery R.
 * Do not invoke in a UI/multithreaded process or terminate a recovery keeper. */
int envara_app_supervisor_run(const struct envara_app_supervisor_context *context,
    const char *ticket_id, int output_fd, struct envara_app_supervisor_report *out);
#endif
