#include "app-control.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Standalone unprivileged fixture only. Synthetic authority is compiled here,
 * never exposed by app-control-main or the installed native entry. No action
 * executes the copied .app, resumes a child, or claims native routing evidence. */
struct fixture_authority {
    const char *workspace, *lease, *mode, *allowed_app;
    int inspections, verifications, adoptions;
};
static const char *error_name(int error) {
    switch (error) {
        case 0: return "OK"; case EINVAL: return "EINVAL"; case EACCES: return "EACCES";
        case ENOTSUP: return "ENOTSUP"; case ESTALE: return "ESTALE"; case EALREADY: return "EALREADY";
        case EEXIST: return "EEXIST"; case ENOENT: return "ENOENT"; case EILSEQ: return "EILSEQ";
        case EAGAIN: return "EAGAIN"; case ENOSPC: return "ENOSPC"; default: return "OTHER";
    }
}
static int inspect_authority(const char *environment, const char *run, const struct envara_app_registration *app, struct envara_gui_request *request,
                             char hash[65], void *context) {
    struct fixture_authority *state = context; state->inspections++; (void)run;
    if (!app || strcmp(app->registration_id, state->allowed_app) || !app->fixture_only || app->ready || app->protected_ready) { errno = EACCES; return -1; }
    memset(request, 0, sizeof(*request)); request->schema = ENVARA_GUI_SCHEMA;
    request->console_uid = getuid(); request->realm_gid = getgid();
    const char *lease = !strcmp(state->mode, "flip-lease") && state->inspections > 1 ?
        "00000000-0000-4000-8000-000000009999" : state->lease;
    if (snprintf(request->lease_id, sizeof(request->lease_id), "%s", lease) >= (int)sizeof(request->lease_id) ||
        snprintf(request->environment_id, sizeof(request->environment_id), "%s", environment) >= (int)sizeof(request->environment_id) ||
        snprintf(request->cwd, sizeof(request->cwd), "%s", state->workspace) >= (int)sizeof(request->cwd)) { errno = EINVAL; return -1; }
    strcpy(request->timezone, "Asia/Shanghai"); strcpy(request->browser_locale, "zh-CN");
    memset(hash, !strcmp(state->mode, "changed-hash") ? '2' : '1', 64); hash[64] = 0;
    return 0;
}
static int verify_authority(const struct envara_app_registration *app, const struct envara_gui_request *request, const char *run, const char *hash, void *context) {
    struct fixture_authority *state = context; state->verifications++; (void)request; (void)run; (void)hash;
    if (!app || strcmp(app->registration_id, state->allowed_app) || !strcmp(state->mode, "deny")) { errno = EACCES; return -1; } return 0;
}
static int adopt_authority(const struct envara_app_ticket *ticket, struct envara_gui_lifecycle *child, void *context) {
    struct fixture_authority *state = context; state->adoptions++; (void)ticket; (void)child;
    /* Presence exercises the mandatory custody hook. It never attests custody. */
    errno = ENOTSUP; return -1;
}
static int valid_mode(const char *mode) {
    const char *modes[] = {"good", "none", "no-adopt", "deny", "changed-hash", "flip-lease"};
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) if (!strcmp(mode, modes[i])) return 1;
    return 0;
}
static int emit(int result, int error, struct fixture_authority *state, const struct envara_app_ticket *ticket,
                int claimed_before_stage, enum envara_gui_phase phase) {
    printf("{\"ok\":%s,\"error\":%d,\"errorName\":\"%s\",\"fixtureOnly\":true,\"ready\":false,\"protected\":false,\"activatesSystem\":false,"
           "\"inspectCalls\":%d,\"verifyCalls\":%d,\"adoptCalls\":%d,\"claimedBeforeStage\":%s,\"phase\":%d",
           result == 0 ? "true" : "false", error, error_name(error), state->inspections, state->verifications, state->adoptions,
           claimed_before_stage ? "true" : "false", phase);
    if (result == 0 && ticket) printf(",\"ticketId\":\"%s\",\"runId\":\"%s\",\"leaseId\":\"%s\",\"requestUID\":%u,\"requestGID\":%u,"
        "\"recordReady\":%s,\"recordProtected\":%s,\"recordFixtureOnly\":%s,\"issuedNS\":%llu,\"expiresNS\":%llu",
        ticket->ticket_id, ticket->run_id, ticket->request.lease_id, ticket->request.console_uid, ticket->request.realm_gid,
        ticket->ready ? "true" : "false", ticket->protected_ready ? "true" : "false", ticket->fixture_only ? "true" : "false",
        (unsigned long long)ticket->issued_ns, (unsigned long long)ticket->expires_ns);
    puts("}"); return result == 0 ? 0 : 1;
}
int main(int argc, char **argv) {
    if (!getuid() || geteuid() != getuid()) return 90;
    if (argc < 8 || (strcmp(argv[1], "control") && strcmp(argv[1], "api"))) return 91;
    int control = !strcmp(argv[1], "control");
    const char *registry_root = argv[control ? 2 : 3], *ticket_root = argv[control ? 3 : 4];
    struct fixture_authority state = {argv[control ? 4 : 5], argv[control ? 5 : 6], argv[control ? 6 : 7], argv[argc - 1], 0, 0, 0};
    if (!valid_mode(state.mode)) return 92;
    struct envara_app_ticket_authority authority = {inspect_authority, verify_authority,
        !strcmp(state.mode, "no-adopt") ? NULL : adopt_authority, &state};
    const struct envara_app_ticket_authority *selected = !strcmp(state.mode, "none") ? NULL : &authority;
    if (control) {
        struct envara_app_control_context context = {1, registry_root, ticket_root, selected, NULL};
        return envara_app_control_dispatch(&context, argc - 7, (const char *const *)(argv + 6), STDOUT_FILENO) ? 1 : 0;
    }
    if (argc < 10) return 93;
    const char *action = argv[2], *id = argv[8];
    struct envara_app_ticket_store store; memset(&store, 0, sizeof(store)); store.fd = -1;
    struct envara_app_registry registry; memset(&registry, 0, sizeof(registry)); registry.fd = -1;
    struct envara_app_ticket ticket; memset(&ticket, 0, sizeof(ticket));
    struct envara_gui_lifecycle child; envara_gui_lifecycle_init(&child);
    int claimed = 0, has_ticket = 0, result = envara_app_ticket_store_open(&store, ticket_root, 1, !strcmp(action, "store-create"));
    if (result != 0) return emit(result, errno, &state, NULL, 0, child.phase);
    if (!strcmp(action, "store-create")) { if (argc != 10) result = -1, errno = EINVAL; goto done; }
    result = envara_app_registry_open(&registry, registry_root, 1, 0);
    if (result != 0) goto done;
    if (!strcmp(action, "prepare") && argc == 14) {
        result = envara_app_ticket_prepare(&store, &registry, id, argv[9], argv[10], argv[11], argv[12], selected, &ticket);
    } else if (!strcmp(action, "inspect") && argc == 10) {
        result = envara_app_ticket_inspect(&store, &registry, id, &ticket);
    } else if ((!strcmp(action, "claim") || !strcmp(action, "stage-consumed")) && argc == 10) {
        result = envara_app_ticket_claim(&store, &registry, id, selected, &ticket);
        if (!result && !strcmp(action, "stage-consumed")) {
            claimed = 1;
            // Claim has already burned the ticket: stage must refuse before fork.
            result = envara_app_ticket_stage(&store, &registry, id, selected, &child);
        }
    } else { result = -1; errno = EINVAL; }
    has_ticket = result == 0;
done:
    { int error = result == 0 ? 0 : errno;
      envara_app_ticket_store_close(&store); envara_app_registry_close(&registry);
      return emit(result, error, &state, has_ticket ? &ticket : NULL, claimed, child.phase); }
}
