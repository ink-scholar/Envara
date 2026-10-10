#include "app-control.h"
#include <libproc.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

static int uuid(const char *s) {
    if (!s || !memchr(s, 0, 37) || strlen(s) != 36 || s[14] != '4' || !strchr("89ab", s[19])) return 0;
    for (int i = 0; i < 36; i++) if (i == 8 || i == 13 || i == 18 || i == 23) { if (s[i] != '-') return 0; }
        else if (!strchr("0123456789abcdef", s[i])) return 0; return 1;
}
static int production_entry(void) {
    char executable[PROC_PIDPATHINFO_MAXSIZE], path[PATH_MAX]; struct stat info;
    if (getuid() || geteuid() || proc_pidpath(getpid(), executable, sizeof(executable)) <= 0 ||
        strcmp(executable, ENVARA_GUI_NATIVE_PATH)) return -1;
    strcpy(path, executable);
    for (;;) {
        if (lstat(path, &info) || info.st_uid || (info.st_mode & (S_ISUID | S_ISGID | 0022)) ||
            (strcmp(path, executable) ? !S_ISDIR(info.st_mode) : !S_ISREG(info.st_mode) || info.st_nlink != 1 || !(info.st_mode & 0111)) ||
            envara_gui_acl_free(path)) return -1;
        char *slash = strrchr(path, '/'); if (!slash || slash == path) break; *slash = 0;
    }
    return envara_gui_acl_free("/");
}
static int emit(int fd, int ok, int error, int app_verified, int environment_verified, int ticket_issued,
                const char *reason, const struct envara_app_registration *app, const char *ticket_id) {
    char data[1024]; int size = snprintf(data, sizeof(data),
        "{\"schema\":1,\"ok\":%s,\"error\":%d,\"ready\":false,\"protected\":false,\"activatesSystem\":false,"
        "\"applicationIdentityVerified\":%s,\"environmentLeaseVerified\":%s,\"ticketIssued\":%s,\"reason\":\"%s\","
        "\"registrationId\":\"%s\",\"versionId\":\"%s\",\"ticketId\":\"%s\",\"snapshotContentSHA256\":\"%s\"}\n",
        ok ? "true" : "false", error, app_verified ? "true" : "false", environment_verified ? "true" : "false", ticket_issued ? "true" : "false", reason,
        app ? app->registration_id : "", app ? app->version_id : "", ticket_id ? ticket_id : "", app ? app->snapshot.content_digest : "");
    if (size < 0 || size >= (int)sizeof(data)) { errno = EOVERFLOW; return -1; }
    size_t offset = 0; while (offset < (size_t)size) { ssize_t n = write(fd, data + offset, (size_t)size - offset);
        if (n < 0 && errno == EINTR) continue; if (n <= 0) return -1; offset += n; } return 0;
}
int envara_app_control_dispatch(const struct envara_app_control_context *input, int argc, const char *const argv[], int output) {
    struct envara_app_control_context empty = {0}; const struct envara_app_control_context *ctx = input ? input : &empty;
    int error = 0, result = -1, app_valid = 0, environment_valid = 0, issued = 0; const char *reason = "INVALID_NATIVE_APP_REQUEST", *ticket_id = NULL;
    struct envara_app_registration app; memset(&app, 0, sizeof(app));
    struct envara_app_registry registry; memset(&registry, 0, sizeof(registry)); registry.fd = -1;
    struct envara_app_ticket_store store; memset(&store, 0, sizeof(store)); store.fd = -1; struct envara_app_ticket ticket;
    if (output < 0 || !argv || argc < 2 || argc > 7 || !argv[1]) { error = EINVAL; goto done; }
    for (int i = 0; i < argc; i++) if (!argv[i] || !memchr(argv[i], 0, PATH_MAX)) { error = EINVAL; goto done; }
    if ((ctx->fixture_only != 0 && ctx->fixture_only != 1) || (ctx->fixture_only ? !getuid() || geteuid() != getuid() : production_entry())) {
        error = EACCES; reason = "FIXED_ROOT_NATIVE_ENTRY_REQUIRED"; goto done;
    }
    const char *command = argv[1]; int registration_command = !strcmp(command, "app-register");
    int plan = !strcmp(command, "app-plan"), retire = !strcmp(command, "app-retire"), prepare = !strcmp(command, "app-ticket-prepare"), inspect = !strcmp(command, "app-ticket-inspect");
    if (!strcmp(command, "gui-launch-lease")) { error = ENOTSUP; reason = "PERSISTENT_NATIVE_SUPERVISOR_ENTRY_REQUIRED"; goto done; }
    if (!(registration_command || plan || retire || prepare || inspect) ||
        (registration_command && (argc != 6 || !uuid(argv[2]) || !uuid(argv[3]) || (strcmp(argv[5], "-") && !uuid(argv[5])))) ||
        (plan && (argc != 6 || !uuid(argv[2]) || !uuid(argv[3]) || !uuid(argv[4]) || !uuid(argv[5]))) ||
        (retire && (argc != 3 || !uuid(argv[2]))) ||
        (prepare && (argc != 7 || !uuid(argv[2]) || !uuid(argv[3]) || !uuid(argv[4]) || !uuid(argv[5]) || !uuid(argv[6]))) ||
        (inspect && (argc != 3 || !uuid(argv[2])))) { error = EINVAL; goto done; }
    if (prepare && (!ctx->authority || !ctx->authority->inspect || !ctx->authority->verify || !ctx->authority->adopt)) {
        error = ENOTSUP; reason = "LIVE_NATIVE_LAUNCH_AUTHORITY_REQUIRED"; goto done; /* No store creation. */
    }
    if (envara_app_registry_open(&registry, ctx->fixture_registry_root, ctx->fixture_only, registration_command)) { error = errno; reason = "APP_REGISTRY_UNAVAILABLE"; goto done; }
    if (registration_command) {
        result = envara_app_registry_register(&registry, argv[2], argv[3], argv[4], !strcmp(argv[5], "-") ? NULL : argv[5], NULL, &app);
        reason = "APPLICATION_SNAPSHOT_REGISTERED"; app_valid = result == 0;
    } else if (retire) { result = envara_app_registry_retire(&registry, argv[2]); reason = "APPLICATION_REGISTRATION_RETIRED"; }
    else if (plan) {
        result = envara_app_registry_resolve(&registry, argv[2], argv[3], &app); app_valid = result == 0; reason = "LIVE_NATIVE_LAUNCH_AUTHORITY_REQUIRED";
        if (!result && ctx->authority && ctx->authority->inspect) {
            struct envara_gui_request request; char hash[65]; memset(&request, 0, sizeof(request)); memset(hash, 0, sizeof(hash));
            if (!ctx->authority->inspect(argv[4], argv[5], &app, &request, hash, ctx->authority->context) &&
                !envara_gui_request_validate(&app.snapshot, &request, ctx->fixture_only) && !strcmp(request.environment_id, argv[4])) environment_valid = 1;
        }
    } else {
        ticket_id = argv[2];
        if (envara_app_ticket_store_open(&store, ctx->fixture_ticket_root, ctx->fixture_only, prepare)) { error = errno; reason = "PRIVATE_APP_TICKET_STORE_UNAVAILABLE"; goto done; }
        result = prepare ? envara_app_ticket_prepare(&store, &registry, argv[2], argv[3], argv[4], argv[5], argv[6], ctx->authority, &ticket) :
            envara_app_ticket_inspect(&store, &registry, argv[2], &ticket);
        if (!result) { app = ticket.app; app_valid = 1; issued = prepare; environment_valid = prepare; }
        reason = prepare ? "PRIVATE_PREPARATION_TICKET_ISSUED" : "PRIVATE_PREPARATION_TICKET_INSPECTED";
    }
    if (result) { error = errno ? errno : EIO; reason = "NATIVE_APP_OPERATION_REFUSED"; }
done:
    envara_app_ticket_store_close(&store); envara_app_registry_close(&registry);
    if (emit(output, result == 0 && !error, error, app_valid, environment_valid, issued, reason, app_valid ? &app : NULL, ticket_id)) return -1;
    if (error || result) { errno = error ? error : EIO; return -1; } return 0;
}
