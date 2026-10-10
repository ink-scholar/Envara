#include "gui-launch.h"
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <signal.h>

#define CHECK(expression) do { if (!(expression)) { fprintf(stderr, "fixture failed line %d errno %d\n", __LINE__, errno); goto fail; } } while (0)

static int probe(void) {
    char cwd[PATH_MAX], command[8];
    if (!getcwd(cwd, sizeof(cwd)) || strcmp(getenv("TZ") ?: "", "Asia/Shanghai") ||
        strcmp(getenv("ENVARA_BROWSER_LOCALE") ?: "", "zh-CN") ||
        getenv("HTTP_PROXY") || getenv("ALL_PROXY") || getenv("GUI_PARENT_SENTINEL") ||
        fcntl(200, F_GETFD) != -1 || errno != EBADF) return 80;
    struct envara_identity info;
    if (envara_identity_read(getpid(), &info) || !envara_identity_matches(&info, getuid(), getgid())) return 81;
    printf("{\"probe\":true,\"uid\":%u,\"gid\":%u,\"networkFDClosed\":true,\"envScoped\":true}\n", getuid(), getgid());
    printf("CWD:%s\n", cwd);
    fflush(stdout);
    ssize_t count = read(0, command, sizeof(command));
    return count == 4 && !memcmp(command, "quit", 4) ? 0 : 82;
}
static void request_init(struct envara_gui_request *request, const char *cwd) {
    memset(request, 0, sizeof(*request)); request->schema = ENVARA_GUI_SCHEMA;
    strcpy(request->lease_id, "00000000-0000-4000-8000-000000000001");
    strcpy(request->environment_id, "00000000-0000-4000-8000-000000000002");
    request->console_uid = getuid(); request->realm_gid = getgid();
    strcpy(request->cwd, cwd); strcpy(request->timezone, "Asia/Shanghai"); strcpy(request->browser_locale, "zh-CN");
}
static int line(int fd, char *out, size_t capacity) {
    size_t offset = 0;
    while (offset + 1 < capacity) {
        struct pollfd item = {fd, POLLIN | POLLHUP, 0};
        if (poll(&item, 1, 3000) != 1) return -1;
        ssize_t count = read(fd, out + offset, 1);
        if (count != 1) return -1;
        if (out[offset++] == '\n') { out[offset] = 0; return 0; }
    }
    return -1;
}
int main(int argc, char **argv) {
    if (argc == 1 && getenv("ENVARA_BROWSER_LOCALE")) return probe();
    if (argc == 3 && !strcmp(argv[1], "acl-inspect")) {
        struct stat info;
        if (getuid() == 0 || geteuid() != getuid() || lstat(argv[2], &info) || info.st_uid != getuid() ||
            !(S_ISREG(info.st_mode) || S_ISDIR(info.st_mode) || S_ISLNK(info.st_mode))) return 90;
        int result = envara_gui_acl_free(argv[2]);
        int error = result == 0 ? 0 : errno;
        printf("{\"ok\":%s,\"errno\":%d,\"ready\":false,\"protected\":false,\"activatesSystem\":false}\n",
               result == 0 ? "true" : "false", error);
        return result == 0 ? 0 : 1;
    }
    if (argc == 3 && (!strcmp(argv[1], "inspect-fixture") || !strcmp(argv[1], "inspect-production"))) {
        struct envara_gui_manifest inspected;
        int result = envara_gui_manifest_inspect(argv[2], !strcmp(argv[1], "inspect-fixture"), &inspected);
        if (result == 0 && !strcmp(argv[1], "inspect-production") && envara_gui_sealed_snapshot_validate(&inspected) != -1) return 97;
        puts(result == 0 ? "{\"ok\":true,\"ready\":false,\"activatesSystem\":false}" : "{\"ok\":false,\"ready\":false,\"activatesSystem\":false}");
        return result == 0 ? 0 : 1;
    }
    if (argc != 3 || getuid() == 0 || geteuid() != getuid()) return 90;
    const char *bundle = argv[1], *cwd = argv[2];
    struct envara_gui_manifest manifest; struct envara_gui_request request, invalid;
    struct envara_gui_lifecycle lifecycle; envara_gui_lifecycle_init(&lifecycle);
    struct envara_gui_lifecycle mutation; envara_gui_lifecycle_init(&mutation);
    int input[2] = {-1,-1}, output[2] = {-1,-1}, held = -1, status = 0; pid_t running;
    CHECK(ENVARA_GUI_PRODUCTION_READY == 0);
    struct envara_gui_bootstrap_plan plan; memset(&plan, 0, sizeof(plan));
    strcpy(plan.executable, "/bin/launchctl"); strcpy(plan.uid_decimal, "501");
    strcpy(plan.arguments[0], "/bin/launchctl"); strcpy(plan.arguments[1], "asuser"); strcpy(plan.arguments[2], "501");
    strcpy(plan.arguments[3], ENVARA_GUI_NATIVE_PATH); strcpy(plan.arguments[4], "gui-launch-lease");
    strcpy(plan.arguments[5], "00000000-0000-4000-8000-000000000001");
    struct envara_gui_bootstrap_plan copied_plan = plan; memset(&plan, 0, sizeof(plan)); const char *bootstrap_argv[7];
    CHECK(envara_gui_bootstrap_argv(&copied_plan, bootstrap_argv) == 0 && !strcmp(bootstrap_argv[2], "501") && bootstrap_argv[6] == NULL);
    CHECK(envara_gui_manifest_inspect(bundle, 1, &manifest) == 0);
    CHECK(envara_gui_manifest_unchanged(&manifest) == 0);
    struct envara_gui_manifest malformed = manifest;
    memset(malformed.executable, 'x', sizeof(malformed.executable));
    CHECK(envara_gui_manifest_unchanged(&malformed) == -1 && errno == EINVAL);
    request_init(&request, cwd);
    CHECK(envara_gui_request_validate(&manifest, &request, 1) == 0);
    invalid = request; strcpy(invalid.timezone, "../UTC"); CHECK(envara_gui_request_validate(&manifest, &invalid, 1) == -1);
    invalid = request; strcpy(invalid.timezone, "Etc/../../etc/passwd"); CHECK(envara_gui_request_validate(&manifest, &invalid, 1) == -1);
    invalid = request; strcpy(invalid.browser_locale, "zh-CN\nALL_PROXY=x"); CHECK(envara_gui_request_validate(&manifest, &invalid, 1) == -1);
    invalid = request; invalid.lease_id[0] = 'z'; CHECK(envara_gui_request_validate(&manifest, &invalid, 1) == -1);
    invalid = request; memset(invalid.cwd, 'x', sizeof(invalid.cwd)); CHECK(envara_gui_request_validate(&manifest, &invalid, 1) == -1);
    CHECK(envara_gui_original_running(&manifest, getuid(), &running) == 0 && running == 0);
    CHECK(envara_gui_stage(&manifest, &manifest, &request, 0, NULL, -1, -1, &lifecycle) == -1 && errno == EACCES &&
          lifecycle.blocked_reason == ENVARA_GUI_ROOT_HELPER_REQUIRED);
    CHECK(pipe(input) == 0 && pipe(output) == 0);
    held = socket(AF_INET, SOCK_STREAM, 0); CHECK(held >= 0 && dup2(held, 200) == 200);
    CHECK(fcntl(200, F_SETFD, 0) == 0);
    CHECK(envara_gui_stage(&manifest, &manifest, &request, 1, NULL, -1, 200, &lifecycle) == -1 &&
          lifecycle.blocked_reason == ENVARA_GUI_PRIVATE_PIPES_REQUIRED);
    CHECK(setenv("HTTP_PROXY", "http://fixture.invalid:1", 1) == 0 && setenv("ALL_PROXY", "socks5://fixture.invalid:1", 1) == 0 &&
          setenv("GUI_PARENT_SENTINEL", "must-not-cross", 1) == 0);
    CHECK(envara_gui_stage(&manifest, &manifest, &request, 1, NULL, input[0], output[1], &lifecycle) == 0);
    CHECK(lifecycle.phase == ENVARA_GUI_SUSPENDED && !lifecycle.protected_ready && !lifecycle.scope_quiescent);
    CHECK(envara_gui_stage(&manifest, &manifest, &request, 1, NULL, input[0], output[1], &lifecycle) == -1 && errno == EALREADY);
    CHECK(envara_identity_matches(&lifecycle.child.identity, getuid(), getgid()));
    CHECK(envara_gui_poll(&lifecycle, &status) == 0);
    CHECK(envara_gui_resume_fixture(&lifecycle, 3000) == 0);
    CHECK(envara_gui_resume_fixture(&lifecycle, 3000) == -1); /* no duplicate resume */
    close(input[0]); input[0] = -1; close(output[1]); output[1] = -1;
    char response[256]; CHECK(line(output[0], response, sizeof(response)) == 0 && strstr(response, "\"envScoped\":true"));
    char actual_cwd[PATH_MAX + 8], expected_cwd[PATH_MAX + 8];
    CHECK(snprintf(expected_cwd, sizeof(expected_cwd), "CWD:%s\n", cwd) < (int)sizeof(expected_cwd));
    CHECK(line(output[0], actual_cwd, sizeof(actual_cwd)) == 0 && !strcmp(actual_cwd, expected_cwd));
    CHECK(envara_gui_original_running(&manifest, getuid(), &running) == 1 && running == lifecycle.child.identity.pid);
    struct envara_gui_lifecycle duplicate; envara_gui_lifecycle_init(&duplicate);
    CHECK(envara_gui_stage(&manifest, &manifest, &request, 1, NULL, -1, -1, &duplicate) == -1 && errno == EALREADY);
    CHECK(write(input[1], "quit", 4) == 4);
    for (int i = 0; i < 300 && !lifecycle.leader_reaped; i++) { CHECK(envara_gui_poll(&lifecycle, &status) >= 0); if (!lifecycle.leader_reaped) usleep(10000); }
    CHECK(lifecycle.leader_reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0 && !lifecycle.scope_quiescent);
    status = -1; CHECK(envara_gui_poll(&lifecycle, &status) == 1 && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(envara_gui_stage(&manifest, &manifest, &request, 1, NULL, -1, -1, &lifecycle) == -1 && errno == EALREADY);
    close(input[1]); input[1] = -1; close(output[0]); output[0] = -1;
    CHECK(envara_gui_original_running(&manifest, getuid(), &running) == 0);
    CHECK(envara_gui_stage(&manifest, &manifest, &request, 1, NULL, -1, -1, &mutation) == 0);
    char marker[PATH_MAX]; CHECK(snprintf(marker, sizeof(marker), "%s/Contents/Resources/marker", bundle) < (int)sizeof(marker));
    int marker_fd = open(marker, O_WRONLY | O_TRUNC); CHECK(marker_fd >= 0);
    CHECK(write(marker_fd, "changed", 7) == 7); close(marker_fd);
    CHECK(envara_gui_manifest_unchanged(&manifest) == -1 && errno == ESTALE);
    CHECK(envara_gui_resume_fixture(&mutation, 3000) == -1 && mutation.leader_reaped && mutation.phase == ENVARA_GUI_CANCELLED);
    close(held); close(200);
    puts("{\"ok\":true,\"ready\":false,\"protected\":false,\"activatesSystem\":false,\"fixtures\":{\"immutableBundle\":true,\"strictRequest\":true,\"suspendedBeforeExec\":true,\"scopedEnvironment\":true,\"inheritedNetworkFDClosed\":true,\"originalRunningRefused\":true,\"duplicateResumeRefused\":true,\"mutationCancels\":true,\"noQuiescenceClaim\":true}}"); return 0;
fail:
    if (lifecycle.phase != ENVARA_GUI_EMPTY && !lifecycle.leader_reaped) envara_gui_cancel(&lifecycle);
    if (mutation.phase != ENVARA_GUI_EMPTY && !mutation.leader_reaped) envara_gui_cancel(&mutation);
    for (int i = 0; i < 2; i++) { if (input[i] >= 0) close(input[i]); if (output[i] >= 0) close(output[i]); }
    if (held >= 0) close(held); close(200); return 1;
}
