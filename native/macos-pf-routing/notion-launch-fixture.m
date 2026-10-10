#import <Foundation/Foundation.h>
#include "notion-launch.m"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Standalone nonroot fixture. It never executes/copies/modifies Notion,
 * contacts a DNS broker, activates PF, or authorizes a protected launch. */
static int deny(const struct envara_gui_request *request, void *context) {
    (void)request; (void)context; errno = ENOTSUP; return -1;
}
static int inet_probe(const char *host, const char *port, int udp, int inherited) {
    int parsed = atoi(port); if (parsed < 1024 || parsed > 65535 || (strcmp(host, "127.0.0.1") && strcmp(host, "::1"))) return 101;
    int pair[2]; pid_t child;
    if (inherited) {
        if (pipe(pair) || (child = fork()) < 0) return 102;
        if (child) {
            close(pair[1]); int values[2], status; ssize_t n = read(pair[0], values, sizeof(values)); close(pair[0]);
            if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) || n != sizeof(values)) return 103;
            printf("{\"connected\":%s,\"error\":%d,\"childObserved\":true,\"ready\":false,\"protected\":false}\n", values[0] ? "true" : "false", values[1]); return 0;
        }
        close(pair[0]);
    }
    int v6 = !strcmp(host, "::1"), fd = socket(v6 ? AF_INET6 : AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (fd < 0) return 104;
    struct sockaddr_storage storage = {0}; socklen_t size;
    if (v6) {
        struct sockaddr_in6 *address = (void *)&storage; address->sin6_len = sizeof(*address); address->sin6_family = AF_INET6;
        address->sin6_port = htons((uint16_t)parsed); inet_pton(AF_INET6, host, &address->sin6_addr); size = sizeof(*address);
    } else {
        struct sockaddr_in *address = (void *)&storage; address->sin_len = sizeof(*address); address->sin_family = AF_INET;
        address->sin_port = htons((uint16_t)parsed); inet_pton(AF_INET, host, &address->sin_addr); size = sizeof(*address);
    }
    int success = udp ? sendto(fd, "owned", 5, 0, (struct sockaddr *)&storage, size) == 5 : connect(fd, (struct sockaddr *)&storage, size) == 0;
    int error = success ? 0 : errno; close(fd);
    if (inherited) { int values[] = {success,error}; _exit(write(pair[1], values, sizeof(values)) == sizeof(values) ? 0 : 105); }
    printf("{\"connected\":%s,\"error\":%d,\"childObserved\":false,\"ready\":false,\"protected\":false}\n", success ? "true" : "false", error); return 0;
}
static int socket_probe(const char *path, int inherited) {
    if (!path || path[0] != '/' || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 90;
    struct stat s;
    if (lstat(path, &s) || !S_ISSOCK(s.st_mode) || s.st_uid != getuid()) return 91;
    int result_pipe[2] = {-1, -1}; pid_t child = -1;
    if (inherited) {
        if (pipe(result_pipe)) return 92;
        child = fork(); if (child < 0) return 93;
        if (child > 0) {
            close(result_pipe[1]); int result[2], status;
            ssize_t count = read(result_pipe[0], result, sizeof(result)); close(result_pipe[0]);
            if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) || count != (ssize_t)sizeof(result)) return 94;
            printf("{\"connected\":%s,\"error\":%d,\"childObserved\":true,\"ready\":false,\"protected\":false}\n",
                result[0] ? "true" : "false", result[1]); return 0;
        }
        close(result_pipe[0]);
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0); if (fd < 0) return 95;
    struct sockaddr_un address = {0}; address.sun_family = AF_UNIX; address.sun_len = sizeof(address); strcpy(address.sun_path, path);
    int connected = connect(fd, (const struct sockaddr *)&address, sizeof(address)) == 0, error = connected ? 0 : errno;
    close(fd);
    if (inherited) { int result[] = {connected, error}; _exit(write(result_pipe[1], result, sizeof(result)) == (ssize_t)sizeof(result) ? 0 : 96); }
    printf("{\"connected\":%s,\"error\":%d,\"childObserved\":false,\"ready\":false,\"protected\":false}\n", connected ? "true" : "false", error);
    return 0;
}
static int refusal(const char *bundle, const char *workspace) {
    struct envara_gui_manifest manifest;
    if (envara_gui_manifest_inspect(bundle, 1, &manifest) || strcmp(manifest.identifier, "notion.id")) return 97;
    int supported_refused = envara_notion_supported(&manifest) == -1 && errno == EACCES;
    struct envara_app_registration app = {0}; app.schema = ENVARA_APP_REGISTRY_SCHEMA;
    strcpy(app.registration_id, "00000000-0000-4000-8000-000000000201");
    strcpy(app.version_id, "00000000-0000-4000-8000-000000000202"); app.original = app.snapshot = manifest;
    app.original.fixture_only = app.snapshot.fixture_only = 0;
    struct envara_gui_request request = {0}; request.schema = ENVARA_GUI_SCHEMA;
    request.console_uid = getuid(); request.realm_gid = ENVARA_REALM_GID_MIN;
    strcpy(request.lease_id, "00000000-0000-4000-8000-000000000203");
    strcpy(request.environment_id, "00000000-0000-4000-8000-000000000204");
    if (strlen(workspace) >= sizeof(request.cwd)) return 98;
    strcpy(request.cwd, workspace); strcpy(request.timezone, "Asia/Shanghai"); strcpy(request.browser_locale, "zh-CN");
    struct envara_notion_context context = {0}; strcpy(context.registration_id, app.registration_id); context.front_port = 23456;
    struct envara_notion_plan plan; memset(&plan, 0xa5, sizeof(plan));
    int plan_refused = envara_notion_plan(&app, &request, &context, &plan) == -1 &&
        !plan.ready && !plan.protected_ready && !plan.resumed;
    int unsealed_refused = envara_gui_sealed_snapshot_validate(&app.snapshot) == -1;
    struct envara_gui_lifecycle lifecycle; envara_gui_lifecycle_init(&lifecycle);
    struct envara_gui_stage_authority authority = {deny, NULL};
    int stage_refused = envara_notion_stage(&app, &request, &context, &authority, &lifecycle) == -1 && errno == EACCES &&
        lifecycle.phase == ENVARA_GUI_EMPTY && lifecycle.child.identity.pid == 0 && !lifecycle.protected_ready;
    int okay = supported_refused && plan_refused && unsealed_refused && stage_refused;
    printf("{\"ok\":%s,\"fixtureManifestRefused\":%s,\"unsealedRefused\":%s,\"planRefused\":%s,\"stageRefused\":%s,"
        "\"childPID\":%d,\"ready\":false,\"protected\":false,\"activatesSystem\":false}\n",
        okay ? "true" : "false", supported_refused ? "true" : "false", unsealed_refused ? "true" : "false",
        plan_refused ? "true" : "false", stage_refused ? "true" : "false", lifecycle.child.identity.pid);
    return okay ? 0 : 1;
}
static int supported(const char *bundle) {
    struct envara_gui_manifest manifest; int result = envara_gui_manifest_inspect(bundle, 0, &manifest), error = errno;
    if (!result) { result = envara_notion_supported(&manifest); error = result ? errno : 0; }
    NSString *version = plist_string(bundle, @"Contents/Info.plist", @"CFBundleShortVersionString");
    NSString *electron = plist_string(bundle, @"Contents/Frameworks/Electron Framework.framework/Resources/Info.plist", @"CFBundleVersion");
    NSDictionary *report = @{@"ok":@YES,@"supported":result == 0 ? @YES : @NO,@"error":@(error),@"ready":@NO,@"protected":@NO,@"activatesSystem":@NO,
        @"supportedVersion":version ?: @"",@"electronVersion":electron ?: @"",@"requiredTeam":@"LBQJ96FQ8D"};
    NSData *bytes = [NSJSONSerialization dataWithJSONObject:report options:0 error:NULL];
    if (!bytes || fwrite(bytes.bytes, 1, bytes.length, stdout) != bytes.length || putchar('\n') == EOF) return 107;
    return 0;
}
static int versions(void) {
    if (!supported_versions(@"7.34.0", @"43.6.0") || !supported_versions(@"7.37.1", @"43.6.0")) return 108;
    for (NSString *version in @[@"7.33.9",@"7.34.1",@"7.37.0",@"7.37.1-suffix",@"7.38.0",@" 7.37.1",@"7.37.1 ",@""])
        if (supported_versions(version, @"43.6.0")) return 109;
    for (NSString *electron in @[@"43.5.0",@"43.6.1",@"43.6.0-suffix",@""])
        if (supported_versions(@"7.34.0", electron) || supported_versions(@"7.37.1", electron)) return 110;
    if (supported_versions(nil, @"43.6.0") || supported_versions(@"7.37.1", nil)) return 111;
    puts("{\"ok\":true,\"bothExactVersionsAccepted\":true,\"otherVersionsRefused\":true,\"electronPairRequired\":true,\"ready\":false,\"protected\":false,\"activatesSystem\":false}");
    return 0;
}
int main(int argc, char **argv) {
    if (!getuid() || geteuid() != getuid() || getgid() != getegid() || argc < 2) return 99;
    @autoreleasepool {
        if (argc == 2 && !strcmp(argv[1], "profile")) { puts(envara_notion_dns_profile()); return 0; }
        if (argc == 2 && !strcmp(argv[1], "versions")) return versions();
        if (argc == 3 && !strcmp(argv[1], "scoped-profile")) {
            char profile[PATH_MAX]; int p = atoi(argv[2]);
            if (p < 1024 || p > 65535 || envara_notion_scoped_profile((uint16_t)p, profile, sizeof(profile))) return 106;
            puts(profile); return 0;
        }
        if (argc == 6 && !strcmp(argv[1], "inet-probe") && (!strcmp(argv[4], "tcp") || !strcmp(argv[4], "udp")) &&
            (!strcmp(argv[5], "direct") || !strcmp(argv[5], "inherit"))) return inet_probe(argv[2], argv[3], !strcmp(argv[4], "udp"), !strcmp(argv[5], "inherit"));
        if (argc == 4 && !strcmp(argv[1], "refusal")) return refusal(argv[2], argv[3]);
        if (argc == 3 && !strcmp(argv[1], "supported")) return supported(argv[2]);
        if (argc == 4 && !strcmp(argv[1], "socket-probe") && (!strcmp(argv[3], "direct") || !strcmp(argv[3], "inherit")))
            return socket_probe(argv[2], !strcmp(argv[3], "inherit"));
    }
    return 100;
}
