#include "native.h"
#include "pf-hook.h"
#include "pf-filter-command.h"
#include "app-command.h"
#include "app-native-factory.h"
#include "app-transport.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <libproc.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <poll.h>
#include <signal.h>
#include <pwd.h>
#include <time.h>

extern char **environ;
static volatile sig_atomic_t termination_requested = 0;
static void request_termination(int signal_number) { (void)signal_number; termination_requested = 1; }
static int64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static int control_line(int fd, char *line, size_t capacity, int timeout, int monitor_lease) {
    size_t length = 0; int64_t deadline = milliseconds() + timeout;
    while (length + 1 < capacity) {
        int64_t remaining = deadline - milliseconds();
        if (remaining <= 0 || termination_requested) return -1;
        struct pollfd descriptors[] = {{fd, POLLIN | POLLHUP, 0}, {STDIN_FILENO, POLLHUP, 0}};
        int result = poll(descriptors, monitor_lease ? 2 : 1, (int)remaining);
        if (result < 1 || (monitor_lease && (descriptors[1].revents & (POLLHUP | POLLERR)))) return -1;
        if (!(descriptors[0].revents & (POLLIN | POLLHUP))) continue;
        char byte; ssize_t count = read(fd, &byte, 1);
        if (count != 1 || !byte) return -1;
        if (byte == '\n') { line[length] = 0; return 0; }
        line[length++] = byte;
    }
    return -1;
}
static int base64_value(unsigned char value) {
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '+') return 62;
    if (value == '/') return 63;
    return -1;
}
static int decode_probe(const char *encoded, char *decoded, size_t capacity) {
    size_t length = strlen(encoded), output = 0;
    if (!length || length % 4) return -1;
    for (size_t i = 0; i < length; i += 4) {
        int a = base64_value((unsigned char)encoded[i]), b = base64_value((unsigned char)encoded[i+1]);
        int c = encoded[i+2] == '=' ? 0 : base64_value((unsigned char)encoded[i+2]);
        int d = encoded[i+3] == '=' ? 0 : base64_value((unsigned char)encoded[i+3]);
        if (a < 0 || b < 0 || c < 0 || d < 0 || (encoded[i+2] == '=' && encoded[i+3] != '=') ||
            ((encoded[i+2] == '=' || encoded[i+3] == '=') && i + 4 != length)) return -1;
        unsigned char bytes[] = {(unsigned char)((a << 2) | (b >> 4)), (unsigned char)((b << 4) | (c >> 2)), (unsigned char)((c << 6) | d)};
        int count = encoded[i+2] == '=' ? 1 : (encoded[i+3] == '=' ? 2 : 3);
        if ((count == 1 && (b & 15)) || (count == 2 && (c & 3))) return -1;
        for (int j = 0; j < count; j++) {
            if (!bytes[j] || bytes[j] == '\n' || bytes[j] == '\r' || output + 2 >= capacity) return -1;
            decoded[output++] = (char)bytes[j];
        }
    }
    decoded[output++] = '\n'; decoded[output] = 0; return (int)output;
}
static int write_probe(int fd, const char *data, size_t size) {
    int64_t deadline = milliseconds() + 2000;
    while (size) {
        int64_t remaining = deadline - milliseconds(); if (remaining <= 0 || termination_requested) return -1;
        struct pollfd descriptors[] = {{fd, POLLOUT, 0}, {STDIN_FILENO, POLLHUP, 0}};
        if (poll(descriptors, 2, (int)remaining) < 1 || (descriptors[1].revents & (POLLHUP | POLLERR))) return -1;
        ssize_t count = write(fd, data, size);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) return -1;
        data += count; size -= (size_t)count;
    }
    return 0;
}

static void json_string(const char *value) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}
static int failure(const char *reason) {
    printf("{\"schema\":\"envara.macos-pf-native/v1\",\"ok\":false,\"protected\":false,\"reason\":");
    json_string(reason); puts("}"); return 1;
}
static int number(const char *value, unsigned long *out) {
    char *end;
    if (!value || !*value || *value == '-' || *value == '+') return -1;
    errno = 0; *out = strtoul(value, &end, 10);
    return errno || !end || *end || !*out || *out > INT32_MAX ? -1 : 0;
}
static void print_identity(const struct envara_identity *identity) {
    printf("\"pid\":%d,\"parentPid\":%d,\"consoleUID\":%u,\"uid\":%u,\"realUID\":%u,\"savedUID\":%u,"
           "\"gid\":%u,\"realGID\":%u,\"savedGID\":%u,\"birth\":\"%llu:%06llu\"",
           identity->pid, identity->parent_pid, identity->uid, identity->uid, identity->ruid, identity->saved_uid,
           identity->gid, identity->rgid, identity->saved_gid,
           (unsigned long long)identity->birth_seconds, (unsigned long long)identity->birth_microseconds);
}
static int identify(pid_t pid) {
    struct envara_identity before, after;
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (envara_identity_read(pid, &before) || proc_pidpath(pid, path, sizeof(path)) <= 0 ||
        envara_identity_read(pid, &after) || before.birth_seconds != after.birth_seconds ||
        before.birth_microseconds != after.birth_microseconds ||
        !envara_identity_matches(&after, before.uid, before.gid)) return failure("PROCESS_IDENTITY_UNAVAILABLE");
    printf("{\"schema\":\"envara.macos-pf-native/v1\",\"ok\":true,\"protected\":false,");
    print_identity(&after); printf(",\"path\":"); json_string(path); puts("}"); return 0;
}

static int status(void) {
    uid_t console_uid = 0;
    int have_console = envara_console_uid(&console_uid) == 0;
    printf("{\"schema\":\"envara.macos-pf-native/v1\",\"backend\":\"pf-utun\",\"ok\":true,"
           "\"ready\":false,\"protected\":false,\"consoleUID\":%u,\"consoleAvailable\":%s,"
           "\"realmGID\":{\"min\":7100,\"max\":7999,\"groupNamePrefix\":\"_envara_pf_\"},"
           "\"gates\":{\"administratorHelper\":false,\"ownedUtun\":false,\"packetEngine\":false,"
           "\"pfPolicyAcknowledged\":false,\"dnsAttribution\":false,\"nativeAcceptance\":false},"
           "\"reason\":\"PF_CONTROLLER_AND_NATIVE_ACCEPTANCE_REQUIRED\"}\n", console_uid, have_console ? "true" : "false");
    return 0;
}

static int plan(int argc, char **argv) {
    unsigned long uid = 0, gid = 0;
    const char *cwd = NULL, *executable = NULL;
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 >= argc) return failure("INVALID_PLAN");
        if (!strcmp(argv[i], "--uid") && !uid) { if (number(argv[i+1], &uid)) return failure("INVALID_UID"); }
        else if (!strcmp(argv[i], "--gid") && !gid) { if (number(argv[i+1], &gid)) return failure("INVALID_GID"); }
        else if (!strcmp(argv[i], "--cwd") && !cwd) cwd = argv[i+1];
        else if (!strcmp(argv[i], "--exec") && !executable) executable = argv[i+1];
        else return failure("INVALID_PLAN");
    }
    if (!uid || gid < ENVARA_REALM_GID_MIN || gid > ENVARA_REALM_GID_MAX ||
        !cwd || cwd[0] != '/' || !executable || executable[0] != '/')
        return failure("INVALID_PLAN");
    printf("{\"schema\":\"envara.macos-pf-native/v1\",\"ok\":true,\"ready\":false,\"protected\":false,"
           "\"operation\":\"plan\",\"activatesSystem\":false,\"consoleUID\":%lu,\"gid\":%lu,"
           "\"credentialPolicy\":\"console-uid-and-three-realm-gids\",\"cwd\":", uid, gid);
    json_string(cwd); printf(",\"executable\":"); json_string(executable);
    puts(",\"launch\":\"cold-executable-suspended-until-controller-commit\",\"reason\":\"CONTROLLER_GATES_REQUIRED\"}");
    return 0;
}

static void cancel_family(struct envara_child *child) {
    /* Only the original birth can authorize a group signal. Detached and
     * delegated processes need controller scope/DNS accounting separately. */
    struct envara_identity current;
    if (envara_same_process(&child->identity)) {
        (void)kill(-child->identity.pid, SIGKILL);
        (void)envara_child_cancel(child);
    } else if (!envara_identity_read(child->identity.pid, &current) &&
               current.birth_seconds == child->identity.birth_seconds &&
               current.birth_microseconds == child->identity.birth_microseconds) {
        /* A credential change does not permit touching a replacement PID or
         * an unverified group, but the original child still belongs to us. */
        (void)kill(child->identity.pid, SIGKILL);
    }
    (void)waitpid(child->identity.pid, NULL, WNOHANG);
    if (child->error_fd >= 0) close(child->error_fd);
}

static int launch_fixture(int argc, char **argv) {
    unsigned long uid = 0, gid = 0;
    const char *cwd = NULL, *executable = NULL;
    struct envara_child child;
    int resumed = 0, input_pipe[2], output_pipe[2];
    /* This private fixture primitive is not a public attached-app launcher. */
    if (getuid() != 0 || geteuid() != 0) return failure("ADMINISTRATOR_HELPER_REQUIRED");
    struct sigaction action;
    memset(&action, 0, sizeof(action)); action.sa_handler = request_termination;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL) || sigaction(SIGHUP, &action, NULL))
        return failure("GUARDIAN_SIGNAL_HANDLERS_UNAVAILABLE");
    signal(SIGPIPE, SIG_IGN);
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 >= argc) return failure("INVALID_FIXTURE_LAUNCH");
        if (!strcmp(argv[i], "--uid") && !uid) { if (number(argv[i+1], &uid)) return failure("INVALID_UID"); }
        else if (!strcmp(argv[i], "--gid") && !gid) { if (number(argv[i+1], &gid)) return failure("INVALID_GID"); }
        else if (!strcmp(argv[i], "--cwd") && !cwd) cwd = argv[i+1];
        else if (!strcmp(argv[i], "--executable") && !executable) executable = argv[i+1];
        else return failure("INVALID_FIXTURE_LAUNCH");
    }
    if (!uid || gid < ENVARA_REALM_GID_MIN || gid > ENVARA_REALM_GID_MAX ||
        !cwd || !envara_root_owned_executable(executable))
        return failure("ROOT_OWNED_FIXTURE_AND_REALM_REQUIRED");
    struct passwd *user = getpwuid((uid_t)uid);
    if (!user || !user->pw_name || !user->pw_dir) return failure("CONSOLE_ACCOUNT_UNAVAILABLE");
    char home[PATH_MAX+6], account[256], login[256];
    if (snprintf(home, sizeof(home), "HOME=%s", user->pw_dir) >= (int)sizeof(home) ||
        snprintf(account, sizeof(account), "USER=%s", user->pw_name) >= (int)sizeof(account) ||
        snprintf(login, sizeof(login), "LOGNAME=%s", user->pw_name) >= (int)sizeof(login))
        return failure("CONSOLE_ACCOUNT_INVALID");
    /* Credentials, DYLD hooks and arbitrary parent variables never cross the
     * boundary. A future app controller must explicitly add scoped locale/TZ. */
    char *environment[] = {home, account, login, "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", NULL};
    char *arguments[] = {(char *)executable, NULL};
    if (pipe(input_pipe)) return failure("FIXTURE_CHANNEL_CREATION_FAILED");
    if (pipe(output_pipe)) { close(input_pipe[0]); close(input_pipe[1]); return failure("FIXTURE_CHANNEL_CREATION_FAILED"); }
    if (fcntl(input_pipe[1], F_SETFL, O_NONBLOCK) ||
        envara_spawn_suspended_io((uid_t)uid, (gid_t)gid, cwd, executable, arguments, environment, 0,
                                  input_pipe[0], output_pipe[1], &child)) {
        close(input_pipe[0]); close(input_pipe[1]); close(output_pipe[0]); close(output_pipe[1]);
        return failure("SUSPENDED_FIXTURE_LAUNCH_FAILED");
    }
    close(input_pipe[0]); close(output_pipe[1]);
    if (termination_requested) { cancel_family(&child); return 1; }
    printf("{\"schema\":\"envara.macos-pf-native/v1\",\"ok\":true,\"protected\":false,"
           "\"operation\":\"launch-fixture\",\"phase\":\"suspended\",\"activatesSystem\":false,");
    print_identity(&child.identity); puts("}");
    if (fflush(stdout) || ferror(stdout)) { cancel_family(&child); return 1; }
    for (;;) {
        if (termination_requested) { cancel_family(&child); return 1; }
        struct pollfd input = {STDIN_FILENO, POLLIN | POLLHUP, 0};
        int status, result = (int)waitpid(child.identity.pid, &status, WNOHANG);
        if (result == child.identity.pid) {
            close(child.error_fd);
            puts("{\"schema\":\"envara.macos-pf-native/v1\",\"ok\":true,\"protected\":false,\"phase\":\"fixture-exited\",\"scopeQuiescent\":false}");
            return 0;
        }
        if (result < 0 || !envara_same_process(&child.identity)) { cancel_family(&child); return failure("FIXTURE_SCOPE_IDENTITY_CHANGED"); }
        result = poll(&input, 1, 500);
        if (result < 0) { if (errno == EINTR) continue; cancel_family(&child); return failure("LEASE_PIPE_FAILED"); }
        if (result == 0) continue;
        char command[24584];
        int have_command = control_line(STDIN_FILENO, command, sizeof(command), 2000, 0) == 0;
        if (have_command && !strcmp(command, "RESUME") && !resumed) {
            if (envara_child_resume(&child)) { cancel_family(&child); return failure("FIXTURE_RESUME_FAILED"); }
            resumed = 1;
            puts("{\"schema\":\"envara.macos-pf-native/v1\",\"ok\":true,\"protected\":false,\"phase\":\"fixture-resumed\"}");
            if (fflush(stdout) || ferror(stdout)) { cancel_family(&child); return 1; }
        } else if (have_command && !strncmp(command, "PROBE ", 6) && resumed) {
            char decoded[16385], response[16385];
            int length = decode_probe(command + 6, decoded, sizeof(decoded));
            if (length < 0 || write_probe(input_pipe[1], decoded, (size_t)length) ||
                control_line(output_pipe[0], response, sizeof(response), 15000, 1)) {
                cancel_family(&child); return failure("BOUNDED_FIXTURE_PROBE_FAILED");
            }
            printf("{\"schema\":\"envara.macos-pf-native/v1\",\"ok\":true,\"protected\":false,"
                   "\"operation\":\"fixture-response\",\"payload\":");
            json_string(response); puts("}");
            if (fflush(stdout) || ferror(stdout)) { cancel_family(&child); return 1; }
        } else {
            cancel_family(&child);
            puts("{\"schema\":\"envara.macos-pf-native/v1\",\"ok\":true,\"protected\":false,\"phase\":\"fixture-terminated\",\"scopeQuiescent\":false}");
            return have_command && !strcmp(command, "TERMINATE") ? 0 : 1;
        }
    }
}

static int fixture_child(void) {
    struct envara_identity identity, descendant;
    pid_t child;
    int status;
    if (envara_identity_read(getpid(), &identity) ||
        !envara_identity_matches(&identity, getuid(), getgid()) || fcntl(200, F_GETFD) != -1 || errno != EBADF)
        return 91;
    child = fork();
    if (child < 0) return 92;
    if (!child) {
        if (envara_identity_read(getpid(), &descendant) ||
            !envara_identity_matches(&descendant, identity.uid, identity.gid) ||
            fcntl(200, F_GETFD) != -1 || errno != EBADF) _exit(93);
        _exit(0);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 94;
    return 0;
}

static int fixture_io_child(void) {
    char request[256];
    struct envara_identity identity;
    if (envara_identity_read(getpid(), &identity) || !envara_identity_matches(&identity, getuid(), getgid()) ||
        control_line(STDIN_FILENO, request, sizeof(request), 3000, 0) || strcmp(request, "{\"nonce\":\"fixture\"}")) return 95;
    puts("{\"nonce\":\"fixture\",\"fixture\":\"stdio-isolated\"}");
    return fflush(stdout) ? 96 : 0;
}

static int fixture_io(const char *executable, const char *cwd) {
    struct envara_child child;
    int input[2], output[2], status;
    char probe[256], response[256];
    if (decode_probe("eyJub25jZSI6ImZpeHR1cmUifQ==", probe, sizeof(probe)) < 0 ||
        strcmp(probe, "{\"nonce\":\"fixture\"}\n") ||
        decode_probe("A===", probe, sizeof(probe)) != -1 ||
        decode_probe("e===", probe, sizeof(probe)) != -1 ||
        decode_probe("Zh==", probe, sizeof(probe)) != -1) return -1;
    if (pipe(input)) return -1;
    if (pipe(output)) { close(input[0]); close(input[1]); return -1; }
    char *args[] = {(char *)executable, "fixture-io-child", NULL};
    if (envara_spawn_suspended_io(getuid(), getgid(), cwd, executable, args, environ, 1, input[0], output[1], &child)) {
        close(input[0]); close(input[1]); close(output[0]); close(output[1]); return -1;
    }
    close(input[0]); close(output[1]);
    int error = 0;
    if (envara_child_resume(&child)) error = 1;
    const char *request = "{\"nonce\":\"fixture\"}\n";
    if (!error && write(input[1], request, strlen(request)) != (ssize_t)strlen(request)) error = 1;
    if (!error && (control_line(output[0], response, sizeof(response), 3000, 0) ||
        strcmp(response, "{\"nonce\":\"fixture\",\"fixture\":\"stdio-isolated\"}"))) error = 1;
    close(input[1]); close(output[0]); close(child.error_fd);
    if (error) envara_child_cancel(&child);
    if (waitpid(child.identity.pid, &status, 0) != child.identity.pid || !WIFEXITED(status) || WEXITSTATUS(status)) error = 1;
    return error ? -1 : 0;
}

static int fixture(const char *self) {
    struct envara_child child;
    unsigned char v4[24] = {0}, v6[44] = {0};
    uint32_t family;
    char executable[PATH_MAX], cwd[PATH_MAX];
    int socketfd[2], error = 0, status, result;
    if (getuid() == 0) return failure("FIXTURE_MUST_BE_UNPRIVILEGED");
    if (!realpath(self, executable) || !getcwd(cwd, sizeof(cwd))) return failure("FIXTURE_PATH_UNAVAILABLE");
    family = htonl(AF_INET); memcpy(v4, &family, 4); v4[4] = 0x45;
    family = htonl(AF_INET6); memcpy(v6, &family, 4); v6[4] = 0x60;
    if (envara_utun_frame_family(v4, sizeof(v4)) != AF_INET ||
        envara_utun_frame_family(v6, sizeof(v6)) != AF_INET6 ||
        envara_utun_frame_family(v4, 4) != -1) return failure("PACKET_FRAME_FIXTURE_FAILED");
    v4[4] = 0x60;
    if (envara_utun_frame_family(v4, sizeof(v4)) != -1) return failure("PACKET_FRAME_FIXTURE_FAILED");
    /* A live non-CLOEXEC socket is a stronger closure check than a file. No
     * network listener or external connection is opened by this fixture. */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socketfd)) return failure("FIXTURE_SOCKET_FAILED");
    if (dup2(socketfd[0], 200) != 200 || fcntl(200, F_SETFD, 0)) return failure("FIXTURE_FD_FAILED");
    close(socketfd[0]); close(socketfd[1]);
    char *args[] = { executable, "fixture-child", NULL };
    result = envara_spawn_suspended(getuid(), getgid(), cwd, executable, args, environ, 1, &child);
    close(200);
    if (result) return failure("FIXTURE_SUSPENDED_SPAWN_FAILED");
    if (!envara_identity_matches(&child.identity, getuid(), getgid()) || envara_child_resume(&child)) {
        envara_child_cancel(&child); waitpid(child.identity.pid, NULL, 0); close(child.error_fd);
        return failure("FIXTURE_RESUME_FAILED");
    }
    /* EOF proves a successful SETEXEC closed the error descriptor. */
    result = (int)read(child.error_fd, &error, sizeof(error)); close(child.error_fd);
    if (waitpid(child.identity.pid, &status, 0) != child.identity.pid || result != 0 ||
        !WIFEXITED(status) || WEXITSTATUS(status)) return failure("FIXTURE_EXEC_OR_INHERITANCE_FAILED");
    if (fixture_io(executable, cwd) || envara_transport_fixture()) return failure("PRIVATE_CHANNEL_OR_TRANSPORT_PARSER_FIXTURE_FAILED");
    puts("{\"schema\":\"envara.macos-pf-native/v1\",\"ok\":true,\"protected\":false,"
         "\"activatesSystem\":false,\"fixture\":{\"coldExec\":true,\"threeUIDsUnchanged\":true,"
         "\"threeGIDsUnchanged\":true,\"ordinaryChildInheritance\":true,\"inheritedSocketClosed\":true,"
         "\"suspendedBeforeExec\":true,\"utunPacketFrames\":true,\"privateFixtureStdio\":true,"
         "\"boundedBase64Probe\":true,\"managedRouteParser\":true},"
         "\"unverified\":[\"rootCredentialTransition\",\"GUIAndXPCDelegates\",\"PF\",\"utun\",\"egress\",\"DNS\",\"failSafe\"]}");
    return 0;
}

int main(int argc, char **argv) {
    if(argc>=2&&!strcmp(argv[1],"app-context-clock"))return envara_app_native_context_clock(argc,argv);
    if(argc>=2&&(!strcmp(argv[1],"app-tunnel-bootstrap")||!strcmp(argv[1],"app-tunnel-run")||!strcmp(argv[1],"app-listener-create")))return envara_app_transport_command(argc,argv)?1:0;
    int app_status;
    if (envara_app_command_dispatch(argc, argv, NULL, &app_status)) return app_status;
    if (argc >= 2 && !strcmp(argv[1], "replace-owned-filter")) return envara_pf_filter_command(argc, argv);
    if (argc >= 2 && (!strcmp(argv[1], "hook-status") || !strcmp(argv[1], "insert-owned-root-hook") || !strcmp(argv[1], "delete-owned-root-hook")))
        return envara_pf_hook_main(argc, argv);
    if (argc == 2 && !strcmp(argv[1], "status")) return status();
    if (argc >= 2 && !strcmp(argv[1], "plan")) return plan(argc, argv);
    if (argc == 3 && !strcmp(argv[1], "identity")) {
        unsigned long pid;
        if (number(argv[2], &pid) || pid < 2) return failure("INVALID_PID");
        return identify((pid_t)pid);
    }
    if (argc == 4 && !strcmp(argv[1], "identity") && !strcmp(argv[2], "--pid")) {
        unsigned long pid;
        if (number(argv[3], &pid) || pid < 2) return failure("INVALID_PID");
        return identify((pid_t)pid);
    }
    if (argc >= 2 && !strcmp(argv[1], "launch-fixture")) return launch_fixture(argc, argv);
    if (argc >= 2 && !strcmp(argv[1], "tunnel-core")) return envara_transport_main(argc, argv);
    if (argc == 2 && !strcmp(argv[1], "fixture")) return fixture(argv[0]);
    if (argc == 2 && !strcmp(argv[1], "fixture-child")) return fixture_child();
    if (argc == 2 && !strcmp(argv[1], "fixture-io-child")) return fixture_io_child();
    if (argc == 4 && !strcmp(argv[1], "transport-config-fixture") && !strcmp(argv[2], "--output"))
        return envara_transport_config_fixture(argv[3]);
    /* Root primitives are library APIs. No public CLI can skip the complete
     * controller's PF/transport/DNS/guardian authorization and ACK checks. */
    return failure("CONTROLLER_GATES_REQUIRED");
}
