/* Experimental owned-utun FD guardian, invoked only by an installed root
 * controller. No PF is installed here and no protected claim is made. */
#include "native.h"
#include "transport-session.h"
#include "gui-launch.h"
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <spawn.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>

struct managed_route { char host[16], username[256], password[256]; unsigned port; int udp; };
static volatile sig_atomic_t stop_core_requested, release_requested;
static void guard_signal(int value) {
    if (value == SIGUSR1) release_requested = 1;
    else stop_core_requested = 1;
}
static void erase(void *data, size_t size) { volatile unsigned char *p = data; while (size--) *p++ = 0; }
static int fail(const char *reason) {
    printf("{\"schema\":\"envara.macos-pf-native/v1\",\"ok\":false,\"protected\":false,\"reason\":\"%s\"}\n", reason);
    return 1;
}
static void json_string(FILE *file, const char *value) {
    fputc('"', file);
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"' || *p == '\\') { fputc('\\', file); fputc(*p, file); }
        else if (*p < 32) fprintf(file, "\\u%04x", *p);
        else fputc(*p, file);
    }
    fputc('"', file);
}
static void whitespace(const char **cursor) { while (**cursor == ' ' || **cursor == '\t' || **cursor == '\r') ++*cursor; }
static int hex(unsigned char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}
static int json_text(const char **cursor, char *out, size_t capacity) {
    size_t length = 0;
    whitespace(cursor);
    if (*(*cursor)++ != '"') return -1;
    while (**cursor && **cursor != '"') {
        unsigned char value = (unsigned char)*(*cursor)++;
        if (value < 32) return -1;
        if (value == '\\') {
            value = (unsigned char)*(*cursor)++;
            if (value == 'n') value = '\n';
            else if (value == 'r') value = '\r';
            else if (value == 't') value = '\t';
            else if (value == 'b') value = '\b';
            else if (value == 'f') value = '\f';
            else if (value == 'u') {
                /* Runtime listener credentials are ASCII. Accept escaped
                 * byte-valued JSON strings, reject NUL and wide escapes. */
                int code = 0;
                for (int i = 0; i < 4; i++) { int digit = hex((unsigned char)**cursor); if (digit < 0) return -1; code = code * 16 + digit; ++*cursor; }
                if (code < 1 || code > 127) return -1;
                value = (unsigned char)code;
            } else if (value != '"' && value != '\\' && value != '/') return -1;
        }
        if (!value || length + 1 >= capacity) return -1;
        out[length++] = (char)value;
    }
    if (**cursor != '"') return -1;
    ++*cursor; out[length] = 0; return 0;
}
static int parse_route(const char *json, struct managed_route *route) {
    const char *cursor = json;
    unsigned seen = 0;
    memset(route, 0, sizeof(*route)); whitespace(&cursor);
    if (*cursor++ != '{') return -1;
    for (;;) {
        char key[32], policy[16]; unsigned field;
        if (json_text(&cursor, key, sizeof(key))) return -1;
        whitespace(&cursor); if (*cursor++ != ':') return -1;
        whitespace(&cursor);
        if (!strcmp(key, "host")) { field = 1; if (json_text(&cursor, route->host, sizeof(route->host))) return -1; }
        else if (!strcmp(key, "username")) { field = 2; if (json_text(&cursor, route->username, sizeof(route->username))) return -1; }
        else if (!strcmp(key, "password")) { field = 4; if (json_text(&cursor, route->password, sizeof(route->password))) return -1; }
        else if (!strcmp(key, "udpPolicy")) {
            field = 8; if (json_text(&cursor, policy, sizeof(policy))) return -1;
            if (!strcmp(policy, "proxy")) route->udp = 1;
            else if (strcmp(policy, "block")) return -1;
        } else if (!strcmp(key, "port")) {
            field = 16;
            if (*cursor < '1' || *cursor > '9') return -1;
            while (*cursor >= '0' && *cursor <= '9') {
                route->port = route->port * 10 + (unsigned)(*cursor++ - '0');
                if (route->port > 65535) return -1;
            }
        } else return -1;
        if (seen & field) return -1;
        seen |= field; whitespace(&cursor);
        if (*cursor == '}') { ++cursor; break; }
        if (*cursor++ != ',') return -1;
    }
    whitespace(&cursor);
    return seen == 31 && !*cursor && route->port && route->username[0] && route->password[0] &&
        (!strcmp(route->host, "127.0.0.1") || !strcmp(route->host, "::1")) ? 0 : -1;
}
static int read_line(int fd, char *line, size_t capacity, int timeout) {
    size_t length = 0;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + timeout;
    for (;;) {
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
        int64_t remaining = deadline - ((int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000);
        if (remaining <= 0 || stop_core_requested || release_requested) return -1;
        struct pollfd input = { fd, POLLIN | POLLHUP, 0 };
        int result = poll(&input, 1, (int)remaining);
        if (result < 0) { if (errno == EINTR) return -1; return -1; }
        if (!result) return -1;
        char byte; ssize_t count = read(fd, &byte, 1);
        if (count != 1) return -1;
        if (byte == '\n') { line[length] = 0; return 0; }
        if (!byte || length + 1 >= capacity) return -1;
        line[length++] = byte;
    }
}
static int send_all(int fd, const unsigned char *data, size_t size) {
    while (size) { ssize_t count = send(fd, data, size, 0); if (count <= 0) return -1; data += count; size -= (size_t)count; }
    return 0;
}
static int receive_all(int fd, unsigned char *data, size_t size) {
    while (size) { ssize_t count = recv(fd, data, size, 0); if (count <= 0) return -1; data += count; size -= (size_t)count; }
    return 0;
}
static int authenticate(const struct managed_route *route) {
    int family = !strcmp(route->host, "::1") ? AF_INET6 : AF_INET;
    int fd = socket(family, SOCK_STREAM, 0), result = -1;
    unsigned char response[2], greeting[] = {5, 1, 2}, credentials[513];
    if (fd < 0) return -1;
    struct timeval timeout = {3, 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) goto done;
    if (family == AF_INET) {
        struct sockaddr_in target; memset(&target, 0, sizeof(target));
        target.sin_len = sizeof(target); target.sin_family = AF_INET; target.sin_port = htons((uint16_t)route->port);
        inet_pton(AF_INET, route->host, &target.sin_addr);
        if (connect(fd, (struct sockaddr *)&target, sizeof(target))) goto done;
    } else {
        struct sockaddr_in6 target; memset(&target, 0, sizeof(target));
        target.sin6_len = sizeof(target); target.sin6_family = AF_INET6; target.sin6_port = htons((uint16_t)route->port);
        inet_pton(AF_INET6, route->host, &target.sin6_addr);
        if (connect(fd, (struct sockaddr *)&target, sizeof(target))) goto done;
    }
    if (send_all(fd, greeting, sizeof(greeting)) || receive_all(fd, response, 2) || response[0] != 5 || response[1] != 2) goto done;
    size_t username_length = strlen(route->username), password_length = strlen(route->password);
    credentials[0] = 1; credentials[1] = (unsigned char)username_length;
    memcpy(credentials + 2, route->username, username_length);
    credentials[2 + username_length] = (unsigned char)password_length;
    memcpy(credentials + 3 + username_length, route->password, password_length);
    if (send_all(fd, credentials, 3 + username_length + password_length) || receive_all(fd, response, 2) || response[0] != 1 || response[1] != 0) goto done;
    result = 0;
done:
    erase(credentials, sizeof(credentials)); close(fd); return result;
}
static int private_directory(const char *path) {
    char resolved[PATH_MAX]; struct stat info;
    if (!path || !realpath(path, resolved) || strcmp(path, resolved) || lstat(path, &info) ||
        !S_ISDIR(info.st_mode) || info.st_uid != 0 || (info.st_mode & 0077)) return 0;
    char *separator = strrchr(resolved, '/');
    while (separator && separator != resolved) {
        *separator = 0;
        if (lstat(resolved, &info) || !S_ISDIR(info.st_mode) || info.st_uid != 0 || (info.st_mode & 0022)) return 0;
        separator = strrchr(resolved, '/');
    }
    return 1;
}
static int write_config(const char *filename, const char *name, const char *ipv4, const struct managed_route *route) {
    struct in_addr address;
    char prefix[INET_ADDRSTRLEN + 4];
    if (!ipv4 || inet_pton(AF_INET, ipv4, &address) != 1 ||
        (ntohl(address.s_addr) & 0xfffe0000U) != 0xc6120000U ||
        snprintf(prefix, sizeof(prefix), "%s/30", ipv4) >= (int)sizeof(prefix)) return -1;
    int fd = open(filename, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    FILE *file = fdopen(fd, "w"); if (!file) { close(fd); unlink(filename); return -1; }
    fputs("{\"port\":0,\"socks-port\":0,\"mixed-port\":0,\"redir-port\":0,\"tproxy-port\":0,\"allow-lan\":false,"
          "\"bind-address\":\"127.0.0.1\",\"external-controller\":\"\",\"external-controller-tls\":\"\","
          "\"external-controller-unix\":\"\",\"external-controller-pipe\":\"\",\"external-ui\":\"\",\"external-ui-url\":\"\","
          "\"mode\":\"rule\",\"log-level\":\"silent\",\"ipv6\":false,\"find-process-mode\":\"off\","
          "\"geo-auto-update\":false,\"geodata-mode\":false,\"geox-url\":{\"geo-ip\":\"\",\"mmdb\":\"\",\"asn\":\"\",\"geosite\":\"\"},"
          "\"sniffer\":{\"enable\":false},\"ntp\":{\"enable\":false,\"write-to-system\":false},"
          "\"profile\":{\"store-selected\":false,\"store-fake-ip\":false},"
          "\"dns\":{\"enable\":false,\"listen\":\"\",\"ipv6\":false,\"use-hosts\":false,\"use-system-hosts\":false,"
          "\"enhanced-mode\":\"redir-host\",\"default-nameserver\":[\"https://1.1.1.1/dns-query\"],\"nameserver\":[],\"fallback\":[],\"fake-ip-range\":", file);
    json_string(file, prefix);
    fputs("},\"tun\":{\"enable\":true,\"device\":", file);
    json_string(file, name);
    fputs(",\"file-descriptor\":3,\"stack\":\"gvisor\",\"mtu\":9000,\"auto-route\":false,\"auto-redirect\":false,"
          "\"auto-detect-interface\":false,\"strict-route\":false,\"disable-icmp-forwarding\":true,\"dns-hijack\":[],\"inet6-address\":[]},"
          "\"proxies\":[{\"name\":\"ENVARA_MANAGED_ROUTE\",\"type\":\"socks5\",\"server\":", file);
    json_string(file, route->host); fprintf(file, ",\"port\":%u,\"username\":", route->port);
    json_string(file, route->username); fputs(",\"password\":", file); json_string(file, route->password);
    fprintf(file, ",\"udp\":%s}],\"proxy-groups\":[],\"proxy-providers\":{},\"rule-providers\":{},\"listeners\":[],\"tunnels\":[],\"rules\":[", route->udp ? "true" : "false");
    if (!route->udp) fputs("\"NETWORK,UDP,REJECT\",", file);
    fputs("\"MATCH,ENVARA_MANAGED_ROUTE\"]}\n", file);
    int error = ferror(file) || fflush(file) || fsync(fd); if (fclose(file)) error = 1;
    if (error) { unlink(filename); return -1; }
    return 0;
}

static int spawn_core(const char *core, const char *directory, const char *config, int tunfd, struct envara_identity *identity) {
    posix_spawnattr_t attributes;
    posix_spawn_file_actions_t actions;
    int result; pid_t pid;
    if ((result = posix_spawnattr_init(&attributes))) return result;
    if ((result = posix_spawn_file_actions_init(&actions))) { posix_spawnattr_destroy(&attributes); return result; }
    result = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP);
    if (!result) result = posix_spawnattr_setpgroup(&attributes, 0);
    for (int fd = 0; fd < 3 && !result; fd++) result = posix_spawn_file_actions_addopen(&actions, fd, "/dev/null", O_RDWR, 0);
    if (!result) result = posix_spawn_file_actions_adddup2(&actions, tunfd, 3);
    if (!result) result = posix_spawn_file_actions_addinherit_np(&actions, 3);
    char *arguments[] = {(char *)core, "-d", (char *)directory, "-f", (char *)config, NULL};
    char *environment[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", NULL};
    if (!result) result = posix_spawn(&pid, core, &actions, &attributes, arguments, environment);
    posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attributes);
    if (result) return result;
    if (envara_identity_read(pid, identity) || identity->uid != 0) { kill(pid, SIGKILL); waitpid(pid, NULL, 0); return EACCES; }
    return 0;
}

static int same_file(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_mode == b->st_mode;
}
static int session_directory(const char *path, int *out, struct stat *identity) {
    char chain[PATH_MAX]; struct stat named, held;
    if (!private_directory(path) || strlen(path) >= sizeof(chain)) { errno = EACCES; return -1; }
    strcpy(chain, path);
    for (;;) {
        if (envara_gui_acl_free(chain)) return -1;
        char *slash = strrchr(chain, '/'); if (!slash || slash == chain) break; *slash = 0;
    }
    if (envara_gui_acl_free("/")) return -1;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, &held) || lstat(path, &named) || !same_file(&held, &named) || !S_ISDIR(held.st_mode)) {
        int error = errno ? errno : ESTALE; close(fd); errno = error; return -1;
    }
    *out = fd; *identity = held; return 0;
}
void envara_transport_session_init(struct envara_transport_session *session) {
    if (!session) return;
    memset(session, 0, sizeof(*session)); session->original_utun_fd = session->state_fd = -1;
}
int envara_transport_session_start(const char *core, const char *directory, const char *ipv4,
                                   const char *json, struct envara_transport_session *session) {
    struct managed_route route; struct stat named, held; int result = -1, error;
    memset(&route, 0, sizeof(route));
    if (!session || session->original_utun_fd != -1 || session->state_fd != -1 || !json ||
        strnlen(json, 4096) >= 4096) { errno = EINVAL; return -1; }
    if (getuid() || geteuid()) { errno = EACCES; return -1; }
    if (!envara_root_owned_executable(core) || envara_gui_acl_free(core) || !ipv4 ||
        session_directory(directory, &session->state_fd, &session->state_identity) ||
        snprintf(session->configuration, sizeof(session->configuration), "%s/transport-config.json", directory) >= (int)sizeof(session->configuration)) {
        error = errno ? errno : EACCES; goto failure;
    }
    if (parse_route(json, &route) || authenticate(&route)) { error = EACCES; goto failure; }
    session->original_utun_fd = envara_utun_open(session->interface_name, sizeof(session->interface_name));
    if (session->original_utun_fd < 0 || envara_utun_configure(session->interface_name, ipv4, 9000)) { error = errno; goto failure; }
    if (fstat(session->state_fd, &held) || lstat(directory, &named) || !same_file(&held, &named) ||
        !same_file(&held, &session->state_identity)) { error = ESTALE; goto failure; }
    if (write_config(session->configuration, session->interface_name, ipv4, &route)) { error = errno; goto failure; }
    if (fstatat(session->state_fd, "transport-config.json", &session->configuration_identity, AT_SYMLINK_NOFOLLOW) ||
        lstat(session->configuration, &named) || !same_file(&named, &session->configuration_identity) ||
        !S_ISREG(named.st_mode) || named.st_uid || named.st_nlink != 1 || (named.st_mode & 0077)) { error = ESTALE; goto failure; }
    error = spawn_core(core, directory, session->configuration, session->original_utun_fd, &session->core);
    if (error) goto failure;
    erase(&route, sizeof(route)); return 0;
failure:
    erase(&route, sizeof(route));
    if (session->configuration_identity.st_ino && session->state_fd >= 0 &&
        !fstatat(session->state_fd, "transport-config.json", &named, AT_SYMLINK_NOFOLLOW) &&
        same_file(&named, &session->configuration_identity)) (void)unlinkat(session->state_fd, "transport-config.json", 0);
    if (session->original_utun_fd >= 0) close(session->original_utun_fd);
    if (session->state_fd >= 0) close(session->state_fd);
    envara_transport_session_init(session); errno = error ? error : EIO; return result;
}
int envara_transport_session_stop(struct envara_transport_session *session) {
    if (!session || session->state_fd < 0 || session->original_utun_fd < 0 || session->core.pid < 2) { errno = EINVAL; return -1; }
    if (!session->core_reaped) {
        if (session->core.parent_pid != getpid()) { errno = EACCES; return -1; }
        int status; pid_t reaped = waitpid(session->core.pid, &status, WNOHANG);
        if (reaped == 0) {
            if (!envara_same_process(&session->core) || kill(session->core.pid, SIGKILL)) return -1;
            do { reaped = waitpid(session->core.pid, &status, 0); } while (reaped < 0 && errno == EINTR);
        }
        if (reaped != session->core.pid) { if (!errno) errno = ECHILD; return -1; }
        session->core_reaped = 1;
    }
    struct stat named;
    if (!fstatat(session->state_fd, "transport-config.json", &named, AT_SYMLINK_NOFOLLOW)) {
        if (!same_file(&named, &session->configuration_identity)) { errno = ESTALE; return -1; }
        if (unlinkat(session->state_fd, "transport-config.json", 0) || fsync(session->state_fd)) return -1;
    } else if (errno != ENOENT) return -1;
    return 0;
}
int envara_transport_session_release(struct envara_transport_session *session) {
    if (!session || !session->core_reaped || session->original_utun_fd < 0 || session->state_fd < 0) { errno = EBUSY; return -1; }
    int error = 0; if (close(session->original_utun_fd)) error = errno;
    if (close(session->state_fd) && !error) error = errno;
    envara_transport_session_init(session); if (error) { errno = error; return -1; } return 0;
}

int envara_transport_fixture(void) {
    struct managed_route route;
    const char *valid = "{\"host\":\"127.0.0.1\",\"port\":1080,\"username\":\"fixture-user\",\"password\":\"fixture-password\",\"udpPolicy\":\"block\"}";
    if (parse_route(valid, &route) || strcmp(route.username, "fixture-user") || route.port != 1080 || route.udp) return -1;
    const char *proxy = "{\"udpPolicy\":\"proxy\",\"password\":\"fixture-password\",\"username\":\"fixture-user\",\"port\":65535,\"host\":\"::1\"}";
    if (parse_route(proxy, &route) || !route.udp || route.port != 65535) return -1;
    const char *bad[] = {
        "{}", "{\"host\":\"localhost\",\"port\":1080,\"username\":\"u\",\"password\":\"p\",\"udpPolicy\":\"block\"}",
        "{\"host\":\"127.0.0.1\",\"port\":0,\"username\":\"u\",\"password\":\"p\",\"udpPolicy\":\"block\"}",
        "{\"host\":\"127.0.0.1\",\"port\":65536,\"username\":\"u\",\"password\":\"p\",\"udpPolicy\":\"block\"}",
        "{\"host\":\"127.0.0.1\",\"port\":1080,\"username\":\"\",\"password\":\"p\",\"udpPolicy\":\"block\"}",
        "{\"host\":\"127.0.0.1\",\"port\":1080,\"username\":\"u\",\"password\":\"p\",\"udpPolicy\":\"direct\"}",
        "{\"host\":\"127.0.0.1\",\"port\":1080,\"username\":\"u\",\"password\":\"p\",\"udpPolicy\":\"block\",\"port\":1080}",
        "{\"host\":\"127.0.0.1\",\"port\":1080,\"username\":\"u\",\"password\":\"p\",\"udpPolicy\":\"block\"} trailing",
        "{\"host\":\"127.0.0.1\",\"port\":1080,\"username\":\"u\",\"password\":\"\\u0000\",\"udpPolicy\":\"block\"}",
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) if (!parse_route(bad[i], &route)) return -1;
    erase(&route, sizeof(route)); return 0;
}

int envara_transport_config_fixture(const char *filename) {
    struct managed_route route = { "127.0.0.1", "fixture-user", "fixture-password", 1080, 0 };
    if (getuid() == 0 || !filename || filename[0] != '/') return fail("UNPRIVILEGED_FIXTURE_OUTPUT_REQUIRED");
    if (write_config(filename, "utun9999", "198.18.1.1", &route)) return fail("FIXTURE_CONFIG_WRITE_FAILED");
    puts("{\"schema\":\"envara.macos-pf-native/v1\",\"ok\":true,\"protected\":false,\"activatesSystem\":false,\"operation\":\"transport-config-fixture\"}");
    return 0;
}
static void kill_core(const struct envara_identity *identity, int *alive) {
    if (!*alive) return;
    if (envara_same_process(identity)) { kill(-identity->pid, SIGKILL); kill(identity->pid, SIGKILL); }
    waitpid(identity->pid, NULL, WNOHANG); *alive = 0;
}

int envara_transport_main(int argc, char **argv) {
    const char *core = NULL, *directory = NULL, *ipv4 = NULL;
    char input[4096], name[32], config[PATH_MAX], instance[33];
    struct managed_route route;
    struct envara_identity identity;
    int tunfd = -1, alive = 0, orphaned = 0;
    if (getuid() != 0 || geteuid() != 0) return fail("ADMINISTRATOR_HELPER_REQUIRED");
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 >= argc) return fail("INVALID_TRANSPORT_REQUEST");
        if (!strcmp(argv[i], "--core") && !core) core = argv[i+1];
        else if (!strcmp(argv[i], "--state-dir") && !directory) directory = argv[i+1];
        else if (!strcmp(argv[i], "--ipv4") && !ipv4) ipv4 = argv[i+1];
        else return fail("INVALID_TRANSPORT_REQUEST");
    }
    if (!envara_root_owned_executable(core) || !private_directory(directory) || !ipv4 ||
        snprintf(config, sizeof(config), "%s/transport-config.json", directory) >= (int)sizeof(config))
        return fail("ROOT_OWNED_CORE_AND_PRIVATE_STATE_REQUIRED");
    struct sigaction action; memset(&action, 0, sizeof(action)); action.sa_handler = guard_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL) ||
        sigaction(SIGHUP, &action, NULL) || sigaction(SIGUSR1, &action, NULL)) return fail("GUARDIAN_SIGNALS_UNAVAILABLE");
    signal(SIGPIPE, SIG_IGN);
    if (read_line(STDIN_FILENO, input, sizeof(input), 5000) || parse_route(input, &route)) {
        erase(input, sizeof(input)); erase(&route, sizeof(route)); return fail("PRIVATE_MANAGED_ROUTE_REQUIRED");
    }
    erase(input, sizeof(input));
    if (authenticate(&route)) { erase(&route, sizeof(route)); return fail("MANAGED_SOCKS_AUTHENTICATION_FAILED"); }
    tunfd = envara_utun_open(name, sizeof(name));
    if (tunfd < 0 || envara_utun_configure(name, ipv4, 9000)) {
        if (tunfd >= 0) close(tunfd);
        erase(&route, sizeof(route)); return fail("OWNED_UTUN_CREATION_FAILED");
    }
    if (write_config(config, name, ipv4, &route)) { close(tunfd); erase(&route, sizeof(route)); return fail("PRIVATE_CONFIG_CREATION_FAILED"); }
    erase(&route, sizeof(route));
    if (spawn_core(core, directory, config, tunfd, &identity)) { unlink(config); close(tunfd); return fail("PACKET_CORE_SPAWN_FAILED"); }
    alive = 1;
    unsigned char random[16]; arc4random_buf(random, sizeof(random));
    for (size_t i = 0; i < sizeof(random); i++) snprintf(instance + 2*i, 3, "%02x", random[i]);
    printf("{\"schema\":\"envara.macos-pf-native/v1\",\"ok\":true,\"protected\":false,\"operation\":\"tunnel-core\","
           "\"phase\":\"core-spawned\",\"interfaceName\":\"%s\",\"ipv4Address\":\"%s\",\"pid\":%d,"
           "\"birth\":\"%llu:%06llu\",\"guardianPid\":%d,\"instanceId\":\"%s\",\"ownsOriginalFD\":true,"
           "\"nativeAcceptance\":false}\n", name, ipv4, identity.pid,
           (unsigned long long)identity.birth_seconds, (unsigned long long)identity.birth_microseconds, getpid(), instance);
    if (fflush(stdout) || ferror(stdout)) orphaned = 1;
    for (;;) {
        int child_status;
        if (alive && waitpid(identity.pid, &child_status, WNOHANG) == identity.pid) {
            alive = 0; unlink(config);
            if (!orphaned) {
                puts("{\"schema\":\"envara.macos-pf-native/v1\",\"ok\":true,\"protected\":false,\"phase\":\"core-exited-fd-held\",\"ownsOriginalFD\":true}");
                if (fflush(stdout) || ferror(stdout)) orphaned = 1;
            }
        }
        if (stop_core_requested || orphaned) { kill_core(&identity, &alive); unlink(config); orphaned = 1; stop_core_requested = 0; }
        if (release_requested) { kill_core(&identity, &alive); unlink(config); close(tunfd); return 0; }
        if (orphaned) { poll(NULL, 0, 500); continue; }
        struct pollfd control = {STDIN_FILENO, POLLIN | POLLHUP, 0};
        int ready = poll(&control, 1, 500);
        if (ready < 0) { if (errno != EINTR) orphaned = 1; continue; }
        if (!ready) continue;
        char command[16];
        if (read_line(STDIN_FILENO, command, sizeof(command), 1000)) { orphaned = 1; continue; }
        if (!strcmp(command, "KEEP")) continue;
        if (!strcmp(command, "RELEASE")) { release_requested = 1; continue; }
        orphaned = 1;
    }
}
