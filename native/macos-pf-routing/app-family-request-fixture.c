#include "app-family.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Real kernel observations, with no syscall substitutions or production
 * branches included here. The fixture owns the only lifeline writer, a
 * shell-like parent, and an independent same-credential sibling. Only the
 * loopback listener below is contacted; no PF, installed app or GUI is used. */
enum { EVENT_STARTED = 1, EVENT_REAPED };
struct event {
    unsigned kind;
    struct envara_identity identity;
    int status;
};
struct fixture {
    int lifeline[2], control[2], events[2], sibling[2];
    int listener, connection;
    pid_t leader_pid, sibling_pid;
    int leader_reaped, sibling_reaped;
    struct envara_identity leader, unrelated, active;
    char url[96];
};
static volatile sig_atomic_t interrupted;
static void interrupt_fixture(int number) { (void)number; interrupted = 1; }
static uint64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
static int exact_io(int fd, void *bytes, size_t length, int writing, int timeout) {
    size_t offset = 0;
    uint64_t deadline = milliseconds() + (unsigned)timeout;
    while (!interrupted && offset < length) {
        uint64_t now = milliseconds();
        if (now >= deadline) return 0;
        struct pollfd item = {.fd = fd, .events = writing ? POLLOUT : POLLIN};
        int ready = poll(&item, 1, (int)(deadline - now));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0 || (item.revents & (POLLERR | POLLNVAL))) return 0;
        ssize_t count = writing ? write(fd, (char *)bytes + offset, length - offset) :
            read(fd, (char *)bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        offset += (size_t)count;
    }
    return offset == length;
}
static int command(int fd, char value) { return exact_io(fd, &value, 1, 1, 1000); }
static int same_identity(const struct envara_identity *a, const struct envara_identity *b) {
    return a->pid == b->pid && a->birth_seconds == b->birth_seconds &&
        a->birth_microseconds == b->birth_microseconds && a->uid == b->uid &&
        a->ruid == b->ruid && a->saved_uid == b->saved_uid && a->gid == b->gid &&
        a->rgid == b->rgid && a->saved_gid == b->saved_gid;
}
static int identity_state(const struct envara_identity *identity) {
    struct proc_bsdinfo info = {0}; errno = 0;
    int count = proc_pidinfo(identity->pid, PROC_PIDTBSDINFO, 1, &info, sizeof(info));
    if (!count && errno == ESRCH) return 0;
    if (count != sizeof(info) || info.pbi_pid != (uint32_t)identity->pid ||
        !info.pbi_start_tvsec || info.pbi_status < SIDL || info.pbi_status > SZOMB) return -1;
    struct envara_identity actual = {.pid = identity->pid, .parent_pid = (pid_t)info.pbi_ppid,
        .uid = info.pbi_uid, .ruid = info.pbi_ruid, .saved_uid = info.pbi_svuid,
        .gid = info.pbi_gid, .rgid = info.pbi_rgid, .saved_gid = info.pbi_svgid,
        .birth_seconds = info.pbi_start_tvsec, .birth_microseconds = info.pbi_start_tvusec};
    if (!same_identity(identity, &actual)) return -1;
    return info.pbi_status == SZOMB ? 2 : 1;
}
static int reap_direct(pid_t pid, int *reaped, int timeout, int *status_out) {
    if (*reaped) return 1;
    uint64_t deadline = milliseconds() + (unsigned)timeout;
    do {
        int status = 0;
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid && (WIFEXITED(status) || WIFSIGNALED(status))) {
            *reaped = 1;
            if (status_out) *status_out = status;
            return 1;
        }
        if (result < 0 && errno != EINTR) return 0;
        struct timespec pause = {.tv_nsec = 1000000};
        (void)nanosleep(&pause, NULL);
    } while (milliseconds() < deadline);
    return 0;
}
static void close_descriptor(int *fd) {
    if (*fd >= 0) close(*fd);
    *fd = -1;
}
static int wait_exited(const struct envara_identity *identity, int timeout) {
    uint64_t deadline = milliseconds() + (unsigned)timeout;
    do {
        int state = identity_state(identity);
        if (state != 1) return state == 0 || state == 2;
        struct timespec pause = {.tv_nsec = 1000000}; (void)nanosleep(&pause, NULL);
    } while (milliseconds() < deadline);
    return 0;
}
static int wait_gate(int lifeline, int gate) {
    uint64_t deadline = milliseconds() + 5000;
    while (milliseconds() < deadline) {
        struct pollfd items[] = {{.fd = lifeline, .events = POLLIN}, {.fd = gate, .events = POLLIN}};
        int ready = poll(items, 2, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || items[0].revents & (POLLHUP | POLLERR | POLLNVAL) ||
            items[1].revents & (POLLERR | POLLNVAL)) return 0;
        if (items[1].revents & POLLIN) {
            char value;
            return read(gate, &value, 1) == 1 && value == 'G';
        }
        if (items[1].revents & POLLHUP) return 0;
    }
    return 0;
}
static void execute_child(int lifeline, int gate, const char *url) {
    if (gate >= 0) {
        int held[] = {lifeline, gate};
        if (envara_close_inherited_descriptors(held, 2) || !wait_gate(lifeline, gate)) _exit(70);
    }
    if (envara_close_inherited_descriptors(NULL, 0)) _exit(71);
    char *environment[] = {"PATH=/usr/bin:/bin", "LC_ALL=C", NULL};
    if (gate >= 0) {
        char *arguments[] = {"/usr/bin/true", NULL};
        execve(arguments[0], arguments, environment);
    } else {
        /* -q disables personal curl configuration; explicit empty proxy and
         * fixed environment prevent inherited proxy/credential settings. */
        char *arguments[] = {"/usr/bin/curl", "-q", "--silent", "--fail", "--max-time", "4",
            "--connect-timeout", "1", "--noproxy", "*", "--proxy", "", "--output", "/dev/null",
            "--proto", "=http", "--http1.1", (char *)url, NULL};
        execve(arguments[0], arguments, environment);
    }
    _exit(72);
}
static void leader_loop(int lifeline, int control, int events, const char *url) {
    pid_t child = -1; int release = -1;
    uint64_t deadline = milliseconds() + 45000;
    while (milliseconds() < deadline) {
        /* This is the real shell-like wait/reap, concurrent with the fixture's
         * public envara_app_family_observe calls. No observer hook drives it. */
        if (child > 1) {
            int status = 0; pid_t result = waitpid(child, &status, WNOHANG);
            if (result == child) {
                struct event event = {.kind = EVENT_REAPED, .status = status};
                child = -1; close_descriptor(&release);
                if (!exact_io(events, &event, sizeof(event), 1, 1000)) break;
            } else if (result < 0 && errno != EINTR) break;
        }
        struct pollfd items[] = {{.fd = lifeline, .events = POLLIN}, {.fd = control, .events = POLLIN}};
        int ready = poll(items, 2, child > 1 ? 1 : 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || (items[0].revents | items[1].revents) & (POLLHUP | POLLERR | POLLNVAL)) break;
        if (!(items[1].revents & POLLIN)) continue;
        char value; if (read(control, &value, 1) != 1) break;
        if (value == 'G') { if (release < 0 || !command(release, 'G')) break; close_descriptor(&release); continue; }
        if ((value != 'C' && value != 'T') || child > 1) break;
        int gate[2] = {-1, -1};
        if (value == 'T' && pipe(gate)) break;
        child = fork();
        if (!child) {
            close_descriptor(&gate[1]);
            execute_child(lifeline, gate[0], url);
        }
        close_descriptor(&gate[0]); release = gate[1];
        if (child < 0) break;
        struct event event = {.kind = EVENT_STARTED};
        if (envara_identity_read(child, &event.identity) ||
            !exact_io(events, &event, sizeof(event), 1, 1000)) break;
    }
    close_descriptor(&release);
    if (child > 1) {
        /* The direct child is still unreaped, so this fixture-only emergency
         * cleanup cannot signal a reused PID or an unrelated process. */
        (void)kill(child, SIGKILL);
        int reaped = 0;
        if (!reap_direct(child, &reaped, 2000, NULL)) _exit(73);
    }
    _exit(0);
}
static void sibling_loop(int lifeline, int control) {
    uint64_t deadline = milliseconds() + 45000;
    while (milliseconds() < deadline) {
        struct pollfd items[] = {{.fd = lifeline, .events = POLLIN}, {.fd = control, .events = POLLIN}};
        int ready = poll(items, 2, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || (items[0].revents | items[1].revents) & (POLLHUP | POLLERR | POLLNVAL)) break;
        if (items[1].revents & POLLIN) {
            char value;
            if (read(control, &value, 1) != 1 || value != 'P' || !command(control, 'P')) break;
        }
    }
    _exit(0);
}
static int create_fixture(struct fixture *f) {
    memset(f, 0, sizeof(*f));
    f->listener = f->connection = -1;
    int *pairs[] = {f->lifeline, f->control, f->events, f->sibling};
    for (unsigned i = 0; i < 4; i++) pairs[i][0] = pairs[i][1] = -1;
    f->listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {.sin_len = sizeof(address), .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);
    if (f->listener < 0 || bind(f->listener, (struct sockaddr *)&address, sizeof(address)) ||
        listen(f->listener, 2) || getsockname(f->listener, (struct sockaddr *)&address, &length)) return 0;
    snprintf(f->url, sizeof(f->url), "http://127.0.0.1:%u/request", (unsigned)ntohs(address.sin_port));
    if (pipe(f->lifeline) || pipe(f->events) || socketpair(AF_UNIX, SOCK_STREAM, 0, f->control) ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, f->sibling)) return 0;
    f->leader_pid = fork();
    if (f->leader_pid < 0) return 0;
    if (!f->leader_pid) {
        int held[] = {f->lifeline[0], f->control[1], f->events[1]};
        if (envara_close_inherited_descriptors(held, 3)) _exit(74);
        leader_loop(held[0], held[1], held[2], f->url);
    }
    f->sibling_pid = fork();
    if (f->sibling_pid < 0) return 0;
    if (!f->sibling_pid) {
        int held[] = {f->lifeline[0], f->sibling[1]};
        if (envara_close_inherited_descriptors(held, 2)) _exit(75);
        sibling_loop(held[0], held[1]);
    }
    close_descriptor(&f->lifeline[0]); close_descriptor(&f->events[1]);
    close_descriptor(&f->control[1]); close_descriptor(&f->sibling[1]);
    return !envara_identity_read(f->leader_pid, &f->leader) &&
        !envara_identity_read(f->sibling_pid, &f->unrelated) &&
        f->leader.parent_pid == getpid() && f->unrelated.parent_pid == getpid() &&
        envara_identity_matches(&f->leader, getuid(), getgid()) &&
        envara_identity_matches(&f->unrelated, getuid(), getgid());
}
static int sibling_alive(struct fixture *f) {
    char value = 0;
    return identity_state(&f->unrelated) == 1 && command(f->sibling[0], 'P') &&
        exact_io(f->sibling[0], &value, 1, 0, 1000) && value == 'P';
}
static int accept_request(struct fixture *f) {
    struct pollfd item = {.fd = f->listener, .events = POLLIN};
    if (poll(&item, 1, 2000) != 1 || !(item.revents & POLLIN)) return 0;
    struct sockaddr_in peer = {0}; socklen_t length = sizeof(peer);
    f->connection = accept(f->listener, (struct sockaddr *)&peer, &length);
    if (f->connection < 0 || peer.sin_family != AF_INET || peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) return 0;
    char request[2048] = {0}; size_t offset = 0;
    while (offset + 1 < sizeof(request)) {
        if (!exact_io(f->connection, request + offset, 1, 0, 1000)) return 0;
        request[++offset] = 0;
        if (strstr(request, "\r\n\r\n")) return !strncmp(request, "GET /request HTTP/1.1\r\n", 23);
    }
    return 0;
}
static int cleanup(struct fixture *f) {
    /* Production Stop may have frozen the owned leader before a refusal.
     * It is our direct unreaped child; resume only that exact child so it can
     * consume lifeline EOF and bound/reap its own outstanding child. */
    close_descriptor(&f->connection); close_descriptor(&f->listener);
    if (f->leader_pid > 1 && !f->leader_reaped) (void)kill(f->leader_pid, SIGCONT);
    close_descriptor(&f->lifeline[1]); close_descriptor(&f->control[0]); close_descriptor(&f->events[0]);
    close_descriptor(&f->sibling[0]);
    int okay = 1;
    if (f->leader_pid > 1) okay &= reap_direct(f->leader_pid, &f->leader_reaped, 3000, NULL);
    if (f->sibling_pid > 1) okay &= reap_direct(f->sibling_pid, &f->sibling_reaped, 2000, NULL);
    if (f->active.pid > 1) okay &= wait_exited(&f->active, 2000);
    int *pairs[] = {f->lifeline, f->control, f->events, f->sibling};
    for (unsigned i = 0; i < 4; i++) for (unsigned j = 0; j < 2; j++) close_descriptor(&pairs[i][j]);
    return okay;
}
#define REQUIRE(value) do { if (!(value)) { \
    fprintf(stderr, "request fixture check failed at line %d (round %u, %s)\n", __LINE__, round, phase); \
    okay = 0; goto finished; \
} } while (0)
#define OBSERVE() do { observations++; if (!envara_app_family_observe(family)) { \
    observation_failed = 1; REQUIRE(0); \
} } while (0)

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || !getuid() || getuid() != geteuid() || getgid() != getegid()) return 64;
    signal(SIGPIPE, SIG_IGN); signal(SIGTERM, interrupt_fixture); signal(SIGALRM, interrupt_fixture);
    alarm(40);
    struct fixture f;
    envara_app_family *family = NULL;
    struct envara_app_family_failure failure = {0};
    unsigned round = 0, observations = 0, registered = 0, requests = 0, responses = 0;
    unsigned curl_reaped = 0, quick_reaped = 0;
    int okay = 1, observation_failed = 0, family_stopped = 0, leader_sent = 0, active_stopped = 0;
    int sibling_untouched = 0, failure_retained = 0;
    const char *phase = "create";
    REQUIRE(create_fixture(&f));
    family = envara_app_family_create_diagnosed(&f.leader, &failure);
    REQUIRE(family && envara_app_family_count(family) == 1);
    REQUIRE(sibling_alive(&f));
    /* First 63 naturally completed curls, then 64 true commands. The 64th
     * curl stays behind the response gate to verify an active descendant Stop.
     * Keeping these phases distinct preserves useful HTTP evidence when an
     * actual exec/exit transition still triggers a production refusal. */
    for (round = 1; round <= 128; round++) {
        int curl = round <= 63 || round == 128;
        phase = "start"; REQUIRE(!interrupted && command(f.control[0], curl ? 'C' : 'T'));
        struct event event;
        REQUIRE(exact_io(f.events[0], &event, sizeof(event), 0, 2000));
        REQUIRE(event.kind == EVENT_STARTED && event.identity.parent_pid == f.leader_pid &&
            envara_identity_matches(&event.identity, getuid(), getgid()));
        f.active = event.identity;
        if (curl) { phase = "http-request"; REQUIRE(accept_request(&f)); requests++; }
        phase = "register-live"; OBSERVE();
        REQUIRE(envara_app_family_count(family) == 2 && identity_state(&f.active) == 1); registered++;
        if (round == 128) break;
        phase = "release";
        if (curl) {
            char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            REQUIRE(exact_io(f.connection, response, sizeof(response) - 1, 1, 1000));
            responses++; close_descriptor(&f.connection);
        } else REQUIRE(command(f.control[0], 'G'));
        phase = "observe-exit-reap";
        uint64_t deadline = milliseconds() + 5000; int reaped = 0;
        while (!interrupted && milliseconds() < deadline) {
            OBSERVE();
            struct pollfd item = {.fd = f.events[0], .events = POLLIN};
            int ready = poll(&item, 1, 0);
            REQUIRE(ready >= 0 && !(item.revents & (POLLHUP | POLLERR | POLLNVAL)));
            if (!(item.revents & POLLIN)) continue;
            REQUIRE(exact_io(f.events[0], &event, sizeof(event), 0, 1000));
            REQUIRE(event.kind == EVENT_REAPED && WIFEXITED(event.status) && !WEXITSTATUS(event.status));
            reaped = 1; break;
        }
        REQUIRE(reaped);
        if (curl) curl_reaped++; else quick_reaped++;
        phase = "observe-after-reap"; OBSERVE();
        REQUIRE(envara_app_family_count(family) == 1 && identity_state(&f.active) == 0);
        memset(&f.active, 0, sizeof(f.active));
        if (round % 16 == 0) REQUIRE(sibling_alive(&f));
    }
    phase = "audit-token-stop";
    REQUIRE(envara_app_family_stop(family, &leader_sent)); family_stopped = 1;
    int status = 0;
    REQUIRE(leader_sent && reap_direct(f.leader_pid, &f.leader_reaped, 2000, &status));
    REQUIRE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    active_stopped = wait_exited(&f.active, 2000);
    REQUIRE(active_stopped && envara_app_family_quiescent(family));
finished:
    if (family) envara_app_family_first_failure(family, &failure);
    if (observation_failed) {
        int sent = 0;
        failure_retained = !envara_app_family_quiescent(family) && !envara_app_family_stop(family, &sent) && !sent;
    }
    sibling_untouched = f.unrelated.pid > 1 && sibling_alive(&f);
    if (!sibling_untouched) okay = 0;
    if (family) envara_app_family_destroy(family);
    int cleaned = cleanup(&f);
    if (!cleaned) okay = 0;
    alarm(0);
    printf("{\"ok\":%s,\"fixtureOnly\":true,\"ready\":false,\"protected\":false,\"activatesSystem\":false,"
        "\"usesProductionObserver\":true,\"faultInjection\":false,\"loopbackRequests\":%u,\"httpResponses\":%u,"
        "\"curlReaped\":%u,\"quickCommandsReaped\":%u,\"registeredChildren\":%u,\"observationCalls\":%u,"
        "\"sameIdentitySiblingUnaffected\":%s,\"ownedCleanupComplete\":%s,\"familyStopped\":%s,"
        "\"leaderSignalSent\":%s,\"activeRequestStopped\":%s,\"failureRetainedCustody\":%s,"
        "\"failedRound\":%u,\"failedPhase\":\"%s\",\"failureReason\":\"%s\",\"failureOsError\":%d,\"failureMachError\":%d}\n",
        okay ? "true" : "false", requests, responses, curl_reaped, quick_reaped, registered, observations,
        sibling_untouched ? "true" : "false", cleaned ? "true" : "false", family_stopped ? "true" : "false",
        leader_sent ? "true" : "false", active_stopped ? "true" : "false", failure_retained ? "true" : "false",
        okay ? 0 : round, okay ? "none" : phase, envara_app_family_failure_name(failure.reason),
        failure.os_error, failure.mach_error);
    return okay ? 0 : 1;
}
