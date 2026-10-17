#include "launch-guardian.h"
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

/* Preserve each native inventory result, but schedule a real fork/exit after
 * the registered member's second empty snapshot. The actual guardian and
 * family implementations decide observation, Stop, custody and release. */
static int boundary_listchildren(pid_t parent, void *buffer, int size);
#define proc_listchildpids boundary_listchildren
#include "launch-guardian.c"
#undef proc_listchildpids

enum { BOUNDARY_REACHED = 1000 };
struct boundary_receipt {
    int event, descendant_live;
    unsigned scope_calls, scope_refusals;
    struct envara_launch_guard_report report;
    struct envara_identity leader, member, descendant;
};
struct boundary_context {
    int armed, triggered, lists, original_fd, report_fd, member_control, member_events;
    int network_revoked;
    unsigned scope_calls, scope_refusals;
    struct envara_launch_guard_report report;
    struct envara_identity leader, member, descendant;
};
static struct boundary_context boundary;
static volatile sig_atomic_t fixture_interrupted;
static int boundary_released_while_live;
static void boundary_interrupt(int number) { (void)number; fixture_interrupted = 1; }
static uint64_t boundary_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
static int boundary_io(int fd, void *bytes, size_t length, int writing, int timeout) {
    size_t offset = 0; uint64_t deadline = boundary_ms() + (unsigned)timeout;
    while (!fixture_interrupted && offset < length) {
        uint64_t now = boundary_ms(); if (now >= deadline) return 0;
        struct pollfd item = {.fd = fd, .events = writing ? POLLOUT : POLLIN};
        int ready = poll(&item, 1, (int)(deadline - now));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0 || item.revents & (POLLERR | POLLNVAL)) return 0;
        ssize_t count = writing ? write(fd, (char *)bytes + offset, length - offset) :
            read(fd, (char *)bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        offset += (size_t)count;
    }
    return offset == length;
}
static int boundary_command(int fd, char byte) { return boundary_io(fd, &byte, 1, 1, 1000); }
static void boundary_close(int *fd) { if (*fd >= 0) close(*fd); *fd = -1; }
static int boundary_pipe(int pair[2]) {
    return !pipe(pair) && !fcntl(pair[0], F_SETFD, FD_CLOEXEC) && !fcntl(pair[1], F_SETFD, FD_CLOEXEC);
}
static int boundary_state(const struct envara_identity *identity, pid_t *parent) {
    struct proc_bsdinfo info = {0}; errno = 0;
    if (identity->pid <= 1) return -1;
    int bytes = proc_pidinfo(identity->pid, PROC_PIDTBSDINFO, 1, &info, sizeof(info));
    if (!bytes && errno == ESRCH) return 0;
    if (bytes != sizeof(info) || info.pbi_pid != (uint32_t)identity->pid ||
        info.pbi_status < SIDL || info.pbi_status > SZOMB ||
        info.pbi_start_tvsec != identity->birth_seconds || info.pbi_start_tvusec != identity->birth_microseconds ||
        info.pbi_uid != identity->uid || info.pbi_ruid != identity->ruid || info.pbi_svuid != identity->saved_uid ||
        info.pbi_gid != identity->gid || info.pbi_rgid != identity->rgid || info.pbi_svgid != identity->saved_gid) return -1;
    if (parent) *parent = (pid_t)info.pbi_ppid;
    return info.pbi_status == SZOMB ? 2 : 1;
}
static int boundary_wait_absent(const struct envara_identity *identity, int timeout) {
    uint64_t deadline = boundary_ms() + (unsigned)timeout;
    do {
        int state = boundary_state(identity, NULL);
        if (state == 0) return 1;
        if (state < 0) return 0;
        struct timespec pause = {.tv_nsec = 1000000}; (void)nanosleep(&pause, NULL);
    } while (boundary_ms() < deadline);
    return 0;
}
static int boundary_reap(pid_t pid, int *reaped, int timeout, int *status_out) {
    if (*reaped || pid <= 1) return 1;
    uint64_t deadline = boundary_ms() + (unsigned)timeout;
    do {
        int status = 0; pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid && (WIFEXITED(status) || WIFSIGNALED(status))) {
            *reaped = 1; if (status_out) *status_out = status; return 1;
        }
        if (result < 0 && errno != EINTR) return 0;
        struct timespec pause = {.tv_nsec = 1000000}; (void)nanosleep(&pause, NULL);
    } while (boundary_ms() < deadline);
    return 0;
}
static void boundary_wait_lifeline(int lifeline, int ping) {
    uint64_t deadline = boundary_ms() + 15000;
    while (boundary_ms() < deadline) {
        struct pollfd items[] = {{.fd = lifeline, .events = POLLIN}, {.fd = ping, .events = POLLIN}};
        int ready = poll(items, 2, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || items[0].revents & (POLLHUP | POLLERR | POLLNVAL)) break;
        if (ping >= 0 && items[1].revents & POLLIN) {
            char byte;
            if (read(ping, &byte, 1) != 1 || byte != 'P' || !boundary_command(ping, 'P')) break;
        }
    }
}
static void boundary_member(int lifeline, int control, int events) {
    struct envara_identity identity;
    if (envara_identity_read(getpid(), &identity) || !boundary_io(events, &identity, sizeof(identity), 1, 1000)) _exit(70);
    uint64_t deadline = boundary_ms() + 15000;
    while (boundary_ms() < deadline) {
        struct pollfd items[] = {{.fd = lifeline, .events = POLLIN}, {.fd = control, .events = POLLIN}};
        int ready = poll(items, 2, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || (items[0].revents | items[1].revents) & (POLLHUP | POLLERR | POLLNVAL)) _exit(0);
        if (!(items[1].revents & POLLIN)) continue;
        char byte; if (read(control, &byte, 1) != 1 || byte != 'F') _exit(71);
        pid_t child = fork();
        if (child < 0) _exit(72);
        if (!child) {
            if (envara_launch_guard_isolate_descriptors(&lifeline, 1)) _exit(73);
            boundary_wait_lifeline(lifeline, -1); _exit(0);
        }
        if (envara_identity_read(child, &identity) || identity.parent_pid != getpid() ||
            !boundary_io(events, &identity, sizeof(identity), 1, 1000)) _exit(74);
        _exit(0); /* Real surviving descendant, now reparented by the kernel. */
    }
    _exit(75);
}
static void boundary_leader(int lifeline, int control, int events) {
    int held[] = {lifeline, control, events};
    if (envara_launch_guard_isolate_descriptors(held, 3)) _exit(76);
    pid_t member = fork();
    if (member < 0) _exit(77);
    if (!member) boundary_member(lifeline, control, events);
    close(control); close(events);
    int reaped = 0;
    uint64_t deadline = boundary_ms() + 15000;
    while (boundary_ms() < deadline) {
        if (!reaped) {
            int status; pid_t result = waitpid(member, &status, WNOHANG);
            if (result == member) reaped = 1;
            else if (result < 0 && errno != EINTR) _exit(78);
        }
        struct pollfd item = {.fd = lifeline, .events = POLLIN};
        int ready = poll(&item, 1, reaped ? 100 : 1);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || item.revents & (POLLHUP | POLLERR | POLLNVAL)) break;
    }
    if (!reaped) {
        /* Direct unreaped child: fixture cleanup cannot target a reused PID. */
        (void)kill(member, SIGKILL);
        if (!boundary_reap(member, &reaped, 1000, NULL)) _exit(79);
    }
    _exit(0);
}
static void boundary_receipt(int event, const struct envara_launch_guard_report *report) {
    struct boundary_receipt value = {.event = event, .descendant_live = boundary_state(&boundary.descendant, NULL) == 1,
        .scope_calls = boundary.scope_calls, .scope_refusals = boundary.scope_refusals,
        .report = report ? *report : boundary.report,
        .leader = boundary.leader, .member = boundary.member, .descendant = boundary.descendant};
    (void)boundary_io(boundary.report_fd, &value, sizeof(value), 1, 1000);
}
static int boundary_listchildren(pid_t parent, void *buffer, int size) {
    int count = proc_listchildpids(parent, buffer, size), saved_errno = errno;
    if (!boundary.armed || boundary.triggered || parent != boundary.member.pid || ++boundary.lists != 2) return count;
    if (count != 0 || !boundary_command(boundary.member_control, 'F') ||
        !boundary_io(boundary.member_events, &boundary.descendant, sizeof(boundary.descendant), 0, 2000) ||
        boundary.descendant.parent_pid != boundary.member.pid ||
        !envara_identity_matches(&boundary.descendant, getuid(), getgid()) ||
        !boundary_wait_absent(&boundary.member, 2000)) { errno = EIO; return -1; }
    pid_t reparented = 0;
    if (boundary_state(&boundary.descendant, &reparented) != 1 || reparented != 1) { errno = EIO; return -1; }
    boundary.triggered = 1; boundary_receipt(BOUNDARY_REACHED, NULL);
    errno = saved_errno;
    return count; /* Exactly the native empty snapshot taken before the fork. */
}
static int boundary_deny(void *opaque) { (void)opaque; return 1; }
static int boundary_revoke(void *opaque) {
    struct boundary_context *context = opaque; context->network_revoked = 1; return 1;
}
static int boundary_scope(void *opaque) {
    struct boundary_context *context = opaque; context->scope_calls++;
    /* Fixture callback only: real owned-process absence, not the privileged
     * production realm-GID census. Unknown identity also refuses release. */
    int absent = context->network_revoked && context->triggered && boundary_state(&context->descendant, NULL) == 0;
    if (!absent) context->scope_refusals++;
    return absent;
}
static void boundary_observe(enum envara_launch_guard_event event,
    const struct envara_launch_guard_report *report, void *opaque) {
    struct boundary_context *context = opaque; context->report = *report;
    if (event == ENVARA_GUARD_ARMED) {
        boundary_close(&context->original_fd); context->armed = 1;
    }
    boundary_receipt(event, report);
}
static void boundary_guardian(pid_t controller, int lifeline, int lease, int recovery, int reports, int original) {
    int held[] = {lifeline, lease, recovery, reports, original};
    if (envara_launch_guard_isolate_descriptors(held, 5)) _exit(80);
    int control[2], events[2];
    if (!boundary_pipe(control) || !boundary_pipe(events)) _exit(81);
    pid_t leader = fork();
    if (leader < 0) _exit(82);
    if (!leader) boundary_leader(lifeline, control[0], events[1]);
    close(control[0]); close(events[1]);
    boundary = (struct boundary_context){.original_fd = original, .report_fd = reports,
        .member_control = control[1], .member_events = events[0]};
    if (!boundary_io(events[0], &boundary.member, sizeof(boundary.member), 0, 2000) ||
        envara_identity_read(leader, &boundary.leader) || boundary.member.parent_pid != leader) _exit(83);
    struct envara_launch_guard_request request = {.fixture_only = 1, .dependency_count = 1,
        .child.identity = boundary.leader, .lease_fd = lease, .recovery_fd = recovery,
        .retained_fd = original, .lease_milliseconds = 12000};
    if (envara_identity_read(controller, &request.dependencies[0])) _exit(84);
    struct envara_launch_guard_authority authority = {.verify_persistent_deny = boundary_deny,
        .verify_scope_quiescent = boundary_scope, .observe = boundary_observe, .context = &boundary,
        .revoke_owned_network = boundary_revoke};
    struct envara_launch_guard_report report = {0};
    int result = envara_launch_guard_run(&request, &authority, &report);
    _exit(result == 0 && boundary.triggered && boundary.scope_refusals == 2 && report.child_reaped &&
        report.scope_quiescent_observed && !report.owns_retained_fd && !report.ready && !report.protected_ready ? 0 : 85);
}
static int boundary_receive(int reports, int expected, struct boundary_receipt *latest, unsigned *released) {
    uint64_t deadline = boundary_ms() + 2500;
    while (boundary_ms() < deadline) {
        if (!boundary_io(reports, latest, sizeof(*latest), 0, 2500)) return 0;
        if (latest->event == ENVARA_GUARD_RELEASED) {
            (*released)++;
            if (latest->descendant_live) boundary_released_while_live = 1;
        }
        if (latest->event == expected) return 1;
        if (latest->event == ENVARA_GUARD_RELEASED) return 0;
    }
    return 0;
}
static int boundary_ping(int fd, const struct envara_identity *sibling) {
    char response = 0;
    return boundary_state(sibling, NULL) == 1 && boundary_command(fd, 'P') &&
        boundary_io(fd, &response, 1, 0, 1000) && response == 'P';
}
static void boundary_resume_owned(const struct envara_identity *identity) {
    if (boundary_state(identity, NULL) != 1) return;
    struct proc_bsdinfo info = {0};
    if (proc_pidinfo(identity->pid, PROC_PIDTBSDINFO, 1, &info, sizeof(info)) != sizeof(info) || info.pbi_status != SSTOP) return;
    mach_port_t name = MACH_PORT_NULL; audit_token_t token; pid_t actual = 0;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    int valid = task_name_for_pid(mach_task_self(), identity->pid, &name) == KERN_SUCCESS &&
        pid_for_task(name, &actual) == KERN_SUCCESS && actual == identity->pid &&
        task_info(name, TASK_AUDIT_TOKEN, (task_info_t)&token, &count) == KERN_SUCCESS &&
        count == TASK_AUDIT_TOKEN_COUNT && envara_same_process(identity);
    if (name != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), name);
    if (valid && proc_signal_with_audittoken) (void)proc_signal_with_audittoken(&token, SIGCONT);
}
#define BOUNDARY_REQUIRE(value) do { if (!(value)) { \
    fprintf(stderr, "fork boundary fixture failed at line %d (%s)\n", __LINE__, phase); okay = 0; goto finished; \
} } while (0)

int main(void) {
    if (!getuid() || getuid() != geteuid() || getgid() != getegid()) return 64;
    signal(SIGPIPE, SIG_IGN); signal(SIGALRM, boundary_interrupt); signal(SIGTERM, boundary_interrupt); alarm(15);
    int lifeline[2] = {-1, -1}, lease[2] = {-1, -1}, recovery[2] = {-1, -1};
    int reports[2] = {-1, -1}, custody[2] = {-1, -1}, sibling[2] = {-1, -1};
    int *pairs[] = {lifeline, lease, recovery, reports, custody, sibling};
    pid_t guardian = -1, peer = -1; int guardian_reaped = 0, peer_reaped = 0, forced = 0;
    struct envara_identity independent = {0}; struct boundary_receipt latest = {0};
    unsigned released = 0, refused = 0; int okay = 1, survivor_verified = 0, custody_held = 0, sibling_untouched = 0;
    int final_release = 0, final_eof = 0; const char *phase = "setup";
    BOUNDARY_REQUIRE(boundary_pipe(lifeline) && boundary_pipe(lease) && boundary_pipe(recovery) && boundary_pipe(reports) &&
        !socketpair(AF_UNIX, SOCK_STREAM, 0, custody) && !socketpair(AF_UNIX, SOCK_STREAM, 0, sibling));
    peer = fork(); BOUNDARY_REQUIRE(peer >= 0);
    if (!peer) {
        int held[] = {lifeline[0], sibling[1]};
        if (envara_launch_guard_isolate_descriptors(held, 2)) _exit(86);
        boundary_wait_lifeline(held[0], held[1]); _exit(0);
    }
    guardian = fork(); BOUNDARY_REQUIRE(guardian >= 0);
    if (!guardian) boundary_guardian(getppid(), lifeline[0], lease[0], recovery[0], reports[1], custody[0]);
    boundary_close(&lifeline[0]); boundary_close(&lease[0]); boundary_close(&recovery[0]);
    boundary_close(&reports[1]); boundary_close(&custody[0]); boundary_close(&sibling[1]);
    BOUNDARY_REQUIRE(!envara_identity_read(peer, &independent) && boundary_ping(sibling[0], &independent));
    phase = "real-fork-after-empty-vector";
    BOUNDARY_REQUIRE(boundary_receive(reports[0], ENVARA_GUARD_ARMED, &latest, &released));
    BOUNDARY_REQUIRE(boundary_receive(reports[0], BOUNDARY_REACHED, &latest, &released));
    BOUNDARY_REQUIRE(latest.descendant_live && boundary_state(&latest.descendant, NULL) == 1 &&
        boundary_state(&latest.member, NULL) == 0);
    phase = "production-family-stop";
    BOUNDARY_REQUIRE(boundary_command(lease[1], 'S'));
    BOUNDARY_REQUIRE(boundary_receive(reports[0], ENVARA_GUARD_REVOKED, &latest, &released));
    if (!latest.report.child_reaped)
        BOUNDARY_REQUIRE(boundary_receive(reports[0], ENVARA_GUARD_CHILD_REAPED, &latest, &released));
    BOUNDARY_REQUIRE(latest.report.family_stop_confirmed && latest.report.child_reaped && latest.descendant_live);
    survivor_verified = 1;
    phase = "scope-refuses-release";
    for (unsigned attempt = 1; attempt <= 2; attempt++) {
        BOUNDARY_REQUIRE(boundary_command(recovery[1], 'R'));
        BOUNDARY_REQUIRE(boundary_receive(reports[0], ENVARA_GUARD_RELEASE_REFUSED, &latest, &released));
        BOUNDARY_REQUIRE(latest.scope_calls == attempt && latest.scope_refusals == attempt &&
            latest.report.family_stop_confirmed && latest.report.child_reaped && latest.report.network_revoked &&
            latest.report.persistent_deny_observed && !latest.report.scope_quiescent_observed &&
            latest.report.owns_retained_fd && latest.descendant_live && !released);
        struct pollfd item = {.fd = custody[1], .events = POLLIN | POLLHUP};
        BOUNDARY_REQUIRE(poll(&item, 1, 50) == 0); refused++;
    }
    custody_held = 1;
    BOUNDARY_REQUIRE(boundary_ping(sibling[0], &independent)); sibling_untouched = 1;
    phase = "owned-descendant-cleanup";
    boundary_close(&lifeline[1]);
    BOUNDARY_REQUIRE(boundary_wait_absent(&latest.descendant, 2000));
    BOUNDARY_REQUIRE(boundary_command(recovery[1], 'R'));
    BOUNDARY_REQUIRE(boundary_receive(reports[0], ENVARA_GUARD_RELEASED, &latest, &released));
    BOUNDARY_REQUIRE(released == 1 && latest.scope_calls == 3 && latest.scope_refusals == 2 &&
        latest.report.scope_quiescent_observed && !latest.report.owns_retained_fd && !latest.descendant_live);
    final_release = 1;
    struct pollfd item = {.fd = custody[1], .events = POLLIN | POLLHUP}; char byte;
    BOUNDARY_REQUIRE(poll(&item, 1, 1000) == 1 && read(custody[1], &byte, 1) == 0); final_eof = 1;
    int status = 0;
    BOUNDARY_REQUIRE(boundary_reap(guardian, &guardian_reaped, 1000, &status) && WIFEXITED(status) && !WEXITSTATUS(status));
finished:
    boundary_close(&lifeline[1]);
    boundary_resume_owned(&latest.leader); boundary_resume_owned(&latest.member);
    if (guardian > 1 && !guardian_reaped) {
        if (recovery[1] >= 0) (void)boundary_command(recovery[1], 'R');
        if (!boundary_reap(guardian, &guardian_reaped, 2000, NULL)) {
            forced = 1; (void)kill(guardian, SIGKILL);
            (void)boundary_reap(guardian, &guardian_reaped, 1000, NULL);
        }
    }
    int cleaned = guardian <= 1 || (guardian_reaped && latest.leader.pid > 1);
    cleaned &= boundary_reap(peer, &peer_reaped, 2000, NULL);
    if (latest.leader.pid > 1) cleaned &= boundary_wait_absent(&latest.leader, 2000);
    if (latest.member.pid > 1) cleaned &= boundary_wait_absent(&latest.member, 2000);
    if (latest.descendant.pid > 1) cleaned &= boundary_wait_absent(&latest.descendant, 2000);
    for (unsigned i = 0; i < 6; i++) for (unsigned j = 0; j < 2; j++) boundary_close(&pairs[i][j]);
    alarm(0); if (!cleaned) okay = 0;
    printf("{\"ok\":%s,\"fixtureOnly\":true,\"ready\":false,\"protected\":false,\"activatesSystem\":false,"
        "\"usesProductionGuardian\":true,\"usesProductionFamily\":true,\"schedulingHook\":true,"
        "\"nativeInventorySnapshots\":true,\"inertNetworkAuthority\":true,\"rootRealmGidCensus\":false,"
        "\"unregisteredDescendantSurvivedFamilyStop\":%s,\"scopeRefusalsWhileDescendantLive\":%u,"
        "\"custodyHeldWhileDescendantLive\":%s,\"releasedWhileDescendantLive\":%s,"
        "\"releasedAfterOwnedDescendantExit\":%s,\"custodyEofAfterRelease\":%s,"
        "\"sameIdentitySiblingUnaffected\":%s,\"ownedCleanupComplete\":%s,\"forcedGuardianCleanup\":%s}\n",
        okay ? "true" : "false", survivor_verified ? "true" : "false", refused, custody_held ? "true" : "false",
        boundary_released_while_live ? "true" : "false",
        final_release ? "true" : "false", final_eof ? "true" : "false", sibling_untouched ? "true" : "false",
        cleaned ? "true" : "false", forced ? "true" : "false");
    return okay ? 0 : 1;
}
