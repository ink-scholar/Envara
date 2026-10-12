#include "launch-guardian.h"
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
#include <sys/proc_info.h>
#include <sys/proc.h>
#include <net/if_utun.h>
#include <libproc.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>

static volatile sig_atomic_t requested_signal;
static void revoke_signal(int number) { requested_signal = number; }
static int reject(int error) { errno = error; return -1; }
static int64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
/* Darwin CLOCK_MONOTONIC keeps counting while the Mac sleeps. A heartbeat gap
 * must count only awake time, or every lid close would revoke on wake. */
static int64_t awake_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_UPTIME_RAW, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static int same_identity(const struct envara_identity *a, const struct envara_identity *b) {
    return a->pid == b->pid && a->parent_pid == b->parent_pid &&
        a->uid == b->uid && a->ruid == b->ruid && a->saved_uid == b->saved_uid &&
        a->gid == b->gid && a->rgid == b->rgid && a->saved_gid == b->saved_gid &&
        a->birth_seconds == b->birth_seconds && a->birth_microseconds == b->birth_microseconds;
}
static int unchanged(const struct envara_identity *expected) {
    struct envara_identity before, after;
    return expected->pid > 1 && expected->birth_seconds &&
        !envara_identity_read(expected->pid, &before) &&
        !envara_identity_read(expected->pid, &after) &&
        same_identity(expected, &before) && same_identity(&before, &after);
}
static int direct_birth_unchanged(const struct envara_identity *expected) {
    struct envara_identity before, after;
    return !envara_identity_read(expected->pid, &before) &&
        !envara_identity_read(expected->pid, &after) &&
        before.pid == expected->pid && after.pid == expected->pid &&
        before.parent_pid == getpid() && after.parent_pid == getpid() &&
        before.birth_seconds == expected->birth_seconds && before.birth_microseconds == expected->birth_microseconds &&
        after.birth_seconds == expected->birth_seconds && after.birth_microseconds == expected->birth_microseconds;
}
static int live_unchanged(const struct envara_identity *expected) {
    struct proc_bsdinfo info;
    return unchanged(expected) &&
        proc_pidinfo(expected->pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) == sizeof(info) &&
        info.pbi_status != SZOMB && info.pbi_pid == (uint32_t)expected->pid &&
        info.pbi_ppid == (uint32_t)expected->parent_pid &&
        (uint64_t)info.pbi_start_tvsec == expected->birth_seconds &&
        (uint64_t)info.pbi_start_tvusec == expected->birth_microseconds && unchanged(expected);
}
static int peers_live(const struct envara_launch_guard_request *request) {
    for (size_t i = 0; i < request->dependency_count; i++)
        if (!live_unchanged(&request->dependencies[i])) return 0;
    return 1;
}
static int stopped_native(const struct envara_child *child) {
    struct proc_bsdinfo before, after;
    char self[PROC_PIDPATHINFO_MAXSIZE], target[PROC_PIDPATHINFO_MAXSIZE];
    const struct envara_identity *identity = &child->identity;
    return identity->parent_pid == getpid() && unchanged(identity) &&
        proc_pidinfo(identity->pid, PROC_PIDTBSDINFO, 0, &before, sizeof(before)) == sizeof(before) &&
        before.pbi_status == SSTOP && before.pbi_ppid == (uint32_t)getpid() &&
        (uint64_t)before.pbi_start_tvsec == identity->birth_seconds &&
        (uint64_t)before.pbi_start_tvusec == identity->birth_microseconds &&
        proc_pidpath(getpid(), self, sizeof(self)) > 0 &&
        proc_pidpath(identity->pid, target, sizeof(target)) > 0 && !strcmp(self, target) &&
        proc_pidinfo(identity->pid, PROC_PIDTBSDINFO, 0, &after, sizeof(after)) == sizeof(after) &&
        after.pbi_status == SSTOP && after.pbi_ppid == before.pbi_ppid &&
        after.pbi_start_tvsec == before.pbi_start_tvsec && after.pbi_start_tvusec == before.pbi_start_tvusec &&
        unchanged(identity);
}
static int anonymous_reader(int fd, struct stat *identity) {
    int flags = fcntl(fd, F_GETFL), descriptor_flags = fcntl(fd, F_GETFD);
    return fd >= 3 && flags >= 0 && (flags & O_ACCMODE) == O_RDONLY &&
        descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) &&
        !fstat(fd, identity) && S_ISFIFO(identity->st_mode) &&
        identity->st_uid == geteuid() && identity->st_nlink == 0;
}
static int custody_fd(const struct envara_launch_guard_request *request) {
    struct stat before, after;
    int type = 0; socklen_t length = sizeof(type);
    if (request->retained_fd < 3 || fstat(request->retained_fd, &before) ||
        !S_ISSOCK(before.st_mode) ||
        getsockopt(request->retained_fd, SOL_SOCKET, SO_TYPE, &type, &length) ||
        length != sizeof(type)) return -1;
    if (request->fixture_only) {
        struct sockaddr_storage address; socklen_t address_length = sizeof(address);
        memset(&address, 0, sizeof(address));
        if (getsockname(request->retained_fd, (struct sockaddr *)&address, &address_length)) return -1;
        if (address.ss_family != AF_UNIX || type != SOCK_STREAM) return reject(EACCES);
    } else {
        /* Darwin kernel-control sockets implement peeraddr, not sockaddr:
         * getsockname returns EOPNOTSUPP even for a connected owned utun.
         * Bind its actual control ID/unit and interface through peeraddr. */
        struct ctl_info info; memset(&info, 0, sizeof(info));
        strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
        struct sockaddr_ctl peer; socklen_t peer_length = sizeof(peer);
        char name[16]; socklen_t name_length = sizeof(name); memset(name, 0, sizeof(name));
        if (type != SOCK_DGRAM ||
            ioctl(request->retained_fd, CTLIOCGINFO, &info) ||
            getpeername(request->retained_fd, (struct sockaddr *)&peer, &peer_length) ||
            peer_length != sizeof(peer) || peer.sc_family != AF_SYSTEM ||
            peer.ss_sysaddr != AF_SYS_CONTROL || peer.sc_id != info.ctl_id || !peer.sc_unit ||
            getsockopt(request->retained_fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &name_length) ||
            !memchr(name, 0, sizeof(name)) || !memchr(request->tunnel_name, 0, sizeof(request->tunnel_name)) ||
            strncmp(name, "utun", 4) || strcmp(name, request->tunnel_name)) return reject(EACCES);
    }
    int duplicate = fcntl(request->retained_fd, F_DUPFD_CLOEXEC, 3);
    if (duplicate < 0) return -1;
    if (fstat(duplicate, &after) || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_mode != after.st_mode) { close(duplicate); return reject(ESTALE); }
    return duplicate;
}
static int child_reap(const struct envara_launch_guard_request *request,
                      struct envara_launch_guard_report *report) {
    if (report->child_reaped) return 0;
    int status; pid_t result = waitpid(request->child.identity.pid, &status, WNOHANG);
    if (result == request->child.identity.pid) { report->child_reaped = 1; return 1; }
    if (result == 0) return 0;
    return -1; /* ECHILD never means ownership or absence is verified. */
}
static void observe(const struct envara_launch_guard_authority *authority,
                    enum envara_launch_guard_event event, const struct envara_launch_guard_report *report) {
    if (authority->observe) authority->observe(event, report, authority->context);
}
static void guardian_revoke(const struct envara_launch_guard_request *request,
                   const struct envara_launch_guard_authority *authority,
                   struct envara_launch_guard_report *report, enum envara_launch_guard_reason reason, int dependency) {
    if (report->reason != ENVARA_GUARD_NONE) return;
    report->reason = reason; report->dependency_index = dependency;
    report->persistent_deny_observed = authority->verify_persistent_deny(authority->context) == 1;
    if (!report->persistent_deny_observed) report->reason = ENVARA_GUARD_DENY_UNCONFIRMED;
    /* The guardian is the original parent and has not reaped this child.
     * Its PID cannot be recycled between identity check and kill. Do not
     * target PGIDs, descendants, delegated helpers, or a foreign child. */
    int reaped = child_reap(request, report);
    if (reaped == 0 && direct_birth_unchanged(&request->child.identity) &&
        request->child.identity.parent_pid == getpid()) {
        if (!kill(request->child.identity.pid, SIGKILL)) report->child_signal_sent = 1;
    }
    observe(authority, ENVARA_GUARD_REVOKED, report);
}
int envara_launch_guard_isolate_descriptors(const int *held, size_t count) {
    return envara_close_inherited_descriptors(held, count);
}
int envara_launch_guard_run(const struct envara_launch_guard_request *request,
                           const struct envara_launch_guard_authority *authority,
                           struct envara_launch_guard_report *out) {
    if (!request || !authority || !out || !authority->verify_persistent_deny ||
        !authority->verify_scope_quiescent || (request->fixture_only != 0 && request->fixture_only != 1) ||
        request->dependency_count < 1 || request->dependency_count > ENVARA_LAUNCH_GUARDIAN_MAX_PEERS ||
        !request->lease_milliseconds || request->lease_milliseconds > ENVARA_LAUNCH_GUARDIAN_MAX_LEASE_MS ||
        (request->heartbeat_timeout_milliseconds && (request->heartbeat_timeout_milliseconds < ENVARA_LAUNCH_GUARDIAN_MIN_HEARTBEAT_MS ||
            request->heartbeat_timeout_milliseconds > ENVARA_LAUNCH_GUARDIAN_MAX_HEARTBEAT_MS)) ||
        (!request->fixture_only && !request->heartbeat_timeout_milliseconds) ||
        request->child.identity.parent_pid != getpid() || request->child.identity.pid <= 1 ||
        request->lease_fd == request->recovery_fd || request->lease_fd == request->retained_fd ||
        request->recovery_fd == request->retained_fd) return reject(EINVAL);
    if (request->fixture_only ? (getuid() == 0 || getuid() != geteuid() || getgid() != getegid() ||
        !envara_identity_matches(&request->child.identity, getuid(), getgid())) :
        (getuid() != 0 || geteuid() != 0 || request->child.identity.uid == 0 ||
         request->child.identity.gid < ENVARA_REALM_GID_MIN || request->child.identity.gid > ENVARA_REALM_GID_MAX)) return reject(EACCES);
    if (!request->fixture_only) {
        uid_t console = 0;
        if (request->dependency_count != ENVARA_LAUNCH_GUARDIAN_MAX_PEERS || envara_console_uid(&console) || !envara_identity_matches(&request->child.identity, console,
            request->child.identity.gid)) return reject(EACCES);
    }
    struct stat lease, recovery;
    if (!anonymous_reader(request->lease_fd, &lease) || !anonymous_reader(request->recovery_fd, &recovery) ||
        (lease.st_dev == recovery.st_dev && lease.st_ino == recovery.st_ino) ||
        !unchanged(&request->child.identity)) return reject(EACCES);
    for (size_t i = 0; i < request->dependency_count; i++) {
        const struct envara_identity *peer = &request->dependencies[i];
        if (peer->pid == getpid() || peer->pid == request->child.identity.pid || !unchanged(peer)) return reject(ESTALE);
        for (size_t j = 0; j < i; j++) if (peer->pid == request->dependencies[j].pid) return reject(EINVAL);
    }
    struct envara_launch_guard_report report = {.dependency_index = -1};
    if (child_reap(request, &report) != 0) {
        /* The original parent may have consumed the exact child's wait status.
         * Preserve that positive evidence for its recovery keeper. ECHILD and
         * other unknown wait failures never set child_reaped. No FD was taken. */
        *out = report; return reject(EACCES);
    }
    if (authority->verify_persistent_deny(authority->context) != 1) return reject(EACCES);
    int custody = custody_fd(request); if (custody < 0) return -1;
    int queue = kqueue(); if (queue < 0) { int error = errno; close(custody); return reject(error); }
    if (fcntl(queue, F_SETFD, FD_CLOEXEC)) { int error = errno; close(queue); close(custody); return reject(error); }
    struct kevent registrations[5]; size_t length = 0;
    for (size_t i = 0; i < request->dependency_count; i++) {
        EV_SET(&registrations[length++], request->dependencies[i].pid, EVFILT_PROC,
               EV_ADD | EV_ENABLE | EV_CLEAR, NOTE_EXIT | NOTE_EXEC, 0, (void *)(uintptr_t)(i + 1));
    }
    EV_SET(&registrations[length++], request->lease_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
    EV_SET(&registrations[length++], request->recovery_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
    struct timespec zero = {0, 0};
    if (kevent(queue, registrations, (int)length, NULL, 0, &zero)) {
        int error = errno; close(queue); close(custody); return reject(error);
    }
    for (size_t i = 0; i < request->dependency_count; i++) if (!unchanged(&request->dependencies[i])) {
        close(queue); close(custody); return reject(ESTALE);
    }
    struct sigaction action = {0}, previous[3]; const int signals[] = {SIGTERM, SIGINT, SIGHUP};
    action.sa_handler = revoke_signal; sigemptyset(&action.sa_mask); requested_signal = 0;
    for (int i = 0; i < 3; i++) if (sigaction(signals[i], &action, &previous[i])) {
        int error = errno; while (i--) sigaction(signals[i], &previous[i], NULL);
        close(queue); close(custody); return reject(error);
    }
    int64_t started = monotonic_ms();
    if (started < 0) { for (int i = 0; i < 3; i++) sigaction(signals[i], &previous[i], NULL);
        close(queue); close(custody); return -1; }
    const int64_t deadline = started + request->lease_milliseconds;
    report.owns_retained_fd = 1; report.persistent_deny_observed = 1;
    observe(authority, ENVARA_GUARD_ARMED, &report);
    int lease_open = 1, recovery_open = 1, heartbeat_armed = 0;
    int64_t execution_deadline = -1, last_heartbeat = -1;
    for (;;) {
        if (requested_signal) guardian_revoke(request, authority, &report, ENVARA_GUARD_SIGNAL, -1);
        int64_t now = monotonic_ms();
        if (now < 0) guardian_revoke(request, authority, &report, ENVARA_GUARD_INSPECTION_UNAVAILABLE, -1);
        else if (now >= deadline) guardian_revoke(request, authority, &report, ENVARA_GUARD_LEASE_EXPIRED, -1);
        if (heartbeat_armed) {
            int64_t awake = awake_ms();
            if (awake < 0) guardian_revoke(request, authority, &report, ENVARA_GUARD_INSPECTION_UNAVAILABLE, -1);
            else if (awake - last_heartbeat >= (int64_t)request->heartbeat_timeout_milliseconds)
                guardian_revoke(request, authority, &report, ENVARA_GUARD_HEARTBEAT_LOST, -1);
        }
        if (!report.child_reaped) {
            int reaped = child_reap(request, &report);
            if (reaped == 1) { observe(authority, ENVARA_GUARD_CHILD_REAPED, &report);
                guardian_revoke(request, authority, &report, ENVARA_GUARD_CHILD_EXITED, -1); }
            else if (reaped < 0) guardian_revoke(request, authority, &report, ENVARA_GUARD_INSPECTION_UNAVAILABLE, -1);
            else if (!unchanged(&request->child.identity)) guardian_revoke(request, authority, &report, ENVARA_GUARD_DEPENDENCY_CHANGED, -1);
        }
        if (report.reason == ENVARA_GUARD_NONE) for (size_t i = 0; i < request->dependency_count; i++) {
            if (!unchanged(&request->dependencies[i])) { guardian_revoke(request, authority, &report, ENVARA_GUARD_DEPENDENCY_CHANGED, (int)i); break; }
        }
        if (report.reason == ENVARA_GUARD_NONE && report.resume_sent) {
            if (!peers_live(request) || authority->verify_persistent_deny(authority->context) != 1)
                guardian_revoke(request, authority, &report, ENVARA_GUARD_DENY_UNCONFIRMED, -1);
            else if (!report.resumed) {
                int executed = request->verify_executed(&request->child, request->resume_context);
                int verified = executed >= 0 && executed <= 1 && live_unchanged(&request->child.identity) &&
                    peers_live(request) && authority->verify_persistent_deny(authority->context) == 1;
                int64_t observed = monotonic_ms();
                if (!verified || observed < 0 || !live_unchanged(&request->child.identity) ||
                    !peers_live(request))
                    guardian_revoke(request, authority, &report, ENVARA_GUARD_EXECUTION_UNVERIFIED, -1);
                else if (requested_signal || observed >= deadline)
                    guardian_revoke(request, authority, &report, requested_signal ? ENVARA_GUARD_SIGNAL : ENVARA_GUARD_LEASE_EXPIRED, -1);
                else if (observed >= execution_deadline)
                    guardian_revoke(request, authority, &report, ENVARA_GUARD_EXECUTION_UNVERIFIED, -1);
                else if (executed == 1) {
                    report.resumed = 1; observe(authority, ENVARA_GUARD_RESUMED, &report);
                }
            }
        }
        struct kevent events[5]; struct timespec interval = {0, 50000000};
        int count = kevent(queue, NULL, 0, events, 5, &interval);
        if (count < 0) { if (errno != EINTR) guardian_revoke(request, authority, &report, ENVARA_GUARD_INSPECTION_UNAVAILABLE, -1); continue; }
        for (int i = 0; i < count; i++) {
            struct kevent *event = &events[i];
            if (event->flags & EV_ERROR) { guardian_revoke(request, authority, &report, ENVARA_GUARD_INSPECTION_UNAVAILABLE, -1); continue; }
            if (event->filter == EVFILT_PROC) {
                guardian_revoke(request, authority, &report, event->fflags & NOTE_EXIT ? ENVARA_GUARD_DEPENDENCY_EXITED : ENVARA_GUARD_DEPENDENCY_CHANGED,
                       (int)(uintptr_t)event->udata - 1); continue;
            }
            int fd = (int)event->ident;
            if ((fd == request->lease_fd && !lease_open) || (fd == request->recovery_fd && !recovery_open)) continue;
            char bytes[32]; ssize_t amount = read(fd, bytes, sizeof(bytes));
            if (amount < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            if (amount <= 0) {
                if (fd == request->lease_fd) lease_open = 0; else recovery_open = 0;
                struct kevent remove; EV_SET(&remove, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
                (void)kevent(queue, &remove, 1, NULL, 0, &zero);
                guardian_revoke(request, authority, &report, ENVARA_GUARD_LEASE_CLOSED, -1); continue;
            }
            for (ssize_t j = 0; j < amount; j++) {
                if (fd == request->lease_fd) {
                    if (bytes[j] == 'B') {
                        if (report.reason != ENVARA_GUARD_NONE || report.resume_sent ||
                            !request->verify_resume || !request->verify_executed ||
                            !stopped_native(&request->child) || !peers_live(request) ||
                            authority->verify_persistent_deny(authority->context) != 1 ||
                            request->verify_resume(&request->child, request->resume_context) != 1) {
                            guardian_revoke(request, authority, &report, ENVARA_GUARD_RESUME_REFUSED, -1); continue;
                        }
                        /* Callbacks do not grant PID custody. Re-read exact
                         * parent/birth/native SSTOP and every live dependency
                         * after the fixed authority's potentially slow work. */
                        if (!stopped_native(&request->child) || !peers_live(request) ||
                            authority->verify_persistent_deny(authority->context) != 1) {
                            guardian_revoke(request, authority, &report, ENVARA_GUARD_RESUME_REFUSED, -1); continue;
                        }
                        int64_t resume_now = monotonic_ms();
                        if (requested_signal || resume_now < 0 || resume_now >= deadline ||
                            !stopped_native(&request->child) || !peers_live(request) ||
                            kill(request->child.identity.pid, SIGCONT)) {
                            guardian_revoke(request, authority, &report, ENVARA_GUARD_RESUME_REFUSED, -1); continue;
                        }
                        report.resume_sent = 1;
                        int64_t execution_started = monotonic_ms();
                        if (requested_signal || execution_started < 0 || execution_started >= deadline) {
                            guardian_revoke(request, authority, &report, requested_signal ? ENVARA_GUARD_SIGNAL :
                                execution_started < 0 ? ENVARA_GUARD_INSPECTION_UNAVAILABLE : ENVARA_GUARD_LEASE_EXPIRED, -1);
                            continue;
                        }
                        execution_deadline = execution_started + 5000;
                    } else if (bytes[j] == 'K') {
                        /* A heartbeat proves only that the fixed controller is
                         * still scheduling work. It never extends the lease. */
                        int64_t awake = awake_ms();
                        if (awake < 0) guardian_revoke(request, authority, &report, ENVARA_GUARD_INSPECTION_UNAVAILABLE, -1);
                        else if (request->heartbeat_timeout_milliseconds) { last_heartbeat = awake; heartbeat_armed = 1; }
                    } else guardian_revoke(request, authority, &report,
                        bytes[j] == 'S' ? ENVARA_GUARD_LEASE_CLOSED : ENVARA_GUARD_INVALID_COMMAND, -1);
                } else if (bytes[j] == 'R') {
                    /* 'R' carries no authority. Only the fixed native checks
                     * can confirm the complete scope plus denial/ownership. */
                    int reaped = child_reap(request, &report);
                    if (reaped == 1) observe(authority, ENVARA_GUARD_CHILD_REAPED, &report);
                    report.persistent_deny_observed = authority->verify_persistent_deny(authority->context) == 1;
                    report.scope_quiescent_observed = report.child_reaped &&
                        authority->verify_scope_quiescent(authority->context) == 1;
                    if (!report.persistent_deny_observed || !report.scope_quiescent_observed) {
                        observe(authority, ENVARA_GUARD_RELEASE_REFUSED, &report); continue;
                    }
                    close(custody); report.owns_retained_fd = 0;
                    observe(authority, ENVARA_GUARD_RELEASED, &report);
                    for (int k = 0; k < 3; k++) sigaction(signals[k], &previous[k], NULL);
                    close(queue); *out = report; return 0;
                } else guardian_revoke(request, authority, &report, ENVARA_GUARD_INVALID_COMMAND, -1);
            }
        }
    }
}
