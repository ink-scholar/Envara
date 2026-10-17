#include "app-supervisor.h"
#include "app-family.h"
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <mach/mach_time.h>
#include <libproc.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>

struct keeper {
    const struct envara_app_supervisor_provider *provider;
    struct envara_launch_guard_request guard;
    struct envara_launch_guard_authority authority;
    struct envara_app_ticket ticket;
    struct envara_app_supervisor_report *report;
    struct envara_gui_lifecycle *child;
    int output, prepared, output_failed, stopped_before_exec, validation_scope_open;
    envara_app_family *family;
    struct envara_identity own;
};
/* Installed before any descriptor transfer/claim/fork and retained across the
 * guardian's handler restoration. Catchable signals cannot drop socket custody
 * in the pre-arm or post-arm-failure windows. SIGKILL stays an unverified gate. */
static volatile sig_atomic_t quarantine_signal;
static void quarantined(int number) { quarantine_signal = number; }
static int reject(int error) { errno = error; return -1; }
static int uuid(const char *s) {
    if (!s || !memchr(s, 0, 37) || strlen(s) != 36 || s[14] != '4' || !strchr("89ab", s[19])) return 0;
    for (int i = 0; i < 36; i++) if (i == 8 || i == 13 || i == 18 || i == 23) { if (s[i] != '-') return 0; }
        else if (!strchr("0123456789abcdef", s[i])) return 0; return 1;
}
static int entry(void) {
    char executable[PROC_PIDPATHINFO_MAXSIZE], path[PATH_MAX]; struct stat info;
    if (getuid() || geteuid() || proc_pidpath(getpid(), executable, sizeof(executable)) <= 0 ||
        strcmp(executable, ENVARA_GUI_NATIVE_PATH)) return reject(EACCES);
    strcpy(path, executable);
    for (;;) {
        if (lstat(path, &info) || info.st_uid || (info.st_mode & (S_ISUID | S_ISGID | 0022)) ||
            (strcmp(path, executable) ? !S_ISDIR(info.st_mode) : !S_ISREG(info.st_mode) || info.st_nlink != 1 || !(info.st_mode & 0111)) ||
            envara_gui_acl_free(path)) return reject(EACCES);
        char *slash = strrchr(path, '/'); if (!slash || slash == path) break; *slash = 0;
    }
    return envara_gui_acl_free("/");
}
static int reader(int fd, struct stat *info) {
    int flags = fcntl(fd, F_GETFL), descriptor = fcntl(fd, F_GETFD);
    return fd >= 3 && flags >= 0 && (flags & O_ACCMODE) == O_RDONLY &&
        descriptor >= 0 && (descriptor & FD_CLOEXEC) && !fstat(fd, info) &&
        S_ISFIFO(info->st_mode) && info->st_uid == geteuid() && info->st_nlink == 0;
}
static int guard_preflight(struct keeper *k, int fixture) {
    struct envara_launch_guard_request *g = &k->guard; struct stat a, b, socket;
    if (g->fixture_only != fixture || g->dependency_count < 1 || g->dependency_count > 3 ||
        (!fixture && g->dependency_count != 3) || !g->lease_milliseconds || g->lease_milliseconds > ENVARA_LAUNCH_GUARDIAN_MAX_LEASE_MS ||
        (!fixture && !g->heartbeat_timeout_milliseconds) ||
        !k->authority.verify_persistent_deny || !k->authority.verify_scope_quiescent || !k->authority.revoke_owned_network ||
        g->lease_fd == g->recovery_fd || g->lease_fd == g->retained_fd || g->recovery_fd == g->retained_fd ||
        !reader(g->lease_fd, &a) || !reader(g->recovery_fd, &b) || (a.st_dev == b.st_dev && a.st_ino == b.st_ino) ||
        g->retained_fd < 3 || fcntl(g->retained_fd, F_GETFD) < 0 || fstat(g->retained_fd, &socket) || !S_ISSOCK(socket.st_mode)) return reject(EACCES);
    for (size_t i = 0; i < g->dependency_count; i++) {
        if (g->dependencies[i].pid == getpid() || !envara_same_process(&g->dependencies[i])) return reject(ESTALE);
        for (size_t j = 0; j < i; j++) if (g->dependencies[i].pid == g->dependencies[j].pid) return reject(EINVAL);
    }
    if (k->authority.verify_persistent_deny(k->authority.context) != 1) return reject(EAGAIN);
    return 0; /* Guardian independently validates original utun identity at arm. */
}
static int inspect(const char *environment, const char *run, const struct envara_app_registration *app,
                   struct envara_gui_request *request, char hash[65], void *context) {
    struct keeper *k = context;
    return k->provider->ticket.inspect(environment, run, app, request, hash, k->provider->ticket.context);
}
static int verify(const struct envara_app_registration *app, const struct envara_gui_request *request,
                  const char *run, const char *hash, void *context) {
    struct keeper *k = context;
    if (quarantine_signal) return reject(ECANCELED);
    if (k->provider->ticket.verify(app, request, run, hash, k->provider->ticket.context)) return -1;
    if (k->prepared) {
        if (memcmp(&k->ticket.app, app, sizeof(*app)) || memcmp(&k->ticket.request, request, sizeof(*request)) ||
            strcmp(k->ticket.run_id, run) || strcmp(k->ticket.environment_lease_sha256, hash)) return reject(ESTALE);
        return guard_preflight(k, app->fixture_only);
    }
    memset(&k->guard, 0, sizeof(k->guard)); k->guard.lease_fd = k->guard.recovery_fd = k->guard.retained_fd = -1;
    if (k->provider->prepare_guard(app, request, run, hash, &k->guard, &k->authority, k->provider->context)) return -1;
    /* Mark transferred custody even when subsequent read-only checks refuse. */
    k->prepared = 1; k->ticket.app = *app; k->ticket.request = *request;
    strcpy(k->ticket.run_id, run); strcpy(k->ticket.environment_lease_sha256, hash);
    return guard_preflight(k, app->fixture_only);
}
static int deny(void *context) {
    struct keeper *k = context;
    return !k->provider->ticket.verify(&k->ticket.app, &k->ticket.request, k->ticket.run_id,
        k->ticket.environment_lease_sha256, k->provider->ticket.context) &&
        k->authority.verify_persistent_deny(k->authority.context) == 1;
}
static int scope(void *context) {
    struct keeper *k = context;
    return k->authority.verify_scope_quiescent(k->authority.context) == 1;
}
static int revoke_network(void *context) {
    struct keeper *k = context;
    return k->authority.revoke_owned_network && k->authority.revoke_owned_network(k->authority.context) == 1;
}
static int emit(struct keeper *k, const char *event, const struct envara_launch_guard_report *report) {
    const struct envara_app_ticket *t = &k->ticket;
    int front_profile = !t->app.fixture_only && k->provider->execution_profile == ENVARA_APP_EXECUTION_NOTION_FRONT_ONLY;
    int front_executed = report->resumed && front_profile;
    const char *profile = t->app.fixture_only ? "fixture" : front_profile ? "seatbelt-front-only" : "cold";
    char bytes[1024]; int length = snprintf(bytes, sizeof(bytes),
        "{\"schema\":\"%s\",\"event\":\"%s\",\"ticketId\":\"%s\",\"registrationId\":\"%s\",\"versionId\":\"%s\","
        "\"environmentId\":\"%s\",\"runId\":\"%s\",\"pid\":%d,\"birth\":\"%llu:%06llu\",\"keeperPID\":%d,"
        "\"persistentDenyObserved\":%s,\"stoppedBeforeExec\":%s,\"childReaped\":%s,\"scopeQuiescentObserved\":%s,"
        "\"resumeSent\":%s,\"resumed\":%s,\"cancelSent\":%s,"
        "\"executedIdentityVerified\":%s,\"seatbeltAppliedByFixedExec\":%s,\"frontAdmissionVerified\":%s,\"profile\":\"%s\","
        "\"ready\":false,\"protected\":false}\n",
        ENVARA_APP_KEEPER_PROTOCOL, event, t->ticket_id, t->app.registration_id, t->app.version_id,
        t->environment_id, t->run_id, k->child->child.identity.pid,
        (unsigned long long)k->child->child.identity.birth_seconds,
        (unsigned long long)k->child->child.identity.birth_microseconds, getpid(),
        report->persistent_deny_observed ? "true" : "false", k->stopped_before_exec && !report->resume_sent ? "true" : "false", report->child_reaped ? "true" : "false",
        report->scope_quiescent_observed ? "true" : "false", report->resume_sent ? "true" : "false",
        report->resumed ? "true" : "false", report->child_signal_sent ? "true" : "false",
        report->resumed ? "true" : "false", front_executed ? "true" : "false",
        front_executed ? "true" : "false", profile);
    if (length <= 0 || length >= (int)sizeof(bytes)) return reject(EOVERFLOW);
    /* One atomic bounded frame. A stuck/detached reader cannot block denial. */
    ssize_t count; do { count = write(k->output, bytes, (size_t)length); } while (count < 0 && errno == EINTR);
    return count == length ? 0 : reject(count < 0 ? errno : EIO);
}
static int emit_cleanup_pending(struct keeper *k, const struct envara_launch_guard_report *report) {
    const struct envara_app_ticket *t = &k->ticket; struct envara_identity own;
    if (envara_identity_read(getpid(), &own)) return reject(ESTALE);
    const char *profile = t->app.fixture_only ? "fixture" :
        k->provider->execution_profile == ENVARA_APP_EXECUTION_NOTION_FRONT_ONLY ? "seatbelt-front-only" : "cold";
    int stopped = report->child_reaped && scope(k);
    const char *family_failure = envara_app_family_failure_name(report->family_failure.reason);
    if (!family_failure || report->family_failure.os_error < 0 || report->family_failure.os_error > 1024 ||
        (report->family_failure.reason == ENVARA_APP_FAMILY_FAILURE_NONE ?
            report->family_failure.os_error != 0 || report->family_failure.mach_error != 0 : report->family_failure.os_error == 0))
        return reject(EINVAL);
    char bytes[1536]; int length = snprintf(bytes, sizeof(bytes),
        "{\"schema\":\"%s\",\"event\":\"cleanup-pending\",\"ticketId\":\"%s\",\"registrationId\":\"%s\",\"versionId\":\"%s\","
        "\"environmentId\":\"%s\",\"runId\":\"%s\",\"pid\":%d,\"birth\":\"%llu:%06llu\",\"keeperPID\":%d,"
        "\"keeperBirth\":\"%llu:%06llu\",\"profile\":\"%s\",\"cleanupAttempt\":%u,\"launchAuthorityBurned\":true,\"custodyHeld\":true,"
        "\"denyVerified\":%s,\"frontClosedVerified\":%s,\"familyStoppedVerified\":%s,\"familyFailureReason\":\"%s\",\"familyFailureErrno\":%d,\"familyFailureMach\":%d,\"ready\":false,\"protected\":false}\n",
        ENVARA_APP_KEEPER_PROTOCOL, t->ticket_id, t->app.registration_id, t->app.version_id,
        t->environment_id, t->run_id, k->child->child.identity.pid,
        (unsigned long long)k->child->child.identity.birth_seconds, (unsigned long long)k->child->child.identity.birth_microseconds,
        getpid(), (unsigned long long)own.birth_seconds, (unsigned long long)own.birth_microseconds, profile, report->cleanup_attempt,
        report->network_revoked && report->persistent_deny_observed ? "true" : "false", report->network_revoked ? "true" : "false", stopped ? "true" : "false", family_failure,
        report->family_failure.os_error, report->family_failure.mach_error);
    if (length <= 0 || length >= (int)sizeof(bytes)) return reject(EOVERFLOW);
    ssize_t count; do { count = write(k->output, bytes, (size_t)length); } while (count < 0 && errno == EINTR);
    return count == length ? 0 : reject(count < 0 ? errno : EIO);
}
static int stopped_native_child(const struct envara_child *child) {
    struct proc_bsdinfo info; struct envara_identity before, after;
    char self[PROC_PIDPATHINFO_MAXSIZE], target[PROC_PIDPATHINFO_MAXSIZE];
    return !envara_identity_read(child->identity.pid, &before) &&
        proc_pidinfo(child->identity.pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) == sizeof(info) &&
        info.pbi_status == SSTOP && info.pbi_ppid == (uint32_t)getpid() &&
        (uint64_t)info.pbi_start_tvsec == child->identity.birth_seconds &&
        (uint64_t)info.pbi_start_tvusec == child->identity.birth_microseconds &&
        proc_pidpath(getpid(), self, sizeof(self)) > 0 && proc_pidpath(child->identity.pid, target, sizeof(target)) > 0 &&
        !strcmp(self, target) && !envara_identity_read(child->identity.pid, &after) &&
        before.pid == after.pid && before.parent_pid == after.parent_pid && before.uid == after.uid &&
        before.ruid == after.ruid && before.saved_uid == after.saved_uid && before.gid == after.gid &&
        before.rgid == after.rgid && before.saved_gid == after.saved_gid &&
        before.birth_seconds == after.birth_seconds && before.birth_microseconds == after.birth_microseconds &&
        envara_same_process(&child->identity);
}
static void observe(enum envara_launch_guard_event event, const struct envara_launch_guard_report *report, void *context) {
    struct keeper *k = context; k->report->guardian = *report;
    if (report->child_reaped) { k->child->leader_reaped = 1; k->child->phase = ENVARA_GUI_EXITED; }
    if (event == ENVARA_GUARD_ARMED) {
        k->report->armed = 1;
        k->stopped_before_exec = stopped_native_child(&k->child->child);
        if (!k->stopped_before_exec || emit(k, "stopped", report)) { k->output_failed = 1; raise(SIGTERM); }
        if (quarantine_signal) raise(SIGTERM);
    } else if (event == ENVARA_GUARD_RESUMED) {
        k->report->resumed = report->resumed;
        k->stopped_before_exec = 0; k->child->phase = ENVARA_GUI_EXECUTING;
        if (!report->resumed || emit(k, "resumed", report)) { k->output_failed = 1; raise(SIGTERM); }
    } else if (event == ENVARA_GUARD_REVOKED) {
        /* Revocation is not proof that the staged child stayed stopped:
         * it may already have executed or become uninspectable. */
        k->stopped_before_exec = 0;
        if (report->child_signal_sent && !report->child_reaped) k->child->phase = ENVARA_GUI_CANCELLED;
        if (emit(k, "stopping", report)) k->output_failed = 1;
    } else if (event == ENVARA_GUARD_RELEASED) {
        k->report->released = 1;
        if (emit(k, "released", report)) k->output_failed = 1;
    } else if (event == ENVARA_GUARD_CLEANUP_PENDING) {
        k->stopped_before_exec = 0;
        if (emit_cleanup_pending(k, report)) k->output_failed = 1;
    }
    if (k->authority.observe) k->authority.observe(event, report, k->authority.context);
}
static void quarantine_refusal_delay(void) {
    struct timespec delay = {0, 50000000};
    while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
}
static int quarantine(struct keeper *k) {
    /* Arming can fail after fork. Never exit and drop the original utun socket
     * merely because a dependent birth/FD changed. Exact child cancel is once;
     * fixed native denial and complete scope proof are still required. */
    k->report->recovery_required = 1;
    /* Only the guardian's positive direct-child wait result permits this
     * already-terminal entry. ECHILD/unavailable identity is never promoted. */
    int prior_reaped = k->report->guardian.child_reaped && k->child->leader_reaped;
    /* Pre-arm refusal obeys the same order as a running guardian. Never cancel
     * the application before fresh DENY plus original frontend shutdown. */
    k->report->guardian.network_revoked = revoke_network(k);
    if (!k->family && !prior_reaped) {
        struct envara_app_family_failure failure;
        k->family = envara_app_family_create_diagnosed(&k->child->child.identity, &failure);
        if (k->report->guardian.family_failure.reason == ENVARA_APP_FAMILY_FAILURE_NONE)
            k->report->guardian.family_failure = failure;
    }
    if (prior_reaped) k->report->guardian.family_stop_confirmed = 1;
    if (k->report->guardian.network_revoked && k->family) {
        int sent = 0;
        k->report->guardian.family_stop_confirmed = envara_app_family_stop(k->family, &sent);
        k->report->guardian.child_signal_sent |= sent;
    }
    for (;;) {
        if (!k->child->leader_reaped) { int status; (void)envara_gui_poll(k->child, &status); }
        struct pollfd item = {k->guard.recovery_fd, POLLIN, 0};
        int result = poll(&item, 1, 50); (void)quarantine_signal;
        if (result <= 0 || !(item.revents & POLLIN)) {
            if (result < 0 || (item.revents & (POLLHUP | POLLERR | POLLNVAL))) { quarantine_refusal_delay(); }
            continue;
        }
        char command[32]; ssize_t amount = read(item.fd, command, sizeof(command));
        if (amount <= 0) { quarantine_refusal_delay(); continue; }
        for (ssize_t i = 0; i < amount; i++) if (command[i] == 'R') {
            if (!k->report->guardian.network_revoked) k->report->guardian.network_revoked = revoke_network(k);
            if (k->report->guardian.network_revoked && k->family && !k->report->guardian.family_stop_confirmed) {
                int sent = 0; k->report->guardian.family_stop_confirmed = envara_app_family_stop(k->family, &sent);
                k->report->guardian.child_signal_sent |= sent;
            }
            if (!k->report->guardian.network_revoked || !k->report->guardian.family_stop_confirmed ||
                (!prior_reaped && (!k->family || !envara_app_family_quiescent(k->family))) ||
                !k->child->leader_reaped || !deny(k) || !scope(k)) continue;
            struct envara_launch_guard_report report = k->report->guardian;
            report.child_reaped = report.persistent_deny_observed = report.scope_quiescent_observed = 1;
            report.owns_retained_fd = 0;
            k->child->scope_quiescent = 1;
            observe(ENVARA_GUARD_RELEASED, &report, k);
            k->report->recovery_required = 0; return 0;
        }
        quarantine_refusal_delay();
    }
}
/* Staging, from claim to the exact stopped child, is one native operation.
 * Custody is not: the guardian holds the child for the run's whole lifetime,
 * and resume re-verifies in its own operation. */
static void staging_scope_end(struct keeper *k) {
    if (k->validation_scope_open) { envara_gui_validation_scope_end(); k->validation_scope_open = 0; }
}
/* Preparation quarantine is deliberately separate from application custody.
 * The only wait/signalling authority lives inside the fixed opaque module. */
int envara_app_preparation_pending_event(const struct envara_app_preparation_report *p,
    const char *command, int denied, int front_closed, int output) {
    if (!p || !command || (strcmp(command,"automatic") && strcmp(command,"S") && strcmp(command,"R")) ||
        !uuid(p->ticket_id) || !uuid(p->registration_id) || !uuid(p->version_id) || !uuid(p->environment_id) ||
        !uuid(p->run_id) || !uuid(p->snapshot.slot_id) || p->snapshot.generation < 1 || p->snapshot.generation > 5 ||
        p->cleanup_attempt > INT_MAX || (!strcmp(command,"automatic") && p->cleanup_attempt) ||
        (!strcmp(command,"S") && !p->cleanup_attempt) || p->keeper.pid != getpid() || !p->keeper.birth_seconds ||
        p->keeper.birth_microseconds >= 1000000) return reject(EINVAL);
    const char *state = p->snapshot.child_state == ENVARA_APP_KEYCHAIN_LAUNCHER_CLEAR ? "launcher-clear" :
        p->snapshot.child_state == ENVARA_APP_KEYCHAIN_UNWAITED ? "unreaped" :
        p->snapshot.child_state == ENVARA_APP_KEYCHAIN_REAPED ? "reaped" :
        p->snapshot.child_state == ENVARA_APP_KEYCHAIN_UNKNOWN ? "unknown" : NULL;
    if (!state) return reject(EINVAL);
    char bytes[1536]; int n = snprintf(bytes,sizeof(bytes),
        "{\"schema\":\"envara.pf-app-preparation/v1\",\"event\":\"cleanup-pending\",\"ticketId\":\"%s\","
        "\"registrationId\":\"%s\",\"versionId\":\"%s\",\"environmentId\":\"%s\",\"runId\":\"%s\","
        "\"keeperPID\":%d,\"keeperBirth\":\"%llu:%06llu\",\"preparationId\":\"%s\",\"generation\":%llu,"
        "\"command\":\"%s\",\"cleanupAttempt\":%u,\"childState\":\"%s\",\"launchAuthorityBurned\":true,"
        "\"custodyHeld\":true,\"denyVerified\":%s,\"frontClosedVerified\":%s,\"ready\":false,\"protected\":false}\n",
        p->ticket_id,p->registration_id,p->version_id,p->environment_id,p->run_id,p->keeper.pid,
        (unsigned long long)p->keeper.birth_seconds,(unsigned long long)p->keeper.birth_microseconds,p->snapshot.slot_id,
        (unsigned long long)p->snapshot.generation,command,p->cleanup_attempt,state,denied?"true":"false",front_closed?"true":"false");
    if (n <= 0 || n >= (int)sizeof(bytes)) return reject(EOVERFLOW);
    ssize_t wrote = write(output,bytes,(size_t)n);
    return wrote == n ? 0 : reject(wrote < 0 ? errno : EIO);
}
static int preparation_snapshot(struct keeper *k) {
    struct envara_app_keychain_snapshot next;
    if (envara_app_keychain_custody_snapshot(k->provider->preparation,&k->ticket.app,&k->ticket.request,k->ticket.run_id,&next)) return -1;
    struct envara_app_preparation_report *p = &k->report->preparation;
    if (p->snapshot.generation && (strcmp(p->snapshot.slot_id,next.slot_id) || p->snapshot.generation != next.generation)) return reject(ESTALE);
    p->snapshot = next; return 0;
}
static int preparation_attempt(struct keeper *k, int *denied, int *closed) {
    /* persistent_deny permits a live mode during staging. Only this fresh
     * revocation establishes DENY and frontend closure before cancellation. */
    *closed = revoke_network(k); *denied = *closed && k->authority.verify_persistent_deny(k->authority.context) == 1;
    if (!*denied) return 0;
    int clear = envara_app_keychain_custody_cleanup(k->provider->preparation,&k->ticket.app,&k->ticket.request,k->ticket.run_id);
    int snapshot_valid = preparation_snapshot(k) == 0;
    return clear == 1 && snapshot_valid && scope(k);
}
static int preparation_quarantine(struct keeper *k, int original_error) {
    staging_scope_end(k); k->report->recovery_required = 1;
    struct envara_app_preparation_report *p = &k->report->preparation;
    strcpy(p->ticket_id,k->ticket.ticket_id); strcpy(p->registration_id,k->ticket.app.registration_id);
    strcpy(p->version_id,k->ticket.app.version_id); strcpy(p->environment_id,k->ticket.environment_id); strcpy(p->run_id,k->ticket.run_id);
    p->keeper = k->own; p->original_error = original_error > 0 && original_error <= 1024 ? original_error : EIO;
    (void)preparation_snapshot(k);
    char bytes[768]; int n = snprintf(bytes,sizeof(bytes),
        "{\"schema\":\"envara.macos-pf-app-transport/v1\",\"event\":\"transport-refused\",\"runId\":\"%s\",\"environmentId\":\"%s\","
        "\"stage\":\"guardian\",\"reason\":\"NATIVE_APP_KEYCHAIN_PREPARATION_REFUSED\",\"error\":%d,\"ready\":false,\"protected\":false}\n",
        p->run_id,p->environment_id,p->original_error);
    if (n > 0 && n < (int)sizeof(bytes) && write(k->output,bytes,(size_t)n) == n) k->report->preparation_refusal_emitted = 1;
    else k->output_failed = 1;
    /* The controller may send S as soon as it reads the original refusal.
     * Do not queue that S behind full preparation/scope inventories here. */
    int closed = revoke_network(k);
    int denied = closed && k->authority.verify_persistent_deny(k->authority.context) == 1;
    (void)preparation_snapshot(k);
    if (k->report->preparation_refusal_emitted && envara_app_preparation_pending_event(p,"automatic",denied,closed,k->output)) k->output_failed = 1;
    for (;;) {
        struct pollfd inputs[2] = {{k->guard.lease_fd,POLLIN,0},{k->guard.recovery_fd,POLLIN,0}};
        int ready = poll(inputs,2,250);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) { if (ready < 0) quarantine_refusal_delay(); continue; }
        for (int i = 0; i < 2; i++) {
            if (!(inputs[i].revents & POLLIN)) continue;
            char command; if (read(inputs[i].fd,&command,1) != 1) continue;
            if (i == 0 && command == 'S') {
                if (p->cleanup_attempt == INT_MAX) { k->output_failed = 1; continue; }
                p->cleanup_attempt++;
                if (preparation_attempt(k,&denied,&closed) && !k->output_failed && k->report->preparation_refusal_emitted) {
                    k->report->preparation_cleanup_confirmed = 1; k->report->recovery_required = 0;
                    return reject(p->original_error); /* Transport must retire its relay before ACK. */
                }
                if (envara_app_preparation_pending_event(p,"S",denied,closed,k->output)) k->output_failed = 1;
            } else if (i == 1 && command == 'R') {
                /* Before an S handoff, R is diagnostic-only, never release. */
                if (envara_app_preparation_pending_event(p,"R",denied,closed,k->output)) k->output_failed = 1;
            }
            /* K/B, malformed input and signals cannot renew spent authority. */
        }
        /* EOF/error cannot spin or surrender original descriptor custody. */
        if ((inputs[0].revents | inputs[1].revents) & (POLLHUP | POLLERR | POLLNVAL)) quarantine_refusal_delay();
    }
}
static int adopt(const struct envara_app_ticket *ticket, struct envara_gui_lifecycle *child, void *context) {
    struct keeper *k = context; staging_scope_end(k);
    k->ticket = *ticket; k->child = child; k->guard.child = child->child;
    struct envara_launch_guard_authority authority = {.verify_persistent_deny = deny, .verify_scope_quiescent = scope,
        .observe = observe, .context = k, .revoke_owned_network = revoke_network};
    if (envara_launch_guard_run(&k->guard, &authority, &k->report->guardian)) {
        if (k->report->guardian.child_reaped) {
            /* Only guardian's exact direct-child waitpid result is evidence;
             * unknown ECHILD is never promoted to this state. */
            child->leader_reaped = 1; child->phase = ENVARA_GUI_EXITED;
            if (child->child.error_fd >= 0) { close(child->child.error_fd); child->child.error_fd = -1; }
        }
        if (quarantine(k)) return -1;
    }
    if (!k->report->released || !k->report->guardian.child_reaped || !k->report->guardian.persistent_deny_observed ||
        !k->report->guardian.scope_quiescent_observed) return reject(EIO);
    child->leader_reaped = 1; child->scope_quiescent = 1; child->phase = ENVARA_GUI_EXITED; child->protected_ready = 0;
    if (child->child.error_fd >= 0) { close(child->child.error_fd); child->child.error_fd = -1; }
    return k->output_failed ? reject(EPIPE) : 0;
}
struct adapter_stage_context { struct keeper *keeper; struct envara_app_registry *registry; };
static int adapter_ticket_live(const struct envara_app_ticket *ticket) {
    mach_timebase_info_data_t base; char boot[64] = {0}; size_t length = sizeof(boot);
    if (mach_timebase_info(&base) != KERN_SUCCESS || !base.denom ||
        sysctlbyname("kern.bootsessionuuid", boot, &length, NULL, 0) || !memchr(boot, 0, sizeof(boot)) ||
        strcmp(boot, ticket->boot_id)) return reject(ESTALE);
    __uint128_t nanos = (__uint128_t)mach_continuous_time() * base.numer / base.denom;
    return nanos <= UINT64_MAX && nanos >= ticket->issued_ns && nanos < ticket->expires_ns ? 0 : reject(ESTALE);
}
static int adapter_fresh(const struct envara_gui_request *request, void *context) {
    struct adapter_stage_context *stage = context; struct keeper *k = stage->keeper;
    struct envara_app_registration app; struct envara_gui_request current; char hash[65];
    memset(&current, 0, sizeof(current)); memset(hash, 0, sizeof(hash));
    if (adapter_ticket_live(&k->ticket) || memcmp(request, &k->ticket.request, sizeof(*request)) ||
        envara_app_registry_resolve(stage->registry, k->ticket.app.registration_id, k->ticket.app.version_id, &app) ||
        memcmp(&app, &k->ticket.app, sizeof(app)) ||
        inspect(k->ticket.environment_id, k->ticket.run_id, &app, &current, hash, k) ||
        memcmp(&current, request, sizeof(current)) || strcmp(hash, k->ticket.environment_lease_sha256) ||
        verify(&app, &current, k->ticket.run_id, hash, k) || adapter_ticket_live(&k->ticket)) return reject(ESTALE);
    return 0;
}
static int direct_child(const struct envara_child *claimed, struct envara_identity *actual) {
    struct envara_identity before, after;
    if (claimed->identity.pid <= 1) return 0;
    if (envara_identity_read(claimed->identity.pid, &before) || envara_identity_read(claimed->identity.pid, &after) ||
        before.parent_pid != after.parent_pid || before.birth_seconds != after.birth_seconds ||
        before.birth_microseconds != after.birth_microseconds) return -1;
    if (before.parent_pid != getpid()) return 0; /* Independently observed foreign PID. */
    if (!claimed->identity.birth_seconds ||
        before.birth_seconds != claimed->identity.birth_seconds || before.birth_microseconds != claimed->identity.birth_microseconds ||
        after.birth_seconds != before.birth_seconds || after.birth_microseconds != before.birth_microseconds ||
        before.uid != after.uid || before.ruid != after.ruid || before.saved_uid != after.saved_uid ||
        before.gid != after.gid || before.rgid != after.rgid || before.saved_gid != after.saved_gid) return -1;
    *actual = after; return 1;
}
static int adapter_stage(struct keeper *k, struct envara_app_ticket_store *store,
                         struct envara_app_registry *registry, const char *id,
                         const struct envara_app_ticket_authority *authority) {
    if (envara_app_ticket_claim(store, registry, id, authority, &k->ticket)) return -1;
    envara_gui_step(ENVARA_GUI_STEP_TICKET_CLAIM);
    struct adapter_stage_context context = {k, registry};
    struct envara_gui_stage_authority fresh = {adapter_fresh, &context};
    if (adapter_fresh(&k->ticket.request, &context)) return -1;
    envara_gui_step(ENVARA_GUI_STEP_STAGE_FRESH);
    struct envara_gui_lifecycle *child = &k->report->child;
    if (k->provider->preparation && envara_identity_read(getpid(),&k->own)) return reject(ESTALE);
    int result = k->provider->stage(&k->ticket.app, &k->ticket.request, &fresh, child, k->provider->context);
    int error = result ? (errno ? errno : EIO) : EACCES;
    if (envara_app_keychain_custody_pending(k->provider->preparation,&k->ticket.app,&k->ticket.request,k->ticket.run_id) != 0)
        return preparation_quarantine(k,error);
    struct envara_identity actual;
    int ownership = direct_child(&child->child, &actual);
    if (!ownership && child->child.identity.pid <= 1 && child->phase != ENVARA_GUI_EMPTY) ownership = -1;
    if (ownership < 0) {
        /* No identity/birth proof means no safe PID signal or socket release.
         * Keep the original reservation under catchable-signal handlers. A
         * separate proved recovery is required; never invent ECHILD evidence. */
        child->phase = ENVARA_GUI_UNCERTAIN; child->protected_ready = 0;
        k->report->recovery_required = 1;
        for (;;) pause();
    }
    if (!ownership) {
        /* A foreign/unavailable PID is never adopted, signalled or accepted
         * from callback fields. No child means the durable claim stays spent. */
        envara_gui_lifecycle_init(child); return reject(error);
    }
    enum envara_gui_phase phase = child->phase; int protected_ready = child->protected_ready;
    struct stat error_pipe, lease_pipe, recovery_pipe;
    int error_reader = child->child.error_fd != k->guard.lease_fd && child->child.error_fd != k->guard.recovery_fd &&
        child->child.error_fd != k->guard.retained_fd && child->child.error_fd != k->output && reader(child->child.error_fd, &error_pipe) &&
        !fstat(k->guard.lease_fd, &lease_pipe) && !fstat(k->guard.recovery_fd, &recovery_pipe) &&
        !(error_pipe.st_dev == lease_pipe.st_dev && error_pipe.st_ino == lease_pipe.st_ino) &&
        !(error_pipe.st_dev == recovery_pipe.st_dev && error_pipe.st_ino == recovery_pipe.st_ino);
    if (!error_reader) child->child.error_fd = -1; /* Never close an unrelated callback FD. */
    child->child.identity = actual; child->leader_reaped = child->scope_quiescent = child->protected_ready = 0;
    child->request = k->ticket.request; child->original = k->ticket.app.original; child->manifest = k->ticket.app.snapshot;
    child->fixture_only = k->ticket.fixture_only; k->child = child; k->guard.child = child->child;
    k->stopped_before_exec = stopped_native_child(&child->child);
    child->phase = k->stopped_before_exec ? ENVARA_GUI_SUSPENDED : ENVARA_GUI_UNCERTAIN;
    if (result || phase != ENVARA_GUI_SUSPENDED || protected_ready || !error_reader || !k->stopped_before_exec ||
        !envara_identity_matches(&actual, k->ticket.request.console_uid, k->ticket.request.realm_gid) ||
        adapter_fresh(&k->ticket.request, &context)) return reject(error);
    envara_gui_step(ENVARA_GUI_STEP_STAGE_ADOPT);
    return adopt(&k->ticket, child, k);
}
int envara_app_supervisor_run(const struct envara_app_supervisor_context *context, const char *id,
                             int output, struct envara_app_supervisor_report *out) {
    if (!out) return reject(EINVAL); memset(out, 0, sizeof(*out)); envara_gui_lifecycle_init(&out->child);
    if (!context || !uuid(id) || output < 0 || (context->fixture_only != 0 && context->fixture_only != 1)) return reject(EINVAL);
    if (context->fixture_only ? (!getuid() || getuid() != geteuid()) : entry()) return reject(EACCES);
    const struct envara_app_supervisor_provider *p = context->provider;
    if (!p || !p->ticket.inspect || !p->ticket.verify || !p->prepare_guard) return reject(ENOTSUP);
    int flags = fcntl(output, F_GETFL); if (flags < 0 || fcntl(output, F_SETFL, flags | O_NONBLOCK)) return -1;
    struct sigaction ignore = {0}, previous_pipe; ignore.sa_handler = SIG_IGN; sigemptyset(&ignore.sa_mask);
    if (sigaction(SIGPIPE, &ignore, &previous_pipe)) return -1;
    struct sigaction hold = {0}, previous_signals[3]; const int signals[] = {SIGTERM, SIGINT, SIGHUP};
    hold.sa_handler = quarantined; sigemptyset(&hold.sa_mask); quarantine_signal = 0;
    for (int i = 0; i < 3; i++) if (sigaction(signals[i], &hold, &previous_signals[i])) {
        int error = errno; while (i--) sigaction(signals[i], &previous_signals[i], NULL);
        sigaction(SIGPIPE, &previous_pipe, NULL); (void)fcntl(output, F_SETFL, flags); return reject(error);
    }
    struct envara_app_registry registry; memset(&registry, 0, sizeof(registry)); registry.fd = -1;
    struct envara_app_ticket_store store; memset(&store, 0, sizeof(store)); store.fd = -1;
    struct keeper k = {.provider = p, .report = out, .output = output};
    int result = -1, error;
    if (envara_app_registry_open(&registry, context->fixture_registry_root, context->fixture_only, 0) ||
        envara_app_ticket_store_open(&store, context->fixture_ticket_root, context->fixture_only, 0)) goto done;
    struct envara_app_ticket_authority authority = {inspect, verify, adopt, &k};
    /* Its first check of each bundle is a full signed inspection; later
     * staging boundaries re-prove that exact state's identity. adopt ends it. */
    if (!envara_gui_validation_scope_begin()) { result = -1; errno = EOVERFLOW; goto done; }
    k.validation_scope_open = 1;
    result = p->stage ? adapter_stage(&k, &store, &registry, id, &authority) :
        envara_app_ticket_stage(&store, &registry, id, &authority, &out->child);
done:
    { int saved = errno; staging_scope_end(&k); errno = saved; }
    error = result ? errno : 0;
    /* Prior to a child, failing claim/stage can release local reservation FDs.
     * After a child, adopt never returns before exact reap + fixed deny/scope. */
    if (k.prepared) {
        if (out->child.phase != ENVARA_GUI_EMPTY && !out->released) {
            k.child = &out->child;
            (void)quarantine(&k);
        }
        int held[] = {k.guard.lease_fd, k.guard.recovery_fd, k.guard.retained_fd};
        for (size_t i = 0; i < 3; i++) if (held[i] >= 3) {
            int duplicate = 0; for (size_t j = 0; j < i; j++) if (held[j] == held[i]) duplicate = 1;
            if (!duplicate) close(held[i]);
        }
    }
    envara_app_ticket_store_close(&store); envara_app_registry_close(&registry);
    envara_app_family_destroy(k.family);
    for (int i = 0; i < 3; i++) (void)sigaction(signals[i], &previous_signals[i], NULL);
    (void)fcntl(output, F_SETFL, flags); (void)sigaction(SIGPIPE, &previous_pipe, NULL);
    out->recovery_required = out->child.phase != ENVARA_GUI_EMPTY && !out->released;
    return error ? reject(error) : 0;
}
