#include "app-supervisor.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/proc.h>
#include <libproc.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Unprivileged own-bundle fixture only. Synthetic denial is never PF proof.
 * Resume cases execute only this copied own Mach-O through fixed callbacks. */
static const char Registration[] = "00000000-0000-4000-8000-000000000101";
static const char Version[] = "00000000-0000-4000-8000-000000000102";
static const char Ticket[] = "00000000-0000-4000-8000-000000000103";
static const char Environment[] = "00000000-0000-4000-8000-000000000104";
static const char Run[] = "00000000-0000-4000-8000-000000000105";
static const char Lease[] = "00000000-0000-4000-8000-000000000106";
struct fixture {
    const char *workspace, *mode;
    int lease[2], recovery[2], custody[2], transferred;
    struct envara_identity manager;
    struct envara_app_supervisor_report *report;
    const char *tickets;
    int evidence_fd;
    const struct envara_app_registration *app;
};
struct stage_evidence {
    int calls, after_claim, after_guard, after_fresh;
    struct envara_identity child;
    int verify_resume_calls, verify_executed_calls, resume_sent, resumed;
    int supervisor_error, blocked_reason;
};
static struct stage_evidence stage_evidence;
static int resumed_ack, stopping_ack, cancel_sent, profile_ack_count;
static int claimed(const char *tickets);
#ifdef ENVARA_NOTION_POSTCHECK_FIXTURE
/* Linked only by the own-temp test. It calls the actual Notion post-fork
 * validator on this real stopped child; no root/vendor gates are bypassed in
 * the production translation units. */
extern int envara_fixture_notion_postcheck(const struct envara_app_registration *,
    const struct envara_gui_request *, struct envara_gui_lifecycle *);
#endif
static int callback_stage(const struct envara_app_registration *app, const struct envara_gui_request *request,
                          const struct envara_gui_stage_authority *authority,
                          struct envara_gui_lifecycle *out, void *opaque) {
    struct fixture *f = opaque; stage_evidence.calls++;
    stage_evidence.after_claim = claimed(f->tickets); stage_evidence.after_guard = f->transferred;
    stage_evidence.after_fresh = authority && authority->verify_committed_deny &&
        authority->verify_committed_deny(request, authority->context) == 0;
    if (!stage_evidence.after_claim || !stage_evidence.after_guard || !stage_evidence.after_fresh) { errno = EACCES; return -1; }
    if (!strcmp(f->mode, "callback-refused")) { errno = ENOTSUP; return -1; }
    if (!strcmp(f->mode, "callback-foreign")) { out->child.identity = f->manager; out->phase = ENVARA_GUI_SUSPENDED; return 0; }
    int result = envara_gui_stage(&app->original, &app->snapshot, request, app->fixture_only, authority, -1, -1, out);
    if (!result && !strcmp(f->mode, "callback-partial")) {
#ifdef ENVARA_NOTION_POSTCHECK_FIXTURE
        if (envara_fixture_notion_postcheck(app, request, out) != -1 || errno != ESTALE) return -1;
#endif
        /* Independent fixture record of the real cold child before the
         * supervisor cancels it. This is not a guardian stopped ACK. */
        stage_evidence.child = out->child.identity;
        if (write(f->evidence_fd, &stage_evidence, sizeof(stage_evidence)) != (ssize_t)sizeof(stage_evidence)) return -1;
        errno = EIO; return -1;
    }
    return result;
}
static volatile sig_atomic_t manager_interrupted;
static void manager_cancel(int number) { manager_interrupted = number; }
static int reject(int error) { errno = error; return -1; }
static int path(char out[PATH_MAX], const char *parent, const char *leaf) {
    int size = snprintf(out, PATH_MAX, "%s/%s", parent, leaf);
    return size > 0 && size < PATH_MAX ? 0 : reject(ENAMETOOLONG);
}
static int private_pipe(int pair[2]) {
    return pipe(pair) || fcntl(pair[0], F_SETFD, FD_CLOEXEC) || fcntl(pair[1], F_SETFD, FD_CLOEXEC) ? -1 : 0;
}
static int inspect(const char *environment, const char *run, const struct envara_app_registration *app,
                   struct envara_gui_request *request, char hash[65], void *opaque) {
    struct fixture *f = opaque;
    if (strcmp(environment, Environment) || strcmp(run, Run) || strcmp(app->registration_id, Registration) ||
        strcmp(app->version_id, Version) || !app->fixture_only || app->ready || app->protected_ready) return reject(EACCES);
    memset(request, 0, sizeof(*request)); request->schema = ENVARA_GUI_SCHEMA;
    request->console_uid = getuid(); request->realm_gid = getgid();
    strcpy(request->environment_id, Environment); strcpy(request->lease_id, Lease);
    if (strlen(f->workspace) >= sizeof(request->cwd)) return reject(EINVAL);
    strcpy(request->cwd, f->workspace); strcpy(request->timezone, "Asia/Shanghai"); strcpy(request->browser_locale, "zh-CN");
    memset(hash, '1', 64); hash[64] = 0; return 0;
}
static int verify(const struct envara_app_registration *app, const struct envara_gui_request *request,
                  const char *run, const char *hash, void *opaque) {
    struct envara_gui_request expected; char expected_hash[65];
    if (inspect(Environment, run, app, &expected, expected_hash, opaque) ||
        memcmp(request, &expected, sizeof(expected)) || strcmp(hash, expected_hash)) return reject(ESTALE);
    return 0;
}
static int never_adopt(const struct envara_app_ticket *ticket, struct envara_gui_lifecycle *child, void *opaque) {
    (void)ticket; (void)child; (void)opaque; return reject(ENOTSUP);
}
static int fixture_deny(void *opaque) { (void)opaque; return 1; }
static int fixture_scope(void *opaque) {
    struct fixture *f = opaque;
    return f->report && f->report->child.leader_reaped && !envara_same_process(&f->report->child.child.identity);
}
static int fixture_resume(const struct envara_child *child, void *opaque) {
    struct fixture *f = opaque; stage_evidence.verify_resume_calls++;
    return claimed(f->tickets) && f->transferred && envara_same_process(&child->identity) &&
        child->identity.parent_pid == getpid() && f->app &&
        !envara_gui_manifest_unchanged(&f->app->original) &&
        !envara_gui_manifest_unchanged(&f->app->snapshot);
}
static int fixture_executed(const struct envara_child *child, void *opaque) {
    struct fixture *f = opaque; stage_evidence.verify_executed_calls++;
    char image[PROC_PIDPATHINFO_MAXSIZE], self[PROC_PIDPATHINFO_MAXSIZE];
    if (!f->app || !envara_same_process(&child->identity) || child->identity.parent_pid != getpid() ||
        proc_pidpath(child->identity.pid, image, sizeof(image)) <= 0 ||
        proc_pidpath(getpid(), self, sizeof(self)) <= 0) return -1;
    if (!strcmp(image, self)) return 0;
    if (strcmp(image, f->app->snapshot.executable) || envara_gui_manifest_unchanged(&f->app->snapshot)) return -1;
    return !strcmp(f->mode, "resume-unverified") ? 0 : 1;
}
static int prepare_guard(const struct envara_app_registration *app, const struct envara_gui_request *request,
                         const char *run, const char *hash, struct envara_launch_guard_request *guard,
                         struct envara_launch_guard_authority *authority, void *opaque) {
    struct fixture *f = opaque;
    if (verify(app, request, run, hash, opaque) || f->transferred) return reject(EACCES);
    guard->fixture_only = 1; guard->dependency_count = 1; guard->dependencies[0] = f->manager;
    guard->lease_fd = f->lease[0]; guard->recovery_fd = f->recovery[0]; guard->retained_fd = f->custody[0];
    guard->lease_milliseconds = 10000;
    if (!strncmp(f->mode, "resume-", 7) && strcmp(f->mode, "resume-missing")) {
        guard->verify_resume = fixture_resume; guard->verify_executed = fixture_executed; guard->resume_context = f;
    }
    authority->verify_persistent_deny = fixture_deny;
    authority->verify_scope_quiescent = !strcmp(f->mode, "missing-guardian") ? NULL : fixture_scope;
    authority->context = f; f->transferred = 1; return 0;
}
static int claimed(const char *tickets) {
    char directory[PATH_MAX], file[PATH_MAX]; struct stat s;
    return !path(directory, tickets, Ticket) && !path(file, directory, "claimed") &&
        !lstat(file, &s) && S_ISREG(s.st_mode) && s.st_uid == getuid() && (s.st_mode & 07777) == 0600 && s.st_nlink == 1;
}
static int read_line(int fd, char bytes[2048], int timeout) {
    size_t used = 0;
    while (used < 2047) {
        if (manager_interrupted) return -1;
        struct pollfd item = {fd, POLLIN | POLLHUP, 0};
        if (poll(&item, 1, timeout) <= 0) return -1;
        ssize_t amount = read(fd, bytes + used, 1);
        if (amount < 0 && errno == EINTR) continue;
        if (amount != 1) return -1;
        if (bytes[used++] == '\n') { bytes[used] = 0; return 0; }
    }
    return -1;
}
static int ack(const char *bytes, const char *event, pid_t keeper, struct envara_identity *identity) {
    char expected[128];
    snprintf(expected, sizeof(expected), "\"event\":\"%s\"", event);
    if (!strstr(bytes, expected) || !strstr(bytes, "\"ready\":false,\"protected\":false") ||
        !strstr(bytes, "\"persistentDenyObserved\":true")) return -1;
    int executed = strstr(bytes, "\"resumed\":true") != NULL;
    if (!strstr(bytes, "\"profile\":\"fixture\"") || !strstr(bytes, "\"seatbeltAppliedByFixedExec\":false") ||
        !strstr(bytes, "\"frontAdmissionVerified\":false") || strstr(bytes, "\"seatbeltVerified\":") ||
        !strstr(bytes, executed ? "\"executedIdentityVerified\":true" : "\"executedIdentityVerified\":false")) return -1;
    snprintf(expected, sizeof(expected), "\"keeperPID\":%d", keeper);
    if (!strstr(bytes, expected)) return -1;
    const char *pid = strstr(bytes, "\"pid\":"); const char *birth = strstr(bytes, "\"birth\":\"");
    int number; unsigned long long seconds, micros;
    if (!pid || !birth || sscanf(pid, "\"pid\":%d", &number) != 1 ||
        sscanf(birth, "\"birth\":\"%llu:%llu", &seconds, &micros) != 2) return -1;
    if (!strcmp(event, "stopped")) {
        if (!strstr(bytes, "\"stoppedBeforeExec\":true") || !strstr(bytes, "\"resumeSent\":false,\"resumed\":false,\"cancelSent\":false")) return -1;
        if (envara_identity_read(number, identity) || identity->parent_pid != keeper || identity->uid != getuid() ||
            identity->gid != getgid() || identity->birth_seconds != seconds || identity->birth_microseconds != micros) return -1;
        struct proc_bsdinfo process;
        if (proc_pidinfo(number, PROC_PIDTBSDINFO, 0, &process, sizeof(process)) != sizeof(process) ||
            process.pbi_status != SSTOP || !envara_same_process(identity)) return -1;
        int status; if (waitpid(number, &status, WNOHANG) != -1 || errno != ECHILD) return -1;
    } else {
        if (number != identity->pid || seconds != identity->birth_seconds || micros != identity->birth_microseconds) return -1;
        if (!strcmp(event, "resumed")) {
            if (!strstr(bytes, "\"stoppedBeforeExec\":false") || !strstr(bytes, "\"resumeSent\":true,\"resumed\":true,\"cancelSent\":false") ||
                !envara_same_process(identity)) return -1;
        } else if (!strcmp(event, "stopping")) {
            if (!strstr(bytes, "\"cancelSent\":true") && !strstr(bytes, "\"cancelSent\":false")) return -1;
            cancel_sent = strstr(bytes, "\"cancelSent\":true") != NULL;
        } else if (!strstr(bytes, "\"childReaped\":true") || !strstr(bytes, "\"scopeQuiescentObserved\":true")) return -1;
        if (strstr(bytes, "\"resumeSent\":true") && !strstr(bytes, "\"stoppedBeforeExec\":false")) return -1;
    }
    profile_ack_count++; return 0;
}
static int emit(const char *mode, int okay, int has_claim, int stopped, int released, int gone, int replay) {
    printf("{\"ok\":%s,\"mode\":\"%s\",\"ready\":false,\"protected\":false,\"activatesSystem\":false,\"fixtureOnly\":true,"
           "\"claimed\":%s,\"stoppedACK\":%s,\"releasedACK\":%s,\"childGone\":%s,\"replayRefused\":%s,"
           "\"stageCalls\":%d,\"stageAfterClaim\":%s,\"stageAfterGuard\":%s,\"stageAfterFreshVerify\":%s,\"childPID\":%d,"
           "\"verifyResumeCalls\":%d,\"verifyExecutedCalls\":%d,\"resumeSent\":%s,\"resumed\":%s,\"resumedACK\":%s,\"stoppingACK\":%s,\"cancelSent\":%s,\"profileACKs\":%d,"
           "\"supervisorError\":%d,\"blockedReason\":\"%s\"}\n",
           okay ? "true" : "false", mode, has_claim ? "true" : "false", stopped ? "true" : "false",
           released ? "true" : "false", gone ? "true" : "false", replay ? "true" : "false", stage_evidence.calls,
           stage_evidence.after_claim ? "true" : "false", stage_evidence.after_guard ? "true" : "false",
           stage_evidence.after_fresh ? "true" : "false", stage_evidence.child.pid,
           stage_evidence.verify_resume_calls, stage_evidence.verify_executed_calls,
           stage_evidence.resume_sent ? "true" : "false", stage_evidence.resumed ? "true" : "false",
           resumed_ack ? "true" : "false", stopping_ack ? "true" : "false", cancel_sent ? "true" : "false", profile_ack_count,
           stage_evidence.supervisor_error, envara_gui_precondition_name(stage_evidence.blocked_reason));
    return okay ? 0 : 1;
}
int main(int argc, char **argv) {
    if (argc == 1 && getuid() && getuid() == geteuid() && getgid() == getegid()) {
        /* Only the registered copied fixture reaches this target. It performs
         * no I/O/network/PF work and stays observable until its own keeper S. */
        pid_t parent = getppid();
        for (int i = 0; i < 200 && getppid() == parent; i++) (void)poll(NULL, 0, 50);
        return 0;
    }
    if (argc != 5 || !getuid() || geteuid() != getuid() || getgid() != getegid()) return 90;
    const char *mode = argv[1];
    int callback = !strncmp(mode, "callback-", 9), resume = !strncmp(mode, "resume-", 7);
    int succeeds_resume = !strcmp(mode, "resume-good") || !strcmp(mode, "resume-replay");
    int no_callback_child = !strcmp(mode, "callback-refused") || !strcmp(mode, "callback-foreign");
    if (strcmp(mode, "lifecycle") && strcmp(mode, "manager-signal") && strcmp(mode, "source-changed") && strcmp(mode, "missing-guardian") && strcmp(mode, "missing-authority") &&
        strcmp(mode, "callback-lifecycle") && strcmp(mode, "callback-refused") && strcmp(mode, "callback-partial") && strcmp(mode, "callback-foreign") &&
        strcmp(mode, "resume-good") && strcmp(mode, "resume-missing") && strcmp(mode, "resume-stale") && strcmp(mode, "resume-replay") && strcmp(mode, "resume-unverified")) return 91;
    struct stat parent; char canonical[PATH_MAX], registry_path[PATH_MAX], tickets[PATH_MAX], own_bundle[PATH_MAX], own_workspace[PATH_MAX];
    if (!realpath(argv[2], canonical) || strcmp(canonical, argv[2]) || lstat(canonical, &parent) ||
        !S_ISDIR(parent.st_mode) || parent.st_uid != getuid() || (parent.st_mode & 07777) != 0700 ||
        path(registry_path, canonical, "registry") || path(tickets, canonical, "tickets") ||
        path(own_bundle, canonical, "Fixture.app") || path(own_workspace, canonical, "workspace") ||
        strcmp(argv[3], own_bundle) || strcmp(argv[4], own_workspace)) return 92;
    struct envara_app_supervisor_report report;
    if (!strcmp(mode, "missing-authority")) {
        struct envara_app_supervisor_context context = {1, registry_path, tickets, NULL};
        int result = envara_app_supervisor_run(&context, Ticket, STDOUT_FILENO, &report);
        int error = errno; struct stat absent;
        int okay = result == -1 && error == ENOTSUP && report.child.phase == ENVARA_GUI_EMPTY &&
            lstat(registry_path, &absent) == -1 && errno == ENOENT && lstat(tickets, &absent) == -1 && errno == ENOENT;
        return emit(mode, okay, 0, 0, 0, 1, 0);
    }
    struct fixture f = {.workspace = argv[4], .mode = mode, .lease = {-1, -1}, .recovery = {-1, -1}, .custody = {-1, -1}, .report = &report, .tickets = tickets, .evidence_fd = -1};
    struct envara_app_supervisor_provider provider = {.ticket = {inspect, verify, never_adopt, &f}, .prepare_guard = prepare_guard, .context = &f,
        .stage = callback ? callback_stage : NULL};
    struct envara_app_registry registry = {.fd = -1}; struct envara_app_ticket_store store = {.fd = -1};
    struct envara_app_registration app; struct envara_app_ticket ticket;
    if (envara_app_registry_open(&registry, registry_path, 1, 1) ||
        envara_app_registry_register(&registry, Registration, Version, argv[3], NULL, NULL, &app) ||
        envara_app_ticket_store_open(&store, tickets, 1, 1) ||
        envara_app_ticket_prepare(&store, &registry, Ticket, Registration, Version, Environment, Run, &provider.ticket, &ticket)) return 93;
    f.app = &app;
    envara_app_ticket_store_close(&store); envara_app_registry_close(&registry);
    if (!strcmp(mode, "source-changed")) {
        char contents[PATH_MAX], resources[PATH_MAX], marker[PATH_MAX];
        if (path(contents, argv[3], "Contents") || path(resources, contents, "Resources") || path(marker, resources, "marker")) return 94;
        int fd = open(marker, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0 || write(fd, "-changed", 8) != 8 || fsync(fd) || close(fd)) return 95;
    }
    if (private_pipe(f.lease) || private_pipe(f.recovery) || socketpair(AF_UNIX, SOCK_STREAM, 0, f.custody) ||
        fcntl(f.custody[0], F_SETFD, FD_CLOEXEC) || fcntl(f.custody[1], F_SETFD, FD_CLOEXEC) ||
        envara_identity_read(getpid(), &f.manager)) return 96;
    struct envara_app_supervisor_context context = {1, registry_path, tickets, &provider};
    if (strcmp(mode, "lifecycle") && strcmp(mode, "manager-signal") && !callback && !resume) {
        int result = envara_app_supervisor_run(&context, Ticket, STDOUT_FILENO, &report);
        int okay = result == -1 && report.child.phase == ENVARA_GUI_EMPTY && !report.armed && !report.released &&
            !report.ready && !report.protected_ready && !report.resumed && !claimed(tickets);
        for (int i = 0; i < 2; i++) {
            if (!f.transferred || i == 1) { close(f.lease[i]); close(f.recovery[i]); close(f.custody[i]); }
        }
        return emit(mode, okay, 0, 0, 0, 1, 0);
    }
    int output[2], evidence[2]; if (private_pipe(output) || private_pipe(evidence)) return 97;
    f.evidence_fd = evidence[1];
    struct sigaction cancel = {0}; cancel.sa_handler = manager_cancel; sigemptyset(&cancel.sa_mask);
    if (sigaction(SIGTERM, &cancel, NULL) || sigaction(SIGINT, &cancel, NULL) || sigaction(SIGHUP, &cancel, NULL)) return 97;
    pid_t keeper = fork(); if (keeper < 0) return 98;
    if (!keeper) {
        signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL); signal(SIGHUP, SIG_DFL);
        close(output[0]); close(f.lease[1]); close(f.recovery[1]); close(f.custody[1]);
        close(evidence[0]);
        int result = envara_app_supervisor_run(&context, Ticket, output[1], &report);
        stage_evidence.supervisor_error = result ? errno : 0;
        stage_evidence.blocked_reason = report.child.blocked_reason;
        stage_evidence.child = report.child.child.identity;
        stage_evidence.resume_sent = report.guardian.resume_sent; stage_evidence.resumed = report.resumed;
        if (write(evidence[1], &stage_evidence, sizeof(stage_evidence)) != (ssize_t)sizeof(stage_evidence)) _exit(100);
        close(evidence[1]);
        close(output[1]);
        if (no_callback_child) _exit(result == -1 && report.child.phase == ENVARA_GUI_EMPTY && !report.armed && !report.released && !report.recovery_required ? 0 : 99);
        if (!strcmp(mode, "callback-partial")) _exit(result == -1 && !report.armed && report.released && report.child.leader_reaped && !report.recovery_required ? 0 : 99);
        _exit(result || !report.armed || !report.released || !report.child.leader_reaped ||
              report.ready || report.protected_ready || report.resumed != succeeds_resume ||
              report.guardian.resume_sent != (succeeds_resume || !strcmp(mode, "resume-unverified")) || report.recovery_required ? 99 : 0);
    }
    close(output[1]); close(evidence[1]); close(f.lease[0]); close(f.recovery[0]); close(f.custody[0]);
    signal(SIGPIPE, SIG_IGN);
    char frame[2048]; struct envara_identity child = {0};
    int partial = !strcmp(mode, "callback-partial"), stopped = 0;
    if (partial || no_callback_child) {
        if (read(evidence[0], &stage_evidence, sizeof(stage_evidence)) != (ssize_t)sizeof(stage_evidence)) return 101;
        child = stage_evidence.child;
    } else if (!no_callback_child) stopped = !read_line(output[0], frame, 4000) && !ack(frame, "stopped", keeper, &child);
    int has_claim = claimed(tickets), released = 0, okay = stopped && has_claim;
    if (partial) okay = child.pid > 1 && child.parent_pid == keeper && has_claim;
    if (no_callback_child) okay = has_claim;
    if (!strcmp(mode, "manager-signal") && okay) raise(SIGTERM);
    if (manager_interrupted) okay = 0;
    if (okay && !no_callback_child) {
        struct pollfd socket = {f.custody[1], POLLIN | POLLHUP, 0};
        okay = poll(&socket, 1, 0) == 0;
        if (okay && resume) {
            if (!strcmp(mode, "resume-stale")) {
                char marker[PATH_MAX];
                if (snprintf(marker, sizeof(marker), "%s/Contents/Resources/marker", app.original.bundle) >= (int)sizeof(marker)) okay = 0;
                int fd = okay ? open(marker, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC) : -1;
                if (fd < 0 || write(fd, "-resume-stale", 13) != 13 || fsync(fd)) okay = 0;
                if (fd >= 0 && close(fd)) okay = 0;
            }
            okay = okay && write(f.lease[1], "B", 1) == 1 && !read_line(output[0], frame, 8000);
            if (okay && succeeds_resume) {
                char actual[PROC_PIDPATHINFO_MAXSIZE];
                resumed_ack = !ack(frame, "resumed", keeper, &child) &&
                    proc_pidpath(child.pid, actual, sizeof(actual)) > 0 && !strcmp(actual, app.snapshot.executable);
                okay = resumed_ack && write(f.lease[1], !strcmp(mode, "resume-replay") ? "B" : "S", 1) == 1;
            } else if (okay) {
                stopping_ack = !ack(frame, "stopping", keeper, &child) && strstr(frame, "\"resumed\":false") &&
                    strstr(frame, !strcmp(mode, "resume-unverified") ? "\"resumeSent\":true" : "\"resumeSent\":false");
                okay = stopping_ack;
            }
        } else if (okay && !partial) okay = write(f.lease[1], "S", 1) == 1;
        for (int i = 0; okay && i < 60 && !released; i++) {
            if (write(f.recovery[1], "R", 1) != 1) { okay = 0; break; }
            struct pollfd item = {output[0], POLLIN | POLLHUP, 0};
            if (poll(&item, 1, 50) > 0) {
                if (read_line(output[0], frame, 200)) okay = 0;
                else if (strstr(frame, "\"event\":\"stopping\"")) { stopping_ack = !ack(frame, "stopping", keeper, &child); okay = stopping_ack; }
                else { released = !ack(frame, "released", keeper, &child); if (!released) okay = 0; }
            }
        }
        okay = okay && released;
    }
    if (!okay) {
        (void)write(f.lease[1], "S", 1);
        if (child.pid > 1 && envara_same_process(&child)) kill(child.pid, SIGKILL);
        /* Signal cancellation must still complete custody recovery. The
         * interrupted reader flag applies only to the normal wait above. */
        manager_interrupted = 0;
        for (int i = 0; i < 20; i++) {
            (void)write(f.recovery[1], "R", 1); struct pollfd p = {output[0], POLLIN | POLLHUP, 0};
            if (poll(&p, 1, 50) > 0 && !read_line(output[0], frame, 200)) {
                if (strstr(frame, "\"event\":\"stopping\"")) { stopping_ack = !ack(frame, "stopping", keeper, &child); continue; }
                released = !ack(frame, "released", keeper, &child); if (released) break;
            }
        }
    }
    int status = 0, reaped = 0;
    /* EOF on the ACK pipe can precede the keeper's final _exit. Do not spin
     * through the reap deadline on an already-readable POLLHUP descriptor. */
    for (int i = 0; i < 60; i++) {
        if (waitpid(keeper, &status, WNOHANG) == keeper) { reaped = 1; break; }
        (void)poll(NULL, 0, 50);
    }
    if (!reaped) { kill(keeper, SIGKILL); waitpid(keeper, &status, 0); okay = 0; }
    if (!no_callback_child && read(evidence[0], &stage_evidence, sizeof(stage_evidence)) != (ssize_t)sizeof(stage_evidence)) okay = 0;
    close(evidence[0]);
    int gone = no_callback_child ? stage_evidence.child.pid == 0 : child.pid > 1 && !envara_same_process(&child);
    char byte; struct pollfd eof = {f.custody[1], POLLIN | POLLHUP, 0};
    if (!strcmp(mode, "manager-signal")) okay = stopped && has_claim && released;
    okay = okay && reaped && WIFEXITED(status) && !WEXITSTATUS(status) && gone && poll(&eof, 1, 1000) > 0 && read(f.custody[1], &byte, 1) == 0;
    close(output[0]); close(f.lease[1]); close(f.recovery[1]); close(f.custody[1]);
    struct envara_app_supervisor_report replay;
    int replay_refused = envara_app_supervisor_run(&context, Ticket, STDOUT_FILENO, &replay) == -1 &&
        replay.child.phase == ENVARA_GUI_EMPTY && !replay.armed && claimed(tickets);
    return emit(mode, okay && replay_refused, has_claim, stopped, released, gone, replay_refused);
}
