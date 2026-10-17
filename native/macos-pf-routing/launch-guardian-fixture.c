#include "launch-guardian.h"
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>

#ifdef ENVARA_GUARDIAN_TYPED_RETRY_FIXTURE
#include <mach/mach.h>
static pid_t fixture_guardian_leader;
static int fixture_guardian_churn,fixture_guardian_signal_calls;
static unsigned fixture_guardian_inventory_calls;
static int fixture_guardian_listchildren(pid_t parent,void *buffer,int size);
static int fixture_guardian_signal(audit_token_t *token,int signal_number);
#define proc_listchildpids fixture_guardian_listchildren
#define proc_signal_with_audittoken fixture_guardian_signal
#include "launch-guardian.c"
#undef proc_listchildpids
#undef proc_signal_with_audittoken
static int fixture_guardian_listchildren(pid_t parent,void *buffer,int size) {
    int count=proc_listchildpids(parent,buffer,size);
    if (fixture_guardian_churn && parent==fixture_guardian_leader && count>0 && (++fixture_guardian_inventory_calls%2)==0) return 0;
    return count;
}
static int fixture_guardian_signal(audit_token_t *token,int signal_number) {
    fixture_guardian_signal_calls++;
    return proc_signal_with_audittoken(token,signal_number);
}
#endif

/* This fixture uses only its own processes, anonymous pipes, and AF_UNIX
 * sockets. The denial callback is deliberately a fixture stub: no PF or
 * protected state exists. It is not a production kernel-denial proof. */
struct receipt {
    int event, guardian_pid, child_pid;
    struct envara_launch_guard_report report;
    unsigned revoke_calls;
    int revoke_before_family, fixture_front_closed, family_signal_calls;
};
struct context {
    int report_fd, original_fd, scope_fd, child_pid, deny;
    const char *scenario;
    unsigned deny_calls;
    int executed_fd, executed_seen;
    unsigned revoke_calls;
    int revoke_before_family, fixture_front_closed;
};
static const char *fixture_executable;
static int fixture_lifeline = -1;
extern char **environ;
static void peer_exec(int number) {
    (void)number;
    char *arguments[] = {(char *)fixture_executable, "--peer-exec", NULL};
    execve(fixture_executable, arguments, environ); _exit(93);
}
static int pipe_cloexec(int pair[2]) {
    if (pipe(pair)) return -1;
    if (fcntl(pair[0], F_SETFD, FD_CLOEXEC) || fcntl(pair[1], F_SETFD, FD_CLOEXEC)) return -1;
    return 0;
}
static int read_exact(int fd, void *buffer, size_t length, int timeout) {
    unsigned char *bytes = buffer;
    while (length) {
        struct pollfd poller = {fd, POLLIN | POLLHUP, 0};
        if (poll(&poller, 1, timeout) <= 0) return -1;
        ssize_t count = read(fd, bytes, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        bytes += count; length -= (size_t)count;
    }
    return 0;
}
static int fixture_deny(void *opaque) {
    struct context *context = opaque;
    if (++context->deny_calls == 3 && !strncmp(context->scenario, "resume-", 7)) {
        /* The final pre-SIGCONT callback, after the initial arming and B
         * checks. Use actual elapsed time rather than a fake clock. */
        struct timespec delay = !strcmp(context->scenario, "resume-slow-final-deny") ?
            (struct timespec){5, 500000000} : (struct timespec){0, 650000000};
        while (nanosleep(&delay, &delay) && errno == EINTR) {}
    }
    return context->deny;
}
static int fixture_revoke(void *opaque) {
    struct context *context = opaque;
    struct proc_bsdinfo info = {0};
    context->revoke_calls++;
    int live = proc_pidinfo(context->child_pid, PROC_PIDTBSDINFO, 1, &info, sizeof(info)) == sizeof(info) &&
        info.pbi_pid == (uint32_t)context->child_pid && info.pbi_ppid == (uint32_t)getpid() &&
        info.pbi_status != SZOMB;
    /* The application starts stopped in the two explicit-resume fixtures. */
    int initially_stopped = !strncmp(context->scenario, "resume-", 7);
    context->revoke_before_family = live && (initially_stopped || info.pbi_status != SSTOP);
    if (!context->revoke_before_family) return 0;
#ifdef ENVARA_GUARDIAN_TYPED_RETRY_FIXTURE
    if (!strcmp(context->scenario,"typed-churn-retry")) fixture_guardian_churn=context->revoke_calls==1;
#endif
    if (context->revoke_calls == 1 && (!strcmp(context->scenario, "network-retry") ||
        !strcmp(context->scenario, "network-auto-retry") || !strcmp(context->scenario,"network-recovery-retry"))) return 0;
    /* Deliberately inert authority: only fixture state changes. It is not PF
     * or real FRONT routing/stream-closure evidence. */
    context->fixture_front_closed = 1;
    if (strcmp(context->scenario, "deny-loss") || context->revoke_calls > 1) context->deny = 1;
    return 1;
}
static int fixture_resume(const struct envara_child *child, void *opaque) {
    struct context *context = opaque;
    return child->identity.pid == context->child_pid && envara_same_process(&child->identity);
}
static int fixture_executed(const struct envara_child *child, void *opaque) {
    struct context *context = opaque;
    if (!fixture_resume(child, opaque)) return -1;
    if (!context->executed_seen) {
        char byte; ssize_t count = read(context->executed_fd, &byte, 1);
        if (count == 1 && byte == 'X') context->executed_seen = 1;
        else if (count != -1 || (errno != EAGAIN && errno != EINTR)) return -1;
    }
    return context->executed_seen;
}
static int fixture_scope(void *opaque) {
    struct context *context = opaque;
    if (!context->fixture_front_closed) return 0;
    struct pollfd item = {context->scope_fd, POLLIN | POLLHUP, 0};
    if (poll(&item, 1, 0) <= 0) return 0;
    char byte; return read(context->scope_fd, &byte, 1) == 0;
}
static void receipt(enum envara_launch_guard_event event,
                    const struct envara_launch_guard_report *report, void *opaque) {
    struct context *context = opaque;
    if (event == ENVARA_GUARD_ARMED) { close(context->original_fd); context->original_fd = -1;
        if (!strcmp(context->scenario, "deny-loss")) context->deny = 0; }
    struct receipt record = {.event=event, .guardian_pid=getpid(), .child_pid=context->child_pid,
        .report=*report, .revoke_calls=context->revoke_calls, .revoke_before_family=context->revoke_before_family,
        .fixture_front_closed=context->fixture_front_closed};
#ifdef ENVARA_GUARDIAN_TYPED_RETRY_FIXTURE
    record.family_signal_calls=fixture_guardian_signal_calls;
    if (event==ENVARA_GUARD_CLEANUP_PENDING && !strcmp(context->scenario,"typed-churn-retry")) fixture_guardian_churn=0;
#endif
    (void)write(context->report_fd, &record, sizeof(record));
    if (event == ENVARA_GUARD_CLEANUP_PENDING && !strcmp(context->scenario, "deny-loss")) context->deny = 1;
}
static void fixture_wait_lifeline(void) {
    for (int i = 0; i < 200; i++) {
        struct pollfd line = {.fd=fixture_lifeline,.events=POLLIN|POLLHUP};
        if (poll(&line,1,100) > 0 && line.revents & (POLLHUP|POLLERR|POLLNVAL)) return;
    }
}
static void own_child(int scope_writer, int ready_writer, int detached) {
    int held[] = {scope_writer, ready_writer, fixture_lifeline};
    if (envara_launch_guard_isolate_descriptors(held, 3)) _exit(81);
    pid_t descendant = -1;
    if (detached) {
        descendant = fork();
        if (descendant < 0) _exit(82);
        if (!descendant) {
            if (write(ready_writer,"G",1)!=1) _exit(82);
            close(ready_writer);
            /* Persistent even after leader exit: only Stop or root fixture
             * lifeline closure ends this owned process. */
            fixture_wait_lifeline(); _exit(0);
        }
    }
    if (write(ready_writer,"C",1)!=1) _exit(82);
    close(ready_writer);
    fixture_wait_lifeline();
    if (descendant > 1) while (waitpid(descendant,NULL,0)<0 && errno==EINTR) {}
    _exit(0);
}
static void guardian(const char *scenario, pid_t controller, pid_t peer, int lease_reader,
                     int recovery_reader, int report_writer, int original_fd) {
    signal(SIGPIPE, SIG_IGN);
    int scope[2], ready[2]; if (pipe_cloexec(scope) || pipe_cloexec(ready)) _exit(83);
    pid_t child = fork();
    if (child < 0) _exit(84);
    int descendants=!strcmp(scenario,"descendant") || !strcmp(scenario,"typed-churn-retry");
    if (!child) { close(scope[0]); close(ready[0]); own_child(scope[1],ready[1],descendants); }
    close(scope[1]); close(ready[1]);
    char ready_bytes[2];
    if (read_exact(ready[0],ready_bytes,descendants?2:1,2000)) _exit(83);
    close(ready[0]);
    int heartbeat = !strcmp(scenario, "heartbeat-lost") || !strcmp(scenario, "heartbeat-kept");
    struct envara_launch_guard_request request = {.fixture_only = 1, .dependency_count = 2,
        .lease_fd = lease_reader, .recovery_fd = recovery_reader, .retained_fd = original_fd,
        .lease_milliseconds = !strcmp(scenario, "expiry") ? 250 : 5000,
        .heartbeat_timeout_milliseconds = heartbeat ? 1000 : 0};
    if (envara_identity_read(child, &request.child.identity) ||
        envara_identity_read(controller, &request.dependencies[0]) ||
        envara_identity_read(peer, &request.dependencies[1])) { kill(child, SIGKILL); waitpid(child, NULL, 0); _exit(85); }
    struct context context = {.report_fd=report_writer, .original_fd=original_fd,
        .scope_fd=scope[0], .child_pid=child, .deny=1, .scenario=scenario};
#ifdef ENVARA_GUARDIAN_TYPED_RETRY_FIXTURE
    fixture_guardian_leader=child;
#endif
    struct envara_launch_guard_authority authority = {.verify_persistent_deny=fixture_deny,
        .verify_scope_quiescent=fixture_scope,.observe=receipt,.context=&context,.revoke_owned_network=fixture_revoke};
    struct envara_launch_guard_report report = {0};
    int expected_refusal = 0;
    if (!strcmp(scenario, "birth-mismatch")) { request.dependencies[0].birth_microseconds ^= 1; expected_refusal = 1; }
    if (!strcmp(scenario, "duplicate-peer")) { request.dependencies[1] = request.dependencies[0]; expected_refusal = 1; }
    if (!strcmp(scenario, "foreign-child")) { request.child.identity = request.dependencies[1]; expected_refusal = 1; }
    if (!strcmp(scenario, "missing-authority")) { authority.verify_scope_quiescent = NULL; expected_refusal = 1; }
    if (!strcmp(scenario, "missing-network-authority")) { authority.revoke_owned_network = NULL; expected_refusal = 1; }
    if (!strcmp(scenario, "production-unprivileged")) { request.fixture_only = 0; expected_refusal = 1; }
    if (!strcmp(scenario, "alias-pipe")) { request.recovery_fd = dup(request.lease_fd); fcntl(request.recovery_fd, F_SETFD, FD_CLOEXEC); expected_refusal = 1; }
    if (!strcmp(scenario, "invalid-custody")) { request.retained_fd = scope[0]; expected_refusal = 1; }
    int result = envara_launch_guard_run(&request, &authority, &report);
    if (expected_refusal) {
        int error = errno; kill(child, SIGKILL); waitpid(child, NULL, 0);
        struct receipt record = {.event=-1,.guardian_pid=getpid(),.child_pid=child};
        record.report.dependency_index = error; (void)write(report_writer, &record, sizeof(record));
        _exit(result == -1 ? 0 : 86);
    }
    close(scope[0]); close(report_writer);
    _exit(result == 0 && report.child_reaped && !report.owns_retained_fd &&
          !report.ready && !report.protected_ready && !report.whole_guard_crash_verified ? 0 : 87);
}
static void controller(const char *scenario, int command_reader, int recovery_reader,
                       int report_writer, int original_fd) {
    int lease[2]; if (pipe_cloexec(lease)) _exit(88);
    pid_t peer = fork();
    if (peer < 0) _exit(89);
    if (!peer) {
        envara_launch_guard_isolate_descriptors(NULL, 0);
        signal(SIGUSR1, peer_exec);
        pid_t parent = getppid();
        for (int i = 0; i < 700; i++) {
            if (getppid() != parent) _exit(0);
            struct timespec delay = {0, 10000000}; nanosleep(&delay, NULL);
        }
        _exit(0);
    }
    pid_t guard = fork(); if (guard < 0) { kill(peer, SIGKILL); waitpid(peer, NULL, 0); _exit(90); }
    if (!guard) {
        close(command_reader); close(lease[1]);
        guardian(scenario, getppid(), peer, lease[0], recovery_reader, report_writer, original_fd);
    }
    close(lease[0]); close(recovery_reader); close(report_writer); close(original_fd);
    int peer_alive = 1, guard_alive = 1;
    for (;;) {
        struct pollfd command = {command_reader, POLLIN | POLLHUP, 0};
        if (poll(&command, 1, 50) > 0) {
            char byte; if (read(command_reader, &byte, 1) != 1) break;
            if (byte == 'C') { close(lease[1]); lease[1] = -1; }
            if (byte == 'S' && lease[1] >= 0) (void)write(lease[1], "S", 1);
            if (byte == 'B' && lease[1] >= 0) (void)write(lease[1], "B", 1);
            if (byte == 'M' && lease[1] >= 0) (void)write(lease[1], "X", 1);
            if (byte == 'K' && lease[1] >= 0) (void)write(lease[1], "K", 1);
            if (byte == 'D' && peer_alive) { kill(peer, SIGKILL); waitpid(peer, NULL, 0); peer_alive = 0; }
            if (byte == 'E' && peer_alive) kill(peer, SIGUSR1);
            if (byte == 'T' && guard_alive) { int status;
                pid_t result = waitpid(guard, &status, WNOHANG);
                if (result == 0) kill(guard, SIGTERM); else if (result == guard) guard_alive = 0; }
            if (byte == 'Q') break;
        }
        int status;
        if (guard_alive && waitpid(guard, &status, WNOHANG) == guard) { guard_alive = 0;
            if (!WIFEXITED(status) || WEXITSTATUS(status)) break; }
        if (!guard_alive) { if (peer_alive) { kill(peer, SIGKILL); waitpid(peer, NULL, 0); } _exit(0); }
    }
    if (peer_alive) { kill(peer, SIGKILL); waitpid(peer, NULL, 0); }
    if (guard_alive) { int status;
        if (waitpid(guard, &status, WNOHANG) == 0) { kill(guard, SIGKILL); waitpid(guard, NULL, 0); } }
    _exit(91);
}
static int wait_event(int fd, int target, struct receipt *last) {
    for (int i = 0; i < 20; i++) {
        if (read_exact(fd, last, sizeof(*last), 3000)) return -1;
        if (last->report.ready || last->report.protected_ready || last->report.whole_guard_crash_verified) return -1;
        if (last->event == target) return 0;
    }
    return -1;
}
static int no_eof(int fd) {
    struct pollfd item = {fd, POLLIN | POLLHUP, 0};
    return poll(&item, 1, 50) == 0;
}
static int descriptors(void) {
    int keep[2], extra[2]; if (socketpair(AF_UNIX, SOCK_STREAM, 0, keep) || socketpair(AF_UNIX, SOCK_STREAM, 0, extra)) return 1;
    pid_t child = fork(); if (child < 0) return 1;
    if (!child) {
        /* A live descriptor above a subsequently lowered soft limit must also
         * be closed. A getdtablesize-bounded loop would leak it. */
        int high = fcntl(extra[0], F_DUPFD, 200);
        struct rlimit limit; if (high < 200 || getrlimit(RLIMIT_NOFILE, &limit)) _exit(94);
        limit.rlim_cur = 128; if (setrlimit(RLIMIT_NOFILE, &limit)) _exit(95);
        int held[] = {keep[0]};
        if (envara_launch_guard_isolate_descriptors(held, 1) ||
            fcntl(high, F_GETFD) != -1 || errno != EBADF ||
            fcntl(extra[0], F_GETFD) != -1 || errno != EBADF ||
            fcntl(extra[1], F_GETFD) != -1 || errno != EBADF ||
            !(fcntl(keep[0], F_GETFD) & FD_CLOEXEC) || write(keep[0], "Y", 1) != 1) _exit(92);
        _exit(0);
    }
    close(keep[0]); close(extra[0]); close(extra[1]); char byte; int status;
    int failed = read_exact(keep[1], &byte, 1, 3000) || byte != 'Y' ||
        waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status);
    close(keep[1]); return failed;
}
static int resume_clock_fixture(const char *scenario) {
    int lease[2], recovery[2], reports[2], scope[2], executed[2], custody[2];
    if (pipe_cloexec(lease) || pipe_cloexec(recovery) || pipe_cloexec(reports) ||
        pipe_cloexec(scope) || pipe_cloexec(executed) ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, custody)) return 1;
    int positive = !strcmp(scenario, "resume-slow-final-deny");
    pid_t owner = fork(); if (owner < 0) return 1;
    if (!owner) {
        close(lease[1]); close(recovery[1]); close(reports[0]); close(custody[1]);
        pid_t child = fork(); if (child < 0) _exit(101);
        if (!child) {
            int held[] = {scope[1], executed[1]};
            if (envara_launch_guard_isolate_descriptors(held, 2)) _exit(102);
            pid_t parent = getppid(); raise(SIGSTOP);
            if (write(executed[1], "X", 1) != 1) _exit(103);
            close(executed[1]);
            for (int i=0;i<1500;i++) {
                if (getppid()!=parent) _exit(0);
                struct timespec pause={0,10000000}; nanosleep(&pause,NULL);
            }
            _exit(0);
        }
        close(scope[1]); close(executed[1]);
        int status;
        if (waitpid(child,&status,WUNTRACED)!=child || !WIFSTOPPED(status)) _exit(104);
        int flags=fcntl(executed[0],F_GETFL);
        if (flags<0 || fcntl(executed[0],F_SETFL,flags|O_NONBLOCK)) _exit(105);
        struct context context={.report_fd=reports[1],.original_fd=custody[0],
            .scope_fd=scope[0],.child_pid=child,.deny=1,.scenario=scenario,.executed_fd=executed[0]};
        struct envara_launch_guard_request request={.fixture_only=1,.dependency_count=1,
            .lease_fd=lease[0],.recovery_fd=recovery[0],.retained_fd=custody[0],
            .lease_milliseconds=positive?20000:500,.verify_resume=fixture_resume,
            .verify_executed=fixture_executed,.resume_context=&context};
        if (envara_identity_read(child,&request.child.identity) ||
            envara_identity_read(getppid(),&request.dependencies[0])) _exit(106);
        struct envara_launch_guard_authority authority={.verify_persistent_deny=fixture_deny,
            .verify_scope_quiescent=fixture_scope,.observe=receipt,.context=&context,.revoke_owned_network=fixture_revoke};
        struct envara_launch_guard_report report={0};
        int result=envara_launch_guard_run(&request,&authority,&report);
        _exit(result==0 && report.child_reaped && !report.owns_retained_fd &&
            report.resume_sent==positive && report.resumed==positive &&
            context.executed_seen==positive ? 0:107);
    }
    close(lease[0]); close(recovery[0]); close(reports[1]); close(scope[0]); close(scope[1]);
    close(executed[0]); close(executed[1]); close(custody[0]);
    struct receipt record={0}; int failed=wait_event(reports[0],ENVARA_GUARD_ARMED,&record);
    if (!failed && (!record.report.owns_retained_fd || !no_eof(custody[1]) || write(lease[1],"B",1)!=1)) failed=1;
    if (!failed) failed=positive ? (read_exact(reports[0],&record,sizeof(record),8000) ||
        record.event!=ENVARA_GUARD_RESUMED) : wait_event(reports[0],ENVARA_GUARD_REVOKED,&record);
    if (!failed && (!record.report.owns_retained_fd || record.report.resume_sent!=positive ||
        record.report.resumed!=positive || !no_eof(custody[1]))) failed=1;
    if (!failed && positive) {
        if (write(lease[1],"S",1)!=1 || wait_event(reports[0],ENVARA_GUARD_REVOKED,&record)) failed=1;
    }
    if (!failed && ((!record.report.child_reaped && wait_event(reports[0],ENVARA_GUARD_CHILD_REAPED,&record)) ||
        !record.report.child_reaped || !no_eof(custody[1]) || write(recovery[1],"R",1)!=1 ||
        wait_event(reports[0],ENVARA_GUARD_RELEASED,&record) ||
        record.report.owns_retained_fd || !record.report.persistent_deny_observed ||
        !record.report.scope_quiescent_observed)) failed=1;
    int status=0;
    if (failed) { /* This is the fixture's own unreaped direct child only. */
        if (waitpid(owner,&status,WNOHANG)==0) {kill(owner,SIGKILL);waitpid(owner,&status,0);}
    } else if (waitpid(owner,&status,0)!=owner || !WIFEXITED(status) || WEXITSTATUS(status)) failed=1;
    char byte; struct pollfd eof={custody[1],POLLIN|POLLHUP,0};
    if (!failed && (poll(&eof,1,1000)<=0 || read(custody[1],&byte,1)!=0)) failed=1;
    close(lease[1]);close(recovery[1]);close(reports[0]);close(custody[1]);
    printf("{\"ok\":%s,\"fixtureOnly\":true,\"ready\":false,\"protected\":false,\"activatesSystem\":false,"
        "\"resumedAfterSlowFinalDeny\":%s,\"expiredFinalDenyRefusedBeforeSignal\":%s,\"custodyHeldUntilVerifiedRelease\":%s}\n",
        failed?"false":"true",positive&&!failed?"true":"false",!positive&&!failed?"true":"false",failed?"false":"true");
    return failed;
}
int main(int argc, char **argv) {
    if (argc != 2 || getuid() == 0 || geteuid() != getuid()) return 1;
    if (!strcmp(argv[1], "--peer-exec")) {
        /* Keep the same PID/birth alive after exec, proving NOTE_EXEC rather
         * than conflating exec with the later process-exit notification. */
        struct timespec delay = {6, 0}; nanosleep(&delay, NULL); return 0;
    }
    fixture_executable = argv[0];
    signal(SIGPIPE,SIG_IGN);
    const char *scenario = argv[1];
    if (!strcmp(scenario,"resume-slow-final-deny") || !strcmp(scenario,"resume-expired-final-deny"))
        return resume_clock_fixture(scenario);
    if (!strcmp(scenario, "descriptors")) {
        int failed = descriptors(); printf("{\"ok\":%s,\"ready\":false,\"protected\":false,\"activatesSystem\":false,\"fixtureOnly\":true}\n", failed ? "false" : "true"); return failed;
    }
    int command[2], recovery[2], report[2], custody[2], lifeline[2];
    if (pipe_cloexec(command) || pipe_cloexec(recovery) || pipe_cloexec(report) ||
        pipe_cloexec(lifeline) || socketpair(AF_UNIX, SOCK_STREAM, 0, custody)) return 1;
    fixture_lifeline=lifeline[0];
    pid_t owner = fork(); if (owner < 0) return 1;
    if (!owner) { close(command[1]); close(recovery[1]); close(report[0]); close(custody[1]); close(lifeline[1]);
        controller(scenario, command[0], recovery[0], report[1], custody[0]); }
    close(command[0]); close(recovery[0]); close(report[1]); close(custody[0]); close(lifeline[0]);
    struct receipt record = {0}; int failed = read_exact(report[0], &record, sizeof(record), 3000);
    int refused = record.event == -1, reason = 0, owner_reaped = 0, status = 0;
    int network_retry_verified=0, network_before_family=0,typed_retry_verified=0;
    if (!failed && refused) {
        reason = record.report.dependency_index;
        if (!reason || waitpid(owner, &status, 0) != owner || !WIFEXITED(status) || WEXITSTATUS(status)) failed = 1;
        owner_reaped = 1;
    } else if (!failed) {
        if (record.event != ENVARA_GUARD_ARMED || !record.report.owns_retained_fd || !no_eof(custody[1])) failed = 1;
        /* Early release must be refused while the exact direct child lives. */
        if (!failed && (write(recovery[1], "R", 1) != 1 ||
            wait_event(report[0], ENVARA_GUARD_RELEASE_REFUSED, &record) || !no_eof(custody[1]))) failed = 1;
        if (!failed) {
            char fault = !strcmp(scenario, "dependency-death") ? 'D' : !strcmp(scenario, "dependency-exec") ? 'E' : !strcmp(scenario, "signal") ? 'T' :
                (!strcmp(scenario, "malformed") || !strcmp(scenario,"network-auto-retry")) ? 'M' : !strcmp(scenario, "eof") ? 'C' : 'S';
            if (!strcmp(scenario, "parent-death")) {
                kill(owner, SIGKILL); waitpid(owner, &status, 0); owner_reaped = 1;
            } else if (!strcmp(scenario, "expiry")) {
                struct timespec keep_delay = {0, 100000000};
                if (write(command[1], "K", 1) != 1) failed = 1;
                nanosleep(&keep_delay, NULL);
                if (write(command[1], "K", 1) != 1) failed = 1;
            } else if (!strcmp(scenario, "heartbeat-lost")) {
                /* One heartbeat arms the 1s awake-time window; silence revokes. */
                if (write(command[1], "K", 1) != 1) failed = 1;
            } else if (!strcmp(scenario, "heartbeat-kept")) {
                /* Heartbeats well past the window keep custody; only S revokes. */
                struct timespec beat = {0, 250000000};
                for (int i = 0; i < 9 && !failed; i++) {
                    if (write(command[1], "K", 1) != 1) failed = 1;
                    nanosleep(&beat, NULL);
                }
                if (!failed && write(command[1], "S", 1) != 1) failed = 1;
            } else if (write(command[1], &fault, 1) != 1) failed = 1;
            int recovery_retry=!strcmp(scenario,"network-recovery-retry");
            int typed_retry=!strcmp(scenario,"typed-churn-retry");
            int retry=!strcmp(scenario,"network-retry") || !strcmp(scenario,"network-auto-retry") ||
                !strcmp(scenario,"deny-loss") || recovery_retry || typed_retry;
            if (!failed && retry) {
                unsigned initial_attempt=!strcmp(scenario,"network-auto-retry")?0:1;
                if (read_exact(report[0],&record,sizeof(record),3000) || record.event!=ENVARA_GUARD_CLEANUP_PENDING ||
                    record.report.cleanup_attempt!=initial_attempt || !record.report.reason || record.report.child_signal_sent ||
                    record.report.child_reaped || record.report.family_stop_confirmed || !record.report.owns_retained_fd ||
                    record.revoke_calls!=1 || !record.revoke_before_family || !no_eof(custody[1])) failed=1;
                reason=record.report.reason;
                struct proc_bsdinfo actual={0};
                if (!failed && (proc_pidinfo(record.child_pid,PROC_PIDTBSDINFO,1,&actual,sizeof(actual))!=sizeof(actual) ||
                    actual.pbi_status==SZOMB || actual.pbi_status==SSTOP)) failed=1;
                if (!failed && ((!strcmp(scenario,"deny-loss") &&
                    (!record.report.network_revoked || record.report.persistent_deny_observed)) ||
                    (typed_retry && (!record.report.network_revoked || !record.report.persistent_deny_observed || record.family_signal_calls)) ||
                    (strcmp(scenario,"deny-loss") && !typed_retry && record.report.network_revoked))) failed=1;
                if (!failed && typed_retry) {
                    /* Disable the injected drift before R. R must still not
                     * clear the typed latch or send any application signal. */
                    if (write(recovery[1],"R",1)!=1 || read_exact(report[0],&record,sizeof(record),3000) ||
                        record.event!=ENVARA_GUARD_RELEASE_REFUSED || record.family_signal_calls ||
                        record.report.family_stop_confirmed || record.report.child_signal_sent ||
                        !record.report.owns_retained_fd || !no_eof(custody[1])) failed=1;
                }
                /* An attempted B after failure cannot restore launch authority.
                 * Cleanup retry keeps the original reason and never resumes. */
                if (!failed && write(command[1],"B",1)!=1) failed=1;
                if (!failed && ((recovery_retry ? write(recovery[1],"R",1) : write(command[1],"S",1))!=1 ||
                    wait_event(report[0],ENVARA_GUARD_REVOKED,&record) ||
                    record.report.cleanup_attempt!=initial_attempt+(recovery_retry?0:1) || (int)record.report.reason!=reason ||
                    record.report.resume_sent || record.report.resumed)) failed=1;
                if (!failed && typed_retry && (record.revoke_calls<2 || record.family_signal_calls<=0)) failed=1;
                if (!failed) {if (typed_retry) typed_retry_verified=1;else network_retry_verified=1;}
            } else if (!failed && wait_event(report[0], ENVARA_GUARD_REVOKED, &record)) failed = 1;
            reason = record.report.reason;
            if (!failed && (!reason || !record.report.owns_retained_fd ||
                !record.report.network_revoked || !record.report.family_stop_confirmed || !record.revoke_before_family ||
                !record.fixture_front_closed || (!record.report.child_signal_sent && !record.report.child_reaped) ||
                (!recovery_retry && !no_eof(custody[1])))) failed = 1;
            network_before_family=!failed;
            /* Scope EOF and child reap are observed facts, never a fixed delay
             * allowing a persistent descendant to disappear naturally. */
            int released=0;
            for (unsigned attempt=0;!failed && !released && attempt<50;attempt++) {
                if ((!recovery_retry || attempt) && write(recovery[1],"R",1)!=1) {failed=1;break;}
                for (;;) {
                    if (read_exact(report[0],&record,sizeof(record),3000)) {failed=1;break;}
                    if (record.event==ENVARA_GUARD_CHILD_REAPED) continue;
                    if (record.event==ENVARA_GUARD_RELEASED) {released=1;break;}
                    if (record.event!=ENVARA_GUARD_RELEASE_REFUSED || !record.report.owns_retained_fd ||
                        !record.report.network_revoked || !record.report.family_stop_confirmed || !no_eof(custody[1])) failed=1;
                    break;
                }
                if (!released) {struct timespec pause={0,10000000};nanosleep(&pause,NULL);}
            }
            if (!failed && (!released || record.report.owns_retained_fd || !record.report.child_reaped ||
                !record.report.scope_quiescent_observed || !record.report.persistent_deny_observed ||
                (int)record.report.reason!=reason)) failed=1;
            char byte;
            if (!failed && read_exact(custody[1], &byte, 1, 3000) != -1) failed = 1;
            struct pollfd eof = {custody[1], POLLIN | POLLHUP, 0};
            if (!failed && (poll(&eof, 1, 1000) <= 0 || read(custody[1], &byte, 1) != 0)) failed = 1;
        }
    }
    close(lifeline[1]); close(recovery[1]); close(report[0]); close(custody[1]);
    if (!owner_reaped) {
        if (failed) (void)write(command[1], "Q", 1);
        if (waitpid(owner, &status, 0) != owner || (!failed && (!WIFEXITED(status) || WEXITSTATUS(status)))) failed = 1;
    }
    close(command[1]);
    printf("{\"ok\":%s,\"ready\":false,\"protected\":false,\"activatesSystem\":false,\"fixtureOnly\":true,"
           "\"refused\":%s,\"reason\":%d,\"wholeGuardCrashVerified\":false,\"networkBeforeFamilyVerified\":%s,"
           "\"networkRetryVerified\":%s,\"typedRetryVerified\":%s}\n", failed ? "false" : "true", refused ? "true" : "false", reason,
           network_before_family?"true":"false",network_retry_verified?"true":"false",typed_retry_verified?"true":"false");
    return failed ? 1 : 0;
}
