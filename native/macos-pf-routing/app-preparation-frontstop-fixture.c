/* Unprivileged fixture for the actual private frontend-stop helper. Every
 * process signal targets one inert direct child forked here. Wait/clock fault
 * seams model unavailable evidence; they never establish PF or app acceptance. */
#include "app-transport.h"
#include "launch-guardian.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum wait_mode { WAIT_REAL, WAIT_DELAY_TERMINAL, WAIT_ECHILD, WAIT_ERROR,
    WAIT_NONTERMINAL, WAIT_OTHER_PID, WAIT_INTERRUPTED };
static enum wait_mode wait_mode;
static pid_t owned_child;
static int owned_command, exit_before_identity, exit_during_kill, child_commanded_exit;
static enum wait_mode raced_wait_mode = WAIT_REAL;
static unsigned wait_calls, signal_calls, successful_signals, terminal_waits, clock_calls;
static unsigned fail_clock_call, fail_signals;
static int terminal_status;
static uint64_t fixture_ms = 1000, clock_step = 1;
static void command_terminal_without_reap(void) {
    assert(!child_commanded_exit && write(owned_command, "7", 1) == 1);
    child_commanded_exit = 1;
    siginfo_t info = {0}; int result;
    do { result = waitid(P_PID, (id_t)owned_child, &info, WEXITED | WNOWAIT); } while (result < 0 && errno == EINTR);
    assert(!result && info.si_pid == owned_child && info.si_code == CLD_EXITED);
}

static pid_t fixture_waitpid(pid_t pid, int *status, int options) {
    assert(pid == owned_child && pid > 1 && status && options == WNOHANG);
    wait_calls++;
    if (child_commanded_exit && raced_wait_mode == WAIT_ECHILD) { errno = ECHILD; return -1; }
    if (child_commanded_exit && raced_wait_mode == WAIT_ERROR) { errno = EIO; return -1; }
    if (child_commanded_exit && raced_wait_mode == WAIT_NONTERMINAL) { *status = (SIGSTOP << 8) | 0x7f; return pid; }
    if (child_commanded_exit && raced_wait_mode == WAIT_DELAY_TERMINAL) return 0;
    if (wait_mode == WAIT_ECHILD) { errno = ECHILD; return -1; }
    if (wait_mode == WAIT_ERROR) { errno = EIO; return -1; }
    if (wait_mode == WAIT_INTERRUPTED) { errno = EINTR; return -1; }
    if (wait_mode == WAIT_NONTERMINAL) { *status = (SIGSTOP << 8) | 0x7f; return pid; }
    if (wait_mode == WAIT_OTHER_PID) return pid + 1;
    /* The first zero result is from the real kernel before our SIGKILL. Only
     * subsequent terminal visibility is delayed, without consuming the reap. */
    if (wait_mode == WAIT_DELAY_TERMINAL && successful_signals) return 0;
    pid_t result = waitpid(pid, status, options);
    /* Keep the real initial zero result, then let only this original child
     * exit. WNOWAIT preserves its wait evidence for the production helper. */
    if (exit_before_identity && wait_calls == 1 && result == 0) command_terminal_without_reap();
    if (result == pid && (WIFEXITED(*status) || WIFSIGNALED(*status))) {
        terminal_waits++; terminal_status = *status;
    }
    return result;
}
static int fixture_kill(pid_t pid, int number) {
    assert(pid == owned_child && pid > 1 && number == SIGKILL);
    signal_calls++;
    if (exit_during_kill) { command_terminal_without_reap(); errno = ESRCH; return -1; }
    if (fail_signals) { fail_signals--; errno = EAGAIN; return -1; }
    int result = kill(pid, number); if (!result) successful_signals++;
    return result;
}
static int fixture_clock_gettime(clockid_t clock, struct timespec *value) {
    assert(clock == CLOCK_MONOTONIC && value); clock_calls++;
    if (fail_clock_call && clock_calls == fail_clock_call) { errno = EIO; return -1; }
    value->tv_sec = (time_t)(fixture_ms / 1000);
    value->tv_nsec = (long)(fixture_ms % 1000) * 1000000;
    fixture_ms += clock_step; return 0;
}
static int fixture_nanosleep(const struct timespec *requested, struct timespec *remaining) {
    assert(requested && requested->tv_sec == 0 && requested->tv_nsec > 0 && requested->tv_nsec <= 10000000);
    fixture_ms += (uint64_t)requested->tv_nsec / 1000000;
    /* Give an actually signalled child time to become waitable. The deadline
     * clock remains explicitly synthetic so timeout coverage stays quick. */
    struct timespec brief = {0, 1000000}; return nanosleep(&brief, remaining);
}
#define waitpid fixture_waitpid
#define kill fixture_kill
#define clock_gettime fixture_clock_gettime
#define nanosleep fixture_nanosleep
#include "app-transport.c"
#undef waitpid
#undef kill
#undef clock_gettime
#undef nanosleep

static pid_t create_child(int *command, int *input, struct envara_identity *identity) {
    int commands[2], front[2], ready[2];
    assert(!pipe(commands) && !pipe(front) && !pipe(ready));
    pid_t pid = fork(); assert(pid >= 0);
    if (!pid) {
        int held[] = {commands[0], front[0], ready[1]};
        assert(!envara_launch_guard_isolate_descriptors(held, 3));
        assert(write(ready[1], "Y", 1) == 1); close(ready[1]);
        char value; ssize_t count;
        do { count = read(commands[0], &value, 1); } while (count < 0 && errno == EINTR);
        _exit(count == 1 && value == '7' ? 7 : 0);
    }
    close(commands[0]); close(front[0]); close(ready[1]);
    struct pollfd p = {ready[0], POLLIN, 0}; char value;
    assert(poll(&p, 1, 3000) == 1 && read(ready[0], &value, 1) == 1 && value == 'Y'); close(ready[0]);
    assert(!envara_identity_read(pid, identity) && identity->parent_pid == getpid());
    *command = commands[1]; *input = front[1]; return pid;
}
static void terminal_without_reap(pid_t pid) {
    siginfo_t info; memset(&info, 0, sizeof(info)); int result;
    do { result = waitid(P_PID, (id_t)pid, &info, WEXITED | WNOWAIT); } while (result < 0 && errno == EINTR);
    assert(!result && info.si_pid == pid && (info.si_code == CLD_EXITED || info.si_code == CLD_KILLED));
}
static void retained(const struct frontend_stop_context *context, const struct envara_identity *original) {
    assert(!*context->reaped && !memcmp(context->frontend, original, sizeof(*original)));
    assert(context->owner == getpid());
}
static void remembered_terminal(struct frontend_stop_context *context) {
    assert(*context->reaped && terminal_waits == 1);
    unsigned prior_waits = wait_calls, prior_signals = signal_calls, prior_clock = clock_calls;
    fail_clock_call = clock_calls + 1; wait_mode = WAIT_ECHILD;
    assert(stop_owned_frontend(context) == 1);
    assert(wait_calls == prior_waits && signal_calls == prior_signals && clock_calls == prior_clock);
    fail_clock_call = 0; wait_mode = WAIT_REAL;
}
int main(int argc, char **argv) {
    assert(argc == 2 && getuid() != 0 && getuid() == geteuid() && getgid() == getegid());
    struct sigaction action = {0}; action.sa_handler = SIG_DFL;
    assert(!sigemptyset(&action.sa_mask) && !sigaction(SIGCHLD, &action, NULL));
    int command, input, reaped = 0; struct envara_identity identity;
    owned_child = create_child(&command, &input, &identity); owned_command = command;
    struct envara_identity original = identity;
    struct frontend_stop_context context = {.owner = getpid(), .input = &input, .reaped = &reaped, .frontend = &identity};
    assert(!fstat(input, &context.writer));
    const char *mode = argv[1]; int injected_fault = 1;
    if (!strncmp(mode, "exit-before-identity", 20) || !strcmp(mode, "exit-during-kill")) {
        exit_during_kill = !strcmp(mode, "exit-during-kill"); exit_before_identity = !exit_during_kill;
        if (!strcmp(mode, "exit-before-identity-echild")) raced_wait_mode = WAIT_ECHILD;
        else if (!strcmp(mode, "exit-before-identity-error")) raced_wait_mode = WAIT_ERROR;
        else if (!strcmp(mode, "exit-before-identity-nonterminal")) raced_wait_mode = WAIT_NONTERMINAL;
        else if (!strcmp(mode, "exit-before-identity-not-waitable")) raced_wait_mode = WAIT_DELAY_TERMINAL;
        int result = stop_owned_frontend(&context);
        assert(child_commanded_exit && input == -1 && !successful_signals && !context.kill_sent);
        if (raced_wait_mode == WAIT_ECHILD || raced_wait_mode == WAIT_ERROR || raced_wait_mode == WAIT_NONTERMINAL) {
            assert(!result && context.wait_unknown && !terminal_waits); retained(&context, &original);
            unsigned prior_waits = wait_calls; raced_wait_mode = WAIT_REAL;
            assert(!stop_owned_frontend(&context) && context.wait_unknown && wait_calls == prior_waits);
        } else {
            if (raced_wait_mode == WAIT_DELAY_TERMINAL) {
                assert(!result && errno == ESRCH && !context.wait_unknown && !terminal_waits); retained(&context, &original);
                raced_wait_mode = WAIT_REAL; assert(stop_owned_frontend(&context) == 1);
            } else assert(result == 1);
            assert(WIFEXITED(terminal_status) && WEXITSTATUS(terminal_status) == 7);
            remembered_terminal(&context);
        }
    } else if (!strcmp(mode, "delayed-terminal")) {
        wait_mode = WAIT_DELAY_TERMINAL; uint64_t start = fixture_ms;
        assert(!stop_owned_frontend(&context) && errno == ETIMEDOUT);
        assert(fixture_ms - start >= 2000 && fixture_ms - start <= 2020);
        retained(&context, &original);
        assert(input == -1 && context.kill_sent && !context.wait_unknown && signal_calls == 1 && successful_signals == 1);
        assert(wait_calls > 1 && !terminal_waits);
        wait_mode = WAIT_REAL; terminal_without_reap(owned_child);
        assert(stop_owned_frontend(&context) == 1 && signal_calls == 1);
        assert(WIFSIGNALED(terminal_status) && WTERMSIG(terminal_status) == SIGKILL);
        remembered_terminal(&context);
    } else if (!strcmp(mode, "echild") || !strcmp(mode, "wait-error") ||
               !strcmp(mode, "nonterminal") || !strcmp(mode, "unexpected-pid")) {
        wait_mode = !strcmp(mode, "echild") ? WAIT_ECHILD : !strcmp(mode, "wait-error") ? WAIT_ERROR :
            !strcmp(mode, "nonterminal") ? WAIT_NONTERMINAL : WAIT_OTHER_PID;
        assert(!stop_owned_frontend(&context)); retained(&context, &original);
        assert(context.wait_unknown && !context.kill_sent && !signal_calls && wait_calls == 1);
        wait_mode = WAIT_REAL;
        assert(!stop_owned_frontend(&context)); retained(&context, &original);
        assert(wait_calls == 1 && !signal_calls && !terminal_waits && context.wait_unknown);
    } else if (!strcmp(mode, "clock-start") || !strcmp(mode, "clock-after-kill")) {
        int after_kill = !strcmp(mode, "clock-after-kill"); fail_clock_call = after_kill ? 3 : 1;
        assert(!stop_owned_frontend(&context) && errno == EIO); retained(&context, &original);
        assert(!context.wait_unknown && context.kill_sent == after_kill && successful_signals == (unsigned)after_kill);
        assert(after_kill || !wait_calls); fail_clock_call = 0;
        if (after_kill) terminal_without_reap(owned_child);
        assert(stop_owned_frontend(&context) == 1 && signal_calls == 1 && successful_signals == 1);
        remembered_terminal(&context);
    } else if (!strcmp(mode, "exact-exit") || !strcmp(mode, "exact-signal")) {
        injected_fault = 0;
        if (!strcmp(mode, "exact-exit")) assert(write(command, "7", 1) == 1);
        else assert(!kill(owned_child, SIGKILL));
        terminal_without_reap(owned_child);
        assert(stop_owned_frontend(&context) == 1 && !context.kill_sent && !context.wait_unknown && !signal_calls);
        if (!strcmp(mode, "exact-exit")) assert(WIFEXITED(terminal_status) && WEXITSTATUS(terminal_status) == 7);
        else assert(WIFSIGNALED(terminal_status) && WTERMSIG(terminal_status) == SIGKILL);
        remembered_terminal(&context);
    } else if (!strcmp(mode, "wrong-owner")) {
        context.owner = getppid(); assert(!stop_owned_frontend(&context));
        assert(!wait_calls && !signal_calls && !clock_calls && input >= 3 && !reaped);
        context.owner = getpid(); identity.parent_pid = getppid();
        assert(!stop_owned_frontend(&context));
        assert(!wait_calls && !signal_calls && !clock_calls && !reaped);
        identity = original; assert(stop_owned_frontend(&context) == 1 && successful_signals == 1);
    } else if (!strcmp(mode, "wait-interrupted")) {
        wait_mode = WAIT_INTERRUPTED; clock_step = 25; uint64_t start = fixture_ms;
        assert(!stop_owned_frontend(&context) && errno == ETIMEDOUT); retained(&context, &original);
        assert(fixture_ms - start >= 2000 && fixture_ms - start <= 2050);
        assert(wait_calls > 1 && !signal_calls && !context.kill_sent && !context.wait_unknown);
        wait_mode = WAIT_REAL; clock_step = 1;
        assert(stop_owned_frontend(&context) == 1 && successful_signals == 1);
    } else if (!strcmp(mode, "kill-retry")) {
        fail_signals = 1;
        assert(!stop_owned_frontend(&context) && errno == EAGAIN); retained(&context, &original);
        assert(signal_calls == 1 && !successful_signals && !context.kill_sent && !context.wait_unknown);
        assert(stop_owned_frontend(&context) == 1 && signal_calls == 2 && successful_signals == 1);
    } else if (!strcmp(mode, "changed-identity")) {
        identity.birth_microseconds++;
        assert(!stop_owned_frontend(&context) && !reaped && !signal_calls && !context.kill_sent && !context.wait_unknown);
        assert(wait_calls == 1 && errno == EACCES); /* No race reconciliation after an observed mismatch. */
        identity = original; assert(stop_owned_frontend(&context) == 1 && successful_signals == 1);
    } else assert(!"unknown fixture mode");
    unsigned helper_terminal_waits = terminal_waits;
    /* Final fixture cleanup is separate from helper evidence. A sticky unknown
     * helper never regains authority merely because our fault seam was removed. */
    if (input >= 0) close(input);
    if (!reaped) {
        assert(!context.kill_sent && !successful_signals);
        if (!child_commanded_exit) assert(write(command, "0", 1) == 1);
        close(command); command = -1;
        int status; assert(waitpid(owned_child, &status, 0) == owned_child && WIFEXITED(status));
    } else {
        int status; errno = 0; assert(waitpid(owned_child, &status, WNOHANG) == -1 && errno == ECHILD);
    }
    if (command >= 0) close(command);
    printf("{\"ok\":true,\"mode\":\"%s\",\"injectedFault\":%s,\"helperReaped\":%s,\"helperTerminalWaits\":%u,"
        "\"signalCalls\":%u,\"successfulSignals\":%u,\"waitUnknown\":%s,\"ownedChildCleaned\":true,"
        "\"syntheticDeadline\":true,\"ready\":false,\"protected\":false}\n", mode,
        injected_fault ? "true" : "false", reaped ? "true" : "false", helper_terminal_waits,
        signal_calls, successful_signals, context.wait_unknown ? "true" : "false");
    return 0;
}
