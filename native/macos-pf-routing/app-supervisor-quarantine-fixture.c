/* Own-process, unprivileged fixture for the actual quarantine loop. Synthetic
 * authority callbacks are never PF evidence. Only fixture children are reaped
 * or signalled; retained custody is an AF_UNIX socket, never a host utun. */
#include "app-supervisor.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct fixture_state {
    volatile unsigned polls, reads, cancels, denied, scopes, released, held;
    volatile int deny_allowed, scope_allowed, child_exit, child_reaped;
    volatile short actual_eof_events;
};
static struct fixture_state *state;
static int fixture_mode, recovery_reader;
static int fixture_poll(struct pollfd *items, nfds_t count, int timeout) {
    assert(count == 1 && items[0].fd == recovery_reader && timeout == 50);
    state->polls++;
    int result = poll(items, count, timeout);
    if (fixture_mode == 1 && result > 0 && (items[0].revents & POLLHUP)) {
        /* Darwin's actual owned pipe reports readable EOF plus HUP. Nothing
         * is injected here: the production read consumes a real pipe EOF. */
        state->actual_eof_events = items[0].revents;
        assert(items[0].revents & POLLIN);
    }
    return result;
}
static ssize_t fixture_read(int fd, void *bytes, size_t size) {
    assert(fd == recovery_reader && size == 32); state->reads++;
    if (fixture_mode == 2) { errno = EINTR; return -1; }
    if (fixture_mode == 3) { errno = EIO; return -1; }
    return read(fd, bytes, size);
}
static int __attribute__((unused)) fixture_cancel(struct envara_gui_lifecycle *child) {
    (void)child; state->cancels++;
    /* Explicit cancellation-refused seam: an actual own direct child remains
     * alive until the parent fixture lets it exit, then actual waitpid proves
     * reap. This exercises the unchanged release requirement for child reap. */
    errno = EAGAIN; return -1;
}
#define poll fixture_poll
#define read fixture_read
#define envara_gui_cancel fixture_cancel
#ifndef ENVARA_QUARANTINE_SOURCE
#define ENVARA_QUARANTINE_SOURCE "app-supervisor.c"
#endif
#include ENVARA_QUARANTINE_SOURCE
#undef poll
#undef read
#undef envara_gui_cancel

static double now(void) {
    struct timespec value; assert(!clock_gettime(CLOCK_MONOTONIC, &value));
    return value.tv_sec + value.tv_nsec / 1e9;
}
static void pause_ms(long milliseconds) {
    struct timespec delay = {milliseconds / 1000, (milliseconds % 1000) * 1000000};
    while (nanosleep(&delay, &delay) && errno == EINTR) {}
}
static int fixture_verify(const struct envara_app_registration *app,
    const struct envara_gui_request *request, const char *run, const char *hash, void *context) {
    (void)app; (void)request; (void)run; (void)hash; (void)context; return 0;
}
static int fixture_deny(void *context) { (void)context; state->denied++; return state->deny_allowed; }
static int fixture_network_revoke(void *context) { (void)context; return state->deny_allowed; } /* inert only */
static int fixture_scope(void *context) { (void)context; state->scopes++; return state->scope_allowed; }
static void still_held(pid_t worker, int peer) {
    struct envara_identity identity; assert(!envara_identity_read(worker, &identity));
    assert(identity.parent_pid == getpid() && identity.uid == getuid() && envara_same_process(&identity));
    char byte; errno = 0; assert(recv(peer, &byte, 1, MSG_DONTWAIT) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
    assert(state->held && !state->released);
}
int main(int argc, char **argv) {
    assert(getuid() != 0 && getuid() == geteuid() && getgid() == getegid());
    struct sigaction own_child = {0}; own_child.sa_handler = SIG_DFL;
    assert(!sigemptyset(&own_child.sa_mask) && !sigaction(SIGCHLD, &own_child, NULL));
    assert(argc == 2); fixture_mode = atoi(argv[1]); assert(fixture_mode >= 1 && fixture_mode <= 7);
    state = mmap(NULL, sizeof(*state), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    assert(state != MAP_FAILED); memset(state, 0, sizeof(*state));
    int commands[2], retained[2], output[2]; assert(!pipe(commands) && !socketpair(AF_UNIX, SOCK_STREAM, 0, retained) && !pipe(output));
    recovery_reader = commands[0]; if (fixture_mode == 1) { close(commands[1]); commands[1] = -1; }
    else if (fixture_mode >= 6) assert(write(commands[1], "R", 1) == 1);
    else if (fixture_mode != 4) assert(write(commands[1], "X", 1) == 1);
    pid_t worker = fork(); assert(worker >= 0);
    if (!worker) {
        close(retained[1]); close(output[0]); if (commands[1] >= 0) close(commands[1]);
        struct envara_app_supervisor_provider provider = {.ticket = {.verify = fixture_verify}};
        struct envara_app_supervisor_report report = {0}; struct envara_gui_lifecycle child = {0};
        child.phase = ENVARA_GUI_EXITED; child.child.error_fd = -1; child.leader_reaped = 1;
        if (fixture_mode == 4) {
            pid_t direct = fork(); assert(direct >= 0);
            if (!direct) { close(retained[0]); close(commands[0]); close(output[1]); while (!state->child_exit) pause_ms(10); _exit(0); }
            assert(!envara_identity_read(direct, &child.child.identity)); child.leader_reaped = 0; child.phase = ENVARA_GUI_UNCERTAIN;
        }
        if (fixture_mode >= 6) {
            pid_t direct = fork(); assert(direct >= 0);
            if (!direct) { while (1) pause(); }
            assert(!envara_identity_read(direct, &child.child.identity));
            assert(!kill(direct, SIGKILL)); int terminal; assert(waitpid(direct, &terminal, 0) == direct);
            assert(WIFSIGNALED(terminal) && WTERMSIG(terminal) == SIGKILL);
            child.leader_reaped = 1; report.guardian.child_reaped = fixture_mode == 6;
            state->deny_allowed = state->scope_allowed = 1;
        }
        struct keeper k = {.provider = &provider, .report = &report, .child = &child, .output = output[1], .prepared = 1,
            .guard = {.recovery_fd = commands[0], .retained_fd = retained[0]},
            .authority = {.verify_persistent_deny = fixture_deny, .verify_scope_quiescent = fixture_scope,
                .revoke_owned_network = fixture_network_revoke}};
        state->held = 1; assert(!quarantine(&k));
        assert(child.leader_reaped && report.released && !report.recovery_required && child.scope_quiescent);
        assert(fcntl(retained[0], F_GETFD) >= 0); state->child_reaped = child.leader_reaped;
        state->released = 1; close(retained[0]); close(commands[0]); close(output[1]); _exit(0);
    }
    close(commands[0]); close(retained[0]); close(output[1]);
    double started = now(); while (!state->held && now() - started < 2) pause_ms(5); assert(state->held);
    if (fixture_mode == 4) {
        assert(write(commands[1], "R", 1) == 1); pause_ms(100); still_held(worker, retained[1]); assert(!state->denied && !state->scopes);
        state->child_exit = 1; pause_ms(150);
        assert(write(commands[1], "R", 1) == 1); pause_ms(100); still_held(worker, retained[1]);
#ifdef ENVARA_QUARANTINE_LEGACY
        assert(state->denied && !state->scopes);
#else
        assert(!state->denied && !state->scopes); /* DENY/front authority still refused */
#endif
        state->deny_allowed = 1; assert(write(commands[1], "R", 1) == 1); pause_ms(100); still_held(worker, retained[1]); assert(state->scopes);
        state->scope_allowed = 1; assert(write(commands[1], "X", 1) == 1); pause_ms(100); still_held(worker, retained[1]);
        assert(write(commands[1], "R", 1) == 1); int status; assert(waitpid(worker, &status, 0) == worker && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        assert(state->released && state->child_reaped);
#ifdef ENVARA_QUARANTINE_LEGACY
        assert(state->cancels == 1);
#else
        assert(state->cancels == 0); /* no pre-DENY cancellation; actual child exited itself */
#endif
        printf("{\"mode\":4,\"heldUntilAuthorizedR\":true,\"actualChildReaped\":true,\"ready\":false,\"protected\":false}\n");
    } else if (fixture_mode >= 6) {
        if (fixture_mode == 6) {
            int status; assert(waitpid(worker, &status, 0) == worker && WIFEXITED(status) && WEXITSTATUS(status) == 0);
            assert(state->released && state->child_reaped);
        } else {
            pause_ms(150); still_held(worker, retained[1]);
            assert(!state->released); assert(!kill(worker, SIGKILL)); int status; assert(waitpid(worker, &status, 0) == worker);
        }
        printf("{\"mode\":%d,\"positivePriorReapReleased\":%s,\"unknownPriorReapHeld\":%s,\"ready\":false,\"protected\":false}\n",
            fixture_mode, fixture_mode == 6 ? "true" : "false", fixture_mode == 7 ? "true" : "false");
    } else {
        if (fixture_mode == 5) {
            assert(fcntl(commands[1], F_SETFL, O_NONBLOCK) == 0);
            double until = now() + .6; char unknown[64]; memset(unknown, 'X', sizeof(unknown));
            while (now() < until) {
                errno = 0; ssize_t written = write(commands[1], unknown, sizeof(unknown));
                assert(written == sizeof(unknown) || (written == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)));
                pause_ms(5);
            }
        } else pause_ms(600);
        still_held(worker, retained[1]);
        struct envara_identity identity; assert(!envara_identity_read(worker, &identity) && envara_same_process(&identity));
        assert(!kill(worker, SIGTERM)); int status; struct rusage usage; assert(wait4(worker, &status, 0, &usage) == worker && WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
        double cpu = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6 + usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6;
        printf("{\"mode\":%d,\"polls\":%u,\"reads\":%u,\"cpuSeconds\":%.6f,\"elapsedSeconds\":%.6f,\"actualEOFEvents\":%d,\"heldBeforeOwnFixtureCancellation\":true,\"released\":false,\"ready\":false,\"protected\":false}\n",
            fixture_mode, state->polls, state->reads, cpu, now() - started, state->actual_eof_events);
    }
    if (commands[1] >= 0) close(commands[1]); close(retained[1]); close(output[0]); assert(!munmap(state, sizeof(*state))); return 0;
}
