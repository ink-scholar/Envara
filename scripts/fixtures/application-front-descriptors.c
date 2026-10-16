/* Nonroot acceptance fixture, not an application launcher.
 *
 * Build with native/macos-pf-routing/launcher.c and -I native/macos-pf-routing.
 * Usage: application-front-descriptors 127.0.0.1|::1 OWNED_TCP_PORT OWNED_CWD
 * The harness must hold its own loopback listener for the entire invocation.
 * No hostname lookup, DNS query, PF, privilege change, or real app is used.
 * Only this executable is cold-started, using the production launcher's
 * current-UID/current-GID fixture mode and dedicated stdio pipes.
 */
#include "native.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { PROBE_FD = 200, OPERATION_MS = 5000 };
static volatile sig_atomic_t interrupted;
static int descriptor_close_error;
static void interrupted_by(int signal_number) { interrupted = signal_number; }
static const char *boolean(int value) { return value ? "true" : "false"; }

static int clock_ms(uint64_t *value) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 ||
        (uint64_t)now.tv_sec > (UINT64_MAX - OPERATION_MS) / 1000) return -1;
    *value = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
    return 0;
}
static int begin_deadline(uint64_t *deadline) {
    if (clock_ms(deadline)) return -1;
    *deadline += OPERATION_MS; return 0;
}
static int pending(uint64_t deadline) {
    uint64_t now;
    if (interrupted) { errno = EINTR; return 0; }
    if (clock_ms(&now)) return 0;
    if (now >= deadline) { errno = ETIMEDOUT; return 0; }
    return 1;
}
static void close_owned(int *fd) {
    if (*fd >= 0) {
        if (close(*fd) && !descriptor_close_error) descriptor_close_error = errno ? errno : EIO;
        *fd = -1;
    }
}

/* A complete, bounded descriptor enumeration is the absence evidence;
 * proc_pidfdinfo alone could fail because inspection itself was unavailable. */
static int descriptor_listed(pid_t pid, int target, int *present) {
    int needed = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (needed <= 0 || needed > 1024 * 1024) { errno = EIO; return -1; }
    size_t capacity = (size_t)needed + 32 * sizeof(struct proc_fdinfo);
    struct proc_fdinfo *entries = malloc(capacity);
    if (!entries) return -1;
    int length = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, entries, (int)capacity);
    if (length <= 0 || (size_t)length >= capacity || length % sizeof(*entries)) {
        free(entries); errno = EIO; return -1;
    }
    *present = 0;
    for (size_t i = 0; i < (size_t)length / sizeof(*entries); i++)
        if (entries[i].proc_fd == target) *present = 1;
    free(entries); return 0;
}

static int connected_socket(const char *host, const char *port_text) {
    char *end = NULL; errno = 0;
    unsigned long port = strtoul(port_text, &end, 10);
    int ipv6 = !strcmp(host, "::1");
    if (errno || !port_text[0] || !end || *end || port < 1024 || port > 65535 ||
        (!ipv6 && strcmp(host, "127.0.0.1"))) { errno = EINVAL; return -1; }
    int fd = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int original_flags = fcntl(fd, F_GETFL);
    if (original_flags < 0 || fcntl(fd, F_SETFL, original_flags | O_NONBLOCK)) goto fail;
    struct sockaddr_storage address = {0}; socklen_t length;
    if (ipv6) {
        struct sockaddr_in6 *v6 = (void *)&address;
        v6->sin6_len = sizeof(*v6); v6->sin6_family = AF_INET6;
        v6->sin6_port = htons((uint16_t)port); length = sizeof(*v6);
        if (inet_pton(AF_INET6, host, &v6->sin6_addr) != 1) goto fail;
    } else {
        struct sockaddr_in *v4 = (void *)&address;
        v4->sin_len = sizeof(*v4); v4->sin_family = AF_INET;
        v4->sin_port = htons((uint16_t)port); length = sizeof(*v4);
        if (inet_pton(AF_INET, host, &v4->sin_addr) != 1) goto fail;
    }
    if (connect(fd, (struct sockaddr *)&address, length)) {
        if (errno != EINPROGRESS) goto fail;
        uint64_t deadline;
        if (begin_deadline(&deadline)) goto fail;
        struct pollfd waiter = {fd, POLLOUT, 0}; int result = 0;
        while (pending(deadline)) {
            result = poll(&waiter, 1, 50);
            if (result > 0) break;
            if (result < 0 && errno != EINTR) goto fail;
        }
        if (result <= 0) goto fail;
        int socket_error = 0; socklen_t size = sizeof(socket_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &size)) goto fail;
        if (socket_error) { errno = socket_error; goto fail; }
    }
    if (fcntl(fd, F_SETFL, original_flags)) goto fail;
    return fd;
fail: {
    int error = errno ? errno : EIO; close(fd); errno = error; return -1;
    }
}

static int own_child_mode(void) {
    errno = 0;
    int result = fcntl(PROBE_FD, F_GETFD), error = result < 0 ? errno : 0;
    int closed = result < 0 && error == EBADF;
    if (printf("{\"fd200Closed\":%s,\"fdError\":%d}\n", boolean(closed), error) < 0 || fflush(stdout)) return 2;
    return closed ? 0 : 1;
}

static int read_child_report(int fd, char *output, size_t capacity) {
    uint64_t deadline; size_t used = 0;
    if (begin_deadline(&deadline)) return -1;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) return -1;
    while (pending(deadline)) {
        struct pollfd waiter = {fd, POLLIN | POLLHUP, 0};
        int result = poll(&waiter, 1, 50);
        if (result < 0) { if (errno == EINTR) continue; return -1; }
        if (!result) continue;
        if (used + 1 >= capacity) { errno = EOVERFLOW; return -1; }
        ssize_t count = read(fd, output + used, capacity - used - 1);
        if (count < 0) { if (errno == EINTR || errno == EAGAIN) continue; return -1; }
        if (!count) { output[used] = 0; return 0; }
        used += (size_t)count;
    }
    return -1;
}

static int reap_bounded(pid_t pid, int *status, int obey_interrupt) {
    uint64_t deadline, now;
    if (begin_deadline(&deadline)) return -1;
    for (;;) {
        pid_t result = waitpid(pid, status, WNOHANG);
        if (result == pid) return 0;
        if (result < 0 && errno != EINTR) return -1;
        if ((obey_interrupt && interrupted) || clock_ms(&now) || now >= deadline) {
            errno = interrupted && obey_interrupt ? EINTR : ETIMEDOUT; return -1;
        }
        struct timespec pause = {0, 10000000}; (void)nanosleep(&pause, NULL);
    }
}

int main(int argc, char **argv) {
    if (!getuid() || getuid() != geteuid() || getgid() != getegid()) return 64;
    if (argc == 2 && !strcmp(argv[1], "--exec-child")) return own_child_mode();
    if (argc != 4) return 64;
    struct sigaction action = {0}; action.sa_handler = interrupted_by; sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) return 65;
    (void)signal(SIGPIPE, SIG_IGN);

    int socket_fd = -1, fixed_fd = -1, input[2] = {-1, -1}, output[2] = {-1, -1};
    struct envara_child child = {0}; child.error_fd = -1;
    int parent_listed = 0, parent_connected = 0, parent_noncloexec = 0, stopped_absent = 0, stopped_query_error = 0;
    int child_closed = 0, reaped = 0, status = 0, error = 0, cleanup_error = 0, native_exec_error = 0;
    int staged = 0, resumed = 0;
    const char *stage = "arguments";
    char executable[PATH_MAX], image[PATH_MAX], cwd[PATH_MAX], child_output[128] = {0}, expected[128];
    uint32_t image_capacity = sizeof(image);
    struct stat file;
    if (_NSGetExecutablePath(image, &image_capacity) || !realpath(image, executable) ||
        lstat(executable, &file) || !S_ISREG(file.st_mode) || file.st_uid != getuid() ||
        (file.st_mode & (S_ISUID | S_ISGID | S_IWGRP | S_IWOTH)) ||
        !realpath(argv[3], cwd) || lstat(cwd, &file) || !S_ISDIR(file.st_mode) ||
        file.st_uid != getuid() || (file.st_mode & (S_IWGRP | S_IWOTH))) { error = errno ? errno : EACCES; goto cleanup; }

    stage = "owned-loopback-connect";
    socket_fd = connected_socket(argv[1], argv[2]);
    if (socket_fd < 0) { error = errno; goto cleanup; }
    stage = "reserve-fd-200";
    errno = 0;
    if (fcntl(PROBE_FD, F_GETFD) >= 0 || errno != EBADF) { error = EBUSY; goto cleanup; }
    if (dup2(socket_fd, PROBE_FD) != PROBE_FD) { error = errno; goto cleanup; }
    fixed_fd = PROBE_FD;
    if (fcntl(fixed_fd, F_SETFD, 0)) { error = errno; goto cleanup; }
    close_owned(&socket_fd);

    stage = "parent-positive-control";
    struct sockaddr_storage peer = {0}; socklen_t peer_size = sizeof(peer);
    struct socket_fdinfo socket_info;
    parent_connected = getpeername(fixed_fd, (struct sockaddr *)&peer, &peer_size) == 0 &&
        proc_pidfdinfo(getpid(), fixed_fd, PROC_PIDFDSOCKETINFO, &socket_info, sizeof(socket_info)) == sizeof(socket_info);
    if (!parent_connected || descriptor_listed(getpid(), fixed_fd, &parent_listed) || !parent_listed ||
        fcntl(fixed_fd, F_GETFD) != 0) { error = errno ? errno : EIO; goto cleanup; }
    parent_noncloexec = 1;

    stage = "owned-pipes";
    if (pipe(input) || pipe(output)) { error = errno; goto cleanup; }
    char *child_argv[] = {executable, "--exec-child", NULL};
    char *environment[] = {"PATH=/usr/bin:/bin", "LANG=C", NULL};
    stage = "native-cold-stage";
    if (envara_spawn_suspended_io(getuid(), getgid(), cwd, executable, child_argv, environment,
        1, input[0], output[1], &child)) { error = errno; goto cleanup; }
    staged = 1;
    close_owned(&input[0]); close_owned(&input[1]); close_owned(&output[1]);
    stage = "stopped-child-descriptors";
    int listed = 1;
    if (descriptor_listed(child.identity.pid, PROBE_FD, &listed) || listed) { error = errno ? errno : EIO; goto cleanup; }
    errno = 0;
    int queried = proc_pidfdinfo(child.identity.pid, PROBE_FD, PROC_PIDFDSOCKETINFO, &socket_info, sizeof(socket_info));
    stopped_query_error = errno;
    if (queried > 0) { error = EIO; goto cleanup; }
    stopped_absent = 1;
    if (fcntl(fixed_fd, F_GETFD) != 0) { error = errno ? errno : EIO; goto cleanup; }

    stage = "resume-own-executable";
    if (envara_child_resume(&child)) { error = errno; goto cleanup; }
    resumed = 1;
    stage = "exec-child-report";
    if (read_child_report(output[0], child_output, sizeof(child_output))) { error = errno; goto cleanup; }
    (void)snprintf(expected, sizeof(expected), "{\"fd200Closed\":true,\"fdError\":%d}\n", EBADF);
    child_closed = !strcmp(child_output, expected);
    if (!child_closed) { error = EIO; goto cleanup; }
    stage = "reap-own-child";
    if (reap_bounded(child.identity.pid, &status, 1)) { error = errno; goto cleanup; }
    reaped = 1;
    if (!WIFEXITED(status) || WEXITSTATUS(status)) { error = ECHILD; goto cleanup; }
    stage = "native-exec-confirmation";
    ssize_t bytes = read(child.error_fd, &native_exec_error, sizeof(native_exec_error));
    if (bytes != 0) { error = native_exec_error > 0 ? native_exec_error : EIO; goto cleanup; }
    stage = "complete";

cleanup:
    if (child.identity.pid > 0 && !reaped) {
        /* This is our direct fork child, still unreaped: its PID cannot be
         * reused. Never signal a process group or a caller-supplied PID. */
        pid_t result = waitpid(child.identity.pid, &status, WNOHANG);
        if (result == child.identity.pid) reaped = 1;
        else if (result == 0 || (result < 0 && errno == EINTR)) {
            if (kill(child.identity.pid, SIGKILL) && errno != ESRCH) cleanup_error = errno;
            if (!reap_bounded(child.identity.pid, &status, 0)) reaped = 1;
            else if (!cleanup_error) cleanup_error = errno;
        } else cleanup_error = errno ? errno : ECHILD;
    }
    close_owned(&child.error_fd); close_owned(&socket_fd); close_owned(&fixed_fd);
    close_owned(&input[0]); close_owned(&input[1]); close_owned(&output[0]); close_owned(&output[1]);
    if (descriptor_close_error && !cleanup_error) cleanup_error = descriptor_close_error;
    if (cleanup_error && !error) stage = "cleanup";
    int okay = !error && !cleanup_error && parent_connected && parent_listed && parent_noncloexec && staged && stopped_absent && resumed && child_closed && reaped;
    printf("{\"ok\":%s,\"fixtureOnly\":true,\"ready\":false,\"protected\":false,\"activatesSystem\":false,"
        "\"parentConnectedFD200Present\":%s,\"parentFD200Listed\":%s,\"parentFD200NonCloexec\":%s,"
        "\"nativeColdStageUsed\":%s,\"stoppedFD200Absent\":%s,\"stoppedFDQueryError\":%d,"
        "\"resumed\":%s,\"execChildFD200Closed\":%s,\"ownedChildReaped\":%s,\"ownedDescriptorsClosed\":%s,"
        "\"nativeExecError\":%d,\"failureStage\":\"%s\",\"error\":%d,\"cleanupError\":%d}\n",
        boolean(okay), boolean(parent_connected), boolean(parent_listed), boolean(parent_noncloexec), boolean(staged), boolean(stopped_absent),
        stopped_query_error, boolean(resumed), boolean(child_closed), boolean(reaped), boolean(!descriptor_close_error), native_exec_error,
        stage, error, cleanup_error);
    return okay ? 0 : 1;
}
