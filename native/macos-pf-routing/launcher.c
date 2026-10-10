#include "native.h"
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <unistd.h>
#include <spawn.h>
#include <signal.h>
#include <fcntl.h>
#include <grp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>

static int monotonic_milliseconds(uint64_t *out) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L ||
        (uint64_t)now.tv_sec > (UINT64_MAX - 7000) / 1000) return -1;
    *out = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
    return 0;
}

static void cancel_rejected_stopped_child(pid_t pid, struct envara_child *out) {
    /* This is the direct fork PID, still unreaped: it cannot have been reused.
     * A failed signal/identity lookup is never terminal wait evidence. Keep
     * the owned identity/error reader unless this exact child is reaped. */
    uint64_t now, deadline;
    int timed = !monotonic_milliseconds(&now);
    deadline = timed ? now + 2000 : 0;
    (void)kill(pid, SIGKILL);
    while (timed) {
        if (monotonic_milliseconds(&now) || now >= deadline) break;
        int status = 0;
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid && (WIFEXITED(status) || WIFSIGNALED(status))) {
            close(out->error_fd);
            memset(out, 0, sizeof(*out)); out->error_fd = -1;
            return;
        }
        if (result != 0 && !(result < 0 && errno == EINTR)) break;
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
        (void)nanosleep(&pause, NULL);
    }
}

static int terminal_child_error(struct envara_child *out) {
    /* A terminal wait is already authoritative. Do not turn a damaged error
     * pipe into another unbounded wait while reporting the fixed errno. */
    int error = EIO, flags = fcntl(out->error_fd, F_GETFL);
    if (flags >= 0 && !fcntl(out->error_fd, F_SETFL, flags | O_NONBLOCK)) {
        int reported = 0;
        ssize_t count = read(out->error_fd, &reported, sizeof(reported));
        if (count == sizeof(reported) && reported > 0 && reported <= 1024) error = reported;
    }
    close(out->error_fd);
    memset(out, 0, sizeof(*out)); out->error_fd = -1;
    errno = error; return -1;
}

int envara_console_uid(uid_t *uid) {
    struct stat info;
    if (!uid || stat("/dev/console", &info) || info.st_uid == 0) {
        errno = EACCES; return -1;
    }
    *uid = info.st_uid; return 0;
}

int envara_identity_read(pid_t pid, struct envara_identity *out) {
    struct proc_bsdinfo info;
    if (!out || pid < 2) { errno = EINVAL; return -1; }
    memset(&info, 0, sizeof(info));
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) {
        if (!errno) errno = EIO;
        return -1;
    }
    if (info.pbi_pid != (uint32_t)pid || !info.pbi_start_tvsec) { errno = ESRCH; return -1; }
    *out = (struct envara_identity){ pid, (pid_t)info.pbi_ppid, info.pbi_uid, info.pbi_ruid, info.pbi_svuid,
        info.pbi_gid, info.pbi_rgid, info.pbi_svgid, info.pbi_start_tvsec, info.pbi_start_tvusec };
    return 0;
}

int envara_identity_matches(const struct envara_identity *actual, uid_t uid, gid_t gid) {
    return actual && actual->uid == uid && actual->ruid == uid && actual->saved_uid == uid &&
        actual->gid == gid && actual->rgid == gid && actual->saved_gid == gid;
}

int envara_same_process(const struct envara_identity *expected) {
    struct envara_identity now;
    if (!expected || envara_identity_read(expected->pid, &now)) return 0;
    return now.birth_seconds == expected->birth_seconds && now.birth_microseconds == expected->birth_microseconds &&
        now.uid == expected->uid && now.ruid == expected->ruid && now.saved_uid == expected->saved_uid &&
        now.gid == expected->gid && now.rgid == expected->rgid && now.saved_gid == expected->saved_gid;
}

static int valid_path(const char *path, int directory) {
    struct stat info;
    if (!path || path[0] != '/' || strlen(path) >= PATH_MAX || stat(path, &info)) return 0;
    if (directory) return S_ISDIR(info.st_mode);
    return S_ISREG(info.st_mode) && (info.st_mode & 0111) && !(info.st_mode & (S_ISUID | S_ISGID));
}

int envara_root_owned_executable(const char *path) {
    struct stat info;
    char resolved[PATH_MAX];
    if (!path || !realpath(path, resolved) || strcmp(path, resolved) ||
        lstat(resolved, &info) || !S_ISREG(info.st_mode) || !(info.st_mode & 0111) ||
        info.st_uid != 0 || (info.st_mode & (S_ISUID | S_ISGID | S_IWGRP | S_IWOTH))) return 0;
    char *separator = strrchr(resolved, '/');
    while (separator && separator != resolved) {
        *separator = 0;
        if (lstat(resolved, &info) || !S_ISDIR(info.st_mode) || info.st_uid != 0 ||
            (info.st_mode & (S_IWGRP | S_IWOTH))) return 0;
        separator = strrchr(resolved, '/');
    }
    return 1;
}

static int dedicated_group(gid_t gid) {
    /* Setup owns allocation. Refuse an existing ordinary group, including a
     * group shared by unprotected applications. No group is created here. */
    if (gid < ENVARA_REALM_GID_MIN || gid > ENVARA_REALM_GID_MAX) return 0;
    struct group *group = getgrgid(gid);
    char expected[64];
    snprintf(expected, sizeof(expected), "_envara_pf_%u", gid);
    return group && group->gr_name && !strcmp(group->gr_name, expected);
}

static void child_failure(int fd, int error) {
    /* Fixed numeric error only: never emit environment values or arguments. */
    (void)write(fd, &error, sizeof(error));
    _exit(126);
}
int envara_close_inherited_descriptors(const int *held, size_t count) {
    if ((count && !held) || count > 16) { errno = EINVAL; return -1; }
    for (size_t i = 0; i < count; i++) {
        if (held[i] < 3 || fcntl(held[i], F_GETFD) < 0) { errno = EINVAL; return -1; }
        for (size_t j = 0; j < i; j++) if (held[j] == held[i]) { errno = EINVAL; return -1; }
    }
    /* Enumerate, rather than assume RLIMIT_NOFILE bounds already open FDs.
     * Two snapshots refuse an unknown survivor instead of inheriting it. */
    for (int pass = 0; pass < 2; pass++) {
        int needed = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
        if (needed <= 0 || needed > 8 * 1024 * 1024) { errno = EIO; return -1; }
        size_t capacity = (size_t)needed + sizeof(struct proc_fdinfo) * 32;
        struct proc_fdinfo *entries = malloc(capacity); if (!entries) return -1;
        int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, entries, (int)capacity);
        if (bytes <= 0 || (size_t)bytes >= capacity || bytes % sizeof(*entries)) { free(entries); errno = EIO; return -1; }
        for (size_t i = 0; i < (size_t)bytes / sizeof(*entries); i++) {
            int fd = entries[i].proc_fd; if (fd < 3) continue;
            int keep = 0; for (size_t j = 0; j < count; j++) if (held[j] == fd) keep = 1;
            if (keep) {
                if (fcntl(fd, F_SETFD, FD_CLOEXEC)) { int error = errno; free(entries); errno = error; return -1; }
            } else if (pass == 1) { free(entries); errno = EBUSY; return -1; }
            else if (close(fd)) { int error = errno; free(entries); errno = error; return -1; }
        }
        free(entries);
    }
    return 0;
}

int envara_spawn_suspended_io(uid_t uid, gid_t gid, const char *cwd,
                           const char *executable, char *const argv[],
                           char *const environment[], int fixture_mode,
                           int stdin_fd, int stdout_fd,
                           struct envara_child *out) {
    uid_t console_uid = 0;
    int pipefd[2], result, status;
    pid_t pid;
    if (!out || !argv || !argv[0] || !environment || uid == 0 || gid == 0 ||
        !valid_path(cwd, 1) || !valid_path(executable, 0)) { errno = EINVAL; return -1; }
    if (fixture_mode) {
        if (getuid() == 0 || geteuid() != getuid() || uid != getuid() || gid != getgid() || getegid() != gid) {
            errno = EACCES; return -1;
        }
    } else if (geteuid() != 0 || getuid() != 0 || envara_console_uid(&console_uid) ||
               uid != console_uid || !dedicated_group(gid)) {
        errno = EACCES; return -1;
    }
    if (pipe(pipefd)) return -1;
    if (fcntl(pipefd[0], F_SETFD, FD_CLOEXEC) || fcntl(pipefd[1], F_SETFD, FD_CLOEXEC)) {
        result = errno; close(pipefd[0]); close(pipefd[1]); errno = result; return -1;
    }
    pid = fork();
    if (pid < 0) { result = errno; close(pipefd[0]); close(pipefd[1]); errno = result; return -1; }
    if (!pid) {
        struct envara_identity identity;
        posix_spawnattr_t attributes;
        posix_spawn_file_actions_t actions;
        close(pipefd[0]);
        if (setpgid(0, 0)) child_failure(pipefd[1], errno);
        if (!fixture_mode || stdin_fd >= 0 || stdout_fd >= 0) {
            /* Dedicated fixture pipes are not the guardian's control pipe.
             * The guardian wraps child responses as bounded JSON strings. */
            int nullfd = open("/dev/null", O_RDWR);
            if (nullfd < 0) child_failure(pipefd[1], errno);
            int sources[] = { stdin_fd >= 0 ? stdin_fd : nullfd, stdout_fd >= 0 ? stdout_fd : nullfd, nullfd };
            for (int fd = 0; fd < 3; fd++) if (dup2(sources[fd], fd) < 0) child_failure(pipefd[1], errno);
            if (nullfd > 2) close(nullfd);
        }
        /* The cold child must not hold the guardian's original utun/listener
         * or control/configuration FDs while stopped. Preserve only its error
         * writer after mapping stdio, BEFORE credential transition and stop. */
        if (envara_close_inherited_descriptors(&pipefd[1], 1)) child_failure(pipefd[1], errno);
        if (!fixture_mode) {
            /* No ordinary supplementary groups or socket-GID escape. */
            if (setgroups(1, &gid) || setgid(gid) || setuid(uid)) child_failure(pipefd[1], errno);
        }
        if (envara_identity_read(getpid(), &identity) || !envara_identity_matches(&identity, uid, gid))
            child_failure(pipefd[1], EACCES);
        if (chdir(cwd)) child_failure(pipefd[1], errno);
        umask(077);
        /* Child has no target code yet. Parent verifies the actual IDs and
         * birth generation, then commits all enforcement before SIGCONT. */
        if (raise(SIGSTOP)) child_failure(pipefd[1], errno);
        result = posix_spawnattr_init(&attributes);
        if (result) child_failure(pipefd[1], result);
        result = posix_spawn_file_actions_init(&actions);
        if (result) child_failure(pipefd[1], result);
        result = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETEXEC | POSIX_SPAWN_CLOEXEC_DEFAULT);
        if (result) child_failure(pipefd[1], result);
        for (int fd = 0; fd < 3; fd++) {
            if (fcntl(fd, F_GETFD) < 0) child_failure(pipefd[1], EBADF);
            result = posix_spawn_file_actions_addinherit_np(&actions, fd);
            if (result) child_failure(pipefd[1], result);
        }
        /* Cold executable spawn. LaunchServices/open is intentionally not
         * used: it could deliver an event to an existing unscoped process.
         * CLOEXEC_DEFAULT also closes non-CLOEXEC inherited TCP sockets. */
        result = posix_spawn(NULL, executable, &actions, &attributes, argv, environment);
        child_failure(pipefd[1], result ? result : EIO);
    }
    close(pipefd[1]);
    memset(out, 0, sizeof(*out));
    /* Preserve custody even when the parent cannot read the birth/IDs. A
     * positive terminal wait can clear this PID; missing lookup data cannot. */
    out->identity.pid = pid; out->identity.parent_pid = getpid();
    out->error_fd = pipefd[0];
    uint64_t now, deadline;
    if (monotonic_milliseconds(&now)) {
        cancel_rejected_stopped_child(pid, out); errno = EIO; return -1;
    }
    deadline = now + 5000;
    for (;;) {
        int clock_failed = monotonic_milliseconds(&now);
        if (clock_failed || now >= deadline) {
            int error = clock_failed ? EIO : ETIMEDOUT;
            cancel_rejected_stopped_child(pid, out); errno = error; return -1;
        }
        result = waitpid(pid, &status, WNOHANG | WUNTRACED);
        if (result == pid) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) return terminal_child_error(out);
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) break;
            cancel_rejected_stopped_child(pid, out); errno = EIO; return -1;
        }
        if (result < 0) {
            if (errno == EINTR) continue; /* The next turn still checks time. */
            /* ECHILD/unknown wait is not a terminal reap or safe PID signal. */
            return -1;
        }
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
        (void)nanosleep(&pause, NULL);
    }
    struct envara_identity actual;
    if (envara_identity_read(pid, &actual)) {
        cancel_rejected_stopped_child(pid, out); errno = EACCES; return -1;
    }
    out->identity = actual;
    if (actual.parent_pid != getpid() || !envara_identity_matches(&actual, uid, gid)) {
        cancel_rejected_stopped_child(pid, out); errno = EACCES; return -1;
    }
    return 0;
}

int envara_spawn_suspended(uid_t uid, gid_t gid, const char *cwd,
                           const char *executable, char *const argv[],
                           char *const environment[], int fixture_mode,
                           struct envara_child *out) {
    return envara_spawn_suspended_io(uid, gid, cwd, executable, argv, environment, fixture_mode, -1, -1, out);
}

int envara_child_resume(struct envara_child *child) {
    if (!child || !envara_same_process(&child->identity)) { errno = ESRCH; return -1; }
    return kill(child->identity.pid, SIGCONT);
}

int envara_child_cancel(struct envara_child *child) {
    if (!child || !envara_same_process(&child->identity)) { errno = ESRCH; return -1; }
    return kill(child->identity.pid, SIGKILL);
}
