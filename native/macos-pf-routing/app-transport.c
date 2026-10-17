#include "app-transport.h"
#include "app-native-factory.h"
#include "transport-session.h"
#include "gui-launch.h"
#include "launch-guardian.h"
#include "app-scope-proof.h"
#include "pf-hook.h"
#include "pf-hook-abi.h"
#include <CommonCrypto/CommonDigest.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/proc_info.h>
#include <sys/proc.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libproc.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <limits.h>

#define INSTALL "/Library/PrivilegedHelperTools/io.envara.pf-routing"
#define RUNTIME "/Library/PrivilegedHelperTools/io.envara.pf-runtime"
static int fixed_entry(void);
static volatile sig_atomic_t stopped;
static void stop_signal(int number) { stopped = number; }
static int refuse(int error) { errno = error; return -1; }
/* A live mode carries admission and needs held original descriptors plus live
 * dependencies; DENY/EMPTY never do. Kept local so this file never guesses the
 * factory's profile — it asks the factory which mode is live. */
static int mode_is_live_mode(EnvaraPFProductionMode mode) {
    return mode == ENVARA_PF_PRODUCTION_FRONT || mode == ENVARA_PF_PRODUCTION_ROUTED;
}
static int write_bounded(int fd,const char *buffer,size_t count);
static void refused_event_reason(const char *run,const char *environment,const char *stage,const char *reason,int error) {
    char frame[768]; int saved_errno=errno; if (error < 1 || error > 1024) error = EIO;
    int n = snprintf(frame, sizeof(frame),
        "{\"schema\":\"%s\",\"event\":\"transport-refused\",\"runId\":\"%s\",\"environmentId\":\"%s\","
        "\"stage\":\"%s\",\"reason\":\"%s\",\"error\":%d,\"ready\":false,\"protected\":false}\n",
        ENVARA_APP_TRANSPORT_PROTOCOL, run, environment, stage,reason,error);
    /* Complete bounded frame; short writes/EAGAIN must not silently discard
     * the only original diagnostic. Sending never changes saved errno. */
    if (n > 0 && n < (int)sizeof(frame)) (void)write_bounded(1,frame,(size_t)n);
    errno=saved_errno;
}
static void refused_event(const char *run,const char *environment,const char *stage,int error) {
    refused_event_reason(run,environment,stage,envara_app_native_failure_reason(),error);
}
static int uuid(const char *s) {
    if (!s || strnlen(s, 37) != 36 || s[14] != '4' || !strchr("89ab", s[19])) return 0;
    for (int i = 0; i < 36; i++) if (i == 8 || i == 13 || i == 18 || i == 23) { if (s[i] != '-') return 0; }
        else if (!strchr("0123456789abcdef", s[i])) return 0; return 1;
}
static uint64_t milliseconds(void) {
    struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static void erase(void *p, size_t size) { volatile unsigned char *bytes = p; while (size--) *bytes++ = 0; }
static int line(int fd, char *buffer, size_t size, unsigned timeout) {
    size_t count = 0; uint64_t now = milliseconds(), deadline = now + timeout;
    if (!now || !timeout) return refuse(EIO);
    while (!stopped) {
        now = milliseconds(); if (!now || now >= deadline) return refuse(ETIMEDOUT);
        struct pollfd poller = {fd, POLLIN | POLLHUP, 0}; int ready = poll(&poller, 1, (int)(deadline-now));
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 1) return refuse(ready == 0 ? ETIMEDOUT : errno);
        char c; ssize_t n = read(fd, &c, 1);
        if (n != 1) return refuse(n == 0 ? EPIPE : errno);
        if (c == '\n') { buffer[count] = 0; return 0; }
        if (!c || c == '\r' || count + 1 >= size) return refuse(EINVAL);
        buffer[count++] = c;
    }
    return refuse(ECANCELED);
}
static int write_bounded(int fd, const char *buffer, size_t count) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) return -1;
    uint64_t deadline = milliseconds() + 3000;
    while (count) {
        uint64_t now = milliseconds(); if (!now || now >= deadline) return refuse(ETIMEDOUT);
        struct pollfd p = {fd, POLLOUT, 0}; int ready=poll(&p,1,(int)(deadline-now));
        if(ready<0&&errno==EINTR)continue;if(ready<0)return -1;if(!ready)return refuse(ETIMEDOUT);
        ssize_t n = write(fd, buffer, count); if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) return refuse(EPIPE); buffer += n; count -= (size_t)n;
    }
    return 0;
}
static int pipe_private(int pair[2]) {
    if (pipe(pair)) return -1;
    if (fcntl(pair[0], F_SETFD, FD_CLOEXEC) || fcntl(pair[1], F_SETFD, FD_CLOEXEC)) {
        int error = errno; close(pair[0]); close(pair[1]); return refuse(error);
    }
    return 0;
}
struct abort_pin {
    int run_fd, lease_fd;
    struct stat run, lease;
    char run_path[PATH_MAX], sha256[65];
    uid_t owner;
};
struct abort_proof {
    struct envara_app_native_preflight plan;
    struct envara_identity keeper, parent, core, front;
    struct stat utun, listener, lease, run;
    struct socket_fdinfo utun_socket, listener_socket;
    char utun_name[16];
    uint32_t control_id, control_unit;
    uint16_t port;
    int factory_failed, deny_attempted, filter_attempted, launch_accepted, cold_attempted;
    int captured, core_reaped, front_reaped, scope_before, scope_after, journal_before, journal_after;
    int utun_closed, listener_closed;
};
static int abort_same_stat(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
static int abort_digest(int fd, char out[65]) {
    struct stat before, after; if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_size < 1 || before.st_size > 16384) return refuse(EACCES);
    unsigned char bytes[16384], digest[CC_SHA256_DIGEST_LENGTH]; size_t offset = 0;
    while (offset < (size_t)before.st_size) {
        ssize_t n = pread(fd, bytes + offset, (size_t)before.st_size - offset, (off_t)offset);
        if (n < 0 && errno == EINTR) continue; if (n <= 0) { erase(bytes, sizeof(bytes)); return refuse(EIO); } offset += (size_t)n;
    }
    if (memchr(bytes, 0, offset) || fstat(fd, &after) || !abort_same_stat(&before, &after)) { erase(bytes, sizeof(bytes)); return refuse(ESTALE); }
    CC_SHA256(bytes, (CC_LONG)offset, digest); erase(bytes, sizeof(bytes));
    for (size_t i = 0; i < sizeof(digest); i++) snprintf(out + 2*i, 3, "%02x", digest[i]); out[64] = 0; return 0;
}
static int abort_metadata(int fd, uid_t owner, int directory) {
    struct stat s; char path[PATH_MAX];
    if (fstat(fd, &s) || (directory ? !S_ISDIR(s.st_mode) : !S_ISREG(s.st_mode)) || s.st_uid != owner ||
        (!owner && s.st_gid) || (s.st_mode & 07777) != (directory ? 0700 : 0600) || (!directory && s.st_nlink != 1) ||
        fcntl(fd, F_GETPATH, path) || envara_gui_acl_free(path)) return refuse(EACCES);
    return 0;
}
/* The preflight already parsed all twenty private fields. Pin those exact raw
 * bytes by SHA instead of introducing another JSON parser or accepting claims. */
static int abort_pin_at(int run_fd, const char *run_path, const char *sha256, uid_t owner, struct abort_pin *out) {
    memset(out, 0, sizeof(*out)); out->run_fd = out->lease_fd = -1;
    if (!run_path || strlen(run_path) >= sizeof(out->run_path) || !sha256 || strlen(sha256) != 64) return refuse(EINVAL);
    for (const char *p = sha256; *p; p++) if (!strchr("0123456789abcdef", *p)) return refuse(EINVAL);
    out->owner = owner; strcpy(out->run_path, run_path); strcpy(out->sha256, sha256);
    out->run_fd = fcntl(run_fd, F_DUPFD_CLOEXEC, 3);
    if (out->run_fd < 0 || abort_metadata(out->run_fd, owner, 1) || fstat(out->run_fd, &out->run)) return -1;
    out->lease_fd = openat(out->run_fd, "app-bound-lease.json", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    char actual[65]; struct stat named;
    if (out->lease_fd < 0 || abort_metadata(out->lease_fd, owner, 0) || fstat(out->lease_fd, &out->lease) ||
        fstatat(out->run_fd, "app-bound-lease.json", &named, AT_SYMLINK_NOFOLLOW) || !abort_same_stat(&out->lease, &named) ||
        abort_digest(out->lease_fd, actual) || strcmp(actual, sha256)) return refuse(ESTALE);
    return 0;
}
static void abort_pin_close(struct abort_pin *pin) {
    if (pin->lease_fd >= 0) close(pin->lease_fd); if (pin->run_fd >= 0) close(pin->run_fd);
    pin->lease_fd = pin->run_fd = -1;
}
static int abort_pin_open(const struct envara_app_native_preflight *plan, struct abort_pin *out) {
    char path[PATH_MAX], canonical[PATH_MAX], current[PATH_MAX];
    if (getuid() || geteuid() || !uuid(plan->run_id) ||
        snprintf(path, sizeof(path), RUNTIME "/%s", plan->run_id) >= (int)sizeof(path) ||
        !realpath(path, canonical) || strcmp(path, canonical)) return refuse(EACCES);
    strcpy(current, path);
    for (;;) {
        struct stat s;
        if (lstat(current, &s) || !S_ISDIR(s.st_mode) || s.st_uid || (s.st_mode & (S_ISUID | S_ISGID | 0022)) || envara_gui_acl_free(current)) return refuse(EACCES);
        char *slash = strrchr(current, '/'); if (!slash || slash == current) break; *slash = 0;
    }
    if (envara_gui_acl_free("/")) return -1;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); if (fd < 0) return -1;
    int result = abort_pin_at(fd, path, plan->lease_sha256, 0, out), error = errno; close(fd); errno = error; return result;
}
static int abort_pin_fresh(const struct abort_pin *pin) {
    struct stat lease, named, run, current; char path[PATH_MAX], digest[65];
    if (pin->run_fd < 0 || pin->lease_fd < 0 || fstat(pin->lease_fd, &lease) || !abort_same_stat(&lease, &pin->lease) ||
        fstatat(pin->run_fd, "app-bound-lease.json", &named, AT_SYMLINK_NOFOLLOW) || !abort_same_stat(&lease, &named) ||
        fstat(pin->run_fd, &run) || !abort_same_stat(&run, &pin->run) || !realpath(pin->run_path, path) || strcmp(path, pin->run_path) ||
        lstat(path, &current) || !abort_same_stat(&run, &current) || abort_digest(pin->lease_fd, digest) || strcmp(digest, pin->sha256)) return refuse(ESTALE);
    return 0;
}
static int abort_journal_absent(const struct abort_pin *pin) {
    struct stat s; errno = 0;
    return fstatat(pin->run_fd, "app-filter-events", &s, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT;
}
static int abort_socket_capture(int fd, struct stat *s, struct socket_fdinfo *socket) {
    int flags = fcntl(fd, F_GETFD);
    if (fd < 3 || flags < 0 || !(flags & FD_CLOEXEC) || fstat(fd, s) || !S_ISSOCK(s->st_mode) ||
        proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, socket, sizeof(*socket)) != sizeof(*socket)) return refuse(EACCES);
    return 0;
}
static int abort_socket_same(int fd, const struct stat *expected, const struct socket_fdinfo *socket) {
    struct stat s; struct socket_fdinfo actual;
    return !abort_socket_capture(fd, &s, &actual) && s.st_dev == expected->st_dev && s.st_ino == expected->st_ino &&
        s.st_mode == expected->st_mode && s.st_uid == expected->st_uid && s.st_gid == expected->st_gid &&
        actual.psi.soi_so == socket->psi.soi_so && actual.psi.soi_pcb == socket->psi.soi_pcb &&
        actual.psi.soi_family == socket->psi.soi_family && actual.psi.soi_type == socket->psi.soi_type;
}
static int abort_capture(const struct envara_app_native_preflight *plan, const struct envara_transport_session *session,
                         const struct envara_app_listener *listener, const struct envara_identity *front,
                         const struct abort_pin *pin, struct abort_proof *p) {
    memset(p, 0, sizeof(*p)); p->plan = *plan; p->core = session->core; p->front = *front; p->lease = pin->lease; p->run = pin->run;
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (fixed_entry() || envara_identity_read(getpid(), &p->keeper) || !envara_identity_matches(&p->keeper, 0, 0) ||
        p->keeper.parent_pid < 2 || envara_identity_read(p->keeper.parent_pid, &p->parent) || !envara_identity_matches(&p->parent, 0, 0) ||
        proc_pidpath(p->parent.pid, path, sizeof(path)) <= 0 || (strcmp(path, INSTALL "/node") && strcmp(path, "/bin/launchctl")) ||
        !envara_root_owned_executable(path) || envara_gui_acl_free(path) || !envara_same_process(&p->keeper) || !envara_same_process(&p->parent) ||
        !envara_same_process(&plan->controller) || p->core.parent_pid != getpid() || p->front.parent_pid != getpid() ||
        !envara_same_process(&p->core) || !envara_same_process(&p->front) || envara_app_listener_verify(listener) ||
        abort_pin_fresh(pin) || !abort_journal_absent(pin) || strlen(session->interface_name) >= sizeof(p->utun_name) ||
        abort_socket_capture(session->original_utun_fd, &p->utun, &p->utun_socket) ||
        abort_socket_capture(listener->fd, &p->listener, &p->listener_socket)) return refuse(EACCES);
    struct ctl_info control = {0}; struct sockaddr_ctl peer = {0}; socklen_t length = sizeof(peer), size = sizeof(p->utun_name);
    strcpy(control.ctl_name, "com.apple.net.utun_control");
    if (p->utun_socket.psi.soi_family != AF_SYSTEM || p->utun_socket.psi.soi_type != SOCK_DGRAM ||
        ioctl(session->original_utun_fd, CTLIOCGINFO, &control) || getpeername(session->original_utun_fd, (struct sockaddr *)&peer, &length) ||
        length != sizeof(peer) || peer.sc_family != AF_SYSTEM || peer.ss_sysaddr != AF_SYS_CONTROL || peer.sc_id != control.ctl_id || !peer.sc_unit ||
        getsockopt(session->original_utun_fd, SYSPROTO_CONTROL, 2, p->utun_name, &size) || !memchr(p->utun_name, 0, sizeof(p->utun_name)) ||
        strcmp(session->interface_name, p->utun_name)) return refuse(EACCES);
    p->control_id = peer.sc_id; p->control_unit = peer.sc_unit; p->port = listener->port; p->captured = 1; return 0;
}
static int abort_close_original(int fd) {
    if (fd < 3 || close(fd)) return -1;
    errno = 0; return fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : refuse(EIO);
}
static int abort_originals_fresh(const struct envara_transport_session *session, const struct envara_app_listener *listener,
                                 const struct abort_proof *p) {
    struct ctl_info control = {0}; struct sockaddr_ctl peer = {0}; char name[16] = {0};
    socklen_t length = sizeof(peer), size = sizeof(name); strcpy(control.ctl_name, "com.apple.net.utun_control");
    return abort_socket_same(session->original_utun_fd, &p->utun, &p->utun_socket) &&
        abort_socket_same(listener->fd, &p->listener, &p->listener_socket) && !envara_app_listener_verify(listener) &&
        !ioctl(session->original_utun_fd, CTLIOCGINFO, &control) && !getpeername(session->original_utun_fd, (struct sockaddr *)&peer, &length) &&
        length == sizeof(peer) && peer.sc_family == AF_SYSTEM && peer.ss_sysaddr == AF_SYS_CONTROL && peer.sc_id == p->control_id &&
        peer.sc_id == control.ctl_id && peer.sc_unit == p->control_unit &&
        !getsockopt(session->original_utun_fd, SYSPROTO_CONTROL, 2, name, &size) && memchr(name, 0, sizeof(name)) && !strcmp(name, p->utun_name);
}
static int abort_proof_valid(const struct abort_proof *p) {
    if (!p || strnlen(p->plan.lease_sha256, 65) != 64 || strnlen(p->utun_name, 16) < 5 || strnlen(p->utun_name, 16) >= 16 || strncmp(p->utun_name, "utun", 4)) return 0;
    for (size_t i = 0; i < 64; i++) if (!strchr("0123456789abcdef", p->plan.lease_sha256[i])) return 0;
    for (const char *c = p->utun_name + 4; *c; c++) if (*c < '0' || *c > '9') return 0;
    return p->factory_failed == 1 && p->captured == 1 && !p->deny_attempted && !p->filter_attempted && !p->launch_accepted && !p->cold_attempted &&
        uuid(p->plan.run_id) && uuid(p->plan.environment_id) && uuid(p->plan.realm_id) &&
        p->plan.realm_gid >= ENVARA_REALM_GID_MIN && p->plan.realm_gid <= ENVARA_REALM_GID_MAX &&
        p->keeper.pid > 1 && p->parent.pid > 1 && p->keeper.parent_pid == p->parent.pid && p->keeper.birth_seconds && p->parent.birth_seconds &&
        p->core.pid > 1 && p->front.pid > 1 && p->core.parent_pid == p->keeper.pid && p->front.parent_pid == p->keeper.pid &&
        p->core.birth_seconds && p->front.birth_seconds && p->plan.controller.pid > 1 && p->plan.controller.birth_seconds &&
        p->keeper.birth_microseconds < 1000000 && p->parent.birth_microseconds < 1000000 && p->core.birth_microseconds < 1000000 &&
        p->front.birth_microseconds < 1000000 && p->plan.controller.birth_microseconds < 1000000 &&
        p->core.pid != p->front.pid && p->keeper.pid != p->core.pid && p->keeper.pid != p->front.pid &&
        p->core_reaped == 1 && p->front_reaped == 1 && p->scope_before == 1 && p->scope_after == 1 && p->journal_before == 1 && p->journal_after == 1 &&
        p->utun_closed == 1 && p->listener_closed == 1 && p->port >= 1024 && p->control_id && p->control_unit;
}
static int abort_frame(const struct abort_proof *p, char *frame, size_t size) {
    if (!abort_proof_valid(p)) return refuse(EACCES);
    int n = snprintf(frame, size,
        "{\"schema\":\"%s\",\"event\":\"prestage-aborted\",\"stage\":\"factory-open\",\"runId\":\"%s\",\"environmentId\":\"%s\",\"realmId\":\"%s\",\"gid\":%u,\"leaseSHA256\":\"%s\","
        "\"controllerPID\":%d,\"controllerBirth\":\"%llu:%06llu\",\"keeperPID\":%d,\"keeperBirth\":\"%llu:%06llu\",\"keeperParentPID\":%d,\"keeperParentBirth\":\"%llu:%06llu\","
        "\"corePID\":%d,\"coreBirth\":\"%llu:%06llu\",\"frontPID\":%d,\"frontBirth\":\"%llu:%06llu\","
        "\"leaseDevice\":\"%llu\",\"leaseInode\":\"%llu\",\"runDirectoryDevice\":\"%llu\",\"runDirectoryInode\":\"%llu\","
        "\"utunName\":\"%s\",\"utunDevice\":\"%llu\",\"utunInode\":\"%llu\",\"utunControlId\":%u,\"utunControlUnit\":%u,"
        "\"listenerHost\":\"127.0.0.1\",\"listenerPort\":%u,\"listenerDevice\":\"%llu\",\"listenerInode\":\"%llu\","
        "\"originalUTunVerified\":true,\"originalListenerVerified\":true,\"coreReaped\":true,\"frontReaped\":true,\"gidScopeAbsent\":true,\"filterJournalAbsent\":true,"
        "\"originalUTunClosed\":true,\"originalListenerClosed\":true,\"denyAttempted\":false,\"filterWriteAttempted\":false,\"launchCommandAccepted\":false,\"coldStageAttempted\":false,\"exitStatus\":1,\"ready\":false,\"protected\":false}\n",
        ENVARA_APP_TRANSPORT_PROTOCOL, p->plan.run_id, p->plan.environment_id, p->plan.realm_id, p->plan.realm_gid, p->plan.lease_sha256,
        p->plan.controller.pid, (unsigned long long)p->plan.controller.birth_seconds, (unsigned long long)p->plan.controller.birth_microseconds,
        p->keeper.pid, (unsigned long long)p->keeper.birth_seconds, (unsigned long long)p->keeper.birth_microseconds,
        p->parent.pid, (unsigned long long)p->parent.birth_seconds, (unsigned long long)p->parent.birth_microseconds,
        p->core.pid, (unsigned long long)p->core.birth_seconds, (unsigned long long)p->core.birth_microseconds,
        p->front.pid, (unsigned long long)p->front.birth_seconds, (unsigned long long)p->front.birth_microseconds,
        (unsigned long long)p->lease.st_dev, (unsigned long long)p->lease.st_ino, (unsigned long long)p->run.st_dev, (unsigned long long)p->run.st_ino,
        p->utun_name, (unsigned long long)p->utun.st_dev, (unsigned long long)p->utun.st_ino, p->control_id, p->control_unit, p->port,
        (unsigned long long)p->listener.st_dev, (unsigned long long)p->listener.st_ino);
    return n > 0 && (size_t)n < size ? n : refuse(EOVERFLOW);
}

/* A bootstrap rejection occurs before launchctl, transport descriptors or any
 * child constructor. It needs a different terminal proof: no fictional socket
 * closure/reap facts and no acceptance of a later run/listener preflight. */
struct preflight_abort_proof {
    struct envara_app_native_preflight plan;
    struct envara_identity bootstrap, parent;
    struct stat executable, parent_executable, lease, run;
    char nonce[33];
    int captured, scope_before, scope_after, children_before, children_after;
    int journal_before, journal_after, empty_before, empty_after;
    int bootstrap_attempted, transport_attempted, filter_attempted, cold_attempted;
};
static int preflight_identity_shape(const struct envara_identity *p) {
    return p && p->pid > 1 && p->birth_seconds && p->birth_microseconds < 1000000 &&
        envara_identity_matches(p, 0, 0);
}
static int preflight_proof_file_shape(const struct stat *p, int directory, mode_t mode) {
    return p && (directory ? S_ISDIR(p->st_mode) : S_ISREG(p->st_mode)) && !p->st_uid && !p->st_gid &&
        (p->st_mode & 07777) == mode && (directory || (p->st_nlink == 1 && p->st_size > 0));
}
static int preflight_abort_valid(const struct preflight_abort_proof *p) {
    if (!p || !uuid(p->plan.run_id) || !uuid(p->plan.environment_id) || !uuid(p->plan.realm_id) ||
        p->plan.realm_gid < ENVARA_REALM_GID_MIN || p->plan.realm_gid > ENVARA_REALM_GID_MAX ||
        strnlen(p->plan.lease_sha256, sizeof(p->plan.lease_sha256)) != 64 || strnlen(p->nonce, sizeof(p->nonce)) != 32 || !preflight_identity_shape(&p->bootstrap) ||
        !preflight_identity_shape(&p->parent) || !preflight_identity_shape(&p->plan.controller) ||
        p->bootstrap.parent_pid != p->parent.pid || p->bootstrap.pid == p->parent.pid ||
        memcmp(&p->parent, &p->plan.controller, sizeof(p->parent)) ||
        !preflight_proof_file_shape(&p->lease, 0, 0600) || !preflight_proof_file_shape(&p->run, 1, 0700) ||
        !preflight_proof_file_shape(&p->executable, 0, 0755) || !preflight_proof_file_shape(&p->parent_executable, 0, 0755)) return 0;
    for (size_t i = 0; i < 64; i++) if (!strchr("0123456789abcdef", p->plan.lease_sha256[i])) return 0;
    for (size_t i = 0; i < 32; i++) if (!strchr("0123456789abcdef", p->nonce[i])) return 0;
    return p->captured == 1 && p->scope_before == 1 && p->scope_after == 1 &&
        p->children_before == 1 && p->children_after == 1 && p->journal_before == 1 && p->journal_after == 1 &&
        p->empty_before == 1 && p->empty_after == 1 && !p->bootstrap_attempted && !p->transport_attempted &&
        !p->filter_attempted && !p->cold_attempted;
}
static int preflight_abort_frame(const struct preflight_abort_proof *p, char *frame, size_t size) {
    if (!preflight_abort_valid(p)) return refuse(EACCES);
    int n = snprintf(frame, size,
        "{\"schema\":\"%s\",\"event\":\"preflight-aborted\",\"stage\":\"preflight\",\"runId\":\"%s\",\"environmentId\":\"%s\",\"realmId\":\"%s\",\"gid\":%u,\"leaseSHA256\":\"%s\","
        "\"controllerPID\":%d,\"controllerBirth\":\"%llu:%06llu\",\"bootstrapPID\":%d,\"bootstrapBirth\":\"%llu:%06llu\",\"bootstrapParentPID\":%d,\"bootstrapParentBirth\":\"%llu:%06llu\","
        "\"leaseDevice\":\"%llu\",\"leaseInode\":\"%llu\",\"runDirectoryDevice\":\"%llu\",\"runDirectoryInode\":\"%llu\","
        "\"bootstrapDevice\":\"%llu\",\"bootstrapInode\":\"%llu\",\"bootstrapParentDevice\":\"%llu\",\"bootstrapParentInode\":\"%llu\",\"proofNonce\":\"%s\","
        "\"sealedContextVerified\":true,\"privateChildrenAbsent\":true,\"gidScopeAbsent\":true,\"filterJournalAbsent\":true,\"ownedFilterClassesEmpty\":true,"
        "\"bootstrapAttempted\":false,\"transportAttempted\":false,\"filterWriteAttempted\":false,\"coldStageAttempted\":false,\"exitStatus\":1,\"ready\":false,\"protected\":false}\n",
        ENVARA_APP_TRANSPORT_PROTOCOL, p->plan.run_id, p->plan.environment_id, p->plan.realm_id, p->plan.realm_gid, p->plan.lease_sha256,
        p->plan.controller.pid, (unsigned long long)p->plan.controller.birth_seconds, (unsigned long long)p->plan.controller.birth_microseconds,
        p->bootstrap.pid, (unsigned long long)p->bootstrap.birth_seconds, (unsigned long long)p->bootstrap.birth_microseconds,
        p->parent.pid, (unsigned long long)p->parent.birth_seconds, (unsigned long long)p->parent.birth_microseconds,
        (unsigned long long)p->lease.st_dev, (unsigned long long)p->lease.st_ino, (unsigned long long)p->run.st_dev, (unsigned long long)p->run.st_ino,
        (unsigned long long)p->executable.st_dev, (unsigned long long)p->executable.st_ino,
        (unsigned long long)p->parent_executable.st_dev, (unsigned long long)p->parent_executable.st_ino, p->nonce);
    return n > 0 && (size_t)n < size ? n : refuse(EOVERFLOW);
}
#define PREFLIGHT_PID_LIMIT 16384U
typedef struct {
    void *context;
    int (*list)(void *, pid_t *, size_t);
    int (*bsd)(void *, pid_t, struct proc_bsdinfo *);
} PreflightChildReaders;
static int preflight_pid_compare(const void *a, const void *b) {
    pid_t left = *(const pid_t *)a, right = *(const pid_t *)b; return left < right ? -1 : left > right ? 1 : 0;
}
static int preflight_child_list(const PreflightChildReaders *r, pid_t *out) {
    int n = r->list(r->context, out, PREFLIGHT_PID_LIMIT); if (n < 1 || n >= (int)PREFLIGHT_PID_LIMIT) return -1;
    int count = 0;
    for (int i = 0; i < n; i++) { if (out[i] < 0) return -1; if (out[i]) out[count++] = out[i]; }
    if (!count) return -1; qsort(out, (size_t)count, sizeof(*out), preflight_pid_compare);
    for (int i = 1; i < count; i++) if (out[i] == out[i-1]) return -1; return count;
}
static int preflight_bsd_same(const struct proc_bsdinfo *a, const struct proc_bsdinfo *b) {
    return a->pbi_pid == b->pbi_pid && a->pbi_ppid == b->pbi_ppid && a->pbi_start_tvsec == b->pbi_start_tvsec &&
        a->pbi_start_tvusec == b->pbi_start_tvusec && (a->pbi_status == SZOMB) == (b->pbi_status == SZOMB) &&
        a->pbi_uid == b->pbi_uid && a->pbi_ruid == b->pbi_ruid && a->pbi_svuid == b->pbi_svuid &&
        a->pbi_gid == b->pbi_gid && a->pbi_rgid == b->pbi_rgid && a->pbi_svgid == b->pbi_svgid;
}
static int preflight_bsd_valid(const struct proc_bsdinfo *p, pid_t pid, pid_t parent) {
    return p->pbi_pid == (uint32_t)pid && p->pbi_start_tvsec && p->pbi_start_tvusec < 1000000 &&
        p->pbi_status >= SIDL && p->pbi_status <= SZOMB && p->pbi_ppid != (uint32_t)parent;
}
/* Complete BSD inventories, including zombies; PID disappearance/truncation is
 * unknown. No unrelated application executable path is queried. This is a
 * snapshot, not an atomic credential or process-creation barrier. */
static int preflight_children_absent_with(pid_t parent, const PreflightChildReaders *r) {
    if (parent < 2 || !r || !r->list || !r->bsd) return 0;
    uint64_t start = milliseconds(), deadline = start + 15000; if (!start) return 0;
    pid_t *first = calloc(PREFLIGHT_PID_LIMIT, sizeof(pid_t)), *second = calloc(PREFLIGHT_PID_LIMIT, sizeof(pid_t));
    struct proc_bsdinfo *baseline = calloc(PREFLIGHT_PID_LIMIT, sizeof(*baseline)); int okay = 0;
    if (!first || !second || !baseline) goto done;
    int count = preflight_child_list(r, first); if (count < 1) goto done;
    for (int i = 0; i < count; i++) if (milliseconds() >= deadline || r->bsd(r->context, first[i], &baseline[i]) || !preflight_bsd_valid(&baseline[i], first[i], parent)) goto done;
    int other = preflight_child_list(r, second);
    if (other != count || memcmp(first, second, (size_t)count * sizeof(pid_t))) goto done;
    for (int i = 0; i < count; i++) { struct proc_bsdinfo now = {0};
        if (milliseconds() >= deadline || r->bsd(r->context, second[i], &now) || !preflight_bsd_valid(&now, second[i], parent) || !preflight_bsd_same(&baseline[i], &now)) goto done; }
    okay = 1;
done: free(first); free(second); free(baseline); return okay;
}
static int preflight_native_list(void *context, pid_t *pids, size_t capacity) {
    (void)context; int estimated = proc_listallpids(NULL, 0);
    if (capacity != PREFLIGHT_PID_LIMIT || estimated < 1 || estimated >= (int)capacity) return -1;
    return proc_listallpids(pids, (int)(capacity * sizeof(pid_t)));
}
static int preflight_native_bsd(void *context, pid_t pid, struct proc_bsdinfo *out) {
    (void)context; memset(out, 0, sizeof(*out)); return proc_pidinfo(pid, PROC_PIDTBSDINFO, 1, out, sizeof(*out)) == sizeof(*out) ? 0 : -1;
}
static int preflight_children_absent(pid_t parent) {
    const PreflightChildReaders readers = {NULL, preflight_native_list, preflight_native_bsd};
    return !getuid() && !geteuid() && preflight_children_absent_with(parent, &readers);
}
typedef int (*PreflightRuleReader)(void *, EnvaraPFHookRequest *);
static int preflight_classes_empty_with(const char *run, PreflightRuleReader read_rule, void *context) {
    const unsigned char actions[] = {0, 2, 4, 6, 8, 11}; char anchor[1024];
    if (!uuid(run) || !read_rule || snprintf(anchor, sizeof(anchor), "io.envara.pf.run.%s", run) >= (int)sizeof(anchor)) return 0;
    for (size_t i = 0; i < sizeof(actions); i++) {
        EnvaraPFHookRequest first = {0}, second = {0}; strcpy(first.anchor, anchor); first.rule.action = actions[i]; second = first;
        if (read_rule(context, &first) || first.nr || first.action || first.rule.action != actions[i] ||
            strnlen(first.anchor, sizeof(first.anchor)) >= sizeof(first.anchor) || strcmp(first.anchor, anchor) ||
            read_rule(context, &second) || second.nr || second.action || second.rule.action != actions[i] ||
            strnlen(second.anchor, sizeof(second.anchor)) >= sizeof(second.anchor) || strcmp(second.anchor, anchor) ||
            first.ticket != second.ticket) return 0;
    }
    return 1;
}
static int preflight_native_rules(void *context, EnvaraPFHookRequest *r) { return ioctl(*(int *)context, ENVARA_PF_HOOK_GET_RULES, r); }
static int preflight_fixed_file(const char *path, struct stat *identity) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat named;
    if (fd < 0) return -1;
    if (!envara_root_owned_executable(path) || envara_gui_acl_free(path) || fstat(fd, identity) || lstat(path, &named) ||
        !S_ISREG(identity->st_mode) || identity->st_uid || identity->st_gid || identity->st_nlink != 1 ||
        (identity->st_mode & 07777) != 0755 || !abort_same_stat(identity, &named)) { close(fd); return refuse(EACCES); }
    return fd;
}
static int preflight_file_fresh(int fd, const char *path, const struct stat *identity) {
    struct stat actual, named; return fd >= 0 && !fstat(fd, &actual) && !lstat(path, &named) &&
        abort_same_stat(identity, &actual) && abort_same_stat(&actual, &named) && !envara_gui_acl_free(path);
}
static int preflight_abort_emit(const char *run, const char *environment) {
    struct preflight_abort_proof p = {0}; struct abort_pin pin = {.run_fd = -1, .lease_fd = -1};
    EnvaraPFHookFilterLease *hook = NULL; char hook_bytes[16384], path[PROC_PIDPATHINFO_MAXSIZE], frame[4096]; size_t hook_size = 0;
    int native_fd = -1, parent_fd = -1, pf_fd = -1, okay = -1; struct stat pf, pf_now, pf_named;
    if (fixed_entry() || envara_app_native_abort_plan(run, environment, &p.plan, hook_bytes, sizeof(hook_bytes), &hook_size) ||
        abort_pin_open(&p.plan, &pin) || envara_identity_read(getpid(), &p.bootstrap) ||
        envara_identity_read(getppid(), &p.parent) || !preflight_identity_shape(&p.bootstrap) || !preflight_identity_shape(&p.parent) ||
        p.bootstrap.parent_pid != p.parent.pid || memcmp(&p.parent, &p.plan.controller, sizeof(p.parent)) ||
        proc_pidpath(p.parent.pid, path, sizeof(path)) <= 0 || strcmp(path, INSTALL "/node")) goto done;
    native_fd = preflight_fixed_file(ENVARA_GUI_NATIVE_PATH, &p.executable); parent_fd = preflight_fixed_file(INSTALL "/node", &p.parent_executable);
    if (native_fd < 0 || parent_fd < 0 || envara_pf_hook_filter_open(run, hook_bytes, (unsigned long)hook_size, &hook) != 1 ||
        !envara_pf_hook_filter_matches(hook, hook_bytes, (unsigned long)hook_size)) goto done;
    pf_fd = open("/dev/pf", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (pf_fd < 0 || fstat(pf_fd, &pf) || !S_ISCHR(pf.st_mode) || pf.st_uid || lstat("/dev/pf", &pf_named) ||
        pf.st_dev != pf_named.st_dev || pf.st_ino != pf_named.st_ino || pf.st_rdev != pf_named.st_rdev || !S_ISCHR(pf_named.st_mode) || pf_named.st_uid) goto done;
    p.lease = pin.lease; p.run = pin.run;
    unsigned char nonce[16]; arc4random_buf(nonce, sizeof(nonce));
    for (size_t i = 0; i < sizeof(nonce); i++) snprintf(p.nonce + i*2, 3, "%02x", nonce[i]); erase(nonce, sizeof(nonce));
    p.scope_before = envara_app_scope_gid_absent(p.plan.realm_gid); p.children_before = preflight_children_absent(p.bootstrap.pid);
    p.journal_before = abort_journal_absent(&pin);
    p.empty_before = envara_pf_hook_filter_guard(hook, -1) && preflight_classes_empty_with(run, preflight_native_rules, &pf_fd);
    if (p.scope_before != 1 || p.children_before != 1 || p.journal_before != 1 || p.empty_before != 1 || abort_pin_fresh(&pin)) goto done;
    p.scope_after = envara_app_scope_gid_absent(p.plan.realm_gid);
    p.journal_after = abort_journal_absent(&pin);
    p.empty_after = envara_pf_hook_filter_guard(hook, -1) && preflight_classes_empty_with(run, preflight_native_rules, &pf_fd);
    /* Hook readback uses fixed readonly pfctl children. Observe their actual
     * absence after the final guard call; no later operation forks a child. */
    p.children_after = preflight_children_absent(p.bootstrap.pid);
    struct envara_identity bootstrap_now, parent_now;
    if (abort_pin_fresh(&pin) || fstat(pf_fd, &pf_now) || lstat("/dev/pf", &pf_named) ||
        !S_ISCHR(pf_now.st_mode) || !S_ISCHR(pf_named.st_mode) || pf_now.st_uid || pf_named.st_uid ||
        pf.st_dev != pf_now.st_dev || pf.st_ino != pf_now.st_ino || pf.st_rdev != pf_now.st_rdev ||
        pf.st_dev != pf_named.st_dev || pf.st_ino != pf_named.st_ino || pf.st_rdev != pf_named.st_rdev ||
        !preflight_file_fresh(native_fd, ENVARA_GUI_NATIVE_PATH, &p.executable) || !preflight_file_fresh(parent_fd, INSTALL "/node", &p.parent_executable) ||
        envara_identity_read(p.bootstrap.pid, &bootstrap_now) || envara_identity_read(p.parent.pid, &parent_now) ||
        memcmp(&p.bootstrap, &bootstrap_now, sizeof(bootstrap_now)) || memcmp(&p.parent, &parent_now, sizeof(parent_now)) || getppid() != p.parent.pid) goto done;
    p.captured = 1; int length = preflight_abort_frame(&p, frame, sizeof(frame)); if (length < 1 || write_bounded(1, frame, (size_t)length)) goto done; okay = 0;
done:
    if (pf_fd >= 0) close(pf_fd); if (native_fd >= 0) close(native_fd); if (parent_fd >= 0) close(parent_fd);
    envara_pf_hook_filter_close(hook); abort_pin_close(&pin); erase(hook_bytes, sizeof(hook_bytes)); return okay;
}
int envara_app_listener_open(struct envara_app_listener *out) {
    if (!out) return refuse(EINVAL); memset(out, 0, sizeof(*out)); out->fd = -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0); if (fd < 0) return -1;
    struct sockaddr_in address = {.sin_len = sizeof(address), .sin_family = AF_INET,
        .sin_port = 0, .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}};
    socklen_t size = sizeof(address);
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) || bind(fd, (struct sockaddr *)&address, sizeof(address)) ||
        listen(fd, 16) || getsockname(fd, (struct sockaddr *)&address, &size) || size != sizeof(address) ||
        ntohs(address.sin_port) < 1024) { int error = errno ? errno : EACCES; close(fd); return refuse(error); }
    struct stat credential;
    if (fstat(fd, &credential) || !S_ISSOCK(credential.st_mode)) { int error=errno?errno:EACCES;close(fd);return refuse(error); }
    out->fd = fd; out->owner = getpid(); out->port = ntohs(address.sin_port);
    out->credential_uid=credential.st_uid;out->credential_gid=credential.st_gid;return 0;
}
int envara_app_listener_verify(const struct envara_app_listener *held) {
    struct sockaddr_in address; socklen_t size = sizeof(address); struct stat info;
    int type = 0, reuse_address = 1, reuse_port = 1, descriptor = held ? fcntl(held->fd, F_GETFD) : -1;
    socklen_t integer = sizeof(int);
    if (!held || held->fd < 3 || held->owner != getpid() || held->port < 1024 || fstat(held->fd, &info) ||
        !S_ISSOCK(info.st_mode) || info.st_uid != held->credential_uid || info.st_gid != held->credential_gid ||
        descriptor < 0 || !(descriptor & FD_CLOEXEC) ||
        getsockname(held->fd, (struct sockaddr *)&address, &size) || size != sizeof(address) ||
        address.sin_family != AF_INET || address.sin_addr.s_addr != htonl(INADDR_LOOPBACK) || ntohs(address.sin_port) != held->port ||
        getsockopt(held->fd, SOL_SOCKET, SO_TYPE, &type, &integer) || integer != sizeof(int) || type != SOCK_STREAM) return refuse(EACCES);
    struct socket_fdinfo socket_info;
    if (proc_pidfdinfo(getpid(), held->fd, PROC_PIDFDSOCKETINFO, &socket_info, sizeof(socket_info)) != sizeof(socket_info) ||
        socket_info.psi.soi_family != AF_INET || socket_info.psi.soi_kind != SOCKINFO_TCP ||
        socket_info.psi.soi_proto.pri_tcp.tcpsi_state != TSI_S_LISTEN) return refuse(EACCES);
    integer = sizeof(int);
    if (getsockopt(held->fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address, &integer) || integer != sizeof(int) || reuse_address) return refuse(EACCES);
    integer = sizeof(int);
    if (getsockopt(held->fd, SOL_SOCKET, SO_REUSEPORT, &reuse_port, &integer) || integer != sizeof(int) || reuse_port) return refuse(EACCES);
    return 0;
}
int envara_app_listener_close(struct envara_app_listener *held) {
    if (envara_app_listener_verify(held)) return -1;
    int result = close(held->fd); held->fd = -1; return result;
}
int envara_app_transport_relay(int input, int lease_writer, int recovery_writer, pid_t parent) {
    if (input < 0 || lease_writer < 3 || recovery_writer < 3 || lease_writer == recovery_writer || parent < 2) return refuse(EINVAL);
    for (;;) {
        if (stopped) { close(lease_writer); close(recovery_writer); return refuse(ECANCELED); }
        if (getppid() != parent) { close(lease_writer); close(recovery_writer); return refuse(EPIPE); }
        struct pollfd p = {input, POLLIN | POLLHUP, 0}; int ready = poll(&p, 1, 250);
        if (ready < 0 && errno == EINTR) continue; if (ready < 0) break; if (!ready) continue;
        char command[4]; if (line(input, command, sizeof(command), 1000)) break;
        int fd = lease_writer; char byte;
        if (!strcmp(command, "K")) byte = 'K'; else if (!strcmp(command, "S")) byte = 'S';
        else if (!strcmp(command, "B")) byte = 'B';
        else if (!strcmp(command, "R")) { byte = 'R'; fd = recovery_writer; } else break;
        if (write(fd, &byte, 1) != 1) break;
    }
    close(lease_writer); close(recovery_writer); return refuse(EPIPE);
}
static int fixed_entry(void) {
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (getuid() || geteuid() || proc_pidpath(getpid(), path, sizeof(path)) <= 0 || strcmp(path, ENVARA_GUI_NATIVE_PATH) ||
        !envara_root_owned_executable(ENVARA_GUI_NATIVE_PATH) || envara_gui_acl_free(ENVARA_GUI_NATIVE_PATH) ||
        !envara_root_owned_executable("/bin/launchctl") || envara_gui_acl_free("/bin/launchctl")) return refuse(EACCES);
    return 0;
}
struct listener_request {
    unsigned char nonce[32];
    char run[37], environment[37], lease_sha256[65];
    struct envara_identity parent;
};
struct listener_response {
    struct listener_request binding;
    struct envara_identity creator;
    uint16_t port;
};
/* Frozen Darwin UIPC_MAX_CMSG_FD is 512 and internalize accepts one complete
 * SCM_RIGHTS mbuf. Receive the whole kernel-supported control vector: Darwin
 * may install unreported rights when a smaller control buffer is truncated. */
#define LISTENER_RIGHTS_MAX 512
static int listener_private_channel(int fd) {
    struct stat s;int type=0;socklen_t size=sizeof(type);struct sockaddr_un peer={0};socklen_t length=sizeof(peer);
    if(fd<3||fstat(fd,&s)||!S_ISSOCK(s.st_mode)||getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&size)||size!=sizeof(type)||type!=SOCK_DGRAM||
        getpeername(fd,(struct sockaddr *)&peer,&length)||peer.sun_family!=AF_UNIX||length<offsetof(struct sockaddr_un,sun_path)||length>sizeof(peer))return refuse(EACCES);
    for(size_t i=offsetof(struct sockaddr_un,sun_path);i<length;i++)if(((unsigned char *)&peer)[i])return refuse(EACCES);
    return 0;
}
/* All received rights are owned by this process, including malformed or
 * truncated packets. Close every visible right before reporting refusal. */
static int listener_receive(int channel,void *bytes,size_t size,int want_fd,int *out_fd,unsigned timeout) {
    if(out_fd)*out_fd=-1;
    uint64_t now=milliseconds(),deadline=now+timeout;if(!now||!timeout)return refuse(EIO);
    struct pollfd p={channel,POLLIN,0};int ready;
    do{now=milliseconds();if(!now||now>=deadline)return refuse(ETIMEDOUT);ready=poll(&p,1,(int)(deadline-now));}while(ready<0&&errno==EINTR);
    if(ready<1||!(p.revents&POLLIN))return refuse(ready==0?ETIMEDOUT:EPIPE);
    unsigned char control[CMSG_SPACE(sizeof(int)*LISTENER_RIGHTS_MAX)]={0};struct iovec vector={bytes,size};
    struct msghdr message={0};message.msg_iov=&vector;message.msg_iovlen=1;message.msg_control=control;message.msg_controllen=sizeof(control);
    ssize_t count=recvmsg(channel,&message,MSG_DONTWAIT);if(count<0)return -1;
    int rights[LISTENER_RIGHTS_MAX],number=0,valid=count==(ssize_t)size&&!(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC));
    if(message.msg_controllen>sizeof(control)){message.msg_controllen=sizeof(control);valid=0;}
    unsigned char *end=control+message.msg_controllen;
    for(struct cmsghdr *c=CMSG_FIRSTHDR(&message);c;c=CMSG_NXTHDR(&message,c)){
        unsigned char *header=(unsigned char *)c;
        if(header<control||header>end||(size_t)(end-header)<sizeof(*c)){valid=0;break;}
        if(c->cmsg_len<CMSG_LEN(0)||(size_t)(end-header)<CMSG_LEN(0)){valid=0;break;}
        unsigned char *data=(unsigned char *)CMSG_DATA(c);size_t payload=c->cmsg_len-CMSG_LEN(0),visible=(size_t)(end-data);
        if(payload>visible){payload=visible;valid=0;}
        if(c->cmsg_level!=SOL_SOCKET||c->cmsg_type!=SCM_RIGHTS)valid=0;
        else for(size_t i=0;i<payload/sizeof(int);i++){
            int fd;memcpy(&fd,(unsigned char *)CMSG_DATA(c)+i*sizeof(int),sizeof(fd));
            if(number<LISTENER_RIGHTS_MAX)rights[number++]=fd;else{close(fd);valid=0;}
        }
        if(payload%sizeof(int)||payload!=sizeof(int)||number!=1)valid=0;
        if(c->cmsg_len>(size_t)(end-header)){valid=0;break;}
    }
    if(number!=want_fd||(want_fd&&!out_fd))valid=0;
    if(valid&&want_fd&&(rights[0]<3||fcntl(rights[0],F_SETFD,FD_CLOEXEC)))valid=0;
    if(!valid){for(int i=0;i<number;i++)close(rights[i]);return refuse(message.msg_flags&MSG_CTRUNC?EOVERFLOW:EACCES);}
    if(want_fd)*out_fd=rights[0];return 0;
}
static int listener_send(int channel,const void *bytes,size_t size,int fd) {
    struct iovec vector={(void *)bytes,size};struct msghdr message={0};unsigned char control[CMSG_SPACE(sizeof(int))]={0};
    message.msg_iov=&vector;message.msg_iovlen=1;
    if(fd>=0){message.msg_control=control;message.msg_controllen=sizeof(control);struct cmsghdr *c=CMSG_FIRSTHDR(&message);
        c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));memcpy(CMSG_DATA(c),&fd,sizeof(fd));}
    struct pollfd p={channel,POLLOUT,0};if(poll(&p,1,1000)!=1)return refuse(ETIMEDOUT);
    return sendmsg(channel,&message,MSG_DONTWAIT)==(ssize_t)size?0:refuse(EIO);
}
static int listener_binding(const struct listener_request *request,const struct envara_app_native_preflight *plan,
    const struct envara_identity *parent) {
    unsigned char any=0;for(size_t i=0;i<sizeof(request->nonce);i++)any|=request->nonce[i];
    return any&&strnlen(request->run,sizeof(request->run))==36&&strnlen(request->environment,sizeof(request->environment))==36&&
        strnlen(request->lease_sha256,sizeof(request->lease_sha256))==64&&!strcmp(request->run,plan->run_id)&&
        !strcmp(request->environment,plan->environment_id)&&!strcmp(request->lease_sha256,plan->lease_sha256)&&
        !memcmp(&request->parent,parent,sizeof(*parent));
}
static int listener_response_valid(const struct listener_request *request,const struct listener_response *response,
    const struct envara_identity *creator,uid_t uid,gid_t gid,struct envara_app_listener *held) {
    struct stat s;
    if(memcmp(request,&response->binding,sizeof(*request))||response->creator.pid!=creator->pid||response->creator.parent_pid!=request->parent.pid||
        response->creator.birth_seconds!=creator->birth_seconds||response->creator.birth_microseconds!=creator->birth_microseconds||
        !envara_identity_matches(&response->creator,uid,gid)||response->port<1024||held->fd<3||fstat(held->fd,&s)||s.st_uid!=uid||s.st_gid!=gid)return refuse(EACCES);
    held->owner=getpid();held->port=response->port;held->credential_uid=uid;held->credential_gid=gid;
    return envara_app_listener_verify(held);
}
static int listener_creator(const struct envara_app_native_preflight *plan) {
    struct envara_identity parent,self;char path[PROC_PIDPATHINFO_MAXSIZE];
    if(listener_private_channel(3)||envara_identity_read(getpid(),&self)||!envara_identity_matches(&self,0,0)||
        envara_identity_read(getppid(),&parent)||!envara_identity_matches(&parent,0,0)||
        proc_pidpath(parent.pid,path,sizeof(path))<=0||strcmp(path,ENVARA_GUI_NATIVE_PATH)||!envara_same_process(&parent))return refuse(EACCES);
    struct listener_request request={0};if(listener_receive(3,&request,sizeof(request),0,NULL,3000)||!listener_binding(&request,plan,&parent))return refuse(EACCES);
    int held[]={3};gid_t gid=plan->realm_gid;
    if(envara_close_inherited_descriptors(held,1)||setgroups(1,&gid)||setgid(gid)||envara_identity_read(getpid(),&self)||
        !envara_identity_matches(&self,0,gid))return refuse(EACCES);
    gid_t actual[NGROUPS_MAX];int groups=getgroups(NGROUPS_MAX,actual);if(groups!=1||actual[0]!=gid)return refuse(EACCES);
    struct envara_app_listener listener={.fd=-1};if(envara_app_listener_open(&listener))return -1;
    struct listener_response response={0};response.binding=request;response.creator=self;response.port=listener.port;
    int result=listener.credential_uid||listener.credential_gid!=gid||!envara_same_process(&parent)?refuse(EACCES):listener_send(3,&response,sizeof(response),listener.fd);
    int error=errno;if(close(listener.fd)&&!result){result=-1;error=errno;}close(3);erase(&request,sizeof(request));erase(&response,sizeof(response));return result?refuse(error):0;
}
static int listener_reap(pid_t pid,uint64_t deadline,int *status) {
    for(;;){pid_t result=waitpid(pid,status,WNOHANG);if(result==pid)return 0;if(result<0&&errno==EINTR)continue;if(result<0)return -1;
        uint64_t now=milliseconds();if(!now||now>=deadline)return refuse(ETIMEDOUT);poll(NULL,0,10);}
}
static int listener_stopped(const struct envara_identity *creator) {
    struct proc_bsdinfo info;
    return proc_pidinfo(creator->pid,PROC_PIDTBSDINFO,0,&info,sizeof(info))==sizeof(info)&&info.pbi_status==SSTOP&&
        info.pbi_start_tvsec==creator->birth_seconds&&info.pbi_start_tvusec==creator->birth_microseconds;
}
static int listener_cancel(pid_t pid) {
    int status;pid_t result;do{result=waitpid(pid,&status,WNOHANG);}while(result<0&&errno==EINTR);
    if(result==pid)return 0;if(result<0)return -1;
    /* An unreaped direct child cannot be replaced by PID reuse. No foreign
     * identity is adopted, and neither ESRCH nor a sent signal proves reap. */
    if(kill(pid,SIGKILL)&&errno!=ESRCH)return -1;
    return listener_reap(pid,milliseconds()+3000,&status);
}
static int listener_queue_empty(int fd) {
    /* Darwin marks a disconnected datagram socket readable for EOF. After
     * the fixed creator has actually exited 0, accept only empty EOF with no
     * control data; any queued nonempty frame is TRUNC and all rights close. */
    if(!listener_receive(fd,NULL,0,0,NULL,250))return 1;
    /* AF_UNIX datagram peer close is ECONNRESET on Darwin, not stream EOF.
     * Never clear a pending nonempty response when recognizing that close. */
    if(errno==ECONNRESET){int bytes=-1;socklen_t size=sizeof(bytes);
        return !getsockopt(fd,SOL_SOCKET,SO_NREAD,&bytes,&size)&&size==sizeof(bytes)&&bytes==0;
    }
    return 0;
}
int envara_app_listener_open_for_plan(const struct envara_app_native_preflight *plan,struct envara_app_listener *out) {
    if(!out)return refuse(EINVAL);memset(out,0,sizeof(*out));out->fd=-1;
    struct envara_identity parent,creator;gid_t before[NGROUPS_MAX],after[NGROUPS_MAX];int count=getgroups(NGROUPS_MAX,before);
    if(!plan||fixed_entry()||count<0||!uuid(plan->run_id)||!uuid(plan->environment_id)||plan->realm_gid<7100||plan->realm_gid>7999||
        envara_identity_read(getpid(),&parent)||!envara_identity_matches(&parent,0,0))return refuse(EACCES);
    int pair[2];if(socketpair(AF_UNIX,SOCK_DGRAM,0,pair))return -1;
    if(fcntl(pair[0],F_SETFD,FD_CLOEXEC)||fcntl(pair[1],F_SETFD,FD_CLOEXEC)){int error=errno;close(pair[0]);close(pair[1]);return refuse(error);}
    int copy=fcntl(pair[1],F_DUPFD_CLOEXEC,10);if(copy<0){int error=errno;close(pair[0]);close(pair[1]);return refuse(error);}
    posix_spawn_file_actions_t actions;posix_spawnattr_t attributes;pid_t pid=-1;int result=posix_spawn_file_actions_init(&actions);
    if(!result){result=posix_spawnattr_init(&attributes);if(!result){
        result=posix_spawnattr_setflags(&attributes,POSIX_SPAWN_CLOEXEC_DEFAULT|POSIX_SPAWN_START_SUSPENDED);
        for(int fd=0;fd<3&&!result;fd++)result=posix_spawn_file_actions_addopen(&actions,fd,"/dev/null",O_RDWR,0);
        if(!result)result=posix_spawn_file_actions_adddup2(&actions,copy,3);
        if(!result)result=posix_spawn_file_actions_addinherit_np(&actions,3);
        char *args[]={ENVARA_GUI_NATIVE_PATH,"app-listener-create",(char *)plan->run_id,(char *)plan->environment_id,NULL};
        char *env[]={"PATH=/usr/bin:/bin:/usr/sbin:/sbin","LANG=C","LC_ALL=C",NULL};
        if(!result)result=posix_spawn(&pid,ENVARA_GUI_NATIVE_PATH,&actions,&attributes,args,env);
        posix_spawnattr_destroy(&attributes);}posix_spawn_file_actions_destroy(&actions);}
    close(copy);close(pair[1]);if(result){close(pair[0]);return refuse(result);}
    uint64_t deadline=milliseconds()+5000;struct listener_request request={0};struct listener_response response={0};char path[PROC_PIDPATHINFO_MAXSIZE];
    request.parent=parent;strcpy(request.run,plan->run_id);strcpy(request.environment,plan->environment_id);
    if(strnlen(plan->lease_sha256,sizeof(plan->lease_sha256))!=64){errno=EACCES;goto failed;}
    strcpy(request.lease_sha256,plan->lease_sha256);arc4random_buf(request.nonce,sizeof(request.nonce));
    if(envara_identity_read(pid,&creator)||creator.parent_pid!=getpid()||!envara_identity_matches(&creator,0,0)||
        proc_pidpath(pid,path,sizeof(path))<=0||strcmp(path,ENVARA_GUI_NATIVE_PATH)||!envara_same_process(&creator)||!listener_stopped(&creator)||
        listener_private_channel(pair[0])||listener_send(pair[0],&request,sizeof(request),-1)||kill(pid,SIGCONT)||
        listener_receive(pair[0],&response,sizeof(response),1,&out->fd,4000)||
        listener_response_valid(&request,&response,&creator,0,plan->realm_gid,out))goto failed;
    int status;if(listener_reap(pid,deadline,&status))goto failed;pid=-1;
    if(!WIFEXITED(status)||WEXITSTATUS(status)||!envara_same_process(&parent)||getgroups(NGROUPS_MAX,after)!=count||memcmp(before,after,(size_t)count*sizeof(gid_t))||
        envara_app_listener_verify(out)){errno=EACCES;goto failed;}
    if(!listener_queue_empty(pair[0]))goto failed; /* Preserve EOVERFLOW custody. */
    close(pair[0]);erase(&request,sizeof(request));erase(&response,sizeof(response));return 0;
failed: {int error=errno?errno:EACCES;if(pid>1&&listener_cancel(pid)){
        refused_event(plan->run_id,plan->environment_id,"front-listen",errno?errno:ECHILD);for(;;)poll(NULL,0,250);
    }if(error==EOVERFLOW){refused_event(plan->run_id,plan->environment_id,"front-listen",error);for(;;)poll(NULL,0,250);}
    if(out->fd>=0)close(out->fd);memset(out,0,sizeof(*out));out->fd=-1;
    close(pair[0]);erase(&request,sizeof(request));erase(&response,sizeof(response));return refuse(error);}
}
static int bootstrap(const struct envara_app_native_preflight *plan) {
    char uid[16]; snprintf(uid, sizeof(uid), "%u", plan->console_uid);
    char *argv[] = {"/bin/launchctl", "asuser", uid, ENVARA_GUI_NATIVE_PATH, "app-tunnel-run",
        (char *)plan->run_id, (char *)plan->environment_id, NULL};
    char *environment[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", NULL};
    /* Replacing this transient bootstrap preserves only the private stdio;
     * the new console native process creates its original sockets itself. */
    if (envara_launch_guard_isolate_descriptors(NULL, 0)) return -1;
    execve("/bin/launchctl", argv, environment); return -1;
}
static int exact_stop(struct envara_identity *identity, int *reaped) {
    if (*reaped) return 0; if (identity->pid < 2 || identity->parent_pid != getpid()) return refuse(EACCES);
    int status; pid_t pid = waitpid(identity->pid, &status, WNOHANG);
    if (!pid) {
        if (!envara_same_process(identity) || kill(identity->pid, SIGKILL)) return -1;
        do { pid = waitpid(identity->pid, &status, 0); } while (pid < 0 && errno == EINTR);
    }
    if (pid != identity->pid) return refuse(ECHILD); *reaped = 1; return 0;
}
struct frontend_stop_context {
    pid_t owner;
    int *input, *reaped;
    struct envara_identity *frontend;
    struct stat writer;
    int kill_sent, wait_unknown;
};
/* The original direct child can exit after a zero WNOHANG result but before
 * its identity read or signal. Only a terminal wait for that still-unreaped
 * child resolves this race; absent/unknown evidence never means stopped. */
static int frontend_exit_after_race(struct frontend_stop_context *context, int operation_error) {
    int status = 0; pid_t pid = waitpid(context->frontend->pid, &status, WNOHANG);
    if (pid == context->frontend->pid && (WIFEXITED(status) || WIFSIGNALED(status))) {
        *context->reaped = 1; return 0;
    }
    if (!pid || (pid < 0 && errno == EINTR)) return refuse(operation_error ? operation_error : EIO);
    context->wait_unknown = 1;
    return pid < 0 ? -1 : refuse(ECHILD);
}
static int bounded_front_stop(struct frontend_stop_context *context) {
    if (!context || context->owner != getpid() || !context->reaped || !context->frontend) return refuse(EACCES);
    if (*context->reaped) return 0;
    struct envara_identity *identity = context->frontend;
    if (context->wait_unknown || identity->pid < 2 || identity->parent_pid != getpid()) return refuse(ECHILD);
    uint64_t now = milliseconds(); if (!now || now > UINT64_MAX - 2000) return refuse(EIO);
    uint64_t deadline = now + 2000;
    for (;;) {
        now = milliseconds(); if (!now) return refuse(EIO); if (now >= deadline) return refuse(ETIMEDOUT);
        int status = 0; pid_t pid = waitpid(identity->pid,&status,WNOHANG);
        if (pid == identity->pid) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) { *context->reaped = 1; return 0; }
            context->wait_unknown = 1; return refuse(ECHILD);
        }
        if (pid < 0) {
            if (errno == EINTR) continue;
            context->wait_unknown = 1; return -1;
        }
        if (pid != 0) { context->wait_unknown = 1; return refuse(ECHILD); }
        if (!context->kill_sent) {
            struct envara_identity actual;
            if (envara_identity_read(identity->pid, &actual)) return frontend_exit_after_race(context, errno);
            /* An observed different generation or credential is a refusal,
             * never an exit race and never authority to signal or reap. */
            if (actual.pid != identity->pid || actual.parent_pid != identity->parent_pid ||
                actual.birth_seconds != identity->birth_seconds || actual.birth_microseconds != identity->birth_microseconds ||
                actual.uid != identity->uid || actual.ruid != identity->ruid || actual.saved_uid != identity->saved_uid ||
                actual.gid != identity->gid || actual.rgid != identity->rgid || actual.saved_gid != identity->saved_gid) return refuse(EACCES);
            if (kill(identity->pid,SIGKILL)) return frontend_exit_after_race(context, errno);
            context->kill_sent = 1;
        }
        struct timespec delay = {0,10000000}; (void)nanosleep(&delay,NULL);
    }
}
static int stop_owned_frontend(void *opaque) {
    struct frontend_stop_context *context = opaque;
    if (!context || context->owner != getpid() || !context->input || !context->reaped || !context->frontend) return 0;
    int closed = *context->input == -1;
    if (!closed) {
        struct stat current;
        if (*context->input >= 3 && !fstat(*context->input, &current) && S_ISFIFO(current.st_mode) &&
            current.st_dev == context->writer.st_dev && current.st_ino == context->writer.st_ino &&
            current.st_uid == context->writer.st_uid && current.st_nlink == 0) {
            if (!close(*context->input)) { *context->input = -1; closed = 1; }
        }
    }
    /* This is the original unreaped direct frontend, not the application or a
     * discovered descendant. Its PID cannot be recycled before our waitpid. */
    int stopped_front = bounded_front_stop(context) == 0;
    return closed && stopped_front;
}
static int spawn_front(const struct envara_app_listener *listener, int *input, int *output,
                       struct envara_identity *identity) {
    const char *node = INSTALL "/node", *service = INSTALL "/notion-front-service.mjs";
    struct stat info;
    if (envara_app_listener_verify(listener) || !envara_root_owned_executable(node) || envara_gui_acl_free(node) ||
        lstat(service, &info) || !S_ISREG(info.st_mode) || info.st_uid || info.st_nlink != 1 || (info.st_mode & 0022) ||
        envara_gui_acl_free(service)) return refuse(EACCES);
    int a[2], b[2]; if (pipe_private(a)) return -1;
    if (pipe_private(b)) { int error = errno; close(a[0]); close(a[1]); return refuse(error); }
    int listen_copy = fcntl(listener->fd, F_DUPFD_CLOEXEC, 10);
    if (listen_copy < 0) { int error = errno; close(a[0]); close(a[1]); close(b[0]); close(b[1]); return refuse(error); }
    posix_spawn_file_actions_t actions; posix_spawnattr_t attributes; int result;
    result = posix_spawn_file_actions_init(&actions);
    if (!result) {
        result = posix_spawnattr_init(&attributes);
        if (!result) {
            result = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT);
            if (!result) result = posix_spawn_file_actions_adddup2(&actions, a[0], 0);
            if (!result) result = posix_spawn_file_actions_adddup2(&actions, b[1], 1);
            if (!result) result = posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0);
            if (!result) result = posix_spawn_file_actions_adddup2(&actions, listen_copy, 3);
            for (int fd = 0; fd <= 3 && !result; fd++) result = posix_spawn_file_actions_addinherit_np(&actions, fd);
            char *argv[] = {(char *)node, "--no-addons", "--disable-proto=throw", (char *)service, "--native-fd3", NULL};
            char *env[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", NULL}; pid_t pid;
            if (!result) result = posix_spawn(&pid, node, &actions, &attributes, argv, env);
            posix_spawnattr_destroy(&attributes);
            if (!result && (envara_identity_read(pid, identity) || identity->parent_pid != getpid() ||
                !envara_identity_matches(identity, 0, getgid()))) {
                kill(pid, SIGKILL); waitpid(pid, NULL, 0); result = EACCES;
            }
        }
        posix_spawn_file_actions_destroy(&actions);
    }
    close(listen_copy); close(a[0]); close(b[1]);
    if (result) { close(a[1]); close(b[0]); return refuse(result); }
    *input = a[1]; *output = b[0]; return 0;
}
/* Implemented below with the native factory; the unchanged generic transport
 * path remains separate and retains its original fixture protocol. */
static int run(const struct envara_app_native_preflight *plan);
int envara_app_transport_command(int argc, char *const argv[]) {
    if (argc != 4 || !argv || (strcmp(argv[1], "app-tunnel-bootstrap") && strcmp(argv[1], "app-tunnel-run") && strcmp(argv[1],"app-listener-create")) ||
        !uuid(argv[2]) || !uuid(argv[3]) || fixed_entry()) return refuse(EACCES);
    struct envara_app_native_preflight plan;
    if (envara_app_native_preflight(argv[2], argv[3], &plan)) {
        int error = errno; refused_event(argv[2], argv[3], "preflight", error);
        /* Only this direct root bootstrap can certify that no later resource
         * constructor was entered. Run/listener refusals remain uncertain. */
        if (!strcmp(argv[1], "app-tunnel-bootstrap")) (void)preflight_abort_emit(argv[2], argv[3]);
        return refuse(error);
    }
    if (!strcmp(argv[1],"app-listener-create"))return listener_creator(&plan);
    if (!strcmp(argv[1], "app-tunnel-bootstrap")) return bootstrap(&plan);
    return run(&plan);
}

static int admission(envara_app_native_factory *factory, int front_input) {
    struct envara_app_native_admission p;
    if (envara_app_native_factory_admission(factory, &p)) return -1;
    /* The profile label is derived from the factory's registered snapshot, not
     * assumed here, so a generic app never reports the Notion front profile. */
    const char *profile = envara_app_native_factory_profile(factory);
    char frame[1536]; int n = snprintf(frame, sizeof(frame),
        "{\"schema\":\"envara.macos-pf-notion-admission/v1\",\"operation\":\"activate\",\"runId\":\"%s\","
        "\"environmentId\":\"%s\",\"leaseId\":\"%s\",\"generation\":\"%s\",\"leaseSHA256\":\"%s\","
        "\"keeperPID\":%d,\"keeperBirth\":\"%llu:%06llu\",\"frontPID\":%d,\"frontBirth\":\"%llu:%06llu\","
        "\"frontPort\":%u,\"gid\":%u,\"filterRevision\":%u,\"writerPid\":%u,\"profile\":\"%s\","
        "\"rulesVerified\":true,\"poolsVerified\":true,\"lo0FilteringVerified\":true,\"originalListenerHeld\":true,"
        "\"originalUTunHeld\":true,\"expiresMonotonicMs\":%llu,\"bootTimeSeconds\":%llu,\"ready\":false,\"protected\":false}\n",
        p.run_id, p.environment_id, p.lease_id, p.generation, p.lease_sha256,
        p.keeper.pid, (unsigned long long)p.keeper.birth_seconds, (unsigned long long)p.keeper.birth_microseconds,
        p.frontend.pid, (unsigned long long)p.frontend.birth_seconds, (unsigned long long)p.frontend.birth_microseconds,
        p.front_port, p.gid, p.filter_revision, p.writer_pid, profile,
        (unsigned long long)p.expires_monotonic_ms,
        (unsigned long long)p.boot_time_seconds);
    if (n <= 0 || n >= (int)sizeof(frame)) return refuse(EOVERFLOW);
    return write_bounded(front_input, frame, (size_t)n);
}
static int transport_event(const struct envara_app_native_preflight *p, const struct envara_transport_session *session,
    const struct envara_app_listener *listener, const struct envara_identity *front) {
    char frame[1024]; int n = snprintf(frame, sizeof(frame),
        "{\"schema\":\"%s\",\"event\":\"transport-started\",\"runId\":\"%s\",\"environmentId\":\"%s\","
        "\"interfaceName\":\"%s\",\"corePID\":%d,\"coreBirth\":\"%llu:%06llu\",\"frontPID\":%d,"
        "\"frontBirth\":\"%llu:%06llu\",\"frontPort\":%u,\"keeperPID\":%d,\"ownsOriginalUTunFD\":true,"
        "\"ownsOriginalListenerFD\":true,\"ready\":false,\"protected\":false}\n",
        ENVARA_APP_TRANSPORT_PROTOCOL, p->run_id, p->environment_id, session->interface_name, session->core.pid,
        (unsigned long long)session->core.birth_seconds, (unsigned long long)session->core.birth_microseconds,
        front->pid, (unsigned long long)front->birth_seconds, (unsigned long long)front->birth_microseconds,
        listener->port, getpid());
    if (n <= 0 || n >= (int)sizeof(frame)) return refuse(EOVERFLOW);
    return write_bounded(1, frame, (size_t)n);
}
static int cleanup_ready_event(const struct envara_app_native_preflight *p,const struct envara_transport_session *session,
    const struct envara_app_listener *listener,const struct envara_identity *front,const char *stage) {
    char frame[1536];int n=snprintf(frame,sizeof(frame),
        "{\"schema\":\"%s\",\"event\":\"transport-cleanup-ready\",\"runId\":\"%s\",\"environmentId\":\"%s\","
        "\"interfaceName\":\"%s\",\"corePID\":%d,\"coreBirth\":\"%llu:%06llu\",\"frontPID\":%d,"
        "\"frontBirth\":\"%llu:%06llu\",\"frontPort\":%u,\"keeperPID\":%d,\"ownsOriginalUTunFD\":true,"
        "\"ownsOriginalListenerFD\":true,\"ready\":false,\"protected\":false,\"cleanupOnly\":true,\"stage\":\"%s\"}\n",
        ENVARA_APP_TRANSPORT_PROTOCOL,p->run_id,p->environment_id,session->interface_name,session->core.pid,
        (unsigned long long)session->core.birth_seconds,(unsigned long long)session->core.birth_microseconds,
        front->pid,(unsigned long long)front->birth_seconds,(unsigned long long)front->birth_microseconds,listener->port,getpid(),stage);
    if(n<=0||n>=(int)sizeof(frame))return refuse(EOVERFLOW);return write_bounded(1,frame,(size_t)n);
}
static int cleanup_stopping_event(const struct envara_app_native_preflight *p,int child_reaped,int child_absent) {
    struct envara_identity keeper;if(envara_identity_read(getpid(),&keeper)||!envara_identity_matches(&keeper,0,0)||
        (!child_reaped&&!child_absent)||envara_app_scope_gid_absent(p->realm_gid)!=1)return refuse(EACCES);
    char frame[1024];int n=snprintf(frame,sizeof(frame),
        "{\"schema\":\"%s\",\"event\":\"transport-cleanup-stopping\",\"runId\":\"%s\",\"environmentId\":\"%s\","
        "\"keeperPID\":%d,\"keeperBirth\":\"%llu:%06llu\",\"childReaped\":%s,\"childAbsent\":%s,"
        "\"scopeQuiescentObserved\":true,\"persistentDenyObserved\":true,\"ready\":false,\"protected\":false}\n",
        ENVARA_APP_TRANSPORT_PROTOCOL,p->run_id,p->environment_id,keeper.pid,(unsigned long long)keeper.birth_seconds,
        (unsigned long long)keeper.birth_microseconds,child_reaped?"true":"false",child_absent?"true":"false");
    if(n<=0||n>=(int)sizeof(frame))return refuse(EOVERFLOW);return write_bounded(1,frame,(size_t)n);
}
/* The relay is our direct, unreaped fork. A successful signal or ECHILD is
 * not retirement. Until terminal wait, its original pipes remain the sole
 * command path and the main transport must not compete for stdin. */
static int preparation_relay_retire(pid_t *relay,int stop,int *wait_unknown) {
    if (!wait_unknown || *wait_unknown) return 0;
    if (*relay <= 1) return *relay == -1;
    int wait_for_exit = stop;
    uint64_t now = milliseconds(), deadline = now ? now + 2000 : 0;
    for (;;) {
        int status = 0; pid_t got = waitpid(*relay,&status,WNOHANG);
        if (got == *relay && (WIFEXITED(status) || WIFSIGNALED(status))) { *relay = -1; return 1; }
        if (got > 0 || (got < 0 && errno != EINTR)) { *wait_unknown = 1; return 0; }
        if (got == 0 && stop) { (void)kill(*relay,SIGTERM); stop = 0; }
        if (!wait_for_exit) return 0;
        if (!deadline || !(now = milliseconds()) || now >= deadline) return 0;
        struct timespec pause = {0,10000000}; (void)nanosleep(&pause,NULL);
    }
}
static int preparation_command(pid_t relay,int lease,int recovery,unsigned *drained,char command[40]) {
    /* A reaped relay can still have commands buffered in its pipes. Consume
     * both through EOF before stdin takes over; otherwise a retry S is lost. */
    int pipes = relay > 1 || *drained != 3;
    struct pollfd inputs[2] = {{pipes ? (*drained & 1 ? -1 : lease) : 0,POLLIN | POLLHUP,0},
        {*drained & 2 ? -1 : recovery,POLLIN | POLLHUP,0}};
    int ready = poll(inputs,pipes ? 2 : 1,250);
    if (ready <= 0) return ready < 0 && errno != EINTR ? -1 : 0;
    if (!pipes) return line(0,command,40,1000) ? -1 : 1;
    for (int i = 0; i < 2; i++) {
        if (!(inputs[i].revents & (POLLIN | POLLHUP))) continue;
        ssize_t n = read(inputs[i].fd,command,1);
        if (n == 0) { *drained |= 1U << i; continue; }
        if (n < 0) return errno == EINTR || errno == EAGAIN ? 0 : -1;
        command[1] = 0;
        if ((i == 1 && command[0] != 'R') || (i == 0 && command[0] == 'R')) return refuse(EINVAL);
        return 1;
    }
    if ((inputs[0].revents | inputs[1].revents) & (POLLHUP | POLLERR | POLLNVAL)) poll(NULL,0,50);
    return 0;
}
static int preparation_handoff_stop(const struct envara_app_native_preflight *plan,
    envara_app_native_factory *factory,struct frontend_stop_context *frontend,
    pid_t relay,struct envara_app_preparation_report *preparation) {
    int denied = envara_app_native_factory_cleanup_deny(factory) == 1;
    int closed = stop_owned_frontend(frontend) == 1;
    if (relay == -1 && denied && closed && envara_app_native_factory_cleanup_binding(factory) == 1 &&
        cleanup_stopping_event(plan,0,1) == 0) return 1;
    (void)envara_app_preparation_pending_event(preparation,"S",denied,closed,1); return 0;
}
static int run(const struct envara_app_native_preflight *plan) {
    envara_app_native_failure_begin();
    struct envara_gui_session graphics;
    if (envara_gui_session_read(&graphics) || graphics.console_uid != plan->console_uid ||
        !graphics.audit_has_console_graphics || !graphics.security_has_graphics) {
        refused_event(plan->run_id, plan->environment_id, "gui-session", EACCES); return refuse(EACCES);
    }
    /* Audit/session evidence is fresh. Exact bootstrap namespace and whole-
     * guardian death remain acceptance gates; no verified/ready flag is set. */
    struct sigaction action = {0}; action.sa_handler = stop_signal; sigemptyset(&action.sa_mask); stopped = 0;
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) || sigaction(SIGHUP, &action, NULL)) return -1;
    signal(SIGPIPE, SIG_IGN);
    struct envara_transport_session session; envara_transport_session_init(&session);
    struct envara_app_listener listener = {.fd = -1}; struct envara_identity front = {0};
    envara_app_native_factory *factory = NULL;
    struct abort_pin abort_pin = {.run_fd = -1, .lease_fd = -1}; struct abort_proof abort = {0};
    int front_input = -1, front_output = -1, front_reaped = 0, lease[2] = {-1,-1}, recovery[2] = {-1,-1};
    const char *stage = "route-read";
    const char *early_reason="NATIVE_OPERATION_REFUSED";
    pid_t relay = -1; char route[4096] = {0}, first[4608], reply[1024], expected[1024]; int error;
    if (line(0, route, sizeof(route), 5000)) goto early;
    stage = "transport-start";
    if (envara_transport_session_start(INSTALL "/mihomo", plan->state_directory, plan->ipv4, route, &session)) goto early;
    stage = "front-listen"; if (envara_app_listener_open_for_plan(plan,&listener)) goto early;
    stage = "front-spawn"; if (spawn_front(&listener, &front_input, &front_output, &front)) goto early;
    stage = "front-handshake";
    int n = snprintf(first, sizeof(first),
        "{\"schema\":\"envara.macos-pf-notion-front/v1\",\"runId\":\"%s\",\"environmentId\":\"%s\","
        "\"leaseId\":\"%s\",\"generation\":\"%s\",\"upstream\":%s}\n",
        plan->run_id, plan->environment_id, plan->lease_id, plan->generation, route);
    erase(route, sizeof(route));
    if (n <= 0 || n >= (int)sizeof(first) || write_bounded(front_input, first, (size_t)n)) { erase(first, sizeof(first)); goto early; }
    erase(first, sizeof(first));
    n = snprintf(expected, sizeof(expected),
        "{\"schema\":\"envara.macos-pf-notion-front/v1\",\"operation\":\"front-started\",\"runId\":\"%s\","
        "\"environmentId\":\"%s\",\"leaseId\":\"%s\",\"generation\":\"%s\",\"pid\":%d,\"host\":\"127.0.0.1\","
        "\"port\":%u,\"ready\":false,\"protected\":false}",
        plan->run_id, plan->environment_id, plan->lease_id, plan->generation, front.pid, listener.port);
    if (n <= 0 || n >= (int)sizeof(expected) || line(front_output, reply, sizeof(reply), 5000) ||
        strcmp(reply, expected) || !envara_same_process(&front) || envara_app_listener_verify(&listener)) goto early;
    close(front_output); front_output = -1;
    /* Control relay is created only when L is accepted. Before that, the
     * original native parent reads K/S/R itself and retains both sockets. */
    if (pipe_private(lease) || pipe_private(recovery)) goto early;
    struct frontend_stop_context frontend_stop = {.owner = getpid(), .input = &front_input, .reaped = &front_reaped, .frontend = &front};
    if (fstat(front_input, &frontend_stop.writer)) goto early;
    struct envara_app_native_owned_context owned = {.original_utun_fd = session.original_utun_fd,
        .original_listener_fd = listener.fd, .lease_read_fd = lease[0], .recovery_read_fd = recovery[0],
        .controller = plan->controller, .core = session.core, .frontend = front,
        .stop_frontend = stop_owned_frontend, .frontend_context = &frontend_stop};
    strcpy(owned.run_id, plan->run_id); strcpy(owned.environment_id, plan->environment_id);
    if (strlen(session.interface_name) >= sizeof(owned.tunnel_name)) goto early;
    strcpy(owned.tunnel_name, session.interface_name);
    stage = "factory-open";
    if(abort_pin_open(plan,&abort_pin)){early_reason="NATIVE_CONTEXT_LOAD_REFUSED";goto early;}
    if(abort_capture(plan,&session,&listener,&front,&abort_pin,&abort)){early_reason="NATIVE_ORIGINAL_SOCKET_REFUSED";goto early;}
    if (envara_app_native_factory_open(&owned, &factory)) { early_reason=envara_app_native_failure_reason();abort.factory_failed = 1; goto early; }
    abort_pin_close(&abort_pin);
    EnvaraPFProductionResult filter;
    stage = "deny-commit";
    /* Burn the pre-stage abort path BEFORE any attempt, including lost replies. */
    abort.deny_attempted = abort.filter_attempted = 1;
    int deny_confirmed=envara_app_native_factory_apply(factory,ENVARA_PF_PRODUCTION_DENY,&filter)==0;
    int initial_error=errno;const char *initial_reason=envara_app_native_failure_reason();
    int fault=!deny_confirmed,deny_attempted=!deny_confirmed;
    int fault_error=fault?initial_error:0;const char *fault_reason=initial_reason,*fault_stage=stage;
    int transport_acked=0;
#define RUN_FAULT(value,reason) do {if(!fault){fault_error=(value)>0?(value):EIO;fault_reason=(reason);fault_stage=stage;}fault=1;}while(0)
    if(!fault){stage="transport-ack";if(transport_event(plan,&session,&listener,&front))RUN_FAULT(errno,"NATIVE_OPERATION_REFUSED");else transport_acked=1;}
    int stage_used=0,diagnosed=0,child_reaped=0,child_absent=1,scope_quiescent=0;
    int preparation_handoff=0,preparation_stop_confirmed=0;
    int preparation_relay_wait_unknown=0;
    unsigned preparation_pipes_drained=0;
    struct envara_app_preparation_report preparation={0};
    for(;;){
        /* Capture a failure before process/lease queries or any cleanup can
         * change errno. A valid refusal permanently burns all launch paths. */
        if(stopped)RUN_FAULT(ECANCELED,"NATIVE_OPERATION_REFUSED");
        if(!fault&&(!envara_same_process(&session.core)||!envara_same_process(&front)||!envara_same_process(&plan->controller)))RUN_FAULT(ESTALE,"NATIVE_OPERATION_REFUSED");
        if(fault){
            envara_gui_steps_end();
            if(!diagnosed){
                refused_event_reason(plan->run_id,plan->environment_id,fault_stage,fault_reason,fault_error);diagnosed=1;
                if(!transport_acked&&envara_app_native_factory_cleanup_binding(factory)&&envara_same_process(&session.core)&&envara_same_process(&front)&&
                    cleanup_ready_event(plan,&session,&listener,&front,fault_stage)==0)transport_acked=1;
            }
            if(!deny_confirmed&&!deny_attempted){deny_attempted=1;deny_confirmed=envara_app_native_factory_cleanup_deny(factory)==1;}
            stopped=0;
        }
        if(preparation_handoff&&relay>1)(void)preparation_relay_retire(&relay,0,&preparation_relay_wait_unknown);
        char command[40];
        if(preparation_handoff){
            int got=preparation_command(relay,lease[0],recovery[0],&preparation_pipes_drained,command);
            if(got<0){RUN_FAULT(errno,"NATIVE_OPERATION_REFUSED");poll(NULL,0,250);}if(got<=0)continue;
        }else{
            struct pollfd input={0,POLLIN|POLLHUP,0};int ready=poll(&input,1,250);
            if(ready<0&&errno==EINTR)continue;if(ready<0){RUN_FAULT(errno,"NATIVE_OPERATION_REFUSED");continue;}if(!ready)continue;
            if(line(0,command,sizeof(command),1000)){int read_error=errno;RUN_FAULT(read_error,"NATIVE_OPERATION_REFUSED");poll(NULL,0,250);continue;}
        }
        if(!strcmp(command,"K")){if(!fault)continue;RUN_FAULT(ECANCELED,"NATIVE_OPERATION_REFUSED");continue;}
        if(!strcmp(command,"S")){
            RUN_FAULT(ECANCELED,"NATIVE_OPERATION_REFUSED");
            if(preparation_handoff){
                if(preparation.cleanup_attempt==INT_MAX)continue;
                preparation.cleanup_attempt++;
                preparation_stop_confirmed=preparation_handoff_stop(plan,factory,&frontend_stop,relay,&preparation);
                if(preparation_stop_confirmed)scope_quiescent=1;
                continue;
            }
            deny_confirmed=envara_app_native_factory_cleanup_deny(factory)==1;
            if(deny_confirmed&&envara_app_scope_gid_absent(plan->realm_gid)==1&&(child_reaped||child_absent)){
                scope_quiescent=1;(void)cleanup_stopping_event(plan,child_reaped,child_absent);
            }
            continue;
        }
        if(!strcmp(command,"R")){
            if(preparation_handoff&&!preparation_stop_confirmed){
                (void)envara_app_preparation_pending_event(&preparation,"R",0,front_reaped,1);continue;
            }
            if((child_reaped||child_absent)&&envara_app_native_factory_release_safe(factory)==1&&
                !envara_transport_session_stop(&session)&&!exact_stop(&front,&front_reaped))break;
            RUN_FAULT(errno,"NATIVE_OPERATION_REFUSED");continue;
        }
        if(fault||stage_used||strncmp(command,"L ",2)||!uuid(command+2)){RUN_FAULT(EINVAL,"NATIVE_OPERATION_REFUSED");continue;}
        stage_used=1;abort.launch_accepted=1;
        /* Diagnostic-only step timing for this one accepted launch; it can
         * never affect what the launch may do or what any frame proves. */
        (void)envara_gui_steps_begin(1,ENVARA_APP_TRANSPORT_PROTOCOL,plan->run_id,plan->environment_id);
        const struct envara_app_supervisor_provider *provider=envara_app_native_factory_provider(factory);
        /* A NULL adapter is the generic cold profile, which the supervisor runs
         * through envara_app_ticket_stage/envara_gui_stage. An absent provider
         * object itself is still a refusal. */
        if(!provider){RUN_FAULT(EACCES,"NATIVE_OPERATION_REFUSED");continue;}
        EnvaraPFProductionMode live=envara_app_native_factory_live_mode(factory);
        if(!mode_is_live_mode(live)){RUN_FAULT(ENOTSUP,"NATIVE_OPERATION_REFUSED");continue;}
        deny_confirmed=0;deny_attempted=0;stage="front-commit";
        if(envara_app_native_factory_apply(factory,live,&filter)){int e=errno;RUN_FAULT(e,envara_app_native_failure_reason());continue;}
        envara_gui_step(ENVARA_GUI_STEP_FRONT_COMMIT);
        stage="front-admission";if(admission(factory,front_input)){int e=errno;RUN_FAULT(e,envara_app_native_failure_reason());continue;}
        envara_gui_step(ENVARA_GUI_STEP_FRONT_ADMISSION);
        stage="ticket-prepare";
        /* Ticket preparation is one native operation: its first check of each
         * bundle is a full signed inspection; its later boundaries re-prove
         * that exact state's identity instead of re-hashing every byte. */
        if(!envara_gui_validation_scope_begin()){RUN_FAULT(EOVERFLOW,"NATIVE_OPERATION_REFUSED");continue;}
        struct envara_app_registry registry={.fd=-1};struct envara_app_ticket_store tickets={.fd=-1};struct envara_app_ticket prepared;
        int failed=envara_app_registry_open(&registry,NULL,0,0)||envara_app_ticket_store_open(&tickets,NULL,0,1)||
            envara_app_ticket_prepare(&tickets,&registry,command+2,plan->registration_id,plan->version_id,plan->environment_id,plan->run_id,&provider->ticket,&prepared);
        int prepare_error=errno;const char *prepare_reason=envara_app_native_failure_reason();
        envara_app_ticket_store_close(&tickets);envara_app_registry_close(&registry);
        envara_gui_validation_scope_end();
        if(failed){RUN_FAULT(prepare_error,prepare_reason);continue;}
        envara_gui_step(ENVARA_GUI_STEP_TICKET_PREPARE);
        stage="relay-fork";pid_t parent=getpid();relay=fork();
        if(relay<0){int e=errno;RUN_FAULT(e,"NATIVE_OPERATION_REFUSED");continue;}
        if(!relay){
            int held[]={lease[1],recovery[1]};if(envara_launch_guard_isolate_descriptors(held,2))_exit(126);
            int null=open("/dev/null",O_RDWR);if(null<0||dup2(null,1)<0||dup2(null,2)<0)_exit(126);if(null>2)close(null);stopped=0;
            (void)envara_app_transport_relay(0,lease[1],recovery[1],parent);_exit(0);
        }
        close(lease[1]);close(recovery[1]);lease[1]=recovery[1]=-1;
        envara_gui_step(ENVARA_GUI_STEP_RELAY_FORK);
        struct envara_app_supervisor_context supervisor={.provider=provider};struct envara_app_supervisor_report report;
        stage="guardian";abort.cold_attempted=1;envara_app_native_failure_begin();
        int status=envara_app_supervisor_run(&supervisor,command+2,1,&report);
        int supervisor_error=envara_app_native_failure_error(errno);const char *supervisor_reason=envara_app_native_failure_reason();
        envara_gui_steps_end();errno=supervisor_error;
        child_absent=report.child.phase==ENVARA_GUI_EMPTY;child_reaped=report.guardian.child_reaped;scope_quiescent=report.guardian.scope_quiescent_observed;
        /* Save the supervisor's first refusal BEFORE terminate/wait/query. */
        if(report.preparation_refusal_emitted){
            supervisor_error=report.preparation.original_error;supervisor_reason="NATIVE_APP_KEYCHAIN_PREPARATION_REFUSED";diagnosed=1;
        }
        if(status||!report.released)RUN_FAULT(supervisor_error,supervisor_reason);
        if(report.preparation_cleanup_confirmed){
            preparation_handoff=1;preparation=report.preparation;
            child_absent=1;child_reaped=0;scope_quiescent=0;
            (void)preparation_relay_retire(&relay,1,&preparation_relay_wait_unknown);
            preparation_stop_confirmed=preparation_handoff_stop(plan,factory,&frontend_stop,relay,&preparation);
            if(preparation_stop_confirmed)scope_quiescent=1;
            continue;
        }
        kill(relay,SIGTERM);while(waitpid(relay,NULL,0)<0&&errno==EINTR){}relay=-1;
        if(status||!report.released)continue;
        if(envara_app_native_factory_release_safe(factory)==1&&!envara_transport_session_stop(&session)&&!exact_stop(&front,&front_reaped))break;
        RUN_FAULT(errno,"NATIVE_OPERATION_REFUSED");
    }
#undef RUN_FAULT
    envara_app_native_factory_close(factory); factory = NULL;
    if (front_input >= 0) close(front_input);
    for (int i = 0; i < 2; i++) { if (lease[i] >= 0) close(lease[i]); if (recovery[i] >= 0) close(recovery[i]); }
    if (envara_app_listener_close(&listener) || envara_transport_session_release(&session)) return -1;
    char released[768]; int released_size = snprintf(released, sizeof(released),
        "{\"schema\":\"%s\",\"event\":\"transport-released\",\"runId\":\"%s\",\"environmentId\":\"%s\","
        "\"keeperPID\":%d,\"coreReaped\":true,\"frontReaped\":true,\"childReaped\":%s,\"childAbsent\":%s,"
        "\"scopeQuiescentObserved\":%s,\"originalUTunClosed\":true,\"originalListenerClosed\":true,"
        "\"filterEmptyVerified\":true,\"privateJournalRetired\":true,\"ready\":false,\"protected\":false}\n",
        ENVARA_APP_TRANSPORT_PROTOCOL, plan->run_id, plan->environment_id, getpid(), child_reaped ? "true" : "false",
        child_absent ? "true" : "false", (scope_quiescent || child_absent) ? "true" : "false");
    stopped = 0;
    if (released_size <= 0 || released_size >= (int)sizeof(released)) return refuse(EOVERFLOW);
    if (write_bounded(1, released, (size_t)released_size)) return -1;
    return 0;
early:
    /* No factory mutation or application child exists on this path. Core and
     * front must still be exactly reaped before original descriptor release. */
    error = errno ? errno : EIO; refused_event_reason(plan->run_id,plan->environment_id,stage,early_reason,error);
    erase(route, sizeof(route)); erase(first, sizeof(first));
    if (front_output >= 0) close(front_output);
    if (front_input >= 0) close(front_input);
    if (!strcmp(stage, "factory-open")) {
        /* This distinct receipt has no application-child or FILTER release
         * semantics. Unknown bindings, observations or closes retain custody. */
        if (factory || !abort.factory_failed || !abort.captured || abort.deny_attempted || abort.filter_attempted ||
            abort.launch_accepted || abort.cold_attempted) for (;;) poll(NULL, 0, 250);
        if (exact_stop(&front, &front_reaped) || envara_transport_session_stop(&session)) for (;;) poll(NULL, 0, 250);
        abort.front_reaped = front_reaped; abort.core_reaped = session.core_reaped;
        if (abort_pin_fresh(&abort_pin) || !abort_journal_absent(&abort_pin) || envara_app_scope_gid_absent(plan->realm_gid) != 1 ||
            !abort_originals_fresh(&session, &listener, &abort) || !envara_same_process(&abort.keeper) || !envara_same_process(&abort.parent)) for (;;) poll(NULL, 0, 250);
        abort.scope_before = abort.journal_before = 1;
        if (abort_close_original(session.original_utun_fd)) for (;;) poll(NULL, 0, 250);
        abort.utun_closed = 1; session.original_utun_fd = -1;
        if (abort_close_original(listener.fd)) for (;;) poll(NULL, 0, 250);
        abort.listener_closed = 1; listener.fd = -1;
        if (envara_app_scope_gid_absent(plan->realm_gid) != 1 || abort_pin_fresh(&abort_pin) || !abort_journal_absent(&abort_pin) ||
            !envara_same_process(&abort.keeper) || !envara_same_process(&abort.parent)) for (;;) poll(NULL, 0, 250);
        abort.scope_after = abort.journal_after = 1;
        char terminal[4096]; int count = abort_frame(&abort, terminal, sizeof(terminal));
        if (count < 1 || write_bounded(1, terminal, (size_t)count)) for (;;) poll(NULL, 0, 250);
        abort_pin_close(&abort_pin);
        if (session.state_fd >= 0) close(session.state_fd);
        for (int i = 0; i < 2; i++) { if (lease[i] >= 0) close(lease[i]); if (recovery[i] >= 0) close(recovery[i]); }
        return refuse(error); /* main exits 1; Node must observe that same exit. */
    }
    abort_pin_close(&abort_pin);
    if (front.pid > 1 && exact_stop(&front, &front_reaped)) {
        for (;;) poll(NULL, 0, 250); /* unknown custody: no optimistic close */
    }
    if (session.core.pid > 1 && envara_transport_session_stop(&session)) for (;;) poll(NULL, 0, 250);
    if (listener.fd >= 0) (void)envara_app_listener_close(&listener);
    if (session.core_reaped) (void)envara_transport_session_release(&session);
    for (int i = 0; i < 2; i++) { if (lease[i] >= 0) close(lease[i]); if (recovery[i] >= 0) close(recovery[i]); }
    return refuse(error);
}
