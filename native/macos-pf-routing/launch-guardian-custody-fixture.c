#include "launch-guardian.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* Exercise the actual custody function, not a second implementation. The
 * production branch below has synthetic control metadata over an owned UNIX
 * socket; it never proves real UTun custody or protected application routing.
 * A separate real, UNCONNECTED kernel-control socket establishes Darwin's
 * getsockname API behavior without connect, an interface, PF, or routing.
 * Apple XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea:
 * kern_control.c ctl_usrreqs has peeraddr but no sockaddr callback;
 * uipc_socket2.c pru_sanitize selects pru_sockaddr_notsupp (EOPNOTSUPP).
 */
static int (*actual_getsockname)(int, struct sockaddr *, socklen_t *) = getsockname;
static int (*actual_getpeername)(int, struct sockaddr *, socklen_t *) = getpeername;
enum fault {
    GOOD, WRONG_TYPE, TYPE_LENGTH, CONTROL_ERROR, PEER_ERROR, PEER_LENGTH,
    PEER_FAMILY, PEER_SYSTEM, PEER_ID, PEER_UNIT, NAME_ERROR, NAME_UNTERMINATED,
    NAME_MISMATCH
};
static enum fault fault;
static int production_mode, local_name_calls, peer_calls, control_calls, name_calls;
static int observed_getsockname(int fd, struct sockaddr *address, socklen_t *length) {
    local_name_calls++;
    if (production_mode) { errno = EOPNOTSUPP; return -1; }
    return actual_getsockname(fd, address, length);
}
static int observed_getsockopt(int fd, int level, int option, void *value, socklen_t *length) {
    (void)fd;
    if (level == SOL_SOCKET && option == SO_TYPE) {
        *(int *)value = production_mode ? (fault == WRONG_TYPE ? SOCK_STREAM : SOCK_DGRAM) : SOCK_STREAM;
        *length = fault == TYPE_LENGTH ? sizeof(int) - 1 : sizeof(int); return 0;
    }
    if (level != SYSPROTO_CONTROL || option != UTUN_OPT_IFNAME || *length != 16) { errno = EINVAL; return -1; }
    name_calls++;
    if (fault == NAME_ERROR) { errno = ENXIO; return -1; }
    if (fault == NAME_UNTERMINATED) memset(value, 'x', 16);
    else strlcpy(value, fault == NAME_MISMATCH ? "utun998" : "utun999", *length);
    return 0;
}
static int observed_ioctl(int fd, unsigned long request, ...) {
    (void)fd; control_calls++;
    if (request != CTLIOCGINFO || fault == CONTROL_ERROR) { errno = ENOENT; return -1; }
    va_list arguments; va_start(arguments, request); struct ctl_info *info = va_arg(arguments, struct ctl_info *); va_end(arguments);
    if (strcmp(info->ctl_name, UTUN_CONTROL_NAME)) { errno = EINVAL; return -1; }
    info->ctl_id = 73; return 0;
}
static int observed_getpeername(int fd, struct sockaddr *address, socklen_t *length) {
    (void)fd; peer_calls++;
    if (fault == PEER_ERROR) { errno = ENOTCONN; return -1; }
    if (*length != sizeof(struct sockaddr_ctl)) { errno = EINVAL; return -1; }
    struct sockaddr_ctl peer = {0}; peer.sc_len = sizeof(peer);
    peer.sc_family = fault == PEER_FAMILY ? AF_UNIX : AF_SYSTEM;
    peer.ss_sysaddr = fault == PEER_SYSTEM ? 0 : AF_SYS_CONTROL;
    peer.sc_id = fault == PEER_ID ? 74 : 73;
    peer.sc_unit = fault == PEER_UNIT ? 0 : 1000;
    memcpy(address, &peer, sizeof(peer));
    *length = fault == PEER_LENGTH ? sizeof(peer) - 1 : sizeof(peer); return 0;
}
#define getsockname observed_getsockname
#define getsockopt observed_getsockopt
#define getpeername observed_getpeername
#define ioctl observed_ioctl
#include "launch-guardian.c"
#undef getsockname
#undef getsockopt
#undef getpeername
#undef ioctl

static int native_api(void) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) return 0;
    struct sockaddr_storage address = {0}; socklen_t length = sizeof(address);
    errno = 0; int result = actual_getsockname(fd, (struct sockaddr *)&address, &length), error = errno;
    length = sizeof(address); errno = 0;
    int peer_result = actual_getpeername(fd, (struct sockaddr *)&address, &length), peer_error = errno;
    close(fd);
    return result == -1 && error == EOPNOTSUPP && peer_result == -1 && peer_error == ENOTCONN;
}
int main(void) {
    if (getuid() == 0 || geteuid() != getuid()) return 1;
    int api = native_api(), pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return 1;
    struct envara_launch_guard_request request = {.retained_fd = pair[0]};
    strcpy(request.tunnel_name, "utun999");
    production_mode = 1; fault = GOOD;
    int duplicate = custody_fd(&request); struct stat original, copied;
    int valid = duplicate >= 3 && duplicate != pair[0] && !local_name_calls &&
        peer_calls == 1 && control_calls == 1 && name_calls == 1 &&
        !fstat(pair[0], &original) && !fstat(duplicate, &copied) &&
        original.st_dev == copied.st_dev && original.st_ino == copied.st_ino && original.st_mode == copied.st_mode &&
        (fcntl(duplicate, F_GETFD) & FD_CLOEXEC) && fcntl(pair[0], F_GETFD) >= 0;
    if (duplicate >= 0) close(duplicate);
    int refused = 0;
    for (fault = WRONG_TYPE; fault <= NAME_MISMATCH; fault++) {
        duplicate = custody_fd(&request);
        if (duplicate >= 0) { close(duplicate); valid = 0; } else refused++;
        if (local_name_calls || fcntl(pair[0], F_GETFD) < 0) valid = 0;
    }
    fault = GOOD; production_mode = 0; request.fixture_only = 1;
    duplicate = custody_fd(&request);
    int fixture = duplicate >= 3 && local_name_calls == 1;
    if (duplicate >= 0) close(duplicate);
    close(pair[0]); close(pair[1]);
    int okay = api && valid && fixture && refused == NAME_MISMATCH;
    printf("{\"ok\":%s,\"fixtureOnly\":true,\"ready\":false,\"protected\":false,\"activatesSystem\":false,"
           "\"createsUTun\":false,\"actualKernelControlGetsocknameUnsupported\":%s,\"productionUsesPeerOnly\":%s,"
           "\"fixtureUsesUnixGetsockname\":%s,\"rejectedMetadataCases\":%d}\n",
           okay ? "true" : "false", api ? "true" : "false", valid ? "true" : "false", fixture ? "true" : "false", refused);
    return okay ? 0 : 1;
}
