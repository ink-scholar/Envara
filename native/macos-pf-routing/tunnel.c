#include "native.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int envara_utun_open(char *name, size_t name_size) {
    struct ctl_info info;
    struct sockaddr_ctl address;
    int fd, error;
    socklen_t length;
    if (!name || name_size < 16 || name_size > 256) { errno = EINVAL; return -1; }
    if (getuid() != 0 || geteuid() != 0) { errno = EACCES; return -1; }
    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) return -1;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC)) goto failure;
    memset(&info, 0, sizeof(info));
    strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
    if (ioctl(fd, CTLIOCGINFO, &info)) goto failure;
    memset(&address, 0, sizeof(address));
    address.sc_len = sizeof(address);
    address.sc_family = AF_SYSTEM;
    address.ss_sysaddr = AF_SYS_CONTROL;
    address.sc_id = info.ctl_id;
    /* Zero requests a new free interface; never attach to a user's VPN. */
    address.sc_unit = 0;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address))) goto failure;
    length = (socklen_t)name_size;
    memset(name, 0, name_size);
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &length) ||
        !memchr(name, 0, name_size) || strncmp(name, "utun", 4)) goto failure;
    return fd;
failure:
    error = errno ? errno : EIO; close(fd); errno = error; return -1;
}

int envara_utun_configure(const char *name, const char *ipv4_address, unsigned mtu) {
    struct in_addr ipv4;
    struct ifaddrs *addresses = NULL;
    struct ifaliasreq alias;
    struct ifreq request;
    struct sockaddr_in address;
    int fd, error;
    if (getuid() != 0 || geteuid() != 0 || !name || strncmp(name, "utun", 4) ||
        strlen(name) >= IFNAMSIZ || mtu != 9000 || !ipv4_address || inet_pton(AF_INET, ipv4_address, &ipv4) != 1) {
        errno = EINVAL; return -1;
    }
    /* Dedicated benchmarking range, no arbitrary host address or default
     * route. Refuse overlap with any current interface's local address. */
    uint32_t host_address = ntohl(ipv4.s_addr);
    if ((host_address & 0xfffe0000U) != 0xc6120000U || getifaddrs(&addresses)) { errno = EINVAL; return -1; }
    for (struct ifaddrs *item = addresses; item; item = item->ifa_next) {
        if (item->ifa_addr && item->ifa_addr->sa_family == AF_INET &&
            ((struct sockaddr_in *)item->ifa_addr)->sin_addr.s_addr == ipv4.s_addr) {
            freeifaddrs(addresses); errno = EADDRINUSE; return -1;
        }
    }
    freeifaddrs(addresses);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    memset(&request, 0, sizeof(request)); strlcpy(request.ifr_name, name, sizeof(request.ifr_name));
    request.ifr_mtu = (int)mtu;
    if (ioctl(fd, SIOCSIFMTU, &request)) goto failure;
    memset(&alias, 0, sizeof(alias)); strlcpy(alias.ifra_name, name, sizeof(alias.ifra_name));
    memset(&address, 0, sizeof(address)); address.sin_len = sizeof(address); address.sin_family = AF_INET;
    address.sin_addr = ipv4;
    memcpy(&alias.ifra_addr, &address, sizeof(address));
    memcpy(&alias.ifra_broadaddr, &address, sizeof(address));
    address.sin_addr.s_addr = htonl(0xffffffffU); /* /32, own host route only. */
    memcpy(&alias.ifra_mask, &address, sizeof(address));
    if (ioctl(fd, SIOCAIFADDR, &alias)) goto failure;
    memset(&request, 0, sizeof(request)); strlcpy(request.ifr_name, name, sizeof(request.ifr_name));
    if (ioctl(fd, SIOCGIFFLAGS, &request)) goto failure;
    request.ifr_flags |= IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &request)) goto failure;
    close(fd); return 0;
failure:
    error = errno ? errno : EIO; close(fd); errno = error; return -1;
}

int envara_utun_frame_family(const unsigned char *frame, size_t length) {
    uint32_t family;
    if (!frame || length < 5) return -1;
    memcpy(&family, frame, sizeof(family)); family = ntohl(family);
    if (family == AF_INET && (frame[4] >> 4) == 4 && length >= 24) return AF_INET;
    if (family == AF_INET6 && (frame[4] >> 4) == 6 && length >= 44) return AF_INET6;
    return -1;
}
