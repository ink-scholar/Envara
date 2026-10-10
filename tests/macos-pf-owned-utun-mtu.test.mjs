import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, realpath, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const source = fileURLToPath(new URL('../native/macos-pf-routing/tunnel.c', import.meta.url));

test('production owned-utun configuration fixes MTU9000 only on its interface and refuses other MTUs before syscalls', { skip: process.platform !== 'darwin' }, async () => {
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-owned-utun-mtu-')));
  try {
    const fixture = path.join(directory, 'fixture.c');
    const binary = path.join(directory, 'fixture');
    await writeFile(fixture, `
#include <sys/types.h>
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
#include <stdarg.h>
#include <assert.h>

static uid_t fixture_uid;
static unsigned sockets, ioctls, closes, address_reads, address_frees;
static int inject_overlap, inject_mtu_failure;
static struct sockaddr_in existing_address;
static struct ifaddrs existing_interface;
static uid_t inert_getuid(void) { return fixture_uid; }
static int inert_socket(int family, int kind, int protocol) {
    assert(family == AF_INET && kind == SOCK_DGRAM && protocol == 0);
    sockets++; return 77;
}
static int inert_close(int fd) { assert(fd == 77); closes++; return 0; }
static int inert_getifaddrs(struct ifaddrs **out) {
    address_reads++;
    *out = inject_overlap ? &existing_interface : NULL; return 0;
}
static void inert_freeifaddrs(struct ifaddrs *value) {
    assert(value == (inject_overlap ? &existing_interface : NULL)); address_frees++;
}
static int inert_ioctl(int fd, unsigned long operation, ...) {
    assert(fd == 77); va_list values; va_start(values, operation);
    void *input = va_arg(values, void *); va_end(values); ioctls++;
    if (operation == SIOCSIFMTU) {
        struct ifreq *request = input;
        assert(!strcmp(request->ifr_name, "utun12345") && request->ifr_mtu == 9000);
        if (inject_mtu_failure) { errno = EIO; return -1; }
    } else if (operation == SIOCAIFADDR) {
        struct ifaliasreq *request = input;
        assert(!strcmp(request->ifra_name, "utun12345"));
        assert(((struct sockaddr_in *)&request->ifra_addr)->sin_addr.s_addr == existing_address.sin_addr.s_addr);
        assert(((struct sockaddr_in *)&request->ifra_mask)->sin_addr.s_addr == htonl(0xffffffffU));
    } else if (operation == SIOCGIFFLAGS) {
        struct ifreq *request = input; assert(!strcmp(request->ifr_name, "utun12345")); request->ifr_flags = 0;
    } else if (operation == SIOCSIFFLAGS) {
        struct ifreq *request = input; assert(!strcmp(request->ifr_name, "utun12345") && request->ifr_flags == IFF_UP);
    } else assert(0);
    return 0;
}
#define getuid inert_getuid
#define geteuid inert_getuid
#define socket inert_socket
#define close inert_close
#define getifaddrs inert_getifaddrs
#define freeifaddrs inert_freeifaddrs
#define ioctl inert_ioctl
#include ${JSON.stringify(source)}
#undef getuid
#undef geteuid
#undef socket
#undef close
#undef getifaddrs
#undef freeifaddrs
#undef ioctl

int main(void) {
    existing_address.sin_family = AF_INET;
    assert(inet_pton(AF_INET, "198.18.1.1", &existing_address.sin_addr) == 1);
    existing_interface.ifa_addr = (struct sockaddr *)&existing_address;
    unsigned rejected_mtus[] = {0, 1500, 4096, 8999, 9001, 65535};
    for (size_t i = 0; i < sizeof(rejected_mtus)/sizeof(rejected_mtus[0]); i++) {
        assert(envara_utun_configure("utun12345", "198.18.1.1", rejected_mtus[i]) == -1);
        assert(errno == EINVAL && !sockets && !ioctls && !address_reads);
    }
    assert(envara_utun_configure("en0", "198.18.1.1", 9000) == -1);
    assert(envara_utun_configure("utun12345", "192.0.2.1", 9000) == -1);
    assert(!sockets && !ioctls && !address_reads);
    fixture_uid = 501;
    assert(envara_utun_configure("utun12345", "198.18.1.1", 9000) == -1);
    assert(!sockets && !ioctls && !address_reads);
    fixture_uid = 0; inject_overlap = 1;
    assert(envara_utun_configure("utun12345", "198.18.1.1", 9000) == -1);
    assert(errno == EADDRINUSE && !sockets && !ioctls && address_reads == 1 && address_frees == 1);
    inject_overlap = 0;
    assert(envara_utun_configure("utun12345", "198.18.1.1", 9000) == 0);
    assert(sockets == 1 && ioctls == 4 && closes == 1 && address_reads == 2 && address_frees == 2);
    inject_mtu_failure = 1;
    assert(envara_utun_configure("utun12345", "198.18.1.1", 9000) == -1);
    assert(errno == EIO && sockets == 2 && ioctls == 5 && closes == 2);
    return 0;
}
`);
    await execute('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', fixture, '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
    await execute(binary, [], { timeout: 10000, maxBuffer: 1024 * 1024 });
  } finally { await rm(directory, { recursive: true, force: true }); }
});
