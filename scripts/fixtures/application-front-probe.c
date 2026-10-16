/* Nonroot, bounded network probe for the exact native application front profile.
 * The harness supplies owned numeric endpoints. DNSServiceCreateConnection opens
 * and immediately closes the stock daemon connection; no name query is sent. */
#include <arpa/inet.h>
#include <dns_sd.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <netinet/in.h>
#include <servers/bootstrap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

struct result {
    int success, error, echoed, status, socket_fd, peer_family;
    char peer[108];
};

static void report(const char *operation, const char *mode, const struct result *r) {
    /* peer is either empty or the fixed public mDNSResponder socket pathname. */
    printf("{\"operation\":\"%s\",\"mode\":\"%s\",\"pid\":%d,\"ppid\":%d,"
        "\"success\":%s,\"error\":%d,\"echoed\":%s,\"status\":%d,\"socketFD\":%d,"
        "\"peerFamily\":%d,\"systemDNSPeer\":\"%s\",\"dnsNameQueriesSent\":0}\n",
        operation, mode, getpid(), getppid(), r->success ? "true" : "false", r->error,
        r->echoed ? "true" : "false", r->status, r->socket_fd, r->peer_family, r->peer);
    fflush(stdout);
}

static int parse_port(const char *text) {
    char *end = NULL; long port = strtol(text, &end, 10);
    return end && !*end && port > 0 && port <= 65535 ? (int)port : -1;
}

static struct result inet_probe(const char *operation, const char *host, const char *port_text, const char *nonce) {
    struct result r = {.socket_fd = -1};
    int port = parse_port(port_text), v6 = strchr(host, ':') != NULL;
    int udp = !strncmp(operation, "udp", 3), connect_only = !strcmp(operation, "udp-connect");
    if (port < 0 || strlen(nonce) < 8 || strlen(nonce) > 60 || strspn(nonce, "abcdefghijklmnopqrstuvwxyz0123456789-") != strlen(nonce)) {
        r.error = EINVAL; return r;
    }
    struct sockaddr_storage storage = {0}; socklen_t length;
    if (v6) {
        struct sockaddr_in6 *address = (void *)&storage;
        address->sin6_len = sizeof(*address); address->sin6_family = AF_INET6; address->sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, host, &address->sin6_addr) != 1) { r.error = EINVAL; return r; }
        length = sizeof(*address);
    } else {
        struct sockaddr_in *address = (void *)&storage;
        address->sin_len = sizeof(*address); address->sin_family = AF_INET; address->sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, host, &address->sin_addr) != 1) { r.error = EINVAL; return r; }
        length = sizeof(*address);
    }
    int fd = socket(v6 ? AF_INET6 : AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (fd < 0) { r.error = errno; return r; }
    struct timeval timeout = {.tv_sec = 2};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (udp && !connect_only) {
        unsigned char payload[128]; size_t count = strlen(nonce);
        if (!strcmp(operation, "udp-dns")) {
            /* A complete A/IN query, sent only to the harness's owned high-port
             * receiver. No system resolver or external destination is used. */
            memset(payload, 0, sizeof(payload)); payload[0] = 0x45; payload[1] = 0x6e;
            payload[2] = 1; payload[5] = 1; payload[12] = (unsigned char)count;
            memcpy(payload + 13, nonce, count); size_t end = 13 + count;
            payload[end++] = 7; memcpy(payload + end, "invalid", 7); end += 7;
            payload[end++] = 0; payload[end++] = 0; payload[end++] = 1;
            payload[end++] = 0; payload[end++] = 1; count = end;
        } else memcpy(payload, nonce, count);
        r.success = sendto(fd, payload, count, 0, (struct sockaddr *)&storage, length) == (ssize_t)count;
        r.error = r.success ? 0 : errno;
    } else {
        r.success = connect(fd, (struct sockaddr *)&storage, length) == 0;
        r.error = r.success ? 0 : errno;
        if (r.success && !connect_only) {
            size_t count = strlen(nonce); char reply[128] = {0};
            ssize_t sent = send(fd, nonce, count, 0), received = sent == (ssize_t)count ? recv(fd, reply, sizeof(reply), 0) : -1;
            r.echoed = received == (ssize_t)count && !memcmp(reply, nonce, count);
            if (!r.echoed) r.error = errno ? errno : EIO;
        }
        /* UDP connect sets a peer without transmitting any datagram. This is
         * used for port 53/853/5353 denial without contacting a DNS server. */
    }
    close(fd); return r;
}

static struct result unix_probe(const char *filename, const char *nonce) {
    struct result r = {.socket_fd = -1};
    struct sockaddr_un address = {0};
    if (filename[0] != '/' || strlen(filename) >= sizeof(address.sun_path)) { r.error = EINVAL; return r; }
    address.sun_len = sizeof(address); address.sun_family = AF_UNIX; strcpy(address.sun_path, filename);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0); if (fd < 0) { r.error = errno; return r; }
    struct timeval timeout = {.tv_sec = 2};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    r.success = connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0;
    r.error = r.success ? 0 : errno;
    if (r.success) {
        char reply[128] = {0}; size_t count = strlen(nonce);
        ssize_t sent = send(fd, nonce, count, 0), received = sent == (ssize_t)count ? recv(fd, reply, sizeof(reply), 0) : -1;
        r.echoed = received == (ssize_t)count && !memcmp(reply, nonce, count);
        if (!r.echoed) r.error = errno ? errno : EIO;
    }
    close(fd); return r;
}

static struct result dns_connection(void) {
    struct result r = {.socket_fd = -1}; DNSServiceRef ref = NULL;
    errno = 0; r.status = DNSServiceCreateConnection(&ref); r.error = errno; r.success = r.status == kDNSServiceErr_NoError;
    if (r.success && ref) {
        r.socket_fd = DNSServiceRefSockFD(ref);
        struct sockaddr_un peer = {0}; socklen_t length = sizeof(peer);
        if (!getpeername(r.socket_fd, (struct sockaddr *)&peer, &length)) {
            r.peer_family = peer.sun_family;
            if (peer.sun_family == AF_UNIX && (!strcmp(peer.sun_path, "/var/run/mDNSResponder") ||
                !strcmp(peer.sun_path, "/private/var/run/mDNSResponder"))) strcpy(r.peer, peer.sun_path);
        }
    }
    if (ref) DNSServiceRefDeallocate(ref);
    return r;
}

static struct result dns_mach(void) {
    struct result r = {.socket_fd = -1}; mach_port_t port = MACH_PORT_NULL;
    errno = 0; r.status = bootstrap_look_up(bootstrap_port, "com.apple.dnssd.service", &port);
    r.error = errno; r.success = r.status == KERN_SUCCESS;
    if (port != MACH_PORT_NULL) (void)mach_port_deallocate(mach_task_self(), port);
    return r;
}

int main(int argc, char **argv) {
    if (!getuid() || geteuid() != getuid() || getgid() != getegid() || argc != 7) return 90;
    const char *operation = argv[1], *mode = argv[6];
    if (strcmp(mode, "direct") && strcmp(mode, "fork") && strcmp(mode, "exec") && strcmp(mode, "exec-child")) return 91;
    if (strcmp(operation, "tcp") && strcmp(operation, "udp") && strcmp(operation, "udp-dns") && strcmp(operation, "udp-connect") &&
        strcmp(operation, "unix") && strcmp(operation, "dnssd") && strcmp(operation, "dns-mach")) return 92;
    alarm(10); signal(SIGPIPE, SIG_IGN);
    if (!strcmp(mode, "fork") || !strcmp(mode, "exec")) {
        pid_t child = fork(); if (child < 0) return 93;
        if (child) {
            int status; while (waitpid(child, &status, 0) < 0) { if (errno != EINTR) return 94; }
            return WIFEXITED(status) ? WEXITSTATUS(status) : 95;
        }
        alarm(8);
        if (!strcmp(mode, "exec")) { argv[6] = "exec-child"; execv(argv[0], argv); return 96; }
    }
    struct result result;
    if (!strcmp(operation, "dnssd")) result = dns_connection();
    else if (!strcmp(operation, "dns-mach")) result = dns_mach();
    else if (!strcmp(operation, "unix")) result = unix_probe(argv[2], argv[4]);
    else result = inet_probe(operation, argv[2], argv[3], argv[4]);
    report(operation, !strcmp(mode, "exec-child") ? "exec" : mode, &result);
    return 0;
}
