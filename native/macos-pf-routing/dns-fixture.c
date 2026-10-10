/* Owned, unprivileged DNS acceptance fixture. Never launch a user application. */
#include <arpa/inet.h>
#include <dispatch/dispatch.h>
#include <dns_sd.h>
#include <errno.h>
#include <netdb.h>
#include <Network/Network.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 64;
    size_t host_length = strlen(argv[2]);
    if (host_length < 8 || strcmp(argv[2] + host_length - 8, ".invalid") != 0) return 64;
    alarm(10);
    if (strncmp(argv[1], "dns-udp", 7) == 0 || strncmp(argv[1], "dns-tcp", 7) == 0) {
        int is_udp = strncmp(argv[1], "dns-udp", 7) == 0;
        int is_v6 = strchr(argv[1], '6') != NULL;
        int fd = socket(is_v6 ? AF_INET6 : AF_INET, is_udp ? SOCK_DGRAM : SOCK_STREAM, 0);
        struct sockaddr_in v4 = {.sin_len = sizeof(v4), .sin_family = AF_INET, .sin_port = htons(53)};
        struct sockaddr_in6 v6 = {.sin6_len = sizeof(v6), .sin6_family = AF_INET6, .sin6_port = htons(53)};
        v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        v6.sin6_addr = in6addr_loopback;
        const struct sockaddr *destination = is_v6 ? (const struct sockaddr *)&v6 : (const struct sockaddr *)&v4;
        socklen_t length = is_v6 ? sizeof(v6) : sizeof(v4);
        errno = 0;
        int status = is_udp ? (int)sendto(fd, "\0", 1, 0, destination, length) : connect(fd, destination, length);
        printf("{\"mode\":\"%s\",\"uid\":%u,\"status\":%d,\"errno\":%d}\n", argv[1], getuid(), status, errno);
        if (fd >= 0) close(fd);
        return 0;
    }
    if (strcmp(argv[1], "getaddrinfo") == 0) {
        struct addrinfo hints = {0}, *answers = NULL;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int status = getaddrinfo(argv[2], "443", &hints, &answers);
        printf("{\"mode\":\"getaddrinfo\",\"uid\":%u,\"status\":%d,\"addresses\":[", getuid(), status);
        int first = 1;
        for (struct addrinfo *answer = answers; answer; answer = answer->ai_next) {
            char address[INET_ADDRSTRLEN];
            if (answer->ai_family != AF_INET) continue;
            struct sockaddr_in *sa = (struct sockaddr_in *)answer->ai_addr;
            if (!inet_ntop(AF_INET, &sa->sin_addr, address, sizeof(address))) continue;
            printf("%s\"%s\"", first ? "" : ",", address);
            first = 0;
        }
        puts("]}");
        if (answers) freeaddrinfo(answers);
        return 0;
    }
    if (strcmp(argv[1], "dnssd") == 0) {
        DNSServiceRef service = NULL;
        DNSServiceErrorType status = DNSServiceCreateConnection(&service);
        printf("{\"mode\":\"dnssd\",\"uid\":%u,\"status\":%d}\n", getuid(), status);
        if (service) DNSServiceRefDeallocate(service);
        return 0;
    }
    if (strcmp(argv[1], "network-framework") == 0) {
        nw_endpoint_t endpoint = nw_endpoint_create_host(argv[2], "443");
        nw_parameters_t parameters = nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
        nw_connection_t connection = nw_connection_create(endpoint, parameters);
        dispatch_queue_t queue = dispatch_queue_create("io.envara.fixture.dns", DISPATCH_QUEUE_SERIAL);
        dispatch_semaphore_t finished = dispatch_semaphore_create(0);
        __block int state = 0, error_code = 0, error_domain = 0;
        nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t new_state, nw_error_t error) {
            state = (int)new_state;
            error_code = error ? nw_error_get_error_code(error) : 0;
            error_domain = error ? (int)nw_error_get_error_domain(error) : 0;
            if (new_state == nw_connection_state_failed || new_state == nw_connection_state_ready || (new_state == nw_connection_state_waiting && error)) dispatch_semaphore_signal(finished);
        });
        nw_connection_set_queue(connection, queue);
        nw_connection_start(connection);
        int timed_out = dispatch_semaphore_wait(finished, dispatch_time(DISPATCH_TIME_NOW, 4 * NSEC_PER_SEC)) != 0;
        dispatch_sync(queue, ^{});
        printf("{\"mode\":\"network-framework\",\"uid\":%u,\"state\":%d,\"errorCode\":%d,\"errorDomain\":%d,\"timedOut\":%s}\n", getuid(), state, error_code, error_domain, timed_out ? "true" : "false");
        nw_connection_cancel(connection);
        return 0;
    }
    return 64;
}
