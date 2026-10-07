#ifndef ENVARA_CAPTURE_H
#define ENVARA_CAPTURE_H
#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#ifdef ENVARA_CAPTURE_BUILD
#define ENVARA_API __declspec(dllexport)
#else
#define ENVARA_API __declspec(dllimport)
#endif
#define ENVARA_CALL WINAPI
#else
#define ENVARA_API
#define ENVARA_CALL
#endif
#ifdef __cplusplus
extern "C" {
#endif

#define ENVARA_CAPTURE_ABI 1u
#define ENVARA_CAPTURE_MAX_FLOWS 2048u
#define ENVARA_CAPTURE_MAX_IDENTITIES 1024u
enum { ENVARA_ID_UNKNOWN=0, ENVARA_ID_UNOWNED=1, ENVARA_ID_OWNED=2, ENVARA_ID_BLOCKED=3 };
enum { ENVARA_OK=0, ENVARA_ERR_ARGUMENT=1, ENVARA_ERR_STATE=2, ENVARA_ERR_DRIVER=3,
       ENVARA_ERR_IDENTITY=4, ENVARA_ERR_CAPACITY=5, ENVARA_ERR_NOT_FOUND=6 };

/* IPv4 uses address[0..3] in network byte order; IPv6 uses all 16 bytes.
 * Ports, counters and all scalar fields are host byte order. No packed structs. */
typedef struct { uint8_t address[16]; uint16_t port; uint8_t family; uint8_t reserved; } EnvaraEndpoint;
typedef struct { EnvaraEndpoint source, destination; uint8_t protocol; uint8_t reserved[7]; } EnvaraTuple;
typedef struct {
    uint32_t size, version, pid, reserved;
    uint64_t creation_time, process_handle;
} EnvaraIdentityRequest;
typedef struct {
    uint32_t size, version, decision, reserved;
    uint64_t route_tag, session_tag, generation;
} EnvaraIdentityResult;
/* Called concurrently on SOCKET event and NETWORK worker threads, without
 * capture's lock held. The callback must be thread safe. process_handle
 * is borrowed only for this call. The service must query this actual handle's
 * membership in retained Jobs. Names, parent PID claims and caller JSON are not
 * ownership evidence. UNKNOWN must never be promoted to UNOWNED. */
typedef uint32_t (ENVARA_CALL *EnvaraResolveIdentity)(uint64_t context,
    const EnvaraIdentityRequest *, EnvaraIdentityResult *);
typedef struct {
    uint32_t size, version, relay_port, hold_milliseconds;
    uint64_t resolve_identity, callback_context;
} EnvaraCaptureConfig;
typedef struct {
    uint32_t size, version;
    EnvaraTuple accepted; /* peer/source and local/destination from accepted socket */
} EnvaraRelayQuery;
typedef struct {
    uint32_t size, version;
    uint64_t flow_id, route_tag, session_tag, generation, creation_time;
    uint32_t pid, reserved;
    EnvaraTuple original;
} EnvaraRelayResult;
typedef struct {
    uint32_t size, version;
    uint64_t session_tag, generation;
} EnvaraRevokeRequest;
typedef struct {
    uint32_t size, version, running, socket_ready;
    uint32_t network_ready, tcp_capture, udp_blocking, identity_callback;
    uint32_t ready, dns, fail_closed, verification_passed;
    uint64_t intercepted, reinjected, blocked, unknown_dropped, unsupported_dropped;
    uint32_t active_flows, active_identities, last_error, reserved;
} EnvaraCaptureStatus;

/* One DLL instance per privileged service. Bind Go relay on 0.0.0.0 and [::]
 * with this same port (separate IPv6-only socket). Existing loopback-only binds
 * do not match the NAT addresses. Reject every socket without LookupRelay.
 * Start reports capture setup only, never readiness or protected acceptance. */
ENVARA_API uint32_t ENVARA_CALL EnvaraCaptureStart(const EnvaraCaptureConfig *);
ENVARA_API uint32_t ENVARA_CALL EnvaraCaptureStop(void);
ENVARA_API uint32_t ENVARA_CALL EnvaraCaptureRevokeSession(const EnvaraRevokeRequest *);
ENVARA_API uint32_t ENVARA_CALL EnvaraCaptureLookupRelay(const EnvaraRelayQuery *, EnvaraRelayResult *);
ENVARA_API uint32_t ENVARA_CALL EnvaraCaptureStatusRead(EnvaraCaptureStatus *);
#ifdef __cplusplus
}
#endif
#endif
