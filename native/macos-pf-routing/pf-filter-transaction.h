#ifndef ENVARA_PF_FILTER_TRANSACTION_H
#define ENVARA_PF_FILTER_TRANSACTION_H
#include <stdint.h>
#define ENVARA_PF_FILTER_MAX_REALMS 2U
#define ENVARA_PF_FILTER_MAX_RULES 64U

/* Generated stateless controlled fixtures only. The destinations are fixed:
 * 1.1.1.1:53 and 198.51.100.42:44441..44444. No caller rule bytes, arbitrary
 * targets, devices, authorization, PF activation or production gates. */
typedef enum { ENVARA_PF_FILTER_EMPTY = 0, ENVARA_PF_FILTER_DENY = 1,
    ENVARA_PF_FILTER_ROUTED = 2 } EnvaraPFFilterMode;
typedef struct {
    char realm_id[37];
    uint32_t gid;
    char utun[16];
    uint8_t route_ipv4[4];
    int routed, udp_proxy;
} EnvaraPFFilterRealm;
typedef struct {
    char run_id[37];
    uint32_t realm_count;
    EnvaraPFFilterRealm realms[ENVARA_PF_FILTER_MAX_REALMS];
    uint32_t expected_writer_pid, expected_revision;
    int has_previous_revision;
} EnvaraPFFilterConfig;
typedef enum {
    ENVARA_PF_FILTER_GUARD_INITIAL = 0, ENVARA_PF_FILTER_GUARD_BEGIN,
    ENVARA_PF_FILTER_GUARD_BEGIN_ADDRS, ENVARA_PF_FILTER_GUARD_ADD_ADDR,
    ENVARA_PF_FILTER_GUARD_ADD_RULE, ENVARA_PF_FILTER_GUARD_COMMIT,
    ENVARA_PF_FILTER_GUARD_ROLLBACK, ENVARA_PF_FILTER_GUARD_VERIFY
} EnvaraPFFilterStage;
typedef enum {
    ENVARA_PF_FILTER_OK = 0, ENVARA_PF_FILTER_INVALID_CONTEXT,
    ENVARA_PF_FILTER_INVALID_CONFIG, ENVARA_PF_FILTER_ALREADY_USED,
    ENVARA_PF_FILTER_GUARD_REJECTED, ENVARA_PF_FILTER_BEGIN_FAILED,
    ENVARA_PF_FILTER_BEGIN_REPLY_INVALID, ENVARA_PF_FILTER_POOL_FAILED,
    ENVARA_PF_FILTER_POOL_REPLY_INVALID, ENVARA_PF_FILTER_ADD_ADDR_FAILED,
    ENVARA_PF_FILTER_ADD_ADDR_REPLY_INVALID, ENVARA_PF_FILTER_ADD_RULE_FAILED,
    ENVARA_PF_FILTER_ADD_RULE_REPLY_INVALID, ENVARA_PF_FILTER_COMMIT_FAILED,
    ENVARA_PF_FILTER_COMMIT_REPLY_INVALID, ENVARA_PF_FILTER_VERIFY_FAILED
} EnvaraPFFilterReason;
typedef int (*EnvaraPFFilterIoctl)(void *, int, unsigned long, void *);
/* Exact 1 means fresh root lease, descriptor, permitted PF state and all owned
 * realm/GID/interface identity proofs. BEGIN_ADDRS resets global pf_pabuf;
 * caller must explicitly authorize this and retain the foreign-pool concurrency
 * gate as unverified. rule_index is UINT32_MAX outside per-rule operations. */
typedef int (*EnvaraPFFilterGuard)(void *, int, EnvaraPFFilterStage, uint32_t rule_index);
typedef struct {
    int fd;
    void *opaque;
    EnvaraPFFilterIoctl ioctl_call;
    EnvaraPFFilterGuard guard;
    uint32_t magic, phase, creator_uid, creator_pid;
    int apply_used;
    EnvaraPFFilterConfig config;
} EnvaraPFFilterContext;
typedef struct {
    int read_only, begun, ticket_known;
    uint32_t ticket, writer_pid, expected_count, actual_count, rules_added, pools_verified;
    uint32_t rule_index;
    int pool_attempted, add_addr_attempted, commit_attempted, committed;
    int rollback_attempted, rollback_acknowledged, uncertain, verified;
    EnvaraPFFilterReason reason;
    int os_error;
} EnvaraPFFilterResult;

/* Zero-initialize; one serialized caller in the initializing process. NULL
 * ioctl_call uses real ioctl(2); inert tests must inject it. No ioctl is retried.
 * Apply is one-shot; a new process does not resolve a previous lost reply.
 * The root caller must persist uncertain intent/receipt and forbid future writes.
 * Verify never clears Apply's used/poison latch. Nonempty prior Verify requires
 * has_previous_revision=1 and exact recorded expected_writer_pid. A blocked
 * kernel ioctl has no hard wall-clock deadline in this component. */
int EnvaraPFFilterInit(EnvaraPFFilterContext *, int fd, void *opaque,
    EnvaraPFFilterIoctl, EnvaraPFFilterGuard, const EnvaraPFFilterConfig *);
int EnvaraPFFilterApply(EnvaraPFFilterContext *, EnvaraPFFilterMode, EnvaraPFFilterResult *);
int EnvaraPFFilterVerify(EnvaraPFFilterContext *, EnvaraPFFilterMode, EnvaraPFFilterResult *);
const char *EnvaraPFFilterReasonName(EnvaraPFFilterReason);
#endif
