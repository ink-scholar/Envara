#ifndef ENVARA_PF_PRODUCTION_FILTER_H
#define ENVARA_PF_PRODUCTION_FILTER_H
#include <stdint.h>
#define ENVARA_PF_PRODUCTION_MAX_RULES 16U

/* Internal native constructor for exactly one owned application realm. This
 * source component does not open PF, authorize, activate PF, launch an app or
 * turn on any production capability. No caller rule bytes or target lists.
 * Fixed ROUTED profile: only the proved loopback TCP front, IPv4 TCP/UDP route
 * via the owned utun, no PF states; all other owned loopback/IPv6 TCP/UDP denied.
 * Pinned PF fragment handling omits GID checks: every GID row uses inclusive
 * port range 0..65535, which skips fragments. Owned fragment protection remains
 * unaccepted and MUST keep production activation gated off.
 * GID socket attribution does not cover ICMP/other protocols. */
typedef enum { ENVARA_PF_PRODUCTION_EMPTY = 0, ENVARA_PF_PRODUCTION_DENY = 1,
    ENVARA_PF_PRODUCTION_ROUTED = 2,
    /* First Notion scope: exact held loopback TCP port only. Its child-side
     * Seatbelt policy is a separate mandatory boundary; no broad route rows. */
    ENVARA_PF_PRODUCTION_FRONT = 3 } EnvaraPFProductionMode;
typedef struct {
    char run_id[37], realm_id[37];
    /* One shared root hook serves up to five attached applications. Each
     * application keeps its own rules in a sub-anchor below the shared anchor;
     * the shared anchor holds only the fixed call lines that reach them.
     * session_run_id is the shared (hook) run; run_id stays the application's
     * own run. An empty session_run_id keeps the original single-run layout,
     * where the anchor is the run itself. */
    char session_run_id[37];
    uint32_t gid;
    char utun[16];
    uint8_t route_ipv4[4];
    int listener_fd;
    uint16_t tcp_front_port;
    uint32_t expected_writer_pid, expected_revision;
    int has_previous_revision;
} EnvaraPFProductionConfig;
typedef enum {
    ENVARA_PF_PRODUCTION_GUARD_INITIAL = 0, ENVARA_PF_PRODUCTION_GUARD_BEGIN,
    ENVARA_PF_PRODUCTION_GUARD_BEGIN_ADDRS, ENVARA_PF_PRODUCTION_GUARD_ADD_ADDR,
    ENVARA_PF_PRODUCTION_GUARD_ADD_RULE, ENVARA_PF_PRODUCTION_GUARD_COMMIT,
    ENVARA_PF_PRODUCTION_GUARD_ROLLBACK, ENVARA_PF_PRODUCTION_GUARD_VERIFY
} EnvaraPFProductionStage;
typedef enum {
    ENVARA_PF_PRODUCTION_OK = 0, ENVARA_PF_PRODUCTION_INVALID_CONTEXT,
    ENVARA_PF_PRODUCTION_INVALID_CONFIG, ENVARA_PF_PRODUCTION_ALREADY_USED,
    ENVARA_PF_PRODUCTION_GUARD_REJECTED, ENVARA_PF_PRODUCTION_BEGIN_FAILED,
    ENVARA_PF_PRODUCTION_BEGIN_REPLY_INVALID, ENVARA_PF_PRODUCTION_POOL_FAILED,
    ENVARA_PF_PRODUCTION_POOL_REPLY_INVALID, ENVARA_PF_PRODUCTION_ADD_ADDR_FAILED,
    ENVARA_PF_PRODUCTION_ADD_ADDR_REPLY_INVALID, ENVARA_PF_PRODUCTION_ADD_RULE_FAILED,
    ENVARA_PF_PRODUCTION_ADD_RULE_REPLY_INVALID, ENVARA_PF_PRODUCTION_COMMIT_FAILED,
    ENVARA_PF_PRODUCTION_COMMIT_REPLY_INVALID, ENVARA_PF_PRODUCTION_VERIFY_FAILED
} EnvaraPFProductionReason;
typedef int (*EnvaraPFProductionIoctl)(void *, int, unsigned long, void *);
/* Exact 1 must freshly prove the held root lease, original PF descriptor,
 * sealed application/GID, exact owned utun /32, and the original held IPv4
 * TCP LISTEN descriptor bound to 127.0.0.1:tcp_front_port. The native factory
 * must inspect the actual FD and retain its identity; a port number or a JSON
 * assertion is not listener proof. Deny/empty still require the held binding.
 * BEGIN_ADDRS clears GLOBAL pf_pabuf; an Envara lock cannot exclude foreign
 * writers. Keep that concurrency gate unverified. rule_index=UINT32_MAX for
 * operations outside a rule. Configuration is copied at Init and immutable. */
typedef int (*EnvaraPFProductionGuard)(void *, int, EnvaraPFProductionStage,
    uint32_t rule_index);
typedef struct {
    int fd;
    void *opaque;
    EnvaraPFProductionIoctl ioctl_call;
    EnvaraPFProductionGuard guard;
    uint32_t magic, phase, creator_uid, creator_pid;
    int apply_used;
    EnvaraPFProductionConfig config;
} EnvaraPFProductionContext;
typedef struct {
    int read_only, begun, ticket_known;
    uint32_t ticket, writer_pid, expected_count, actual_count, rules_added, pools_verified;
    uint32_t rule_index;
    int pool_attempted, add_addr_attempted, commit_attempted, committed;
    int rollback_attempted, rollback_acknowledged, uncertain, verified;
    EnvaraPFProductionReason reason;
    int os_error;
} EnvaraPFProductionResult;

/* Zero-init; one serialized caller in the initializing native process. A NULL
 * ioctl callback uses ioctl(2), which can block without a hard deadline. Never
 * retry an ioctl, including EINTR. Apply is one-shot. Unknown/lost reply remains
 * uncertain even if an exact rollback is acknowledged or a later Verify passes.
 * The factory must durably preserve uncertain intent across new processes and
 * reject all future writes; Verify cannot adopt it or clear the poison latch.
 * Nonempty prior Verify requires the exact recorded writer PID and revision. */
int EnvaraPFProductionInit(EnvaraPFProductionContext *, int fd, void *opaque,
    EnvaraPFProductionIoctl, EnvaraPFProductionGuard, const EnvaraPFProductionConfig *);
int EnvaraPFProductionApply(EnvaraPFProductionContext *, EnvaraPFProductionMode, EnvaraPFProductionResult *);
int EnvaraPFProductionVerify(EnvaraPFProductionContext *, EnvaraPFProductionMode, EnvaraPFProductionResult *);
const char *EnvaraPFProductionReasonName(EnvaraPFProductionReason);
#endif
