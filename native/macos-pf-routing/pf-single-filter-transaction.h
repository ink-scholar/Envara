#ifndef ENVARA_PF_SINGLE_FILTER_TRANSACTION_H
#define ENVARA_PF_SINGLE_FILTER_TRANSACTION_H
#include <stdint.h>

/* Source-only canary primitive. It does not open devices, authorize, install,
 * enable PF, delete a root hook, touch states, or start a production adapter.
 * Callers own the descriptor, its access/device proof, the exclusive installed
 * lease and a fresh PF-disabled proof. No arbitrary anchor or rule is accepted.
 * A NULL ioctl callback uses the real ioctl(2); tests must supply a mock. */
#define ENVARA_SINGLE_FILTER_UUID "a85314b8-5b24-4784-95ec-47b739c2e841"
#define ENVARA_SINGLE_FILTER_ANCHOR "io.envara.pf.run." ENVARA_SINGLE_FILTER_UUID
#define ENVARA_SINGLE_FILTER_LABEL "envara.single-filter.v1.d48eea351ad7f68f5e847861d154e219"

typedef enum {
    ENVARA_SINGLE_FILTER_EMPTY = 0,
    ENVARA_SINGLE_FILTER_DENY = 1
} EnvaraSingleFilterOperation;
typedef enum {
    ENVARA_SINGLE_FILTER_GUARD_INITIAL = 0,
    ENVARA_SINGLE_FILTER_GUARD_BEGIN,
    ENVARA_SINGLE_FILTER_GUARD_BEGIN_ADDRS,
    ENVARA_SINGLE_FILTER_GUARD_ADD,
    ENVARA_SINGLE_FILTER_GUARD_COMMIT,
    ENVARA_SINGLE_FILTER_GUARD_ROLLBACK,
    ENVARA_SINGLE_FILTER_GUARD_VERIFY
} EnvaraSingleFilterStage;
typedef enum {
    ENVARA_SINGLE_FILTER_OK = 0,
    ENVARA_SINGLE_FILTER_INVALID_CONTEXT,
    ENVARA_SINGLE_FILTER_INVALID_SEQUENCE,
    ENVARA_SINGLE_FILTER_GUARD_REJECTED,
    ENVARA_SINGLE_FILTER_BEGIN_FAILED,
    ENVARA_SINGLE_FILTER_BEGIN_REPLY_INVALID,
    ENVARA_SINGLE_FILTER_POOL_FAILED,
    ENVARA_SINGLE_FILTER_POOL_REPLY_INVALID,
    ENVARA_SINGLE_FILTER_ADD_FAILED,
    ENVARA_SINGLE_FILTER_ADD_REPLY_INVALID,
    ENVARA_SINGLE_FILTER_COMMIT_FAILED,
    ENVARA_SINGLE_FILTER_COMMIT_REPLY_INVALID,
    ENVARA_SINGLE_FILTER_VERIFY_FAILED
} EnvaraSingleFilterReason;
typedef int (*EnvaraSingleFilterIoctl)(void *opaque, int fd, unsigned long request, void *argument);
/* Return exactly 1 only after fresh proof of PF disabled, the exact leased own
 * root hook and this descriptor. BEGIN_ADDRS also requires the caller's explicit
 * permission for its global pf_pabuf reset: an Envara lock cannot exclude a
 * foreign PF pool transaction. This concurrency gate remains unaccepted. */
typedef int (*EnvaraSingleFilterGuard)(void *opaque, int fd, EnvaraSingleFilterStage stage);
typedef struct {
    int fd;
    void *opaque;
    EnvaraSingleFilterIoctl ioctl_call;
    EnvaraSingleFilterGuard guard;
    uint32_t magic, phase, creator_uid, creator_pid;
} EnvaraSingleFilterContext;
typedef struct {
    int begun, ticket_known;
    uint32_t ticket;
    int pool_attempted, pool_known, add_attempted;
    int commit_attempted, committed;
    int rollback_attempted, rollback_acknowledged;
    int uncertain, verified;
    uint32_t actual_count;
    EnvaraSingleFilterReason reason;
    int os_error;
} EnvaraSingleFilterResult;

/* Context must be zero initialized and used in its initializing process.
 * Exactly EMPTY -> DENY -> EMPTY is allowed. Use one serialized caller; this
 * context is not a thread-safe shared object. Reentrant calls poison it.
 * Any failure poisons it; initialize
 * cannot reset a used context. There is no retry of any ioctl, including EINTR.
 * A kernel-blocked ioctl has no hard wall-clock deadline in this component. */
int EnvaraSingleFilterInit(EnvaraSingleFilterContext *context, int fd, void *opaque,
    EnvaraSingleFilterIoctl ioctl_call, EnvaraSingleFilterGuard guard);
int EnvaraSingleFilterApply(EnvaraSingleFilterContext *context,
    EnvaraSingleFilterOperation operation, EnvaraSingleFilterResult *result);
const char *EnvaraSingleFilterReasonName(EnvaraSingleFilterReason reason);
#endif
