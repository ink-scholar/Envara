#include "pf-single-filter-transaction.h"
#include "pf-hook-abi.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

/* Layout source: Mullvad pfctl-rs commit
 * 273e96bec0f5b983f16cfd43b6512f4c97a3f848/src/ffi/pfvar.rs
 * SHA256 e09ade2fe4be76579bd8185eeccd561deb9f89f84db69dc5ae50a386425b78d6.
 * Behavior source: Apple XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea,
 * bsd/net/pf_ioctl.c: pf_begin_rules, pf_rollback_rules, pf_commit_rules,
 * pf_rule_copyin/out, DIOCXBEGIN/COMMIT/ROLLBACK, DIOCBEGINADDRS/ADDRULE.
 * Current Darwin 27 source is unpublished: this is not host ABI acceptance or
 * proof of the cause of earlier namespace retention. No TABLE entry exists. */
typedef struct {
    int32_t rs_num;
    char anchor[1024];
    uint32_t ticket;
} SingleFilterEntry;
typedef struct {
    int32_t size, esize;
    SingleFilterEntry *array;
} SingleFilterTransaction;
typedef struct __attribute__((aligned(8))) { uint8_t bytes[88]; } SingleFilterPoolAddress;
typedef struct {
    uint32_t action, ticket, nr, r_num;
    uint8_t r_action, r_last, af;
    char anchor[1024];
    SingleFilterPoolAddress addr;
} SingleFilterPoolRequest;
typedef struct {
    uint8_t address[16], mask[16];
    uint64_t pointer;
    uint8_t type, iflags, pad[6];
} SingleFilterAddressWrap;
typedef union {
    struct { uint16_t port[2]; uint8_t op, pad; } range;
    uint32_t alignment[2];
} SingleFilterTransport;
typedef struct {
    SingleFilterAddressWrap address;
    SingleFilterTransport transport;
    uint8_t neg, pad[7];
} SingleFilterRuleAddress;
_Static_assert(sizeof(SingleFilterEntry) == 1032, "transaction entry size");
_Static_assert(offsetof(SingleFilterEntry, anchor) == 4, "transaction anchor offset");
_Static_assert(offsetof(SingleFilterEntry, ticket) == 1028, "transaction ticket offset");
_Static_assert(sizeof(SingleFilterTransaction) == 16, "transaction envelope size");
_Static_assert(offsetof(SingleFilterTransaction, array) == 8, "transaction array offset");
_Static_assert(sizeof(SingleFilterPoolRequest) == 1136, "pool request size");
_Static_assert(offsetof(SingleFilterPoolRequest, ticket) == 4, "pool ticket offset");
_Static_assert(offsetof(SingleFilterPoolRequest, anchor) == 19, "pool anchor offset");
_Static_assert(offsetof(SingleFilterPoolRequest, addr) == 1048, "pool address offset");
_Static_assert(sizeof(SingleFilterAddressWrap) == 48, "address wrapper size");
_Static_assert(offsetof(SingleFilterAddressWrap, type) == 40, "address type offset");
_Static_assert(sizeof(SingleFilterTransport) == 8, "transport union size");
_Static_assert(sizeof(SingleFilterRuleAddress) == 64, "rule address size");
_Static_assert(offsetof(SingleFilterRuleAddress, transport) == 48, "transport offset");
_Static_assert(offsetof(SingleFilterRuleAddress, neg) == 56, "negation offset");
#define SINGLE_BEGIN _IOWR('D', 81, SingleFilterTransaction)
#define SINGLE_COMMIT _IOWR('D', 82, SingleFilterTransaction)
#define SINGLE_ROLLBACK _IOWR('D', 83, SingleFilterTransaction)
#define SINGLE_BEGIN_ADDRS _IOWR('D', 51, SingleFilterPoolRequest)
#define SINGLE_ADD _IOWR('D', 4, EnvaraPFHookRequest)
_Static_assert(SINGLE_BEGIN == 0xc0104451UL, "BEGIN ioctl encoding");
_Static_assert(SINGLE_COMMIT == 0xc0104452UL, "COMMIT ioctl encoding");
_Static_assert(SINGLE_ROLLBACK == 0xc0104453UL, "ROLLBACK ioctl encoding");
_Static_assert(SINGLE_BEGIN_ADDRS == 0xc4704433UL, "BEGINADDRS ioctl encoding");
_Static_assert(SINGLE_ADD == 0xcc204404UL, "ADDRULE ioctl encoding");
#define SINGLE_MAGIC UINT32_C(0x45534631)
#define SINGLE_POISON UINT32_MAX
#define SINGLE_IN_PROGRESS (UINT32_MAX - 1U)

static int single_ioctl(EnvaraSingleFilterContext *context, unsigned long request, void *argument) {
    uint32_t expected_phase = request == SINGLE_ROLLBACK ? SINGLE_POISON : SINGLE_IN_PROGRESS;
    if (context->phase != expected_phase) { errno = ECANCELED; return -1; }
    errno = 0;
    int response = context->ioctl_call ? context->ioctl_call(context->opaque, context->fd, request, argument)
        : ioctl(context->fd, request, argument);
    if (context->phase != expected_phase) { errno = ECANCELED; return -1; }
    return response;
}
static int single_guard(EnvaraSingleFilterContext *context, EnvaraSingleFilterStage stage,
    EnvaraSingleFilterResult *result) {
    uint32_t expected_phase = stage == ENVARA_SINGLE_FILTER_GUARD_ROLLBACK ? SINGLE_POISON : SINGLE_IN_PROGRESS;
    if (context->phase == expected_phase && context->creator_pid == (uint32_t)getpid() &&
        context->creator_uid == (uint32_t)geteuid() && context->guard(context->opaque, context->fd, stage) == 1 &&
        context->phase == expected_phase) return 1;
    result->reason = ENVARA_SINGLE_FILTER_GUARD_REJECTED;
    return 0;
}
static SingleFilterEntry single_entry(uint32_t ticket) {
    SingleFilterEntry entry = {0}; entry.rs_num = 1; entry.ticket = ticket;
    memcpy(entry.anchor, ENVARA_SINGLE_FILTER_ANCHOR, sizeof(ENVARA_SINGLE_FILTER_ANCHOR));
    return entry;
}
static int single_transaction_reply(const SingleFilterTransaction *transaction,
    const SingleFilterEntry *entry, uint32_t ticket) {
    SingleFilterEntry expected = single_entry(ticket);
    return transaction->size == 1 && transaction->esize == (int32_t)sizeof(*entry) &&
        transaction->array == entry && !memcmp(entry, &expected, sizeof(expected));
}
static EnvaraPFHookRule single_deny_rule(const EnvaraSingleFilterContext *context, int readback) {
    EnvaraPFHookRule rule = {0}; SingleFilterRuleAddress destination = {0};
    const uint8_t address[4] = {198, 51, 100, 42};
    memcpy(destination.address.address, address, sizeof(address));
    memset(destination.address.mask, 255, sizeof(address));
    destination.transport.range.port[0] = htons(44441);
    destination.transport.range.port[1] = htons(44441);
    destination.transport.range.op = 2;
    memcpy(rule.dst, &destination, sizeof(destination));
    memcpy(rule.owner, ENVARA_SINGLE_FILTER_ANCHOR, sizeof(ENVARA_SINGLE_FILTER_ANCHOR));
    memcpy(rule.label, ENVARA_SINGLE_FILTER_LABEL, sizeof(ENVARA_SINGLE_FILTER_LABEL));
    rule.priority = UINT32_MAX; rule.action = 1; rule.direction = 2;
    rule.quick = 1; rule.af = 2; rule.proto = 6;
    if (readback) {
        /* Exact pinned copyin/setup/copyout changes, not an opaque-field mask:
         * rpool.af = rule.af (pf_rule_setup); cuid/cpid set by pf_rule_copyin;
         * one final rule has no following skip targets (DIOCGETRULE).
         * All state, source-node and packet counters must remain zero. */
        uint8_t *bytes = (uint8_t *)&rule;
        bytes[576 + 66] = 2;
        memcpy(bytes + 956, &context->creator_uid, sizeof(uint32_t));
        memcpy(bytes + 960, &context->creator_pid, sizeof(uint32_t));
        for (size_t i = 0; i < sizeof(rule.skip); i += 8) {
            uint32_t end = UINT32_MAX; memcpy(rule.skip + i, &end, sizeof(end));
        }
    }
    return rule;
}
static EnvaraPFHookRequest single_read_request(void) {
    EnvaraPFHookRequest request = {0};
    memcpy(request.anchor, ENVARA_SINGLE_FILTER_ANCHOR, sizeof(ENVARA_SINGLE_FILTER_ANCHOR));
    return request;
}
static int single_verify(EnvaraSingleFilterContext *context, EnvaraSingleFilterOperation operation,
    EnvaraSingleFilterResult *result) {
    EnvaraPFHookRequest first = single_read_request();
    uint32_t expected_count = operation == ENVARA_SINGLE_FILTER_DENY ? 1U : 0U;
    if (!single_guard(context, ENVARA_SINGLE_FILTER_GUARD_VERIFY, result)) return 0;
    if (single_ioctl(context, ENVARA_PF_HOOK_GET_RULES, &first)) { result->os_error = errno; return 0; }
    result->actual_count = first.nr;
    EnvaraPFHookRequest expected = single_read_request();
    expected.nr = expected_count; expected.ticket = result->ticket;
    if (memcmp(&first, &expected, sizeof(first))) return 0;
    if (expected_count) {
        EnvaraPFHookRequest row = single_read_request(); row.ticket = result->ticket;
        if (!single_guard(context, ENVARA_SINGLE_FILTER_GUARD_VERIFY, result)) return 0;
        if (single_ioctl(context, ENVARA_PF_HOOK_GET_RULE, &row)) { result->os_error = errno; return 0; }
        EnvaraPFHookRequest wanted = single_read_request(); wanted.ticket = result->ticket;
        wanted.rule = single_deny_rule(context, 1);
        if (memcmp(&row, &wanted, sizeof(row))) return 0;
    }
    EnvaraPFHookRequest last = single_read_request();
    if (!single_guard(context, ENVARA_SINGLE_FILTER_GUARD_VERIFY, result)) return 0;
    if (single_ioctl(context, ENVARA_PF_HOOK_GET_RULES, &last)) { result->os_error = errno; return 0; }
    return !memcmp(&last, &expected, sizeof(last));
}
static void single_rollback(EnvaraSingleFilterContext *context, EnvaraSingleFilterResult *result) {
    /* A reply to a failed BEGIN is not an owned ticket. Rollback's zero return
     * also means missing/mismatched/no-open transaction in pinned XNU, so this
     * acknowledgement is never proof of active emptiness or namespace removal.
     * After a lost COMMIT reply uncertainty stays true, even if rollback is 0. */
    if (!result->ticket_known || result->committed || result->rollback_attempted) return;
    EnvaraSingleFilterReason original = result->reason;
    if (!single_guard(context, ENVARA_SINGLE_FILTER_GUARD_ROLLBACK, result)) { result->reason = original; return; }
    SingleFilterEntry entry = single_entry(result->ticket);
    SingleFilterTransaction transaction = {1, (int32_t)sizeof(entry), &entry};
    result->rollback_attempted = 1;
    if (!single_ioctl(context, SINGLE_ROLLBACK, &transaction) &&
        single_transaction_reply(&transaction, &entry, result->ticket)) result->rollback_acknowledged = 1;
}
int EnvaraSingleFilterInit(EnvaraSingleFilterContext *context, int fd, void *opaque,
    EnvaraSingleFilterIoctl ioctl_call, EnvaraSingleFilterGuard guard) {
    if (!context || context->magic || fd < 0 || !guard) return 0;
    memset(context, 0, sizeof(*context)); context->fd = fd; context->opaque = opaque;
    context->ioctl_call = ioctl_call; context->guard = guard; context->magic = SINGLE_MAGIC;
    context->creator_uid = (uint32_t)geteuid(); context->creator_pid = (uint32_t)getpid();
    return 1;
}
int EnvaraSingleFilterApply(EnvaraSingleFilterContext *context,
    EnvaraSingleFilterOperation operation, EnvaraSingleFilterResult *result) {
    if (!result) { if (context && context->magic == SINGLE_MAGIC) context->phase = SINGLE_POISON; return 0; }
    memset(result, 0, sizeof(*result)); result->actual_count = UINT32_MAX;
    if (!context || context->magic != SINGLE_MAGIC || !context->guard || context->fd < 0) {
        result->reason = ENVARA_SINGLE_FILTER_INVALID_CONTEXT; return 0;
    }
    if (!((context->phase == 0 && operation == ENVARA_SINGLE_FILTER_EMPTY) ||
        (context->phase == 1 && operation == ENVARA_SINGLE_FILTER_DENY) ||
        (context->phase == 2 && operation == ENVARA_SINGLE_FILTER_EMPTY))) {
        result->reason = ENVARA_SINGLE_FILTER_INVALID_SEQUENCE; context->phase = SINGLE_POISON; return 0;
    }
    uint32_t original_phase = context->phase;
    context->phase = SINGLE_IN_PROGRESS;
    if (!single_guard(context, ENVARA_SINGLE_FILTER_GUARD_INITIAL, result) ||
        !single_guard(context, ENVARA_SINGLE_FILTER_GUARD_BEGIN, result)) goto failed;
    SingleFilterEntry entry = single_entry(0);
    SingleFilterTransaction transaction = {1, (int32_t)sizeof(entry), &entry};
    result->begun = 1; result->uncertain = 1;
    if (single_ioctl(context, SINGLE_BEGIN, &transaction)) {
        result->reason = ENVARA_SINGLE_FILTER_BEGIN_FAILED; result->os_error = errno; goto failed;
    }
    /* Successful exact replies preserve all uint32 tickets, including wrap to
     * zero. The success/envelope proof, not a nonzero heuristic, owns it. */
    if (!single_transaction_reply(&transaction, &entry, entry.ticket)) {
        result->reason = ENVARA_SINGLE_FILTER_BEGIN_REPLY_INVALID; goto failed;
    }
    result->ticket_known = 1; result->ticket = entry.ticket;
    if (operation == ENVARA_SINGLE_FILTER_DENY) {
        if (!single_guard(context, ENVARA_SINGLE_FILTER_GUARD_BEGIN_ADDRS, result)) goto failed;
        /* DIOCBEGINADDRS clears global pf_pabuf even for a no-pool filter. The
         * fixed all-zero request adds no addresses. No DIOCADDADDR or route
         * pool is supported. Caller must keep the concurrency gate explicit. */
        SingleFilterPoolRequest pool = {0}; result->pool_attempted = 1;
        if (single_ioctl(context, SINGLE_BEGIN_ADDRS, &pool)) {
            result->reason = ENVARA_SINGLE_FILTER_POOL_FAILED; result->os_error = errno; goto failed;
        }
        SingleFilterPoolRequest expected_pool = {0}; expected_pool.ticket = pool.ticket;
        if (memcmp(&pool, &expected_pool, sizeof(pool))) {
            result->reason = ENVARA_SINGLE_FILTER_POOL_REPLY_INVALID; goto failed;
        }
        result->pool_known = 1;
        EnvaraPFHookRequest request = single_read_request(); request.ticket = result->ticket;
        request.pool_ticket = pool.ticket; request.rule = single_deny_rule(context, 0);
        EnvaraPFHookRequest expected_request = request;
        if (!single_guard(context, ENVARA_SINGLE_FILTER_GUARD_ADD, result)) goto failed;
        result->add_attempted = 1;
        if (single_ioctl(context, SINGLE_ADD, &request)) {
            result->reason = ENVARA_SINGLE_FILTER_ADD_FAILED; result->os_error = errno; goto failed;
        }
        if (memcmp(&request, &expected_request, sizeof(request))) {
            result->reason = ENVARA_SINGLE_FILTER_ADD_REPLY_INVALID; goto failed;
        }
    }
    if (!single_guard(context, ENVARA_SINGLE_FILTER_GUARD_COMMIT, result)) goto failed;
    entry = single_entry(result->ticket); transaction = (SingleFilterTransaction){1, (int32_t)sizeof(entry), &entry};
    result->commit_attempted = 1;
    if (single_ioctl(context, SINGLE_COMMIT, &transaction)) {
        result->reason = ENVARA_SINGLE_FILTER_COMMIT_FAILED; result->os_error = errno; goto failed;
    }
    result->committed = 1;
    if (!single_transaction_reply(&transaction, &entry, result->ticket)) {
        result->reason = ENVARA_SINGLE_FILTER_COMMIT_REPLY_INVALID; goto failed;
    }
    if (!single_verify(context, operation, result)) {
        if (result->reason != ENVARA_SINGLE_FILTER_GUARD_REJECTED) result->reason = ENVARA_SINGLE_FILTER_VERIFY_FAILED;
        goto failed;
    }
    result->verified = 1; result->uncertain = 0; context->phase = original_phase + 1U; return 1;
failed:
    context->phase = SINGLE_POISON; single_rollback(context, result); return 0;
}
const char *EnvaraSingleFilterReasonName(EnvaraSingleFilterReason reason) {
    static const char *const names[] = {"okay", "invalid-context", "invalid-sequence", "guard-rejected",
        "begin-failed", "begin-reply-invalid", "pool-failed", "pool-reply-invalid", "add-failed",
        "add-reply-invalid", "commit-failed", "commit-reply-invalid", "verify-failed"};
    return (unsigned)reason < sizeof(names) / sizeof(names[0]) ? names[reason] : "invalid-reason";
}
