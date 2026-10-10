#include "pf-filter-transaction.h"
#include "pf-hook-abi.h"
#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Generated layout: Mullvad pfctl-rs 273e96bec0f5b983f16cfd43b6512f4c97a3f848
 * src/ffi/pfvar.rs, SHA256 e09ade2fe4be76579bd8185eeccd561deb9f89f84db69dc5ae50a386425b78d6.
 * Behavior: Apple XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea bsd/net/pf_ioctl.c,
 * pf_rule_copyin/out/setup, pf_get_pool, DIOCX*, DIOCBEGINADDRS/ADDADDR/ADDRULE;
 * bsd/net/pf.c pf_calc_skip_steps and PF_POOL_NONE. Matching Darwin27 source is
 * unpublished. Source/build checks are not route, ABI or production acceptance.
 * There is exactly one FILTER entry; no TABLE, state, authorization or CLI API. */
typedef struct { int32_t rs_num; char anchor[1024]; uint32_t ticket; } FilterEntry;
typedef struct { int32_t size, esize; FilterEntry *array; } FilterTransaction;
typedef struct { uint8_t address[16], mask[16]; uint64_t pointer; uint8_t type, iflags, pad[6]; } FilterAddress;
typedef struct { FilterAddress address; uint64_t entries[2]; char ifname[16]; uint64_t kif; } FilterPoolAddress;
typedef struct {
    uint32_t action, ticket, nr, r_num;
    uint8_t r_action, r_last, af;
    char anchor[1024];
    FilterPoolAddress addr;
} FilterPoolRequest;
typedef union { struct { uint16_t port[2]; uint8_t op, pad; } range; uint32_t words[2]; } FilterTransport;
typedef struct { FilterAddress address; FilterTransport transport; uint8_t neg, pad[7]; } FilterRuleAddress;
typedef struct { EnvaraPFHookRule rule; FilterPoolAddress pool; int has_pool; } FilterGeneratedRule;
typedef struct { char anchor[64]; uint32_t count; FilterGeneratedRule rows[ENVARA_PF_FILTER_MAX_RULES]; } FilterPlan;
#define FILTER_OFFSET(type, field, offset) _Static_assert(offsetof(type, field) == offset, #field " ABI offset")
_Static_assert(sizeof(FilterEntry) == 1032 && _Alignof(FilterEntry) == 4, "transaction entry ABI");
FILTER_OFFSET(FilterEntry, anchor, 4); FILTER_OFFSET(FilterEntry, ticket, 1028);
_Static_assert(sizeof(FilterTransaction) == 16 && _Alignof(FilterTransaction) == 8, "transaction envelope ABI");
FILTER_OFFSET(FilterTransaction, array, 8);
_Static_assert(sizeof(FilterAddress) == 48 && _Alignof(FilterAddress) == 8, "address ABI");
FILTER_OFFSET(FilterAddress, mask, 16); FILTER_OFFSET(FilterAddress, pointer, 32); FILTER_OFFSET(FilterAddress, type, 40);
_Static_assert(sizeof(FilterPoolAddress) == 88 && _Alignof(FilterPoolAddress) == 8, "pool address ABI");
FILTER_OFFSET(FilterPoolAddress, entries, 48); FILTER_OFFSET(FilterPoolAddress, ifname, 64); FILTER_OFFSET(FilterPoolAddress, kif, 80);
_Static_assert(sizeof(FilterPoolRequest) == 1136 && _Alignof(FilterPoolRequest) == 8, "pool request ABI");
FILTER_OFFSET(FilterPoolRequest, ticket, 4); FILTER_OFFSET(FilterPoolRequest, r_num, 12); FILTER_OFFSET(FilterPoolRequest, r_action, 16);
FILTER_OFFSET(FilterPoolRequest, af, 18); FILTER_OFFSET(FilterPoolRequest, anchor, 19); FILTER_OFFSET(FilterPoolRequest, addr, 1048);
_Static_assert(sizeof(FilterRuleAddress) == 64 && _Alignof(FilterRuleAddress) == 8, "rule address ABI");
FILTER_OFFSET(FilterRuleAddress, transport, 48); FILTER_OFFSET(FilterRuleAddress, neg, 56);
#undef FILTER_OFFSET
#define FILTER_BEGIN _IOWR('D', 81, FilterTransaction)
#define FILTER_COMMIT _IOWR('D', 82, FilterTransaction)
#define FILTER_ROLLBACK _IOWR('D', 83, FilterTransaction)
#define FILTER_BEGIN_ADDRS _IOWR('D', 51, FilterPoolRequest)
#define FILTER_ADD_ADDR _IOWR('D', 52, FilterPoolRequest)
#define FILTER_GET_ADDRS _IOWR('D', 53, FilterPoolRequest)
#define FILTER_GET_ADDR _IOWR('D', 54, FilterPoolRequest)
#define FILTER_ADD_RULE _IOWR('D', 4, EnvaraPFHookRequest)
_Static_assert(FILTER_BEGIN == 0xc0104451UL && FILTER_COMMIT == 0xc0104452UL && FILTER_ROLLBACK == 0xc0104453UL, "transaction ioctl ABI");
_Static_assert(FILTER_BEGIN_ADDRS == 0xc4704433UL && FILTER_ADD_ADDR == 0xc4704434UL, "pool mutation ioctl ABI");
_Static_assert(FILTER_GET_ADDRS == 0xc4704435UL && FILTER_GET_ADDR == 0xc4704436UL && FILTER_ADD_RULE == 0xcc204404UL, "pool/rule ioctl ABI");
enum { FILTER_PASS = 0, FILTER_DROP = 1, FILTER_IN = 1, FILTER_OUT = 2,
    FILTER_INET = 2, FILTER_INET6 = 30, FILTER_TCP = 6, FILTER_UDP = 17,
    FILTER_EQ = 2, FILTER_ROUTETO = 2, FILTER_RETURN = 8 };
#define FILTER_MAGIC UINT32_C(0x45465431)
#define FILTER_FRESH 0U
#define FILTER_COMPLETE 1U
#define FILTER_MUTATING (UINT32_MAX - 1U)
#define FILTER_READING (UINT32_MAX - 2U)
#define FILTER_POISON UINT32_MAX

static int filter_uuid(const char *value) {
    if (!value || value[36]) return 0;
    for (size_t i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (value[i] != '-') return 0; }
        else if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return 0;
    }
    return value[14] == '4' && (value[19] == '8' || value[19] == '9' || value[19] == 'a' || value[19] == 'b');
}
static int filter_utun(const char value[16]) {
    if (memcmp(value, "utun", 4)) return 0;
    size_t length = 0; while (length < 16 && value[length]) length++;
    if (length < 5 || length > 10 || (length > 5 && value[4] == '0')) return 0;
    for (size_t i = 4; i < length; i++) if (value[i] < '0' || value[i] > '9') return 0;
    return 1;
}
static int filter_config_valid(const EnvaraPFFilterConfig *config) {
    if (!config || !filter_uuid(config->run_id) || config->realm_count > ENVARA_PF_FILTER_MAX_REALMS ||
        (config->has_previous_revision != 0 && config->has_previous_revision != 1) ||
        config->expected_writer_pid > INT32_MAX || (config->expected_writer_pid && config->expected_writer_pid < 2)) return 0;
    for (uint32_t i = 0; i < config->realm_count; i++) {
        const EnvaraPFFilterRealm *realm = &config->realms[i];
        if (!filter_uuid(realm->realm_id) || realm->gid < 7100 || realm->gid > 7999 ||
            (realm->routed != 0 && realm->routed != 1) || (realm->udp_proxy != 0 && realm->udp_proxy != 1)) return 0;
        int no_tunnel = !realm->utun[0] && !realm->route_ipv4[0] && !realm->route_ipv4[1] && !realm->route_ipv4[2] && !realm->route_ipv4[3];
        if (!no_tunnel && (!filter_utun(realm->utun) || realm->route_ipv4[0] != 198 ||
            (realm->route_ipv4[1] != 18 && realm->route_ipv4[1] != 19) || !realm->route_ipv4[3] || realm->route_ipv4[3] == 255)) return 0;
        if (realm->routed && no_tunnel) return 0;
        for (uint32_t j = 0; j < i; j++) {
            const EnvaraPFFilterRealm *prior = &config->realms[j];
            if (!strcmp(realm->realm_id, prior->realm_id) || realm->gid == prior->gid ||
                (!no_tunnel && prior->utun[0] && (!strcmp(realm->utun, prior->utun) || !memcmp(realm->route_ipv4, prior->route_ipv4, 4)))) return 0;
        }
    }
    return 1;
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static void filter_digest(const char *input, char output[65]) {
    unsigned char bytes[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(input, (CC_LONG)strlen(input), bytes);
    for (size_t i = 0; i < sizeof(bytes); i++) snprintf(output + i * 2, 3, "%02x", bytes[i]);
    output[64] = 0;
}
#pragma clang diagnostic pop
static void filter_label(const EnvaraPFFilterConfig *config, const EnvaraPFFilterRealm *realm, const char *suffix, char label[64]) {
    char input[75], digest[65]; snprintf(input, sizeof(input), "%s|%s", config->run_id, realm->realm_id); filter_digest(input, digest);
    snprintf(label, 64, "envara_%.24s_%s", digest, suffix);
}
static void filter_target_suffix(const EnvaraPFFilterRealm *realm, int dns, uint8_t protocol, int inbound, char suffix[20]) {
    char input[160], digest[65]; snprintf(input, sizeof(input), "%s:%s:%s:%s", realm->realm_id,
        dns ? "1.1.1.1" : "198.51.100.42", dns ? "53" : "{ 44441, 44442, 44443, 44444 }", protocol == FILTER_TCP ? "tcp" : "udp");
    filter_digest(input, digest); snprintf(suffix, 20, "%s_%.12s", inbound ? "in" : "out", digest);
}
static void filter_match_address(uint8_t destination[64], const uint8_t ipv4[4], uint16_t port) {
    FilterRuleAddress address = {0}; memcpy(address.address.address, ipv4, 4); memset(address.address.mask, 255, 4);
    address.transport.range.port[0] = htons(port); address.transport.range.port[1] = htons(port); address.transport.range.op = FILTER_EQ;
    memcpy(destination, &address, sizeof(address));
}
static FilterGeneratedRule *filter_append(FilterPlan *plan, const EnvaraPFFilterConfig *config, const EnvaraPFFilterRealm *realm,
    uint8_t action, uint8_t direction, uint8_t af, uint8_t protocol, const char *interface, int negate_interface, int gid_match, const char *suffix) {
    if (plan->count >= ENVARA_PF_FILTER_MAX_RULES) return NULL;
    FilterGeneratedRule *generated = &plan->rows[plan->count++]; EnvaraPFHookRule *rule = &generated->rule;
    memcpy(rule->owner, plan->anchor, strlen(plan->anchor) + 1); filter_label(config, realm, suffix, rule->label);
    rule->priority = UINT32_MAX; rule->action = action; rule->direction = direction;
    rule->af = af; rule->proto = protocol; rule->quick = 1; rule->ifnot = (uint8_t)negate_interface;
    if (interface) memcpy(rule->ifname, interface, strlen(interface) + 1);
    if (gid_match) { rule->gid[0] = realm->gid; rule->gid[1] = realm->gid; rule->gid_op = FILTER_EQ; }
    if (action == FILTER_DROP) {
        rule->rule_flag = FILTER_RETURN;
        uint16_t icmp = 0x0303, icmp6 = 0x0104;
        memcpy((uint8_t *)rule + 964, &icmp, 2); memcpy((uint8_t *)rule + 966, &icmp6, 2);
    }
    return generated;
}
static int filter_plan(const EnvaraPFFilterConfig *config, EnvaraPFFilterMode mode, FilterPlan *plan) {
    memset(plan, 0, sizeof(*plan)); if (!filter_config_valid(config) || mode < ENVARA_PF_FILTER_EMPTY || mode > ENVARA_PF_FILTER_ROUTED) return 0;
    snprintf(plan->anchor, sizeof(plan->anchor), "io.envara.pf.run.%s", config->run_id);
    if (mode == ENVARA_PF_FILTER_EMPTY) return 1;
    if (!config->realm_count) return 0;
    uint32_t order[ENVARA_PF_FILTER_MAX_REALMS] = {0, 1};
    if (config->realm_count == 2 && strcmp(config->realms[0].realm_id, config->realms[1].realm_id) > 0) { order[0] = 1; order[1] = 0; }
    for (uint32_t ordinal = 0; ordinal < config->realm_count; ordinal++) {
        const EnvaraPFFilterRealm *realm = &config->realms[order[ordinal]];
        for (size_t p = 0; p < 2; p++) if (!filter_append(plan, config, realm, FILTER_DROP, FILTER_OUT, 0,
            p ? FILTER_UDP : FILTER_TCP, "lo0", 0, 1, "loopback")) return 0;
        for (size_t p = 0; p < 2; p++) if (!filter_append(plan, config, realm, FILTER_DROP, FILTER_OUT, FILTER_INET6,
            p ? FILTER_UDP : FILTER_TCP, NULL, 0, 1, "ipv6")) return 0;
        if (!realm->udp_proxy && !filter_append(plan, config, realm, FILTER_DROP, FILTER_OUT, FILTER_INET, FILTER_UDP,
            NULL, 0, 1, "udp")) return 0;
        if (mode == ENVARA_PF_FILTER_ROUTED && realm->routed) {
            for (int host = 0; host < 2; host++) {
                const uint8_t target[2][4] = {{1, 1, 1, 1}, {198, 51, 100, 42}};
                for (int protocol = 0; protocol < (realm->udp_proxy ? 2 : 1); protocol++) {
                    uint8_t proto = protocol ? FILTER_UDP : FILTER_TCP;
                    for (int inbound = 1; inbound >= 0; inbound--) {
                        char suffix[20]; filter_target_suffix(realm, host == 0, proto, inbound, suffix);
                        for (int port = 0; port < (host == 0 ? 1 : 4); port++) {
                            FilterGeneratedRule *generated = filter_append(plan, config, realm, FILTER_PASS, inbound ? FILTER_IN : FILTER_OUT,
                                FILTER_INET, proto, inbound ? realm->utun : "lo0", !inbound, !inbound, suffix);
                            if (!generated) return 0;
                            filter_match_address(inbound ? generated->rule.src : generated->rule.dst, target[host],
                                (uint16_t)(host == 0 ? 53 : 44441 + port));
                            if (!inbound) {
                                generated->rule.rt = FILTER_ROUTETO; generated->has_pool = 1;
                                memcpy(generated->pool.address.address, realm->route_ipv4, 4); memset(generated->pool.address.mask, 255, 4);
                                memcpy(generated->pool.ifname, realm->utun, strlen(realm->utun) + 1);
                            }
                        }
                    }
                }
            }
            for (size_t p = 0; p < 2; p++) if (!filter_append(plan, config, realm, FILTER_DROP, FILTER_IN, 0,
                p ? FILTER_UDP : FILTER_TCP, realm->utun, 0, 0, "fixture_in_block")) return 0;
        }
        for (size_t p = 0; p < 2; p++) if (!filter_append(plan, config, realm, FILTER_DROP, FILTER_OUT, 0,
            p ? FILTER_UDP : FILTER_TCP, NULL, 0, 1, "blocked")) return 0;
    }
    return 1;
}
static int filter_key_diff(const EnvaraPFHookRule *a, const EnvaraPFHookRule *b, size_t key) {
    if (key == 0) return strcmp(a->ifname, b->ifname) || a->ifnot != b->ifnot;
    if (key == 1) return a->direction != b->direction;
    if (key == 2) return a->af != b->af;
    if (key == 3) return a->proto != b->proto;
    const uint8_t *x = key < 6 ? a->src : a->dst, *y = key < 6 ? b->src : b->dst;
    if (key == 4 || key == 6) return x[56] != y[56] || x[40] != y[40] || memcmp(x, y, 32);
    return x[52] != y[52] || memcmp(x + 48, y + 48, 4);
}
static EnvaraPFHookRule filter_readback_rule(const FilterPlan *plan, uint32_t index, uint32_t uid, uint32_t pid) {
    EnvaraPFHookRule rule = plan->rows[index].rule; rule.nr = index;
    uint8_t *bytes = (uint8_t *)&rule; bytes[642] = rule.af;
    memcpy(bytes + 956, &uid, 4); memcpy(bytes + 960, &pid, 4);
    for (size_t key = 0; key < 8; key++) {
        uint32_t next = UINT32_MAX;
        for (uint32_t j = index + 1; j < plan->count; j++) if (filter_key_diff(&plan->rows[index].rule, &plan->rows[j].rule, key)) { next = j; break; }
        memcpy(rule.skip + key * 8, &next, 4);
    }
    return rule;
}
static int filter_guard(EnvaraPFFilterContext *context, EnvaraPFFilterStage stage, uint32_t index,
    uint32_t phase, EnvaraPFFilterResult *result) {
    result->rule_index = index;
    if (context->phase == phase && context->creator_uid == (uint32_t)geteuid() && context->creator_pid == (uint32_t)getpid() &&
        context->guard(context->opaque, context->fd, stage, index) == 1 && context->phase == phase) return 1;
    result->reason = ENVARA_PF_FILTER_GUARD_REJECTED; return 0;
}
static int filter_ioctl(EnvaraPFFilterContext *context, unsigned long request, void *argument, uint32_t phase) {
    if (context->phase != phase) { errno = ECANCELED; return -1; }
    errno = 0; int response = context->ioctl_call ? context->ioctl_call(context->opaque, context->fd, request, argument)
        : ioctl(context->fd, request, argument);
    if (context->phase != phase) { errno = ECANCELED; return -1; } return response;
}
static FilterEntry filter_entry(const FilterPlan *plan, uint32_t ticket) {
    FilterEntry entry = {0}; entry.rs_num = 1; entry.ticket = ticket; memcpy(entry.anchor, plan->anchor, strlen(plan->anchor) + 1); return entry;
}
static int filter_transaction_reply(const FilterPlan *plan, const FilterTransaction *transaction, const FilterEntry *entry, uint32_t ticket) {
    FilterEntry expected = filter_entry(plan, ticket);
    return transaction->size == 1 && transaction->esize == (int32_t)sizeof(*entry) && transaction->array == entry && !memcmp(entry, &expected, sizeof(expected));
}
static EnvaraPFHookRequest filter_rule_request(const FilterPlan *plan) {
    EnvaraPFHookRequest request = {0}; memcpy(request.anchor, plan->anchor, strlen(plan->anchor) + 1); return request;
}
static FilterPoolRequest filter_pool_query(const FilterPlan *plan, uint32_t ticket, uint32_t index) {
    FilterPoolRequest request = {0}; request.ticket = ticket; request.r_num = index; request.af = FILTER_INET;
    memcpy(request.anchor, plan->anchor, strlen(plan->anchor) + 1); return request;
}
static int filter_read_ioctl(EnvaraPFFilterContext *context, unsigned long operation, void *request,
    uint32_t index, uint32_t phase, EnvaraPFFilterResult *result) {
    if (!filter_guard(context, ENVARA_PF_FILTER_GUARD_VERIFY, index, phase, result)) return 0;
    if (filter_ioctl(context, operation, request, phase)) { result->os_error = errno; return 0; } return 1;
}
static int filter_readback(EnvaraPFFilterContext *context, const FilterPlan *plan, uint32_t phase, int prior,
    EnvaraPFFilterResult *result) {
    EnvaraPFHookRequest first = filter_rule_request(plan);
    if (!filter_read_ioctl(context, ENVARA_PF_HOOK_GET_RULES, &first, UINT32_MAX, phase, result)) return 0;
    result->actual_count = first.nr;
    uint32_t ticket = prior ? first.ticket : result->ticket;
    if (prior && context->config.has_previous_revision && first.ticket != context->config.expected_revision) return 0;
    EnvaraPFHookRequest expected = filter_rule_request(plan); expected.ticket = ticket; expected.nr = plan->count;
    if (memcmp(&first, &expected, sizeof(first))) return 0;
    if (prior) { result->ticket_known = 1; result->ticket = ticket; result->writer_pid = context->config.expected_writer_pid; }
    for (uint32_t i = 0; i < plan->count; i++) {
        EnvaraPFHookRequest row = filter_rule_request(plan); row.ticket = ticket; row.nr = i;
        if (!filter_read_ioctl(context, ENVARA_PF_HOOK_GET_RULE, &row, i, phase, result)) return 0;
        EnvaraPFHookRequest wanted = filter_rule_request(plan); wanted.ticket = ticket; wanted.nr = i;
        wanted.rule = filter_readback_rule(plan, i, prior ? 0U : context->creator_uid,
            prior ? context->config.expected_writer_pid : context->creator_pid);
        /* Only evaluation/packet/byte counters are volatile. Skip bytes, rule
         * order, creator receipt, all opaque semantics, states and src_nodes
         * remain strict. GET action is zero, never PF_GET_CLR_CNTR. */
        memset((uint8_t *)&row.rule + 648, 0, 40);
        if (memcmp(&row, &wanted, sizeof(row))) return 0;
        FilterPoolRequest count = filter_pool_query(plan, ticket, i);
        if (!filter_read_ioctl(context, FILTER_GET_ADDRS, &count, i, phase, result)) return 0;
        FilterPoolRequest expected_count = filter_pool_query(plan, ticket, i); expected_count.nr = plan->rows[i].has_pool ? 1U : 0U;
        if (memcmp(&count, &expected_count, sizeof(count))) return 0;
        if (plan->rows[i].has_pool) {
            FilterPoolRequest address = filter_pool_query(plan, ticket, i);
            if (!filter_read_ioctl(context, FILTER_GET_ADDR, &address, i, phase, result)) return 0;
            FilterPoolRequest wanted_address = filter_pool_query(plan, ticket, i); wanted_address.addr = plan->rows[i].pool;
            if (memcmp(&address, &wanted_address, sizeof(address))) return 0;
        }
        result->pools_verified++;
    }
    EnvaraPFHookRequest last = filter_rule_request(plan);
    if (!filter_read_ioctl(context, ENVARA_PF_HOOK_GET_RULES, &last, UINT32_MAX, phase, result)) return 0;
    return !memcmp(&last, &expected, sizeof(last));
}
static void filter_rollback(EnvaraPFFilterContext *context, const FilterPlan *plan, EnvaraPFFilterResult *result) {
    if (!result->ticket_known || result->committed || result->rollback_attempted) return;
    EnvaraPFFilterReason original = result->reason;
    if (!filter_guard(context, ENVARA_PF_FILTER_GUARD_ROLLBACK, UINT32_MAX, FILTER_POISON, result)) { result->reason = original; return; }
    FilterEntry entry = filter_entry(plan, result->ticket); FilterTransaction transaction = {1, (int32_t)sizeof(entry), &entry};
    result->rollback_attempted = 1;
    if (!filter_ioctl(context, FILTER_ROLLBACK, &transaction, FILTER_POISON) &&
        filter_transaction_reply(plan, &transaction, &entry, result->ticket)) result->rollback_acknowledged = 1;
    /* Pinned rollback can acknowledge an already committed/no-open/mismatched
     * transaction. Never clear uncertainty or prove active/namespace emptiness. */
}
static void filter_result(EnvaraPFFilterResult *result, int read_only) {
    memset(result, 0, sizeof(*result)); result->read_only = read_only;
    result->actual_count = UINT32_MAX; result->rule_index = UINT32_MAX;
}
int EnvaraPFFilterInit(EnvaraPFFilterContext *context, int fd, void *opaque, EnvaraPFFilterIoctl ioctl_call,
    EnvaraPFFilterGuard guard, const EnvaraPFFilterConfig *config) {
    if (!context || context->magic || fd < 0 || !guard || !filter_config_valid(config)) return 0;
    memset(context, 0, sizeof(*context)); context->fd = fd; context->opaque = opaque; context->ioctl_call = ioctl_call;
    context->guard = guard; context->config = *config; context->magic = FILTER_MAGIC;
    context->creator_uid = (uint32_t)geteuid(); context->creator_pid = (uint32_t)getpid(); return 1;
}
int EnvaraPFFilterVerify(EnvaraPFFilterContext *context, EnvaraPFFilterMode mode, EnvaraPFFilterResult *result) {
    if (!result) { if (context && context->magic == FILTER_MAGIC) context->phase = FILTER_POISON; return 0; }
    filter_result(result, 1);
    if (!context || context->magic != FILTER_MAGIC || !context->guard || context->fd < 0) { result->reason = ENVARA_PF_FILTER_INVALID_CONTEXT; return 0; }
    FilterPlan plan;
    if (!filter_plan(&context->config, mode, &plan) || (plan.count && (!context->config.has_previous_revision || !context->config.expected_writer_pid))) {
        result->reason = ENVARA_PF_FILTER_INVALID_CONFIG; context->phase = FILTER_POISON; return 0;
    }
    if (context->phase == FILTER_MUTATING || context->phase == FILTER_READING) {
        result->reason = ENVARA_PF_FILTER_ALREADY_USED; context->phase = FILTER_POISON; return 0;
    }
    uint32_t previous_phase = context->phase; context->phase = FILTER_READING; result->expected_count = plan.count;
    if (!filter_readback(context, &plan, FILTER_READING, 1, result)) {
        if (result->reason != ENVARA_PF_FILTER_GUARD_REJECTED) result->reason = ENVARA_PF_FILTER_VERIFY_FAILED;
        context->phase = FILTER_POISON; return 0;
    }
    result->verified = 1; result->uncertain = previous_phase == FILTER_POISON;
    context->phase = previous_phase; return 1;
}
int EnvaraPFFilterApply(EnvaraPFFilterContext *context, EnvaraPFFilterMode mode, EnvaraPFFilterResult *result) {
    if (!result) { if (context && context->magic == FILTER_MAGIC) context->phase = FILTER_POISON; return 0; }
    filter_result(result, 0);
    if (!context || context->magic != FILTER_MAGIC || !context->guard || context->fd < 0) { result->reason = ENVARA_PF_FILTER_INVALID_CONTEXT; return 0; }
    if (context->apply_used || context->phase != FILTER_FRESH) { result->reason = ENVARA_PF_FILTER_ALREADY_USED; context->phase = FILTER_POISON; return 0; }
    context->apply_used = 1; context->phase = FILTER_MUTATING; FilterPlan plan;
    if (!filter_plan(&context->config, mode, &plan)) { result->reason = ENVARA_PF_FILTER_INVALID_CONFIG; context->phase = FILTER_POISON; return 0; }
    result->expected_count = plan.count; result->writer_pid = context->creator_pid;
    if (!filter_guard(context, ENVARA_PF_FILTER_GUARD_INITIAL, UINT32_MAX, FILTER_MUTATING, result) ||
        !filter_guard(context, ENVARA_PF_FILTER_GUARD_BEGIN, UINT32_MAX, FILTER_MUTATING, result)) goto failed;
    FilterEntry entry = filter_entry(&plan, 0); FilterTransaction transaction = {1, (int32_t)sizeof(entry), &entry};
    result->begun = 1; result->uncertain = 1;
    if (filter_ioctl(context, FILTER_BEGIN, &transaction, FILTER_MUTATING)) { result->reason = ENVARA_PF_FILTER_BEGIN_FAILED; result->os_error = errno; goto failed; }
    if (!filter_transaction_reply(&plan, &transaction, &entry, entry.ticket)) { result->reason = ENVARA_PF_FILTER_BEGIN_REPLY_INVALID; goto failed; }
    result->ticket_known = 1; result->ticket = entry.ticket;
    for (uint32_t i = 0; i < plan.count; i++) {
        if (!filter_guard(context, ENVARA_PF_FILTER_GUARD_BEGIN_ADDRS, i, FILTER_MUTATING, result)) goto failed;
        FilterPoolRequest pool = {0}; result->pool_attempted = 1;
        if (filter_ioctl(context, FILTER_BEGIN_ADDRS, &pool, FILTER_MUTATING)) { result->reason = ENVARA_PF_FILTER_POOL_FAILED; result->os_error = errno; goto failed; }
        FilterPoolRequest expected_pool = {0}; expected_pool.ticket = pool.ticket;
        if (memcmp(&pool, &expected_pool, sizeof(pool))) { result->reason = ENVARA_PF_FILTER_POOL_REPLY_INVALID; goto failed; }
        if (plan.rows[i].has_pool) {
            FilterPoolRequest address = {0}; address.ticket = pool.ticket; address.af = FILTER_INET; address.addr = plan.rows[i].pool;
            memcpy(address.anchor, plan.anchor, strlen(plan.anchor) + 1); FilterPoolRequest expected_address = address;
            if (!filter_guard(context, ENVARA_PF_FILTER_GUARD_ADD_ADDR, i, FILTER_MUTATING, result)) goto failed;
            result->add_addr_attempted = 1;
            if (filter_ioctl(context, FILTER_ADD_ADDR, &address, FILTER_MUTATING)) { result->reason = ENVARA_PF_FILTER_ADD_ADDR_FAILED; result->os_error = errno; goto failed; }
            if (memcmp(&address, &expected_address, sizeof(address))) { result->reason = ENVARA_PF_FILTER_ADD_ADDR_REPLY_INVALID; goto failed; }
        }
        EnvaraPFHookRequest request = filter_rule_request(&plan); request.ticket = result->ticket; request.pool_ticket = pool.ticket; request.rule = plan.rows[i].rule;
        EnvaraPFHookRequest expected_request = request;
        if (!filter_guard(context, ENVARA_PF_FILTER_GUARD_ADD_RULE, i, FILTER_MUTATING, result)) goto failed;
        if (filter_ioctl(context, FILTER_ADD_RULE, &request, FILTER_MUTATING)) { result->reason = ENVARA_PF_FILTER_ADD_RULE_FAILED; result->os_error = errno; goto failed; }
        if (memcmp(&request, &expected_request, sizeof(request))) { result->reason = ENVARA_PF_FILTER_ADD_RULE_REPLY_INVALID; goto failed; }
        result->rules_added++;
    }
    if (!filter_guard(context, ENVARA_PF_FILTER_GUARD_COMMIT, UINT32_MAX, FILTER_MUTATING, result)) goto failed;
    entry = filter_entry(&plan, result->ticket); transaction = (FilterTransaction){1, (int32_t)sizeof(entry), &entry}; result->commit_attempted = 1;
    if (filter_ioctl(context, FILTER_COMMIT, &transaction, FILTER_MUTATING)) { result->reason = ENVARA_PF_FILTER_COMMIT_FAILED; result->os_error = errno; goto failed; }
    result->committed = 1;
    if (!filter_transaction_reply(&plan, &transaction, &entry, result->ticket)) { result->reason = ENVARA_PF_FILTER_COMMIT_REPLY_INVALID; goto failed; }
    if (!filter_readback(context, &plan, FILTER_MUTATING, 0, result)) {
        if (result->reason != ENVARA_PF_FILTER_GUARD_REJECTED) result->reason = ENVARA_PF_FILTER_VERIFY_FAILED; goto failed;
    }
    result->verified = 1; result->uncertain = 0; context->phase = FILTER_COMPLETE; return 1;
failed:
    context->phase = FILTER_POISON; filter_rollback(context, &plan, result); return 0;
}
const char *EnvaraPFFilterReasonName(EnvaraPFFilterReason reason) {
    static const char *const names[] = {"okay", "invalid-context", "invalid-config", "already-used", "guard-rejected", "begin-failed",
        "begin-reply-invalid", "pool-failed", "pool-reply-invalid", "add-address-failed", "add-address-reply-invalid", "add-rule-failed",
        "add-rule-reply-invalid", "commit-failed", "commit-reply-invalid", "verify-failed"};
    return (unsigned)reason < sizeof(names)/sizeof(names[0]) ? names[reason] : "invalid-reason";
}
