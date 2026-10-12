#include "pf-production-filter.h"
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
 * There is exactly one FILTER entry; no TABLE, state, authorization or CLI API.
 * Production activation is gated OFF outside this constructor. In particular,
 * pinned pf_test_fragment does not check GID. Each GID row therefore has an
 * inclusive full transport-port range, causing fragment processing to skip it.
 * Owned fragments remain unprotected, not accepted as fail-safe. IPv6,
 * unsupported protocols, inherited/external processes and guard crash are gates. */
typedef struct { int32_t rs_num; char anchor[1024]; uint32_t ticket; } ProductionEntry;
typedef struct { int32_t size, esize; ProductionEntry *array; } ProductionTransaction;
typedef struct { uint8_t address[16], mask[16]; uint64_t pointer; uint8_t type, iflags, pad[6]; } ProductionAddress;
typedef struct { ProductionAddress address; uint64_t entries[2]; char ifname[16]; uint64_t kif; } ProductionPoolAddress;
typedef struct {
    uint32_t action, ticket, nr, r_num;
    uint8_t r_action, r_last, af;
    char anchor[1024];
    ProductionPoolAddress addr;
} ProductionPoolRequest;
typedef union { struct { uint16_t port[2]; uint8_t op, pad; } range; uint32_t words[2]; } ProductionTransport;
typedef struct { ProductionAddress address; ProductionTransport transport; uint8_t neg, pad[7]; } ProductionRuleAddress;
typedef struct { EnvaraPFHookRule rule; ProductionPoolAddress pool; int has_pool; } ProductionGeneratedRule;
typedef struct { char anchor[64]; uint32_t count; ProductionGeneratedRule rows[ENVARA_PF_PRODUCTION_MAX_RULES]; } ProductionPlan;
#define PRODUCTION_OFFSET(type, field, offset) _Static_assert(offsetof(type, field) == offset, #field " ABI offset")
_Static_assert(sizeof(ProductionEntry) == 1032 && _Alignof(ProductionEntry) == 4, "transaction entry ABI");
PRODUCTION_OFFSET(ProductionEntry, anchor, 4); PRODUCTION_OFFSET(ProductionEntry, ticket, 1028);
_Static_assert(sizeof(ProductionTransaction) == 16 && _Alignof(ProductionTransaction) == 8, "transaction envelope ABI");
PRODUCTION_OFFSET(ProductionTransaction, array, 8);
_Static_assert(sizeof(ProductionAddress) == 48 && _Alignof(ProductionAddress) == 8, "address ABI");
PRODUCTION_OFFSET(ProductionAddress, mask, 16); PRODUCTION_OFFSET(ProductionAddress, pointer, 32); PRODUCTION_OFFSET(ProductionAddress, type, 40);
_Static_assert(sizeof(ProductionPoolAddress) == 88 && _Alignof(ProductionPoolAddress) == 8, "pool address ABI");
PRODUCTION_OFFSET(ProductionPoolAddress, entries, 48); PRODUCTION_OFFSET(ProductionPoolAddress, ifname, 64); PRODUCTION_OFFSET(ProductionPoolAddress, kif, 80);
_Static_assert(sizeof(ProductionPoolRequest) == 1136 && _Alignof(ProductionPoolRequest) == 8, "pool request ABI");
PRODUCTION_OFFSET(ProductionPoolRequest, ticket, 4); PRODUCTION_OFFSET(ProductionPoolRequest, r_num, 12); PRODUCTION_OFFSET(ProductionPoolRequest, r_action, 16);
PRODUCTION_OFFSET(ProductionPoolRequest, af, 18); PRODUCTION_OFFSET(ProductionPoolRequest, anchor, 19); PRODUCTION_OFFSET(ProductionPoolRequest, addr, 1048);
_Static_assert(sizeof(ProductionRuleAddress) == 64 && _Alignof(ProductionRuleAddress) == 8, "rule address ABI");
PRODUCTION_OFFSET(ProductionRuleAddress, transport, 48); PRODUCTION_OFFSET(ProductionRuleAddress, neg, 56);
/* Generated pf_rule_uid/pf_rule_gid selectors: 32-bit low/high bounds plus
 * 8-bit op, followed by three zero pad bytes. UID selector is distinct from
 * the creator UID receipt at byte 956, which readback checks separately. */
PRODUCTION_OFFSET(EnvaraPFHookRule, uid, 976); PRODUCTION_OFFSET(EnvaraPFHookRule, uid_op, 984);
PRODUCTION_OFFSET(EnvaraPFHookRule, gid, 988); PRODUCTION_OFFSET(EnvaraPFHookRule, gid_op, 996);
#undef PRODUCTION_OFFSET
#define PRODUCTION_BEGIN _IOWR('D', 81, ProductionTransaction)
#define PRODUCTION_COMMIT _IOWR('D', 82, ProductionTransaction)
#define PRODUCTION_ROLLBACK _IOWR('D', 83, ProductionTransaction)
#define PRODUCTION_BEGIN_ADDRS _IOWR('D', 51, ProductionPoolRequest)
#define PRODUCTION_ADD_ADDR _IOWR('D', 52, ProductionPoolRequest)
#define PRODUCTION_GET_ADDRS _IOWR('D', 53, ProductionPoolRequest)
#define PRODUCTION_GET_ADDR _IOWR('D', 54, ProductionPoolRequest)
#define PRODUCTION_ADD_RULE _IOWR('D', 4, EnvaraPFHookRequest)
_Static_assert(PRODUCTION_BEGIN == 0xc0104451UL && PRODUCTION_COMMIT == 0xc0104452UL && PRODUCTION_ROLLBACK == 0xc0104453UL, "transaction ioctl ABI");
_Static_assert(PRODUCTION_BEGIN_ADDRS == 0xc4704433UL && PRODUCTION_ADD_ADDR == 0xc4704434UL, "pool mutation ioctl ABI");
_Static_assert(PRODUCTION_GET_ADDRS == 0xc4704435UL && PRODUCTION_GET_ADDR == 0xc4704436UL && PRODUCTION_ADD_RULE == 0xcc204404UL, "pool/rule ioctl ABI");
enum { PRODUCTION_PASS = 0, PRODUCTION_DROP = 1, PRODUCTION_IN = 1, PRODUCTION_OUT = 2,
    PRODUCTION_INET = 2, PRODUCTION_INET6 = 30, PRODUCTION_TCP = 6, PRODUCTION_UDP = 17,
    PRODUCTION_EQ = 2, PRODUCTION_RRG = 9, PRODUCTION_ROUTETO = 2, PRODUCTION_RETURN = 8 };
#define PRODUCTION_MAGIC UINT32_C(0x45505431)
#define PRODUCTION_FRESH 0U
#define PRODUCTION_COMPLETE 1U
#define PRODUCTION_MUTATING (UINT32_MAX - 1U)
#define PRODUCTION_READING (UINT32_MAX - 2U)
#define PRODUCTION_POISON UINT32_MAX

static int production_uuid(const char *value) {
    if (!value || value[36]) return 0;
    for (size_t i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (value[i] != '-') return 0; }
        else if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return 0;
    }
    return value[14] == '4' && (value[19] == '8' || value[19] == '9' || value[19] == 'a' || value[19] == 'b');
}
static int production_utun(const char value[16]) {
    if (memcmp(value, "utun", 4)) return 0;
    size_t length = 0; while (length < 16 && value[length]) length++;
    if (length < 5 || length > 10 || (length > 5 && value[4] == '0')) return 0;
    for (size_t i = 4; i < length; i++) if (value[i] < '0' || value[i] > '9') return 0;
    return 1;
}
static int production_config_valid(const EnvaraPFProductionConfig *config) {
    if (!config || !production_uuid(config->run_id) || !production_uuid(config->realm_id) ||
        config->gid < 7100 || config->gid > 7999 || !production_utun(config->utun) ||
        config->route_ipv4[0] != 198 || (config->route_ipv4[1] != 18 && config->route_ipv4[1] != 19) ||
        !config->route_ipv4[3] || config->route_ipv4[3] == 255 || config->listener_fd < 3 ||
        config->tcp_front_port < 1024 || (config->has_previous_revision != 0 && config->has_previous_revision != 1) ||
        config->expected_writer_pid > INT32_MAX || (config->expected_writer_pid && config->expected_writer_pid < 2)) return 0;
    size_t end = strlen(config->utun) + 1;
    for (size_t i = end; i < sizeof(config->utun); i++) if (config->utun[i]) return 0;
    return 1;
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static void production_digest(const char *input, char output[65]) {
    unsigned char bytes[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(input, (CC_LONG)strlen(input), bytes);
    for (size_t i = 0; i < sizeof(bytes); i++) snprintf(output + i * 2, 3, "%02x", bytes[i]);
    output[64] = 0;
}
#pragma clang diagnostic pop
static void production_label(const EnvaraPFProductionConfig *config, const char *suffix, char label[64]) {
    char input[75], digest[65]; snprintf(input, sizeof(input), "%s|%s", config->run_id, config->realm_id); production_digest(input, digest);
    snprintf(label, 64, "envara_prod_v1_%.24s_%s", digest, suffix);
}
static void production_match_front(uint8_t destination[64], uint16_t port) {
    ProductionRuleAddress address = {0}; const uint8_t loopback[4] = {127, 0, 0, 1};
    memcpy(address.address.address, loopback, 4); memset(address.address.mask, 255, 4);
    address.transport.range.port[0] = htons(port); address.transport.range.port[1] = htons(port); address.transport.range.op = PRODUCTION_EQ;
    memcpy(destination, &address, sizeof(address));
}
static ProductionGeneratedRule *production_append(ProductionPlan *plan, const EnvaraPFProductionConfig *config,
    uint8_t action, uint8_t direction, uint8_t af, uint8_t protocol, const char *interface, int negate_interface, int gid_match, const char *suffix) {
    if (plan->count >= ENVARA_PF_PRODUCTION_MAX_RULES) return NULL;
    ProductionGeneratedRule *generated = &plan->rows[plan->count++]; EnvaraPFHookRule *rule = &generated->rule;
    memcpy(rule->owner, plan->anchor, strlen(plan->anchor) + 1); production_label(config, suffix, rule->label);
    rule->priority = UINT32_MAX; rule->action = action; rule->direction = direction;
    rule->af = af; rule->proto = protocol; rule->quick = 1; rule->ifnot = (uint8_t)negate_interface;
    if (interface) memcpy(rule->ifname, interface, strlen(interface) + 1);
    if (gid_match) {
        rule->gid[0] = config->gid; rule->gid[1] = config->gid; rule->gid_op = PRODUCTION_EQ;
        /* Fixed pf.c 2826-2858: RRG is inclusive, IRG is exclusive. Match all
         * normal ports including 0/65535, while 6247-6253 skips this row for
         * fragments. The fragment path otherwise omits socket GID attribution. */
        ProductionTransport all_ports = {0}; all_ports.range.port[0] = htons(0);
        all_ports.range.port[1] = htons(UINT16_MAX); all_ports.range.op = PRODUCTION_RRG;
        memcpy(rule->src + 48, &all_ports, sizeof(all_ports));
    }
    if (action == PRODUCTION_DROP) {
        rule->rule_flag = PRODUCTION_RETURN;
        uint16_t icmp = 0x0303, icmp6 = 0x0104;
        memcpy((uint8_t *)rule + 964, &icmp, 2); memcpy((uint8_t *)rule + 966, &icmp6, 2);
    }
    return generated;
}
static int production_plan(const EnvaraPFProductionConfig *config, EnvaraPFProductionMode mode, ProductionPlan *plan) {
    memset(plan, 0, sizeof(*plan));
    if (!production_config_valid(config) || mode < ENVARA_PF_PRODUCTION_EMPTY || mode > ENVARA_PF_PRODUCTION_FRONT) return 0;
    /* Every application keeps its own top-level anchor. A shared root hook
     * reaches them through fixed call lines, not through nesting: a nested path
     * is 90 bytes and both the plan anchor and the rule owner hold 64. */
    snprintf(plan->anchor, sizeof(plan->anchor), "io.envara.pf.run.%s", config->run_id);
    if (mode == ENVARA_PF_PRODUCTION_EMPTY) return 1;
    if (mode == ENVARA_PF_PRODUCTION_FRONT) {
        ProductionGeneratedRule *allow = production_append(plan, config, PRODUCTION_PASS, PRODUCTION_OUT,
            PRODUCTION_INET, PRODUCTION_TCP, "lo0", 0, 1, "front_scoped");
        ProductionGeneratedRule *deny = production_append(plan, config, PRODUCTION_DROP, PRODUCTION_OUT,
            PRODUCTION_INET, PRODUCTION_TCP, "lo0", 0, 0, "front_foreign");
        ProductionGeneratedRule *ipv6 = production_append(plan, config, PRODUCTION_DROP, PRODUCTION_OUT,
            PRODUCTION_INET6, PRODUCTION_TCP, "lo0", 0, 1, "front_ipv6");
        ProductionGeneratedRule *server = production_append(plan, config, PRODUCTION_PASS, PRODUCTION_IN,
            PRODUCTION_INET, PRODUCTION_TCP, "lo0", 0, 1, "front_listener");
        ProductionGeneratedRule *foreign_server = production_append(plan, config, PRODUCTION_DROP, PRODUCTION_IN,
            PRODUCTION_INET, PRODUCTION_TCP, "lo0", 0, 0, "front_listener_other");
        if (!allow || !deny || !ipv6 || !server || !foreign_server) return 0;
        production_match_front(allow->rule.dst, config->tcp_front_port);
        production_match_front(deny->rule.dst, config->tcp_front_port);
        /* Fixed Apple pf.c 4170-4208 selects the receiving local socket for
         * PF_IN, and the sending socket for PF_OUT. in_pcb.c 2475-2478 and
         * 2513-2516 read that socket's so_cred UID/GID; accepted sockets inherit
         * head->so_cred (uipc_socket2.c 377-385). The native listener creator
         * must independently prove its socket credential UID0+this realm GID.
         * The keeper/front process GID0 is NOT this socket credential. This is
         * credential scoping, not a PID/birth or whole-guard acceptance claim. */
        server->rule.uid[0] = 0; server->rule.uid[1] = 0; server->rule.uid_op = PRODUCTION_EQ;
        production_match_front(server->rule.dst, config->tcp_front_port);
        production_match_front(foreign_server->rule.dst, config->tcp_front_port);
        ProductionRuleAddress loopback6 = {0}; loopback6.address.address[15] = 1;
        memset(loopback6.address.mask, 255, 16);
        loopback6.transport.range.port[0] = htons(config->tcp_front_port);
        loopback6.transport.range.port[1] = htons(config->tcp_front_port);
        loopback6.transport.range.op = PRODUCTION_EQ;
        memcpy(ipv6->rule.dst, &loopback6, sizeof(loopback6));
        return 1;
    }
    if (mode == ENVARA_PF_PRODUCTION_ROUTED) {
        ProductionGeneratedRule *front = production_append(plan, config, PRODUCTION_PASS, PRODUCTION_OUT,
            PRODUCTION_INET, PRODUCTION_TCP, "lo0", 0, 1, "front");
        if (!front) return 0; production_match_front(front->rule.dst, config->tcp_front_port);
    }
    for (size_t p = 0; p < 2; p++) if (!production_append(plan, config, PRODUCTION_DROP, PRODUCTION_OUT, 0,
        p ? PRODUCTION_UDP : PRODUCTION_TCP, "lo0", 0, 1, "loopback")) return 0;
    for (size_t p = 0; p < 2; p++) if (!production_append(plan, config, PRODUCTION_DROP, PRODUCTION_OUT, PRODUCTION_INET6,
        p ? PRODUCTION_UDP : PRODUCTION_TCP, NULL, 0, 1, "ipv6")) return 0;
    if (mode == ENVARA_PF_PRODUCTION_ROUTED) {
        /* Pinned pf_route re-enters PF_OUT with a fresh socket lookup. A pass
         * on only this owned utun and exact GID ends that second evaluation. */
        for (size_t p = 0; p < 2; p++) if (!production_append(plan, config, PRODUCTION_PASS, PRODUCTION_OUT, PRODUCTION_INET,
            p ? PRODUCTION_UDP : PRODUCTION_TCP, config->utun, 0, 1, "utun_out")) return 0;
        for (size_t p = 0; p < 2; p++) {
            ProductionGeneratedRule *route = production_append(plan, config, PRODUCTION_PASS, PRODUCTION_OUT,
                PRODUCTION_INET, p ? PRODUCTION_UDP : PRODUCTION_TCP, "lo0", 1, 1, "route");
            if (!route) return 0; route->rule.rt = PRODUCTION_ROUTETO; route->has_pool = 1;
            memcpy(route->pool.address.address, config->route_ipv4, 4); memset(route->pool.address.mask, 255, 4);
            memcpy(route->pool.ifname, config->utun, strlen(config->utun) + 1);
        }
        for (size_t p = 0; p < 2; p++) if (!production_append(plan, config, PRODUCTION_PASS, PRODUCTION_IN, PRODUCTION_INET,
            p ? PRODUCTION_UDP : PRODUCTION_TCP, config->utun, 0, 0, "utun_in")) return 0;
    }
    for (size_t p = 0; p < 2; p++) if (!production_append(plan, config, PRODUCTION_DROP, PRODUCTION_OUT, 0,
        p ? PRODUCTION_UDP : PRODUCTION_TCP, NULL, 0, 1, "blocked")) return 0;
    return 1;
}
static int production_key_diff(const EnvaraPFHookRule *a, const EnvaraPFHookRule *b, size_t key) {
    if (key == 0) return strcmp(a->ifname, b->ifname) || a->ifnot != b->ifnot;
    if (key == 1) return a->direction != b->direction;
    if (key == 2) return a->af != b->af;
    if (key == 3) return a->proto != b->proto;
    const uint8_t *x = key < 6 ? a->src : a->dst, *y = key < 6 ? b->src : b->dst;
    if (key == 4 || key == 6) return x[56] != y[56] || x[40] != y[40] || memcmp(x, y, 32);
    return x[52] != y[52] || memcmp(x + 48, y + 48, 4);
}
static EnvaraPFHookRule production_readback_rule(const ProductionPlan *plan, uint32_t index, uint32_t uid, uint32_t pid) {
    EnvaraPFHookRule rule = plan->rows[index].rule; rule.nr = index;
    uint8_t *bytes = (uint8_t *)&rule; bytes[642] = rule.af;
    memcpy(bytes + 956, &uid, 4); memcpy(bytes + 960, &pid, 4);
    for (size_t key = 0; key < 8; key++) {
        uint32_t next = UINT32_MAX;
        for (uint32_t j = index + 1; j < plan->count; j++) if (production_key_diff(&plan->rows[index].rule, &plan->rows[j].rule, key)) { next = j; break; }
        memcpy(rule.skip + key * 8, &next, 4);
    }
    return rule;
}
static int production_guard(EnvaraPFProductionContext *context, EnvaraPFProductionStage stage, uint32_t index,
    uint32_t phase, EnvaraPFProductionResult *result) {
    result->rule_index = index;
    if (context->phase == phase && context->creator_uid == (uint32_t)geteuid() && context->creator_pid == (uint32_t)getpid() &&
        context->guard(context->opaque, context->fd, stage, index) == 1 && context->phase == phase) return 1;
    result->reason = ENVARA_PF_PRODUCTION_GUARD_REJECTED; return 0;
}
static int production_ioctl(EnvaraPFProductionContext *context, unsigned long request, void *argument, uint32_t phase) {
    if (context->phase != phase) { errno = ECANCELED; return -1; }
    errno = 0; int response = context->ioctl_call ? context->ioctl_call(context->opaque, context->fd, request, argument)
        : ioctl(context->fd, request, argument);
    if (context->phase != phase) { errno = ECANCELED; return -1; } return response;
}
static ProductionEntry production_entry(const ProductionPlan *plan, uint32_t ticket) {
    ProductionEntry entry = {0}; entry.rs_num = 1; entry.ticket = ticket; memcpy(entry.anchor, plan->anchor, strlen(plan->anchor) + 1); return entry;
}
static int production_transaction_reply(const ProductionPlan *plan, const ProductionTransaction *transaction, const ProductionEntry *entry, uint32_t ticket) {
    ProductionEntry expected = production_entry(plan, ticket);
    return transaction->size == 1 && transaction->esize == (int32_t)sizeof(*entry) && transaction->array == entry && !memcmp(entry, &expected, sizeof(expected));
}
static EnvaraPFHookRequest production_rule_request(const ProductionPlan *plan) {
    EnvaraPFHookRequest request = {0}; memcpy(request.anchor, plan->anchor, strlen(plan->anchor) + 1); return request;
}
static ProductionPoolRequest production_pool_query(const ProductionPlan *plan, uint32_t ticket, uint32_t index) {
    ProductionPoolRequest request = {0}; request.ticket = ticket; request.r_num = index; request.af = PRODUCTION_INET;
    memcpy(request.anchor, plan->anchor, strlen(plan->anchor) + 1); return request;
}
static int production_read_ioctl(EnvaraPFProductionContext *context, unsigned long operation, void *request,
    uint32_t index, uint32_t phase, EnvaraPFProductionResult *result) {
    if (!production_guard(context, ENVARA_PF_PRODUCTION_GUARD_VERIFY, index, phase, result)) return 0;
    if (production_ioctl(context, operation, request, phase)) { result->os_error = errno; return 0; } return 1;
}
static int production_readback(EnvaraPFProductionContext *context, const ProductionPlan *plan, uint32_t phase, int prior,
    EnvaraPFProductionResult *result) {
    EnvaraPFHookRequest first = production_rule_request(plan);
    if (!production_read_ioctl(context, ENVARA_PF_HOOK_GET_RULES, &first, UINT32_MAX, phase, result)) return 0;
    result->actual_count = first.nr;
    uint32_t ticket = prior ? first.ticket : result->ticket;
    if (prior && context->config.has_previous_revision && first.ticket != context->config.expected_revision) return 0;
    EnvaraPFHookRequest expected = production_rule_request(plan); expected.ticket = ticket; expected.nr = plan->count;
    if (memcmp(&first, &expected, sizeof(first))) return 0;
    if (prior) { result->ticket_known = 1; result->ticket = ticket; result->writer_pid = context->config.expected_writer_pid; }
    for (uint32_t i = 0; i < plan->count; i++) {
        EnvaraPFHookRequest row = production_rule_request(plan); row.ticket = ticket; row.nr = i;
        if (!production_read_ioctl(context, ENVARA_PF_HOOK_GET_RULE, &row, i, phase, result)) return 0;
        EnvaraPFHookRequest wanted = production_rule_request(plan); wanted.ticket = ticket; wanted.nr = i;
        wanted.rule = production_readback_rule(plan, i, prior ? 0U : context->creator_uid,
            prior ? context->config.expected_writer_pid : context->creator_pid);
        /* Only evaluation/packet/byte counters are volatile. Skip bytes, rule
         * order, creator receipt, all opaque semantics, states and src_nodes
         * remain strict. GET action is zero, never PF_GET_CLR_CNTR. */
        memset((uint8_t *)&row.rule + 648, 0, 40);
        if (memcmp(&row, &wanted, sizeof(row))) return 0;
        ProductionPoolRequest count = production_pool_query(plan, ticket, i);
        if (!production_read_ioctl(context, PRODUCTION_GET_ADDRS, &count, i, phase, result)) return 0;
        ProductionPoolRequest expected_count = production_pool_query(plan, ticket, i); expected_count.nr = plan->rows[i].has_pool ? 1U : 0U;
        if (memcmp(&count, &expected_count, sizeof(count))) return 0;
        if (plan->rows[i].has_pool) {
            ProductionPoolRequest address = production_pool_query(plan, ticket, i);
            if (!production_read_ioctl(context, PRODUCTION_GET_ADDR, &address, i, phase, result)) return 0;
            ProductionPoolRequest wanted_address = production_pool_query(plan, ticket, i); wanted_address.addr = plan->rows[i].pool;
            if (memcmp(&address, &wanted_address, sizeof(address))) return 0;
        }
        result->pools_verified++;
    }
    EnvaraPFHookRequest last = production_rule_request(plan);
    if (!production_read_ioctl(context, ENVARA_PF_HOOK_GET_RULES, &last, UINT32_MAX, phase, result)) return 0;
    return !memcmp(&last, &expected, sizeof(last));
}
static void production_rollback(EnvaraPFProductionContext *context, const ProductionPlan *plan, EnvaraPFProductionResult *result) {
    if (!result->ticket_known || result->committed || result->rollback_attempted) return;
    EnvaraPFProductionReason original = result->reason;
    if (!production_guard(context, ENVARA_PF_PRODUCTION_GUARD_ROLLBACK, UINT32_MAX, PRODUCTION_POISON, result)) { result->reason = original; return; }
    ProductionEntry entry = production_entry(plan, result->ticket); ProductionTransaction transaction = {1, (int32_t)sizeof(entry), &entry};
    result->rollback_attempted = 1;
    if (!production_ioctl(context, PRODUCTION_ROLLBACK, &transaction, PRODUCTION_POISON) &&
        production_transaction_reply(plan, &transaction, &entry, result->ticket)) result->rollback_acknowledged = 1;
    /* Pinned rollback can acknowledge an already committed/no-open/mismatched
     * transaction. Never clear uncertainty or prove active/namespace emptiness. */
}
static void production_result(EnvaraPFProductionResult *result, int read_only) {
    memset(result, 0, sizeof(*result)); result->read_only = read_only;
    result->actual_count = UINT32_MAX; result->rule_index = UINT32_MAX;
}
int EnvaraPFProductionInit(EnvaraPFProductionContext *context, int fd, void *opaque, EnvaraPFProductionIoctl ioctl_call,
    EnvaraPFProductionGuard guard, const EnvaraPFProductionConfig *config) {
    if (!context || context->magic || fd < 0 || !guard || !production_config_valid(config) ||
        fd == config->listener_fd || geteuid() != 0) return 0;
    memset(context, 0, sizeof(*context)); context->fd = fd; context->opaque = opaque; context->ioctl_call = ioctl_call;
    context->guard = guard; context->config = *config; context->magic = PRODUCTION_MAGIC;
    context->creator_uid = (uint32_t)geteuid(); context->creator_pid = (uint32_t)getpid(); return 1;
}
int EnvaraPFProductionVerify(EnvaraPFProductionContext *context, EnvaraPFProductionMode mode, EnvaraPFProductionResult *result) {
    if (!result) { if (context && context->magic == PRODUCTION_MAGIC) context->phase = PRODUCTION_POISON; return 0; }
    production_result(result, 1);
    if (context && context->magic == PRODUCTION_MAGIC && context->phase == PRODUCTION_POISON) result->uncertain = 1;
    if (!context || context->magic != PRODUCTION_MAGIC || !context->guard || context->fd < 0) { result->reason = ENVARA_PF_PRODUCTION_INVALID_CONTEXT; return 0; }
    ProductionPlan plan;
    if (!production_plan(&context->config, mode, &plan) || (plan.count && (!context->config.has_previous_revision || !context->config.expected_writer_pid))) {
        result->reason = ENVARA_PF_PRODUCTION_INVALID_CONFIG; context->phase = PRODUCTION_POISON; return 0;
    }
    if (context->phase == PRODUCTION_MUTATING || context->phase == PRODUCTION_READING) {
        result->reason = ENVARA_PF_PRODUCTION_ALREADY_USED; context->phase = PRODUCTION_POISON; return 0;
    }
    uint32_t previous_phase = context->phase; context->phase = PRODUCTION_READING; result->expected_count = plan.count;
    if (!production_readback(context, &plan, PRODUCTION_READING, 1, result)) {
        if (result->reason != ENVARA_PF_PRODUCTION_GUARD_REJECTED) result->reason = ENVARA_PF_PRODUCTION_VERIFY_FAILED;
        context->phase = PRODUCTION_POISON; return 0;
    }
    result->verified = 1; result->uncertain = previous_phase == PRODUCTION_POISON;
    context->phase = previous_phase; return 1;
}
int EnvaraPFProductionApply(EnvaraPFProductionContext *context, EnvaraPFProductionMode mode, EnvaraPFProductionResult *result) {
    if (!result) { if (context && context->magic == PRODUCTION_MAGIC) context->phase = PRODUCTION_POISON; return 0; }
    production_result(result, 0);
    if (context && context->magic == PRODUCTION_MAGIC && context->phase == PRODUCTION_POISON) result->uncertain = 1;
    if (!context || context->magic != PRODUCTION_MAGIC || !context->guard || context->fd < 0) { result->reason = ENVARA_PF_PRODUCTION_INVALID_CONTEXT; return 0; }
    if (context->apply_used || context->phase != PRODUCTION_FRESH) { result->reason = ENVARA_PF_PRODUCTION_ALREADY_USED; context->phase = PRODUCTION_POISON; return 0; }
    context->apply_used = 1; context->phase = PRODUCTION_MUTATING; ProductionPlan plan;
    if (!production_plan(&context->config, mode, &plan)) { result->reason = ENVARA_PF_PRODUCTION_INVALID_CONFIG; context->phase = PRODUCTION_POISON; return 0; }
    result->expected_count = plan.count; result->writer_pid = context->creator_pid;
    if (!production_guard(context, ENVARA_PF_PRODUCTION_GUARD_INITIAL, UINT32_MAX, PRODUCTION_MUTATING, result) ||
        !production_guard(context, ENVARA_PF_PRODUCTION_GUARD_BEGIN, UINT32_MAX, PRODUCTION_MUTATING, result)) goto failed;
    ProductionEntry entry = production_entry(&plan, 0); ProductionTransaction transaction = {1, (int32_t)sizeof(entry), &entry};
    result->begun = 1; result->uncertain = 1;
    if (production_ioctl(context, PRODUCTION_BEGIN, &transaction, PRODUCTION_MUTATING)) { result->reason = ENVARA_PF_PRODUCTION_BEGIN_FAILED; result->os_error = errno; goto failed; }
    if (!production_transaction_reply(&plan, &transaction, &entry, entry.ticket)) { result->reason = ENVARA_PF_PRODUCTION_BEGIN_REPLY_INVALID; goto failed; }
    result->ticket_known = 1; result->ticket = entry.ticket;
    for (uint32_t i = 0; i < plan.count; i++) {
        if (!production_guard(context, ENVARA_PF_PRODUCTION_GUARD_BEGIN_ADDRS, i, PRODUCTION_MUTATING, result)) goto failed;
        ProductionPoolRequest pool = {0}; result->pool_attempted = 1;
        if (production_ioctl(context, PRODUCTION_BEGIN_ADDRS, &pool, PRODUCTION_MUTATING)) { result->reason = ENVARA_PF_PRODUCTION_POOL_FAILED; result->os_error = errno; goto failed; }
        ProductionPoolRequest expected_pool = {0}; expected_pool.ticket = pool.ticket;
        if (memcmp(&pool, &expected_pool, sizeof(pool))) { result->reason = ENVARA_PF_PRODUCTION_POOL_REPLY_INVALID; goto failed; }
        if (plan.rows[i].has_pool) {
            ProductionPoolRequest address = {0}; address.ticket = pool.ticket; address.af = PRODUCTION_INET; address.addr = plan.rows[i].pool;
            memcpy(address.anchor, plan.anchor, strlen(plan.anchor) + 1); ProductionPoolRequest expected_address = address;
            if (!production_guard(context, ENVARA_PF_PRODUCTION_GUARD_ADD_ADDR, i, PRODUCTION_MUTATING, result)) goto failed;
            result->add_addr_attempted = 1;
            if (production_ioctl(context, PRODUCTION_ADD_ADDR, &address, PRODUCTION_MUTATING)) { result->reason = ENVARA_PF_PRODUCTION_ADD_ADDR_FAILED; result->os_error = errno; goto failed; }
            if (memcmp(&address, &expected_address, sizeof(address))) { result->reason = ENVARA_PF_PRODUCTION_ADD_ADDR_REPLY_INVALID; goto failed; }
        }
        EnvaraPFHookRequest request = production_rule_request(&plan); request.ticket = result->ticket; request.pool_ticket = pool.ticket; request.rule = plan.rows[i].rule;
        EnvaraPFHookRequest expected_request = request;
        if (!production_guard(context, ENVARA_PF_PRODUCTION_GUARD_ADD_RULE, i, PRODUCTION_MUTATING, result)) goto failed;
        if (production_ioctl(context, PRODUCTION_ADD_RULE, &request, PRODUCTION_MUTATING)) { result->reason = ENVARA_PF_PRODUCTION_ADD_RULE_FAILED; result->os_error = errno; goto failed; }
        if (memcmp(&request, &expected_request, sizeof(request))) { result->reason = ENVARA_PF_PRODUCTION_ADD_RULE_REPLY_INVALID; goto failed; }
        result->rules_added++;
    }
    if (!production_guard(context, ENVARA_PF_PRODUCTION_GUARD_COMMIT, UINT32_MAX, PRODUCTION_MUTATING, result)) goto failed;
    entry = production_entry(&plan, result->ticket); transaction = (ProductionTransaction){1, (int32_t)sizeof(entry), &entry}; result->commit_attempted = 1;
    if (production_ioctl(context, PRODUCTION_COMMIT, &transaction, PRODUCTION_MUTATING)) { result->reason = ENVARA_PF_PRODUCTION_COMMIT_FAILED; result->os_error = errno; goto failed; }
    result->committed = 1;
    if (!production_transaction_reply(&plan, &transaction, &entry, result->ticket)) { result->reason = ENVARA_PF_PRODUCTION_COMMIT_REPLY_INVALID; goto failed; }
    if (!production_readback(context, &plan, PRODUCTION_MUTATING, 0, result)) {
        if (result->reason != ENVARA_PF_PRODUCTION_GUARD_REJECTED) result->reason = ENVARA_PF_PRODUCTION_VERIFY_FAILED; goto failed;
    }
    result->verified = 1; result->uncertain = 0; context->phase = PRODUCTION_COMPLETE; return 1;
failed:
    context->phase = PRODUCTION_POISON; production_rollback(context, &plan, result); return 0;
}
const char *EnvaraPFProductionReasonName(EnvaraPFProductionReason reason) {
    static const char *const names[] = {"okay", "invalid-context", "invalid-config", "already-used", "guard-rejected", "begin-failed",
        "begin-reply-invalid", "pool-failed", "pool-reply-invalid", "add-address-failed", "add-address-reply-invalid", "add-rule-failed",
        "add-rule-reply-invalid", "commit-failed", "commit-reply-invalid", "verify-failed"};
    return (unsigned)reason < sizeof(names)/sizeof(names[0]) ? names[reason] : "invalid-reason";
}
