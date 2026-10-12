import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, realpath, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const execute = promisify(execFile);
const source = fileURLToPath(new URL('../native/macos-pf-routing/pf-production-filter.c', import.meta.url));
const runId = 'a85314b8-5b24-4784-95ec-47b739c2e841';
const realmId = '00112233-4455-4677-8899-aabbccddeeff';
const digest = text => createHash('sha256').update(text).digest('hex');

test('production constructor remains separate, source-only, with no caller targets or states', async () => {
  const implementation = await readFile(source, 'utf8');
  assert.doesNotMatch(implementation, /\b(?:open|fork|execve|system|posix_spawn|setuid|kill)\s*\(/);
  assert.doesNotMatch(implementation, /DIOC(?:START|STOP|KILLSTATES|CLRSTATES|ADDSTATE)\s*\(/);
  assert.match(implementation, /PRODUCTION_ROUTETO = 2/);
  assert.match(implementation, /PRODUCTION_RRG = 9/);
  assert.match(implementation, /geteuid\(\) != 0/);
  assert.doesNotMatch(implementation, /1\.1\.1\.1|198\.51\.100\.42|target_suffix/);
  assert.match(implementation, /entry\.rs_num = 1/);
  assert.match(implementation, /has_previous_revision/);
  assert.match(implementation, /memset\(\(uint8_t \*\)&row\.rule \+ 648, 0, 40\)/);
});

const harness = String.raw`
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
static uint32_t fixture_pid = 2401;
static uid_t fixture_uid = 0;
static uid_t fixture_geteuid(void) { return fixture_uid; }
static pid_t fixture_getpid(void) { return (pid_t)fixture_pid; }
static int forbidden_ioctl(int fd, unsigned long request, ...) { (void)fd; (void)request; abort(); }
#define ioctl forbidden_ioctl
#define geteuid fixture_geteuid
#define getpid fixture_getpid
#include PRODUCTION_SOURCE
#undef ioctl
#undef geteuid
#undef getpid
typedef struct {
    const char *scenario;
    EnvaraPFProductionContext *context;
    int fail_guard, last_guard, mutations, reads, begins, resets, addrs, adds, commits, rollbacks;
    uint32_t last_index, next_ticket, pending_ticket, active_ticket, global_pool_ticket, pending_count, active_count, writer_pid;
    ProductionGeneratedRule pending[ENVARA_PF_PRODUCTION_MAX_RULES], active[ENVARA_PF_PRODUCTION_MAX_RULES];
    ProductionPoolAddress staged;
    int staged_count;
} Fixture;
static int is(Fixture *f, const char *scenario) { return !strcmp(f->scenario, scenario); }
static EnvaraPFProductionConfig config(void) {
#define RUN_ID "a85314b8-5b24-4784-95ec-47b739c2e841"
    EnvaraPFProductionConfig value = {0}; strcpy(value.run_id, RUN_ID);
    strcpy(value.realm_id, "00112233-4455-4677-8899-aabbccddeeff"); value.gid = 7111;
    strcpy(value.utun, "utun911"); value.route_ipv4[0] = 198; value.route_ipv4[1] = 18;
    value.route_ipv4[2] = 11; value.route_ipv4[3] = 1; value.listener_fd = 124; value.tcp_front_port = 49151;
    return value;
}
static int guarded(void *opaque, int fd, EnvaraPFProductionStage stage, uint32_t index) {
    Fixture *fixture = opaque; assert(fd == 123); fixture->last_guard = (int)stage; fixture->last_index = index;
    if (is(fixture, "guard-reenter") && stage == ENVARA_PF_PRODUCTION_GUARD_INITIAL) {
        EnvaraPFProductionResult nested; assert(!EnvaraPFProductionApply(fixture->context, ENVARA_PF_PRODUCTION_EMPTY, &nested));
        assert(nested.reason == ENVARA_PF_PRODUCTION_ALREADY_USED);
    }
    return (int)stage == fixture->fail_guard ? 0 : 1;
}
static void require_guard(Fixture *fixture, EnvaraPFProductionStage stage, uint32_t index) {
    assert(fixture->last_guard == (int)stage && fixture->last_index == index); fixture->last_guard = -1;
}
static void transaction_shape(ProductionTransaction *transaction, uint32_t ticket) {
    assert(transaction->size == 1 && transaction->esize == 1032 && transaction->array);
    ProductionEntry *entry = transaction->array; assert(entry->rs_num == 1 && entry->ticket == ticket);
    assert(!strcmp(entry->anchor, "io.envara.pf.run.a85314b8-5b24-4784-95ec-47b739c2e841"));
    for (size_t i = strlen(entry->anchor) + 1; i < sizeof(entry->anchor); i++) assert(entry->anchor[i] == 0);
}
static int independent_key_equal(const EnvaraPFHookRule *a, const EnvaraPFHookRule *b, unsigned key) {
    switch (key) {
        case 0: return !strcmp(a->ifname, b->ifname) && a->ifnot == b->ifnot;
        case 1: return a->direction == b->direction;
        case 2: return a->af == b->af;
        case 3: return a->proto == b->proto;
        case 4: return a->src[56] == b->src[56] && a->src[40] == b->src[40] && !memcmp(a->src, b->src, 32);
        case 5: return a->src[52] == b->src[52] && !memcmp(a->src + 48, b->src + 48, 4);
        case 6: return a->dst[56] == b->dst[56] && a->dst[40] == b->dst[40] && !memcmp(a->dst, b->dst, 32);
        case 7: return a->dst[52] == b->dst[52] && !memcmp(a->dst + 48, b->dst + 48, 4);
    }
    abort();
}
static void native_row(Fixture *fixture, uint32_t index, EnvaraPFHookRule *output) {
    *output = fixture->active[index].rule; output->nr = index;
    uint8_t *bytes = (uint8_t *)output; bytes[642] = output->af;
    uint32_t uid = 0; memcpy(bytes + 956, &uid, 4); memcpy(bytes + 960, &fixture->writer_pid, 4);
    /* Model the COMPLETE GETRULE pipeline: copyout first clears every 8-byte
     * pointer union, then GETRULE repopulates the low32 target nr. Stopping at
     * copyout alone would incorrectly expect all-zero final skip bytes. */
    uint32_t final_indices[8];
    for (unsigned key = 0; key < 8; key++) {
        uint32_t next = UINT32_MAX;
        for (uint32_t j = fixture->active_count - 1; j > index; j--)
            if (!independent_key_equal(&fixture->active[j - 1].rule, &fixture->active[j].rule, key)) next = j;
        final_indices[key] = next;
        uint64_t internal_pointer = next == UINT32_MAX ? 0U : UINT64_C(0xfedcba9876540000) + next;
        memcpy(output->skip + key * 8, &internal_pointer, 8);
    }
    memset(output->skip, 0, sizeof(output->skip)); /* pf_rule_copyout */
    for (unsigned key = 0; key < 8; key++) memcpy(output->skip + key * 8, &final_indices[key], 4); /* DIOCGETRULE */
    output->evaluations = 11; output->packets[0] = 12; output->bytes[1] = 1300;
    if (index == 0) {
        if (is(fixture, "verify-state")) bytes[904] = 1;
        if (is(fixture, "verify-source-node")) bytes[912] = 1;
        if (is(fixture, "verify-opaque")) bytes[810] = 1;
        if (is(fixture, "verify-skip")) output->skip[0] ^= 1;
        if (is(fixture, "verify-skip-upper")) output->skip[7] = 1;
        if (is(fixture, "verify-redaction-only")) memset(output->skip, 0, sizeof(output->skip));
        if (is(fixture, "verify-owner")) output->owner[0] = 'x';
        if (is(fixture, "verify-label")) output->label[0] = 'x';
        if (is(fixture, "verify-writer")) bytes[960] ^= 1;
        if (is(fixture, "verify-uid")) bytes[956] = 1;
        if (is(fixture, "verify-gid")) output->gid[0]++;
        if (is(fixture, "verify-state-policy")) output->keep_state = 1;
        if (is(fixture, "verify-rule-index")) output->nr++;
        if (is(fixture, "verify-port-op")) output->src[52] = 0;
        if (is(fixture, "verify-port-range")) output->src[51] = 0;
        if (is(fixture, "verify-front-ip")) output->dst[3] = 2;
        if (is(fixture, "verify-front-mask")) output->dst[16] = 0;
        if (is(fixture, "verify-front-port")) output->dst[49] ^= 1;
    }
    if (fixture->active[index].has_pool) {
        if (is(fixture, "verify-rt1")) output->rt = 1;
        if (is(fixture, "verify-pool-opaque")) bytes[600] = 1;
    }
    if (index == 3) {
        if (is(fixture, "verify-listener-uid")) output->uid[0] = 501;
        if (is(fixture, "verify-listener-uid-last")) output->uid[1] = 501;
        if (is(fixture, "verify-listener-uid-op")) output->uid_op = 0;
        if (is(fixture, "verify-listener-uid-pad")) output->uid_pad[0] = 1;
        if (is(fixture, "verify-listener-gid")) output->gid[0] = 0;
        if (is(fixture, "verify-listener-gid-last")) output->gid[1] = 0;
        if (is(fixture, "verify-listener-gid-op")) output->gid_op = 0;
        if (is(fixture, "verify-listener-gid-pad")) output->gid_pad[0] = 1;
        if (is(fixture, "verify-listener-direction")) output->direction = PRODUCTION_OUT;
        if (is(fixture, "verify-listener-ip")) output->dst[3] = 2;
        if (is(fixture, "verify-listener-port")) output->dst[49] ^= 1;
        if (is(fixture, "verify-listener-interface")) output->ifname[2] = '1';
        if (is(fixture, "verify-listener-state")) output->keep_state = 1;
        if (is(fixture, "verify-listener-quick")) output->quick = 0;
    }
    if (index == 4) {
        if (is(fixture, "verify-listener-fallback-uid")) output->uid_op = PRODUCTION_EQ;
        if (is(fixture, "verify-listener-fallback-gid")) output->gid_op = PRODUCTION_EQ;
        if (is(fixture, "verify-listener-fallback-action")) output->action = PRODUCTION_PASS;
    }
}
static int mock_ioctl(void *opaque, int fd, unsigned long operation, void *argument) {
    Fixture *fixture = opaque; assert(fd == 123);
    if (operation == PRODUCTION_BEGIN) {
        require_guard(fixture, ENVARA_PF_PRODUCTION_GUARD_BEGIN, UINT32_MAX); fixture->begins++; fixture->mutations++;
        ProductionTransaction *transaction = argument; transaction_shape(transaction, 0);
        fixture->pending_count = 0; fixture->pending_ticket = is(fixture, "zero-ticket") ? 0U : ++fixture->next_ticket;
        transaction->array->ticket = fixture->pending_ticket;
        if (is(fixture, "begin-error")) { errno = EINTR; return -1; }
        if (is(fixture, "begin-anchor")) transaction->array->anchor[0] = 'x';
        if (is(fixture, "begin-class")) transaction->array->rs_num = 7;
        if (is(fixture, "begin-array")) transaction->array = NULL;
        return 0;
    }
    if (operation == PRODUCTION_BEGIN_ADDRS) {
        require_guard(fixture, ENVARA_PF_PRODUCTION_GUARD_BEGIN_ADDRS, fixture->pending_count); fixture->resets++; fixture->mutations++;
        ProductionPoolRequest *request = argument, zero = {0}; assert(!memcmp(request, &zero, sizeof(zero)));
        fixture->staged = (ProductionPoolAddress){0}; fixture->staged_count = 0;
        request->ticket = fixture->global_pool_ticket = is(fixture, "zero-ticket") ? 0U : 800U + (uint32_t)fixture->resets;
        if (is(fixture, "pool-error")) { errno = EIO; return -1; }
        if (is(fixture, "pool-reply")) request->addr.address.address[0] = 1;
        return 0;
    }
    if (operation == PRODUCTION_ADD_ADDR) {
        require_guard(fixture, ENVARA_PF_PRODUCTION_GUARD_ADD_ADDR, fixture->pending_count); fixture->addrs++; fixture->mutations++;
        ProductionPoolRequest *request = argument;
        assert(request->ticket == fixture->global_pool_ticket && request->af == 2 && request->nr == 0 && request->r_num == 0);
        assert(!request->action && !request->r_action && !request->r_last && !fixture->staged_count);
        assert(!strcmp(request->anchor, "io.envara.pf.run.a85314b8-5b24-4784-95ec-47b739c2e841"));
        assert(request->addr.address.address[0] == 198 && request->addr.address.address[1] == 18 && request->addr.address.address[3] == 1);
        assert(!strcmp(request->addr.ifname, "utun911"));
        assert(!request->addr.kif && !request->addr.entries[0] && !request->addr.entries[1] && !request->addr.address.pointer);
        for (size_t i = 0; i < 4; i++) assert(request->addr.address.mask[i] == 255);
        fixture->staged = request->addr; fixture->staged_count = 1;
        if (is(fixture, "address-error")) { errno = EBUSY; return -1; }
        if (is(fixture, "address-reply")) request->addr.ifname[0] = 'x';
        return 0;
    }
    if (operation == PRODUCTION_ADD_RULE) {
        require_guard(fixture, ENVARA_PF_PRODUCTION_GUARD_ADD_RULE, fixture->pending_count); fixture->adds++; fixture->mutations++;
        EnvaraPFHookRequest *request = argument;
        assert(request->ticket == fixture->pending_ticket && request->pool_ticket == fixture->global_pool_ticket);
        assert(!request->action && !request->nr && !request->anchor_call[0] && request->rule.nr == 0 && request->rule.ticket == 0);
        assert(request->rule.keep_state == 0);
        if (request->rule.uid_op) {
            assert(!strcmp(request->rule.label + strlen(request->rule.label) - strlen("_front_listener"), "_front_listener"));
            assert(request->rule.uid_op == PRODUCTION_EQ && !request->rule.uid[0] && !request->rule.uid[1]);
            assert(request->rule.gid_op == PRODUCTION_EQ && request->rule.gid[0] == 7111 && request->rule.gid[1] == 7111);
            assert(request->rule.action == PRODUCTION_PASS && request->rule.direction == PRODUCTION_IN && request->rule.quick == 1);
        }
        if (request->rule.rt) assert(request->rule.rt == 2 && fixture->staged_count == 1 && request->rule.action == 0 && request->rule.af == 2);
        else assert(fixture->staged_count == 0);
        fixture->pending[fixture->pending_count++] = (ProductionGeneratedRule){request->rule, fixture->staged, fixture->staged_count};
        fixture->staged = (ProductionPoolAddress){0}; fixture->staged_count = 0;
        if (is(fixture, "rule-error")) { errno = EINTR; return -1; }
        if (is(fixture, "rule-reply")) request->rule.rt = 1;
        return 0;
    }
    if (operation == PRODUCTION_COMMIT) {
        require_guard(fixture, ENVARA_PF_PRODUCTION_GUARD_COMMIT, UINT32_MAX); fixture->commits++; fixture->mutations++;
        transaction_shape(argument, fixture->pending_ticket);
        fixture->active_ticket = fixture->pending_ticket; fixture->active_count = fixture->pending_count;
        fixture->writer_pid = fixture_pid; memcpy(fixture->active, fixture->pending, sizeof(fixture->active));
        if (is(fixture, "commit-lost")) { errno = EINTR; return -1; }
        if (is(fixture, "commit-reply")) ((ProductionTransaction *)argument)->array->ticket++;
        return 0;
    }
    if (operation == PRODUCTION_ROLLBACK) {
        require_guard(fixture, ENVARA_PF_PRODUCTION_GUARD_ROLLBACK, UINT32_MAX); fixture->rollbacks++; fixture->mutations++;
        transaction_shape(argument, fixture->pending_ticket);
        if (is(fixture, "rollback-error")) { errno = EIO; return -1; } return 0;
    }
    fixture->reads++;
    if (operation == ENVARA_PF_HOOK_GET_RULES) {
        require_guard(fixture, ENVARA_PF_PRODUCTION_GUARD_VERIFY, UINT32_MAX); EnvaraPFHookRequest *request = argument;
        assert(!request->action && !request->rule.action); request->nr = fixture->active_count; request->ticket = fixture->active_ticket;
        if (is(fixture, "verify-count")) request->nr++;
        if (is(fixture, "verify-ticket")) request->ticket++;
        if (is(fixture, "verify-error")) { errno = EIO; return -1; }
        if (is(fixture, "verify-race") && fixture->reads > 1) request->ticket++;
        if (is(fixture, "ioctl-reenter") && fixture->reads > 1) {
            EnvaraPFProductionResult nested; assert(!EnvaraPFProductionApply(fixture->context, ENVARA_PF_PRODUCTION_EMPTY, &nested));
        }
        return 0;
    }
    if (operation == ENVARA_PF_HOOK_GET_RULE) {
        EnvaraPFHookRequest *request = argument; require_guard(fixture, ENVARA_PF_PRODUCTION_GUARD_VERIFY, request->nr);
        assert(request->ticket == fixture->active_ticket && request->nr < fixture->active_count && request->action == 0);
        native_row(fixture, request->nr, &request->rule); return 0;
    }
    if (operation == PRODUCTION_GET_ADDRS || operation == PRODUCTION_GET_ADDR) {
        ProductionPoolRequest *request = argument; require_guard(fixture, ENVARA_PF_PRODUCTION_GUARD_VERIFY, request->r_num);
        /* Both queries use ACTIVE FILTER revision, never global pool ticket. */
        assert(request->ticket == fixture->active_ticket && request->r_num < fixture->active_count && !request->r_action && !request->r_last);
        assert(!request->action && !request->nr && request->af == 2);
        if (operation == PRODUCTION_GET_ADDRS) {
            request->nr = fixture->active[request->r_num].has_pool ? 1U : 0U;
            if (is(fixture, "verify-pool-count")) request->nr++;
        } else {
            assert(fixture->active[request->r_num].has_pool); request->addr = fixture->active[request->r_num].pool;
            if (is(fixture, "verify-pool-interface")) request->addr.ifname[0] = 'x';
            if (is(fixture, "verify-pool-ip")) request->addr.address.address[2]++;
            if (is(fixture, "verify-pool-mask")) request->addr.address.mask[0] = 0;
            if (is(fixture, "verify-pool-pointer")) request->addr.kif = 1;
        }
        return 0;
    }
    abort();
}
static void no_replay(EnvaraPFProductionContext *context, Fixture *fixture) {
    int before = fixture->mutations; EnvaraPFProductionResult repeated;
    assert(!EnvaraPFProductionApply(context, ENVARA_PF_PRODUCTION_EMPTY, &repeated));
    assert(!EnvaraPFProductionApply(context, ENVARA_PF_PRODUCTION_ROUTED, &repeated));
    assert(fixture->mutations == before && !repeated.begun && !repeated.rollback_attempted && repeated.uncertain);
    EnvaraPFProductionConfig value = config(); assert(!EnvaraPFProductionInit(context, 123, fixture, mock_ioctl, guarded, &value));
}
static void dump(const EnvaraPFProductionConfig *value, EnvaraPFProductionMode mode) {
    ProductionPlan plan; assert(production_plan(value, mode, &plan)); printf("{\"count\":%u,\"rows\":[", plan.count);
    for (uint32_t i = 0; i < plan.count; i++) {
        const ProductionGeneratedRule *row = &plan.rows[i]; const EnvaraPFHookRule *rule = &row->rule;
        uint16_t src_port, src_last, dst_port; memcpy(&src_port, rule->src + 48, 2); memcpy(&src_last, rule->src + 50, 2); memcpy(&dst_port, rule->dst + 48, 2);
        printf("%s{\"label\":\"%s\",\"action\":%u,\"direction\":%u,\"af\":%u,\"proto\":%u,\"interface\":\"%s\",\"ifnot\":%u,\"uid\":%u,\"uidLast\":%u,\"uidOp\":%u,\"gid\":%u,\"gidLast\":%u,\"gidOp\":%u,\"quick\":%u,\"route\":%u,\"state\":%u,\"srcPort\":%u,\"srcLast\":%u,\"srcOp\":%u,\"dstPort\":%u,\"dstOp\":%u,\"dstIp\":\"%u.%u.%u.%u\",\"dstMask\":[%u,%u,%u,%u],\"pool\":\"%s\"}", i ? "," : "", rule->label,rule->action,rule->direction,rule->af,rule->proto,rule->ifname,rule->ifnot,rule->uid[0],rule->uid[1],rule->uid_op,rule->gid[0],rule->gid[1],rule->gid_op,rule->quick,rule->rt,rule->keep_state,ntohs(src_port),ntohs(src_last),rule->src[52],ntohs(dst_port),rule->dst[52],rule->dst[0],rule->dst[1],rule->dst[2],rule->dst[3],rule->dst[16],rule->dst[17],rule->dst[18],rule->dst[19],row->pool.ifname);
    }
    puts("]}");
}
/* A deliberately limited independent model of the pinned PF TCP row walk,
 * not a socket lookup, real PF experiment, or whole-guard acceptance. For IN
 * the supplied local UID/GID is the receiving socket's credential; for OUT it
 * is the sending socket's credential. Unknown lookup returns UINT32_MAX. */
typedef struct {
    uint8_t direction, af, protocol, destination[4];
    const char *interface;
    uint32_t socket_uid, socket_gid;
    uint16_t source_port, destination_port;
    int fragment;
} ModelPacket;
static int model_front_action(const ProductionPlan *plan, const ModelPacket *packet) {
    for (uint32_t i = 0; i < plan->count; i++) {
        const EnvaraPFHookRule *row = &plan->rows[i].rule;
        if (row->direction != packet->direction || row->af != packet->af || row->proto != packet->protocol ||
            strcmp(row->ifname, packet->interface) || row->ifnot) continue;
        if (packet->fragment) {
            if (row->src[52] || row->dst[52]) continue;
        } else {
            if (row->uid_op && (row->uid_op != 2 || packet->socket_uid != row->uid[0])) continue;
            if (row->gid_op && (row->gid_op != 2 || packet->socket_gid != row->gid[0])) continue;
            ProductionTransport source, destination;
            memcpy(&source, row->src + 48, sizeof(source)); memcpy(&destination, row->dst + 48, sizeof(destination));
            if (source.range.op && (source.range.op != 9 || packet->source_port < ntohs(source.range.port[0]) ||
                packet->source_port > ntohs(source.range.port[1]))) continue;
            if (destination.range.op != 2 || packet->destination_port != ntohs(destination.range.port[0])) continue;
            int different = 0;
            for (size_t k = 0; k < 4; k++) if ((packet->destination[k] & row->dst[k + 16]) != (row->dst[k] & row->dst[k + 16])) different = 1;
            if (different) continue;
        }
        assert(row->quick == 1 && row->keep_state == 0 && !row->rt);
        return row->action;
    }
    return -1;
}
static void model_front_credentials(const EnvaraPFProductionConfig *value) {
    ProductionPlan plan; assert(production_plan(value, ENVARA_PF_PRODUCTION_FRONT, &plan));
    ModelPacket packet = {.direction=1,.af=2,.protocol=6,.destination={127,0,0,1},.interface="lo0",
        .socket_uid=0,.socket_gid=7111,.source_port=49152,.destination_port=49151};
    for (unsigned port = 0; port <= UINT16_MAX; port += UINT16_MAX) {
        packet.source_port = (uint16_t)port;
        assert(model_front_action(&plan, &packet) == 0);
        packet.socket_uid=501; assert(model_front_action(&plan, &packet) == 1); // ordinary realm user
        packet.socket_uid=0; packet.socket_gid=0; assert(model_front_action(&plan, &packet) == 1); // other root service
        packet.socket_uid=UINT32_MAX; packet.socket_gid=UINT32_MAX; assert(model_front_action(&plan, &packet) == 1); // failed lookup
        packet.socket_uid=0; packet.socket_gid=UINT32_MAX; assert(model_front_action(&plan, &packet) == 1);
        packet.socket_uid=UINT32_MAX; packet.socket_gid=7111; assert(model_front_action(&plan, &packet) == 1);
        packet.socket_uid=0; packet.socket_gid=7112; assert(model_front_action(&plan, &packet) == 1);
        packet.socket_gid=7111;
    }
    packet.fragment=1; assert(model_front_action(&plan, &packet) == -1); // not accepted fragment safety
    packet.fragment=0; packet.destination_port++; assert(model_front_action(&plan, &packet) == -1);
    packet.destination_port--; packet.destination[3]=2; assert(model_front_action(&plan, &packet) == -1);
    packet.destination[3]=1; packet.interface="en0"; assert(model_front_action(&plan, &packet) == -1);
    packet.interface="lo0"; packet.protocol=17; assert(model_front_action(&plan, &packet) == -1);
    packet.protocol=6; packet.af=30; assert(model_front_action(&plan, &packet) == -1);
    packet.af=2; packet.direction=2; packet.socket_uid=501;
    assert(model_front_action(&plan, &packet) == 0); // original client realm OUT remains independent
    packet.socket_gid=20; assert(model_front_action(&plan, &packet) == 1);
}
int main(int argc, char **argv) {
    assert(argc == 2); EnvaraPFProductionConfig value = config();
    if (!strcmp(argv[1], "model-front-credentials")) { model_front_credentials(&value); return 0; }
    if (!strcmp(argv[1], "dump-sibling-anchor")) {
        /* Per-application rules live in their own top-level anchor. A nested
         * path is 90 bytes while both the plan anchor and the rule owner field
         * hold 64, so the shared root hook reaches each application by a fixed
         * call line rather than by nesting. Each anchor stays within the owner
         * field that must carry it.
         */
        ProductionPlan plan; assert(production_plan(&value, ENVARA_PF_PRODUCTION_FRONT, &plan));
        assert(strcmp(plan.anchor, "io.envara.pf.run." RUN_ID) == 0);
        assert(strlen(plan.anchor) == 53 && strlen(plan.anchor) < sizeof(plan.anchor));
        assert(strchr(plan.anchor, '/') == NULL);
        assert(plan.count);
        for (uint32_t i = 0; i < plan.count; i++) {
            assert(strcmp(plan.rows[i].rule.owner, plan.anchor) == 0);
            assert(strnlen(plan.rows[i].rule.owner, sizeof(plan.rows[i].rule.owner)) < sizeof(plan.rows[i].rule.owner));
            assert(strnlen(plan.rows[i].rule.label, sizeof(plan.rows[i].rule.label)) < sizeof(plan.rows[i].rule.label));
        }
        printf("{\"anchor\":\"%s\",\"count\":%u}", plan.anchor, plan.count);
        return 0;
    }
    if (!strncmp(argv[1], "dump-", 5)) {
        dump(&value, !strcmp(argv[1], "dump-empty") ? ENVARA_PF_PRODUCTION_EMPTY : !strcmp(argv[1], "dump-deny") ? ENVARA_PF_PRODUCTION_DENY : !strcmp(argv[1], "dump-front") ? ENVARA_PF_PRODUCTION_FRONT : ENVARA_PF_PRODUCTION_ROUTED); return 0;
    }
    Fixture fixture = {.scenario=argv[1], .fail_guard=-1, .last_guard=-1, .next_ticket=100};
    EnvaraPFProductionContext context = {0}; EnvaraPFProductionResult result; fixture.context = &context;
    if (is(&fixture,"readonly-complete")) { value.has_previous_revision = 1; value.expected_revision = 101; value.expected_writer_pid = fixture_pid; }
    if (!strncmp(argv[1], "invalid-", 8)) {
        if (is(&fixture, "invalid-run")) value.run_id[0] = 'X';
        if (is(&fixture, "invalid-realm")) value.realm_id[14] = '5';
        if (is(&fixture, "invalid-gid")) value.gid = 501;
        if (is(&fixture, "invalid-interface")) strcpy(value.utun, "en0");
        if (is(&fixture, "invalid-interface-zero")) strcpy(value.utun, "utun01");
        if (is(&fixture, "invalid-interface-tail")) value.utun[15] = 'x';
        if (is(&fixture, "invalid-route")) value.route_ipv4[0] = 127;
        if (is(&fixture, "invalid-route-zero")) value.route_ipv4[3] = 0;
        if (is(&fixture, "invalid-route-broadcast")) value.route_ipv4[3] = 255;
        if (is(&fixture, "invalid-listener")) value.listener_fd = -1;
        if (is(&fixture, "invalid-shared-fd")) value.listener_fd = 123;
        if (is(&fixture, "invalid-port")) value.tcp_front_port = 0;
        if (is(&fixture, "invalid-system-port")) value.tcp_front_port = 443;
        if (is(&fixture, "invalid-receipt")) value.has_previous_revision = 2;
        if (is(&fixture, "invalid-writer")) value.expected_writer_pid = 1;
        assert(!EnvaraPFProductionInit(&context,123,&fixture,mock_ioctl,guarded,&value)); assert(!fixture.mutations && !fixture.reads); return 0;
    }
    if (is(&fixture,"init-nonroot")) {
        fixture_uid = 501; assert(!EnvaraPFProductionInit(&context,123,&fixture,mock_ioctl,guarded,&value));
        assert(!fixture.mutations && !fixture.reads); return 0;
    }
    assert(EnvaraPFProductionInit(&context, 123, &fixture, mock_ioctl, guarded, &value));
    if (is(&fixture,"uid-drift")) fixture_uid = 501;
    if (is(&fixture,"pid-drift")) fixture_pid++;
    if (is(&fixture,"copied-config")) { value.gid = 7999; value.listener_fd = 999; value.tcp_front_port = 3000; }
    if (is(&fixture, "verify-no-receipt")) {
        assert(!EnvaraPFProductionVerify(&context,ENVARA_PF_PRODUCTION_ROUTED,&result)); assert(result.read_only && !fixture.reads && !fixture.mutations); no_replay(&context,&fixture); return 0;
    }
    if (!strncmp(argv[1], "guard-", 6) && !is(&fixture, "guard-reenter")) {
        if (is(&fixture, "guard-initial")) fixture.fail_guard = ENVARA_PF_PRODUCTION_GUARD_INITIAL;
        if (is(&fixture, "guard-listener")) fixture.fail_guard = ENVARA_PF_PRODUCTION_GUARD_INITIAL;
        if (is(&fixture, "guard-begin")) fixture.fail_guard = ENVARA_PF_PRODUCTION_GUARD_BEGIN;
        if (is(&fixture, "guard-pool")) fixture.fail_guard = ENVARA_PF_PRODUCTION_GUARD_BEGIN_ADDRS;
        if (is(&fixture, "guard-address")) fixture.fail_guard = ENVARA_PF_PRODUCTION_GUARD_ADD_ADDR;
        if (is(&fixture, "guard-rule")) fixture.fail_guard = ENVARA_PF_PRODUCTION_GUARD_ADD_RULE;
        if (is(&fixture, "guard-commit")) fixture.fail_guard = ENVARA_PF_PRODUCTION_GUARD_COMMIT;
        if (is(&fixture, "guard-verify")) fixture.fail_guard = ENVARA_PF_PRODUCTION_GUARD_VERIFY;
        if (is(&fixture, "guard-rollback")) { fixture.scenario = "rule-error"; fixture.fail_guard = ENVARA_PF_PRODUCTION_GUARD_ROLLBACK; }
    }
    if (is(&fixture, "rollback-error")) fixture.fail_guard = ENVARA_PF_PRODUCTION_GUARD_COMMIT;
    int success = is(&fixture,"success") || is(&fixture,"success-empty") || is(&fixture,"success-deny") || is(&fixture,"success-front") || is(&fixture,"copied-config") || is(&fixture,"zero-ticket") || is(&fixture,"readonly-before") ||
        is(&fixture,"readonly-complete") || !strncmp(argv[1],"prior-",6);
    if (is(&fixture,"readonly-before")) {
        assert(EnvaraPFProductionVerify(&context,ENVARA_PF_PRODUCTION_EMPTY,&result)); assert(result.verified && result.read_only && !fixture.mutations);
    }
    EnvaraPFProductionMode mode = is(&fixture,"success-empty") ? ENVARA_PF_PRODUCTION_EMPTY :
        is(&fixture,"success-deny") ? ENVARA_PF_PRODUCTION_DENY : is(&fixture,"success-front") || !strncmp(argv[1], "verify-listener-", 16) ? ENVARA_PF_PRODUCTION_FRONT : ENVARA_PF_PRODUCTION_ROUTED;
    uint32_t count = mode == ENVARA_PF_PRODUCTION_EMPTY ? 0U : mode == ENVARA_PF_PRODUCTION_DENY ? 6U : mode == ENVARA_PF_PRODUCTION_FRONT ? 5U : 13U;
    int okay = EnvaraPFProductionApply(&context,mode,&result);
    if (!success) {
        assert(!okay && !result.verified);
        if (result.begun) assert(result.uncertain);
        if (!result.ticket_known || result.committed) assert(!result.rollback_attempted && !fixture.rollbacks);
        else if (fixture.fail_guard == ENVARA_PF_PRODUCTION_GUARD_ROLLBACK) assert(!result.rollback_attempted);
        else assert(result.rollback_attempted && fixture.rollbacks == 1);
        if (is(&fixture,"commit-lost")) assert(!result.committed && result.rollback_acknowledged && fixture.active_count == 13);
        no_replay(&context,&fixture); return 0;
    }
    assert(okay && result.verified && !result.uncertain && result.actual_count == count && result.rules_added == count && result.pools_verified == count);
    assert(fixture.resets == (int)count && fixture.adds == (int)count && fixture.addrs == (mode == ENVARA_PF_PRODUCTION_ROUTED ? 2 : 0) && fixture.commits == 1 && !fixture.rollbacks);
    if (is(&fixture,"readonly-complete")) {
        int before = fixture.mutations;
        assert(EnvaraPFProductionVerify(&context,ENVARA_PF_PRODUCTION_ROUTED,&result));
        assert(result.verified && result.read_only && !result.uncertain && fixture.mutations == before);
        no_replay(&context,&fixture);
        assert(EnvaraPFProductionVerify(&context,ENVARA_PF_PRODUCTION_ROUTED,&result));
        assert(result.verified && result.read_only && result.uncertain && fixture.mutations == before);
        no_replay(&context,&fixture); return 0;
    }
    if (!strncmp(argv[1],"prior-",6)) {
        uint32_t committed_pid = fixture_pid; fixture_pid++;
        EnvaraPFProductionConfig prior = config(); prior.has_previous_revision = 1; prior.expected_revision = result.ticket; prior.expected_writer_pid = committed_pid;
        if (is(&fixture,"prior-writer")) prior.expected_writer_pid++;
        if (is(&fixture,"prior-revision")) prior.expected_revision++;
        EnvaraPFProductionContext reader = {0}; assert(EnvaraPFProductionInit(&reader,123,&fixture,mock_ioctl,guarded,&prior));
        fixture.context = &reader; int before = fixture.mutations;
        int verified = EnvaraPFProductionVerify(&reader,ENVARA_PF_PRODUCTION_ROUTED,&result);
        assert(fixture.mutations == before && result.read_only);
        assert(verified == is(&fixture,"prior-good"));
        if (!verified) no_replay(&reader,&fixture);
        fixture.context = &context; fixture_pid = committed_pid;
    }
    no_replay(&context,&fixture);
    assert(!strcmp(EnvaraPFProductionReasonName(ENVARA_PF_PRODUCTION_OK),"okay"));
    assert(!strcmp(EnvaraPFProductionReasonName((EnvaraPFProductionReason)999),"invalid-reason")); return 0;
}
`;

test('inert production filter transactions and fixed policy scope', { skip: process.platform !== 'darwin' }, async t => {
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-production-filter-test-')));
  try {
    const input = path.join(directory, 'fixture.c');
    const binary = path.join(directory, 'fixture');
    await writeFile(input, harness.replace('PRODUCTION_SOURCE', JSON.stringify(source)));
    await execute('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', input, '-o', binary],
      { timeout: 30000, maxBuffer: 1024 * 1024 });
    const cases = ['success', 'success-empty', 'success-deny', 'success-front', 'dump-sibling-anchor', 'copied-config', 'init-nonroot', 'uid-drift', 'pid-drift', 'zero-ticket', 'readonly-before', 'readonly-complete', 'prior-good', 'prior-writer', 'prior-revision', 'verify-no-receipt',
      'invalid-run', 'invalid-realm', 'invalid-gid', 'invalid-interface', 'invalid-route', 'invalid-interface-zero', 'invalid-interface-tail', 'invalid-route-zero',
      'invalid-route-broadcast', 'invalid-listener', 'invalid-shared-fd', 'invalid-port', 'invalid-system-port', 'invalid-writer', 'invalid-receipt', 'guard-initial', 'guard-listener', 'guard-begin',
      'guard-reenter', 'ioctl-reenter', 'guard-pool', 'guard-address', 'guard-rule', 'guard-commit', 'guard-verify', 'guard-rollback',
      'begin-error', 'begin-anchor', 'begin-class', 'begin-array', 'pool-error', 'pool-reply', 'address-error', 'address-reply',
      'rule-error', 'rule-reply', 'rollback-error', 'commit-lost', 'commit-reply', 'verify-error', 'verify-count', 'verify-ticket',
      'verify-race', 'verify-state', 'verify-source-node', 'verify-opaque', 'verify-skip', 'verify-skip-upper', 'verify-redaction-only', 'verify-owner',
      'verify-label', 'verify-writer', 'verify-uid', 'verify-gid', 'verify-state-policy', 'verify-rule-index', 'verify-rt1',
      'verify-pool-opaque', 'verify-pool-count', 'verify-pool-interface', 'verify-pool-ip', 'verify-pool-mask', 'verify-pool-pointer',
      'verify-port-op', 'verify-port-range', 'verify-front-ip', 'verify-front-mask', 'verify-front-port',
      'verify-listener-uid', 'verify-listener-uid-last', 'verify-listener-uid-op', 'verify-listener-uid-pad',
      'verify-listener-gid', 'verify-listener-gid-last', 'verify-listener-gid-op', 'verify-listener-gid-pad',
      'verify-listener-direction', 'verify-listener-ip', 'verify-listener-port', 'verify-listener-interface',
      'verify-listener-state', 'verify-listener-quick', 'verify-listener-fallback-uid', 'verify-listener-fallback-gid', 'verify-listener-fallback-action'];
    for (const scenario of cases) await t.test(scenario, () => execute(binary, [scenario], { timeout: 10000 }));
    await t.test('inert C credential model rejects ordinary realm users, root GID0 and unknown lookups', () =>
      execute(binary, ['model-front-credentials'], { timeout: 10000 }));
    await t.test('FRONT has exact service-side UID0+realm admission and preserves outgoing/IPv6 scope', async () => {
      const scoped = JSON.parse((await execute(binary, ['dump-front'])).stdout);
      assert.equal(scoped.count,5);
      assert.deepEqual(scoped.rows.map(row => [row.action,row.direction,row.af,row.proto,row.interface,row.uidOp,row.uid,row.uidLast,row.gidOp,row.gid,row.gidLast,row.dstPort,row.dstOp,row.route,row.state,row.quick]),
        [[0,2,2,6,'lo0',0,0,0,2,7111,7111,49151,2,0,0,1],[1,2,2,6,'lo0',0,0,0,0,0,0,49151,2,0,0,1],
          [1,2,30,6,'lo0',0,0,0,2,7111,7111,49151,2,0,0,1],[0,1,2,6,'lo0',2,0,0,2,7111,7111,49151,2,0,0,1],
          [1,1,2,6,'lo0',0,0,0,0,0,0,49151,2,0,0,1]]);
      assert.equal(scoped.rows[0].dstIp,'127.0.0.1'); assert.equal(scoped.rows[1].dstIp,'127.0.0.1');
      assert.equal(scoped.rows[2].dstIp,'0.0.0.0'); assert.deepEqual(scoped.rows[2].dstMask,[255,255,255,255]);
      assert.ok(scoped.rows.every(row => row.pool==='' && row.dstOp===2));
      assert.deepEqual(scoped.rows.filter(row=>row.gidOp).map(row=>[row.srcPort,row.srcLast,row.srcOp]),[[0,65535,9],[0,65535,9],[0,65535,9]]);
      assert.equal(scoped.rows[1].srcOp,0);
      assert.equal(scoped.rows[4].srcOp,0);
      assert.equal(scoped.rows[3].dstIp,'127.0.0.1'); assert.deepEqual(scoped.rows[3].dstMask,[255,255,255,255]);
      assert.equal(scoped.rows[4].dstIp,'127.0.0.1'); assert.deepEqual(scoped.rows[4].dstMask,[255,255,255,255]);
      const sourceText=await readFile(source,'utf8');
      assert.match(sourceText,/loopback6\.address\.address\[15\] = 1/);
      // Each row has a destination port: the pinned fragment walker skips all
      // FRONT rows instead of applying a GID-less block to unrelated packets.
      assert.ok(scoped.rows.every(row=>row.dstOp!==0));
      // The IPv6 block has a GID, preserving other applications' ::1 service.
      assert.equal(scoped.rows[2].gidOp,2);
    });
    await t.test('ordered fixed production scope and exact held loopback front', async () => {
      const generated = JSON.parse((await execute(binary, ['dump-routed'])).stdout);
      assert.equal(generated.count, 13);
      const base = `envara_prod_v1_${digest(`${runId}|${realmId}`).slice(0, 24)}_`;
      assert.deepEqual(generated.rows.map(row => row.label),
        ['front','loopback','loopback','ipv6','ipv6','utun_out','utun_out','route','route','utun_in','utun_in','blocked','blocked'].map(suffix => base + suffix));
      assert.deepEqual(generated.rows.map(row => row.proto), [6,6,17,6,17,6,17,6,17,6,17,6,17]);
      assert.ok(generated.rows.every(row => row.state === 0));
      const [front] = generated.rows;
      assert.equal(front.interface, 'lo0'); assert.equal(front.gid,7111); assert.equal(front.gidOp,2);
      assert.equal(front.action,0); assert.equal(front.direction,2); assert.equal(front.af,2); assert.equal(front.dstPort,49151);
      assert.equal(front.dstIp,'127.0.0.1'); assert.deepEqual(front.dstMask,[255,255,255,255]); assert.equal(front.dstOp,2);
      assert.ok(generated.rows.filter(row => row.gidOp).every(row => row.srcOp === 9 && row.srcPort === 0 && row.srcLast === 65535));
      assert.deepEqual(generated.rows.filter(row => row.route).map(row => [row.proto,row.interface,row.ifnot,row.gid,row.pool]),
        [[6,'lo0',1,7111,'utun911'],[17,'lo0',1,7111,'utun911']]);
      assert.equal(JSON.parse((await execute(binary, ['dump-empty'])).stdout).count, 0);
      const deny = JSON.parse((await execute(binary, ['dump-deny'])).stdout);
      assert.equal(deny.count,6); assert.ok(deny.rows.every(row => row.action === 1 && row.route === 0 && row.gid === 7111));
    });
    await t.test('normal port endpoints cover all ports; global GID rows skip fragments', async () => {
      const routed = JSON.parse((await execute(binary,['dump-routed'])).stdout).rows;
      const denied = JSON.parse((await execute(binary,['dump-deny'])).stdout).rows;
      // Independent subset of pinned pf_match_port / pf_test_fragment. This is
      // an inert scope check, not proof of actual socket GID or fragment safety.
      const match = (rows, packet) => rows.find(row => {
        const onInterface = !row.interface || ((row.interface === packet.interface) !== Boolean(row.ifnot));
        if (!onInterface || row.direction !== packet.direction || (row.af && row.af !== packet.af) || row.proto !== packet.proto) return false;
        if (packet.fragment) {
          if (row.srcOp || row.dstOp) return false;
          // The native fragment path omits UID/GID checks.
        } else {
          if (row.gidOp && row.gid !== packet.gid) return false;
          if (row.srcOp === 9 && !(packet.srcPort >= row.srcPort && packet.srcPort <= row.srcLast)) return false;
          if (row.dstOp === 2 && (packet.destination !== row.dstIp || packet.dstPort !== row.dstPort)) return false;
        }
        return true;
      });
      const base = {interface:'en0',direction:2,af:2,proto:6,gid:7111,srcPort:0,dstPort:443,destination:'203.0.113.7',fragment:false};
      for (const proto of [6,17]) for (const srcPort of [0,1,32768,65535]) {
        assert.equal(match(routed,{...base,proto,srcPort}).route,2);
        assert.equal(match(denied,{...base,proto,srcPort}).action,1);
        assert.equal(match(routed,{...base,proto,srcPort,gid:7112}),undefined);
        assert.equal(match(routed,{...base,proto,srcPort,fragment:true}),undefined);
        assert.equal(match(routed,{...base,proto,srcPort,gid:7112,fragment:true}),undefined);
        assert.equal(match(routed,{...base,proto,srcPort,af:30,fragment:true}),undefined);
        const ownedOut = match(routed,{...base,proto,srcPort,interface:'utun911'});
        assert.equal(ownedOut.action,0); assert.equal(ownedOut.route,0);
      }
      assert.equal(match(routed,{...base,interface:'lo0',destination:'127.0.0.1',dstPort:49151}).action,0);
      for (const changed of [{destination:'127.0.0.2'}, {dstPort:49152}, {proto:17}, {af:30}])
        assert.equal(match(routed,{...base,interface:'lo0',destination:'127.0.0.1',dstPort:49151,...changed}).action,1);
      for (const proto of [6,17]) assert.equal(match(routed,{...base,proto,af:30}).action,1);
      assert.equal(match(routed,{...base,direction:1,interface:'utun911'}).action,0);
      assert.equal(match(routed,{...base,direction:1,interface:'en0'}),undefined);
      assert.equal(match(routed,{...base,proto:1}),undefined); // unsupported attribution remains gated.
    });
    await t.test('accepted controlled engine stays byte-for-byte unchanged', async () => {
      const fixed = await readFile(new URL('../native/macos-pf-routing/pf-filter-transaction.c',import.meta.url));
      assert.equal(createHash('sha256').update(fixed).digest('hex'),'f4bb0b12fef44c68d50cb7bd060c3a54b20b5c9b01967b08a8c16cdf58acf127');
    });

  } finally { await rm(directory, { recursive: true, force: true }); }
});
