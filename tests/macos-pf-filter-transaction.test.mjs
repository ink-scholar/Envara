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
const source = fileURLToPath(new URL('../native/macos-pf-routing/pf-filter-transaction.c', import.meta.url));
const runId = 'a85314b8-5b24-4784-95ec-47b739c2e841';
const realmId = '00112233-4455-4677-8899-aabbccddeeff';
const digest = text => createHash('sha256').update(text).digest('hex');

test('generic filter component remains source-only and excludes arbitrary targets and states', async () => {
  const implementation = await readFile(source, 'utf8');
  assert.doesNotMatch(implementation, /\b(?:open|fork|execve|system|posix_spawn|setuid|kill)\s*\(/);
  assert.doesNotMatch(implementation, /DIOC(?:START|STOP|KILLSTATES|CLRSTATES|ADDSTATE)\s*\(/);
  assert.match(implementation, /FILTER_ROUTETO = 2/);
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
static uid_t fixture_geteuid(void) { return 0; }
static pid_t fixture_getpid(void) { return (pid_t)fixture_pid; }
static int forbidden_ioctl(int fd, unsigned long request, ...) { (void)fd; (void)request; abort(); }
#define ioctl forbidden_ioctl
#define geteuid fixture_geteuid
#define getpid fixture_getpid
#include FILTER_SOURCE
#undef ioctl
#undef geteuid
#undef getpid
typedef struct {
    const char *scenario;
    EnvaraPFFilterContext *context;
    int fail_guard, last_guard, mutations, reads, begins, resets, addrs, adds, commits, rollbacks;
    uint32_t last_index, next_ticket, pending_ticket, active_ticket, global_pool_ticket, pending_count, active_count, writer_pid;
    FilterGeneratedRule pending[ENVARA_PF_FILTER_MAX_RULES], active[ENVARA_PF_FILTER_MAX_RULES];
    FilterPoolAddress staged;
    int staged_count;
} Fixture;
static int is(Fixture *f, const char *scenario) { return !strcmp(f->scenario, scenario); }
static EnvaraPFFilterConfig config(void) {
    EnvaraPFFilterConfig value = {0}; strcpy(value.run_id, "a85314b8-5b24-4784-95ec-47b739c2e841"); value.realm_count = 1;
    strcpy(value.realms[0].realm_id, "00112233-4455-4677-8899-aabbccddeeff"); value.realms[0].gid = 7111;
    strcpy(value.realms[0].utun, "utun911"); value.realms[0].route_ipv4[0] = 198; value.realms[0].route_ipv4[1] = 18;
    value.realms[0].route_ipv4[2] = 11; value.realms[0].route_ipv4[3] = 1; value.realms[0].routed = 1; value.realms[0].udp_proxy = 1;
    return value;
}
static void add_second(EnvaraPFFilterConfig *value) {
    value->realm_count = 2; value->realms[1] = value->realms[0];
    strcpy(value->realms[1].realm_id, "11223344-5566-4788-99aa-bbccddeeff00"); value->realms[1].gid = 7112;
    strcpy(value->realms[1].utun, "utun912"); value->realms[1].route_ipv4[2] = 12;
}
static int guarded(void *opaque, int fd, EnvaraPFFilterStage stage, uint32_t index) {
    Fixture *fixture = opaque; assert(fd == 123); fixture->last_guard = (int)stage; fixture->last_index = index;
    if (is(fixture, "guard-reenter") && stage == ENVARA_PF_FILTER_GUARD_INITIAL) {
        EnvaraPFFilterResult nested; assert(!EnvaraPFFilterApply(fixture->context, ENVARA_PF_FILTER_EMPTY, &nested));
        assert(nested.reason == ENVARA_PF_FILTER_ALREADY_USED);
    }
    return (int)stage == fixture->fail_guard ? 0 : 1;
}
static void require_guard(Fixture *fixture, EnvaraPFFilterStage stage, uint32_t index) {
    assert(fixture->last_guard == (int)stage && fixture->last_index == index); fixture->last_guard = -1;
}
static void transaction_shape(FilterTransaction *transaction, uint32_t ticket) {
    assert(transaction->size == 1 && transaction->esize == 1032 && transaction->array);
    FilterEntry *entry = transaction->array; assert(entry->rs_num == 1 && entry->ticket == ticket);
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
    }
    if (fixture->active[index].has_pool) {
        if (is(fixture, "verify-rt1")) output->rt = 1;
        if (is(fixture, "verify-pool-opaque")) bytes[600] = 1;
    }
}
static int mock_ioctl(void *opaque, int fd, unsigned long operation, void *argument) {
    Fixture *fixture = opaque; assert(fd == 123);
    if (operation == FILTER_BEGIN) {
        require_guard(fixture, ENVARA_PF_FILTER_GUARD_BEGIN, UINT32_MAX); fixture->begins++; fixture->mutations++;
        FilterTransaction *transaction = argument; transaction_shape(transaction, 0);
        fixture->pending_count = 0; fixture->pending_ticket = is(fixture, "zero-ticket") ? 0U : ++fixture->next_ticket;
        transaction->array->ticket = fixture->pending_ticket;
        if (is(fixture, "begin-error")) { errno = EINTR; return -1; }
        if (is(fixture, "begin-anchor")) transaction->array->anchor[0] = 'x';
        if (is(fixture, "begin-class")) transaction->array->rs_num = 7;
        if (is(fixture, "begin-array")) transaction->array = NULL;
        return 0;
    }
    if (operation == FILTER_BEGIN_ADDRS) {
        require_guard(fixture, ENVARA_PF_FILTER_GUARD_BEGIN_ADDRS, fixture->pending_count); fixture->resets++; fixture->mutations++;
        FilterPoolRequest *request = argument, zero = {0}; assert(!memcmp(request, &zero, sizeof(zero)));
        fixture->staged = (FilterPoolAddress){0}; fixture->staged_count = 0;
        request->ticket = fixture->global_pool_ticket = is(fixture, "zero-ticket") ? 0U : 800U + (uint32_t)fixture->resets;
        if (is(fixture, "pool-error")) { errno = EIO; return -1; }
        if (is(fixture, "pool-reply")) request->addr.address.address[0] = 1;
        return 0;
    }
    if (operation == FILTER_ADD_ADDR) {
        require_guard(fixture, ENVARA_PF_FILTER_GUARD_ADD_ADDR, fixture->pending_count); fixture->addrs++; fixture->mutations++;
        FilterPoolRequest *request = argument;
        assert(request->ticket == fixture->global_pool_ticket && request->af == 2 && request->nr == 0 && request->r_num == 0);
        assert(!request->action && !request->r_action && !request->r_last && !fixture->staged_count);
        assert(!strcmp(request->anchor, "io.envara.pf.run.a85314b8-5b24-4784-95ec-47b739c2e841"));
        assert(request->addr.address.address[0] == 198 && request->addr.address.address[1] == 18 && request->addr.address.address[3] == 1);
        assert(!strcmp(request->addr.ifname, "utun911") || !strcmp(request->addr.ifname, "utun912"));
        assert(!request->addr.kif && !request->addr.entries[0] && !request->addr.entries[1] && !request->addr.address.pointer);
        for (size_t i = 0; i < 4; i++) assert(request->addr.address.mask[i] == 255);
        fixture->staged = request->addr; fixture->staged_count = 1;
        if (is(fixture, "address-error")) { errno = EBUSY; return -1; }
        if (is(fixture, "address-reply")) request->addr.ifname[0] = 'x';
        return 0;
    }
    if (operation == FILTER_ADD_RULE) {
        require_guard(fixture, ENVARA_PF_FILTER_GUARD_ADD_RULE, fixture->pending_count); fixture->adds++; fixture->mutations++;
        EnvaraPFHookRequest *request = argument;
        assert(request->ticket == fixture->pending_ticket && request->pool_ticket == fixture->global_pool_ticket);
        assert(!request->action && !request->nr && !request->anchor_call[0] && request->rule.nr == 0 && request->rule.ticket == 0);
        assert(request->rule.keep_state == 0 && request->rule.uid_op == 0);
        if (request->rule.rt) assert(request->rule.rt == 2 && fixture->staged_count == 1 && request->rule.action == 0 && request->rule.af == 2);
        else assert(fixture->staged_count == 0);
        fixture->pending[fixture->pending_count++] = (FilterGeneratedRule){request->rule, fixture->staged, fixture->staged_count};
        fixture->staged = (FilterPoolAddress){0}; fixture->staged_count = 0;
        if (is(fixture, "rule-error")) { errno = EINTR; return -1; }
        if (is(fixture, "rule-reply")) request->rule.rt = 1;
        return 0;
    }
    if (operation == FILTER_COMMIT) {
        require_guard(fixture, ENVARA_PF_FILTER_GUARD_COMMIT, UINT32_MAX); fixture->commits++; fixture->mutations++;
        transaction_shape(argument, fixture->pending_ticket);
        fixture->active_ticket = fixture->pending_ticket; fixture->active_count = fixture->pending_count;
        fixture->writer_pid = fixture_pid; memcpy(fixture->active, fixture->pending, sizeof(fixture->active));
        if (is(fixture, "commit-lost")) { errno = EINTR; return -1; }
        if (is(fixture, "commit-reply")) ((FilterTransaction *)argument)->array->ticket++;
        return 0;
    }
    if (operation == FILTER_ROLLBACK) {
        require_guard(fixture, ENVARA_PF_FILTER_GUARD_ROLLBACK, UINT32_MAX); fixture->rollbacks++; fixture->mutations++;
        transaction_shape(argument, fixture->pending_ticket);
        if (is(fixture, "rollback-error")) { errno = EIO; return -1; } return 0;
    }
    fixture->reads++;
    if (operation == ENVARA_PF_HOOK_GET_RULES) {
        require_guard(fixture, ENVARA_PF_FILTER_GUARD_VERIFY, UINT32_MAX); EnvaraPFHookRequest *request = argument;
        assert(!request->action && !request->rule.action); request->nr = fixture->active_count; request->ticket = fixture->active_ticket;
        if (is(fixture, "verify-count")) request->nr++;
        if (is(fixture, "verify-ticket")) request->ticket++;
        if (is(fixture, "verify-error")) { errno = EIO; return -1; }
        if (is(fixture, "verify-race") && fixture->reads > 1) request->ticket++;
        if (is(fixture, "ioctl-reenter") && fixture->reads > 1) {
            EnvaraPFFilterResult nested; assert(!EnvaraPFFilterApply(fixture->context, ENVARA_PF_FILTER_EMPTY, &nested));
        }
        return 0;
    }
    if (operation == ENVARA_PF_HOOK_GET_RULE) {
        EnvaraPFHookRequest *request = argument; require_guard(fixture, ENVARA_PF_FILTER_GUARD_VERIFY, request->nr);
        assert(request->ticket == fixture->active_ticket && request->nr < fixture->active_count && request->action == 0);
        native_row(fixture, request->nr, &request->rule); return 0;
    }
    if (operation == FILTER_GET_ADDRS || operation == FILTER_GET_ADDR) {
        FilterPoolRequest *request = argument; require_guard(fixture, ENVARA_PF_FILTER_GUARD_VERIFY, request->r_num);
        /* Both queries use ACTIVE FILTER revision, never global pool ticket. */
        assert(request->ticket == fixture->active_ticket && request->r_num < fixture->active_count && !request->r_action && !request->r_last);
        assert(!request->action && !request->nr && request->af == 2);
        if (operation == FILTER_GET_ADDRS) {
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
static void no_replay(EnvaraPFFilterContext *context, Fixture *fixture) {
    int before = fixture->mutations; EnvaraPFFilterResult repeated;
    assert(!EnvaraPFFilterApply(context, ENVARA_PF_FILTER_EMPTY, &repeated));
    assert(!EnvaraPFFilterApply(context, ENVARA_PF_FILTER_ROUTED, &repeated));
    assert(fixture->mutations == before && !repeated.begun && !repeated.rollback_attempted);
    EnvaraPFFilterConfig value = config(); assert(!EnvaraPFFilterInit(context, 123, fixture, mock_ioctl, guarded, &value));
}
static void dump(const EnvaraPFFilterConfig *value, EnvaraPFFilterMode mode) {
    FilterPlan plan; assert(filter_plan(value, mode, &plan)); printf("{\"count\":%u,\"rows\":[", plan.count);
    for (uint32_t i = 0; i < plan.count; i++) {
        const FilterGeneratedRule *row = &plan.rows[i]; const EnvaraPFHookRule *rule = &row->rule;
        uint16_t src_port, dst_port; memcpy(&src_port, rule->src + 48, 2); memcpy(&dst_port, rule->dst + 48, 2);
        printf("%s{\"label\":\"%s\",\"action\":%u,\"direction\":%u,\"af\":%u,\"proto\":%u,\"interface\":\"%s\",\"ifnot\":%u,\"gid\":%u,\"gidOp\":%u,\"route\":%u,\"state\":%u,\"srcPort\":%u,\"dstPort\":%u,\"pool\":\"%s\"}", i ? "," : "", rule->label,rule->action,rule->direction,rule->af,rule->proto,rule->ifname,rule->ifnot,rule->gid[0],rule->gid_op,rule->rt,rule->keep_state,ntohs(src_port),ntohs(dst_port),row->pool.ifname);
    }
    puts("]}");
}
int main(int argc, char **argv) {
    assert(argc == 2); EnvaraPFFilterConfig value = config();
    if (!strncmp(argv[1], "dump-", 5)) {
        if (!strcmp(argv[1], "dump-two")) add_second(&value);
        if (!strcmp(argv[1], "dump-udp-block")) value.realms[0].udp_proxy = 0;
        if (!strcmp(argv[1], "dump-blocked-realm")) value.realms[0].routed = 0;
        if (!strcmp(argv[1], "dump-sorted")) { add_second(&value); EnvaraPFFilterRealm swap = value.realms[0]; value.realms[0] = value.realms[1]; value.realms[1] = swap; }
        dump(&value, !strcmp(argv[1], "dump-empty") ? ENVARA_PF_FILTER_EMPTY : !strcmp(argv[1], "dump-deny") ? ENVARA_PF_FILTER_DENY : ENVARA_PF_FILTER_ROUTED); return 0;
    }
    Fixture fixture = {.scenario=argv[1], .fail_guard=-1, .last_guard=-1, .next_ticket=100};
    EnvaraPFFilterContext context = {0}; EnvaraPFFilterResult result; fixture.context = &context;
    if (is(&fixture,"readonly-complete")) { value.has_previous_revision = 1; value.expected_revision = 101; value.expected_writer_pid = fixture_pid; }
    if (!strncmp(argv[1], "invalid-", 8)) {
        if (is(&fixture, "invalid-run")) value.run_id[0] = 'X';
        if (is(&fixture, "invalid-realm")) value.realms[0].realm_id[14] = '5';
        if (is(&fixture, "invalid-gid")) value.realms[0].gid = 501;
        if (is(&fixture, "invalid-interface")) strcpy(value.realms[0].utun, "en0");
        if (is(&fixture, "invalid-route")) value.realms[0].route_ipv4[0] = 127;
        if (is(&fixture, "invalid-count")) value.realm_count = 3;
        if (is(&fixture, "invalid-duplicate-gid")) { add_second(&value); value.realms[1].gid = value.realms[0].gid; }
        if (is(&fixture, "invalid-duplicate-interface")) { add_second(&value); strcpy(value.realms[1].utun,value.realms[0].utun); }
        if (is(&fixture, "invalid-duplicate-ip")) { add_second(&value); memcpy(value.realms[1].route_ipv4,value.realms[0].route_ipv4,4); }
        if (is(&fixture, "invalid-boolean")) value.realms[0].routed = 2;
        if (is(&fixture, "invalid-receipt")) value.has_previous_revision = 2;
        assert(!EnvaraPFFilterInit(&context,123,&fixture,mock_ioctl,guarded,&value)); assert(!fixture.mutations && !fixture.reads); return 0;
    }
    assert(EnvaraPFFilterInit(&context, 123, &fixture, mock_ioctl, guarded, &value));
    if (is(&fixture, "verify-no-receipt")) {
        assert(!EnvaraPFFilterVerify(&context,ENVARA_PF_FILTER_ROUTED,&result)); assert(result.read_only && !fixture.reads && !fixture.mutations); no_replay(&context,&fixture); return 0;
    }
    if (!strncmp(argv[1], "guard-", 6) && !is(&fixture, "guard-reenter")) {
        if (is(&fixture, "guard-initial")) fixture.fail_guard = ENVARA_PF_FILTER_GUARD_INITIAL;
        if (is(&fixture, "guard-begin")) fixture.fail_guard = ENVARA_PF_FILTER_GUARD_BEGIN;
        if (is(&fixture, "guard-pool")) fixture.fail_guard = ENVARA_PF_FILTER_GUARD_BEGIN_ADDRS;
        if (is(&fixture, "guard-address")) fixture.fail_guard = ENVARA_PF_FILTER_GUARD_ADD_ADDR;
        if (is(&fixture, "guard-rule")) fixture.fail_guard = ENVARA_PF_FILTER_GUARD_ADD_RULE;
        if (is(&fixture, "guard-commit")) fixture.fail_guard = ENVARA_PF_FILTER_GUARD_COMMIT;
        if (is(&fixture, "guard-verify")) fixture.fail_guard = ENVARA_PF_FILTER_GUARD_VERIFY;
        if (is(&fixture, "guard-rollback")) { fixture.scenario = "rule-error"; fixture.fail_guard = ENVARA_PF_FILTER_GUARD_ROLLBACK; }
    }
    if (is(&fixture, "rollback-error")) fixture.fail_guard = ENVARA_PF_FILTER_GUARD_COMMIT;
    int success = is(&fixture,"success") || is(&fixture,"zero-ticket") || is(&fixture,"readonly-before") ||
        is(&fixture,"readonly-complete") || !strncmp(argv[1],"prior-",6);
    if (is(&fixture,"readonly-before")) {
        assert(EnvaraPFFilterVerify(&context,ENVARA_PF_FILTER_EMPTY,&result)); assert(result.verified && result.read_only && !fixture.mutations);
    }
    int okay = EnvaraPFFilterApply(&context,ENVARA_PF_FILTER_ROUTED,&result);
    if (!success) {
        assert(!okay && !result.verified);
        if (result.begun) assert(result.uncertain);
        if (!result.ticket_known || result.committed) assert(!result.rollback_attempted && !fixture.rollbacks);
        else if (fixture.fail_guard == ENVARA_PF_FILTER_GUARD_ROLLBACK) assert(!result.rollback_attempted);
        else assert(result.rollback_attempted && fixture.rollbacks == 1);
        if (is(&fixture,"commit-lost")) assert(!result.committed && result.rollback_acknowledged && fixture.active_count == 28);
        no_replay(&context,&fixture); return 0;
    }
    assert(okay && result.verified && !result.uncertain && result.actual_count == 28 && result.rules_added == 28 && result.pools_verified == 28);
    assert(fixture.resets == 28 && fixture.adds == 28 && fixture.addrs == 10 && fixture.commits == 1 && !fixture.rollbacks);
    if (is(&fixture,"readonly-complete")) {
        int before = fixture.mutations;
        assert(EnvaraPFFilterVerify(&context,ENVARA_PF_FILTER_ROUTED,&result));
        assert(result.verified && result.read_only && !result.uncertain && fixture.mutations == before);
        no_replay(&context,&fixture);
        assert(EnvaraPFFilterVerify(&context,ENVARA_PF_FILTER_ROUTED,&result));
        assert(result.verified && result.read_only && result.uncertain && fixture.mutations == before);
        no_replay(&context,&fixture); return 0;
    }
    if (!strncmp(argv[1],"prior-",6)) {
        uint32_t committed_pid = fixture_pid; fixture_pid++;
        EnvaraPFFilterConfig prior = config(); prior.has_previous_revision = 1; prior.expected_revision = result.ticket; prior.expected_writer_pid = committed_pid;
        if (is(&fixture,"prior-writer")) prior.expected_writer_pid++;
        if (is(&fixture,"prior-revision")) prior.expected_revision++;
        EnvaraPFFilterContext reader = {0}; assert(EnvaraPFFilterInit(&reader,123,&fixture,mock_ioctl,guarded,&prior));
        fixture.context = &reader; int before = fixture.mutations;
        int verified = EnvaraPFFilterVerify(&reader,ENVARA_PF_FILTER_ROUTED,&result);
        assert(fixture.mutations == before && result.read_only);
        assert(verified == is(&fixture,"prior-good"));
        if (!verified) no_replay(&reader,&fixture);
        fixture.context = &context; fixture_pid = committed_pid;
    }
    no_replay(&context,&fixture);
    assert(!strcmp(EnvaraPFFilterReasonName(ENVARA_PF_FILTER_OK),"okay"));
    assert(!strcmp(EnvaraPFFilterReasonName((EnvaraPFFilterReason)999),"invalid-reason")); return 0;
}
`;

test('inert generated filter transactions and canonical fixture labels', { skip: process.platform !== 'darwin' }, async t => {
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-filter-transaction-test-')));
  try {
    const input = path.join(directory, 'fixture.c');
    const binary = path.join(directory, 'fixture');
    await writeFile(input, harness.replace('FILTER_SOURCE', JSON.stringify(source)));
    await execute('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', input, '-o', binary],
      { timeout: 30000, maxBuffer: 1024 * 1024 });
    const cases = ['success', 'zero-ticket', 'readonly-before', 'readonly-complete', 'prior-good', 'prior-writer', 'prior-revision', 'verify-no-receipt',
      'invalid-run', 'invalid-realm', 'invalid-gid', 'invalid-interface', 'invalid-route', 'invalid-count', 'invalid-duplicate-gid',
      'invalid-duplicate-interface', 'invalid-duplicate-ip', 'invalid-boolean', 'invalid-receipt', 'guard-initial', 'guard-begin',
      'guard-reenter', 'ioctl-reenter', 'guard-pool', 'guard-address', 'guard-rule', 'guard-commit', 'guard-verify', 'guard-rollback',
      'begin-error', 'begin-anchor', 'begin-class', 'begin-array', 'pool-error', 'pool-reply', 'address-error', 'address-reply',
      'rule-error', 'rule-reply', 'rollback-error', 'commit-lost', 'commit-reply', 'verify-error', 'verify-count', 'verify-ticket',
      'verify-race', 'verify-state', 'verify-source-node', 'verify-opaque', 'verify-skip', 'verify-skip-upper', 'verify-redaction-only', 'verify-owner',
      'verify-label', 'verify-writer', 'verify-uid', 'verify-gid', 'verify-state-policy', 'verify-rule-index', 'verify-rt1',
      'verify-pool-opaque', 'verify-pool-count', 'verify-pool-interface', 'verify-pool-ip', 'verify-pool-mask', 'verify-pool-pointer'];
    for (const scenario of cases) await t.test(scenario, () => execute(binary, [scenario], { timeout: 10000 }));
    await t.test('expanded target ports retain the existing JavaScript grouped labels and semantic scope', async () => {
      const generated = JSON.parse((await execute(binary, ['dump-routed'])).stdout);
      assert.equal(generated.count, 28);
      const base = `envara_${digest(`${runId}|${realmId}`).slice(0, 24)}_`;
      assert.deepEqual(generated.rows.slice(0, 4).map(row => row.label),
        ['loopback', 'loopback', 'ipv6', 'ipv6'].map(suffix => base + suffix));
      for (const protocol of ['tcp', 'udp']) {
        for (const [host, ports] of [['1.1.1.1', [53]], ['198.51.100.42', [44441, 44442, 44443, 44444]]]) {
          const expression = ports.length === 1 ? '53' : '{ 44441, 44442, 44443, 44444 }';
          const suffix = digest(`${realmId}:${host}:${expression}:${protocol}`).slice(0, 12);
          const proto = protocol === 'tcp' ? 6 : 17;
          const inbound = generated.rows.filter(row => row.label === `${base}in_${suffix}`);
          const outbound = generated.rows.filter(row => row.label === `${base}out_${suffix}`);
          assert.deepEqual(inbound.map(row => row.srcPort), ports);
          assert.deepEqual(outbound.map(row => row.dstPort), ports);
          assert.ok(inbound.every(row => row.proto === proto && row.direction === 1 && row.interface === 'utun911' && row.gidOp === 0 && row.route === 0));
          assert.ok(outbound.every(row => row.proto === proto && row.direction === 2 && row.interface === 'lo0' && row.ifnot === 1 && row.gid === 7111 && row.gidOp === 2 && row.route === 2 && row.pool === 'utun911'));
        }
      }
      assert.ok(generated.rows.every(row => row.state === 0));
      assert.equal(JSON.parse((await execute(binary, ['dump-empty'])).stdout).count, 0);
      assert.equal(JSON.parse((await execute(binary, ['dump-deny'])).stdout).count, 6);
      assert.equal(JSON.parse((await execute(binary, ['dump-udp-block'])).stdout).count, 19);
      assert.equal(JSON.parse((await execute(binary, ['dump-blocked-realm'])).stdout).count, 6);
      const two = JSON.parse((await execute(binary, ['dump-two'])).stdout);
      const sorted = JSON.parse((await execute(binary, ['dump-sorted'])).stdout);
      assert.equal(two.count, 56); assert.deepEqual(sorted, two);
    });
  } finally { await rm(directory, { recursive: true, force: true }); }
});
