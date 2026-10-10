import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, realpath, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const source = fileURLToPath(new URL('../native/macos-pf-routing/pf-single-filter-transaction.c', import.meta.url));
const header = fileURLToPath(new URL('../native/macos-pf-routing/pf-single-filter-transaction.h', import.meta.url));

test('single-filter primitive is separately scoped, with no device, authorization, state or runtime operations', async () => {
  const [implementation, declaration] = await Promise.all([readFile(source, 'utf8'), readFile(header, 'utf8')]);
  assert.match(declaration, /a85314b8-5b24-4784-95ec-47b739c2e841/);
  assert.match(implementation, /rs_num = 1/);
  assert.match(implementation, /1032/);
  assert.match(implementation, /transaction envelope size/);
  assert.doesNotMatch(implementation, /\b(?:open|fork|execve|system|posix_spawn|setuid|kill)\s*\(/);
  assert.doesNotMatch(implementation, /DIOC(?:START|STOP|KILLSTATES|CLRSTATES|ADDSTATE|ADDADDR)\s*\(/);
  assert.match(declaration, /kernel-blocked ioctl has no hard wall-clock deadline/);
  assert.match(declaration, /foreign PF pool transaction/);
});

const harness = String.raw`
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
static int forbidden_real_ioctl(int fd, unsigned long request, ...) {
    (void)fd; (void)request; abort();
}
#define ioctl forbidden_real_ioctl
#include SINGLE_SOURCE
#undef ioctl
typedef struct {
    const char *scenario;
    int guard_stage, last_guard, calls, begins, pools, adds, commits, rollbacks, reads, rows;
    uint32_t next_ticket, active_ticket, pending_ticket, pool_ticket, active_count;
    EnvaraPFHookRule pending_rule, active_rule;
    EnvaraSingleFilterContext *reenter_context;
} Fixture;
static int is(Fixture *fixture, const char *scenario) { return !strcmp(fixture->scenario, scenario); }
static int guard(void *opaque, int fd, EnvaraSingleFilterStage stage) {
    Fixture *fixture = opaque; assert(fd == 123); fixture->last_guard = (int)stage;
    if (is(fixture, "guard-reenter") && fixture->reenter_context && stage == ENVARA_SINGLE_FILTER_GUARD_INITIAL) {
        EnvaraSingleFilterResult nested;
        assert(!EnvaraSingleFilterApply(fixture->reenter_context, ENVARA_SINGLE_FILTER_DENY, &nested));
        assert(nested.reason == ENVARA_SINGLE_FILTER_INVALID_SEQUENCE);
    }
    return (int)stage == fixture->guard_stage ? 0 : 1;
}
static void require_guard(Fixture *fixture, EnvaraSingleFilterStage stage) {
    assert(fixture->last_guard == (int)stage); fixture->last_guard = -1;
}
static void assert_transaction(SingleFilterTransaction *transaction, uint32_t ticket) {
    assert(transaction->size == 1 && transaction->esize == 1032 && transaction->array);
    assert(transaction->array->rs_num == 1 && transaction->array->ticket == ticket);
    assert(!strcmp(transaction->array->anchor, ENVARA_SINGLE_FILTER_ANCHOR));
    assert(!memchr(transaction->array->anchor + sizeof(ENVARA_SINGLE_FILTER_ANCHOR), 1,
        sizeof(transaction->array->anchor) - sizeof(ENVARA_SINGLE_FILTER_ANCHOR)));
}
static void assert_deny(const EnvaraPFHookRequest *request, Fixture *fixture) {
    assert(request->action == 0 && request->nr == 0 && request->ticket == fixture->pending_ticket);
    assert(request->pool_ticket == fixture->pool_ticket);
    assert(!strcmp(request->anchor, ENVARA_SINGLE_FILTER_ANCHOR) && !request->anchor_call[0]);
    const EnvaraPFHookRule *rule = &request->rule;
    assert(!strcmp(rule->owner, ENVARA_SINGLE_FILTER_ANCHOR) && !strcmp(rule->label, ENVARA_SINGLE_FILTER_LABEL));
    assert(rule->action == 1 && rule->direction == 2 && rule->quick == 1 && rule->af == 2 && rule->proto == 6);
    assert(rule->keep_state == 0 && rule->rt == 0 && rule->uid_op == 0 && rule->gid_op == 0 && rule->ticket == 0);
    unsigned char wanted_destination[64] = {0};
    wanted_destination[0] = 198; wanted_destination[1] = 51; wanted_destination[2] = 100; wanted_destination[3] = 42;
    memset(wanted_destination + 16, 255, 4);
    /* 44441 == 0xad99, in network order; equality op is at byte 52. */
    wanted_destination[48] = 0xad; wanted_destination[49] = 0x99;
    wanted_destination[50] = 0xad; wanted_destination[51] = 0x99; wanted_destination[52] = 2;
    assert(!memcmp(rule->dst, wanted_destination, sizeof(wanted_destination)));
    unsigned char zero_source[64] = {0}; assert(!memcmp(rule->src, zero_source, sizeof(zero_source)));
    const unsigned char *bytes = (const unsigned char *)rule;
    for (size_t i = 272; i < 648; i++) assert(bytes[i] == 0);
    for (size_t i = 764; i < 948; i++) assert(bytes[i] == 0);
    for (size_t i = 952; i < 1004; i++) assert(bytes[i] == 0);
}
static void make_readback(Fixture *fixture, EnvaraPFHookRule *rule) {
    *rule = fixture->active_rule;
    unsigned char *bytes = (unsigned char *)rule;
    bytes[642] = 2;
    uint32_t uid = (uint32_t)geteuid(), pid = (uint32_t)getpid();
    memcpy(bytes + 956, &uid, 4); memcpy(bytes + 960, &pid, 4);
    for (size_t i = 0; i < 64; i += 8) memset(rule->skip + i, 255, 4);
    if (is(fixture, "verify-source")) rule->src[0] = 1;
    if (is(fixture, "verify-destination")) rule->dst[3] = 43;
    if (is(fixture, "verify-port")) rule->dst[49] = 0x98;
    if (is(fixture, "verify-state")) bytes[904] = 1;
    if (is(fixture, "verify-source-node")) bytes[912] = 1;
    if (is(fixture, "verify-opaque")) bytes[810] = 1;
    if (is(fixture, "verify-counter")) rule->packets[0] = 1;
    if (is(fixture, "verify-ticket-inner")) rule->ticket = 4;
    if (is(fixture, "verify-owner")) rule->owner[0] = 'x';
    if (is(fixture, "verify-label")) rule->label[0] = 'x';
    if (is(fixture, "verify-route")) rule->rt = 4;
    if (is(fixture, "verify-skip")) rule->skip[7] = 1;
    if (is(fixture, "verify-pid")) bytes[960] ^= 1;
    if (is(fixture, "verify-rpool")) bytes[642] = 0;
    if (is(fixture, "verify-keep-state")) rule->keep_state = 1;
}
static int mock_ioctl(void *opaque, int fd, unsigned long request, void *argument) {
    Fixture *fixture = opaque; assert(fd == 123); fixture->calls++;
    if (request == SINGLE_BEGIN) {
        require_guard(fixture, ENVARA_SINGLE_FILTER_GUARD_BEGIN); fixture->begins++;
        SingleFilterTransaction *transaction = argument; assert_transaction(transaction, 0);
        fixture->pending_ticket = is(fixture, "begin-zero") ? 0U : ++fixture->next_ticket;
        fixture->pending_rule = (EnvaraPFHookRule){0};
        transaction->array->ticket = fixture->pending_ticket;
        if (is(fixture, "begin-error") || is(fixture, "begin-error-zero")) {
            if (is(fixture, "begin-error-zero")) transaction->array->ticket = 0;
            errno = EINTR; return -1;
        }
        if (is(fixture, "begin-anchor")) transaction->array->anchor[0] = 'x';
        if (is(fixture, "begin-class")) transaction->array->rs_num = 7;
        if (is(fixture, "begin-size")) transaction->size = 2;
        if (is(fixture, "begin-array")) transaction->array = NULL;
        return 0;
    }
    if (request == SINGLE_BEGIN_ADDRS) {
        require_guard(fixture, ENVARA_SINGLE_FILTER_GUARD_BEGIN_ADDRS); fixture->pools++;
        SingleFilterPoolRequest *pool = argument, zero = {0}; assert(!memcmp(pool, &zero, sizeof(zero)));
        pool->ticket = fixture->pool_ticket = is(fixture, "pool-zero") ? 0U : 71U;
        if (is(fixture, "pool-error")) { errno = EIO; return -1; }
        if (is(fixture, "pool-address")) pool->addr.bytes[0] = 1;
        return 0;
    }
    if (request == SINGLE_ADD) {
        require_guard(fixture, ENVARA_SINGLE_FILTER_GUARD_ADD); fixture->adds++;
        EnvaraPFHookRequest *rule = argument; assert_deny(rule, fixture); fixture->pending_rule = rule->rule;
        if (is(fixture, "add-error")) { errno = EBUSY; return -1; }
        if (is(fixture, "add-reply")) rule->rule.keep_state = 1;
        return 0;
    }
    if (request == SINGLE_COMMIT) {
        require_guard(fixture, ENVARA_SINGLE_FILTER_GUARD_COMMIT); fixture->commits++;
        assert_transaction(argument, fixture->pending_ticket);
        fixture->active_ticket = fixture->pending_ticket; fixture->active_rule = fixture->pending_rule;
        fixture->active_count = fixture->pending_rule.action ? 1U : 0U;
        if (is(fixture, "commit-lost-reply")) { errno = EINTR; return -1; }
        if (is(fixture, "commit-reply")) ((SingleFilterTransaction *)argument)->array->ticket++;
        return 0;
    }
    if (request == SINGLE_ROLLBACK) {
        require_guard(fixture, ENVARA_SINGLE_FILTER_GUARD_ROLLBACK); fixture->rollbacks++;
        assert_transaction(argument, fixture->pending_ticket);
        if (is(fixture, "rollback-error")) { errno = EIO; return -1; }
        return 0; /* also possible when COMMIT already happened */
    }
    if (request == ENVARA_PF_HOOK_GET_RULES) {
        require_guard(fixture, ENVARA_SINGLE_FILTER_GUARD_VERIFY); fixture->reads++;
        EnvaraPFHookRequest *rule = argument;
        assert(rule->action == 0 && rule->rule.action == 0 && !strcmp(rule->anchor, ENVARA_SINGLE_FILTER_ANCHOR));
        rule->nr = fixture->active_count; rule->ticket = fixture->active_ticket;
        if (is(fixture, "verify-error")) { errno = EIO; return -1; }
        if (is(fixture, "verify-count")) rule->nr++;
        if (is(fixture, "verify-ticket")) rule->ticket++;
        if (is(fixture, "verify-envelope")) rule->anchor_call[0] = 'x';
        if (is(fixture, "verify-race") && fixture->reads % 2 == 0) rule->ticket++;
        if (is(fixture, "ioctl-reenter") && fixture->rows == 1 && fixture->reads == 4) {
            EnvaraSingleFilterResult nested;
            assert(!EnvaraSingleFilterApply(fixture->reenter_context, ENVARA_SINGLE_FILTER_DENY, &nested));
            assert(nested.reason == ENVARA_SINGLE_FILTER_INVALID_SEQUENCE);
        }
        return 0;
    }
    if (request == ENVARA_PF_HOOK_GET_RULE) {
        require_guard(fixture, ENVARA_SINGLE_FILTER_GUARD_VERIFY); fixture->rows++;
        EnvaraPFHookRequest *rule = argument;
        assert(rule->action == 0 && rule->nr == 0 && rule->ticket == fixture->active_ticket && fixture->active_count == 1);
        assert(!strcmp(rule->anchor, ENVARA_SINGLE_FILTER_ANCHOR)); make_readback(fixture, &rule->rule);
        return 0;
    }
    abort(); /* no table/state/start/stop/address/foreign call is permitted */
}
static int poisoned(EnvaraSingleFilterContext *context, Fixture *fixture) {
    int before = fixture->calls; EnvaraSingleFilterResult repeated;
    assert(!EnvaraSingleFilterApply(context, ENVARA_SINGLE_FILTER_EMPTY, &repeated));
    assert(!EnvaraSingleFilterApply(context, ENVARA_SINGLE_FILTER_DENY, &repeated));
    assert(fixture->calls == before && !repeated.begun && !repeated.rollback_attempted);
    assert(!EnvaraSingleFilterInit(context, 123, fixture, mock_ioctl, guard));
    return 0;
}
int main(int argc, char **argv) {
    assert(argc == 2); Fixture fixture = {.scenario=argv[1], .guard_stage=-1, .last_guard=-1, .next_ticket=100};
    EnvaraSingleFilterContext context = {0}; EnvaraSingleFilterResult result;
    assert(!EnvaraSingleFilterInit(NULL, 123, &fixture, mock_ioctl, guard));
    assert(!EnvaraSingleFilterInit(&context, -1, &fixture, mock_ioctl, guard));
    assert(!EnvaraSingleFilterInit(&context, 123, &fixture, mock_ioctl, NULL));
    assert(EnvaraSingleFilterInit(&context, 123, &fixture, mock_ioctl, guard));
    if (is(&fixture, "guard-reenter")) {
        fixture.reenter_context = &context;
        assert(!EnvaraSingleFilterApply(&context, ENVARA_SINGLE_FILTER_EMPTY, &result));
        assert(result.reason == ENVARA_SINGLE_FILTER_GUARD_REJECTED && fixture.calls == 0);
        fixture.reenter_context = NULL; return poisoned(&context, &fixture);
    }
    if (is(&fixture, "invalid-sequence")) {
        assert(!EnvaraSingleFilterApply(&context, ENVARA_SINGLE_FILTER_DENY, &result));
        assert(fixture.calls == 0 && result.reason == ENVARA_SINGLE_FILTER_INVALID_SEQUENCE); return poisoned(&context, &fixture);
    }
    if (is(&fixture, "guard-initial")) fixture.guard_stage = ENVARA_SINGLE_FILTER_GUARD_INITIAL;
    if (is(&fixture, "guard-begin")) fixture.guard_stage = ENVARA_SINGLE_FILTER_GUARD_BEGIN;
    int first_failure = (!strncmp(argv[1], "begin-", 6) && !is(&fixture, "begin-zero")) ||
        is(&fixture, "guard-initial") || is(&fixture, "guard-begin");
    if (first_failure) {
        assert(!EnvaraSingleFilterApply(&context, ENVARA_SINGLE_FILTER_EMPTY, &result));
        assert(!result.ticket_known && !fixture.rollbacks && !fixture.commits && !fixture.pools);
        assert(result.begun == (fixture.begins != 0));
        assert(result.uncertain == (fixture.begins != 0)); return poisoned(&context, &fixture);
    }
    const char *saved = fixture.scenario; fixture.scenario = "initial-good";
    assert(EnvaraSingleFilterApply(&context, ENVARA_SINGLE_FILTER_EMPTY, &result));
    assert(result.verified && !result.uncertain && result.actual_count == 0 && !fixture.pools && !fixture.adds);
    fixture.scenario = saved;
    if (is(&fixture, "ioctl-reenter")) fixture.reenter_context = &context;
    if (is(&fixture, "guard-pool")) fixture.guard_stage = ENVARA_SINGLE_FILTER_GUARD_BEGIN_ADDRS;
    if (is(&fixture, "guard-add")) fixture.guard_stage = ENVARA_SINGLE_FILTER_GUARD_ADD;
    if (is(&fixture, "guard-commit")) fixture.guard_stage = ENVARA_SINGLE_FILTER_GUARD_COMMIT;
    if (is(&fixture, "guard-verify")) fixture.guard_stage = ENVARA_SINGLE_FILTER_GUARD_VERIFY;
    if (is(&fixture, "guard-rollback")) { fixture.scenario = "add-error"; fixture.guard_stage = ENVARA_SINGLE_FILTER_GUARD_ROLLBACK; }
    if (is(&fixture, "rollback-error")) fixture.guard_stage = ENVARA_SINGLE_FILTER_GUARD_COMMIT;
    if (!is(&fixture, "cycle") && !is(&fixture, "begin-zero") && !is(&fixture, "pool-zero")) {
        assert(!EnvaraSingleFilterApply(&context, ENVARA_SINGLE_FILTER_DENY, &result));
        assert(result.ticket_known && result.ticket == fixture.pending_ticket && result.uncertain && !result.verified);
        if (result.committed) assert(!result.rollback_attempted && !fixture.rollbacks);
        else if (is(&fixture, "add-error") && fixture.guard_stage == ENVARA_SINGLE_FILTER_GUARD_ROLLBACK) assert(!result.rollback_attempted);
        else assert(result.rollback_attempted && fixture.rollbacks == 1);
        if (is(&fixture, "commit-lost-reply")) {
            assert(result.commit_attempted && !result.committed && result.rollback_acknowledged && fixture.active_count == 1);
            assert(result.os_error == EINTR && result.reason == ENVARA_SINGLE_FILTER_COMMIT_FAILED);
        }
        return poisoned(&context, &fixture);
    }
    assert(EnvaraSingleFilterApply(&context, ENVARA_SINGLE_FILTER_DENY, &result));
    assert(result.pool_attempted && result.pool_known && result.add_attempted && result.verified && result.actual_count == 1);
    assert(EnvaraSingleFilterApply(&context, ENVARA_SINGLE_FILTER_EMPTY, &result));
    assert(result.actual_count == 0 && result.verified && !result.pool_attempted && !result.add_attempted);
    assert(fixture.begins == 3 && fixture.commits == 3 && fixture.pools == 1 && fixture.adds == 1);
    assert(fixture.reads == 6 && fixture.rows == 1 && fixture.rollbacks == 0);
    assert(!strcmp(EnvaraSingleFilterReasonName(ENVARA_SINGLE_FILTER_OK), "okay"));
    assert(!strcmp(EnvaraSingleFilterReasonName((EnvaraSingleFilterReason)999), "invalid-reason"));
    return poisoned(&context, &fixture);
}
`;

test('mocked single FILTER transaction preserves tickets, narrow scope and strict failure boundaries',
  { skip: process.platform !== 'darwin' }, async t => {
    const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-single-filter-test-')));
    try {
      const input = path.join(directory, 'fixture.c');
      const binary = path.join(directory, 'fixture');
      await writeFile(input, harness.replace('SINGLE_SOURCE', JSON.stringify(source)));
      await execute('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', input, '-o', binary],
        { timeout: 30000, maxBuffer: 1024 * 1024 });
      const cases = ['cycle', 'invalid-sequence', 'guard-reenter', 'ioctl-reenter', 'guard-initial', 'guard-begin', 'begin-error', 'begin-error-zero', 'begin-zero',
        'begin-anchor', 'begin-class', 'begin-size', 'begin-array', 'guard-pool', 'guard-add', 'guard-commit',
        'guard-verify', 'guard-rollback', 'pool-error', 'pool-zero', 'pool-address', 'add-error', 'add-reply',
        'rollback-error', 'commit-lost-reply', 'commit-reply', 'verify-error', 'verify-count', 'verify-ticket',
        'verify-envelope', 'verify-race', 'verify-source', 'verify-destination', 'verify-port', 'verify-state',
        'verify-source-node', 'verify-opaque', 'verify-counter', 'verify-ticket-inner', 'verify-owner',
        'verify-label', 'verify-route', 'verify-skip', 'verify-pid', 'verify-rpool', 'verify-keep-state'];
      for (const scenario of cases) await t.test(scenario, () => execute(binary, [scenario], { timeout: 10000 }));
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
