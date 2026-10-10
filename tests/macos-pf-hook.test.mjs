import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, realpath, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const source = fileURLToPath(new URL('../native/macos-pf-routing/pf-hook.c', import.meta.url));
const ledgerSource = fileURLToPath(new URL('../native/macos-pf-routing/pf-run-ledger.c', import.meta.url));
const onlyMac = { skip: process.platform !== 'darwin' };
async function native(callback, harness) {
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-pf-hook-test-')));
  try {
    const input = harness ? path.join(directory, 'fixture.c') : source;
    if (harness) await writeFile(input, harness.replace('HOOK_SOURCE', JSON.stringify(source)));
    const binary = path.join(directory, 'hook');
    await execute('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      ...(harness ? [] : ['-DENVARA_PF_HOOK_STANDALONE']), input, ledgerSource, '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
    return await callback(binary);
  } finally { await rm(directory, { recursive: true, force: true }); }
}
async function output(binary, args) {
  try { return { code: 0, value: JSON.parse((await execute(binary, args, { timeout: 15000 })).stdout) }; }
  catch (error) { assert.equal(typeof error.code, 'number'); return { code: error.code, value: JSON.parse(error.stdout) }; }
}
test('native status is inert without the authenticated root controller and unknown operations are refused', onlyMac, async () => {
  await native(async binary => {
    for (const args of [[], ['hook-status', 'untrusted'], ['generic-delete'], ['--request-canary']]) {
      const result = await output(binary, args);
      assert.equal(result.code, 1); assert.equal(result.value.reason, 'INVALID_FIXED_OPERATION');
    }
    if (process.getuid() !== 0) {
      const status = await output(binary, ['hook-status']);
      assert.equal(status.code, 0); assert.equal(status.value.readOnly, true);
      assert.equal(status.value.canCreateOwnedHook, false); assert.equal(status.value.ownedRootHookVerified, false);
      assert.equal(status.value.productionReady, false); assert.ok(Object.values(status.value.gates).every(gate => gate === false));
      for (const operation of ['insert-owned-root-hook', 'delete-owned-root-hook']) {
        const result = await output(binary, [operation]);
        assert.equal(result.code, 1); assert.equal(result.value.reason, 'AUTHENTICATED_ROOT_CONTROLLER_REQUIRED');
        assert.equal(result.value.lease, null);
      }
    }
  });
});
test('native bounded JSON parser binds the lease to run and nonce and rejects extra, duplicate or zero-ticket input', onlyMac, async () => {
  const harness = `
#include HOOK_SOURCE
static HookLease fixture_lease(void) {
    HookLease lease = {0}; strcpy(lease.schema,LEASE_SCHEMA); strcpy(lease.runId,"00112233-4455-4677-8899-aabbccddeeff");
    strcpy(lease.leaseId,"11223344-5566-4788-99aa-bbccddeeff00"); if (!envara_pf_run_anchor(lease.runId,lease.anchor)) abort(); strcpy(lease.owner,lease.anchor);
    strcpy(lease.ticket,"18446744073709551615"); strcpy(lease.rootBeforeSHA256,ROOT_RULE_HASH); strcpy(lease.rootBeforeTextSHA256,ROOT_TEXT_HASH); lease_label(&lease,lease.label); return lease;
}
int main(void) {
    HookInput input;
    if (!parse_input("{\\\"runId\\\":\\\"00112233-4455-4677-8899-aabbccddeeff\\\"}","insert-owned-root-hook",&input)) return 1;
    if (parse_input("{\\\"runId\\\":\\\"00112233-4455-4677-8899-aabbccddeeff\\\",\\\"runId\\\":\\\"duplicate\\\"}","insert-owned-root-hook",&input)) return 2;
    if (parse_input("{\\\"anchor\\\":\\\"foreign\\\"}","hook-status",&input)) return 3;
    if (parse_input("{} {}","hook-status",&input)) return 4;
    if (parse_input("{}","delete-owned-root-hook",&input)) return 5;
    if (parse_input("{\\\"runId\\\":\\\"invalid\\\\u0000\\\"}","insert-owned-root-hook",&input)) return 6;
    HookLease lease = fixture_lease(); if (!lease_valid(&lease)) return 7;
    lease.runId[0] = 'f'; if (lease_valid(&lease)) return 8;
    lease = fixture_lease(); strcpy(lease.ticket,"0"); if (lease_valid(&lease)) return 9;
    lease = fixture_lease(); strcpy(lease.ticket,"18446744073709551616"); if (lease_valid(&lease)) return 10;
    lease = fixture_lease(); strcpy(lease.ticket,"+1"); if (lease_valid(&lease)) return 11;
    lease = fixture_lease(); strcpy(lease.anchor,"foreign"); if (lease_valid(&lease)) return 12;
    char json[2048]; lease = fixture_lease();
    snprintf(json,sizeof(json),"{\\\"lease\\\":{\\\"schema\\\":\\\"%s\\\",\\\"runId\\\":\\\"%s\\\",\\\"leaseId\\\":\\\"%s\\\",\\\"anchor\\\":\\\"%s\\\",\\\"owner\\\":\\\"%s\\\",\\\"label\\\":\\\"%s\\\",\\\"ticket\\\":\\\"%s\\\",\\\"rootBeforeSHA256\\\":\\\"%s\\\",\\\"rootBeforeTextSHA256\\\":\\\"%s\\\"}}",lease.schema,lease.runId,lease.leaseId,lease.anchor,lease.owner,lease.label,lease.ticket,lease.rootBeforeSHA256,lease.rootBeforeTextSHA256);
    if (!parse_input(json,"delete-owned-root-hook",&input) || strcmp(input.lease.ticket,lease.ticket)) return 13;
    if (!parse_input("{}","hook-status",&input) || input.has_run || input.has_lease) return 14;
    if (!parse_input("{\\\"runId\\\":\\\"00112233-4455-4677-8899-aabbccddeeff\\\"}","hook-status",&input) || !input.has_run) return 15;
    const char *invalid[] = {"00112233-4455-5677-8899-aabbccddeeff","00112233-4455-4677-7899-aabbccddeeff","00112233-4455-4677-8899-AABBCCDDEEFF"};
    for (size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) if (uuid_valid(invalid[i])) return 16;
    lease=fixture_lease(); strcpy(lease.schema,"envara.macos-pf-owned-root-hook-lease/v1"); if (lease_valid(&lease)) return 17;
    lease=fixture_lease(); strcpy(lease.anchor,"io.envara.pf.root.v1"); strcpy(lease.owner,lease.anchor); if (lease_valid(&lease)) return 18;
    lease=fixture_lease(); strcpy(lease.owner,"io.envara.pf.run.11223344-5566-4788-99aa-bbccddeeff00"); if (lease_valid(&lease)) return 19;
    return 0;
}`;
  await native(binary => execute(binary, [], { timeout: 15000 }), harness);
});
test('native ioctl boundary never performs zero-ticket or name-only deletion and requires exact receipt readback', onlyMac, async () => {
  const harness = `
#include <stdarg.h>
#include <sys/ioctl.h>
static unsigned observed;
static int inert_ioctl(int fd,unsigned long op,...) { (void)fd; (void)op; observed++; return 0; }
#define ioctl inert_ioctl
#include HOOK_SOURCE
#undef ioctl
int main(void) {
    HookLease lease = {0}; strcpy(lease.schema,LEASE_SCHEMA); strcpy(lease.runId,"00112233-4455-4677-8899-aabbccddeeff");
    strcpy(lease.leaseId,"11223344-5566-4788-99aa-bbccddeeff00"); if (!envara_pf_run_anchor(lease.runId,lease.anchor)) abort(); strcpy(lease.owner,lease.anchor);
    strcpy(lease.rootBeforeSHA256,ROOT_RULE_HASH); strcpy(lease.rootBeforeTextSHA256,ROOT_TEXT_HASH); lease_label(&lease,lease.label);
    int fd = open("/dev/null",O_RDWR|O_CLOEXEC); if (fd < 0) return 1;
    EnvaraPFHookRequest request = new_rule(&lease);
    if (write_rule(fd,ENVARA_PF_HOOK_INSERT,&request,&lease) || observed != 1) return 2;
    if (write_rule(fd,ENVARA_PF_HOOK_DELETE,&request,&lease) != -1 || observed != 1) return 3;
    strcpy(lease.ticket,"112233445566778899"); request.rule.ticket = UINT64_C(112233445566778899);
    if (write_rule(fd,ENVARA_PF_HOOK_DELETE,&request,&lease) || observed != 2) return 4;
    request.rule.ticket++;
    if (write_rule(fd,ENVARA_PF_HOOK_DELETE,&request,&lease) != -1 || observed != 2) return 5;
    request.rule.ticket--; strcpy(request.rule.owner,"foreign");
    if (write_rule(fd,ENVARA_PF_HOOK_DELETE,&request,&lease) != -1 || observed != 2) return 6;
    request = new_rule(&lease); request.rule.ticket = UINT64_C(112233445566778899); memset(request.rule.label,'x',sizeof(request.rule.label));
    if (write_rule(fd,ENVARA_PF_HOOK_DELETE,&request,&lease) != -1 || observed != 2) return 7;
    request = new_rule(&lease); request.rule.ticket = UINT64_C(112233445566778899);
    if (write_rule(fd,1234,&request,&lease) != -1 || observed != 2) return 8;
    HookRoot root = {0}; root.count = 1; request.rule.anchor_relative = 1; root.rows[0] = request; EnvaraPFHookRequest found;
    if (!find_lease(&root,&lease,&found)) return 9;
    root.rows[0].rule.ticket++; if (find_lease(&root,&lease,&found)) return 10;
    root.rows[0].rule.ticket--; root.rows[0].rule.label[16] = 'f'; if (find_lease(&root,&lease,&found)) return 11;
    root.rows[0] = request; root.rows[0].rule.rt = 1;
    if (find_lease(&root,&lease,&found) || !find_identity(&root,&lease,&found)) return 12;
    root.rows[0] = request; root.rows[0].rule.anchor_wildcard = 1; if (find_lease(&root,&lease,&found)) return 13;
    root.rows[0] = request; root.rows[0].rule.rule_flag = 1; if (find_lease(&root,&lease,&found)) return 14;
    root.rows[0] = request; root.rows[0].rule.log = 1; if (find_lease(&root,&lease,&found)) return 15;
    strcpy(lease.anchor,"io.envara.pf.root.v1"); strcpy(lease.owner,lease.anchor); request=new_rule(&lease); request.rule.ticket=0;
    if (write_rule(fd,ENVARA_PF_HOOK_INSERT,&request,&lease)!=-1 || observed!=2) return 16;
    close(fd); return 0;
}`;
  await native(binary => execute(binary, [], { timeout: 15000 }), harness);
});
test('native fixed root-flat anchor normalization separates zeroed writes from relative-one readback and fixed-template deletion', onlyMac, async () => {
  const harness = `
#include <stdarg.h>
#include <sys/ioctl.h>
static int inert_normalizing_ioctl(int fd,unsigned long op,...);
#define ioctl inert_normalizing_ioctl
#include HOOK_SOURCE
#undef ioctl
static EnvaraPFHookRequest kernel_row;
static unsigned inserts,deletes;
static int inert_normalizing_ioctl(int fd,unsigned long op,...) {
    (void)fd; va_list args; va_start(args,op); EnvaraPFHookRequest *r = va_arg(args,EnvaraPFHookRequest *); va_end(args);
    if (op == ENVARA_PF_HOOK_INSERT) {
        if (r->rule.anchor_relative || r->rule.ticket) return -1;
        inserts++; kernel_row = *r;
        /* Fixed Apple pf_anchor_setup normalizes this root-flat no-slash call. */
        kernel_row.rule.anchor_relative = 1; kernel_row.rule.ticket = UINT64_C(112233445566778899);
        *r = kernel_row; return 0;
    }
    if (op == ENVARA_PF_HOOK_GET_RULES) { r->nr = r->anchor[0] ? 0 : 1; r->ticket = 77; return 0; }
    if (op == ENVARA_PF_HOOK_GET_RULE) { *r = kernel_row; r->ticket = 77; return 0; }
    if (op == ENVARA_PF_HOOK_DELETE) {
        /* The observed normalized rule must never be the deletion payload. */
        if (r->rule.anchor_relative || r->rule.ticket != kernel_row.rule.ticket || r->rule.anchor_wildcard || r->rule.rt ||
            strcmp(r->anchor_call,kernel_row.anchor_call) || strcmp(r->rule.label,kernel_row.rule.label) || strcmp(r->rule.owner,kernel_row.rule.owner)) return -1;
        deletes++; return 0;
    }
    return -1;
}
int main(void) {
    HookLease lease = {0}; strcpy(lease.schema,LEASE_SCHEMA); strcpy(lease.runId,"00112233-4455-4677-8899-aabbccddeeff");
    strcpy(lease.leaseId,"11223344-5566-4788-99aa-bbccddeeff00"); if (!envara_pf_run_anchor(lease.runId,lease.anchor)) abort(); strcpy(lease.owner,lease.anchor);
    strcpy(lease.rootBeforeSHA256,ROOT_RULE_HASH); strcpy(lease.rootBeforeTextSHA256,ROOT_TEXT_HASH); lease_label(&lease,lease.label);
    int pipefd[2]; if (pipe(pipefd)) return 1; int writable = open("/dev/null",O_RDWR|O_CLOEXEC); if (writable < 0) return 2;
    EnvaraPFHookRequest write = new_rule(&lease);
    if (!owned_write_template(&write,&lease) || owned_readback(&write,&lease)) return 3;
    if (write_rule(writable,ENVARA_PF_HOOK_INSERT,&write,&lease) || inserts != 1 || write.rule.anchor_relative != 1) return 4;
    snprintf(lease.ticket,sizeof(lease.ticket),"%llu",(unsigned long long)write.rule.ticket);
    HookRoot root; EnvaraPFHookRequest found;
    if (!lease_valid(&lease) || !read_root(pipefd[0],&root) || !find_lease(&root,&lease,&found) || owned_write_template(&found,&lease)) return 5;
    if (write_rule(writable,ENVARA_PF_HOOK_DELETE,&found,&lease) != -1 || deletes) return 6;
    EnvaraPFHookRequest normalized = kernel_row;
    kernel_row.rule.anchor_relative = 0; if (!read_root(pipefd[0],&root) || find_lease(&root,&lease,&found)) return 7;
    kernel_row.rule.anchor_relative = 2; if (!read_root(pipefd[0],&root) || find_lease(&root,&lease,&found)) return 8;
    kernel_row = normalized; kernel_row.rule.anchor_wildcard = 1;
    if (!read_root(pipefd[0],&root) || find_lease(&root,&lease,&found)) return 9;
    kernel_row = normalized; strcpy(kernel_row.anchor_call,"../io.envara.pf.root.v1");
    if (!read_root(pipefd[0],&root) || find_lease(&root,&lease,&found) || exact_remove(pipefd[0],writable,&lease) || deletes) return 10;
    kernel_row = normalized; strcpy(kernel_row.rule.owner,"foreign");
    if (!read_root(pipefd[0],&root) || find_lease(&root,&lease,&found) || exact_remove(pipefd[0],writable,&lease) || deletes) return 11;
    kernel_row = normalized;
    if (!exact_remove(pipefd[0],writable,&lease) || inserts != 1 || deletes != 1) return 12;
    close(pipefd[0]); close(pipefd[1]); close(writable); return 0;
}`;
  await native(binary => execute(binary, [], { timeout: 15000 }), harness);
});
test('native original semantic hash agrees with verified canary normalization and preserves original tickets and opaque fields', onlyMac, async () => {
  const harness = `
#include HOOK_SOURCE
int main(void) {
    HookRoot first = {0}, second; first.count = 7;
    for (uint32_t i = 0; i < 7; i++) { snprintf(first.rows[i].anchor_call,1024,"original-%u",i); first.rows[i].rule.nr = first.rows[i].nr = i; first.rows[i].rule.ticket = i + 10; }
    root_hash(&first,7); second = first; second.rows[0].ticket++; second.rows[0].rule.skip[0] = 1; second.rows[0].rule.evaluations = 4; second.rows[0].rule.packets[1] = 5; second.rows[0].rule.bytes[0] = 6;
    root_hash(&second,7); if (strcmp(first.canonical,second.canonical)) return 1;
    second.rows[0].rule.ticket++; root_hash(&second,7); if (!strcmp(first.canonical,second.canonical)) return 2;
    second = first; second.rows[0].rule.opaque272[0]++; root_hash(&second,7); if (!strcmp(first.canonical,second.canonical)) return 3;
    second = first; second.rows[0].rule.owner[0] = 'x'; root_hash(&second,7); if (!strcmp(first.canonical,second.canonical)) return 4;
    second = first; second.rows[0].rule.src[0] = 1; root_hash(&second,7); if (!strcmp(first.canonical,second.canonical)) return 5;
    if (!old_text_matches("anchor \\\"original-0\\\" all",&first.rows[0])) return 6;
    if (old_text_matches("pass out quick all",&first.rows[0])) return 7;
    return 0;
}`;
  await native(binary => execute(binary, [], { timeout: 15000 }), harness);
});
test('native preflight independently refuses latent foreign filters, auxiliary rules, unsupported or unstable reads', onlyMac, async () => {
  const harness = `
#include <stdarg.h>
#include <sys/ioctl.h>
#include <stdint.h>
static unsigned observed,scenario;
static int inert_prior_ioctl(int fd,unsigned long op,...);
#define ioctl inert_prior_ioctl
#include HOOK_SOURCE
#undef ioctl
static int inert_prior_ioctl(int fd,unsigned long op,...) {
    (void)fd; if (op != ENVARA_PF_HOOK_GET_RULES) return -1;
    va_list args; va_start(args,op); EnvaraPFHookRequest *r = va_arg(args,EnvaraPFHookRequest *); va_end(args);
    if (r->action) return -1; observed++; r->ticket = 5; r->nr = 0;
    if (scenario == 1 && r->anchor[0] && r->rule.action == 0) r->nr = 1;
    if (scenario == 2 && !r->anchor[0] && r->rule.action == 4) r->nr = 1;
    if (scenario == 3 && r->rule.action == 11) { errno = EINVAL; return -1; }
    if (scenario == 4 && observed % 2 == 0) r->ticket++;
    return 0;
}
int main(void) {
    int pipefd[2]; if (pipe(pipefd)) return 1; HookRoot root = {0}; root.count = 7; strcpy(root.canonical,ROOT_RULE_HASH);
    for (uint32_t i = 0; i < 7; i++) snprintf(root.rows[i].anchor_call,1024,"verified.foreign.%u",i);
    char digest[65]; if (!prior_anchors_empty(pipefd[0],&root,digest) || observed != 94 || strlen(digest) != 64) return 2;
    for (scenario = 1; scenario < 5; scenario++) { observed = 0; if (prior_anchors_empty(pipefd[0],&root,digest)) return 2 + scenario; }
    scenario = 0; observed = 0; uint32_t count;
    if (prior_count(pipefd[0],&root,-1,123,&count) || observed) return 8;
    if (prior_count(pipefd[1],&root,-1,4,&count) || observed) return 9;
    root.canonical[0] = 'x'; if (prior_count(pipefd[0],&root,0,0,&count) || observed) return 10;
    strcpy(root.canonical,ROOT_RULE_HASH); strcpy(root.rows[0].anchor_call,"foreign/*");
    if (prior_count(pipefd[0],&root,0,0,&count) || observed) return 11;
    close(pipefd[0]); close(pipefd[1]); return 0;
}`;
  await native(binary => execute(binary, [], { timeout: 15000 }), harness);
});
test('native cleanup refuses stale receipts and populated anchors while preserving exact owned cleanup after unrelated additions', onlyMac, async () => {
  const harness = `
#include <stdarg.h>
#include <sys/ioctl.h>
static int inert_cleanup_ioctl(int fd,unsigned long op,...);
#define ioctl inert_cleanup_ioctl
#include HOOK_SOURCE
#undef ioctl
static unsigned scenario,deletes,root_reads;
static HookLease lease;
static int inert_cleanup_ioctl(int fd,unsigned long op,...) {
    (void)fd; va_list args; va_start(args,op); EnvaraPFHookRequest *r = va_arg(args,EnvaraPFHookRequest *); va_end(args);
    if (op == ENVARA_PF_HOOK_GET_RULES) {
        if (r->anchor[0]) { r->nr = scenario == 4 ? 1 : 0; return 0; }
        root_reads++; r->ticket = scenario == 5 && root_reads > 1 ? 12 : 11; r->nr = scenario == 8 ? 9 : 8; return 0;
    }
    if (op == ENVARA_PF_HOOK_GET_RULE) {
        uint32_t index = r->nr;
        if (index == 7) {
            *r = new_rule(&lease); r->rule.anchor_relative = 1; r->rule.ticket = UINT64_C(112233445566778899);
            if (scenario == 1) r->rule.ticket++;
            if (scenario == 2) strcpy(r->rule.owner,"foreign");
            if (scenario == 3) r->rule.label[16] = 'f';
            if (scenario == 9) r->rule.rt = 1;
        } else snprintf(r->anchor_call,1024,"original-%u",index);
        r->nr = r->rule.nr = index; return 0;
    }
    if (op == ENVARA_PF_HOOK_DELETE) { if (r->rule.anchor_relative || r->rule.rt) return -1; deletes++; return scenario == 6 ? -1 : 0; }
    return -1;
}
int main(void) {
    strcpy(lease.schema,LEASE_SCHEMA); strcpy(lease.runId,"00112233-4455-4677-8899-aabbccddeeff");
    strcpy(lease.leaseId,"11223344-5566-4788-99aa-bbccddeeff00"); if (!envara_pf_run_anchor(lease.runId,lease.anchor)) abort(); strcpy(lease.owner,lease.anchor);
    strcpy(lease.ticket,"112233445566778899"); strcpy(lease.rootBeforeSHA256,ROOT_RULE_HASH); strcpy(lease.rootBeforeTextSHA256,ROOT_TEXT_HASH); lease_label(&lease,lease.label);
    int pipefd[2]; if (pipe(pipefd)) return 1; int writable = open("/dev/null",O_RDWR|O_CLOEXEC); if (writable < 0) return 2;
    for (scenario = 0; scenario < 10; scenario++) {
        deletes = root_reads = 0; if (scenario == 7) strcpy(lease.ticket,"0");
        int okay = exact_remove(pipefd[0],writable,&lease);
        if (scenario == 0 || scenario == 8 || scenario == 9) { if (!okay || deletes != 1) return 10 + scenario; }
        else if (scenario == 6) { if (okay || deletes != 1) return 26; }
        else if (okay || deletes) return 30 + scenario;
        strcpy(lease.ticket,"112233445566778899");
    }
    close(pipefd[0]); close(pipefd[1]); close(writable); return 0;
}`;
  await native(binary => execute(binary, [], { timeout: 15000 }), harness);
});
test('hook source has no self-authorization, generic PF command, state clearing or installed network activation', async () => {
  const text = await readFile(source, 'utf8');
  assert.doesNotMatch(text, /Authorization|DIOCSTART|DIOCSTOP|DIOCCLRSTATES|DIOCCHANGERULE|["']-f["']|["']-E["']|["']-X["']/);
  assert.match(text, /arc4random_buf/); assert.match(text, /lease_valid\(lease\).*read_root\(read_fd/s);
  assert.match(text, /request->rule\.ticket != ticket/); assert.match(text, /leaf_empty\(read_fd,lease->anchor\)/);
  assert.match(text, /is_delete && \(!proof\.readable \|\| !proof\.disabled \|\| !find_identity\(&proof\.root,&input\.lease,&known\)/);
  assert.doesNotMatch(text, /is_delete && \(!proof\.hook_verified/);
  assert.match(text, /"io\.envara\.pf\.run\."/); assert.match(text, /root-canary-native-20261008/);
  assert.match(text, /owned_write_template[\s\S]*anchor_relative == 0/);
  assert.match(text, /owned_readback[\s\S]*anchor_relative == 1/);
  assert.doesNotMatch(text, /anchor_relative\s*(?:<=\s*1|==\s*0\s*\|\|)/);
  assert.match(text, /productionReady\\":false/);
});
