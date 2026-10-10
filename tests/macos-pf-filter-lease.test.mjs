// PF, host pins and pfctl are mocked in a temporary translation unit. Only a
// real nonroot self-owned inert ledger is exercised; no PF/system operation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, realpath, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const directory = fileURLToPath(new URL('../native/macos-pf-routing/', import.meta.url));
function replaceFunction(source, name, replacement) {
  const start = source.indexOf(`static int ${name}(`);
  assert.ok(start >= 0);
  let index = source.indexOf('{', start), depth = 0, quote = null, escaped = false;
  const body = index;
  for (; index < source.length; index++) {
    const character = source[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === quote) quote = null;
    } else if (character === '"' || character === "'") quote = character;
    else if (character === '{') depth++;
    else if (character === '}' && --depth === 0) break;
  }
  assert.ok(index < source.length);
  return source.slice(0, body) + `{ ${replacement} }` + source.slice(index + 1);
}

test('FILTER lease API holds an issued handle without deleting or reentering the ledger lock', async () => {
  const source = await readFile(path.join(directory, 'pf-hook.c'), 'utf8');
  const from = source.indexOf('struct EnvaraPFHookFilterLease {');
  const to = source.indexOf('static void lease_output', from);
  assert.ok(from >= 0 && to > from);
  const leaseSource = source.slice(from, to);
  assert.match(leaseSource, /envara_pf_run_ledger_open_issued/);
  assert.doesNotMatch(leaseSource, /envara_pf_run_ledger_(?:allocate|issue|begin_delete|retire)\s*\(/);
  assert.doesNotMatch(leaseSource, /ENVARA_PF_HOOK_(?:INSERT|DELETE)/);
  assert.match(leaseSource, /prove\(held->read_fd,held->lease.runId,&held->lease,0\)/);
  assert.doesNotMatch(leaseSource, /proof\.disabled/);
});

const harness = String.raw`
#define _DARWIN_C_SOURCE
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <assert.h>
static char fixture_rule_hash[65], fixture_text_hash[65], fixture_rules[2048], fixture_root[PATH_MAX];
static int fixture_pins = 1, fixture_disabled = 1;
static uid_t fixture_uid, fixture_euid;
static pid_t fixture_pid;
static int fixture_open(const char *, int, ...);
static int fixture_ioctl(int, unsigned long, ...);
static int fixture_lstat(const char *, struct stat *);
static int fixture_fstat(int, struct stat *);
static uid_t fixture_getuid(void) { return fixture_uid; }
static uid_t fixture_geteuid(void) { return fixture_euid; }
static pid_t fixture_getpid(void) { return fixture_pid; }
#define getuid fixture_getuid
#define geteuid fixture_geteuid
#define getpid fixture_getpid
#define open fixture_open
#define ioctl fixture_ioctl
#define lstat fixture_lstat
#define fstat fixture_fstat
#include "mock-hook.c"
#undef getuid
#undef geteuid
#undef getpid
#undef open
#undef ioctl
#undef lstat
#undef fstat
static HookRoot original;
static EnvaraPFHookRequest hook;
static char own_anchor[64];
static int live = 1, namespace_present = 1, root_extra, prior_dirty, read_error;
static int path_fault, descriptor_fault, pf_opens, pf_reads;
static uint32_t revision = 17;
static int fixture_open(const char *selected, int flags, ...) {
    if (!strcmp(selected,"/dev/pf")) { pf_opens++; return open("/dev/null", flags); }
    if (!strcmp(selected,"/sbin/pfctl") || !strcmp(selected,"/usr/libexec/pfd")) abort();
    return open(selected, flags);
}
static int fixture_lstat(const char *selected, struct stat *output) {
    if (strcmp(selected,"/dev/pf")) return lstat(selected,output);
    int result=lstat("/dev/null",output); if(result) return result;
    if(path_fault==1) output->st_ino++;
    if(path_fault==2) output->st_uid=501;
    if(path_fault==3) output->st_mode=(output->st_mode&07777)|S_IFREG;
    return 0;
}
static int fixture_fstat(int fd, struct stat *output) {
    int result=fstat(fd,output); if(result)return result;
    if(descriptor_fault==1) output->st_rdev++;
    if(descriptor_fault==2) output->st_uid=501;
    if(descriptor_fault==3) output->st_mode=(output->st_mode&07777)|S_IFREG;
    return 0;
}
static int fixture_ioctl(int fd,unsigned long operation,...) {
    assert((fcntl(fd,F_GETFL)&O_ACCMODE)==O_RDONLY); pf_reads++;
    va_list arguments;va_start(arguments,operation);EnvaraPFHookRequest *request=va_arg(arguments,EnvaraPFHookRequest*);va_end(arguments);
    assert(!request->action);
    if(read_error) {errno=EIO;return -1;}
    if(operation==ENVARA_PF_HOOK_GET_RULES) {
        if(!request->anchor[0]) {request->nr=request->rule.action?0:7+(unsigned)live+(unsigned)root_extra;request->ticket=revision;return 0;}
        if(!strncmp(request->anchor,"original-",9)) {request->nr=(unsigned)prior_dirty;request->ticket=20;return 0;}
        if(!strcmp(request->anchor,own_anchor)&&namespace_present) {request->nr=0;request->ticket=30;return 0;}
        errno=EINVAL;return -1;
    }
    if(operation==ENVARA_PF_HOOK_GET_RULE) {
        uint32_t index=request->nr;
        if(index<7) *request=original.rows[index];
        else if(index==7&&live) *request=hook;
        else {memset(request,0,sizeof(*request));strcpy(request->anchor_call,"foreign-hook");}
        request->nr=request->rule.nr=index;request->ticket=revision;return 0;
    }
    abort(); /* INSERT/DELETE/state/PF activation can never be called. */
}
static HookLease make_lease(const char *run, const char *nonce) {
    HookLease value={0};strcpy(value.schema,LEASE_SCHEMA);strcpy(value.runId,run);strcpy(value.leaseId,nonce);
    assert(envara_pf_run_anchor(run,value.anchor));strcpy(value.owner,value.anchor);lease_label(&value,value.label);
    strcpy(value.ticket,"112233445566778899");strcpy(value.rootBeforeSHA256,fixture_rule_hash);strcpy(value.rootBeforeTextSHA256,fixture_text_hash);
    return value;
}
static void issue(const HookLease *value,char json[ENVARA_PF_RUN_LEASE_LIMIT+1],size_t *size) {
    *size=lease_json(value,json);assert(*size);
    EnvaraPFRunLedger *ledger=NULL;assert(envara_pf_run_ledger_allocate(value->runId,&ledger));
    assert(envara_pf_run_ledger_issue(ledger,json,*size));envara_pf_run_ledger_close(ledger);
}
static void ensure_unlock(const HookLease *value,const char *json,size_t length) {
    EnvaraPFRunLedger *ledger=NULL;assert(envara_pf_run_ledger_open_issued(value->runId,json,length,&ledger));envara_pf_run_ledger_close(ledger);
}
int main(int argc,char **argv) {
    assert(argc==3&&getuid()!=0);fixture_pid=getpid();strcpy(fixture_root,argv[1]);assert(envara_pf_run_ledger_test_root(fixture_root));
    original.count=7;size_t text_size=0;
    for(uint32_t i=0;i<7;i++) {
        EnvaraPFHookRequest *row=&original.rows[i];row->nr=row->rule.nr=i;row->rule.ticket=i+10;
        snprintf(row->anchor_call,sizeof(row->anchor_call),"original-%u",i);
        text_size+=(size_t)snprintf(fixture_rules+text_size,sizeof(fixture_rules)-text_size,"anchor \"original-%u\" all\n",i);
    }
    root_hash(&original,7);strcpy(fixture_rule_hash,original.canonical);hook_hash(fixture_rules,text_size,fixture_text_hash);
    const char *run="00112233-4455-4677-8899-aabbccddeeff",*other="11223344-5566-4788-99aa-bbccddeeff00";
    HookLease lease=make_lease(run,other);char json[ENVARA_PF_RUN_LEASE_LIMIT+1];size_t length;
    issue(&lease,json,&length);hook=new_rule(&lease);hook.rule.anchor_relative=1;hook.rule.ticket=UINT64_C(112233445566778899);strcpy(own_anchor,lease.anchor);
    EnvaraPFHookFilterLease *held=NULL;const char *scenario=argv[2];
    if(!strcmp(scenario,"retired")||!strcmp(scenario,"delete-intent")) {
        EnvaraPFRunLedger *ledger=NULL;assert(envara_pf_run_ledger_open_issued(run,json,length,&ledger));assert(envara_pf_run_ledger_begin_delete(ledger));
        if(!strcmp(scenario,"retired"))assert(envara_pf_run_ledger_retire(ledger,ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_ABSENT));
        envara_pf_run_ledger_close(ledger);
        assert(!envara_pf_hook_filter_open(run,json,length,&held)&&!held&&!pf_opens&&!pf_reads);return 0;
    }
    if(!strcmp(scenario,"unknown")) {
        char file[PATH_MAX];snprintf(file,sizeof(file),"%s/%s/issued.json",fixture_root,run);
        int fd=open(file,O_WRONLY|O_TRUNC|O_NOFOLLOW);assert(fd>=0&&write(fd,"{}",2)==2);close(fd);
        assert(!envara_pf_hook_filter_open(run,json,length,&held)&&!held&&!pf_opens&&!pf_reads);return 0;
    }
    if(!strcmp(scenario,"allocation-only")) {
        HookLease selected=make_lease(other,run);size_t selected_length=lease_json(&selected,json);
        EnvaraPFRunLedger *ledger=NULL;assert(envara_pf_run_ledger_allocate(other,&ledger));envara_pf_run_ledger_close(ledger);
        assert(!envara_pf_hook_filter_open(other,json,selected_length,&held)&&!held&&!pf_opens&&!pf_reads);return 0;
    }
    if(!strcmp(scenario,"wrong-run")) {
        assert(!envara_pf_hook_filter_open(other,json,length,&held)&&!held&&!pf_opens&&!pf_reads);ensure_unlock(&lease,json,length);return 0;
    }
    if(!strcmp(scenario,"wrong-lease")) {
        HookLease changed=lease;strcpy(changed.leaseId,run);lease_label(&changed,changed.label);
        char selected[ENVARA_PF_RUN_LEASE_LIMIT+1];size_t selected_length=lease_json(&changed,selected);
        assert(!envara_pf_hook_filter_open(run,selected,selected_length,&held)&&!held&&!pf_opens&&!pf_reads);ensure_unlock(&lease,json,length);return 0;
    }
    if(!strcmp(scenario,"nonroot-uid"))fixture_uid=501;
    if(!strcmp(scenario,"nonroot-euid"))fixture_euid=501;
    if(fixture_uid||fixture_euid) {assert(!envara_pf_hook_filter_open(run,json,length,&held)&&!held&&!pf_opens&&!pf_reads);return 0;}
    if(!strcmp(scenario,"pins"))fixture_pins=0;
    if(!strcmp(scenario,"root-extra"))root_extra=1;
    if(!strcmp(scenario,"root-missing"))live=0;
    if(!strcmp(scenario,"root-ticket"))hook.rule.ticket++;
    if(!strcmp(scenario,"root-owner"))hook.rule.owner[0]='x';
    if(!strcmp(scenario,"root-label"))hook.rule.label[0]='x';
    if(!strcmp(scenario,"root-route"))hook.rule.rt=2;
    if(!strcmp(scenario,"prior-dirty"))prior_dirty=1;
    if(!strcmp(scenario,"namespace-missing"))namespace_present=0;
    if(!strcmp(scenario,"read-error"))read_error=1;
    if(!strcmp(scenario,"path-inode"))path_fault=1;
    if(!strcmp(scenario,"path-uid"))path_fault=2;
    if(!strcmp(scenario,"path-type"))path_fault=3;
    if(!strcmp(scenario,"fd-type"))descriptor_fault=3;
    if(!strcmp(scenario,"enabled-pf"))fixture_disabled=0;
    int expected=!strcmp(scenario,"success")||!strcmp(scenario,"exclusive")||!strcmp(scenario,"enabled-pf")||!strncmp(scenario,"held-",5);
    assert(envara_pf_hook_filter_open(run,json,length,&held)==expected);
    if(!expected) {assert(!held);ensure_unlock(&lease,json,length);return 0;}
    assert(held&&envara_pf_hook_filter_matches(held,json,length)&&envara_pf_hook_filter_guard(held,-1));
    int write_fd=open("/dev/null",O_RDWR|O_CLOEXEC);assert(write_fd>=0&&envara_pf_hook_filter_guard(held,write_fd));
    if(!strcmp(scenario,"exclusive")) {
        EnvaraPFHookFilterLease *second=NULL;int before=pf_opens;
        assert(!envara_pf_hook_filter_open(run,json,length,&second)&&!second&&pf_opens==before);
        EnvaraPFRunLedger *ledger=NULL;assert(!envara_pf_run_ledger_open_issued(run,json,length,&ledger)&&!ledger);
    }
    if(!strcmp(scenario,"held-uid"))fixture_uid=501;
    if(!strcmp(scenario,"held-euid"))fixture_euid=501;
    if(!strcmp(scenario,"held-pid"))fixture_pid++;
    if(!strcmp(scenario,"held-path"))path_fault=1;
    if(!strcmp(scenario,"held-fd"))descriptor_fault=1;
    if(!strcmp(scenario,"held-read-error"))read_error=1;
    if(!strcmp(scenario,"held-pins"))fixture_pins=0;
    if(!strcmp(scenario,"held-root-ticket"))hook.rule.ticket++;
    if(!strcmp(scenario,"held-access")) {
        int readonly=open("/dev/null",O_RDONLY|O_CLOEXEC),writeonly=open("/dev/null",O_WRONLY|O_CLOEXEC);assert(readonly>=0&&writeonly>=0);
        assert(!envara_pf_hook_filter_guard(held,readonly)&&!envara_pf_hook_filter_guard(held,writeonly));close(readonly);close(writeonly);
    } else if(!strcmp(scenario,"held-matches")) {
        HookLease changed=lease;strcpy(changed.leaseId,run);lease_label(&changed,changed.label);
        char selected[ENVARA_PF_RUN_LEASE_LIMIT+1];size_t size=lease_json(&changed,selected);
        assert(!envara_pf_hook_filter_matches(held,selected,size));
        assert(!envara_pf_hook_filter_matches(held,json,length+1));assert(!envara_pf_hook_filter_matches(held,json,0));
        assert(envara_pf_hook_filter_guard(held,write_fd));
    } else if(!strncmp(scenario,"held-",5)) assert(!envara_pf_hook_filter_guard(held,write_fd));
    if(fixture_uid||fixture_euid||fixture_pid!=getpid())assert(!envara_pf_hook_filter_matches(held,json,length));
    fixture_uid=fixture_euid=0;fixture_pid=getpid();path_fault=descriptor_fault=read_error=0;fixture_pins=1;
    close(write_fd);envara_pf_hook_filter_close(held);held=NULL;ensure_unlock(&lease,json,length);
    if(!strcmp(scenario,"exclusive")||!strcmp(scenario,"success")||!strcmp(scenario,"enabled-pf")) {
        assert(envara_pf_hook_filter_open(run,json,length,&held));envara_pf_hook_filter_close(held);ensure_unlock(&lease,json,length);
    }
    envara_pf_hook_filter_close(NULL);return 0;
}
`;

test('issued FILTER lease, guard and close preserve exact ownership with only mocked PF',
  { skip: process.platform !== 'darwin' || process.getuid?.() === 0 }, async t => {
    const temporary = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-filter-lease-test-')));
    try {
      let mock = await readFile(path.join(directory, 'pf-hook.c'), 'utf8');
      mock = mock.replace(/^#define ROOT_RULE_HASH .*$/m, '#define ROOT_RULE_HASH fixture_rule_hash')
        .replace(/^#define ROOT_TEXT_HASH .*$/m, '#define ROOT_TEXT_HASH fixture_text_hash');
      mock = replaceFunction(mock, 'pins_verified', 'return fixture_pins;');
      mock = replaceFunction(mock, 'fixed_pfctl', '(void)mode; strcpy(output,fixture_rules); return 1;');
      mock = replaceFunction(mock, 'pf_disabled', 'return fixture_disabled;');
      await writeFile(path.join(temporary, 'mock-hook.c'), mock);
      await writeFile(path.join(temporary, 'fixture.c'), harness);
      const common = ['-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', '-DENVARA_PF_RUN_LEDGER_INERT', '-I', directory];
      const object = path.join(temporary, 'ledger.o'), binary = path.join(temporary, 'fixture');
      await execute('/usr/bin/clang', [...common, '-c', path.join(directory, 'pf-run-ledger.c'), '-o', object], { timeout: 30000 });
      await execute('/usr/bin/clang', [...common, '-Wno-unused-function', path.join(temporary, 'fixture.c'), object, '-o', binary], { timeout: 30000 });
      const cases = ['success', 'exclusive', 'enabled-pf', 'retired', 'delete-intent', 'unknown', 'allocation-only', 'wrong-run',
        'wrong-lease', 'nonroot-uid', 'nonroot-euid', 'pins', 'root-extra', 'root-missing', 'root-ticket', 'root-owner',
        'root-label', 'root-route', 'prior-dirty', 'namespace-missing', 'read-error', 'path-inode', 'path-uid', 'path-type',
        'fd-type', 'held-uid', 'held-euid', 'held-pid', 'held-path', 'held-fd', 'held-read-error', 'held-pins',
        'held-root-ticket', 'held-access', 'held-matches'];
      for (const scenario of cases) await t.test(scenario, async () => {
        const ledger = path.join(temporary, scenario); await mkdir(ledger, { mode: 0o700 });
        await execute(binary, [ledger, scenario], { timeout: 10000 });
      });
    } finally { await rm(temporary, { recursive: true, force: true }); }
  });
