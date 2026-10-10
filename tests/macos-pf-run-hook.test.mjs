// Native lifecycle fixture: PF devices/ioctls, host pins and pfctl are replaced
// in a temporary translation unit. The actual ledger is compiled in its
// nonroot/self-owned mode. No helper, authorization or networking is invoked.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, realpath, writeFile, readFile, rm } from 'node:fs/promises';
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
static char fixture_rule_hash[65],fixture_text_hash[65],fixture_rules[2048],fixture_root[PATH_MAX];
static int fixture_open(const char *path,int flags,...);
static int fixture_ioctl(int fd,unsigned long operation,...);
static uid_t fixture_zero_uid(void) { return 0; }
#define getuid fixture_zero_uid
#define geteuid fixture_zero_uid
#define open fixture_open
#define ioctl fixture_ioctl
#include "mock-hook.c"
#undef getuid
#undef geteuid
#undef open
#undef ioctl
static HookRoot fixture_original;
static EnvaraPFHookRequest fixture_hook;
static int fixture_live,fixture_namespace,fixture_retain,fixture_old_touched,fixture_inserts,fixture_deletes;
static uint32_t fixture_revision=10;
static char fixture_selected[64],fixture_fault[32];
static int fixture_fault_used;
static void require(int accepted) { if(!accepted) abort(); }
static void event_path(char out[PATH_MAX],const char *run,const char *name) {
    int length=snprintf(out,PATH_MAX,"%s/%s/%s",fixture_root,run,name); require(length>0 && length<PATH_MAX);
}
int fixture_fsync(int fd) {
    char selected[PATH_MAX];
    if(fixture_fault[0] && !fixture_fault_used && !fcntl(fd,F_GETPATH,selected)) {
        const char *leaf=strrchr(selected,'/');
        if(leaf && !strcmp(leaf+1,fixture_fault)) { fixture_fault_used=1; errno=EIO; return -1; }
    }
    return fsync(fd);
}
static int fixture_open(const char *selected,int flags,...) {
    if(!strcmp(selected,"/dev/pf")) return open("/dev/null",flags);
    /* No unmocked child executable/device can be reached by this fixture. */
    if(!strcmp(selected,"/sbin/pfctl") || !strcmp(selected,"/usr/libexec/pfd")) abort();
    return open(selected,flags);
}
static int fixture_ioctl(int fd,unsigned long operation,...) {
    (void)fd; va_list arguments; va_start(arguments,operation);
    EnvaraPFHookRequest *request=va_arg(arguments,EnvaraPFHookRequest*); va_end(arguments);
    require(!request->action);
    if(strstr(request->anchor,"root.v1") || strstr(request->anchor_call,"root.v1")) fixture_old_touched++;
    if(operation==ENVARA_PF_HOOK_GET_RULES) {
        if(!request->anchor[0]) { request->nr=request->rule.action?0:7+(unsigned)fixture_live; request->ticket=fixture_revision; return 0; }
        if(!strncmp(request->anchor,"original-",9)) { request->nr=0; request->ticket=20; return 0; }
        if(!strcmp(request->anchor,fixture_selected) && fixture_namespace) { request->nr=0; request->ticket=30; return 0; }
        errno=EINVAL; return -1;
    }
    if(operation==ENVARA_PF_HOOK_GET_RULE) {
        uint32_t index=request->nr; require(index<7+(unsigned)fixture_live);
        *request=index<7?fixture_original.rows[index]:fixture_hook;
        request->nr=request->rule.nr=index; request->ticket=fixture_revision; return 0;
    }
    if(operation==ENVARA_PF_HOOK_INSERT) {
        char allocation[PATH_MAX]; const char *run=request->anchor_call+strlen("io.envara.pf.run.");
        require(!fixture_live && envara_pf_run_uuid_valid(run)); event_path(allocation,run,"allocation.json");
        struct stat st; require(!lstat(allocation,&st) && S_ISREG(st.st_mode) && (st.st_mode&07777)==0600);
        fixture_hook=*request; fixture_hook.rule.anchor_relative=1; fixture_hook.rule.ticket=UINT64_C(112233445566778899);
        strcpy(fixture_selected,request->anchor_call); fixture_live=fixture_namespace=1; fixture_revision++; fixture_inserts++;
        *request=fixture_hook; return 0;
    }
    if(operation==ENVARA_PF_HOOK_DELETE) {
        char intent[PATH_MAX]; const char *run=request->anchor_call+strlen("io.envara.pf.run.");
        event_path(intent,run,"delete-intent.json"); struct stat st;
        require(!lstat(intent,&st) && S_ISREG(st.st_mode) && (st.st_mode&07777)==0600);
        require(fixture_live && request->rule.ticket==fixture_hook.rule.ticket && !request->rule.anchor_relative);
        fixture_live=0; fixture_namespace=fixture_retain; fixture_revision++; fixture_deletes++; return 0;
    }
    abort();
}
static int call(const char *operation,const char *json) {
    int channel[2]; require(!pipe(channel)); size_t length=strlen(json);
    require(write(channel[1],json,length)==(ssize_t)length); close(channel[1]);
    require(dup2(channel[0],STDIN_FILENO)>=0); close(channel[0]);
    char *arguments[]={"fixture",(char*)operation,NULL}; return envara_pf_hook_main(2,arguments);
}
static void candidate(const char *run) {
    char json[128]; snprintf(json,sizeof(json),"{\"runId\":\"%s\"}",run); require(!call("hook-status",json));
}
static int insert(const char *run) {
    char json[128]; snprintf(json,sizeof(json),"{\"runId\":\"%s\"}",run); return call("insert-owned-root-hook",json);
}
static void issued(const char *run,char json[ENVARA_PF_RUN_LEASE_LIMIT+32]) {
    char file[PATH_MAX]; event_path(file,run,"issued.json");
    int fd=open(file,O_RDONLY|O_NOFOLLOW); require(fd>=0);
    char lease[ENVARA_PF_RUN_LEASE_LIMIT+1]; ssize_t size=read(fd,lease,ENVARA_PF_RUN_LEASE_LIMIT); close(fd); require(size>0);
    lease[size]=0; snprintf(json,ENVARA_PF_RUN_LEASE_LIMIT+32,"{\"lease\":%s}",lease);
}
int main(int argc,char **argv) {
    require(argc==2 && getuid()!=0); strcpy(fixture_root,argv[1]); require(envara_pf_run_ledger_test_root(fixture_root));
    fixture_original.count=7; size_t text_length=0;
    for(uint32_t i=0;i<7;i++) {
        EnvaraPFHookRequest *row=&fixture_original.rows[i]; row->nr=row->rule.nr=i; row->rule.ticket=i+10;
        snprintf(row->anchor_call,sizeof(row->anchor_call),"original-%u",i);
        text_length+=(size_t)snprintf(fixture_rules+text_length,sizeof(fixture_rules)-text_length,"anchor \"original-%u\" all\n",i);
    }
    root_hash(&fixture_original,7); strcpy(fixture_rule_hash,fixture_original.canonical); hook_hash(fixture_rules,text_length,fixture_text_hash);
    const char *one="00112233-4455-4677-8899-aabbccddeeff",*two="11223344-5566-4788-99aa-bbccddeeff00";
    const char *three="22334455-6677-4899-aabb-ccddeeff0011",*four="33445566-7788-49aa-abcc-ddeeff001122";
    char json[ENVARA_PF_RUN_LEASE_LIMIT+32];
    require(!call("hook-status","{}")); candidate(one); require(!insert(one)); issued(one,json);
    require(!call("delete-owned-root-hook",json) && fixture_deletes==1);
    require(call("delete-owned-root-hook",json)==1 && fixture_deletes==1);
    require(!call("hook-status",json)); candidate(one); candidate(two);
    fixture_retain=1; require(!insert(two)); issued(two,json);
    require(!call("delete-owned-root-hook",json) && fixture_deletes==2); require(!call("hook-status",json));
    candidate(three); fixture_retain=0; fixture_namespace=0;
    strcpy(fixture_fault,"issued.json"); fixture_fault_used=0;
    require(insert(three)==1 && fixture_fault_used && fixture_inserts==3 && fixture_deletes==2 && fixture_live);
    issued(three,json); require(!call("hook-status",json));
    /* The failed issue retains this simulated hook. An independent fixture
     * state begins here; production has no corresponding reset/flush API. */
    fixture_live=fixture_namespace=0; fixture_revision++;
    strcpy(fixture_fault,""); require(!insert(four)); issued(four,json);
    strcpy(fixture_fault,"delete-intent.json"); fixture_fault_used=0;
    require(call("delete-owned-root-hook",json)==1 && fixture_fault_used && fixture_deletes==2 && fixture_live);
    strcpy(fixture_fault,""); require(call("delete-owned-root-hook",json)==1 && fixture_deletes==2);
    require(!fixture_old_touched); return 0;
}
`;

test('fresh run native lifecycle burns names, durably gates one DELETE and preserves retained namespaces',
  { skip: process.platform !== 'darwin' || process.getuid?.() === 0 }, async () => {
    const temporary = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-pf-run-hook-')));
    try {
      const fixtureRoot = path.join(temporary, 'ledger');
      const { mkdir } = await import('node:fs/promises'); await mkdir(fixtureRoot, { mode: 0o700 });
      let mock = await readFile(path.join(directory, 'pf-hook.c'), 'utf8');
      mock = mock.replace(/^#define ROOT_RULE_HASH .*$/m, '#define ROOT_RULE_HASH fixture_rule_hash')
        .replace(/^#define ROOT_TEXT_HASH .*$/m, '#define ROOT_TEXT_HASH fixture_text_hash');
      mock = replaceFunction(mock, 'pins_verified', 'return 1;');
      mock = replaceFunction(mock, 'fixed_pfctl', '(void)mode; strcpy(output,fixture_rules); return 1;');
      mock = replaceFunction(mock, 'pf_disabled', 'return 1;');
      await writeFile(path.join(temporary, 'mock-hook.c'), mock);
      await writeFile(path.join(temporary, 'fixture.c'), harness);
      const common = ['-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', '-DENVARA_PF_RUN_LEDGER_INERT', '-I', directory];
      const object = path.join(temporary, 'ledger.o'), binary = path.join(temporary, 'fixture');
      await execute('/usr/bin/clang', [...common, '-Dfsync=fixture_fsync', '-c', path.join(directory, 'pf-run-ledger.c'), '-o', object], { timeout: 30000 });
      await execute('/usr/bin/clang', [...common, '-Wno-unused-function', path.join(temporary, 'fixture.c'), object, '-o', binary], { timeout: 30000 });
      const output = await execute(binary, [fixtureRoot], { timeout: 15000 });
      const responses = output.stdout.trim().split('\n').map(line => JSON.parse(line));
      assert.equal(responses[0].anchor, ''); assert.equal(responses[0].canCreateOwnedHook, false);
      assert.equal(responses[1].canCreateOwnedHook, true);
      assert.equal(responses[3].ownedRootHookRemoved, true); assert.equal(responses[3].receiptRetired, true);
      assert.equal(responses[3].namespaceReclaimed, true);
      assert.equal(responses[4].ok, false); assert.equal(responses[5].receiptRetired, true);
      assert.equal(responses[6].canCreateOwnedHook, false); assert.equal(responses[7].canCreateOwnedHook, true);
      assert.equal(responses[9].ownedRootHookRemoved, true); assert.equal(responses[9].originalRootRestored, true);
      assert.equal(responses[9].namespaceState, 'present'); assert.equal(responses[9].cleanupPending, true);
      assert.equal(responses[10].receiptRetired, true); assert.equal(responses[11].canCreateOwnedHook, true);
      assert.equal(responses[12].ok, false); assert.equal(responses[12].receiptRetired, false);
      assert.equal(responses[12].reason, 'INSERT_UNCONFIRMED_OWN_ROLLBACK_REFUSED');
      assert.equal(responses[13].receiptRetired, false); assert.equal(responses[13].ownedRootHookVerified, true);
      assert.equal(responses[15].reason, 'OWNED_HOOK_DELETE_INTENT_REQUIRED'); assert.equal(responses[16].ok, false);
      for (const response of responses) { assert.equal(response.ready, false); assert.equal(response.productionReady, false); assert.equal(response.protected, false); }
    } finally { await rm(temporary, { recursive: true, force: true }); }
  });
