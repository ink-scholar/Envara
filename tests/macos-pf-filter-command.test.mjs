// Every executable below is an inert user-owned fixture. The actual private CLI
// is not invoked; PF/issued-lease APIs are never allowed to open a real device.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, readFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const execute=promisify(execFile),native=fileURLToPath(new URL('../native/macos-pf-routing/',import.meta.url));
const runId='5e408244-d338-43f8-b847-19caa2c32f40',generation='41d871a3-64d0-463b-9e73-7ab3ae2e4800';
const realm={environmentId:'00112233-4455-4677-8899-aabbccddeeff',gid:7111,udpPolicy:'proxy',tunnel:null};
const request=()=>({schema:'envara.macos-pf-filter-replacement/v1',runId,generation,lease:{token:'INERT_ONLY_PRIVATE_LEASE'},previous:{mode:'empty',realms:[],writerPid:0,filterRevision:null},next:{mode:'deny',realms:[structuredClone(realm)]}});
const record=p=>structuredClone({schema:'envara.macos-pf-owned-registry/v1',runId:p.runId,supervisorPid:7,anchor:`io.envara.pf.run.${p.runId}`,rootHook:{verified:true,mutationAttempted:true,removed:false,receiptRetired:false,lease:p.lease},filterReplacement:{schema:p.schema,generation:p.generation,state:'pending',previous:p.previous,next:p.next}});
const harness=String.raw`
#include <sys/types.h>
#include <assert.h>
static pid_t fixture_parent(void);
#define getppid fixture_parent
#include "command-fixture.c"
#undef getppid
static pid_t fixture_parent(void) { return 7; }
int envara_pf_hook_filter_open(const char *run,const char *json,unsigned long n,EnvaraPFHookFilterLease **out) { (void)run;(void)json;(void)n;(void)out;abort(); }
int envara_pf_hook_filter_matches(const EnvaraPFHookFilterLease *held,const char *json,unsigned long n) { (void)held;return n==strlen("{\"token\":\"INERT_ONLY_PRIVATE_LEASE\"}")&&!memcmp(json,"{\"token\":\"INERT_ONLY_PRIVATE_LEASE\"}",n); }
int envara_pf_hook_filter_guard(EnvaraPFHookFilterLease *held,int fd) { (void)held;(void)fd;abort(); }
void envara_pf_hook_filter_close(EnvaraPFHookFilterLease *held) { (void)held; }
int envara_identity_read(pid_t pid,struct envara_identity *out) { (void)pid;(void)out;errno=ESRCH;return -1; }
static size_t read_file(const char *name,char *out) { int fd=open(name,O_RDONLY);assert(fd>=0);ssize_t n=read(fd,out,FILTER_LIMIT+1);close(fd);assert(n>0&&n<=FILTER_LIMIT);return (size_t)n; }
int main(int argc,char **argv) {
 assert(argc==4&&getuid()!=0);FilterCommand *c=calloc(1,sizeof(*c));assert(c);c->runtime_fd=c->registry_fd=-1;
 size_t n=read_file(argv[2],c->input_text);int parsed=parse_request(c,n);
 if(!strcmp(argv[1],"parse")) { printf("{\"parsed\":%s}\n",parsed?"true":"false"); }
 else if(!strcmp(argv[1],"record")) { size_t size=read_file(argv[3],c->record_text);int valid=json_parse(&c->record,c->record_text,size);printf("{\"parsed\":%s,\"record\":%s}\n",parsed?"true":"false",parsed&&valid&&pending_record_matches(c)?"true":"false"); }
 else if(!strncmp(argv[1],"emit",4)) { EnvaraPFFilterResult r={0};if(!strcmp(argv[1],"emit-unknown-begin")) { r.begun=1;r.uncertain=1; }else if(!strcmp(argv[1],"emit-ack-zero")) { r.begun=1;r.ticket_known=1;r.ticket=0;r.writer_pid=42;r.actual_count=6; }emit_filter(c,!strcmp(argv[1],"emit-ack-zero"),"GENERATED_SINGLE_FILTER_VERIFIED",&r); }
 else if(!strncmp(argv[1],"guard-",6)) { c->supervisor=7;c->deadline=filter_now()+30;if(!strcmp(argv[1],"guard-parent"))c->supervisor=8;else if(!strcmp(argv[1],"guard-deadline"))c->deadline=filter_now()-1;else if(!strcmp(argv[1],"guard-signal"))filter_interrupted=SIGTERM;else abort();printf("{\"accepted\":%s}\n",filter_guard(c,123,ENVARA_PF_FILTER_GUARD_BEGIN,UINT32_MAX)?"true":"false"); }
 else if(!strncmp(argv[1],"identity-",9)) {
  c->runtime_fd=open(FILTER_RUNTIME,O_RDONLY|O_DIRECTORY);c->registry_fd=open(FILTER_RUNTIME "/registry.json",O_RDONLY);assert(c->runtime_fd>=0&&c->registry_fd>=0);
  assert(!fstat(c->runtime_fd,&c->runtime_identity)&&!fstat(c->registry_fd,&c->registry_identity));c->record.size=read_file(FILTER_RUNTIME "/registry.json",c->record_text);int before=registry_stable(c);if(!before)fprintf(stderr,"ACL directory=%d file=%d errno=%d\n",no_write_acl(c->runtime_fd),no_write_acl(c->registry_fd),errno);assert(before);
  if(!strcmp(argv[1],"identity-bytes")) { int fd=open(FILTER_RUNTIME "/registry.json",O_WRONLY);assert(fd>=0&&write(fd,"x",1)==1);close(fd); }
  else if(!strcmp(argv[1],"identity-file")) { assert(!rename(FILTER_RUNTIME "/registry.json",FILTER_RUNTIME "/old.json"));int fd=open(FILTER_RUNTIME "/registry.json",O_WRONLY|O_CREAT|O_EXCL,0600);assert(fd>=0&&write(fd,c->record_text,c->record.size)==(ssize_t)c->record.size);close(fd); }
  else if(!strcmp(argv[1],"identity-directory")) { assert(!rename(FILTER_RUNTIME,FILTER_RUNTIME "-old"));assert(!mkdir(FILTER_RUNTIME,0700)); }
  printf("{\"before\":true,\"after\":%s}\n",registry_stable(c)?"true":"false");close(c->registry_fd);close(c->runtime_fd);
 }else abort();free(c);return 0;
}
`;
let fixturePromise;
async function fixture(){
 if(!fixturePromise)fixturePromise=(async()=>{const dir=await mkdtemp(path.join(tmpdir(),'envara-inert-filter-command-'));const runtime=path.join(dir,'runtime');
 const source=(await readFile(path.join(native,'pf-filter-command.c'),'utf8')).replace('#define FILTER_RUNTIME "/Library/PrivilegedHelperTools/io.envara.pf-runtime"',`#define FILTER_RUNTIME ${JSON.stringify(runtime)}`);
 await writeFile(path.join(dir,'command-fixture.c'),source);await writeFile(path.join(dir,'fixture.c'),harness);
 const binary=path.join(dir,'fixture');await execute('clang',['-std=c11','-Wall','-Wextra','-Werror','-I',native,'-I',dir,path.join(dir,'fixture.c'),path.join(native,'pf-run-ledger.c'),path.join(native,'pf-filter-transaction.c'),'-o',binary]);return {dir,binary,runtime};})();return fixturePromise;
}
async function check(mode,p,r={}){const f=await fixture(),input=path.join(f.dir,'request.json'),registry=path.join(f.dir,'record.json');await writeFile(input,typeof p==='string'?p:JSON.stringify(p));await writeFile(registry,JSON.stringify(r));return JSON.parse((await execute(f.binary,[mode,input,registry])).stdout);}
test.after(async()=>{if(fixturePromise){const f=await fixturePromise;await rm(f.dir,{recursive:true,force:true});}});
test('exact typed request and private pending generation are bound independently',async()=>{const p=request();assert.equal((await check('parse',p)).parsed,true);assert.equal((await check('record',p,record(p))).record,true);const reordered=record(p);reordered.filterReplacement.next={realms:p.next.realms,mode:'deny'};assert.equal((await check('record',p,reordered)).record,true);});
for(const [name,change] of Object.entries({extra:p=>{p.arbitraryCommand='pfctl';},wrongRun:p=>{p.runId=p.runId.toUpperCase();},wrongGeneration:p=>{p.generation='PRIVATE_SECRET';},typeGID:p=>{p.next.realms[0].gid='7111';},lowGID:p=>{p.next.realms[0].gid=501;},liveMissing:p=>{p.next.mode='routed';},unknownTarget:p=>{p.next.targets=['8.8.8.8'];},initialRevision:p=>{p.previous.filterRevision='0';},revisionOverflow:p=>{p.previous.writerPid=99;p.previous.filterRevision='4294967296';},revisionLeadingZero:p=>{p.previous.writerPid=99;p.previous.filterRevision='01';},emptyWithRealm:p=>{p.next.mode='empty';},duplicateRealm:p=>{p.next.realms.push(structuredClone(p.next.realms[0]));},negativeWriter:p=>{p.previous.writerPid=-1;}}))test(`request refuses ${name}`,async()=>{const p=request();change(p);assert.equal((await check('parse',p)).parsed,false);});
for(const [name,text] of Object.entries({duplicate:'{"x":0,"x":1}',nestedDuplicate:'{"x":{"a":1,"a":2}}',fraction:'{"x":1.0}',exponent:'{"x":1e2}',escaped:'{"x":"\\u0000"}',nul:'{"x":null}\u0000',trailing:'{}{}',leading:'{"x":01}'}))test(`bounded JSON rejects ${name}`,async()=>assert.equal((await check('parse',text)).parsed,false));
for(const [name,change] of Object.entries({generation:r=>{r.filterReplacement.generation='7e408244-d338-43f8-b847-19caa2c32f40';},committed:r=>{r.filterReplacement.state='committed';},uncertain:r=>{r.filterReplacement.state='uncertain';},extraIntent:r=>{r.filterReplacement.retry=true;},rootHookRemoved:r=>{r.rootHook.removed=true;},removedString:r=>{r.rootHook.removed='false';},missingRetired:r=>{delete r.rootHook.receiptRetired;},retired:r=>{r.rootHook.receiptRetired=true;},leaseMismatch:r=>{r.rootHook.lease.token='FOREIGN';},supervisor:r=>{r.supervisorPid=8;},priorRevision:r=>{r.filterReplacement.previous.filterRevision='0';},nextGID:r=>{r.filterReplacement.next.realms[0].gid=7998;}}))test(`sealed record refuses ${name}`,async()=>{const p=request(),r=record(p);change(r);assert.equal((await check('record',p,r)).record,false);});
test('uint32 revision zero is an exact committed receipt, never an unknown ticket',async()=>{const p=request();p.previous.writerPid=42;p.previous.filterRevision='0';assert.equal((await check('parse',p)).parsed,true);const result=await check('emit-ack-zero',p);assert.equal(result.filterRevision,'0');assert.equal(result.writerPid,42);assert.equal(result.readOnly,false);assert.equal(result.productionReady,false);});
test('unknown BEGIN retains attempted/uncertain and public error filters private payload',async()=>{const p=request();const value=await check('emit-unknown-begin',p);assert.equal(value.replacementAttempted,true);assert.equal(value.replacementUncertain,true);assert.equal(value.readOnly,false);assert.doesNotMatch(JSON.stringify(value),/INERT_ONLY_PRIVATE_LEASE/);p.runId='PRIVATE_SECRET';const invalid=await check('emit-unknown-begin',p);assert.equal(invalid.runId,'');assert.doesNotMatch(JSON.stringify(invalid),/PRIVATE_SECRET/);});
for(const name of ['bytes','file','directory'])test(`held registry rejects changed ${name}`,async()=>{const f=await fixture();await rm(f.runtime,{recursive:true,force:true});await rm(`${f.runtime}-old`,{recursive:true,force:true});await mkdir(f.runtime,{mode:0o700});await writeFile(path.join(f.runtime,'registry.json'),'{}',{mode:0o600});assert.deepEqual(await check(`identity-${name}`,request()),{before:true,after:false});});
for(const name of ['parent','deadline','signal'])test(`writer refuses ended ${name} before any lease/PF read`,async()=>assert.deepEqual(await check(`guard-${name}`,request()),{accepted:false}));
