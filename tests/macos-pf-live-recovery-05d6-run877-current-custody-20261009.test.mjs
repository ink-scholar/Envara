import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import { tmpdir } from 'node:os';

const exec = promisify(execFile);
const root = path.resolve(import.meta.dirname, '..');
const native = path.join(root, 'native/macos-pf-routing');
const flags = ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function'];

test('fixed 05d6/run877 current FRONT5 constructor matches installed native readback; strict group and port predicates refuse unknowns', async () => {
  assert.notEqual(process.getuid(), 0);
  const dir = await mkdtemp(path.join(tmpdir(), 'envara-r877c-recovery-constructors-'));
  try {
    const source = `
#define R877C_RECOVERY_INERT 1
#include "${path.join(native, 'recovery-app-05d6-run877-current-custody-20261009.m')}"
#include "${path.join(native, 'pf-production-filter.c')}"
#include <assert.h>
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);
 R877CContext c={.gid=7100,.lease=@{@"realmId":@"73e9d9b3-6b9c-435b-8f64-8305e5a60859"},.transport=@{@"frontPort":@54321}};
 EnvaraPFProductionConfig cfg={.gid=7100,.listener_fd=9,.tcp_front_port=54321};
 strcpy(cfg.run_id,CANARY_RUN.UTF8String);strcpy(cfg.realm_id,[c.lease[@"realmId"]UTF8String]);strcpy(cfg.utun,"utun6");cfg.route_ipv4[0]=198;cfg.route_ipv4[1]=18;cfg.route_ipv4[2]=1;cfg.route_ipv4[3]=1;
 ProductionPlan plan;assert(production_plan(&cfg,ENVARA_PF_PRODUCTION_FRONT,&plan)&&plan.count==5);
 for(uint32_t i=0;i<5;i++){EnvaraPFHookRule actual=production_readback_rule(&plan,i,0,R877C_KEEPER_PID),wanted=r877cFrontRule(&c,i);assert(!memcmp(&actual,&wanted,sizeof(actual)));assert(!actual.keep_state);assert(actual.uid_op==(i==3?2:0));assert(actual.gid_op==((i==0||i==2||i==3)?2:0));
 EnvaraPFHookRequest got={0};strcpy(got.anchor,CANARY_ANCHOR.UTF8String);got.ticket=2;got.nr=i;got.rule=actual;assert(r877cFrontRowMatches(&c,2,i,&got));
 EnvaraPFHookRequest bad=got;bad.rule.gid[0]++;assert(!r877cFrontRowMatches(&c,2,i,&bad));bad=got;bad.rule.dst[48]++;assert(!r877cFrontRowMatches(&c,2,i,&bad));
 bad=got;bad.rule.uid_op++;assert(!r877cFrontRowMatches(&c,2,i,&bad));bad=got;bad.rule.keep_state=1;assert(!r877cFrontRowMatches(&c,2,i,&bad));
 bad=got;bad.rule.skip[0]++;assert(!r877cFrontRowMatches(&c,2,i,&bad));bad=got;bad.ticket=3;assert(!r877cFrontRowMatches(&c,2,i,&bad));
 bad=got;bad.nr=6;assert(!r877cFrontRowMatches(&c,2,i,&bad));bad=got;bad.anchor[0]='x';assert(!r877cFrontRowMatches(&c,2,i,&bad));
 bad=got;((uint8_t*)&bad.rule)[960]++;assert(!r877cFrontRowMatches(&c,2,i,&bad));bad=got;memset((uint8_t*)&bad.rule+648,255,40);assert(r877cFrontRowMatches(&c,2,i,&bad));
 assert(!r877cFrontRowMatches(&c,3,i,&got));assert(!r877cFrontRowMatches(&c,2,5,&got));}
 NSString*base=@"root 0\\nnobody -2\\nnogroup -1\\nwheel 0\\nstaff 20\\n";
 assert(r877cNegativeGroups(base,7100));assert(!r877cNegativeGroups([base stringByAppendingString:@"_envara_pf_7100 7100\\n"],7100));
 assert(!r877cNegativeGroups([base stringByAppendingString:@"foreign 7100\\n"],7100));
 assert(!r877cNegativeGroups([base stringByAppendingString:@"invalid -2147483649\\n"],7100));
 assert(!r877cNegativeGroups([base stringByAppendingString:@"invalid 4294967296\\n"],7100));
 assert(!r877cNegativeGroups([base stringByAppendingString:@"invalid -4294960196\\n"],7100));
 assert(!r877cNegativeGroups([base stringByAppendingString:@"invalid 01\\n"],7100));
 assert(!r877cNegativeGroups([base stringByAppendingString:@"root 0\\n"],7100));
 assert(r877cGroupRows([base stringByAppendingString:@"_envara_pf_7100 7100\\n"],7100,true));
 assert(!r877cGroupRows(base,7100,true));assert(!r877cGroupRows([base stringByAppendingString:@"_envara_pf_7100 7101\\n"],7100,true));
 assert(!r877cGroupRows([base stringByAppendingString:@"_envara_pf_7100 7100\\nforeign 7100\\n"],7100,true));
 NSString*head=@"Active Internet connections (including servers)\\nProto Recv-Q Send-Q Local Address Foreign Address (state)\\n";
 assert(r877cPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\n"],54321,true));
 assert(!r877cPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\n"],54321,false));
 assert(!r877cPortRows([head stringByAppendingString:@"tcp4 0 0 *.54321 *.* LISTEN\\n"],54321,false));
 assert(r877cPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 127.0.0.1.43210 TIME_WAIT\\n"],54321,false));
 assert(r877cPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54320 *.* LISTEN\\n"],54321,false));
 /* Apple netstat.tproj/inet.c prints dualstack IPv4 tuples as tcp46 and
  * appends verbose socket statistics after the fixed six leading columns. */
 assert(r877cPortRows([head stringByAppendingString:@"tcp46 0 0 *.54321 *.* LISTEN 131072 131072 0 0 0x00000 0x00000000\\n"],54321,true));
 assert(!r877cPortRows([head stringByAppendingString:@"tcp46 0 0 *.54321 *.* LISTEN\\n"],54321,false));
 assert(!r877cPortRows([head stringByAppendingString:@"tcp4 0 0 999.0.0.1.54321 *.* LISTEN\\n"],54321,false));
 assert(!r877cPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.65536 *.* LISTEN\\n"],54321,false));
 assert(!r877cPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 unknown.service LISTEN\\n"],54321,false));
 assert(!r877cPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\nSome tcp sockets may have been created.\\n"],54321,false));
 assert(!r877cPortRows([head stringByAppendingString:head],54321,false));
 assert(!r877cPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* UNKNOWN\\n"],54321,false));
 assert(!r877cPortRows([head stringByAppendingString:@"tcp6 0 0 ::1.54321 *.* LISTEN\\n"],54321,false));
 assert(!r877cPortRows(@"",54321,false));assert(!r877cPortRows(@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\n",54321,false));
 NSMutableDictionary*out=r877cOutcome(false);assert(CFGetTypeID((__bridge CFTypeRef)out[@"readOnly"])==CFBooleanGetTypeID());
 for(NSString*k in @[@"cleanupConfirmed",@"originalApplicationHostBaselineVerified",@"ready",@"protected",@"productionReady",@"fullGuardFailureAccepted",@"originalDescriptorCustodyVerified"]){assert(CFGetTypeID((__bridge CFTypeRef)out[k])==CFBooleanGetTypeID()&&![out[k]boolValue]);}
 puts("actual-FRONT5-parity-and-strict-predicates");return 0;
}}`;
    await writeFile(path.join(dir, 'fixture.m'), source);
    await exec('/usr/bin/clang', [...flags, path.join(dir, 'fixture.m'), path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', path.join(dir, 'fixture')], { timeout: 30000 });
    const result = await exec(path.join(dir, 'fixture'), [], { timeout: 10000 });
    assert.match(result.stdout, /actual-FRONT5-parity-and-strict-predicates/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('actual one-FILTER clear function binds ticket and namespace, never retries and never rolls back after COMMIT attempt', async () => {
  assert.notEqual(process.getuid(), 0);
  const dir = await mkdtemp(path.join(tmpdir(), 'envara-r877c-recovery-one-filter-'));
  try {
    const source = `
#define R877C_RECOVERY_INERT 1
#include "${path.join(native, 'recovery-app-05d6-run877-current-custody-20261009.m')}"
#include <assert.h>
static int scenario,operations,begin_count,commit_count,rollback_count;
static bool guard(R877CContext*c,unsigned phase){(void)c;return scenario!=1&&(phase!=1||scenario!=8);}
static int opener(void){return scenario==2?-1:open("/dev/null",O_RDWR|O_CLOEXEC);}
static bool readback(R877CContext*c){(void)c;return scenario!=11;}
static int fakeIoctl(int fd,unsigned long operation,void*argument){assert(fd>=0);R877CTransaction*t=argument;assert(t->size==1&&t->esize==sizeof(R877CEntry)&&t->array);R877CEntry*e=t->array;assert(e->rs_num==1&&!strcmp(e->anchor,CANARY_ANCHOR.UTF8String));operations++;
 if(operation==R877C_BEGIN){begin_count++;assert(e->ticket==0);e->ticket=71;
  if(scenario==3){errno=EIO;return -1;}if(scenario==4)e->ticket=0;if(scenario==5)strcpy(e->anchor,"foreign.anchor");if(scenario==6)t->esize=1;if(scenario==7)t->array=(R877CEntry*)1;return 0;}
 assert(e->ticket==71);
 if(operation==R877C_COMMIT){commit_count++;if(scenario==9){errno=EIO;return -1;}if(scenario==10)e->ticket=72;return 0;}
 assert(operation==R877C_ROLLBACK);rollback_count++;return 0;
}
int main(void){@autoreleasepool{assert(getuid()!=0&&geteuid()!=0);
 r877c_test_clear_guard=guard;r877c_test_write_open=opener;r877c_test_transaction_ioctl=fakeIoctl;r877c_test_empty_readback=readback;
 for(scenario=0;scenario<12;scenario++){operations=begin_count=commit_count=rollback_count=0;R877CContext c={0};NSMutableDictionary*out=r877cOutcome(true);
  bool result=r877cClearOnce(&c,out);assert(result==(scenario==0));
  if(scenario==1||scenario==2)assert(operations==0);else assert(begin_count==1);
  if(scenario>=3&&scenario<=7)assert(commit_count==0&&rollback_count==0);
  if(scenario==8)assert(commit_count==0&&rollback_count==1);
  if(scenario==0||scenario>=9)assert(commit_count==1&&rollback_count==0);
  int saved=operations;assert(!r877cClearOnce(&c,out));assert(operations==saved);
  for(NSString*k in @[@"cleanupConfirmed",@"ownedFilterEmptyVerified",@"namespaceReclaimed",@"ownedPFReferenceReleased",@"rootHookRemoved",@"ready",@"protected"]){assert(![out[k]boolValue]);}
 }
 assert(r877cTransactionIoctl(-1,0xc4704433UL,NULL)==-1); /* no BEGINADDRS */
 puts("12-owned-transaction-fault-cases-no-retry");return 0;
}}`;
    await writeFile(path.join(dir, 'fixture.m'), source);
    await exec('/usr/bin/clang', [...flags, path.join(dir, 'fixture.m'), path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', path.join(dir, 'fixture')], { timeout: 30000 });
    const result = await exec(path.join(dir, 'fixture'), [], { timeout: 10000 });
    assert.match(result.stdout, /12-owned-transaction-fault-cases-no-retry/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('current two-FD custody predicate requires exactly one identical nonzero socket and refuses foreign aliases',async()=>{
 assert.notEqual(process.getuid(),0);const dir=await mkdtemp(path.join(tmpdir(),'envara-run877-current-aliases-'));
 try{const source=`
#define R877C_RECOVERY_INERT 1
#include "${path.join(native,'recovery-app-05d6-run877-current-custody-20261009.m')}"
#include <assert.h>
int main(void){@autoreleasepool{
 R877CContext c={.transport=@{@"interfaceName":@"utun6"}};
 R877CSocketIdentity sockets[3]={{.fd=5,.socket=123,.pcb=456,.kind=SOCKINFO_KERN_CTL,.family=AF_SYSTEM,.type=SOCK_DGRAM,.ctl_id=2,.ctl_unit=7},
 {.fd=15,.socket=123,.pcb=456,.kind=SOCKINFO_KERN_CTL,.family=AF_SYSTEM,.type=SOCK_DGRAM,.ctl_id=2,.ctl_unit=7}};
 strcpy(sockets[0].ctl_name,"com.apple.net.utun_control");strcpy(sockets[1].ctl_name,"com.apple.net.utun_control");
 R877CFDPass p={.sockets=sockets,.socket_count=2,.utun_count=2};assert(r877cSameUTunObject(&p,&c));
 sockets[1].socket++;assert(!r877cSameUTunObject(&p,&c));sockets[1].socket--;
 sockets[1].pcb++;assert(!r877cSameUTunObject(&p,&c));sockets[1].pcb--;
 sockets[1].ctl_id++;assert(!r877cSameUTunObject(&p,&c));sockets[1].ctl_id--;
 sockets[1].ctl_unit++;assert(!r877cSameUTunObject(&p,&c));sockets[1].ctl_unit--;
 sockets[1].gid=7100;assert(!r877cSameUTunObject(&p,&c));sockets[1].gid=0;
 sockets[1].type=SOCK_STREAM;assert(!r877cSameUTunObject(&p,&c));sockets[1].type=SOCK_DGRAM;
 sockets[0].socket=sockets[1].socket=0;assert(!r877cSameUTunObject(&p,&c));sockets[0].socket=sockets[1].socket=123;
 p.utun_count=1;assert(!r877cSameUTunObject(&p,&c));p.utun_count=2;
 sockets[2]=sockets[1];sockets[2].fd=16;p.socket_count=3;assert(!r877cSameUTunObject(&p,&c));
 p.socket_count=2;assert(r877cSameUTunObject(&p,&c));
 puts("same-object-two-descriptors-strict-negative-metadata");return 0;
}}
`;await writeFile(path.join(dir,'fixture.m'),source);await exec('/usr/bin/clang',[...flags,path.join(dir,'fixture.m'),path.join(native,'app-scope-proof.c'),'-framework','Foundation','-framework','Security','-o',path.join(dir,'fixture')],{timeout:30000});
 assert.match((await exec(path.join(dir,'fixture'),[],{timeout:10000})).stdout,/same-object-two-descriptors/);
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('fixed current-custody executable has inert plan and refuses nonroot recovery without authorizing',async()=>{
 assert.notEqual(process.getuid(),0);const dir=await mkdtemp(path.join(tmpdir(),'envara-run877-current-nonroot-'));
 try{const binary=path.join(dir,'FixedCurrentRecovery');await exec('/usr/bin/clang',[...flags,path.join(native,'recovery-app-05d6-run877-current-custody-20261009.m'),path.join(native,'app-scope-proof.c'),'-framework','Foundation','-framework','Security','-o',binary],{timeout:30000});
 const plan=JSON.parse((await exec(binary,['--plan'],{timeout:10000})).stdout);assert.equal(plan.runId,'877ab9cc-ed91-4f2d-a8cd-86cedc2f3e21');assert.equal(plan.manifestSHA256,'05d6eb6ab3d63870d37825b47e2847789a6b5b8c3cf93c434636e0b8aad4f061');assert.equal(plan.ok,true);
 for(const key of ['cleanupConfirmed','ready','protected','productionReady','ownedDenialVerified','ownedFrontVerified','coreStopped','coreTerminateAttempted','coreTerminatedObserved','coreReapedByRecovery','frontZombieBound','coreFinalAbsent','frontFinalAbsent','currentUTunAliasCustodyVerified'])assert.equal(plan[key],false);
 for(const args of [['--inspect-fixed-root'],['--cleanup-fixed-root'],['--cleanup-fixed-root','/foreign'],['--request-cleanup']]){const result=await exec(binary,args,{timeout:10000}).catch(error=>error);assert.equal(result.code,1);const proof=JSON.parse(result.stdout);assert.equal(proof.cleanupConfirmed,false);assert.equal(proof.cleanupUncertain,true);for(const key of ['coreStopped','coreTerminateAttempted','ownedFilterClearAttempted','ownedPFReferenceReleaseAttempted','rootHookDeleteAttempted','ownedGroupDeleteAttempted','runtimeArchived'])assert.equal(proof[key],false);}
 const source=await readFile(path.join(native,'recovery-app-05d6-run877-current-custody-20261009.m'),'utf8');assert.doesNotMatch(source,/kill\(15545/);assert.doesNotMatch(source,/AuthorizationCopyRights|AuthorizationExecuteWithPrivileges/);assert.match(source,/@"coreReapedByRecovery":@NO/);
 }finally{await rm(dir,{recursive:true,force:true});}
});
