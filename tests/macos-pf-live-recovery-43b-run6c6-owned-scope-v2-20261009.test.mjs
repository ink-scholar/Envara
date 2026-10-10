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

test('fixed 43b/run6c6 current FRONT5 constructor matches installed native readback; strict group and port predicates refuse unknowns', async () => {
  assert.notEqual(process.getuid(), 0);
  const dir = await mkdtemp(path.join(tmpdir(), 'envara-r5bes-recovery-constructors-'));
  try {
    const source = `
#define R5BES_RECOVERY_INERT 1
#include "${path.join(native, 'recovery-app-43b-run6c6-owned-scope-v2-20261009.m')}"
#include "${path.join(native, 'pf-production-filter.c')}"
#include <assert.h>
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);
 R5BESContext c={.gid=7100,.lease=@{@"realmId":@"73e9d9b3-6b9c-435b-8f64-8305e5a60859"},.transport=@{@"frontPort":@54321}};
 EnvaraPFProductionConfig cfg={.gid=7100,.listener_fd=9,.tcp_front_port=54321};
 strcpy(cfg.run_id,CANARY_RUN.UTF8String);strcpy(cfg.realm_id,[c.lease[@"realmId"]UTF8String]);strcpy(cfg.utun,"utun6");cfg.route_ipv4[0]=198;cfg.route_ipv4[1]=18;cfg.route_ipv4[2]=1;cfg.route_ipv4[3]=1;
 ProductionPlan plan;assert(production_plan(&cfg,ENVARA_PF_PRODUCTION_FRONT,&plan)&&plan.count==5);
 for(uint32_t i=0;i<5;i++){EnvaraPFHookRule actual=production_readback_rule(&plan,i,0,R5BES_KEEPER_PID),wanted=r5besFrontRule(&c,i);assert(!memcmp(&actual,&wanted,sizeof(actual)));assert(!actual.keep_state);assert(actual.uid_op==(i==3?2:0));assert(actual.gid_op==((i==0||i==2||i==3)?2:0));
 EnvaraPFHookRequest got={0};strcpy(got.anchor,CANARY_ANCHOR.UTF8String);got.ticket=2;got.nr=i;got.rule=actual;assert(r5besFrontRowMatches(&c,2,i,&got));
 EnvaraPFHookRequest bad=got;bad.rule.gid[0]++;assert(!r5besFrontRowMatches(&c,2,i,&bad));bad=got;bad.rule.dst[48]++;assert(!r5besFrontRowMatches(&c,2,i,&bad));
 bad=got;bad.rule.uid_op++;assert(!r5besFrontRowMatches(&c,2,i,&bad));bad=got;bad.rule.keep_state=1;assert(!r5besFrontRowMatches(&c,2,i,&bad));
 bad=got;bad.rule.skip[0]++;assert(!r5besFrontRowMatches(&c,2,i,&bad));bad=got;bad.ticket=3;assert(!r5besFrontRowMatches(&c,2,i,&bad));
 bad=got;bad.nr=6;assert(!r5besFrontRowMatches(&c,2,i,&bad));bad=got;bad.anchor[0]='x';assert(!r5besFrontRowMatches(&c,2,i,&bad));
 bad=got;((uint8_t*)&bad.rule)[960]++;assert(!r5besFrontRowMatches(&c,2,i,&bad));bad=got;memset((uint8_t*)&bad.rule+648,255,40);assert(r5besFrontRowMatches(&c,2,i,&bad));
 assert(!r5besFrontRowMatches(&c,3,i,&got));assert(!r5besFrontRowMatches(&c,2,5,&got));}
 NSString*base=@"root 0\\nnobody -2\\nnogroup -1\\nwheel 0\\nstaff 20\\n";
 assert(r5besNegativeGroups(base,7100));assert(!r5besNegativeGroups([base stringByAppendingString:@"_envara_pf_7100 7100\\n"],7100));
 assert(!r5besNegativeGroups([base stringByAppendingString:@"foreign 7100\\n"],7100));
 assert(!r5besNegativeGroups([base stringByAppendingString:@"invalid -2147483649\\n"],7100));
 assert(!r5besNegativeGroups([base stringByAppendingString:@"invalid 4294967296\\n"],7100));
 assert(!r5besNegativeGroups([base stringByAppendingString:@"invalid -4294960196\\n"],7100));
 assert(!r5besNegativeGroups([base stringByAppendingString:@"invalid 01\\n"],7100));
 assert(!r5besNegativeGroups([base stringByAppendingString:@"root 0\\n"],7100));
 assert(r5besGroupRows([base stringByAppendingString:@"_envara_pf_7100 7100\\n"],7100,true));
 assert(!r5besGroupRows(base,7100,true));assert(!r5besGroupRows([base stringByAppendingString:@"_envara_pf_7100 7101\\n"],7100,true));
 assert(!r5besGroupRows([base stringByAppendingString:@"_envara_pf_7100 7100\\nforeign 7100\\n"],7100,true));
 NSString*head=@"Active Internet connections (including servers)\\nProto Recv-Q Send-Q Local Address Foreign Address (state)\\n";
 assert(r5besPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\n"],54321,true));
 assert(!r5besPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\n"],54321,false));
 assert(!r5besPortRows([head stringByAppendingString:@"tcp4 0 0 *.54321 *.* LISTEN\\n"],54321,false));
 assert(r5besPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 127.0.0.1.43210 TIME_WAIT\\n"],54321,false));
 assert(r5besPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54320 *.* LISTEN\\n"],54321,false));
 /* Apple netstat.tproj/inet.c prints dualstack IPv4 tuples as tcp46 and
  * appends verbose socket statistics after the fixed six leading columns. */
 assert(r5besPortRows([head stringByAppendingString:@"tcp46 0 0 *.54321 *.* LISTEN 131072 131072 0 0 0x00000 0x00000000\\n"],54321,true));
 assert(!r5besPortRows([head stringByAppendingString:@"tcp46 0 0 *.54321 *.* LISTEN\\n"],54321,false));
 assert(!r5besPortRows([head stringByAppendingString:@"tcp4 0 0 999.0.0.1.54321 *.* LISTEN\\n"],54321,false));
 assert(!r5besPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.65536 *.* LISTEN\\n"],54321,false));
 assert(!r5besPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 unknown.service LISTEN\\n"],54321,false));
 assert(!r5besPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\nSome tcp sockets may have been created.\\n"],54321,false));
 assert(!r5besPortRows([head stringByAppendingString:head],54321,false));
 assert(!r5besPortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* UNKNOWN\\n"],54321,false));
 assert(!r5besPortRows([head stringByAppendingString:@"tcp6 0 0 ::1.54321 *.* LISTEN\\n"],54321,false));
 assert(!r5besPortRows(@"",54321,false));assert(!r5besPortRows(@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\n",54321,false));
 NSMutableDictionary*out=r5besOutcome(false);assert(CFGetTypeID((__bridge CFTypeRef)out[@"readOnly"])==CFBooleanGetTypeID());
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
  const dir = await mkdtemp(path.join(tmpdir(), 'envara-r5bes-recovery-one-filter-'));
  try {
    const source = `
#define R5BES_RECOVERY_INERT 1
#include "${path.join(native, 'recovery-app-43b-run6c6-owned-scope-v2-20261009.m')}"
#include <assert.h>
static int scenario,operations,begin_count,commit_count,rollback_count;
static bool guard(R5BESContext*c,unsigned phase){(void)c;return scenario!=1&&(phase!=1||scenario!=8);}
static int opener(void){return scenario==2?-1:open("/dev/null",O_RDWR|O_CLOEXEC);}
static bool readback(R5BESContext*c){(void)c;return scenario!=11;}
static int fakeIoctl(int fd,unsigned long operation,void*argument){assert(fd>=0);R5BESTransaction*t=argument;assert(t->size==1&&t->esize==sizeof(R5BESEntry)&&t->array);R5BESEntry*e=t->array;assert(e->rs_num==1&&!strcmp(e->anchor,CANARY_ANCHOR.UTF8String));operations++;
 if(operation==R5BES_BEGIN){begin_count++;assert(e->ticket==0);e->ticket=71;
  if(scenario==3){errno=EIO;return -1;}if(scenario==4)e->ticket=0;if(scenario==5)strcpy(e->anchor,"foreign.anchor");if(scenario==6)t->esize=1;if(scenario==7)t->array=(R5BESEntry*)1;return 0;}
 assert(e->ticket==71);
 if(operation==R5BES_COMMIT){commit_count++;if(scenario==9){errno=EIO;return -1;}if(scenario==10)e->ticket=72;return 0;}
 assert(operation==R5BES_ROLLBACK);rollback_count++;return 0;
}
int main(void){@autoreleasepool{assert(getuid()!=0&&geteuid()!=0);
 r5bes_test_clear_guard=guard;r5bes_test_write_open=opener;r5bes_test_transaction_ioctl=fakeIoctl;r5bes_test_empty_readback=readback;
 for(scenario=0;scenario<12;scenario++){operations=begin_count=commit_count=rollback_count=0;R5BESContext c={0};NSMutableDictionary*out=r5besOutcome(true);
  bool result=r5besClearOnce(&c,out);assert(result==(scenario==0));
  if(scenario==1||scenario==2)assert(operations==0);else assert(begin_count==1);
  if(scenario>=3&&scenario<=7)assert(commit_count==0&&rollback_count==0);
  if(scenario==8)assert(commit_count==0&&rollback_count==1);
  if(scenario==0||scenario>=9)assert(commit_count==1&&rollback_count==0);
  int saved=operations;assert(!r5besClearOnce(&c,out));assert(operations==saved);
  for(NSString*k in @[@"cleanupConfirmed",@"ownedFilterEmptyVerified",@"namespaceReclaimed",@"ownedPFReferenceReleased",@"rootHookRemoved",@"ready",@"protected"]){assert(![out[k]boolValue]);}
 }
 assert(r5besTransactionIoctl(-1,0xc4704433UL,NULL)==-1); /* no BEGINADDRS */
 puts("12-owned-transaction-fault-cases-no-retry");return 0;
}}`;
    await writeFile(path.join(dir, 'fixture.m'), source);
    await exec('/usr/bin/clang', [...flags, path.join(dir, 'fixture.m'), path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', path.join(dir, 'fixture')], { timeout: 30000 });
    const result = await exec(path.join(dir, 'fixture'), [], { timeout: 10000 });
    assert.match(result.stdout, /12-owned-transaction-fault-cases-no-retry/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('current three-FD custody predicate requires exactly one identical nonzero socket and refuses foreign aliases',async()=>{
 assert.notEqual(process.getuid(),0);const dir=await mkdtemp(path.join(tmpdir(),'envara-run6c6-current-aliases-'));
 try{const source=`
#define R5BES_RECOVERY_INERT 1
#include "${path.join(native,'recovery-app-43b-run6c6-owned-scope-v2-20261009.m')}"
#include <assert.h>
int main(void){@autoreleasepool{
 R5BESContext c={.transport=@{@"interfaceName":@"utun6"}};
 R5BESSocketIdentity sockets[4]={{.fd=5,.socket=123,.pcb=456,.kind=SOCKINFO_KERN_CTL,.family=AF_SYSTEM,.type=SOCK_DGRAM,.ctl_id=2,.ctl_unit=7},
 {.fd=15,.socket=123,.pcb=456,.kind=SOCKINFO_KERN_CTL,.family=AF_SYSTEM,.type=SOCK_DGRAM,.ctl_id=2,.ctl_unit=7}};
 strcpy(sockets[0].ctl_name,"com.apple.net.utun_control");strcpy(sockets[1].ctl_name,"com.apple.net.utun_control");sockets[2]=sockets[1];sockets[2].fd=16;
 R5BESFDPass p={.sockets=sockets,.socket_count=3,.utun_count=3};assert(r5besSameUTunObject(&p,&c));
 sockets[1].socket++;assert(!r5besSameUTunObject(&p,&c));sockets[1].socket--;
 sockets[1].pcb++;assert(!r5besSameUTunObject(&p,&c));sockets[1].pcb--;
 sockets[1].ctl_id++;assert(!r5besSameUTunObject(&p,&c));sockets[1].ctl_id--;
 sockets[1].ctl_unit++;assert(!r5besSameUTunObject(&p,&c));sockets[1].ctl_unit--;
 sockets[1].gid=7100;assert(!r5besSameUTunObject(&p,&c));sockets[1].gid=0;
 sockets[1].type=SOCK_STREAM;assert(!r5besSameUTunObject(&p,&c));sockets[1].type=SOCK_DGRAM;
 sockets[0].socket=sockets[1].socket=0;assert(!r5besSameUTunObject(&p,&c));sockets[0].socket=sockets[1].socket=123;
 p.utun_count=1;assert(!r5besSameUTunObject(&p,&c));p.utun_count=3;
 sockets[3]=sockets[1];sockets[3].fd=17;p.socket_count=4;assert(!r5besSameUTunObject(&p,&c));
 p.socket_count=3;assert(r5besSameUTunObject(&p,&c));
 puts("same-object-three-descriptors-strict-negative-metadata");return 0;
}}
`;await writeFile(path.join(dir,'fixture.m'),source);await exec('/usr/bin/clang',[...flags,path.join(dir,'fixture.m'),path.join(native,'app-scope-proof.c'),'-framework','Foundation','-framework','Security','-o',path.join(dir,'fixture')],{timeout:30000});
 assert.match((await exec(path.join(dir,'fixture'),[],{timeout:10000})).stdout,/same-object-three-descriptors/);
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('state archival preserves exactly the observed configuration, refuses unsafe metadata, and nonroot recovery cannot mutate',async()=>{
 assert.notEqual(process.getuid(),0);const dir=await mkdtemp(path.join(tmpdir(),'envara-run6c6-state-archive-predicates-'));
 try{const file=path.join(dir,'fixture.m'),binary=path.join(dir,'StateArchiveFixture');
 await writeFile(file,`#define R5BES_RECOVERY_INERT 1\n#include "${path.join(native,'recovery-app-43b-run6c6-owned-scope-v2-20261009.m')}"\n#include <assert.h>\nint main(void){@autoreleasepool{struct stat s={.st_mode=S_IFREG|0600,.st_uid=0,.st_gid=0,.st_nlink=1,.st_size=4096};assert(r5besStateMetadata(&s,65536));struct stat bad=s;bad.st_mode=S_IFREG|0644;assert(!r5besStateMetadata(&bad,65536));bad=s;bad.st_uid=501;assert(!r5besStateMetadata(&bad,65536));bad=s;bad.st_gid=20;assert(!r5besStateMetadata(&bad,65536));bad=s;bad.st_nlink=2;assert(!r5besStateMetadata(&bad,65536));bad=s;bad.st_mode=S_IFLNK|0600;assert(!r5besStateMetadata(&bad,65536));bad=s;bad.st_size=0;assert(!r5besStateMetadata(&bad,65536));bad=s;bad.st_size=65537;assert(!r5besStateMetadata(&bad,65536));assert(!r5besStateMetadata(NULL,65536));NSDictionary*d=r5besOutcome(false);assert(d.count==54);assert(![d[@"cleanupConfirmed"]boolValue]);assert([d[@"cleanupUncertain"]boolValue]);return 0;}}\n`);
 await exec('/usr/bin/clang',[...flags,file,path.join(native,'app-scope-proof.c'),'-framework','Foundation','-framework','Security','-o',binary],{timeout:30000});await exec(binary,[],{timeout:10000});
 const productionBinary=path.join(dir,'ActualStateRecovery');await exec('/usr/bin/clang',[...flags,path.join(native,'recovery-app-43b-run6c6-owned-scope-v2-20261009.m'),path.join(native,'app-scope-proof.c'),'-framework','Foundation','-framework','Security','-o',productionBinary],{timeout:30000});
 const plan=JSON.parse((await exec(productionBinary,['--plan'],{timeout:10000})).stdout);assert.equal(plan.ok,true);assert.equal(plan.mutationEntryLinked,true);
 for(const args of [['--inspect-fixed-root'],['--cleanup-fixed-root'],['--cleanup-fixed-root','/foreign'],['--request-cleanup']]){const result=await exec(productionBinary,args,{timeout:10000}).catch(error=>error);assert.equal(result.code,1);const proof=JSON.parse(result.stdout);assert.equal(proof.cleanupConfirmed,false);assert.equal(proof.cleanupUncertain,true);for(const key of ['coreStopped','coreTerminateAttempted','ownedFilterClearAttempted','ownedPFReferenceReleaseAttempted','rootHookDeleteAttempted','ownedGroupDeleteAttempted','runtimeArchived'])assert.equal(proof[key],false);}
 const source=await readFile(path.join(native,'recovery-app-43b-run6c6-owned-scope-v2-20261009.m'),'utf8');assert.doesNotMatch(source,/names\(c->state,@\[\]\)/);assert.match(source,/names\(c->state,@\[@"transport-config.json"\]\)/);assert.match(source,/absent\(c->state,"cache.db"\)/);assert.doesNotMatch(source,/unlinkat\(c->state/);assert.match(source,/renameatx_np\(c->parent,"io.envara.pf-runtime",cap,"runtime",RENAME_EXCL\)/);assert.doesNotMatch(source,/kill\(88331/);assert.doesNotMatch(source,/AuthorizationCopyRights|AuthorizationExecuteWithPrivileges/);
 }finally{await rm(dir,{recursive:true,force:true});}
});


test('host volatility cannot waive any owned retirement or fresh retired native status fact',async()=>{
 assert.notEqual(process.getuid(),0);const dir=await mkdtemp(path.join(tmpdir(),'envara-run6c6-owned-host-observation-'));
 try{const file=path.join(dir,'fixture.m'),binary=path.join(dir,'OwnedHostFixture');
 await writeFile(file,`#define R5BES_RECOVERY_INERT 1
#include "${path.join(native,'recovery-app-43b-run6c6-owned-scope-v2-20261009.m')}"
#include <assert.h>
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);
 NSString*a=@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
 NSString*b=@"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
 NSDictionary*before=@{@"routes":a,@"dns":a,@"nat":a,@"pfconf":a},*after=@{@"routes":b,@"dns":a,@"nat":a,@"pfconf":a};
 NSDictionary*comparison=r5besCompareHost(before,after);assert(comparison&&comparison.count==4);
 assert(CFGetTypeID((__bridge CFTypeRef)comparison[@"routes"])==CFBooleanGetTypeID()&&![comparison[@"routes"]boolValue]);
 for(NSString*k in @[@"dns",@"nat",@"pfconf"])assert([comparison[k]boolValue]);
 assert(!r5besCompareHost(before,@{@"routes":@"unknown",@"dns":a,@"nat":a,@"pfconf":a}));
 assert(!r5besCompareHost(before,@{@"routes":a,@"dns":a,@"nat":a}));
 assert(!r5besCompareHost(before,@{@"routes":a,@"dns":a,@"nat":a,@"pfconf":a,@"extra":a}));
 NSMutableDictionary*out=r5besOutcome(true);
 NSArray*mandatory=@[@"ownedGIDScopeAbsent",@"ownedFilterEmptyVerified",@"keeperExitObserved",@"controllerExitObserved",@"ownedInterfaceAbsent",@"ownedListenerAbsent",@"ownedPFReferenceReleased",@"rootHookRemoved",@"originalRootRestored",@"receiptRetired",@"namespaceReclaimed",@"ownedGroupRemoved",@"coreFinalAbsent",@"frontFinalAbsent"];
 for(NSString*k in mandatory)out[k]=@YES;
 out[@"hostComparisonAvailable"]=@YES;out[@"hostSnapshotsMatched"]=@NO;out[@"recoveryScopeHostNetworkRestored"]=@NO;
 assert(r5besOwnedRetirementFacts(out)); /* Valid difference never fabricates equality. */
 for(NSString*k in mandatory){out[k]=@NO;assert(!r5besOwnedRetirementFacts(out));out[k]=@YES;}
 for(NSString*k in @[@"ready",@"protected",@"productionReady",@"fullGuardFailureAccepted",@"ownedDenialVerified",@"originalDescriptorCustodyVerified",@"coreReapedByRecovery",@"globalFlushExecuted",@"PFEnableExecuted",@"globalPoolResetExecuted",@"applicationLaunchExecuted"]){out[k]=@YES;assert(!r5besOwnedRetirementFacts(out));out[k]=@NO;}
 out[@"hostSnapshotsMatched"]=@YES;assert(!r5besOwnedRetirementFacts(out));out[@"recoveryScopeHostNetworkRestored"]=@YES;assert(r5besOwnedRetirementFacts(out));
 out[@"hostSnapshotsMatched"]=@1;assert(!r5besOwnedRetirementFacts(out));out[@"hostSnapshotsMatched"]=@YES;
 out[@"originalApplicationHostBaselineVerified"]=@YES;assert(!r5besOwnedRetirementFacts(out));out[@"originalApplicationHostBaselineVerified"]=@NO;
 NSMutableDictionary*proof=[@{@"ok":@YES,@"pinsVerified":@YES,@"originalRootCompatible":@YES,@"priorAnchorsCompatible":@YES,@"originalRootSHA256":ROOT_RULE,@"originalRootTextSHA256":ROOT_TEXT,@"pfDisabled":@YES,@"ownedRootHookRemoved":@YES,@"originalRootRestored":@YES,@"receiptRetired":@YES,@"namespaceReclaimed":@YES,@"namespaceState":@"absent",@"runLedgerState":@"retired"}mutableCopy];
 assert(r5besRetiredNativeFacts(proof));
 for(NSString*k in @[@"ok",@"pinsVerified",@"originalRootCompatible",@"priorAnchorsCompatible",@"pfDisabled",@"ownedRootHookRemoved",@"originalRootRestored",@"receiptRetired",@"namespaceReclaimed"]){proof[k]=@NO;assert(!r5besRetiredNativeFacts(proof));proof[k]=@YES;}
 proof[@"namespaceState"]=@"present";assert(!r5besRetiredNativeFacts(proof));proof[@"namespaceState"]=@"absent";
 proof[@"runLedgerState"]=@"issued";assert(!r5besRetiredNativeFacts(proof));proof[@"runLedgerState"]=@"retired";
 proof[@"pfDisabled"]=@1;assert(!r5besRetiredNativeFacts(proof));
 assert(![out[@"cleanupConfirmed"]boolValue]&&![out[@"runtimeArchived"]boolValue]&&[out[@"cleanupUncertain"]boolValue]);
 puts("host-volatility-preserved-14-required-facts-and-fresh-native-status");return 0;
}}
`);
 await exec('/usr/bin/clang',[...flags,file,path.join(native,'app-scope-proof.c'),'-framework','Foundation','-framework','Security','-o',binary],{timeout:30000});
 assert.match((await exec(binary,[],{timeout:10000})).stdout,/host-volatility-preserved-14-required-facts/);
 }finally{await rm(dir,{recursive:true,force:true});}
});


test('sealed recorded application child requires exact root zombie or double ESRCH, never resumed=false inference',async()=>{
 assert.notEqual(process.getuid(),0);const dir=await mkdtemp(path.join(tmpdir(),'envara-run6c6-child-boundary-'));
 try{const file=path.join(dir,'fixture.m'),binary=path.join(dir,'ChildBoundary');
 await writeFile(file,`#define R5BES_RECOVERY_INERT 1
#include "${path.join(native,'recovery-app-43b-run6c6-owned-scope-v2-20261009.m')}"
#include <assert.h>
int main(void){@autoreleasepool{
 NSDictionary*record=@{@"pid":@912345,@"birth":@"1791545555:123456"};
 NSDictionary*p=r5besApplicationChildFromBSD(record,NULL,NULL,true);assert([p[@"state"]isEqual:@"absent"]&&[p[@"exitCode"]intValue]==-1&&[p[@"signal"]intValue]==0&&CFGetTypeID((__bridge CFTypeRef)p[@"causeVerified"])==CFBooleanGetTypeID()&&![p[@"causeVerified"]boolValue]);
 assert([r5besApplicationChildFromBSD(record,NULL,NULL,false)[@"state"]isEqual:@"unknown"]);
 struct proc_bsdinfo a={.pbi_pid=912345,.pbi_ppid=R5BES_KEEPER_PID,.pbi_status=SZOMB,.pbi_start_tvsec=1791545555,.pbi_start_tvusec=123456,.pbi_xstatus=1<<8},b=a;
 p=r5besApplicationChildFromBSD(record,&a,&b,false);assert([p[@"state"]isEqual:@"exact-recorded-zombie"]&&[p[@"exitCode"]intValue]==1&&[p[@"signal"]intValue]==0);
 a.pbi_xstatus=b.pbi_xstatus=SIGKILL;p=r5besApplicationChildFromBSD(record,&a,&b,false);assert([p[@"state"]isEqual:@"exact-recorded-zombie"]&&[p[@"exitCode"]intValue]==-1&&[p[@"signal"]intValue]==SIGKILL);a.pbi_xstatus=b.pbi_xstatus=1<<8;
 struct proc_bsdinfo bad=b;
 #define REFUSE(field,value) bad=b;bad.field=value;assert([r5besApplicationChildFromBSD(record,&a,&bad,false)[@"state"]isEqual:@"unknown"])
 REFUSE(pbi_pid,1);REFUSE(pbi_ppid,1);REFUSE(pbi_uid,501);REFUSE(pbi_ruid,501);REFUSE(pbi_svuid,501);REFUSE(pbi_gid,7100);REFUSE(pbi_rgid,7100);REFUSE(pbi_svgid,7100);REFUSE(pbi_status,SSTOP);REFUSE(pbi_start_tvsec,1);REFUSE(pbi_start_tvusec,1);REFUSE(pbi_xstatus,0);
 a.pbi_status=b.pbi_status=SSTOP;assert([r5besApplicationChildFromBSD(record,&a,&b,false)[@"state"]isEqual:@"unknown"]);
 assert(!r5besApplicationChildFromBSD(@{@"pid":@YES,@"birth":record[@"birth"]},NULL,NULL,true));assert(!r5besApplicationChildFromBSD(@{@"pid":@1,@"birth":record[@"birth"]},NULL,NULL,true));assert(!r5besApplicationChildFromBSD(@{@"pid":@912345,@"birth":@"wrong"},NULL,NULL,true));assert(!r5besApplicationChildFromBSD(@{@"pid":@912345,@"birth":record[@"birth"],@"resumed":@NO},NULL,NULL,true));
 puts("exact-sealed-child-root-zombie-or-double-ESRCH-only");return 0;}}
`);
 await exec('/usr/bin/clang',[...flags,file,path.join(native,'app-scope-proof.c'),'-framework','Foundation','-framework','Security','-o',binary],{timeout:30000});assert.match((await exec(binary,[],{timeout:10000})).stdout,/exact-sealed-child-root-zombie/);
 const production=await readFile(path.join(native,'recovery-app-43b-run6c6-owned-scope-v2-20261009.m'),'utf8');assert.doesNotMatch(production,/kill\(\s*\[.*child/);assert(production.indexOf("r5besChildrenFinalAbsent(&c,10)")<production.indexOf("r5besSignal(&c,false,SIGKILL)"));assert.match(production,/r5besApplicationChildAbsent\(c\).*r5besChildFinalAbsent\(88328\)/);assert.match(production,/r5besApplicationChildTerminated\(c\)&&r5besStateStable/);
 }finally{await rm(dir,{recursive:true,force:true});}
});
