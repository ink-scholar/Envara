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

test('fixed f99 recovery constructor matches actual native DENY readback; strict group and port predicates refuse unknowns', async () => {
  assert.notEqual(process.getuid(), 0);
  const dir = await mkdtemp(path.join(tmpdir(), 'envara-f99-recovery-constructors-'));
  try {
    const source = `
#define F99_RECOVERY_INERT 1
#include "${path.join(native, 'recovery-app-f99-run145.m')}"
#include "${path.join(native, 'pf-production-filter.c')}"
#include <assert.h>
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);
 F99Context c={.gid=7100,.lease=@{@"realmId":@"73e9d9b3-6b9c-435b-8f64-8305e5a60859"}};
 EnvaraPFProductionConfig cfg={.gid=7100,.listener_fd=9,.tcp_front_port=54321};
 strcpy(cfg.run_id,CANARY_RUN.UTF8String);strcpy(cfg.realm_id,[c.lease[@"realmId"]UTF8String]);strcpy(cfg.utun,"utun6");cfg.route_ipv4[0]=198;cfg.route_ipv4[1]=18;cfg.route_ipv4[2]=1;cfg.route_ipv4[3]=1;
 ProductionPlan plan;assert(production_plan(&cfg,ENVARA_PF_PRODUCTION_DENY,&plan)&&plan.count==6);
 for(uint32_t i=0;i<6;i++){EnvaraPFHookRule actual=production_readback_rule(&plan,i,0,F99_KEEPER_PID),wanted=f99DenyRule(&c,i);assert(!memcmp(&actual,&wanted,sizeof(actual)));assert(!actual.keep_state&&!actual.uid_op&&actual.gid_op==2);}
 NSString*base=@"root 0\\nnobody -2\\nnogroup -1\\nwheel 0\\nstaff 20\\n";
 assert(f99NegativeGroups(base,7100));assert(!f99NegativeGroups([base stringByAppendingString:@"_envara_pf_7100 7100\\n"],7100));
 assert(!f99NegativeGroups([base stringByAppendingString:@"foreign 7100\\n"],7100));
 assert(!f99NegativeGroups([base stringByAppendingString:@"invalid -2147483649\\n"],7100));
 assert(!f99NegativeGroups([base stringByAppendingString:@"invalid 4294967296\\n"],7100));
 assert(!f99NegativeGroups([base stringByAppendingString:@"invalid -4294960196\\n"],7100));
 assert(!f99NegativeGroups([base stringByAppendingString:@"invalid 01\\n"],7100));
 assert(!f99NegativeGroups([base stringByAppendingString:@"root 0\\n"],7100));
 assert(f99GroupRows([base stringByAppendingString:@"_envara_pf_7100 7100\\n"],7100,true));
 assert(!f99GroupRows(base,7100,true));assert(!f99GroupRows([base stringByAppendingString:@"_envara_pf_7100 7101\\n"],7100,true));
 assert(!f99GroupRows([base stringByAppendingString:@"_envara_pf_7100 7100\\nforeign 7100\\n"],7100,true));
 NSString*head=@"Active Internet connections (including servers)\\nProto Recv-Q Send-Q Local Address Foreign Address (state)\\n";
 assert(f99PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\n"],54321,true));
 assert(!f99PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\n"],54321,false));
 assert(!f99PortRows([head stringByAppendingString:@"tcp4 0 0 *.54321 *.* LISTEN\\n"],54321,false));
 assert(f99PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 127.0.0.1.43210 TIME_WAIT\\n"],54321,false));
 assert(f99PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54320 *.* LISTEN\\n"],54321,false));
 /* Apple netstat.tproj/inet.c prints dualstack IPv4 tuples as tcp46 and
  * appends verbose socket statistics after the fixed six leading columns. */
 assert(f99PortRows([head stringByAppendingString:@"tcp46 0 0 *.54321 *.* LISTEN 131072 131072 0 0 0x00000 0x00000000\\n"],54321,true));
 assert(!f99PortRows([head stringByAppendingString:@"tcp46 0 0 *.54321 *.* LISTEN\\n"],54321,false));
 assert(!f99PortRows([head stringByAppendingString:@"tcp4 0 0 999.0.0.1.54321 *.* LISTEN\\n"],54321,false));
 assert(!f99PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.65536 *.* LISTEN\\n"],54321,false));
 assert(!f99PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 unknown.service LISTEN\\n"],54321,false));
 assert(!f99PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\nSome tcp sockets may have been created.\\n"],54321,false));
 assert(!f99PortRows([head stringByAppendingString:head],54321,false));
 assert(!f99PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* UNKNOWN\\n"],54321,false));
 assert(!f99PortRows([head stringByAppendingString:@"tcp6 0 0 ::1.54321 *.* LISTEN\\n"],54321,false));
 assert(!f99PortRows(@"",54321,false));assert(!f99PortRows(@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\n",54321,false));
 NSMutableDictionary*out=f99Outcome(false);assert(CFGetTypeID((__bridge CFTypeRef)out[@"readOnly"])==CFBooleanGetTypeID());
 for(NSString*k in @[@"cleanupConfirmed",@"originalApplicationHostBaselineVerified",@"ready",@"protected",@"productionReady",@"fullGuardFailureAccepted",@"originalDescriptorCustodyVerified"]){assert(CFGetTypeID((__bridge CFTypeRef)out[k])==CFBooleanGetTypeID()&&![out[k]boolValue]);}
 puts("actual-DENY-parity-and-strict-predicates");return 0;
}}`;
    await writeFile(path.join(dir, 'fixture.m'), source);
    await exec('/usr/bin/clang', [...flags, path.join(dir, 'fixture.m'), path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', path.join(dir, 'fixture')], { timeout: 30000 });
    const result = await exec(path.join(dir, 'fixture'), [], { timeout: 10000 });
    assert.match(result.stdout, /actual-DENY-parity-and-strict-predicates/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('actual one-FILTER clear function binds ticket and namespace, never retries and never rolls back after COMMIT attempt', async () => {
  assert.notEqual(process.getuid(), 0);
  const dir = await mkdtemp(path.join(tmpdir(), 'envara-f99-recovery-one-filter-'));
  try {
    const source = `
#define F99_RECOVERY_INERT 1
#include "${path.join(native, 'recovery-app-f99-run145.m')}"
#include <assert.h>
static int scenario,operations,begin_count,commit_count,rollback_count;
static bool guard(F99Context*c,unsigned phase){(void)c;return scenario!=1&&(phase!=1||scenario!=8);}
static int opener(void){return scenario==2?-1:open("/dev/null",O_RDWR|O_CLOEXEC);}
static bool readback(F99Context*c){(void)c;return scenario!=11;}
static int fakeIoctl(int fd,unsigned long operation,void*argument){assert(fd>=0);F99Transaction*t=argument;assert(t->size==1&&t->esize==sizeof(F99Entry)&&t->array);F99Entry*e=t->array;assert(e->rs_num==1&&!strcmp(e->anchor,CANARY_ANCHOR.UTF8String));operations++;
 if(operation==F99_BEGIN){begin_count++;assert(e->ticket==0);e->ticket=71;
  if(scenario==3){errno=EIO;return -1;}if(scenario==4)e->ticket=0;if(scenario==5)strcpy(e->anchor,"foreign.anchor");if(scenario==6)t->esize=1;if(scenario==7)t->array=(F99Entry*)1;return 0;}
 assert(e->ticket==71);
 if(operation==F99_COMMIT){commit_count++;if(scenario==9){errno=EIO;return -1;}if(scenario==10)e->ticket=72;return 0;}
 assert(operation==F99_ROLLBACK);rollback_count++;return 0;
}
int main(void){@autoreleasepool{assert(getuid()!=0&&geteuid()!=0);
 f99_test_clear_guard=guard;f99_test_write_open=opener;f99_test_transaction_ioctl=fakeIoctl;f99_test_empty_readback=readback;
 for(scenario=0;scenario<12;scenario++){operations=begin_count=commit_count=rollback_count=0;F99Context c={0};NSMutableDictionary*out=f99Outcome(true);
  bool result=f99ClearOnce(&c,out);assert(result==(scenario==0));
  if(scenario==1||scenario==2)assert(operations==0);else assert(begin_count==1);
  if(scenario>=3&&scenario<=7)assert(commit_count==0&&rollback_count==0);
  if(scenario==8)assert(commit_count==0&&rollback_count==1);
  if(scenario==0||scenario>=9)assert(commit_count==1&&rollback_count==0);
  int saved=operations;assert(!f99ClearOnce(&c,out));assert(operations==saved);
  for(NSString*k in @[@"cleanupConfirmed",@"ownedFilterEmptyVerified",@"namespaceReclaimed",@"ownedPFReferenceReleased",@"rootHookRemoved",@"ready",@"protected"]){assert(![out[k]boolValue]);}
 }
 assert(f99TransactionIoctl(-1,0xc4704433UL,NULL)==-1); /* no BEGINADDRS */
 puts("12-owned-transaction-fault-cases-no-retry");return 0;
}}`;
    await writeFile(path.join(dir, 'fixture.m'), source);
    await exec('/usr/bin/clang', [...flags, path.join(dir, 'fixture.m'), path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', path.join(dir, 'fixture')], { timeout: 30000 });
    const result = await exec(path.join(dir, 'fixture'), [], { timeout: 10000 });
    assert.match(result.stdout, /12-owned-transaction-fault-cases-no-retry/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('standalone production entry plan is inert; both privileged entries refuse without root and no caller-selected inputs exist', async () => {
  assert.notEqual(process.getuid(), 0);
  const dir = await mkdtemp(path.join(tmpdir(), 'envara-f99-recovery-entry-'));
  try {
    const binary = path.join(dir, 'FixedF99Recovery');
    await exec('/usr/bin/clang', [...flags, path.join(native, 'recovery-app-f99-run145.m'), path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000 });
    const plan = JSON.parse((await exec(binary, ['--plan'], { timeout: 5000 })).stdout);
    assert.equal(plan.runId, '14514ea6-7f9c-4cdc-92ae-c67d5ac31a7a');
    assert.equal(plan.environmentId, '9b5fb67d-7d8e-492b-a1f5-cccd893b0567');
    assert.equal(plan.manifestSHA256, 'f99aac934122ac3cafe992ac6fbf232ff917c1b8632034d19491b3dca7ab0d51');
    for (const key of ['cleanupConfirmed', 'originalApplicationHostBaselineVerified', 'ready', 'protected', 'productionReady', 'globalFlushExecuted', 'PFEnableExecuted', 'globalPoolResetExecuted', 'applicationLaunchExecuted']) assert.equal(plan[key], false);
    assert.equal(plan.readOnly, true); assert.equal(plan.ok, true); assert.equal(plan.cleanupUncertain, true);
    for (const args of [['--inspect-fixed-root'], ['--cleanup-fixed-root'], ['--request-cleanup'], ['--cleanup-fixed-root', '/foreign']]) {
      const result = await exec(binary, args, { timeout: 5000 }).catch(error => error);
      assert.equal(result.code, 1);
      const refused = JSON.parse(result.stdout); assert.equal(refused.ok, false); assert.equal(refused.cleanupConfirmed, false);
      for (const key of ['controllerStopped', 'keeperStopped', 'ownedFilterClearAttempted', 'ownedPFReferenceReleaseAttempted', 'rootHookDeleteAttempted', 'ownedGroupDeleteAttempted', 'runtimeArchived']) assert.equal(refused[key], false);
    }
    const symbols = (await exec('/usr/bin/nm', ['-u', binary])).stdout;
    assert.match(symbols, /\b_getgroups\b/); assert.doesNotMatch(symbols, /_getgroups\$DARWIN_EXTSN/);
    const source = await readFile(path.join(native, 'recovery-app-f99-run145.m'), 'utf8');
    assert.doesNotMatch(source, /AuthorizationExecuteWithPrivileges|AuthorizationCopyRights|\bDIOCBEGINADDRS\s*\(/);
    assert.match(source, /rootHookDeleteAttempted/); assert.match(source, /RENAME_EXCL/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
