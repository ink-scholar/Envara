import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { tmpdir } from 'node:os';

const exec = promisify(execFile);
const root = path.resolve(import.meta.dirname, '..');
const native = path.join(root, 'native/macos-pf-routing');
const flags = ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function'];

test('fixed 05d6/run877 draft recovery constructor matches actual native DENY readback; strict group and port predicates refuse unknowns', async () => {
  assert.notEqual(process.getuid(), 0);
  const dir = await mkdtemp(path.join(tmpdir(), 'envara-r877-recovery-constructors-'));
  try {
    const source = `
#define R877_RECOVERY_INERT 1
#include "${path.join(native, 'recovery-app-05d6-run877-draft-20261009.m')}"
#include "${path.join(native, 'pf-production-filter.c')}"
#include <assert.h>
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);
 R877Context c={.gid=7100,.lease=@{@"realmId":@"73e9d9b3-6b9c-435b-8f64-8305e5a60859"}};
 EnvaraPFProductionConfig cfg={.gid=7100,.listener_fd=9,.tcp_front_port=54321};
 strcpy(cfg.run_id,CANARY_RUN.UTF8String);strcpy(cfg.realm_id,[c.lease[@"realmId"]UTF8String]);strcpy(cfg.utun,"utun6");cfg.route_ipv4[0]=198;cfg.route_ipv4[1]=18;cfg.route_ipv4[2]=1;cfg.route_ipv4[3]=1;
 ProductionPlan plan;assert(production_plan(&cfg,ENVARA_PF_PRODUCTION_DENY,&plan)&&plan.count==6);
 for(uint32_t i=0;i<6;i++){EnvaraPFHookRule actual=production_readback_rule(&plan,i,0,R877_KEEPER_PID),wanted=r877DenyRule(&c,i);assert(!memcmp(&actual,&wanted,sizeof(actual)));assert(!actual.keep_state&&!actual.uid_op&&actual.gid_op==2);}
 NSString*base=@"root 0\\nnobody -2\\nnogroup -1\\nwheel 0\\nstaff 20\\n";
 assert(r877NegativeGroups(base,7100));assert(!r877NegativeGroups([base stringByAppendingString:@"_envara_pf_7100 7100\\n"],7100));
 assert(!r877NegativeGroups([base stringByAppendingString:@"foreign 7100\\n"],7100));
 assert(!r877NegativeGroups([base stringByAppendingString:@"invalid -2147483649\\n"],7100));
 assert(!r877NegativeGroups([base stringByAppendingString:@"invalid 4294967296\\n"],7100));
 assert(!r877NegativeGroups([base stringByAppendingString:@"invalid -4294960196\\n"],7100));
 assert(!r877NegativeGroups([base stringByAppendingString:@"invalid 01\\n"],7100));
 assert(!r877NegativeGroups([base stringByAppendingString:@"root 0\\n"],7100));
 assert(r877GroupRows([base stringByAppendingString:@"_envara_pf_7100 7100\\n"],7100,true));
 assert(!r877GroupRows(base,7100,true));assert(!r877GroupRows([base stringByAppendingString:@"_envara_pf_7100 7101\\n"],7100,true));
 assert(!r877GroupRows([base stringByAppendingString:@"_envara_pf_7100 7100\\nforeign 7100\\n"],7100,true));
 NSString*head=@"Active Internet connections (including servers)\\nProto Recv-Q Send-Q Local Address Foreign Address (state)\\n";
 assert(r877PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\n"],54321,true));
 assert(!r877PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\n"],54321,false));
 assert(!r877PortRows([head stringByAppendingString:@"tcp4 0 0 *.54321 *.* LISTEN\\n"],54321,false));
 assert(r877PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 127.0.0.1.43210 TIME_WAIT\\n"],54321,false));
 assert(r877PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54320 *.* LISTEN\\n"],54321,false));
 /* Apple netstat.tproj/inet.c prints dualstack IPv4 tuples as tcp46 and
  * appends verbose socket statistics after the fixed six leading columns. */
 assert(r877PortRows([head stringByAppendingString:@"tcp46 0 0 *.54321 *.* LISTEN 131072 131072 0 0 0x00000 0x00000000\\n"],54321,true));
 assert(!r877PortRows([head stringByAppendingString:@"tcp46 0 0 *.54321 *.* LISTEN\\n"],54321,false));
 assert(!r877PortRows([head stringByAppendingString:@"tcp4 0 0 999.0.0.1.54321 *.* LISTEN\\n"],54321,false));
 assert(!r877PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.65536 *.* LISTEN\\n"],54321,false));
 assert(!r877PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 unknown.service LISTEN\\n"],54321,false));
 assert(!r877PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\nSome tcp sockets may have been created.\\n"],54321,false));
 assert(!r877PortRows([head stringByAppendingString:head],54321,false));
 assert(!r877PortRows([head stringByAppendingString:@"tcp4 0 0 127.0.0.1.54321 *.* UNKNOWN\\n"],54321,false));
 assert(!r877PortRows([head stringByAppendingString:@"tcp6 0 0 ::1.54321 *.* LISTEN\\n"],54321,false));
 assert(!r877PortRows(@"",54321,false));assert(!r877PortRows(@"tcp4 0 0 127.0.0.1.54321 *.* LISTEN\\n",54321,false));
 NSMutableDictionary*out=r877Outcome(false);assert(CFGetTypeID((__bridge CFTypeRef)out[@"readOnly"])==CFBooleanGetTypeID());
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
  const dir = await mkdtemp(path.join(tmpdir(), 'envara-r877-recovery-one-filter-'));
  try {
    const source = `
#define R877_RECOVERY_INERT 1
#include "${path.join(native, 'recovery-app-05d6-run877-draft-20261009.m')}"
#include <assert.h>
static int scenario,operations,begin_count,commit_count,rollback_count;
static bool guard(R877Context*c,unsigned phase){(void)c;return scenario!=1&&(phase!=1||scenario!=8);}
static int opener(void){return scenario==2?-1:open("/dev/null",O_RDWR|O_CLOEXEC);}
static bool readback(R877Context*c){(void)c;return scenario!=11;}
static int fakeIoctl(int fd,unsigned long operation,void*argument){assert(fd>=0);R877Transaction*t=argument;assert(t->size==1&&t->esize==sizeof(R877Entry)&&t->array);R877Entry*e=t->array;assert(e->rs_num==1&&!strcmp(e->anchor,CANARY_ANCHOR.UTF8String));operations++;
 if(operation==R877_BEGIN){begin_count++;assert(e->ticket==0);e->ticket=71;
  if(scenario==3){errno=EIO;return -1;}if(scenario==4)e->ticket=0;if(scenario==5)strcpy(e->anchor,"foreign.anchor");if(scenario==6)t->esize=1;if(scenario==7)t->array=(R877Entry*)1;return 0;}
 assert(e->ticket==71);
 if(operation==R877_COMMIT){commit_count++;if(scenario==9){errno=EIO;return -1;}if(scenario==10)e->ticket=72;return 0;}
 assert(operation==R877_ROLLBACK);rollback_count++;return 0;
}
int main(void){@autoreleasepool{assert(getuid()!=0&&geteuid()!=0);
 r877_test_clear_guard=guard;r877_test_write_open=opener;r877_test_transaction_ioctl=fakeIoctl;r877_test_empty_readback=readback;
 for(scenario=0;scenario<12;scenario++){operations=begin_count=commit_count=rollback_count=0;R877Context c={0};NSMutableDictionary*out=r877Outcome(true);
  bool result=r877ClearOnce(&c,out);assert(result==(scenario==0));
  if(scenario==1||scenario==2)assert(operations==0);else assert(begin_count==1);
  if(scenario>=3&&scenario<=7)assert(commit_count==0&&rollback_count==0);
  if(scenario==8)assert(commit_count==0&&rollback_count==1);
  if(scenario==0||scenario>=9)assert(commit_count==1&&rollback_count==0);
  int saved=operations;assert(!r877ClearOnce(&c,out));assert(operations==saved);
  for(NSString*k in @[@"cleanupConfirmed",@"ownedFilterEmptyVerified",@"namespaceReclaimed",@"ownedPFReferenceReleased",@"rootHookRemoved",@"ready",@"protected"]){assert(![out[k]boolValue]);}
 }
 assert(r877TransactionIoctl(-1,0xc4704433UL,NULL)==-1); /* no BEGINADDRS */
 puts("12-owned-transaction-fault-cases-no-retry");return 0;
}}`;
    await writeFile(path.join(dir, 'fixture.m'), source);
    await exec('/usr/bin/clang', [...flags, path.join(dir, 'fixture.m'), path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', path.join(dir, 'fixture')], { timeout: 30000 });
    const result = await exec(path.join(dir, 'fixture'), [], { timeout: 10000 });
    assert.match(result.stdout, /12-owned-transaction-fault-cases-no-retry/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('run877 draft cannot compile as a privileged executable before actual readonly facts', async () => {
  assert.notEqual(process.getuid(), 0);
  const dir = await mkdtemp(path.join(tmpdir(), 'envara-run877-draft-refusal-'));
  try {
    const binary = path.join(dir, 'ForbiddenDraftExecutable');
    const result = await exec('/usr/bin/clang', [...flags, path.join(native, 'recovery-app-05d6-run877-draft-20261009.m'),
      path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000 }).catch(error => error);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /RUN877_RECOVERY_DRAFT_REQUIRES_ACTUAL_READONLY_FACTS_AND_CHILD_SCOPE_REVIEW/);
    await assert.rejects(readFile(binary), { code: 'ENOENT' });
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('fixed run877 draft recipe rejects verified source drift and grants no executable or cleanup acceptance', async () => {
  const { inspectFixedRun877Draft } = await import('../scripts/build-macos-pf-live-recovery-05d6-run877-draft-20261009.mjs');
  // The immutable historical recipe must not adopt today's source merely
  // because this test runs after a legitimate upgrade. Independently hash its
  // fixed manifest and each bound source before expecting the exact refusal.
  const digest = bytes => createHash('sha256').update(bytes).digest('hex');
  const manifestBytes = await readFile(path.join(native, 'inspector-app-05d6-manifest.json'));
  const manifestSHA256 = '05d6eb6ab3d63870d37825b47e2847789a6b5b8c3cf93c434636e0b8aad4f061';
  assert.equal(digest(manifestBytes), manifestSHA256);
  const manifest = JSON.parse(manifestBytes);
  assert.equal(Object.keys(manifest.nativeSourceFiles).length, 69);
  const drift = [];
  for (const [name, expected] of Object.entries(manifest.nativeSourceFiles)) {
    assert.match(name, /^(?:native\/macos-pf-routing|electron|scripts|tests)\/[A-Za-z0-9_./-]+$/);
    assert.equal(name.split('/').includes('..'), false);
    assert.match(expected, /^[0-9a-f]{64}$/);
    const actual = digest(await readFile(path.join(root, name)));
    if (actual !== expected) drift.push({ name, expected, actual });
  }
  if (drift.length) {
    assert.notEqual(drift[0].actual, drift[0].expected);
    await assert.rejects(inspectFixedRun877Draft(), error =>
      error.message === `Current source differs from installed 05d6: ${drift[0].name}`);
  } else {
    const proof = await inspectFixedRun877Draft();
    assert.equal(proof.fixedRunId, '877ab9cc-ed91-4f2d-a8cd-86cedc2f3e21');
    assert.equal(proof.fixedManifestSHA256, manifestSHA256);
    assert.equal(proof.installedSourceBindingsVerified, 69);
    assert.equal(proof.compilationBlocked, true);
    for (const key of ['executableProduced', 'authorizationEntryIncluded', 'actualReadonlyFactsAccepted', 'currentLiveChildrenHandled',
      'cleanupConfirmed', 'ready', 'protected', 'productionReady', 'rootExecuted', 'systemOperationExecuted', 'PFWriteExecuted',
      'ownedSignalExecuted', 'groupOperationExecuted', 'runtimeArchiveExecuted', 'installedCandidateChanged']) assert.equal(proof[key], false);
    assert.equal(proof.cleanupUncertain, true);
  }
  const result = await exec(process.execPath, [path.join(root, 'scripts/build-macos-pf-live-recovery-05d6-run877-draft-20261009.mjs'),
    '--cleanup-fixed-root'], { timeout: 10000 }).catch(error => error);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /accepts no paths, UUIDs or operation arguments/);
});
