import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';

const exec = promisify(execFile);
const root = path.resolve(import.meta.dirname, '..');
const native = path.join(root, 'native/macos-pf-routing');
const source = path.join(native, 'recovery-app-46ae-run904-finalize.m');
const priorFile = path.join(root, 'test-artifacts/mac-pf-routing/recovery-exact-cleanup-result-20261009.json');
const priorSHA = '8b568ac1bed533515fbf278b2d8138acf0a8121796f7e7a4887e88b4a75b1df3';

test('finalizer sealed prior evidence and fresh retired predicates refuse unknown or live scope', async () => {
  assert.notEqual(process.getuid(), 0);
  const temp = await mkdtemp(path.join(tmpdir(), 'envara-finalize46-inert-'));
  try {
    const harness = path.join(temp, 'inert.m'), binary = path.join(temp, 'inert');
    await writeFile(harness, `
#define FINALIZER_INERT 1
#include "${source}"
#include <assert.h>
static NSMutableDictionary *clone(NSDictionary *v){return [[NSJSONSerialization JSONObjectWithData:[NSJSONSerialization dataWithJSONObject:v options:NSJSONWritingWithoutEscapingSlashes error:NULL] options:NSJSONReadingMutableContainers error:NULL]mutableCopy];}
static NSDictionary *exactLease(void){NSString*id=@"62d7b9b9-019a-42b0-86e0-3d081367c10a";return @{@"schema":@"envara.macos-pf-owned-root-hook-lease/v2",@"runId":CANARY_RUN,@"leaseId":id,@"anchor":CANARY_ANCHOR,@"owner":CANARY_ANCHOR,@"label":[@"envara.hook.v2." stringByAppendingString:[hashText([NSString stringWithFormat:@"%@|%@",CANARY_RUN,id])substringToIndex:32]],@"ticket":@"18446744073709551615",@"rootBeforeSHA256":ROOT_RULE,@"rootBeforeTextSHA256":ROOT_TEXT};}
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);unsigned checks=0;
 NSDictionary *prior=sealedPriorReceipt();assert(prior&&[prior[@"deleteAttempted"]boolValue]&&![prior[@"ownedGroupRemoved"]boolValue]);checks++;
 EnvaraPFHookRequest a={0},b={0};a.ticket=b.ticket=99;
 assert(retiredClassEmpty(0,0,&a,0,0,&b));assert(retiredClassEmpty(-1,EINVAL,&a,-1,EINVAL,&b));checks+=2;
 for(int err=1;err<100;err++){if(err!=EINVAL){assert(!retiredClassEmpty(-1,err,&a,-1,err,&b));checks++;}}
 assert(!retiredClassEmpty(0,0,&a,-1,EINVAL,&b));assert(!retiredClassEmpty(-1,EINVAL,&a,0,0,&b));checks+=2;
 a.nr=1;assert(!retiredClassEmpty(0,0,&a,0,0,&b));a.nr=0;b.ticket++;assert(!retiredClassEmpty(0,0,&a,0,0,&b));checks+=2;
 NSDictionary *lease=exactLease();assert(validLease(lease));
 NSDictionary *proof=@{@"ok":@YES,@"pinsVerified":@YES,@"originalRootCompatible":@YES,@"priorAnchorsCompatible":@YES,@"originalRootSHA256":ROOT_RULE,@"originalRootTextSHA256":ROOT_TEXT,@"anchor":CANARY_ANCHOR,@"readOnly":@YES,@"pfDisabled":@YES,@"hookInstalled":@NO,@"ownedRootHookVerified":@NO,@"ownedRootHookRemoved":@YES,@"originalRootRestored":@YES,@"receiptRetired":@YES,@"namespaceReclaimed":@YES,@"namespaceExists":@NO,@"cleanupPending":@NO,@"namespaceState":@"absent",@"runLedgerState":@"retired",@"lease":lease};
 assert(retiredRootProof(proof,lease,0));checks++;
 for(NSString *key in @[@"pfDisabled",@"readOnly",@"hookInstalled",@"ownedRootHookVerified",@"ownedRootHookRemoved",@"originalRootRestored",@"receiptRetired",@"namespaceReclaimed",@"namespaceExists",@"cleanupPending"]){NSMutableDictionary *p=clone(proof);p[key]=@(![proof[key]boolValue]);assert(!retiredRootProof(p,lease,0));p[key]=@1;assert(!retiredRootProof(p,lease,0));checks+=2;}
 for(NSString *key in @[@"namespaceState",@"runLedgerState",@"anchor",@"originalRootSHA256"]){NSMutableDictionary *p=clone(proof);p[key]=@"unknown";assert(!retiredRootProof(p,lease,0));checks++;}
 assert(!retiredRootProof(proof,lease,1));NSMutableDictionary *foreign=clone(lease);foreign[@"ticket"]=@"0";assert(!retiredRootProof(proof,foreign,0));checks+=2;
 NSString *name=@"_envara_pf_7100";
 assert([negativeGroupList(@"wheel 0\\nstaff 20\\nadmin 80\\n",name,7100)isEqual:@"admin|80\\nstaff|20\\nwheel|0"]);checks++;
 assert([negativeGroupList(@"nobody -2\\nnogroup -1\\nwheel 0\\n",name,7100)isEqual:@"nobody|4294967294\\nnogroup|4294967295\\nwheel|0"]);checks++;
 assert(negativeGroupList(@"minimum -2147483648\\nwheel 0\\n",name,7100));checks++;
 for(id text in @[@"",@"wheel",@"wheel 0 extra",@"wheel 0\\nwheel 1",@"foreign 7100",@"_envara_pf_7100 20",@"wheel -2147483649",@"wheel -4294960196",@"wheel -0",@"wheel -01",@"wheel 4294967296",@"wheel false",@"wheel 0\\nunknown-line",@YES]){assert(!negativeGroupList(text,name,7100));checks++;}
 for(unsigned mutate=0;mutate<2;mutate++){NSDictionary *v=finalizerOutcome(mutate!=0);assert([v[@"schema"]isEqual:FINALIZER_SCHEMA]&&[v[@"priorRecoveryReceiptSHA256"]isEqual:@FINALIZER_PRIOR_SHA]);for(NSString *key in @[@"rootHookRemoved",@"namespaceReclaimed",@"receiptRetired",@"ownedPFReferenceReleased",@"ownedGroupRemoved",@"runtimeArchived",@"cleanupConfirmed",@"deleteAttempted",@"recoveryHostNetworkUnchanged",@"finalizationHostNetworkUnchanged",@"originalHostBaselineVerified",@"ready",@"protected",@"productionReady"]){assert(typedFlag(v,key,false));checks++;}}
 /* Nonroot entry stops before obtaining Authorization, opening /dev/pf or
  * inspecting system directories. Both modes retain uncertainty. */
 assert(finalizeRun(false)==1);assert(finalizeRun(true)==1);checks+=2;
 printf("inert finalization predicates passed: %u\\n",checks);return 0;
}}
`, { mode: 0o600 });
    await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', harness,
      path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000 });
    const { stdout } = await exec(binary, [], { timeout: 15000 });
    assert.match(stdout, /inert finalization predicates passed: 1[5-9]\d/);
    const replies = stdout.split('\n').filter(line => line.startsWith('{')).map(line => JSON.parse(line));
    assert.equal(replies.length, 2);
    for (const reply of replies) {
      assert.equal(reply.preflightGate, 'rights');
      assert.equal(reply.ok, false);
      assert.equal(reply.cleanupUncertain, true);
      assert.equal(reply.cleanupConfirmed, false);
      assert.equal(reply.finalizationHostNetworkUnchanged, false);
      assert.equal(reply.priorRecoveryReceiptSHA256, priorSHA);
    }
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('finalizer entry can archive only and never replay completed PF or group operations', async () => {
  const text = await readFile(source, 'utf8');
  assert.match(text, /#define RECOVERY_INERT 1/);
  assert.doesNotMatch(text, /recover\(|requestRecovery\(|nativeCall\([12],|"-X"|"-delete"|"-e"|"-f"|"-F"/);
  assert.match(text, /const uint8_t actions\[\] = \{0,2,4,6,8,11\}/);
  assert.match(text, /nativeCall\(0,/);
  assert.match(text, /errno=0;if\(getgrgid\(gid\)!=NULL\|\|errno\)return false/);
  assert.match(text, /errno=0;if\(getgrnam\(name.UTF8String\)!=NULL\|\|errno\)return false/);
  assert.match(text, /"-list",\(char\*\)"\/Groups",\(char\*\)"PrimaryGroupID"/);
  assert.equal((text.match(/freshFinalizerProof\(&c,out,/g) ?? []).length, 5);
  assert.match(text, /RENAME_EXCL/);
  assert.match(text, /"recovery-46ae.intent"/);
  assert.match(text, /"finalize-46ae.intent"/);
  assert.match(text, /unchanged\(capsule,"prior-root-recovery.json"/);
  assert.match(text, /unchanged\(capsule,"finalization-proof.json"/);
  assert.match(text, /out\[@"finalizationHostNetworkUnchanged"\]=@YES/);
  assert.doesNotMatch(text, /recoveryHostNetworkUnchanged"\]\s*=\s*@YES|originalHostBaselineVerified"\]\s*=\s*@YES/);
  assert.match(text, /#ifndef FINALIZER_INERT/);
  const main = text.slice(text.indexOf('#ifndef FINALIZER_INERT'));
  assert.deepEqual([...main.matchAll(/strcmp\(argv\[1\],"([^"]+)"\)/g)].map(match => match[1]),
    ['--plan', '--inspect-fixed-root', '--cleanup-fixed-root']);
  const header = await readFile(path.join(native, 'recovery-app-46ae-run904-finalize-prior.h'), 'utf8');
  const bytes = Buffer.from([...header.matchAll(/0x([0-9a-f]{2})/g)].map(match => parseInt(match[1], 16)));
  // The sealed source bytes are present in a clean checkout. A private local
  // receipt, when available, must still match; its absence is not authority.
  assert.equal(createHash('sha256').update(bytes).digest('hex'), priorSHA);
  const prior = await readFile(priorFile).catch(error => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (prior !== null) assert.deepEqual(bytes, prior);
});

test('standalone finalizer plan has exact fixed role with no operation or cleanup claims', async () => {
  assert.notEqual(process.getuid(), 0);
  const temp = await mkdtemp(path.join(tmpdir(), 'envara-finalize46-plan-'));
  try {
    const binary = path.join(temp, 'finalizer');
    await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', source,
      path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000 });
    const { stdout } = await exec(binary, ['--plan'], { timeout: 15000 });
    const plan = JSON.parse(stdout);
    assert.equal(plan.schema, 'envara.macos-pf-application-finalization/v1');
    assert.equal(plan.manifestSHA256, '46ae6acddd4f7b0a941bfbf6d6cc12aaedf59dd0c681b9aa440e72c38536d56b');
    assert.equal(plan.runId, '90401ced-5d54-4422-b80c-c7c4485a037b');
    assert.equal(plan.environmentId, 'f285429a-61e4-4023-8749-ec9073ce6a39');
    assert.equal(plan.priorRecoveryReceiptSHA256, priorSHA);
    assert.equal(plan.runtimeLeafCount, 19);
    assert.equal(plan.ok, true);
    assert.equal(plan.readOnly, true);
    assert.equal(plan.reason, 'INERT_PLAN');
    for (const key of ['ready', 'protected', 'productionReady', 'cleanupConfirmed', 'deleteAttempted', 'ownedPFReferenceReleased',
      'runtimeArchived', 'recoveryHostNetworkUnchanged', 'finalizationHostNetworkUnchanged', 'originalHostBaselineVerified']) assert.equal(plan[key], false);
  } finally { await rm(temp, { recursive: true, force: true }); }
});
