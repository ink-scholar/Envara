import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const source = path.resolve(import.meta.dirname, '../native/macos-pf-routing/recovery-app-46ae-finalize-wrapper.m');

test('native finalization relay requires its own network proof and sealed prior receipt without promoting the lost baseline', async () => {
  assert.equal(process.platform, 'darwin');
  assert.notEqual(process.getuid(), 0);
  const directory = await mkdtemp(path.join(tmpdir(), 'envara-finalizer-relay-inert-'));
  try {
    const sha = 'a'.repeat(64), prior = 'b'.repeat(64);
    await writeFile(path.join(directory, 'recovery-app-46ae-finalize-wrapper-build.h'), [
      `#define WRAPPER_SELF ${JSON.stringify(path.join(directory, 'inert'))}`,
      `#define WRAPPER_CONSOLE_UID ${process.getuid()}`,
      `#define WRAPPER_RECOVERY_SHA "${sha}"`,
      `#define WRAPPER_PRIOR_RECEIPT_SHA "${prior}"`,
      `#define WRAPPER_ROOT_TARGET "/Library/PrivilegedHelperTools/io.envara.pf-recovery-46ae-${sha}"`,
      '#define WRAPPER_STAGE_PROGRAM "closed inert placeholder; never executed"',
    ].join('\n') + '\n', { flag: 'wx', mode: 0o600 });
    const harness = path.join(directory, 'inert.m'), executable = path.join(directory, 'inert');
    await writeFile(harness, `
#define WRAPPER_INERT 1
#include "${source}"
#include <assert.h>
static NSMutableDictionary*reply(bool cleanup){return [@{
 @"schema":RECOVERY_SCHEMA,@"runId":RUN,@"environmentId":ENV,@"manifestSHA256":MF,@"priorRecoveryReceiptSHA256":@WRAPPER_PRIOR_RECEIPT_SHA,
 @"ready":@NO,@"protected":@NO,@"productionReady":@NO,@"readOnly":@((BOOL)!cleanup),@"ok":@YES,@"cleanupUncertain":@((BOOL)!cleanup),
 @"rootHookRemoved":@((BOOL)cleanup),@"namespaceReclaimed":@((BOOL)cleanup),@"receiptRetired":@((BOOL)cleanup),
 @"ownedPFReferenceReleased":@((BOOL)cleanup),@"ownedGroupRemoved":@((BOOL)cleanup),@"runtimeArchived":@((BOOL)cleanup),@"cleanupConfirmed":@((BOOL)cleanup),
 @"originalHostBaselineVerified":@NO,@"interactiveAuthorizationAllowed":@NO,@"bootstrapIdentityBound":@NO,
 @"reason":cleanup?@"EXACT_RECOVERY_COMPLETED":@"READ_ONLY_PREFLIGHT_VERIFIED",@"preflightVerified":@YES,@"ownedGIDScopeAbsent":@YES,
 @"ownedFilterEmpty":@YES,@"rootRuntimeComponentsAbsent":@YES,@"deleteAttempted":@((BOOL)cleanup),
 @"recoveryHostNetworkUnchanged":@NO,@"finalizationHostNetworkUnchanged":@((BOOL)cleanup)}mutableCopy];}
static void refuse(NSDictionary*value,bool cleanup){NSDictionary*checked=sanitize(value,cleanup);assert(![checked[@"ok"]boolValue]);assert(![checked[@"cleanupConfirmed"]boolValue]);assert([checked[@"cleanupUncertain"]boolValue]);}
int main(void){@autoreleasepool{assert(getuid()!=0&&geteuid()!=0&&compiledInputs());
 for(int cleanup=0;cleanup<2;cleanup++){
  NSMutableDictionary*v=reply(cleanup);NSDictionary*checked=sanitize(v,cleanup);assert([checked[@"ok"]boolValue]);assert([checked[@"cleanupConfirmed"]boolValue]==(bool)cleanup);
  assert(![checked[@"originalHostBaselineVerified"]boolValue]&&![checked[@"recoveryHostNetworkUnchanged"]boolValue]);
  NSMutableDictionary*x=[v mutableCopy];x[@"priorRecoveryReceiptSHA256"]=@"foreign";refuse(x,cleanup);x=[v mutableCopy];[x removeObjectForKey:@"priorRecoveryReceiptSHA256"];refuse(x,cleanup);
  x=[v mutableCopy];x[@"schema"]=@"envara.macos-pf-application-recovery/v1";refuse(x,cleanup);
  x=[v mutableCopy];x[@"recoveryHostNetworkUnchanged"]=@YES;refuse(x,cleanup);
  x=[v mutableCopy];x[@"finalizationHostNetworkUnchanged"]=@1;refuse(x,cleanup);
  x=[v mutableCopy];x[@"originalHostBaselineVerified"]=@YES;refuse(x,cleanup);
  x=[v mutableCopy];x[@"unreviewedProof"]=@YES;refuse(x,cleanup);
  if(cleanup){for(NSString*k in @[@"preflightVerified",@"ownedGIDScopeAbsent",@"ownedFilterEmpty",@"rootRuntimeComponentsAbsent",@"rootHookRemoved",@"namespaceReclaimed",@"receiptRetired",@"ownedPFReferenceReleased",@"ownedGroupRemoved",@"runtimeArchived",@"deleteAttempted",@"finalizationHostNetworkUnchanged"]){x=[v mutableCopy];x[k]=@NO;refuse(x,true);}
   x=[v mutableCopy];[x removeObjectForKey:@"finalizationHostNetworkUnchanged"];refuse(x,true);
   x=[v mutableCopy];[x removeObjectForKey:@"recoveryHostNetworkUnchanged"];assert([sanitize(x,true)[@"ok"]boolValue]);
  }else{x=[v mutableCopy];x[@"finalizationHostNetworkUnchanged"]=@YES;refuse(x,false);}
 }
 assert(stageDecision(false,false,false)==COMPONENT_REQUIRED&&stageDecision(true,true,false)==COMPONENT_REQUIRED);
 assert(stageDecision(false,true,false)==EXPLICIT_INSTALL_TARGET);
 puts("finalizer strict relay passed");return 0;}}
`, { flag: 'wx', mode: 0o600 });
    await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I', directory,
      harness, '-framework', 'Foundation', '-framework', 'Security', '-o', executable], { timeout: 30000 });
    const result = await exec(executable, [], { timeout: 10000 });
    assert.equal(result.stdout, 'finalizer strict relay passed\n');
    assert.equal(result.stderr, '');
  } finally { await rm(directory, { recursive: true, force: true }); }
});
