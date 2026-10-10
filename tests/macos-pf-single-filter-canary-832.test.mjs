import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, realpath, readFile, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const source = fileURLToPath(new URL('../native/macos-pf-routing/pf-single-filter-canary-832.m', import.meta.url));
const onlyMac = { skip: process.platform !== 'darwin' };
async function fixture(callback, harness) {
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-pf-run-canary-inert-')));
  try {
    const input = harness ? path.join(directory, 'fixture.m') : source;
    if (harness) await writeFile(input, harness.replace('CANARY_SOURCE', JSON.stringify(source)));
    const binary = path.join(directory, 'canary');
    await execute('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', input, fileURLToPath(new URL('../native/macos-pf-routing/pf-single-filter-transaction.c',import.meta.url)),
      '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
    return await callback(binary);
  } finally { await rm(directory, { recursive: true, force: true }); }
}
async function result(binary, args) {
  try { return { code: 0, value: JSON.parse((await execute(binary, args, { timeout: 15000 })).stdout) }; }
  catch (error) { assert.equal(typeof error.code, 'number'); return { code: error.code, value: JSON.parse(error.stdout) }; }
}

test('fixed-832 single-FILTER plan is inert and never selects a caller UUID or native path', onlyMac, async () => {
  await fixture(async binary => {
    for (const args of [[], ['--plan']]) {
      const { code, value } = await result(binary, args);
      assert.equal(code, 0); assert.equal(value.readOnly, true); assert.equal(value.authorizationRequested, false);
      assert.equal(value.runId, 'a85314b8-5b24-4784-95ec-47b739c2e841');
      assert.equal(value.anchor, `io.envara.pf.run.${value.runId}`);
      assert.equal(value.manifestSHA256, '83256899dc6db90bb6a21dcd18d17cb08a46d3ba4e79177098629475cc107f78');
      assert.equal(value.installedLeafCount, 15); assert.equal(value.fixedRunMayNeverBeReused, true);
      assert.equal(value.insertAttempted, false); assert.equal(value.deleteAttempted, false);
      assert.equal(value.requiresPFAlreadyDisabled, true); assert.equal(value.keepState, 0);
      assert.equal(value.operations.singleFilterDenyAndEmpty, true); assert.equal(value.operations.globalTemporaryPoolBufferReset, true);
      assert.equal(value.gates.foreignPoolConcurrencyExcluded, false); assert.equal(value.kernelIoctlHardDeadline, false);
      assert.equal(value.fullCleanupVerified, false); assert.equal(value.bootstrapIdentityBound, false);
      assert.ok(Object.values(value.gates).every(gate => gate === false));
      for (const key of ['PFEnable', 'PFReference', 'groups', 'tunnels', 'otherChildRuleClasses', 'applications', 'hostDNSChanges', 'hostRouteChanges', 'stateControl', 'globalReload'])
        assert.equal(value.operations[key], false);
    }
    for (const args of [['--activate'], ['--canary', 'other'], ['--plan', '/untrusted'], ['--request-canary', '--runId']]) {
      const { code, value } = await result(binary, args);
      assert.equal(code, 1); assert.equal(value.reason, 'INVALID_FIXED_OPERATION'); assert.equal(value.insertAttempted, false);
    }
    if (process.getuid() !== 0) {
      const { code, value } = await result(binary, ['--canary']);
      assert.equal(code, 1); assert.equal(value.reason, 'PRIVILEGED_REFERENCE_REQUIRED'); assert.equal(value.insertAttempted, false);
    }
  });
});

const helpers = `
#define CANARY_INERT_MAIN canary_program_main
#include CANARY_SOURCE
#undef main
static NSDictionary *testLease(void) {
 NSString *leaseId = @"517b28ec-36f6-49b8-85e1-405d8d6b34f1";
 NSString *label = [@"envara.hook.v2." stringByAppendingString:[hashText([NSString stringWithFormat:@"%@|%@",CANARY_RUN,leaseId]) substringToIndex:32]];
 return @{@"schema":@"envara.macos-pf-owned-root-hook-lease/v2",@"runId":CANARY_RUN,@"leaseId":leaseId,@"anchor":CANARY_ANCHOR,@"owner":CANARY_ANCHOR,
  @"label":label,@"ticket":@"18446744073709551615",@"rootBeforeSHA256":ROOT_RULE,@"rootBeforeTextSHA256":ROOT_TEXT};
}
static NSMutableDictionary *proof(unsigned op, bool baseline, NSString *state) {
 NSMutableDictionary *p = [NSMutableDictionary dictionary];
 for (NSString *key in proofKeys()) p[key] = @NO;
 p[@"schema"] = NATIVE_SCHEMA; p[@"ok"] = @YES; p[@"operation"] = @(nativeOperation(op));
 p[@"reason"] = op == 0 ? @"READ_ONLY_OWNED_HOOK_PROOF" : op == 1 ? @"OWNED_EMPTY_HOOK_VERIFIED" : @"EXACT_OWNED_HOOK_REMOVED";
 p[@"anchor"] = baseline ? @"" : CANARY_ANCHOR; p[@"namespaceScheme"] = @"full-run-uuid/v2";
 p[@"readOnly"] = @((BOOL)(op == 0)); p[@"fixtureOnly"] = @YES; p[@"pfDisabled"] = @YES; p[@"pinsVerified"] = @YES;
 p[@"originalRootCompatible"] = @YES; p[@"priorAnchorsCompatible"] = @YES;
 p[@"originalRootSHA256"] = ROOT_RULE; p[@"originalRootTextSHA256"] = ROOT_TEXT; p[@"priorRulesetCountsSHA256"] = ROOT_RULE;
 p[@"priorRootDerivedAnchorCount"] = @7; p[@"ticketSource"] = @"this-INSERT-return-only";
 p[@"nativeCanaryProof"] = @"root-canary-native-20261008-fixed-v1-only"; p[@"namespaceState"] = baseline ? @"unselected" : @"absent";
 p[@"runLedgerState"] = baseline ? @"unselected" : state; p[@"lease"] = NSNull.null;
 p[@"gates"] = @{@"productionHook":@NO,@"fullKernelLayout":@NO,@"fullFixtureAcceptance":@NO,@"wholeGuardCrash":@NO,@"allStatePreservation":@NO};
 if ([state isEqual:@"unused"]) { p[@"ownedRootHookCanCreate"] = @YES; p[@"canCreateOwnedHook"] = @YES; p[@"namespaceReclaimed"] = @YES; }
 if ([state isEqual:@"issued"]) { p[@"ownedRootHookVerified"] = @YES; p[@"hookInstalled"] = @YES; p[@"namespaceState"] = @"present"; p[@"namespaceExists"] = @YES; }
 if ([state isEqual:@"retired"]) { p[@"ownedRootHookRemoved"] = @YES; p[@"originalRootRestored"] = @YES; p[@"receiptRetired"] = @YES; p[@"namespaceReclaimed"] = @YES; }
 return p;
}
static NSDictionary *decoded(NSDictionary *p, unsigned op, bool baseline, int code) {
 return nativeProof([NSJSONSerialization dataWithJSONObject:p options:NSJSONWritingWithoutEscapingSlashes error:NULL],op,baseline,code);
}
`;

test('strict v2 proof rejects booleans, malformed tickets, duplicates, foreign identity and secret-bearing extra keys', onlyMac, async () => {
  const harness = helpers + `
int main(void) { @autoreleasepool {
 NSMutableDictionary *p = proof(1,false,@"issued"); p[@"lease"] = testLease();
 if (!decoded(p,1,false,0) || !validLease(testLease())) return 1;
 NSMutableDictionary *bad = [p mutableCopy]; bad[@"pfDisabled"] = @1; if (decoded(bad,1,false,0)) return 2;
 bad = [p mutableCopy]; bad[@"password"] = @"private-credential"; if (decoded(bad,1,false,0)) return 3;
 bad = [p mutableCopy]; bad[@"reason"] = @"private-credential"; if (decoded(bad,1,false,0)) return 4;
 bad = [p mutableCopy]; bad[@"operation"] = @"hook-status"; if (decoded(bad,1,false,0)) return 5;
 bad = [p mutableCopy]; bad[@"anchor"] = @"io.envara.pf.root.v1"; if (decoded(bad,1,false,0)) return 6;
 if (decoded(p,1,false,1)) return 7;
 for (id ticket in @[@0,@"0",@"18446744073709551616",@"012",@"1e5"]) {
  NSMutableDictionary *lease = [testLease() mutableCopy]; lease[@"ticket"] = ticket; if (validLease(lease)) return 8;
 }
 for (NSString *key in @[@"runId",@"owner",@"anchor",@"label",@"rootBeforeSHA256"]) {
  NSMutableDictionary *lease = [testLease() mutableCopy]; lease[key] = @"foreign"; if (validLease(lease)) return 9;
 }
 NSData *dupe = [@"{\\"ok\\":true,\\"ok\\":false}" dataUsingEncoding:NSUTF8StringEncoding]; if (strictJSON(dupe,OUTPUT_LIMIT)) return 10;
 NSData *escape = [@"{\\"reason\\":\\"escaped\\\\nvalue\\"}" dataUsingEncoding:NSUTF8StringEncoding]; if (strictJSON(escape,OUTPUT_LIMIT)) return 11;
 NSMutableDictionary *secrets = [emptyOutcome(@"private-credential",true,false) mutableCopy]; secrets[@"hostComponentHashes"] = @{@"before":@{@"password":@"secret"},@"after":@{}};
 NSDictionary *safe = report(@"canary",secrets,true); if ([safe[@"ok"] boolValue] || [safe[@"readOnly"] boolValue] || ![safe[@"cleanupUncertain"] boolValue] || safe[@"hostComponentHashes"]) return 12;
 NSString *printed = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:safe options:0 error:NULL] encoding:NSUTF8StringEncoding];
 if ([printed containsString:@"credential"] || [printed containsString:@"secret"]) return 13;
 secrets = [emptyOutcome(@"CANARY_PREFLIGHT_REFUSED",true,false) mutableCopy]; secrets[@"insertAttempted"] = @[];
 safe = report(@"canary",secrets,true); if ([safe[@"readOnly"] boolValue] || [safe[@"ok"] boolValue] || ![safe[@"cleanupUncertain"] boolValue]) return 14;
 safe = report(@"requestCanary",emptyOutcome(@"ROOT_COMPLETION_UNCONFIRMED_READ_ONLY_RECOVERY_REQUIRED",false,true),true);
 if ([safe[@"readOnly"] boolValue] || ![safe[@"cleanupUncertain"] boolValue]) return 15;
 return 0;
} }
`;
  await fixture(binary => execute(binary, [], { timeout: 15000 }), harness);
});

test('inert lifecycle burns once, deletes once, and retains uncertainty after missing evidence', onlyMac, async () => {
  const harness = helpers + `
int main(void) { @autoreleasepool {
 for (unsigned scenario = 0; scenario < 15; scenario++) {
  interrupted = 0; rootDeadline = seconds() + (scenario == 14 ? 50 : 175); __block unsigned inserts = 0, deletes = 0, snapshots = 0;
  CanaryCall call = ^NSDictionary *(unsigned op, NSDictionary *input, int *status) {
   *status = 0;
   if (op == 3) return @{@"filterCycleVerified":@YES,@"filterDenyVerified":@YES,@"filterEmptyVerified":@YES,@"filterMutationAttempted":@YES,@"filterTransactionUncertain":@NO,@"reason":@"FILTER_EMPTY_DENY_EMPTY_VERIFIED"};
   if (op == 1) { inserts++;
    if (scenario == 7) return nil;
    NSMutableDictionary *p = proof(1,false,@"issued"); p[@"lease"] = testLease();
    if (scenario == 8) { p[@"ok"] = @NO; p[@"reason"] = @"INSERT_UNCONFIRMED_OWN_ROLLBACK_ATTEMPTED"; *status = 1; }
    if (scenario == 9) onSignal(SIGTERM);
    return decoded(p,op,false,*status);
   }
   if (op == 2) { deletes++;
    if (scenario == 5) return nil;
    NSMutableDictionary *p = proof(2,false,scenario == 6 ? @"delete-intent" : @"retired");
    if (scenario == 6) { p[@"ok"] = @NO; p[@"reason"] = @"EXACT_CLEANUP_UNCONFIRMED"; *status = 1; }
    return decoded(p,op,false,*status);
   }
   if (input[@"runId"]) {
    NSMutableDictionary *p = proof(0,false,@"unused");
    if (scenario == 1) p[@"runLedgerState"] = @"retired";
    if (scenario == 2) p[@"namespaceState"] = @"unknown";
    return decoded(p,op,false,0);
   }
   if (input[@"lease"]) { 
    NSString *state = scenario == 8 ? @"retired" : deletes ? scenario == 6 ? @"delete-intent" : @"retired" : @"issued";
    NSMutableDictionary *p = proof(0,false,state);
    if (scenario == 4 && deletes) { p[@"namespaceState"] = @"present"; p[@"namespaceExists"] = @YES; p[@"namespaceReclaimed"] = @NO; p[@"cleanupPending"] = @YES; }
    if (scenario == 10 && !deletes) p[@"ownedRootHookVerified"] = @NO;
    return decoded(p,op,false,0);
   }
   NSMutableDictionary *p = proof(0,true,@"unselected"); if (scenario == 3) p[@"originalRootSHA256"] = @"foreign";
   return decoded(p,op,true,0);
  };
  CanarySnapshot snapshot = ^NSDictionary * { snapshots++;
   return @{@"routes":scenario == 11 && snapshots > 1 ? ROOT_TEXT : ROOT_RULE,@"dns":ROOT_RULE,@"nat":ROOT_RULE,@"pfconf":ROOT_RULE}; };
  NSDictionary *out = exchangeCanary(call,snapshot,^bool { return scenario == 12 || (scenario == 13 && inserts > 0); }), *safe = report(@"canary",out,true);
  if (inserts > 1 || deletes > 1) return 20+scenario;
  if (scenario == 1 || scenario == 2 || scenario == 3 || scenario == 12 || scenario == 14) { if (inserts || deletes || [out[@"insertAttempted"] boolValue]) return 40+scenario; continue; }
  if (scenario == 0) { if (inserts != 1 || deletes != 1 || ![out[@"ok"] boolValue] || [out[@"cleanupUncertain"] boolValue]) return 60; }
  if (scenario == 4) { if (![out[@"singleFilterCycleVerified"] boolValue] || [out[@"ok"] boolValue] || ![out[@"cleanupPending"] boolValue]) return 64; }
  if (scenario == 5) { if (deletes != 1 || ![out[@"receiptRetired"] boolValue] || [out[@"deleteReceiptVerified"] boolValue] || [out[@"cleanupUncertain"] boolValue]) return 65; }
  if (scenario == 6) { if (deletes != 1 || ![out[@"cleanupUncertain"] boolValue] || [out[@"ok"] boolValue]) return 66; }
  if (scenario == 7) { if (deletes || ![out[@"insertAttempted"] boolValue] || ![out[@"cleanupUncertain"] boolValue]) return 67; }
  if (scenario == 8) { if (deletes || ![out[@"receiptRetired"] boolValue] || [out[@"ok"] boolValue] || [out[@"cleanupUncertain"] boolValue]) return 68; }
  if (scenario == 9) { if (deletes != 1 || [out[@"ok"] boolValue] || ![out[@"originalRootRestored"] boolValue]) return 69; }
  if (scenario == 10) { if (deletes != 1 || [out[@"insertReadbackVerified"] boolValue] || [out[@"ok"] boolValue]) return 70; }
  if (scenario == 13) { if (deletes != 1 || [out[@"ok"] boolValue] || ![out[@"originalRootRestored"] boolValue]) return 73; }
  if (scenario == 11) { if (![out[@"cleanupUncertain"] boolValue] || [out[@"hostNetworkRestored"] boolValue]) return 71; }
  if ([safe[@"fullCleanupVerified"] boolValue] || [safe[@"ready"] boolValue] || [safe[@"productionReady"] boolValue]) return 80+scenario;
 }
 return 0;
} }
`;
  await fixture(binary => execute(binary, [], { timeout: 15000 }), harness);
});

test('route comparison keeps actual configuration while excluding only dynamic counters', onlyMac, async () => {
  const harness = `
#define CANARY_INERT_MAIN canary_program_main
#include CANARY_SOURCE
#undef main
int main(void) { @autoreleasepool {
 NSString *a = @"Routing tables\\nInternet:\\nDestination Gateway Flags Refs Use Netif Expire\\ndefault 192.0.2.1 UGSc 1 20 en0 13\\nInternet6:\\nDestination Gateway Flags Netif Expire\\n::1 ::1 UH lo0 3\\n";
 NSString *b = @"Routing tables\\nInternet6:\\nDestination Gateway Flags Netif Expire\\n::1 ::1 UH lo0 4\\nInternet:\\nDestination Gateway Flags Refs Use Netif Expire\\ndefault 192.0.2.1 UGSc 17 999 en0 100\\n";
 if (![normalizedRoutes(a) isEqual:normalizedRoutes(b)]) return 1;
 if ([normalizedRoutes(a) isEqual:normalizedRoutes([b stringByReplacingOccurrencesOfString:@"192.0.2.1" withString:@"192.0.2.2"])]) return 2;
 if (normalizedRoutes(@"Routing tables\\nunknown")) return 3;
 return 0;
} }
`;
  await fixture(binary => execute(binary, [], { timeout: 15000 }), harness);
});

test('signals require both an unreaped child and its exact recorded process birth', onlyMac, async () => {
  const harness = `
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <libproc.h>
#include <errno.h>
#include <string.h>
static unsigned waits, signals, scenario;
static pid_t inertWait(pid_t pid, int *status, int flags) {
 (void)status; (void)flags; waits++;
 if (scenario == 1) return pid;
 if (scenario == 2) { errno = ECHILD; return -1; }
 return 0;
}
static int inertSignal(pid_t pid, int signal) { (void)pid; (void)signal; signals++; return 0; }
static int inertInfo(int pid, int flavor, uint64_t arg, void *buffer, int size) {
 (void)flavor; (void)arg; struct proc_bsdinfo *info = buffer; memset(info,0,(size_t)size);
 info->pbi_pid = (uint32_t)pid; info->pbi_ppid = (uint32_t)getpid(); info->pbi_start_tvsec = scenario == 3 ? 43 : 42;
 info->pbi_start_tvusec = 17; if (scenario == 4) info->pbi_ppid++;
 return size;
}
#define kill inertSignal
#define waitpid inertWait
#define proc_pidinfo inertInfo
#define CANARY_INERT_MAIN canary_program_main
#include CANARY_SOURCE
#undef main
#undef kill
#undef waitpid
#undef proc_pidinfo
int main(void) { @autoreleasepool {
 CanaryChildIdentity identity = {.pid=12345,.parent=getpid(),.seconds=42,.microseconds=17,.known=true};
 for (scenario = 0; scenario < 5; scenario++) {
  waits = signals = 0; bool ended = false, owned = true; int status = 0;
  bool sent = signalOwnedChild(&identity,SIGTERM,&ended,&owned,&status);
  if (scenario == 0) { if (!sent || signals != 1 || waits != 1) return 1; }
  else if (sent || signals) return 2;
  if (scenario == 1 && (!ended || owned)) return 3;
  if (scenario == 2 && owned) return 4;
 }
 waits = signals = 0; bool ended = true, owned = true; int status = 0;
 if (signalOwnedChild(&identity,SIGTERM,&ended,&owned,&status) || waits || signals) return 5;
 ended = false; owned = false;
 if (signalOwnedChild(&identity,SIGKILL,&ended,&owned,&status) || waits || signals) return 6;
 scenario = 0; identity.known = false; owned = true;
 if (signalOwnedChild(&identity,SIGTERM,&ended,&owned,&status) || signals) return 7;
 return 0;
} }
`;
  await fixture(binary => execute(binary, [], { timeout: 15000 }), harness);
});

test('a reaped inert fixture with an inherited stdout writer is never signalled at the shared deadline', onlyMac, async () => {
  const harness = `
#include <signal.h>
#include <unistd.h>
static unsigned signals;
static int inertSignal(pid_t pid, int signal) { (void)pid; (void)signal; signals++; return 0; }
#define kill inertSignal
#define CANARY_INERT_MAIN canary_program_main
#include CANARY_SOURCE
#undef main
#undef kill
int main(int argc,char **argv) { @autoreleasepool {
 if (argc == 2 && !strcmp(argv[1],"--hold-inert-pipe")) {
  pid_t child = fork(); if (child < 0) return 1;
  if (!child) { struct timespec pause = {0,350000000}; nanosleep(&pause,NULL); _exit(0); }
  return 0;
 }
 rootDeadline = seconds() + 0.15; int status = -1; char *args[] = {argv[0],"--hold-inert-pipe",NULL};
 NSData *result = fixedProcess(argv[0],args,nil,&status,false);
 if (result || signals || seconds() > rootDeadline + 0.1) return 2;
 return 0;
} }
`;
  await fixture(binary => execute(binary, [], { timeout: 15000 }), harness);
});

test('candidate source does not import legacy PF writer or mutate frozen resources', async () => {
  const text = await readFile(source, 'utf8');
  assert.doesNotMatch(text, /pf-root-canary\.c|recovery-readonly-518\.m|["']-f["']/);
  assert.match(text,/EnvaraSingleFilterApply/); assert.match(text,/canaryAllLeafClassesEmpty/); assert.match(text,/runtimeAbsentOrEmpty/);
  assert.match(text,/!validLease\(lease\) \|\| !runtimeAbsentOrEmpty\(\)/);
  assert.match(text,/operation == 1 && !runtimeAbsentOrEmpty\(\)/);
  assert.match(text, /LOCK_EX\|LOCK_NB/); assert.match(text, /POSIX_SPAWN_CLOEXEC_DEFAULT/);
  assert.match(text, /rootAuthorization\(\)/); assert.match(text, /deleteEligible/);
  assert.match(text, /if \(geteuid\(\) \|\| AuthorizationCopyPrivilegedReference/);
  assert.match(text, /setgroups\(1,&rootGroup\) \|\| setgid\(0\) \|\| setuid\(0\) \|\| getuid\(\) \|\| geteuid\(\)/);
  assert.match(text, /strictJSON\(data, OUTPUT_LIMIT\)/); assert.match(text, /fullCleanupVerified.*@NO/);
  assert.match(text, /SIGKILL\/power loss\/output loss may leave an issued lease/);
  assert.match(text, /if \(\*ended \|\| !\*owned\) return false/);
  assert.match(text, /rootDeadline = seconds\(\) \+ 175/);
  assert.match(text, /rootDeadline - seconds\(\) < INSERT_REQUIRED_SECONDS/);
  assert.match(text, /childAction\.sa_handler = SIG_DFL/); assert.match(text, /sigaction\(SIGCHLD,&childAction,NULL\)/);
  const header = await readFile(new URL('../native/macos-pf-routing/pf-single-filter-canary-inventory-832.h', import.meta.url), 'utf8');
  assert.equal((header.match(/^ \{"/gm) ?? []).length, 15);
  assert.match(header, /83256899dc6db90bb6a21dcd18d17cb08a46d3ba4e79177098629475cc107f78/);
  const build = await readFile(new URL('../scripts/build-macos-pf-single-filter-canary-832.mjs', import.meta.url), 'utf8');
  assert.match(build, /exec\(binary, \['--plan'\]/);
  assert.match(build, /nativeSourceSnapshot/); assert.match(build, /Buffer\.alloc\(65536\)/);
  assert.doesNotMatch(build, /exec\([^\n]*--request-canary|exec\([^\n]*--canary/);
});

test('builder hashes regular inputs with held descriptors and refuses symlinks', async () => {
  const { hashPFCanaryInput } = await import('../scripts/build-macos-pf-single-filter-canary-832.mjs');
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-pf-canary-hash-inert-')));
  try {
    const input = path.join(directory, 'input'), linked = path.join(directory, 'link');
    await writeFile(input, 'abc'); await symlink(input, linked);
    assert.equal((await hashPFCanaryInput(input)).sha256, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    await assert.rejects(hashPFCanaryInput(linked));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

// Mutation fixtures below never call the real ioctl adapter/native child.
test('inert filter faults preserve unknown state, refuse root DELETE, and never retry a transaction', onlyMac, async () => {
 const harness=helpers+`
int main(void){@autoreleasepool{
 for(unsigned scenario=0;scenario<5;scenario++){
  __block unsigned filters=0,deletes=0;interrupted=0;rootDeadline=seconds()+175;
  CanaryCall call=^NSDictionary *(unsigned op,NSDictionary *input,int *status){
   *status=0;
   if(op==3){filters++;if(scenario==0)return nil;
    if(scenario==1)return @{@"filterCycleVerified":@YES,@"filterDenyVerified":@YES,@"filterEmptyVerified":@YES,@"filterMutationAttempted":@YES,@"filterTransactionUncertain":@NO,@"reason":@"FILTER_EMPTY_DENY_EMPTY_VERIFIED",@"password":@"not-public"};
    return @{@"filterCycleVerified":@NO,@"filterDenyVerified":@NO,@"filterEmptyVerified":@((BOOL)(scenario!=3)),@"filterMutationAttempted":@YES,@"filterTransactionUncertain":@((BOOL)(scenario==2)),@"reason":@(EnvaraSingleFilterReasonName(ENVARA_SINGLE_FILTER_VERIFY_FAILED))};
   }
   if(op==1){NSMutableDictionary *p=proof(1,false,@"issued");p[@"lease"]=testLease();return decoded(p,1,false,0);}
   if(op==2){deletes++;return decoded(proof(2,false,@"retired"),2,false,0);}
   return decoded(proof(0,!input.count,input[@"runId"]?@"unused":input[@"lease"]?(deletes?@"retired":@"issued"):@"unselected"),0,!input.count,0);
  };
  NSDictionary *out=exchangeCanary(call,^NSDictionary *{return @{@"routes":ROOT_RULE,@"dns":ROOT_RULE,@"nat":ROOT_RULE,@"pfconf":ROOT_RULE};},^bool{return false;});
  if(filters!=1 || deletes>1 || [out[@"ok"] boolValue])return 10+scenario;
  if(scenario<4 && (deletes || ![out[@"cleanupUncertain"] boolValue]))return 20+scenario;
  if(scenario==4 && (deletes!=1 || [out[@"cleanupUncertain"] boolValue] || ![out[@"originalRootRestored"] boolValue]))return 30;
  NSDictionary *safe=report(@"canary",out,true);
  NSString *json=[[NSString alloc]initWithData:[NSJSONSerialization dataWithJSONObject:safe options:0 error:NULL] encoding:NSUTF8StringEncoding];
  if([json containsString:@"not-public"] || [json containsString:@"leaseId"] || [safe[@"fullCleanupVerified"] boolValue])return 40+scenario;
 }
 return 0;
}}
`;
 await fixture(binary=>execute(binary,[],{timeout:15000}),harness);
});
