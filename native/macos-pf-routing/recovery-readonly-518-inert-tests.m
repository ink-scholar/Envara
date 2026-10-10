/* INERT parser/output tests: compile/run only after root reviews. No main
 * activation entry, process probes, file access, child spawn or native rights.
 * Not linked into the resource snapshot or authorization carrier. */
#define ENVARA_RECOVERY_INERT_TEST 1
#include "recovery-readonly-518.m"
#include <assert.h>
static NSData *json(id value) { return [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingWithoutEscapingSlashes error:NULL]; }
static NSDictionary *fixtureLease(void) {
 NSString *id = @"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
 NSString *label = [@"envara.hook.v1." stringByAppendingString:[hashText([NSString stringWithFormat:@"%@|%@",FIXED_RUN,id]) substringToIndex:32]];
 return @{@"schema": @"envara.macos-pf-owned-root-hook-lease/v1", @"runId": FIXED_RUN, @"leaseId": id,
  @"anchor": FIXED_ANCHOR, @"owner": FIXED_ANCHOR, @"label": label, @"ticket": @"12345", @"rootBeforeSHA256": ROOT_RULE, @"rootBeforeTextSHA256": ROOT_TEXT};
}
static NSDictionary *fixtureRecord(void) {
 return @{@"schema": @"envara.macos-pf-owned-registry/v1", @"runId": FIXED_RUN, @"supervisorPid": @999,
  @"anchor": FIXED_ANCHOR, @"phase": @"cleanup-required", @"cleanupUncertain": @YES,
  @"rootHook": @{@"mutationAttempted": @YES, @"verified": @YES, @"removed": @NO, @"lease": fixtureLease()},
  @"ownedPFReference": @{@"attempted": @YES, @"acquired": @YES, @"released": @YES, @"token": @"private-token"},
  @"incompleteGroupAllocations": @[], @"realms": @[], @"guardians": @[]};
}
typedef struct { unsigned char action; unsigned count; int mode, calls; } RuleMock;
static int mockRuleReader(int fd,unsigned long operation,EnvaraPFHookRequest *request,void *context) {
 (void)fd; RuleMock *mock=context; assert(operation==ENVARA_PF_HOOK_GET_RULES); assert(request->action==0);
 assert(request->rule.action==mock->action); assert(!strcmp(request->anchor,"io.envara.pf.root.v1"));
 assert(!request->anchor_call[0]); mock->calls++;
 if(mock->mode==2) { errno=EINVAL; return -1; }
 if(mock->mode==3) { errno=EPERM; return -1; }
 if(mock->mode==4 && mock->calls==2) { errno=EINVAL; return -1; }
 request->nr=mock->mode==5?9000:mock->mode==6?mock->count+(unsigned)mock->calls:mock->count;
 request->ticket=mock->mode==1?(uint32_t)(100+mock->calls):100;
 return 0;
}
static void inertCountAndListingTests(void) {
 NSMutableArray *rows=[NSMutableArray array];
 for(size_t i=0;i<sizeof(ruleActions);i++) { RuleMock mock={ruleActions[i],0,0,0};
  NSDictionary *row=readRuleClass(-1,ruleActions[i],mockRuleReader,&mock); assert(mock.calls==2);
  assert([row[@"outcome"] isEqual:@"present"] && [row[@"stable"] boolValue] && [row[@"count"] integerValue]==0);
  assert(!row[@"ticket"]); [rows addObject:row]; }
 NSDictionary *counts=safeActiveCounts(@{@"classes":rows,@"privateTicket":@"DO_NOT_LOG_PRIVATE"});
 assert([counts[@"readable"] boolValue] && [counts[@"allActiveRulesEmptyOrAbsent"] boolValue]); assert(!counts[@"privateTicket"]);
 RuleMock changed={0,0,1,0}; NSDictionary *row=readRuleClass(-1,0,mockRuleReader,&changed);
 assert([row[@"outcome"] isEqual:@"unstable"] && ![row[@"stable"] boolValue] && row[@"count"]==NSNull.null);
 RuleMock countChanged={0,0,6,0}; row=readRuleClass(-1,0,mockRuleReader,&countChanged); assert([row[@"outcome"] isEqual:@"unstable"]);
 RuleMock absent={2,0,2,0}; row=readRuleClass(-1,2,mockRuleReader,&absent);
 assert([row[@"outcome"] isEqual:@"absent"] && [row[@"errnoClass"] isEqual:@"EINVAL"] && [row[@"stable"] boolValue]);
 RuleMock denied={4,0,3,0}; row=readRuleClass(-1,4,mockRuleReader,&denied);
 assert([row[@"outcome"] isEqual:@"unreadable"] && [row[@"errnoClass"] isEqual:@"NON_EINVAL"] && ![row[@"stable"] boolValue]);
 RuleMock mixed={6,0,4,0}; row=readRuleClass(-1,6,mockRuleReader,&mixed);
 assert([row[@"outcome"] isEqual:@"unstable"] && [row[@"errnoClass"] isEqual:@"MIXED_RESULT"]);
 RuleMock oversized={8,0,5,0}; row=readRuleClass(-1,8,mockRuleReader,&oversized); assert([row[@"outcome"] isEqual:@"unreadable"]);
 RuleMock invalid={12,0,0,0}; assert(!readRuleClass(-1,12,mockRuleReader,&invalid) && invalid.calls==0);
 NSMutableDictionary *bad=[rows[0] mutableCopy]; bad[@"count"]=@9000; rows[0]=bad; assert(!safeActiveCounts(@{@"classes":rows}));
 NSData *zero=[@"\n" dataUsingEncoding:NSASCIIStringEncoding];
 NSDictionary *tables=listingObservation(zero,zero,true); assert([tables[@"emptyVerified"] boolValue]); assert(safeListing(tables,true));
 NSData *owned=[@"--a-r- DO_NOT_LOG_PRIVATE\n" dataUsingEncoding:NSASCIIStringEncoding];
 tables=listingObservation(owned,owned,true); assert([tables[@"count"] integerValue]==1 && ![tables[@"emptyVerified"] boolValue]);
 NSString *safeText=[[NSString alloc] initWithData:json(safeListing(tables,true)) encoding:NSUTF8StringEncoding];
 assert([safeText rangeOfString:@"DO_NOT_LOG_PRIVATE"].location==NSNotFound);
 NSData *unknown=[@"UNKNOWN-PRIVATE-FORMAT\n" dataUsingEncoding:NSASCIIStringEncoding];
 tables=listingObservation(zero,unknown,true); assert(![tables[@"formatVerified"] boolValue] && ![tables[@"emptyVerified"] boolValue]);
 assert([tables[@"entriesPresent"] boolValue] && tables[@"count"]==NSNull.null);
 tables=listingObservation(nil,nil,true); assert(![tables[@"readSucceeded"] boolValue] && ![tables[@"emptyVerified"] boolValue]);
 NSDictionary *anchors=listingObservation([@"DO_NOT_LOG_PRIVATE\n" dataUsingEncoding:NSASCIIStringEncoding],zero,false);
 assert(![anchors[@"stable"] boolValue] && ![anchors[@"emptyVerified"] boolValue] && anchors[@"count"]==NSNull.null);
}
int main(void) { @autoreleasepool {
 inertCountAndListingTests();
 assert(sizeof(files)/sizeof(files[0]) == 14);
 assert(validLease(fixtureLease())); assert(validRegistry(json(fixtureRecord())));
 NSMutableDictionary *lease = [fixtureLease() mutableCopy]; lease[@"runId"] = @"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"; assert(!validLease(lease));
 lease = [fixtureLease() mutableCopy]; lease[@"ticket"] = @"18446744073709551616"; assert(!validLease(lease));
 lease = [fixtureLease() mutableCopy]; lease[@"label"] = @"forged-label"; assert(!validLease(lease));
 lease = [fixtureLease() mutableCopy]; lease[@"extra"] = @"private"; assert(!validLease(lease));
 NSMutableDictionary *record = [fixtureRecord() mutableCopy]; record[@"runId"] = @"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"; assert(!validRegistry(json(record)));
 record = [fixtureRecord() mutableCopy]; record[@"cleanupUncertain"] = @1; assert(!validRegistry(json(record)));
 assert(!strictJSON([@"{\"runId\":\"one\",\"runId\":\"two\"}" dataUsingEncoding:NSUTF8StringEncoding],65536));
 assert(!strictJSON([@"{\"nested\":{\"x\":1,\"x\":2}}" dataUsingEncoding:NSUTF8StringEncoding],65536));
 assert(!strictJSON([@"{\"x\":\"\\u0078\"}" dataUsingEncoding:NSUTF8StringEncoding],65536));
 assert(!strictJSON([NSMutableData dataWithLength:65537],65536));
 NSDictionary *native = @{@"schema": @"envara.macos-pf-owned-root-hook/v1", @"operation": @"hook-status", @"anchor": FIXED_ANCHOR,
  @"readOnly": @YES, @"ok": @YES, @"pfDisabled": @YES, @"pinsVerified": @YES, @"originalRootCompatible": @YES,
  @"ownedRootHookVerified": @NO, @"hookInstalled": @NO, @"canCreateOwnedHook": @YES, @"ownedRootHookCanCreate": @YES, @"priorAnchorsCompatible": @YES,
  @"originalRootSHA256": ROOT_RULE, @"originalRootTextSHA256": ROOT_TEXT, @"reason": @"READ_ONLY_OWNED_HOOK_PROOF", @"lease": fixtureLease()};
 NSDictionary *proof = safeHook(native); assert(proof); assert(!proof[@"lease"]); assert(!proof[@"label"]); assert(!proof[@"ticket"]);
 NSMutableDictionary *malformed = [native mutableCopy]; malformed[@"pfDisabled"] = @1; assert(!safeHook(malformed));
 NSMutableDictionary *report = baseResult(); report[@"lease"] = fixtureLease(); report[@"privateToken"] = @"DO_NOT_LOG_PRIVATE";
 report[@"privateLeaseRootProof"] = proof; report[@"reason"] = @"READ_ONLY_FIXED_RUN_INSPECTED"; report[@"inspectionCompleted"] = @YES;
 NSDictionary *safe = safeReport(report); assert(safe); assert(!safe[@"lease"]); assert(!safe[@"privateToken"]);
 NSString *out = [[NSString alloc] initWithData:json(safe) encoding:NSUTF8StringEncoding]; assert([out rangeOfString:@"DO_NOT_LOG_PRIVATE"].location == NSNotFound);
 assert(![safe[@"cleanupConfirmed"] boolValue]); assert(![safe[@"productionReady"] boolValue]);
 report[@"controlledProcessProof"]=@{@"recordedProcessCount":@11,@"absentPIDsDoubleChecked":@11,@"controlledProcessesGone":@((BOOL)(11==11))};
 safe=safeReport(report); assert(isBool(safe[@"controlledProcessProof"][@"controlledProcessesGone"]));
 assert([safe[@"controlledProcessProof"][@"controlledProcessesGone"] boolValue]);
 NSMutableDictionary *inventory=[@{@"schema":@"envara.macos-pf-runtime-inventory/v1",@"readOnly":@YES,@"cleanupConfirmed":@YES,
  @"productionReady":@YES,@"exactInventoryVerified":@YES,@"inventorySHA256":NSNull.null,@"reason":@"READ_ONLY_FIXED_RUNTIME_INVENTORY",
  @"privateConfig":@"DO_NOT_LOG_PRIVATE"} mutableCopy];
 NSDictionary *safeInventory=safeRuntimeInventory(inventory); assert(!safeInventory[@"privateConfig"]);
 assert(![safeInventory[@"cleanupConfirmed"] boolValue] && ![safeInventory[@"productionReady"] boolValue]);
 puts("Readonly fixed-run parser/output inert tests passed; no system inspection performed."); return 0;
} }
