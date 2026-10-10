/* Fixed post-retirement finalizer. The earlier recovery implementation is
 * included only for its audited readers. Its recover/main mutation path is
 * never called here: no PF token release, hook DELETE or group deletion. */
#define RECOVERY_INERT 1
#include "recovery-app-46ae-run904.m"
#include "recovery-app-46ae-run904-finalize-prior.h"
#define FINALIZER_SCHEMA @"envara.macos-pf-application-finalization/v1"
static const char recoveryMarker[] = "fixed46ae/run904 cleanup attempted; never replay token or DELETE\n";
static const char finalizerMarker[] = "fixed46ae/run904 filesystem finalization attempted; no PF or group operations\n";

static bool typedFlag(NSDictionary *v, NSString *key, bool expected) {
 return isBool(v[key]) && [v[key] boolValue] == expected;
}
static NSDictionary *sealedPriorReceipt(void) {
 NSData *bytes = [NSData dataWithBytes:finalizerPriorBytes length:sizeof(finalizerPriorBytes)];
 NSString *text = [[NSString alloc] initWithData:bytes encoding:NSUTF8StringEncoding];
 if (!text || ![hashText(text) isEqual:@FINALIZER_PRIOR_SHA]) return nil;
 NSDictionary *container = strictJSON(bytes,16384), *v = container[@"result"];
 if (!keys(container,@[@"checkedAt",@"exitCode",@"result"]) || ![container[@"checkedAt"] isEqual:@"2026-10-09T01:08:20.752Z"] ||
  isBool(container[@"exitCode"]) || ![container[@"exitCode"] isEqual:@1] || ![v isKindOfClass:NSDictionary.class] ||
  ![v[@"schema"] isEqual:@"envara.macos-pf-application-recovery-wrapper/v1"] || ![v[@"runId"] isEqual:CANARY_RUN] ||
  ![v[@"environmentId"] isEqual:FIXED_ENV] || ![v[@"manifestSHA256"] isEqual:@MF] ||
  ![v[@"recoveryBinarySHA256"] isEqual:@FINALIZER_PRIOR_BINARY_SHA] || ![v[@"reason"] isEqual:@"CLEANUP_UNCONFIRMED"] ||
  ![v[@"preflightGate"] isEqual:@"preflight-complete"]) return nil;
 for (NSString *key in @[@"rootTargetVerified",@"bootstrapRootTargetBound",@"preflightVerified",@"ownedGIDScopeAbsent",@"ownedFilterEmpty",
  @"rootRuntimeComponentsAbsent",@"rootHookRemoved",@"namespaceReclaimed",@"receiptRetired",@"ownedPFReferenceReleased",@"deleteAttempted",@"cleanupUncertain"])
  if (!typedFlag(v,key,true)) return nil;
 for (NSString *key in @[@"ok",@"ready",@"protected",@"productionReady",@"ownedGroupRemoved",@"runtimeArchived",@"cleanupConfirmed",@"originalHostBaselineVerified"])
  if (!typedFlag(v,key,false)) return nil;
 return v;
}
static NSMutableDictionary *finalizerOutcome(bool mutate) {
 NSMutableDictionary *v = outcome(mutate);
 v[@"schema"] = FINALIZER_SCHEMA;
 v[@"priorRecoveryReceiptSHA256"] = @FINALIZER_PRIOR_SHA;
 v[@"finalizationHostNetworkUnchanged"] = @NO;
 v[@"recoveryHostNetworkUnchanged"] = @NO;
 v[@"deleteAttempted"] = @NO;
 return v;
}
/* An absent exact namespace yields EINVAL rather than an active queue.
 * Accept only two equal EINVAL observations or stable zero-count readback;
 * an independent receipt-bound native STATUS proves absence on both sides. */
static bool retiredClassEmpty(int first, int firstErr, const EnvaraPFHookRequest *a,
 int second, int secondErr, const EnvaraPFHookRequest *b) {
 if (first == 0 && second == 0) return !a->nr && !b->nr && a->ticket == b->ticket;
 return first == -1 && second == -1 && firstErr == EINVAL && secondErr == EINVAL;
}
static bool retiredFilterEmpty(void) {
 int fd = open("/dev/pf",O_RDONLY|O_CLOEXEC|O_NOFOLLOW); struct stat device;
 if (fd < 0) return false;
 bool okay = !fstat(fd,&device) && S_ISCHR(device.st_mode) && !device.st_uid;
 const uint8_t actions[] = {0,2,4,6,8,11};
 for (size_t i=0; okay && i<sizeof(actions); i++) {
  EnvaraPFHookRequest a={0},b={0};strcpy(a.anchor,CANARY_ANCHOR.UTF8String);a.rule.action=actions[i];b=a;
  errno=0;int first=ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&a), firstErr=errno;
  errno=0;int second=ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&b), secondErr=errno;
  okay=retiredClassEmpty(first,firstErr,&a,second,secondErr,&b);
 }
 close(fd);if(!okay)return false;
 char *tables[]={(char*)"/sbin/pfctl",(char*)"-a",(char*)CANARY_ANCHOR.UTF8String,(char*)"-s",(char*)"Tables",NULL};
 char *children[]={(char*)"/sbin/pfctl",(char*)"-a",(char*)CANARY_ANCHOR.UTF8String,(char*)"-s",(char*)"Anchors",NULL};
 for(unsigned i=0;i<2;i++){int code=-1;NSString *text=command(i?children:tables,false,&code);
  if(!text||code||[text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length)return false;}
 return true;
}
static bool retiredRootProof(NSDictionary *v, NSDictionary *lease, int code) {
 return !code && validLease(lease) && rootProof(v) && [v[@"anchor"] isEqual:CANARY_ANCHOR] &&
  typedFlag(v,@"readOnly",true) && typedFlag(v,@"pfDisabled",true) && typedFlag(v,@"hookInstalled",false) &&
  typedFlag(v,@"ownedRootHookVerified",false) && typedFlag(v,@"ownedRootHookRemoved",true) &&
  typedFlag(v,@"originalRootRestored",true) && typedFlag(v,@"receiptRetired",true) && typedFlag(v,@"namespaceReclaimed",true) &&
  typedFlag(v,@"namespaceExists",false) && typedFlag(v,@"cleanupPending",false) &&
  [v[@"namespaceState"] isEqual:@"absent"] && [v[@"runLedgerState"] isEqual:@"retired"] &&
  (v[@"lease"] == NSNull.null || [v[@"lease"] isEqual:lease]);
}
/* Full fixed dscl inventory avoids relying on getgrgid's old-process cache or
 * undocumented missing-record exit codes. Unknown/truncated rows refuse. */
static NSString *negativeGroupList(NSString *text, NSString *name, gid_t gid) {
 if (![text isKindOfClass:NSString.class] || !text.length || text.length>OUTPUT_LIMIT) return nil;
 NSMutableSet *seen=[NSMutableSet set];NSMutableArray *rows=[NSMutableArray array];
 for(NSString *raw in [text componentsSeparatedByString:@"\n"]){
  NSString *line=[raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];if(!line.length)continue;
  NSArray *pieces=[[line componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet] filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(id value,NSDictionary *bindings){(void)bindings;return [value length]>0;}]];
  if(pieces.count!=2||!regex(pieces[0],@"^[A-Za-z0-9_.-]{1,255}$")||!regex(pieces[1],@"^([0-9]{1,10}|-[1-9][0-9]{0,9})$")||[seen containsObject:pieces[0]])return nil;
  long long signedValue=strtoll([pieces[1] UTF8String],NULL,10);
  if(signedValue<INT32_MIN||signedValue>UINT32_MAX)return nil;
  unsigned long long value=(uint32_t)signedValue;if([pieces[0] isEqual:name]||value==gid)return nil;
  [seen addObject:pieces[0]];[rows addObject:[NSString stringWithFormat:@"%@|%llu",pieces[0],value]];
 }
 return rows.count ? [[rows sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@"\n"] : nil;
}
static bool groupAlreadyAbsent(NSString *group, gid_t gid) {
 NSString *name=[group lastPathComponent];
 if(![group isEqual:[NSString stringWithFormat:@"/Groups/_envara_pf_%u",gid]])return false;
 errno=0;if(getgrgid(gid)!=NULL||errno)return false;
 errno=0;if(getgrnam(name.UTF8String)!=NULL||errno)return false;
 char *argv[]={(char*)"/usr/bin/dscl",(char*)".",(char*)"-list",(char*)"/Groups",(char*)"PrimaryGroupID",NULL};
 int code=-1;NSString *one=negativeGroupList(command(argv,false,&code),name,gid);if(!one||code)return false;
 NSString *two=negativeGroupList(command(argv,false,&code),name,gid);return !code&&two&&[one isEqual:two];
}
typedef struct {
 int parent,installed,runtime,lock,run,state;
 struct stat parentIdentity,runtimeIdentity,runIdentity,stateIdentity,recordIdentity,lockIdentity,leaseIdentity,recoveryIntentIdentity,finalizerIntentIdentity;
 NSData *recordBytes,*lockBytes,*leaseBytes,*recoveryIntentBytes,*finalizerIntentBytes;
 NSDictionary *lease,*hook;
 NSString *realm,*group;
 uint64_t gid,pid;
 bool intent;
} FinalizerContext;
static bool directoryIdentity(int fd,int parent,const char *name,const struct stat *expected,mode_t mode) {
 struct stat held,named;return secureFD(fd,true,mode)&&!fstat(fd,&held)&&!fstatat(parent,name,&named,AT_SYMLINK_NOFOLLOW)&&
  held.st_dev==expected->st_dev&&held.st_ino==expected->st_ino&&named.st_dev==held.st_dev&&named.st_ino==held.st_ino&&
  S_ISDIR(named.st_mode)&&named.st_uid==0&&named.st_gid==0&&(named.st_mode&07777)==mode;
}
static bool finalizerBinding(FinalizerContext *c, bool archived, int capsule) {
 struct stat p;int runtimeParent=archived?capsule:c->parent;const char *runtimeName=archived?"runtime":"io.envara.pf-runtime";
 if(!secureFD(c->parent,true,0)||fstat(c->parent,&p)||p.st_dev!=c->parentIdentity.st_dev||p.st_ino!=c->parentIdentity.st_ino||
  !directoryIdentity(c->runtime,runtimeParent,runtimeName,&c->runtimeIdentity,0700)||
  !directoryIdentity(c->run,c->runtime,CANARY_RUN.UTF8String,&c->runIdentity,0700)||
  !directoryIdentity(c->state,c->run,c->realm.UTF8String,&c->stateIdentity,0700)||
  !unchanged(c->runtime,"registry.json",&c->recordIdentity,c->recordBytes)||
  !unchanged(c->runtime,"registry.lock",&c->lockIdentity,c->lockBytes)||
  !unchanged(c->run,"app-bound-lease.json",&c->leaseIdentity,c->leaseBytes)||
  !unchanged(c->run,"recovery-46ae.intent",&c->recoveryIntentIdentity,c->recoveryIntentBytes)||
  !names(c->runtime,@[@"registry.json",@"registry.lock",CANARY_RUN])||!names(c->state,@[])||!absent(c->run,"app-filter-events"))return false;
 NSArray *runNames=c->intent?@[@"app-bound-lease.json",c->realm,@"recovery-46ae.intent",@"finalize-46ae.intent"]:@[@"app-bound-lease.json",c->realm,@"recovery-46ae.intent"];
 return names(c->run,runNames)&&(!c->intent||unchanged(c->run,"finalize-46ae.intent",&c->finalizerIntentIdentity,c->finalizerIntentBytes));
}
static bool freshFinalizerProof(FinalizerContext *c, NSMutableDictionary *out, bool archived, int capsule) {
 out[@"preflightGate"]=@"root-hook-readback";int code=-1;NSDictionary *one=nativeCall(0,@{@"lease":c->hook},&code,c->installed);
 if(!retiredRootProof(one,c->hook,code))return false;
 out[@"preflightGate"]=@"pf-empty";if(!retiredFilterEmpty())return false;
 NSDictionary *two=nativeCall(0,@{@"lease":c->hook},&code,c->installed);if(!retiredRootProof(two,c->hook,code))return false;
 /* Both native children have been reaped before enumerating every component. */
 out[@"preflightGate"]=@"controller-gone";if(!stillGone((pid_t)c->pid))return false;
 out[@"preflightGate"]=@"gid-scope-absent";if(envara_app_scope_gid_absent((gid_t)c->gid)!=1)return false;
 out[@"preflightGate"]=@"components-absent";if(!componentsAbsent(c->lease)){out[@"preflightGate"]=componentFailureReason;out[@"componentPid"]=@(componentFailurePid);return false;}
 out[@"preflightGate"]=@"dedicated-group";if(!groupAlreadyAbsent(c->group,(gid_t)c->gid))return false;
 out[@"preflightGate"]=@"empty-state-shape";return finalizerBinding(c,archived,capsule);
}
static bool writePrivateExact(int parent,const char *name,NSData *bytes,struct stat *identity) {
 int fd=openat(parent,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return false;
 bool okay=secureFD(fd,false,0600)&&bytes.length&&write(fd,bytes.bytes,bytes.length)==(ssize_t)bytes.length&&!fsync(fd)&&!fsync(parent);
 close(fd);NSData *readback=okay?privateRead(parent,name,65536,identity):nil;return readback&&[readback isEqual:bytes];
}
static int finalizeRun(bool mutate) {
 NSMutableDictionary *out=finalizerOutcome(mutate);rootDeadline=seconds()+175;
 out[@"preflightGate"]=@"rights";if(!rights()||!sealedPriorReceipt())return emit(out);
 out[@"preflightGate"]=@"root-credentials";gid_t zero=0;if(setgroups(1,&zero)||setgid(0)||setuid(0)||getuid()||geteuid())return emit(out);umask(077);
 struct sigaction sa={0};sa.sa_handler=onSignal;sigemptyset(&sa.sa_mask);
 for(unsigned i=0;i<4;i++){int signals[]={SIGTERM,SIGINT,SIGHUP,SIGPIPE};if(sigaction(signals[i],&sa,NULL))return emit(out);}
 sa.sa_handler=SIG_DFL;if(sigaction(SIGCHLD,&sa,NULL))return emit(out);
 FinalizerContext c={.parent=-1,.installed=-1,.runtime=-1,.lock=-1,.run=-1,.state=-1};
 int capsule=-1;struct stat capsuleIdentity,priorIdentity,receiptIdentity;NSData *priorBytes=nil,*receiptBytes=nil;NSDictionary *hostBefore=nil,*hostAfter=nil;
 do {
  out[@"preflightGate"]=@"root-parent";c.parent=directory(INSTALL_PARENT);if(c.parent<0||flock(c.parent,LOCK_EX|LOCK_NB)||fstat(c.parent,&c.parentIdentity))break;
  out[@"preflightGate"]=@"installed-inventory";c.installed=verifiedInstallation(MIN(rootDeadline,seconds()+30));if(c.installed<0)break;
  out[@"preflightGate"]=@"private-runtime";c.runtime=directory(RUNTIME);if(!secureFD(c.runtime,true,0700)||fstat(c.runtime,&c.runtimeIdentity))break;
  struct stat heldLock;
  out[@"preflightGate"]=@"registry-lock";c.lock=openat(c.runtime,"registry.lock",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(c.lock,false,0600)||flock(c.lock,LOCK_EX|LOCK_NB)||fstat(c.lock,&heldLock))break;
  out[@"preflightGate"]=@"registry-shape";c.recordBytes=privateRead(c.runtime,"registry.json",65536,&c.recordIdentity);NSDictionary *record=strictJSON(c.recordBytes,65536);
  c.lockBytes=privateRead(c.runtime,"registry.lock",4096,&c.lockIdentity);NSDictionary *lockValue=strictJSON(c.lockBytes,4096);
  if(!sameStat(&heldLock,&c.lockIdentity)||!keys(lockValue,@[@"runId",@"pid",@"anchor"])||![lockValue[@"runId"] isEqual:CANARY_RUN]||![lockValue[@"anchor"] isEqual:CANARY_ANCHOR]||![lockValue[@"pid"] isEqual:record[@"supervisorPid"]])break;
  out[@"preflightGate"]=@"run-directory";c.run=openat(c.runtime,CANARY_RUN.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(c.run,true,0700)||fstat(c.run,&c.runIdentity))break;
  out[@"preflightGate"]=@"lease-shape";c.leaseBytes=privateRead(c.run,"app-bound-lease.json",16384,&c.leaseIdentity);c.lease=strictJSON(c.leaseBytes,16384);NSString *unusedToken=nil;
  NSString *realm=nil,*group=nil;NSDictionary *hook=nil;
  if(!contextShape(record,c.lease,c.leaseBytes,&c.gid,&c.pid,&realm,&hook,&group,&unusedToken))break;
  c.realm=realm;c.group=group;c.hook=hook;
  out[@"preflightGate"]=@"state-directory";c.state=openat(c.run,c.realm.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(c.state,true,0700)||fstat(c.state,&c.stateIdentity))break;
  c.recoveryIntentBytes=privateRead(c.run,"recovery-46ae.intent",4096,&c.recoveryIntentIdentity);
  if(![c.recoveryIntentBytes isEqual:[NSData dataWithBytes:recoveryMarker length:sizeof(recoveryMarker)-1]]||!absent(c.parent,CAPSULE)||!freshFinalizerProof(&c,out,false,-1))break;
  out[@"preflightGate"]=@"preflight-complete";
  out[@"preflightVerified"]=@YES;out[@"ownedGIDScopeAbsent"]=@YES;out[@"ownedFilterEmpty"]=@YES;out[@"rootRuntimeComponentsAbsent"]=@YES;
  out[@"ok"]=@YES;out[@"reason"]=@"READ_ONLY_PREFLIGHT_VERIFIED";if(!mutate)break;
  out[@"ok"]=@NO;out[@"reason"]=@"CLEANUP_UNCONFIRMED";
  hostBefore=hostSnapshot();if(!hostBefore||seconds()+60>=rootDeadline||interrupted||!freshFinalizerProof(&c,out,false,-1))break;
  c.finalizerIntentBytes=[NSData dataWithBytes:finalizerMarker length:sizeof(finalizerMarker)-1];
  if(!writePrivateExact(c.run,"finalize-46ae.intent",c.finalizerIntentBytes,&c.finalizerIntentIdentity))break;c.intent=true;
  if(!freshFinalizerProof(&c,out,false,-1)||!absent(c.parent,CAPSULE)||interrupted)break;
  if(mkdirat(c.parent,CAPSULE,0700))break;
  capsule=openat(c.parent,CAPSULE,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(capsule,true,0700)||fstat(capsule,&capsuleIdentity)||!names(capsule,@[]))break;
  priorBytes=[NSData dataWithBytes:finalizerPriorBytes length:sizeof(finalizerPriorBytes)];
  if(!writePrivateExact(capsule,"prior-root-recovery.json",priorBytes,&priorIdentity))break;
  NSMutableDictionary *pending=finalizerOutcome(true);pending[@"reason"]=@"CLEANUP_UNCONFIRMED";pending[@"preflightGate"]=@"preflight-complete";
  /* Archive evidence records the actual pre-rename boundary. Completion is
   * emitted only after rename/fsync/readback and a fifth full fresh proof. */
  receiptBytes=[NSJSONSerialization dataWithJSONObject:pending options:NSJSONWritingWithoutEscapingSlashes error:NULL];
  if(!writePrivateExact(capsule,"finalization-proof.json",receiptBytes,&receiptIdentity)||fsync(c.parent))break;
  if(!directoryIdentity(capsule,c.parent,CAPSULE,&capsuleIdentity,0700)||!names(capsule,@[@"prior-root-recovery.json",@"finalization-proof.json"])||
   !unchanged(capsule,"prior-root-recovery.json",&priorIdentity,priorBytes)||!unchanged(capsule,"finalization-proof.json",&receiptIdentity,receiptBytes)||
   interrupted||seconds()+15>=rootDeadline||!freshFinalizerProof(&c,out,false,-1))break;
  if(renameatx_np(c.parent,"io.envara.pf-runtime",capsule,"runtime",RENAME_EXCL)||fsync(capsule)||fsync(c.parent))break;
  if(!absent(c.parent,"io.envara.pf-runtime")||!directoryIdentity(capsule,c.parent,CAPSULE,&capsuleIdentity,0700)||!names(capsule,@[@"prior-root-recovery.json",@"finalization-proof.json",@"runtime"])||
   !unchanged(capsule,"prior-root-recovery.json",&priorIdentity,priorBytes)||!unchanged(capsule,"finalization-proof.json",&receiptIdentity,receiptBytes)||
   !freshFinalizerProof(&c,out,true,capsule))break;
  hostAfter=hostSnapshot();if(!hostAfter||![hostBefore isEqual:hostAfter]||interrupted)break;
  out[@"preflightGate"]=@"preflight-complete";
  /* Cumulative run facts, not operations replayed by this finalizer. */
  for(NSString *key in @[@"rootHookRemoved",@"namespaceReclaimed",@"receiptRetired",@"ownedPFReferenceReleased",@"deleteAttempted",@"ownedGroupRemoved",@"runtimeArchived"])out[key]=@YES;
  out[@"finalizationHostNetworkUnchanged"]=@YES;out[@"cleanupUncertain"]=@NO;out[@"cleanupConfirmed"]=@YES;out[@"ok"]=@YES;out[@"reason"]=@"EXACT_RECOVERY_COMPLETED";
 } while(0);
 if(capsule>=0)close(capsule);if(c.state>=0)close(c.state);if(c.run>=0)close(c.run);if(c.lock>=0)close(c.lock);
 if(c.runtime>=0)close(c.runtime);if(c.installed>=0)close(c.installed);if(c.parent>=0)close(c.parent);return emit(out);
}
#ifndef FINALIZER_INERT
int main(int argc,char **argv){@autoreleasepool{
 if(argc!=2)return emit(finalizerOutcome(false));
 if(!strcmp(argv[1],"--plan")){NSMutableDictionary *v=finalizerOutcome(false);v[@"ok"]=sealedPriorReceipt()?@YES:@NO;v[@"reason"]=@"INERT_PLAN";v[@"runtimeLeafCount"]=@(sizeof(files)/sizeof(files[0]));return emit(v);}
 if(!strcmp(argv[1],"--inspect-fixed-root"))return finalizeRun(false);
 if(!strcmp(argv[1],"--cleanup-fixed-root"))return finalizeRun(true);
 return emit(finalizerOutcome(false));
}}
#endif
