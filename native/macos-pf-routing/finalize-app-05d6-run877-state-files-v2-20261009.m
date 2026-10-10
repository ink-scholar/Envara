/* Fixed run877 post-retirement finalizer. Prior system operations have already
 * happened and are sealed below. This source does not include the recovery
 * translation unit and cannot repeat PF writes, token release, DELETE, group
 * operations or signals to old processes. Only bounded private proof/intent
 * files and one held-inode whole-runtime rename are writable operations.
 * Historical host snapshot equality is observational and never claimed true.
 */
#define INSPECTOR_INERT 1
#include "inspector-app-05d6-run877-v2.m"
#include "finalize-app-05d6-run877-prior-20261009.h"
#include <arpa/inet.h>
#include <net/if.h>
#define F877_CAPSULE "io.envara.pf-recovery-05d6-877ab9cc-state-files"
#define F877_RECOVERY_INTENT "recovery-05d6-run877-state-files.intent"
#define F877_FINALIZE_INTENT "finalize-05d6-run877-state-files.intent"
typedef struct {int installed,parent,cap,runtime,lock,run,state;struct stat parent_i,cap_i,runtime_i,run_i,state_i,registry_i,lock_i,lease_i,config_i,intent_i,before_i,final_intent_i,prior_i,proof_i;
 NSData *registry_bytes,*lock_bytes,*lease_bytes,*config_bytes,*intent_bytes,*before_bytes,*final_intent_bytes,*prior_bytes,*proof_bytes;NSDictionary *record,*lease,*transport,*journal,*baseline;uint64_t gid;bool final_intent;unsigned host_difference_mask;}F877Context;
static NSMutableDictionary *f877Outcome(bool mutation){
 return [@{@"schema":@"envara.macos-pf-live-application-finalization/v1",@"manifestSHA256":@MF,@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,
 @"readOnly":@((BOOL)!mutation),@"ok":@NO,@"reason":@"FINALIZATION_PREFLIGHT_REFUSED",@"gate":@"not-started",
 @"cleanupConfirmed":@NO,@"cleanupUncertain":@YES,@"originalApplicationHostBaselineVerified":@NO,
 @"ready":@NO,@"protected":@NO,@"productionReady":@NO,@"fullGuardFailureAccepted":@NO,
 @"ownedGIDScopeAbsent":@NO,@"ownedDenialVerified":@NO,@"ownedFrontVerified":@NO,@"originalDescriptorCustodyVerified":@NO,@"uniqueCurrentKeeperCustodyVerified":@NO,
 @"controllerStopped":@NO,@"keeperStopped":@NO,@"ownedFilterClearAttempted":@NO,@"ownedFilterEmptyVerified":@NO,
 @"keeperExitObserved":@NO,@"controllerExitObserved":@NO,@"ownedInterfaceAbsent":@NO,@"ownedListenerAbsent":@NO,
 @"ownedPFReferenceReleaseAttempted":@NO,@"ownedPFReferenceReleased":@NO,@"rootHookDeleteAttempted":@NO,
 @"rootHookRemoved":@NO,@"originalRootRestored":@NO,@"receiptRetired":@NO,@"namespaceReclaimed":@NO,
 @"ownedGroupDeleteAttempted":@NO,@"ownedGroupRemoved":@NO,@"runtimeArchived":@NO,@"recoveryScopeHostNetworkRestored":@NO,
 @"coreStopped":@NO,@"coreTerminateAttempted":@NO,@"coreTerminatedObserved":@NO,@"coreReapedByRecovery":@NO,
 @"frontZombieBound":@NO,@"coreFinalAbsent":@NO,@"frontFinalAbsent":@NO,@"currentUTunAliasCustodyVerified":@NO,
 @"globalFlushExecuted":@NO,@"PFEnableExecuted":@NO,@"globalPoolResetExecuted":@NO,@"applicationLaunchExecuted":@NO}mutableCopy];
}
static NSData *f877HashData(NSData*d){unsigned char digest[32];CC_SHA256(d.bytes,(CC_LONG)d.length,digest);return [NSData dataWithBytes:digest length:32];}
static NSString *f877HexData(NSData*d){NSData*h=f877HashData(d);char hex[65];for(NSUInteger i=0;i<h.length;i++)snprintf(hex+2*i,3,"%02x",((const unsigned char*)h.bytes)[i]);return @(hex);}
static bool f877HostPins(void){
 char os[128]={0},kernel[1024]={0};size_t a=sizeof(os),b=sizeof(kernel);
 if(sysctlbyname("kern.osrelease",os,&a,NULL,0)||sysctlbyname("kern.version",kernel,&b,NULL,0)||a>sizeof(os)||b>sizeof(kernel)||
 !memchr(os,0,sizeof(os))||!memchr(kernel,0,sizeof(kernel))||strcmp(os,"27.0.0")||!strstr(kernel,"xnu-13432.0.94.501.4~1/RELEASE_ARM64_T6020"))return false;
 const char*parents[]={"/sbin","/usr/libexec"},*leaves[]={"pfctl","pfd"};const char*hashes[]={"ceae69b705ccb481c9bce4fc4a3b9fb8cb4e9775b09677901bac6f4c44398bef","ce0e2352db81ea01fdc592c56447c5f89a3ee1a923122ef6ba5f78259bc47049"};
 for(unsigned i=0;i<2;i++){int parent=directory(parents[i]);int fd=parent<0?-1:openat(parent,leaves[i],O_RDONLY|O_NOFOLLOW|O_CLOEXEC);bool ok=secureFD(fd,false,0)&&hashFD(fd,hashes[i],rootDeadline);if(fd>=0)close(fd);if(parent>=0)close(parent);if(!ok)return false;}return true;
}
static bool f877NumericIPv4Endpoint(NSString*text){
 if(![text isKindOfClass:NSString.class]||text.length>32)return false;NSRange dot=[text rangeOfString:@"."options:NSBackwardsSearch];if(dot.location==NSNotFound)return false;
 NSString*address=[text substringToIndex:dot.location],*service=[text substringFromIndex:dot.location+1];
 if(![service isEqual:@"*"]){if(!regex(service,@"^(0|[1-9][0-9]{0,4})$")||service.longLongValue>UINT16_MAX)return false;}
 struct in_addr ip;return [address isEqual:@"*"]||inet_pton(AF_INET,address.UTF8String,&ip)==1;
}
static bool f877PortRows(NSString*text,uint16_t port,bool expectListener){
 if(![text isKindOfClass:NSString.class]||!text.length||text.length>OUTPUT_LIMIT)return false;
 bool header=false;unsigned matches=0;
 for(NSString*raw in [text componentsSeparatedByString:@"\n"]){NSString*line=[raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];if(!line.length)continue;
  if([line hasPrefix:@"Active Internet connections"])continue;
  if(regex(line,@"^Proto[ \\t]+Recv-Q[ \\t]+Send-Q[ \\t]+Local Address[ \\t]+Foreign Address[ \\t]+[(]state[)]([ \\t].*)?$")){if(header)return false;header=true;continue;}
  if(!header)return false;NSArray*f=[[line componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet]filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"length > 0"]];
  if(f.count<6||f.count>32||![@[@"tcp4",@"tcp46"]containsObject:f[0]]||!regex(f[1],@"^[0-9]+$")||!regex(f[2],@"^[0-9]+$")||
   !f877NumericIPv4Endpoint(f[3])||!f877NumericIPv4Endpoint(f[4])||
   ![@[@"CLOSED",@"LISTEN",@"SYN_SENT",@"SYN_RECEIVED",@"SYN_RCVD",@"ESTABLISHED",@"CLOSE_WAIT",@"FIN_WAIT_1",@"CLOSING",@"LAST_ACK",@"FIN_WAIT_2",@"TIME_WAIT"]containsObject:f[5]])return false;
  NSString*suffix=[NSString stringWithFormat:@".%u",port];if([f[5]isEqual:@"LISTEN"]&&([f[3]isEqual:[@"127.0.0.1"stringByAppendingString:suffix]]||[f[3]isEqual:[@"*"stringByAppendingString:suffix]]))matches++;
 }
 return header&&matches==(expectListener?1U:0U);
}
static bool f877PortObservation(F877Context*c,bool listener){
 /* Numeric kernel TCP inventory only, no bind/connect or unrelated process FD
  * inspection. Two bounded reads must agree on this exact IPv4 front port. */
 char*argv[]={(char*)"/usr/sbin/netstat",(char*)"-an",(char*)"-p",(char*)"tcp",(char*)"-f",(char*)"inet",NULL};int code=-1;
 NSString*one=command(argv,false,&code);if(!one||code||!f877PortRows(one,[c->transport[@"frontPort"]unsignedShortValue],listener))return false;
 NSString*two=command(argv,false,&code);return two&&!code&&f877PortRows(two,[c->transport[@"frontPort"]unsignedShortValue],listener);
}
static bool f877StatesEmpty(void){int code=-1;char*argv[]={(char*)"/sbin/pfctl",(char*)"-ss",NULL};NSString*s=command(argv,false,&code);return s&&code==0&&![s stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length;}
static NSString *f877GroupRows(NSString*text,gid_t gid,bool present){
 if(![text isKindOfClass:NSString.class]||!text.length||text.length>OUTPUT_LIMIT)return nil;NSMutableSet*seen=[NSMutableSet set];NSMutableArray*normalized=[NSMutableArray array];NSString*owned=[NSString stringWithFormat:@"_envara_pf_%u",gid];unsigned ownedRows=0;
 for(NSString*raw in [text componentsSeparatedByString:@"\n"]){NSString*line=[raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];if(!line.length)continue;
  NSArray*f=[[line componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet]filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"length > 0"]];
  if(f.count!=2||!regex(f[0],@"^[A-Za-z0-9_.-]{1,255}$")||!regex(f[1],@"^(0|[1-9][0-9]{0,9}|-[1-9][0-9]{0,9})$")||[seen containsObject:f[0]])return nil;
  errno=0;long long value=strtoll([f[1]UTF8String],NULL,10);if(errno||value<INT32_MIN||value>UINT32_MAX)return nil;if([f[0]isEqual:owned]||(uint32_t)value==gid){if(!present||![f[0]isEqual:owned]||(uint32_t)value!=gid)return nil;ownedRows++;}
  [seen addObject:f[0]];[normalized addObject:[NSString stringWithFormat:@"%@|%u",f[0],(uint32_t)value]];
 }return normalized.count&&ownedRows==(present?1U:0U)?[[normalized sortedArrayUsingSelector:@selector(compare:)]componentsJoinedByString:@"\n"]:nil;
}
static bool f877GroupInventory(gid_t gid,bool present){char*argv[]={(char*)"/usr/bin/dscl",(char*)".",(char*)"-list",(char*)"/Groups",(char*)"PrimaryGroupID",NULL};int code=-1;
 NSString*one=f877GroupRows(command(argv,false,&code),gid,present);if(!one||code)return false;NSString*two=f877GroupRows(command(argv,false,&code),gid,present);return !code&&two&&[one isEqual:two];}
static bool f877GroupAbsent(gid_t gid){return f877GroupInventory(gid,false);}
static bool f877WritePrivate(int parent,const char*name,NSData*bytes,struct stat*identity){
 int fd=openat(parent,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);bool ok=secureFD(fd,false,0600)&&bytes.length>0&&bytes.length<=65536&&write(fd,bytes.bytes,bytes.length)==(ssize_t)bytes.length&&!fsync(fd)&&!fsync(parent);if(fd>=0)close(fd);
 return ok&&[privateRead(parent,name,65536,identity)isEqual:bytes];
}
static NSDictionary *f877SealedPrior(void){
 NSData*d=[NSData dataWithBytes:f877PriorBytes length:sizeof(f877PriorBytes)];if(![f877HexData(d)isEqual:@F877_PRIOR_SHA])return nil;
 NSDictionary*container=strictJSON(d,16384),*v=container[@"result"];
 if(!container||![container[@"schema"]isEqual:@"envara.fixed-live-recovery-actual/v1"]||![container[@"checkedAt"]isEqual:@"2026-10-09T08:41:51.279159+00:00"]||
 !boolValue(container[@"sourceAndSignaturesVerified"],true)||!boolValue(container[@"freshReadonlyVerified"],true)||!boolValue(container[@"cleanupAttempted"],true)||
 !boolValue(container[@"cleanupConfirmed"],false)||![container[@"exitCode"]isEqual:@1]||![v[@"schema"]isEqual:@"envara.macos-pf-live-application-recovery-wrapper/v1"]||
 ![v[@"runId"]isEqual:CANARY_RUN]||![v[@"environmentId"]isEqual:FIXED_ENV]||![v[@"manifestSHA256"]isEqual:@MF]||
 ![v[@"recoveryBinarySHA256"]isEqual:@"54ed301d7721f227540b49855b84094b0e3316901ac794f93313fe93d56d69b0"]||
 ![v[@"reason"]isEqual:@"FIXED_LIVE_RECOVERY_UNCONFIRMED"]||![v[@"gate"]isEqual:@"recovery-scope-host-network-postflight"])return nil;
 for(NSString*k in @[@"ownedGIDScopeAbsent",@"ownedFilterEmptyVerified",@"keeperExitObserved",@"controllerExitObserved",@"ownedInterfaceAbsent",@"ownedListenerAbsent",@"ownedPFReferenceReleased",@"rootHookRemoved",@"originalRootRestored",@"receiptRetired",@"namespaceReclaimed",@"ownedGroupRemoved",@"coreFinalAbsent",@"frontFinalAbsent",@"cleanupUncertain"])if(!boolValue(v[k],true))return nil;
 for(NSString*k in @[@"ok",@"cleanupConfirmed",@"runtimeArchived",@"recoveryScopeHostNetworkRestored",@"originalApplicationHostBaselineVerified",@"ready",@"protected",@"productionReady",@"ownedDenialVerified",@"coreReapedByRecovery",@"globalFlushExecuted",@"PFEnableExecuted",@"globalPoolResetExecuted",@"applicationLaunchExecuted"])if(!boolValue(v[k],false))return nil;
 return v;
}
static bool f877Directory(int held,int parent,const char*name,const struct stat*expected,mode_t mode){
 struct stat a,b;return secureFD(held,true,mode)&&!fstat(held,&a)&&!fstatat(parent,name,&b,AT_SYMLINK_NOFOLLOW)&&a.st_dev==expected->st_dev&&a.st_ino==expected->st_ino&&b.st_dev==a.st_dev&&b.st_ino==a.st_ino;
}
static bool f877PrivateStable(F877Context*c,bool archived){
 struct stat parent;NSArray*runNames=c->final_intent?@[@"app-bound-lease.json",c->lease[@"realmId"],@"app-filter-events",@F877_RECOVERY_INTENT,@F877_FINALIZE_INTENT]:@[@"app-bound-lease.json",c->lease[@"realmId"],@"app-filter-events",@F877_RECOVERY_INTENT];
 return !fstat(c->parent,&parent)&&parent.st_dev==c->parent_i.st_dev&&parent.st_ino==c->parent_i.st_ino&&
  f877Directory(c->cap,c->parent,F877_CAPSULE,&c->cap_i,0700)&&f877Directory(c->runtime,archived?c->cap:c->parent,archived?"runtime":"io.envara.pf-runtime",&c->runtime_i,0700)&&
  f877Directory(c->run,c->runtime,CANARY_RUN.UTF8String,&c->run_i,0700)&&f877Directory(c->state,c->run,[c->lease[@"realmId"]UTF8String],&c->state_i,0700)&&
  unchanged(c->runtime,"registry.json",&c->registry_i,c->registry_bytes)&&unchanged(c->runtime,"registry.lock",&c->lock_i,c->lock_bytes)&&
  unchanged(c->run,"app-bound-lease.json",&c->lease_i,c->lease_bytes)&&unchanged(c->run,F877_RECOVERY_INTENT,&c->intent_i,c->intent_bytes)&&
  unchanged(c->cap,"recovery-before.json",&c->before_i,c->before_bytes)&&unchanged(c->state,"transport-config.json",&c->config_i,c->config_bytes)&&
  names(c->runtime,@[@"registry.json",@"registry.lock",CANARY_RUN])&&names(c->run,runNames)&&names(c->state,@[@"transport-config.json"])&&absent(c->state,"cache.db")&&
  [c->journal isEqual:readJournal(c->run,c->lease,c->transport[@"keeperPID"]) ]&&
  (!c->final_intent||unchanged(c->run,F877_FINALIZE_INTENT,&c->final_intent_i,c->final_intent_bytes));
}
static bool f877Gone(pid_t pid){struct proc_bsdinfo p={0};errno=0;int n=proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&p,sizeof(p));return n==0&&errno==ESRCH;}
static bool f877ProcessesAbsent(void){const pid_t pids[]={15418,15492,15525,15545};for(unsigned pass=0;pass<2;pass++)for(unsigned i=0;i<4;i++)if(!f877Gone(pids[i]))return false;return true;}
/* A retired namespace must be absent in each stable read, not merely have a
 * zero active rule count. The independent lease-bound native STATUS below
 * verifies the retired ledger and exact restored seven original root rules. */
#ifdef F877_FINALIZER_INERT
/* Inert producer tests only; no environment, argument or production entry can
 * select this capture seam. It exercises the real fixed readonly argv. */
static NSString*(*f877_test_namespace_command)(char*const*,int*);
#endif
static bool f877NamespaceTextEmpty(void){
 for(unsigned i=0;i<2;i++){int code=-1;char*argv[]={(char*)"/sbin/pfctl",(char*)"-a",(char*)CANARY_ANCHOR.UTF8String,(char*)"-s",(char*)(i?"Anchors":"Tables"),NULL};NSString*s;
#ifdef F877_FINALIZER_INERT
  s=f877_test_namespace_command?f877_test_namespace_command(argv,&code):command(argv,false,&code);
#else
  s=command(argv,false,&code);
#endif
  if(!s||code||[s stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length)return false;
 }return true;
}
static bool f877RetiredNamespace(void){
 int fd=open("/dev/pf",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat h,n;if(fd<0)return false;
 bool ok=!fstat(fd,&h)&&!lstat("/dev/pf",&n)&&S_ISCHR(h.st_mode)&&!h.st_uid&&h.st_dev==n.st_dev&&h.st_ino==n.st_ino&&h.st_rdev==n.st_rdev;
 const uint8_t actions[]={0,2,4,6,8,11};for(unsigned pass=0;ok&&pass<2;pass++)for(unsigned i=0;ok&&i<6;i++){EnvaraPFHookRequest q={0};strcpy(q.anchor,CANARY_ANCHOR.UTF8String);q.rule.action=actions[i];errno=0;ok=ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&q)==-1&&errno==EINVAL;}close(fd);
 return ok&&f877NamespaceTextEmpty();
}
static bool f877RetiredProof(F877Context*c){
 int code=-1;NSDictionary*p=nativeCall(0,@{@"lease":c->lease[@"rootHookLease"]},&code,c->installed);if(!p||code||![p[@"originalRootSHA256"]isEqual:ROOT_RULE]||![p[@"originalRootTextSHA256"]isEqual:ROOT_TEXT]||
 ![p[@"namespaceState"]isEqual:@"absent"]||![p[@"runLedgerState"]isEqual:@"retired"]||(p[@"lease"]!=NSNull.null&&![p[@"lease"]isEqual:c->lease[@"rootHookLease"]]))return false;
 for(NSString*k in @[@"ok",@"readOnly",@"pfDisabled",@"pinsVerified",@"originalRootCompatible",@"priorAnchorsCompatible",@"ownedRootHookRemoved",@"originalRootRestored",@"receiptRetired",@"namespaceReclaimed"])if(!boolValue(p[k],true))return false;
 for(NSString*k in @[@"hookInstalled",@"ownedRootHookVerified",@"namespaceExists",@"cleanupPending",@"ready",@"protected",@"productionReady"])if(!boolValue(p[k],false))return false;return true;
}
static bool f877OwnedRouteAbsent(F877Context*c){
 int code=-1;char*argv[]={(char*)"/usr/sbin/netstat",(char*)"-rn",NULL};NSString*routes=normalizedRoutes(command(argv,false,&code));if(!routes||code)return false;
 for(NSString*row in [routes componentsSeparatedByString:@"\n"]){NSArray*fields=[row componentsSeparatedByString:@"|"];if(fields.count!=5||[fields[4]isEqual:c->transport[@"interfaceName"]])return false;}return true;
}
static void f877VerifiedFacts(NSMutableDictionary*out){
 for(NSString*k in @[@"ownedGIDScopeAbsent",@"ownedFilterEmptyVerified",@"keeperExitObserved",@"controllerExitObserved",@"ownedInterfaceAbsent",@"ownedListenerAbsent",@"ownedPFReferenceReleased",@"rootHookRemoved",@"originalRootRestored",@"receiptRetired",@"namespaceReclaimed",@"ownedGroupRemoved",@"coreFinalAbsent",@"frontFinalAbsent"])out[k]=@YES;
}
static bool f877FreshProof(F877Context*c,NSMutableDictionary*out,bool archived){
 out[@"gate"]=@"finalization-private-snapshot";if(!f877PrivateStable(c,archived))return false;
 out[@"gate"]=@"finalization-retired-root-proof";if(!f877RetiredProof(c))return false;
 out[@"gate"]=@"finalization-namespace-absent";if(!f877RetiredNamespace()||!f877StatesEmpty())return false;
 out[@"gate"]=@"finalization-processes-absent";if(!f877ProcessesAbsent())return false;
 out[@"gate"]=@"finalization-gid-scope-absent";if(envara_app_scope_gid_absent((gid_t)c->gid)!=1)return false;
 out[@"gate"]=@"finalization-group-absent";if(!f877GroupAbsent((gid_t)c->gid))return false;
 out[@"gate"]=@"finalization-interface-and-listener-absent";errno=0;unsigned index=if_nametoindex([c->transport[@"interfaceName"]UTF8String]);if(index||!(errno==ENXIO||errno==ENODEV||errno==0)||!f877PortObservation(c,false)||!f877OwnedRouteAbsent(c))return false;
 out[@"gate"]=@"finalization-retired-root-repeat";if(!f877RetiredProof(c)||!f877PrivateStable(c,archived)||!f877ProcessesAbsent())return false;f877VerifiedFacts(out);return true;
}
static NSDictionary *f877CompareHost(NSDictionary*before,NSDictionary*current,unsigned*mask){
 NSArray*fields=@[@"routes",@"dns",@"nat",@"pfconf"];if(!keys(before,fields)||!keys(current,fields))return nil;NSMutableDictionary*comparison=[NSMutableDictionary dictionary];unsigned difference=0;
 for(unsigned i=0;i<4;i++){NSString*k=fields[i];if(!regex(before[k],@"^[0-9a-f]{64}$")||!regex(current[k],@"^[0-9a-f]{64}$"))return nil;bool same=[before[k]isEqual:current[k]];comparison[k]=@((BOOL)same);if(!same)difference|=1U<<i;}if(mask)*mask=difference;return comparison;
}
static bool f877Load(F877Context*c,NSMutableDictionary*out){
 out[@"gate"]=@"finalization-sealed-prior-receipt";if(!f877SealedPrior())return false;
 out[@"gate"]=@"finalization-fixed-host-pins";if(!f877HostPins())return false;
 out[@"gate"]=@"finalization-installed-inventory";c->installed=verifiedInstallation(MIN(rootDeadline,seconds()+30));if(c->installed<0)return false;
 out[@"gate"]=@"finalization-private-parent";c->parent=directory(INSTALL_PARENT);if(c->parent<0||flock(c->parent,LOCK_EX|LOCK_NB)||fstat(c->parent,&c->parent_i))return false;
 out[@"gate"]=@"finalization-private-runtime";c->runtime=directory(RUNTIME);if(!secureFD(c->runtime,true,0700)||fstat(c->runtime,&c->runtime_i))return false;
 out[@"gate"]=@"finalization-exclusive-registry";c->lock=openat(c->runtime,"registry.lock",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat held;if(!secureFD(c->lock,false,0600)||flock(c->lock,LOCK_EX|LOCK_NB)||fstat(c->lock,&held))return false;
 c->registry_bytes=privateRead(c->runtime,"registry.json",65536,&c->registry_i);c->record=strictJSON(c->registry_bytes,65536);c->lock_bytes=privateRead(c->runtime,"registry.lock",4096,&c->lock_i);NSDictionary*lock=strictJSON(c->lock_bytes,4096);
 if(!sameStat(&held,&c->lock_i)||!keys(lock,@[@"runId",@"pid",@"anchor"])||![lock[@"runId"]isEqual:CANARY_RUN]||![lock[@"pid"]isEqual:@15418]||![lock[@"anchor"]isEqual:CANARY_ANCHOR])return false;
 out[@"gate"]=@"finalization-run-and-sealed-context";c->run=openat(c->runtime,CANARY_RUN.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(c->run,true,0700)||fstat(c->run,&c->run_i))return false;
 c->lease_bytes=privateRead(c->run,"app-bound-lease.json",16384,&c->lease_i);c->lease=strictJSON(c->lease_bytes,16384);NSDictionary*t=nil;if(!liveShape(c->record,c->lease,c->lease_bytes,&t,&c->gid)||c->gid!=7100||c->record[@"application"][@"child"]!=NSNull.null||!boolValue(c->record[@"application"][@"resumed"],false)||![c->record[@"phase"]isEqual:@"cleanup-required"]||!boolValue(c->record[@"cleanupUncertain"],true))return false;c->transport=t;
 out[@"gate"]=@"finalization-fixed-state-config";c->state=openat(c->run,[c->lease[@"realmId"]UTF8String],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(c->state,true,0700)||fstat(c->state,&c->state_i)||!names(c->state,@[@"transport-config.json"]))return false;c->config_bytes=privateRead(c->state,"transport-config.json",65536,&c->config_i);if(!c->config_bytes)return false;
 out[@"gate"]=@"finalization-existing-intent-and-capsule";c->intent_bytes=privateRead(c->run,F877_RECOVERY_INTENT,4096,&c->intent_i);NSDictionary*intent=strictJSON(c->intent_bytes,4096);if(!keys(intent,@[@"schema",@"runId",@"environmentId",@"manifestSHA256",@"scope"])||![intent[@"schema"]isEqual:@"envara.macos-pf-live-recovery-intent/v1"]||![intent[@"runId"]isEqual:CANARY_RUN]||![intent[@"environmentId"]isEqual:FIXED_ENV]||![intent[@"manifestSHA256"]isEqual:@MF]||![intent[@"scope"]isEqual:@"one-empty-filter-one-pf-token-one-issued-delete-no-retry"]||!absent(c->run,F877_FINALIZE_INTENT))return false;
 c->cap=openat(c->parent,F877_CAPSULE,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(c->cap,true,0700)||fstat(c->cap,&c->cap_i)||!names(c->cap,@[@"recovery-before.json"]))return false;
 out[@"gate"]=@"finalization-private-baseline-binding";c->before_bytes=privateRead(c->cap,"recovery-before.json",65536,&c->before_i);c->baseline=strictJSON(c->before_bytes,65536);NSDictionary*b=c->baseline;
 if(!keys(b,@[@"schema",@"scope",@"runId",@"environmentId",@"manifestSHA256",@"originalApplicationHostBaselineVerified",@"hostExcludingOnlyRecordedUTunRoutes",@"registrySHA256",@"leaseSHA256",@"lockSHA256",@"journalObservation",@"stateConfigSHA256"])||
 ![b[@"schema"]isEqual:@"envara.macos-pf-live-recovery-baseline/v1"]||![b[@"scope"]isEqual:@"fixed-05d6-run877-recovery-only"]||![b[@"runId"]isEqual:CANARY_RUN]||![b[@"environmentId"]isEqual:FIXED_ENV]||![b[@"manifestSHA256"]isEqual:@MF]||!boolValue(b[@"originalApplicationHostBaselineVerified"],false)||
 ![b[@"registrySHA256"]isEqual:f877HexData(c->registry_bytes)]||![b[@"leaseSHA256"]isEqual:f877HexData(c->lease_bytes)]||![b[@"lockSHA256"]isEqual:f877HexData(c->lock_bytes)]||![b[@"stateConfigSHA256"]isEqual:f877HexData(c->config_bytes)])return false;
 c->journal=readJournal(c->run,c->lease,c->transport[@"keeperPID"]);if(!c->journal||![b[@"journalObservation"]isEqual:c->journal])return false;
 return f877FreshProof(c,out,false);
}
static void f877Close(F877Context*c){int fds[]={c->state,c->run,c->lock,c->runtime,c->cap,c->parent,c->installed};for(unsigned i=0;i<7;i++)if(fds[i]>=0)close(fds[i]);}
static int f877Finalize(bool mutate){
 NSMutableDictionary*out=f877Outcome(mutate);rootDeadline=seconds()+175;
 if(!inspectorRootCredentials()||!inspectorChildWaitBoundary())return emitInspection(out);umask(077);
 F877Context c={.installed=-1,.parent=-1,.cap=-1,.runtime=-1,.lock=-1,.run=-1,.state=-1};
 do{
  if(!f877Load(&c,out))break;out[@"gate"]=@"finalization-host-baseline-comparison";NSDictionary*current=hostSnapshot();NSDictionary*comparison=f877CompareHost(c.baseline[@"hostExcludingOnlyRecordedUTunRoutes"],current,&c.host_difference_mask);if(!comparison)break;
  out[@"ok"]=@YES;out[@"reason"]=@"READ_ONLY_OWNED_SCOPE_FINALIZATION_VERIFIED";out[@"gate"]=[NSString stringWithFormat:@"finalization-preflight-host-diff-%u",c.host_difference_mask];if(!mutate)break;
  out[@"ok"]=@NO;out[@"reason"]=@"OWNED_SCOPE_FINALIZATION_UNCONFIRMED";out[@"gate"]=@"finalization-single-use-private-proof";if(!f877FreshProof(&c,out,false)||seconds()+45>=rootDeadline)break;
  c.final_intent_bytes=[NSJSONSerialization dataWithJSONObject:@{@"schema":@"envara.macos-pf-live-finalization-intent/v1",@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,@"manifestSHA256":@MF,@"scope":@"filesystem-archive-only-no-system-replay"}options:NSJSONWritingWithoutEscapingSlashes error:NULL];if(!f877WritePrivate(c.run,F877_FINALIZE_INTENT,c.final_intent_bytes,&c.final_intent_i))break;c.final_intent=true;
  c.prior_bytes=[NSData dataWithBytes:f877PriorBytes length:sizeof(f877PriorBytes)];if(!f877WritePrivate(c.cap,"prior-recovery-result.json",c.prior_bytes,&c.prior_i))break;
  NSDictionary*p=@{@"schema":@"envara.macos-pf-live-finalization-before/v1",@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,@"manifestSHA256":@MF,@"priorRecoveryReceiptSHA256":@F877_PRIOR_SHA,@"observedHostBaselineComparison":comparison,@"observedCurrentHostSHA256":current,@"recoveryScopeHostNetworkRestored":@NO,@"originalApplicationHostBaselineVerified":@NO,@"runtimeArchived":@NO,@"cleanupConfirmed":@NO,@"scope":@"own-retirement-and-private-archive-only-no-system-replay"};
  c.proof_bytes=[NSJSONSerialization dataWithJSONObject:p options:NSJSONWritingWithoutEscapingSlashes error:NULL];if(!f877WritePrivate(c.cap,"finalization-before.json",c.proof_bytes,&c.proof_i))break;
  out[@"gate"]=@"finalization-held-inode-archive";if(!names(c.cap,@[@"recovery-before.json",@"prior-recovery-result.json",@"finalization-before.json"])||!unchanged(c.cap,"prior-recovery-result.json",&c.prior_i,c.prior_bytes)||!unchanged(c.cap,"finalization-before.json",&c.proof_i,c.proof_bytes)||!f877FreshProof(&c,out,false)||seconds()+20>=rootDeadline)break;
  if(renameatx_np(c.parent,"io.envara.pf-runtime",c.cap,"runtime",RENAME_EXCL)||fsync(c.cap)||fsync(c.parent))break;
  out[@"gate"]=@"finalization-held-inode-postflight";if(!absent(c.parent,"io.envara.pf-runtime")||!names(c.cap,@[@"recovery-before.json",@"prior-recovery-result.json",@"finalization-before.json",@"runtime"])||!unchanged(c.cap,"prior-recovery-result.json",&c.prior_i,c.prior_bytes)||!unchanged(c.cap,"finalization-before.json",&c.proof_i,c.proof_bytes)||!f877FreshProof(&c,out,true))break;
  out[@"runtimeArchived"]=@YES;out[@"cleanupConfirmed"]=@YES;out[@"cleanupUncertain"]=@NO;out[@"ok"]=@YES;out[@"reason"]=@"OWNED_SCOPE_FINALIZATION_COMPLETED";out[@"gate"]=[NSString stringWithFormat:@"owned-scope-finalized-host-diff-%u",c.host_difference_mask];
 }while(0);f877Close(&c);return emitInspection(out);
}
#ifndef F877_FINALIZER_INERT
int main(int argc,char**argv){@autoreleasepool{
 if(argc!=2)return emitInspection(f877Outcome(false));
 if(!strcmp(argv[1],"--plan")){NSMutableDictionary*out=f877Outcome(false);out[@"ok"]=f877SealedPrior()?@YES:@NO;out[@"reason"]=@"INERT_FIXED_FINALIZATION_PLAN";out[@"mutationEntryLinked"]=@YES;out[@"systemRetirementReplayLinked"]=@NO;return emitInspection(out);}
 if(!strcmp(argv[1],"--inspect-fixed-root"))return f877Finalize(false);
 if(!strcmp(argv[1],"--finalize-fixed-root"))return f877Finalize(true);
 return emitInspection(f877Outcome(false));
}}
#endif
