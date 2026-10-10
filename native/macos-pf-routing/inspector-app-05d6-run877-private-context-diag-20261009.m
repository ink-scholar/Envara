/* Fixed read-only diagnostic for run877 recovery's private-context predicates.
 * This translation unit includes only the frozen observational inspector.
 * It has no recovery source, mutation command, PF writer, authorization entry,
 * group creation, application launch or process signal. Unknown entry names
 * and private bytes are never emitted; bounded hashes and typed roles only. */
#define INSPECTOR_INERT 1
#include "inspector-app-05d6-run877-v2.m"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static NSString *pcdDataHash(NSData*d){if(!d)return nil;unsigned char digest[32];CC_SHA256(d.bytes,(CC_LONG)d.length,digest);char h[65];for(unsigned i=0;i<32;i++)snprintf(h+2*i,3,"%02x",digest[i]);return @(h);}
#pragma clang diagnostic pop

static NSString *pcdRole(NSString*name,NSArray*expected){
 if([name isEqual:@"registry.json"])return @"runtime-registry";
 if([name isEqual:@"registry.lock"])return @"runtime-lock";
 if([name isEqual:CANARY_RUN])return @"fixed-run-directory";
 if([name isEqual:@"app-bound-lease.json"])return @"fixed-bound-lease";
 if([name isEqual:@"app-filter-events"])return @"fixed-filter-journal";
 if(expected.count&&[name isEqual:expected.lastObject])return @"fixed-realm-directory";
 if([name isEqual:@"config.yaml"])return @"core-config-yaml";
 if([name isEqual:@"cache.db"])return @"core-cache-db";
 if([name isEqual:@"GeoIP.dat"])return @"core-geoip-data";
 if([name isEqual:@"geoip.metadb"])return @"core-geoip-metadb";
 if([name isEqual:@"geosite.dat"])return @"core-geosite-data";
 return @"unrecognized-entry";
}
/* This reports metadata even when an entry's mode violates the old empty-tree
 * assumptions. It does not grant cleanup authority or classify unknown names
 * as owned. Every descriptor is O_NOFOLLOW and the held/named metadata and
 * entire directory inventory must remain stable across two snapshots. */
static NSDictionary *pcdInventory(int fd,NSArray*expected){
 if(!secureFD(fd,true,0700))return nil;int scan=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(scan<0)return nil;
 DIR*dir=fdopendir(scan);if(!dir){close(scan);return nil;}NSMutableArray*rows=[NSMutableArray array],*privateNames=[NSMutableArray array],*unknownNames=[NSMutableArray array];
 struct dirent*entry;bool ok=true;unsigned unknown=0;errno=0;
 while((entry=readdir(dir))){if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,".."))continue;
  NSString*name=@(entry->d_name);struct stat s;if(rows.count>=64||!regex(name,@"^[A-Za-z0-9_.-]{1,255}$")||fstatat(fd,entry->d_name,&s,AT_SYMLINK_NOFOLLOW)){ok=false;break;}
  NSString*role=pcdRole(name,expected),*kind=S_ISREG(s.st_mode)?@"regular":S_ISDIR(s.st_mode)?@"directory":S_ISLNK(s.st_mode)?@"symlink":@"other";
  if([role isEqual:@"unrecognized-entry"]){unknown++;[unknownNames addObject:name];}
  [privateNames addObject:[NSString stringWithFormat:@"%@|%llu|%llu|%u|%u|%u|%llu|%llu|%lld:%ld|%lld:%ld",name,(unsigned long long)s.st_dev,(unsigned long long)s.st_ino,(unsigned)(s.st_mode&07777),s.st_uid,s.st_gid,(unsigned long long)s.st_nlink,(unsigned long long)s.st_size,(long long)s.st_mtimespec.tv_sec,s.st_mtimespec.tv_nsec,(long long)s.st_ctimespec.tv_sec,s.st_ctimespec.tv_nsec]];
  [rows addObject:@{@"role":role,@"kind":kind,@"mode":@(s.st_mode&07777),@"uid":@(s.st_uid),@"gid":@(s.st_gid),@"linkCount":@(s.st_nlink),@"size":@(s.st_size),@"device":@(s.st_dev),@"inode":@(s.st_ino)}];errno=0;
 }
 if(errno)ok=false;if(closedir(dir))ok=false;if(!ok)return nil;
 NSArray*sorted=[rows sortedArrayUsingComparator:^NSComparisonResult(NSDictionary*a,NSDictionary*b){NSComparisonResult r=[a[@"role"]compare:b[@"role"]];return r==NSOrderedSame?[a[@"inode"]compare:b[@"inode"]]:r;}];
 return @{@"entryCount":@(rows.count),@"knownRoleCount":@(rows.count-unknown),@"unrecognizedEntryCount":@(unknown),@"inventorySHA256":hashText([[privateNames sortedArrayUsingSelector:@selector(compare:)]componentsJoinedByString:@"\n"]),@"unrecognizedNameSetSHA256":hashText([[unknownNames sortedArrayUsingSelector:@selector(compare:)]componentsJoinedByString:@"\n"]),@"entries":sorted,@"contentBindingsVerified":@NO};
}

static NSMutableDictionary *pcdOutcome(void){
 return [@{@"schema":@"envara.macos-pf-live-application-recovery/v1",@"manifestSHA256":@MF,@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,
 @"readOnly":@YES,@"ok":@NO,@"reason":@"FIXED_LIVE_RECOVERY_PREFLIGHT_REFUSED",@"gate":@"not-started",
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
/* All public states retain the existing frozen 51-field recovery envelope.
 * A diagnostic is always refused as a recovery preflight, including when its
 * narrow observation succeeds. The fixed gate is its sole public diagnostic;
 * no private names, byte contents, opaque pointers, or cache hash are emitted. */
static int pcdInspect(void){
 NSMutableDictionary*out=pcdOutcome();rootDeadline=seconds()+80;
 if(!inspectorRootCredentials()||!inspectorChildWaitBoundary()){out[@"gate"]=@"root-credentials";return emitInspection(out);}
 int installed=-1,parent=-1,runtime=-1,run=-1,state=-1;struct stat ri,ki,li,rti,runi,sti;NSData*rb=nil,*kb=nil,*lb=nil;NSDictionary*record=nil,*lock=nil,*lease=nil,*transport=nil;uint64_t gid=0;
 do{
  out[@"gate"]=@"installed-inventory";installed=verifiedInstallation(MIN(rootDeadline,seconds()+30));if(installed<0)break;
  out[@"gate"]=@"private-parent-directory";parent=directory(INSTALL_PARENT);if(parent<0)break;
  out[@"gate"]=@"private-runtime-directory";runtime=directory(RUNTIME);if(!secureFD(runtime,true,0700)||fstat(runtime,&rti))break;
  out[@"gate"]=@"private-registry-bytes";rb=privateRead(runtime,"registry.json",65536,&ri);record=strictJSON(rb,65536);if(!rb||!record)break;
  out[@"gate"]=@"private-lock-bytes";kb=privateRead(runtime,"registry.lock",4096,&ki);lock=strictJSON(kb,4096);if(!kb||!lock)break;
  out[@"gate"]=@"private-lock-three-keys";if(!keys(lock,@[@"runId",@"pid",@"anchor"]))break;
  out[@"gate"]=@"private-lock-run-binding";if(![lock[@"runId"]isEqual:CANARY_RUN])break;
  out[@"gate"]=@"private-lock-controller-binding";if(![lock[@"pid"]isEqual:@15418])break;
  out[@"gate"]=@"private-lock-anchor-binding";if(![lock[@"anchor"]isEqual:CANARY_ANCHOR])break;
  out[@"gate"]=@"private-run-directory";run=openat(runtime,CANARY_RUN.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(run,true,0700)||fstat(run,&runi))break;
  out[@"gate"]=@"private-lease-bytes";lb=privateRead(run,"app-bound-lease.json",16384,&li);lease=strictJSON(lb,16384);if(!lb||!lease)break;
  out[@"gate"]=@"private-live-shape";if(!liveShape(record,lease,lb,&transport,&gid))break;
  out[@"gate"]=@"private-gid-binding";if(gid!=7100)break;
  out[@"gate"]=@"private-child-unrecorded";if(record[@"application"][@"child"]!=NSNull.null)break;
  out[@"gate"]=@"private-resumed-false";if(!boolValue(record[@"application"][@"resumed"],false))break;
  out[@"gate"]=@"private-cleanup-required";if(![record[@"phase"]isEqual:@"cleanup-required"])break;
  out[@"gate"]=@"private-cleanup-uncertain";if(!boolValue(record[@"cleanupUncertain"],true))break;
  out[@"gate"]=@"private-state-directory";state=openat(run,[lease[@"realmId"]UTF8String],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(state,true,0700)||fstat(state,&sti))break;
  NSArray*runtimeExpected=@[@"registry.json",@"registry.lock",CANARY_RUN],*runExpected=@[@"app-bound-lease.json",@"app-filter-events",lease[@"realmId"]];
  out[@"gate"]=@"private-runtime-exact-three";if(!names(runtime,runtimeExpected))break;
  out[@"gate"]=@"private-run-exact-three";if(!names(run,runExpected))break;
  out[@"gate"]=@"private-single-use-intent-absent";if(!absent(run,"recovery-05d6-run877-current-custody.intent"))break;
  out[@"gate"]=@"private-recovery-capsule-absent";if(!absent(parent,"io.envara.pf-recovery-05d6-877ab9cc-current-custody"))break;
  out[@"gate"]=@"private-state-known-inventory";NSDictionary*st=pcdInventory(state,@[]);if(!st)break;
  bool empty=names(state,@[]),cacheOnly=names(state,@[@"cache.db"]);NSData*cache=nil;struct stat cachei;
  if(!empty&&!cacheOnly){out[@"gate"]=@"private-state-unknown-entry-refused";break;}
  if(cacheOnly){out[@"gate"]=@"private-state-cache-db-metadata-refused";cache=privateRead(state,"cache.db",32*1024*1024,&cachei);if(!cache||!pcdDataHash(cache))break;}
  out[@"gate"]=@"private-context-stable-snapshot";struct stat a,b,c;bool stable=unchanged(runtime,"registry.json",&ri,rb)&&unchanged(runtime,"registry.lock",&ki,kb)&&unchanged(run,"app-bound-lease.json",&li,lb)&&!fstatat(runtime,CANARY_RUN.UTF8String,&a,AT_SYMLINK_NOFOLLOW)&&a.st_dev==runi.st_dev&&a.st_ino==runi.st_ino&&!fstatat(run,[lease[@"realmId"]UTF8String],&b,AT_SYMLINK_NOFOLLOW)&&b.st_dev==sti.st_dev&&b.st_ino==sti.st_ino&&!lstat(RUNTIME,&c)&&c.st_dev==rti.st_dev&&c.st_ino==rti.st_ino&&[st isEqual:pcdInventory(state,@[])]&&names(runtime,runtimeExpected)&&names(run,runExpected)&&(!cacheOnly||unchanged(state,"cache.db",&cachei,cache));
  if(!stable)break;out[@"gate"]=empty?@"private-context-empty-state-observed":@"private-context-cache-db-only-stable";
 }while(0);
 if(state>=0)close(state);if(run>=0)close(run);if(runtime>=0)close(runtime);if(parent>=0)close(parent);if(installed>=0)close(installed);return emitInspection(out);
}
#ifndef PRIVATE_CONTEXT_DIAG_INERT
int main(int argc,char**argv){@autoreleasepool{
 if(argc>2)return emitInspection(pcdOutcome());const char*mode=argc==1?"--plan":argv[1];
 if(!strcmp(mode,"--plan")){NSMutableDictionary*out=pcdOutcome();out[@"ok"]=@YES;out[@"reason"]=@"INERT_FIXED_LIVE_RECOVERY_PLAN";out[@"mutationEntryLinked"]=@NO;out[@"nativeStatusRequiredAfterCustodianExit"]=@YES;return emitInspection(out);}
 if(!strcmp(mode,"--inspect-fixed-root"))return pcdInspect();return emitInspection(pcdOutcome());
}}
#endif
