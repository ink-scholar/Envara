/* Local user-present review tool. Builders never request authorization.
 * Only closed embedded bytes and a pinned root-owned Node enter root staging.
 * This is not an installed service or an Apple distribution identity. */
#define _DARWIN_C_SOURCE
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <mach-o/dyld.h>
#include <crt_externs.h>
#include <libproc.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <time.h>
#include "sampler-app-14b87-wrapper-build.h"
#define MF @"14b87d3452af4acaf67709c2494d637163d108a101f6d07fb27ce8e61c2d1d50"
#define RUN @"5be11012-0c9e-456c-84b9-9e311df4cbdd"
#define ENV @"5a50dcef-3314-4195-8ba5-c94ca6a0bef0"
#define SCHEMA @"envara.macos-pf-application-sampling-wrapper/v1"
#define SAMPLE_SCHEMA @"envara.macos-pf-application-sampling/v1"
#define STAGE_SCHEMA @"envara.macos-fixed-sampler-stage/v1"
#define ROOT_PARENT "/Library/PrivilegedHelperTools"
#define ROOT_NODE ROOT_PARENT "/io.envara.pf-routing/node"
#define ROOT_NODE_SHA "ee6fb0e015284d83a91e8ec5213f43a157f8a392b58555301682892ba928c04a"
#define REPLY_LIMIT 32768U
static bool boolean(id v){return v&&CFGetTypeID((__bridge CFTypeRef)v)==CFBooleanGetTypeID();}
static bool number(id v,uint64_t*out){if(![v isKindOfClass:NSNumber.class]||boolean(v))return false;double x=[v doubleValue];if(!isfinite(x)||x<0||x!=floor(x)||x>9007199254740991.)return false;*out=[v unsignedLongLongValue];return true;}
static double now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;return t.tv_sec+t.tv_nsec/1e9;}
static bool stable(const struct stat*a,const struct stat*b){return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec&&a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec&&a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec&&a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec;}
static void clearOwnEnvironment(void){static char*empty[]={NULL};*_NSGetEnviron()=empty;}
static bool console(void){struct stat s;if(!WRAPPER_CONSOLE_UID||lstat("/dev/console",&s)||!S_ISCHR(s.st_mode)||s.st_uid!=WRAPPER_CONSOLE_UID)return false;return getuid()==s.st_uid&&geteuid()==s.st_uid;}
static bool exactKeys(NSDictionary*v,NSArray*keys){return [v isKindOfClass:NSDictionary.class]&&v.count==keys.count&&[[NSSet setWithArray:v.allKeys]isEqualToSet:[NSSet setWithArray:keys]];}
static bool noWriteACL(int fd){
 errno=0;acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);if(!acl)return errno==ENOENT;
 acl_entry_t entry;int cursor=ACL_FIRST_ENTRY,result;bool ok=true;
 while((result=acl_get_entry(acl,cursor,&entry))==0){cursor=ACL_NEXT_ENTRY;acl_tag_t tag;acl_permset_t perms;
  if(acl_get_tag_type(entry,&tag)||acl_get_permset(entry,&perms)){ok=false;break;}if(tag!=ACL_EXTENDED_ALLOW)continue;
  const acl_perm_t forbidden[]={ACL_WRITE_DATA,ACL_APPEND_DATA,ACL_DELETE,ACL_DELETE_CHILD,ACL_WRITE_ATTRIBUTES,ACL_WRITE_EXTATTRIBUTES,ACL_WRITE_SECURITY,ACL_CHANGE_OWNER};
  for(size_t i=0;i<sizeof(forbidden)/sizeof(forbidden[0]);i++)if(acl_get_perm_np(perms,forbidden[i])!=0){ok=false;break;}if(!ok)break;
 }
 if(ok)ok=result==-1&&errno==EINVAL;acl_free(acl);return ok;
}
static bool rootFD(int fd,bool directory){struct stat s;return fd>=0&&!fstat(fd,&s)&&s.st_uid==0&&s.st_gid==0&&!(s.st_mode&0022)&&
 (directory?S_ISDIR(s.st_mode):S_ISREG(s.st_mode)&&s.st_nlink==1&&(s.st_mode&07777)==0755)&&noWriteACL(fd);}
static int rootDirectory(const char*path){
 char canonical[PATH_MAX],copy[PATH_MAX];if(!realpath(path,canonical)||strcmp(canonical,path)||strlen(path)>=sizeof(copy))return -1;
 int fd=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!rootFD(fd,true)){if(fd>=0)close(fd);return -1;}
 strcpy(copy,path);char*save=NULL;
 for(char*part=strtok_r(copy+1,"/",&save);part;part=strtok_r(NULL,"/",&save)){
  if(!strcmp(part,".")||!strcmp(part,"..")){close(fd);return -1;}int next=openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(fd);fd=next;
  if(!rootFD(fd,true)){if(fd>=0)close(fd);return -1;}
 }
 return fd;
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static bool digest(int fd,const char*expected){
 struct stat a,b;if(fstat(fd,&a)||!S_ISREG(a.st_mode)||a.st_nlink!=1||a.st_size<1||a.st_size>512LL*1024*1024||lseek(fd,0,SEEK_SET)<0)return false;
 CC_SHA256_CTX c;CC_SHA256_Init(&c);unsigned char bytes[65536],result[32];off_t total=0;double deadline=now()+10;
 for(;;){if(now()<0||now()>=deadline)return false;ssize_t n=read(fd,bytes,sizeof(bytes));if(n<0&&errno==EINTR)continue;if(n<0)return false;if(!n)break;total+=n;if(total>a.st_size)return false;CC_SHA256_Update(&c,bytes,(CC_LONG)n);}
 if(total!=a.st_size||fstat(fd,&b)||!stable(&a,&b))return false;CC_SHA256_Final(result,&c);char text[65];for(size_t i=0;i<32;i++)snprintf(text+i*2,3,"%02x",result[i]);return !strcmp(text,expected);
}
#pragma clang diagnostic pop
static bool signedFile(const char*path){CFURLRef u=CFURLCreateFromFileSystemRepresentation(NULL,(const UInt8*)path,strlen(path),false);SecStaticCodeRef c=NULL;OSStatus e=u?SecStaticCodeCreateWithPath(u,kSecCSDefaultFlags,&c):errSecParam;if(!e)e=SecStaticCodeCheckValidity(c,kSecCSStrictValidate|kSecCSCheckAllArchitectures,NULL);if(c)CFRelease(c);if(u)CFRelease(u);return e==errSecSuccess;}
static bool hardenedSigningPolicy(NSDictionary*dynamic,NSDictionary*disk){
 uint64_t flags,diskFlags;if(![dynamic isKindOfClass:NSDictionary.class]||![disk isKindOfClass:NSDictionary.class]||!number(dynamic[(__bridge NSString*)kSecCodeInfoFlags],&flags)||!(flags&kSecCodeSignatureRuntime)||!number(disk[(__bridge NSString*)kSecCodeInfoFlags],&diskFlags)||!(diskFlags&kSecCodeSignatureRuntime))return false;
 id e=dynamic[(__bridge NSString*)kSecCodeInfoEntitlementsDict];if(e&&(![e isKindOfClass:NSDictionary.class]||[e count]))return false;
 e=disk[(__bridge NSString*)kSecCodeInfoEntitlementsDict];if(e&&(![e isKindOfClass:NSDictionary.class]||[e count]))return false;
 id a=dynamic[(__bridge NSString*)kSecCodeInfoUnique],b=disk[(__bridge NSString*)kSecCodeInfoUnique];
 return [a isKindOfClass:NSData.class]&&[b isKindOfClass:NSData.class]&&[a length]==20&&[a isEqual:b];
}
static bool hardenedSelf(const char*path){
 SecCodeRef dynamic=NULL;SecStaticCodeRef disk=NULL;CFDictionaryRef dynamicInfo=NULL,diskInfo=NULL;
 CFURLRef u=CFURLCreateFromFileSystemRepresentation(NULL,(const UInt8*)path,strlen(path),false);bool ok=false;
 if(u&&SecCodeCopySelf(kSecCSDefaultFlags,&dynamic)==errSecSuccess&&SecCodeCheckValidity(dynamic,kSecCSStrictValidate,NULL)==errSecSuccess&&
  SecStaticCodeCreateWithPath(u,kSecCSDefaultFlags,&disk)==errSecSuccess&&SecStaticCodeCheckValidity(disk,kSecCSStrictValidate|kSecCSCheckAllArchitectures,NULL)==errSecSuccess&&
  SecCodeCopySigningInformation(dynamic,kSecCSSigningInformation|kSecCSDynamicInformation,&dynamicInfo)==errSecSuccess&&
  SecCodeCopySigningInformation((SecCodeRef)disk,kSecCSSigningInformation,&diskInfo)==errSecSuccess)ok=hardenedSigningPolicy((__bridge NSDictionary*)dynamicInfo,(__bridge NSDictionary*)diskInfo);
 if(dynamicInfo)CFRelease(dynamicInfo);if(diskInfo)CFRelease(diskInfo);if(dynamic)CFRelease(dynamic);if(disk)CFRelease(disk);if(u)CFRelease(u);return ok;
}
static bool heldMatches(int fd,const char*path,const struct stat*identity){struct stat held,named;return !fstat(fd,&held)&&!lstat(path,&named)&&stable(identity,&held)&&stable(&held,&named);}
static int heldSelf(struct stat*identity){
 char raw[PATH_MAX],canonical[PATH_MAX],actual[PROC_PIDPATHINFO_MAXSIZE];uint32_t size=sizeof(raw);
 if(_NSGetExecutablePath(raw,&size)||!realpath(raw,canonical)||strcmp(canonical,WRAPPER_SELF)||proc_pidpath(getpid(),actual,sizeof(actual))<=0||strcmp(actual,WRAPPER_SELF))return -1;
 int fd=open(WRAPPER_SELF,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);struct stat named;
 if(fd<0||fstat(fd,identity)||identity->st_uid!=WRAPPER_CONSOLE_UID||(identity->st_mode&07777)!=0755||identity->st_nlink!=1||!S_ISREG(identity->st_mode)||!noWriteACL(fd)||
  lstat(WRAPPER_SELF,&named)||!stable(identity,&named)||!hardenedSelf(WRAPPER_SELF)){if(fd>=0)close(fd);return -1;}return fd;
}
static int heldRootFile(const char*path,const char*sha,struct stat*identity){
 char canonical[PATH_MAX],parent[PATH_MAX];if(!realpath(path,canonical)||strcmp(canonical,path)||strlen(path)>=sizeof(parent))return -1;
 strcpy(parent,path);char*slash=strrchr(parent,'/');if(!slash||slash==parent)return -1;*slash=0;int base=rootDirectory(parent);if(base<0)return -1;
 int fd=openat(base,slash+1,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);close(base);struct stat named;
 if(!rootFD(fd,false)||fstat(fd,identity)||(!strcmp(path,WRAPPER_ROOT_TARGET)&&identity->st_size>32*1024*1024)||lstat(path,&named)||!stable(identity,&named)||!digest(fd,sha)||!signedFile(path)||!heldMatches(fd,path,identity)){if(fd>=0)close(fd);return -1;}return fd;
}
static bool rootChainSafe(const char*path){char parent[PATH_MAX];if(strlen(path)>=sizeof(parent))return false;strcpy(parent,path);char*slash=strrchr(parent,'/');if(!slash||slash==parent)return false;*slash=0;int fd=rootDirectory(parent);if(fd<0)return false;close(fd);return true;}
typedef enum{COMPONENT_REQUIRED,REUSE_VERIFIED_TARGET,EXPLICIT_INSTALL_TARGET}StageDecision;
static StageDecision stageDecision(bool allowStage,bool targetPresent){return targetPresent?REUSE_VERIFIED_TARGET:allowStage?EXPLICIT_INSTALL_TARGET:COMPONENT_REQUIRED;}
static bool compiledInputs(void){
 if(strlen(WRAPPER_SAMPLER_SHA)!=64||strspn(WRAPPER_SAMPLER_SHA,"0123456789abcdef")!=64||!strlen(WRAPPER_STAGE_PROGRAM)||strlen(WRAPPER_STAGE_PROGRAM)>196608)return false;
 char target[PATH_MAX];int n=snprintf(target,sizeof(target),ROOT_PARENT "/io.envara.pf-sampler-14b87-%s",WRAPPER_SAMPLER_SHA);
 return n>0&&n<(int)sizeof(target)&&!strcmp(target,WRAPPER_ROOT_TARGET)&&WRAPPER_SELF[0]=='/'&&WRAPPER_CONSOLE_UID>0;
}
/* Duplicate/escaped keys are rejected before Foundation can collapse them. */
typedef struct{const unsigned char*bytes;size_t size,at;} Cursor;
static void whitespace(Cursor*c){while(c->at<c->size&&strchr(" \t\r\n",c->bytes[c->at]))c->at++;}
static NSString*jsonString(Cursor*c){whitespace(c);if(c->at>=c->size||c->bytes[c->at++]!='"')return nil;size_t start=c->at;
 while(c->at<c->size&&c->bytes[c->at]!='"'){unsigned char x=c->bytes[c->at++];if(x<32||x>126||x=='\\')return nil;}if(c->at==c->size||c->at-start>4096)return nil;
 NSString*v=[[NSString alloc]initWithBytes:c->bytes+start length:c->at-start encoding:NSASCIIStringEncoding];c->at++;return v;}
static bool jsonValue(Cursor*c,unsigned depth){if(depth>4)return false;whitespace(c);if(c->at>=c->size)return false;unsigned char x=c->bytes[c->at];if(x=='"')return jsonString(c)!=nil;
 if(x=='{'||x=='['){bool object=x=='{';unsigned char end=object?'}':']';c->at++;whitespace(c);if(c->at<c->size&&c->bytes[c->at]==end){c->at++;return true;}
  NSMutableSet*seen=[NSMutableSet set];unsigned count=0;for(;;){if(++count>64)return false;if(object){NSString*k=jsonString(c);if(!k||[seen containsObject:k])return false;[seen addObject:k];whitespace(c);if(c->at>=c->size||c->bytes[c->at++]!=':')return false;}
   if(!jsonValue(c,depth+1))return false;whitespace(c);if(c->at>=c->size)return false;x=c->bytes[c->at++];if(x==end)return true;if(x!=',')return false;}}
 size_t start=c->at;while(c->at<c->size&&!strchr(" \t\r\n,}]",c->bytes[c->at]))c->at++;return c->at>start&&c->at-start<=64;}
static NSDictionary*strictJSON(NSData*d){if(!d.length||d.length>REPLY_LIMIT)return nil;Cursor c={d.bytes,d.length,0};if(!jsonValue(&c,0))return nil;whitespace(&c);if(c.at!=c.size)return nil;id value=[NSJSONSerialization JSONObjectWithData:d options:0 error:NULL];return [value isKindOfClass:NSDictionary.class]?value:nil;}
static NSMutableDictionary*report(NSString*reason){return [@{@"schema":SCHEMA,@"runId":RUN,@"environmentId":ENV,@"manifestSHA256":MF,@"samplerBinarySHA256":@WRAPPER_SAMPLER_SHA,@"ok":@NO,@"reason":reason,@"ready":@NO,@"protected":@NO,@"productionReady":@NO,@"cleanupConfirmed":@NO,@"cleanupPermitted":@NO,@"cleanupUncertain":@YES,@"originalDescriptorCustodyVerified":@NO,@"liveGuardianFailureAccepted":@NO,@"authorizationRequested":@NO,@"interactive":@YES,@"userPresenceRequired":@YES,@"bootstrapIdentityBound":@NO,@"atomicExecutableBindingVerified":@NO,@"externalReferenceInjected":@NO,@"installedCandidateChanged":@NO,@"runtimeChanged":@NO,@"PFWriteExecuted":@NO,@"ownedAppOrKeeperSignalExecuted":@NO,@"originalHostBaselineVerified":@NO,@"readOnly":@YES,@"overallReadOnly":@YES,@"samplingReadOnly":@YES,@"rootStageAttempted":@NO,@"rootStageCompleted":@NO,@"rootTargetVerified":@NO,@"bootstrapRootTargetBound":@NO}mutableCopy];}
static bool stageAck(NSDictionary*v,const struct stat*identity){
 uint64_t bytes;if(!exactKeys(v,@[@"schema",@"ok",@"binarySHA256",@"binaryBytes",@"device",@"inode",@"closed"])||![v[@"schema"]isEqual:STAGE_SCHEMA]||!boolean(v[@"ok"])||![v[@"ok"]boolValue]||!boolean(v[@"closed"])||![v[@"closed"]boolValue]||![v[@"binarySHA256"]isEqual:@WRAPPER_SAMPLER_SHA]||!number(v[@"binaryBytes"],&bytes)||bytes!=(uint64_t)identity->st_size)return false;
 return [v[@"device"]isEqual:[NSString stringWithFormat:@"%llu",(unsigned long long)identity->st_dev]]&&[v[@"inode"]isEqual:[NSString stringWithFormat:@"%llu",(unsigned long long)identity->st_ino]];
}
static bool textMatches(id v,NSString*pattern){return [v isKindOfClass:NSString.class]&&[v rangeOfString:pattern options:NSRegularExpressionSearch].location!=NSNotFound;}
static bool bounded(id v,uint64_t low,uint64_t high){uint64_t n;return number(v,&n)&&n>=low&&n<=high;}
static bool falseFields(NSDictionary*v,NSArray*fields){for(NSString*k in fields)if(!boolean(v[k])||[v[k]boolValue])return false;return true;}
static bool trueFields(NSDictionary*v,NSArray*fields){for(NSString*k in fields)if(!boolean(v[k])||![v[k]boolValue])return false;return true;}
static NSArray*safeSymbols(void){return @[@"run",@"envara_app_tunnel_run",@"envara_app_supervisor_run",@"adapter_stage",@"adapter_fresh",@"quarantine",@"adopt",@"guard_preflight",@"envara_app_ticket_claim",@"envara_app_registry_resolve",@"envara_notion_stage",@"envara_notion_plan",@"envara_notion_supported",@"envara_notion_data_prepare",@"envara_gui_manifest_unchanged",@"envara_gui_manifest_inspect",@"tree_hash",@"file_hash",@"hash_bytes",@"fts_read",@"read",@"CC_SHA256_Update",@"ccsha256_vng_armv8_compress",@"registered_app",@"ticket_verify",@"verify_mode",@"basic",@"pf_read",@"envara_pf_hook_filter_guard",@"envara_spawn_suspended_io",@"waitpid",@"poll",@"nanosleep",@"envara_launch_guard_run",@"kevent"];}
static NSDictionary*sanitize(NSDictionary*input){
 NSMutableDictionary*v=report(@"PRIVATE_SAMPLE_UNCONFIRMED");v[@"authorizationRequested"]=@YES;
 NSArray*base=@[@"schema",@"runId",@"environmentId",@"manifestSHA256",@"sourceObservationSHA256",@"priorReadonlyReceiptSHA256",@"readOnly",@"ok",@"reason",@"gate",@"cleanupConfirmed",@"cleanupUncertain",@"cleanupPermitted",@"ready",@"protected",@"productionReady",@"originalHostBaselineVerified",@"PFWriteExecuted",@"ownedAppOrKeeperSignalExecuted",@"runtimeChanged",@"keeperPID",@"keeperBirth",@"controllerPID",@"controllerBirth",@"sampleDurationSeconds",@"samplingIntervalMilliseconds",@"rawReportExposed",@"rawReportRetained",@"sampleBytes",@"stackFrameCount",@"unrecognizedFrameCount",@"symbols",@"beforeIdentityVerified",@"afterIdentityVerified",@"stablePrivateSnapshotVerified"];
 NSArray*gates=@[@"not-started",@"root-credentials",@"installed-inventory",@"private-bindings",@"fixed-identities",@"bounded-sample",@"safe-symbol-summary",@"stable-private-snapshot",@"sampling-complete"];
 if(!exactKeys(input,base)||![input[@"schema"]isEqual:SAMPLE_SCHEMA]||![input[@"runId"]isEqual:RUN]||![input[@"environmentId"]isEqual:ENV]||![input[@"manifestSHA256"]isEqual:MF]||
  ![input[@"sourceObservationSHA256"]isEqual:@"5dbc68f6b1230469b18e3cdb493ed537bf8afd41e59ae9ddd589d52b103dfc45"]||![input[@"priorReadonlyReceiptSHA256"]isEqual:@"de1f82d89784168cdb5fc532ae94667fc6486eb7270b753e75ca0a748cd9e301"]||
  ![input[@"keeperBirth"]isEqual:@"1791536847:878082"]||![input[@"controllerBirth"]isEqual:@"1791536844:980868"]||!bounded(input[@"keeperPID"],48779,48779)||!bounded(input[@"controllerPID"],48707,48707)||
  !bounded(input[@"sampleDurationSeconds"],1,1)||!bounded(input[@"samplingIntervalMilliseconds"],1,1)||!boolean(input[@"ok"])||![gates containsObject:input[@"gate"]]||
  !trueFields(input,@[@"readOnly",@"cleanupUncertain"])||!falseFields(input,@[@"cleanupConfirmed",@"cleanupPermitted",@"ready",@"protected",@"productionReady",@"originalHostBaselineVerified",@"PFWriteExecuted",@"ownedAppOrKeeperSignalExecuted",@"runtimeChanged",@"rawReportExposed",@"rawReportRetained"])||
  !bounded(input[@"sampleBytes"],0,131072)||!bounded(input[@"stackFrameCount"],0,65536)||!bounded(input[@"unrecognizedFrameCount"],0,65536))return v;
 for(NSString*k in @[@"beforeIdentityVerified",@"afterIdentityVerified",@"stablePrivateSnapshotVerified"])if(!boolean(input[k]))return v;
 if([input[@"ok"]boolValue]){if(![input[@"reason"]isEqual:@"EXACT_FIXED_KEEPER_SAMPLED"]||![input[@"gate"]isEqual:@"sampling-complete"]||!trueFields(input,@[@"beforeIdentityVerified",@"afterIdentityVerified",@"stablePrivateSnapshotVerified"]))return v;}
 else if(![input[@"reason"]isEqual:@"SAMPLING_UNCONFIRMED"])return v;
 NSArray*rows=input[@"symbols"];if(![rows isKindOfClass:NSArray.class]||rows.count>safeSymbols().count)return v;NSMutableSet*names=[NSMutableSet set];
 for(NSDictionary*r in rows){if(!exactKeys(r,@[@"name",@"occurrences",@"reportedWeight"])||![safeSymbols()containsObject:r[@"name"]]||[names containsObject:r[@"name"]]||!bounded(r[@"occurrences"],1,65536)||!bounded(r[@"reportedWeight"],0,UINT32_MAX))return v;[names addObject:r[@"name"]];}
 for(NSString*k in base)if(![k isEqual:@"schema"])v[k]=input[k];return v;
}
static int emit(NSDictionary*v){NSData*d=[NSJSONSerialization dataWithJSONObject:v options:NSJSONWritingWithoutEscapingSlashes error:NULL];if(!d||d.length>REPLY_LIMIT||fwrite(d.bytes,1,d.length,stdout)!=d.length||fputc('\n',stdout)==EOF||fflush(stdout))return 1;return [v[@"ok"]boolValue]?0:1;}
static NSData*readCompletion(FILE*pipe,double budget){if(!pipe)return nil;int fd=fileno(pipe),flags=fcntl(fd,F_GETFL);if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK))return nil;NSMutableData*d=[NSMutableData data];double start=now();if(start<0)return nil;
 while(now()>=0&&now()<start+budget){struct pollfd pfd={fd,POLLIN|POLLHUP,0};int n=poll(&pfd,1,100);if(n<0&&errno==EINTR)continue;if(n<0)return nil;if(!n)continue;unsigned char b[4096];ssize_t count=read(fd,b,sizeof(b));if(count>0){if(d.length+(size_t)count>REPLY_LIMIT)return nil;[d appendBytes:b length:(NSUInteger)count];}else if(!count)return d;else if(errno!=EINTR&&errno!=EAGAIN)return nil;}return nil;}
typedef OSStatus(*Execute)(AuthorizationRef,const char*,AuthorizationFlags,char*const*,FILE**);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static OSStatus executeStage(AuthorizationRef ref,bool allowStage,FILE**pipe,Execute execute){if(!allowStage)return errAuthorizationDenied;char*a[]={"--input-type=commonjs","--no-addons","--disable-proto=throw","--disable-sigusr1","--eval",WRAPPER_STAGE_PROGRAM,NULL};return execute(ref,ROOT_NODE,0,a,pipe);}
static OSStatus executeSample(AuthorizationRef ref,FILE**pipe,Execute execute){char*a[]={"--sample-fixed-root",NULL};return execute(ref,WRAPPER_ROOT_TARGET,0,a,pipe);}
static int request(bool allowStage){
 clearOwnEnvironment(); /* Before ALL Authorization calls; stays clear for both execs. */
 if(!compiledInputs()||!console())return emit(report(@"CONSOLE_IDENTITY_REFUSED"));
 struct stat selfStat,nodeStat,targetStat;int self=heldSelf(&selfStat),node=-1,target=-1;AuthorizationRef ref=NULL;FILE*pipe=NULL;NSMutableDictionary*v=nil;NSData*completion=nil;bool stageAttempted=false,stageCompleted=false,targetVerified=false;
 if(self<0)return emit(report(@"SELF_IDENTITY_REFUSED"));node=heldRootFile(ROOT_NODE,ROOT_NODE_SHA,&nodeStat);if(node<0){close(self);return emit(report(@"ROOT_NODE_PIN_REFUSED"));}
 struct stat existing;bool needsStage=false;if(lstat(WRAPPER_ROOT_TARGET,&existing)){if(errno!=ENOENT){v=report(@"ROOT_TARGET_REFUSED");goto done;}int parent=rootDirectory(ROOT_PARENT);if(parent<0){v=report(@"ROOT_TARGET_REFUSED");goto done;}close(parent);needsStage=true;}
 else {target=heldRootFile(WRAPPER_ROOT_TARGET,WRAPPER_SAMPLER_SHA,&targetStat);if(target<0){v=report(@"ROOT_TARGET_REFUSED");goto done;}}
 if(stageDecision(allowStage,!needsStage)==COMPONENT_REQUIRED){v=report(@"SAMPLE_COMPONENT_INSTALLATION_REQUIRED");goto done;}
 AuthorizationItem item={kAuthorizationRightExecute,0,NULL,0};AuthorizationRights rights={1,&item};
 const char*prompt=allowStage?"Envara：安装固定一秒只读栈采样工具并观察14b87/run5be。将内嵌审核工具独占封存到固定root文件；随后只读核验固定进程身份并采样一秒；仅输出白名单函数计数。不恢复、不控制keeper、不清理、不启动应用、不修改网络。需要您在场确认。":"Envara：仅只读核验固定14b87/run5be进程身份并采样一秒，输出白名单函数计数。不安装、不恢复、不控制keeper、不清理、不修改网络。需要您在场确认。";
 AuthorizationItem p={kAuthorizationEnvironmentPrompt,strlen(prompt),(void*)prompt,0};AuthorizationEnvironment env={1,&p};
 OSStatus e=AuthorizationCreate(NULL,kAuthorizationEmptyEnvironment,0,&ref);if(e==errAuthorizationSuccess)e=AuthorizationCopyRights(ref,&rights,&env,kAuthorizationFlagInteractionAllowed|kAuthorizationFlagExtendRights,NULL);
 if(e!=errAuthorizationSuccess){v=report(e==errAuthorizationCanceled?@"AUTHORIZATION_CANCELLED":@"AUTHORIZATION_UNAVAILABLE");v[@"authorizationRequested"]=@YES;goto done;}
 if(!console()||!heldMatches(self,WRAPPER_SELF,&selfStat)||!hardenedSelf(WRAPPER_SELF)||!heldMatches(node,ROOT_NODE,&nodeStat)||!rootFD(node,false)||!rootChainSafe(ROOT_NODE)||!rootChainSafe(WRAPPER_ROOT_TARGET)||!digest(node,ROOT_NODE_SHA)){v=report(@"POST_AUTHORIZATION_PIN_REFUSED");goto done;}
 if(needsStage){stageAttempted=true;e=executeStage(ref,allowStage,&pipe,AuthorizationExecuteWithPrivileges);if(e!=errAuthorizationSuccess||!pipe){v=report(@"FIXED_STAGE_REFUSED");goto done;}
  NSData*reply=readCompletion(pipe,10);fclose(pipe);pipe=NULL;target=heldRootFile(WRAPPER_ROOT_TARGET,WRAPPER_SAMPLER_SHA,&targetStat);
  if(!reply||target<0||!stageAck(strictJSON(reply),&targetStat)){v=report(@"FIXED_STAGE_COMPLETION_UNCONFIRMED");goto done;}stageCompleted=true;}
 if(!console()||!heldMatches(self,WRAPPER_SELF,&selfStat)||!hardenedSelf(WRAPPER_SELF)||!heldMatches(node,ROOT_NODE,&nodeStat)||!rootFD(node,false)||!digest(node,ROOT_NODE_SHA)||
  !heldMatches(target,WRAPPER_ROOT_TARGET,&targetStat)||!rootFD(target,false)||!rootChainSafe(ROOT_NODE)||!rootChainSafe(WRAPPER_ROOT_TARGET)||!digest(target,WRAPPER_SAMPLER_SHA)||!signedFile(WRAPPER_ROOT_TARGET)){v=report(@"ROOT_TARGET_PIN_REFUSED");goto done;}targetVerified=true;
 e=executeSample(ref,&pipe,AuthorizationExecuteWithPrivileges);if(e!=errAuthorizationSuccess||!pipe){v=report(@"SAMPLE_AUTHORIZATION_UNAVAILABLE");goto done;}
 completion=readCompletion(pipe,180);fclose(pipe);pipe=NULL;v=[sanitize(strictJSON(completion))mutableCopy];
done:if(pipe)fclose(pipe);if(!v)v=report(@"PRIVATE_SAMPLE_UNCONFIRMED");if(ref){v[@"authorizationRequested"]=@YES;AuthorizationFree(ref,kAuthorizationFlagDestroyRights);}if(target>=0)close(target);if(node>=0)close(node);close(self);
 v[@"readOnly"]=@((BOOL)!stageAttempted);v[@"overallReadOnly"]=v[@"readOnly"];v[@"samplingReadOnly"]=@YES;v[@"rootStageAttempted"]=@((BOOL)stageAttempted);v[@"rootStageCompleted"]=@((BOOL)stageCompleted);v[@"rootTargetVerified"]=@((BOOL)targetVerified);v[@"bootstrapRootTargetBound"]=@((BOOL)targetVerified);return emit(v);
}
#pragma clang diagnostic pop
#ifndef WRAPPER_INERT
int main(int argc,char**argv){@autoreleasepool{
 if(argc>2)return emit(report(@"INVALID_FIXED_OPERATION"));const char*mode=argc==1?"--plan":argv[1];
 if(!strcmp(mode,"--request-readonly"))return request(false);if(!strcmp(mode,"--request-install-and-readonly"))return request(true);
 NSMutableDictionary*v=report(!strcmp(mode,"--plan")?@"INERT_PLAN":@"INVALID_FIXED_OPERATION");
 if(!strcmp(mode,"--plan")){v[@"ok"]=@YES;v[@"readOnly"]=@YES;v[@"authorizationRequested"]=@NO;v[@"closedStageProgramAvailable"]=@((BOOL)compiledInputs());v[@"rootTargetVerified"]=@NO;v[@"localHardenedSelfVerified"]=@((BOOL)hardenedSelf(WRAPPER_SELF));}
 return emit(v);
}}
#endif
