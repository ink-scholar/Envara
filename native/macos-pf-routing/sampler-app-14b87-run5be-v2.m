/* Fixed one-second read-only keeper sampler. No application control or recovery.
 * Raw /usr/bin/sample bytes stay in the bounded private stdout pipe/RAM. The
 * explicit /dev/stdout report destination prohibits sample's default file. */
#define INSPECTOR_INERT 1
#include "inspector-app-14b87-run5be.m"
#define SAMPLING_SCHEMA @"envara.macos-pf-application-sampling/v2"
#define SAMPLING_PRIOR_SHA @"de1f82d89784168cdb5fc532ae94667fc6486eb7270b753e75ca0a748cd9e301"
#define KEEPER_BIRTH @"1791536847:878082"
#define CONTROLLER_BIRTH @"1791536844:980868"
static NSArray *samplingSymbols(void){return @[@"run",@"envara_app_tunnel_run",@"envara_app_supervisor_run",@"adapter_stage",@"adapter_fresh",@"quarantine",@"adopt",@"guard_preflight",@"envara_app_ticket_claim",@"envara_app_registry_resolve",@"envara_notion_stage",@"envara_notion_plan",@"envara_notion_supported",@"envara_notion_data_prepare",@"envara_gui_manifest_unchanged",@"envara_gui_manifest_inspect",@"tree_hash",@"file_hash",@"hash_bytes",@"fts_read",@"read",@"CC_SHA256_Update",@"ccsha256_vng_armv8_compress",@"registered_app",@"ticket_verify",@"verify_mode",@"basic",@"pf_read",@"envara_pf_hook_filter_guard",@"envara_spawn_suspended_io",@"waitpid",@"poll",@"nanosleep",@"envara_launch_guard_run",@"kevent"];} 
static NSMutableDictionary *samplingOutcome(void){return [@{@"schema":SAMPLING_SCHEMA,@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,@"manifestSHA256":@MF,@"sourceObservationSHA256":SOURCE_OBSERVATION_SHA,@"priorReadonlyReceiptSHA256":SAMPLING_PRIOR_SHA,@"readOnly":@YES,@"ok":@NO,@"reason":@"SAMPLING_UNCONFIRMED",@"gate":@"not-started",@"cleanupConfirmed":@NO,@"cleanupUncertain":@YES,@"cleanupPermitted":@NO,@"ready":@NO,@"protected":@NO,@"productionReady":@NO,@"originalHostBaselineVerified":@NO,@"PFWriteExecuted":@NO,@"ownedAppOrKeeperSignalExecuted":@NO,@"runtimeChanged":@NO,@"keeperPID":@(SOURCE_KEEPER_PID),@"keeperBirth":KEEPER_BIRTH,@"controllerPID":@(SOURCE_CONTROLLER_PID),@"controllerBirth":CONTROLLER_BIRTH,@"sampleDurationSeconds":@1,@"samplingIntervalMilliseconds":@1,@"rawReportExposed":@NO,@"rawReportRetained":@NO,@"sampleBytes":@0,@"stackFrameCount":@0,@"unrecognizedFrameCount":@0,@"symbols":@[],@"beforeIdentityVerified":@NO,@"afterIdentityVerified":@NO,@"stablePrivateSnapshotVerified":@NO,@"samplingToolExitedSuccessfully":@NO,@"reportProcessPIDMatched":@NO,@"reportPathExactlyMatched":@NO,@"reportFrameFormatObserved":@NO}mutableCopy];}
/* Count only report call-tree frames. Inclusive sample weights are reported as
 * observations; they are not exclusive CPU percentages or proof of a defect.
 * Unknown names, binary images, addresses, paths and arguments never escape. */
static bool sampleSummaryRefused(NSMutableDictionary*out,NSString*gate){out[@"gate"]=gate;return false;}
static bool samplingReportForPID(NSMutableDictionary*out,NSData*data,pid_t expectedPID){
 if(!data.length)return sampleSummaryRefused(out,@"safe-symbol-summary-empty");
 if(data.length>OUTPUT_LIMIT)return sampleSummaryRefused(out,@"safe-symbol-summary-size");out[@"sampleBytes"]=@(data.length);
 NSString*text=[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];if(!text)return sampleSummaryRefused(out,@"safe-symbol-summary-utf8");
 if(expectedPID<2)return sampleSummaryRefused(out,@"safe-symbol-summary-process-header");
 NSString*processPattern=[NSString stringWithFormat:@"^Process:[ \\t]+[^\\r\\n\\[\\]]{1,256}\\[%d\\][ \\t]*$",expectedPID];
 NSRegularExpression*process=[NSRegularExpression regularExpressionWithPattern:processPattern options:NSRegularExpressionAnchorsMatchLines error:NULL];
 NSRegularExpression*allProcesses=[NSRegularExpression regularExpressionWithPattern:@"^Process:[^\\r\\n]*$" options:NSRegularExpressionAnchorsMatchLines error:NULL];
 NSRegularExpression*allPaths=[NSRegularExpression regularExpressionWithPattern:@"^Path:[ \\t]+[^\\r\\n]{1,4096}$" options:NSRegularExpressionAnchorsMatchLines error:NULL];
 NSRegularExpression*exactPath=[NSRegularExpression regularExpressionWithPattern:@"^Path:[ \\t]+/Library/PrivilegedHelperTools/io\\.envara\\.pf-routing/envara-pf-native[ \\t]*$" options:NSRegularExpressionAnchorsMatchLines error:NULL];
 NSRange whole=NSMakeRange(0,text.length);
 bool processMatched=process&&allProcesses&&[process numberOfMatchesInString:text options:0 range:whole]==1&&[allProcesses numberOfMatchesInString:text options:0 range:whole]==1;
 out[@"reportProcessPIDMatched"]=@((BOOL)processMatched);if(!processMatched)return sampleSummaryRefused(out,@"safe-symbol-summary-process-header");
 /* Vendor sample redacts human paths on this host. Real executable identity
  * remains authenticated by kernel before/after observations, not this text. */
 out[@"reportPathExactlyMatched"]=@((BOOL)(exactPath&&[exactPath numberOfMatchesInString:text options:0 range:whole]==1));
 if(!allPaths||[allPaths numberOfMatchesInString:text options:0 range:whole]!=1)return sampleSummaryRefused(out,@"safe-symbol-summary-path-header");
 NSRegularExpression*frame=[NSRegularExpression regularExpressionWithPattern:@"^[ \\t+!|:]*([0-9]{1,7})[ \\t]+([^\\r\\n]{1,512}?)[ \\t]+\\(in[ \\t]" options:NSRegularExpressionAnchorsMatchLines error:NULL];if(!frame)return sampleSummaryRefused(out,@"safe-symbol-summary-frame-format");
 NSArray*matches=[frame matchesInString:text options:0 range:whole];out[@"reportFrameFormatObserved"]=@((BOOL)(matches.count>0));
 if(!matches.count)return sampleSummaryRefused(out,@"safe-symbol-summary-frame-format");if(matches.count>65536)return sampleSummaryRefused(out,@"safe-symbol-summary-frame-limit");
 NSMutableDictionary*occurrences=[NSMutableDictionary dictionary],*weights=[NSMutableDictionary dictionary];uint64_t unknown=0;
 for(NSTextCheckingResult*m in matches){if(m.numberOfRanges!=3)return sampleSummaryRefused(out,@"safe-symbol-summary-frame-format");NSString*weightText=[text substringWithRange:[m rangeAtIndex:1]],*name=[text substringWithRange:[m rangeAtIndex:2]];
  uint64_t weight=strtoull(weightText.UTF8String,NULL,10);if(!weight||weight>UINT32_MAX)return sampleSummaryRefused(out,@"safe-symbol-summary-weight-bound");
  if(![samplingSymbols()containsObject:name]){unknown++;continue;}
  uint64_t old=[weights[name]unsignedLongLongValue],n=[occurrences[name]unsignedLongLongValue];if(old+weight>UINT32_MAX||n>=65536)return sampleSummaryRefused(out,@"safe-symbol-summary-weight-bound");
  occurrences[name]=@(n+1);weights[name]=@(old+weight);
 }
 NSMutableArray*symbols=[NSMutableArray array];for(NSString*name in samplingSymbols())if(occurrences[name])[symbols addObject:@{@"name":name,@"occurrences":occurrences[name],@"reportedWeight":weights[name]}];
 out[@"stackFrameCount"]=@(matches.count);out[@"unrecognizedFrameCount"]=@(unknown);out[@"symbols"]=symbols;return true;
}
static bool formatSafeSampleReport(NSMutableDictionary*out,NSData*data){return samplingReportForPID(out,data,SOURCE_KEEPER_PID);}

static NSDictionary *samplingIdentity(NSDictionary*lease,NSDictionary*transport){
 if(![lease[@"controllerPid"]isEqual:@(SOURCE_CONTROLLER_PID)]||![lease[@"controllerBirth"]isEqual:CONTROLLER_BIRTH]||
  ![transport[@"keeperPID"]isEqual:@(SOURCE_KEEPER_PID)]||![transport[@"keeperBirth"]isEqual:KEEPER_BIRTH])return nil;
 NSDictionary*controller=processObservation(@"controller",@(SOURCE_CONTROLLER_PID),CONTROLLER_BIRTH,INSTALL "/node",0);
 NSDictionary*keeper=processObservation(@"keeper",@(SOURCE_KEEPER_PID),KEEPER_BIRTH,NATIVE,SOURCE_CONTROLLER_PID);
 if(![controller[@"state"]isEqual:@"live-exact-recorded-identity"]||![keeper[@"state"]isEqual:@"live-exact-recorded-identity"])return nil;
 return @{@"controller":controller,@"keeper":keeper};
}
static int sampleFixedKeeper(void){
 NSMutableDictionary*out=samplingOutcome();rootDeadline=seconds()+45;
 if(!inspectorRootCredentials()||!inspectorChildWaitBoundary()){out[@"gate"]=@"root-credentials";return emitInspection(out);}
 int installed=-1,runtime=-1,run=-1,state=-1;NSData*rb=nil,*lb=nil,*kb=nil;struct stat ri,li,ki,rooti,runi,statei;NSDictionary*record=nil,*lease=nil,*transport=nil;uint64_t gid=0;
 do{
  out[@"gate"]=@"installed-inventory";installed=verifiedInstallation(MIN(rootDeadline,seconds()+30));if(installed<0)break;
  out[@"gate"]=@"private-bindings";runtime=directory(RUNTIME);if(!secureFD(runtime,true,0700)||fstat(runtime,&rooti))break;
  rb=privateRead(runtime,"registry.json",65536,&ri);record=strictJSON(rb,65536);kb=privateRead(runtime,"registry.lock",4096,&ki);NSDictionary*lock=strictJSON(kb,4096);
  if(!keys(lock,@[@"runId",@"pid",@"anchor"])||![lock[@"runId"]isEqual:CANARY_RUN]||![lock[@"anchor"]isEqual:CANARY_ANCHOR]||![lock[@"pid"]isEqual:@(SOURCE_CONTROLLER_PID)])break;
  run=openat(runtime,CANARY_RUN.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(run,true,0700)||fstat(run,&runi))break;
  lb=privateRead(run,"app-bound-lease.json",16384,&li);lease=strictJSON(lb,16384);if(!liveShape(record,lease,lb,&transport,&gid)||!transport)break;
  state=openat(run,[lease[@"realmId"]UTF8String],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(state,true,0700)||fstat(state,&statei))break;
  out[@"gate"]=@"fixed-identities";NSDictionary*before=samplingIdentity(lease,transport);if(!before)break;out[@"beforeIdentityVerified"]=@YES;
  out[@"gate"]=@"bounded-sample";char*argv[]={(char*)"/usr/bin/sample",(char*)"48779",(char*)"1",(char*)"1",(char*)"-file",(char*)"/dev/stdout",NULL};int status=-1;
  NSData*report=fixedProcess(argv[0],argv,nil,&status,false);if(!report){out[@"gate"]=@"bounded-sample-unavailable";break;}if(status){out[@"gate"]=@"bounded-sample-nonzero-exit";break;}out[@"samplingToolExitedSuccessfully"]=@YES;
  NSDictionary*after=samplingIdentity(lease,transport);if(!after||![before isEqual:after])break;out[@"afterIdentityVerified"]=@YES;
  out[@"gate"]=@"safe-symbol-summary";if(!formatSafeSampleReport(out,report))break;
  out[@"gate"]=@"stable-private-snapshot";struct stat a,b,c;
  if(!unchanged(runtime,"registry.json",&ri,rb)||!unchanged(runtime,"registry.lock",&ki,kb)||!unchanged(run,"app-bound-lease.json",&li,lb)||
   fstatat(runtime,CANARY_RUN.UTF8String,&a,AT_SYMLINK_NOFOLLOW)||a.st_dev!=runi.st_dev||a.st_ino!=runi.st_ino||
   fstatat(run,[lease[@"realmId"]UTF8String],&b,AT_SYMLINK_NOFOLLOW)||b.st_dev!=statei.st_dev||b.st_ino!=statei.st_ino||lstat(RUNTIME,&c)||c.st_dev!=rooti.st_dev||c.st_ino!=rooti.st_ino||
   ![after isEqual:samplingIdentity(lease,transport)])break;
  out[@"stablePrivateSnapshotVerified"]=@YES;out[@"gate"]=@"sampling-complete";out[@"ok"]=@YES;out[@"reason"]=@"EXACT_FIXED_KEEPER_SAMPLED";
 }while(0);
 if(state>=0)close(state);if(run>=0)close(run);if(runtime>=0)close(runtime);if(installed>=0)close(installed);return emitInspection(out);
}
#ifndef SAMPLER_INERT
int main(int argc,char**argv){@autoreleasepool{
 if(argc>2)return emitInspection(samplingOutcome());const char*mode=argc==1?"--plan":argv[1];
 if(!strcmp(mode,"--plan")){NSMutableDictionary*out=samplingOutcome();out[@"ok"]=@YES;out[@"reason"]=@"INERT_READ_ONLY_PLAN";return emitInspection(out);}
 if(!strcmp(mode,"--sample-fixed-root"))return sampleFixedKeeper();return emitInspection(samplingOutcome());
}}
#endif
