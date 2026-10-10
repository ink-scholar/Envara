import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile), root=path.resolve(import.meta.dirname,'..'),native=path.join(root,'native/macos-pf-routing');
test('fixed sampler reachable entry contains only private bound one-second observation and never application recovery',async()=>{
 const s=await readFile(path.join(native,'sampler-app-14b87-run5be-v2.m'),'utf8');
 assert.match(s,/"\/usr\/bin\/sample".*?"48779".*?"1".*?"1".*?"-file".*?"\/dev\/stdout"/s);
 assert.match(s,/samplingIdentity\(lease,transport\).*?fixedProcess.*?samplingIdentity\(lease,transport\)/s);
 assert.doesNotMatch(s,/\bkill\s*\(|\bioctl\s*\(|\brenameatx_np\s*\(|\bunlinkat\s*\(|\bmkdirat\s*\(|\bnativeCall\s*\(|\bactiveClassObservation\s*\(|\bpfEmpty\s*\(|Authorization/);
 assert.match(s,/if\(!strcmp\(mode,"--sample-fixed-root"\)\)return sampleFixedKeeper\(\)/);
 assert.doesNotMatch(s,/--cleanup-fixed-root|--inspect-fixed-root|\"-E\"|\"-X\"|SIGKILL|SIGTERM/);
});
test('actual sample formatter only exports exact bounded whitelisted symbol observations and never raw report',async()=>{
 assert.notEqual(process.getuid(),0);const temp=await mkdtemp(path.join(tmpdir(),'envara-fixed-sampler-inert-'));
 try{const source=path.join(temp,'sample.m'),binary=path.join(temp,'sample');
 await writeFile(source,`
#define SAMPLER_INERT 1
#include "${path.join(native,'sampler-app-14b87-run5be-v2.m')}"
#include <assert.h>
static NSData*bytes(NSString*s){return [s dataUsingEncoding:NSUTF8StringEncoding];}
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);NSMutableDictionary*out=samplingOutcome();
 NSString*report=@"Process: envara-pf-native [48779]\\nPath: /Library/PrivilegedHelperTools/io.envara.pf-routing/envara-pf-native\\n  + 900 quarantine  (in envara-pf-native) + 100 [0xffff]\\n  +   899 read  (in libsystem_kernel.dylib) + 1 [0x1234]\\n  +   3 private-unknown-user-argument  (in unknown) + 1 [0xabcd]\\n  +   2 read  (in libsystem_kernel.dylib) + 1 [0x9876]\\n";
 assert(formatSafeSampleReport(out,bytes(report)));assert([out[@"stackFrameCount"]isEqual:@4]&&[out[@"unrecognizedFrameCount"]isEqual:@1]);assert([out[@"symbols"]count]==2);
 NSDictionary*q=out[@"symbols"][0],*r=out[@"symbols"][1];assert([q[@"name"]isEqual:@"quarantine"]&&[q[@"reportedWeight"]isEqual:@900]&&[q[@"occurrences"]isEqual:@1]);assert([r[@"name"]isEqual:@"read"]&&[r[@"reportedWeight"]isEqual:@901]&&[r[@"occurrences"]isEqual:@2]);
 NSData*json=[NSJSONSerialization dataWithJSONObject:out options:NSJSONWritingWithoutEscapingSlashes error:NULL];NSString*public=[[NSString alloc]initWithData:json encoding:NSUTF8StringEncoding];assert(![public containsString:@"private-unknown"]&&![public containsString:@"libsystem"]&&![public containsString:@"0xffff"]&&![public containsString:@"/Library"]);
 for(NSString*k in @[@"rawReportExposed",@"rawReportRetained",@"cleanupConfirmed",@"cleanupPermitted",@"ready",@"protected",@"productionReady",@"originalHostBaselineVerified",@"PFWriteExecuted",@"ownedAppOrKeeperSignalExecuted",@"runtimeChanged",@"beforeIdentityVerified",@"afterIdentityVerified",@"stablePrivateSnapshotVerified"])assert(isBool(out[k])&&![out[k]boolValue]);
 assert(isBool(out[@"readOnly"])&&[out[@"readOnly"]boolValue]&&isBool(out[@"cleanupUncertain"])&&[out[@"cleanupUncertain"]boolValue]);
 assert(!formatSafeSampleReport(samplingOutcome(),bytes([report stringByReplacingOccurrencesOfString:@"[48779]" withString:@"[15545]"])));
 NSMutableDictionary*redacted=samplingOutcome();assert(formatSafeSampleReport(redacted,bytes([report stringByReplacingOccurrencesOfString:@"/Library/PrivilegedHelperTools/io.envara.pf-routing/" withString:@"/Library/*/"])));assert(isBool(redacted[@"reportPathExactlyMatched"])&&![redacted[@"reportPathExactlyMatched"]boolValue]&&[redacted[@"reportProcessPIDMatched"]boolValue]&&[redacted[@"reportFrameFormatObserved"]boolValue]);
 assert(!formatSafeSampleReport(samplingOutcome(),bytes([report stringByAppendingString:@"Process: envara-pf-native [48779]\\n"])));
 assert(!formatSafeSampleReport(samplingOutcome(),bytes([report stringByReplacingOccurrencesOfString:@"900 quarantine" withString:@"0 quarantine"])));
 NSMutableDictionary*failure=samplingOutcome();assert(!formatSafeSampleReport(failure,bytes([report stringByReplacingOccurrencesOfString:@"[48779]" withString:@"[15545]"])));assert([failure[@"sampleBytes"]unsignedIntegerValue]>0&&[failure[@"gate"]isEqual:@"safe-symbol-summary-process-header"]);
 assert(!formatSafeSampleReport(samplingOutcome(),[NSData data]));assert(!formatSafeSampleReport(samplingOutcome(),[NSMutableData dataWithLength:OUTPUT_LIMIT+1]));
 assert(sampleFixedKeeper()==1);puts("typed sample-only whitelist and strict unsafe-report rejection passed");return 0;
}}
`,{mode:0o600});
 await exec('/usr/bin/clang',['-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function',source,path.join(native,'app-scope-proof.c'),'-framework','Foundation','-framework','Security','-o',binary],{timeout:30000});
 const result=await exec(binary,[],{timeout:10000});assert.match(result.stdout,/typed sample-only whitelist/);const refusal=JSON.parse(result.stdout.split('\n').find(l=>l.startsWith('{')));assert.equal(refusal.gate,'root-credentials');assert.equal(refusal.rawReportExposed,false);assert.equal(refusal.cleanupConfirmed,false);
 }finally{await rm(temp,{recursive:true,force:true});}
});


test('real vendor sample through actual native private-pipe capture reaches V2 formatter for a self-owned UID child',async()=>{
 assert.equal(process.platform,'darwin');assert.notEqual(process.getuid(),0);
 const {spawn}=await import('node:child_process');const temp=await mkdtemp(path.join(tmpdir(),'envara-vendor-sample-own-child-'));
 let child,exited;
 try{
  const source=path.join(temp,'actual.m'),binary=path.join(temp,'actual');
  await writeFile(source,`
#define SAMPLER_INERT 1
#include "${path.join(native,'sampler-app-14b87-run5be-v2.m')}"
#include <assert.h>
int main(int argc,char**argv){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0&&argc==2);pid_t ownChild=(pid_t)strtol(argv[1],NULL,10);assert(ownChild>1);struct proc_bsdinfo a={0},b={0};assert(proc_pidinfo(ownChild,PROC_PIDTBSDINFO,1,&a,sizeof(a))==sizeof(a)&&a.pbi_uid==getuid()&&a.pbi_ruid==getuid());
 rootDeadline=seconds()+10;char*sample[]={(char*)"/usr/bin/sample",argv[1],(char*)"1",(char*)"1",(char*)"-file",(char*)"/dev/stdout",NULL};int status=-1;NSData*actual=fixedProcess(sample[0],sample,nil,&status,false);assert(actual&&status==0);
 assert(proc_pidinfo(ownChild,PROC_PIDTBSDINFO,1,&b,sizeof(b))==sizeof(b)&&a.pbi_pid==b.pbi_pid&&a.pbi_ppid==b.pbi_ppid&&a.pbi_uid==b.pbi_uid&&a.pbi_start_tvsec==b.pbi_start_tvsec&&a.pbi_start_tvusec==b.pbi_start_tvusec);
 NSMutableDictionary*out=samplingOutcome();assert(samplingReportForPID(out,actual,ownChild));
 assert(isBool(out[@"reportProcessPIDMatched"])&&[out[@"reportProcessPIDMatched"]boolValue]&&isBool(out[@"reportFrameFormatObserved"])&&[out[@"reportFrameFormatObserved"]boolValue]);
 assert([out[@"sampleBytes"]unsignedIntegerValue]==actual.length&&[out[@"stackFrameCount"]unsignedIntegerValue]>0);
 assert(isBool(out[@"reportPathExactlyMatched"]));for(NSString*k in @[@"rawReportExposed",@"rawReportRetained",@"ready",@"protected",@"cleanupConfirmed",@"beforeIdentityVerified",@"afterIdentityVerified"])assert(isBool(out[k])&&![out[k]boolValue]);
 printf("{\\"sampleBytes\\":%lu,\\"stackFrameCount\\":%lu,\\"reportProcessPIDMatched\\":true,\\"reportFrameFormatObserved\\":true,\\"reportPathExactlyMatched\\":%s,\\"rawReportExposed\\":false}\\n",(unsigned long)actual.length,(unsigned long)[out[@"stackFrameCount"]unsignedIntegerValue],[out[@"reportPathExactlyMatched"]boolValue]?"true":"false");return 0;
}}
`,{flag:'wx',mode:0o600});
  await exec('/usr/bin/clang',['-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function',source,path.join(native,'app-scope-proof.c'),'-framework','Foundation','-framework','Security','-o',binary],{timeout:30000});
  child=spawn('/usr/bin/python3',['-c','import time; time.sleep(5)'],{stdio:'ignore',env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin'}});
  exited=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(code,signal)=>resolve({code,signal}));});
  assert.ok(child.pid>1&&child.exitCode===null);const identity=async()=>{const r=await exec('/bin/ps',['-p',String(child.pid),'-o','pid=,ppid=,uid='],{timeout:3000});return r.stdout.trim().split(/\s+/).map(Number);};
  const before=await identity();assert.deepEqual(before,[child.pid,process.pid,process.getuid()]);
  const summary=JSON.parse((await exec(binary,[String(child.pid)],{timeout:12000})).stdout);assert.equal(summary.reportProcessPIDMatched,true);assert.equal(summary.reportFrameFormatObserved,true);assert.equal(summary.reportPathExactlyMatched,false);assert.equal(summary.rawReportExposed,false);
  const after=await identity();assert.deepEqual(after,before);assert.equal(child.exitCode,null);
  const ending=await exited;assert.deepEqual(ending,{code:0,signal:null});
  const evidence={schema:'envara.vendor-sample-own-uid-child-format/v1',readOnly:true,sampledRootKeeper:false,childOwned:true,childUID:process.getuid(),exactUIDParentPIDBeforeAfter:true,vendorSampleExitCode:0,sampleArguments:['OWNED_CHILD_PID','1','1','-file','/dev/stdout'],actualNativePrivatePipeCapture:true,stderrNotForwarded:true,rawReportPublic:false,rawReportRetained:false,summary,childExitedNaturally:true};
  await writeFile(path.join(root,'test-artifacts/mac-pf-routing/14b87-run5be-vendor-own-child-sample-format-20261009.json'),JSON.stringify(evidence,null,2)+'\n',{mode:0o600});
 }finally{if(exited)await exited;await rm(temp,{recursive:true,force:true});}
});
