import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile), root=path.resolve(import.meta.dirname,'..'),native=path.join(root,'native/macos-pf-routing');
test('fixed sampler reachable entry contains only private bound one-second observation and never application recovery',async()=>{
 const s=await readFile(path.join(native,'sampler-app-14b87-run5be.m'),'utf8');
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
#include "${path.join(native,'sampler-app-14b87-run5be.m')}"
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
 assert(!formatSafeSampleReport(samplingOutcome(),bytes([report stringByReplacingOccurrencesOfString:@"/io.envara.pf-routing/" withString:@"/foreign/"])));
 assert(!formatSafeSampleReport(samplingOutcome(),bytes([report stringByAppendingString:@"Process: envara-pf-native [48779]\\n"])));
 assert(!formatSafeSampleReport(samplingOutcome(),bytes([report stringByReplacingOccurrencesOfString:@"900 quarantine" withString:@"0 quarantine"])));
 assert(!formatSafeSampleReport(samplingOutcome(),[NSData data]));assert(!formatSafeSampleReport(samplingOutcome(),[NSMutableData dataWithLength:OUTPUT_LIMIT+1]));
 assert(sampleFixedKeeper()==1);puts("typed sample-only whitelist and strict unsafe-report rejection passed");return 0;
}}
`,{mode:0o600});
 await exec('/usr/bin/clang',['-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function',source,path.join(native,'app-scope-proof.c'),'-framework','Foundation','-framework','Security','-o',binary],{timeout:30000});
 const result=await exec(binary,[],{timeout:10000});assert.match(result.stdout,/typed sample-only whitelist/);const refusal=JSON.parse(result.stdout.split('\n').find(l=>l.startsWith('{')));assert.equal(refusal.gate,'root-credentials');assert.equal(refusal.rawReportExposed,false);assert.equal(refusal.cleanupConfirmed,false);
 }finally{await rm(temp,{recursive:true,force:true});}
});
