import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile), source = path.resolve('native/macos-pf-routing/utun-api-probe.m');
const flags = ['-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function'];
test('actual producer preserves unsupported getsockname and denies missing custody, host mismatch and numeric BOOL', async () => {
 const directory=await mkdtemp(path.join(tmpdir(),'envara-utun-api-fixture-'));
 try {
  const fixture=path.join(directory,'fixture.m'), binary=path.join(directory,'fixture');
  await writeFile(fixture,`#define UTUN_PROBE_INERT 1
#include ${JSON.stringify(source)}
int envara_utun_open(char*n,size_t s){(void)n;(void)s;abort();}
static void require(bool x){if(!x)abort();}
static NSMutableDictionary*complete(void){NSMutableDictionary*d=probeOutcome(false);for(NSString*k in d.allKeys)if(CFGetTypeID((__bridge CFTypeRef)d[k])==CFBooleanGetTypeID()&&![ @[@"ok",@"readOnly",@"cleanupConfirmed",@"cleanupUncertain",@"ready",@"protected",@"productionReady",@"originalHostBaselineVerified",@"PFWriteExecuted",@"routeWriteExecuted",@"DNSWriteExecuted",@"MTUWriteExecuted",@"IPConfigurationExecuted",@"coreLaunched",@"groupChanged",@"applicationLaunchExecuted"] containsObject:k])d[k]=@YES;
 d[@"getsocknameReturn"]=@(-1);d[@"getsocknameErrno"]=@(ENOTSUP);for(NSString*k in @[@"ctlInfo",@"getpeername",@"ifname"])observation(d,k,0,0);return d;}
int main(void){@autoreleasepool{
 NSMutableDictionary*d=complete();require(d.count==50&&finishProbe(d));require([d[@"getsocknameReturn"]intValue]==-1&&[d[@"getsocknameErrno"]intValue]==ENOTSUP&&[d[@"cleanupConfirmed"]boolValue]&&![d[@"readOnly"]boolValue]);
 for(NSString*k in @[@"duplicateEBADF",@"originalClosed",@"interfaceAbsent",@"pfConfigMatched"]){NSMutableDictionary*x=complete();x[k]=@NO;require(!finishProbe(x));x[k]=@1;require(!finishProbe(x));}
 for(NSNumber*e in @[@0,@1025]){NSMutableDictionary*x=complete();x[@"getsocknameErrno"]=e;require(!finishProbe(x));}
 NSMutableDictionary*x=complete();x[@"ctlInfoReturn"]=@(-1);require(!finishProbe(x));
 NSDictionary*a=@{@"routes":@1,@"dns":@2,@"nat":@3,@"rootPF":@4,@"pfConfig":@5};NSMutableDictionary*b=[a mutableCopy];b[@"dns"]=@6;x=probeOutcome(false);comparison(x,a,b);require([x[@"hostComparisonAvailable"]boolValue]&&![x[@"dnsMatched"]boolValue]&&![x[@"currentHostNetworkUnchanged"]boolValue]);
 int f[2];require(socketpair(AF_UNIX,SOCK_DGRAM,0,f)==0);struct stat before,copy,held;require(fstat(f[0],&before)==0);int dup=fcntl(f[0],F_DUPFD_CLOEXEC,3);require(dup>=3&&fstat(dup,&copy)==0&&sameSocket(&before,&copy));require(close(dup)==0&&closedFD(dup)&&fcntl(f[0],F_GETFD)>=0&&fstat(f[0],&held)==0&&sameSocket(&before,&held));
 x=probeOutcome(false);require(!inspectSocket(f[0],"utun-fixture",x)&&![x[@"peerAddressVerified"]boolValue]);require(close(f[0])==0&&closedFD(f[0]));close(f[1]);
 errno=0;require(if_nametoindex("envara-absent")==0&&errno==ENXIO&&interfacePresence("envara-absent")==0&&interfacePresence("lo0")==1);
 return emit(d);}}
`,{flag:'wx',mode:0o600});
  await exec('/usr/bin/clang',[...flags,fixture,'-framework','Foundation','-o',binary]);
  const result=JSON.parse((await exec(binary,[])).stdout);assert.equal(result.ok,true);assert.equal(result.cleanupConfirmed,true);assert.equal(result.getsocknameReturn,-1);assert.equal(result.originalHostBaselineVerified,false);
 } finally {await rm(directory,{recursive:true,force:true});}
});
test('compiled real entry plan and nonroot or arbitrary argument refusals never open a UTUN', async () => {
 assert.notEqual(process.getuid(),0);const directory=await mkdtemp(path.join(tmpdir(),'envara-utun-api-entry-'));
 try {
  const binary=path.join(directory,'probe');await exec('/usr/bin/clang',[...flags,source,path.resolve('native/macos-pf-routing/tunnel.c'),'-framework','Foundation','-Wl,-dead_strip','-o',binary]);
  const plan=JSON.parse((await exec(binary,['--plan'])).stdout);assert.equal(Object.keys(plan).length,50);assert.equal(plan.ok,true);assert.equal(plan.readOnly,true);assert.equal(plan.socketCreated,false);
  for(const args of [[],['--probe-fixed-root'],['--probe-fixed-root','utun0'],['--cleanup-fixed-root']]){
   let output;try{await exec(binary,args);assert.fail('Expected refusal');}catch(error){assert.equal(error.code,1);output=JSON.parse(error.stdout);}
   assert.equal(output.ok,false);assert.equal(output.socketCreated,false);assert.equal(output.cleanupConfirmed,false);if(args.length===1&&args[0]==='--probe-fixed-root')assert.equal(output.gate,'root-credentials');
  }
  const symbols=(await exec('/usr/bin/nm',['-u',binary])).stdout;assert.match(symbols,/(?:^|\n)_getgroups(?:\n|$)/);assert.ok(!symbols.includes('$DARWIN_EXTSN'));
  assert.ok(!(await exec('/usr/bin/nm',[binary])).stdout.includes('_envara_utun_configure'));
 } finally{await rm(directory,{recursive:true,force:true});}
});
