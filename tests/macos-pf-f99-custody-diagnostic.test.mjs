import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import path from 'node:path';
const exec=promisify(execFile),native=path.resolve(import.meta.dirname,'../native/macos-pf-routing');
const flags=['-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function'];
test('actual nonroot current-process FD getter demonstrates capacity != populated bytes; diagnostic accepts complete bounded list',async()=>{
 assert.notEqual(process.getuid(),0);const dir=await mkdtemp(path.join(tmpdir(),'envara-f99-custody-capacity-'));
 try{const source=`
#define CUSTODY_DIAGNOSTIC_INERT 1
#include "${path.join(native,'diagnostic-app-f99-custody-run145.m')}"
#include <assert.h>
int main(void){@autoreleasepool{
 assert(getuid()!=0&&geteuid()!=0);int size=proc_pidinfo(getpid(),PROC_PIDLISTFDS,0,NULL,0);assert(size>0&&size<65536);
 struct proc_fdinfo*list=calloc(1,(size_t)size);assert(list);int got=proc_pidinfo(getpid(),PROC_PIDLISTFDS,0,list,size);free(list);
 assert(got>0&&got<size&&custodyListSize(size,size+256,got));assert(custodyListSize(size,size+256,size));assert(!custodyListSize(size,size+256,size+8));assert(!custodyListSize(0,256,8));assert(!custodyListSize(65544,65800,24));assert(!custodyListSize(360,616,23));assert(!custodyListSize(360,616,0));
 NSDictionary*out=custodyOutcome();for(NSString*k in @[@"readOnly",@"cleanupConfirmed",@"cleanupPermitted",@"recordedProcessSignalExecuted",@"PFWriteExecuted",@"runtimeWriteExecuted",@"ready",@"protected",@"productionReady"]){assert(CFGetTypeID((__bridge CFTypeRef)out[k])==CFBooleanGetTypeID());assert([out[k]boolValue]==[k isEqual:@"readOnly"]);}
 F99FDPass first={0},second={0};NSMutableDictionary *a=custodyFDOutcome(),*b=custodyFDOutcome();
 assert(custodyReadPass(getpid(),NULL,&first,a));assert(custodyReadPass(getpid(),NULL,&second,b));assert([a[@"completeList"]boolValue]&&[a[@"metadataComplete"]boolValue]);
 assert([a[@"queryBytes"]intValue]>[a[@"readBytes"]intValue]);assert(custodyListSame(&first,&second)&&custodyMetadataSame(&first,&second));
 second.list[0].proc_fd++;assert(!custodyListSame(&first,&second));second.list[0].proc_fd--;
 F99SocketIdentity wa={.fd=100,.uid=0,.gid=7100,.inode=123,.ctl_unit=7},wb=wa;F99FDPass sa={.sockets=&wa,.socket_count=1},sb={.sockets=&wb,.socket_count=1};
 assert(custodyMetadataSame(&sa,&sb));wb.gid=0;assert(!custodyMetadataSame(&sa,&sb));wb=wa;wb.inode++;assert(!custodyMetadataSame(&sa,&sb));wb=wa;wb.ctl_unit++;assert(!custodyMetadataSame(&sa,&sb));
 f99FreeFDPass(&first);f99FreeFDPass(&second);NSDictionary*n=out[@"netstat"];assert([n[@"firstExit"]intValue]==-1&&![n[@"firstTextAvailable"]boolValue]);
 assert([out count]==35&&[a count]==18&&[n count]==10);
 printf("actual-own-FD-capacity-%d-populated-%d-no-root-or-other-process\\n",size,got);return 0;
}}`;
 await writeFile(path.join(dir,'fixture.m'),source);await exec('/usr/bin/clang',[...flags,path.join(dir,'fixture.m'),path.join(native,'app-scope-proof.c'),'-framework','Foundation','-framework','Security','-o',path.join(dir,'fixture')],{timeout:30000});
 assert.match((await exec(path.join(dir,'fixture'),[],{timeout:10000})).stdout,/actual-own-FD-capacity-/);
 }finally{await rm(dir,{recursive:true,force:true});}
});
test('standalone only fixed readonly entry, no cleanup operation, legacy kernel getter retained',async()=>{
 assert.notEqual(process.getuid(),0);const dir=await mkdtemp(path.join(tmpdir(),'envara-f99-custody-entry-'));
 try{const binary=path.join(dir,'FixedCustodyDiagnostic');await exec('/usr/bin/clang',[...flags,path.join(native,'diagnostic-app-f99-custody-run145.m'),path.join(native,'app-scope-proof.c'),'-framework','Foundation','-framework','Security','-o',binary],{timeout:30000});
 const plan=JSON.parse((await exec(binary,['--plan'])).stdout);assert.equal(plan.schema,'envara.macos-pf-live-custody-diagnostic/v1');assert.equal(plan.manifestSHA256,'f99aac934122ac3cafe992ac6fbf232ff917c1b8632034d19491b3dca7ab0d51');
 for(const k of ['cleanupConfirmed','cleanupPermitted','ready','protected','productionReady','recordedProcessSignalExecuted','PFWriteExecuted','runtimeWriteExecuted'])assert.equal(plan[k],false);
 for(const args of [['--inspect-fixed-root'],['--cleanup-fixed-root'],['--request-readonly'],['--inspect-fixed-root','/arbitrary']]){const result=await exec(binary,args).catch(e=>e);assert.equal(result.code,1);const r=JSON.parse(result.stdout);assert.equal(r.readOnly,true);assert.equal(r.cleanupPermitted,false);assert.equal(r.PFWriteExecuted,false);}
 const allSymbols=(await exec('/usr/bin/nm',[binary])).stdout;assert.doesNotMatch(allSymbols, /f99Recover|f99Signal|f99ClearFilter|f99GroupDelete|f99Archive|f99Load|f99ObserveCustody|f99PortObservation/);
 const symbols=(await exec('/usr/bin/nm',['-u',binary])).stdout;assert.match(symbols,/(?:^|\n)_getgroups(?:\n|$)/);assert.doesNotMatch(symbols,/_getgroups\$DARWIN_EXTSN|AuthorizationExecuteWithPrivileges|AuthorizationCopyRights/);
 }finally{await rm(dir,{recursive:true,force:true});}
});
