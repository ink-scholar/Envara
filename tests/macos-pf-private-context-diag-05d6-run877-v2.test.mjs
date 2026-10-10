import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile),root=path.resolve(import.meta.dirname,'..'),native=path.join(root,'native/macos-pf-routing');
test('pure private-context diagnostic preserves the frozen 51-field recovery envelope, has no cleanup entry and refuses nonroot',async()=>{
 if(process.platform!=='darwin'||process.arch!=='arm64'||process.getuid()===0)return;
 const temporary=await mkdtemp(path.join(tmpdir(),'envara-private-context-diag-test-'));
 try{
  const file=path.join(temporary,'fixture.m'),binary=path.join(temporary,'fixture');
  await writeFile(file,`#define PRIVATE_CONTEXT_DIAG_INERT 1\n#include "${path.join(native,'inspector-app-05d6-run877-private-context-diag-v2-20261009.m')}"\n#include <assert.h>\nint main(void){@autoreleasepool{NSDictionary*d=pcdOutcome();assert(d.count==51);assert([d[@"schema"]isEqual:@"envara.macos-pf-live-application-recovery/v1"]);assert([d[@"readOnly"]isEqual:@YES]);assert([d[@"cleanupConfirmed"]isEqual:@NO]);assert([d[@"cleanupUncertain"]isEqual:@YES]);assert([d[@"coreReapedByRecovery"]isEqual:@NO]);assert([d[@"ownedDenialVerified"]isEqual:@NO]);assert([pcdRole(@"cache.db",@[])isEqual:@"core-cache-db"]);assert([pcdRole(@"secret-name",@[])isEqual:@"unrecognized-entry"]);return pcdInspect();}}\n`,{mode:0o600});
  await exec('/usr/bin/clang',['-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function',file,path.join(native,'app-scope-proof.c'),'-framework','Foundation','-framework','Security','-o',binary],{timeout:30000});
  let result;try{await exec(binary,[],{timeout:10000});assert.fail('Nonroot inspection succeeded');}catch(error){assert.equal(error.code,1);result=JSON.parse(error.stdout);}
  assert.equal(Object.keys(result).length,51);assert.equal(result.gate,'root-credentials');
  const source=await readFile(path.join(native,'inspector-app-05d6-run877-private-context-diag-v2-20261009.m'),'utf8');
  assert.ok(!source.includes('#include "recovery-'));assert.ok(!source.includes('"--cleanup-fixed-root"'));assert.ok(!source.includes('privateContextDiagnostic'));assert.ok(!source.includes('kill('));assert.ok(!source.includes('renameat'));assert.ok(!source.includes('O_RDWR'));
 }finally{await rm(temporary,{recursive:true,force:true});}
});
