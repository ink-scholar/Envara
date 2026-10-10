// Source-only, unprivileged builder. Only --plan and nonroot refusals execute.
import path from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { constants } from 'node:fs';
import { mkdtemp, realpath, open, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec=promisify(execFile),root=path.resolve(import.meta.dirname,'..');
async function hash(filename){const f=await open(filename,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);try{const a=await f.stat({bigint:true});if(!a.isFile()||a.nlink!==1n||a.size>1048576n)throw Error('Unsafe source input');const b=await f.readFile(),c=await f.stat({bigint:true});if(BigInt(b.length)!==a.size||['dev','ino','mode','size','mtimeNs','ctimeNs'].some(k=>a[k]!==c[k]))throw Error('Input changed');return createHash('sha256').update(b).digest('hex');}finally{await f.close();}}
export async function buildFixedUTunAPIProbe(){
 if(process.platform!=='darwin'||process.arch!=='arm64'||process.getuid()===0)throw Error('Requires unprivileged Darwin arm64');
 const names=['native/macos-pf-routing/utun-api-probe.m','native/macos-pf-routing/tunnel.c','native/macos-pf-routing/native.h','tests/macos-utun-api-probe.test.mjs','scripts/build-macos-utun-api-probe.mjs'];
 const sourceInputs=Object.fromEntries(await Promise.all(names.map(async name=>[name,await hash(path.join(root,name))])));
 const directory=await realpath(await mkdtemp(path.join(tmpdir(),'envara-utun-api-probe-'))),binary=path.join(directory,'EnvaraFixedUTunAPIProbe');
 await exec('/usr/bin/clang',['-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function',path.join(root,names[0]),path.join(root,names[1]),'-framework','Foundation','-Wl,-dead_strip','-o',binary]);
 await exec('/usr/bin/codesign',['--force','--sign','-','--identifier','io.envara.fixed-utun-api-probe','--options','runtime','--timestamp=none',binary]);
 await exec('/usr/bin/codesign',['--verify','--strict','--all-architectures',binary]);
 const details=(await exec('/usr/bin/codesign',['--display','--verbose=4',binary])).stderr;if(!details.includes('Info.plist=not bound')||!details.includes('runtime'))throw Error('Standalone signature missing');
 const symbols=(await exec('/usr/bin/nm',['-u',binary])).stdout;if(!/(?:^|\n)_getgroups(?:\n|$)/.test(symbols)||symbols.includes('$DARWIN_EXTSN')||(await exec('/usr/bin/nm',[binary])).stdout.includes('_envara_utun_configure'))throw Error('Unexpected native credential/configuration linkage');
 const plan=JSON.parse((await exec(binary,['--plan'])).stdout);if(Object.keys(plan).length!==50||plan.schema!=='envara.macos-utun-api-probe/v1'||plan.ok!==true||plan.readOnly!==true||plan.socketCreated!==false||plan.cleanupConfirmed!==false||plan.ready!==false||plan.protected!==false)throw Error('Invalid inert plan');
 let refusal;try{await exec(binary,['--probe-fixed-root']);throw Error('Nonroot probe succeeded');}catch(e){if(e.code!==1)throw e;refusal=JSON.parse(e.stdout);if(refusal.socketCreated!==false||refusal.gate!=='root-credentials'||refusal.ok!==false)throw Error('Invalid nonroot refusal');}
 for(const[name,sha]of Object.entries(sourceInputs))if(await hash(path.join(root,name))!==sha)throw Error('Source changed during build');
 const proof={schema:'envara.macos-utun-api-probe-build/v1',checkedAt:new Date().toISOString(),directory,app:binary,binary,binarySHA256:await hash(binary),sourceInputs,plan,refusal,kernelCredentialGetter:{symbol:'_getgroups',darwinDirectoryExtensionImported:false},signature:{localAdHoc:true,hardenedRuntime:true,standalone:true,strictAllArchitecturesVerified:true,distributionTrustEstablished:false},authorizationRequested:false,rootExecuted:false,nativeProbeExecuted:false,systemOperationExecuted:false,PFWriteExecuted:false,configurationExecuted:false,applicationLaunchExecuted:false,originalHostBaselineVerified:false,productionReady:false};
 await writeFile(path.join(directory,'build.json'),JSON.stringify(proof,null,2)+'\n',{flag:'wx',mode:0o600});
 await writeFile(path.join(root,'test-artifacts/mac-pf-routing/utun-api-probe-build-20261009.json'),JSON.stringify(proof,null,2)+'\n',{flag:'wx',mode:0o600});return proof;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){if(process.argv.length!==2){console.error('No operation or path overrides');process.exitCode=1;}else{try{console.log(JSON.stringify(await buildFixedUTunAPIProbe()));}catch(e){console.error(e.message);process.exitCode=1;}}}
