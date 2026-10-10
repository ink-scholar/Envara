// Independent fixed-run filesystem archive carrier. Builds / inert fixtures / --plan
// only; no native rights, installed helper invocation or system inspection.
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { mkdtemp, realpath, mkdir, readFile, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { hashPFCanaryInput } from './build-macos-pf-run-canary-2a7.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const MF='83256899dc6db90bb6a21dcd18d17cb08a46d3ba4e79177098629475cc107f78';
const NATIVE='8259641a73e96a28a8d1ca373b2d51c066bb74fafd91450e3f59279a477844b8';
const RUN='95c92c49-063e-4595-b28f-232f558d6f6e';
const exec=promisify(execFile), options={timeout:30000,maxBuffer:1024*1024,env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin'}};
assert.equal(process.platform,'darwin'); assert.equal(process.arch,'arm64');
assert.equal(process.argv.length,2,'Builder accepts no activation, installation or caller paths.');
const source='native/macos-pf-routing/recovery-runtime-retirement-832-run95c92.m';
const tests=['native/macos-pf-routing/recovery-readonly-832-run95c92-inert-tests.m','native/macos-pf-routing/recovery-gid-proof-832-run95c92-inert-tests.m','native/macos-pf-routing/recovery-runtime-inventory-832-run95c92-inert-tests.m','native/macos-pf-routing/recovery-runtime-retirement-832-run95c92-inert-tests.m'];
const inputs=[source,...tests,'native/macos-pf-routing/recovery-readonly-832-run95c92.m','native/macos-pf-routing/recovery-runtime-inventory-832-run95c92.h','native/macos-pf-routing/recovery-gid-proof-832-run95c92.h','native/macos-pf-routing/pf-hook-abi.h','scripts/build-macos-pf-runtime-retirement-832-run95c92.mjs','scripts/build-macos-pf-run-canary-2a7.mjs'];
const snapshot=async()=>{ const result={}; for(const name of inputs) result[name]=(await hashPFCanaryInput(path.join(root,name))).sha256; return result; };
const before=await snapshot(), staged=path.join(root,'build/app-routing/macos-pf'), manifestFile=path.join(staged,'manifest.json');
assert.equal((await hashPFCanaryInput(manifestFile)).sha256,MF);
const manifest=JSON.parse(await readFile(manifestFile,'utf8'));
assert.equal(manifest.schema,'envara.macos-pf-installation/v1'); assert.equal(Object.keys(manifest.files).length,14);
assert.equal(manifest.files['envara-pf-native'],NATIVE);
// Future controller/fixture fixes may coexist in the checkout; never compile
// those into this carrier. The sole shared C ABI is independently bound to
// the corresponding-source hash in the immutable 832 manifest.
assert.equal(before['native/macos-pf-routing/pf-hook-abi.h'],manifest.nativeSourceFiles?.['native/macos-pf-routing/pf-hook-abi.h']);
const executableLeaves=new Set(['node','mihomo','envara-pf-native','EnvaraPFHelper','fixtures/EnvaraRoutingAcceptanceFixture']);
const runtimeInputs={'manifest.json':{sha256:MF,mode:0o644}};
const sourceText=await readFile(path.join(root,'native/macos-pf-routing/recovery-readonly-832-run95c92.m'),'utf8');
for(const [name,expected] of Object.entries(manifest.files)) {
 assert.ok(/^[a-zA-Z0-9_.-]+$/.test(name)||name==='fixtures/EnvaraRoutingAcceptanceFixture');
 const actual=await hashPFCanaryInput(path.join(staged,name)),mode=executableLeaves.has(name)?0o755:0o644;
 assert.equal(actual.sha256,expected,`Fixed 832 leaf changed: ${name}`); assert.equal(actual.mode,mode);
 assert.ok(sourceText.includes(`{"${name}", "${expected}", 0${mode.toString(8)}}`),`Compiled leaf pin missing: ${name}`);
 runtimeInputs[name]={sha256:expected,mode};
}
assert.ok(sourceText.includes(MF) && sourceText.includes(RUN));
const directory=await realpath(await mkdtemp(path.join(tmpdir(),'envara-pf-archive-832-run95c92-')));
const app=path.join(directory,'Envara PF Runtime Archive 832 Run95c92.app'),contents=path.join(app,'Contents'),macOS=path.join(contents,'MacOS');
await mkdir(macOS,{recursive:true,mode:0o700}); const binary=path.join(macOS,'EnvaraPFRuntimeRetirement832Run95c92');
const flags=['-fobjc-arc','-fblocks','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function'];
await exec('/usr/bin/clang',[...flags,path.join(root,source),'-framework','Foundation','-framework','Security','-o',binary],options);
const inertResults=[];
for(const [index,name] of tests.entries()) {
 const executable=path.join(directory,`inert-${index}`);
 await exec('/usr/bin/clang',[...flags,'-Wno-unused-function',path.join(root,name),'-framework','Foundation','-framework','Security','-o',executable],options);
 const result=await exec(executable,[],options); assert.match(result.stdout,/inert.*(tests|fixture)|inert GID-proof tests/);
 inertResults.push({source:name,passed:true,stdout:result.stdout.trim()});
}
assert.deepEqual(await snapshot(),before,'Independent diagnostic source changed while compiling.');
const plist='<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.envara.pf-runtime-retirement-832-run95c92</string><key>CFBundleName</key><string>Envara PF Runtime Archive 832 Run95c92</string><key>CFBundleExecutable</key><string>EnvaraPFRuntimeRetirement832Run95c92</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>1</string><key>LSUIElement</key><true/></dict></plist>\n';
await writeFile(path.join(contents,'Info.plist'),plist,{flag:'wx',mode:0o600});
await exec('/usr/bin/plutil',['-lint',path.join(contents,'Info.plist')],options);
await exec('/usr/bin/codesign',['--force','--sign','-','--timestamp=none',app],options);
await exec('/usr/bin/codesign',['--verify','--strict',app],options);
const plan=JSON.parse((await exec(binary,['--plan'],options)).stdout);
assert.equal(plan.runId,RUN); assert.equal(plan.installedManifestSHA256,MF); assert.equal(plan.manifestSHA256,MF);
assert.equal(plan.readOnly,true); assert.equal(plan.changesFilesystem,false); assert.equal(plan.retirementAttempted,false); assert.equal(plan.namespaceReclaimed,false);
assert.equal(plan.authorizationRequested,false); assert.equal(plan.cleanupConfirmed,false); assert.equal(plan.productionReady,false);
assert.equal(plan.failedRunHostBaselineMatched,false); assert.equal(plan.scope,'atomic-filesystem-archive-only');
assert.equal(plan.fixedCapsule,'/Library/PrivilegedHelperTools/io.envara.pf-retired-832-95c92c49');
assert.deepEqual(await snapshot(),before,'Source changed before final proof.');
assert.equal((await hashPFCanaryInput(manifestFile)).sha256,MF,'Frozen runtime manifest changed.');
for(const [name,expected] of Object.entries(runtimeInputs)) assert.equal((await hashPFCanaryInput(path.join(staged,name))).sha256,expected.sha256);
const report={schema:'envara.macos-pf-fixed-runtime-retirement-build/v1',at:new Date().toISOString(),app,binary,
 pinnedABISHA256:manifest.nativeSourceFiles['native/macos-pf-routing/pf-hook-abi.h'],binarySHA256:(await hashPFCanaryInput(binary)).sha256,sourceSHA256:before[source],compiledInputs:before,
 compiledInputSHA256:createHash('sha256').update(JSON.stringify(before)).digest('hex'),runtimeInputs,inertResults,plan,
 rootAuthorizationRequested:false,installedSystemInspected:false,systemArchiveExecuted:false,systemMutated:false,PFWritesExecuted:false,
 leaseDELETEReplayPossible:false,cleanupConfirmed:false,productionReady:false,bootstrapSelfPathAttested:false};
const artifact=path.join(root,'test-artifacts/mac-pf-routing',`runtime-retirement-832-run95c92-candidate-${before[source].slice(0,8)}-${report.compiledInputSHA256.slice(0,8)}.json`);
await writeFile(artifact,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
console.log(JSON.stringify({...report,artifact},null,2));
