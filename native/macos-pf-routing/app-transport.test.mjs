import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, realpathSync, chmodSync, rmSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

test('same native transport retains listener custody, strictly relays controls and refuses rootless activation',
  { skip: process.platform !== 'darwin' }, async t => {
    assert.notEqual(process.getuid(),0); assert.equal(process.getuid(),process.geteuid());
    const root=path.dirname(fileURLToPath(import.meta.url));
    const temporary=realpathSync(mkdtempSync('/private/tmp/envara-app-transport-')); chmodSync(temporary,0o700);
    const names=['launcher.c','tunnel.c','transport.c','gui-launch.m','app-registry.c','app-ticket.c','app-supervisor.c','launch-guardian.c',
      'notion-launch.m','app-native-factory.m','app-scope-proof.c','pf-hook.c','pf-run-ledger.c','pf-production-filter.c','app-transport.c','app-transport-fixture.c'];
    const hash=()=>names.map(name=>createHash('sha256').update(readFileSync(path.join(root,name))).digest('hex'));
    const before=hash();
    try {
      const executable=path.join(temporary,'fixture');
      const result=spawnSync('xcrun',['clang','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations',
        '-target',`${process.arch==='arm64'?'arm64':'x86_64'}-apple-macos13.0`,...names.filter(name=>name!=='app-transport.c').map(name=>path.join(root,name)),
        '-framework','Foundation','-framework','AppKit','-framework','Security','-lbsm','-o',executable],{encoding:'utf8',timeout:60000});
      assert.equal(result.status,0,result.stderr);
      for (const mode of ['bounded-diagnostic','listener','relay','malformed','refused','cold-fds','abort-proofs','preflight-proofs','listener-protocol']) await t.test(mode,()=>{
        const result=spawnSync(executable,[mode],{encoding:'utf8',timeout:10000});
        assert.equal(result.signal,null,result.stderr); assert.equal(result.status,0,result.stderr+'\n'+result.stdout);
        const report=JSON.parse(result.stdout); assert.equal(report.ok,true); assert.equal(report.ready,false); assert.equal(report.protected,false);
        if(mode==='listener-protocol') {
          for(const [key,value]of Object.entries(report))if(!['ready','protected','rightsCapacity','fdCensus'].includes(key))assert.equal(value,true,key);
          assert.equal(report.rightsCapacity,512);assert.equal(report.fdCensus.length,11);
          for(const item of report.fdCensus){assert.ok(Number.isInteger(item.before)&&item.before>=0);assert.equal(item.after,item.before,item.case);}
          console.log(JSON.stringify({schema:'envara.listener-creator-inert-receipt/v1',counterexample:{rightsSent:20,oldRightsCapacity:16,fdCountBefore:4,fdCountAfter:8},...report}));
        }
        if(mode==='abort-proofs') {
          assert.equal(report.builderOnly,true); assert.equal(report.realRootAcceptance,false);
          for(const [key,value] of Object.entries(report)) if(key.endsWith('Refused')||key==='closeVerified'||key==='directChildrenReaped'||key==='noAdoptedReap') assert.equal(value,true,key);
          const proof=report.frame;
          const trueKeys=['originalUTunVerified','originalListenerVerified','coreReaped','frontReaped','gidScopeAbsent','filterJournalAbsent','originalUTunClosed','originalListenerClosed'];
          const falseKeys=['denyAttempted','filterWriteAttempted','launchCommandAccepted','coldStageAttempted','ready','protected'];
          assert.deepEqual(Object.keys(proof).sort(),['schema','event','stage','runId','environmentId','realmId','gid','leaseSHA256',
            'controllerPID','controllerBirth','keeperPID','keeperBirth','keeperParentPID','keeperParentBirth','corePID','coreBirth','frontPID','frontBirth',
            'leaseDevice','leaseInode','runDirectoryDevice','runDirectoryInode','utunName','utunDevice','utunInode','utunControlId','utunControlUnit',
            'listenerHost','listenerPort','listenerDevice','listenerInode',...trueKeys,...falseKeys,'exitStatus'].sort());
          assert.equal(proof.schema,'envara.macos-pf-app-transport/v1'); assert.equal(proof.event,'prestage-aborted');assert.equal(proof.stage,'factory-open');
          assert.equal(proof.exitStatus,1);assert.notEqual(proof.keeperPID,proof.corePID);
          assert.notEqual(proof.keeperPID,proof.frontPID);assert.notEqual(proof.corePID,proof.frontPID);assert.equal(proof.listenerHost,'127.0.0.1');
          for(const key of trueKeys) assert.equal(proof[key],true,key);
          for(const key of falseKeys) assert.equal(proof[key],false,key);
          for(const key of ['controllerBirth','keeperBirth','keeperParentBirth','coreBirth','frontBirth']) assert.match(proof[key],/^[1-9][0-9]*:[0-9]{6}$/);
          for(const key of ['leaseDevice','leaseInode','runDirectoryDevice','runDirectoryInode','utunDevice','utunInode','listenerDevice','listenerInode']) assert.match(proof[key],/^(0|[1-9][0-9]*)$/);
          assert.match(proof.leaseSHA256,/^[a-f0-9]{64}$/);assert.match(proof.utunName,/^utun[0-9]+$/);
          assert.equal(Object.hasOwn(proof,'childReaped'),false);assert.equal(Object.hasOwn(proof,'filterEmptyVerified'),false);
        }
        if(mode==='preflight-proofs') {
          assert.equal(report.builderOnly,true);assert.equal(report.realRootAcceptance,false);assert.equal(report.nonrootAbortPlanRefused,true);
          assert.ok(report.checks>=75);
          const proof=report.frame;
          const trueKeys=['sealedContextVerified','privateChildrenAbsent','gidScopeAbsent','filterJournalAbsent','ownedFilterClassesEmpty'];
          const falseKeys=['bootstrapAttempted','transportAttempted','filterWriteAttempted','coldStageAttempted','ready','protected'];
          assert.deepEqual(Object.keys(proof).sort(),['schema','event','stage','runId','environmentId','realmId','gid','leaseSHA256',
            'controllerPID','controllerBirth','bootstrapPID','bootstrapBirth','bootstrapParentPID','bootstrapParentBirth',
            'leaseDevice','leaseInode','runDirectoryDevice','runDirectoryInode','bootstrapDevice','bootstrapInode',
            'bootstrapParentDevice','bootstrapParentInode','proofNonce',...trueKeys,...falseKeys,'exitStatus'].sort());
          assert.equal(Object.keys(proof).length,35);assert.equal(proof.event,'preflight-aborted');assert.equal(proof.stage,'preflight');assert.equal(proof.exitStatus,1);
          assert.equal(proof.bootstrapParentPID,proof.controllerPID);assert.equal(proof.bootstrapParentBirth,proof.controllerBirth);
          assert.match(proof.proofNonce,/^[a-f0-9]{32}$/);
          for(const key of trueKeys)assert.equal(proof[key],true,key);
          for(const key of falseKeys)assert.equal(proof[key],false,key);
          for(const key of ['coreReaped','frontReaped','childReaped','originalUTunClosed','originalListenerClosed','utunName','listenerPort'])assert.equal(Object.hasOwn(proof,key),false,key);
        }
      });
      assert.deepEqual(hash(),before,'compile and tests must use one frozen source set');
    } finally { rmSync(temporary,{recursive:true,force:true}); }
  });
