import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import vm from 'node:vm';
import fs from 'node:fs';
import { mkdtemp, writeFile, readFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { createFixedInspectorStage, FIXED_INSPECTOR_STAGE_SCHEMA } from '../scripts/lib/macos-fixed-inspector-43b-stage.mjs';

const exec = promisify(execFile), native = path.resolve(import.meta.dirname, '../native/macos-pf-routing');
const parent = '/Library/PrivilegedHelperTools';
const binary = Buffer.from('closed inert signed-binary fixture\n'.repeat(1024));
const sha = createHash('sha256').update(binary).digest('hex');
const target = `${parent}/io.envara.pf-inspector-43b-${sha}`;
const stage = createFixedInspectorStage({ binary, binarySHA256: sha, rootTarget: target });

// Runs precisely the generated production --eval program. Only the fs and
// credential capabilities are substituted: filesystem calls act on OWN temp.
function confinedStage(directory, { fault, realUID = 0, effectiveUID = 0, onCreate } = {}) {
  const events = [], handles = new Map(); let stdout = '', ruid = realUID, euid = effectiveUID, gid = 20, groups = [20];
  let writes = 0;
  const translated = input => {
    if (input === '/') return directory;
    if (input === '/Library') return path.join(directory, 'Library');
    if (input === parent) return path.join(directory, 'Library/PrivilegedHelperTools');
    if (input === target) return path.join(directory, 'Library/PrivilegedHelperTools', path.basename(target));
    throw new Error('Unconfined fixture path refused.');
  };
  const metadata = stat => new Proxy(stat, { get(object, key) {
    if (key === 'uid' || key === 'gid') return 0n;
    const value = object[key]; return typeof value === 'function' ? value.bind(object) : value;
  } });
  const fixtureFS = {
    constants: fs.constants,
    realpathSync(input) { fs.realpathSync(translated(input)); return input; },
    lstatSync(input, options) { return metadata(fs.lstatSync(translated(input), options)); },
    openSync(input, flags, mode) { events.push(['open', input, flags]); const fd = fs.openSync(translated(input), flags, mode); handles.set(fd, input); if (input === target && onCreate) onCreate(); return fd; },
    fstatSync(fd, options) { const stat = fs.fstatSync(fd, options); return metadata(stat); },
    writeSync(fd, bytes, offset, count, position) {
      writes++; events.push(['write', count]);
      if (fault === 'zero-write') return 0;
      if (fault === 'partial-error' && writes === 2) throw new Error('Owned partial failure.');
      const actual = fault === 'short-writes' || fault === 'partial-error' ? Math.min(count, 17) : count;
      return fs.writeSync(fd, bytes, offset, actual, position);
    },
    fchmodSync(fd, mode) { events.push(['chmod', handles.get(fd), mode]); fs.fchmodSync(fd, mode); },
    fsyncSync(fd) { events.push(['sync', handles.get(fd)]); if (fault === 'sync-error') throw new Error(); fs.fsyncSync(fd); },
    closeSync(fd) { events.push(['close', handles.get(fd)]); fs.closeSync(fd); handles.delete(fd); },
  };
  const processMock = {
    getuid: () => ruid, geteuid: () => euid, getgid: () => gid, getegid: () => gid, getgroups: () => [...groups],
    setgroups(value) { events.push(['groups', value]); groups = [...value]; },
    setgid(value) { events.push(['gid', value]); gid = value; },
    setuid(value) { events.push(['uid', value]); if (fault !== 'uid-normalization') { ruid = value; euid = value; } },
    umask(value) { events.push(['umask', value]); return 0o077; },
    stdout: { write(value) { events.push(['ack']); stdout += value; } }, exitCode: 0,
  };
  return {
    execute(program = stage.program) {
      vm.runInNewContext(program, { Buffer, process: processMock, require(name) {
        if (name === 'node:fs') return fixtureFS;
        if (name === 'node:zlib') return requireBuiltin('node:zlib');
        if (name === 'node:crypto') return requireBuiltin('node:crypto');
        throw new Error('Unreviewed capability refused.');
      } }, { timeout: 3000 });
      assert.equal(handles.size, 0, 'Every owned fixture descriptor must close even on refusal.');
      return { value: JSON.parse(stdout), events, exitCode: processMock.exitCode };
    },
    destination: translated(target),
  };
}
import { createRequire } from 'node:module';
const requireBuiltin = createRequire(import.meta.url);
async function ownFixture() {
  assert.notEqual(process.getuid(), 0);
  const directory = await mkdtemp(path.join(tmpdir(), 'envara-wrapper-stage-inert-'));
  await mkdir(path.join(directory, 'Library/PrivilegedHelperTools'), { recursive: true, mode: 0o700 });
  return directory;
}

test('generator accepts only bounded embedded bytes and one exact hash-derived destination', () => {
  assert.equal(stage.schema, FIXED_INSPECTOR_STAGE_SCHEMA);
  for (const change of [{ binarySHA256: '0'.repeat(64) }, { binary: 'not-buffer' }, { binary: Buffer.alloc(0) },
    { rootTarget: '/tmp/arbitrary' }, { rootTarget: `${parent}/../arbitrary` }, { binarySHA256: sha.toUpperCase() }]) {
    assert.throws(() => createFixedInspectorStage({ binary, binarySHA256: sha, rootTarget: target, ...change }), /refused/);
  }
  assert.doesNotMatch(stage.program, /readFile|readSync|process\.env|process\.argv|child_process|SOURCE|eval\(/);
});

test('identical closed program fully loops short writes, durably closes before ACK and normalizes actual EUID0', async () => {
  const directory = await ownFixture();
  try {
    const fixture = confinedStage(directory, { fault: 'short-writes', realUID: 501, effectiveUID: 0 });
    const result = fixture.execute();
    assert.equal(result.value.ok, true, JSON.stringify(result.events.slice(-8)));
    assert.deepEqual(Object.keys(result.value).sort(), ['schema', 'ok', 'binarySHA256', 'binaryBytes', 'device', 'inode', 'closed'].sort());
    assert.equal(result.value.binarySHA256, sha); assert.equal(result.value.binaryBytes, binary.length);
    assert.equal(result.value.closed, true); assert.equal(result.exitCode, 0);
    assert.deepEqual(await readFile(fixture.destination), binary);
    const stat = fs.statSync(fixture.destination); assert.equal(stat.mode & 0o7777, 0o755);
    assert.equal(result.value.device, String(stat.dev)); assert.equal(result.value.inode, String(stat.ino));
    const chmod = result.events.findIndex(event => event[0] === 'chmod');
    const fileSyncAfterMode = result.events.findIndex((event, index) => index > chmod && event[0] === 'sync' && event[1] === target);
    const parentSync = result.events.findIndex((event, index) => index > fileSyncAfterMode && event[0] === 'sync' && event[1] === parent);
    const fileClose = result.events.findIndex((event, index) => index > parentSync && event[0] === 'close' && event[1] === target);
    assert.ok(chmod >= 0 && fileSyncAfterMode > chmod && parentSync > fileSyncAfterMode && fileClose > parentSync);
    assert.equal(result.events.at(-1)[0], 'ack');
    assert.equal(result.events[0][0], 'groups');
    assert.ok(result.events.findIndex(event => event[0] === 'uid') < result.events.findIndex(event => event[0] === 'open'));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('EEXIST, partial writes, bad embedded hash, decompression bound and failed credential normalization never adopt or delete', async () => {
  for (const mode of ['eexist', 'partial-error', 'zero-write', 'sync-error', 'bad-sha', 'buffer-bound', 'uid-normalization', 'ruid-only']) {
    const directory = await ownFixture();
    try {
      const fixture = confinedStage(directory, { fault: mode, realUID: mode === 'uid-normalization' ? 501 : 0, effectiveUID: mode === 'ruid-only' ? 501 : 0 });
      if (mode === 'eexist') await writeFile(fixture.destination, 'unknown preserved', { mode: 0o600 });
      let program = stage.program;
      if (mode === 'bad-sha') program = program.replace(/"gzip":"[A-Za-z0-9+/=]+"/, `"gzip":"${gzipSync(Buffer.alloc(binary.length, 7)).toString('base64')}"`);
      if (mode === 'buffer-bound') program = program.replace(`"size":${binary.length}`, '"size":1');
      const result = fixture.execute(program);
      assert.equal(result.value.ok, false, mode); assert.equal(result.exitCode, 1, mode);
      assert.deepEqual(Object.keys(result.value).sort(), ['schema', 'ok', 'reason'].sort());
      assert.equal(result.value.reason, 'FIXED_STAGE_REFUSED');
      if (mode === 'eexist') assert.equal(await readFile(fixture.destination, 'utf8'), 'unknown preserved');
      else if (['partial-error', 'zero-write', 'sync-error'].includes(mode)) {
        const data = await readFile(fixture.destination); assert.ok(data.length <= binary.length);
        const retry = confinedStage(directory).execute(); assert.equal(retry.value.ok, false, 'Partial destination must never be reopened/adopted.');
        assert.deepEqual(await readFile(fixture.destination), data);
      } else assert.equal(fs.existsSync(fixture.destination), false);
    } finally { await rm(directory, { recursive: true, force: true }); }
  }
});

test('production closed program refuses nonroot and an overlapping writer cannot adopt an in-flight destination', async () => {
  assert.notEqual(process.getuid(), 0);
  const result = await exec(process.execPath, ['--input-type=commonjs', '--no-addons', '--disable-proto=throw', '--eval', stage.program], { timeout: 5000 }).then(
    () => assert.fail('Nonroot production stage must refuse.'), error => error);
  assert.equal(result.code, 1); assert.equal(JSON.parse(result.stdout).ok, false); assert.equal(result.stderr, '');
  const directory = await ownFixture();
  try {
    const second = confinedStage(directory); let overlapping;
    const first = confinedStage(directory, { onCreate() {
      assert.equal(fs.statSync(second.destination).size, 0, 'Second writer must overlap first writer before any bytes are written.');
      overlapping = second.execute();
    } });
    const completed = first.execute();
    assert.equal(completed.value.ok, true); assert.equal(overlapping.value.ok, false);
    assert.equal(overlapping.exitCode, 1);
    assert.deepEqual(await readFile(first.destination), binary);
  } finally { await rm(directory, { recursive: true, force: true }); }
});


test('native inspector carrier strictly relays observation shapes and has only one privileged inspect argv', async () => {
  assert.notEqual(process.getuid(), 0);
  const directory = await mkdtemp(path.join(tmpdir(), 'envara-inspector-wrapper-inert-'));
  try {
    await writeFile(path.join(directory, 'inspector-app-43b-wrapper-build.h'), `#define WRAPPER_SELF ${JSON.stringify(path.join(directory, 'Wrapper'))}\n#define WRAPPER_CONSOLE_UID ${process.getuid()}\n#define WRAPPER_INSPECTOR_SHA ${JSON.stringify(sha)}\n#define WRAPPER_ROOT_TARGET ${JSON.stringify(target)}\n#define WRAPPER_STAGE_PROGRAM ${JSON.stringify(stage.program)}\n`);
    const harness = path.join(directory, 'inert.m'), executable = path.join(directory, 'inert');
    await writeFile(harness, `
#define WRAPPER_INERT 1
#include "${path.join(native, 'inspector-app-43b-wrapper.m')}"
#include <assert.h>
static unsigned calls;
static OSStatus mock(AuthorizationRef ref,const char*path,AuthorizationFlags flags,char*const*argv,FILE**pipe){(void)ref;(void)pipe;assert(flags==0&&!**_NSGetEnviron());
 if(calls==0){assert(!strcmp(path,ROOT_NODE));const char*expected[]={"--input-type=commonjs","--no-addons","--disable-proto=throw","--disable-sigusr1","--eval",WRAPPER_STAGE_PROGRAM};for(unsigned i=0;i<6;i++)assert(!strcmp(argv[i],expected[i]));assert(!argv[6]);}
 else {assert(!strcmp(path,WRAPPER_ROOT_TARGET));assert(!strcmp(argv[0],"--inspect-fixed-root"));assert(!argv[1]);}calls++;return errAuthorizationDenied;}
static NSMutableDictionary*observation(void){
 NSString*h=@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
 NSMutableDictionary*v=[@{@"schema":INSPECTION_SCHEMA,@"runId":RUN,@"environmentId":ENV,@"manifestSHA256":MF,@"sourceObservationSHA256":@"7733109a57069a8d156bf41d9540b1b1faf373dc866a37da95b0e7ea9d98433e",@"readOnly":@YES,@"ok":@YES,@"reason":@"READ_ONLY_FIXED_RUN_OBSERVED",@"gate":@"inspection-complete",@"cleanupConfirmed":@NO,@"cleanupUncertain":@YES,@"cleanupPermitted":@NO,@"ready":@NO,@"protected":@NO,@"productionReady":@NO,@"originalHostBaselineVerified":@NO,@"PFWriteExecuted":@NO,@"ownedAppOrKeeperSignalExecuted":@NO,@"runtimeChanged":@NO,@"ownedReferenceRecordedUnreleased":@YES,@"realmGID":@7101,@"gidScopeObservation":@(-1),@"lastJournalRevisionAndCountMatchActiveFilter":@NO,@"ownedTablesEmptyObserved":@YES,@"ownedTablesSHA256":h,@"ownedChildrenEmptyObserved":@YES,@"ownedChildrenSHA256":h,@"nativeHookStatusAvailable":@NO,@"stablePrivateSnapshotVerified":@YES,@"originalDescriptorCustodyVerified":@NO,@"liveGuardianFailureAccepted":@NO}mutableCopy];
 v[@"registryObservation"]=@{@"phase":@"cleanup-required",@"cleanupUncertain":@YES,@"childRecorded":@NO,@"resumed":@NO,@"transportRecorded":@YES};
 v[@"ticketStoreObservation"]=@{@"storePresent":@NO,@"ticketDirectoryPresent":@NO,@"reservedPresent":@NO,@"issuedPresent":@NO,@"claimedPresent":@NO,@"stablePrivateInventoryVerified":@YES,@"entryCount":@0,@"inventorySHA256":h,@"contentBindingsVerified":@NO};
 v[@"kernelCustodyObservation"]=@{@"firstComplete":@NO,@"secondComplete":@NO,@"metadataStable":@NO,@"keeperIdentityStable":@NO,@"uniqueCurrentCustodyObserved":@NO,@"firstQueryBytes":@0,@"firstReadBytes":@0,@"secondQueryBytes":@0,@"secondReadBytes":@0,@"firstFDCount":@0,@"secondFDCount":@0,@"firstSocketCount":@0,@"secondSocketCount":@0,@"firstListenerCount":@0,@"secondListenerCount":@0,@"firstUTunCount":@0,@"secondUTunCount":@0,@"interfaceIndex":@0,@"firstUTunObjectCount":@0,@"secondUTunObjectCount":@0,@"firstUTunDescriptorsAliasSameObject":@NO,@"secondUTunDescriptorsAliasSameObject":@NO,@"creatorCredentialVerified":@NO,@"originalDescriptorCustodyVerified":@NO};
 v[@"privateFileIdentities"]=@{@"runtimeDevice":@1,@"runtimeInode":@2,@"runDevice":@1,@"runInode":@3,@"leaseDevice":@1,@"leaseInode":@4,@"registryDevice":@1,@"registryInode":@5};
 NSMutableArray*p=[NSMutableArray array];unsigned pid=100;for(NSString*r in @[@"controller",@"keeper",@"core",@"front"])[p addObject:@{@"role":r,@"pid":@(pid++),@"recordedBirth":@"123:000001",@"state":@"absent"}];v[@"recordedProcesses"]=p;
 v[@"journal"]=@{@"present":@NO,@"eventCount":@0,@"pendingIntent":@NO,@"nativeRulesVerified":@NO};
 NSMutableArray*c=[NSMutableArray array];for(NSNumber*a in @[@0,@2,@4,@6,@8,@11])[c addObject:@{@"action":a,@"activeRuleCount":@0,@"revision":@1,@"observedRuleBytesSHA256":h,@"keepStateZeroObserved":@YES}];
 v[@"activeClasses"]=@{@"classes":c,@"inactiveQueuesVerified":@NO,@"fullRuleSemanticsVerified":@NO};v[@"stateDirectoryInventory"]=@{@"entryCount":@0,@"inventorySHA256":h};return v;
}
static void rejected(NSDictionary*v){NSDictionary*safe=sanitize(v);assert(![safe[@"ok"]boolValue]&&[safe[@"cleanupUncertain"]boolValue]&&![safe[@"cleanupPermitted"]boolValue]&&![safe[@"cleanupConfirmed"]boolValue]);assert(!safe[@"journal"]&&!safe[@"recordedProcesses"]&&!safe[@"rootCredentialObservation"]);}
int main(int argc,char**argv){@autoreleasepool{assert(argc==2&&getuid()!=0&&geteuid()!=0&&compiledInputs());
 setenv("NODE_OPTIONS","--require /must-never-read",1);setenv("DYLD_INSERT_LIBRARIES","must-never-load",1);clearOwnEnvironment();assert(!getenv("NODE_OPTIONS")&&!getenv("DYLD_INSERT_LIBRARIES"));
 FILE*p=NULL;assert(stageDecision(false,false)==COMPONENT_REQUIRED);assert(stageDecision(true,false)==EXPLICIT_INSTALL_TARGET);assert(stageDecision(false,true)==REUSE_VERIFIED_TARGET);assert(executeStage(NULL,false,&p,mock)==errAuthorizationDenied&&calls==0);assert(executeStage(NULL,true,&p,mock)==errAuthorizationDenied);assert(executeInspection(NULL,&p,mock)==errAuthorizationDenied&&calls==2);
 int own=open(argv[1],O_RDONLY|O_NOFOLLOW);assert(own>=0&&!rootFD(own,false));close(own);
 NSMutableDictionary*v=observation();NSDictionary*safe=sanitize(v);assert([safe[@"ok"]boolValue]&&![safe[@"cleanupPermitted"]boolValue]&&![safe[@"originalDescriptorCustodyVerified"]boolValue]&&![safe[@"liveGuardianFailureAccepted"]boolValue]);
 NSData*bytes=[NSJSONSerialization dataWithJSONObject:v options:NSJSONWritingWithoutEscapingSlashes error:NULL];assert([sanitize(strictJSON(bytes))[@"ok"]boolValue]);
 for(NSString*k in v){NSMutableDictionary*q=[v mutableCopy];[q removeObjectForKey:k];rejected(q);}
 for(NSString*k in @[@"cleanupPermitted",@"cleanupConfirmed",@"ready",@"protected",@"productionReady",@"originalHostBaselineVerified",@"PFWriteExecuted",@"ownedAppOrKeeperSignalExecuted",@"runtimeChanged",@"originalDescriptorCustodyVerified",@"liveGuardianFailureAccepted"]){NSMutableDictionary*q=[v mutableCopy];q[k]=@YES;rejected(q);q[k]=@0;rejected(q);}
 for(id value in @[@YES,@4294967296LL,@(-4294967296LL),@0.5,@"0",NSNull.null]){NSMutableDictionary*q=[v mutableCopy];q[@"gidScopeObservation"]=value;rejected(q);}
 for(NSNumber*n in @[@(-1),@0,@1]){NSMutableDictionary*q=[v mutableCopy];q[@"gidScopeObservation"]=n;assert([sanitize(q)[@"ok"]boolValue]);}
 for(NSString*k in @[@"schema",@"runId",@"environmentId",@"manifestSHA256",@"sourceObservationSHA256",@"gate",@"reason"]){NSMutableDictionary*q=[v mutableCopy];q[k]=@"private-secret";rejected(q);}
 NSMutableDictionary*q=[v mutableCopy];q[@"unknownTicket"]=@"private-secret";rejected(q);
 for(NSString*k in @[@"journal",@"activeClasses",@"privateFileIdentities",@"stateDirectoryInventory",@"registryObservation",@"ticketStoreObservation",@"kernelCustodyObservation"]){q=[v mutableCopy];NSMutableDictionary*r=[v[k]mutableCopy];r[@"unknownToken"]=@"private-secret";q[k]=r;rejected(q);q[k]=@[];rejected(q);}
 for(NSString*k in @[@"registryObservation",@"ticketStoreObservation",@"kernelCustodyObservation"]){
  NSDictionary*o=v[k];for(NSString*f in o){q=[v mutableCopy];NSMutableDictionary*b=[o mutableCopy];[b removeObjectForKey:f];q[k]=b;rejected(q);}
 }
 for(NSString*k in @[@"registryObservation",@"ticketStoreObservation",@"kernelCustodyObservation"]){
  for(NSString*f in v[k])if(boolean(v[k][f])){q=[v mutableCopy];NSMutableDictionary*b=[v[k]mutableCopy];b[f]=@0;q[k]=b;rejected(q);}
 }
 q=[v mutableCopy];NSMutableDictionary*b=[v[@"registryObservation"]mutableCopy];b[@"phase"]=@"private-secret";q[@"registryObservation"]=b;rejected(q);
 for(NSString*f in @[@"contentBindingsVerified"]){q=[v mutableCopy];b=[v[@"ticketStoreObservation"]mutableCopy];b[f]=@YES;q[@"ticketStoreObservation"]=b;rejected(q);}
 for(NSString*f in @[@"creatorCredentialVerified",@"originalDescriptorCustodyVerified"]){q=[v mutableCopy];b=[v[@"kernelCustodyObservation"]mutableCopy];b[f]=@YES;q[@"kernelCustodyObservation"]=b;rejected(q);}
 for(NSString*f in @[@"firstQueryBytes",@"firstReadBytes",@"secondQueryBytes",@"secondReadBytes"]){q=[v mutableCopy];b=[v[@"kernelCustodyObservation"]mutableCopy];b[f]=@65537;q[@"kernelCustodyObservation"]=b;rejected(q);}
 for(NSString*f in @[@"firstFDCount",@"secondFDCount",@"firstSocketCount",@"secondSocketCount",@"firstListenerCount",@"secondListenerCount",@"firstUTunCount",@"secondUTunCount",@"firstUTunObjectCount",@"secondUTunObjectCount"]){q=[v mutableCopy];b=[v[@"kernelCustodyObservation"]mutableCopy];b[f]=@8193;q[@"kernelCustodyObservation"]=b;rejected(q);}
 q=[v mutableCopy];NSMutableArray*processes=[v[@"recordedProcesses"]mutableCopy];NSMutableDictionary*process=[processes[0]mutableCopy];process[@"path"]=@"private-secret";processes[0]=process;q[@"recordedProcesses"]=processes;rejected(q);
 q=[v mutableCopy];q[@"nativeHookStatusAvailable"]=@YES;q[@"nativeRootStatus"]=@{@"ok":@NO,@"reason":@"OWNED_RUN_LEDGER_UNVERIFIED",@"pfDisabled":@NO,@"hookInstalled":@NO,@"ownedRootHookVerified":@NO,@"namespaceState":@"unknown",@"runLedgerState":@"unknown",@"receiptRetired":@NO,@"originalRootCompatible":@NO,@"originalRootSHA256":@"",@"originalRootTextSHA256":@""};assert([sanitize(q)[@"ok"]boolValue]);NSMutableDictionary*status=[q[@"nativeRootStatus"]mutableCopy];status[@"ticket"]=@"private-secret";q[@"nativeRootStatus"]=status;rejected(q);
 NSMutableDictionary*progress=[v mutableCopy];progress[@"ok"]=@NO;progress[@"gate"]=@"recorded-processes";progress[@"reason"]=@"INSPECTION_UNCONFIRMED";
 for(unsigned n=2;n<=3;n++){progress[@"recordedProcesses"]=[v[@"recordedProcesses"]subarrayWithRange:NSMakeRange(0,n)];assert([sanitize(progress)[@"recordedProcesses"]count]==n);}
 progress[@"recordedProcesses"]=[v[@"recordedProcesses"]subarrayWithRange:NSMakeRange(0,1)];rejected(progress);
 progress[@"recordedProcesses"]=v[@"recordedProcesses"];
 NSDictionary*zombie=@{@"state":@"exact-recorded-zombie",@"exitStatusAvailable":@YES,@"exitCode":@1,@"signal":@0,@"causeVerified":@NO};progress[@"zombieFrontObservation"]=zombie;assert([sanitize(progress)[@"zombieFrontObservation"]isEqual:zombie]);
 for(NSString*k in zombie){q=[progress mutableCopy];b=[zombie mutableCopy];[b removeObjectForKey:k];q[@"zombieFrontObservation"]=b;rejected(q);}
 for(NSString*k in @[@"exitStatusAvailable",@"causeVerified"]){q=[progress mutableCopy];b=[zombie mutableCopy];b[k]=@0;q[@"zombieFrontObservation"]=b;rejected(q);}
 for(NSDictionary*z in @[@{@"state":@"exact-recorded-zombie",@"exitStatusAvailable":@NO,@"exitCode":@(-1),@"signal":@(-1),@"causeVerified":@NO},@{@"state":@"exact-recorded-zombie",@"exitStatusAvailable":@YES,@"exitCode":@(-1),@"signal":@9,@"causeVerified":@NO}]){progress[@"zombieFrontObservation"]=z;assert([sanitize(progress)[@"zombieFrontObservation"]isEqual:z]);}
 for(NSDictionary*z in @[@{@"state":@"exact-recorded-zombie",@"exitStatusAvailable":@NO,@"exitCode":@0,@"signal":@0,@"causeVerified":@NO},@{@"state":@"exact-recorded-zombie",@"exitStatusAvailable":@YES,@"exitCode":@1,@"signal":@9,@"causeVerified":@NO},@{@"state":@"exact-recorded-zombie",@"exitStatusAvailable":@YES,@"exitCode":@(-1),@"signal":@128,@"causeVerified":@NO},@{@"state":@"exact-recorded-zombie",@"exitStatusAvailable":@YES,@"exitCode":@256,@"signal":@0,@"causeVerified":@NO},@{@"state":@"exact-recorded-zombie",@"exitStatusAvailable":@YES,@"exitCode":@1,@"signal":@0,@"causeVerified":@YES}]){progress[@"zombieFrontObservation"]=z;rejected(progress);}
 NSMutableDictionary*partial=[@{@"schema":INSPECTION_SCHEMA,@"runId":RUN,@"environmentId":ENV,@"manifestSHA256":MF,@"sourceObservationSHA256":v[@"sourceObservationSHA256"],@"readOnly":@YES,@"ok":@NO,@"reason":@"INSPECTION_UNCONFIRMED",@"gate":@"root-credentials",@"cleanupConfirmed":@NO,@"cleanupUncertain":@YES,@"cleanupPermitted":@NO,@"ready":@NO,@"protected":@NO,@"productionReady":@NO,@"originalHostBaselineVerified":@NO,@"PFWriteExecuted":@NO,@"ownedAppOrKeeperSignalExecuted":@NO,@"runtimeChanged":@NO}mutableCopy];assert([sanitize(partial)[@"reason"]isEqual:@"INSPECTION_UNCONFIRMED"]&&[sanitize(partial)[@"gate"]isEqual:@"root-credentials"]);
 NSMutableDictionary*credential=[@{@"stage":@"kernel-groups",@"errno":@22,@"realUID":@0,@"effectiveUID":@0,@"realGID":@0,@"effectiveGID":@0,@"groupCount":@(-1)}mutableCopy];partial[@"rootCredentialObservation"]=credential;
 for(NSString*step in @[@"effective-root",@"setgroups",@"setgid",@"setuid",@"kernel-groups",@"identity-check",@"group-check",@"child-wait-boundary"]){credential[@"stage"]=step;NSDictionary*received=sanitize(partial);assert([received[@"rootCredentialObservation"]isEqual:credential]&&![received[@"ok"]boolValue]&&![received[@"cleanupPermitted"]boolValue]);}
 credential[@"stage"]=@"kernel-groups";NSData*diagnosticBytes=[NSJSONSerialization dataWithJSONObject:partial options:NSJSONWritingWithoutEscapingSlashes error:NULL];assert([sanitize(strictJSON(diagnosticBytes))[@"rootCredentialObservation"]isEqual:credential]);
 for(NSString*k in credential){NSMutableDictionary*bad=[credential mutableCopy];[bad removeObjectForKey:k];q=[partial mutableCopy];q[@"rootCredentialObservation"]=bad;rejected(q);}
 for(NSString*k in @[@"errno",@"realUID",@"effectiveUID",@"realGID",@"effectiveGID",@"groupCount"]){for(id invalid in @[@YES,@0.5,@"0",NSNull.null]){NSMutableDictionary*bad=[credential mutableCopy];bad[k]=invalid;q=[partial mutableCopy];q[@"rootCredentialObservation"]=bad;rejected(q);}}
 for(NSNumber*count in @[@(-1),@0,@1,@16]){credential[@"groupCount"]=count;assert(sanitize(partial)[@"rootCredentialObservation"]);}credential[@"groupCount"]=@(-1);
 for(NSNumber*count in @[@(-2),@17,@4294967296LL]){NSMutableDictionary*bad=[credential mutableCopy];bad[@"groupCount"]=count;q=[partial mutableCopy];q[@"rootCredentialObservation"]=bad;rejected(q);}
 for(NSString*k in @[@"errno",@"realUID",@"effectiveUID",@"realGID",@"effectiveGID"]){for(NSNumber*invalid in @[@(-1),@4294967296LL]){NSMutableDictionary*bad=[credential mutableCopy];bad[k]=invalid;q=[partial mutableCopy];q[@"rootCredentialObservation"]=bad;rejected(q);}}
 NSMutableDictionary*bad=[credential mutableCopy];bad[@"errno"]=@1025;q=[partial mutableCopy];q[@"rootCredentialObservation"]=bad;rejected(q);bad=[credential mutableCopy];bad[@"stage"]=@"private-secret";q[@"rootCredentialObservation"]=bad;rejected(q);
 for(NSString*k in @[@"groups",@"path",@"environment",@"token"]){bad=[credential mutableCopy];bad[k]=@"private-secret";q=[partial mutableCopy];q[@"rootCredentialObservation"]=bad;rejected(q);}
 q=[partial mutableCopy];q[@"gate"]=@"installed-inventory";rejected(q);q=[v mutableCopy];q[@"rootCredentialObservation"]=credential;rejected(q);
 assert(!strictJSON([@"{\\"ok\\":true,\\"ok\\":false}"dataUsingEncoding:NSUTF8StringEncoding]));assert(!strictJSON([@"{\\"\\\\u006fk\\":true}"dataUsingEncoding:NSUTF8StringEncoding]));assert(!strictJSON([@"{} {}"dataUsingEncoding:NSUTF8StringEncoding]));assert(!strictJSON([NSMutableData dataWithLength:REPLY_LIMIT+1]));
 NSData*cd=[NSData dataWithBytes:"01234567890123456789"length:20];NSDictionary*d=@{(__bridge NSString*)kSecCodeInfoFlags:@(kSecCodeSignatureRuntime),(__bridge NSString*)kSecCodeInfoUnique:cd};assert(hardenedSigningPolicy(d,d));NSMutableDictionary*policy=[d mutableCopy];policy[(__bridge NSString*)kSecCodeInfoEntitlementsDict]=@{@"com.apple.security.cs.allow-dyld-environment-variables":@YES};assert(!hardenedSigningPolicy(policy,d));
 puts("inert fixed inspector wrapper checks passed");return 0;}}
`);
    const flags = ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I', directory];
    await exec('/usr/bin/clang', [...flags, harness, '-framework', 'Foundation', '-framework', 'Security', '-o', executable], { timeout: 30000 });
    const owned = path.join(directory, 'owned'); await writeFile(owned, 'own inert', { mode: 0o755 });
    assert.equal((await exec(executable, [owned], { timeout: 15000 })).stdout, 'inert fixed inspector wrapper checks passed\n');
    const wrapper = path.join(directory, 'Wrapper');
    await exec('/usr/bin/clang', [...flags, path.join(native, 'inspector-app-43b-wrapper.m'), '-framework', 'Foundation', '-framework', 'Security', '-o', wrapper], { timeout: 30000 });
    await exec('/usr/bin/codesign', ['--force', '--options', 'runtime', '--sign', '-', wrapper], { timeout: 15000 });
    await exec('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', wrapper], { timeout: 15000 });
    const plan = JSON.parse((await exec(wrapper, ['--plan'], { timeout: 5000 })).stdout);
    assert.equal(plan.ok, true); assert.equal(plan.reason, 'INERT_PLAN'); assert.equal(plan.localHardenedSelfVerified, true);
    for (const k of ['authorizationRequested', 'cleanupConfirmed', 'cleanupPermitted', 'ready', 'protected', 'productionReady', 'rootStageAttempted', 'rootStageCompleted', 'bootstrapRootTargetBound', 'originalDescriptorCustodyVerified', 'liveGuardianFailureAccepted']) assert.equal(plan[k], false);
    for (const mode of ['--request-cleanup', '--cleanup-fixed-root', '--foreign']) {
      const refusal = await exec(wrapper, [mode], { timeout: 5000 }).then(() => assert.fail('Unknown/cleanup entry must refuse.'), error => error);
      assert.equal(refusal.code, 1); assert.equal(JSON.parse(refusal.stdout).reason, 'INVALID_FIXED_OPERATION'); assert.equal(JSON.parse(refusal.stdout).authorizationRequested, false);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('actual inspector writer with present journal and six classes survives the strict carrier while integer booleans refuse', async () => {
  assert.notEqual(process.getuid(), 0);
  const directory = await mkdtemp(path.join(tmpdir(), 'envara-inspector-writer-reader-'));
  try {
    const producer = path.join(directory, 'producer'), consumer = path.join(directory, 'consumer');
    const inspectorSource = await readFile(path.join(native, 'inspector-app-43b-run6c6.m'), 'utf8');
    const registryWriter = 'out[@"registryObservation"]=registryObservation(record,@{});';
    const producerSource = String.raw`
#define _DARWIN_C_SOURCE
#import <Foundation/Foundation.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <libproc.h>
#include <stdarg.h>
#include <assert.h>
#include "@ABI@"
/* Only fixture-created inodes and the current fixture PID are mapped. The
 * actual readJournal, six-class formatter, identity reader and JSON writer run;
 * no privileged path, kernel ioctl or other process is observed. */
static struct {dev_t dev;ino_t ino;uid_t uid;gid_t gid;} tracked[16];static unsigned trackedCount;
static int fixturePF=-1,openedPF=-1,fixtureRoot=-1;static struct stat pfIdentity;
static void track(int fd){struct stat s;assert(!fstat(fd,&s)&&s.st_uid==getuid());assert(trackedCount<16);tracked[trackedCount].dev=s.st_dev;tracked[trackedCount].ino=s.st_ino;tracked[trackedCount].uid=s.st_uid;tracked[trackedCount++].gid=s.st_gid;}
static void map(struct stat*s){for(unsigned i=0;i<trackedCount;i++)if(s->st_dev==tracked[i].dev&&s->st_ino==tracked[i].ino&&s->st_uid==tracked[i].uid&&s->st_gid==tracked[i].gid){s->st_uid=0;s->st_gid=0;return;}}
static int ownFstat(int fd,struct stat*s){int e=fstat(fd,s);if(!e){if(fd==openedPF){*s=pfIdentity;s->st_mode=S_IFCHR|0600;s->st_uid=0;s->st_gid=0;}else map(s);}return e;}
static int ownFstatat(int fd,const char*n,struct stat*s,int flags){int e=fstatat(fd,n,s,flags);if(!e)map(s);return e;}
static int ownLstat(const char*p,struct stat*s){if(!strcmp(p,"/dev/pf")){*s=pfIdentity;s->st_mode=S_IFCHR|0600;s->st_uid=0;s->st_gid=0;return 0;}return lstat(p,s);}
static int ownOpen(const char*p,int flags,...){if(!strcmp(p,"/")){assert(fixtureRoot>=0&&!(flags&O_CREAT));return dup(fixtureRoot);}if(!strcmp(p,"/dev/pf")){assert(fixturePF>=0&&!(flags&O_CREAT));openedPF=dup(fixturePF);return openedPF;}mode_t mode=0;if(flags&O_CREAT){va_list a;va_start(a,flags);mode=(mode_t)va_arg(a,int);va_end(a);}return open(p,flags,mode);}
static int ownIoctl(int fd,unsigned long request,...){assert(fd==openedPF);va_list args;va_start(args,request);EnvaraPFHookRequest*q=va_arg(args,EnvaraPFHookRequest*);va_end(args);assert(q&&q->rule.action<=11);
 if(request==ENVARA_PF_HOOK_GET_RULES){q->nr=q->rule.action==0?5:0;q->ticket=42;return 0;}
 assert(request==ENVARA_PF_HOOK_GET_RULE&&q->rule.action==0&&q->nr<5&&q->ticket==42);q->rule.keep_state=0;return 0;}
static int ownProcInfo(int pid,int flavor,uint64_t arg,void*buffer,int size){assert(flavor==PROC_PIDTBSDINFO);if(pid==INT32_MAX||pid==INT32_MAX-1){errno=ESRCH;return 0;}assert(pid==getpid());int n=proc_pidinfo(pid,flavor,arg,buffer,size);if(n==sizeof(struct proc_bsdinfo)){struct proc_bsdinfo*p=buffer;p->pbi_uid=p->pbi_ruid=p->pbi_svuid=0;p->pbi_gid=p->pbi_rgid=p->pbi_svgid=0;}return n;}
#define fstat ownFstat
#define fstatat ownFstatat
#define lstat ownLstat
#define open ownOpen
#define ioctl ownIoctl
#define proc_pidinfo ownProcInfo
#define INSPECTOR_INERT 1
#include "@SOURCE@"
#undef fstat
#undef fstatat
#undef lstat
#undef open
#undef ioctl
#undef proc_pidinfo
static void put(int fd,const char*name,NSDictionary*v){NSData*d=[NSJSONSerialization dataWithJSONObject:v options:0 error:NULL];assert(d);int f=openat(fd,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);assert(f>=0&&!fchmod(f,0600));assert(write(f,d.bytes,d.length)==(ssize_t)d.length);track(f);assert(!close(f));}
int main(int argc,char**argv){@autoreleasepool{
 assert(argc==3&&getuid()!=0&&geteuid()!=0);int run=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW);assert(run>=0&&!fchmod(run,0700));track(run);
 fixtureRoot=run;assert(!mkdirat(run,"Library",0700));int library=openat(run,"Library",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);assert(library>=0);track(library);assert(!mkdirat(library,"PrivilegedHelperTools",0700));int helpers=openat(library,"PrivilegedHelperTools",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);assert(helpers>=0);track(helpers);close(helpers);close(library);
 assert(!mkdirat(run,"app-filter-events",0700));int journal=openat(run,"app-filter-events",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);assert(journal>=0);track(journal);
 NSDictionary*lease=@{@"leaseId":@"73e9d9b3-6b9c-435b-8f64-8305e5a60859",@"generation":@"5145eb2d-79e5-4e0a-a98e-5fe389b6fdf9"};NSNumber*keeper=@(getpid());
 put(journal,"000.intent",@{@"schema":@"envara.macos-pf-app-filter-event/v1",@"runId":CANARY_RUN,@"leaseId":lease[@"leaseId"],@"generation":lease[@"generation"],@"sequence":@0,@"previous":@0,@"next":@3,@"writerPid":keeper});
 put(journal,"000.receipt",@{@"schema":@"envara.macos-pf-app-filter-receipt/v1",@"runId":CANARY_RUN,@"leaseId":lease[@"leaseId"],@"generation":lease[@"generation"],@"sequence":@0,@"mode":@3,@"writerPid":keeper,@"revision":@42,@"ruleCount":@5});close(journal);
 fixturePF=openat(run,"fixture-pf",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW,0600);assert(fixturePF>=0&&!fstat(fixturePF,&pfIdentity));
 assert(!mkdirat(run,"state",0700));int state=openat(run,"state",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);assert(state>=0);track(state);
 NSMutableDictionary*out=inspectionOutcome();out[@"ownedReferenceRecordedUnreleased"]=@YES;out[@"realmGID"]=@7101;
 struct stat s;assert(!fstat(run,&s));out[@"privateFileIdentities"]=@{@"runtimeDevice":@(s.st_dev),@"runtimeInode":@(s.st_ino),@"runDevice":@(s.st_dev),@"runInode":@(s.st_ino),@"leaseDevice":@(s.st_dev),@"leaseInode":@(s.st_ino),@"registryDevice":@(s.st_dev),@"registryInode":@(s.st_ino)};
 struct proc_bsdinfo self;assert(proc_pidinfo(getpid(),PROC_PIDTBSDINFO,1,&self,sizeof(self))==sizeof(self));NSString*birth=[NSString stringWithFormat:@"%llu:%06llu",self.pbi_start_tvsec,self.pbi_start_tvusec];char image[PROC_PIDPATHINFO_MAXSIZE];assert(proc_pidpath(getpid(),image,sizeof(image))>0);
 NSMutableArray*processes=[NSMutableArray array];for(NSString*role in @[@"controller",@"keeper"]){NSDictionary*p=processObservation(role,keeper,birth,image,0);assert(p);[processes addObject:p];}
 for(unsigned i=0;i<2;i++){NSDictionary*p=processObservation(i?@"front":@"core",@(INT32_MAX-(int)i),birth,image,0);assert(p);[processes addObject:p];}out[@"recordedProcesses"]=processes;
 NSDictionary*record=@{@"phase":@"cleanup-required",@"cleanupUncertain":@YES,@"application":@{@"child":!strcmp(argv[2],"source-only")?NSNull.null:@{@"pid":keeper,@"birth":birth},@"resumed":@((BOOL)(strcmp(argv[2],"source-only")!=0)),@"ticketId":@"c732f7ba-9112-463b-b7a8-c22dcff82e4a"}};
 @REGISTRY_WRITER@
 out[@"ticketStoreObservation"]=ticketStoreObservation(record);assert(out[@"ticketStoreObservation"]);
 NSDictionary*t=@{@"keeperPID":keeper,@"keeperBirth":birth,@"interfaceName":@"utun999999"};
 out[@"kernelCustodyObservation"]=kernelCustodyObservation(@{@"controllerPid":@0},t,7101);assert(out[@"kernelCustodyObservation"]);
 int scope=0;out[@"gidScopeObservation"]=@(scope);NSDictionary*j=readJournal(run,lease,keeper);assert(j);out[@"journal"]=j;
 NSDictionary*classes=activeClassObservation();assert(classes);out[@"activeClasses"]=classes;out[@"lastJournalRevisionAndCountMatchActiveFilter"]=@(journalMatchesActiveFilter(j,classes));
 formatOwnedNamespaceObservation(out,false,@"\n");formatOwnedNamespaceObservation(out,true,@" ");
 NSDictionary*proof=@{@"ok":@NO,@"reason":@"OWNED_RUN_LEDGER_UNVERIFIED",@"pfDisabled":@NO,@"hookInstalled":@NO,@"ownedRootHookVerified":@NO,@"namespaceState":@"unknown",@"runLedgerState":@"unknown",@"receiptRetired":@NO,@"originalRootCompatible":@NO,@"originalRootSHA256":@"",@"originalRootTextSHA256":@""};
 formatNativeHookObservation(out,!strcmp(argv[2],"unavailable")?nil:proof);
 out[@"stablePrivateSnapshotVerified"]=@YES;out[@"originalDescriptorCustodyVerified"]=@NO;out[@"liveGuardianFailureAccepted"]=@NO;out[@"stateDirectoryInventory"]=directorySnapshot(state);assert(out[@"stateDirectoryInventory"]);
 out[@"gate"]=@"inspection-complete";out[@"ok"]=@YES;out[@"reason"]=@"READ_ONLY_FIXED_RUN_OBSERVED";
 if(!strcmp(argv[2],"partial")){out[@"gate"]=@"owned-tables-and-children";out[@"ok"]=@NO;out[@"reason"]=@"INSPECTION_UNCONFIRMED";}
 if(!strncmp(argv[2],"zombie-",7)){
  struct proc_bsdinfo a={0};a.pbi_pid=(uint32_t)getpid();a.pbi_ppid=(uint32_t)getppid();a.pbi_status=SZOMB;a.pbi_start_tvsec=self.pbi_start_tvsec;a.pbi_start_tvusec=self.pbi_start_tvusec;a.pbi_xstatus=!strcmp(argv[2],"zombie-unknown")?65536:256;struct proc_bsdinfo b=a;
  NSDictionary*z=zombieFrontFromBSD(&a,&b,getpid(),birth,getppid());assert(z);out[@"zombieFrontObservation"]=z;
  out[@"recordedProcesses"]=[processes subarrayWithRange:NSMakeRange(0,!strcmp(argv[2],"zombie-partial2")?2:3)];out[@"ok"]=@NO;out[@"gate"]=@"recorded-processes";out[@"reason"]=@"INSPECTION_UNCONFIRMED";
  for(NSString*k in @[@"ownedTablesEmptyObserved",@"ownedTablesSHA256",@"ownedChildrenEmptyObserved",@"ownedChildrenSHA256",@"nativeHookStatusAvailable",@"nativeRootStatus",@"stablePrivateSnapshotVerified",@"originalDescriptorCustodyVerified",@"liveGuardianFailureAccepted",@"stateDirectoryInventory"])[out removeObjectForKey:k];
 }
 if(!strcmp(argv[2],"source-only")){
  struct proc_bsdinfo a={0};a.pbi_pid=SOURCE_KEEPER_PID;a.pbi_ppid=SOURCE_CONTROLLER_PID;a.pbi_status=SRUN;a.pbi_start_tvsec=self.pbi_start_tvsec;a.pbi_start_tvusec=self.pbi_start_tvusec;struct proc_bsdinfo b=a;
  NSDictionary*current=sourceKeeperFromBSD(&a,&b,NATIVE);assert(current);
  out[@"sourceObservedKeeperObservation"]=current;out[@"registryObservation"]=registryObservation(record,nil);
  out[@"recordedProcesses"]=[processes subarrayWithRange:NSMakeRange(0,1)];out[@"ok"]=@NO;out[@"gate"]=@"transport-not-recorded";out[@"reason"]=@"INSPECTION_UNCONFIRMED";
  for(NSString*k in @[@"kernelCustodyObservation",@"ownedTablesEmptyObserved",@"ownedTablesSHA256",@"ownedChildrenEmptyObserved",@"ownedChildrenSHA256",@"nativeHookStatusAvailable",@"nativeRootStatus",@"originalDescriptorCustodyVerified",@"liveGuardianFailureAccepted",@"stateDirectoryInventory"])[out removeObjectForKey:k];
 }
 if(!strcmp(argv[2],"legacy-tables"))out[@"ownedTablesEmptyObserved"]=@1;
 if(!strcmp(argv[2],"legacy-children"))out[@"ownedChildrenEmptyObserved"]=@1;
 if(!strcmp(argv[2],"legacy-hook"))out[@"nativeHookStatusAvailable"]=@1;
 close(state);close(fixturePF);close(run);return emitInspection(out);
}}
`.replace('@REGISTRY_WRITER@', registryWriter).replace('@ABI@', path.join(native, 'pf-hook-abi.h')).replace('@SOURCE@', path.join(native, 'inspector-app-43b-run6c6.m'));
    await writeFile(path.join(directory, 'producer.m'), producerSource);
    await writeFile(path.join(directory, 'inspector-app-43b-wrapper-build.h'), `#define WRAPPER_SELF ${JSON.stringify(consumer)}\n#define WRAPPER_CONSOLE_UID ${process.getuid()}\n#define WRAPPER_INSPECTOR_SHA ${JSON.stringify(sha)}\n#define WRAPPER_ROOT_TARGET ${JSON.stringify(target)}\n#define WRAPPER_STAGE_PROGRAM ${JSON.stringify(stage.program)}\n`);
    await writeFile(path.join(directory, 'consumer.m'), `#define WRAPPER_INERT 1\n#include "${path.join(native, 'inspector-app-43b-wrapper.m')}"\n#include <assert.h>\nint main(int argc,char**argv){@autoreleasepool{assert(argc==2&&getuid()!=0&&geteuid()!=0);return emit(sanitize(strictJSON([NSData dataWithContentsOfFile:@(argv[1])])));}}\n`);
    const flags = ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I', directory];
    await exec('/usr/bin/clang', [...flags, path.join(directory, 'producer.m'), path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', producer], { timeout: 30000 });
    await exec('/usr/bin/clang', [...flags, path.join(directory, 'consumer.m'), '-framework', 'Foundation', '-framework', 'Security', '-o', consumer], { timeout: 30000 });
    for (const mode of ['available', 'unavailable', 'partial', 'legacy-tables', 'legacy-children', 'legacy-hook', 'zombie-partial2', 'zombie-partial3', 'zombie-unknown', 'source-only']) {
      const ownRun = path.join(directory, mode); await mkdir(ownRun, { mode: 0o700 });
      const writer = await exec(producer, [ownRun, mode], { timeout: 10000 }).catch(error => error);
      assert.ok(writer.stdout, `Actual producer failed before output: ${writer.stderr || writer.message}`);
      const input = JSON.parse(writer.stdout); assert.ok(Buffer.byteLength(writer.stdout) < 32768);
      assert.equal(input.registryObservation.phase, 'cleanup-required');
      assert.equal(input.registryObservation.childRecorded, mode !== 'source-only');
      assert.equal(input.registryObservation.resumed, mode !== 'source-only');
      assert.equal(input.ticketStoreObservation.contentBindingsVerified, false);
      if (mode !== 'source-only') { assert.equal(input.kernelCustodyObservation.creatorCredentialVerified, false);
      assert.equal(input.kernelCustodyObservation.originalDescriptorCustodyVerified, false); }
      assert.equal(input.journal.present, true); assert.equal(input.journal.eventCount, 2);
      assert.equal(input.activeClasses.classes.length, 6); assert.equal(input.lastJournalRevisionAndCountMatchActiveFilter, true);
      const fixture = path.join(directory, `${mode}.json`); await writeFile(fixture, writer.stdout, { flag: 'wx', mode: 0o600 });
      const read = await exec(consumer, [fixture], { timeout: 10000 }).catch(error => error); const output = JSON.parse(read.stdout);
      if (mode.startsWith('legacy-')) {
        assert.equal(output.reason, 'PRIVATE_INSPECTION_UNCONFIRMED'); assert.equal(output.ok, false); assert.equal(output.gate, undefined);
      } else {
        for (const [key, value] of Object.entries(input)) if (key !== 'schema') assert.deepEqual(output[key], value, `${mode}:${key}`);
        assert.equal(output.reason, mode === 'partial' || mode === 'source-only' || mode.startsWith('zombie-') ? 'INSPECTION_UNCONFIRMED' : 'READ_ONLY_FIXED_RUN_OBSERVED');
        assert.equal(output.ok, mode !== 'partial' && mode !== 'source-only' && !mode.startsWith('zombie-'));
        if (mode !== 'source-only' && !mode.startsWith('zombie-')) for (const key of ['ownedTablesEmptyObserved', 'ownedChildrenEmptyObserved', 'nativeHookStatusAvailable']) assert.equal(typeof output[key], 'boolean', key);
        else if (mode.startsWith('zombie-')) { assert.equal(output.zombieFrontObservation.causeVerified, false); assert.equal(output.recordedProcesses.length, mode === 'zombie-partial2' ? 2 : 3); }
        else { assert.equal(output.sourceObservedKeeperObservation.historicalBirthBindingVerified, false); assert.equal(output.registryObservation.transportRecorded, false); assert.equal(output.recordedProcesses.length, 1); }
      }
      for (const key of ['cleanupPermitted', 'cleanupConfirmed', 'ready', 'protected', 'productionReady', 'PFWriteExecuted', 'ownedAppOrKeeperSignalExecuted', 'runtimeChanged']) assert.equal(output[key], false, `${mode}:${key}`);
      if (mode === 'source-only') {
        const invalid = [];
        for (const key of Object.keys(input.sourceObservedKeeperObservation)) {
          const value = structuredClone(input); delete value.sourceObservedKeeperObservation[key]; invalid.push(value);
        }
        for (const [key, value] of [['historicalBirthBindingVerified', true], ['historicalBirthBindingVerified', 0], ['pid', 88326], ['pid', true], ['parentPid', 88254], ['uid', 1], ['gid', 1], ['observedBirth', 'unknown'], ['state', 'live-exact-recorded-identity'], ['unknownToken', 'fixture-only']]) {
          const changed = structuredClone(input); changed.sourceObservedKeeperObservation[key] = value; invalid.push(changed);
        }
        const recorded = structuredClone(input); recorded.registryObservation.transportRecorded = true; invalid.push(recorded);
        const promoted = structuredClone(input); promoted.ok = true; promoted.reason = 'READ_ONLY_FIXED_RUN_OBSERVED'; promoted.gate = 'inspection-complete'; invalid.push(promoted);
        const missingBinding = structuredClone(input); delete missingBinding.registryObservation; invalid.push(missingBinding);
        for (const [index, value] of invalid.entries()) {
          const changedPath = path.join(directory, `source-only-refusal-${index}.json`);
          await writeFile(changedPath, JSON.stringify(value), { flag: 'wx', mode: 0o600 });
          const refused = await exec(consumer, [changedPath], { timeout: 10000 }).catch(error => error);
          const safe = JSON.parse(refused.stdout);
          assert.equal(safe.reason, 'PRIVATE_INSPECTION_UNCONFIRMED');
          assert.equal(safe.sourceObservedKeeperObservation, undefined);
          assert.equal(safe.cleanupPermitted, false); assert.equal(safe.cleanupConfirmed, false); assert.equal(safe.ready, false);
        }
      }

    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
