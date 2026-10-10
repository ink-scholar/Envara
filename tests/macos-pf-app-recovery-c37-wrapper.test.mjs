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
import { createFixedRecoveryStage, FIXED_RECOVERY_STAGE_SCHEMA } from '../scripts/lib/macos-fixed-recovery-c37-stage.mjs';

const exec = promisify(execFile), native = path.resolve(import.meta.dirname, '../native/macos-pf-routing');
const parent = '/Library/PrivilegedHelperTools';
const binary = Buffer.from('closed inert signed-binary fixture\n'.repeat(1024));
const sha = createHash('sha256').update(binary).digest('hex');
const target = `${parent}/io.envara.pf-recovery-c37-${sha}`;
const stage = createFixedRecoveryStage({ binary, binarySHA256: sha, rootTarget: target });

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
  assert.equal(stage.schema, FIXED_RECOVERY_STAGE_SCHEMA);
  for (const change of [{ binarySHA256: '0'.repeat(64) }, { binary: 'not-buffer' }, { binary: Buffer.alloc(0) },
    { rootTarget: '/tmp/arbitrary' }, { rootTarget: `${parent}/../arbitrary` }, { binarySHA256: sha.toUpperCase() }]) {
    assert.throws(() => createFixedRecoveryStage({ binary, binarySHA256: sha, rootTarget: target, ...change }), /refused/);
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

test('native strict relay, hardened policy, root-owner refusal and fixed authorization argv use inert callbacks only', async () => {
  assert.notEqual(process.getuid(), 0);
  const directory = await mkdtemp(path.join(tmpdir(), 'envara-wrapper-native-inert-'));
  try {
    const header = path.join(directory, 'recovery-app-c37-wrapper-build.h');
    await writeFile(header, `#define WRAPPER_SELF ${JSON.stringify(path.join(directory, 'Wrapper'))}\n#define WRAPPER_CONSOLE_UID ${process.getuid()}\n#define WRAPPER_RECOVERY_SHA ${JSON.stringify(sha)}\n#define WRAPPER_ROOT_TARGET ${JSON.stringify(target)}\n#define WRAPPER_STAGE_PROGRAM ${JSON.stringify(stage.program)}\n`);
    const harness = path.join(directory, 'inert.m'), executable = path.join(directory, 'inert');
    await writeFile(harness, `
#define WRAPPER_INERT 1
#include "${path.join(native, 'recovery-app-c37-wrapper.m')}"
#include <assert.h>
static unsigned calls=0;
static OSStatus mock(AuthorizationRef ref,const char*path,AuthorizationFlags flags,char*const*argv,FILE**pipe){(void)ref;(void)pipe;assert(flags==0&&!**_NSGetEnviron());
 if(calls==0){assert(!strcmp(path,ROOT_NODE));const char*expected[]={"--input-type=commonjs","--no-addons","--disable-proto=throw","--disable-sigusr1","--eval",WRAPPER_STAGE_PROGRAM,NULL};for(unsigned i=0;i<6;i++)assert(!strcmp(argv[i],expected[i]));assert(!argv[6]);}
 else {assert(!strcmp(path,WRAPPER_ROOT_TARGET));assert(!strcmp(argv[0],calls==1?"--inspect-fixed-root":"--cleanup-fixed-root"));assert(!argv[1]);}calls++;return errAuthorizationDenied;}
static NSMutableDictionary*completion(bool cleanup){NSMutableDictionary*v=[@{@"schema":RECOVERY_SCHEMA,@"runId":RUN,@"environmentId":ENV,@"manifestSHA256":MF,@"ready":@NO,@"protected":@NO,@"productionReady":@NO,@"readOnly":@((BOOL)!cleanup),@"ok":@YES,@"cleanupUncertain":@((BOOL)!cleanup),@"rootHookRemoved":@((BOOL)cleanup),@"namespaceReclaimed":@((BOOL)cleanup),@"receiptRetired":@((BOOL)cleanup),@"ownedPFReferenceReleased":@((BOOL)cleanup),@"ownedGroupRemoved":@((BOOL)cleanup),@"runtimeArchived":@((BOOL)cleanup),@"cleanupConfirmed":@((BOOL)cleanup),@"originalHostBaselineVerified":@NO,@"interactiveAuthorizationAllowed":@NO,@"bootstrapIdentityBound":@NO,@"reason":cleanup?@"EXACT_RECOVERY_COMPLETED":@"READ_ONLY_PREFLIGHT_VERIFIED",@"preflightVerified":@YES,@"ownedGIDScopeAbsent":@YES,@"ownedFilterEmpty":@YES,@"rootRuntimeComponentsAbsent":@YES}mutableCopy];if(cleanup){v[@"deleteAttempted"]=@YES;v[@"recoveryHostNetworkUnchanged"]=@YES;}return v;}
int main(int argc,char**argv){@autoreleasepool{assert(argc==2&&getuid()!=0&&geteuid()!=0);assert(compiledInputs());
 setenv("NODE_OPTIONS","--require /inert-never-read",1);setenv("DYLD_INSERT_LIBRARIES","inert-never-load",1);clearOwnEnvironment();assert(!getenv("NODE_OPTIONS")&&!getenv("DYLD_INSERT_LIBRARIES"));
 FILE*p=NULL;assert(stageDecision(false,false,false)==COMPONENT_REQUIRED);assert(stageDecision(true,false,false)==COMPONENT_REQUIRED);assert(stageDecision(true,true,false)==COMPONENT_REQUIRED);assert(stageDecision(false,true,false)==EXPLICIT_INSTALL_TARGET);assert(stageDecision(false,false,true)==REUSE_VERIFIED_TARGET);
 assert(executeStage(NULL,false,&p,mock)==errAuthorizationDenied&&calls==0);assert(executeStage(NULL,true,&p,mock)==errAuthorizationDenied);assert(executeRecovery(NULL,false,&p,mock)==errAuthorizationDenied);assert(executeRecovery(NULL,true,&p,mock)==errAuthorizationDenied);assert(calls==3);
 int own=open(argv[1],O_RDONLY|O_NOFOLLOW);assert(own>=0&&!rootFD(own,false));close(own);
 NSData*cd=[NSData dataWithBytes:"01234567890123456789" length:20];NSDictionary*d=@{(__bridge NSString*)kSecCodeInfoFlags:@(kSecCodeSignatureRuntime),(__bridge NSString*)kSecCodeInfoUnique:cd};assert(hardenedSigningPolicy(d,d));
 for(id flags in @[@0,@YES,@(kSecCodeSignatureAdhoc)]){NSMutableDictionary*x=[d mutableCopy];x[(__bridge NSString*)kSecCodeInfoFlags]=flags;assert(!hardenedSigningPolicy(x,d));assert(!hardenedSigningPolicy(d,x));}
 for(NSString*k in @[@"com.apple.security.cs.allow-dyld-environment-variables",@"com.apple.security.cs.disable-library-validation",@"com.apple.security.get-task-allow"]){NSMutableDictionary*x=[d mutableCopy];x[(__bridge NSString*)kSecCodeInfoEntitlementsDict]=@{k:@YES};assert(!hardenedSigningPolicy(x,d));assert(!hardenedSigningPolicy(d,x));}
 NSMutableDictionary*x=[d mutableCopy];x[(__bridge NSString*)kSecCodeInfoUnique]=[NSData dataWithBytes:"different01234567890" length:20];assert(!hardenedSigningPolicy(d,x));
 assert(!strictJSON([@"{\\"ok\\":true,\\"ok\\":false}"dataUsingEncoding:NSUTF8StringEncoding]));assert(!strictJSON([@"{\\"\\\\u006fk\\":true}"dataUsingEncoding:NSUTF8StringEncoding]));
 assert(!strictJSON([@"{} {}"dataUsingEncoding:NSUTF8StringEncoding]));assert(!strictJSON([NSMutableData dataWithLength:REPLY_LIMIT+1]));
 for(int cleanup=0;cleanup<2;cleanup++){NSMutableDictionary*v=completion(cleanup);assert([sanitize(v,cleanup)[@"ok"]boolValue]);assert([sanitize(v,cleanup)[@"cleanupConfirmed"]boolValue]==(bool)cleanup);
  for(NSString*gate in @[@"not-started",@"rights",@"root-credentials",@"root-parent",@"installed-inventory",@"private-runtime",@"registry-lock",@"registry-shape",@"run-directory",@"lease-shape",@"scope-and-empty-filter",@"state-directory",@"empty-state-shape",@"filter-journal-absent",@"controller-gone",@"gid-scope-absent",@"components-absent",@"pf-empty",@"dedicated-group",@"root-hook-readback",@"preflight-complete",@"component-capacity",@"component-lease",@"component-memory",@"component-list-first",@"component-list-second",@"component-inventory-change",@"component-bsd-before",@"component-path-read",@"component-owned-runtime-live",@"component-notion-groups",@"component-bsd-after",@"component-identity-change",@"component-baseline-change",@"component-deadline"]){NSMutableDictionary*q=[v mutableCopy];q[@"preflightGate"]=gate;NSDictionary*clean=sanitize(q,cleanup);assert([clean[@"ok"]boolValue]&&[clean[@"preflightGate"]isEqual:gate]);assert([clean[@"cleanupConfirmed"]boolValue]==(bool)cleanup);}
  for(id gate in @[@"unknown-secret",@YES,@1,NSNull.null,@[],@{}]){NSMutableDictionary*q=[v mutableCopy];q[@"preflightGate"]=gate;NSDictionary*clean=sanitize(q,cleanup);assert(![clean[@"ok"]boolValue]&&[clean[@"reason"]isEqual:@"PRIVATE_COMPLETION_UNCONFIRMED"]&&!clean[@"preflightGate"]);assert([clean[@"cleanupUncertain"]boolValue]&&![clean[@"cleanupConfirmed"]boolValue]);}
  for(NSNumber*pid in @[@0,@2,@INT32_MAX]){NSMutableDictionary*q=[v mutableCopy];q[@"componentPid"]=pid;NSDictionary*clean=sanitize(q,cleanup);assert([clean[@"ok"]boolValue]&&[clean[@"componentPid"]isEqual:pid]);assert([clean[@"cleanupConfirmed"]boolValue]==(bool)cleanup);}
  for(id pid in @[@YES,@(-1),@(INT32_MAX+1LL),@0.5,@(INFINITY),@(NAN),@"123",NSNull.null,@[],@{}]){NSMutableDictionary*q=[v mutableCopy];q[@"componentPid"]=pid;NSDictionary*clean=sanitize(q,cleanup);assert(![clean[@"ok"]boolValue]&&[clean[@"reason"]isEqual:@"PRIVATE_COMPLETION_UNCONFIRMED"]&&!clean[@"componentPid"]);assert([clean[@"cleanupUncertain"]boolValue]&&![clean[@"cleanupConfirmed"]boolValue]);}
  for(NSString*k in @[@"schema",@"runId",@"environmentId",@"manifestSHA256",@"reason"]){NSMutableDictionary*q=[v mutableCopy];q[k]=@"foreign";assert(![sanitize(q,cleanup)[@"ok"]boolValue]);}
  NSMutableDictionary*q=[v mutableCopy];q[@"unknownSecret"]=@"must-not-relay";assert(![sanitize(q,cleanup)[@"ok"]boolValue]);
  for(NSString*k in v)if(boolean(v[k])){q=[v mutableCopy];q[k]=@1;assert(![sanitize(q,cleanup)[@"ok"]boolValue]);}
  q=[v mutableCopy];q[@"ready"]=@YES;assert(![sanitize(q,cleanup)[@"ok"]boolValue]);q=[v mutableCopy];q[@"originalHostBaselineVerified"]=@YES;assert(![sanitize(q,cleanup)[@"ok"]boolValue]);
  if(cleanup){q=[v mutableCopy];q[@"ok"]=@NO;q[@"cleanupConfirmed"]=@NO;q[@"cleanupUncertain"]=@NO;q[@"reason"]=@"CLEANUP_UNCONFIRMED";assert([sanitize(q,true)[@"reason"]isEqual:@"PRIVATE_COMPLETION_UNCONFIRMED"]);assert([sanitize(q,true)[@"cleanupUncertain"]boolValue]);}
 }
 NSMutableDictionary*refused=completion(false);refused[@"ok"]=@NO;refused[@"reason"]=@"RECOVERY_PREFLIGHT_REFUSED";refused[@"preflightGate"]=@"component-path-read";refused[@"componentPid"]=@123;NSDictionary*diagnostic=sanitize(refused,false);assert([diagnostic[@"reason"]isEqual:@"RECOVERY_PREFLIGHT_REFUSED"]&&[diagnostic[@"preflightGate"]isEqual:@"component-path-read"]&&[diagnostic[@"componentPid"]isEqual:@123]);assert(![diagnostic[@"ok"]boolValue]&&[diagnostic[@"cleanupUncertain"]boolValue]&&![diagnostic[@"cleanupConfirmed"]boolValue]);
 struct stat st={.st_size=123,.st_dev=1,.st_ino=2};NSMutableDictionary*a=[@{@"schema":STAGE_SCHEMA,@"ok":@YES,@"binarySHA256":@WRAPPER_RECOVERY_SHA,@"binaryBytes":@123,@"device":@"1",@"inode":@"2",@"closed":@YES}mutableCopy];assert(stageAck(a,&st));
 for(NSString*k in a){NSMutableDictionary*q=[a mutableCopy];q[k]=NSNull.null;assert(!stageAck(q,&st));}a[@"binaryBytes"]=@YES;assert(!stageAck(a,&st));a[@"binaryBytes"]=@123;a[@"extra"]=@YES;assert(!stageAck(a,&st));
 puts("inert wrapper strict relay/signing/argv checks passed");return 0;}}
`);
    const flags = ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I', directory];
    await exec('/usr/bin/clang', [...flags, harness, '-framework', 'Foundation', '-framework', 'Security', '-o', executable], { timeout: 30000 });
    const owned = path.join(directory, 'owned'); await writeFile(owned, 'owned inert file', { mode: 0o755 });
    const result = await exec(executable, [owned], { timeout: 15000 });
    assert.equal(result.stdout, 'inert wrapper strict relay/signing/argv checks passed\n'); assert.equal(result.stderr, '');
    const wrapper = path.join(directory, 'Wrapper');
    await exec('/usr/bin/clang', [...flags, path.join(native, 'recovery-app-c37-wrapper.m'), '-framework', 'Foundation', '-framework', 'Security', '-o', wrapper], { timeout: 30000 });
    await exec('/usr/bin/codesign', ['--force', '--options', 'runtime', '--sign', '-', wrapper], { timeout: 15000 });
    await exec('/usr/bin/codesign', ['--verify', '--strict', wrapper], { timeout: 15000 });
    const plan = JSON.parse((await exec(wrapper, ['--plan'], { timeout: 5000 })).stdout);
    assert.equal(plan.reason, 'INERT_PLAN'); assert.equal(plan.readOnly, true); assert.equal(plan.userPresenceRequired, true);
    assert.equal(plan.closedStageProgramAvailable, true); assert.equal(plan.rootTargetVerified, false);
    assert.equal(plan.localHardenedSelfVerified, true, 'Actual dynamic/static hardened self policy must verify after inert signing.');
    for (const key of ['authorizationRequested', 'cleanupConfirmed', 'ready', 'protected', 'productionReady', 'rootStageAttempted', 'rootStageCompleted', 'bootstrapRootTargetBound']) assert.equal(plan[key], false);
    assert.equal(plan.overallReadOnly, true); assert.equal(plan.recoveryReadOnly, true);
    assert.equal(plan.cleanupUncertain, true);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
