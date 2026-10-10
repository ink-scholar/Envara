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
import { createFixedPrivateContextDiagnosticStage, FIXED_PRIVATE_CONTEXT_DIAGNOSTIC_STAGE_SCHEMA } from '../scripts/lib/macos-fixed-private-context-05d6-run877-stage.mjs';

const exec = promisify(execFile), native = path.resolve(import.meta.dirname, '../native/macos-pf-routing');
const parent = '/Library/PrivilegedHelperTools';
const binary = Buffer.from('closed inert signed-binary fixture\n'.repeat(1024));
const sha = createHash('sha256').update(binary).digest('hex');
const target = `${parent}/io.envara.pf-private-context-05d6-run877-${sha}`;
const stage = createFixedPrivateContextDiagnosticStage({ binary, binarySHA256: sha, rootTarget: target });

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
  assert.equal(stage.schema, FIXED_PRIVATE_CONTEXT_DIAGNOSTIC_STAGE_SCHEMA);
  for (const change of [{ binarySHA256: '0'.repeat(64) }, { binary: 'not-buffer' }, { binary: Buffer.alloc(0) },
    { rootTarget: '/tmp/arbitrary' }, { rootTarget: `${parent}/../arbitrary` }, { binarySHA256: sha.toUpperCase() }]) {
    assert.throws(() => createFixedPrivateContextDiagnosticStage({ binary, binarySHA256: sha, rootTarget: target, ...change }), /refused/);
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




async function fixtureHeader(directory, self) {
  await writeFile(path.join(directory, 'inspector-app-05d6-run877-private-context-wrapper-build.h'),
    `#define WRAPPER_SELF ${JSON.stringify(self)}\n#define WRAPPER_CONSOLE_UID ${process.getuid()}\n#define WRAPPER_RECOVERY_SHA ${JSON.stringify(sha)}\n#define WRAPPER_RECOVERY_BYTES ${binary.length}\n#define WRAPPER_ROOT_TARGET ${JSON.stringify(target)}\n#define WRAPPER_STAGE_PROGRAM ${JSON.stringify(stage.program)}\n`);
}
const objcFlags = ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function'];

// The actual immutable diagnostic writer and strict carrier reader run in
// separate owned images. No privileged inspection or Authorization is called.
test('actual pcdOutcome writer retains every diagnostic gate and genuine BOOL through the strict 51-field consumer', async () => {
  assert.notEqual(process.getuid(), 0);
  const directory = await mkdtemp(path.join(tmpdir(), 'envara-run877-private-context-writer-reader-'));
  try {
    const producer = path.join(directory, 'producer'), consumer = path.join(directory, 'consumer');
    await fixtureHeader(directory, consumer);
    await writeFile(path.join(directory, 'producer.m'), String.raw`
#define PRIVATE_CONTEXT_DIAG_INERT 1
#include "@SOURCE@"
#include <assert.h>
int main(int argc,char**argv){@autoreleasepool{
 assert(argc==2&&getuid()!=0&&geteuid()!=0);NSMutableDictionary*out=pcdOutcome();out[@"gate"]=@(argv[1]);assert(out.count==51);
 for(NSString*k in out)if(![out[k]isKindOfClass:NSString.class])assert(CFGetTypeID((__bridge CFTypeRef)out[k])==CFBooleanGetTypeID());
 return emitInspection(out);
}}
`.replace('@SOURCE@', path.join(native, 'inspector-app-05d6-run877-private-context-diag-v2-20261009.m')));
    await writeFile(path.join(directory, 'consumer.m'), String.raw`
#define WRAPPER_INERT 1
#include "@SOURCE@"
#include <assert.h>
static void refuse(NSDictionary*input){NSDictionary*out=sanitize(input);assert([out[@"reason"]isEqual:@"PRIVATE_CONTEXT_DIAGNOSTIC_UNCONFIRMED"]&&!out[@"gate"]&&![out[@"ok"]boolValue]&&![out[@"cleanupConfirmed"]boolValue]&&[out[@"cleanupUncertain"]boolValue]&&![out[@"cleanupPermitted"]boolValue]);}
int main(int argc,char**argv){@autoreleasepool{
 assert(argc==2&&getuid()!=0&&geteuid()!=0);NSDictionary*input=strictJSON([NSData dataWithContentsOfFile:@(argv[1])]);assert(input&&input.count==51);NSDictionary*out=sanitize(input);assert([out[@"reason"]isEqual:@"FIXED_LIVE_RECOVERY_PREFLIGHT_REFUSED"]);
 for(NSString*k in input){if(![k isEqual:@"schema"])assert([out[k]isEqual:input[k]]);NSMutableDictionary*q=[input mutableCopy];[q removeObjectForKey:k];refuse(q);if(boolean(input[k])){q=[input mutableCopy];q[k]=@([input[k]boolValue]?1:0);refuse(q);q=[input mutableCopy];q[k]=@((BOOL)![input[k]boolValue]);refuse(q);}}
 for(NSString*k in @[@"schema",@"manifestSHA256",@"runId",@"environmentId",@"reason",@"gate"]){NSMutableDictionary*q=[input mutableCopy];q[k]=@"unknown";refuse(q);q[k]=@YES;refuse(q);}
 for(NSString*k in @[@"path",@"token",@"credentials",@"inventory",@"privateContextDiagnostic"]){NSMutableDictionary*q=[input mutableCopy];q[k]=@"never-forward";refuse(q);}
 NSMutableDictionary*q=[input mutableCopy];q[@"ok"]=@YES;q[@"reason"]=@"READ_ONLY_LIVE_RECOVERY_PREFLIGHT_VERIFIED";q[@"gate"]=@"preflight-complete";refuse(q);
 assert(!strictJSON([@"{\"ok\":true,\"ok\":false}"dataUsingEncoding:NSUTF8StringEncoding]));assert(!strictJSON([@"{\"\\u006fk\":true}"dataUsingEncoding:NSUTF8StringEncoding]));assert(!strictJSON([@"{} {}"dataUsingEncoding:NSUTF8StringEncoding]));assert(!strictJSON([NSMutableData dataWithLength:REPLY_LIMIT+1]));return emit(out);
}}
`.replace('@SOURCE@', path.join(native, 'inspector-app-05d6-run877-private-context-wrapper.m')));
    await exec('/usr/bin/clang', [...objcFlags, '-I', directory, path.join(directory, 'producer.m'), path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', producer], { timeout: 30000 });
    await exec('/usr/bin/clang', [...objcFlags, '-I', directory, path.join(directory, 'consumer.m'), '-framework', 'Foundation', '-framework', 'Security', '-o', consumer], { timeout: 30000 });
    const gates = ['not-started', 'root-credentials', 'private-lock-three-keys', 'private-live-shape', 'private-state-unknown-entry-refused', 'private-context-empty-state-observed', 'private-context-cache-db-only-stable', 'private-context-transport-config-only-stable', 'private-context-transport-config-and-cache-stable'];
    for (const gate of gates) {
      const writer = await exec(producer, [gate], { timeout: 10000 }).catch(error => error);
      assert.equal(writer.code, 1); const input = JSON.parse(writer.stdout); assert.equal(Object.keys(input).length, 51);
      const file = path.join(directory, `${gate}.json`); await writeFile(file, writer.stdout, { flag: 'wx', mode: 0o600 });
      const read = await exec(consumer, [file], { timeout: 10000 }).catch(error => error);
      assert.equal(read.code, 1); const output = JSON.parse(read.stdout);
      for (const [key, value] of Object.entries(input)) if (key !== 'schema') assert.deepEqual(output[key], value);
      assert.equal(output.cleanupPermitted, false); assert.equal(output.ready, false); assert.equal(output.protected, false);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('the sole fixed inspect argv stays read-only and real hardened plan never exposes cleanup or implicit staging', async () => {
  assert.notEqual(process.getuid(), 0);
  const directory = await mkdtemp(path.join(tmpdir(), 'envara-run877-private-context-wrapper-inert-'));
  try {
    const wrapper = path.join(directory, 'Wrapper'), harness = path.join(directory, 'inert.m'), executable = path.join(directory, 'inert');
    await fixtureHeader(directory, wrapper);
    await writeFile(harness, String.raw`
#define WRAPPER_INERT 1
#include "@SOURCE@"
#include <assert.h>
static unsigned calls;
static OSStatus mock(AuthorizationRef ref,const char*path,AuthorizationFlags flags,char*const*argv,FILE**pipe){(void)ref;(void)pipe;assert(flags==0&&!**_NSGetEnviron());
 if(!calls){assert(!strcmp(path,ROOT_NODE));const char*expected[]={"--input-type=commonjs","--no-addons","--disable-proto=throw","--disable-sigusr1","--eval",WRAPPER_STAGE_PROGRAM};for(unsigned i=0;i<6;i++)assert(!strcmp(argv[i],expected[i]));assert(!argv[6]);}
 else{assert(!strcmp(path,WRAPPER_ROOT_TARGET)&&!strcmp(argv[0],"--inspect-fixed-root")&&!argv[1]);}calls++;return errAuthorizationDenied;}
int main(int argc,char**argv){@autoreleasepool{
 assert(argc==2&&getuid()!=0&&geteuid()!=0&&compiledInputs());setenv("NODE_OPTIONS","--require /never-read",1);setenv("DYLD_INSERT_LIBRARIES","never-load",1);clearOwnEnvironment();assert(!getenv("NODE_OPTIONS")&&!getenv("DYLD_INSERT_LIBRARIES"));
 assert(stageDecision(false,false)==COMPONENT_REQUIRED&&stageDecision(true,false)==EXPLICIT_INSTALL_TARGET&&stageDecision(false,true)==REUSE_VERIFIED_TARGET);
 FILE*p=NULL;assert(executeStage(NULL,false,&p,mock)==errAuthorizationDenied&&!calls);assert(executeStage(NULL,true,&p,mock)==errAuthorizationDenied&&calls==1);assert(executeInspection(NULL,&p,mock)==errAuthorizationDenied&&calls==2);
 int own=open(argv[1],O_RDONLY|O_NOFOLLOW);assert(own>=0&&!rootFD(own,false));close(own);
 struct stat identity={.st_size=WRAPPER_RECOVERY_BYTES,.st_dev=1,.st_ino=2};NSMutableDictionary*ack=[@{@"schema":STAGE_SCHEMA,@"ok":@YES,@"binarySHA256":@WRAPPER_RECOVERY_SHA,@"binaryBytes":@(WRAPPER_RECOVERY_BYTES),@"device":@"1",@"inode":@"2",@"closed":@YES}mutableCopy];assert(stageAck(ack,&identity));ack[@"closed"]=@1;assert(!stageAck(ack,&identity));ack[@"closed"]=@YES;ack[@"token"]=@"unknown";assert(!stageAck(ack,&identity));puts("inert fixed private context wrapper checks passed");return 0;
}}
`.replace('@SOURCE@', path.join(native, 'inspector-app-05d6-run877-private-context-wrapper.m')));
    await exec('/usr/bin/clang', [...objcFlags, '-I', directory, harness, '-framework', 'Foundation', '-framework', 'Security', '-o', executable], { timeout: 30000 });
    const owned = path.join(directory, 'owned'); await writeFile(owned, 'owned inert bytes', { mode: 0o755 });
    assert.equal((await exec(executable, [owned], { timeout: 10000 })).stdout, 'inert fixed private context wrapper checks passed\n');
    await exec('/usr/bin/clang', [...objcFlags, '-I', directory, path.join(native, 'inspector-app-05d6-run877-private-context-wrapper.m'), '-framework', 'Foundation', '-framework', 'Security', '-o', wrapper], { timeout: 30000 });
    await exec('/usr/bin/codesign', ['--force', '--options', 'runtime', '--sign', '-', wrapper], { timeout: 15000 });
    await exec('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', wrapper], { timeout: 15000 });
    const plan = JSON.parse((await exec(wrapper, ['--plan'], { timeout: 5000 })).stdout);
    assert.equal(plan.ok, true); assert.equal(plan.reason, 'INERT_PLAN'); assert.equal(plan.localHardenedSelfVerified, true);
    for (const key of ['authorizationRequested', 'cleanupConfirmed', 'cleanupPermitted', 'rootStageAttempted', 'rootStageCompleted', 'bootstrapRootTargetBound', 'originalApplicationHostBaselineVerified', 'originalDescriptorCustodyVerified', 'fullGuardFailureAccepted', 'ready', 'protected', 'productionReady']) assert.equal(plan[key], false, key);
    for (const mode of ['--cleanup-fixed-root', '--request-cleanup', '--foreign']) {
      const refusal = await exec(wrapper, [mode], { timeout: 5000 }).catch(error => error);
      assert.equal(refusal.code, 1); assert.equal(JSON.parse(refusal.stdout).reason, 'INVALID_FIXED_OPERATION'); assert.equal(JSON.parse(refusal.stdout).authorizationRequested, false);
    }
    const source = await readFile(path.join(native, 'inspector-app-05d6-run877-private-context-wrapper.m'), 'utf8');
    assert.doesNotMatch(source, /--cleanup-fixed-root|--request-cleanup/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
