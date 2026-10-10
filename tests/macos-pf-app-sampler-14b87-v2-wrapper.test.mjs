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
import { createFixedSamplerStage, FIXED_SAMPLER_STAGE_SCHEMA } from '../scripts/lib/macos-fixed-sampler-14b87-v2-stage.mjs';

const exec = promisify(execFile), native = path.resolve(import.meta.dirname, '../native/macos-pf-routing');
const parent = '/Library/PrivilegedHelperTools';
const binary = Buffer.from('closed inert signed-binary fixture\n'.repeat(1024));
const sha = createHash('sha256').update(binary).digest('hex');
const target = `${parent}/io.envara.pf-sampler-14b87-v2-${sha}`;
const stage = createFixedSamplerStage({ binary, binarySHA256: sha, rootTarget: target });

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
  assert.equal(stage.schema, FIXED_SAMPLER_STAGE_SCHEMA);
  for (const change of [{ binarySHA256: '0'.repeat(64) }, { binary: 'not-buffer' }, { binary: Buffer.alloc(0) },
    { rootTarget: '/tmp/arbitrary' }, { rootTarget: `${parent}/../arbitrary` }, { binarySHA256: sha.toUpperCase() }]) {
    assert.throws(() => createFixedSamplerStage({ binary, binarySHA256: sha, rootTarget: target, ...change }), /refused/);
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



test('actual fixed sampler writer survives strict projection; raw, foreign, missing and false proof inputs refuse', async () => {
  assert.notEqual(process.getuid(), 0);
  const directory = await mkdtemp(path.join(tmpdir(), 'envara-sampler-writer-reader-'));
  try {
    const producer = path.join(directory, 'producer'), consumer = path.join(directory, 'consumer');
    await writeFile(path.join(directory, 'sampler-app-14b87-v2-wrapper-build.h'), `#define WRAPPER_SELF ${JSON.stringify(consumer)}\n#define WRAPPER_CONSOLE_UID ${process.getuid()}\n#define WRAPPER_SAMPLER_SHA ${JSON.stringify(sha)}\n#define WRAPPER_ROOT_TARGET ${JSON.stringify(target)}\n#define WRAPPER_STAGE_PROGRAM ${JSON.stringify(stage.program)}\n`);
    await writeFile(path.join(directory, 'producer.m'), `#define SAMPLER_INERT 1
#include "${path.join(native, 'sampler-app-14b87-run5be-v2.m')}"
#include <assert.h>
int main(int argc,char**argv){@autoreleasepool{assert(argc==2&&getuid()!=0&&geteuid()!=0);NSMutableDictionary*v=samplingOutcome();
 NSMutableString*report=[NSMutableString stringWithString:@"Process: envara-pf-native [48779]\\nPath: /Library/PrivilegedHelperTools/io.envara.pf-routing/envara-pf-native\\n"];
 for(NSString*name in samplingSymbols())[report appendFormat:@"+ 2 %@ (in envara-pf-native) [0xabcdef]\\n",name];
 [report appendString:@"+ 7 fixture-private-function (in fixture-private-module) [0x123456]\\n"];
 if(!strcmp(argv[1],"wildcard"))[report replaceOccurrencesOfString:@"/Library/PrivilegedHelperTools/io.envara.pf-routing/envara-pf-native" withString:@"/Library/*/envara-pf-native" options:0 range:NSMakeRange(0,report.length)];
 v[@"samplingToolExitedSuccessfully"]=@YES;assert(formatSafeSampleReport(v,[report dataUsingEncoding:NSUTF8StringEncoding]));v[@"beforeIdentityVerified"]=@YES;v[@"afterIdentityVerified"]=@YES;
 v[@"stablePrivateSnapshotVerified"]=@YES;v[@"ok"]=@YES;v[@"reason"]=@"EXACT_FIXED_KEEPER_SAMPLED";v[@"gate"]=@"sampling-complete";
 if(!strcmp(argv[1],"early")){v=samplingOutcome();v[@"gate"]=@"private-bindings";}
 if(!strcmp(argv[1],"partial")){v[@"ok"]=@NO;v[@"reason"]=@"SAMPLING_UNCONFIRMED";v[@"gate"]=@"stable-private-snapshot";v[@"stablePrivateSnapshotVerified"]=@NO;}
 return emitInspection(v);}}
`);
    await writeFile(path.join(directory, 'consumer.m'), `#define WRAPPER_INERT 1
#include "${path.join(native, 'sampler-app-14b87-v2-wrapper.m')}"
#include <assert.h>
static OSStatus mock(AuthorizationRef ref,const char*file,AuthorizationFlags flags,char*const*args,FILE**p){(void)ref;(void)flags;(void)p;assert(!strcmp(file,WRAPPER_ROOT_TARGET));assert(args&&!strcmp(args[0],"--sample-fixed-root")&&!args[1]);return errAuthorizationDenied;}
int main(int argc,char**argv){@autoreleasepool{assert(argc==2&&getuid()!=0&&geteuid()!=0);FILE*p=NULL;assert(executeSample(NULL,&p,mock)==errAuthorizationDenied);
 return emit(sanitize(strictJSON([NSData dataWithContentsOfFile:@(argv[1])])));}}
`);
    const flags = ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I', directory];
    await exec('/usr/bin/clang', [...flags, path.join(directory, 'producer.m'), path.join(native, 'app-scope-proof.c'), '-framework', 'Foundation', '-framework', 'Security', '-o', producer], { timeout: 30000 });
    await exec('/usr/bin/clang', [...flags, path.join(directory, 'consumer.m'), '-framework', 'Foundation', '-framework', 'Security', '-o', consumer], { timeout: 30000 });
    let complete;
    for (const mode of ['complete', 'early', 'partial', 'wildcard']) {
      const produced = await exec(producer, [mode], { timeout: 10000 }).catch(error => error);
      const input = JSON.parse(produced.stdout); assert.equal(Object.keys(input).length, 39);
      const fixture = path.join(directory, `${mode}.json`); await writeFile(fixture, produced.stdout, { flag: 'wx', mode: 0o600 });
      const received = await exec(consumer, [fixture], { timeout: 10000 }).catch(error => error); const output = JSON.parse(received.stdout);
      for (const [key, value] of Object.entries(input)) if (key !== 'schema') assert.deepEqual(output[key], value, `${mode}:${key}`);
      assert.doesNotMatch(received.stdout, /fixture-private|0xabcdef|0x123456|PrivilegedHelperTools|stdin|argv/);
      for (const key of ['cleanupConfirmed', 'cleanupPermitted', 'ready', 'protected', 'productionReady', 'PFWriteExecuted', 'runtimeChanged', 'ownedAppOrKeeperSignalExecuted', 'rawReportExposed', 'rawReportRetained']) assert.equal(output[key], false);
      if (mode === 'wildcard') { assert.equal(input.reportPathExactlyMatched, false); assert.equal(output.ok, true); }
      if (mode === 'complete') { complete = input; assert.equal(input.symbols.length, 35); assert.equal(input.stackFrameCount, 36); assert.equal(input.unrecognizedFrameCount, 1); }
    }
    const invalid = [];
    for (const key of Object.keys(complete)) { const value = structuredClone(complete); delete value[key]; invalid.push(value); }
    for (const key of Object.keys(complete).filter(key => typeof complete[key] === 'boolean')) { const value = structuredClone(complete); value[key] = Number(value[key]); invalid.push(value); }
    for (const [key, value] of [['keeperPID', 48780], ['controllerPID', 48708], ['keeperBirth', '1:000001'], ['controllerBirth', '1:000001'], ['gate', 'unknown'], ['reason', 'unknown'], ['rawReportExposed', true], ['rawReportRetained', true], ['ready', true], ['stablePrivateSnapshotVerified', false], ['samplingToolExitedSuccessfully', false], ['reportProcessPIDMatched', false], ['reportFrameFormatObserved', false], ['sampleBytes', 131073], ['stackFrameCount', 65537], ['unrecognizedFrameCount', 65537], ['sampleDurationSeconds', 2], ['samplingIntervalMilliseconds', 2], ['unknownRawReport', 'fixture-private']]) {
      const changed = structuredClone(complete); changed[key] = value; invalid.push(changed);
    }
    for (const [key, value] of [['name', 'fixture-private'], ['occurrences', 0], ['occurrences', true], ['occurrences', 65537], ['reportedWeight', true], ['reportedWeight', 4294967296], ['unknownAddress', '0x123456']]) {
      const changed = structuredClone(complete); changed.symbols[0][key] = value; invalid.push(changed);
    }
    const duplicate = structuredClone(complete); duplicate.symbols[1] = duplicate.symbols[0]; invalid.push(duplicate);
    for (const [index, input] of invalid.entries()) {
      const fixture = path.join(directory, `refusal-${index}.json`); await writeFile(fixture, JSON.stringify(input), { flag: 'wx', mode: 0o600 });
      const received = await exec(consumer, [fixture], { timeout: 10000 }).catch(error => error); const output = JSON.parse(received.stdout);
      assert.equal(output.reason, 'PRIVATE_SAMPLE_UNCONFIRMED'); assert.equal(output.symbols, undefined); assert.equal(output.gate, undefined);
      assert.equal(output.ok, false); assert.equal(output.cleanupConfirmed, false); assert.equal(output.ready, false);
    }
    const wrapper = path.join(directory, 'Wrapper');
    const header = path.join(directory, 'sampler-app-14b87-v2-wrapper-build.h');
    await writeFile(header, (await readFile(header, 'utf8')).replace(`#define WRAPPER_SELF ${JSON.stringify(consumer)}`, `#define WRAPPER_SELF ${JSON.stringify(wrapper)}`));
    await exec('/usr/bin/clang', [...flags, path.join(native, 'sampler-app-14b87-v2-wrapper.m'), '-framework', 'Foundation', '-framework', 'Security', '-o', wrapper], { timeout: 30000 });
    await exec('/usr/bin/codesign', ['--force', '--options', 'runtime', '--sign', '-', wrapper], { timeout: 15000 });
    await exec('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', wrapper], { timeout: 15000 });
    const plan = JSON.parse((await exec(wrapper, ['--plan'], { timeout: 5000 })).stdout);
    assert.equal(plan.ok, true); assert.equal(plan.reason, 'INERT_PLAN'); assert.equal(plan.localHardenedSelfVerified, true);
    assert.equal(plan.authorizationRequested, false); assert.equal(plan.rootStageAttempted, false); assert.equal(plan.ready, false);
    for (const mode of ['--request-cleanup', '--inspect-fixed-root', '--sample-fixed-root', '--foreign']) {
      const refusal = await exec(wrapper, [mode], { timeout: 5000 }).then(() => assert.fail('Root/cleanup/unknown entries must refuse.'), error => error);
      assert.equal(JSON.parse(refusal.stdout).reason, 'INVALID_FIXED_OPERATION');
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
