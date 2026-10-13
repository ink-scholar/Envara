import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, realpath, writeFile, readFile, chmod, rm, symlink, link, stat, lstat, readdir } from 'node:fs/promises';
import { tmpdir, userInfo } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { execFile, spawn } from 'node:child_process';
import { PF_MANIFEST_FILES } from '../native/macos-pf-routing/controller.mjs';

const exec = promisify(execFile);
const source = fileURLToPath(new URL('../native/macos-pf-routing/authorize-install.c', import.meta.url));
const onlyMac = { skip: process.platform !== 'darwin' };
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const helperBytes = '#!/bin/sh\n# Inert owned test data; never executed.\nexit 91\n';
const manifestBytes = '{"component":"owned-authorizer-test","ready":false}\n';
const priorFixtureHelper = '# owned prior snapshot, never executed\n';
const priorFixtureManifest = '{"fixturePrior":true}\n';

async function fixture(callback, { entries, count, manifestHash, harness } = {}) {
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-authorizer-test-')));
  try {
    await writeFile(path.join(directory, 'EnvaraPFHelper'), helperBytes, { mode: 0o755 });
    await writeFile(path.join(directory, 'manifest.json'), manifestBytes, { mode: 0o644 });
    const files = entries ?? [
      { name: 'EnvaraPFHelper', hash: digest(helperBytes), mode: '0755' },
      { name: 'manifest.json', hash: digest(manifestBytes), mode: '0644' },
    ];
    await writeFile(path.join(directory, 'installer-manifest.h'),
      `#define ENVARA_PF_INSTALL_SOURCE ${JSON.stringify(directory)}\n` +
      `#define ENVARA_PF_INSTALL_MANIFEST_SHA256 ${JSON.stringify(manifestHash ?? digest(manifestBytes))}\n` +
      'typedef struct {const char *name;const char *sha256;unsigned int mode;} EnvaraPFInstallFile;\n' +
      `static const EnvaraPFInstallFile ENVARA_PF_INSTALL_FILES[]={${files.map(file => `{${JSON.stringify(file.name)},${JSON.stringify(file.hash)},${file.mode}}`).join(',')}};\n` +
      `#define ENVARA_PF_INSTALL_FILE_COUNT ${count ?? '(sizeof(ENVARA_PF_INSTALL_FILES)/sizeof(ENVARA_PF_INSTALL_FILES[0]))'}\n`);
    const input = harness ? path.join(directory, 'relay-fixture.c') : source;
    if (harness) await writeFile(input, harness.replace('AUTHORIZE_SOURCE', JSON.stringify(source)));
    const binary = path.join(directory, 'EnvaraPFInstall');
    const compiled = await exec('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-I', directory,
      input, '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
    assert.equal(compiled.stderr, '', 'strict compilation must have no warnings');
    await rm(path.join(directory, 'installer-manifest.h'));
    return await callback({ directory, binary });
  } finally { await rm(directory, { recursive: true, force: true }); }
}

async function plan(binary, args = ['--plan'], testCase = 'read-only-plan') {
  try {
    const result = await exec(binary, args, { timeout: 15000, maxBuffer: 1024 * 1024 });
    return { code: 0, signal: null, value: JSON.parse(result.stdout), stderr: result.stderr };
  } catch (error) {
    const diagnostic = JSON.stringify({ case: testCase, code: error.code ?? null, signal: error.signal ?? null,
      killed: error.killed === true, stdoutBytes: Buffer.byteLength(error.stdout ?? '') });
    assert.equal(typeof error.code, 'number', `fixture must exit normally: ${diagnostic}`);
    assert.equal(error.signal ?? null, null, `fixture must not be terminated by a signal: ${diagnostic}`);
    return { code: error.code, signal: null, value: JSON.parse(error.stdout), stderr: error.stderr };
  }
}

async function inventory(directory) {
  return Promise.all((await readdir(directory)).sort().map(async name => {
    const file = path.join(directory, name), info = await stat(file);
    return { name, sha256: digest(await readFile(file)), mode: info.mode & 0o7777, mtime: info.mtimeMs };
  }));
}

test('native default and explicit plans inspect real held file FDs without mutation or activation', onlyMac, async () => {
  await fixture(async ({ directory, binary }) => {
    const before = await inventory(directory);
    for (const args of [[], ['--plan']]) {
      const { code, value, stderr } = await plan(binary, args);
      assert.equal(code, 0); assert.equal(stderr, '');
      assert.equal(value.schema, 'envara.macos-pf-install/v1');
      assert.equal(value.action, 'installedResourcesOnly');
      assert.equal(value.readOnly, true); assert.equal(value.sourceVerified, true);
      assert.equal(value.ready, false); assert.equal(value.productionReady, false);
      assert.equal(value.systemInstallation, false); assert.equal(value.activation, false);
      assert.equal(value.requiresAppleDeveloperIdentity, false);
      assert.equal(value.bootstrapIdentityBound, false);
      assert.equal(value.manifestSHA256, digest(manifestBytes));
      assert.equal(value.source, directory);
      assert.deepEqual(value.operations, { copyFixedResources: true, changePF: false, createGroups: false,
        createTunnel: false, startDaemon: false, launchApplication: false });
      assert.equal(value.controlledExperiment.separateApprovalRequired, true);
      assert.equal(value.controlledExperiment.boundedSeconds, 180);
      if (value.existingInstallation === 'absent') assert.equal(value.canRequestInstall, true,
        'ordinary absent-ACL root directories must not be mistaken for unsafe ACLs');
      if (value.existingInstallation === 'known-prior') {
        assert.ok(['f8fce1d14566fdf822d220ef1a3469cbb815a37924c7ed709a1098729b8bed8b',
          'e940e171ac39624cd3cfeaea09234f4e8e035bfba141a843950cb0209e00db04',
          '518a75d94bac4f17d9e1ce60e842648ba6ff657a68cc62e95ce13718abda6d5a',
          '2a7f4ad635041c434b511034e9535b688cee8eeaebce97617586ad142db5f02d',
          '83256899dc6db90bb6a21dcd18d17cb08a46d3ba4e79177098629475cc107f78',
          'ff9f6a77bb8eeb105e35ce9b9bdd55f69d2995ab63d8f64f42b7004d7899951b',
          '6f8386e1586af12775c9aadd1de339568d29cf93dc4135d8de00b8661407026f',
          '199ff3f1e9b5c36a41f27903db0c592471516d35c44147803b3e09fc6bb29053',
          '46ae6acddd4f7b0a941bfbf6d6cc12aaedf59dd0c681b9aa440e72c38536d56b',
          'c37c49f9ca94b285d7b362ee4a42a01203d3632874d803e90ff38e48dd66c5e0',
          'f99aac934122ac3cafe992ac6fbf232ff917c1b8632034d19491b3dca7ab0d51',
          '05d6eb6ab3d63870d37825b47e2847789a6b5b8c3cf93c434636e0b8aad4f061',
          '14b87d3452af4acaf67709c2494d637163d108a101f6d07fb27ce8e61c2d1d50',
          'dbcf5262ae01da769a85d1f4c104b9f3402d3b54b69e7c6ff862ea871e85c56d',
          '43b392665e496cba2bc2675284fd2d03390ea92db85496d07e49ba696cd7c2a7',
      'acfc112b497c680001c7ce37dcdc99021b51de615072b15c096895900ecfa0c6',
      'c34cba313dad0712fc53eaea514d8466c6710eb70cc7840a1ca4238eea3817e4',
      '4b9f859585a10e31eb98d43682595a9e152b3f93439ebea6ef1de0a4659ba557',
      '43392e3095a921e1531d459a93d5d7329bfc5a28bab5192179eb1fc4fadd0fce',
      'f0b99f600185ecadd9c862fe826193a52e348cde3fb77d353ab5bd7471ab1bfc',
      'f39101dd94c622c886ca6709f2f13f8c826cdd1f3fe609112d5445ad2fd6f305',
      'a8bd008ae1b54f656e52ecba509e706811df386ac7a2b12bb269cd095fc74575',
      'da6e7c9714ec57781f68d875d131e9ee178adbaab401793a153ac7b216ceef05',
      '03245359a948d31c9f4b87fe88dd1b3cb6a270228fbfc13fe873de50cdcce7da',
      '2059a0870f88f6fa6caa89c9dbd751e41ee3b2cbf4101933c8519efa32f08b68'].includes(value.priorManifestSHA256));
        assert.equal(value.requiresUpgradeApproval, true);
        assert.equal(value.canRequestInstall, (value.controlledRuntimeAbsent || value.privateRuntimeInspectionRequired) && !value.needsManualReview,
          'a verified prior may request an administrator precheck but cannot assume private runtime contents are empty');
        if (value.privateRuntimeInspectionRequired) {
          assert.equal(value.controlledRuntimeAbsent, false); assert.equal(value.canRequestAuthorizationForInspection, true);
          assert.equal(value.reason, 'privileged-runtime-inspection-required');
        }
      }
    }
    assert.deepEqual(await inventory(directory), before);
  });
});

test('native plan refuses mutated resource bytes even when source path is unchanged', onlyMac, async () => {
  await fixture(async ({ directory, binary }) => {
    await writeFile(path.join(directory, 'EnvaraPFHelper'), helperBytes + 'changed\n');
    const result = await plan(binary);
    assert.equal(result.code, 1); assert.equal(result.value.sourceVerified, false);
    assert.equal(result.value.reason, 'resource-hash-mismatch');
    assert.equal(result.value.canRequestInstall, false);
  });
});

test('native plan refuses symlink and hardlink resources instead of trusting matching bytes', onlyMac, async () => {
  await fixture(async ({ directory, binary }) => {
    const helper = path.join(directory, 'EnvaraPFHelper'), other = path.join(directory, 'other');
    await writeFile(other, helperBytes); await rm(helper); await symlink(other, helper);
    let result = await plan(binary);
    assert.equal(result.code, 1); assert.equal(result.value.reason, 'resource-path-unsafe');
    await rm(helper); await link(other, helper);
    result = await plan(binary);
    assert.equal(result.code, 1); assert.equal(result.value.reason, 'resource-file-unsafe');
  });
});

test('native plan refuses missing resource files', onlyMac, async () => {
  await fixture(async ({ directory, binary }) => {
    await rm(path.join(directory, 'manifest.json'));
    const result = await plan(binary);
    assert.equal(result.code, 1); assert.equal(result.value.reason, 'resource-path-unsafe');
    assert.equal(result.value.sourceVerified, false);
  });
});

test('fixed operation parser rejects caller commands and extra authorization arguments before requesting rights', onlyMac, async () => {
  await fixture(async ({ binary }) => {
    for (const args of [['--exec'], ['--request-install', '/untrusted'], ['--request-controlled-experiment', '--caller-uid'], ['--plan', '/untrusted']]) {
      const result = await plan(binary, args);
      assert.equal(result.code, 1); assert.equal(result.value.reason, 'invalid-fixed-operation');
      assert.equal(result.value.ready, false);
    }
  });
});

test('invalid compiled paths, modes and count fail safely in real native plan', onlyMac, async () => {
  const base = [{ name: 'EnvaraPFHelper', hash: digest(helperBytes), mode: '0755' },
    { name: 'manifest.json', hash: digest(manifestBytes), mode: '0644' }];
  for (const options of [
    { entries: [{ ...base[0], name: '../outside' }, base[1]] },
    { entries: [{ ...base[0], mode: '04755' }, base[1]] },
    { entries: [base[0], base[0], base[1]] },
    { entries: base, count: '999' },
    { entries: base, count: '0' },
    { entries: base, manifestHash: 'invalid"digest' },
  ]) await fixture(async ({ binary }) => {
    const result = await plan(binary, ['--plan'], options.count ? 'declared-count-mismatch' :
      options.manifestHash ? 'manifest-digest-invalid' : 'compiled-entry-invalid');
    assert.equal(result.code, 1); assert.equal(result.value.sourceVerified, false);
    assert.equal(result.value.reason, 'fixed-manifest-invalid');
    assert.equal(result.value.canRequestInstall, false);
    assert.equal(result.value.files.length, options.entries.length);
  }, options);
});

// Calls the actual production relay through a compile-time fixture main. The
// peer is an unprivileged fork with an anonymous AF_UNIX socket pair: there is
// no Security request, installed helper, networking, root entry or system edit.
const relayHarness = `
#define main envara_installer_entry
#include AUTHORIZE_SOURCE
#undef main
#include <sys/wait.h>
int main(int argc, char **argv) {
    if (argc != 2) return 90;
    if (!strcmp(argv[1], "not-bidirectional")) {
        int descriptors[2]; if (pipe(descriptors)) return 91;
        bool okay = relay_helper(descriptors[0], 1.0);
        close(descriptors[0]); close(descriptors[1]);
        return !okay && !strcmp(failure, "private-bidirectional-communication-required") ? 0 : 92;
    }
    int pair[2]; if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return 93;
    pid_t child = fork(); if (child < 0) return 94;
    if (!child) {
        close(pair[0]);
        if (!strcmp(argv[1], "deadline")) { usleep(200000); close(pair[1]); _exit(0); }
        unsigned char bytes[4096]; size_t received = 0;
        for (;;) {
            ssize_t size = read(pair[1], bytes, sizeof(bytes));
            if (size < 0 && errno == EINTR) continue;
            if (size < 0) _exit(95); if (!size) break;
            for (ssize_t i = 0; i < size; i++) if (bytes[i] != (unsigned char)((received + (size_t)i) % 251)) _exit(96);
            received += (size_t)size;
        }
        if (received != 262144) _exit(97);
        for (size_t offset = 0; offset < 524288; offset += sizeof(bytes)) {
            for (size_t i = 0; i < sizeof(bytes); i++) bytes[i] = (unsigned char)((offset + i) % 239);
            if (!write_all(pair[1], bytes, sizeof(bytes))) _exit(98);
        }
        close(pair[1]); _exit(0);
    }
    close(pair[1]);
    bool timeout_case = !strcmp(argv[1], "deadline");
    bool okay = relay_helper(pair[0], timeout_case ? 0.025 : 5.0);
    close(pair[0]); int status = 0;
    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) return 99;
    if (timeout_case) return !okay && !strcmp(failure, "controlled-session-deadline") ? 0 : 100;
    return okay ? 0 : 101;
}
`;

async function runRelay(binary, argument, input = Buffer.alloc(0)) {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, [argument], { stdio: ['pipe', 'pipe', 'pipe'] });
    const output = [], errors = [];
    const timeout = setTimeout(() => { child.kill(); reject(new Error('owned relay fixture timed out')); }, 10000);
    child.on('error', reject);
    child.stdout.on('data', bytes => output.push(bytes));
    child.stderr.on('data', bytes => errors.push(bytes));
    child.stdin.on('error', error => { if (error.code !== 'EPIPE') reject(error); });
    child.on('close', (code, signal) => { clearTimeout(timeout); resolve({ code, signal,
      output: Buffer.concat(output), errors: Buffer.concat(errors).toString() }); });
    child.stdin.end(input);
  });
}

test('real production relay drains 512KiB final response after 256KiB input write-half close', onlyMac, async () => {
  await fixture(async ({ binary }) => {
    const input = Buffer.alloc(262144), expected = Buffer.alloc(524288);
    for (let i = 0; i < input.length; i++) input[i] = i % 251;
    for (let i = 0; i < expected.length; i++) expected[i] = i % 239;
    const result = await runRelay(binary, 'tail', input);
    assert.equal(result.code, 0); assert.equal(result.signal, null); assert.equal(result.errors, '');
    assert.deepEqual(result.output, expected, 'private final response must not be truncated at stdin EOF');
  }, { harness: relayHarness });
});

test('production relay refuses a unidirectional pipe rather than pretending JSONL is bidirectional', onlyMac, async () => {
  await fixture(async ({ binary }) => {
    const result = await runRelay(binary, 'not-bidirectional');
    assert.equal(result.code, 0); assert.equal(result.output.length, 0); assert.equal(result.errors, '');
  }, { harness: relayHarness });
});

test('production relay bounds a silent owned socket peer and preserves timeout reason', onlyMac, async () => {
  await fixture(async ({ binary }) => {
    const result = await runRelay(binary, 'deadline');
    assert.equal(result.code, 0); assert.equal(result.output.length, 0); assert.equal(result.errors, '');
  }, { harness: relayHarness });
});

const upgradeHarness = `
#define main envara_installer_entry
#include AUTHORIZE_SOURCE
#undef main
static const EnvaraPFInstallFile fixture_prior_files[]={
 {"EnvaraPFHelper","${digest(priorFixtureHelper)}",0755},
 {"manifest.json","${digest(priorFixtureManifest)}",0644}
};
static const InstallSnapshot fixture_prior={"${digest(priorFixtureManifest)}",fixture_prior_files,2};
typedef struct { const InstallSnapshot *snapshot; const char *mode; bool old; int calls,parent; } FixtureContext;
static bool fixture_validator(int fd,void *value){
 FixtureContext *context=value;context->calls++;
 bool tamper=(context->old&&!strcmp(context->mode,"tamper-backup")&&context->calls==2)||
  (!context->old&&!strcmp(context->mode,"rollback")&&context->calls==2);
 if(tamper){int file=openat(fd,"EnvaraPFHelper",O_WRONLY|O_TRUNC|O_NOFOLLOW);if(file<0)return false;
  bool wrote=write_all(file,(const unsigned char *)"corrupted owned test data\\n",26);close(file);if(!wrote)return false;}
 if(context->old&&((!strcmp(context->mode,"replace-before")&&context->calls==1)||
  (!strcmp(context->mode,"replace-after")&&context->calls==2))){
  const char *evidence=context->calls==1?"held-old":"held-new";
  if(renameat(context->parent,INSTALL_NAME,context->parent,evidence)||renameat(context->parent,"replacement",context->parent,INSTALL_NAME))return false;
 }
 return snapshot_matches(fd,context->snapshot,false);
}
int main(int argc,char **argv){
 if(argc!=3)return 91;
 int parent=absolute_directory(argv[2],false);if(parent<0)return 92;
 if(!strcmp(argv[1],"lock-contention")){
  int contender=absolute_directory(argv[2],false);if(contender<0)return 95;
  if(flock(parent,LOCK_SH|LOCK_NB))return 96;
  bool blockedWriter=flock(contender,LOCK_EX|LOCK_NB)<0&&(errno==EWOULDBLOCK||errno==EAGAIN);
  close(parent);
  bool releasedWriter=flock(contender,LOCK_EX|LOCK_NB)==0;
  int reader=absolute_directory(argv[2],false);if(reader<0)return 97;
  bool blockedReader=flock(reader,LOCK_SH|LOCK_NB)<0&&(errno==EWOULDBLOCK||errno==EAGAIN);
  close(contender);
  bool releasedReader=flock(reader,LOCK_SH|LOCK_NB)==0;
  printf("{\\"blockedWriter\\":%s,\\"releasedWriter\\":%s,\\"blockedReader\\":%s,\\"releasedReader\\":%s}\\n",
   blockedWriter?"true":"false",releasedWriter?"true":"false",blockedReader?"true":"false",releasedReader?"true":"false");
  close(reader);return 0;
 }
 if(flock(parent,LOCK_EX|LOCK_NB)){close(parent);return 93;}
 const char *stage_name=STAGE_PREFIX "owned-test";
 int old=directory_at(parent,INSTALL_NAME,false,false),fresh=directory_at(parent,stage_name,false,false);
 if(old<0||fresh<0)return 94;
 if(!strcmp(argv[1],"inspect")||!strcmp(argv[1],"inspect-cleanup")){
  bool matches=snapshot_matches(fresh,&current_snapshot,false);
  bool cleanup=!strcmp(argv[1],"inspect-cleanup")&&cleanup_exact_snapshot(parent,stage_name,fresh,&current_snapshot,false);
  printf("{\\"matches\\":%s,\\"rootMetadataAccepted\\":%s,\\"cleanup\\":%s,\\"pendingStage\\":%s}\\n",
   matches?"true":"false",snapshot_matches(fresh,&current_snapshot,true)?"true":"false",cleanup?"true":"false",pending_stage(parent)?"true":"false");
  close(old);close(fresh);close(parent);return 0;
 }
 FixtureContext before={&fixture_prior,argv[1],true,0,parent},after={&current_snapshot,argv[1],false,0,parent};
 ExchangeResult result=exchange_known_snapshot(parent,stage_name,INSTALL_NAME,old,fresh,fixture_validator,&before,fixture_validator,&after);
 bool cleanup=false;
 if(!strcmp(argv[1],"commit-cleanup")&&result==EXCHANGE_COMMITTED)cleanup=cleanup_exact_snapshot(parent,stage_name,old,&fixture_prior,false);
 printf("{\\"result\\":%d,\\"cleanup\\":%s,\\"pendingStage\\":%s}\\n",(int)result,cleanup?"true":"false",pending_stage(parent)?"true":"false");
 close(old);close(fresh);close(parent);return 0;
}
`;

async function ownedUpgradeLayout(directory) {
  const parent = await mkdtemp(path.join(directory, 'owned-upgrade-'));
  const old = path.join(parent, 'io.envara.pf-routing'), stage = path.join(parent, '.io.envara.pf-routing-stage-owned-test');
  await mkdir(old); await mkdir(stage);
  await writeFile(path.join(old, 'EnvaraPFHelper'), priorFixtureHelper, { mode: 0o755 });
  await writeFile(path.join(old, 'manifest.json'), priorFixtureManifest, { mode: 0o644 });
  await writeFile(path.join(stage, 'EnvaraPFHelper'), helperBytes, { mode: 0o755 });
  await writeFile(path.join(stage, 'manifest.json'), manifestBytes, { mode: 0o644 });
  await mkdir(path.join(parent, 'replacement'));
  await writeFile(path.join(parent, 'replacement/unknown-marker'), 'preserve unknown installation');
  return { parent, old, stage };
}
async function runUpgradeFixture(binary, mode, parent) {
  const result = await exec(binary, [mode, parent], { timeout: 10000, maxBuffer: 65536 });
  assert.equal(result.stderr, ''); return JSON.parse(result.stdout);
}

test('upgrade allows only twenty pinned prior manifests and each exact file table, with no runtime-derived allowlist', async () => {
  const base = new URL('../native/macos-pf-routing/', import.meta.url);
  for (const [tag, pinned, runtimeCount] of [['f8', 'f8fce1d14566fdf822d220ef1a3469cbb815a37924c7ed709a1098729b8bed8b', 13],
    ['e940', 'e940e171ac39624cd3cfeaea09234f4e8e035bfba141a843950cb0209e00db04', 13],
    ['518', '518a75d94bac4f17d9e1ce60e842648ba6ff657a68cc62e95ce13718abda6d5a', 13],
    ['2a7', '2a7f4ad635041c434b511034e9535b688cee8eeaebce97617586ad142db5f02d', 14],
    ['832', '83256899dc6db90bb6a21dcd18d17cb08a46d3ba4e79177098629475cc107f78', 14],
    ['ff9', 'ff9f6a77bb8eeb105e35ce9b9bdd55f69d2995ab63d8f64f42b7004d7899951b', 14],
    ['6f8', '6f8386e1586af12775c9aadd1de339568d29cf93dc4135d8de00b8661407026f', 14],
    ['199', '199ff3f1e9b5c36a41f27903db0c592471516d35c44147803b3e09fc6bb29053', 18],
    ['46a', '46ae6acddd4f7b0a941bfbf6d6cc12aaedf59dd0c681b9aa440e72c38536d56b', 18],
    ['c37', 'c37c49f9ca94b285d7b362ee4a42a01203d3632874d803e90ff38e48dd66c5e0', 18],
    ['f99', 'f99aac934122ac3cafe992ac6fbf232ff917c1b8632034d19491b3dca7ab0d51', 18],
    ['05d6', '05d6eb6ab3d63870d37825b47e2847789a6b5b8c3cf93c434636e0b8aad4f061', 18],
    ['14b87', '14b87d3452af4acaf67709c2494d637163d108a101f6d07fb27ce8e61c2d1d50', 18],
    ['dbcf', 'dbcf5262ae01da769a85d1f4c104b9f3402d3b54b69e7c6ff862ea871e85c56d', 18],
    ['43b', '43b392665e496cba2bc2675284fd2d03390ea92db85496d07e49ba696cd7c2a7', 18],
    ['acfc', 'acfc112b497c680001c7ce37dcdc99021b51de615072b15c096895900ecfa0c6', 18],
    ['c34', 'c34cba313dad0712fc53eaea514d8466c6710eb70cc7840a1ca4238eea3817e4', 18],
    ['4b9f85', '4b9f859585a10e31eb98d43682595a9e152b3f93439ebea6ef1de0a4659ba557', 18],
    ['43392e', '43392e3095a921e1531d459a93d5d7329bfc5a28bab5192179eb1fc4fadd0fce', 18],
    ['f0b99f', 'f0b99f600185ecadd9c862fe826193a52e348cde3fb77d353ab5bd7471ab1bfc', 18],
    ['f39101', 'f39101dd94c622c886ca6709f2f13f8c826cdd1f3fe609112d5445ad2fd6f305', 18],
    ['a8bd00', 'a8bd008ae1b54f656e52ecba509e706811df386ac7a2b12bb269cd095fc74575', 18],
    ['da6e7c', 'da6e7c9714ec57781f68d875d131e9ee178adbaab401793a153ac7b216ceef05', 18]]) {
    const bytes = await readFile(new URL(`known-installations/${tag}.manifest.json`, base));
    assert.equal(digest(bytes), pinned);
    const manifest = JSON.parse(bytes); assert.equal(Object.keys(manifest.files).length, runtimeCount);
    assert.equal(manifest.arch, 'arm64'); assert.equal(manifest.component, 'envara-pf-routing');
    const header = await readFile(new URL(`installer-upgrade-${tag}.h`, base), 'utf8');
    const entries = [...header.matchAll(/\{"([^"\n]+)","([0-9a-f]{64})",(0[0-7]{3})\}/g)];
    assert.equal(entries.length, runtimeCount + 1);
    assert.deepEqual(entries.map(([, name]) => name).sort(), [...Object.keys(manifest.files), 'manifest.json'].sort());
    const executable = new Set(['EnvaraPFHelper', 'node', 'mihomo', 'envara-pf-native', 'fixtures/EnvaraRoutingAcceptanceFixture']);
    for (const [, name, hash, mode] of entries) {
      assert.equal(hash, name === 'manifest.json' ? digest(bytes) : manifest.files[name]);
      assert.equal(mode, executable.has(name) ? '0755' : '0644');
    }
  }
});

test('the forty earlier reviewed prior inputs remain byte-for-byte pinned', async () => {
  const base = new URL('../native/macos-pf-routing/', import.meta.url);
  for (const [tag, headerSHA256, manifestSHA256] of [
    ['f8', '15f324849482024c72388bb5018f82d0755ea376c19df83d6cec2a78914dcd9f', 'f8fce1d14566fdf822d220ef1a3469cbb815a37924c7ed709a1098729b8bed8b'],
    ['e940', 'c8e8f6b4b76a12d24a8c9fbcde29e8372a848f44fa00392f89cd83b2454b6b20', 'e940e171ac39624cd3cfeaea09234f4e8e035bfba141a843950cb0209e00db04'],
    ['518', 'd3b8cc03d547863c9f3bfade524dca5b94c28fe9f04d613141093834d705de39', '518a75d94bac4f17d9e1ce60e842648ba6ff657a68cc62e95ce13718abda6d5a'],
    ['2a7', '214b68289edf5685eef4e10707984abac20f712cdc78ab4c0392aae66b25077c', '2a7f4ad635041c434b511034e9535b688cee8eeaebce97617586ad142db5f02d'],
    ['832', '22306a17c1b5bc9a8bf8bf9be80369942b8194a87f3d71c190d72ea5c1edfe5f', '83256899dc6db90bb6a21dcd18d17cb08a46d3ba4e79177098629475cc107f78'],
    ['ff9', '7d236ac613aa49ff9d9bab8a30c4804b7d8e991fd5ac9d921fe42e45807f1f8b', 'ff9f6a77bb8eeb105e35ce9b9bdd55f69d2995ab63d8f64f42b7004d7899951b'],
    ['6f8', '3cb315512ea79ad3d9d60dfe282036b6108a1f0191f82b72fe220541034d5a6c', '6f8386e1586af12775c9aadd1de339568d29cf93dc4135d8de00b8661407026f'],
    ['199', 'a19185f6337b0aac299c9f94d8adde4834c7fb5cec7231968a567f7435969fe7', '199ff3f1e9b5c36a41f27903db0c592471516d35c44147803b3e09fc6bb29053'],
    ['46a', 'a066a45135aef11272fc276113d0cb0d075a9ab89a125a5b927fd10c12e98392', '46ae6acddd4f7b0a941bfbf6d6cc12aaedf59dd0c681b9aa440e72c38536d56b'],
    ['c37', 'd0bdbed7a45f96b525bed7a9be7ff974a78ce5826eb000444f027a0f10e8b4be', 'c37c49f9ca94b285d7b362ee4a42a01203d3632874d803e90ff38e48dd66c5e0'],
    ['f99', '87cb2dac4815999495a673a93d130048b38e7fbab7113d3917c64c5697a3a712', 'f99aac934122ac3cafe992ac6fbf232ff917c1b8632034d19491b3dca7ab0d51'],
    ['05d6', '4f1ff1dcedf427eb646dbc23a56b9f036fa3cf9fb6a9ef4e1451bddbb2d27038', '05d6eb6ab3d63870d37825b47e2847789a6b5b8c3cf93c434636e0b8aad4f061'],
    ['14b87', '826a825bf776d84550e77df1f77e79552ff0d32240d1e57ce23f803723d91ed3', '14b87d3452af4acaf67709c2494d637163d108a101f6d07fb27ce8e61c2d1d50'],
    ['dbcf', '62fe468071ccf5d6998e10af35ef14af8d0de8fe94703cf897c7565e14e80afc', 'dbcf5262ae01da769a85d1f4c104b9f3402d3b54b69e7c6ff862ea871e85c56d'],
    ['43b', '27721aa950446faf2bedc95ad247df613db4a169a4cac15595cd6bc8ea8ffb3e', '43b392665e496cba2bc2675284fd2d03390ea92db85496d07e49ba696cd7c2a7'],
    ['acfc', '723b52f2959c7119f613b0a14127a17f48988ffd988d457f0c549f8beba0b0fa', 'acfc112b497c680001c7ce37dcdc99021b51de615072b15c096895900ecfa0c6'],
    ['4b9f85', '05bede0c97da1e69d2118f5f073361f9d914d2f659edb355d573fcdf7256eb54', '4b9f859585a10e31eb98d43682595a9e152b3f93439ebea6ef1de0a4659ba557'],
    ['43392e', 'bd3867f07f92e2a5308fd587f761ed3d34fd198c597476a1cc9577450bca8756', '43392e3095a921e1531d459a93d5d7329bfc5a28bab5192179eb1fc4fadd0fce'],
    ['f0b99f', 'e0e6cadaa4a85443158446f5cf4c6e29a2a75d756584679ecb6b5695bef58184', 'f0b99f600185ecadd9c862fe826193a52e348cde3fb77d353ab5bd7471ab1bfc'],
    ['f39101', '5cff757ccaf75f86fea0ffde53f008dfd36c784ab8b03d4c7260da6591186005', 'f39101dd94c622c886ca6709f2f13f8c826cdd1f3fe609112d5445ad2fd6f305'],
    ['a8bd00', 'd33441dc803cb69d942b87e597646cada7e79b668746578fdbadcaa7d9c3c447', 'a8bd008ae1b54f656e52ecba509e706811df386ac7a2b12bb269cd095fc74575'],
    ['03245359', '0da9db2c560a1c8351af69f781cddf34914007ae8d83691205b815b42468dcd2', '03245359a948d31c9f4b87fe88dd1b3cb6a270228fbfc13fe873de50cdcce7da'],
    ['2059a0', '25c0648936fc71b9ebeb9e3c9585c5f98854a24137b80cd8896ff2fe7a1a831d', '2059a0870f88f6fa6caa89c9dbd751e41ee3b2cbf4101933c8519efa32f08b68'],
    ['da6e7c', '4cc282fbb509c0c4e8fb328ffd46a8c7964e1202c44e1f1c58dd61f5ebb7144f', 'da6e7c9714ec57781f68d875d131e9ee178adbaab401793a153ac7b216ceef05'],
  ]) {
    assert.equal(digest(await readFile(new URL(`installer-upgrade-${tag}.h`, base))), headerSHA256);
    assert.equal(digest(await readFile(new URL(`known-installations/${tag}.manifest.json`, base))), manifestSHA256);
  }
});

test('source trust tables classify exact 14-, 15- and 19-file priors independently of the current target', async () => {
  const contents = await readFile(source, 'utf8');
  const priors = contents.match(/known_prior_snapshots\[\]\s*=\s*\{([^}]+)\}/)?.[1];
  assert.deepEqual([...priors.matchAll(/&ENVARA_PF_UPGRADE_([A-Z0-9]+)_SNAPSHOT/g)].map(([, tag]) => tag), ['F8', 'E940', '518', '2A7', '832', 'FF9', '6F8', '199', '46A', 'C37', 'F99', '05D6', '14B87', 'DBCF', '43B', 'ACFC', 'C34', '4B9F85', '43392E', 'F0B99F', 'F39101', 'A8BD00', 'DA6E7C', '03245359', '2059A0']);
  const targetNames = [...Object.keys(PF_MANIFEST_FILES), 'manifest.json'].sort();
  assert.equal(targetNames.length, 19); assert.equal(PF_MANIFEST_FILES['stateless-verifier.mjs'], false);
  const snapshotMatcher = contents.match(/static bool snapshot_matches\([^)]*\)\s*\{([\s\S]*?)\n\}/)?.[1];
  assert.ok(snapshotMatcher.includes('snapshot->count'));
  assert.ok(snapshotMatcher.includes('&snapshot->files[i]'));
  assert.ok(snapshotMatcher.includes('exact_snapshot_tree(fd, "", 0, snapshot, root_owned)'));
  assert.doesNotMatch(snapshotMatcher, /ACTUAL_FILE_COUNT|ENVARA_PF_INSTALL_FILE_COUNT|ENVARA_PF_INSTALL_FILES/);
  const classifier = contents.match(/static int existing_installation\([^)]*\)\s*\{([\s\S]*?)\n\}/)?.[1];
  assert.ok(classifier.includes('snapshot_matches(fd, known_prior_snapshots[i], true)'));
  for (const tag of ['f8', 'e940', '518', '2a7', '832', 'ff9', '6f8', '199', '46a', 'c37', 'f99', '05d6', '14b87', 'dbcf', '43b', 'acfc', 'c34', '4b9f85', '43392e', 'f0b99f', 'f39101', 'a8bd00', 'da6e7c', '03245359', '2059a0']) {
    const header = await readFile(new URL(`../native/macos-pf-routing/installer-upgrade-${tag}.h`, import.meta.url), 'utf8');
    const entries = [...header.matchAll(/\{"([^"\n]+)","([0-9a-f]{64})",(0[0-7]{3})\}/g)];
    assert.equal(entries.length, ['199', '46a', 'c37', 'f99', '05d6', '14b87', 'dbcf', '43b', 'acfc', 'c34', '4b9f85', '43392e', 'f0b99f', 'f39101', 'a8bd00', 'da6e7c', '03245359', '2059a0'].includes(tag) ? 19 : ['2a7', '832', 'ff9', '6f8'].includes(tag) ? 15 : 14);
    const absentNewModules = ['helper-production-native.mjs', 'notion-front-service.mjs', 'notion-socks-front.mjs', 'notion-socks-reader.mjs'];
    const absent = ['199', '46a', 'c37', 'f99', '05d6', '14b87', 'dbcf', '43b', 'acfc', 'c34', '4b9f85', '43392e', 'f0b99f', 'f39101', 'a8bd00', 'da6e7c', '03245359', '2059a0'].includes(tag) ? [] : [...absentNewModules, ...(['2a7', '832', 'ff9', '6f8'].includes(tag) ? [] : ['stateless-verifier.mjs'])].sort();
    assert.deepEqual(targetNames.filter(name => !entries.some(([, priorName]) => priorName === name)), absent);
    assert.match(header, /sizeof\(ENVARA_PF_UPGRADE_[A-Z0-9]+_FILES\)\/sizeof\(ENVARA_PF_UPGRADE_[A-Z0-9]+_FILES\[0\]\)/);
  }
});

test('production upgrade exchange commits and preserves crash backup until exact owned cleanup', onlyMac, async () => {
  await fixture(async ({ directory, binary }) => {
    for (const mode of ['commit', 'commit-cleanup']) {
      const layout = await ownedUpgradeLayout(directory);
      const result = await runUpgradeFixture(binary, mode, layout.parent);
      assert.equal(result.result, 1); assert.equal(await readFile(path.join(layout.old, 'EnvaraPFHelper'), 'utf8'), helperBytes);
      if (mode === 'commit') {
        assert.equal(result.pendingStage, true, 'crash-left prior evidence must block idempotent completion');
        assert.equal(await readFile(path.join(layout.stage, 'EnvaraPFHelper'), 'utf8'), priorFixtureHelper);
      } else {
        assert.equal(result.cleanup, true); assert.equal(result.pendingStage, false);
        await assert.rejects(stat(layout.stage), { code: 'ENOENT' });
      }
    }
  }, { harness: upgradeHarness });
});

test('production upgrade rolls back corrupt new bytes and preserves unknown replacements or corrupt prior evidence', onlyMac, async () => {
  await fixture(async ({ directory, binary }) => {
    for (const [mode, resultCode] of [['rollback', 2], ['replace-before', 0], ['replace-after', 3], ['tamper-backup', 3]]) {
      const layout = await ownedUpgradeLayout(directory);
      const result = await runUpgradeFixture(binary, mode, layout.parent);
      assert.equal(result.result, resultCode, mode); assert.equal(result.pendingStage, true, mode);
      if (mode === 'rollback') {
        assert.equal(await readFile(path.join(layout.old, 'EnvaraPFHelper'), 'utf8'), priorFixtureHelper);
        assert.equal(await readFile(path.join(layout.stage, 'EnvaraPFHelper'), 'utf8'), 'corrupted owned test data\n');
      } else if (mode.startsWith('replace-')) {
        assert.equal(await readFile(path.join(layout.old, 'unknown-marker'), 'utf8'), 'preserve unknown installation');
        const evidence = path.join(layout.parent, mode === 'replace-before' ? 'held-old' : 'held-new', 'EnvaraPFHelper');
        assert.equal(await readFile(evidence, 'utf8'), mode === 'replace-before' ? priorFixtureHelper : helperBytes);
      } else {
        assert.equal(await readFile(path.join(layout.old, 'EnvaraPFHelper'), 'utf8'), helperBytes);
        assert.equal(await readFile(path.join(layout.stage, 'EnvaraPFHelper'), 'utf8'), 'corrupted owned test data\n');
      }
    }
  }, { harness: upgradeHarness });
});

test('shared production snapshot validation refuses unknown, mode, link, symlink and ownership substitutions in owned temp', onlyMac, async () => {
  await fixture(async ({ directory, binary }) => {
    for (const variant of ['exact', 'unknown', 'mode', 'symlink', 'hardlink', 'corrupt']) {
      const layout = await ownedUpgradeLayout(directory), file = path.join(layout.stage, 'EnvaraPFHelper');
      if (variant === 'unknown') await writeFile(path.join(layout.stage, 'unknown'), 'unknown');
      if (variant === 'mode') await chmod(file, 0o666);
      if (variant === 'symlink' || variant === 'hardlink') {
        const alternate = path.join(layout.parent, 'linked'); await writeFile(alternate, helperBytes, { mode: 0o755 });
        await rm(file); if (variant === 'symlink') await symlink(alternate, file); else await link(alternate, file);
      }
      if (variant === 'corrupt') await writeFile(file, helperBytes + 'changed');
      const result = await runUpgradeFixture(binary, variant === 'exact' ? 'inspect' : 'inspect-cleanup', layout.parent);
      assert.equal(result.matches, variant === 'exact', variant);
      assert.equal(result.rootMetadataAccepted, false, 'owned user fixtures cannot become privileged installed snapshots');
      assert.equal(result.pendingStage, true);
      assert.equal(result.cleanup, false, 'unknown or malformed staging must remain available for manual review');
      assert.equal((await stat(layout.stage)).isDirectory(), true);
      assert.equal(await readFile(path.join(layout.old, 'EnvaraPFHelper'), 'utf8'), priorFixtureHelper);
    }
  }, { harness: upgradeHarness });
});

test('native installation directory leases exclude writers during controlled sessions and readers during maintenance', onlyMac, async () => {
  await fixture(async ({ directory, binary }) => {
    const layout = await ownedUpgradeLayout(directory);
    assert.deepEqual(await runUpgradeFixture(binary, 'lock-contention', layout.parent), {
      blockedWriter: true, releasedWriter: true, blockedReader: true, releasedReader: true,
    });
    assert.equal(await readFile(path.join(layout.old, 'EnvaraPFHelper'), 'utf8'), priorFixtureHelper);
    assert.equal(await readFile(path.join(layout.stage, 'EnvaraPFHelper'), 'utf8'), helperBytes);
  }, { harness: upgradeHarness });
});

const nestedSyncHarness = `
#define main envara_installer_entry
#include AUTHORIZE_SOURCE
#undef main
typedef struct { const char *fail_at; unsigned int calls; } SyncContext;
static bool record_sync(int fd,const char *relative,void *value){
 SyncContext *context=value;if(context->calls++)printf(",");json_string(relative);
 return strcmp(relative,context->fail_at)&&fsync(fd)==0;
}
int main(int argc,char **argv){
 if(argc!=3)return 90;
 int stage=absolute_directory(argv[2],false);if(stage<0)return 91;
 SyncContext context={!strcmp(argv[1],"fail")?"fixtures/deep":"not-a-fixed-path",0};
 printf("{\\"directories\\":[");
 bool okay=sync_snapshot_directories(stage,"",0,&current_snapshot,false,record_sync,&context);
 printf("],\\"synced\\":%s}\\n",okay?"true":"false");close(stage);return 0;
}
`;

test('production staging sync flushes nested fixed directories bottom-up and refuses incomplete sync or unsafe paths', onlyMac, async () => {
  const nestedBytes = 'inert nested fixture data\n';
  await fixture(async ({ directory, binary }) => {
    for (const variant of ['exact', 'fail', 'symlink', 'unknown']) {
      const stage = await mkdtemp(path.join(directory, 'owned-sync-'));
      await mkdir(path.join(stage, 'fixtures/deep'), { recursive: true });
      await writeFile(path.join(stage, 'EnvaraPFHelper'), helperBytes, { mode: 0o755 });
      await writeFile(path.join(stage, 'manifest.json'), manifestBytes, { mode: 0o644 });
      await writeFile(path.join(stage, 'fixtures/deep/value'), nestedBytes, { mode: 0o644 });
      if (variant === 'symlink') {
        const outside = path.join(directory, 'outside-' + variant); await mkdir(outside);
        await writeFile(path.join(outside, 'marker'), 'untouched');
        await rm(path.join(stage, 'fixtures/deep'), { recursive: true }); await symlink(outside, path.join(stage, 'fixtures/deep'));
      }
      if (variant === 'unknown') await writeFile(path.join(stage, 'fixtures/unknown'), 'retain unknown data');
      const result = await runUpgradeFixture(binary, variant === 'fail' ? 'fail' : 'sync', stage);
      assert.equal(result.synced, variant === 'exact', variant);
      if (variant === 'exact') assert.deepEqual(result.directories, ['fixtures/deep', 'fixtures', '']);
      if (variant === 'fail') assert.deepEqual(result.directories, ['fixtures/deep'], 'a failed child flush must stop the parent commit path');
      if (variant === 'symlink') assert.equal(await readFile(path.join(directory, 'outside-symlink/marker'), 'utf8'), 'untouched');
      if (variant === 'unknown') assert.equal(await readFile(path.join(stage, 'fixtures/unknown'), 'utf8'), 'retain unknown data');
    }
  }, { harness: nestedSyncHarness, entries: [
    { name: 'EnvaraPFHelper', hash: digest(helperBytes), mode: '0755' },
    { name: 'manifest.json', hash: digest(manifestBytes), mode: '0644' },
    { name: 'fixtures/deep/value', hash: digest(nestedBytes), mode: '0644' },
  ] });
});

const guardianHarness = `
#define main envara_installer_entry
#include AUTHORIZE_SOURCE
#undef main
typedef struct { int ready,finish; } ChildFixture;
static void fixture_helper(void *value){
 ChildFixture *context=value;char byte='h';
 if(write(context->ready,&byte,1)!=1)_exit(91);
 close(context->ready);
 while(read(context->finish,&byte,1)>0){}
 close(context->finish);
 struct timespec cleanup={0,100000000};nanosleep(&cleanup,NULL);_exit(0);
}
static bool ready_byte(int fd,char expected){
 struct pollfd item={fd,POLLIN,0};char actual=0;
 return poll(&item,1,4000)>0&&read(fd,&actual,1)==1&&actual==expected;
}
int main(int argc,char **argv){
 if(argc!=3)return 90;
 int ready[2],finish[2];if(pipe(ready)||pipe(finish))return 92;
 pid_t relay=fork();if(relay<0)return 93;
 if(!relay){
  close(ready[0]);close(finish[0]);close(finish[1]);
  int lease=absolute_directory(argv[2],false);if(lease<0||flock(lease,LOCK_SH|LOCK_NB))_exit(94);
  char byte='r';if(write(ready[1],&byte,1)!=1)_exit(95);close(ready[1]);for(;;)pause();
 }
 pid_t guardian=-1;int contender=-1,result=96,status=0;
 bool relayDeathBlocked=false,guardianTermBlocked=false,cleanupBlocked=false,releasedAfterExit=false;
 if(!ready_byte(ready[0],'r'))goto done;
 guardian=fork();if(guardian<0)goto done;
 if(!guardian){
  close(ready[0]);close(finish[1]);
  int lease=absolute_directory(argv[2],false);if(lease<0||flock(lease,LOCK_SH|LOCK_NB))_exit(97);
  ChildFixture context={ready[1],finish[0]};_exit(guard_owned_helper(lease,fixture_helper,&context));
 }
 close(ready[1]);ready[1]=-1;close(finish[0]);finish[0]=-1;
 if(!ready_byte(ready[0],'h'))goto done;
 if(kill(relay,SIGKILL)||waitpid(relay,&status,0)!=relay||!WIFSIGNALED(status))goto done;relay=-1;
 contender=absolute_directory(argv[2],false);if(contender<0)goto done;
 relayDeathBlocked=flock(contender,LOCK_EX|LOCK_NB)<0&&(errno==EWOULDBLOCK||errno==EAGAIN);
 if(kill(guardian,SIGTERM))goto done;
 struct timespec pause_time={0,20000000};nanosleep(&pause_time,NULL);
 guardianTermBlocked=waitpid(guardian,&status,WNOHANG)==0&&flock(contender,LOCK_EX|LOCK_NB)<0&&(errno==EWOULDBLOCK||errno==EAGAIN);
 close(finish[1]);finish[1]=-1;
 cleanupBlocked=flock(contender,LOCK_EX|LOCK_NB)<0&&(errno==EWOULDBLOCK||errno==EAGAIN);
 if(waitpid(guardian,&status,0)!=guardian||!WIFEXITED(status)||WEXITSTATUS(status))goto done;guardian=-1;
 releasedAfterExit=flock(contender,LOCK_EX|LOCK_NB)==0;result=0;
done:
 if(finish[1]>=0)close(finish[1]);if(finish[0]>=0)close(finish[0]);
 if(relay>0){kill(relay,SIGKILL);waitpid(relay,&status,0);}
 if(guardian>0){kill(guardian,SIGKILL);waitpid(guardian,&status,0);}
 close(ready[0]);if(ready[1]>=0)close(ready[1]);if(contender>=0)close(contender);
 printf("{\\"relayDeathBlocked\\":%s,\\"guardianTermBlocked\\":%s,\\"cleanupBlocked\\":%s,\\"releasedAfterExit\\":%s}\\n",
  relayDeathBlocked?"true":"false",guardianTermBlocked?"true":"false",cleanupBlocked?"true":"false",releasedAfterExit?"true":"false");
 return result;
}
`;

test('production guardian retains its independent lease after relay death and throughout helper EOF cleanup', onlyMac, async () => {
  await fixture(async ({ directory, binary }) => {
    const owned = await mkdtemp(path.join(directory, 'owned-guardian-'));
    assert.deepEqual(await runUpgradeFixture(binary, 'guardian', owned), {
      relayDeathBlocked: true, guardianTermBlocked: true, cleanupBlocked: true, releasedAfterExit: true,
    });
    assert.deepEqual(await readdir(owned), [], 'the ordinary permission fixture must not install or create runtime resources');
  }, { harness: guardianHarness });
});

const runtimePresenceHarness = `
#define main envara_installer_entry
#include AUTHORIZE_SOURCE
#undef main
int main(int argc,char **argv){
 if(argc==2&&!strcmp(argv[1],"native-ro")){
  int run=absolute_directory("/private/var/run",false);
  bool genericSafe=run>=0&&secure_root_object(run,true);if(run>=0)close(run);
  RuntimeInspection state=runtime_inspection();
  printf("{\\"legacyAbsent\\":%s,\\"currentRuntimeAbsent\\":%s,\\"privateInspectionRequired\\":%s,\\"genericRunSafe\\":%s}\\n",
   legacy_runtime_absent()?"true":"false",state==RUNTIME_VERIFIED_ABSENT?"true":"false",state==RUNTIME_PRIVATE_INSPECTION?"true":"false",genericSafe?"true":"false");
  return 0;
 }
 if(argc!=2)return 90;
 int parent=absolute_directory(argv[1],false);if(parent<0)return 91;
 printf("{\\"entryAbsent\\":%s,\\"empty\\":%s}\\n",fixed_entry_absent(parent,"envara-pf-routing")?"true":"false",directory_contents_empty(parent)?"true":"false");
 close(parent);return 0;
}
`;

test('production legacy presence probe refuses every existing entry and empty-runtime scan retains unknown evidence', onlyMac, async () => {
  await fixture(async ({ directory, binary }) => {
    for (const variant of ['absent', 'file', 'directory', 'dangling-symlink', 'unknown']) {
      const owned = await mkdtemp(path.join(directory, 'owned-runtime-presence-'));
      const entry = path.join(owned, 'envara-pf-routing');
      if (variant === 'file') await writeFile(entry, 'retain');
      if (variant === 'directory') await mkdir(entry);
      if (variant === 'dangling-symlink') await symlink('missing', entry);
      if (variant === 'unknown') await writeFile(path.join(owned, 'unknown-state'), 'retain');
      const result = JSON.parse((await exec(binary, [owned], { timeout: 10000 })).stdout);
      assert.equal(result.entryAbsent, ['absent', 'unknown'].includes(variant));
      assert.equal(result.empty, variant === 'absent');
      assert.equal((await readdir(owned)).length, variant === 'absent' ? 0 : 1, 'read-only probe must preserve all evidence');
    }
  }, { harness: runtimePresenceHarness });
});

const privateRuntimeHarness = `
#define main envara_installer_entry
#include AUTHORIZE_SOURCE
#undef main
int main(int argc,char **argv){
 if(argc!=2)return 90;
 int parent=absolute_directory(argv[1],false);if(parent<0)return 91;
 RuntimeInspection state=runtime_directory_inspection(parent,"current",false);
 printf("{\\"state\\":%d,\\"strictMutationAllowed\\":%s,\\"rootMetadataAccepted\\":%s}\\n",(int)state,
  state==RUNTIME_VERIFIED_ABSENT?"true":"false",runtime_directory_inspection(parent,"current",true)!=RUNTIME_REFUSED?"true":"false");
 close(parent);return 0;
}
`;

test('real unprivileged ACL-denied private runtime requires administrator inspection without claiming empty or permitting writes',
  { skip: process.platform !== 'darwin' || process.getuid?.() === 0 }, async () => {
  await fixture(async ({ directory, binary }) => {
    const parent = await mkdtemp(path.join(directory, 'private-runtime-')), runtime = path.join(parent, 'current');
    await mkdir(runtime, { mode: 0o700 });
    const inspect = async () => JSON.parse((await exec(binary, [parent], { timeout: 10000 })).stdout);
    assert.deepEqual(await inspect(), { state: 1, strictMutationAllowed: true, rootMetadataAccepted: false });
    await writeFile(path.join(runtime, 'unknown-evidence'), 'preserve unknown evidence');
    assert.deepEqual(await inspect(), { state: 0, strictMutationAllowed: false, rootMetadataAccepted: false });
    try {
      await exec('/bin/chmod', ['+a', `user:${userInfo().username} deny list`, runtime], { timeout: 10000 });
      await assert.rejects(readdir(runtime), { code: 'EACCES' }, 'the ordinary user must actually be unable to inspect this fixture');
      assert.deepEqual(await inspect(), { state: 2, strictMutationAllowed: false, rootMetadataAccepted: false });
    } finally { await exec('/bin/chmod', ['-N', runtime], { timeout: 10000 }); }
    assert.equal(await readFile(path.join(runtime, 'unknown-evidence'), 'utf8'), 'preserve unknown evidence');
    await chmod(runtime, 0o755);
    assert.deepEqual(await inspect(), { state: 0, strictMutationAllowed: false, rootMetadataAccepted: false });
    await rm(runtime, { recursive: true }); await symlink('missing', runtime);
    assert.deepEqual(await inspect(), { state: 0, strictMutationAllowed: false, rootMetadataAccepted: false });
  }, { harness: privateRuntimeHarness });
});

const receiptHarness = `
#define main envara_installer_entry
#include AUTHORIZE_SOURCE
#undef main
int main(int argc,char **argv){
 if(argc!=2)return 90;
 const char *sha=known_prior_receipt(argv[1]);json_string(sha);puts("");return 0;
}
`;
test('compiled prior receipt metadata accepts only one exact f8, e940, 518, 2a7, 832, ff9, 6f8, 199, 46a, c37, f99, 05d6, 14b87, dbcf, 43b, acfc, c34, 4b9f85, 43392e, f0b99f, f39101, a8bd00 or da6e7c hash and refuses unknown or conflicting claims', onlyMac, async () => {
  await fixture(async ({ binary }) => {
    const known = ['f8fce1d14566fdf822d220ef1a3469cbb815a37924c7ed709a1098729b8bed8b',
      'e940e171ac39624cd3cfeaea09234f4e8e035bfba141a843950cb0209e00db04',
      '518a75d94bac4f17d9e1ce60e842648ba6ff657a68cc62e95ce13718abda6d5a',
      '2a7f4ad635041c434b511034e9535b688cee8eeaebce97617586ad142db5f02d',
      '83256899dc6db90bb6a21dcd18d17cb08a46d3ba4e79177098629475cc107f78',
      'ff9f6a77bb8eeb105e35ce9b9bdd55f69d2995ab63d8f64f42b7004d7899951b',
      '6f8386e1586af12775c9aadd1de339568d29cf93dc4135d8de00b8661407026f',
      '199ff3f1e9b5c36a41f27903db0c592471516d35c44147803b3e09fc6bb29053',
      '46ae6acddd4f7b0a941bfbf6d6cc12aaedf59dd0c681b9aa440e72c38536d56b',
      'c37c49f9ca94b285d7b362ee4a42a01203d3632874d803e90ff38e48dd66c5e0',
      'f99aac934122ac3cafe992ac6fbf232ff917c1b8632034d19491b3dca7ab0d51',
      '05d6eb6ab3d63870d37825b47e2847789a6b5b8c3cf93c434636e0b8aad4f061',
      '14b87d3452af4acaf67709c2494d637163d108a101f6d07fb27ce8e61c2d1d50',
      'dbcf5262ae01da769a85d1f4c104b9f3402d3b54b69e7c6ff862ea871e85c56d',
      '43b392665e496cba2bc2675284fd2d03390ea92db85496d07e49ba696cd7c2a7',
      'acfc112b497c680001c7ce37dcdc99021b51de615072b15c096895900ecfa0c6',
      'c34cba313dad0712fc53eaea514d8466c6710eb70cc7840a1ca4238eea3817e4',
      '4b9f859585a10e31eb98d43682595a9e152b3f93439ebea6ef1de0a4659ba557',
      '43392e3095a921e1531d459a93d5d7329bfc5a28bab5192179eb1fc4fadd0fce',
      'f0b99f600185ecadd9c862fe826193a52e348cde3fb77d353ab5bd7471ab1bfc',
      'f39101dd94c622c886ca6709f2f13f8c826cdd1f3fe609112d5445ad2fd6f305',
      'a8bd008ae1b54f656e52ecba509e706811df386ac7a2b12bb269cd095fc74575',
      'da6e7c9714ec57781f68d875d131e9ee178adbaab401793a153ac7b216ceef05'];
    const inspect = async input => JSON.parse((await exec(binary, [input], { timeout: 10000 })).stdout);
    for (const sha of known) {
      assert.equal(await inspect(JSON.stringify({ priorManifestSHA256: sha })), sha);
      assert.equal(await inspect(JSON.stringify({ priorManifestSHA256: sha.slice(0, 63) + (sha.endsWith('0') ? '1' : '0') })), null);
    }
    assert.equal(await inspect(JSON.stringify({ priorManifestSHA256: '0'.repeat(64) })), null);
    assert.equal(await inspect(known.map(sha => JSON.stringify({ priorManifestSHA256: sha })).join('\n')), null);
    for (const other of known.slice(0, -1)) {
      for (const pair of [[other, known.at(-1)], [known.at(-1), other]])
        assert.equal(await inspect(pair.map(sha => JSON.stringify({ priorManifestSHA256: sha })).join('\n')), null,
          'a later prior may not override a conflicting older verified prior receipt');
    }
  }, { harness: receiptHarness });
});

test('actual stock macOS legacy parent is compatible only with the narrow read-only absence probe', onlyMac, async () => {
  await fixture(async ({ binary }) => {
    const exists = await lstat('/var/run/envara-pf-routing').then(() => true, error => {
      if (error.code === 'ENOENT') return false; throw error;
    });
    const result = JSON.parse((await exec(binary, ['native-ro'], { timeout: 15000 })).stdout);
    assert.equal(result.legacyAbsent, !exists, 'actual legacy entry absence is detected without opening or changing it');
    const parent = await lstat('/private/var/run');
    if ((parent.mode & 0o7777) === 0o775) assert.equal(result.genericRunSafe, false,
      'compatibility must not weaken generic privileged-directory checks');
    if (!exists) {
      const current = await lstat('/Library/PrivilegedHelperTools/io.envara.pf-runtime').catch(error => {
        if (error.code === 'ENOENT') return null; throw error;
      });
      if (current === null) assert.equal(result.currentRuntimeAbsent, true, 'current verified idle host has no runtime evidence');
    }
  }, { harness: runtimePresenceHarness });
});
