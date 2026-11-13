import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { buildClaudeKeychainResources, checkClaudeKeychainResources, claudeKeychainOutputDirectory } from '../scripts/build-macos-claude-keychain.mjs';

const execute = promisify(execFile);
const native = process.platform === 'darwin' && typeof process.getuid === 'function' && process.getuid() !== 0;
let root, executable, resourceDirectory;

before(async () => {
  if (!native) return;
  root = await mkdtemp(path.join(os.tmpdir(), 'envara-keychain-native-'));
  // macOS /var is a system alias; the production helper deliberately requires
  // canonical paths for the exact directories it is allowed to prepare.
  root = await (await import('node:fs/promises')).realpath(root);
  resourceDirectory = path.join(root, 'resources');
  await buildClaudeKeychainResources({ directory: resourceDirectory });
  executable = path.join(resourceDirectory, 'envara-claude-keychain');
});
after(async () => { if (root) await rm(root, { recursive: true, force: true }); });

async function fixture(t) {
  const directory = await mkdtemp(path.join(root, 'case-'));
  const source = path.join(directory, 'source'), target = path.join(directory, 'target');
  await mkdir(source, { mode: 0o700 }); await mkdir(target, { mode: 0o700 });
  t.after(() => rm(directory, { recursive: true, force: true }));
  return { directory, source, target };
}

async function run(target, source, args = ['prepare', '--home', target, '--host-home', source], binary = executable) {
  let result;
  try { result = { ...await execute(binary, args, { timeout: 30000, maxBuffer: 4096,
    env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: source } }), exitCode: 0 }; }
  catch (error) { if (typeof error.code !== 'number') throw error; result = { stdout: error.stdout, stderr: error.stderr, exitCode: error.code }; }
  assert.equal(result.stderr, '');
  const lines = result.stdout.trim().split('\n'); assert.equal(lines.length, 1);
  const reply = JSON.parse(lines[0]); assert.equal(reply.schemaVersion, 1);
  assert.ok(!result.stdout.includes(root), 'public reply does not expose source or target paths');
  return { ...reply, exitCode: result.exitCode };
}

test('keychain resource architecture is explicit', () => {
  assert.match(claudeKeychainOutputDirectory('arm64'), /darwin-arm64$/);
  assert.match(claudeKeychainOutputDirectory('x64'), /darwin-x64$/);
  assert.throws(() => claudeKeychainOutputDirectory('ia32'), { code: 'CLAUDE_KEYCHAIN_RESOURCE_INVALID' });
});

async function failureFixture(mode) {
  // Replace only the external Security-worker boundary in a disposable build.
  // The production preparation, exclusive publication, error retention, and
  // subsequent invocation paths execute unchanged. No real Keychain is used.
  const production = await readFile(new URL('../native/macos-claude-keychain/main.c', import.meta.url), 'utf8');
  const start = production.indexOf('static int run_worker('), end = production.indexOf('static int usable(', start);
  assert.ok(start > 0 && end > start);
  const injected = `static int run_worker(const char *self,enum mode mode,const char *home,const char *selected,struct reply *reply) {
    (void)self;(void)selected;memset(reply,0,sizeof(*reply));reply->schema=SCHEMA;
    char filename[PATH_MAX];snprintf(filename,sizeof(filename),"%s/Library/Preferences/" SELECTOR,home);
    if(mode==SELECT){FILE *file=fopen(filename,"w");if(!file)return -1;fputs("fixture-selector",file);return fclose(file);}
    const char *name=strrchr(home,'/');name=name?name+1:home;
    if(!strcmp(name,"source")){static int source_queries=0;if(source_queries++ && ${mode === 'host-check' ? '1' : '0'})return -1;}
    else if(access(filename,F_OK)){reply->status=errSecNoDefaultKeychain;return 0;}
    else if(!strcmp(name,"target") && ${mode === 'final-verify' ? '1' : '0'})return -1;
    reply->present=reply->user_present=reply->unlocked=reply->readable=reply->writable=1;
    strcpy(reply->selected,"/synthetic-owned-keychain");strcpy(reply->user_selected,reply->selected);return 0;
  }\n`;
  const sourcePath = path.join(root, `failure-${mode}.c`), binary = path.join(root, `failure-${mode}`);
  await writeFile(sourcePath, production.slice(0, start) + injected + production.slice(end), { flag: 'wx', mode: 0o600 });
  await execute('/usr/bin/clang', ['-Wno-deprecated-declarations', sourcePath, '-framework', 'Security', '-framework', 'CoreFoundation', '-o', binary], { timeout: 60000, maxBuffer: 65536 });
  return binary;
}

let metadataBinary;
async function metadataFixture() {
  if (metadataBinary) return metadataBinary;
  // Exercise the production metadata/path/list checks with synthetic Security
  // API replies. CFString objects stand in for Keychain references; only the
  // owned ordinary files below are inspected, never a real Keychain or item.
  const production = await readFile(new URL('../native/macos-claude-keychain/main.c', import.meta.url), 'utf8');
  const boundary = production.indexOf('static int key_path(');
  assert.ok(boundary > 0);
  const injected = `
static const char *fixture_mode;
static CFStringRef fixture_selected,fixture_user,fixture_other;
static unsigned fixture_status_calls;
static OSStatus fixture_copy_default(SecKeychainRef *key) {
    *key=NULL;
    if(!strcmp(fixture_mode,"both-missing")||!strcmp(fixture_mode,"current-missing"))return errSecNoDefaultKeychain;
    *key=(SecKeychainRef)CFRetain(fixture_selected);return 0;
}
static OSStatus fixture_copy_user_default(SecPreferencesDomain domain,SecKeychainRef *key) {
    *key=NULL;if(domain!=kSecPreferencesDomainUser)return errSecParam;
    if(!strcmp(fixture_mode,"both-missing")||!strcmp(fixture_mode,"user-missing"))return errSecNoDefaultKeychain;
    *key=(SecKeychainRef)CFRetain(!strcmp(fixture_mode,"different-user-default")?fixture_other:fixture_user);return 0;
}
static OSStatus fixture_key_path(SecKeychainRef key,UInt32 *length,char *path) {
    if(!CFStringGetCString((CFStringRef)key,path,*length,kCFStringEncodingUTF8))return errSecParam;
    *length=(UInt32)strlen(path);return 0;
}
static CFTypeID fixture_key_type(void) {return CFStringGetTypeID();}
static OSStatus fixture_key_status(SecKeychainRef key,SecKeychainStatus *flags) {
    (void)key;fixture_status_calls++;
    *flags=kSecUnlockStateStatus|kSecReadPermStatus|kSecWritePermStatus;
    if(fixture_status_calls==2&&!strcmp(fixture_mode,"user-locked"))*flags&=~kSecUnlockStateStatus;
    if(fixture_status_calls==2&&!strcmp(fixture_mode,"user-readonly"))*flags&=~kSecWritePermStatus;
    return 0;
}
static OSStatus fixture_merged_list(CFArrayRef *list) {
    const void *value=!strcmp(fixture_mode,"merged-excludes-selected")?(const void *)fixture_other:(const void *)fixture_selected;
    *list=CFArrayCreate(NULL,&value,1,&kCFTypeArrayCallBacks);return *list?0:errSecAllocate;
}
static OSStatus fixture_user_list(SecPreferencesDomain domain,CFArrayRef *list) {
    if(domain!=kSecPreferencesDomainUser)return errSecParam;
    const void *values[]={fixture_user,fixture_other};CFIndex count=1;
    if(!strcmp(fixture_mode,"empty-user-list"))count=0;
    else if(!strcmp(fixture_mode,"user-list-excludes-selected"))values[0]=fixture_other;
    else if(!strcmp(fixture_mode,"user-extra"))count=2;
    *list=CFArrayCreate(NULL,values,count,&kCFTypeArrayCallBacks);return *list?0:errSecAllocate;
}
#define SecKeychainCopyDefault fixture_copy_default
#define SecKeychainCopyDomainDefault fixture_copy_user_default
#define SecKeychainGetPath fixture_key_path
#define SecKeychainGetTypeID fixture_key_type
#define SecKeychainGetStatus fixture_key_status
#define SecKeychainCopySearchList fixture_merged_list
#define SecKeychainCopyDomainSearchList fixture_user_list
`;
  const main = `
int main(int argc,char **argv) {
    if(argc!=4)return 2;owner=getuid();fixture_mode=argv[1];
    fixture_selected=CFStringCreateWithCString(NULL,argv[2],kCFStringEncodingUTF8);
    fixture_user=CFStringCreateWithCString(NULL,argv[2],kCFStringEncodingUTF8);
    fixture_other=CFStringCreateWithCString(NULL,argv[3],kCFStringEncodingUTF8);
    if(!fixture_selected||!fixture_user||!fixture_other)return 2;
    int compare=!strcmp(fixture_mode,"user-list-change");
    if(compare)fixture_mode="ready";
    struct reply reply={0};metadata(&reply);int available=usable(&reply,"scoped-query"),same=-1;
    if(compare){struct reply after={0};fixture_mode="user-extra";fixture_status_calls=0;metadata(&after);
        same=same_selection(&reply,&after);if(usable(&after,"host-verify")!=1)return 2;}
    printf("{\\"osStatus\\":%d,\\"available\\":%d,\\"code\\":\\"%s\\",\\"userCount\\":%u,\\"sameSelection\\":%d}\\n",
        (int)reply.status,available,available<0?error_code:"",reply.user_count,same);
    CFRelease(fixture_selected);CFRelease(fixture_user);CFRelease(fixture_other);return 0;
}
`;
  const sourcePath = path.join(root, 'metadata-fixture.c'), binary = path.join(root, 'metadata-fixture');
  const source = (production.slice(0, boundary) + injected + production.slice(boundary)).replace('int main(int argc,char **argv)', 'int production_main(int argc,char **argv)');
  await writeFile(sourcePath, source + main, { flag: 'wx', mode: 0o600 });
  await execute('/usr/bin/clang', ['-Wno-deprecated-declarations', sourcePath, '-framework', 'Security', '-framework', 'CoreFoundation', '-o', binary], { timeout: 60000, maxBuffer: 65536 });
  metadataBinary = binary; return binary;
}

test('ready requires matching current/user defaults and membership in both search lists', { skip: !native }, async t => {
  const f = await fixture(t), binary = await metadataFixture();
  const selected = path.join(f.directory, 'selected.keychain-db'), other = path.join(f.directory, 'other.keychain-db');
  await writeFile(selected, 'synthetic file metadata only', { mode: 0o600 });
  await writeFile(other, 'synthetic file metadata only', { mode: 0o600 });
  const modes = [
    ['ready', 1, ''], ['both-missing', 0, ''],
    ...['user-missing', 'current-missing', 'different-user-default', 'empty-user-list', 'user-list-excludes-selected', 'merged-excludes-selected', 'user-readonly']
      .map(mode => [mode, -1, 'CLAUDE_KEYCHAIN_UNAVAILABLE']),
    ['user-locked', -1, 'CLAUDE_KEYCHAIN_LOCKED'], ['user-list-change', 1, ''],
  ];
  for (const [mode, available, code] of modes) await t.test(mode, async () => {
    const { stdout, stderr } = await execute(binary, [mode, selected, other], { timeout: 10000, maxBuffer: 4096,
      env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: f.source } });
    assert.equal(stderr, '');assert(!stdout.includes(f.directory));
    const reply = JSON.parse(stdout);
    assert.equal(reply.available, available);assert.equal(reply.code, code);
    if (mode === 'both-missing') assert.equal(reply.osStatus, -25307);
    if (mode === 'current-missing' || mode === 'user-missing') assert.notEqual(reply.osStatus, -25307, 'inconsistent domains are not safe first-use absence');
    if (mode === 'user-list-change') assert.equal(reply.sameSelection, 0, 'host verification detects a user-list change even when the current default and merged list stay unchanged');
  });
  assert.deepEqual(await readdir(f.source), []);assert.deepEqual(await readdir(f.target), []);
});

for (const mode of ['final-verify', 'host-check']) test(`published selector with ${mode} failure stays blocked on the next invocation`, { skip: !native }, async t => {
  const f = await fixture(t), binary = await failureFixture(mode);
  const first = await run(f.target, f.source, undefined, binary);
  assert.equal(first.exitCode, 1);
  assert.equal(first.code, mode === 'final-verify' ? 'CLAUDE_KEYCHAIN_PREPARATION_FAILED' : 'CLAUDE_KEYCHAIN_HOST_CHECK_FAILED');
  assert.equal(first.cleanupCode, 'CLAUDE_KEYCHAIN_CLEANUP_FAILED');
  if (mode === 'host-check') assert.equal(first.hostCheckCode, 'CLAUDE_KEYCHAIN_HOST_CHECK_FAILED');
  const selector = path.join(f.target, 'Library/Preferences/com.apple.security.plist');
  assert.equal(await readFile(selector, 'utf8'), 'fixture-selector');
  const retained = (await readdir(f.target)).filter(name => name.startsWith('.envara-keychain-'));
  assert.equal(retained.length, 1);
  const retry = await run(f.target, f.source, undefined, binary);
  assert.equal(retry.code, 'CLAUDE_KEYCHAIN_CLEANUP_FAILED');
  assert.equal(await readFile(selector, 'utf8'), 'fixture-selector');
  assert.deepEqual((await readdir(f.target)).filter(name => name.startsWith('.envara-keychain-')), retained);
  assert.deepEqual(await readdir(f.source), []);
});

test('built native resource matches source and rejects changed manifest bytes', { skip: !native }, async t => {
  const manifest = await checkClaudeKeychainResources(resourceDirectory);
  assert.equal(manifest.architecture, process.arch); assert.match(manifest.sha256, /^[a-f0-9]{64}$/);
  const manifestPath = path.join(resourceDirectory, 'manifest.json'), original = await readFile(manifestPath);
  t.after(() => writeFile(manifestPath, original));
  await writeFile(manifestPath, JSON.stringify({ ...manifest, sourceSha256: '0'.repeat(64) }));
  await assert.rejects(checkClaudeKeychainResources(resourceDirectory), { code: 'CLAUDE_KEYCHAIN_RESOURCE_INVALID' });
  await writeFile(manifestPath, original);
});

test('missing default in disposable source is explicit and preserves existing data', { skip: !native }, async t => {
  const f = await fixture(t); await writeFile(path.join(f.target, 'keep.json'), '{"fixture":true}', { mode: 0o600 });
  const reply = await run(f.target, f.source);
  assert.equal(reply.code, 'CLAUDE_KEYCHAIN_MISSING'); assert.equal(reply.osStatus, -25307); assert.equal(reply.exitCode, 1);
  assert.equal(await readFile(path.join(f.target, 'keep.json'), 'utf8'), '{"fixture":true}');
  await assert.rejects(lstat(path.join(f.target, 'Library/Preferences/com.apple.security.plist')), { code: 'ENOENT' });
  assert.deepEqual(await readdir(f.source), []);
  assert.ok(!(await readdir(f.target)).some(name => name.startsWith('.envara-keychain-')));
  // Advisory lock files have a version marker and are safe to reuse after the
  // owning process exits; they are not stale PID authority.
  const again = await run(f.target, f.source); assert.equal(again.code, 'CLAUDE_KEYCHAIN_MISSING');
});

test('target cannot be the source home or its ancestor', { skip: !native }, async t => {
  const f = await fixture(t);
  assert.equal((await run(f.source, f.source)).code, 'CLAUDE_KEYCHAIN_UNSAFE_PATH');
  assert.equal((await run(f.directory, f.source)).code, 'CLAUDE_KEYCHAIN_UNSAFE_PATH');
  assert.deepEqual(await readdir(f.source), []);
});

test('unsafe home and preference paths fail before any selector mutation', { skip: !native }, async t => {
  const f = await fixture(t), alias = path.join(f.directory, 'alias');
  await symlink(f.target, alias);
  assert.equal((await run(alias, f.source)).code, 'CLAUDE_KEYCHAIN_UNSAFE_PATH');
  await chmod(f.target, 0o755);
  assert.equal((await run(f.target, f.source)).code, 'CLAUDE_KEYCHAIN_UNSAFE_PATH');
  await chmod(f.target, 0o700);await symlink(f.source, path.join(f.target, 'Library'));
  assert.equal((await run(f.target, f.source)).code, 'CLAUDE_KEYCHAIN_UNSAFE_PATH');
  assert.deepEqual(await readdir(f.source), []);
});

test('unsafe or existing invalid selectors are preserved and never rebound', { skip: !native }, async t => {
  const f = await fixture(t), preferences = path.join(f.target, 'Library/Preferences');
  await mkdir(preferences, { recursive: true, mode: 0o700 });
  const selector = path.join(preferences, 'com.apple.security.plist'), original = Buffer.from('synthetic invalid selector');
  await writeFile(selector, original, { mode: 0o600 });
  const invalid = await run(f.target, f.source);
  assert.ok(['CLAUDE_KEYCHAIN_EXISTING_SELECTION', 'CLAUDE_KEYCHAIN_UNAVAILABLE'].includes(invalid.code));
  assert.deepEqual(await readFile(selector), original);
  await link(selector, path.join(f.directory, 'hardlink'));
  assert.equal((await run(f.target, f.source)).code, 'CLAUDE_KEYCHAIN_UNSAFE_PATH');
  assert.deepEqual(await readFile(selector), original);
});

test('extended ACLs on owned target directories are refused', { skip: !native }, async t => {
  const f = await fixture(t);
  await execute('/bin/chmod', ['+a', 'everyone allow write', f.target]);
  t.after(() => execute('/bin/chmod', ['-N', f.target]).catch(() => {}));
  assert.equal((await run(f.target, f.source)).code, 'CLAUDE_KEYCHAIN_UNSAFE_PATH');
});

test('unknown lock and retained preparation directory fail closed', { skip: !native }, async t => {
  const f = await fixture(t), lock = path.join(f.target, '.envara-keychain.lock');
  await writeFile(lock, 'not an Envara lock', { mode: 0o600 });
  assert.equal((await run(f.target, f.source)).code, 'CLAUDE_KEYCHAIN_UNSAFE_PATH');
  assert.equal(await readFile(lock, 'utf8'), 'not an Envara lock');
  await rm(lock); await mkdir(path.join(f.target, '.envara-keychain-retained'), { mode: 0o700 });
  assert.equal((await run(f.target, f.source)).code, 'CLAUDE_KEYCHAIN_CLEANUP_FAILED');
  assert.ok((await lstat(path.join(f.target, '.envara-keychain-retained'))).isDirectory());
});

test('invalid command returns bounded fixed diagnostics without echoing input', { skip: !native }, async t => {
  const f = await fixture(t), reply = await run(f.target, f.source, ['unexpected-private-argument']);
  assert.equal(reply.code, 'CLAUDE_KEYCHAIN_INVALID_ARGUMENT'); assert.equal(reply.stage, 'arguments');
});

test('native binary uses selector and metadata APIs without credential-item APIs', { skip: !native }, async () => {
  const { stdout } = await execute('/usr/bin/nm', ['-u', executable], { maxBuffer: 65536 });
  assert.match(stdout, /_SecKeychainCopyDefault/); assert.match(stdout, /_SecKeychainSetDefault/);
  assert.match(stdout, /_SecKeychainCopyDomainDefault/); assert.match(stdout, /_SecKeychainCopyDomainSearchList/);
  assert.doesNotMatch(stdout, /_SecItem(?:Add|Update|Delete|CopyMatching)|_SecKeychain(?:Create|Delete|Unlock|AddGenericPassword|FindGenericPassword)|_SecKeychainItem/);
});

test('internal worker refuses a normal caller before reading metadata', { skip: !native }, async () => {
  await assert.rejects(execute(executable, ['--worker'], { timeout: 3000, maxBuffer: 4096 }), error =>
    error.code === 2 && error.stdout === '' && error.stderr === '');
});
