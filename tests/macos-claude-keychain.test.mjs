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
    reply->present=reply->unlocked=reply->readable=reply->writable=1;
    strcpy(reply->selected,"/synthetic-owned-keychain");return 0;
  }\n`;
  const sourcePath = path.join(root, `failure-${mode}.c`), binary = path.join(root, `failure-${mode}`);
  await writeFile(sourcePath, production.slice(0, start) + injected + production.slice(end), { flag: 'wx', mode: 0o600 });
  await execute('/usr/bin/clang', ['-Wno-deprecated-declarations', sourcePath, '-framework', 'Security', '-framework', 'CoreFoundation', '-o', binary], { timeout: 60000, maxBuffer: 65536 });
  return binary;
}

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
  assert.doesNotMatch(stdout, /_SecItem(?:Add|Update|Delete|CopyMatching)|_SecKeychain(?:Create|Delete|Unlock|AddGenericPassword|FindGenericPassword)|_SecKeychainItem/);
});

test('internal worker refuses a normal caller before reading metadata', { skip: !native }, async () => {
  await assert.rejects(execute(executable, ['--worker'], { timeout: 3000, maxBuffer: 4096 }), error =>
    error.code === 2 && error.stdout === '' && error.stderr === '');
});
