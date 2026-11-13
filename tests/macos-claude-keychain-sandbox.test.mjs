import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { createServer } from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { chmod, link, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';

const execute = promisify(execFile);
const native = process.platform === 'darwin' && typeof process.getuid === 'function' && process.getuid() !== 0;
let root, binary;

before(async () => {
  if (!native) return;
  root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-keychain-policy-')));
  // Compile the production guards and profile generator unchanged. Only the OS
  // cache-directory lookup is replaced, so no test visits the real user MDS
  // cache or invokes a Security/Keychain API. All files and listeners are owned
  // disposable fixtures; the policy itself is enforced by the macOS kernel.
  const production = await readFile(new URL('../native/macos-claude-keychain/main.c', import.meta.url), 'utf8');
  const marker = '#include <time.h>';
  assert.equal(production.split(marker).length, 2);
  const injected = String.raw`
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
static const char *fixture_cache;
static size_t fixture_confstr(int name,char *buffer,size_t length) {
    if(name!=_CS_DARWIN_USER_CACHE_DIR||!strcmp(fixture_cache,"confstr-error"))return 0;
    if(!strcmp(fixture_cache,"confstr-overflow"))return PATH_MAX+1;
    if(!strcmp(fixture_cache,"confstr-unterminated")){memset(buffer,'x',length);return length;}
    size_t needed=strlen(fixture_cache)+1;
    if(length){size_t copied=needed<length?needed:length;memcpy(buffer,fixture_cache,copied);buffer[copied-1]=0;}
    return needed;
}
#define confstr fixture_confstr
`;
  const main = String.raw`
static int fixture_operation(const char *operation,const char *target,const char *other) {
    int fd=-1,result=-1;
    if(!strcmp(operation,"read")){char value;fd=open(target,O_RDONLY);if(fd>=0)result=read(fd,&value,1)==1?0:-1;}
    else if(!strcmp(operation,"write")){fd=open(target,O_WRONLY);if(fd>=0)result=write(fd,"changed",7)==7?0:-1;}
    else if(!strcmp(operation,"create")){fd=open(target,O_WRONLY|O_CREAT|O_EXCL,0600);if(fd>=0)result=write(fd,"created",7)==7?0:-1;}
    else if(!strcmp(operation,"lock")){fd=open(target,O_EXLOCK|O_NONBLOCK|O_CREAT|O_RDWR,0644);if(fd>=0)result=0;}
    else if(!strcmp(operation,"unlink"))return unlink(target);
    else if(!strcmp(operation,"rename"))return rename(target,other);
    else if(!strcmp(operation,"chmod"))return chmod(target,0644);
    else if(!strcmp(operation,"mkdir"))return mkdir(target,0700);
    else if(!strcmp(operation,"connect4")||!strcmp(operation,"connect6")){
        int family=!strcmp(operation,"connect4")?AF_INET:AF_INET6;
        fd=socket(family,SOCK_STREAM,0);if(fd<0)return -1;
        struct timeval timeout={2,0};setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
        if(family==AF_INET){struct sockaddr_in address={0};address.sin_family=AF_INET;
            address.sin_port=htons((uint16_t)atoi(target));address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
            result=connect(fd,(struct sockaddr*)&address,sizeof(address));
        }else {struct sockaddr_in6 address={0};address.sin6_family=AF_INET6;
            address.sin6_port=htons((uint16_t)atoi(target));address.sin6_addr=in6addr_loopback;
            result=connect(fd,(struct sockaddr*)&address,sizeof(address));}
    }else {errno=EINVAL;return -1;}
    int saved=errno;if(fd>=0)close(fd);errno=saved;return result;
}
int main(int argc,char **argv) {
    if(argc!=7)return 2;
    owner=getuid();fixture_cache=argv[2];
    if(!strcmp(argv[4],"other-owner"))owner++;
    struct mds_cache cache;mds_cache_init(&cache);
    int opened=mds_cache_open(argv[3],&cache);
    if(!strcmp(argv[1],"guard")){
        int mutation=0;
        if(!opened&&strcmp(argv[4],"inspect")&&strcmp(argv[4],"other-owner")){
            if(!strcmp(argv[4],"replace-directory")){mutation=rename(argv[5],argv[6]);if(!mutation)mutation=mkdir(argv[5],0700);}
            else if(!strcmp(argv[4],"replace-file"))mutation=rename(argv[5],argv[6]);
            else if(!strcmp(argv[4],"add-symlink"))mutation=symlink(argv[6],argv[5]);
            else if(!strcmp(argv[4],"add-hardlink")||!strcmp(argv[4],"selection-hardlink"))mutation=link(argv[6],argv[5]);
            else if(!strcmp(argv[4],"make-writable"))mutation=chmod(argv[5],0666);
            else if(!strcmp(argv[4],"add-directory"))mutation=mkdir(argv[5],0700);
            else return 2;
        }
        int matches=!opened&&mds_cache_matches(&cache);
        int selected=!opened&&mds_selection_safe(&cache,!strcmp(argv[4],"selection-hardlink")?argv[5]:argv[6]);
        printf("{\"opened\":%d,\"enabled\":%s,\"matches\":%s,\"selectionSafe\":%s,\"mutation\":%d}\n",
            opened,cache.directory.fd>=0?"true":"false",matches?"true":"false",selected?"true":"false",mutation);
        mds_cache_release(&cache);return 0;
    }
    if(opened){mds_cache_release(&cache);return 3;}
    if(strcmp(argv[1],"control")){
        char profile[PATH_MAX*8+2048];
        enum mode mode=!strcmp(argv[1],"select")?SELECT:QUERY;
        if(worker_profile(profile,sizeof(profile),mode,argv[3],cache.directory.fd>=0?cache.directory_path:NULL))return 4;
        char *error=NULL;if(sandbox_init(profile,0,&error)){if(error)sandbox_free_error(error);return 5;}
        if(error)sandbox_free_error(error);
    }
    errno=0;int result=fixture_operation(argv[4],argv[5],argv[6]),saved=errno;
    int matches=mds_cache_matches(&cache);
    printf("{\"result\":%d,\"error\":%d,\"matches\":%s}\n",result,result<0?saved:0,matches?"true":"false");
    mds_cache_release(&cache);return 0;
}
`;
  const source = production.replace(marker, marker + injected).replace('int main(int argc,char **argv)', 'int production_main(int argc,char **argv)') + main;
  const sourcePath = path.join(root, 'policy-fixture.c'); binary = path.join(root, 'policy-fixture');
  await writeFile(sourcePath, source, { flag: 'wx', mode: 0o600 });
  await execute('/usr/bin/clang', ['-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', sourcePath,
    '-framework', 'Security', '-framework', 'CoreFoundation', '-o', binary], { timeout: 60000, maxBuffer: 65536 });
});

after(async () => { if (root) await rm(root, { recursive: true, force: true }); });

async function fixture(t) {
  const directory = await mkdtemp(path.join(root, 'case-'));
  const cache = path.join(directory, 'cache'), mds = path.join(cache, 'mds'), home = path.join(directory, 'home');
  for (const name of [cache, mds, home]) await mkdir(name, { mode: 0o700 });
  const selector = path.join(home, 'Library/Preferences/com.apple.security.plist');
  await mkdir(path.dirname(selector), { recursive: true, mode: 0o700 });
  await writeFile(selector, 'synthetic selector', { mode: 0o600 });
  for (const name of ['mds.lock', 'mdsObject.db', 'mdsDirectory.db']) await writeFile(path.join(mds, name), 'synthetic cache', { mode: name === 'mds.lock' ? 0o644 : 0o600 });
  const protectedFile = path.join(directory, 'source-keychain-fixture');
  await writeFile(protectedFile, 'synthetic protected data', { mode: 0o600 });
  t.after(() => rm(directory, { recursive: true, force: true }));
  return { directory, cache, mds, home, selector, protectedFile };
}

async function run(f, { mode = 'query', action = 'read', target = f.protectedFile, other = f.protectedFile, cache = f.cache, home = f.home } = {}) {
  const { stdout, stderr } = await execute(binary, [mode, cache, home, action, target, other], {
    timeout: 10000, maxBuffer: 4096, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: f.home },
  });
  assert.equal(stderr, ''); assert(!stdout.includes(root));
  return JSON.parse(stdout);
}

const denied = reply => {
  assert.equal(reply.result, -1);
  assert([1, 13].includes(reply.error), `Expected sandbox EPERM/EACCES, received errno ${reply.error}`);
};

test('production worker policy permits named MDS maintenance and retains the cache guard', { skip: !native }, async t => {
  for (const mode of ['query', 'select']) await t.test(mode, async t => {
    const f = await fixture(t);
    assert.equal((await run(f, { mode, action: 'read' })).result, 0);
    assert.equal((await run(f, { mode, action: 'lock', target: path.join(f.mds, 'mds.lock') })).result, 0);
    for (const name of ['mdsObject.db', 'mdsDirectory.db']) {
      const target = path.join(f.mds, name), temporary = `${target}_`;
      assert.equal((await run(f, { mode, action: 'unlink', target })).result, 0);
      assert.equal((await run(f, { mode, action: 'create', target: temporary })).result, 0);
      const renamed = await run(f, { mode, action: 'rename', target: temporary, other: target });
      assert.equal(renamed.result, 0); assert.equal(renamed.matches, true, 'Safe database replacement is legitimate cache maintenance.');
      assert.equal(await readFile(target, 'utf8'), 'created');
    }
    const written = await run(f, { mode, action: 'write', target: f.selector });
    if (mode === 'select') assert.equal(written.result, 0); else denied(written);
  });
});

test('production worker policy refuses all sibling, host-data, and lock metadata mutations', { skip: !native }, async t => {
  for (const mode of ['query', 'select']) await t.test(mode, async t => {
    const f = await fixture(t), sibling = path.join(f.mds, 'unrelated-file'), nested = path.join(f.mds, 'nested');
    await writeFile(sibling, 'synthetic sibling', { mode: 0o600 }); await mkdir(nested, { mode: 0o700 });
    const nestedFile = path.join(nested, 'mdsObject.db'); await writeFile(nestedFile, 'synthetic nested', { mode: 0o600 });
    for (const target of [f.protectedFile, sibling, nestedFile, path.join(f.home, 'Library/Preferences/not-the-selector')]) {
      if (target.endsWith('not-the-selector')) await writeFile(target, 'synthetic preferences', { mode: 0o600 });
      for (const action of ['write', 'unlink', 'chmod']) denied(await run(f, { mode, action, target }));
    }
    for (const target of [path.join(f.cache, 'outside-mds'), path.join(f.mds, 'unknown.db'), path.join(f.mds, 'mdsObject.db_extra'), path.join(nested, 'new')])
      denied(await run(f, { mode, action: 'create', target }));
    denied(await run(f, { mode, action: 'mkdir', target: path.join(f.mds, 'new-directory') }));
    const lock = path.join(f.mds, 'mds.lock');
    for (const action of ['unlink', 'chmod']) denied(await run(f, { mode, action, target: lock }));
    denied(await run(f, { mode, action: 'rename', target: lock, other: path.join(f.mds, 'renamed-lock') }));
    denied(await run(f, { mode, action: 'rename', target: path.join(f.mds, 'mdsObject.db'), other: sibling }));
    assert.equal(await readFile(f.protectedFile, 'utf8'), 'synthetic protected data');
    assert.equal(await readFile(sibling, 'utf8'), 'synthetic sibling');
    assert.equal(await readFile(nestedFile, 'utf8'), 'synthetic nested');
  });
});

test('empty MDS cache can create only its exact lock while an absent MDS directory remains absent', { skip: !native }, async t => {
  for (const mode of ['query', 'select']) await t.test(mode, async t => {
    const f = await fixture(t);
    for (const name of await readdir(f.mds)) await rm(path.join(f.mds, name));
    const lock = path.join(f.mds, 'mds.lock');
    const created = await run(f, { mode, action: 'lock', target: lock });
    assert.equal(created.result, 0); assert.equal(created.matches, true);
    assert.deepEqual(await readdir(f.mds), ['mds.lock']); assert.equal((await readFile(lock)).length, 0);
    denied(await run(f, { mode, action: 'lock', target: path.join(f.mds, 'another.lock') }));
    denied(await run(f, { mode, action: 'unlink', target: lock }));
    await rm(f.mds, { recursive: true });
    denied(await run(f, { mode, action: 'mkdir', target: f.mds }));
    const missing = await run(f, { mode, action: 'lock', target: lock });
    assert.equal(missing.result, -1); assert([1, 2, 13].includes(missing.error));
    await assert.rejects(readdir(f.mds), { code: 'ENOENT' });
  });
});

test('production worker policy still refuses IPv4 and IPv6 TCP with owned positive controls', { skip: !native }, async t => {
  for (const [host, action] of [['127.0.0.1', 'connect4'], ['::1', 'connect6']]) await t.test(host, async t => {
    const f = await fixture(t); let accepted = 0;
    const server = createServer(socket => { accepted += 1; socket.destroy(); });
    t.after(() => new Promise(resolve => server.close(resolve)));
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, host, resolve); });
    const target = String(server.address().port);
    assert.equal((await run(f, { mode: 'control', action, target })).result, 0);
    await new Promise(resolve => setImmediate(resolve)); assert.equal(accepted, 1);
    for (const mode of ['query', 'select']) denied(await run(f, { mode, action, target }));
    await new Promise(resolve => setImmediate(resolve)); assert.equal(accepted, 1);
  });
});

test('MDS guard accepts canonical system aliases and safe database replacement', { skip: !native }, async t => {
  const f = await fixture(t);
  for (const cache of [f.cache, `${f.cache}/`, `${f.cache.replace(/^\/private\/var\//, '/var/')}/`]) {
    const checked = await run(f, { mode: 'guard', action: 'inspect', cache });
    assert.equal(checked.opened, 0); assert.equal(checked.enabled, true); assert.equal(checked.matches, true); assert.equal(checked.selectionSafe, true);
  }
  const temporary = path.join(f.mds, 'mdsObject.db_'); await writeFile(temporary, 'safe replacement', { mode: 0o600 });
  const replaced = await run(f, { mode: 'guard', action: 'replace-file', target: temporary, other: path.join(f.mds, 'mdsObject.db') });
  assert.equal(replaced.opened, 0); assert.equal(replaced.mutation, 0); assert.equal(replaced.matches, true);
  assert.equal(replaced.selectionSafe, false, 'A selected vault cannot be one of the writable cache files.');
  const alias = await run(f, { mode: 'guard', action: 'selection-hardlink', target: path.join(f.directory, 'selected-alias'), other: path.join(f.mds, 'mdsObject.db') });
  assert.equal(alias.mutation, 0); assert.equal(alias.selectionSafe, false);
  assert.equal(alias.matches, false, 'An external hardlink must not turn cache write authority into vault write authority.');
});

test('MDS guard refuses unsafe cache paths and files without modifying them', { skip: !native }, async t => {
  const cases = ['cache-symlink', 'mds-symlink', 'cache-mode', 'mds-mode', 'cache-acl', 'mds-acl', 'file-acl', 'other-owner', 'file-symlink', 'file-hardlink', 'file-mode', 'file-directory', 'home-inside-cache', 'home-above-cache', 'confstr-error', 'confstr-overflow', 'confstr-unterminated'];
  for (const kind of cases) await t.test(kind, async t => {
    const f = await fixture(t); let cache = f.cache, home = f.home;
    const database = path.join(f.mds, 'mdsObject.db');
    if (kind === 'cache-symlink') { cache = path.join(f.directory, 'alias'); await symlink(f.cache, cache); }
    if (kind === 'mds-symlink') { const other = path.join(f.directory, 'other-mds'); await mkdir(other, { mode: 0o700 }); await rm(f.mds, { recursive: true }); await symlink(other, f.mds); }
    if (kind === 'cache-mode') await chmod(f.cache, 0o755);
    if (kind === 'mds-mode') await chmod(f.mds, 0o755);
    if (kind.endsWith('-acl')) await execute('/bin/chmod', ['+a', 'everyone allow read', kind === 'cache-acl' ? f.cache : kind === 'mds-acl' ? f.mds : database]);
    if (kind === 'file-symlink') { await rm(database); await symlink(f.protectedFile, database); }
    if (kind === 'file-hardlink') { await rm(database); await link(f.protectedFile, database); }
    if (kind === 'file-mode') await chmod(database, 0o666);
    if (kind === 'file-directory') { await rm(database); await mkdir(database, { mode: 0o700 }); }
    if (kind === 'home-inside-cache') home = f.mds;
    if (kind === 'home-above-cache') home = f.directory;
    if (kind.startsWith('confstr-')) cache = kind;
    const checked = await run(f, { mode: 'guard', action: kind === 'other-owner' ? kind : 'inspect', cache, home });
    assert.equal(checked.opened, -1);
    assert.equal(await readFile(f.protectedFile, 'utf8'), 'synthetic protected data');
  });
});

test('MDS guard preserves missing paths and detects a directory or unsafe-file change', { skip: !native }, async t => {
  for (const kind of ['missing-cache', 'missing-mds', 'missing-files', 'missing-mds-created', 'replace-cache', 'replace-mds', 'add-symlink', 'add-hardlink', 'make-writable']) await t.test(kind, async t => {
    const f = await fixture(t); let action = 'inspect', target = f.protectedFile, other = f.protectedFile;
    if (kind === 'missing-cache') await rm(f.cache, { recursive: true });
    if (kind === 'missing-mds') await rm(f.mds, { recursive: true });
    if (kind === 'missing-files') for (const name of await readdir(f.mds)) await rm(path.join(f.mds, name));
    if (kind === 'missing-mds-created') { await rm(f.mds, { recursive: true }); action = 'add-directory'; target = f.mds; }
    if (kind === 'replace-cache' || kind === 'replace-mds') { action = 'replace-directory'; target = kind === 'replace-cache' ? f.cache : f.mds; other = `${target}-old`; }
    if (kind === 'add-symlink' || kind === 'add-hardlink') { action = kind; target = path.join(f.mds, 'mdsObject.db_'); }
    if (kind === 'make-writable') { action = kind; target = path.join(f.mds, 'mdsObject.db'); }
    const checked = await run(f, { mode: 'guard', action, target, other });
    assert.equal(checked.opened, 0); assert.equal(checked.mutation, 0);
    assert.equal(checked.matches, ['missing-cache', 'missing-mds', 'missing-files'].includes(kind));
    if (kind === 'missing-cache') await assert.rejects(readdir(f.cache), { code: 'ENOENT' });
    if (kind === 'missing-mds') await assert.rejects(readdir(f.mds), { code: 'ENOENT' });
    if (kind === 'missing-files') assert.deepEqual(await readdir(f.mds), []);
  });
});
