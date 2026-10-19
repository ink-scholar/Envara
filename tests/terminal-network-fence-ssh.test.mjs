import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { chmod, link, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { TerminalNetworkFence, TERMINAL_FENCE_EXECUTABLE, terminalFenceProfile } from '../electron/terminal-network-fence.mjs';

const execute = promisify(execFile);
const onlyMac = { skip: process.platform !== 'darwin', timeout: 45000 };
const validProtection = () => ({ protectedPaths: ['/owned/store', '/owned/agents'], agentRoot: '/owned/agents',
  agentSocket: '/owned/agents/a/agent.sock', readablePaths: ['/owned/agents/a/public'],
  readOnlyPaths: ['/owned/agents/a/public'], deniedAgentSockets: ['/owned/host-agent.sock'] });
const refused = { code: 'TERMINAL_SSH_PROTECTION_UNAVAILABLE' };

test('SSH protection rejects malformed or cross-session public paths before launch', () => {
  for (const value of [false, [], {},
    { ...validProtection(), protectedPaths: ['/owned/store'] },
    { ...validProtection(), readablePaths: ['/other/public'] },
    { ...validProtection(), agentSocket: '/other/agent.sock' },
    { ...validProtection(), deniedAgentSockets: ['/owned/agents/a/agent.sock'] },
    { ...validProtection(), protectedPaths: ['/owned/agents', '/owned/../store'] },
    { ...validProtection(), readOnlyPaths: ['relative'] },
    { ...validProtection(), deniedAgentSockets: ['/owned/agent\n.sock'] },
    { ...validProtection(), readablePaths: Array(257).fill('/owned/agents/a/public') },
  ]) assert.throws(() => terminalFenceProfile({ sshProtection: value }), refused);
});

test('SSH wrapping preflights the combined profile and never returns authority after failure', async () => {
  const calls = [], shell = { executable: '/bin/zsh', args: ['-d', '-i'], environment: {} };
  const fence = new TerminalNetworkFence({ platform: 'darwin', environment: {},
    inspect: async () => ({ isFile: () => true, isSymbolicLink: () => false, uid: 0, mode: 0o100755 }),
    execute: async (...args) => { calls.push(args); return { stdout: '' }; } });
  const wrapped = await fence.wrap(shell, { routePort: 50000, sshProtection: validProtection(), restrictDeviceIdentifiers: true });
  assert.equal(wrapped.sshPrivateKeyProtection, true);
  assert.equal(wrapped.deviceIdentifierRestrictions, true);
  assert.deepEqual(calls.map(call => call[0]), ['/usr/sbin/scutil', TERMINAL_FENCE_EXECUTABLE]);
  assert.deepEqual(calls[1][1], ['-p', wrapped.args[1], '/usr/bin/true']);
  assert.deepEqual(wrapped.args.slice(2), [shell.executable, ...shell.args]);
  fence.execute = async executable => {
    if (executable === '/usr/sbin/scutil') return { stdout: '' };
    throw Object.assign(new Error('owned fixture diagnostic'), { stderr: 'owned fixture path', code: 'ETIMEDOUT' });
  };
  await assert.rejects(fence.wrap(shell, { routePort: 50000, sshProtection: validProtection() }), error => {
    assert.equal(error.code, refused.code);
    assert.equal(error.stderr, undefined);
    assert.doesNotMatch(error.message, /fixture|ETIMEDOUT/);
    return true;
  });
});

const listen = async (address, peers) => {
  const server = net.createServer(socket => {
    peers.add(socket); socket.once('close', () => peers.delete(socket));
    socket.end('owned-fixture');
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(address, resolve); });
  return server;
};

// Every path and socket is disposable and owned by this test. No host SSH file,
// agent, public Internet endpoint or actual key material is inspected.
test('real Seatbelt confines SSH files and agent sockets while preserving network and device restrictions', onlyMac, async t => {
  const directory = await realpath(await mkdtemp('/private/tmp/envara-ssh-fence-'));
  const peers = new Set(), servers = [];
  t.after(async () => {
    for (const socket of peers) socket.destroy();
    await Promise.all(servers.map(server => new Promise(resolve => server.close(resolve))));
    await rm(directory, { recursive: true, force: true });
  });
  const filename = relative => path.join(directory, relative);
  for (const relative of ['store', 'host-ssh', 'agents/a/public', 'agents/b/public', 'scratch']) {
    await mkdir(filename(relative), { recursive: true, mode: 0o700 });
  }
  const files = { privateKey: filename('host-ssh/id_fixture'), store: filename('store/encrypted.fixture'),
    publicConfig: filename('agents/a/public/config'), otherConfig: filename('agents/b/public/config'),
    symlinkAlias: filename('scratch/key-symlink'),
    scratch: filename('scratch/write-control'), newHardlink: filename('scratch/new-key-hardlink'),
    protectedLink: filename('store/new-symlink'), publicNewFile: filename('agents/a/public/new-file') };
  const privateContents = 'DISPOSABLE-FAKE-PRIVATE-KEY\n', storeContents = 'DISPOSABLE-FAKE-STORE\n';
  await writeFile(files.privateKey, privateContents, { mode: 0o600 });
  await writeFile(files.store, storeContents, { mode: 0o600 });
  await writeFile(files.publicConfig, 'Host owned-fixture\n  HostName reserved.invalid\n', { mode: 0o600 });
  await writeFile(files.otherConfig, 'Host other-fixture\n', { mode: 0o600 });
  await chmod(filename('agents/a/public'), 0o700);
  await symlink(files.privateKey, files.symlinkAlias);
  const sockets = { own: filename('agents/a/agent.sock'), other: filename('agents/b/agent.sock'), host: filename('host-agent.sock') };
  for (const socket of Object.values(sockets)) servers.push(await listen(socket, peers));
  const loopback = await listen({ host: '127.0.0.1', port: 0 }, peers); servers.push(loopback);
  const protection = { protectedPaths: [filename('store'), filename('host-ssh'), filename('agents')],
    agentRoot: filename('agents'), agentSocket: sockets.own, readablePaths: [filename('agents/a/public')],
    readOnlyPaths: [filename('agents/a/public')], deniedAgentSockets: [sockets.host] };
  const profile = terminalFenceProfile({ sshProtection: protection, restrictDeviceIdentifiers: true });
  const options = { timeout: 12000, maxBuffer: 16384,
    env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' } };
  await execute(TERMINAL_FENCE_EXECUTABLE, ['-p', profile, '/usr/bin/true'], options);
  const probe = `const fs=require('node:fs'),net=require('node:net');
    const files=${JSON.stringify(files)},sockets=${JSON.stringify(sockets)};
    const check=operation=>{try{operation();return {ok:true,denied:false};}catch(error){return {ok:false,denied:['EPERM','EACCES'].includes(error.code)};}};
    const connect=address=>new Promise(resolve=>{let done=false;const socket=net.connect(address);const finish=value=>{if(done)return;done=true;clearTimeout(timer);socket.destroy();resolve(value);};
      const timer=setTimeout(()=>finish({ok:false,denied:false}),1500);socket.once('data',()=>finish({ok:true,denied:false}));socket.once('error',error=>finish({ok:false,denied:['EPERM','EACCES'].includes(error.code)}));});
    (async()=>{const result={
      privateRead:check(()=>fs.readFileSync(files.privateKey)),privateWrite:check(()=>fs.appendFileSync(files.privateKey,'x')),
      storeRead:check(()=>fs.readFileSync(files.store)),storeWrite:check(()=>fs.appendFileSync(files.store,'x')),
      symlinkRead:check(()=>fs.readFileSync(files.symlinkAlias)),symlinkWrite:check(()=>fs.appendFileSync(files.symlinkAlias,'x')),
      createHardlink:check(()=>fs.linkSync(files.privateKey,files.newHardlink)),protectedSymlink:check(()=>fs.symlinkSync(files.scratch,files.protectedLink)),
      publicRead:check(()=>fs.readFileSync(files.publicConfig)),publicWrite:check(()=>fs.appendFileSync(files.publicConfig,'x')),
      publicCreate:check(()=>fs.writeFileSync(files.publicNewFile,'x')),otherPublicRead:check(()=>fs.readFileSync(files.otherConfig)),
      scratchWrite:check(()=>fs.writeFileSync(files.scratch,'owned-fixture')),
      ownAgent:await connect(sockets.own),otherAgent:await connect(sockets.other),hostAgent:await connect(sockets.host),
      loopback:await connect({host:'127.0.0.1',port:${loopback.address().port}}),direct:await connect({host:'203.0.113.1',port:443})};
      console.log(JSON.stringify(result));})();`;
  const baselineProbe = `const fs=require('node:fs'),net=require('node:net');
    const connect=address=>new Promise(resolve=>{const socket=net.connect(address);const timer=setTimeout(()=>{socket.destroy();resolve(false);},1500);socket.once('data',()=>{clearTimeout(timer);socket.destroy();resolve(true);});socket.once('error',()=>{clearTimeout(timer);resolve(false);});});
    (async()=>console.log(JSON.stringify({privateReadable:fs.readFileSync(${JSON.stringify(files.privateKey)},'utf8')===${JSON.stringify(privateContents)},
      storeReadable:fs.readFileSync(${JSON.stringify(files.store)},'utf8')===${JSON.stringify(storeContents)},
      publicReadable:fs.readFileSync(${JSON.stringify(files.publicConfig)}).length>0,
      ownAgent:await connect(${JSON.stringify(sockets.own)}),otherAgent:await connect(${JSON.stringify(sockets.other)}),hostAgent:await connect(${JSON.stringify(sockets.host)})})))();`;
  const baseline = JSON.parse((await execute(process.execPath, ['-e', baselineProbe], options)).stdout);
  assert.deepEqual(baseline, { privateReadable: true, storeReadable: true, publicReadable: true, ownAgent: true, otherAgent: true, hostAgent: true });
  const allowed = { ok: true, denied: false }, denied = { ok: false, denied: true };
  const expected = Object.fromEntries(['privateRead', 'privateWrite', 'storeRead', 'storeWrite', 'symlinkRead', 'symlinkWrite',
    'createHardlink', 'protectedSymlink', 'publicWrite', 'publicCreate', 'otherPublicRead',
    'otherAgent', 'hostAgent', 'direct'].map(key => [key, denied]));
  Object.assign(expected, { publicRead: allowed, scratchWrite: allowed, ownAgent: allowed, loopback: allowed });
  const observations = [];
  for (const child of [false, true]) {
    const command = child ? ['/bin/sh', '-c', 'exec "$1" -e "$2"', 'owned-ssh-fence-child', process.execPath, probe] : [process.execPath, '-e', probe];
    const result = JSON.parse((await execute(TERMINAL_FENCE_EXECUTABLE, ['-p', profile, ...command], options)).stdout);
    // Values are booleans only; neither fake file contents nor addresses are printed.
    observations.push(result);
  }
  assert.deepEqual(observations, [expected, expected], 'direct and exec child preserve every file/socket/network boundary');
  assert.equal(await readFile(files.privateKey, 'utf8'), privateContents);
  assert.equal(await readFile(files.store, 'utf8'), storeContents);
});

// Path rules do not discover hardlinks that already exist outside protected
// paths. Managed-key selection/session validation must independently enforce
// nlink===1. This is a measured boundary, not a claim of all-key isolation.
test('real Seatbelt characterizes a preexisting outside hardlink and still denies creating a new one', onlyMac, async t => {
  const directory = await realpath(await mkdtemp('/private/tmp/envara-ssh-alias-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(path.join(directory, 'agents'), { mode: 0o700 });
  await mkdir(path.join(directory, 'store'), { mode: 0o700 });
  const key = path.join(directory, 'store/key.fixture'), alias = path.join(directory, 'outside-hardlink'),
    newAlias = path.join(directory, 'new-hardlink');
  await writeFile(key, 'DISPOSABLE-FAKE-KEY', { mode: 0o600 });
  await link(key, alias);
  const profile = terminalFenceProfile({ restrictDeviceIdentifiers: true, sshProtection: {
    protectedPaths: [path.join(directory, 'store'), path.join(directory, 'agents')], agentRoot: path.join(directory, 'agents'),
    readablePaths: [], readOnlyPaths: [], deniedAgentSockets: [],
  } });
  const program = `const fs=require('node:fs');const check=f=>{try{f();return true;}catch{return false;}};
    console.log(JSON.stringify({protectedRead:check(()=>fs.readFileSync(${JSON.stringify(key)})),
      protectedWrite:check(()=>fs.appendFileSync(${JSON.stringify(key)},'x')),
      preexistingAliasRead:check(()=>fs.readFileSync(${JSON.stringify(alias)})),
      preexistingAliasWrite:check(()=>fs.appendFileSync(${JSON.stringify(alias)},'x')),
      createNewAlias:check(()=>fs.linkSync(${JSON.stringify(key)},${JSON.stringify(newAlias)}))}));`;
  const result = JSON.parse((await execute(TERMINAL_FENCE_EXECUTABLE, ['-p', profile, process.execPath, '-e', program], {
    timeout: 10000, maxBuffer: 4096, env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' },
  })).stdout);
  assert.deepEqual(result, { protectedRead: false, protectedWrite: false,
    preexistingAliasRead: true, preexistingAliasWrite: true, createNewAlias: false });
});


test('production SSH target reader traverses own public ancestors without gaining directory or cross-session reads', onlyMac, async t => {
  const directory = await realpath(await mkdtemp('/private/tmp/envara-ssh-targets-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const agentRoot = path.join(directory, 'agents'), session = path.join(agentRoot, 'a'),
    publicDirectory = path.join(session, 'public'), other = path.join(agentRoot, 'b'),
    otherFile = path.join(other, 'private.fixture'), helper = path.join(publicDirectory, 'proxy.mjs'),
    targetsFile = path.join(publicDirectory, 'targets.json');
  await mkdir(publicDirectory, { recursive: true, mode: 0o700 });
  await mkdir(other, { mode: 0o700 });
  // Byte-for-byte standalone production helper, in its actual public layout.
  await writeFile(helper, await readFile(new URL('../electron/terminal-ssh-proxy.mjs', import.meta.url)), { mode: 0o400 });
  const targets = [{ host: 'ssh-fixture.invalid', port: 2222 }];
  await writeFile(targetsFile, JSON.stringify(targets), { mode: 0o400 });
  await writeFile(otherFile, 'DISPOSABLE-OTHER-SESSION', { mode: 0o600 });
  const profile = terminalFenceProfile({ restrictDeviceIdentifiers: true, sshProtection: {
    agentRoot, protectedPaths: [agentRoot], readablePaths: [publicDirectory], readOnlyPaths: [publicDirectory],
  } });
  const options = { timeout: 10000, maxBuffer: 4096, env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' } };
  const reader = `import {readSshTargets} from ${JSON.stringify(pathToFileURL(helper).href)};
    const targets=await readSshTargets(${JSON.stringify(targetsFile)});
    console.log(JSON.stringify({matched:JSON.stringify(targets)===${JSON.stringify(JSON.stringify(targets))}}));`;
  assert.deepEqual(JSON.parse((await execute(process.execPath, ['--input-type=module', '-e', reader], options)).stdout), { matched: true });
  const probe = `import {readSshTargets} from ${JSON.stringify(pathToFileURL(helper).href)};
    import * as fs from 'node:fs/promises';
    const denied=async operation=>{try{await operation();return false;}catch(error){return ['EPERM','EACCES'].includes(error.code);}};
    const targets=await readSshTargets(${JSON.stringify(targetsFile)});
    console.log(JSON.stringify({targetsMatched:JSON.stringify(targets)===${JSON.stringify(JSON.stringify(targets))},
      rootMetadata:(await fs.lstat(${JSON.stringify(agentRoot)})).isDirectory(),
      sessionMetadata:(await fs.lstat(${JSON.stringify(session)})).isDirectory(),
      ownPublicListing:(await fs.readdir(${JSON.stringify(publicDirectory)})).length===2,
      rootListingDenied:await denied(()=>fs.readdir(${JSON.stringify(agentRoot)})),
      sessionListingDenied:await denied(()=>fs.readdir(${JSON.stringify(session)})),
      otherMetadataDenied:await denied(()=>fs.lstat(${JSON.stringify(other)})),
      otherContentDenied:await denied(()=>fs.readFile(${JSON.stringify(otherFile)})),
      publicWriteDenied:await denied(()=>fs.writeFile(${JSON.stringify(path.join(publicDirectory, 'new-file'))},'x'))}));`;
  for (const child of [false, true]) {
    const command = child ? ['/bin/sh', '-c', 'exec "$1" --input-type=module -e "$2"', 'owned-target-reader-child', process.execPath, probe]
      : [process.execPath, '--input-type=module', '-e', probe];
    const result = JSON.parse((await execute(TERMINAL_FENCE_EXECUTABLE, ['-p', profile, ...command], options)).stdout);
    assert.deepEqual(result, { targetsMatched: true, rootMetadata: true, sessionMetadata: true,
      ownPublicListing: true, rootListingDenied: true, sessionListingDenied: true,
      otherMetadataDenied: true, otherContentDenied: true, publicWriteDenied: true }, child ? 'exec child' : 'direct');
  }
});
