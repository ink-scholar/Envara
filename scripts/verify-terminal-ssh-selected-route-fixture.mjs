/** Opt-in macOS SSH routing acceptance using only owned loopback fixtures.
 * ELECTRON_RUN_AS_NODE=1 <Electron-or-Envara> scripts/verify-terminal-ssh-selected-route-fixture.mjs --run
 * Optional: --packaged /absolute/Envara.app --python /absolute/python --output /absolute/proof.json
 * Uses installed Paramiko and bundled Node. No downloads, real accounts, host
 * SSH configuration, remote shell, model requests or host-setting changes.
 */
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import net from 'node:net';
import path from 'node:path';
import { promisify, stripVTControlCharacters } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2), options = {};
for (let index = 0; index < argv.length; index++) {
  const name = argv[index];
  assert(['--run', '--packaged', '--python', '--node', '--output'].includes(name), 'Unsupported fixture option.');
  assert(!Object.hasOwn(options, name), 'Duplicate fixture option.');
  if (name === '--run') options[name] = true;
  else { assert(path.isAbsolute(argv[index + 1] ?? ''), 'Runtime and output arguments require absolute paths.'); options[name] = argv[++index]; }
}
if (!options['--run']) {
  console.log(JSON.stringify({ schema: 'envara.ssh-selected-route-fixture-plan/v1', optIn: true,
    ownedLoopbackOnly: true, syntheticCredentialsOnly: true, remoteShell: false,
    downloads: false, modelRequests: false, hostSettingsModified: false }));
  process.exit(0);
}
assert.equal(process.platform, 'darwin');
assert(process.versions.electron, 'Use Electron with ELECTRON_RUN_AS_NODE=1 for real native PTYs.');
const application = options['--packaged'];
const resources = application ? path.join(application, 'Contents/Resources') : path.join(root, 'build');
if (application) assert.equal(await realpath(process.resourcesPath), await realpath(resources));
const moduleRoot = application ? path.join(resources, 'app.asar') : root;
const moduleURL = name => pathToFileURL(path.join(moduleRoot, 'electron', name));
const [{ TerminalService }, { TerminalSshManager }] = await Promise.all([
  import(moduleURL('terminal-service.mjs')), import(moduleURL('terminal-ssh-manager.mjs')),
]);
const require = createRequire(moduleURL('terminal-service.mjs'));
const nativePty = require('node-pty');
const bundledNode = await realpath(path.join(resources, 'backend/playwright-driver/node'));
const node = options['--node'] ? await realpath(options['--node']) : bundledNode;
if (application) assert.equal(node, bundledNode);
const python = options['--python'] ?? 'python3';
const execute = promisify(execFile), controller = new AbortController();
const safeEnvironment = { PATH: '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' };
const run = (program, args) => execute(program, args, { env: safeEnvironment, timeout: 15000, maxBuffer: 4 * 1024 * 1024 });
const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
const digestFile = async filename => { const hash = createHash('sha256'); for await (const bytes of createReadStream(filename)) hash.update(bytes); return hash.digest('hex'); };
const failure = code => Object.assign(new Error(code), { code });
const bounded = async (operation, code, milliseconds = 15000) => {
  let timer;
  try { return await Promise.race([Promise.resolve().then(operation), new Promise((_, reject) => { timer = setTimeout(() => reject(failure(code)), milliseconds); })]); }
  finally { clearTimeout(timer); }
};
const wait = async (predicate, code, milliseconds = 15000, allowCancelled = false) => {
  const until = Date.now() + milliseconds;
  while (Date.now() < until) {
    if (!allowCancelled) controller.signal.throwIfAborted();
    const value = await predicate(); if (value) return value;
    await sleep(30);
  }
  throw failure(code);
};
const proof = { schema: 'envara.ssh-selected-route-fixture/v1', passed: false, mode: application ? 'packaged' : 'source',
  platform: `${process.platform}-${process.arch}`, electron: process.versions.electron, checks: [], limitations: [
    'Only generated keys, memory-only synthetic passwords and owned loopback SSH/proxy listeners are exercised; no real account or public egress is tested.',
    'A saved direct SSH server necessarily observes its TCP peer. The fixture returns that peer as synthetic SSH_CONNECTION output; arbitrary remote output is not filtered.',
    'The unknown-host listener is never contacted; all key/password logins use explicit saved routes and fixture-only accounts.',
    'Actual SSH env/PTY requests and native process environment are inspected. This does not create a virtual machine or hide SSH protocol fingerprints and PTY metadata.',
    'The production TerminalService and macOS fence are exercised without starting the application UI, a real browser, Claude, an external API or a model request.',
  ] };
const check = message => { proof.checks.push(message); console.log(`PASS ${message}`); };
const services = [], managers = [], children = new Set(), peers = new Set(), outputs = new Map(), observed = new Map();
const nativeLaunches = [], sessionDirectories = new Set();
const events = [], proxyEvents = [], ports = {};
const password = randomBytes(24).toString('hex'), proxyUser = randomBytes(12).toString('hex'), proxyPassword = randomBytes(24).toString('hex');
const sentinels = Object.fromEntries(['HOSTNAME', 'PWD', 'TZ', 'USER', 'LOGNAME', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'TERM_PROGRAM']
  .map(name => [name, `fixture-${name.toLowerCase()}-${randomBytes(8).toString('hex')}`]));
let temporary, temporaryIdentity, outputPath, manager, terminal, proxyServer, pythonChild, stage = 'prepare';
let selectedProxyServer, selectedProxyReject = false, localCommandMarker, working, hostHome, dataDir, fixtureProcessError = false;
const cancel = () => { controller.abort(); for (const owner of services) void owner.shutdown().catch(() => {}); };
process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
const text = session => stripVTControlCharacters(outputs.get(session.sessionId) ?? '');
const count = (event, listener) => events.filter(item => item.event === event && (!listener || item.listener === listener)).length;
const authenticated = listener => count('authenticated', listener);
const opened = listener => count('opened', listener);
const currentEvents = start => events.slice(start);
const parseJsonLine = source => { for (const line of source.split('\n')) { try { return JSON.parse(line.trim()); } catch {} } throw failure('FIXTURE_JSON_MISSING'); };

// The server implements fixed fixture messages only. It never executes a
// received command or starts a shell, and never logs credential values.
const serverSource = String.raw`import json,sys,socket,threading,time,paramiko,base64
root=sys.argv[1]; password=json.loads(sys.stdin.readline())['password']
client=base64.b64decode(open(root+'/client.pub').read().split()[1])
keys=[paramiko.Ed25519Key.from_private_key_file(root+'/server'),paramiko.Ed25519Key.from_private_key_file(root+'/server-alt')]
lock=threading.Lock(); counter=0
def emit(name,**extra):
 with lock: print(json.dumps(dict(event=name,**extra)),flush=True)
class Server(paramiko.ServerInterface):
 def __init__(self,label,connection): self.label=label;self.connection=connection;self.started=threading.Event();self.kind=None;self.username=None
 def event(self,name,**extra): emit(name,listener=self.label,connection=self.connection,**extra)
 def get_allowed_auths(self,user): return 'none' if self.label=='unknown' else 'publickey,password'
 def check_auth_none(self,user):
  accepted=self.label=='unknown' and user=='adhoc';self.username=user if accepted else None
  self.event('noneAttempt',accepted=accepted);return paramiko.AUTH_SUCCESSFUL if accepted else paramiko.AUTH_FAILED
 def check_auth_password(self,user,value):
  accepted=self.label=='saved' and user=='fixture' and value==password;self.username=user if accepted else None
  self.event('passwordAttempt',accepted=accepted);return paramiko.AUTH_SUCCESSFUL if accepted else paramiko.AUTH_FAILED
 def check_auth_publickey(self,user,key):
  accepted=self.label=='saved' and user=='keyfixture' and key.asbytes()==client;self.username=user if accepted else None
  self.event('publicKeyAttempt',accepted=accepted);return paramiko.AUTH_SUCCESSFUL if accepted else paramiko.AUTH_FAILED
 def check_auth_interactive(self,*args): return paramiko.AUTH_FAILED
 def check_channel_request(self,kind,chanid):
  self.event('channel',kind=kind);return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
 def check_channel_env_request(self,channel,name,value):
  self.event('env',name=name.decode('utf-8','replace'),value=value.decode('utf-8','replace'));return True
 def check_channel_pty_request(self,channel,term,width,height,pixelwidth,pixelheight,modes):
  self.event('pty',term=term.decode('utf-8','replace'),columns=width,rows=height,modesBytes=len(modes));return True
 def check_channel_shell_request(self,channel): self.kind='interactive';self.started.set();return True
 def check_channel_exec_request(self,channel,command):
  accepted=command==b'envara-fixture';self.event('execRequest',accepted=accepted)
  if accepted: self.kind='exec';self.started.set()
  return accepted
 def check_channel_forward_agent_request(self,*args): self.event('agentForward');return False
 def check_channel_direct_tcpip_request(self,*args): self.event('tcpForward');return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
 def check_port_forward_request(self,*args): self.event('portForward');return False
 def check_global_request(self,*args): self.event('globalRequest');return False
def serve(sock,label,connection):
 transport=None;peer=sock.getpeername();local=sock.getsockname()
 emit('opened',listener=label,connection=connection,peer=peer[0],peerPort=peer[1])
 try:
  sock.settimeout(15);transport=paramiko.Transport(sock);transport.add_server_key(keys[1 if open(root+'/mode').read()=='changed' else 0]);instance=Server(label,connection);transport.start_server(server=instance)
  emit('clientVersion',listener=label,connection=connection,value=transport.remote_version)
  channel=transport.accept(15)
  if channel is None: return
  if transport.is_authenticated(): emit('authenticated',listener=label,connection=connection,user=instance.username)
  if not instance.started.wait(5): return
  # This is the actual peer observed by this owned TCP server, using the SSH
  # connection variable's format. Paramiko itself does not run a login shell.
  payload='SSH_CONNECTION=%s %d %s %d\n'%(peer[0],peer[1],local[0],local[1])
  if instance.kind=='exec':
   channel.sendall(('ENVARA_SSH_ROUTING_OK\n'+payload).encode());channel.send_exit_status(0);emit('executed',listener=label,connection=connection);channel.shutdown_write();time.sleep(.1)
  else:
   channel.settimeout(120);channel.sendall(('ENVARA_SSH_ROUTING_READY\n'+payload).encode());emit('interactive',listener=label,connection=connection);buffer=b''
   while transport.is_active():
    chunk=channel.recv(4096)
    if not chunk: break
    buffer+=chunk
    if len(buffer)>8192: break
    while b'\n' in buffer or b'\r' in buffer:
     points=[x for x in [buffer.find(b'\n'),buffer.find(b'\r')] if x>=0];at=min(points);line=buffer[:at];buffer=buffer[at+1:]
     if line==b'fixture-ping': channel.sendall(b'ENVARA_SSH_ROUTING_PONG\n');emit('pong',listener=label,connection=connection)
     elif line==b'exit': channel.send_exit_status(0);channel.close();return
  channel.close()
 except Exception: pass
 finally:
  if transport: transport.close()
  sock.close();emit('closed',listener=label,connection=connection)
def listen(label):
 global counter
 listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',0));listener.listen(20)
 emit('ready',listener=label,port=listener.getsockname()[1])
 while True:
  sock,_=listener.accept()
  with lock: counter+=1;connection=counter
  threading.Thread(target=serve,args=(sock,label,connection),daemon=True).start()
threading.Thread(target=listen,args=('saved',),daemon=True).start();listen('unknown')
`;

async function processRows() {
  const { stdout } = await run('/bin/ps', ['-axo', 'pid=,ppid=,lstart=,comm=']);
  const rows = new Map();
  for (const line of stdout.split('\n')) {
    const match = line.trim().match(/^(\d+)\s+(\d+)\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+)$/);
    if (match) rows.set(Number(match[1]), { pid: Number(match[1]), parent: Number(match[2]), birth: match[3].replace(/\s+/g, ' '), executable: match[4] });
  }
  return rows;
}
async function observeProcesses() {
  const rows = await processRows(), family = new Set([process.pid]);
  let changed;
  do { changed = false; for (const row of rows.values()) if (family.has(row.parent) && !family.has(row.pid)) { family.add(row.pid); changed = true; } } while (changed);
  const owned = new Map([...rows].filter(([pid, row]) => pid !== process.pid && family.has(pid) && row.executable !== '/bin/ps'));
  for (const [pid, row] of owned) observed.set(pid, row);
  return owned;
}
async function command(session, source, { interactiveTrust = false } = {}) {
  controller.signal.throwIfAborted();
  const token = randomBytes(10).toString('hex'), begin = `EVSSH_BEGIN_${token}`, done = `EVSSH_DONE_${token}`, start = text(session).length;
  await terminal.write({ sessionId: session.sessionId, data: `printf '\\n%s\\n' ${quote(begin)}; ${source}; fixture_status=$?; printf '\\n%s:%d\\n' ${quote(done)} "$fixture_status"\r` });
  let approved = false;
  await wait(async () => {
    const value = text(session).slice(start);
    if (interactiveTrust && !approved && /Are you sure you want to continue connecting/.test(value)) {
      approved = true; await terminal.write({ sessionId: session.sessionId, data: 'yes\r' });
    }
    return new RegExp(`(?:^|[\r\n])${done}:[0-9]+`).test(value);
  }, 'FIXTURE_COMMAND_DEADLINE', 25000);
  const value = text(session).slice(start), match = new RegExp(`(?:^|[\r\n])${done}:([0-9]+)`).exec(value);
  await observeProcesses();
  return { code: Number(match[1]), text: value, approved };
}
function nativeLaunch(program, args, settings, pty = false) {
  controller.signal.throwIfAborted();
  assert(!JSON.stringify({ program, args, env: settings.env }).includes(password), 'A native launch exposed a synthetic SSH password.');
  const child = pty ? nativePty.spawn(program, args, settings) : spawn(program, args, settings);
  if (!pty) { children.add(child); child.on('error', () => {}); }
  nativeLaunches.push({ program: path.basename(program), pid: child.pid });
  return child;
}
async function listenRouteProxy(label) {
  const expected = `Basic ${Buffer.from(`${proxyUser}:${proxyPassword}`).toString('base64')}`;
  const server = net.createServer({allowHalfOpen:true},socket=>{
    peers.add(socket);socket.on('error',()=>{});socket.once('close',()=>peers.delete(socket));let buffer=Buffer.alloc(0);
    socket.on('data',function headers(chunk){
      buffer=Buffer.concat([buffer,chunk]);if(buffer.length>16384)return socket.destroy();const at=buffer.indexOf('\r\n\r\n');if(at<0)return;
      socket.pause();socket.off('data',headers);const lines=buffer.subarray(0,at).toString('latin1').split('\r\n');
      const authorized=lines.includes(`Proxy-Authorization: ${expected}`);
      const accepted=label==='selectedB'&&!selectedProxyReject&&authorized&&lines[0]==='CONNECT ssh-route-fixture.invalid:1030 HTTP/1.1';
      proxyEvents.push({label,authorized,accepted,kind:'connect'});
      if(!accepted)return socket.end('HTTP/1.1 407 Refused\r\nContent-Length: 0\r\n\r\n');
      const upstream=net.connect({host:'127.0.0.1',port:ports.saved,allowHalfOpen:true});peers.add(upstream);upstream.on('error',()=>socket.destroy());upstream.once('close',()=>peers.delete(upstream));socket.once('close',()=>upstream.destroy());
      upstream.once('connect',()=>{socket.write('HTTP/1.1 200 Connected\r\n\r\n');const head=buffer.subarray(at+4);if(head.length)upstream.write(head);socket.pipe(upstream);upstream.pipe(socket);socket.resume();});
    });
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});return server;
}
try {
  await run(python,['-I','-c','import paramiko']);
  temporary=await realpath(await mkdtemp('/private/tmp/evsrb-'));temporaryIdentity=await lstat(temporary);
  outputPath=options['--output']??path.join(root,'test-artifacts/ssh-selected-route',`proof-${Date.now()}.json`);
  for(const name of ['client','server','server-alt'])await run('/usr/bin/ssh-keygen',['-q','-t','ed25519','-N','','-C','envara-selected-route-fixture','-f',path.join(temporary,name)]);
  await writeFile(path.join(temporary,'mode'),'normal',{mode:0o600});await writeFile(path.join(temporary,'server.py'),serverSource,{mode:0o600});
  pythonChild=spawn(python,['-I',path.join(temporary,'server.py'),temporary],{env:safeEnvironment,stdio:['pipe','pipe','pipe']});children.add(pythonChild);pythonChild.stderr.resume();pythonChild.on('error',()=>{fixtureProcessError=true;});pythonChild.stdin.end(JSON.stringify({password})+'\n');
  let buffer='';pythonChild.stdout.on('data',chunk=>{buffer+=chunk.toString();if(buffer.length>65536){fixtureProcessError=true;return;}for(;;){const at=buffer.indexOf('\n');if(at<0)break;const line=buffer.slice(0,at);buffer=buffer.slice(at+1);try{const item=JSON.parse(line);if(item.event==='ready')ports[item.listener]=item.port;else events.push(item);}catch{fixtureProcessError=true;}}});
  await wait(()=>{if(fixtureProcessError)throw failure('FIXTURE_SERVER_FAILED');return ports.saved&&ports.unknown;},'FIXTURE_SERVER_READY');
  proxyServer=await listenRouteProxy('ownerA');selectedProxyServer=await listenRouteProxy('selectedB');
  dataDir=path.join(temporary,'data');hostHome=path.join(temporary,'host');working=path.join(temporary,'work');
  for(const folder of [dataDir,hostHome,working,path.join(hostHome,'.ssh')])await mkdir(folder,{recursive:true,mode:0o700});
  await writeFile(path.join(hostHome,'.ssh/known_hosts'),'',{mode:0o600});
  const selectedURL=`http://${encodeURIComponent(proxyUser)}:${encodeURIComponent(proxyPassword)}@127.0.0.1:${selectedProxyServer.address().port}`;
  let selectedActive=true;
  manager=new TerminalSshManager({dataDir,hostHome,nodeExecutable:node,agentRoot:path.join(temporary,'agents'),
    resolveRoute:async({route})=>({route,routeIdentity:route.kind==='host'?'host-generation':'selected-B-generation',
      ...(route.kind==='environment'?{proxyUrl:selectedURL}:{}),isActive:()=>route.kind==='host'||selectedActive,dispose:async()=>{}}),
    spawn:(program,args,settings)=>nativeLaunch(program,args,settings)});
  managers.push(manager);await manager.ready;
  const originalBroker=manager.createPasswordBroker;
  manager.createPasswordBroker=async settings=>{sessionDirectories.add(settings.directory);return originalBroker({...settings,
    spawn:(program,args,settings)=>nativeLaunch(program,args,settings),ptyFactory:(program,args,settings)=>nativeLaunch(program,args,settings,true)});};
  const records={};
  stage='probe and save selected B plus host routes';
  for(const [id,route,target]of [
    ['selected-b',{kind:'environment',profileId:'network-b'},{host:'ssh-route-fixture.invalid',port:1030}],
    ['host-baseline',{kind:'host'},{host:'127.0.0.1',port:ports.saved}],
  ]){
    records[id]={};
    for(const authentication of ['publickey','password']){
      const beforeAuth=count('noneAttempt')+count('passwordAttempt')+count('publicKeyAttempt');
      const settings={id,...target,user:authentication==='password'?'fixture':'keyfixture',route};
      const prepared=authentication==='password'?await manager.preparePassword(settings):await manager.prepareIdentity({...settings,keyPath:path.join(temporary,'client')});
      assert.equal(count('noneAttempt')+count('passwordAttempt')+count('publicKeyAttempt'),beforeAuth,'Host-key discovery must not authenticate');
      await assert.rejects(manager.save({id,name:'Unconfirmed fixture',selectionToken:prepared.selectionToken,...(authentication==='password'?{password}:{})}));
      records[id][authentication]=await manager.save({id,name:`${id} ${authentication}`,selectionToken:prepared.selectionToken,hostKeyConfirmed:true,...(authentication==='password'?{password}:{})});
      assert.deepEqual(records[id][authentication].route,route);
    }
  }
  check('selected B and host key/password probes require explicit confirmation before saving and perform zero authentication');
  const proxy={protocol:'http',host:'127.0.0.1',port:proxyServer.address().port,username:proxyUser,password:proxyPassword};
  terminal=new TerminalService({dataDir,sshManager:manager,availableLocales:['en_US.UTF-8'],additionalExecutablePaths:[path.dirname(node)],
    resolveContext:async id=>({id,name:'Owned route owner A',timezone:'UTC',locale:'en-US',proxy,proxyId:'owner-A',managedProxy:true,privacy:{mode:'strict'},network:{ok:true,source:'owned-fixture'}}),
    ptyFactory:(program,args,settings)=>nativeLaunch(program,args,settings,true),onEvent:event=>{if(event.type==='data')outputs.set(event.sessionId,(outputs.get(event.sessionId)??'')+event.data);}});
  services.push(terminal);await terminal.ready;terminal.hostHome=hostHome;
  const create=async id=>{const session=await terminal.create({id,directory:working,fresh:true,columns:93,rows:27});assert.equal(session.networkFence,true);const lease=manager.sessions.get(session.sessionId);if(lease?.directory)sessionDirectories.add(lease.directory);await observeProcesses();return session;};
  const selectedSession=await create('selected-b');
  stage='native key and password use selected B';
  for(const authentication of ['publickey','password']){
    const beforeB=proxyEvents.filter(event=>event.label==='selectedB').length;
    const result=await command(selectedSession,`ssh -T ${records['selected-b'][authentication].alias} envara-fixture`);
    assert.equal(result.code,0);assert(result.text.includes('ENVARA_SSH_ROUTING_OK'));assert(proxyEvents.filter(event=>event.label==='selectedB').length>beforeB);
  }
  assert.equal(proxyEvents.filter(event=>event.label==='ownerA').length,0);
  assert(events.some(event=>event.event==='publicKeyAttempt'&&event.accepted));assert(events.some(event=>event.event==='passwordAttempt'&&event.accepted));
  check('real fenced native SSH key and password logins select saved environment B instead of terminal owner A');
  stage='duplicate inherits selected route';
  const duplicate=await terminal.duplicate({sessionId:selectedSession.sessionId});await observeProcesses();
  for(const authentication of ['publickey','password']){const result=await command(duplicate,`ssh -T ${records['selected-b'][authentication].alias} envara-fixture`);assert.equal(result.code,0);assert(result.text.includes('ENVARA_SSH_ROUTING_OK'));}
  assert.equal(proxyEvents.filter(event=>event.label==='ownerA').length,0);
  check('independent duplicate preserves both selected B authentication routes');
  stage='host baseline avoids both proxies';
  const hostSession=await create('host-baseline'),beforeHost=proxyEvents.length;
  for(const authentication of ['publickey','password']){const result=await command(hostSession,`ssh -T ${records['host-baseline'][authentication].alias} envara-fixture`);assert.equal(result.code,0);assert(result.text.includes('ENVARA_SSH_ROUTING_OK'));}
  assert.equal(proxyEvents.length,beforeHost);
  check('host key/password logins use their saved host route without contacting A or B');
  stage='B refusal fails closed';
  selectedProxyReject=true;const beforeRefusal=authenticated('saved');
  for(const authentication of ['publickey','password']){const result=await command(selectedSession,`ssh -T ${records['selected-b'][authentication].alias} envara-fixture`);assert.notEqual(result.code,0);}
  assert.equal(authenticated('saved'),beforeRefusal);assert.equal(proxyEvents.filter(event=>event.label==='ownerA').length,0);
  selectedProxyReject=false;
  check('refused selected B connections never authenticate or fall back to owner A or host');
  stage='route revocation fails closed';selectedActive=false;
  const beforeRevoked=proxyEvents.length;for(const authentication of ['publickey','password']){const result=await command(selectedSession,`ssh -T ${records['selected-b'][authentication].alias} envara-fixture`);assert.notEqual(result.code,0);}
  assert.equal(proxyEvents.length,beforeRevoked);
  check('revoked selected route refuses existing native SSH capabilities before any new contact');
  proof.passed=true;
} catch (error) {
  proof.failure = { stage, code: /^[A-Z\d_]+$/.test(String(error?.code ?? '')) ? error.code : 'FIXTURE_ASSERTION' };
  const location = error?.stack?.split('\n').find(line => /verify-terminal-ssh-selected-route-fixture\.mjs:\d+:\d+/.test(line))?.match(/:(\d+):(\d+)\)?$/);
  if (location) proof.failure.line = Number(location[1]);
} finally {
  const cleanup = [];
  const clean = async (operation, code, milliseconds = 15000) => {
    try { await bounded(operation, code, milliseconds); } catch { cleanup.push(code); }
  };
  await observeProcesses().catch(() => cleanup.push('PROCESS_OBSERVATION_FAILED'));
  for (const owner of managers) for (const lease of owner.sessions.values()) if (lease.directory) sessionDirectories.add(lease.directory);
  for (const owner of services) await clean(() => owner.shutdown(), 'TERMINAL_CLEANUP_FAILED');
  for (const owner of managers) await clean(() => owner.close(), 'MANAGER_CLEANUP_FAILED');
  for (const socket of peers) socket.destroy();
  if(selectedProxyServer?.listening)await clean(()=>new Promise((resolve,reject)=>selectedProxyServer.close(error=>error?reject(error):resolve())),'SELECTED_PROXY_CLEANUP_FAILED',2000);
  if (proxyServer?.listening) await clean(() => new Promise((resolve, reject) => proxyServer.close(error => error ? reject(error) : resolve())), 'PROXY_CLEANUP_FAILED', 2000);
  if (pythonChild && pythonChild.exitCode == null && pythonChild.signalCode == null) {
    pythonChild.kill('SIGTERM');
    try { await wait(() => pythonChild.exitCode != null || pythonChild.signalCode != null, 'FIXTURE_SERVER_REMAINS', 2000, true); }
    catch {
      pythonChild.kill('SIGKILL');
      await wait(() => pythonChild.exitCode != null || pythonChild.signalCode != null, 'FIXTURE_SERVER_REMAINS', 2000, true).catch(() => cleanup.push('SERVER_CLEANUP_FAILED'));
    }
  }
  for (const child of children) if (child.exitCode == null && child.signalCode == null) cleanup.push('OWNED_CHILD_REMAINS');
  let remaining = -1;
  try {
    const rows = await processRows();
    remaining = [...observed.values()].filter(row => rows.get(row.pid)?.birth === row.birth && rows.get(row.pid)?.executable === row.executable).length;
    if (remaining) cleanup.push('OBSERVED_PROCESS_REMAINS');
  } catch { cleanup.push('PROCESS_ABSENCE_UNCONFIRMED'); }
  for (const directory of sessionDirectories) try { await lstat(directory); cleanup.push('SESSION_DIRECTORY_REMAINS'); } catch (error) { if (error.code !== 'ENOENT') cleanup.push('SESSION_DIRECTORY_UNKNOWN'); }
  let temporaryRemoved = false;
  if (!cleanup.length && temporary) {
    try {
      const current = await lstat(temporary);
      assert(current.isDirectory() && !current.isSymbolicLink() && current.dev === temporaryIdentity.dev && current.ino === temporaryIdentity.ino);
      await rm(temporary, { recursive: true, force: true }); temporaryRemoved = true;
    } catch { cleanup.push('TEMPORARY_CLEANUP_FAILED'); }
  }
  proof.cleanup = { complete: cleanup.length === 0, remainingObservedProcesses: remaining, temporaryRemoved, errors: [...new Set(cleanup)] };
  proof.passed &&= proof.cleanup.complete && !controller.signal.aborted;
  if (controller.signal.aborted) proof.interrupted = true;
  proof.stats = { savedConnections: opened('saved'), unknownConnections: opened('unknown'),
    authenticatedSaved: authenticated('saved'), authenticatedUnknown: authenticated('unknown'),
    proxyConnects: proxyEvents.filter(event => event.kind === 'connect').length,
    authenticatedProxyConnects: proxyEvents.filter(event => event.kind === 'connect' && event.authorized).length,
    proxyRejections: proxyEvents.filter(event => !event.accepted).length,
    ownerAContacts:proxyEvents.filter(event=>event.label==='ownerA').length,selectedBContacts:proxyEvents.filter(event=>event.label==='selectedB').length,serverEnvironmentRequests: count('env'), nativeLaunches: nativeLaunches.length };
  if (outputPath) {
    await mkdir(path.dirname(outputPath), { recursive: true, mode: 0o700 });
    await writeFile(outputPath, JSON.stringify(proof, null, 2) + '\n', { mode: 0o600 });
  }
  process.off('SIGINT', cancel); process.off('SIGTERM', cancel);
}
console.log(JSON.stringify({ passed: proof.passed, checks: proof.checks.length, proof: outputPath ?? null,
  cleanup: proof.cleanup, ...(proof.failure ? { failure: proof.failure } : {}) }, null, 2));
if (!proof.passed) process.exitCode = controller.signal.aborted ? 130 : 1;
