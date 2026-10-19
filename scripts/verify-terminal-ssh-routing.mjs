/** Opt-in macOS SSH routing acceptance using only owned loopback fixtures.
 * ELECTRON_RUN_AS_NODE=1 <Electron-or-Envara> scripts/verify-terminal-ssh-routing.mjs --run
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
  console.log(JSON.stringify({ schema: 'envara.ssh-routing-fixture-plan/v1', optIn: true,
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
const proof = { schema: 'envara.ssh-routing-fixture/v1', passed: false, mode: application ? 'packaged' : 'source',
  platform: `${process.platform}-${process.arch}`, electron: process.versions.electron, checks: [], limitations: [
    'Only generated keys, memory-only synthetic passwords and owned loopback SSH/proxy listeners are exercised; no real account or public egress is tested.',
    'A saved direct SSH server necessarily observes its TCP peer. The fixture returns that peer as synthetic SSH_CONNECTION output; arbitrary remote output is not filtered.',
    'An ad hoc fixture account accepts SSH none authentication after interactive host trust, so this case proves routing and trust handling rather than ad hoc password authentication.',
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
let proxyReject = false, localCommandMarker, working, hostHome, dataDir, fixtureProcessError = false;
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
async function inspectNativeEnvironment() {
  const before = await observeProcesses(); let checked = 0;
  for (const row of before.values()) {
    if (row.executable !== '/usr/bin/ssh') continue;
    const { stdout } = await run('/bin/ps', ['eww', '-p', String(row.pid), '-o', 'command=']);
    const after = (await processRows()).get(row.pid);
    if (!after || after.birth !== row.birth || after.parent !== row.parent) continue;
    assert(stdout.includes(' -F '), 'Native SSH must use the fixed owned configuration.');
    for (const value of [...Object.values(sentinels), password]) assert(!stdout.includes(value), 'A native SSH process inherited a forbidden synthetic value.');
    checked++;
  }
  assert(checked > 0, 'The real native SSH process must be observed while connected.');
  return checked;
}
async function relayFrame(socketPath, frame, { removed = false } = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(socketPath); let buffer = '', settled = false;
    const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); socket.destroy(); error ? reject(error) : resolve(value); };
    const timer = setTimeout(() => finish(failure('FIXTURE_RELAY_RESPONSE_DEADLINE')), 2000);
    socket.once('connect', () => socket.write(`${JSON.stringify(frame)}\n`));
    socket.on('data', bytes => {
      buffer += bytes.toString(); if (buffer.length > 1024) return finish(failure('FIXTURE_RELAY_RESPONSE_INVALID'));
      const end = buffer.indexOf('\n'); if (end < 0) return;
      try { finish(null, JSON.parse(buffer.slice(0, end))); } catch { finish(failure('FIXTURE_RELAY_RESPONSE_INVALID')); }
    });
    socket.once('error', error => finish(removed && ['ENOENT', 'ECONNREFUSED'].includes(error.code) ? null : error, { removed: true }));
    socket.once('close', () => { if (!settled) finish(failure('FIXTURE_RELAY_RESPONSE_MISSING')); });
  });
}
async function scanPasswordFiles(directory) {
  let count = 0;
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) count += await scanPasswordFiles(filename);
    else if (entry.isFile()) {
      const size = (await lstat(filename)).size; assert(size < 4 * 1024 * 1024, 'Unexpected large fixture file.');
      assert(!(await readFile(filename)).includes(Buffer.from(password)), 'A synthetic SSH password was written to an owned file.'); count++;
    }
  }
  return count;
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
async function startInteractive(session, alias) {
  const token = randomBytes(8).toString('hex'), done = `EVSSH_INTERACTIVE_${token}`, start = text(session).length, eventStart = events.length;
  const prefix = Object.entries(sentinels).map(([name, value]) => `${name}=${quote(value)}`).join(' ');
  await terminal.write({ sessionId: session.sessionId, data: `${prefix} ssh -t ${alias}; fixture_status=$?; printf '\\n${done}:%d\\n' "$fixture_status"\r` });
  await wait(() => text(session).slice(start).includes('ENVARA_SSH_ROUTING_READY')
    && currentEvents(eventStart).some(item => item.event === 'interactive'), 'FIXTURE_INTERACTIVE_READY');
  await observeProcesses();
  const { connection, listener } = currentEvents(eventStart).find(item => item.event === 'interactive');
  return { start, done, connection, listener };
}
async function finishInteractive(session, running) {
  await terminal.write({ sessionId: session.sessionId, data: 'exit\r' });
  await wait(() => new RegExp(`${running.done}:[0-9]+`).test(text(session).slice(running.start)), 'FIXTURE_INTERACTIVE_RETURN');
  assert.equal(Number(new RegExp(`${running.done}:([0-9]+)`).exec(text(session).slice(running.start))[1]), 0);
}
function nativeLaunch(program, args, settings, pty = false) {
  controller.signal.throwIfAborted();
  assert(!JSON.stringify({ program, args, env: settings.env }).includes(password), 'A native launch exposed a synthetic SSH password.');
  const child = pty ? nativePty.spawn(program, args, settings) : spawn(program, args, settings);
  if (!pty) { children.add(child); child.on('error', () => {}); }
  nativeLaunches.push({ program: path.basename(program), pid: child.pid });
  return child;
}
async function listenProxy() {
  controller.signal.throwIfAborted();
  const expected = `Basic ${Buffer.from(`${proxyUser}:${proxyPassword}`).toString('base64')}`;
  proxyServer = net.createServer(socket => {
    peers.add(socket); socket.on('error', () => {}); socket.once('close', () => peers.delete(socket)); let buffer = Buffer.alloc(0);
    socket.on('data', function parse(bytes) {
      buffer = Buffer.concat([buffer, bytes]); if (buffer.length > 16384) return socket.destroy();
      const end = buffer.indexOf('\r\n\r\n'); if (end < 0) return;
      socket.off('data', parse); socket.pause();
      const lines = buffer.subarray(0, end).toString('latin1').split('\r\n');
      const authorized = lines.some(line => line.toLowerCase().startsWith('proxy-authorization:') && line.slice(line.indexOf(':') + 1).trim() === expected);
      const first = lines[0], target = `127.0.0.1:${ports.unknown}`;
      const event = { kind: first.startsWith('CONNECT ') ? 'connect' : 'http', authorized, accepted: false };
      proxyEvents.push(event);
      if (!authorized) return socket.end('HTTP/1.1 407 Refused\r\nConnection: close\r\n\r\n');
      if (first === 'GET http://api-fixture.envara.invalid/ping HTTP/1.1') {
        event.accepted = true; const body = 'ENVARA_API_ROUTE_OK';
        return socket.end(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`);
      }
      if (first !== `CONNECT ${target} HTTP/1.1` || proxyReject) return socket.end('HTTP/1.1 502 Refused\r\nConnection: close\r\n\r\n');
      event.accepted = true;
      const upstream = net.connect({ host: '127.0.0.1', port: ports.unknown }); peers.add(upstream);
      upstream.on('error', () => socket.destroy()); upstream.once('close', () => { peers.delete(upstream); socket.destroy(); }); socket.once('close', () => upstream.destroy());
      upstream.once('connect', () => { socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); const tail = buffer.subarray(end + 4); if (tail.length) upstream.write(tail); upstream.pipe(socket); socket.pipe(upstream); socket.resume(); });
    });
  });
  await new Promise((resolve, reject) => { proxyServer.once('error', reject); proxyServer.listen(0, '127.0.0.1', resolve); });
}

try {
  await run(python, ['-I', '-c', 'import paramiko']); controller.signal.throwIfAborted();
  temporary = await realpath(await mkdtemp('/private/tmp/evsr-')); temporaryIdentity = await lstat(temporary);
  outputPath = options['--output'] ?? path.join(root, 'build/local-verification/ssh-routing', `proof-${application ? 'packaged' : 'source'}-${Date.now()}.json`);
  for (const name of ['client', 'server', 'server-alt']) await run('/usr/bin/ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'envara-routing-fixture', '-f', path.join(temporary, name)]);
  await writeFile(path.join(temporary, 'mode'), 'normal', { mode: 0o600 });
  await writeFile(path.join(temporary, 'server.py'), serverSource, { mode: 0o600 });
  controller.signal.throwIfAborted();
  pythonChild = spawn(python, ['-I', path.join(temporary, 'server.py'), temporary], { env: safeEnvironment, stdio: ['pipe', 'pipe', 'pipe'] });
  children.add(pythonChild); pythonChild.on('error', () => { fixtureProcessError = true; });
  pythonChild.stdin.on('error', () => { fixtureProcessError = true; });
  pythonChild.stderr.resume(); pythonChild.stdin.end(`${JSON.stringify({ password })}\n`);
  let buffer = '';
  pythonChild.stdout.on('data', bytes => {
    buffer += bytes.toString(); if (buffer.length > 32768) { buffer = ''; return; }
    for (;;) {
      const end = buffer.indexOf('\n'); if (end < 0) break;
      const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
      try { const item = JSON.parse(line); if (item.event === 'ready') ports[item.listener] = item.port; else if (events.length < 5000) events.push(item); } catch {}
    }
  });
  await wait(() => { if (fixtureProcessError || pythonChild.exitCode != null || pythonChild.signalCode != null) throw failure('FIXTURE_SERVER_FAILED'); return ports.saved && ports.unknown; }, 'FIXTURE_SSH_READY'); await listenProxy();
  dataDir = path.join(temporary, 'data'); hostHome = path.join(temporary, 'host'); working = path.join(temporary, 'work');
  for (const directory of [dataDir, hostHome, working, path.join(hostHome, '.ssh')]) await mkdir(directory, { recursive: true, mode: 0o700 });
  const hostPublic = (await readFile(path.join(temporary, 'server.pub'), 'utf8')).trim().split(/\s+/).slice(0, 2).join(' ');
  await writeFile(path.join(hostHome, '.ssh/known_hosts'), `[127.0.0.1]:${ports.saved} ${hostPublic}\n`, { mode: 0o600 });
  localCommandMarker = path.join(working, 'host-config-was-read');
  const hostileConfig = `Host *\n  SendEnv *\n  SetEnv ENVARA_HOST_CONFIG=fixture-must-not-send\n  PermitLocalCommand yes\n  ForwardAgent yes\n  LocalCommand /usr/bin/touch ${quote(localCommandMarker)}\n`;
  await writeFile(path.join(hostHome, '.ssh/config'), hostileConfig, { mode: 0o600 });
  manager = new TerminalSshManager({ dataDir, hostHome, nodeExecutable: node, agentRoot: path.join(temporary, 'agents'),
    spawn: (program, args, settings) => nativeLaunch(program, args, settings) });
  managers.push(manager); await manager.ready;
  const originalBroker = manager.createPasswordBroker;
  manager.createPasswordBroker = async settings => {
    sessionDirectories.add(settings.directory);
    return originalBroker({ ...settings, spawn: (program, args, options) => nativeLaunch(program, args, options),
      ptyFactory: (program, args, options) => nativeLaunch(program, args, options, true) });
  };
  const records = {};
  for (const profileId of ['routing-main', 'routing-revoke', 'routing-locked']) {
    const prepared = await manager.preparePassword({ id: profileId, host: '127.0.0.1', port: ports.saved, user: 'fixture' });
    records[profileId] = await manager.save({ id: profileId, name: 'Disposable password SSH', selectionToken: prepared.selectionToken, password });
  }
  const selected = await manager.prepareIdentity({ id: 'routing-main', host: '127.0.0.1', port: ports.saved, user: 'keyfixture', keyPath: path.join(temporary, 'client') });
  const key = await manager.save({ id: 'routing-main', name: 'Disposable key SSH', selectionToken: selected.selectionToken });
  manager.clearPassword(records['routing-locked'].id);
  const proxy = { protocol: 'http', host: '127.0.0.1', port: proxyServer.address().port, username: proxyUser, password: proxyPassword };
  const context = id => ({ id, name: 'Owned routing fixture', timezone: 'UTC', locale: 'en-US', proxy,
    proxyId: id === 'routing-revoke' ? 'fixture-revoke-route' : 'fixture-route', managedProxy: true,
    privacy: { mode: 'strict' }, network: { ok: true, source: 'owned-loopback-fixture' } });
  terminal = new TerminalService({ dataDir, sshManager: manager, availableLocales: ['en_US.UTF-8'], additionalExecutablePaths: [path.dirname(node)],
    resolveContext: async id => context(id), ptyFactory: (program, args, settings) => nativeLaunch(program, args, settings, true),
    onEvent: event => { if (event.type === 'data') outputs.set(event.sessionId, (outputs.get(event.sessionId) ?? '') + event.data); } });
  services.push(terminal); await terminal.ready; terminal.hostHome = hostHome;
  const create = async id => {
    controller.signal.throwIfAborted(); const session = await terminal.create({ id, directory: working, fresh: true, columns: 93, rows: 27 });
    assert(session.networkFence && session.ssh?.privateKeyProtection);
    const lease = manager.sessions.get(session.sessionId); if (lease?.directory) sessionDirectories.add(lease.directory);
    const directories = await terminal.directories(id);
    await mkdir(path.join(directories.home, '.ssh'), { recursive: true, mode: 0o700 });
    await writeFile(path.join(directories.home, '.ssh/config'), hostileConfig, { mode: 0o600 });
    await observeProcesses(); return session;
  };
  const main = await create('routing-main'), second = await create('routing-main');
  const prefix = Object.entries(sentinels).map(([name, value]) => `${name}=${quote(value)}`).join(' ');

  stage = 'saved key and password direct routing';
  const directStart = events.length, proxyBeforeDirect = proxyEvents.length;
  for (const destination of [key.alias, records['routing-main'].alias,
    `keyfixture@127.0.0.1 -p ${ports.saved}`, `fixture@127.0.0.1 -p ${ports.saved}`,
    `${quote('keyfixture@[0:0:0:0:0:ffff:7f00:1]')} -p ${ports.saved}`, `${quote('fixture@[::ffff:127.0.0.1]')} -p ${ports.saved}`]) {
    const result = await command(main, `${prefix} ssh -T ${destination} envara-fixture`);
    assert.equal(result.code, 0); assert(result.text.includes('ENVARA_SSH_ROUTING_OK'));
    assert.match(result.text, /SSH_CONNECTION=127\.0\.0\.1 \d+ 127\.0\.0\.1 \d+/);
  }
  assert.equal(proxyEvents.length, proxyBeforeDirect); assert(authenticated('saved') >= 2);
  assert(currentEvents(directStart).some(item => item.event === 'publicKeyAttempt' && item.accepted));
  assert(currentEvents(directStart).some(item => item.event === 'passwordAttempt' && item.accepted));
  check('saved key/password connections and equivalent IPv4-mapped IPv6 destinations use the direct relay without contacting the environment proxy');
  proof.directPeerBoundary = { actualServerPeer: '127.0.0.1', peerReturnedToTerminal: true, arbitraryRemoteOutputFiltered: false };

  stage = 'native environment and SSH protocol metadata';
  let processEnvironmentChecks = 0;
  const metadataStart = events.length;
  for (const alias of [key.alias, records['routing-main'].alias]) {
    const running = await startInteractive(main, alias);
    processEnvironmentChecks += await inspectNativeEnvironment();
    const start = text(main).length; await terminal.write({ sessionId: main.sessionId, data: 'fixture-ping\r' });
    await wait(() => text(main).slice(start).includes('ENVARA_SSH_ROUTING_PONG'), 'FIXTURE_INTERACTIVE_PONG');
    await finishInteractive(main, running);
  }
  const metadata = currentEvents(metadataStart), ptys = metadata.filter(item => item.event === 'pty');
  assert.equal(metadata.filter(item => item.event === 'env').length, 0);
  assert.equal(ptys.length, 2); for (const pty of ptys) { assert.equal(pty.term, 'xterm-256color'); assert.equal(pty.columns, 93); assert.equal(pty.rows, 27); }
  assert.equal(events.filter(item => ['agentForward', 'tcpForward', 'portForward'].includes(item.event)).length, 0);
  await assert.rejects(lstat(localCommandMarker), { code: 'ENOENT' });
  proof.metadata = { nativeProcessEnvironmentChecks: processEnvironmentChecks, serverEnvironmentRequests: 0,
    pty: ptys.map(({ term, columns, rows, modesBytes }) => ({ term, columns, rows, modesBytes })),
    serverSawNativeClientVersion: metadata.some(item => item.event === 'clientVersion' && /^SSH-2\.0-OpenSSH/.test(item.value)),
    fakeHostLocalCommandExecuted: false };
  check('native key/password SSH drops synthetic host metadata and API variables, sends no SSH env requests, and ignores fake host SendEnv/LocalCommand configuration');

  stage = 'unconfigured destination through authenticated CONNECT';
  const unknown = await create('routing-empty'), unknownBefore = opened('unknown'), proxyBefore = proxyEvents.length;
  const target = `adhoc@127.0.0.1 -p ${ports.unknown}`;
  const unknownResult = await command(unknown, `ssh -T ${target} envara-fixture`, { interactiveTrust: true });
  assert.equal(unknownResult.code, 0); assert(unknownResult.approved); assert(unknownResult.text.includes('ENVARA_SSH_ROUTING_OK'));
  assert.equal(opened('unknown') - unknownBefore, 1);
  const attempts = proxyEvents.slice(proxyBefore); assert.equal(attempts.length, 1); assert.deepEqual(attempts[0], { kind: 'connect', authorized: true, accepted: true });
  const unknownMetadataStart = events.length, unknownInteractive = await startInteractive(unknown, target);
  proof.metadata.nativeProcessEnvironmentChecks += await inspectNativeEnvironment();
  await finishInteractive(unknown, unknownInteractive);
  const unknownMetadata = currentEvents(unknownMetadataStart), unknownPty = unknownMetadata.find(item => item.event === 'pty');
  assert(unknownPty); assert.equal(unknownPty.term, 'xterm-256color'); assert.equal(unknownPty.columns, 93); assert.equal(unknownPty.rows, 27);
  assert.equal(unknownMetadata.filter(item => item.event === 'env').length, 0);
  proof.metadata.pty.push(Object.fromEntries(['term', 'columns', 'rows', 'modesBytes'].map(name => [name, unknownPty[name]])));
  check('an unconfigured destination requires interactive host trust and connects through the authenticated environment CONNECT proxy');

  stage = 'refused proxy without direct fallback';
  proxyReject = true;
  const refusalBefore = opened('unknown'), rejectedProxyBefore = proxyEvents.length;
  const refused = await command(unknown, `ssh -T ${target} envara-fixture`);
  assert.notEqual(refused.code, 0); assert.equal(opened('unknown'), refusalBefore);
  const refusedAttempts = proxyEvents.slice(rejectedProxyBefore); assert.equal(refusedAttempts.length, 1);
  assert.deepEqual(refusedAttempts[0], { kind: 'connect', authorized: true, accepted: false });
  proxyReject = false;
  check('a refused environment proxy fails the unconfigured SSH connection without contacting the directly reachable target');

  stage = 'locked saved destinations and override refusals';
  const locked = await create('routing-locked'), noRouteBefore = { proxy: proxyEvents.length, saved: opened('saved'), unknown: opened('unknown') };
  for (const source of [`ssh -T ${records['routing-locked'].alias} envara-fixture`,
    `ssh -T fixture@127.0.0.1 -p ${ports.saved} envara-fixture`,
    `ssh -T ${quote('fixture@[::ffff:127.0.0.1]')} -p ${ports.saved} envara-fixture`,
    `ssh -T ${quote('fixture@[0:0:0:0:0:ffff:7f00:1]')} -p ${ports.saved} envara-fixture`]) {
    const result = await command(locked, source); assert.notEqual(result.code, 0); assert(result.text.includes('SSH_SAVED_CONNECTION_UNAVAILABLE'));
  }
  for (const source of [`ssh -T other@127.0.0.1 -p ${ports.saved} envara-fixture`,
    `ssh -T ${quote('other@[::ffff:7f00:1]')} -p ${ports.saved} envara-fixture`,
    `ssh -o ProxyCommand=/usr/bin/true ${key.alias}`, `ssh -F /dev/null ${key.alias}`,
    `ssh -i ${quote(path.join(temporary, 'client'))} ${key.alias}`, `ssh -A ${key.alias}`, `ssh -L 22222:127.0.0.1:22 ${key.alias}`]) {
    const result = await command(main, source); assert.notEqual(result.code, 0);
    assert(/SSH_(TARGET_NOT_AUTHORIZED|OPTIONS_UNSUPPORTED|ARGUMENT_INVALID)/.test(result.text));
  }
  assert.deepEqual({ proxy: proxyEvents.length, saved: opened('saved'), unknown: opened('unknown') }, noRouteBefore);
  check('locked saved grants and equivalent IPv4-mapped addresses, changed users and connection overrides refuse before any direct or proxy contact');

  stage = 'changed host key before authentication';
  await writeFile(path.join(temporary, 'mode'), 'changed', { mode: 0o600 });
  for (const alias of [key.alias, records['routing-main'].alias]) {
    const before = { password: count('passwordAttempt'), key: count('publicKeyAttempt') };
    const result = await command(main, `ssh -T ${alias} envara-fixture`);
    assert.notEqual(result.code, 0); assert(/REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed/.test(result.text));
    assert.deepEqual({ password: count('passwordAttempt'), key: count('publicKeyAttempt') }, before);
  }
  await writeFile(path.join(temporary, 'mode'), 'normal', { mode: 0o600 });
  check('changed host keys refuse both saved authentication methods before a private-key signature or password attempt');

  stage = 'private files, cross-session sockets and unchanged terminal API fence';
  const firstLease = manager.sessions.get(main.sessionId), otherLease = manager.sessions.get(second.sessionId);
  const firstBinding = terminal.sessions.get(main.sessionId).sshBinding, otherBinding = terminal.sessions.get(second.sessionId).sshBinding;
  assert(firstBinding.environment.ENVARA_SSH_DIRECT_SOCKET && otherBinding.environment.ENVARA_SSH_DIRECT_SOCKET);
  const beforeFrames = { saved: opened('saved'), proxy: proxyEvents.length };
  const frame = { version: 1, token: firstBinding.environment.ENVARA_SSH_DIRECT_TOKEN, alias: key.alias };
  for (const invalid of [{ ...frame, token: otherBinding.environment.ENVARA_SSH_DIRECT_TOKEN },
    { ...frame, token: randomBytes(32).toString('hex') }, { ...frame, alias: records['routing-revoke'].alias },
    { ...frame, host: '127.0.0.1', port: ports.unknown }]) {
    assert.deepEqual(await relayFrame(firstBinding.environment.ENVARA_SSH_DIRECT_SOCKET, invalid), { ok: false });
  }
  assert.deepEqual({ saved: opened('saved'), proxy: proxyEvents.length }, beforeFrames);
  const privateHelper = (await readdir(firstLease.directory)).find(name => /askpass/i.test(name)); assert(privateHelper);
  const probe = path.join(working, 'boundary.mjs');
  await writeFile(probe, `import fs from 'node:fs';import net from 'node:net';import http from 'node:http';
const denied=fn=>{try{fn();return false}catch(error){return ['EPERM','EACCES'].includes(error.code)}};
const connect=target=>new Promise(resolve=>{const socket=net.connect(target);let done=false;const finish=value=>{if(done)return;done=true;clearTimeout(timer);socket.destroy();resolve(value)};const timer=setTimeout(()=>finish(false),1500);socket.once('connect',()=>finish(false));socket.once('error',error=>finish(['EPERM','EACCES'].includes(error.code)))});
const api=()=>new Promise(resolve=>{const request=http.get('http://203.0.113.1:443',{agent:new http.Agent({proxyEnv:{}})},()=>{request.destroy();resolve(false)});request.on('error',error=>resolve(['EPERM','EACCES'].includes(error.code)));request.setTimeout(1500,()=>{request.destroy();resolve(false)})});
console.log(JSON.stringify({key:denied(()=>fs.readFileSync(${JSON.stringify(path.join(temporary, 'client'))})),store:denied(()=>fs.readFileSync(${JSON.stringify(manager.filename)})),helper:denied(()=>fs.readFileSync(${JSON.stringify(path.join(firstLease.directory, privateHelper))})),auth:await connect(${JSON.stringify(path.join(firstLease.directory, 'auth.sock'))}),otherDirect:await connect(${JSON.stringify(otherBinding.environment.ENVARA_SSH_DIRECT_SOCKET)}),otherCommand:await connect(${JSON.stringify(path.join(otherLease.directory, 'command.sock'))}),direct:await connect({host:'203.0.113.1',port:443}),api:await api()}));`, { mode: 0o600 });
  const boundaryResult = await command(main, `${quote(node)} ${quote(probe)}`); assert.equal(boundaryResult.code, 0);
  const boundary = parseJsonLine(boundaryResult.text);
  proof.fence = boundary;
  assert.deepEqual(boundary, { key: true, store: true, helper: true, auth: true, otherDirect: true, otherCommand: true, direct: true, api: true });
  const api = await command(main, '/usr/bin/curl -fsS --max-time 5 http://api-fixture.envara.invalid/ping');
  assert.equal(api.code, 0); assert(api.text.includes('ENVARA_API_ROUTE_OK'));
  proof.fence = boundary;
  check('terminal/API direct network and private files remain fenced; cross-session sockets, wrong tokens, ungranted aliases and caller-chosen relay targets refuse');

  stage = 'cancel active native SSH and retain independent session';
  const beforeCancelFamily = await observeProcesses(), cancelSession = await create('routing-main');
  const cancelledInteractive = await startInteractive(cancelSession, records['routing-main'].alias);
  const cancelledFamily = [...(await observeProcesses()).values()].filter(row => !beforeCancelFamily.has(row.pid));
  assert(cancelledFamily.length >= 2);
  const cancelledLease = manager.sessions.get(cancelSession.sessionId), cancelledDirectory = cancelledLease.directory;
  const cancelledEnvironment = { ...terminal.sessions.get(cancelSession.sessionId).sshBinding.environment };
  await bounded(() => terminal.close({ sessionId: cancelSession.sessionId }), 'FIXTURE_CANCEL_DEADLINE');
  await wait(() => events.some(item => item.event === 'closed' && item.connection === cancelledInteractive.connection), 'FIXTURE_CANCEL_CONNECTION_REMAINS');
  await wait(async () => { const rows = await processRows(); return cancelledFamily.every(row => rows.get(row.pid)?.birth !== row.birth); }, 'FIXTURE_CANCEL_PROCESS_REMAINS');
  assert(!manager.sessions.has(cancelSession.sessionId)); await assert.rejects(lstat(cancelledDirectory), { code: 'ENOENT' });
  assert.deepEqual(await relayFrame(cancelledEnvironment.ENVARA_SSH_DIRECT_SOCKET,
    { version: 1, token: cancelledEnvironment.ENVARA_SSH_DIRECT_TOKEN, alias: records['routing-main'].alias }, { removed: true }), { removed: true });
  const independent = await command(second, `ssh -T ${key.alias} envara-fixture`); assert.equal(independent.code, 0);
  check('cancelling a real interactive SSH terminal removes its relay and broker while another terminal remains usable');

  stage = 'revoke active direct relay and subsequent authorization';
  const revoked = await create('routing-revoke'), running = await startInteractive(revoked, records['routing-revoke'].alias);
  await bounded(() => terminal.invalidateManagedProxy('fixture-revoke-route'), 'FIXTURE_REVOKE_DEADLINE');
  await wait(() => events.some(item => item.event === 'closed' && item.connection === running.connection), 'FIXTURE_REVOKE_CONNECTION_REMAINS');
  await wait(() => new RegExp(`${running.done}:[0-9]+`).test(text(revoked).slice(running.start)), 'FIXTURE_REVOKE_CLIENT_REMAINS');
  assert.notEqual(Number(new RegExp(`${running.done}:([0-9]+)`).exec(text(revoked).slice(running.start))[1]), 0);
  const beforeReentry = { saved: opened('saved'), proxy: proxyEvents.length };
  const reentry = await command(revoked, `ssh -T ${records['routing-revoke'].alias} envara-fixture`); assert.notEqual(reentry.code, 0);
  assert.deepEqual({ saved: opened('saved'), proxy: proxyEvents.length }, beforeReentry);
  check('revocation closes the active saved direct transport and refuses subsequent authentication without switching routes');

  stage = 'secret projections and final evidence';
  const publicData = JSON.stringify({ list: await manager.list({ id: 'routing-main' }), snapshot: await terminal.snapshot(), records: { ...records, key } });
  assert(!publicData.includes(password)); for (const value of outputs.values()) assert(!value.includes(password));
  proof.password = { ownedFilesScanned: await scanPasswordFiles(temporary), publicProjectionContainsPassword: false, terminalOutputContainsPassword: false };
  stage = 'application restart retains locked destination identity';
  assert.equal((await manager.list({ id: 'routing-revoke' })).connections[0].passwordReady, true);
  await bounded(() => terminal.shutdown(), 'FIXTURE_RESTART_TERMINAL_DEADLINE');
  await bounded(() => manager.close(), 'FIXTURE_RESTART_MANAGER_DEADLINE');
  manager = new TerminalSshManager({ dataDir, hostHome, nodeExecutable: node, agentRoot: path.join(temporary, 'agents'),
    spawn: (program, args, settings) => nativeLaunch(program, args, settings) });
  managers.push(manager); await manager.ready;
  const restored = await manager.list({ id: 'routing-revoke' });
  assert.equal(restored.connections.length, 1); assert.equal(restored.connections[0].passwordReady, false);
  terminal = new TerminalService({ dataDir, sshManager: manager, availableLocales: ['en_US.UTF-8'], additionalExecutablePaths: [path.dirname(node)],
    resolveContext: async id => context(id), ptyFactory: (program, args, settings) => nativeLaunch(program, args, settings, true),
    onEvent: event => { if (event.type === 'data') outputs.set(event.sessionId, (outputs.get(event.sessionId) ?? '') + event.data); } });
  services.push(terminal); await terminal.ready; terminal.hostHome = hostHome;
  const afterRestart = await create('routing-revoke'), restartCounts = { saved: opened('saved'), proxy: proxyEvents.length };
  for (const source of [`ssh -T ${records['routing-revoke'].alias} envara-fixture`,
    `ssh -T -p ${ports.saved} fixture@127.0.0.1 envara-fixture`, `ssh -T fixture@127.0.0.1 -p ${ports.saved} envara-fixture`,
    `ssh -T ${quote('fixture@[::ffff:127.0.0.1]')} -p ${ports.saved} envara-fixture`,
    `ssh -T ${quote('fixture@[0:0:0:0:0:ffff:7f00:1]')} -p ${ports.saved} envara-fixture`]) {
    const result = await command(afterRestart, source); assert.notEqual(result.code, 0); assert(result.text.includes('SSH_SAVED_CONNECTION_UNAVAILABLE'));
  }
  assert.deepEqual({ saved: opened('saved'), proxy: proxyEvents.length }, restartCounts);
  const afterRestartUnknown = await command(afterRestart, `ssh -T ${target} envara-fixture`, { interactiveTrust: true });
  assert.equal(afterRestartUnknown.code, 0); assert(afterRestartUnknown.text.includes('ENVARA_SSH_ROUTING_OK'));
  check('after a manager restart, saved password destinations stay locked while a truly unconfigured destination still uses the proxy');
  stage = 'final evidence';
  assert.equal(events.filter(item => item.event === 'env').length, 0); await assert.rejects(lstat(localCommandMarker), { code: 'ENOENT' });
  proof.sourceHashes = {};
  for (const name of ['terminal-service.mjs', 'terminal-ssh-manager.mjs', 'terminal-ssh-command.mjs', 'terminal-ssh-proxy.mjs', 'terminal-ssh-direct.mjs', 'terminal-ssh-broker.mjs', 'terminal-ssh-client.mjs', 'terminal-network-fence.mjs'])
    proof.sourceHashes[name] = await digestFile(path.join(moduleRoot, 'electron', name));
  proof.packageVersion = JSON.parse(await readFile(path.join(moduleRoot, 'package.json'), 'utf8')).version;
  check('synthetic SSH passwords stay out of files, launch specifications, public metadata and terminal output');
  proof.passed = true;
} catch (error) {
  proof.failure = { stage, code: /^[A-Z\d_]+$/.test(String(error?.code ?? '')) ? error.code : 'FIXTURE_ASSERTION' };
  const location = error?.stack?.split('\n').find(line => /verify-terminal-ssh-routing\.mjs:\d+:\d+/.test(line))?.match(/:(\d+):(\d+)\)?$/);
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
    serverEnvironmentRequests: count('env'), nativeLaunches: nativeLaunches.length };
  if (outputPath) {
    await mkdir(path.dirname(outputPath), { recursive: true, mode: 0o700 });
    await writeFile(outputPath, JSON.stringify(proof, null, 2) + '\n', { mode: 0o600 });
  }
  process.off('SIGINT', cancel); process.off('SIGTERM', cancel);
}
console.log(JSON.stringify({ passed: proof.passed, checks: proof.checks.length, proof: outputPath ?? null,
  cleanup: proof.cleanup, ...(proof.failure ? { failure: proof.failure } : {}) }, null, 2));
if (!proof.passed) process.exitCode = controller.signal.aborted ? 130 : 1;
