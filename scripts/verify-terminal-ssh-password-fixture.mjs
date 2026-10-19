/** Opt-in, disposable saved-password SSH acceptance through host-direct relays.
 * Only an owned loopback SSH server is used. No user passwords/accounts,
 * external SSH endpoints, model calls, real remote shell or host settings.
 * ELECTRON_RUN_AS_NODE=1 <Electron-or-Envara> scripts/verify-terminal-ssh-password-fixture.mjs --run
 * Optional --packaged /absolute/Envara.app --claude /absolute/native/versions/X.Y.Z
 * Requires an already installed Python with Paramiko; never downloads it.
 */
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import net from 'node:net';
import path from 'node:path';
import { promisify, stripVTControlCharacters } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2), options = new Set(['--run', '--packaged', '--claude', '--node', '--python']);
for (let i = 0; i < argv.length; i++) {
  assert(options.has(argv[i]), 'Unsupported fixture option.');
  if (argv[i] !== '--run') assert(argv[++i] && path.isAbsolute(argv[i]), 'Runtime arguments must be absolute paths.');
}
const option = name => argv.includes(name) ? argv[argv.indexOf(name) + 1] : null;
if (!argv.includes('--run')) {
  console.log(JSON.stringify({ schema: 'envara.ssh-password-fixture-plan/v1', optIn: true, productionReady: false,
    savedHostRoute: 'host-direct', ownedLoopbackOnly: true, syntheticPasswordsOnly: true,
    remoteShell: false, downloads: false, modelCalls: false, hostSettingsModified: false }));
  process.exit(0);
}
assert.equal(process.platform, 'darwin'); assert(process.versions.electron, 'Use ELECTRON_RUN_AS_NODE=1 and Electron.');
const application = option('--packaged'), resources = application ? path.join(application, 'Contents/Resources') : null;
if (resources) { assert(application.endsWith('.app')); assert.equal(await realpath(resources), await realpath(process.resourcesPath)); }
const moduleRoot = resources ? path.join(resources, 'app.asar') : root;
const moduleURL = name => pathToFileURL(path.join(moduleRoot, 'electron', name));
const [{ TerminalService }, { TerminalSshManager }, { TerminalBrowserBroker }, { TerminalLinkChannel }, { captureTerminalProcess, closeTerminalProcess }] = await Promise.all([
  import(moduleURL('terminal-service.mjs')), import(moduleURL('terminal-ssh-manager.mjs')),
  import(moduleURL('terminal-browser-broker.mjs')), import(moduleURL('terminal-link-channel.mjs')), import(moduleURL('terminal-process.mjs')),
]);
const require = createRequire(moduleURL('terminal-service.mjs')), execute = promisify(execFile);
const bundledNode = path.join(resources ?? path.join(root, 'build'), 'backend/playwright-driver/node');
const node = await realpath(option('--node') ?? bundledNode);
if (resources) assert.equal(node, await realpath(bundledNode));
const claude = option('--claude') ? await realpath(option('--claude')) : null, python = option('--python') ?? 'python3';
const safeEnvironment = { PATH: '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' };
const run = (command, args) => execute(command, args, { env: safeEnvironment, timeout: 15000, maxBuffer: 2 * 1024 * 1024 });
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const wait = async (predicate, code, milliseconds = 15000) => {
  const until = Date.now() + milliseconds;
  while (Date.now() < until) { const value = await predicate(); if (value) return value; await sleep(30); }
  throw Object.assign(new Error(code), { code });
};
const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
const parseLine = text => { for (const line of text.split('\n')) { try { return JSON.parse(line.trim()); } catch {} } throw Object.assign(new Error(), { code: 'FIXTURE_JSON_MISSING' }); };
const artifactRoot = path.join(root, 'build/local-verification/ssh-app-lifetime');
await mkdir(artifactRoot, { recursive: true, mode: 0o700 });
const runDir = await realpath(await mkdtemp(path.join(artifactRoot, 'run-'))), temporary = await realpath(await mkdtemp('/private/tmp/evspw-'));
const password = randomBytes(24).toString('hex'), wrongPassword = randomBytes(24).toString('hex');
const proxyUser = randomBytes(12).toString('hex'), proxyPassword = randomBytes(24).toString('hex');
const secrets = [password, wrongPassword];
const proof = { schema: 'envara.ssh-password-app-lifetime-fixture/v1', passed: false, packagedModules: !!resources, checks: [],
  limitations: ['Saved key/password SSH uses host-direct relays to an owned loopback Paramiko server; no real account, public host exit or external endpoint is tested.',
    'The environment proxy rejects all CONNECT requests and must remain unused; unsaved-host proxy routing is covered by the separate routing fixture.',
    'Optional official Claude runs --version only. MCP bindings are synthetic; no model request or browser launch.',
    'Time advancement uses only injected clocks, never the system clock. Route revocation uses the real service failure callback, not a real core crash.'] };
const stats = { proxyConnections: 0, serverConnections: 0, passwordAttempts: 0, passwordRejected: 0, authenticated: 0,
  publicKeyAttempts: 0, executions: 0, ptyRequests: 0, interactive: 0, pong: 0, active: 0, closed: 0 };
const peers = new Set(), output = new Map(), managersChildren = [], brokerDirectories = new Set(), passwordBrokerPaths = new Map(), lifecycle = [];
let launchSpecificationsChecked = 0;
const inspectLaunch = (file, args, options) => { const value = JSON.stringify({ file, args, environment: options.env }); for (const secret of secrets) assert(!value.includes(secret)); launchSpecificationsChecked++; };
const recordLifecycle = (event, fields = {}) => { if (lifecycle.length < 512) lifecycle.push({ event, at: Date.now(), ...fields }); };
let phase = 'prepare', manager, terminal, broker, links, proxyServer, pythonChild, sshPort, clockOffset = 0, browserLaunches = 0;
let finiteAlias = null, finiteClock = Date.now(), finiteDeadline = null;
const now = () => Date.now() + clockOffset;
const check = text => { proof.checks.push(text); console.log(`PASS ${text}`); };
const countSnapshot = () => ({ ...stats });
const assertNoConnection = before => {
  for (const key of ['serverConnections', 'proxyConnections', 'passwordAttempts', 'publicKeyAttempts']) assert.equal(stats[key], before[key], key);
};
const serverSource = String.raw`import json,sys,socket,threading,time,paramiko,base64
root=sys.argv[1]; secret=json.loads(sys.stdin.readline())['password']
client=base64.b64decode(open(root+'/client.pub').read().split()[1])
keys=[paramiko.Ed25519Key.from_private_key_file(root+'/server'),paramiko.Ed25519Key.from_private_key_file(root+'/server-alt')]
def event(name,**extra): print(json.dumps(dict(event=name,**extra)),flush=True)
listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',0));listener.listen(12)
event('ready',port=listener.getsockname()[1])
class Server(paramiko.ServerInterface):
 def __init__(self): self.started=threading.Event();self.kind=None
 def get_allowed_auths(self,user): return 'password,publickey'
 def check_auth_password(self,user,password):
  accepted=user=='fixture' and password==secret;event('passwordAttempt',accepted=accepted);return paramiko.AUTH_SUCCESSFUL if accepted else paramiko.AUTH_FAILED
 def check_auth_publickey(self,user,key):
  accepted=user=='fixture' and key.asbytes()==client;event('publicKeyAttempt',accepted=accepted);return paramiko.AUTH_SUCCESSFUL if accepted else paramiko.AUTH_FAILED
 def check_auth_interactive(self,*args): return paramiko.AUTH_FAILED
 def check_channel_request(self,kind,chanid): return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
 def check_channel_pty_request(self,*args): event('pty');return True
 def check_channel_shell_request(self,channel): self.kind='interactive';self.started.set();return True
 def check_channel_exec_request(self,channel,command):
  if command!=b'envara-fixture': return False
  self.kind='exec';self.started.set();return True
 def check_channel_forward_agent_request(self,*args): return False
 def check_channel_direct_tcpip_request(self,*args): return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
 def check_port_forward_request(self,*args): return False
 def check_global_request(self,*args): return False
def serve(sock):
 transport=None;event('opened')
 try:
  sock.settimeout(12);transport=paramiko.Transport(sock);transport.add_server_key(keys[1 if open(root+'/mode').read()=='changed' else 0]);instance=Server();transport.start_server(server=instance)
  channel=transport.accept(15)
  if channel is None: return
  if transport.is_authenticated(): event('authenticated')
  if not instance.started.wait(5): return
  if instance.kind=='exec': channel.sendall(b'ENVARA_PASSWORD_EXEC_OK\n');channel.send_exit_status(0);event('executed');channel.shutdown_write();time.sleep(.1)
  else:
   channel.settimeout(90);channel.sendall(b'ENVARA_PASSWORD_READY\n');event('interactive');buffer=b''
   while transport.is_active():
    chunk=channel.recv(4096)
    if not chunk: break
    buffer+=chunk
    if len(buffer)>16384: break
    while b'\n' in buffer or b'\r' in buffer:
     indices=[p for p in [buffer.find(b'\n'),buffer.find(b'\r')] if p>=0];at=min(indices);line=buffer[:at];buffer=buffer[at+1:]
     if line==b'fixture-ping': channel.sendall(b'ENVARA_PASSWORD_PONG\n');event('pong')
     elif line==b'exit': channel.send_exit_status(0);channel.close();return
     elif line==b'abrupt': return
  channel.close()
 except Exception: pass
 finally:
  if transport: transport.close()
  sock.close();event('closed')
while True:
 sock,_=listener.accept();event('accepted');threading.Thread(target=serve,args=(sock,),daemon=True).start()
`;
async function ownedProcesses() {
  const { stdout } = await run('/bin/ps', ['-axo', 'pid=,ppid=,lstart=,comm=']);
  const rows = new Map();
  for (const line of stdout.split('\n')) {
    const m = line.trim().match(/^(\d+)\s+(\d+)\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+)$/);
    if (m) rows.set(Number(m[1]), { pid: Number(m[1]), parent: Number(m[2]), birth: m[3].replace(/\s+/g, ' '), executable: m[4] });
  }
  const owned = new Map(); let changed = true;
  while (changed) { changed = false; for (const row of rows.values()) if (!owned.has(row.pid) && (row.parent === process.pid || owned.has(row.parent))) { owned.set(row.pid, row); changed = true; } }
  for (const [pid, row] of owned) if (row.executable === '/bin/ps') owned.delete(pid);
  return owned;
}
async function inspectSecretsInProcesses() {
  const before = await ownedProcesses(); let checked = 0;
  for (const row of before.values()) {
    try {
      const { stdout } = await run('/bin/ps', ['eww', '-p', String(row.pid), '-o', 'command=']);
      const after = await ownedProcesses(), same = after.get(row.pid);
      if (!same || same.parent !== row.parent || same.birth !== row.birth) continue;
      for (const secret of secrets) assert(!stdout.includes(secret)); checked++;
    } catch (error) { if (error.code !== 1) throw error; }
  }
  assert(checked > 0); return checked;
}
async function inspectSecretFiles(directory, excludedProgram) {
  let count = 0;
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) { count += await inspectSecretFiles(filename, excludedProgram); continue; }
    if (!entry.isFile()) continue;
    const info = await lstat(filename);
    if (info.size > 2 * 1024 * 1024) { assert.equal(filename, excludedProgram, 'Only the unchanged native CLI program may be excluded from the bounded text scan.'); continue; }
    const bytes = await readFile(filename); for (const secret of secrets) assert(!bytes.includes(Buffer.from(secret))); count++;
  }
  return count;
}
try {
  await run(python, ['-I', '-c', 'import paramiko']);
  for (const name of ['client', 'server', 'server-alt']) await run('/usr/bin/ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'envara-password-fixture', '-f', path.join(temporary, name)]);
  await writeFile(path.join(temporary, 'mode'), 'normal', { mode: 0o600 });
  const source = path.join(temporary, 'server.py'); await writeFile(source, serverSource, { mode: 0o600 });
  pythonChild = spawn(python, ['-I', source, temporary], { env: safeEnvironment, stdio: ['pipe', 'pipe', 'pipe'] });
  pythonChild.stdin.end(`${JSON.stringify({ password })}\n`); pythonChild.stderr.resume();
  let buffered = '';
  pythonChild.stdout.on('data', chunk => {
    buffered += chunk.toString(); if (buffered.length > 16384) { buffered = ''; return; }
    for (;;) { const end = buffered.indexOf('\n'); if (end < 0) break; const line = buffered.slice(0, end); buffered = buffered.slice(end + 1);
      try { const item = JSON.parse(line);
        if (item.event === 'ready') sshPort = item.port;
        if (item.event === 'accepted') stats.serverConnections++;
        if (item.event === 'passwordAttempt') { stats.passwordAttempts++; if (!item.accepted) stats.passwordRejected++; }
        if (item.event === 'publicKeyAttempt') stats.publicKeyAttempts++;
        if (item.event === 'authenticated') stats.authenticated++;
        if (item.event === 'executed') stats.executions++;
        if (item.event === 'pty') stats.ptyRequests++;
        if (item.event === 'interactive') stats.interactive++;
        if (item.event === 'pong') stats.pong++;
        if (item.event === 'opened') stats.active++;
        if (item.event === 'closed') { stats.active--; stats.closed++; }
      } catch {} }
  });
  await wait(() => sshPort, 'FIXTURE_SERVER_READY');
  const basic = `Basic ${Buffer.from(`${proxyUser}:${proxyPassword}`).toString('base64')}`;
  proxyServer = net.createServer(socket => {
    stats.proxyConnections++; peers.add(socket); socket.on('error', () => {}); socket.once('close', () => peers.delete(socket)); let buffer = Buffer.alloc(0);
    socket.on('data', function parse(chunk) {
      buffer = Buffer.concat([buffer, chunk]); if (buffer.length > 16384) return socket.destroy(); const at = buffer.indexOf('\r\n\r\n'); if (at < 0) return;
      socket.off('data', parse); socket.pause(); const header = buffer.subarray(0, at).toString('latin1');
      if (!header.split('\r\n').includes(`Proxy-Authorization: ${basic}`)) return socket.end('HTTP/1.1 407 Refused\r\n\r\n');
      // Saved SSH must use its main-process relay. This context-only proxy
      // cannot map a synthetic hostname or silently provide the saved route.
      socket.end('HTTP/1.1 403 Refused\r\n\r\n');
    });
  });
  await new Promise((resolve, reject) => { proxyServer.once('error', reject); proxyServer.listen(0, '127.0.0.1', resolve); });
  const dataDir = path.join(temporary, 'data'), hostHome = path.join(temporary, 'host'), working = path.join(temporary, 'work');
  for (const directory of [dataDir, hostHome, working]) await mkdir(directory, { mode: 0o700 });
  await mkdir(path.join(hostHome, '.ssh'), { mode: 0o700 });
  const hostPublic = (await readFile(path.join(temporary, 'server.pub'), 'utf8')).trim().split(/\s+/).slice(0, 2).join(' ');
  await writeFile(path.join(hostHome, '.ssh/known_hosts'), `[127.0.0.1]:${sshPort} ${hostPublic}\n`, { mode: 0o600 });
  manager = new TerminalSshManager({ dataDir, hostHome, nodeExecutable: node, agentRoot: path.join(temporary, 'agents'), now,
    spawn: (...args) => { const child = spawn(...args); managersChildren.push(child); return child; } });
  const actualBrokerFactory = manager.createPasswordBroker;
  manager.createPasswordBroker = async settings => {
    // Exercise the broker's separate finite-authorization compatibility path.
    // The manager and its public on-disk session remain app-lifetime; no
    // generated product file is rewritten, and no system clock is changed.
    let brokerSettings = settings;
    if (finiteAlias && settings.manifest.connections.some(record => record.alias === finiteAlias)) {
      finiteClock = Date.now(); finiteDeadline = finiteClock + 60_000;
      const manifest = structuredClone(settings.manifest);
      assert.equal(manifest.version, 2);
      manifest.expiresAt = finiteDeadline;
      for (const connection of manifest.connections) connection.expiresAt = finiteDeadline;
      brokerSettings = { ...settings, manifest, expiresAt: finiteDeadline, now: () => finiteClock };
    }
    const value = await actualBrokerFactory({ ...brokerSettings,
      spawn: (file, args, options) => { inspectLaunch(file, args, options); return spawn(file, args, options); },
      ptyFactory: (file, args, options) => {
        inspectLaunch(file, args, options);
        const pty = require('node-pty').spawn(file, args, options);
        recordLifecycle('native-pty-created', { pid: pty.pid });
        pty.onExit(event => recordLifecycle('native-pty-exit', { pid: pty.pid, code: event.exitCode, signal: event.signal }));
        return pty;
      },
      processControl: {
        capture: async pid => { recordLifecycle('capture-start', { pid }); const identity = await captureTerminalProcess(pid); recordLifecycle('captured', { pid }); return identity; },
        close: async args => { const pid = args.pty?.pid; recordLifecycle('close-start', { pid }); const result = await closeTerminalProcess(args); recordLifecycle('close-end', { pid, ok: result?.ok === true }); return result; },
      },
    });
    passwordBrokerPaths.set(settings.directory, { directory: settings.directory, publicDirectory: settings.publicDirectory, socket: value.socket });
    return value;
  };
  await manager.ready;
  const records = new Map();
  for (const id of ['pw-main', 'pw-wrong', 'pw-revoke', 'pw-mixed', 'pw-finite']) {
    const prepared = await manager.preparePassword({ id, host: '127.0.0.1', port: sshPort, user: 'fixture' });
    records.set(id, await manager.save({ id, name: 'Disposable password SSH', selectionToken: prepared.selectionToken, password: id === 'pw-wrong' ? wrongPassword : password }));
  }
  finiteAlias = records.get('pw-finite').alias;
  const mixedIdentity = await manager.prepareIdentity({ id: 'pw-mixed', host: '127.0.0.1', port: sshPort, user: 'fixture', keyPath: path.join(temporary, 'client') });
  const mixedKey = await manager.save({ id: 'pw-mixed', name: 'Disposable app-lifetime key authority', selectionToken: mixedIdentity.selectionToken });
  check('Temporary password grants use existing isolated host trust and main memory; connection records contain no password.');
  const proxy = { protocol: 'http', host: '127.0.0.1', port: proxyServer.address().port, username: proxyUser, password: proxyPassword };
  const context = id => ({ id, name: 'Synthetic password fixture', timezone: 'UTC', locale: 'en-US', proxy, proxyId: id === 'pw-revoke' ? 'fixture-revoke' : 'fixture-route', managedProxy: true,
    privacy: { mode: 'standard' }, network: { ok: true, source: 'owned-loopback-fixture' } });
  if (claude) {
    const service = { snapshot: async () => ({ profiles: [{ id: 'pw-main', name: 'Synthetic password browser', proxyId: 'fixture-route', engine: 'cloakbrowser', timezone: 'UTC', locale: 'en-US' }] }),
      resolveWorkspaceContext: async id => context(id), ensureBoundBrowser: async () => { browserLaunches++; throw new Error('Browser launch is outside this fixture.'); } };
    broker = new TerminalBrowserBroker({ service, dataDir, nodeExecutable: node });
    links = new TerminalLinkChannel({ root: dataDir, onLink: () => { throw new Error('No links are requested.'); } }); await links.listen();
  }
  terminal = new TerminalService({ dataDir, sshManager: manager, availableLocales: ['en_US.UTF-8'], additionalExecutablePaths: [path.dirname(node)], resolveContext: async id => context(id),
    ...(claude ? { browserBroker: broker, linkChannel: links, claudeExecutableResolver: async () => claude } : {}),
    ptyFactory: (command, args, settings) => { inspectLaunch(command, args, settings); return require('node-pty').spawn(command, args, settings); },
    onEvent: event => { if (event.type === 'data') output.set(event.sessionId, (output.get(event.sessionId) ?? '') + event.data); } });
  await terminal.ready; terminal.hostHome = hostHome;
  const text = session => stripVTControlCharacters(output.get(session.sessionId) ?? '');
  const command = async (session, source) => {
    const tag = `EVPW_${randomBytes(7).toString('hex')}`, start = text(session).length;
    await terminal.write({ sessionId: session.sessionId, data: `${source}; printf '\\n${tag}:%d\\n' "$?"\r` });
    await wait(() => new RegExp(`${tag}:\\d+`).test(text(session).slice(start)), 'FIXTURE_COMMAND_DEADLINE', 25000);
    const value = text(session).slice(start); return { code: Number(new RegExp(`${tag}:(\\d+)`).exec(value)[1]), text: value };
  };
  const create = id => terminal.create({ id, directory: working, fresh: true });
  const invoke = (session, id = 'pw-main') => command(session, `ssh -T ${records.get(id).alias} envara-fixture`);
  phase = 'plain-password-command'; const first = await create('pw-main'); assert(first.networkFence && first.ssh.privateKeyProtection);
  const beforeFirst = countSnapshot();
  const firstResult = await invoke(first); assert.equal(firstResult.code, 0); assert(firstResult.text.includes('ENVARA_PASSWORD_EXEC_OK'));
  assert.equal(stats.serverConnections, beforeFirst.serverConnections + 1); assert.equal(stats.proxyConnections, 0);
  check('Ordinary fenced PTY authenticates saved password SSH through its host-direct relay to the owned server without contacting the environment proxy.');
  phase = 'duplicate'; const beforeDuplicate = countSnapshot(), second = await terminal.duplicate({ sessionId: first.sessionId });
  assert(second.sessionId !== first.sessionId); assertNoConnection(beforeDuplicate);
  const secondResult = await invoke(second); assert.equal(secondResult.code, 0); assert(secondResult.text.includes('ENVARA_PASSWORD_EXEC_OK'));
  check('Duplicated shell is idle and independent, then authenticates through its own password broker and host-direct relay on explicit SSH.');
  phase = 'mixed-key-password'; const mixed = await create('pw-mixed');
  assert(terminal.sessions.get(mixed.sessionId).sshBinding.agentSocket);
  const keyResult = await command(mixed, `ssh -T ${mixedKey.alias} envara-fixture`);
  assert.equal(keyResult.code, 0); assert(keyResult.text.includes('ENVARA_PASSWORD_EXEC_OK')); assert(stats.publicKeyAttempts > 0);
  const mixedKeyShell = await terminal.duplicate({ sessionId: mixed.sessionId });
  const mixedKeyStart = text(mixedKeyShell).length, mixedKeyDone = `EVPW_MIXED_KEY_${randomBytes(7).toString('hex')}`;
  await terminal.write({ sessionId: mixedKeyShell.sessionId, data: `ssh -t ${mixedKey.alias}; printf '\\n${mixedKeyDone}:%d\\n' "$?"\r` });
  await wait(() => text(mixedKeyShell).slice(mixedKeyStart).includes('ENVARA_PASSWORD_READY'), 'FIXTURE_MIXED_KEY_READY');
  const mixedStart = text(mixed).length, mixedDone = `EVPW_MIXED_${randomBytes(7).toString('hex')}`;
  await terminal.write({ sessionId: mixed.sessionId, data: `ssh -t ${records.get('pw-mixed').alias}; printf '\\n${mixedDone}:%d\\n' "$?"\r` });
  await wait(() => text(mixed).slice(mixedStart).includes('ENVARA_PASSWORD_READY'), 'FIXTURE_MIXED_READY');
  phase = 'native-interactive'; let start = text(first).length;
  const interactiveDone = `EVPW_INTERACTIVE_${randomBytes(7).toString('hex')}`;
  await terminal.write({ sessionId: first.sessionId, data: `ssh -t ${records.get('pw-main').alias}; printf '\\n${interactiveDone}:%d\\n' "$?"\r` });
  await wait(() => text(first).slice(start).includes('ENVARA_PASSWORD_READY'), 'FIXTURE_INTERACTIVE_READY');
  assert(stats.ptyRequests > 0); const inspectedProcesses = await inspectSecretsInProcesses();
  await terminal.write({ sessionId: first.sessionId, data: 'fixture-ping\r' });
  await wait(() => text(first).slice(start).includes('ENVARA_PASSWORD_PONG'), 'FIXTURE_INTERACTIVE_PONG');
  phase = 'app-lifetime-active-connection';
  const timeAdvances = [3_600_001, 86_400_001];
  for (const offset of timeAdvances) {
    clockOffset = offset;
    const pingStart = text(first).length;
    await terminal.write({ sessionId: first.sessionId, data: 'fixture-ping\r' });
    await wait(() => text(first).slice(pingStart).includes('ENVARA_PASSWORD_PONG'), 'FIXTURE_ACTIVE_SSH_DISCONNECTED_BY_TIME');
    const description = terminal.readSessionSshConnections(terminal.sessions.get(first.sessionId));
    assert.equal(description.status, 'ready'); assert.equal(description.expiresAt, null);
    assert.equal((await manager.list({ id: 'pw-main' })).connections[0].passwordReady, true);
    const mixedPingStart = text(mixed).length;
    await terminal.write({ sessionId: mixed.sessionId, data: 'fixture-ping\r' });
    await wait(() => text(mixed).slice(mixedPingStart).includes('ENVARA_PASSWORD_PONG'), 'FIXTURE_MIXED_PASSWORD_DISCONNECTED_BY_TIME');
    const keyPingStart = text(mixedKeyShell).length;
    await terminal.write({ sessionId: mixedKeyShell.sessionId, data: 'fixture-ping\r' });
    await wait(() => text(mixedKeyShell).slice(keyPingStart).includes('ENVARA_PASSWORD_PONG'), 'FIXTURE_MIXED_KEY_DISCONNECTED_BY_TIME');
  }
  proof.applicationLifetime = { injectedClockOffsetsMs: timeAdvances, existingInteractivePongAtEachOffset: true,
    expiresAt: null, systemClockChanged: false };
  check('The same real interactive SSH connection keeps receiving PONG after injected time advances beyond one hour and one day.');
  phase = 'app-lifetime-new-connections';
  const existingAfterDay = await invoke(second); assert.equal(existingAfterDay.code, 0); assert(existingAfterDay.text.includes('ENVARA_PASSWORD_EXEC_OK'));
  const newAfterDay = await create('pw-main'), duplicateAfterDay = await terminal.duplicate({ sessionId: second.sessionId });
  for (const session of [newAfterDay, duplicateAfterDay]) {
    assert.equal(terminal.readSessionSshConnections(terminal.sessions.get(session.sessionId)).expiresAt, null);
    const result = await invoke(session); assert.equal(result.code, 0); assert(result.text.includes('ENVARA_PASSWORD_EXEC_OK'));
  }
  assert.notEqual(newAfterDay.sessionId, duplicateAfterDay.sessionId);
  await terminal.close({ sessionId: newAfterDay.sessionId }); await terminal.close({ sessionId: duplicateAfterDay.sessionId });
  proof.applicationLifetime.newAuthentication = { existingShell: true, newShell: true, duplicatedShell: true };
  check('After the injected day, existing, new and duplicated fenced shells still establish independent real password SSH connections.');
  phase = 'mixed-app-lifetime';
  await terminal.write({ sessionId: mixed.sessionId, data: 'exit\r' });
  await wait(() => new RegExp(`${mixedDone}:\\d+`).test(text(mixed).slice(mixedStart)), 'FIXTURE_MIXED_CLIENT_RETURN');
  assert.equal(Number(new RegExp(`${mixedDone}:(\\d+)`).exec(text(mixed).slice(mixedStart))[1]), 0);
  await terminal.write({ sessionId: mixedKeyShell.sessionId, data: 'exit\r' });
  await wait(() => new RegExp(`${mixedKeyDone}:\\d+`).test(text(mixedKeyShell).slice(mixedKeyStart)), 'FIXTURE_MIXED_KEY_CLIENT_RETURN');
  assert.equal(Number(new RegExp(`${mixedKeyDone}:(\\d+)`).exec(text(mixedKeyShell).slice(mixedKeyStart))[1]), 0);
  const keyAfterDay = await command(mixedKeyShell, `ssh -T ${mixedKey.alias} envara-fixture`);
  assert.equal(keyAfterDay.code, 0); assert(keyAfterDay.text.includes('ENVARA_PASSWORD_EXEC_OK'));
  const mixedPassword = await invoke(mixed, 'pw-mixed'); assert.equal(mixedPassword.code, 0); assert(mixedPassword.text.includes('ENVARA_PASSWORD_EXEC_OK'));
  const mixedAfterDay = await create('pw-mixed');
  for (const alias of [mixedKey.alias, records.get('pw-mixed').alias]) {
    const result = await command(mixedAfterDay, `ssh -T ${alias} envara-fixture`);
    assert.equal(result.code, 0); assert(result.text.includes('ENVARA_PASSWORD_EXEC_OK'));
  }
  await terminal.close({ sessionId: mixedAfterDay.sessionId });
  await terminal.close({ sessionId: mixed.sessionId }); await terminal.close({ sessionId: mixedKeyShell.sessionId });
  proof.mixedAuthorization = { nativeKeyAuthenticatedBeforeAdvancement: true, activeKeyPongAtEachOffset: true,
    activePasswordPongAtEachOffset: true, newKeyAuthenticationAfterDay: true, newPasswordAuthenticationAfterDay: true,
    freshMixedSessionAuthenticatesBothAfterDay: true };
  check('Mixed real key/password sessions retain both live SSH connections across injected time advances and authenticate again from existing and newly created shells after one day.');
  const closedBeforeExit = stats.closed; await terminal.write({ sessionId: first.sessionId, data: 'exit\r' });
  await wait(() => stats.closed > closedBeforeExit, 'FIXTURE_INTERACTIVE_EXIT');
  phase = 'native-interactive-client-return';
  await wait(() => new RegExp(`${interactiveDone}:\\d+`).test(text(first).slice(start)), 'FIXTURE_INTERACTIVE_CLIENT_RETURN', 15000);
  assert.equal(Number(new RegExp(`${interactiveDone}:(\\d+)`).exec(text(first).slice(start))[1]), 0);
  assert.equal((await command(first, 'true')).code, 0);
  check('Real remote PTY carries fixed interactive input/output; owned native process argv/environment contain no fixture password.');
  phase = 'abrupt-transport-eof'; start = text(first).length;
  const abruptDone = `EVPW_ABRUPT_${randomBytes(7).toString('hex')}`;
  await terminal.write({ sessionId: first.sessionId, data: `ssh -t ${records.get('pw-main').alias}; printf '\\n${abruptDone}:%d\\n' "$?"\r` });
  await wait(() => text(first).slice(start).includes('ENVARA_PASSWORD_READY'), 'FIXTURE_ABRUPT_READY');
  const closedBeforeAbrupt = stats.closed;
  await terminal.write({ sessionId: first.sessionId, data: 'abrupt\r' });
  await wait(() => stats.closed > closedBeforeAbrupt, 'FIXTURE_ABRUPT_REMOTE_CLOSED');
  await wait(() => new RegExp(`${abruptDone}:\\d+`).test(text(first).slice(start)), 'FIXTURE_ABRUPT_CLIENT_HANG', 15000);
  assert.notEqual(Number(new RegExp(`${abruptDone}:(\\d+)`).exec(text(first).slice(start))[1]), 0);
  proof.abruptTransportEOF = { remoteClosedWithoutChannelClose: true, nativeClientReturnedFailure: true, noHang: true };
  check('Abrupt remote transport EOF without SSH channel-close returns a native failure promptly through the saved host-direct route.');
  phase = 'cancel-interactive';
  const beforeCancelOwned = await ownedProcesses(), cancelSession = await terminal.duplicate({ sessionId: first.sessionId });
  start = text(cancelSession).length;
  await terminal.write({ sessionId: cancelSession.sessionId, data: `ssh -t ${records.get('pw-main').alias}\r` });
  await wait(() => text(cancelSession).slice(start).includes('ENVARA_PASSWORD_READY'), 'FIXTURE_CANCEL_READY');
  const cancelOwned = [...(await ownedProcesses()).values()].filter(row => !beforeCancelOwned.has(row.pid));
  assert(cancelOwned.length >= 2, 'Cancellation must observe the real terminal and its SSH client family.');
  const closedBeforeCancel = stats.closed;
  await terminal.close({ sessionId: cancelSession.sessionId });
  await wait(() => stats.closed > closedBeforeCancel, 'FIXTURE_CANCEL_CLOSED');
  await wait(async () => { const current = await ownedProcesses(); return cancelOwned.every(row => current.get(row.pid)?.birth !== row.birth); }, 'FIXTURE_CANCEL_FAMILY_REMAINS');
  assert(!manager.sessions.has(cancelSession.sessionId));
  proof.cancellation = { terminalClose: true, observedOwnedFamilyCount: cancelOwned.length, observedFamilyAbsent: true };
  assert.equal((await command(second, 'true')).code, 0);
  check('Closing an owned interactive terminal cancels native SSH and removes its observed process family and broker; another session remains usable.');
  phase = 'wrong-password'; const wrong = await create('pw-wrong'), beforeWrong = countSnapshot(), rejected = await invoke(wrong, 'pw-wrong');
  assert.notEqual(rejected.code, 0); assert.equal(stats.passwordAttempts - beforeWrong.passwordAttempts, 1); assert(stats.passwordRejected > 0);
  assert.equal(stats.serverConnections, beforeWrong.serverConnections + 1); assert.equal(stats.proxyConnections, beforeWrong.proxyConnections);
  await terminal.close({ sessionId: wrong.sessionId });
  check('A wrong synthetic password makes exactly one server authentication attempt and never succeeds.');
  phase = 'changed-host-key'; await writeFile(path.join(temporary, 'mode'), 'changed');
  const beforeChanged = countSnapshot(), changed = await invoke(first);
  assert.notEqual(changed.code, 0); assert.equal(stats.passwordAttempts, beforeChanged.passwordAttempts);
  assert.equal(stats.serverConnections, beforeChanged.serverConnections + 1); assert.equal(stats.proxyConnections, beforeChanged.proxyConnections);
  await writeFile(path.join(temporary, 'mode'), 'normal');
  check('Changed host key is refused before any password authentication attempt.');
  let dedicated = null, excludedProgram = null;
  if (claude) {
    phase = 'dedicated-claude'; dedicated = await terminal.create({ id: 'pw-main', directory: working, fresh: true, kind: 'claude-code', browserProfileId: 'pw-main', claudeInstallSource: 'local' });
    assert(dedicated.deviceIdentifierRestrictions && dedicated.ssh.privateKeyProtection && dedicated.networkFence);
    for (const item of broker.sessions.values()) brokerDirectories.add(item.directory);
    const version = await command(dedicated, 'claude --version'); assert.equal(version.code, 0); assert(version.text.includes(`${path.basename(claude)} (Claude Code)`));
    const result = await invoke(dedicated); assert.equal(result.code, 0); assert(result.text.includes('ENVARA_PASSWORD_EXEC_OK')); assert.equal(browserLaunches, 0);
    excludedProgram = terminal.sessions.get(dedicated.sessionId).claudeLaunch.executable;
    proof.claude = { version: path.basename(claude), versionOnly: true, modelCalled: false, deviceIdentifierRestrictions: true };
    check('Dedicated Claude session runs only the unchanged native CLI version, then saved password SSH through its host-direct relay, retaining device and browser-session restrictions.');
  }
  phase = 'broker-fence';
  const firstLease = manager.sessions.get(first.sessionId), otherLease = manager.sessions.get(second.sessionId);
  const firstPaths = passwordBrokerPaths.get(firstLease.directory), otherPaths = passwordBrokerPaths.get(otherLease.directory); assert(firstPaths && otherPaths);
  const privateNames = (await readdir(firstLease.directory)).filter(name => /askpass/i.test(name)); assert(privateNames.length > 0);
  const privateHelper = path.join(firstLease.directory, privateNames[0]), authSocket = path.join(firstLease.directory, 'auth.sock');
  const probe = `const fs=require('node:fs'),net=require('node:net');const denied=f=>{try{f();return false;}catch(error){return ['EPERM','EACCES'].includes(error.code);}};
    const connect=address=>new Promise(resolve=>{let done=false;const socket=net.connect(address);const finish=value=>{if(done)return;done=true;clearTimeout(timer);socket.destroy();resolve(value);};const timer=setTimeout(()=>finish({ok:false,denied:false}),1000);socket.once('connect',()=>finish({ok:true,denied:false}));socket.once('error',error=>finish({ok:false,denied:['EPERM','EACCES'].includes(error.code)}));});
    (async()=>console.log(JSON.stringify({helperReadDenied:denied(()=>fs.readFileSync(${JSON.stringify(privateHelper)})),
      privateAuthSocket:await connect(${JSON.stringify(authSocket)}),otherSessionSocket:await connect(${JSON.stringify(otherPaths.socket)}),
      ownCommandSocket:await connect(${JSON.stringify(firstPaths.socket)}),direct:await connect({host:'203.0.113.1',port:443})})))();`;
  const probeFile = path.join(working, 'broker-boundary.cjs'); await writeFile(probeFile, probe, { mode: 0o400, flag: 'wx' });
  const boundary = await command(first, `${quote(node)} ${quote(probeFile)}`); assert.equal(boundary.code, 0);
  assert.deepEqual(parseLine(boundary.text), { helperReadDenied: true, privateAuthSocket: { ok: false, denied: true },
    otherSessionSocket: { ok: false, denied: true }, ownCommandSocket: { ok: true, denied: false }, direct: { ok: false, denied: true } });
  check('Fenced terminal cannot read private askpass helper or reach its auth socket, other session broker or direct network; own command socket alone remains usable.');
  phase = 'secret-projections';
  const projections = JSON.stringify({ saved: [...records.values()], list: await manager.list({ id: 'pw-main' }),
    snapshot: await terminal.snapshot(), description: terminal.readSessionSshConnections(terminal.sessions.get(first.sessionId)) });
  for (const secret of secrets) { assert(!projections.includes(secret)); for (const value of output.values()) assert(!value.includes(secret)); }
  const filesChecked = await inspectSecretFiles(temporary, excludedProgram);
  proof.secretChecks = { boundedConfigurationFilesChecked: filesChecked, ownedProcessArgvEnvChecked: inspectedProcesses, launchSpecificationsChecked,
    plaintextPasswordFound: false, terminalOutputContainsPassword: false, projectionsContainPassword: false };
  check('Fixture passwords stay out of bounded owned configuration/runtime files, manifests, public projections and terminal output.');
  phase = 'route-revocation'; const revoked = await create('pw-revoke'); const original = terminal.sessions.get(revoked.sessionId).sshBinding;
  const revokedStart = text(revoked).length, revokedDone = `EVPW_REVOKED_${randomBytes(7).toString('hex')}`;
  await terminal.write({ sessionId: revoked.sessionId, data: `ssh -t ${records.get('pw-revoke').alias}; printf '\\n${revokedDone}:%d\\n' "$?"\r` });
  await wait(() => text(revoked).slice(revokedStart).includes('ENVARA_PASSWORD_READY'), 'FIXTURE_REVOKE_ACTIVE_READY');
  const closedBeforeRevoke = stats.closed;
  await terminal.invalidateManagedProxy('fixture-revoke'); assert.equal(terminal.metadata(terminal.sessions.get(revoked.sessionId)).ssh.available, false);
  await wait(() => stats.closed > closedBeforeRevoke, 'FIXTURE_REVOKE_ACTIVE_REMAINS');
  await wait(() => new RegExp(`${revokedDone}:\\d+`).test(text(revoked).slice(revokedStart)), 'FIXTURE_REVOKE_CLIENT_REMAINS');
  assert.notEqual(Number(new RegExp(`${revokedDone}:(\\d+)`).exec(text(revoked).slice(revokedStart))[1]), 0);
  const beforeRevoked = countSnapshot(), revokedResult = await command(revoked, `ssh -T ${records.get('pw-revoke').alias} envara-fixture`);
  assert.notEqual(revokedResult.code, 0); assertNoConnection(beforeRevoked); await original.dispose(); await terminal.close({ sessionId: revoked.sessionId });
  proof.routeRevocation = { activeConnectionClosed: true, clientReturned: true, subsequentAuthenticationRefused: true,
    subsequentServerContacted: false, subsequentProxyContacted: false };
  check('Production route-failure callback closes active saved password SSH and refuses further server or proxy contact in the retained shell.');
  phase = 'finite-broker-authorization';
  const finite = await create('pw-finite'), finiteStart = text(finite).length, finiteDone = `EVPW_FINITE_${randomBytes(7).toString('hex')}`;
  assert(Number.isSafeInteger(finiteDeadline));
  await terminal.write({ sessionId: finite.sessionId, data: `ssh -t ${records.get('pw-finite').alias}; printf '\\n${finiteDone}:%d\\n' "$?"\r` });
  await wait(() => text(finite).slice(finiteStart).includes('ENVARA_PASSWORD_READY'), 'FIXTURE_FINITE_READY');
  const finitePingStart = text(finite).length;
  finiteClock = finiteDeadline + 1;
  // Allow the actual broker's periodic sweep to observe finite expiration.
  await sleep(300);
  await terminal.write({ sessionId: finite.sessionId, data: 'fixture-ping\r' });
  await wait(() => text(finite).slice(finitePingStart).includes('ENVARA_PASSWORD_PONG'), 'FIXTURE_FINITE_EXPIRY_CLOSED_ACTIVE_SSH');
  assert(!new RegExp(`${finiteDone}:\\d+`).test(text(finite).slice(finiteStart)));
  await terminal.write({ sessionId: finite.sessionId, data: 'exit\r' });
  await wait(() => new RegExp(`${finiteDone}:\\d+`).test(text(finite).slice(finiteStart)), 'FIXTURE_FINITE_CLIENT_RETURN');
  assert.equal(Number(new RegExp(`${finiteDone}:(\\d+)`).exec(text(finite).slice(finiteStart))[1]), 0);
  const beforeFiniteNew = countSnapshot(), finiteRefused = await invoke(finite, 'pw-finite');
  assert.notEqual(finiteRefused.code, 0); assertNoConnection(beforeFiniteNew);
  await terminal.close({ sessionId: finite.sessionId });
  proof.finiteBrokerAuthorization = { factoryFiniteDeadlineOnly: true, existingConnectionPongAfterExpiry: true,
    naturalExitCode: 0, newAuthenticationRefused: true, newAuthenticationContactedServer: false, newAuthenticationContactedProxy: false };
  check('The real broker finite-deadline compatibility path refuses new authentication after expiry while the already authenticated SSH connection still carries PONG and exits normally.');
  if (dedicated) await terminal.close({ sessionId: dedicated.sessionId });
  await terminal.close({ sessionId: first.sessionId }); await terminal.close({ sessionId: second.sessionId });
  assert.equal(manager.sessions.size, 0); assert.deepEqual(await readdir(manager.agentRoot), []);
  phase = 'application-restart';
  await terminal.shutdown(); await manager.close();
  manager = new TerminalSshManager({ dataDir, hostHome, nodeExecutable: node, agentRoot: path.join(temporary, 'agents'), now,
    spawn: (...args) => { const child = spawn(...args); managersChildren.push(child); return child; } });
  await manager.ready;
  const reopened = await manager.list({ id: 'pw-main' });
  assert.equal(reopened.connections.length, 1); assert.equal(reopened.connections[0].passwordReady, false);
  terminal = new TerminalService({ dataDir, sshManager: manager, availableLocales: ['en_US.UTF-8'], additionalExecutablePaths: [path.dirname(node)],
    resolveContext: async id => context(id), ptyFactory: (file, args, settings) => { inspectLaunch(file, args, settings); return require('node-pty').spawn(file, args, settings); },
    onEvent: event => { if (event.type === 'data') output.set(event.sessionId, (output.get(event.sessionId) ?? '') + event.data); } });
  await terminal.ready; terminal.hostHome = hostHome;
  const afterRestart = await create('pw-main'), trafficBeforeRestart = countSnapshot();
  const restartedDescription = terminal.readSessionSshConnections(terminal.sessions.get(afterRestart.sessionId));
  assert.equal(restartedDescription.status, 'empty'); assert.equal(restartedDescription.expiresAt, null);
  const restartResult = await invoke(afterRestart); assert.notEqual(restartResult.code, 0);
  assertNoConnection(trafficBeforeRestart);
  await terminal.close({ sessionId: afterRestart.sessionId });
  proof.applicationRestart = { savedConnectionPreserved: true, passwordReady: false, newConnectionRefused: true,
    serverContacted: false, proxyContacted: false };
  check('Closing and recreating the manager models an application restart: public connection settings remain but the memory-only password is unavailable and no route or authentication is attempted.');
  proof.secretChecks.boundedConfigurationFilesChecked = await inspectSecretFiles(temporary, excludedProgram);
  proof.secretChecks.launchSpecificationsChecked = launchSpecificationsChecked;
  for (const secret of secrets) for (const value of output.values()) assert(!value.includes(secret));
  assert(stats.serverConnections > 0); assert.equal(stats.proxyConnections, 0);
  proof.savedRoute = { route: 'host-direct', ownedLoopbackOnly: true,
    acceptedServerConnections: stats.serverConnections, environmentProxyConnections: stats.proxyConnections };
  proof.passed = true;
} catch (error) {
  proof.failure = { phase, code: /^[A-Z_\d]+$/.test(String(error?.code ?? '')) ? String(error.code) : 'FIXTURE_ASSERTION' };
  const owned = await ownedProcesses().catch(() => new Map());
  const tails = [...output.entries()].map(([sessionId, value]) => {
    let tail = stripVTControlCharacters(value).slice(-12000);
    for (const secret of [...secrets, proxyPassword, proxyUser]) tail = tail.replaceAll(secret, '[REDACTED]');
    return { sessionId, tail };
  });
  await writeFile(path.join(runDir, 'failure-diagnostics.json'), JSON.stringify({ phase, lifecycle,
    ownedProcesses: [...owned.values()].map(row => ({ pid: row.pid, parent: row.parent, birth: row.birth, program: path.basename(row.executable) })),
    ownedTerminalTails: tails }, null, 2) + '\n', { mode: 0o600 });
} finally {
  const errors = [];
  if (terminal) try { await terminal.shutdown(); } catch { errors.push('TERMINAL_CLEANUP_FAILED'); }
  if (manager) try { await manager.close(); } catch { errors.push('SSH_MANAGER_CLEANUP_FAILED'); }
  if (broker) try { await broker.shutdown(); } catch { errors.push('BROWSER_BROKER_CLEANUP_FAILED'); }
  if (links) try { await links.close(); } catch { errors.push('LINK_CLEANUP_FAILED'); }
  for (const directory of brokerDirectories) try { await lstat(directory); errors.push('BROWSER_DIRECTORY_REMAINS'); } catch (error) { if (error.code !== 'ENOENT') errors.push('BROWSER_DIRECTORY_UNKNOWN'); }
  for (const peer of peers) peer.destroy();
  if (proxyServer) await new Promise(resolve => proxyServer.close(resolve));
  if (pythonChild && pythonChild.exitCode == null && pythonChild.signalCode == null) { pythonChild.kill('SIGTERM'); await wait(() => pythonChild.exitCode != null || pythonChild.signalCode != null, 'FIXTURE_SERVER_CLEANUP', 4000).catch(() => errors.push('SERVER_CLEANUP_FAILED')); }
  let remaining = -1; try { remaining = (await ownedProcesses()).size; if (remaining) errors.push('OWNED_PROCESS_REMAINS'); } catch { errors.push('PROCESS_ABSENCE_UNCONFIRMED'); }
  for (const child of managersChildren) if (child.exitCode == null && child.signalCode == null) errors.push('MANAGER_CHILD_REMAINS');
  try { await rm(temporary, { recursive: true, force: true }); } catch { errors.push('TEMPORARY_CLEANUP_FAILED'); }
  proof.cleanup = { confirmed: errors.length === 0, ownedProcessCount: remaining, temporaryRemoved: !errors.includes('TEMPORARY_CLEANUP_FAILED'), errors: [...new Set(errors)] };
  proof.stats = stats; proof.lifecycle = lifecycle; proof.passed &&= proof.cleanup.confirmed;
  const file = path.join(runDir, 'proof.json'); await writeFile(file, JSON.stringify(proof, null, 2) + '\n', { mode: 0o600 });
  console.log(JSON.stringify({ passed: proof.passed, checks: proof.checks.length, proof: file, cleanup: proof.cleanup, ...(proof.failure ? { failure: proof.failure } : {}) }));
  if (!proof.passed) process.exitCode = 1;
}
