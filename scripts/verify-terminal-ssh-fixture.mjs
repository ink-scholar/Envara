/** Opt-in macOS-only SSH acceptance with disposable keys and owned loopback
 * listeners. Saved targets use the direct relay; unconfigured targets use an
 * authenticated refusing proxy. No user SSH files, real server or downloads.
 * ELECTRON_RUN_AS_NODE=1 node_modules/electron/dist/Electron.app/Contents/MacOS/Electron scripts/verify-terminal-ssh-fixture.mjs --run
 * --packaged /absolute/Envara.app uses that app own executable/modules/runtime.
 * --claude /absolute/native/versions/X.Y.Z adds version-only dedicated Claude acceptance.
 * Python 3 with Paramiko must already be installed; this never installs it.
 */
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { promisify, stripVTControlCharacters } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { lstat, mkdir, mkdtemp, readFile, realpath, readdir, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2), flags = new Set(['--run', '--node', '--python', '--packaged', '--claude']);
for (let i = 0; i < args.length; i++) {
  if (!flags.has(args[i])) throw new Error('Only --run, --node, --python, --packaged and --claude are supported.');
  if (args[i] !== '--run' && (!args[++i] || !path.isAbsolute(args[i]))) throw new Error('Runtime overrides require absolute paths.');
}
if (!args.includes('--run')) {
  console.log(JSON.stringify({ schema: 'envara.terminal-ssh-fixture-plan/v1', optIn: true, productionReady: false,
    ownedLoopbackOnly: true, generatedKeysOnly: true, authenticationBypass: false, downloads: false,
    executesRemoteShell: false, changesHostSettings: false }));
  process.exit(0);
}
assert.equal(process.platform, 'darwin', 'This acceptance requires macOS Seatbelt and OpenSSH.');
assert(process.versions.electron, 'Use the existing Electron executable with ELECTRON_RUN_AS_NODE=1.');
const packaged = args.includes('--packaged') ? args[args.indexOf('--packaged') + 1] : null;
if (packaged) assert(packaged.endsWith('.app'), '--packaged requires an absolute .app path.');
const resources = packaged ? path.join(packaged, 'Contents/Resources') : null;
if (resources) assert.equal(await realpath(process.resourcesPath), await realpath(resources), 'Run the selected package own executable with ELECTRON_RUN_AS_NODE=1.');
const moduleRoot = resources ? path.join(resources, 'app.asar') : root;
const moduleURL = filename => pathToFileURL(path.join(moduleRoot, 'electron', filename));
const [{ TerminalSshManager }, { TerminalService }, { TerminalBrowserBroker }, { TerminalLinkChannel }] = await Promise.all([
  import(moduleURL('terminal-ssh-manager.mjs')), import(moduleURL('terminal-service.mjs')),
  import(moduleURL('terminal-browser-broker.mjs')), import(moduleURL('terminal-link-channel.mjs')),
]);
const execute = promisify(execFile), require = createRequire(moduleURL('terminal-service.mjs'));
const claudeExecutable = args.includes('--claude') ? await realpath(args[args.indexOf('--claude') + 1]) : null;
const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const waitFor = async (predicate, stage, timeout = 15000) => {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { const result = predicate(); if (result) return result; await sleep(30); }
  throw Object.assign(new Error(stage), { code: 'FIXTURE_DEADLINE' });
};
const bundledRuntime = path.join(resources ?? path.join(root, 'build'), 'backend/playwright-driver/node');
const runtime = await realpath(args.includes('--node') ? args[args.indexOf('--node') + 1] : bundledRuntime);
if (resources) assert.equal(runtime, await realpath(bundledRuntime), 'Packaged acceptance must use that package bundled Node.');
const python = args.includes('--python') ? args[args.indexOf('--python') + 1] : 'python3';
const safeEnv = { PATH: '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' };
const command = (executable, argv) => execute(executable, argv, { timeout: 15000, maxBuffer: 16384, env: safeEnv });
const artifactRoot = path.join(root, 'build/local-verification/terminal-ssh-fixture');
await mkdir(artifactRoot, { recursive: true, mode: 0o700 });
const runDir = await realpath(await mkdtemp(path.join(artifactRoot, 'run-')));
const temporary = await realpath(await mkdtemp('/private/tmp/evssh-e2e-'));
const proof = { schema: 'envara.terminal-ssh-fixture/v1', passed: false, checks: [], sourceModules: !packaged, packagedModules: !!packaged, dedicatedClaudeRequested: !!claudeExecutable,
  limits: ['Local Paramiko authentication only; no real server, public egress, login, model or remote shell.',
    'Ordinary terminal and duplicate use the production SSH manager, native PTY and Seatbelt. Optional dedicated Claude runs --version only, never login or a model.',
    'Browser broker uses a synthetic selected-profile context; no browser is launched or navigated. UI and real upstream acceptance remain separate.'], cleanup: {} };
const children = new Set(), knownPids = new Set(), peers = new Set(), output = new Map();
let stage = 'prepare', terminal, manager, server, pythonChild, broker, linkChannel, proxyMode = 'normal', serverPort;
const brokerDirectories = new Set();
let browserLaunchAttempts = 0;
const stats = { proxyConnections: 0, serverConnections: 0, authenticated: 0, executions: 0, refused407: 0, rejectedTargets: 0, rejectedAuth: 0 };
const check = name => { proof.checks.push(name); console.log(`PASS ${name}`); };
const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
const jsonLine = text => { for (const line of text.split('\n')) { try { const value = JSON.parse(line.trim()); if (value && typeof value === 'object') return value; } catch {} } throw Object.assign(new Error('No structured fixture result.'), { code: 'FIXTURE_JSON_MISSING' }); };
const traffic = () => ({ ...stats });
const pythonSource = String.raw`import sys,json,socket,threading,time,paramiko,base64
root=sys.argv[1]
client=base64.b64decode(open(root+'/client.pub').read().split()[1])
keys=[paramiko.Ed25519Key.from_private_key_file(root+'/server'),paramiko.Ed25519Key.from_private_key_file(root+'/server-alt')]
listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',0));listener.listen(8)
print(json.dumps({'event':'ready','port':listener.getsockname()[1]}),flush=True)
class Server(paramiko.ServerInterface):
 def __init__(self): self.event=threading.Event();self.exec_ok=False
 def get_allowed_auths(self,user): return 'publickey'
 def check_auth_publickey(self,user,key): return paramiko.AUTH_SUCCESSFUL if user=='fixture' and key.asbytes()==client else paramiko.AUTH_FAILED
 def check_channel_request(self,kind,chanid): return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
 def check_channel_shell_request(self,channel): return False
 def check_channel_pty_request(self,*args): return False
 def check_channel_exec_request(self,channel,command):
  if command!=b'envara-fixture': return False
  self.exec_ok=True;self.event.set();return True
 def check_channel_forward_agent_request(self,channel): return False
 def check_port_forward_request(self,address,port): return False
 def check_channel_direct_tcpip_request(self,*args): return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
 def check_global_request(self,*args): return False
def serve(sock):
 transport=None
 try:
  sock.settimeout(8);transport=paramiko.Transport(sock);transport.add_server_key(keys[1 if open(root+'/mode').read()=='changed' else 0]);instance=Server();transport.start_server(server=instance)
  channel=transport.accept(10)
  if channel is None: return
  if transport.is_authenticated(): print(json.dumps({'event':'authenticated'}),flush=True)
  if not instance.event.wait(5) or not instance.exec_ok: return
  channel.sendall(b'ENVARA_SSH_FIXTURE_OK\n');channel.send_exit_status(0);channel.shutdown_write()
  print(json.dumps({'event':'executed'}),flush=True);time.sleep(.2);channel.close()
 except Exception: print(json.dumps({'event':'connectionClosed'}),flush=True)
 finally:
  if transport: transport.close()
  sock.close()
while True:
 sock,_=listener.accept();print(json.dumps({'event':'connected'}),flush=True);threading.Thread(target=serve,args=(sock,),daemon=True).start()
`;
try {
  await command(python, ['-I', '-c', 'import paramiko; print(paramiko.__version__)']);
  for (const name of ['client', 'server', 'server-alt']) await command('/usr/bin/ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'envara-owned-fixture', '-f', path.join(temporary, name)]);
  await writeFile(path.join(temporary, 'mode'), 'normal', { mode: 0o600 });
  const pythonFile = path.join(temporary, 'server.py'); await writeFile(pythonFile, pythonSource, { mode: 0o600 });
  pythonChild = spawn(python, ['-I', pythonFile, temporary], { env: safeEnv, stdio: ['ignore', 'pipe', 'pipe'] });
  children.add(pythonChild); if (pythonChild.pid) knownPids.add(pythonChild.pid); pythonChild.stderr.resume();
  let lines = '';
  pythonChild.stdout.on('data', chunk => {
    lines += chunk.toString(); if (lines.length > 16384) { lines = ''; return; }
    for (;;) { const at = lines.indexOf('\n'); if (at < 0) break; const line = lines.slice(0, at); lines = lines.slice(at + 1);
      try { const item = JSON.parse(line); if (item.event === 'ready' && Number.isInteger(item.port)) serverPort = item.port;
        if (item.event === 'connected') stats.serverConnections++;
        if (item.event === 'authenticated') stats.authenticated++; if (item.event === 'executed') stats.executions++; } catch {} }
  });
  await waitFor(() => serverPort, 'server-ready');
  const user = randomBytes(12).toString('hex'), password = randomBytes(20).toString('hex');
  const authorization = `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;
  server = net.createServer(socket => {
    stats.proxyConnections++;
    peers.add(socket); socket.on('error', () => {}); socket.once('close', () => peers.delete(socket)); let header = Buffer.alloc(0);
    socket.on('data', function handshake(chunk) {
      header = Buffer.concat([header, chunk]); if (header.length > 16384) return socket.destroy();
      const at = header.indexOf('\r\n\r\n'); if (at < 0) return; socket.off('data', handshake); socket.pause();
      const text = header.subarray(0, at).toString('latin1');
      if (proxyMode === '407' || !text.split('\r\n').includes(`Proxy-Authorization: ${authorization}`)) {
        if (proxyMode === '407') stats.refused407++; else stats.rejectedAuth++;
        return socket.end('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n');
      }
      if (!text.startsWith('CONNECT unknown.envara.invalid:1030 HTTP/1.1\r\n')
        && !text.startsWith(`CONNECT 127.0.0.1:${serverPort === 65535 ? 65534 : serverPort + 1} HTTP/1.1\r\n`)) {
        return socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
      }
      stats.rejectedTargets++; socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const dataDir = path.join(temporary, 'data'), hostHome = path.join(temporary, 'host'), working = path.join(temporary, 'work');
  for (const directory of [dataDir, hostHome, working]) await mkdir(directory, { mode: 0o700 });
  await mkdir(path.join(hostHome, '.ssh'), { mode: 0o700 });
  const publicHost = (await readFile(path.join(temporary, 'server.pub'), 'utf8')).trim().split(/\s+/).slice(0, 2).join(' ');
  await writeFile(path.join(hostHome, '.ssh/known_hosts'), `[127.0.0.1]:${serverPort} ${publicHost}\n`, { mode: 0o600 });
  manager = new TerminalSshManager({ dataDir, hostHome, nodeExecutable: runtime, agentRoot: path.join(temporary, 'agents'),
    spawn: (...argv) => { const child = spawn(...argv); children.add(child); if (child.pid) knownPids.add(child.pid); return child; } });
  await manager.ready;
  stage = 'select-save';
  const selected = await manager.prepareIdentity({ id: 'ssh-fixture', host: '127.0.0.1', port: serverPort, user: 'fixture', keyPath: path.join(temporary, 'client') });
  const saved = await manager.save({ id: 'ssh-fixture', name: 'Disposable local SSH', selectionToken: selected.selectionToken });
  check('Disposable key and existing isolated host trust selected with no host credentials.');
  const route = { protocol: 'http', host: '127.0.0.1', port: server.address().port, username: user, password };
  const context = { id: 'ssh-fixture', timezone: 'UTC', locale: 'en-US', proxy: route, proxyId: 'fixture-route',
    privacy: { mode: 'standard' }, network: { ok: true, source: 'owned-loopback-fixture' } };
  if (claudeExecutable) {
    const service = { snapshot: async () => ({ profiles: [{ id: context.id, name: 'Synthetic SSH browser',
      proxyId: context.proxyId, engine: 'cloakbrowser', timezone: context.timezone, locale: context.locale }] }),
      resolveWorkspaceContext: async id => { assert.equal(id, context.id); return structuredClone(context); },
      ensureBoundBrowser: async () => { browserLaunchAttempts++; throw new Error('This fixture never launches a browser.'); } };
    broker = new TerminalBrowserBroker({ service, dataDir, nodeExecutable: runtime });
    linkChannel = new TerminalLinkChannel({ root: dataDir, onLink: () => { throw new Error('No web links are requested by version-only acceptance.'); } });
    await linkChannel.listen();
  }
  terminal = new TerminalService({ dataDir, sshManager: manager, availableLocales: ['en_US.UTF-8'],
    ...(claudeExecutable ? { browserBroker: broker, linkChannel, claudeExecutableResolver: async () => claudeExecutable } : {}),
    additionalExecutablePaths: [path.dirname(runtime)], resolveContext: async id => { assert(['ssh-fixture', 'ssh-empty'].includes(id)); return { ...structuredClone(context), id }; },
    ptyFactory: (executable, argv, options) => { const pty = require('node-pty').spawn(executable, argv, options); knownPids.add(pty.pid); return pty; },
    onEvent: event => { if (event.type === 'data') output.set(event.sessionId, (output.get(event.sessionId) ?? '') + event.data); } });
  await terminal.ready; terminal.hostHome = hostHome;
  const runCommand = async (session, command) => {
    const tag = `EVSSH_${randomBytes(6).toString('hex')}`, before = (output.get(session.sessionId) ?? '').length;
    await terminal.write({ sessionId: session.sessionId, data: `${command}; printf '\\n${tag}:%d\\n' "$?"\r` });
    await waitFor(() => new RegExp(`${tag}:\\d+`).test(stripVTControlCharacters((output.get(session.sessionId) ?? '').slice(before))), stage, 22000);
    const text = stripVTControlCharacters((output.get(session.sessionId) ?? '').slice(before));
    return { code: Number(new RegExp(`${tag}:(\\d+)`).exec(text)[1]), text };
  };
  const invoke = async session => {
    const { code, text } = await runCommand(session, `ssh -T ${saved.alias} envara-fixture`);
    return { code, marker: text.includes('ENVARA_SSH_FIXTURE_OK'),
      hostRefused: /REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed/.test(text),
      routeRefused: text.includes('SSH proxy authentication was refused'), agentRefused: /agent refused operation/.test(text) };
  };
  stage = 'empty-configuration';
  const empty = await terminal.create({ id: 'ssh-empty', directory: working, fresh: true });
  assert(empty.networkFence);
  const beforeEmpty = traffic();
  const emptyListResult = await runCommand(empty, 'envara-ssh list --json'); assert.equal(emptyListResult.code, 0);
  const emptyList = jsonLine(emptyListResult.text);
  assert.equal(emptyList.schema, 'envara.ssh-session'); assert.equal(emptyList.version, 2);
  assert.equal(emptyList.status, 'empty'); assert.equal(emptyList.expiresAt, null); assert.deepEqual(emptyList.connections, []);
  for (const command of ['ssh', 'ssh envara-deadbeefdead']) {
    const result = await runCommand(empty, command); assert.equal(result.code, 2);
    assert(/SSH_(ARGUMENT_INVALID|TARGET_NOT_AUTHORIZED)/.test(result.text));
  }
  assert.deepEqual(traffic(), beforeEmpty);
  const emptyTarget = await runCommand(empty, 'ssh fixture@unknown.envara.invalid -p1030 envara-fixture');
  assert.notEqual(emptyTarget.code, 0); assert(emptyTarget.text.includes('SSH proxy refused this destination'));
  assert.equal(stats.proxyConnections, beforeEmpty.proxyConnections + 1); assert.equal(stats.rejectedTargets, beforeEmpty.rejectedTargets + 1);
  assert.equal(stats.serverConnections, beforeEmpty.serverConnections); assert.equal(stats.authenticated, beforeEmpty.authenticated);
  await terminal.close({ sessionId: empty.sessionId });
  check('Empty saved configuration exposes read-only discovery; only an explicit unconfigured target contacts the environment proxy and its refusal reaches no SSH server.');
  stage = 'terminal-create';
  const first = await terminal.create({ id: 'ssh-fixture', directory: working, fresh: true });
  assert(first.networkFence && first.ssh?.privateKeyProtection && first.ssh.available);
  const discover = async session => {
    const before = traffic(), result = await runCommand(session, 'envara-ssh list --json'); assert.equal(result.code, 0);
    const value = jsonLine(result.text); assert.equal(value.schema, 'envara.ssh-session'); assert.equal(value.version, 2); assert.equal(value.status, 'ready');
    assert.equal(value.expiresAt, null);
    assert.deepEqual(value.connections, [{ id: saved.id, name: saved.name, alias: saved.alias, host: '127.0.0.1', port: serverPort, user: 'fixture',
      authType: 'publickey', expiresAt: null, status: 'ready', available: true }]);
    for (const secret of [user, password, path.join(temporary, 'client'), manager.filename]) assert(!JSON.stringify(value).includes(secret));
    assert.deepEqual(traffic(), before); return value;
  };
  stage = 'discover'; await discover(first);
  check('Structured connection discovery exposes only saved public destinations and aliases, with no route or authentication.');
  stage = 'first-protected-ssh'; const beforeFirst = traffic(), firstResult = await invoke(first); proof.firstResult = firstResult;
  assert.equal(firstResult.code, 0); assert(firstResult.marker); assert(stats.authenticated >= 1 && stats.executions >= 1);
  assert.equal(stats.proxyConnections, beforeFirst.proxyConnections); assert.equal(stats.serverConnections, beforeFirst.serverConnections + 1);
  check('Real protected native SSH authenticates through its constrained agent and saved direct relay without contacting the environment proxy.');
  stage = 'standard-target';
  for (const command of [`ssh fixture@127.0.0.1 -p${serverPort} envara-fixture`, `ssh -p ${serverPort} fixture@127.0.0.1 envara-fixture`]) {
    const result = await runCommand(first, command); assert.equal(result.code, 0); assert(result.text.includes('ENVARA_SSH_FIXTURE_OK'));
  }
  assert.equal(stats.proxyConnections, beforeFirst.proxyConnections);
  check('Common user@host and -pPORT/-p PORT forms resolve only to the registered connection.');
  stage = 'refused-targets-options';
  const beforeRefusals = traffic();
  for (const command of [
    `ssh other@127.0.0.1 -p${serverPort} envara-fixture`, `ssh -p${serverPort === 65535 ? 65534 : serverPort + 1} ${saved.alias}`,
    `ssh -o ProxyCommand=/usr/bin/true ${saved.alias}`,
    `ssh -F /dev/null ${saved.alias}`, `ssh -i ${quote(path.join(temporary, 'client'))} ${saved.alias}`,
    `ssh -A ${saved.alias}`, `ssh -L 22222:127.0.0.1:22 ${saved.alias}`,
  ]) {
    const result = await runCommand(first, command); assert.equal(result.code, 2);
    assert(/SSH_(TARGET_NOT_AUTHORIZED|OPTIONS_UNSUPPORTED|ARGUMENT_INVALID)/.test(result.text));
  }
  assert.deepEqual(traffic(), beforeRefusals);
  check('Mismatched saved users or alias ports and client/identity/forwarding overrides refuse before any proxy or SSH server contact.');
  stage = 'unconfigured-target-proxy';
  for (const command of ['ssh fixture@unknown.envara.invalid -p1030 envara-fixture',
    `ssh fixture@127.0.0.1 -p${serverPort === 65535 ? 65534 : serverPort + 1} envara-fixture`]) {
    const before = traffic(), result = await runCommand(first, command);
    assert.notEqual(result.code, 0); assert(result.text.includes('SSH proxy refused this destination'));
    assert.equal(stats.proxyConnections, before.proxyConnections + 1); assert.equal(stats.rejectedTargets, before.rejectedTargets + 1);
    assert.equal(stats.serverConnections, before.serverConnections); assert.equal(stats.authenticated, before.authenticated);
  }
  check('Unconfigured hosts and different destination ports use the environment proxy; its refusal never opens a direct SSH connection.');
  stage = 'duplicate';
  const beforeDuplicate = stats.executions, second = await terminal.duplicate({ sessionId: first.sessionId });
  assert(second.sessionId !== first.sessionId && second.ssh.privateKeyProtection && second.networkFence);
  assert.equal(stats.executions, beforeDuplicate);
  const sockets = [...manager.sessions.values()].map(lease => lease.directory); assert.equal(new Set(sockets).size, 2);
  const secondResult = await invoke(second); assert.equal(secondResult.code, 0); assert(secondResult.marker);
  check('Duplicate is independent and idle, with a distinct constrained agent, and authenticates only after explicit SSH.');
  stage = 'private-key-network-fence';
  const firstSocket = terminal.sessions.get(first.sessionId).sshBinding.agentSocket,
    otherSocket = terminal.sessions.get(second.sessionId).sshBinding.agentSocket;
  const probe = `const fs=require('node:fs'),net=require('node:net');
    const denied=operation=>{try{operation();return false;}catch(error){return ['EPERM','EACCES'].includes(error.code);}};
    const connect=address=>new Promise(resolve=>{let done=false;const socket=net.connect(address);const finish=value=>{if(done)return;done=true;clearTimeout(timer);socket.destroy();resolve(value);};const timer=setTimeout(()=>finish({ok:false,denied:false}),1500);socket.once('connect',()=>finish({ok:true,denied:false}));socket.once('error',error=>finish({ok:false,denied:['EPERM','EACCES'].includes(error.code)}));});
    (async()=>console.log(JSON.stringify({privateReadDenied:denied(()=>fs.readFileSync(${JSON.stringify(path.join(temporary, 'client'))})),
      privateWriteDenied:denied(()=>fs.appendFileSync(${JSON.stringify(path.join(temporary, 'client'))},'x')),
      storeReadDenied:denied(()=>fs.readFileSync(${JSON.stringify(manager.filename)})),
      ownAgent:await connect(${JSON.stringify(firstSocket)}),otherAgent:await connect(${JSON.stringify(otherSocket)}),
      direct:await connect({host:'203.0.113.1',port:443})})))();`;
  const probeFile = path.join(working, 'owned-network-probe.cjs');
  await writeFile(probeFile, probe, { mode: 0o400, flag: 'wx' });
  const fenceResult = await runCommand(first, `${quote(runtime)} ${quote(probeFile)}`); assert.equal(fenceResult.code, 0);
  assert.deepEqual(jsonLine(fenceResult.text), { privateReadDenied: true, privateWriteDenied: true, storeReadDenied: true,
    ownAgent: { ok: true, denied: false }, otherAgent: { ok: false, denied: true }, direct: { ok: false, denied: true } });
  check('Real PTY descendants cannot read or change registered keys/store, use another session agent or connect directly; own agent remains reachable.');
  let dedicated = null;
  if (claudeExecutable) {
    stage = 'dedicated-claude-create';
    dedicated = await terminal.create({ id: 'ssh-fixture', directory: working, fresh: true, kind: 'claude-code',
      browserProfileId: 'ssh-fixture', claudeInstallSource: 'local' });
    assert(dedicated.networkFence && dedicated.ssh.privateKeyProtection && dedicated.deviceIdentifierRestrictions);
    assert.equal(broker.sessions.size, 1);
    for (const item of broker.sessions.values()) brokerDirectories.add(item.directory);
    stage = 'dedicated-claude-discovery'; const cliDescription = await discover(dedicated);
    stage = 'dedicated-claude-mcp-discovery';
    const internal = terminal.sessions.get(dedicated.sessionId), mcp = internal.browserBinding.mcpServer;
    assert.equal(mcp.command, runtime); assert(mcp.args.length > 0);
    const beforeMcp = traffic(), rpc = [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'owned-ssh-fixture', version: '1.0.0' } } },
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
      { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'envara_ssh_connections', arguments: {} } },
    ];
    // Use the actual copied production bridge and this PTY's existing private
    // environment. No direct broker call or mock transport replaces stdio/IPC.
    const mcpCommand = `printf '%s\\n' ${rpc.map(item => quote(JSON.stringify(item))).join(' ')} | ${[mcp.command, ...mcp.args].map(quote).join(' ')}`;
    const mcpResult = await runCommand(dedicated, mcpCommand); assert.equal(mcpResult.code, 0);
    const responses = mcpResult.text.split('\n').flatMap(line => { try { const item = JSON.parse(line.trim()); return item?.jsonrpc === '2.0' ? [item] : []; } catch { return []; } });
    assert.equal(responses.length, 3); assert(responses.every(item => !item.error));
    const tools = responses.find(item => item.id === 2)?.result?.tools;
    assert(Array.isArray(tools)); assert(tools.some(tool => tool.name === 'envara_ssh_connections' && tool.annotations?.readOnlyHint === true));
    const response = responses.find(item => item.id === 3)?.result;
    assert(response && response.isError !== true && response.content?.length === 1 && response.content[0].type === 'text');
    assert.deepEqual(JSON.parse(response.content[0].text), { ...cliDescription,
      connections: cliDescription.connections.map(connection => ({ ...connection, command: `ssh ${connection.alias}` })) });
    const publicReply = JSON.stringify(responses);
    for (const secret of [user, password, path.join(temporary, 'client'), manager.filename,
      ...Object.values(internal.browserBinding.environment), mcp.command, ...mcp.args]) assert(!publicReply.includes(secret));
    assert.deepEqual(traffic(), beforeMcp); assert.equal(browserLaunchAttempts, 0);
    proof.mcpDiscovery = { actualCopiedStdioBridge: true, fencedPty: true, sshToolListed: true,
      sameSessionDescription: true, noProxyOrAuthentication: true, noBrowserLaunch: true, noPrivateFields: true };
    check('Dedicated fenced PTY runs the real MCP stdio bridge: SSH discovery matches its session, leaks no private fields and causes no SSH or browser traffic.');
    stage = 'dedicated-claude-version';
    const versionResult = await runCommand(dedicated, 'claude --version');
    assert.equal(versionResult.code, 0);
    const version = /\b(\d+\.\d+\.\d+) \(Claude Code\)/.exec(versionResult.text)?.[1];
    assert(version, 'The unchanged official CLI must report its version.');
    assert.equal(version, path.basename(claudeExecutable));
    proof.claude = { version, deviceIdentifierRestrictions: dedicated.deviceIdentifierRestrictions,
      privateKeyProtection: dedicated.ssh.privateKeyProtection, browserSessionBound: true, browserLaunched: false };
    stage = 'dedicated-claude-ssh';
    const result = await invoke(dedicated); assert.equal(result.code, 0); assert(result.marker);
    assert.equal(browserLaunchAttempts, 0);
    check('Dedicated Claude terminal runs official version-only CLI with device restrictions and real broker/link binding, then authenticates through its own constrained SSH agent.');
  }
  stage = 'route-407'; proxyMode = '407'; const before407 = traffic(), savedWhileProxyRefuses = await invoke(first);
  assert.equal(savedWhileProxyRefuses.code, 0); assert(savedWhileProxyRefuses.marker);
  assert.equal(stats.proxyConnections, before407.proxyConnections); assert.equal(stats.serverConnections, before407.serverConnections + 1);
  const beforeUnknown407 = traffic(), refusedRoute = await runCommand(first, 'ssh fixture@unknown.envara.invalid -p1030 envara-fixture');
  assert.notEqual(refusedRoute.code, 0); assert(refusedRoute.text.includes('SSH proxy authentication was refused'));
  assert.equal(stats.refused407, beforeUnknown407.refused407 + 1); assert.equal(stats.proxyConnections, beforeUnknown407.proxyConnections + 1);
  assert.equal(stats.serverConnections, beforeUnknown407.serverConnections); assert.equal(stats.authenticated, beforeUnknown407.authenticated);
  check('Saved SSH remains direct while an environment HTTP 407 refuses an unconfigured target without direct fallback.');
  stage = 'host-key-change'; proxyMode = 'normal'; await writeFile(path.join(temporary, 'mode'), 'changed');
  const authCount = stats.authenticated, proxyCount = stats.proxyConnections;
  const changed = await invoke(first); assert(changed.code !== 0 && !changed.marker && changed.hostRefused); assert.equal(stats.authenticated, authCount);
  assert.equal(stats.proxyConnections, proxyCount);
  check('Changed server host key refuses before authentication; no trust update is applied.');
  stage = 'close'; if (dedicated) await terminal.close({ sessionId: dedicated.sessionId });
  if (broker) assert.equal(broker.sessions.size, 0);
  await terminal.close({ sessionId: first.sessionId }); await terminal.close({ sessionId: second.sessionId });
  assert.equal(manager.sessions.size, 0); assert.deepEqual(await readdir(manager.agentRoot), []);
  check('Both managed PTYs and independent constrained agents close and their session directories disappear.');
  proof.passed = true;
} catch (error) {
  proof.failure = { stage, code: /^[A-Z_\d]+$/.test(String(error?.code ?? '')) ? String(error.code) : 'FIXTURE_ASSERTION' };
} finally {
  const cleanupErrors = [];
  if (terminal) try { await terminal.shutdown(); } catch { cleanupErrors.push('TERMINAL_CLEANUP'); }
  if (manager) try { await manager.close(); } catch { cleanupErrors.push('AGENT_CLEANUP'); }
  if (broker) try { await broker.shutdown(); } catch { cleanupErrors.push('BROWSER_BROKER_CLEANUP'); }
  if (linkChannel) try { await linkChannel.close(); } catch { cleanupErrors.push('LINK_CHANNEL_CLEANUP'); }
  for (const directory of brokerDirectories) { try { await lstat(directory); cleanupErrors.push('BROWSER_BROKER_DIRECTORY_REMAINS'); } catch (error) { if (error.code !== 'ENOENT') cleanupErrors.push('BROWSER_BROKER_ABSENCE_UNCONFIRMED'); } }
  for (const peer of peers) peer.destroy();
  if (server) await new Promise(resolve => server.close(resolve));
  if (pythonChild && pythonChild.exitCode == null && pythonChild.signalCode == null) {
    pythonChild.kill('SIGTERM'); await waitFor(() => pythonChild.exitCode != null || pythonChild.signalCode != null, 'python-cleanup', 4000).catch(() => cleanupErrors.push('SERVER_CLEANUP'));
  }
  for (const pid of knownPids) { try { process.kill(pid, 0); cleanupErrors.push('OWNED_PROCESS_REMAINS'); } catch (error) { if (error.code !== 'ESRCH') cleanupErrors.push('PROCESS_ABSENCE_UNCONFIRMED'); } }
  try { await rm(temporary, { recursive: true, force: true }); } catch { cleanupErrors.push('TEMPORARY_CLEANUP'); }
  proof.stats = stats; proof.cleanup = { ownedProcessCount: cleanupErrors.includes('OWNED_PROCESS_REMAINS') ? 1 : 0,
    confirmed: cleanupErrors.length === 0, errors: [...new Set(cleanupErrors)], temporaryRemoved: !cleanupErrors.includes('TEMPORARY_CLEANUP') };
  proof.passed &&= proof.cleanup.confirmed;
  await writeFile(path.join(runDir, 'proof.json'), JSON.stringify(proof, null, 2) + '\n', { mode: 0o600 });
  console.log(JSON.stringify({ passed: proof.passed, checkCount: proof.checks.length, cleanup: proof.cleanup, proof: path.join(runDir, 'proof.json'), ...(proof.failure ? { failure: proof.failure } : {}) }));
  if (!proof.passed) process.exitCode = 1;
}
