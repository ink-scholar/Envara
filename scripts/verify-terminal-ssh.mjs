// Opt-in live saved SSH acceptance using this computer's network. The server
// sees that network's exit IP. An existing app-owned proxy supplies the isolated
// terminal and Claude environment; the saved SSH connection uses its direct relay.
// Run with ELECTRON_RUN_AS_NODE=1 and this build's Electron executable.
// Required: --route-config <private runtime config.json> --key <private key>
// --host <server> --port <port> --user <user> --claude <native version binary>.
// Optional: --packaged <Envara.app>. The server receives only printf commands.
// All terminal/account data is disposable; existing credentials are not copied.
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { createHash, randomBytes } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { stripVTControlCharacters } from 'node:util';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argument = name => {
  const at = process.argv.indexOf(name);
  return at < 0 ? null : process.argv[at + 1];
};
const required = name => { const value = argument(name); assert(value && !value.startsWith('--'), `${name} is required.`); return value; };
assert.equal(process.platform, 'darwin', 'This acceptance requires macOS.');
assert(process.versions.electron, 'Run with the app Electron binary and ELECTRON_RUN_AS_NODE=1.');
const packagePath = argument('--packaged');
const resources = packagePath ? path.join(packagePath, 'Contents/Resources') : path.join(root, 'build');
if (packagePath) assert.equal(await realpath(process.resourcesPath), await realpath(resources));
const moduleRoot = packagePath ? path.join(resources, 'app.asar') : root;
const moduleURL = name => pathToFileURL(path.join(moduleRoot, 'electron', name)).href;
const [{ TerminalSshManager }, { TerminalService }, { TerminalBrowserBroker }, { TerminalLinkChannel }] = await Promise.all([
  import(moduleURL('terminal-ssh-manager.mjs')), import(moduleURL('terminal-service.mjs')),
  import(moduleURL('terminal-browser-broker.mjs')), import(moduleURL('terminal-link-channel.mjs')),
]);
const keyPath = required('--key'), configPath = required('--route-config');
const claudeExecutable = required('--claude');
const target = { host: required('--host'), port: Number(required('--port')), user: required('--user') };
for (const filename of [keyPath, configPath, claudeExecutable]) assert(path.isAbsolute(filename));
const configInfo = await lstat(configPath);
assert(configInfo.isFile() && !configInfo.isSymbolicLink() && configInfo.uid === process.getuid() && !(configInfo.mode & 0o077));
const runtimeConfig = JSON.parse(await readFile(configPath, 'utf8'));
assert(Array.isArray(runtimeConfig.authentication) && runtimeConfig.authentication.length === 1);
const credential = runtimeConfig.authentication[0], colon = credential.indexOf(':');
assert(colon > 0 && colon < credential.length - 1);
const proxy = { protocol: 'http', host: '127.0.0.1', port: runtimeConfig['mixed-port'],
  username: credential.slice(0, colon), password: credential.slice(colon + 1) };
assert(Number.isInteger(proxy.port) && proxy.port > 0 && proxy.port < 65536);
const initialKeyStat = await lstat(keyPath);
const preserveData = argument('--preserve-data');
async function preservedFiles() {
  const values = new Map();
  if (!preserveData) return values;
  assert(path.isAbsolute(preserveData));
  const wanted = new Set(['workspace.json', 'accounts.json', 'claude-accounts.json', '.credentials.json', '.claude.json', 'settings.json']);
  const walk = async (directory, depth = 0) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const filename = path.join(directory, entry.name);
      if (entry.isFile() && wanted.has(entry.name)) values.set(filename, createHash('sha256').update(await readFile(filename)).digest('hex'));
      else if (entry.isDirectory() && depth < 8 && !['Cache', 'Code Cache', 'GPUCache', 'cache', '.cache', 'logs', 'projects', 'versions', 'browser-data', 'node_modules', 'proxy-core'].includes(entry.name)) await walk(filename, depth + 1);
    }
  };
  await walk(preserveData); return values;
}
const preservedBefore = await preservedFiles();
const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-ssh-accept-')));
const dataDir = path.join(temporary, 'data'), cwd = path.join(temporary, 'workspace');
await mkdir(dataDir, { mode: 0o700 }); await mkdir(cwd, { mode: 0o700 });
const nodeExecutable = path.join(resources, 'backend/playwright-driver/node');
const proof = { passed: false, packaged: Boolean(packagePath), checks: [], limitations: [
  'The saved SSH target receives read-only printf commands through the host network direct relay and can observe its network exit IP.',
  'The selected authenticated proxy remains the terminal and Claude environment route; this check does not prove SSH transport through that proxy.',
  'The official native CLI version runs in a fresh dedicated session. No model request or existing account login is used.',
  'The browser binding uses synthetic profile metadata; no browser or public-egress measurement is exercised.',
] };
const check = value => { proof.checks.push(value); console.log(`PASS ${value}`); };
const quote = value => `'${String(value).replaceAll("'", "'\\''")}'`;
const output = new Map(), leases = [];
let manager, terminal, broker, links;
const waitFor = async predicate => {
  const deadline = Date.now() + 35000;
  while (Date.now() < deadline) { if (predicate()) return; await new Promise(resolve => setTimeout(resolve, 50)); }
  throw new Error('Owned terminal command did not complete.');
};
const text = session => stripVTControlCharacters(output.get(session.sessionId) ?? '');
async function command(session, source) {
  const token = `EVSSH_${randomBytes(12).toString('hex')}`;
  const start = `${token}_BEGIN`, done = `${token}_DONE`;
  output.set(session.sessionId, '');
  await terminal.write({ sessionId: session.sessionId, data: `printf '\\n%s\\n' ${quote(start)}; ${source}; result=$?; printf '\\n%s:%s\\n' ${quote(done)} "$result"\r` });
  await waitFor(() => new RegExp(`(?:^|[\r\n])${done}:\\d+[\r\n]`).test(text(session)));
  const result = text(session).match(new RegExp(`(?:^|[\r\n])${start}\\r?\\n([^]*?)\\r?\\n${done}:(\\d+)`));
  assert(result, 'Command framing failed.');
  if (Number(result[2]) !== 0) {
    const code = /proxy configuration is unavailable or invalid/i.test(result[1]) ? 'SSH_PROXY_CONFIGURATION'
      : /permission denied.*publickey/i.test(result[1]) ? 'SSH_REMOTE_AUTH_REFUSED'
      : /host key verification failed|remote host identification has changed/i.test(result[1]) ? 'SSH_HOST_TRUST_REFUSED'
      : /connection timed out|timed out/i.test(result[1]) ? 'SSH_CONNECT_TIMED_OUT'
      : 'SSH_ACCEPTANCE_COMMAND_FAILED';
    throw Object.assign(new Error('The isolated command failed; raw output is withheld to protect runtime credentials.'), { code });
  }
  return result[1];
}
try {
  manager = new TerminalSshManager({ dataDir, hostHome: os.homedir(), nodeExecutable });
  await manager.ready;
  const prepared = await manager.prepareIdentity({ id: 'ssh_acceptance', ...target, keyPath });
  const connection = await manager.save({ id: 'ssh_acceptance', name: 'SSH acceptance', selectionToken: prepared.selectionToken });
  check('Existing host trust and a private key reference accepted; no private key copied.');
  const context = { id: 'ssh_acceptance', name: 'SSH acceptance', proxyId: 'existing_route', managedProxy: true,
    managedRoute: { proxyId: 'existing_route', routeIdentity: 'acceptance-existing-route', coreGeneration: 1 },
    timezone: 'UTC', locale: 'en-US', privacy: { mode: 'strict' }, proxy,
    network: { ok: true, ip: '192.0.2.1', source: 'synthetic-browser-binding-only' } };
  const service = { snapshot: async () => ({ profiles: [{ id: context.id, name: context.name, proxyId: context.proxyId }] }),
    resolveWorkspaceContext: async () => structuredClone(context) };
  broker = new TerminalBrowserBroker({ service, dataDir, nodeExecutable });
  links = new TerminalLinkChannel({ root: dataDir, onLink: async () => { throw new Error('No links are authorized in this acceptance.'); } });
  await links.listen();
  terminal = new TerminalService({ dataDir, sshManager: manager, browserBroker: broker, linkChannel: links,
    resolveContext: async () => structuredClone(context), additionalExecutablePaths: [path.dirname(nodeExecutable)],
    claudeExecutableResolver: async () => claudeExecutable,
    onEvent: event => { if (event.type === 'data') output.set(event.sessionId, (output.get(event.sessionId) ?? '') + event.data); },
  });
  await terminal.ready;
  for (const kind of ['shell', 'claude-code']) {
    const session = await terminal.create({ id: context.id, directory: cwd, kind, fresh: true,
      ...(kind === 'claude-code' ? { browserProfileId: context.id, claudeInstallSource: 'local' } : {}) });
    const internal = terminal.sessions.get(session.sessionId);
    leases.push(internal.sshBinding.agentSocket);
    assert.equal(session.networkFence, true); assert.equal(session.ssh.privateKeyProtection, true);
    if (kind === 'claude-code') {
      assert.equal(session.deviceIdentifierRestrictions, true);
      assert.match(await command(session, 'claude --version'), /\d+\.\d+\.\d+/);
      check('Unmodified native Claude starts manually inside the dedicated protected session.');
    }
    const deniedProbe = `const fs=require('node:fs'),net=require('node:net');let denied=false;try{const fd=fs.openSync(${JSON.stringify(keyPath)},'r');fs.closeSync(fd);}catch(e){denied=['EPERM','EACCES'].includes(e.code);}if(!denied)process.exit(2);const s=net.connect(1030,'203.0.113.1');s.once('connect',()=>process.exit(3));s.once('error',e=>process.exit(e.code==='EPERM'?0:4));setTimeout(()=>process.exit(5),3000).unref();`;
    await command(session, `${quote(nodeExecutable)} -e ${quote(deniedProbe)}`);
    check(`${kind}: private-key open and direct external TCP refused by the native fence.`);
    const marker = `AUTHENTICATED_${randomBytes(12).toString('hex')}`;
    proof.remoteAttempts ??= [];
    try {
      const result = await command(session, `ssh ${quote(connection.alias)} ${quote(`printf '%s\\n' '${marker}'`)}`);
      assert(result.split(/\r?\n/).includes(marker), 'SSH must authenticate and return the remote command marker.');
      proof.remoteAttempts.push({ kind, authenticated: true });
      check(`${kind}: strict host verification, constrained-agent authentication and remote command succeeded through the saved host network direct relay.`);
    } catch (error) {
      const code = typeof error.code === 'string' && /^[A-Z_\d]+$/.test(error.code) ? error.code : 'SSH_ACCEPTANCE_FAILED';
      proof.remoteAttempts.push({ kind, authenticated: false, error: code });
      console.error(`FAIL ${kind}: ${code}`); process.exitCode = 1;
    }
    const socket = internal.sshBinding.agentSocket;
    await terminal.close({ sessionId: session.sessionId });
    await assert.rejects(lstat(socket), { code: 'ENOENT' });
    assert.equal(internal.sshBinding, null);
    check(`${kind}: closing the session removed its agent socket and private launch context.`);
  }
  assert.equal(new Set(leases).size, leases.length);
  const afterKeyStat = await lstat(keyPath);
  for (const field of ['dev', 'ino', 'size', 'mode', 'mtimeMs', 'ctimeMs']) assert.equal(afterKeyStat[field], initialKeyStat[field]);
  check('Independent session agents and unchanged original key metadata verified.');
  proof.passed = proof.remoteAttempts?.length === 2 && proof.remoteAttempts.every(item => item.authenticated);
} catch (error) {
  proof.error = typeof error.code === 'string' && /^[A-Z_\d]+$/.test(error.code) ? error.code : 'ACCEPTANCE_FAILED';
  console.error(`FAIL ${proof.error}`);
  process.exitCode = 1;
} finally {
  const cleanup = await Promise.allSettled([terminal?.shutdown(), broker?.shutdown(), links?.close(), manager?.close()]);
  if (cleanup.some(result => result.status === 'rejected')) { proof.passed = false; proof.cleanupFailed = true; process.exitCode = 1; }
  const afterKeyStat = await lstat(keyPath);
  proof.originalKeyMetadataUnchanged = ['dev', 'ino', 'size', 'mode', 'mtimeMs', 'ctimeMs'].every(field => afterKeyStat[field] === initialKeyStat[field]);
  const preservedAfter = await preservedFiles();
  proof.existingConfigurationFiles = preservedBefore.size;
  proof.existingConfigurationUnchanged = preservedBefore.size === preservedAfter.size && [...preservedBefore].every(([filename, digest]) => preservedAfter.get(filename) === digest);
  if (!proof.originalKeyMetadataUnchanged || !proof.existingConfigurationUnchanged) { proof.passed = false; process.exitCode = 1; }
  if (!proof.cleanupFailed) await rm(temporary, { recursive: true, force: true });
  const artifactRoot = path.join(root, 'build/local-verification/terminal-ssh');
  await mkdir(artifactRoot, { recursive: true, mode: 0o700 });
  const artifact = path.join(artifactRoot, `${Date.now()}-${packagePath ? 'packaged' : 'source'}.json`);
  await writeFile(artifact, JSON.stringify(proof, null, 2), { mode: 0o600 });
  console.log(`Report: ${artifact}`);
}
