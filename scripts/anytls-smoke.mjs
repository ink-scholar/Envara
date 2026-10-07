/** Real local AnyTLS transport verification. Does not read or start Clash or contact user nodes. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { access, mkdir, mkdtemp, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { startAnyTlsFixture } from './fixtures/anytls-server.mjs';
import { HttpsProxyAgent } from 'https-proxy-agent';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packagedIndex = process.argv.indexOf('--packaged');
const packagedApp = packagedIndex < 0 ? null : path.resolve(process.argv[packagedIndex + 1] ?? '');
if (packagedIndex >= 0 && (!process.argv[packagedIndex + 1] || process.platform !== 'darwin')) throw new Error('--packaged requires a Mac .app path');
const packagedResources = packagedApp ? path.join(packagedApp, 'Contents/Resources') : null;
const backendResources = packagedResources ? path.join(packagedResources, 'backend') : path.join(root, 'build/backend');
const moduleDirectory = packagedResources ? path.join(packagedResources, 'app.asar/electron') : path.join(root, 'electron');
const native = !!packagedApp || process.argv.includes('--native');
const moduleImport = filename => import(pathToFileURL(path.join(moduleDirectory, filename)).href);
if (native && !process.versions.electron) {
  const electron = packagedApp ? path.join(packagedApp, 'Contents/MacOS/Envara') : (await import('electron')).default;
  const child = spawn(electron, [fileURLToPath(import.meta.url), ...process.argv.slice(2)], {
    cwd: root, env: { ...process.env, ELECTRON_RUN_AS_NODE: '1', ENVARA_ANYTLS_SMOKE_NODE: process.execPath }, stdio: 'inherit',
  });
  const timer = setTimeout(() => child.kill('SIGTERM'), 180_000);
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
  clearTimeout(timer); process.exit(code === 0 ? 0 : 1);
}
const isAlive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const artifactDir = path.join(root, packagedApp ? 'test-artifacts/anytls-packaged' : 'test-artifacts/anytls-smoke');
await mkdir(artifactDir, { recursive: true, mode: 0o700 });
const runDir = await mkdtemp(path.join(artifactDir, 'run-'));
const result = {
  passed: false, runDir, platform: `${process.platform}-${process.arch}`, checks: [],
  scope: 'Owned loopback fixture only; encrypted AnyTLS transport, authentication, certificate rejection, fail-closed routing and core cleanup.',
  limitations: ['No user credentials, VPN configuration or remote provider node are used.', 'Geo JSON uses a trusted synthetic HTTPS fixture, not a real public egress geography claim.',
    ...(!native ? ['Browser engine and native terminal PTY checks require --native.'] : [])],
};
const check = name => { result.checks.push(name); console.log(`PASS ${name}`); };
let fixture;
let manager;
const observedPids = new Set();
const observedPorts = new Set();
const routes = [];
let sidecar, workspace, terminal;

async function httpsRequest(proxy) {
  const agent = new HttpsProxyAgent(`http://${proxy.host}:${proxy.port}`, {
    headers: () => ({ 'Proxy-Authorization': `Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString('base64')}` }),
  });
  try {
    return await new Promise((resolve, reject) => {
      const request = https.get(fixture.httpsOriginURL, { agent, ca: fixture.certificate, servername: 'fixture.anytls.test' }, response => {
        let body = ''; response.on('data', chunk => body += chunk);
        response.once('end', () => resolve({ status: response.statusCode, body })); response.once('error', reject);
      });
      request.setTimeout(6000, () => request.destroy(new Error('FIXTURE_HTTPS_TIMEOUT'))); request.once('error', reject);
    });
  } finally { agent.destroy(); }
}

async function waitUntil(predicate, message, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) { const value = await predicate(); if (value) return value; await new Promise(resolve => setTimeout(resolve, 25)); }
  throw new Error(message);
}
const shellQuote = value => `'${value.replaceAll("'", "'\\''")}'`;

async function nativeChecks(binaryPath) {
  assert.ok(process.versions.electron, 'Native checks use the actual Electron/node-pty runtime');
  const [{ SidecarManager }, { BrowseForgeService }, { ProxyNetworkProbe }, { TerminalService }] = await Promise.all([
    moduleImport('sidecar-manager.mjs'), moduleImport('browseforge-service.mjs'),
    moduleImport('proxy-network.mjs'), moduleImport('terminal-service.mjs'),
  ]);
  const dataDir = path.join(runDir, 'native-workspace');
  sidecar = new SidecarManager({ dataDir, resourcesDir: backendResources, legacyCacheDir: path.join(root, 'test-artifacts/engine-cache') });
  // This verification owns every target and performs no downloads; ignore host VPN routing.
  sidecar.env = function () { return { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: dataDir, TMPDIR: runDir,
    NO_PROXY: '127.0.0.1,localhost,::1', BROWSEFORGE_TOKEN: this.token,
    BROWSEFORGE_SKIP_BROWSER_AUTO_UPDATE: 'true', PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1',
    PLAYWRIGHT_DRIVER_PATH: this.driver, PLAYWRIGHT_CLI_PATH: path.join(this.driver, 'package/cli.js'),
    PLAYWRIGHT_NODEJS_PATH: path.join(this.driver, 'node') }; };
  await sidecar.initialize(); observedPids.add(sidecar.process.pid);
  const createWorkspace = () => new BrowseForgeService(dataDir, sidecar.client, { appVersion: '0.4.0-smoke' }, () => {}, {
    profilesDir: path.join(sidecar.baseDir, 'profiles'), getEngineStates: () => sidecar.getEngineStates(), proxyCore: manager,
    networkProbe: new ProxyNetworkProbe({ endpoints: [{ url: fixture.geoURL, source: 'owned-synthetic-https', format: 'ipwho' }], tlsOptions: { ca: fixture.certificate, servername: 'fixture.anytls.test' } }),
  });
  workspace = createWorkspace();
  assert.equal((await workspace.snapshot()).engines.find(item => item.id === 'cloakbrowser')?.installed, true);
  const saved = await workspace.call('saveProxy', { proxy: { ...fixture.proxy, skipCertVerify: true, name: 'Owned AnyTLS fixture' } });
  const node = saved.proxies.find(item => item.name === 'Owned AnyTLS fixture'); assert.ok(node?.id);
  const groupName = 'Owned AnyTLS enforced group';
  await workspace.call('saveGroup', { name: groupName, proxyId: node.id, proxyMode: 'enforced' });
  const created = await workspace.call('createProfile', { profile: { name: 'AnyTLS browser and terminal', engine: 'cloakbrowser',
    platform: 'macos', locale: 'zh-CN', timezone: '', width: 1440, height: 900, group: groupName, startUrl: fixture.originURL, proxyId: node.id } });
  const profileId = created.actionResult.createdId; assert.ok(profileId);
  const rawDraft = (await sidecar.client.request('GET', '/api/profiles')).data.find(item => item.id === profileId);
  assert.equal(rawDraft.managed_proxy_required, true);
  await assert.rejects(sidecar.client.request('POST', '/api/sessions', { profile_id: profileId }), value => value.code === 'MANAGED_PROXY_REQUIRED');
  const mcpResponse = await fetch(`${sidecar.baseUrl}/mcp`, { method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${sidecar.token}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'open_browser', arguments: { profile_id: profileId } } }),
  });
  assert.equal(mcpResponse.status, 200);
  assert.match(JSON.stringify(await mcpResponse.json()), /requires an Envara-managed proxy/);
  assert.equal(((await sidecar.client.request('GET', '/api/sessions')).data ?? []).length, 0);
  check('Direct REST and MCP launch of a managed profile without its transient adapter is rejected before opening a browser');
  const context = await workspace.resolveWorkspaceContext(profileId, { force: true });
  assert.equal(context.managedProxy, true); assert.equal(context.proxy.protocol, 'http');
  assert.equal(context.proxySource, 'group'); assert.equal(context.proxyMode, 'enforced');
  assert.equal(context.timezone, 'Asia/Tokyo'); assert.equal(context.timezoneSource, 'proxy');
  assert.equal(context.network.source, 'owned-synthetic-https');
  check('Automatic timezone resolution uses a real authenticated HTTPS request through AnyTLS and explicitly synthetic geo JSON');
  await observeOwnedPids(binaryPath); observedPorts.add(context.proxy.port);
  await workspace.call('startProfile', { id: profileId });
  const sessions = (await sidecar.client.request('GET', '/api/sessions')).data;
  const browserSession = sessions.find(item => item.profile_id === profileId); assert.ok(browserSession);
  const evaluate = async script => (await sidecar.client.request('POST', `/api/sessions/${browserSession.session_id}/eval`, { script })).data;
  const browser = await evaluate('({body:document.body.textContent,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,userAgent:navigator.userAgent,url:location.href})');
  assert.equal(JSON.parse(browser.body).marker, fixture.marker); assert.equal(browser.timezone, context.timezone);
  assert.match(browser.userAgent, /Chrome\//); assert.ok(fixture.requests.some(item => item.markerMatched));
  result.browser = { engine: 'cloakbrowser', userAgent: browser.userAgent, timezone: browser.timezone, markerMatched: true, throughManagedAnyTls: true };
  await observeOwnedPids(binaryPath);
  check('A real headed CloakBrowser session navigates through the managed AnyTLS route and shares its resolved timezone');
  const selectedDirectory = path.join(runDir, 'selected-project'); await mkdir(selectedDirectory, { mode: 0o700 });
  const verificationNode = packagedApp ? path.join(backendResources, 'playwright-driver/node') : process.env.ENVARA_ANYTLS_SMOKE_NODE ?? path.join(backendResources, 'playwright-driver/node');
  const observationPath = path.join(selectedDirectory, 'observation.json');
  const clientFile = path.join(selectedDirectory, 'https-client.mjs');
  await writeFile(clientFile, `import https from 'node:https';import fs from 'node:fs';import { HttpsProxyAgent } from ${JSON.stringify(path.join(root, 'node_modules/https-proxy-agent/dist/index.js'))};\nconst p=new URL(process.env.HTTPS_PROXY);const agent=new HttpsProxyAgent(p);const req=https.get(${JSON.stringify(fixture.httpsOriginURL)},{agent,ca:fs.readFileSync(${JSON.stringify(fixture.certificatePath)}),servername:'fixture.anytls.test'},res=>{let body='';res.on('data',c=>body+=c);res.on('end',()=>{fs.writeFileSync(${JSON.stringify(observationPath)},JSON.stringify({status:res.statusCode,body,cwd:process.cwd(),timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,proxyHost:p.hostname,proxyPort:p.port,hasSecret:process.env.ANYTLS_SERVER_PASSWORD!=null}));agent.destroy();});});req.on('error',()=>process.exit(1));req.setTimeout(6000,()=>req.destroy());\n`, { mode: 0o600 });
  terminal = new TerminalService({ dataDir, resolveContext: id => workspace.resolveWorkspaceContext(id, { force: true }),
    additionalExecutablePaths: [path.dirname(verificationNode)] });
  await terminal.setDirectory({ id: profileId, path: selectedDirectory });
  const tty = await terminal.create({ id: profileId, columns: 100, rows: 28 });
  const privateSession = terminal.session(tty.sessionId); observedPids.add(privateSession.pty.pid);
  await terminal.write({ sessionId: tty.sessionId, data: `${shellQuote(verificationNode)} ${shellQuote(clientFile)}\r` });
  const observed = await waitUntil(async () => { try { return JSON.parse(await readFile(observationPath, 'utf8')); } catch { return null; } }, 'NATIVE_PTY_HTTPS_OBSERVATION_MISSING');
  assert.equal(observed.status, 200); assert.equal(JSON.parse(observed.body).marker, fixture.marker);
  assert.equal(observed.timezone, browser.timezone); assert.equal(observed.cwd, selectedDirectory);
  assert.equal(observed.proxyHost, context.proxy.host); assert.equal(Number(observed.proxyPort), context.proxy.port); assert.equal(observed.hasSecret, false);
  const metadata = JSON.stringify(await terminal.snapshot());
  assert.equal(metadata.includes(fixture.password), false); assert.equal(metadata.includes(context.proxy.password), false);
  result.terminal = { electron: process.versions.electron, realPtyPidRecorded: true, actualHttps: true, sameWireAsBrowser: true,
    timezone: observed.timezone, selectedDirectoryPreserved: true, credentialsAbsentFromMetadata: true };
  check('A real Electron/node-pty shell performs trusted HTTPS through the same AnyTLS route, with the selected directory and browser timezone');
  const route = manager.routes.get(node.id);
  assert.equal(route.status, 'running');
  const corePid = route.child.pid; observedPids.add(corePid);
  const previousWire = { ...context.proxy }, ttyPid = privateSession.pty.pid;
  const geoRequestsBefore = fixture.requests.filter(item => item.geoMatched).length;
  process.kill(corePid, 'SIGKILL');
  await waitUntil(() => route.status === 'failed' && !isAlive(corePid), 'OWNED_CORE_DID_NOT_EXIT');
  assert.equal(await loopbackOpen(previousWire.port), false);
  const offline = (await workspace.snapshot()).profiles.find(item => item.id === profileId);
  assert.equal(offline.resolvedTimezone, null); assert.equal(offline.network.errorCode, 'PROXY_CORE_STOPPED');
  await workspace.call('focusProfile', { id: profileId });
  const recovered = await workspace.resolveWorkspaceContext(profileId);
  assert.deepEqual(recovered.proxy, previousWire, 'Recovery preserves the exact adapter port and random credentials');
  assert.ok(fixture.requests.filter(item => item.geoMatched).length > geoRequestsBefore, 'Recovery performs new authenticated HTTPS geo verification');
  assert.notEqual(manager.routes.get(node.id).child.pid, corePid);
  await observeOwnedPids(binaryPath);
  const browserAfter = await evaluate('fetch(location.href,{cache:"no-store"}).then(response=>response.json())');
  assert.equal(browserAfter.marker, fixture.marker);
  await writeFile(observationPath, '', { mode: 0o600 });
  await terminal.write({ sessionId: tty.sessionId, data: `${shellQuote(verificationNode)} ${shellQuote(clientFile)}\r` });
  const afterCrash = await waitUntil(async () => { try { return JSON.parse(await readFile(observationPath, 'utf8')); } catch { return null; } }, 'EXISTING_PTY_HTTPS_DID_NOT_RECOVER');
  assert.equal(afterCrash.status, 200); assert.equal(JSON.parse(afterCrash.body).marker, fixture.marker);
  assert.equal(afterCrash.timezone, browser.timezone); assert.equal(Number(afterCrash.proxyPort), previousWire.port);
  assert.equal(privateSession.pty.pid, ttyPid);
  assert.equal((await sidecar.client.request('GET', '/api/sessions')).data.find(item => item.profile_id === profileId).session_id, browserSession.session_id);
  result.recovery = { oldCoreTerminated: true, staleGeoInvalidated: true, newGeoRequestVerified: true, stableAdapterPortAndAuthentication: true,
    originalBrowserSessionRecovered: true, originalPtyRecoveredWithHttps: true };
  check('Unexpected core exit clears stale geography; focus restores the same adapter, and the original browser and PTY perform new requests');
  await workspace.call('stopProfile', { id: profileId }); await terminal.shutdown(); terminal = null;
  const raw = (await sidecar.client.request('GET', '/api/profiles')).data.find(item => item.id === profileId);
  assert.equal(raw.proxy ?? null, null, 'Managed loopback credentials must not persist in native profiles');
  const rawGroups = (await sidecar.client.request('GET', '/api/groups')).data;
  assert.ok(rawGroups.every(item => !JSON.stringify(item).includes(context.proxy.password)), 'Native groups contain no managed adapter credentials');
  const files = await privateFiles(path.join(dataDir, 'browseforge/profiles'));
  for (const filename of files.filter(item => item.endsWith('.json'))) assert.equal((await readFile(filename, 'utf8')).includes(context.proxy.password), false);
  const oldPid = sidecar.process.pid; await sidecar.stop(); await sidecar.start(); observedPids.add(sidecar.process.pid);
  assert.notEqual(sidecar.process.pid, oldPid); workspace.networkProbe.close(); workspace = createWorkspace();
  const restored = await workspace.snapshot(); assert.equal(restored.profiles.find(item => item.id === profileId)?.proxyId, node.id);
  const restoredGroup = restored.groups.find(item => item.name === groupName);
  assert.equal(restoredGroup.proxyId, node.id); assert.equal(restoredGroup.proxy_mode, 'enforced');
  const restoredContext = await workspace.resolveWorkspaceContext(profileId, { force: true });
  assert.equal(restoredContext.timezone, context.timezone); assert.equal(restoredContext.proxy.port, context.proxy.port);
  result.persistence = { originalAnyTlsBindingRestored: true, enforcedGroupBindingRestored: true,
    noDynamicAdapterCredentialsInNativeProfileOrGroups: true, coreRouteReusedAcrossBackendRestart: true };
  check('Backend restart preserves the original AnyTLS binding while native profiles contain no dynamic adapter credentials');
  await sidecar.shutdown(); sidecar = null; workspace.networkProbe.close(); workspace = null;
}

async function observeOwnedPids(binaryPath) {
  if (process.platform === 'win32') throw new Error('THIS_SMOKE_REQUIRES_POSIX_PROCESS_EVIDENCE');
  const child = spawn('ps', ['-axo', 'pid=,command='], { stdio: ['ignore', 'pipe', 'ignore'] });
  let output = '';
  child.stdout.on('data', chunk => { output += chunk.toString(); });
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
  assert.equal(code, 0, 'Owned process inventory is available');
  for (const line of output.split('\n')) {
    const match = /^\s*(\d+)\s+(.+)$/.exec(line);
    if (match && match[2].includes(runDir) && (match[2].includes(binaryPath) || /BrowseForge-sidecar|CloakBrowser|Chromium|chrome/.test(match[2]))) observedPids.add(Number(match[1]));
  }
}

function proxyRequest(proxy, target, { authorized = true } = {}) {
  return new Promise((resolve, reject) => {
    const headers = { Connection: 'close', Host: new URL(target).host };
    if (authorized) headers['Proxy-Authorization'] = `Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString('base64')}`;
    const request = http.request({ host: proxy.host, port: proxy.port, method: 'GET', path: target,
      headers, agent: false }, response => {
      let body = '';
      response.on('data', chunk => { body += chunk.toString(); if (body.length > 8192) request.destroy(new Error('FIXTURE_RESPONSE_TOO_LARGE')); });
      response.once('error', reject);
      response.once('end', () => resolve({ status: response.statusCode, body }));
    });
    const timer = setTimeout(() => request.destroy(new Error('FIXTURE_REQUEST_TIMEOUT')), 6000);
    request.once('error', error => { clearTimeout(timer); reject(error); });
    request.once('close', () => clearTimeout(timer));
    request.end();
  });
}
async function expectFailClosed(proxy, name) {
  const count = fixture.requests.length;
  let response;
  try { response = await proxyRequest(proxy, fixture.originURL); } catch { /* Transport rejection is expected. */ }
  assert.notEqual(response?.status, 200, name);
  assert.equal(fixture.requests.length, count, `${name}: target must receive no request`);
  check(name);
}
async function loopbackOpen(port) {
  return new Promise(resolve => {
    const socket = net.connect({ host: '127.0.0.1', port });
    let settled = false;
    const finish = open => { if (!settled) { settled = true; socket.destroy(); resolve(open); } };
    socket.once('connect', () => finish(true)); socket.once('error', () => finish(false));
    socket.setTimeout(250, () => finish(false));
  });
}
async function unusedLoopbackPort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
async function privateFiles(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true }).catch(() => [])) {
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await privateFiles(filename));
    else if (entry.isFile()) files.push(filename);
  }
  return files;
}

try {
  const binaryPath = packagedResources ? path.join(packagedResources, 'proxy-core/mihomo') :
    path.resolve(process.argv.slice(2).find(argument => !argument.startsWith('--')) ?? path.join(root, 'build/proxy-core', process.platform === 'win32' ? 'mihomo.exe' : 'mihomo'));
  await access(binaryPath);
  result.binarySha256 = createHash('sha256').update(await readFile(binaryPath)).digest('hex');
  fixture = await startAnyTlsFixture({ binaryPath, runDir });
  observedPids.add(fixture.pid);
  observedPorts.add(fixture.proxy.port);
  const { ProxyCoreManager } = await moduleImport('proxy-core-manager.mjs');
  const clientDir = path.join(runDir, 'clients');
  manager = new ProxyCoreManager({ dataDir: clientDir, resourcesDir: path.dirname(binaryPath),
    onChange: change => { if (change?.status === 'failed') workspace?.invalidateManagedProxy(change.id); } });
  if (packagedResources) {
    assert.equal(path.resolve(process.resourcesPath), packagedResources, 'The native runtime comes from the requested package');
    const packageInfo = JSON.parse(await readFile(path.join(packagedResources, 'app.asar/package.json'), 'utf8'));
    const modules = {};
    for (const name of ['proxy-core-manager.mjs', 'browseforge-service.mjs', 'proxy-network.mjs', 'sidecar-manager.mjs', 'terminal-service.mjs']) {
      const imported = path.join(moduleDirectory, name);
      modules[name] = { imported, sha256: createHash('sha256').update(await readFile(imported)).digest('hex') };
    }
    result.packaged = { candidate: packageInfo.version, resources: packagedResources, modules,
      backendSha256: createHash('sha256').update(await readFile(path.join(backendResources, 'BrowseForge-sidecar'))).digest('hex'),
      electron: process.versions.electron, bundledNodeUsedForPty: true };
    check('The requested packaged Electron, ASAR runtime modules and bundled proxy/backend resources are used');
  }
  await assert.rejects(manager.ensure({ id: 'invalid-sni', ...fixture.proxy, serverName: 'https://invalid-sni.example' }),
    value => value.code === 'INVALID_ANYTLS_PROXY');
  check('An invalid TLS server-name field is rejected before creating a core route');
  // PID evidence is read only from the owned runtime directory and contains no secrets in proof.
  const ensure = async (id, fields = {}) => {
    const proxy = await manager.ensure({ id, ...fixture.proxy, ...fields });
    assert.equal(proxy.protocol, 'http'); assert.equal(proxy.host, '127.0.0.1');
    assert.ok(proxy.username && proxy.password, 'Loopback adapter requires authentication');
    observedPorts.add(proxy.port); routes.push({ id, port: proxy.port });
    await observeOwnedPids(binaryPath);
    return proxy;
  };

  const strict = await ensure('strict-certificate');
  await expectFailClosed(strict, 'Untrusted self-signed certificate is rejected with default verification');
  await manager.release('strict-certificate');
  assert.equal(await loopbackOpen(strict.port), false);
  check('Releasing a route closes its owned adapter port');

  const verified = await ensure('working-anytls', { skipCertVerify: true });
  const response = await proxyRequest(verified, fixture.originURL);
  assert.equal(response.status, 200);
  assert.equal(JSON.parse(response.body).marker, fixture.marker);
  assert.equal(fixture.requests.length, 1);
  assert.ok(fixture.wire.tlsRecords >= 2 && fixture.wire.bytes > 0, 'AnyTLS server receives real TLS wire bytes');
  check('Explicit fixture certificate override enables authenticated HTTP → AnyTLS over TLS → origin');

  const unauthenticated = await proxyRequest(verified, fixture.originURL, { authorized: false });
  assert.equal(unauthenticated.status, 407);
  assert.equal(fixture.requests.length, 1);
  check('The owned loopback adapter rejects requests without its random credentials');
  const duplicate = await manager.ensure({ id: 'working-anytls', ...fixture.proxy, skipCertVerify: true });
  assert.deepEqual(duplicate, verified);
  check('Repeated ensure reuses the same owned route');

  const wrongPassword = await ensure('wrong-password', { password: randomUUID(), skipCertVerify: true });
  await expectFailClosed(wrongPassword, 'Wrong AnyTLS server password fails without DIRECT fallback');
  await manager.release('wrong-password');
  const unreachable = await ensure('unreachable-loopback-node', { port: await unusedLoopbackPort(), skipCertVerify: true });
  await expectFailClosed(unreachable, 'Unreachable loopback AnyTLS server fails without DIRECT fallback');
  await manager.release('unreachable-loopback-node');

  const second = await ensure('independent-route', { skipCertVerify: true });
  assert.notEqual(second.port, verified.port);
  assert.notEqual(second.password, verified.password);
  const secondResponse = await proxyRequest(second, fixture.originURL);
  assert.equal(secondResponse.status, 200);
  assert.equal(fixture.requests.length, 2);
  await manager.release('working-anytls');
  assert.equal(await loopbackOpen(verified.port), false);
  assert.equal((await proxyRequest(second, fixture.originURL)).status, 200);
  check('Independent owned routes remain usable when another route is released');
  const secure = await httpsRequest(second);
  assert.equal(secure.status, 200); assert.equal(JSON.parse(secure.body).marker, fixture.marker);
  assert.equal(fixture.requests.at(-1).tls, true);
  assert.ok(fixture.requests.every(item => !item.proxyCredentialsForwarded && !item.nodeSecretInHeaders));
  check('Ordinary certificate-verified HTTPS traverses AnyTLS without forwarding proxy or node credentials to the target');
  if (native) await nativeChecks(binaryPath);

  const filesBefore = await privateFiles(clientDir);
  const credentialFiles = [];
  for (const filename of filesBefore) {
    const metadata = await stat(filename);
    if (filename.endsWith('.json') || filename.endsWith('.yaml') || filename.endsWith('.yml')) {
      const bytes = await readFile(filename, 'utf8');
      if (bytes.includes(fixture.password)) { credentialFiles.push(filename); assert.equal(metadata.mode & 0o777, 0o600); }
    }
  }
  assert.ok(credentialFiles.length > 0, 'Owned runtime config is present while route is alive');
  check('Runtime configuration containing only synthetic fixture credentials uses mode 0600');
  result.wireEvidence = { ...fixture.wire };
  await fixture.stopAnyTlsServer();
  assert.equal(isAlive(fixture.pid), false);
  await expectFailClosed(second, 'Stopping the AnyTLS server fails without DIRECT fallback');

  await manager.close();
  await fixture.close();
  assert.ok(observedPids.size >= 6, 'Fixture server and each independent client core have recorded PIDs');
  for (const port of observedPorts) assert.equal(await loopbackOpen(port), false, 'Owned adapter and server ports must be closed');
  for (const pid of observedPids) assert.equal(isAlive(pid), false, 'Owned process must be gone');
  const filesAfter = await privateFiles(clientDir);
  for (const filename of filesAfter) {
    const bytes = await readFile(filename, 'utf8');
    assert.equal(bytes.includes(fixture.password), false, 'No synthetic server password survives shutdown');
    for (const route of routes) assert.equal(filename.includes(`${route.id}/`), false, 'Released runtime directories are removed');
  }
  result.cleanup = { adapterPortsClosed: true, fixtureServerStopped: true,
    ownedObservedPidsGone: true, syntheticCredentialFilesRemoved: true, observedProcessCount: observedPids.size,
    ...(native ? { browserAndBackendStopped: true, nativePtyStopped: true } : {}) };
  check('Closing the manager removes all owned routes, processes and runtime credentials');
  result.passed = true;
} catch (error) {
  result.error = { name: error.name, message: String(error.message).slice(0, 1000) };
  console.error(`FAIL ${result.error.message}`); process.exitCode = 1;
} finally {
  await terminal?.shutdown().catch(() => {});
  await sidecar?.shutdown().catch(() => {});
  workspace?.networkProbe.close();
  await manager?.close().catch(() => {});
  await fixture?.close().catch(() => {});
  result.completedAt = new Date().toISOString();
  await writeFile(path.join(runDir, 'proof.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
  console.log(`Proof: ${path.join(runDir, 'proof.json')}`);
}
