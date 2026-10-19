/** Real, headed desktop backend checks in a disposable workspace. No personal app data. */
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomUUID, createHash } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { SidecarManager } from '../electron/sidecar-manager.mjs';
import { BrowseForgeService } from '../electron/browseforge-service.mjs';
import { ProxyCoreManager } from '../electron/proxy-core-manager.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const artifactDir = path.join(root, 'test-artifacts/sidecar-smoke');
await mkdir(artifactDir, { recursive: true, mode: 0o700 });
const runDir = await mkdtemp(path.join(artifactDir, 'run-'));
const dataDir = path.join(runDir, 'workspace');
const resourcesDir = path.resolve(process.env.ENVARA_SIDECAR_RESOURCES ?? path.join(root, 'build/backend'));
const legacyCacheDir = path.resolve(process.env.ENVARA_SMOKE_ENGINE_DIR ?? path.join(root, 'test-artifacts/engine-cache'));
const installCamoufox = process.argv.includes('--install-camoufox');
const skipLastTabClose = process.argv.includes('--skip-last-tab-close');
const result = {
  platform: `${process.platform}-${process.arch}`, resourcesDir, runDir,
  checks: [], passed: false, fingerprints: [],
  limitations: ['This harness checks the native backend and real browser sessions. It does not verify the Electron UI or all MCP tools.', 'Font, hardware, WebGL and every fingerprint detector are outside this smoke check.'],
};
const fixture = createServer((_req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end('<!doctype html><meta charset="utf-8"><title>Envara native sidecar fixture</title><h1>Envara · 境舱</h1><p>Isolated local verification fixture</p>');
});
let authenticatedProxyRequests = 0;
const proxyHtml = res => {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end('<!doctype html><meta charset="utf-8"><title>Envara native proxy fixture</title><h1>Authenticated proxy route verified</h1>');
};
const proxyOrigin = createServer((_req, res) => { authenticatedProxyRequests++; proxyHtml(res); });
const proxyFixture = createServer((req, res) => {
  if (req.headers['proxy-authorization'] !== `Basic ${Buffer.from('fixture-user:fixture-password').toString('base64')}`) {
    res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="Envara fixture"' });
    res.end();
    return;
  }
  authenticatedProxyRequests++;
  proxyHtml(res);
});
const proxySockets = new Set();
const trackProxySocket = socket => {
  proxySockets.add(socket); socket.on('error', () => {});
  socket.once('close', () => proxySockets.delete(socket)); return socket;
};
proxyFixture.on('connection', trackProxySocket);
proxyFixture.on('connect', (request, socket, head) => {
  const authorized = request.headers['proxy-authorization'] === `Basic ${Buffer.from('fixture-user:fixture-password').toString('base64')}`;
  // Mihomo uses CONNECT for HTTP destinations too. Only the synthetic origin
  // is mapped to loopback; GeoIP/background requests cannot leave this fixture.
  if (!authorized || request.url !== 'envara-smoke.invalid:80') {
    socket.end(`HTTP/1.1 ${authorized ? '403 Forbidden' : '407 Proxy Authentication Required'}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    return;
  }
  const upstream = trackProxySocket(net.connect(proxyOrigin.address().port, '127.0.0.1'));
  upstream.once('connect', () => {
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length) upstream.write(head);
    socket.pipe(upstream); upstream.pipe(socket);
  });
  socket.once('close', () => upstream.destroy()); upstream.once('close', () => socket.destroy());
});
let manager;
let service;
const proxyCorePids = [];
const proxyCore = new ProxyCoreManager({ dataDir, resourcesDir: path.join(root, 'build/proxy-core'),
  spawn(binary, args, options) { const child = spawn(binary, args, options); proxyCorePids.push(child.pid); return child; },
  onChange: event => { if (event?.status === 'failed' && event.id) service?.invalidateManagedProxy(event.id); },
});
let rpcId = 0;
const check = message => { result.checks.push(message); console.log(`PASS ${message}`); };
const sessionId = async profileId => {
  const sessions = (await manager.client.request('GET', '/api/sessions')).data ?? [];
  const session = sessions.find(item => item.profile_id === profileId);
  assert.ok(session, `Running session missing for ${profileId}`);
  return session.session_id;
};
const evaluate = async (profileId, script) => (await manager.client.request('POST', `/api/sessions/${await sessionId(profileId)}/eval`, { script })).data;
const cookies = async profileId => (await manager.client.request('GET', `/api/sessions/${await sessionId(profileId)}/cookies`)).data ?? [];
const mcp = async (method, params = {}) => {
  const httpResponse = await fetch(`${manager.baseUrl}/mcp`, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(60000),
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${manager.token}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
  });
  assert.equal(httpResponse.status, 200);
  const response = await httpResponse.json();
  assert.equal(response.error, undefined, JSON.stringify(response.error));
  return response.result;
};
const tool = async (name, args = {}) => {
  const response = await mcp('tools/call', { name, arguments: args });
  assert.notEqual(response.isError, true, JSON.stringify(response));
  return response.content?.filter(item => item.type === 'text').map(item => item.text).join('\n') ?? '';
};
const information = profileId => evaluate(profileId, '({title:document.title,url:location.href,userAgent:navigator.userAgent,language:navigator.language,languages:navigator.languages,intlLocale:Intl.DateTimeFormat().resolvedOptions().locale,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,width:screen.width,height:screen.height,platform:navigator.platform,webdriver:navigator.webdriver})');
const makeService = () => new BrowseForgeService(dataDir, manager.client, { appVersion: '0.3.0-smoke' }, () => {}, {
  proxyCore,
  profilesDir: path.join(manager.baseDir, 'profiles'),
  getEngineStates: () => manager.getEngineStates(),
  installEngine: id => manager.installEngine(id),
  assertLegacyStopped: () => manager.assertLegacyStopped(),
  shutdown: () => manager.shutdown(),
});
const create = async profile => {
  const snapshot = await service.call('createProfile', { profile });
  assert.ok(snapshot.actionResult?.createdId);
  return snapshot.profiles.find(item => item.id === snapshot.actionResult.createdId);
};
const assertFingerprint = (actual, desired) => {
  assert.equal(actual.language, desired.locale);
  assert.ok(actual.languages.includes(desired.locale));
  // Firefox exposes an explicit default script (zh-Hans-CN for zh-CN).
  // Compare language/script/region semantics while preserving raw observations.
  assert.equal(new Intl.Locale(actual.intlLocale).maximize().baseName, new Intl.Locale(desired.locale).maximize().baseName);
  assert.equal(actual.timezone, desired.timezone);
  assert.equal(actual.width, desired.width);
  assert.equal(actual.height, desired.height);
  assert.equal(actual.platform, desired.platform === 'windows' ? 'Win32' : desired.platform === 'linux' ? 'Linux x86_64' : 'MacIntel');
  assert.match(actual.userAgent, desired.platform === 'windows' ? /Windows NT/ : desired.platform === 'linux' ? /Linux/ : /Macintosh/);
  assert.equal(actual.webdriver, false);
  assert.equal(actual.title, 'Envara native sidecar fixture');
};
const screenshot = async (profileId, name) => {
  const bytes = await manager.client.request('GET', `/api/sessions/${await sessionId(profileId)}/screenshot`, undefined, { responseType: 'arraybuffer' });
  const png = Buffer.from(bytes);
  assert.equal(png.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
  assert.ok(png.readUInt32BE(16) >= 600 && png.readUInt32BE(20) >= 400);
  await writeFile(path.join(runDir, name), png);
};

try {
  result.sidecarProvenance = JSON.parse(await readFile(path.join(resourcesDir, 'sidecar-provenance.json'), 'utf8'));
  result.binarySha256 = createHash('sha256').update(await readFile(path.join(resourcesDir, process.platform === 'win32' ? 'BrowseForge-sidecar.exe' : 'BrowseForge-sidecar'))).digest('hex');
  assert.equal(result.binarySha256, result.sidecarProvenance.binarySha256);
  result.playwrightDriverVersion = JSON.parse(await readFile(path.join(resourcesDir, 'playwright-driver/package/package.json'), 'utf8')).version;
  await new Promise(resolve => fixture.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${fixture.address().port}/`;
  manager = new SidecarManager({ dataDir, resourcesDir, legacyCacheDir: path.join(runDir, 'empty-engine-cache') });
  await manager.initialize();
  service = makeService();
  const empty = await service.snapshot();
  assert.equal(empty.profiles.length, 0);
  assert.equal(empty.engines.length, 3);
  assert.equal(empty.engines.some(engine => engine.installed), false);
  assert.ok(empty.engines.every(engine => !engine.enabled));
  const unauthorized = await fetch(`${manager.baseUrl}/api/profiles`);
  assert.equal(unauthorized.status, 401);
  const tokenFile = await stat(path.join(manager.baseDir, 'data/.envara-token'));
  if (process.platform !== 'win32') assert.equal(tokenFile.mode & 0o777, 0o600);
  check('A clean workspace starts the loopback backend with zero installed engines, empty profiles and protected private REST.');
  const initialization = await mcp('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'envara-native-smoke', version: '1' } });
  assert.ok(initialization.serverInfo?.name);
  const catalogue = await mcp('tools/list');
  result.mcpTools = catalogue.tools.map(item => item.name);
  assert.equal(result.mcpTools.length, 43);
  assert.ok(result.mcpTools.includes('run_workflow') && result.mcpTools.includes('get_cookies'));
  check('Authenticated MCP initialization and the 43-tool catalogue work before installing a browser.');
  await manager.shutdown();

  // Repeated native checks may copy an already installed official test runtime;
  // the zero-engine first-run above still always uses an empty workspace.
  if (process.env.ENVARA_SMOKE_RUNTIME_CACHE) {
    const cache = path.resolve(process.env.ENVARA_SMOKE_RUNTIME_CACHE);
    assert.ok((await stat(cache)).isDirectory());
    await cp(cache, path.join(dataDir, 'browseforge/browsers'), { recursive: true, force: false, errorOnExist: true, dereference: false });
  }

  // Reuse only the explicitly configured test cache, not the user's application engine cache.
  manager = new SidecarManager({ dataDir, resourcesDir, legacyCacheDir });
  await manager.initialize();
  service = makeService();
  const states = await service.snapshot();
  result.initialEngines = states.engines.map(({ id, installed, supported, version }) => ({ id, installed, supported, version }));
  assert.equal(states.engines.find(engine => engine.id === 'cloakbrowser')?.installed, true);
  const desired = [
    { name: '原生验证 · 上海', group: '本地验证', engine: 'cloakbrowser', platform: 'macos', seed: 348297, locale: 'zh-CN', timezone: 'Asia/Shanghai', width: 1440, height: 900, startUrl: url },
    { name: '原生验证 · 纽约', group: '本地验证', engine: 'cloakbrowser', platform: 'windows', seed: 987312, locale: 'en-US', timezone: 'America/New_York', width: 1920, height: 1080, startUrl: url },
  ];
  const first = await create(desired[0]);
  const second = await create(desired[1]);
  await Promise.all([service.call('startProfile', { id: first.id }), service.call('startProfile', { id: second.id })]);
  const live = await service.snapshot();
  assert.equal(live.profiles.filter(item => item.status === 'running').length, 2);
  for (let index = 0; index < 2; index++) {
    const profile = [first, second][index];
    const actual = await information(profile.id);
    result.fingerprints.push({ engine: 'cloakbrowser', requested: desired[index], observed: actual });
    assertFingerprint(actual, desired[index]);
    const tabs = JSON.parse(await tool('list_tabs', { profile_id: profile.id }));
    (result.startupTabs ??= []).push({ profileId: profile.id, engine: profile.engine, tabs });
    await screenshot(profile.id, `cloakbrowser-${index + 1}.png`);
    assert.equal(tabs.length, 1);
  }
  check('Two headed CloakBrowser sessions concurrently apply independent manual timezone, language, Intl locale, screen and OS identity.');
  await manager.client.request('POST', `/api/sessions/${await sessionId(first.id)}/cookies`, [{ name: 'envara_isolation', value: 'first-only', url, expires: Math.floor(Date.now() / 1000) + 86400 }]);
  await evaluate(first.id, 'localStorage.setItem("envara-isolation","first-only")');
  assert.equal((await cookies(second.id)).some(item => item.name === 'envara_isolation'), false);
  assert.equal(await evaluate(second.id, 'localStorage.getItem("envara-isolation")'), null);
  await service.call('focusProfile', { id: first.id });
  assert.equal(JSON.parse(await tool('list_tabs', { profile_id: first.id })).length, 1);
  check('Profile cookies and localStorage are isolated; focus reuses the existing tab.');
  const evaluated = await tool('evaluate', { profile_id: first.id, script: 'document.title' });
  assert.ok(evaluated.includes('Envara native sidecar fixture'));
  const content = await tool('get_content', { profile_id: first.id });
  assert.ok(content.includes('Isolated local verification fixture'));
  check('MCP evaluate, get_content and list_tabs operate on a real headed browser.');
  await service.call('stopProfile', { id: first.id });
  await service.call('startProfile', { id: first.id });
  assert.equal((await cookies(first.id)).find(item => item.name === 'envara_isolation')?.value, 'first-only');
  assert.equal(await evaluate(first.id, 'localStorage.getItem("envara-isolation")'), 'first-only');
  check('Persistent profile cookies and localStorage survive stop and restart.');
  if (skipLastTabClose) {
    await service.call('stopProfile', { id: second.id });
    result.limitations.push('Last-tab-close lifecycle was explicitly skipped in this provisional run.');
  } else {
    await tool('close_tab', { profile_id: second.id, index: 0 });
    const closedDeadline = Date.now() + 15000;
    while (Date.now() < closedDeadline && (await manager.client.request('GET', '/api/sessions')).data?.some(item => item.profile_id === second.id)) await delay(100);
    assert.equal((await manager.client.request('GET', '/api/sessions')).data?.some(item => item.profile_id === second.id) ?? false, false);
    assert.equal((await service.snapshot()).profiles.find(item => item.id === second.id).status, 'stopped');
    check('Closing the last native browser tab removes the managed session and reports the environment stopped.');
  }
  await service.call('stopProfile', { id: first.id });
  const clone = await service.call('cloneProfile', { id: first.id });
  assert.notEqual(clone.profiles.find(item => item.id === clone.actionResult.createdId).seed, first.seed);
  await new Promise(resolve => proxyOrigin.listen(0, '127.0.0.1', resolve));
  await new Promise(resolve => proxyFixture.listen(0, '127.0.0.1', resolve));
  const savedProxy = await service.call('saveProxy', { proxy: { name: '测试映射代理', protocol: 'http', host: '127.0.0.1', port: proxyFixture.address().port, username: 'fixture-user', password: 'fixture-password' } });
  const proxy = savedProxy.proxies.find(item => item.name === '测试映射代理');
  await service.call('updateProfile', { id: second.id, profile: { proxyId: proxy.id, startUrl: 'http://envara-smoke.invalid/' } });
  await service.call('startProfile', { id: second.id });
  assert.equal(proxyCore.routingIdentity(proxy.id)?.nodeType, 'http');
  assert.equal(await evaluate(second.id, 'document.title'), 'Envara native proxy fixture');
  assert.ok(authenticatedProxyRequests > 0);
  await service.call('stopProfile', { id: second.id });
  result.authenticatedProxyRequests = authenticatedProxyRequests;
  check('A real headed browser request passes through the explicitly configured authenticated HTTP proxy.');
  const document = await service.call('exportProfiles', { id: second.id });
  assert.equal(document.version, 2);
  assert.equal(document.profiles[0].proxyId, proxy.id);
  assert.equal(document.proxies[0].requiresCredentials, true);
  assert.equal(JSON.stringify(document).includes('fixture-password'), false);
  assert.equal(JSON.stringify(document).includes('fixture-user'), false);
  const beforeImport = (await service.snapshot()).profiles.length;
  await assert.rejects(service.call('importProfiles', { document }), value => value.code === 'PROXY_MAPPING_REQUIRED');
  assert.equal((await service.snapshot()).profiles.length, beforeImport);
  const imported = await service.call('importProfiles', { document, proxyMap: { [proxy.id]: proxy.id } });
  assert.equal(imported.actionResult.importedCount, 1);
  assert.equal(imported.profiles.find(item => item.id === imported.actionResult.createdIds[0]).proxyId, proxy.id);
  check('Cloning regenerates the seed; configuration export redacts credentials and import preserves an explicitly mapped proxy.');
  const legacyId = randomUUID();
  const legacyProfileDir = path.join(dataDir, 'profiles', legacyId);
  await cp(path.join(manager.baseDir, 'profiles', first.id, 'browser-data'), legacyProfileDir, { recursive: true, force: false, errorOnExist: true });
  const legacyWorkspace = {
    schema: 'envara.workspace', version: 1, settings: { closeBrowsersOnExit: true }, events: [],
    profiles: [{ ...desired[0], name: '旧版资料复制验证', id: legacyId, proxyId: null, notes: '', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }],
    proxies: [{ id: randomUUID(), name: '旧版凭据复制验证', protocol: 'http', host: '127.0.0.1', port: 8124, username: 'legacy-fixture-user', password: 'legacy-fixture-password', region: '' }],
  };
  const legacyFile = path.join(dataDir, 'workspace.json');
  await writeFile(legacyFile, JSON.stringify(legacyWorkspace, null, 2), { mode: 0o600 });
  const digest = bytes => createHash('sha256').update(bytes).digest('hex');
  const originalHash = digest(await readFile(legacyFile));
  const migration = await service.call('migrateLegacy', { ids: [legacyId], copyBrowserData: true });
  assert.equal(migration.actionResult.migratedCount, 1);
  assert.equal(digest(await readFile(legacyFile)), originalHash);
  assert.equal(digest(await readFile(path.join(migration.actionResult.backupDir, 'workspace.json'))), originalHash);
  assert.ok((await stat(legacyProfileDir)).isDirectory());
  assert.ok(migration.proxies.some(item => item.username === 'legacy-fixture-user' && item.password === 'legacy-fixture-password'));
  const migratedId = migration.actionResult.createdIds[0];
  await service.call('startProfile', { id: migratedId });
  assert.equal((await cookies(migratedId)).find(item => item.name === 'envara_isolation')?.value, 'first-only');
  assert.equal(await evaluate(migratedId, 'localStorage.getItem("envara-isolation")'), 'first-only');
  await service.call('stopProfile', { id: migratedId });
  result.migration = { oldConfigUnchanged: true, backupVerified: true, browserCookiesAndStorageCopied: true, localProxyCredentialsPreserved: true };
  check('Opt-in legacy migration copies a real persistent browser profile and local proxy credentials, verifies a backup and leaves the original configuration intact.');
  const persistentIds = (await service.snapshot()).profiles.map(item => item.id).sort();
  const previousPid = manager.process.pid;
  await manager.stop();
  await manager.start();
  assert.notEqual(manager.process.pid, previousPid);
  service = makeService();
  assert.deepEqual((await service.snapshot()).profiles.map(item => item.id).sort(), persistentIds);
  check('Backend process restart preserves profiles and native manager metadata.');

  if (installCamoufox) {
    assert.equal((await service.snapshot()).engines.find(engine => engine.id === 'camoufox')?.supported, true);
    console.log('Installing the official Camoufox engine into the isolated smoke workspace…');
    await service.call('installEngine', { runtimeId: 'camoufox' });
    assert.equal((await service.snapshot()).engines.find(engine => engine.id === 'camoufox')?.installed, true);
    const firefoxDesired = { name: '跨内核验证 · Firefox', group: '本地验证', engine: 'camoufox', platform: 'macos', locale: 'zh-CN', timezone: 'Asia/Shanghai', width: 1440, height: 900, startUrl: url };
    const firefox = await create(firefoxDesired);
    await Promise.all([service.call('startProfile', { id: first.id }), service.call('startProfile', { id: firefox.id })]);
    const actual = await information(firefox.id);
    result.fingerprints.push({ engine: 'camoufox', requested: firefoxDesired, observed: actual });
    assertFingerprint(actual, firefoxDesired);
    assert.match(actual.userAgent, /Firefox\//);
    assert.equal((await cookies(firefox.id)).some(item => item.name === 'envara_isolation'), false);
    assert.equal(await evaluate(firefox.id, 'localStorage.getItem("envara-isolation")'), null);
    await evaluate(firefox.id, 'localStorage.setItem("envara-firefox-persist","firefox-only")');
    await screenshot(firefox.id, 'camoufox.png');
    await service.call('stopProfile', { id: firefox.id });
    await service.call('startProfile', { id: firefox.id });
    assert.equal(await evaluate(firefox.id, 'localStorage.getItem("envara-firefox-persist")'), 'firefox-only');
    await service.call('stopProfile', { id: firefox.id });
    await service.call('stopProfile', { id: first.id });
    result.camoufox = { tested: true, version: manager.states.camoufox.version };
    check('Official Camoufox (Firefox) installs and runs alongside Chromium with independent persistent data and observed manual fingerprint settings.');
  } else {
    result.camoufox = { tested: false, reason: 'Explicit --install-camoufox was not requested.' };
    result.limitations.push('Camoufox was not installed or executed in this run.');
  }
  result.limitations.push('BrowseForge Chromium Alpha was not installed or executed in this run.');
  result.passed = true;
} catch (error) {
  result.error = error.stack ?? error.message;
  console.error(result.error);
  process.exitCode = 1;
} finally {
  if (manager) {
    try { await manager.shutdown(); result.managedProcessStopped = manager.process === null; } catch (error) { result.cleanupError = error.message; result.passed = false; process.exitCode = 1; }
  }
  try {
    await proxyCore.close();
    assert.equal(proxyCore.snapshot().activeCount, 0);
    for (const pid of proxyCorePids) {
      let alive = false;
      try { process.kill(pid, 0); alive = true; } catch (error) { if (error.code !== 'ESRCH') throw error; }
      assert.equal(alive, false, 'Owned proxy core remains after shutdown');
    }
    if (proxyCorePids.length) assert.deepEqual(await readdir(proxyCore.baseDir), []);
    result.proxyCoreCleanup = { ownedProcessCount: proxyCorePids.length, remainingProcessCount: 0, runtimeFilesRemoved: true };
  } catch (error) { result.proxyCoreCleanupError = error.message; result.passed = false; process.exitCode = 1; }
  if (process.platform !== 'win32') {
    try {
      const { stdout } = await promisify(execFile)('/bin/ps', ['-axo', 'pid=,command='], { timeout: 5000, maxBuffer: 8 * 1024 * 1024 });
      result.remainingOwnedBrowserOrBackendProcesses = stdout.split('\n').filter(line => line.includes(runDir) && /BrowseForge-sidecar|Chromium.app\/Contents\/MacOS\/Chromium|Camoufox.app\/Contents\/MacOS\/camoufox|\bmihomo\b/.test(line)).length;
      if (result.remainingOwnedBrowserOrBackendProcesses) throw new Error('Owned browser or backend processes remain after shutdown.');
    } catch (error) { result.cleanupError = error.message; result.passed = false; process.exitCode = 1; }
  }
  fixture.closeAllConnections();
  await new Promise(resolve => fixture.close(resolve));
  for (const socket of proxySockets) socket.destroy();
  proxyFixture.closeAllConnections();
  await new Promise(resolve => proxyFixture.close(resolve));
  proxyOrigin.closeAllConnections();
  await new Promise(resolve => proxyOrigin.close(resolve));
  const proof = JSON.stringify(result, null, 2);
  await writeFile(path.join(runDir, 'proof.json'), proof, { mode: 0o600 });
  await writeFile(path.join(artifactDir, 'latest-proof.json'), proof, { mode: 0o600 });
  console.log(`Native sidecar smoke ${result.passed ? 'PASSED' : 'FAILED'}; proof: ${path.join(runDir, 'proof.json')}`);
}
