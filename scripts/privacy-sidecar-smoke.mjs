/** Real Go sidecar + cached headed browsers; all fixture traffic stays local. */
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { SidecarManager } from '../electron/sidecar-manager.mjs';
import { BrowseForgeService } from '../electron/browseforge-service.mjs';
import { ProxyNetworkProbe } from '../electron/proxy-network.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const artifacts = path.join(root, 'test-artifacts/privacy-sidecar-smoke');
await mkdir(artifacts, { recursive: true, mode: 0o700 });
const runDir = await mkdtemp(path.join(artifacts, 'run-'));
const dataDir = path.join(runDir, 'workspace');
const resourcesDir = path.join(root, 'build/backend');
const cloakCache = path.join(root, 'test-artifacts/engine-cache');
const camoufoxCache = path.join(root, 'test-artifacts/sidecar-smoke/camoufox-install-workspace/browseforge/browsers/camoufox');
const username = randomUUID(), password = randomUUID();
const authorization = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
const traffic = new Map();
let rejectedConnects = 0, originRequests = 0, geoRequests = 0, includeCoordinates = true;
let manager, service, probe, rpcId = 0;
const proof = {
  platform: `${process.platform}-${process.arch}`, runDir, passed: false, checks: [], observations: [], failures: [],
  scope: 'Real cached browser and Go sidecar behavior in disposable profiles with owned loopback fixtures.',
  limitations: ['Geo lookup uses an injected deterministic PH fixture; this does not verify a live node or live geographic accuracy.', 'Browser traffic is confined by an owned HTTP proxy fixture; no tracker host is contacted.', 'This check does not attest forced attached-application routing, OS location changes, every fingerprint surface, or encrypted telemetry.'],
};
const fixtureHTML = '<!doctype html><meta charset="utf-8"><title>Envara privacy fixture</title><h1>Envara privacy fixture</h1>';
const origin = createServer((request, response) => {
  originRequests++;
  response.writeHead(200, { 'Content-Type': request.url.startsWith('/normal') ? 'application/json' : 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
  response.end(request.url.startsWith('/normal') ? '{"local":true}' : fixtureHTML);
});
const proxy = createServer((request, response) => {
  if (request.headers['proxy-authorization'] !== authorization) {
    response.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="Owned Envara fixture"' }); response.end(); return;
  }
  let destination;
  try { destination = new URL(request.url); } catch { response.writeHead(400); response.end(); return; }
  traffic.set(destination.hostname, (traffic.get(destination.hostname) ?? 0) + 1);
  response.writeHead(200, { 'Content-Type': destination.pathname.startsWith('/normal') || destination.hostname !== '127.0.0.1' ? 'application/json' : 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' });
  response.end(destination.pathname.startsWith('/normal') || destination.hostname !== '127.0.0.1' ? '{"local":true}' : fixtureHTML);
});
// No DNS, TCP forwarding, HTTPS upstream, or general-purpose proxying is allowed.
proxy.on('connect', (_request, socket) => { rejectedConnects++; socket.end('HTTP/1.1 403 Local fixture only\r\nConnection: close\r\n\r\n'); });
const check = message => { proof.checks.push(message); console.log(`PASS ${message}`); };
const exists = async filename => { try { return (await stat(filename)).isDirectory(); } catch { return false; } };
const session = async profileId => {
  const found = ((await manager.client.request('GET', '/api/sessions')).data ?? []).find(item => item.profile_id === profileId);
  assert.ok(found, 'Real browser session missing'); return found;
};
const evaluate = async (profileId, script) => (await manager.client.request('POST', `/api/sessions/${(await session(profileId)).session_id}/eval`, { script }, { timeoutMs: 30000 })).data;
const tool = async (name, args) => {
  const response = await fetch(`${manager.baseUrl}/mcp`, {
    method: 'POST', signal: AbortSignal.timeout(35000), headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${manager.token}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method: 'tools/call', params: { name, arguments: args } }),
  });
  assert.equal(response.status, 200);
  const value = await response.json(); assert.equal(value.error, undefined); assert.notEqual(value.result?.isError, true);
  return value.result?.content?.filter(item => item.type === 'text').map(item => item.text).join('\n') ?? '';
};
const infoScript = '({title:document.title,url:location.href,language:navigator.language,languages:navigator.languages,intlLocale:Intl.DateTimeFormat().resolvedOptions().locale,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone})';
const geoScript = 'new Promise(resolve=>{if(!navigator.geolocation){resolve({ok:false,apiAvailable:false});return}navigator.geolocation.getCurrentPosition(p=>resolve({ok:true,latitude:p.coords.latitude,longitude:p.coords.longitude,accuracy:p.coords.accuracy}),e=>resolve({ok:false,code:e.code}),{timeout:5000,maximumAge:0})})';
const permissionScript = 'navigator.permissions.query({name:"geolocation"}).then(p=>p.state)';
const fetchScript = url => `(async()=>{try{const r=await fetch(${JSON.stringify(url)},{cache:"no-store"});return {ok:r.ok,status:r.status,local:(await r.json()).local===true}}catch(e){return {ok:false,error:e.name}}})()`;
const count = host => traffic.get(host) ?? 0;
const make = async (engine, mode, proxyId, startUrl) => {
  const state = await service.call('createProfile', { profile: { name: `Local privacy ${engine} ${mode}`, engine, platform: process.platform === 'darwin' ? 'macos' : process.platform === 'win32' ? 'windows' : 'linux', locale: '', timezone: '', width: 1440, height: 900, proxyId, privacy: { mode }, startUrl } });
  return state.actionResult.createdId;
};
const screenshot = async (id, filename) => {
  const bytes = Buffer.from(await manager.client.request('GET', `/api/sessions/${(await session(id)).session_id}/screenshot`, undefined, { responseType: 'arraybuffer' }));
  assert.equal(bytes.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
  await writeFile(path.join(runDir, filename), bytes, { mode: 0o600 });
};
const testMode = async (engine, mode, proxyId, url) => {
  includeCoordinates = true;
  const id = await make(engine, mode, proxyId, url);
  await service.call('startProfile', { id });
  try {
    const info = await evaluate(id, infoScript), geo = await evaluate(id, geoScript);
    proof.observations.push({ engine, mode, stage: 'native-identity-and-location', info, geolocation: geo });
    assert.equal(info.title, 'Envara privacy fixture'); assert.equal(info.language, 'en-PH'); assert.equal(info.timezone, 'Asia/Manila');
    assert.equal(new Intl.Locale(info.intlLocale).maximize().baseName, new Intl.Locale('en-PH').maximize().baseName);
    assert.equal(geo.ok, true); assert.equal(geo.latitude, 14.6); assert.equal(geo.longitude, 121); assert.equal(geo.accuracy, 50000);
    const resolved = await service.resolveWorkspaceContext(id);
    assert.equal(resolved.timezoneSource, 'proxy'); assert.equal(resolved.locale, 'en-PH'); assert.equal(resolved.network.locationSource, 'ip-estimate');
    const normal = await evaluate(id, fetchScript(`${url}normal`));
    assert.deepEqual(normal, { ok: true, status: 200, local: true });
    const before = (await session(id)).privacy.blockedRequests;
    const standardBefore = count('google-analytics.com');
    const standard = await evaluate(id, fetchScript('http://google-analytics.com/envara-local-fixture'));
    const afterStandard = (await session(id)).privacy.blockedRequests;
    if (mode === 'off') {
      assert.deepEqual(standard, { ok: true, status: 200, local: true }); assert.ok(count('google-analytics.com') > standardBefore); assert.equal(afterStandard, before);
    } else {
      assert.equal(standard.ok, false); assert.equal(count('google-analytics.com'), standardBefore); assert.ok(afterStandard > before);
    }
    const strictBefore = count('api.mixpanel.com');
    const strict = await evaluate(id, fetchScript('http://api.mixpanel.com/envara-local-fixture'));
    const afterStrict = (await session(id)).privacy.blockedRequests;
    if (mode === 'strict') {
      assert.equal(strict.ok, false); assert.equal(count('api.mixpanel.com'), strictBefore); assert.ok(afterStrict > afterStandard);
    } else {
      assert.deepEqual(strict, { ok: true, status: 200, local: true }); assert.ok(count('api.mixpanel.com') > strictBefore); assert.equal(afterStrict, afterStandard);
    }
    proof.observations.push({ engine, mode, info, geolocation: geo, normal, standardTracker: standard, strictTracker: strict, blockedRequests: afterStrict });
    await screenshot(id, `${engine}-${mode}.png`);
    check(`${engine} ${mode}: automatic en-PH / Asia/Manila, regional 50000 m geolocation, local HTTP 200, and expected real tracker blocking counters.`);
  } finally { await service.call('stopProfile', { id }); }
};
const testMissingGeo = async (engine, proxyId, url) => {
  includeCoordinates = false;
  const id = await make(engine, 'strict', proxyId, url);
  await service.call('startProfile', { id });
  try {
    const observations = [];
    proof.observations.push({ engine, mode: 'strict-without-coordinates', tabs: observations });
    for (let tab = 0; tab < 3; tab++) {
      if (tab) await tool('new_tab', { profile_id: id, url: `${url}?tab=${tab}` });
      let permission;
      const apiAvailable = await evaluate(id, 'typeof navigator.geolocation !== "undefined"');
      if (engine === 'camoufox' && !apiAvailable) permission = 'api-unavailable';
      else {
        for (let attempt = 0; attempt < 25; attempt++) {
          permission = await evaluate(id, permissionScript);
          if (permission === 'denied') break;
          await delay(100);
        }
      }
      const geo = await evaluate(id, geoScript);
      observations.push({ tab, permission, geolocation: geo });
      if (engine === 'camoufox' && !apiAvailable) assert.deepEqual(geo, { ok: false, apiAvailable: false });
      else {
        assert.equal(permission, 'denied', `${engine} tab ${tab} must explicitly deny location`);
        assert.deepEqual(geo, { ok: false, code: 1 });
      }
      const info = await evaluate(id, infoScript);
      assert.equal(info.language, 'en-PH'); assert.equal(info.timezone, 'Asia/Manila');
    }
    const privacy = (await session(id)).privacy;
    assert.equal(privacy.geolocation, null); assert.equal(privacy.geolocationPolicy, 'deny');
    assert.equal(JSON.parse(await tool('list_tabs', { profile_id: id })).length, 3);
    await screenshot(id, `${engine}-location-denied.png`);
    proof.observations.push({ engine, mode: 'strict-without-coordinates', tabs: observations, privacy });
    check(engine === 'camoufox' && observations.every(item => item.permission === 'api-unavailable')
      ? `${engine}: absent IP coordinates remove the geolocation API on the original tab and two new tabs; this is different from Chromium's PERMISSION_DENIED response.`
      : `${engine}: absent IP coordinates explicitly deny geolocation with PERMISSION_DENIED on the original tab and two new tabs.`);
  } finally { await service.call('stopProfile', { id }); }
};
const runCase = async (engine, name, operation) => {
  try { await operation(); }
  catch (error) {
    const message = String(error?.message ?? error).replaceAll(username, '[redacted]').replaceAll(password, '[redacted]').replaceAll(manager?.token ?? 'unused-private-token', '[redacted]');
    proof.failures.push({ engine, name, error: message }); console.error(`FAIL ${engine} ${name}: ${message}`);
  }
};

try {
  const provenance = JSON.parse(await readFile(path.join(resourcesDir, 'sidecar-provenance.json'), 'utf8'));
  const binarySha256 = createHash('sha256').update(await readFile(path.join(resourcesDir, process.platform === 'win32' ? 'BrowseForge-sidecar.exe' : 'BrowseForge-sidecar'))).digest('hex');
  assert.equal(binarySha256, provenance.binarySha256); proof.binarySha256 = binarySha256; proof.sidecarProvenance = provenance;
  if (await exists(camoufoxCache)) {
    await cp(camoufoxCache, path.join(dataDir, 'browseforge/browsers/camoufox'), { recursive: true, dereference: false, force: false, errorOnExist: true });
    proof.camoufoxCacheReused = true;
  } else proof.limitations.push('No installed Camoufox test cache was available; only CloakBrowser was exercised.');
  await new Promise(resolve => origin.listen(0, '127.0.0.1', resolve));
  await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${origin.address().port}/`;
  probe = new ProxyNetworkProbe({ endpoints: [{ url: 'https://geo-fixture.invalid/', source: 'injected-local-test', format: 'ipwho' }], transport: async () => {
    geoRequests++;
    return { success: true, ip: '1.1.1.1', country_code: 'PH', country: 'Philippines', region: 'Metro Manila', city: 'Manila', timezone: { id: 'Asia/Manila' }, ...(includeCoordinates ? { latitude: 14.6, longitude: 121 } : {}) };
  } });
  manager = new SidecarManager({ dataDir, resourcesDir, legacyCacheDir: cloakCache });
  await manager.initialize();
  service = new BrowseForgeService(dataDir, manager.client, { appVersion: '0.5.0-privacy-smoke' }, () => {}, {
    profilesDir: path.join(manager.baseDir, 'profiles'), networkProbe: probe,
    getEngineStates: () => manager.getEngineStates(), shutdown: () => manager.shutdown(),
  });
  const engines = (await service.snapshot()).engines;
  proof.engines = engines.map(({ id, installed, version }) => ({ id, installed, version }));
  assert.equal(engines.find(item => item.id === 'cloakbrowser')?.installed, true);
  const saved = await service.call('saveProxy', { proxy: { name: 'Owned offline privacy fixture', protocol: 'http', host: '127.0.0.1', port: proxy.address().port, username, password } });
  const proxyId = saved.proxies.find(item => item.name === 'Owned offline privacy fixture').id;
  for (const engine of ['cloakbrowser', ...(engines.find(item => item.id === 'camoufox')?.installed ? ['camoufox'] : [])]) {
    for (const mode of ['standard', 'strict', 'off']) await runCase(engine, mode, () => testMode(engine, mode, proxyId, url));
    await runCase(engine, 'missing-geo-tabs', () => testMissingGeo(engine, proxyId, url));
  }
  assert.ok(geoRequests > 0);
  proof.geoLookups = geoRequests; proof.fixtureProxyHTTPRequests = Object.fromEntries(traffic); proof.rejectedHTTPSConnects = rejectedConnects; proof.originRequests = originRequests;
  proof.passed = proof.failures.length === 0;
  if (!proof.passed) process.exitCode = 1;
} catch (error) {
  proof.error = String(error?.message ?? error).replaceAll(username, '[redacted]').replaceAll(password, '[redacted]').replaceAll(manager?.token ?? 'unused-private-token', '[redacted]');
  console.error(`Privacy sidecar smoke failed: ${proof.error}`); process.exitCode = 1;
} finally {
  probe?.close();
  try { await manager?.shutdown(); proof.managedProcessStopped = manager?.process === null; }
  catch (error) { proof.cleanupError = error.message; proof.passed = false; process.exitCode = 1; }
  if (process.platform !== 'win32') {
    try {
      const { stdout } = await promisify(execFile)('/bin/ps', ['-axo', 'pid=,command='], { timeout: 5000, maxBuffer: 8 * 1024 * 1024 });
      proof.remainingOwnedBrowserOrBackendProcesses = stdout.split('\n').filter(line => line.includes(runDir) && /BrowseForge-sidecar|Chromium.app\/Contents\/MacOS\/Chromium|Camoufox.app\/Contents\/MacOS\/camoufox/.test(line)).length;
      assert.equal(proof.remainingOwnedBrowserOrBackendProcesses, 0);
    } catch (error) { proof.cleanupError = error.message; proof.passed = false; process.exitCode = 1; }
  }
  for (const server of [proxy, origin]) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  const serialized = JSON.stringify(proof, null, 2);
  await writeFile(path.join(runDir, 'proof.json'), serialized, { mode: 0o600 });
  await writeFile(path.join(artifacts, 'latest-proof.json'), serialized, { mode: 0o600 });
  console.log(`Privacy sidecar smoke ${proof.passed ? 'PASSED' : 'FAILED'}; proof: ${path.join(runDir, 'proof.json')}`);
}
