/** Offline native capability/packaged device-profile acceptance. Uses only owned profiles.
 * node scripts/verify-browser-device-profile.mjs --probe
 * ELECTRON_RUN_AS_NODE=1 /absolute/Envara.app/Contents/MacOS/Envara scripts/verify-browser-device-profile.mjs --packaged /absolute/Envara.app
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

const execute = promisify(execFile);
const capabilityProbe = process.argv.includes('--probe');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packageIndex = process.argv.indexOf('--packaged');
const application = packageIndex < 0 ? null : process.argv[packageIndex + 1];
if (packageIndex >= 0) assert(application && path.isAbsolute(application) && application.endsWith('.app'));
const resources = application ? path.join(application, 'Contents/Resources/backend') : path.join(root, 'build/backend');
const moduleRoot = application ? path.join(application, 'Contents/Resources/app.asar') : root;
if (application) {
  assert(process.versions.electron && process.env.ELECTRON_RUN_AS_NODE === '1', 'Run using the selected packaged app executable with ELECTRON_RUN_AS_NODE=1.');
  assert.equal(await realpath(process.resourcesPath), await realpath(path.join(application, 'Contents/Resources')));
}
const [{ SidecarManager }, { BrowseForgeService }, { ProxyNetworkProbe }] = await Promise.all([
  import(pathToFileURL(path.join(moduleRoot, 'electron/sidecar-manager.mjs'))),
  import(pathToFileURL(path.join(moduleRoot, 'electron/browseforge-service.mjs'))),
  import(pathToFileURL(path.join(moduleRoot, 'electron/proxy-network.mjs'))),
]);
const artifactRoot = path.join(root, 'build/local-verification/browser-device-profile');
await mkdir(artifactRoot, { recursive: true, mode: 0o700 });
const runDir = await realpath(await mkdtemp(path.join(artifactRoot, 'run-')));
const dataDir = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-device-profile-')));
const report = { passed: false, startedAt: new Date().toISOString(), mode: capabilityProbe ? 'native-capability-probe' : 'device-profile-acceptance', application, runDir, observations: [], checks: [], limitations: [
  'Offline pages measure observable browser properties, not account safety or fingerprint-detector scores.',
  'Font tests measure rendered local families without changing any host fonts.',
  'Authenticated offline routes prove selection and saved context changes, not actual public geolocation or AnyTLS behavior.',
  'Current CloakBrowser 145 does not honor font/GPU overrides; UA and UA-CH consistency is not part of the device-profile guarantee.',
] };
const check = message => { report.checks.push(message); console.log('PASS ' + message); };
const sockets = new Set();
const servers = [];
const ownedPids = new Set();
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const captureOwnedProcesses = async () => {
  const { stdout } = await execute('/bin/ps', ['-axo', 'pid=,ppid='], { timeout: 5000 });
  const rows = stdout.split('\n').map(line => /^\s*(\d+)\s+(\d+)\s*$/.exec(line)).filter(Boolean).map(([, pid, parent]) => ({ pid: Number(pid), parent: Number(parent) }));
  const family = new Set([process.pid]); let added;
  do { added = false; for (const row of rows) if (family.has(row.parent) && !family.has(row.pid)) { family.add(row.pid); added = true; } } while (added);
  for (const pid of family) if (pid !== process.pid) ownedPids.add(pid);
};
const listen = async server => {
  server.on('connection', socket => { sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket)); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  servers.push(server); return server.address().port;
};
const probe = `async () => {
  const canvas = document.createElement('canvas'), context = canvas.getContext('2d');
  const sample = 'mmmmmmmmmmlliW@#漢字字体';
  const families = ['Arial','Helvetica','Times New Roman','Courier New','Menlo','PingFang SC','Apple Color Emoji','SF Pro','Envara Definitely Missing Font'];
  const widths = family => ['monospace','sans-serif','serif'].map(base => { context.font = '72px "' + family + '",' + base; return context.measureText(sample).width; });
  const baseWidths = ['monospace','sans-serif','serif'].map(base => { context.font = '72px ' + base; return context.measureText(sample).width; });
  const fonts = Object.fromEntries(families.map(family => { const measurements = widths(family); return [family, { present: measurements.some((value, i) => value !== baseWidths[i]), widths: measurements }]; }));
  const gl = document.createElement('canvas').getContext('webgl');
  const ext = gl?.getExtension('WEBGL_debug_renderer_info');
  let uaData; try { uaData = await navigator.userAgentData?.getHighEntropyValues(['architecture','bitness','platform','platformVersion','fullVersionList']); } catch {}
  return { title: document.title, url: location.href, userAgent: navigator.userAgent, platform: navigator.platform, hardwareConcurrency: navigator.hardwareConcurrency, deviceMemory: navigator.deviceMemory ?? null,
    secureContext: isSecureContext, language: navigator.language, languages: navigator.languages, intl: Intl.DateTimeFormat().resolvedOptions(), uaData,
    screen: { width: screen.width, height: screen.height, availWidth: screen.availWidth, availHeight: screen.availHeight, colorDepth: screen.colorDepth, dpr: devicePixelRatio, innerWidth, innerHeight, outerWidth, outerHeight },
    gpu: ext ? { vendor: gl.getParameter(ext.UNMASKED_VENDOR_WEBGL), renderer: gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) } : null,
    fonts, headers: window.fixtureHeaders ?? null };
}`;
let manager, service, directContext, networkProbe;
const routeFixtures = [];
try {
  const respond = (req, res) => {
    const target = new URL(req.url, 'http://localhost');
    if (!['localhost', '127.0.0.1'].includes(target.hostname)) { res.writeHead(502); res.end('Offline native probe'); return; }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<!doctype html><meta charset="utf-8"><title>Envara device probe</title><h1>Owned offline device probe</h1><script>window.fixtureHeaders=' + JSON.stringify({ acceptLanguage: req.headers['accept-language'] ?? null }) + '</script>');
  };
  const proxyPort = await listen(http.createServer(respond).on('connect', (_req, socket) => socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')));
  const fixturePort = await listen(http.createServer(respond));
  const url = `http://localhost:${fixturePort}/`;
  manager = new SidecarManager({ dataDir, resourcesDir: resources, legacyCacheDir: path.join(root, 'test-artifacts/engine-cache') });
  await manager.initialize();
  const engine = manager.getEngineStates().cloakbrowser; assert(engine.installed);
  report.engine = { version: engine.version, binarySha256: createHash('sha256').update(await readFile(engine.binaryPath)).digest('hex') };
  report.sidecarSha256 = createHash('sha256').update(await readFile(path.join(resources, 'BrowseForge-sidecar'))).digest('hex');
  report.version = JSON.parse(await readFile(path.join(moduleRoot, 'package.json'), 'utf8')).version;
  if (capabilityProbe) {
  // Raw sidecar creation avoids the evolving device-catalog defaults during this capability measurement.
  const cases = [
    { label: 'native-4', cpu: 4, memory: 4, width: 1280, height: 800, locale: 'en-US', timezone: 'America/New_York' },
    { label: 'native-8-font-restriction', cpu: 8, memory: 8, width: 1920, height: 1080, locale: 'ms-MY', timezone: 'Asia/Kuala_Lumpur', fonts: ['Arial'], gpu: { vendor: 'Envara Probe Vendor', renderer: 'Envara Probe Renderer' } },
  ];
  for (const desired of cases) {
    const fingerprint = { 'navigator.hardwareConcurrency': desired.cpu, 'navigator.deviceMemory': desired.memory, 'screen.width': desired.width, 'screen.height': desired.height,
      'screen.availWidth': desired.width, 'screen.availHeight': desired.height - 40, 'screen.devicePixelRatio': desired.cpu === 4 ? 1 : 2,
      ...(desired.fonts ? { fonts: desired.fonts } : {}), ...(desired.gpu ? { 'webGl:vendor': desired.gpu.vendor, 'webGl:renderer': desired.gpu.renderer } : {}) };
    const created = (await manager.client.request('POST', '/api/profiles', { name: desired.label, runtime_id: 'cloakbrowser', fingerprint_seed: 286313, identity: { target_os: 'macos' }, fingerprint,
      proxy: { type: 'http', host: '127.0.0.1', port: proxyPort }, launch_overrides: { target_os: 'macos', locale: desired.locale, timezone: desired.timezone } })).data;
    assert(created?.id, JSON.stringify(created));
    const session = (await manager.client.request('POST', '/api/sessions', { profile_id: created.id }, { timeoutMs: 180000 })).data;
    const id = session.session_id;
    await manager.client.request('POST', `/api/sessions/${id}/navigate`, { url }, { timeoutMs: 30000 });
    await captureOwnedProcesses();
    const actual = (await manager.client.request('POST', `/api/sessions/${id}/eval`, { script: `(${probe})()` })).data;
    assert.equal(actual.title, 'Envara device probe', 'The actual owned fixture page must have loaded.');
    assert(actual.headers?.acceptLanguage, 'The fixture must capture the actual HTTP Accept-Language header.');
    report.observations.push({ mode: 'sidecar', desired, actual });
    console.log(JSON.stringify({ label: desired.label, actual: { ...actual, fonts: Object.fromEntries(Object.entries(actual.fonts).map(([key, value]) => [key, value.present])) } }));
    await manager.client.request('DELETE', `/api/sessions/${id}`);
  }
  const { chromium } = await import(pathToFileURL(path.join(resources, 'playwright-driver/package/index.mjs')));
  for (const dpr of [1, 2]) {
    const args = ['--fingerprint=286313', '--fingerprint-platform=macos', '--fingerprint-screen-width=1440', '--fingerprint-screen-height=900',
      `--fingerprint-screen-device-scale-factor=${dpr}`, `--force-device-scale-factor=${dpr}`, '--fingerprint-hardware-concurrency=8', '--fingerprint-device-memory=8'];
    directContext = await chromium.launchPersistentContext(path.join(dataDir, `native-dpr-${dpr}`), { executablePath: engine.binaryPath, headless: false, viewport: null, args, proxy: { server: `http://127.0.0.1:${proxyPort}` }, ignoreDefaultArgs: ['--enable-automation'], timeout: 30000 });
    const page = directContext.pages()[0] ?? await directContext.newPage();
    await page.goto(url);
    await captureOwnedProcesses();
    const actual = await page.evaluate(`(${probe})()`);
    report.observations.push({ mode: 'native-dpr', desired: { dpr, args }, actual });
    console.log(JSON.stringify({ label: `native-dpr-${dpr}`, screen: actual.screen, cpu: actual.hardwareConcurrency, memory: actual.deviceMemory }));
    await directContext.close(); directContext = null;
  }
  check('Measured real sidecar hardware/screen/locale/fonts/GPU and native DPR parameters without host configuration changes.');
  } else {
    await verifyDeviceProfiles(url);
  }
  report.passed = true;
} catch (error) {
  report.error = { message: error.message, stack: error.stack }; console.error(error);
} finally {
  try { await captureOwnedProcesses(); } catch {}
  try { await directContext?.close(); } catch (error) { report.cleanupError = error.message; report.passed = false; }
  networkProbe?.close();
  try { await manager?.shutdown(); } catch (error) { report.cleanupError = error.message; report.passed = false; }
  for (const socket of sockets) socket.destroy();
  await Promise.all(servers.map(server => new Promise(resolve => server.close(resolve))));
  for (let count = 0; count < 20 && [...ownedPids].some(alive); count++) await delay(100);
  report.remainingOwnedProcesses = [...ownedPids].filter(alive);
  if (report.remainingOwnedProcesses.length) report.passed = false;
  report.routes = routeFixtures.map(({ label, stats }) => ({ label, ...stats }));
  if (!report.passed) report.retainedDataDir = dataDir;
  await writeFile(path.join(runDir, 'proof.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  if (report.passed) await rm(dataDir, { recursive: true, force: true });
  console.log('Verification proof: ' + path.join(runDir, 'proof.json'));
  if (!report.passed) process.exitCode = 1;
}

async function verifyDeviceProfiles(fixtureURL) {
  const { getBrowserDeviceProfile, deviceProfileFingerprint } = await import(pathToFileURL(path.join(moduleRoot, 'shared/browser-device-profile.mjs')));
  const certConfig = path.join(dataDir, 'certificate.cnf');
  await writeFile(certConfig, '[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=device-geo.envara.invalid\n[v3]\nsubjectAltName=DNS:device-geo.envara.invalid\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n');
  await execute('/usr/bin/openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-config', certConfig, '-keyout', path.join(dataDir, 'key.pem'), '-out', path.join(dataDir, 'cert.pem')], { timeout: 15000 });
  const certificate = { key: await readFile(path.join(dataDir, 'key.pem')), cert: await readFile(path.join(dataDir, 'cert.pem')) };
  const makeRoute = async (label, countryCode, timezone, ip) => {
    const username = `owned-route-${label}`, password = randomBytes(18).toString('hex');
    const authorization = 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64');
    const stats = { authenticated: 0, browserRequests: 0, geoRequests: 0, refusedExternal: 0 };
    const geoPort = await listen(https.createServer(certificate, (_req, res) => {
      stats.geoRequests++;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, ip, country_code: countryCode, country: label, city: 'Owned offline fixture', latitude: 3.1, longitude: 101.7, timezone: { id: timezone } }));
    }));
    const proxy = http.createServer((req, res) => {
      if (req.headers['proxy-authorization'] !== authorization) { res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="Envara device probe"' }); res.end(); return; }
      stats.authenticated++;
      const url = new URL(req.url, 'http://localhost');
      if (url.origin !== new URL(fixtureURL).origin) { stats.refusedExternal++; res.writeHead(502); res.end('Offline route only'); return; }
      stats.browserRequests++;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<!doctype html><meta charset="utf-8"><title>Envara device probe</title><h1>Route ' + label + '</h1><script>window.fixtureHeaders=' + JSON.stringify({ acceptLanguage: req.headers['accept-language'] ?? null, route: label }) + '</script>');
    });
    proxy.on('connect', (req, socket, head) => {
      if (req.headers['proxy-authorization'] !== authorization) { socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Envara device probe"\r\n\r\n'); return; }
      stats.authenticated++;
      if (req.url !== 'device-geo.envara.invalid:443') { stats.refusedExternal++; socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); return; }
      const upstream = net.connect(geoPort, '127.0.0.1'); sockets.add(upstream); upstream.on('close', () => sockets.delete(upstream));
      upstream.on('error', () => socket.destroy()); socket.on('error', () => upstream.destroy());
      upstream.once('connect', () => { socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); if (head.length) upstream.write(head); socket.pipe(upstream); upstream.pipe(socket); });
      socket.on('close', () => upstream.destroy());
    });
    const port = await listen(proxy);
    const route = { label, stats, countryCode, timezone, proxy: { name: `Owned offline route ${label}`, protocol: 'http', host: '127.0.0.1', port, username, password } };
    routeFixtures.push(route); return route;
  };
  const a = await makeRoute('A', 'US', 'America/New_York', '45.1.2.3');
  const b = await makeRoute('B', 'MY', 'Asia/Kuala_Lumpur', '45.2.3.4');
  networkProbe = new ProxyNetworkProbe({ endpoints: [{ url: 'https://device-geo.envara.invalid/', source: 'owned-offline-fixture', format: 'ipwho' }], tlsOptions: { ca: certificate.cert }, cacheTtlMs: 600000 });
  const makeService = () => new BrowseForgeService(dataDir, manager.client, { platform: process.platform, appVersion: report.version }, () => {}, {
    profilesDir: path.join(manager.baseDir, 'profiles'), getEngineStates: () => manager.getEngineStates(), networkProbe,
  });
  service = makeService();
  for (const route of [a, b]) {
    const result = await service.call('saveProxy', { proxy: route.proxy });
    route.proxyId = result.proxies.find(item => item.name === route.proxy.name).id;
  }
  const profile = (await service.call('createProfile', { profile: { name: 'Owned stable device', engine: 'cloakbrowser', proxyId: a.proxyId, timezone: '', startUrl: fixtureURL } })).actionResult.createdId;
  const current = async id => (await service.snapshot()).profiles.find(item => item.id === id);
  const original = await current(profile);
  assert.equal(original.deviceProfileId, 'mac-standard-v1');
  const seed = original.seed;
  const device = getBrowserDeviceProfile(original.deviceProfileId);
  const fixedFingerprint = deviceProfileFingerprint(device.id);
  for (const [key, value] of Object.entries(fixedFingerprint)) assert.equal(original.fingerprint[key], value);
  const sessionId = async id => {
    const sessions = (await manager.client.request('GET', '/api/sessions')).data;
    const session = sessions.find(item => item.profile_id === id); assert(session); return session.session_id;
  };
  const hardware = observation => ({ cpu: observation.hardwareConcurrency, memory: observation.deviceMemory, width: observation.screen.width, height: observation.screen.height, dpr: observation.screen.dpr, platform: observation.platform });
  const capture = async (id, label, expectedDevice, route, locale) => {
    await service.call('startProfile', { id });
    await captureOwnedProcesses();
    const sid = await sessionId(id);
    const actual = (await manager.client.request('POST', `/api/sessions/${sid}/eval`, { script: `(${probe})()` })).data;
    report.observations.push({ label, deviceProfileId: expectedDevice.id, route: route.label, actual });
    assert.equal(actual.title, 'Envara device probe');
    assert.equal(actual.headers?.route, route.label, 'The actual page must come from the selected authenticated proxy.');
    assert.equal(actual.language, locale);
    assert.equal(new Intl.Locale(actual.intl.locale).maximize().baseName, new Intl.Locale(locale).maximize().baseName);
    assert(actual.headers.acceptLanguage.startsWith(locale));
    assert.equal(actual.intl.timeZone, route.timezone);
    assert.equal(actual.hardwareConcurrency, expectedDevice.hardwareConcurrency);
    assert.equal(actual.deviceMemory, expectedDevice.deviceMemory);
    assert.equal(actual.screen.width, expectedDevice.width); assert.equal(actual.screen.height, expectedDevice.height); assert.equal(actual.screen.dpr, expectedDevice.deviceScaleFactor);
    assert.equal(actual.platform, { macos: 'MacIntel', windows: 'Win32', linux: 'Linux x86_64' }[expectedDevice.platform]);
    await service.call('stopProfile', { id });
    return actual;
  };
  const first = await capture(profile, 'fresh-default-device', device, a, 'en-US');
  check('A newly created environment defaults to the versioned Mac device, with real 8-thread/8-GB browser values, 1440×900 screen and DPR 2.');
  await manager.stop(); await manager.start(); service = makeService();
  const persisted = await current(profile);
  assert.equal(persisted.deviceProfileId, device.id); assert.equal(persisted.seed, seed);
  const restarted = await capture(profile, 'after-service-restart', device, a, 'en-US');
  assert.deepEqual(hardware(restarted), hardware(first));
  check('The selected device and seed survive a real sidecar/service restart and the observed hardware stays identical.');
  await service.call('updateProfile', { id: profile, profile: { proxyId: b.proxyId } });
  const changed = await current(profile); assert.equal(changed.deviceProfileId, device.id); assert.equal(changed.seed, seed);
  const relocated = await capture(profile, 'after-network-change', device, b, 'ms-MY');
  assert.deepEqual(hardware(relocated), hardware(first));
  check('Changing only the selected authenticated network changes automatic language/Intl/HTTP headers and timezone to Malaysia while keeping the device and seed unchanged.');
  await service.call('updateProfile', { id: profile, profile: { locale: 'en-US' } });
  const explicitEnglish = await capture(profile, 'explicit-english-language', device, b, 'en-US');
  assert.deepEqual(hardware(explicitEnglish), hardware(first));
  check('An explicit browser-language override changes navigator/Intl/HTTP headers to en-US while preserving the network timezone and device.');
  const beforeConflict = await current(profile);
  await assert.rejects(service.call('updateProfile', { id: profile, profile: { fingerprint: { 'navigator.hardwareConcurrency': 4 } } }), value => value.code === 'DEVICE_PROFILE_CONFLICT');
  const afterConflict = await current(profile); assert.equal(afterConflict.seed, beforeConflict.seed); assert.deepEqual(afterConflict.fingerprint, beforeConflict.fingerprint);
  check('A conflicting edit cannot silently alter a fixed device specification.');
  const clonedId = (await service.call('cloneProfile', { id: profile })).actionResult.createdId;
  const cloned = await current(clonedId); assert.equal(cloned.deviceProfileId, device.id); assert.notEqual(cloned.seed, seed);
  for (const [key, value] of Object.entries(fixedFingerprint)) assert.equal(cloned.fingerprint[key], value);
  check('Cloning retains the versioned device settings but allocates a different fingerprint seed.');
  for (const id of ['windows-standard-v1', 'linux-standard-v1']) {
    await assert.rejects(service.call('createProfile', { profile: { name: `Refused ${id}`, engine: 'cloakbrowser', deviceProfileId: id, proxyId: a.proxyId } }), value => value.code === 'DEVICE_PROFILE_PLATFORM_UNSUPPORTED');
  }
  check('A Mac host refuses Windows/Linux fixed device presets instead of claiming an unverified cross-platform identity.');
  const custom = { id: 'provider-default', platform: 'macos', width: 1440, height: 900, deviceScaleFactor: 1, hardwareConcurrency: 4, deviceMemory: 4 };
  const customId = (await service.call('createProfile', { profile: { name: 'Owned custom DPR 1', engine: 'cloakbrowser', deviceProfileId: custom.id, platform: custom.platform, proxyId: a.proxyId,
    locale: 'en-US', timezone: 'America/New_York', startUrl: fixtureURL, fingerprint: { 'screen.width': custom.width, 'screen.height': custom.height, 'screen.devicePixelRatio': custom.deviceScaleFactor, 'navigator.hardwareConcurrency': custom.hardwareConcurrency, 'navigator.deviceMemory': custom.deviceMemory } } })).actionResult.createdId;
  await capture(customId, 'native-custom-dpr-1', custom, a, 'en-US');
  check('An explicit custom Mac profile proves the sidecar passes native DPR 1 and 4/4 hardware parameters, independently of the fixed DPR-2 preset.');
  assert(a.stats.browserRequests > 0 && b.stats.browserRequests > 0 && a.stats.geoRequests > 0 && b.stats.geoRequests > 0);
  report.stableHardware = hardware(first);
  report.stableDeviceProfileId = device.id;
}
