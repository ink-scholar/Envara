/** Real offline browser-data export/import acceptance. No user profiles/sites.
 * ELECTRON_RUN_AS_NODE=1 /absolute/Envara.app/Contents/MacOS/Envara scripts/verify-scoped-browser-transfer.mjs --packaged /absolute/Envara.app
 * Add --runtime cloakbrowser|camoufox|browseforge-chromium and --browser /absolute/official-binary.
 * CloakBrowser keeps its existing default; other runtimes require an explicit binary.
 * Reexecutes itself in an inherited, loopback-only Seatbelt fence before launch.
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import os from 'node:os';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { access, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

process.umask(0o077);
const execute = promisify(execFile);
const script = fileURLToPath(import.meta.url);
const root = path.resolve(path.dirname(script), '..');
const option = name => {
  const index = process.argv.indexOf(name);
  if (index < 0) return null;
  assert(!process.argv.slice(index + 1).includes(name) && process.argv[index + 1] && !process.argv[index + 1].startsWith('--'), `Provide one value for ${name}.`);
  return process.argv[index + 1];
};
const runtimeId = option('--runtime') ?? 'cloakbrowser';
assert(['cloakbrowser', 'camoufox', 'browseforge-chromium'].includes(runtimeId), 'Select a supported fixture runtime.');
const explicitBrowser = option('--browser');
assert(runtimeId === 'cloakbrowser' || explicitBrowser, 'This runtime requires --browser with an existing official binary.');
const application = option('--packaged');
assert(application && path.isAbsolute(application) && application.endsWith('.app'), 'An explicit packaged Envara.app is required.');
assert(process.platform === 'darwin' && process.versions.electron && process.env.ELECTRON_RUN_AS_NODE === '1', 'Use the selected packaged Mac executable in Node mode.');
assert.equal(await realpath(process.resourcesPath), await realpath(path.join(application, 'Contents/Resources')));
const moduleRoot = path.join(application, 'Contents/Resources/app.asar');
const resourcesDir = path.join(application, 'Contents/Resources/backend');
const browserBinary = explicitBrowser ?? path.join(os.homedir(), 'Library/Application Support/Envara/engines/chromium-145.0.7632.109.2/Chromium.app/Contents/MacOS/Chromium');
assert(path.isAbsolute(browserBinary), 'The selected browser binary must be an absolute path.');
await access(browserBinary, constants.X_OK);

// The script, backend and browser inherit this fence. Host proxy listeners and
// the system DNS service are unavailable; the test origin is a numeric loopback.
if (!process.argv.includes('--loopback-fenced')) {
  const { terminalFenceProfile, systemProxyPorts, environmentProxyPorts } = await import(pathToFileURL(path.join(moduleRoot, 'electron/terminal-network-fence.mjs')));
  const systemProxy = await execute('/usr/sbin/scutil', ['--proxy'], { timeout: 3000 });
  const deniedLoopbackPorts = [...systemProxyPorts(systemProxy.stdout), ...environmentProxyPorts(process.env)];
  const fence = terminalFenceProfile({ deniedLoopbackPorts });
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (/^(?:https?|all|ftp|rsync|socks)_proxy$/i.test(key) || key.startsWith('CLOAKBROWSER_')) delete env[key];
  const child = spawn('/usr/bin/sandbox-exec', ['-p', fence, process.execPath, script, ...process.argv.slice(2), '--loopback-fenced'], { env, stdio: ['inherit', 'inherit', 'inherit', 'ipc'] });
  const owned = new Map();
  child.on('message', async request => {
    if (!['capture', 'remaining'].includes(request?.type) || !Number.isSafeInteger(request.id) ||
        typeof request.dataDir !== 'string' || !path.basename(request.dataDir).startsWith('envara-owned-browser-transfer-')) return;
    try {
      const rows = await processTable(), family = new Set([child.pid]);
      let changed;
      do { changed = false; for (const row of rows) if (family.has(row.parent) && !family.has(row.pid)) { family.add(row.pid); changed = true; } } while (changed);
      for (const row of rows) if (row.pid !== child.pid && (family.has(row.pid) || row.command.includes(request.dataDir))) owned.set(row.pid, row.birth);
      const remaining = rows.filter(row => owned.get(row.pid) === row.birth).map(row => row.pid);
      child.send({ id: request.id, ok: true, remaining });
    } catch { child.send({ id: request.id, ok: false }); }
  });
  child.once('error', () => { process.exitCode = 1; });
  const [code] = await once(child, 'exit');
  process.exit(code ?? 1);
}

const [{ SidecarManager, sidecarConfig }, { BrowseForgeService }, transfer, archive] = await Promise.all([
  import(pathToFileURL(path.join(moduleRoot, 'electron/sidecar-manager.mjs'))),
  import(pathToFileURL(path.join(moduleRoot, 'electron/browseforge-service.mjs'))),
  import(pathToFileURL(path.join(moduleRoot, 'electron/environment-transfer.mjs'))),
  import(pathToFileURL(path.join(moduleRoot, 'electron/environment-export.mjs'))),
]);
const artifactRoot = path.join(root, 'build/local-verification/scoped-browser-transfer');
await mkdir(artifactRoot, { recursive: true, mode: 0o700 });
const runDir = await realpath(await mkdtemp(path.join(artifactRoot, `run-${runtimeId}-`)));
const dataDir = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-owned-browser-transfer-')));
for (const leaf of ['home', 'tmp']) await mkdir(path.join(dataDir, leaf), { mode: 0o700 });
process.env.HOME = path.join(dataDir, 'home');
process.env.TMPDIR = path.join(dataDir, 'tmp');
process.env.CLOAKBROWSER_CACHE_DIR = path.join(dataDir, 'unused-sdk-cache');
process.env.CLOAKBROWSER_AUTO_UPDATE = 'false';
const password = randomBytes(32).toString('base64url');
const value = randomBytes(24).toString('hex');
const report = { passed: false, startedAt: new Date().toISOString(), application, runtime: runtimeId, packageVersion: null, stage: 'INITIALIZE', checks: [],
  scope: 'browser', network: { loopbackFence: true, fixtureRequests: 0, rejectedProxyRequests: 0 }, limitations: [
    'Synthetic state on one owned loopback HTTP origin; not external website sign-in, CAPTCHA, account or cross-machine Keychain acceptance.',
    'Uses only the selected existing browser and packaged production export/import modules; no browser download, user profile, terminal or application data is migrated.',
    'Chromium uses the fixture backend no-sandbox option. Camoufox uses an owned MOZ_DISABLE_*_SANDBOX launcher solely to avoid nesting inside the inherited loopback fence; official binary bytes and production configuration are unchanged.',
  ] };
const check = message => { report.checks.push(message); console.log('PASS ' + message); };
const sockets = new Set(), servers = [];
let ipcSequence = 0;
let manager, service;

const shellQuote = value => `'${String(value).replaceAll("'", "'\\''")}'`;
function camoufoxFixtureLauncher(binary) {
  return '#!/bin/sh\nexport MOZ_DISABLE_CONTENT_SANDBOX=1 MOZ_DISABLE_RDD_SANDBOX=1 MOZ_DISABLE_GMP_SANDBOX=1 MOZ_DISABLE_GPU_SANDBOX=1 MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1\nexec ' + shellQuote(binary) + ' "$@"\n';
}
class OfflineSidecarManager extends SidecarManager {
  async probe() {
    // The CLI probes its managed browser directory, not config.binary_path.
    // Only the owned fixture gets a version marker and a link to the existing
    // bundle; cleanup unlinks it without changing any upstream bytes.
    const status = await this.command(['browsers', 'status', '--runtimes', runtimeId, '--json']);
    const descriptor = status.browsers.find(item => item.name === runtimeId);
    assert.equal(descriptor?.platform_supported, true);
    assert(typeof descriptor.expected === 'string' && /^[A-Za-z0-9_.-]+$/.test(descriptor.expected));
    const bundleName = runtimeId === 'camoufox' ? 'Camoufox.app' : 'Chromium.app';
    const executableName = runtimeId === 'camoufox' ? 'camoufox' : 'Chromium';
    assert(browserBinary.endsWith(path.join(bundleName, 'Contents', 'MacOS', executableName)), 'Select the original macOS browser bundle executable.');
    const ownedBrowser = path.join(this.baseDir, 'browsers', runtimeId);
    await mkdir(ownedBrowser, { recursive: true, mode: 0o700 });
    await symlink(path.dirname(path.dirname(path.dirname(browserBinary))), path.join(ownedBrowser, bundleName), 'dir');
    await writeFile(path.join(ownedBrowser, '.version'), descriptor.expected, { mode: 0o600, flag: 'wx' });
    const states = await super.probe(), selected = states[runtimeId];
    assert.equal(selected?.installed, true, 'The selected official browser must pass the production probe.');
    assert.equal(await realpath(selected.binaryPath), await realpath(browserBinary));
    report.originalBinaryProbed = true;
    report.fixtureVersionMarker = descriptor.expected;
    this.fixtureBrowserPath = browserBinary;
    if (runtimeId === 'camoufox') {
      this.fixtureBrowserPath = path.join(dataDir, 'camoufox-fixture-launcher.sh');
      await writeFile(this.fixtureBrowserPath, camoufoxFixtureLauncher(browserBinary), { mode: 0o700, flag: 'wx' });
      states[runtimeId] = { ...selected, binaryPath: this.fixtureBrowserPath };
      report.camoufoxFixtureSandboxWrapper = true;
    }
    return states;
  }
  async start() {
    // Only fixture launch plumbing differs: the production backend, client,
    // engine probing, profile/session APIs and shutdown remain the real ones.
    const reservation = http.createServer();
    await new Promise((resolve, reject) => { reservation.once('error', reject); reservation.listen(0, '127.0.0.1', resolve); });
    this.port = reservation.address().port;
    await new Promise(resolve => reservation.close(resolve));
    this.baseUrl = `http://127.0.0.1:${this.port}`;
    await writeFile(this.configFile, JSON.stringify({ ...sidecarConfig(this.baseDir, this.port, this.states), no_sandbox: true }), { mode: 0o600 });
    const child = spawn(this.binary, ['--base-dir', this.baseDir, '--config', this.configFile, 'serve', '--host', '127.0.0.1', '--port', String(this.port), '--no-open', '--no-sandbox'], {
      cwd: this.baseDir, env: this.env(), windowsHide: true,
    });
    this.process = child;
    child.stdout.resume(); child.stderr.resume();
    let spawnError;
    child.once('error', error => { spawnError = error; });
    child.once('exit', () => { if (this.process === child) this.process = null; });
    const deadline = Date.now() + 45000;
    while (Date.now() < deadline) {
      if (spawnError || child.exitCode !== null) throw new Error('Owned offline backend could not start.');
      try { await this.client.request('GET', '/api/runtimes', undefined, { timeoutMs: 1000 }); return; } catch {}
      await delay(100);
    }
    throw new Error('Owned offline backend startup timed out.');
  }
}

async function processTable() {
  const { stdout } = await execute('/bin/ps', ['-axo', 'pid=,ppid=,lstart=,command='], { timeout: 5000, maxBuffer: 8 * 1024 * 1024 });
  return stdout.split('\n').map(line => /^\s*(\d+)\s+(\d+)\s+(\w{3}\s+\w{3}\s+\d+\s+\d\d:\d\d:\d\d\s+\d{4})\s+(.+)$/.exec(line))
    .filter(Boolean).map(([, pid, parent, birth, command]) => ({ pid: Number(pid), parent: Number(parent), birth, command }));
}
async function captureOwned() {
  await processObservation('capture');
}
async function remainingOwned() {
  return (await processObservation('remaining')).remaining;
}
function processObservation(type) {
  assert(process.connected, 'The unfenced owned parent observer must remain connected.');
  const id = ++ipcSequence;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { process.off('message', receive); reject(new Error('Owned process observation timed out.')); }, 5000);
    function receive(response) {
      if (response?.id !== id) return;
      clearTimeout(timer); process.off('message', receive);
      response.ok ? resolve(response) : reject(new Error('Owned process observation unavailable.'));
    }
    process.on('message', receive);
    process.send({ type, id, dataDir });
  });
}
async function listen(server) {
  server.on('connection', socket => { sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket)); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  servers.push(server);
  return server.address().port;
}
const body = '<!doctype html><meta charset="utf-8"><title>Envara owned transfer fixture</title><h1>Owned offline transfer fixture</h1>';
let fixtureOrigin;
function respond(req, res) {
  const url = new URL(req.url, fixtureOrigin);
  if (url.origin !== fixtureOrigin) { report.network.rejectedProxyRequests++; res.writeHead(502); res.end(); return; }
  report.network.fixtureRequests++;
  if (url.pathname === '/inspect') {
    const cookies = new Map((req.headers.cookie ?? '').split(';').map(part => part.trim().split('=')));
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ normal: cookies.get('envara_transfer_cookie') === value, httpOnly: cookies.get('envara_transfer_http_only') === value, session: cookies.get('envara_transfer_session') === value, sessionHttpOnly: cookies.get('envara_transfer_session_http_only') === value }));
  } else {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...(url.pathname === '/seed' ? {
      'Set-Cookie': [`envara_transfer_cookie=${value}; Max-Age=2592000; Path=/; SameSite=Lax`, `envara_transfer_http_only=${value}; Max-Age=2592000; Path=/; HttpOnly; SameSite=Lax`, `envara_transfer_session=${value}; Path=/; SameSite=Lax`, `envara_transfer_session_http_only=${value}; Path=/; HttpOnly; SameSite=Lax`],
    } : {}) });
    res.end(body);
  }
}
const evaluate = async (sessionId, script) => (await manager.client.request('POST', `/api/sessions/${sessionId}/eval`, { script }, { timeoutMs: 15000 })).data;
const readState = `async () => {
  const db = await new Promise((resolve,reject) => { const r=indexedDB.open('envara-transfer-state',1); r.onsuccess=()=>resolve(r.result); r.onerror=()=>reject(new Error('IDB_OPEN_FAILED')); });
  const indexedDBValue = await new Promise((resolve,reject) => { const t=db.transaction('values','readonly'),r=t.objectStore('values').get('marker'); r.onsuccess=()=>resolve(r.result); r.onerror=()=>reject(new Error('IDB_READ_FAILED')); });
  db.close();
  const server = await (await fetch('/inspect',{cache:'no-store'})).json();
  return { normalCookie:document.cookie.split(';').some(part=>part.trim()==='envara_transfer_cookie=${value}'), httpOnlyHidden:!document.cookie.includes('envara_transfer_http_only'),
    serverNormalCookie:server.normal, serverHttpOnlyCookie:server.httpOnly, sessionCookie:document.cookie.split(';').some(part=>part.trim()==='envara_transfer_session=${value}'), serverSessionCookie:server.session, serverSessionHttpOnlyCookie:server.sessionHttpOnly, sessionHttpOnlyHidden:!document.cookie.includes('envara_transfer_session_http_only'), pageLocale:navigator.language, pageTimezone:Intl.DateTimeFormat().resolvedOptions().timeZone, localStorage:localStorage.getItem('envara-transfer-marker')==='${value}', indexedDB:indexedDBValue==='${value}', origin:location.origin };
}`;
async function launch(profileId, pathname) {
  let session;
  if (runtimeId === 'browseforge-chromium') {
    await service.startProfile({ id: profileId });
    session = ((await manager.client.request('GET', '/api/sessions')).data ?? []).find(item => item.profile_id === profileId);
    report.productionContextLaunches = (report.productionContextLaunches ?? 0) + 1;
  } else session = (await manager.client.request('POST', '/api/sessions', { profile_id: profileId }, { timeoutMs: 90000 })).data;
  assert(session?.session_id, 'The real backend must return a session.');
  assert.equal(session.runtime_id, runtimeId, 'The backend must launch only the selected provider.');
  await captureOwned();
  await manager.client.request('POST', `/api/sessions/${session.session_id}/navigate`, { url: fixtureOrigin + pathname, wait_until: 'domcontentloaded' }, { timeoutMs: 15000 });
  return session.session_id;
}
async function verifyState(sessionId, label) {
  const actual = await evaluate(sessionId, `(${readState})()`);
  assert.equal(actual.origin, fixtureOrigin, 'The exact original origin/port must be reused.');
  for (const key of ['normalCookie', 'httpOnlyHidden', 'serverNormalCookie', 'serverHttpOnlyCookie', 'localStorage', 'indexedDB', 'sessionHttpOnlyHidden']) assert.equal(actual[key], true, `${label}: ${key}`);
  assert.equal(actual.pageLocale, 'en-US', `${label}: effective locale`);
  assert.equal(actual.pageTimezone, 'America/New_York', `${label}: effective timezone`);
  report[label] = Object.fromEntries(Object.entries(actual).filter(([key]) => key !== 'origin'));
  check(label + ': real persistent/HttpOnly cookies, localStorage and IndexedDB are readable.');
}
try {
  await captureOwned();
  report.packageVersion = JSON.parse(await readFile(path.join(moduleRoot, 'package.json'), 'utf8')).version;
  report.fixtureHarnessSha256 = createHash('sha256').update(await readFile(script)).digest('hex');
  report.browserSha256 = createHash('sha256').update(await readFile(browserBinary)).digest('hex');
  report.backendSha256 = createHash('sha256').update(await readFile(path.join(resourcesDir, 'BrowseForge-sidecar'))).digest('hex');
  const fixturePort = await listen(http.createServer(respond));
  fixtureOrigin = `http://127.0.0.1:${fixturePort}`;
  const proxy = http.createServer(respond);
  proxy.on('connect', (_req, socket) => { report.network.rejectedProxyRequests++; socket.end('HTTP/1.1 502 Offline fixture only\r\n\r\n'); });
  const proxyPort = await listen(proxy);
  manager = new OfflineSidecarManager({ dataDir, resourcesDir, legacyCacheDir: path.join(dataDir, 'unused-legacy-cache') });
  await manager.initialize();
  const engine = manager.getEngineStates()[runtimeId];
  assert.equal(await realpath(engine.binaryPath), await realpath(manager.fixtureBrowserPath));
  report.managerReportedVersion = engine.version;
  // This offline origin cannot establish a public exit country. Feed only BF's
  // desktop resolver a labelled synthetic context, then let real startProfile
  // transmit country_code; the backend's country guard remains unchanged.
  const countryFixture = runtimeId === 'browseforge-chromium' ? {
    networkProbe: {
      probe: async () => ({ ok: true, scope: 'egress', countryCode: 'US', timezone: 'America/New_York' }),
      peek: () => null, invalidate() {}, close() {},
    },
  } : {};
  if (runtimeId === 'browseforge-chromium') {
    report.network.syntheticCountryContext = true;
    report.limitations.push('BrowseForge Chromium uses a synthetic US/New_York resolver response via production startProfile; country_code consumption is verified, not public egress or GeoIP.');
  }
  service = new BrowseForgeService(dataDir, manager.client, { platform: 'darwin', appVersion: report.packageVersion }, () => {}, {
    profilesDir: path.join(manager.baseDir, 'profiles'), getEngineStates: () => manager.getEngineStates(), ...countryFixture,
  });
  const savedProxy = await service.call('saveProxy', { proxy: { name: 'Owned loopback transfer fixture', protocol: 'http', host: '127.0.0.1', port: proxyPort, region: 'us-ny' } });
  const proxyId = savedProxy.proxies.find(item => item.name === 'Owned loopback transfer fixture').id;
  const sourceId = (await service.call('createProfile', { profile: { name: 'Owned browser transfer source', engine: runtimeId, platform: 'macos', timezone: 'America/New_York', locale: 'en-US', proxyId, startUrl: fixtureOrigin + '/read' } })).actionResult.createdId;
  const sourceConfig = (await service.snapshot()).profiles.find(item => item.id === sourceId);
  const configFields = ['engine', 'seed', 'fingerprintGeneration', 'platform', 'locale', 'timezone', 'deviceProfileId', 'fingerprint', 'privacy', 'width', 'height', 'group', 'tags', 'notes', 'startUrl'];
  const configOf = profile => Object.fromEntries(configFields.map(key => [key, profile[key]]));
  const generation = sourceConfig.fingerprintGeneration;
  assert.equal(generation?.provider, runtimeId);
  assert.equal(generation.version, 1);
  assert.equal(typeof generation.tuple_id, 'string');
  assert(Object.keys(generation.generated_fields ?? {}).length > 0, 'A new automatic identity needs persisted generation provenance.');
  for (const [key, generated] of Object.entries(generation.generated_fields)) assert.deepEqual(sourceConfig.fingerprint[key], generated);
  if (runtimeId !== 'camoufox') assert(Number.isSafeInteger(sourceConfig.seed) && sourceConfig.seed > 0);
  check('The new environment records a provider-generated identity before browser launch.');
  report.configuration = { provider: sourceConfig.engine, seed: sourceConfig.seed, locale: sourceConfig.locale, timezone: sourceConfig.timezone, generationProvider: generation.provider, generationVersion: generation.version, generationTupleId: generation.tuple_id, generatedFieldCount: Object.keys(generation.generated_fields).length, comparisonFields: configFields };
  report.stage = 'SEED_BROWSER';
  const sourceSession = await launch(sourceId, '/seed');
  await evaluate(sourceSession, `(async () => {
    localStorage.setItem('envara-transfer-marker','${value}');
    const db=await new Promise((resolve,reject)=>{const r=indexedDB.open('envara-transfer-state',1);r.onupgradeneeded=()=>r.result.createObjectStore('values');r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(new Error('IDB_OPEN_FAILED'));});
    await new Promise((resolve,reject)=>{const t=db.transaction('values','readwrite');t.objectStore('values').put('${value}','marker');t.oncomplete=resolve;t.onerror=()=>reject(new Error('IDB_WRITE_FAILED'));});db.close();return true;
  })()`);
  await verifyState(sourceSession, 'sourceBeforeClose');
  assert.equal(report.sourceBeforeClose.sessionCookie, true);
  assert.equal(report.sourceBeforeClose.serverSessionCookie, true);
  assert.equal(report.sourceBeforeClose.serverSessionHttpOnlyCookie, true);
  check('The fixture sets persistent and session cookies, including HttpOnly; no real account is used.');
  report.browserVersion = await evaluate(sourceSession, 'navigator.userAgent.match(/(?:Chrome|Chromium|Firefox)\\/([0-9.]+)/)?.[1]');
  assert.equal(typeof report.browserVersion, 'string', 'The selected engine must expose a browser version.');
  await service.call('stopProfile', { id: sourceId });
  report.stage = 'REOPEN_WITHOUT_EXPORT';
  const reopenedSession = await launch(sourceId, '/read');
  await verifyState(reopenedSession, 'sourceAfterCloseReopen');
  assert.deepEqual(configOf((await service.snapshot()).profiles.find(item => item.id === sourceId)), configOf(sourceConfig));
  check('Stopping only the browser and reopening the retained environment preserves its configuration and persistent data.');
  report.stage = 'CLOSE_LAST_BROWSER_PAGE';
  await manager.client.request('POST', `/api/sessions/${reopenedSession}/navigate`, { url: fixtureOrigin + '/seed', wait_until: 'domcontentloaded' });
  const tabsResult = await manager.client.callMcpTool('list_tabs', { profile_id: sourceId });
  const tabs = JSON.parse(tabsResult.content.find(item => item.type === 'text').text);
  assert.equal(tabs.length, 1, 'The owned browser must have exactly one fixture tab.');
  await manager.client.callMcpTool('close_tab', { profile_id: sourceId, index: 0 });
  let naturallyStopped = false;
  for (let index = 0; index < 100; index++) {
    const sessions = (await manager.client.request('GET', '/api/sessions')).data ?? [];
    if (!sessions.some(item => item.profile_id === sourceId)) { naturallyStopped = true; break; }
    await delay(100);
  }
  assert.equal(naturallyStopped, true, 'Last-page close must retire the owned backend session without Stop.');
  assert.equal((await stat(path.join(manager.baseDir, 'profiles', sourceId, 'browser-data'))).isDirectory(), true);
  report.lastPageClose = { productionMcpPageClose: true, oneTabBeforeClose: true, sessionRetiredWithoutStop: true, browserDataDirectoryPreserved: true };
  const windowReopenedSession = await launch(sourceId, '/read');
  await verifyState(windowReopenedSession, 'sourceAfterLastPageCloseReopen');
  assert.deepEqual(configOf((await service.snapshot()).profiles.find(item => item.id === sourceId)), configOf(sourceConfig));
  check('Closing the only browser page retires its session; reopening keeps the environment and persistent state.');
  await service.call('stopProfile', { id: sourceId });
  const stopped = (await service.snapshot()).profiles.find(item => item.id === sourceId);
  assert.equal(stopped.status, 'stopped', 'Export starts only after normal browser stop.');
  report.stage = 'EXPORT_AND_DECRYPT';
  const file = path.join(dataDir, 'owned-browser.envara'), staging = path.join(dataDir, 'decrypted');
  const exported = await transfer.exportEnvironment({ profile: stopped, password, file, service, scope: 'browser', appVersion: report.packageVersion, dataDir });
  assert.equal(await archive.isEnvironmentExport(file), true);
  assert.equal((await stat(file)).mode & 0o777, 0o600);
  assert.equal((await readFile(file)).includes(Buffer.from(value)), false, 'The browser marker must not be stored as plaintext in the encrypted archive.');
  const manifest = transfer.checkedExportManifest(await archive.readEnvironmentExport({ file, password, staging }));
  assert.equal(manifest.scope, 'browser');
  assert.deepEqual(await readdir(staging), ['browser']);
  assert.equal(manifest.applications.length, 0);
  report.encryptedArchive = { bytes: exported.bytes ?? (await stat(file)).size, encryptedHeader: true, mode0600: true, scope: manifest.scope, onlyBrowserSection: true };
  check('Real scope:browser export is encrypted and decrypts to browser data only.');
  report.stage = 'IMPORT_AND_RESTORE';
  assert.deepEqual(configOf(manifest.profile.profiles[0]), configOf(sourceConfig));
  const beforeUnmapped = (await service.snapshot()).profiles.length;
  await assert.rejects(service.call('importProfiles', { document: manifest.profile }), { code: 'PROXY_MAPPING_REQUIRED' });
  assert.equal((await service.snapshot()).profiles.length, beforeUnmapped);
  check('Missing proxy mapping refuses import without creating an environment or switching to direct.');
  const mapped = await service.call('saveProxy', { proxy: { name: 'Owned destination local mapping', protocol: 'http', host: '127.0.0.1', port: proxyPort, region: 'us-ny' } });
  const mappedProxyId = mapped.proxies.find(item => item.name === 'Owned destination local mapping').id;
  assert.notEqual(mappedProxyId, proxyId);
  const imported = await service.call('importProfiles', { document: manifest.profile, proxyMap: { [proxyId]: mappedProxyId } });
  const destinationId = imported.actionResult.createdIds[0];
  assert.notEqual(destinationId, sourceId);
  const importedProfile = imported.profiles.find(item => item.id === destinationId);
  assert.deepEqual(configOf(importedProfile), configOf(sourceConfig));
  assert.equal(importedProfile.proxyId, mappedProxyId);
  const nativeProfiles = (await manager.client.request('GET', '/api/profiles')).data;
  const nativeSource = nativeProfiles.find(item => item.id === sourceId), nativeImported = nativeProfiles.find(item => item.id === destinationId);
  for (const key of ['runtime_id', 'fingerprint_seed', 'fingerprint_generation', 'identity', 'launch_overrides', 'fingerprint']) assert.deepEqual(nativeImported[key], nativeSource[key], `native ${key}`);
  assert.notEqual(nativeImported.profile_dir, nativeSource.profile_dir);
  report.configuration = { ...report.configuration, exportFieldsPreserved: true, importedFieldsPreserved: true, nativeFieldsPreserved: true, explicitDifferentProxyIdMapped: true, missingMappingRefused: true, distinctBrowserDirectory: true, liveProxyRoutingMeasured: false };
  check('Export/import preserves provider, generation provenance, seed, platform, locale, timezone and complete fingerprint settings with explicit new local proxy mapping.');
  const restored = await transfer.restoreEnvironment({ staging, manifest, profileId: destinationId, service, dataDir });
  assert.deepEqual(restored, { scope: 'browser', browser: true, terminal: false, applications: [] });
  const restoredSession = await launch(destinationId, '/read');
  await verifyState(restoredSession, 'restoredBrowser');
  await service.call('stopProfile', { id: destinationId });
  report.stage = 'REOPEN_ORIGINAL';
  const originalSession = await launch(sourceId, '/read');
  await verifyState(originalSession, 'originalStillReadable');
  await service.call('stopProfile', { id: sourceId });
  const finalProfiles = (await service.snapshot()).profiles;
  assert(finalProfiles.some(item => item.id === sourceId && item.status === 'stopped'));
  assert(finalProfiles.some(item => item.id === destinationId && item.status === 'stopped'));
  assert.deepEqual(configOf(finalProfiles.find(item => item.id === sourceId)), configOf(sourceConfig));
  assert.deepEqual(configOf(finalProfiles.find(item => item.id === destinationId)), configOf(sourceConfig));
  for (const profileId of [sourceId, destinationId]) {
    const stored = JSON.parse(await readFile(path.join(manager.baseDir, 'profiles', profileId, 'profile.json'), 'utf8'));
    for (const key of ['runtime_id', 'fingerprint_seed', 'fingerprint_generation', 'identity', 'launch_overrides', 'fingerprint'])
      assert.deepEqual(stored[key], nativeSource[key], `persisted ${key}`);
  }
  report.configuration.persistedIdentityPreserved = true;
  report.originalAndImportedProfilesRemain = true;
  report.cookieSemantics = { persistentCookiesRetainedAfterClose: true, persistentCookiesRetainedAfterImport: true, sessionCookiesBeforeClose: { normal: report.sourceBeforeClose.sessionCookie, httpOnly: report.sourceBeforeClose.serverSessionHttpOnlyCookie }, sessionCookiesAfterClose: { normal: report.sourceAfterCloseReopen.sessionCookie, httpOnly: report.sourceAfterCloseReopen.serverSessionHttpOnlyCookie }, sessionCookiesAfterLastPageClose: { normal: report.sourceAfterLastPageCloseReopen.sessionCookie, httpOnly: report.sourceAfterLastPageCloseReopen.serverSessionHttpOnlyCookie }, sessionCookiesAfterImport: { normal: report.restoredBrowser.sessionCookie, httpOnly: report.restoredBrowser.serverSessionHttpOnlyCookie }, guaranteesSessionCookieRestoration: false };
  report.limitations.push('Session-cookie lifetime is the engine/site session policy, not an Envara promise; persistent local synthetic state is not a real Gmail login or server-token guarantee.');
  report.limitations.push('Proxy mapping is validated as configuration metadata/native profile binding; the numeric loopback origin is a supported browser proxy bypass and does not measure public egress.');
  check('Import creates a distinct profile and the original browser remains independently readable.');
  report.passed = true;
} catch (error) {
  report.error = { code: error.code ?? 'ACCEPTANCE_FAILED', message: String(error.message).replaceAll(manager?.token ?? '\0', '[redacted]').slice(0, 800) };
  console.error('FAIL ' + report.stage + ': ' + report.error.message);
} finally {
  try { await captureOwned(); } catch {}
  try { service?.networkProbe?.close?.(); await manager?.shutdown(); }
  catch { report.passed = false; report.shutdownFailed = true; }
  for (const socket of sockets) socket.destroy();
  await Promise.all(servers.map(server => new Promise(resolve => server.close(resolve))));
  await delay(150);
  let remaining = [], processInspectionPassed = true;
  try {
    for (let index = 0; index < 50 && (await remainingOwned()).length; index++) await delay(100);
    remaining = await remainingOwned();
  } catch { processInspectionPassed = false; report.passed = false; }
  report.cleanup = { ownedProcessesRemaining: remaining, processInspectionPassed, fixtureServersClosed: servers.every(server => !server.listening), socketsClosed: sockets.size === 0 };
  if (report.cleanup.ownedProcessesRemaining.length || !report.cleanup.fixtureServersClosed || !report.cleanup.socketsClosed) report.passed = false;
  try { report.originalBrowserBytesUnchanged = createHash('sha256').update(await readFile(browserBinary)).digest('hex') === report.browserSha256; }
  catch { report.originalBrowserBytesUnchanged = false; }
  if (!report.originalBrowserBytesUnchanged) report.passed = false;
  if (report.passed) { await rm(dataDir, { recursive: true, force: true }); report.cleanup.ownedDataRemoved = true; }
  else report.retainedOwnedDataDir = dataDir;
  report.finishedAt = new Date().toISOString();
  await writeFile(path.join(runDir, 'proof.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  console.log('Verification proof: ' + path.join(runDir, 'proof.json'));
  if (!report.passed) process.exitCode = 1;
  process.disconnect?.();
}
