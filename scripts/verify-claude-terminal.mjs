/** Real local acceptance: installed Claude, PTY/Seatbelt, authenticated routes,
 * the production sidecar and its selected browser. No login, inference or
 * personal browser/profile is used. Run with the installed Electron runtime:
 * ELECTRON_RUN_AS_NODE=1 node_modules/electron/dist/Electron.app/Contents/MacOS/Electron scripts/verify-claude-terminal.mjs
 * Or use the compiled app's executable and append --packaged /absolute/Envara.app.
 * --browser /absolute/.../chromium-145.../Chromium.app/Contents/MacOS/Chromium
 * explicitly reuses that existing engine if the old fixture cache is absent.
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn, execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { promisify, stripVTControlCharacters } from 'node:util';
import { createHash, randomBytes } from 'node:crypto';
import { constants, createReadStream } from 'node:fs';
import { access, copyFile, mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createClaudeDownloadFixture, forwardOfficialClaudeDownload, verifyInstallerCancelRetry } from './verify-claude-installer.mjs';

const execute = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const updatedCLIIndex = process.argv.indexOf('--updated-cli');
const updatedExecutable = updatedCLIIndex < 0 ? null : process.argv[updatedCLIIndex + 1];
if (updatedCLIIndex >= 0) assert(updatedExecutable && path.isAbsolute(updatedExecutable), '--updated-cli requires an absolute real native CLI binary path.');
const downloadCLI = process.argv.includes('--download-cli');
const fixtureDownloadIndex = process.argv.indexOf('--fixture-download-cli');
const fixtureDownloadExecutable = fixtureDownloadIndex < 0 ? null : process.argv[fixtureDownloadIndex + 1];
if (fixtureDownloadIndex >= 0) assert(fixtureDownloadExecutable && path.isAbsolute(fixtureDownloadExecutable), '--fixture-download-cli requires an absolute previously verified native CLI path.');
const installingDownload = downloadCLI || Boolean(fixtureDownloadExecutable);
assert(!(downloadCLI && fixtureDownloadExecutable), 'Choose an official download or a local HTTPS replay.');
assert(!installingDownload || !updatedExecutable, 'A fresh download and a two-version update simulation are distinct acceptance modes.');
const baselineCLIIndex = process.argv.indexOf('--baseline-cli');
const baselineExecutable = baselineCLIIndex < 0 ? path.join(os.homedir(), '.local/share/claude/versions/2.1.296') : process.argv[baselineCLIIndex + 1];
const packagedIndex = process.argv.indexOf('--packaged');
const packagedApplication = packagedIndex < 0 ? null : process.argv[packagedIndex + 1];
if (packagedIndex >= 0 && (!packagedApplication || !path.isAbsolute(packagedApplication) || !packagedApplication.endsWith('.app'))) throw new Error('--packaged requires an absolute macOS .app path.');
const browserIndex = process.argv.indexOf('--browser');
const browserExecutable = browserIndex < 0 ? null : process.argv[browserIndex + 1];
if (browserIndex >= 0) assert(browserExecutable && path.isAbsolute(browserExecutable), '--browser requires an absolute existing Chromium 145 executable.');
const packageResources = packagedApplication ? path.join(packagedApplication, 'Contents/Resources') : null;
if (packageResources) assert.equal(await realpath(process.resourcesPath), await realpath(packageResources), 'Use this packaged application\'s own executable with ELECTRON_RUN_AS_NODE=1.');
const moduleRoot = packageResources ? path.join(packageResources, 'app.asar') : root;
const moduleURL = filename => pathToFileURL(path.join(moduleRoot, 'electron', filename)).href;
const require = createRequire(moduleURL('terminal-service.mjs'));
const [ { SidecarManager }, { BrowseForgeService }, { ProxyNetworkProbe }, { TerminalService }, { TerminalBrowserBroker }, { TerminalLinkChannel } ] = await Promise.all([
  import(moduleURL('sidecar-manager.mjs')), import(moduleURL('browseforge-service.mjs')), import(moduleURL('proxy-network.mjs')),
  import(moduleURL('terminal-service.mjs')), import(moduleURL('terminal-browser-broker.mjs')), import(moduleURL('terminal-link-channel.mjs')),
]);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const waitFor = async (predicate, message, timeout = 15000) => {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { const result = await predicate(); if (result) return result; await sleep(75); }
  throw new Error(message);
};
const artifactRoot = path.join(root, 'build/local-verification/claude-terminal');
await mkdir(artifactRoot, { recursive: true, mode: 0o700 });
const runDir = await realpath(await mkdtemp(path.join(artifactRoot, 'run-')));
const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-claude-check-')));
const dataDir = path.join(temporary, 'data'), workingDirectory = path.join(temporary, 'workspace');
await mkdir(workingDirectory, { mode: 0o700 });
const resourcesDir = packageResources ? path.join(packageResources, 'backend') : path.join(root, 'build/backend');
const nodeExecutable = path.join(resourcesDir, 'playwright-driver/node');
const proof = { passed: false, platform: `${process.platform}-${process.arch}`, runDir, moduleRoot, packagedApplication, checks: [], limitations: [
  'Authenticated fixture routes prove selection and refusal; they are not a public-IP or AnyTLS measurement. Only --download-cli permits route A to forward the official host through an explicit external leg; --fixture-download-cli stays entirely local.',
  'An isolated shell invokes Claude only after an explicit terminal command, using a fresh environment configuration. No user login, account, inference, or model-directed tool choice is tested.',
  'Route-loss acceptance injects the owned-core failure notification against a managed local proxy fixture. It does not crash or validate a real AnyTLS core.',
  'Device-read acceptance covers the named IOKit serial/UUID, gethostuuid and kern.uuid surfaces only. Model, memory, CPU count, hostname and boot-session UUID remain available; no replacement identity or full hardware isolation is claimed.',
  packageResources ? 'This exercises archived packaged modules, bundled Node/sidecar and the real native PTY; it does not exercise renderer selection UI.' : 'This exercises the current source and real native dependencies; a separate packaged-app check is required after building.',
] };
const check = message => { proof.checks.push(message); console.log(`PASS ${message}`); };
let manager, service, terminal, routeTerminal, broker, linkChannel, mcp, browserBinding, updateVerification, downloadFixture;
const fixtures = [], children = new Set(), launchedPids = new Set(), launches = [], output = new Map();
const installerCalls = [];
let downloadedExecutable = null;
const downloadRequestId = `verify_download_${randomBytes(8).toString('hex')}`;
const installationProgress = [];
const fixtureExecutableResolver = async () => {
  if (downloadedExecutable ?? fixtureDownloadExecutable) return downloadedExecutable ?? fixtureDownloadExecutable;
  throw Object.assign(new Error('The first-install fixture has no host Claude installation.'), { code: 'CLAUDE_CODE_NOT_INSTALLED' });
};
const receiveEvent = event => {
  if (event.type === 'data') output.set(event.sessionId, (output.get(event.sessionId) ?? '') + event.data);
  if (installingDownload && event.requestId === downloadRequestId && event.claudeInstall) {
    const progress = { ...event.claudeInstall, ptyCount: launches.length };
    const previous = installationProgress.at(-1);
    installationProgress.push(progress);
    if (!previous || previous.phase !== progress.phase) console.log(`Claude first install: ${progress.phase}`);
  }
};
const fileHash = async filename => { const hash = createHash('sha256'); for await (const chunk of createReadStream(filename)) hash.update(chunk); return hash.digest('hex'); };
// A CLI may restore its cursor immediately before the shell prints our marker.
// Compare rendered text while retaining the raw terminal output for diagnostics.
const terminalText = sessionId => stripVTControlCharacters(output.get(sessionId) ?? '');
const shellWord = value => `'${value.replaceAll("'", "'\\''")}'`;
const booleanOnly = value => typeof value === 'boolean' || value && typeof value === 'object' && !Array.isArray(value) && Object.values(value).every(booleanOnly);
const deviceProbeSource = path.join(root, 'scripts/fixtures/terminal-device-identifier-probe.c');
async function compileDeviceProbe() {
  const binary = path.join(temporary, 'device-identifier-probe');
  await execute('/usr/bin/xcrun', ['clang', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', deviceProbeSource,
    '-framework', 'IOKit', '-framework', 'CoreFoundation', '-o', binary], { timeout: 30000, maxBuffer: 16384 });
  return binary;
}
function parseDeviceProbe(text) {
  let result;
  try { result = JSON.parse(text); } catch { throw new Error('The owned device probe did not return its boolean JSON report.'); }
  assert.equal(booleanOnly(result), true, 'Device probe output must contain booleans only, never hardware values.');
  return result;
}
function assertDeviceReads(control, restricted, descendant) {
  assert.equal(control.platformEntryPresent, true); assert.equal(control.registryRootPresent, true);
  for (const surface of ['single', 'searchDirect', 'searchRecursive', 'bytes']) for (const key of ['serial', 'uuid']) {
    assert.equal(control[surface][key].present, true, `${surface}.${key} requires an observable control.`);
    assert.equal(restricted[surface][key].present, false, `${surface}.${key} must not return an identifier.`);
  }
  for (const key of ['serial', 'uuid']) assert.equal(restricted.bytes[key].denied, true);
  assert.equal(control.batch.serialPresent, true); assert.equal(control.batch.uuidPresent, true);
  assert.equal(restricted.batch.present, true); assert.equal(restricted.batch.serialPresent, false); assert.equal(restricted.batch.uuidPresent, false);
  assert.equal(restricted.batch.modelPresent, true); assert.equal(restricted.single.model.present, true);
  for (const method of ['library', 'syscall']) {
    assert.equal(control.hostUuid[method].present, true);
    assert.deepEqual(restricted.hostUuid[method], { present: false, denied: true });
  }
  for (const method of ['byName', 'numericMib']) {
    assert.equal(control.sysctl['kern.uuid'][method].present, true);
    assert.deepEqual(restricted.sysctl['kern.uuid'][method], { present: false, denied: true, absent: false });
  }
  for (const key of ['hw.model', 'hw.memsize', 'hw.logicalcpu', 'kern.hostname', 'kern.bootsessionuuid'])
    for (const method of ['byName', 'numericMib']) assert.equal(restricted.sysctl[key][method].present, true, `${key} remains available.`);
  assert.deepEqual(descendant, restricted, 'The real PTY shell and an additional /bin/sh descendant must enforce the same named read restrictions.');
}
async function assertRealDeviceReads(owner, session, binary) {
  assert.equal(owner.metadata(owner.sessions.get(session.sessionId)).deviceIdentifierRestrictions, true);
  const control = parseDeviceProbe((await execute(binary, [], { timeout: 10000, maxBuffer: 16384,
    env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' } })).stdout);
  const begin = `ENVARA_DEVICE_${randomBytes(8).toString('hex')}`, middle = `${begin}_CHILD`, end = `${begin}_END`;
  await owner.write({ sessionId: session.sessionId, data: `printf '%s\\n' '${begin}'; ${shellWord(binary)}; printf '%s\\n' '${middle}'; /bin/sh -c '"$1"' envara-owned-identifier-child ${shellWord(binary)}; printf '%s\\n' '${end}'\r` });
  await waitFor(() => new RegExp(`(?:^|[\\r\\n])${end}[\\r\\n]`).test(terminalText(session.sessionId)), 'The real PTY device-read probe did not complete.');
  const between = (start, finish) => {
    const body = terminalText(session.sessionId).match(new RegExp(`(?:^|[\\r\\n])${start}\\r?\\n([^]*?)\\r?\\n${finish}(?:\\r?\\n)`))?.[1];
    assert(body, 'The device probe result must be distinguished from echoed shell input.');
    return parseDeviceProbe(body);
  };
  const restricted = between(begin, middle), descendant = between(middle, end);
  assertDeviceReads(control, restricted, descendant);
  proof.deviceIdentifierRestrictions = { metadataVerified: true, realPtyVerified: true, descendantVerified: true,
    sourceSha256: await fileHash(deviceProbeSource), probeSha256: await fileHash(binary), control, restricted, descendant };
}
const stopChild = async child => {
  if (!child || child.exitCode !== null) return;
  child.stdin?.end();
  child.kill('SIGTERM');
  await Promise.race([new Promise(resolve => child.once('exit', resolve)), sleep(3000)]);
  if (child.exitCode === null) child.kill('SIGKILL');
};
const listen = server => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
async function fixtureRoute(label, ip, certificate) {
  const sockets = new Set(), stats = { authenticated: 0, browserRequests: 0, geoRequests: 0, refusedExternal: 0 };
  let pauseExternal = false;
  const username = `route-${label}`, password = randomBytes(18).toString('hex');
  const expected = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
  const geo = https.createServer(certificate, (_request, response) => {
    stats.geoRequests++;
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ success: true, ip, country_code: 'PH', country: 'Philippines', region: 'Metro Manila', city: 'Offline fixture', latitude: 14.6, longitude: 121, timezone: { id: 'Asia/Manila' } }));
  });
  const page = `<!doctype html><meta charset="utf-8"><title>Envara route ${label}</title><h1 id="route">Route ${label}</h1><label>Message <input id="message"></label><button id="apply" onclick="document.querySelector('#result').textContent=document.querySelector('#message').value">Apply</button><p id="result">empty</p><select id="select"><option value="one">One</option><option value="two">Two</option></select><input type="checkbox" id="check"><script>document.querySelector('#message').addEventListener('keydown',e=>{if(e.key==='Enter')document.querySelector('#apply').click()})</script>`;
  const proxy = http.createServer((request, response) => {
    if (request.headers['proxy-authorization'] !== expected) { response.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="Envara verification"' }); response.end(); return; }
    stats.authenticated++;
    let url; try { url = new URL(request.url); } catch {}
    if (url?.hostname !== 'browser.envara.invalid') { stats.refusedExternal++; response.writeHead(502); response.end('Offline verification only'); return; }
    stats.browserRequests++;
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); response.end(page);
  });
  proxy.on('connect', (request, socket, head) => {
    if (request.headers['proxy-authorization'] !== expected) { socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Envara verification"\r\n\r\n'); return; }
    stats.authenticated++;
    if (label === 'A' && downloadFixture?.forward(request, socket, head, stats)) return;
    if (downloadCLI && label === 'A' && forwardOfficialClaudeDownload(request, socket, head, { stats, sockets })) return;
    if (request.url !== 'geo.envara.invalid:443') {
      stats.refusedExternal++;
      // In the route-loss check only, keep the manually invoked real CLI's initial connectivity
      // probe waiting so the notification, rather than a synthetic API failure,
      // is what terminates it. This never forwards traffic to a real provider.
      if (!pauseExternal) socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
      return;
    }
    const upstream = net.connect(geo.address().port, '127.0.0.1'); sockets.add(upstream); upstream.on('close', () => sockets.delete(upstream));
    upstream.on('error', () => socket.destroy()); socket.on('error', () => upstream.destroy());
    upstream.once('connect', () => { socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); if (head.length) upstream.write(head); socket.pipe(upstream); upstream.pipe(socket); });
    socket.on('close', () => upstream.destroy());
  });
  for (const server of [geo, proxy]) server.on('connection', socket => { sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket)); });
  await listen(geo); await listen(proxy);
  const fixture = { label, stats, proxy: { name: `Offline route ${label}`, protocol: 'http', host: '127.0.0.1', port: proxy.address().port, username, password },
    pauseExternal: value => { pauseExternal = value; },
    close: async () => { for (const socket of sockets) socket.destroy(); await Promise.all([geo, proxy].map(server => new Promise(resolve => server.close(resolve)))); } };
  fixtures.push(fixture); return fixture;
}
function stdioRpc(child) {
  let sequence = 0, buffer = ''; const pending = new Map();
  child.stdout.setEncoding('utf8'); child.stdout.on('data', chunk => {
    buffer += chunk; let newline;
    while ((newline = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, newline); buffer = buffer.slice(newline + 1); if (!line.trim()) continue;
      let message; try { message = JSON.parse(line); } catch { continue; }
      const item = pending.get(message.id); if (item) { pending.delete(message.id); clearTimeout(item.timer); item.resolve(message); }
    }
  });
  child.once('exit', () => { for (const item of pending.values()) { clearTimeout(item.timer); item.reject(new Error('MCP process exited')); } pending.clear(); });
  return async (method, params = {}) => {
    const id = ++sequence;
    const response = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(id); reject(new Error(`MCP ${method} timed out`)); }, 75000);
      pending.set(id, { resolve, reject, timer }); child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    });
    if (response.error) throw new Error(response.error.message);
    return response.result;
  };
}
const preparation = (owner, sessionId) => {
  const prepared = owner.sessions.get(sessionId)?.claudeLaunch;
  assert(prepared?.executable && Array.isArray(prepared.args), 'A dedicated shell must retain its fixed Claude launch configuration.');
  return prepared;
};
async function ownedProcessFamily(parent) {
  const { stdout } = await execute('/bin/ps', ['-axo', 'pid=,ppid=,comm='], { timeout: 5000, maxBuffer: 4 * 1024 * 1024 });
  const rows = stdout.split('\n').map(line => /^\s*(\d+)\s+(\d+)\s+(.+)$/.exec(line)).filter(Boolean)
    .map(([, pid, ppid, executable]) => ({ pid: Number(pid), ppid: Number(ppid), executable }));
  const owned = new Set([parent]); let added;
  do { added = false; for (const row of rows) if (owned.has(row.ppid) && !owned.has(row.pid)) { owned.add(row.pid); added = true; } } while (added);
  return rows.filter(row => owned.has(row.pid));
}
const cliProcesses = async (launch, cli) => {
  // A running session can atomically update its entry to a new native version.
  // Match the owned installation directory rather than only its first binary.
  const versionsPrefix = cli.includes('/claude/versions/') ? path.dirname(cli) + path.sep : null;
  return (await ownedProcessFamily(launch.pid)).filter(row => row.executable === cli || (versionsPrefix && row.executable.startsWith(versionsPrefix)) || /(?:^|\/)claude$/.test(row.executable));
};
async function assertIdleClaudeShell(owner, session, launch) {
  assert.equal(launch.executable, '/usr/bin/sandbox-exec');
  assert.match(launch.args[2], /\/(?:zsh|bash|sh)$/);
  await waitFor(() => /envara[^\r\n]*[%#$]/.test(terminalText(session.sessionId)), 'The isolated shell did not show its prompt.');
  assert.doesNotMatch(terminalText(session.sessionId), /Welcome[\s\S]*Claude|Claude[\s\S]*Code[\s\S]*v\d/);
  assert.equal((await cliProcesses(launch, preparation(owner, session.sessionId).executable)).length, 0, 'Creating a dedicated session must not automatically start Claude.');
  assert.equal(owner.metadata(owner.sessions.get(session.sessionId)).status, 'running');
  assert.equal(owner.metadata(owner.sessions.get(session.sessionId)).deviceIdentifierRestrictions, true, 'Every dedicated Claude session must retain the verified read-restriction metadata.');
}
async function assertRealProcessLocale(owner, session, launch, requested, expectedFallback) {
  const language = owner.metadata(owner.sessions.get(session.sessionId)).language;
  assert.equal(language.requested, requested);
  assert.equal(language.fallback, expectedFallback);
  assert.equal(launch.options.env.LANG, language.posix);
  assert.equal(launch.options.env.LC_ALL, language.posix);
  assert(owner.availableLocales.includes(language.posix), 'The selected POSIX locale must exist on this host.');
  const marker = `ENVARA_LOCALE_${randomBytes(6).toString('hex')}`;
  const end = `${marker}_END`;
  const unicode = '境舱中文🙂';
  await owner.write({ sessionId: session.sessionId, data: `printf '%s\\n' '${marker}'; /usr/bin/locale charmap; printf '%s\\n' "$LANG" "$LC_ALL" '${unicode}' '${end}'\r` });
  await waitFor(() => new RegExp(`(?:^|[\\r\\n])${end}[\\r\\n]`).test(terminalText(session.sessionId)), 'The real PTY locale check did not complete.');
  const body = terminalText(session.sessionId).match(new RegExp(`(?:^|[\\r\\n])${marker}\\r?\\n([^]*?)\\r?\\n${end}(?:\\r?\\n)`))?.[1];
  assert(body, 'The actual command result must be distinguished from echoed shell input.');
  const lines = body.split(/\r?\n/);
  assert.deepEqual(lines, ['UTF-8', language.posix, language.posix, unicode]);
  (proof.processLocales ??= []).push({ requested, effective: language.effective, posix: language.posix, fallback: language.fallback, charmap: lines[0], unicodeRoundTrip: lines[3] === unicode });
}
async function assertAccountPolicy(launch, prepared, privacyMode, fixtureSecrets) {
  const settingsPath = prepared.args[prepared.args.indexOf('--settings') + 1];
  const settingsText = await readFile(settingsPath, 'utf8'), settings = JSON.parse(settingsText);
  assert.equal(settings.forceLoginMethod, 'claudeai');
  assert.equal(settings.sandbox.enabled, false);
  for (const flag of ['--no-chrome', '--strict-mcp-config']) assert(prepared.args.includes(flag));
  for (const flag of ['--permission-mode', '--dangerously-skip-permissions', '--allow-dangerously-skip-permissions']) assert(!prepared.args.includes(flag), 'The dedicated shell must not enable a permission bypass by default.');
  assert.equal(prepared.args[prepared.args.indexOf('--setting-sources') + 1], 'user');
  assert.equal(launch.options.env.DISABLE_AUTOUPDATER, '1');
  assert.equal(launch.options.env.ANTHROPIC_API_KEY, undefined);
  assert.equal(launch.options.env.ANTHROPIC_AUTH_TOKEN, undefined);
  assert.equal(launch.options.env.CLAUDE_CODE_USE_BEDROCK, undefined);
  assert.equal(launch.options.env.CLAUDE_CODE_USE_VERTEX, undefined);
  assert.equal(launch.options.env.CLAUDE_CODE_USE_FOUNDRY, undefined);
  for (const name of ['DO_NOT_TRACK', 'DISABLE_TELEMETRY', 'DISABLE_ERROR_REPORTING']) assert.equal(launch.options.env[name], privacyMode === 'off' ? '' : '1');
  assert.equal(launch.options.env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC, privacyMode === 'strict' ? '1' : '');
  for (const secret of [...fixtureSecrets, launch.options.env.ENVARA_BROWSER_TOKEN, launch.options.env.ENVARA_LINK_TOKEN]) if (secret) assert(!settingsText.includes(secret), 'Session settings must contain no route or browser-channel credential.');
  assert.equal((await stat(settingsPath)).mode & 0o777, 0o600);
}
try {
  assert.equal(process.platform, 'darwin', 'This real acceptance harness requires macOS.');
  assert(process.versions.electron && process.env.ELECTRON_RUN_AS_NODE === '1', 'Run in Electron as documented to load the production PTY binding.');
  await access(nodeExecutable);
  proof.version = JSON.parse(await readFile(path.join(moduleRoot, 'package.json'), 'utf8')).version;
  proof.moduleHashes = Object.fromEntries(await Promise.all(['terminal-service.mjs', 'terminal-network-fence.mjs', 'terminal-browser-broker.mjs', 'terminal-browser-mcp.mjs', 'claude-code-session.mjs', 'claude-code-installation.mjs', 'claude-code-download.mjs', 'claude-account-store.mjs'].map(async filename => [filename, createHash('sha256').update(await readFile(path.join(moduleRoot, 'electron', filename))).digest('hex')])));
  proof.sidecarSha256 = createHash('sha256').update(await readFile(path.join(resourcesDir, 'BrowseForge-sidecar'))).digest('hex');
  const deviceProbe = await compileDeviceProbe();
  const { ensureClaudeInstallation, claudeInstallationStatus } = await import(moduleURL('claude-code-installation.mjs'));
  const { createClaudeNativeDownloader, downloadClaudeNative } = await import(moduleURL('claude-code-download.mjs'));
  if (fixtureDownloadExecutable) {
    downloadFixture = await createClaudeDownloadFixture({ executable: fixtureDownloadExecutable, temporary });
    proof.limitations.push('This run replays the previously downloaded official native binary through a local HTTPS fixture and the production downloader. No new public download or real account authentication is performed.');
  }
  const downloader = downloadFixture ? createClaudeNativeDownloader(downloadFixture.downloadOptions) : downloadClaudeNative;
  const installer = async options => {
    const call = { source: options.source, hostCalls: 0, downloadCalls: 0 }; installerCalls.push(call);
    return ensureClaudeInstallation({ ...options,
      findHostExecutable: async () => { call.hostCalls++; return options.findHostExecutable(); },
      downloadNative: async args => { call.downloadCalls++; return downloader(args); },
    });
  };
  const opensslConfig = path.join(temporary, 'certificate.cnf');
  await writeFile(opensslConfig, '[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=geo.envara.invalid\n[v3]\nsubjectAltName=DNS:geo.envara.invalid\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n');
  await execute('/usr/bin/openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-config', opensslConfig, '-keyout', path.join(temporary, 'key.pem'), '-out', path.join(temporary, 'cert.pem')], { timeout: 15000 });
  const certificate = { key: await readFile(path.join(temporary, 'key.pem')), cert: await readFile(path.join(temporary, 'cert.pem')) };
  const a = await fixtureRoute('A', '45.1.2.3', certificate), b = await fixtureRoute('B', '45.2.3.4', certificate);
  let legacyCacheDir = path.join(root, 'test-artifacts/engine-cache');
  if (browserExecutable) {
    await access(browserExecutable, constants.X_OK);
    assert.equal(await realpath(browserExecutable), browserExecutable, 'The explicitly reused browser executable must be canonical.');
    for (let index = 0, parent = browserExecutable; index < 5; index++) { parent = path.dirname(parent); legacyCacheDir = parent; }
    assert.match(path.relative(legacyCacheDir, browserExecutable), /^chromium-145(?:\.\d+){1,5}\/Chromium\.app\/Contents\/MacOS\/Chromium$/, 'Only an existing Chromium 145 cache layout may be reused.');
  }
  manager = new SidecarManager({ dataDir, resourcesDir, legacyCacheDir });
  await manager.initialize();
  assert.equal(manager.getEngineStates().cloakbrowser.installed, true, 'The existing test CloakBrowser cache is required.');
  if (browserExecutable) {
    const engine = manager.getEngineStates().cloakbrowser;
    assert.equal(await realpath(engine.binaryPath), browserExecutable, 'The manager must use exactly the explicitly reused browser, without an install or download.');
    assert.match(engine.version, /^145\./);
    proof.browserReuse = { existingOnly: true, downloaded: false, version: engine.version, sha256: await fileHash(browserExecutable) };
  }
  const networkProbe = new ProxyNetworkProbe({ endpoints: [{ url: 'https://geo.envara.invalid/', source: 'offline-authenticated-fixture', format: 'ipwho' }], tlsOptions: { ca: certificate.cert }, cacheTtlMs: 600000 });
  service = new BrowseForgeService(dataDir, manager.client, { appVersion: '0.5.0-verification' }, () => {}, {
    profilesDir: path.join(manager.baseDir, 'profiles'), networkProbe, getEngineStates: () => manager.getEngineStates(), shutdown: () => manager.shutdown(),
  });
  const profiles = [];
  for (const fixture of [a, b]) {
    const saved = await service.call('saveProxy', { proxy: fixture.proxy });
    const proxyId = saved.proxies.find(item => item.name === fixture.proxy.name).id;
    const created = await service.call('createProfile', { profile: { name: `Claude verification ${fixture.label}`, engine: 'cloakbrowser', proxyId, timezone: 'Asia/Manila', locale: fixture.label === 'A' ? 'en-PH' : 'ms-MY', startUrl: 'about:blank' } });
    profiles.push(created.profiles.find(item => item.id === created.actionResult.createdId));
  }
  const [selected, other] = profiles;
  broker = new TerminalBrowserBroker({ service, dataDir, nodeExecutable });
  linkChannel = new TerminalLinkChannel({ root: dataDir, onLink: () => { throw new Error('Claude must not call the ordinary mutable browser route.'); } });
  await linkChannel.listen();
  terminal = new TerminalService({ dataDir, browserBroker: broker, linkChannel, additionalExecutablePaths: [path.dirname(nodeExecutable)],
    resolveContext: id => service.resolveWorkspaceContext(id),
    claudeInstaller: installer,
    ...(installingDownload ? { claudeExecutableResolver: fixtureExecutableResolver } : {}),
    ptyFactory: (executable, args, options) => { const pty = require('node-pty').spawn(executable, args, options); launches.push({ executable, args: [...args], options, pid: pty.pid }); launchedPids.add(pty.pid); return pty; },
    onEvent: receiveEvent,
  });
  await terminal.ready;
  assert.deepEqual(await terminal.claudeInstallationStatus({ id: selected.id }), { installed: false });
  await assert.rejects(access(path.join(terminal.profilesDir, selected.id)), { code: 'ENOENT' });
  assert.equal(installerCalls.length, 0);
  const originalDirectories = await terminal.directories(selected.id);
  const preexistingMarkerPath = path.join(originalDirectories.claude, 'envara-preexisting-configuration-fixture.json');
  const preexistingMarker = JSON.stringify({ synthetic: true, purpose: 'legacy-default-account-preservation', marker: randomBytes(12).toString('hex') });
  await writeFile(preexistingMarkerPath, preexistingMarker, { mode: 0o600 });
  const created = await terminal.create({ id: selected.id, directory: workingDirectory, kind: 'claude-code', browserProfileId: selected.id, claudeInstallSource: installingDownload ? 'download' : 'local', fresh: true, columns: 110, rows: 30, ...(installingDownload ? { requestId: downloadRequestId } : {}) });
  assert.equal(created.kind, 'claude-code'); assert.equal(created.networkFence, true); assert.equal(created.browserProfileId, selected.id);
  assert.equal(created.deviceIdentifierRestrictions, true);
  const launch = launches.at(-1);
  const prepared = preparation(terminal, created.sessionId);
  const cli = prepared.executable; assert.match(cli, /claude/);
  assert.equal(await readFile(preexistingMarkerPath, 'utf8'), preexistingMarker);
  assert.equal(launch.options.env.CLAUDE_CONFIG_DIR, originalDirectories.claude);
  if (installingDownload) {
    downloadedExecutable = cli;
    assert.equal(b.stats.officialTLSConnections ?? 0, 0);
    assert.equal(b.stats.installerTLSConnections ?? 0, 0);
    assert.equal(downloadCLI ? a.stats.officialTLSConnections : a.stats.installerTLSConnections, 3);
    assert.deepEqual(installerCalls[0], { source: 'download', hostCalls: 0, downloadCalls: 1 });
    for (const phase of ['metadata', 'downloading', 'verifying', 'installing']) assert(installationProgress.some(item => item.phase === phase), `Missing ${phase} progress.`);
    assert(installationProgress.every(item => item.ptyCount === 0), 'The installer must finish before its real PTY is spawned.');
    const completed = installationProgress.findLast(item => item.phase === 'verifying');
    assert(completed.receivedBytes > 0 && completed.receivedBytes === completed.totalBytes);
    const checksum = await fileHash(cli);
    let retainedExecutable = fixtureDownloadExecutable;
    if (downloadCLI) {
      const retained = path.join(runDir, 'official-cli'); await mkdir(retained, { mode: 0o700 });
      retainedExecutable = path.join(retained, path.basename(cli));
      await copyFile(cli, retainedExecutable, constants.COPYFILE_EXCL | constants.COPYFILE_FICLONE);
    } else assert.equal(checksum, downloadFixture.checksum);
    proof[downloadCLI ? 'officialDownload' : 'fixtureDownload'] = {
      mode: downloadCLI ? 'real-official-HTTPS-via-authenticated-selected-fixture' : 'production-downloader-local-HTTPS-replay-of-verified-binary',
      version: path.basename(cli), checksum, size: (await stat(cli)).size, source: 'download', hostResolverCalls: 0, availableFixtureHostIgnored: Boolean(fixtureDownloadExecutable),
      missingHostInstallation: downloadCLI, route: 'A', selectedRouteTLSConnections: 3, publicDownloadThisRun: downloadCLI,
      upstreamMode: a.stats.officialUpstreamMode ?? 'local-HTTPS-no-external-leg', otherRouteDownloadConnections: 0, ptySpawnedAfterInstallation: true,
      originalDefaultConfigurationPreserved: true, retainedExecutable, progress: installationProgress };
    check(downloadCLI
      ? 'With no host CLI, the packaged installer downloads the real official native binary through selected authenticated route A, validates SHA-256 and its Apple signature, preserves the original default config and starts the PTY only after installation.'
      : 'Explicit download mode ignores the available host fixture and transfers the previously verified native binary through selected authenticated route A and local HTTPS; the packaged production downloader validates SHA-256 and Apple signature before PTY startup.');
    await verifyInstallerCancelRetry({ ensureClaudeInstallation, createClaudeNativeDownloader, executable: cli, temporary, proof, check });
  }
  const { verifyClaudeInstallSource } = await import('./verify-claude-install-source.mjs');
  await verifyClaudeInstallSource({ ensureClaudeInstallation, claudeInstallationStatus, executable: cli, temporary, proof, check });
  const configPath = prepared.args[prepared.args.indexOf('--mcp-config') + 1];
  const launchConfiguration = await readFile(configPath, 'utf8');
  assert.equal(Object.hasOwn(JSON.parse(launchConfiguration).mcpServers.envara_browser, 'env'), false);
  assert(!launchConfiguration.includes(launch.options.env.ENVARA_BROWSER_TOKEN));
  assert.equal((await stat(configPath)).mode & 0o777, 0o600);
  assert(launch.options.env.CLAUDE_CONFIG_DIR.startsWith(dataDir + path.sep));
  assert.notEqual(launch.options.env.HOME, os.homedir());
  assert.equal(launch.options.env.ANTHROPIC_API_KEY, undefined);
  await assertAccountPolicy(launch, prepared, 'standard', [a.proxy.password, b.proxy.password]);
  await assertIdleClaudeShell(terminal, created, launch);
  await assertRealDeviceReads(terminal, created, deviceProbe);
  check(`The real ${packageResources ? 'packaged ' : ''}Claude PTY reports device-read restrictions, refuses the named serial/UUID surfaces in an owned native probe and its shell descendant, and preserves ordinary hardware queries; only booleans are recorded.`);
  assert.equal(launch.options.env.PATH.split(path.delimiter)[0], prepared.binDirectory);
  assert.equal(await realpath(path.join(prepared.binDirectory, 'claude')), await realpath(prepared.wrapperPath));
  check('Creating the dedicated session starts a real isolated shell under Seatbelt, shows its prompt, and does not start a Claude process or display Claude onboarding.');
  const { verifyClaudeAccounts } = await import('./verify-claude-accounts.mjs');
  await verifyClaudeAccounts({ terminal, selected, other, created, launches, workingDirectory, preparation, assertIdleClaudeShell, proof, check });
  await assertRealProcessLocale(terminal, created, launch, 'en-PH', false);
  const versionMarker = `ENVARA_CLAUDE_VERSION_RETURNED_${randomBytes(8).toString('hex')}`;
  await terminal.write({ sessionId: created.sessionId, data: `claude --version; printf '%s\\n' '${versionMarker}'\r` });
  await waitFor(() => new RegExp(`(?:^|[\\r\\n])${versionMarker}[\\r\\n]`).test(terminalText(created.sessionId)), 'claude --version did not return to the isolated shell.');
  const versionMatch = terminalText(created.sessionId).match(/\b(\d+\.\d+\.\d+)\s+\(Claude Code\)/);
  assert(versionMatch, 'The real locally installed Claude must print its version.');
  proof.claudeVersion = `${versionMatch[1]} (Claude Code)`;
  assert.equal(terminal.metadata(terminal.sessions.get(created.sessionId)).status, 'running');
  assert.equal((await cliProcesses(launch, cli)).length, 0);
  const permissionMarker = `ENVARA_CLAUDE_PERMISSION_RETURNED_${randomBytes(8).toString('hex')}`;
  await terminal.write({ sessionId: created.sessionId, data: `claude --permission-mode bypassPermissions --version; printf '%s\\n' '${permissionMarker}'\r` });
  await waitFor(() => new RegExp(`(?:^|[\\r\\n])${permissionMarker}[\\r\\n]`).test(terminalText(created.sessionId)), 'An explicitly supplied Claude permission mode was not accepted by the wrapper.');
  assert(terminalText(created.sessionId).match(/\b\d+\.\d+\.\d+\s+\(Claude Code\)/g)?.length >= 2);
  check('User-entered claude --version runs the installed local CLI and returns to the same shell; an explicit --permission-mode bypassPermissions is accepted without enabling it by default.');
  if (updatedExecutable) {
    const { verifyClaudeUpdate } = await import('./verify-claude-update.mjs');
    updateVerification = await verifyClaudeUpdate({ updatedExecutable, hostExecutable: baselineExecutable, terminal, selected, other, created, workingDirectory, launches, output, waitFor, preparation, proof, check });
  }
  const beforeClaude = output.get(created.sessionId)?.length ?? 0;
  await terminal.write({ sessionId: created.sessionId, data: 'claude\r' });
  await waitFor(() => /Welcome|欢迎/.test(stripVTControlCharacters((output.get(created.sessionId) ?? '').slice(beforeClaude))), 'Typing claude did not show the genuine CLI welcome screen.', 30000);
  // The offline proxy refuses the real startup connectivity probe. That CLI
  // child must return to the shell rather than end the terminal or its binding.
  await waitFor(async () => (await cliProcesses(launch, cli)).length === 0, 'The offline CLI did not exit back to its shell.', 30000);
  const returnedMarker = `ENVARA_CLAUDE_SHELL_RETURNED_${randomBytes(8).toString('hex')}`;
  await terminal.write({ sessionId: created.sessionId, data: `printf '%s\\n' '${returnedMarker}'\r` });
  await waitFor(() => new RegExp(`(?:^|[\\r\\n])${returnedMarker}[\\r\\n]`).test(terminalText(created.sessionId)), 'The shell did not remain usable after Claude exited.');
  assert.equal(terminal.metadata(terminal.sessions.get(created.sessionId)).status, 'running');
  await access(configPath);
  check('Only the explicit claude command opens the real CLI; after its offline connection refusal the same shell, configuration and bound-browser capability remain available.');
  const duplicate = await terminal.duplicate({ sessionId: created.sessionId });
  const duplicateLaunch = launches.at(-1);
  assert.equal(duplicate.kind, 'claude-code'); assert.equal(duplicate.browserProfileId, selected.id);
  assert.notEqual(duplicateLaunch.pid, launch.pid);
  assert.equal(duplicateLaunch.options.env.CLAUDE_CONFIG_DIR, launch.options.env.CLAUDE_CONFIG_DIR);
  assert.notEqual(duplicateLaunch.options.env.ENVARA_BROWSER_TOKEN, launch.options.env.ENVARA_BROWSER_TOKEN);
  await assertIdleClaudeShell(terminal, duplicate, duplicateLaunch);
  await terminal.close({ sessionId: duplicate.sessionId });
  const otherSession = await terminal.create({ id: other.id, directory: workingDirectory, kind: 'claude-code', browserProfileId: other.id, claudeInstallSource: 'local', fresh: true });
  assert.notEqual(launches.at(-1).options.env.CLAUDE_CONFIG_DIR, launch.options.env.CLAUDE_CONFIG_DIR);
  await assertRealProcessLocale(terminal, otherSession, launches.at(-1), 'ms-MY', true);
  assert.equal(proof.processLocales.at(-1).effective, 'en-US');
  check('Real PTY libc reports UTF-8, LANG/LC_ALL match an installed requested locale or the disclosed en-US fallback, and non-ASCII text survives output intact.');
  await terminal.close({ sessionId: otherSession.sessionId });
  check('Duplicate creates an independent idle shell and revocable browser token in the same environment without replaying claude; another environment uses a different Claude configuration directory.');
  const terminalPage = await execute(launch.executable, ['-p', launch.args[1], '/usr/bin/curl', '--fail', '--silent', '--max-time', '5', 'http://browser.envara.invalid/terminal'], { cwd: workingDirectory, env: launch.options.env, timeout: 10000 });
  assert.match(terminalPage.stdout, /Route A/);
  assert.equal(b.stats.browserRequests, 0);
  check('A real proxy-aware CLI child with the Claude session environment reaches the authenticated selected route A.');
  for (const mode of ['off', 'strict']) {
    await service.call('updateProfile', { id: other.id, profile: { privacy: { mode } } });
    const policySession = await terminal.create({ id: other.id, directory: workingDirectory, kind: 'claude-code', browserProfileId: other.id, claudeInstallSource: 'local', fresh: true });
    try { await assertAccountPolicy(launches.at(-1), preparation(terminal, policySession.sessionId), mode, [a.proxy.password, b.proxy.password]); }
    finally { await terminal.close({ sessionId: policySession.sessionId }); }
  }
  await service.call('updateProfile', { id: other.id, profile: { privacy: { mode: 'standard' } } });
  check('Real CLI launch policies select Claude account login, disable automatic updates, preserve off/standard/strict privacy choices, and store no proxy or browser-token credentials in settings.');

  const configDirectory = (await terminal.directories(other.id)).claude;
  const userSettingsPath = path.join(configDirectory, 'settings.json');
  const syntheticSecret = 'sk-ant-envara-offline-acceptance-not-a-real-key';
  const savedSettings = `${JSON.stringify({ env: { ANTHROPIC_API_KEY: syntheticSecret }, theme: 'dark' }, null, 2)}\n`;
  const originalSettings = await readFile(userSettingsPath).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
  await writeFile(userSettingsPath, savedSettings, { mode: 0o600 });
  try {
    const launchCount = launches.length;
    await assert.rejects(terminal.create({ id: other.id, directory: workingDirectory, kind: 'claude-code', browserProfileId: other.id, claudeInstallSource: 'local', fresh: true }), { code: 'CLAUDE_CODE_ACCOUNT_CONFIGURATION_CONFLICT' });
    assert.equal(launches.length, launchCount, 'A conflicting saved API configuration must not spawn a CLI.');
    assert.equal(await readFile(userSettingsPath, 'utf8'), savedSettings, 'Conflict refusal must leave the saved configuration byte-for-byte intact.');
    assert(!JSON.stringify(await terminal.snapshot({ id: other.id })).includes(syntheticSecret), 'Conflict diagnostics must not reveal the synthetic key.');
  } finally { if (originalSettings) await writeFile(userSettingsPath, originalSettings, { mode: 0o600 }); else await rm(userSettingsPath, { force: true }); }
  check('A synthetic API key in the environment settings is refused before a real CLI is launched; saved settings are unchanged and the key is absent from diagnostics.');

  // This narrow test seam marks the two locally owned proxy fixtures as managed
  // so the same lifecycle notification as a real proxy-core exit is exercised.
  // The real PTY, Claude executable, fence, route and broker remain unchanged.
  routeTerminal = new TerminalService({ dataDir: path.join(temporary, 'route-loss-data'), browserBroker: broker, linkChannel, additionalExecutablePaths: [path.dirname(nodeExecutable)],
    claudeInstaller: installer,
    ...(installingDownload ? { claudeExecutableResolver: fixtureExecutableResolver } : {}),
    resolveContext: async id => ({ ...await service.resolveWorkspaceContext(id), managedProxy: true }),
    ptyFactory: (executable, args, options) => { const pty = require('node-pty').spawn(executable, args, options); launches.push({ executable, args: [...args], options, pid: pty.pid }); launchedPids.add(pty.pid); return pty; },
    onEvent: event => { if (event.type === 'data') output.set(event.sessionId, (output.get(event.sessionId) ?? '') + event.data); },
  });
  a.pauseExternal(true); b.pauseExternal(true);
  try {
    const untouched = await routeTerminal.create({ id: other.id, directory: workingDirectory, kind: 'claude-code', browserProfileId: other.id, claudeInstallSource: 'local', fresh: true });
    const untouchedLaunch = launches.at(-1), untouchedPid = untouchedLaunch.pid;
    await assertIdleClaudeShell(routeTerminal, untouched, untouchedLaunch);
    await routeTerminal.write({ sessionId: untouched.sessionId, data: 'claude\r' });
    const untouchedCli = await waitFor(async () => (await cliProcesses(untouchedLaunch, preparation(routeTerminal, untouched.sessionId).executable))[0], 'The other-route shell did not launch Claude.');
    launchedPids.add(untouchedCli.pid);
    const shell = await routeTerminal.create({ id: selected.id, directory: workingDirectory, kind: 'shell', fresh: true });
    const shellPid = launches.at(-1).pid;
    const affected = await routeTerminal.create({ id: selected.id, directory: workingDirectory, kind: 'claude-code', browserProfileId: selected.id, claudeInstallSource: 'local', fresh: true });
    const affectedLaunch = launches.at(-1), affectedPrepared = preparation(routeTerminal, affected.sessionId);
    await assertIdleClaudeShell(routeTerminal, affected, affectedLaunch);
    await routeTerminal.write({ sessionId: affected.sessionId, data: 'claude\r' });
    const affectedCli = await waitFor(async () => (await cliProcesses(affectedLaunch, affectedPrepared.executable))[0], 'The affected-route shell did not launch Claude.');
    launchedPids.add(affectedCli.pid);
    const affectedConfigPath = affectedPrepared.args[affectedPrepared.args.indexOf('--mcp-config') + 1];
    const affectedMcp = JSON.parse(await readFile(affectedConfigPath, 'utf8')).mcpServers.envara_browser;
    const routeChild = spawn(affectedLaunch.executable, ['-p', affectedLaunch.args[1], affectedMcp.command, ...affectedMcp.args], { cwd: workingDirectory, env: affectedLaunch.options.env, stdio: ['pipe', 'pipe', 'pipe'] }); children.add(routeChild);
    const routeRpc = stdioRpc(routeChild);
    await routeRpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'Envara route-loss acceptance', version: '1' } });
    const beforeLoss = await routeRpc('tools/call', { name: 'browser_status', arguments: {} }); assert.notEqual(beforeLoss.isError, true);
    assert.equal(routeTerminal.metadata(routeTerminal.sessions.get(affected.sessionId)).status, 'running');
    assert.equal(alive(affectedLaunch.pid), true);
    const invalidated = await routeTerminal.invalidateManagedProxy(selected.proxyId);
    assert.equal(invalidated.length, 1); assert.equal(invalidated[0].status, 'fulfilled');
    const afterLoss = routeTerminal.metadata(routeTerminal.sessions.get(affected.sessionId));
    assert.equal(afterLoss.status, 'error'); assert.equal(afterLoss.errorCode, 'CLAUDE_NETWORK_ROUTE_LOST'); assert.equal(afterLoss.network.available, false);
    await waitFor(() => !alive(affectedLaunch.pid) && !alive(affectedCli.pid), 'The route-loss notification did not end its real shell and Claude child.');
    await assert.rejects(routeRpc('tools/call', { name: 'browser_status', arguments: {} }));
    await assert.rejects(access(affectedConfigPath), { code: 'ENOENT' });
    for (const [session, pid] of [[untouched, untouchedPid], [shell, shellPid]]) {
      assert.equal(routeTerminal.metadata(routeTerminal.sessions.get(session.sessionId)).status, 'running'); assert.equal(alive(pid), true);
    }
    assert.equal(alive(untouchedCli.pid), true, 'The other-route real Claude child must remain alive.');
    const marker = `ENVARA_UNAFFECTED_SHELL_${randomBytes(8).toString('hex')}`;
    await routeTerminal.write({ sessionId: shell.sessionId, data: `printf '%s\\n' '${marker}'\r` });
    await waitFor(() => new RegExp(`(?:^|[\\r\\n])${marker}[\\r\\n]`).test(terminalText(shell.sessionId)), 'The unrelated ordinary shell stopped responding.');
    const savedFailure = (await routeTerminal.snapshot({ id: selected.id })).profiles[0].sessions.find(item => item.sessionId === affected.sessionId);
    assert.equal(savedFailure.errorCode, 'CLAUDE_NETWORK_ROUTE_LOST');
    assert.equal((await routeTerminal.close({ sessionId: affected.sessionId })).errorCode, savedFailure.errorCode);
    await stopChild(routeChild);
    check('An injected owned-route failure ends only its shell and manually started Claude child, revokes its live MCP capability, and retains the failure code; the other-route Claude and same-route ordinary shell remain alive and responsive.');
  } finally {
    await routeTerminal.shutdown(); a.pauseExternal(false); b.pauseExternal(false);
  }

  // Claude already exited back to this still-running terminal. Test its actual
  // original capability rather than creating a stand-in broker session. No
  // logged-in model is used to choose tools in this offline acceptance run.
  browserBinding = terminal.sessions.get(created.sessionId).browserBinding;
  assert(browserBinding);
  const browserEnvironment = launch.options.env;
  const mcpConfiguration = JSON.parse(await readFile(configPath, 'utf8')).mcpServers.envara_browser;
  mcp = spawn(launch.executable, ['-p', launch.args[1], mcpConfiguration.command, ...mcpConfiguration.args], { cwd: workingDirectory, env: browserEnvironment, stdio: ['pipe', 'pipe', 'pipe'] }); children.add(mcp);
  const rpc = stdioRpc(mcp), tool = async (name, args = {}) => { const result = await rpc('tools/call', { name, arguments: args }); assert.notEqual(result.isError, true, JSON.stringify(result)); return result; };
  const initialized = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'Envara offline acceptance', version: '1' } });
  assert.equal(initialized.serverInfo.name, 'envara-browser');
  const listed = await rpc('tools/list'); assert(listed.tools.some(item => item.name === 'browser_navigate')); assert(!listed.tools.some(item => /launch|profile|proxy/.test(item.name)));
  const status = await tool('browser_status'); assert.match(JSON.stringify(status), new RegExp(selected.id));
  assert.equal(((await manager.client.request('GET', '/api/sessions')).data ?? []).length, 0);
  check('The actual stdio MCP child connects through its private authenticated socket; status does not launch a browser or expose general manager tools.');
  await tool('browser_navigate', { url: 'http://browser.envara.invalid/selected' });
  await tool('browser_wait_for', { selector: '#message' });
  let snapshot = await tool('browser_snapshot'); assert.match(JSON.stringify(snapshot), /Route A/);
  await tool('browser_fill', { selector: '#message', value: 'selected-browser-value' });
  await tool('browser_press_key', { key: 'Enter' });
  snapshot = await tool('browser_snapshot'); assert.match(JSON.stringify(snapshot), /selected-browser-value/);
  await tool('browser_select', { selector: '#select', values: ['two'] });
  await tool('browser_check', { selector: '#check', checked: true });
  await tool('browser_click', { selector: '#apply' });
  const sessions = (await manager.client.request('GET', '/api/sessions')).data ?? [];
  assert.equal(sessions.length, 1); assert.equal(sessions[0].profile_id, selected.id);
  const fields = (await manager.client.request('POST', `/api/sessions/${sessions[0].session_id}/eval`, { script: '({value:document.querySelector("#message").value,selected:document.querySelector("#select").value,checked:document.querySelector("#check").checked,timeZone:Intl.DateTimeFormat().resolvedOptions().timeZone})' })).data;
  assert.equal(fields.value, 'selected-browser-value'); assert.equal(fields.selected, 'two'); assert.equal(fields.checked, true); assert.equal(fields.timeZone, 'Asia/Manila');
  assert(a.stats.authenticated > 0 && a.stats.geoRequests > 0 && a.stats.browserRequests > 0); assert.equal(b.stats.browserRequests, 0);
  check('Real Playwright navigation, form fill, Enter, click, select and checkbox act on the exact chosen CloakBrowser and authenticated route A; route B remains unused.');
  await tool('browser_tabs', { action: 'new', url: 'http://browser.envara.invalid/second' });
  const tabs = await tool('browser_tabs', { action: 'list' }); assert.match(JSON.stringify(tabs), /second/);
  await tool('browser_tabs', { action: 'select', index: 0 });
  const png = (await tool('browser_screenshot')).content.find(item => item.type === 'image'); assert(png);
  const image = Buffer.from(png.data, 'base64'); assert.equal(image.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
  await writeFile(path.join(runDir, 'selected-browser.png'), image);
  await tool('browser_tabs', { action: 'close', index: 1 });
  check('Real bound-browser tabs and a PNG screenshot work without creating another profile.');
  const injected = await rpc('tools/call', { name: 'browser_navigate', arguments: { url: 'http://browser.envara.invalid/', profileId: other.id } });
  assert.equal(injected.isError, true);
  const probeScript = 'const net=require("net");const s=net.connect(443,"203.0.113.1");s.on("error",e=>{console.log(e.code);process.exit(e.code==="EPERM"?0:2)});setTimeout(()=>process.exit(3),3000)';
  const direct = await execute(launch.executable, ['-p', launch.args[1], nodeExecutable, '-e', probeScript], { cwd: workingDirectory, env: launch.options.env, timeout: 10000 });
  assert.equal(direct.stdout.trim(), 'EPERM');
  check('A foreign profile argument is refused, and a child with the same real Seatbelt profile gets EPERM on a direct external connection.');
  await terminal.setLinkBrowser({ id: selected.id, browserProfileId: 'system' });
  await execute(launch.executable, ['-p', launch.args[1], path.join(await linkChannel.executableDirectory(selected.id), 'open'), 'http://browser.envara.invalid/pinned-link'], { cwd: workingDirectory, env: browserEnvironment, timeout: 35000 });
  await waitFor(async () => JSON.stringify(await tool('browser_tabs', { action: 'list' })).includes('pinned-link'), 'The terminal open shim did not use its pinned browser.');
  assert.equal(b.stats.browserRequests, 0);
  check('Changing the ordinary environment browser to system does not retarget this Claude session: its actual open shim still uses its pinned browser.');
  await service.call('stopProfile', { id: selected.id });
  await service.call('updateProfile', { id: selected.id, profile: { proxyId: other.proxyId } });
  const changed = await rpc('tools/call', { name: 'browser_navigate', arguments: { url: 'http://browser.envara.invalid/changed' } });
  assert.equal(changed.isError, true); assert.match(JSON.stringify(changed), /BINDING_CHANGED/);
  assert.equal(((await manager.client.request('GET', '/api/sessions')).data ?? []).length, 0);
  assert.equal(b.stats.browserRequests, 0);
  check('After the selected profile network changes through the real service, the old capability refuses rather than launching a browser on the replacement network.');
  await terminal.close({ sessionId: created.sessionId });
  const revoked = await rpc('tools/call', { name: 'browser_status', arguments: {} }).then(() => false, () => true);
  assert.equal(revoked, true); await assert.rejects(access(configPath));
  check('Closing the real dedicated shell removes its session-only launch configuration and revokes that terminal\'s live MCP socket; exiting Claude alone had preserved both.');
  await updateVerification?.verifyAfterClosing();
  assert(installerCalls.filter(call => call.source === 'local').every(call => call.downloadCalls === 0), 'A local selection must never invoke the downloader.');
  assert.equal(installerCalls.reduce((total, call) => total + call.downloadCalls, 0), installingDownload ? 1 : 0);
  proof.terminalInstallationSources = { calls: installerCalls, localDownloadCalls: 0, firstSource: installingDownload ? 'download' : 'local', readOnlyMissingStatusCreatedNoDirectories: true };
  check('Every fixture terminal declares its installation source: download bypasses host lookup, local never invokes a downloader, and the pre-install status read creates no profile directory.');
  proof.routeEvidence = fixtures.map(fixture => ({ route: fixture.label, ...fixture.stats }));
  proof.passed = true;
} catch (error) {
  proof.error = { code: error.code ?? null, message: error.message, stack: error.stack };
  proof.terminalDiagnostics = [...output.entries()].map(([sessionId, text]) => ({ sessionId, status: terminal?.sessions.get(sessionId)?.status, output: text.slice(-8000) }));
  console.error(`${error.code ?? 'VERIFY_FAILED'}: ${error.message}`); process.exitCode = 1;
}
finally {
  for (const close of [() => routeTerminal?.shutdown(), () => terminal?.shutdown(), () => broker?.shutdown(), () => linkChannel?.close()]) {
    try { await close(); }
    catch (error) { proof.cleanupError ??= error.message; proof.passed = false; process.exitCode = 1; }
  }
  for (const child of children) await stopChild(child);
  try { await service?.shutdown(); await manager?.shutdown(); } catch (error) { proof.sidecarCleanupError = error.message; proof.passed = false; process.exitCode = 1; }
  for (const fixture of fixtures) await fixture.close();
  await downloadFixture?.close();
  await waitFor(() => [...launchedPids].every(pid => !alive(pid)), 'An owned Claude PTY is still running.', 5000).catch(error => { proof.cleanupError = error.message; proof.passed = false; process.exitCode = 1; });
  proof.remainingOwnedPtys = [...launchedPids].filter(alive).length;
  if (proof.passed && !proof.remainingOwnedPtys) { await rm(temporary, { recursive: true, force: true }); proof.temporaryFixtureRemoved = true; }
  await writeFile(path.join(runDir, 'proof.json'), `${JSON.stringify(proof, null, 2)}\n`, { mode: 0o600 });
  console.log(`Verification proof: ${path.join(runDir, 'proof.json')}`);
}
