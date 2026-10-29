// Exact packaged desktop acceptance in the release workspace's fixed runtime.
// This runner never installs an app, signs code, opens a real account, or changes
// host preferences. A missing/failed real check cannot produce a passing receipt.
import { execFile, spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const filename = fileURLToPath(import.meta.url);
const check = (value, code) => { if (!value) throw Object.assign(new Error(code), { code }); };
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const hash = value => createHash('sha256').update(value).digest('hex');
const fixedCodes = new Set(['CANDIDATE_INPUT_INVALID', 'CANDIDATE_RUNTIME_UNSAFE', 'CANDIDATE_RUNTIME_NOT_EMPTY',
  'CANDIDATE_ALREADY_RUNNING', 'CANDIDATE_SOCKET_OCCUPIED', 'CANDIDATE_PROCESS_SNAPSHOT_FAILED',
  'CANDIDATE_PROCESS_IDENTITY_CHANGED', 'CANDIDATE_BOOTSTRAP_FAILED', 'CANDIDATE_CHECK_TIMEOUT',
  'CANDIDATE_GUI_FAILED', 'CANDIDATE_KEYCHAIN_FAILED', 'CANDIDATE_CLEANUP_FAILED']);
const safeCode = error => fixedCodes.has(error?.code) ? error.code
  : fixedCodes.has(error?.message) ? error.message : 'CANDIDATE_CHECK_FAILED';
const phases = new Set(['runtime-prepare', 'launch', 'process-identity', 'main-inspector', 'pre-main-isolation', 'main-resume',
  'browser-endpoint', 'browser-connect', 'renderer-target', 'renderer-ownership', 'first-launch-ui', 'desktop-ready',
  'language-selection', 'first-launch-screenshot', 'profile-create', 'terminal-directory', 'terminal-open', 'terminal-io',
  'terminal-close', 'application-quit', 'process-cleanup', 'native-keychain', 'runtime-cleanup']);
const diagnosticReasons = new Set(['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'EADDRINUSE', 'EPIPE', 'ENOENT', 'EACCES', 'EPERM',
  'TimeoutError', 'INSPECTOR_TIMEOUT', 'INSPECTOR_PROTOCOL', 'INSPECTOR_EXCEPTION', 'INSPECTOR_CLOSED',
  'SNAPSHOT_EMPTY', 'SNAPSHOT_ROW_SHAPE', 'SNAPSHOT_PID']);
const inspectorOperations = new Set(['Runtime.enable', 'Debugger.enable', 'Runtime.runIfWaitingForDebugger', 'Runtime.evaluate',
  'Debugger.resume', 'Debugger.disable']);
const codedError = (code, details = {}) => Object.assign(new Error(code), { code, ...details });

/** Failure evidence is deliberately categorical: never persist a raw message,
 * stack, endpoint, expression, page contents, or environment variable. */
export function candidateFailure(error, phase) {
  const value = { code: safeCode(error), phase: phases.has(phase) ? phase : 'unknown' };
  const reason = [error?.reason, error?.code, error?.cause?.code, error?.name].find(item => diagnosticReasons.has(item));
  if (reason) value.reason = reason;
  if (inspectorOperations.has(error?.operation)) value.operation = error.operation;
  if (value.code === 'CANDIDATE_PROCESS_SNAPSHOT_FAILED' && Number.isInteger(error?.attempts) && error.attempts >= 1 && error.attempts <= 3)
    value.attempts = error.attempts;
  return value;
}
const ownedIdentity = info => `${info.dev}:${info.ino}:${info.uid}`;
const ending = row => row.state?.startsWith('Z') === true || row.state?.includes('E') === true;
// Darwin replaces comm with '(name)' or '<defunct>' while exiting (E) or dead
// (Z). A matching birth and ending state may finish observation, never signal.
const sameProcess = (a, b) => a.pid === b.pid && a.birth === b.birth && (a.command === b.command || ending(b));

export const requiredChecks = Object.freeze(['clean-first-launch', 'desktop-service-ready', 'terminal-pty',
  'claude-keychain-persistence', 'owned-process-cleanup']);

export function parseCandidateArguments(args) {
  const names = { '--app': 'app', '--runtime': 'runtime', '--evidence': 'evidence', '--receipt': 'receipt',
    '--source-commit': 'sourceCommit', '--nonce': 'nonce', '--candidate-manifest-sha256': 'candidateManifestSHA256' };
  const value = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = names[args[i]];
    check(key && !Object.hasOwn(value, key) && typeof args[i + 1] === 'string', 'CANDIDATE_INPUT_INVALID');
    value[key] = args[i + 1];
  }
  validateCandidateInputs(value);
  return value;
}

export function validateCandidateInputs(value) {
  check(value && Object.keys(value).length === 7, 'CANDIDATE_INPUT_INVALID');
  for (const name of ['app', 'runtime', 'evidence', 'receipt'])
    check(typeof value[name] === 'string' && path.isAbsolute(value[name]) && path.normalize(value[name]) === value[name]
      && !/[\x00-\x1f\x7f]/.test(value[name]), 'CANDIDATE_INPUT_INVALID');
  check(/^[a-f0-9]{40}$/.test(value.sourceCommit ?? '') && /^[a-f0-9-]{36}$/.test(value.nonce ?? '')
    && /^[a-f0-9]{64}$/.test(value.candidateManifestSHA256 ?? ''), 'CANDIDATE_INPUT_INVALID');
  const root = path.dirname(value.runtime);
  check(path.basename(value.runtime) === 'runtime' && value.app === path.join(root, 'candidate/mac-arm64/Envara.app')
    && value.evidence === path.join(root, 'evidence', value.nonce)
    && value.receipt === path.join(value.evidence, 'candidate-acceptance.json'), 'CANDIDATE_INPUT_INVALID');
}

export function candidateEnvironment(directories) {
  return { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: directories.home, USERPROFILE: directories.home,
    TMPDIR: directories.temp + '/', TMP: directories.temp, TEMP: directories.temp, LANG: 'en_US.UTF-8', LC_ALL: 'en_US.UTF-8',
    XDG_CACHE_HOME: directories.cache, XDG_CONFIG_HOME: directories.config, XDG_DATA_HOME: directories.data,
    CLOAKBROWSER_CACHE_DIR: directories.engines, PLAYWRIGHT_BROWSERS_PATH: directories.engines };
}

async function privateDirectory(name) {
  const info = await fs.lstat(name);
  check(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid() && (info.mode & 0o7777) === 0o700
    && await fs.realpath(name) === name, 'CANDIDATE_RUNTIME_UNSAFE');
  return ownedIdentity(info);
}

export async function prepareCandidateRuntime(input) {
  validateCandidateInputs(input);
  await privateDirectory(input.runtime); await privateDirectory(input.evidence);
  check(await fs.realpath(input.app) === input.app, 'CANDIDATE_INPUT_INVALID');
  const roots = Object.fromEntries(['home', 'userData', 'work'].map(name => [name, path.join(input.runtime, name)]));
  const identities = {};
  for (const [name, root] of Object.entries(roots)) {
    identities[name] = await privateDirectory(root);
    check((await fs.readdir(root)).length === 0, 'CANDIDATE_RUNTIME_NOT_EMPTY');
  }
  try { await fs.lstat(input.receipt); check(false, 'CANDIDATE_INPUT_INVALID'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const directories = { home: roots.home, userData: roots.userData };
  for (const name of ['appData', 'sessionData', 'temp', 'logs', 'crashDumps', 'documents', 'desktop', 'downloads',
    'music', 'pictures', 'videos', 'cache', 'config', 'data', 'engines', 'workingDirectory']) {
    directories[name] = path.join(roots.work, name);
    await fs.mkdir(directories[name], { mode: 0o700 });
  }
  return { roots, identities, directories };
}

export async function clearCandidateRuntime(state) {
  for (const [name, root] of Object.entries(state.roots)) {
    check(await privateDirectory(root) === state.identities[name], 'CANDIDATE_CLEANUP_FAILED');
    for (const entry of await fs.readdir(root)) await fs.rm(path.join(root, entry), { recursive: true, force: false });
    check((await fs.readdir(root)).length === 0, 'CANDIDATE_CLEANUP_FAILED');
  }
}

export async function writeCandidateReceipt(file, value) {
  const parent = path.dirname(file), identity = await privateDirectory(parent);
  const handle = await fs.open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    check(await privateDirectory(parent) === identity, 'CANDIDATE_RUNTIME_UNSAFE');
    await handle.writeFile(JSON.stringify(value, null, 2) + '\n'); await handle.sync();
  } finally { await handle.close(); }
}

export function parseCandidateProcesses(stdout) {
  if (typeof stdout !== 'string' || !stdout.trim()) throw codedError('CANDIDATE_PROCESS_SNAPSHOT_FAILED', { reason: 'SNAPSHOT_EMPTY' });
  const rows = [], seen = new Set();
  for (const line of stdout.split(/\r?\n/).filter(value => value.trim())) {
    const m = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+([A-Za-z<>+\-]+)\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+?)\s*$/.exec(line);
    if (!m) throw codedError('CANDIDATE_PROCESS_SNAPSHOT_FAILED', { reason: 'SNAPSHOT_ROW_SHAPE' });
    const row = { pid: Number(m[1]), ppid: Number(m[2]), pgid: Number(m[3]), state: m[4], birth: m[5].replace(/\s+/g, ' '), command: m[6] };
    if (row.pid <= 0 || seen.has(row.pid)) throw codedError('CANDIDATE_PROCESS_SNAPSHOT_FAILED', { reason: 'SNAPSHOT_PID' });
    seen.add(row.pid); rows.push(row);
  }
  return rows;
}

async function processText() {
  // Darwin comm is reconstructed from argv and can become '(name)' before
  // state changes on exit. ucomm is the stable kernel accounting name; the
  // inspector separately binds the launched PID to its exact executable path.
  const { stdout } = await execute('/bin/ps', ['-axo', 'pid=,ppid=,pgid=,stat=,lstart=,ucomm='], {
    env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, timeout: 5000, maxBuffer: 4 * 1024 * 1024 });
  return stdout;
}

export async function readCandidateProcessSnapshot({ read = processText, delay = pause } = {}) {
  // A process can disappear while ps gathers one row. Retry a complete fresh
  // read, never discard that row or weaken ownership checks in a partial view.
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try { return parseCandidateProcesses(await read()); }
    catch (error) {
      if (error.code !== 'CANDIDATE_PROCESS_SNAPSHOT_FAILED') throw error;
      error.attempts = attempt;
      if (attempt === 3) throw error;
      await delay(25);
    }
  }
}

const processRows = () => readCandidateProcessSnapshot();

export function observeCandidateProcesses(rows, root, known = []) {
  const current = rows.find(row => row.pid === root.pid);
  if (current) check(sameProcess(root, current), 'CANDIDATE_PROCESS_IDENTITY_CHANGED');
  const ids = new Set(rows.filter(row => known.some(item => sameProcess(item, row))).map(row => row.pid));
  if (current) ids.add(root.pid);
  if (ids.size) {
    let again = true;
    while (again) { again = false; for (const row of rows) if (!ids.has(row.pid) && ids.has(row.ppid)) { ids.add(row.pid); again = true; } }
    // A live identity is required before discovering by the original group;
    // an otherwise unassociated group is retained as uncertain, never killed.
    if (root.pgid === root.pid && rows.some(row => ids.has(row.pid) && row.pgid === root.pid))
      for (const row of rows) if (row.pgid === root.pid) ids.add(row.pid);
  }
  const result = [...known];
  for (const row of rows) if (ids.has(row.pid) && !result.some(item => sameProcess(item, row))) result.push(row);
  return result;
}

async function waitFor(operation, timeout = 15000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) {
    let timer;
    try {
      const value = await Promise.race([operation(), new Promise((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error('CANDIDATE_CHECK_TIMEOUT'), { code: 'CANDIDATE_CHECK_TIMEOUT' })), Math.max(1, until - Date.now()));
      })]);
      if (value) return value;
    } finally { clearTimeout(timer); }
    await pause(50);
  }
  check(false, 'CANDIDATE_CHECK_TIMEOUT');
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

async function debuggerJSON(port, resource) {
  return new Promise((resolve, reject) => {
    const request = http.get({ hostname: '127.0.0.1', port, path: resource }, response => {
      if (response.statusCode !== 200) { response.resume(); reject(codedError('CANDIDATE_BOOTSTRAP_FAILED')); return; }
      let body = ''; response.setEncoding('utf8');
      response.on('data', bytes => { body += bytes; if (body.length > 65536) request.destroy(codedError('CANDIDATE_BOOTSTRAP_FAILED')); });
      response.once('error', reject);
      response.once('end', () => { try { resolve(JSON.parse(body)); } catch { reject(codedError('CANDIDATE_BOOTSTRAP_FAILED')); } });
    });
    request.setTimeout(500, () => request.destroy(codedError('CANDIDATE_BOOTSTRAP_FAILED', { reason: 'ETIMEDOUT' })));
    request.once('error', reject);
  });
}

export async function waitForCandidateBrowserEndpoint(port, { timeout = 15000, read = debuggerJSON } = {}) {
  check(Number.isInteger(port) && port > 0 && port <= 65535, 'CANDIDATE_INPUT_INVALID');
  let lastError;
  try {
    return await waitFor(async () => {
      let value;
      try { value = await read(port, '/json/version/'); } catch (error) { lastError = error; return null; }
      let url; try { url = new URL(value?.webSocketDebuggerUrl); } catch { check(false, 'CANDIDATE_BOOTSTRAP_FAILED'); }
      check(url.protocol === 'ws:' && ['127.0.0.1', 'localhost'].includes(url.hostname) && Number(url.port) === port
        && !url.username && !url.password && !url.hash && url.pathname.startsWith('/devtools/browser/'), 'CANDIDATE_BOOTSTRAP_FAILED');
      return url.href;
    }, timeout);
  } catch (error) {
    if (error.code === 'CANDIDATE_CHECK_TIMEOUT') error.reason = candidateFailure(lastError, 'browser-endpoint').reason;
    throw error;
  }
}

async function inspectorConnection(port) {
  const target = await waitFor(async () => {
    try { const values = await debuggerJSON(port, '/json/list'); return values.length === 1 && values[0].type === 'node' && values[0]; } catch { return null; }
  });
  const url = new URL(target.webSocketDebuggerUrl);
  check(url.protocol === 'ws:' && ['127.0.0.1', 'localhost'].includes(url.hostname) && Number(url.port) === port, 'CANDIDATE_BOOTSTRAP_FAILED');
  const socket = new WebSocket(url), pending = new Map(); let counter = 0, paused = false;
  socket.onmessage = event => {
    let value; try { value = JSON.parse(String(event.data)); } catch { return; }
    if (value.method === 'Debugger.paused') paused = true;
    const item = pending.get(value.id); if (!item) return;
    pending.delete(value.id); clearTimeout(item.timer);
    if (value.error) item.reject(codedError('CANDIDATE_BOOTSTRAP_FAILED', { operation: item.operation, reason: 'INSPECTOR_PROTOCOL' }));
    else item.resolve(value.result);
  };
  await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error('CANDIDATE_BOOTSTRAP_FAILED')), 3000);
    socket.onopen = () => { clearTimeout(timer); resolve(); }; socket.onerror = () => { clearTimeout(timer); reject(new Error('CANDIDATE_BOOTSTRAP_FAILED')); }; });
  const command = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++counter, timer = setTimeout(() => { pending.delete(id);
      reject(codedError('CANDIDATE_BOOTSTRAP_FAILED', { operation: method, reason: 'INSPECTOR_TIMEOUT' })); }, 5000);
    pending.set(id, { resolve, reject, timer, operation: method }); socket.send(JSON.stringify({ id, method, params }));
  });
  return { command, paused: () => paused, evaluate: async expression => {
    // Bootstrap runs while the main thread is paused: awaiting a promise here
    // can wait for a microtask that cannot run until Debugger.resume.
    const value = await command('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: false, includeCommandLineAPI: true });
    if (value.exceptionDetails) throw codedError('CANDIDATE_BOOTSTRAP_FAILED', { operation: 'Runtime.evaluate', reason: 'INSPECTOR_EXCEPTION' });
    return value.result?.value;
  }, close: () => { for (const item of pending.values()) { clearTimeout(item.timer);
    item.reject(codedError('CANDIDATE_BOOTSTRAP_FAILED', { operation: item.operation, reason: 'INSPECTOR_CLOSED' })); }
    pending.clear(); socket.close(); } };
}

export function candidateBootstrapExpression({ executable, directories, runtime, pid }) {
  return `(() => {
    const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
    const {app,BrowserWindow}=require('electron'); const c=${JSON.stringify({ executable, directories, runtime, pid })};
    assert.equal(process.pid,c.pid);assert.equal(fs.realpathSync(process.execPath),c.executable);
    assert.equal(app.isReady(),false);assert.equal(BrowserWindow.getAllWindows().length,0);assert.equal(app.isPackaged,true);
    for(const name of ['home','appData','userData','sessionData','temp','logs','crashDumps','documents','desktop','downloads','music','pictures','videos'])app.setPath(name,c.directories[name]);
    for(const name of ['home','appData','userData','sessionData','temp','logs'])assert(app.getPath(name).startsWith(c.runtime+path.sep));
    app.on('session-created',session=>{session.setPermissionRequestHandler((_c,_p,reply)=>reply(false));
      session.webRequest.onBeforeRequest((details,reply)=>reply({cancel:!['file:','data:','blob:','devtools:'].some(prefix=>details.url.startsWith(prefix))}));});
    return {beforeMain:true,isPackaged:true};
  })()`;
}

export async function runCandidateDesktop(input, state) {
  const { chromium } = await import('playwright-core');
  const executable = path.join(input.app, 'Contents/MacOS/Envara');
  check(await fs.realpath(executable) === executable, 'CANDIDATE_INPUT_INVALID');
  check(!(await processRows()).some(row => row.command === 'Envara' || row.command.includes('/Envara.app/Contents/MacOS/Envara')), 'CANDIDATE_ALREADY_RUNNING');
  const socketPath = `/private/tmp/io.envara.link-router.${process.getuid()}.sock`;
  try { await fs.lstat(socketPath); check(false, 'CANDIDATE_SOCKET_OCCUPIED'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const inspectorPort = await freePort(), browserPort = await freePort();
  check(inspectorPort !== browserPort, 'CANDIDATE_BOOTSTRAP_FAILED');
  let child, inspector, browser, root, known = [], normalQuit = false, failure, exitCode, exitSignal, phase = 'launch';
  const checks = [], observed = { appLaunched: false, cleanupComplete: false, remainingOwnedProcesses: null, checks };
  const observe = async () => { const rows = await processRows(); if (root) known = observeCandidateProcesses(rows, root, known); return rows; };
  const remaining = rows => known.filter(item => rows.some(row => sameProcess(item, row)));
  const unassociatedGroup = rows => root?.pgid === root?.pid ? rows.filter(row => row.pgid === root.pid && !known.some(item => sameProcess(item, row))) : [];
  try {
    // Preserve Electron's production renderer sandbox. macOS rejects a second
    // sandbox_init inside an outer sandbox-exec, even with an allow-all profile.
    // Isolation here uses pre-main paths and an allowlisted environment; it is
    // not a process-wide filesystem or public-network security boundary.
    child = spawn(executable, [`--inspect-brk=${inspectorPort}`,
      `--remote-debugging-port=${browserPort}`, `--user-data-dir=${state.directories.userData}`], {
      cwd: state.roots.work, env: candidateEnvironment(state.directories), detached: true, stdio: ['ignore', 'ignore', 'ignore'] });
    child.once('exit', (code, signal) => { exitCode = code; exitSignal = signal; });
    await new Promise((resolve, reject) => { child.once('spawn', resolve); child.once('error', reject); });
    phase = 'process-identity';
    root = await waitFor(async () => (await processRows()).find(row => row.pid === child.pid && row.command === path.basename(executable)));
    check(root.ppid === process.pid, 'CANDIDATE_PROCESS_IDENTITY_CHANGED'); await observe();
    phase = 'main-inspector'; inspector = await inspectorConnection(inspectorPort);
    await inspector.command('Runtime.enable'); await inspector.command('Debugger.enable'); await inspector.command('Runtime.runIfWaitingForDebugger');
    await waitFor(() => inspector.paused(), 5000);
    phase = 'pre-main-isolation';
    const bootstrap = await inspector.evaluate(candidateBootstrapExpression({ executable, directories: state.directories, runtime: input.runtime, pid: child.pid }));
    check(bootstrap?.beforeMain && bootstrap.isPackaged, 'CANDIDATE_BOOTSTRAP_FAILED');
    phase = 'main-resume'; await inspector.command('Debugger.resume'); await inspector.command('Debugger.disable');
    // connectOverCDP performs one HTTP discovery request; its timeout does not
    // retry an endpoint that is still starting after the main thread resumes.
    phase = 'browser-endpoint'; const browserEndpoint = await waitForCandidateBrowserEndpoint(browserPort);
    phase = 'browser-connect'; browser = await chromium.connectOverCDP(browserEndpoint, { timeout: 15000 });
    phase = 'renderer-target';
    const page = await waitFor(() => browser.contexts()[0]?.pages().find(item => item.url().startsWith('file:')));
    const rendererSession = await page.context().newCDPSession(page);
    const { targetInfo } = await rendererSession.send('Target.getTargetInfo');
    await rendererSession.detach();
    // Bind the renderer endpoint to the already identity-checked main process
    // before reading or operating a page, even if a free-port race occurred.
    phase = 'renderer-ownership';
    const rendererOwned = await inspector.evaluate(`(() => { const {webContents,BrowserWindow}=require('electron');
      const contents=webContents.fromDevToolsTargetId(${JSON.stringify(targetInfo.targetId)});
      return !!contents && !!BrowserWindow.fromWebContents(contents); })()`);
    check(rendererOwned === true, 'CANDIDATE_BOOTSTRAP_FAILED');
    page.setDefaultTimeout(10000);
    phase = 'first-launch-ui'; await page.locator('.language-welcome-card').waitFor();
    const windowState = await inspector.evaluate(`(() => { const {app,BrowserWindow}=require('electron'); return {
      packaged:app.isPackaged, appPath:app.getAppPath(), userData:app.getPath('userData'),
      windows:BrowserWindow.getAllWindows().filter(w=>w.isVisible()&&!w.isDestroyed()).length}; })()`);
    check(windowState.packaged && windowState.appPath === path.join(input.app, 'Contents/Resources/app.asar')
      && windowState.userData === state.directories.userData && windowState.windows === 1, 'CANDIDATE_GUI_FAILED');
    observed.appLaunched = true;
    const call = (method, args = {}) => page.evaluate(({ method, args }) => window.envara.call(method, args), { method, args });
    phase = 'desktop-ready'; const snapshot = await waitFor(() => call('snapshot'), 30000);
    check(snapshot.profiles?.length === 0 && snapshot.proxies?.length === 0 && snapshot.applications?.length === 0
      && snapshot.settings?.language === undefined, 'CANDIDATE_GUI_FAILED');
    checks.push({ id: 'desktop-service-ready', passed: true });
    phase = 'language-selection'; check(await page.locator('.language-choice-input').count() === 9, 'CANDIDATE_GUI_FAILED');
    await page.locator('.language-choice-input[value="en"]').check(); await page.locator('.language-start-button').click();
    await page.locator('.language-welcome-layer').waitFor({ state: 'hidden' });
    check((await call('snapshot')).settings.language === 'en', 'CANDIDATE_GUI_FAILED');
    phase = 'first-launch-screenshot'; const screenshot = await page.screenshot({ animations: 'disabled' });
    await fs.writeFile(path.join(input.evidence, 'candidate-first-launch.png'), screenshot, { mode: 0o600, flag: 'wx' });
    checks.push({ id: 'clean-first-launch', passed: true, details: { screenshotSHA256: hash(screenshot) } });
    phase = 'profile-create'; const created = await call('createProfile', { profile: { name: 'Release acceptance fixture', engine: 'cloakbrowser',
      deviceProfileId: 'provider-default', platform: 'macos', proxyId: null, startUrl: 'about:blank' } });
    const id = created.actionResult?.createdId; check(typeof id === 'string', 'CANDIDATE_GUI_FAILED');
    phase = 'terminal-directory'; await inspector.evaluate(`(() => { const {dialog}=require('electron'); const original=dialog.showOpenDialog;
      dialog.showOpenDialog=async(_parent,options)=>{dialog.showOpenDialog=original;
        if(options?.title!=='选择此境舱的工作目录'||JSON.stringify(options.properties)!=='["openDirectory"]')throw new Error('Unexpected fixture dialog');
        return {canceled:false,filePaths:[${JSON.stringify(state.directories.workingDirectory)}]};};return true;})()`);
    const selected = await call('pickTerminalDirectory', { id });
    check(selected.canceled === false && typeof selected.token === 'string', 'CANDIDATE_GUI_FAILED');
    phase = 'terminal-open'; const session = await call('openTerminal', { id, kind: 'shell', directoryToken: selected.token, fresh: true, columns: 80, rows: 24 });
    check(session.status === 'running', 'CANDIDATE_GUI_FAILED');
    phase = 'terminal-io'; const suffix = randomUUID().replaceAll('-', ''), marker = `ENVARA_ACCEPT_${suffix}`;
    await call('writeTerminal', { sessionId: session.sessionId, data: `printf 'ENVARA_ACCEPT_%s\\n' '${suffix}'\r` });
    const sessions = async () => (await call('terminalSnapshot')).profiles.flatMap(row => row.sessions ?? []);
    await waitFor(async () => new RegExp(`(?:^|[\\r\\n])${marker}[\\r\\n]`).test((await sessions()).find(row => row.sessionId === session.sessionId)?.replay ?? ''));
    await call('resizeTerminal', { sessionId: session.sessionId, columns: 100, rows: 30 });
    await observe();
    phase = 'terminal-close'; await call('closeTerminal', { sessionId: session.sessionId });
    await waitFor(async () => !(await sessions()).some(row => ['starting', 'running', 'closing'].includes(row.status)));
    checks.push({ id: 'terminal-pty', passed: true, details: { realShell: true, accountLoginTested: false } });
    await observe();
    // The inspector's command-line require binding exists only during this
    // evaluation. Capture app before the deferred callback runs.
    phase = 'application-quit'; await inspector.evaluate("(() => { const app=require('electron').app; setImmediate(()=>app.quit()); return true; })()");
    normalQuit = true;
    inspector.close(); inspector = null;
    phase = 'process-cleanup';
    await waitFor(async () => { const rows = await observe(); return remaining(rows).length === 0 && unassociatedGroup(rows).length === 0; }, 15000);
    check(exitCode === 0 && exitSignal === null, 'CANDIDATE_CLEANUP_FAILED');
  } catch (error) { failure = error; observed.failure = candidateFailure(error, phase); }
  finally {
    try {
      if (root) {
        let rows = await observe();
        // Only identities observed in this run are eligible for failure cleanup.
        // A forced cleanup always leaves the GUI check failed.
        if (remaining(rows).length) {
          failure ??= Object.assign(new Error('CANDIDATE_CLEANUP_FAILED'), { code: 'CANDIDATE_CLEANUP_FAILED' });
          for (const item of remaining(rows).reverse()) {
            const fresh = (await processRows()).find(row => sameProcess(item, row));
            if (fresh && !ending(fresh)) process.kill(fresh.pid, 'SIGTERM');
          }
          await waitFor(async () => remaining(await observe()).length === 0, 5000).catch(() => {});
        }
        rows = await processRows(); observed.remainingOwnedProcesses = remaining(rows).length + unassociatedGroup(rows).length;
        observed.cleanupComplete = observed.remainingOwnedProcesses === 0;
        try { await fs.lstat(socketPath); observed.cleanupComplete = false; failure ??= new Error('CANDIDATE_CLEANUP_FAILED'); }
        catch (error) { if (error.code !== 'ENOENT') throw error; }
      } else { observed.remainingOwnedProcesses = child?.pid ? 1 : 0; observed.cleanupComplete = !child?.pid; }
    } catch { observed.cleanupComplete = false; failure ??= new Error('CANDIDATE_CLEANUP_FAILED'); }
    inspector?.close(); await browser?.close().catch(() => {});
  }
  if (failure || !normalQuit || !observed.cleanupComplete) {
    observed.failure ??= candidateFailure(failure, 'process-cleanup');
    throw Object.assign(new Error(safeCode(failure)), { code: safeCode(failure), observation: observed });
  }
  return observed;
}

async function defaultKeychainCheck(input, state) {
  const { verifyClaudeKeychain } = await import('./verify-claude-keychain.mjs');
  const helperPath = path.join(input.app, 'Contents/Resources/claude-keychain', `darwin-${process.arch}`, 'envara-claude-keychain');
  return verifyClaudeKeychain({ helperPath, temporaryParent: state.roots.work });
}

export async function verifyMacosReleaseCandidate(input, { platform = process.platform, prepare = prepareCandidateRuntime,
  desktop = runCandidateDesktop, keychain = defaultKeychainCheck, cleanup = clearCandidateRuntime, writeReceipt = writeCandidateReceipt } = {}) {
  validateCandidateInputs(input); check(platform === 'darwin', 'CANDIDATE_INPUT_INVALID');
  const receipt = { schema: 'envara.macos-release-acceptance/v1', sourceCommit: input.sourceCommit, app: input.app,
    runtime: input.runtime, nonce: input.nonce, candidateManifestSHA256: input.candidateManifestSHA256,
    passed: false, appLaunched: false, cleanup: { complete: false, remainingOwnedProcesses: null }, checks: [],
    limitations: ['Synthetic Keychain persistence does not establish real Claude OAuth login or model inference.',
      'Desktop acceptance uses pre-main inspector path isolation and an allowlisted environment; it is not a process-wide filesystem or public-network boundary.',
      'Renderer requests are limited to local content; public provider connectivity is not verified.'] };
  let state, failure, safeToClean = false, phase = 'runtime-prepare';
  try {
    state = await prepare(input);
    phase = 'launch'; const result = await desktop(input, state);
    receipt.appLaunched = result.appLaunched === true;
    receipt.checks.push(...result.checks);
    receipt.cleanup.remainingOwnedProcesses = result.remainingOwnedProcesses;
    check(result.cleanupComplete && result.remainingOwnedProcesses === 0, 'CANDIDATE_CLEANUP_FAILED');
    // The native verifier owns its temporary Keychain. Preserve its directory
    // if its cleanup cannot be confirmed, even when desktop processes exited.
    let native;
    phase = 'native-keychain';
    try { native = await keychain(input, state); }
    catch (error) { safeToClean = error.proof?.cleanupComplete === true; throw error; }
    safeToClean = native.cleanupComplete === true;
    check(native.passed && native.cleanupComplete && native.hostSelectionUnchanged, 'CANDIDATE_KEYCHAIN_FAILED');
    receipt.checks.push({ id: 'claude-keychain-persistence', passed: true, details: { synthetic: true, actualOAuthLogin: false } });
  } catch (error) {
    failure = error; receipt.error = candidateFailure(error, phase);
    if (error.observation) {
      if (error.observation.failure) receipt.error = candidateFailure(error.observation.failure, error.observation.failure.phase);
      receipt.appLaunched = error.observation.appLaunched === true;
      receipt.checks.push(...error.observation.checks);
      receipt.cleanup.remainingOwnedProcesses = error.observation.remainingOwnedProcesses;
      safeToClean = error.observation.cleanupComplete === true;
    }
  } finally {
    if (state && receipt.cleanup.remainingOwnedProcesses === 0 && safeToClean) {
      try { await cleanup(state); receipt.cleanup.complete = true; receipt.checks.push({ id: 'owned-process-cleanup', passed: true }); }
      catch {
        failure ??= codedError('CANDIDATE_CLEANUP_FAILED');
        const cleanupError = candidateFailure(codedError('CANDIDATE_CLEANUP_FAILED'), 'runtime-cleanup');
        if (receipt.error) receipt.cleanup.error = cleanupError; else receipt.error = cleanupError;
      }
    }
    receipt.passed = !failure && receipt.appLaunched && receipt.cleanup.complete
      && requiredChecks.every(id => receipt.checks.filter(item => item.id === id && item.passed === true).length === 1);
    await writeReceipt(input.receipt, receipt);
  }
  if (!receipt.passed) throw Object.assign(new Error(receipt.error?.code ?? 'CANDIDATE_CHECK_FAILED'), { receipt });
  return receipt;
}

if (process.argv[1] && path.resolve(process.argv[1]) === filename) {
  try { await verifyMacosReleaseCandidate(parseCandidateArguments(process.argv.slice(2))); console.log('Exact candidate acceptance passed.'); }
  catch (error) { console.error(safeCode(error)); process.exitCode = 1; }
}
