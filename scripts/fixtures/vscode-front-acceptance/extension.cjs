'use strict';
// Local acceptance fixture: no subprocesses, DNS calls, redirects or route fallback.
const vscode = require('vscode');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');
const tls = require('node:tls');
const sockets = new Set();
const configWaiters = new Set();
let deactivated = false;
const DATA_ROOT = '/Library/PrivilegedHelperTools/io.envara.pf-app-data';
const SEALED_ROOT = '/Library/PrivilegedHelperTools/io.envara.pf-apps/objects';
const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
const IP_HOST = 'api.ipify.org';
const inside = (parent, child) => typeof child === 'string' && child.startsWith(`${parent}${path.sep}`);
const port = value => Number.isInteger(value) && value > 0 && value <= 65535;
const failure = code => Object.assign(new Error(code), { code });
const safeCode = error => typeof error?.code === 'string' && /^[A-Z0-9_]{1,64}$/.test(error.code) ? error.code : 'PROBE_FAILED';
function own(socket) { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); return socket; }

function readConfig(configPath) {
  let fd;
  try { fd = fs.openSync(configPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > 2048) throw failure('CONFIG_INVALID');
    const buffer = Buffer.alloc(2049); const length = fs.readSync(fd, buffer, 0, buffer.length, 0);
    if (length > 2048) throw failure('CONFIG_INVALID');
    let config;
    try { config = JSON.parse(buffer.subarray(0, length).toString('utf8')); } catch { throw failure('CONFIG_INVALID'); }
    if (!config || typeof config !== 'object' || Array.isArray(config) || Object.keys(config).some(key => !['runId', 'frontPort', 'expectedEgressIp', 'deniedLoopbackPort'].includes(key))) throw failure('CONFIG_INVALID');
    if (typeof config.runId !== 'string' || !/^[a-zA-Z0-9_-]{1,80}$/.test(config.runId)) throw failure('CONFIG_INVALID');
    if (!port(config.deniedLoopbackPort) || (config.frontPort !== undefined && !port(config.frontPort))) throw failure('CONFIG_INVALID');
    if (config.frontPort === config.deniedLoopbackPort || (config.expectedEgressIp !== undefined && (typeof config.expectedEgressIp !== 'string' || (config.expectedEgressIp && !net.isIP(config.expectedEgressIp))))) throw failure('CONFIG_INVALID');
    return config;
  } finally { fs.closeSync(fd); }
}

async function waitForConfig(extensionPath) {
  const started = Date.now(); const deadline = started + 60000;
  const statusPath = path.join(extensionPath, `probe-activation-${process.pid}-${started}.json`);
  const fd = fs.openSync(statusPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  const status = { schema: 1, scope: 'config-wait-only', pid: process.pid, startedAt: new Date(started).toISOString(), configDeadlineAt: new Date(deadline).toISOString(), status: 'waiting-for-config', networkProbeStarted: false };
  const save = () => { fs.ftruncateSync(fd, 0); fs.writeSync(fd, JSON.stringify(status, null, 2) + '\n', 0, 'utf8'); };
  try {
    save();
    for (;;) {
      if (deactivated) throw failure('PROBE_CANCELLED');
      if (Date.now() >= deadline) throw failure('CONFIG_TIMEOUT');
      const config = readConfig(path.join(extensionPath, 'probe-config.json'));
      if (config) { status.status = 'config-received'; status.runId = config.runId; return config; }
      await new Promise(resolve => {
        const done = () => { clearTimeout(timer); configWaiters.delete(done); resolve(); };
        const timer = setTimeout(done, Math.min(250, Math.max(1, deadline - Date.now())));
        configWaiters.add(done);
      });
    }
  } catch (error) {
    status.code = safeCode(error);
    status.status = status.code === 'CONFIG_TIMEOUT' ? 'config-timeout' : status.code === 'PROBE_CANCELLED' ? 'cancelled' : 'config-invalid-or-unreadable';
    return null;
  } finally { status.finishedAt = new Date().toISOString(); try { save(); } finally { fs.closeSync(fd); } }
}

function waitFor(socket, event, deadline) {
  return new Promise((resolve, reject) => {
    const finish = (error) => { clearTimeout(timer); socket.off(event, ready); socket.off('error', failed); socket.off('close', closed); error ? reject(error) : resolve(); };
    const ready = () => finish();
    const failed = error => finish(error);
    const closed = () => finish(failure('PREMATURE_CLOSE'));
    const timer = setTimeout(() => finish(failure('PROBE_TIMEOUT')), Math.max(1, deadline - Date.now()));
    socket.once(event, ready); socket.once('error', failed); socket.once('close', closed);
  });
}

function readExact(socket, length, deadline) {
  return new Promise((resolve, reject) => {
    const finish = (error, value) => { clearTimeout(timer); socket.off('readable', readable); socket.off('error', failed); socket.off('end', ended); error ? reject(error) : resolve(value); };
    const readable = () => { const value = socket.read(length); if (value !== null) finish(null, value); };
    const failed = error => finish(error);
    const ended = () => finish(failure('TRUNCATED_SOCKS_REPLY'));
    const timer = setTimeout(() => finish(failure('PROBE_TIMEOUT')), Math.max(1, deadline - Date.now()));
    socket.on('readable', readable); socket.once('error', failed); socket.once('end', ended); readable();
  });
}

async function directAttempt(host, targetPort) {
  if (deactivated) throw failure('PROBE_CANCELLED');
  const socket = own(net.connect({ host, port: targetPort }));
  try { await waitFor(socket, 'connect', Date.now() + 1500); return { denied: false, connected: true }; }
  catch (error) { const code = safeCode(error); return { denied: code === 'EPERM' || code === 'EACCES', connected: false, code }; }
  finally { socket.destroy(); }
}

function responseBody(bytes) {
  const split = bytes.indexOf('\r\n\r\n');
  if (split < 0 || split > 8192) throw failure('HTTP_HEADERS_INVALID');
  const header = bytes.subarray(0, split).toString('ascii');
  if (!/^HTTP\/1\.[01] 200(?: |\r\n)/.test(header)) throw failure('HTTP_STATUS_NOT_200');
  let body = bytes.subarray(split + 4);
  const transfer = header.match(/^transfer-encoding:\s*([^\r\n]+)$/im);
  const length = header.match(/^content-length:\s*(\d+)\s*$/im);
  if (transfer) {
    if (transfer[1].toLowerCase() !== 'chunked' || length) throw failure('HTTP_FRAMING_INVALID');
    const chunks = []; let ended = false;
    while (body.length) {
      const line = body.indexOf('\r\n');
      if (line < 1 || !/^[0-9a-f]+$/i.test(body.subarray(0, line).toString('ascii'))) throw failure('HTTP_CHUNK_INVALID');
      const count = parseInt(body.subarray(0, line).toString('ascii'), 16); body = body.subarray(line + 2);
      if (count === 0) { if (!body.equals(Buffer.from('\r\n'))) throw failure('HTTP_TRAILER_REFUSED'); ended = true; break; }
      if (body.length < count + 2 || body.subarray(count, count + 2).toString('ascii') !== '\r\n') throw failure('HTTP_CHUNK_TRUNCATED');
      chunks.push(body.subarray(0, count)); body = body.subarray(count + 2);
    }
    if (!ended) throw failure('HTTP_BODY_TRUNCATED');
    body = Buffer.concat(chunks);
  } else if (!length || Number(length[1]) !== body.length) throw failure('HTTP_LENGTH_INVALID');
  const result = JSON.parse(body.toString('utf8'));
  if (!result || Object.keys(result).length !== 1 || typeof result.ip !== 'string' || !net.isIP(result.ip)) throw failure('PUBLIC_IP_INVALID');
  return result.ip;
}

async function routedIp(frontPort, expected) {
  if (deactivated) throw failure('PROBE_CANCELLED');
  const result = { frontTcpConnected: false, authorizedSocksGreeting: false, upstreamTunnelEstablished: false, tlsAuthorized: false, ipReceived: false };
  const deadline = Date.now() + 12000;
  const socket = own(net.connect({ host: '127.0.0.1', port: frontPort }));
  let secure;
  try {
    result.stage = 'front-connect'; await waitFor(socket, 'connect', deadline); result.frontTcpConnected = true;
    result.stage = 'socks-greeting'; socket.write(Buffer.from([5, 1, 0]));
    if (!(await readExact(socket, 2, deadline)).equals(Buffer.from([5, 0]))) throw failure('SOCKS_GREETING_REFUSED');
    result.authorizedSocksGreeting = true;
    result.stage = 'socks-connect'; const host = Buffer.from(IP_HOST, 'ascii');
    socket.write(Buffer.concat([Buffer.from([5, 1, 0, 3, host.length]), host, Buffer.from([1, 187])]));
    const reply = await readExact(socket, 4, deadline);
    if (reply[0] !== 5 || reply[1] !== 0 || reply[2] !== 0) throw failure('SOCKS_CONNECT_REFUSED');
    const addressBytes = reply[3] === 1 ? 4 : reply[3] === 4 ? 16 : reply[3] === 3 ? (await readExact(socket, 1, deadline))[0] : 0;
    if (!addressBytes) throw failure('SOCKS_ADDRESS_INVALID');
    await readExact(socket, addressBytes + 2, deadline); result.upstreamTunnelEstablished = true;
    result.stage = 'tls'; secure = own(tls.connect({ socket, servername: IP_HOST, rejectUnauthorized: true, ALPNProtocols: ['http/1.1'] }));
    await waitFor(secure, 'secureConnect', deadline);
    if (!secure.authorized) throw failure('TLS_UNAUTHORIZED'); result.tlsAuthorized = true;
    result.stage = 'http';
    const response = new Promise((resolve, reject) => {
      const chunks = []; let size = 0;
      const timer = setTimeout(() => done(failure('PROBE_TIMEOUT')), Math.max(1, deadline - Date.now()));
      const data = chunk => { size += chunk.length; if (size > 16384) done(failure('HTTP_RESPONSE_TOO_LARGE')); else chunks.push(chunk); };
      const ended = () => done(null, Buffer.concat(chunks));
      const failed = error => done(error);
      const done = (error, value) => { clearTimeout(timer); secure.off('data', data); secure.off('end', ended); secure.off('error', failed); error ? reject(error) : resolve(value); };
      secure.on('data', data); secure.once('end', ended); secure.once('error', failed);
    });
    secure.write(`GET /?format=json HTTP/1.1\r\nHost: ${IP_HOST}\r\nAccept: application/json\r\nConnection: close\r\n\r\n`);
    result.egressIp = responseBody(await response); result.ipReceived = true;
    result.expectedEgressProvided = Boolean(expected);
    result.expectedEgressMatched = expected ? result.egressIp === expected : null;
    result.stage = 'complete';
  } catch (error) { result.code = safeCode(error); }
  finally { secure?.destroy(); socket.destroy(); }
  return result;
}

async function activate(context) {
  // Installation must be a physical directory in this particular isolated registration.
  const match = context.extensionPath.match(new RegExp(`^(${DATA_ROOT}/${UUID}/${UUID})/Extensions/[^/]+$`));
  if (!match || fs.realpathSync(context.extensionPath) !== context.extensionPath) return;
  const base = match[1]; const home = `${base}/Home`; const storage = context.globalStorageUri?.fsPath;
  const config = await waitForConfig(context.extensionPath);
  if (!config || deactivated) return;
  const reportPath = path.join(context.extensionPath, `probe-result-${config.runId}.json`);
  let reportFd;
  try { reportFd = fs.openSync(reportPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600); }
  catch (error) { if (error.code === 'EEXIST') return; throw error; }
  const proof = {
    schema: 1, runId: config.runId, startedAt: new Date().toISOString(), status: 'running',
    execution: { extensionId: context.extension.id, vscodeVersion: vscode.version, pid: process.pid, ppid: process.ppid, uid: process.getuid(), gid: process.getgid(), executableName: path.basename(process.execPath), sealedExecutable: inside(SEALED_ROOT, process.execPath), remoteExtensionHost: Boolean(vscode.env.remoteName) },
    paths: { home: process.env.HOME === home, osHome: os.homedir() === home, temp: path.resolve(process.env.TMPDIR || '/') === `${base}/Temp`, osTemp: path.resolve(os.tmpdir()) === `${base}/Temp`, cache: process.env.XDG_CACHE_HOME === `${base}/Cache`, config: process.env.XDG_CONFIG_HOME === `${base}/UserData`, extension: inside(`${base}/Extensions`, context.extensionPath), globalStorage: inside(`${base}/UserData`, storage) },
    arguments: { ownLoopbackProxyArgument: process.argv.some(value => /^--proxy-server=socks5:\/\/127\.0\.0\.1:\d+$/.test(value)), ownUserDataArgument: process.argv.some(value => value === `--user-data-dir=${base}/UserData`), ownExtensionsArgument: process.argv.some(value => value === `--extensions-dir=${base}/Extensions`) },
    limitations: ['Tests this local VS Code Node extension host only; path comparisons establish configuration consistency.', 'Direct TCP uses owned loopback listeners; outside-fence positive controls and no receiver delivery must be checked independently.', 'No non-loopback direct TCP, UDP, login, Marketplace, XPC delegate, Keychain, hardware identity or whole-guard crash acceptance.', 'A public IP is tied to the expected environment only when compared with independently measured expectedEgressIp.']
  };
  const save = () => {
    fs.ftruncateSync(reportFd, 0);
    fs.writeSync(reportFd, JSON.stringify(proof, null, 2) + '\n', 0, 'utf8');
  };
  try {
    save();
    if (!Object.values(proof.paths).every(Boolean) || proof.execution.remoteExtensionHost || !proof.execution.sealedExecutable) throw failure('ISOLATED_CONTEXT_MISMATCH');
    const argument = process.argv.find(value => /^--proxy-server=socks5:\/\/127\.0\.0\.1:\d+$/.test(value));
    const frontPort = config.frontPort || (argument ? Number(argument.split(':').pop()) : 0);
    if (!port(frontPort) || (config.expectedEgressIp && !net.isIP(config.expectedEgressIp))) throw failure('CONFIG_INVALID');
    if (!port(config.deniedLoopbackPort) || config.deniedLoopbackPort === frontPort) throw failure('CONFIG_INVALID');
    proof.direct = { ipv4: await directAttempt('127.0.0.1', config.deniedLoopbackPort), ipv6: await directAttempt('::1', config.deniedLoopbackPort) };
    proof.route = await routedIp(frontPort, config.expectedEgressIp || '');
    proof.passed = Object.values(proof.direct).every(result => result.denied) && proof.route.ipReceived && proof.route.expectedEgressMatched === true;
    proof.status = proof.passed ? 'passed' : 'incomplete-or-failed';
  } catch (error) { proof.status = 'refused-or-failed'; proof.code = safeCode(error); proof.passed = false; }
  finally { for (const socket of sockets) socket.destroy(); proof.finishedAt = new Date().toISOString(); try { save(); } finally { fs.closeSync(reportFd); } }
}
exports.activate = activate;
exports.deactivate = () => { deactivated = true; for (const done of configWaiters) done(); for (const socket of sockets) socket.destroy(); };
