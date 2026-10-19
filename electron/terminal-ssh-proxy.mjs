// Copied into the terminal's protected runtime. Keep this module standalone:
// OpenSSH runs it as a ProxyCommand, without access to application dependencies.
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';
import { domainToASCII, pathToFileURL } from 'node:url';

const MAX_TARGET_BYTES = 16 * 1024;
const MAX_TARGETS = 128;
const failure = (code, message) => Object.assign(new Error(message), { code });
const invalid = () => failure('SSH_PROXY_CONFIGURATION', 'SSH proxy configuration is unavailable or invalid.');

export function validateSshTarget(host, port) {
  if (typeof host !== 'string' || !host || host.length > 253 || /[\s\x00-\x1f\x7f/\\@?#%]/.test(host)) throw invalid();
  let normalized = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  if (net.isIP(normalized)) normalized = normalized.toLowerCase();
  else {
    normalized = domainToASCII(host).toLowerCase();
    if (!normalized || normalized.length > 253 || !/^[a-z\d.-]+$/.test(normalized)
      || normalized.split('.').some(label => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) throw invalid();
  }
  const numericPort = typeof port === 'string' && /^\d{1,5}$/.test(port) ? Number(port) : port;
  if (!Number.isInteger(numericPort) || numericPort < 1 || numericPort > 65535) throw invalid();
  return { host: normalized, port: numericPort };
}

export function validateSshProxyUrl(value) {
  try {
    if (typeof value !== 'string' || value.length > 8192 || /[\x00-\x20\x7f]/.test(value)) throw invalid();
    const url = new URL(value);
    const host = url.hostname.replace(/^\[|\]$/g, '');
    // Literal addresses avoid even a localhost lookup, and cannot be redirected
    // by DNS, /etc/hosts, proxy environment settings or a resolver hook.
    if (!['http:', 'https:'].includes(url.protocol) || !['127.0.0.1', '::1'].includes(host)
      || (url.pathname && url.pathname !== '/') || url.search || url.hash || !url.username || !url.password) throw invalid();
    const username = decodeURIComponent(url.username);
    const password = decodeURIComponent(url.password);
    if (!username || !password || username.includes(':') || /[\x00-\x1f\x7f]/.test(username + password)
      || Buffer.byteLength(username + password) > 4096) throw invalid();
    return {
      host,
      port: Number(url.port || (url.protocol === 'https:' ? 443 : 80)),
      secure: url.protocol === 'https:',
      authorization: `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`,
    };
  } catch { throw invalid(); }
}

function validateTargets(value) {
  if (!Array.isArray(value) || !value.length || value.length > MAX_TARGETS) throw invalid();
  return value.map(target => {
    if (!target || typeof target !== 'object' || Array.isArray(target)
      || Object.keys(target).some(key => !['host', 'port'].includes(key))) throw invalid();
    return validateSshTarget(target.host, target.port);
  });
}

/** The main process also fences writes to this file and its parent directories.
 * Owner-only permissions alone are not a security boundary against the owner. */
export async function readSshTargets(filePath) {
  let handle;
  try {
    if (typeof filePath !== 'string' || !path.isAbsolute(filePath) || filePath !== path.normalize(filePath)
      || filePath.length > 4096 || /[\x00-\x1f\x7f]/.test(filePath)) throw invalid();
    let current = path.parse(filePath).root;
    for (const component of filePath.slice(current.length).split(path.sep)) {
      current = path.join(current, component);
      const info = await lstat(current);
      if (info.isSymbolicLink()) throw invalid();
      if (current !== filePath && !info.isDirectory()) throw invalid();
    }
    const before = await lstat(filePath);
    if (!before.isFile() || before.size < 2 || before.size > MAX_TARGET_BYTES
      || (process.getuid && before.uid !== process.getuid()) || (before.mode & 0o177) !== 0
      || !(before.mode & 0o400) || before.nlink !== 1) throw invalid();
    handle = await open(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const after = await handle.stat();
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mode !== after.mode) throw invalid();
    // Bounded read prevents a concurrent growth race from allocating an
    // unbounded buffer; the protected runtime makes mutation unavailable.
    const buffer = Buffer.alloc(MAX_TARGET_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead !== before.size || bytesRead > MAX_TARGET_BYTES) throw invalid();
    return validateTargets(JSON.parse(buffer.subarray(0, bytesRead).toString('utf8')));
  } catch { throw invalid(); }
  finally { await handle?.close(); }
}

function responseStatus(header) {
  const lines = header.toString('latin1').split('\r\n');
  const match = /^HTTP\/1\.[01] ([1-5]\d\d)(?: [\x20-\x7e]*)?$/.exec(lines.shift());
  if (!match || lines.some(line => line && !/^[!#$%&'*+.^_`|~\da-z-]+:[\t\x20-\x7e\x80-\xff]*$/i.test(line))) {
    throw failure('SSH_PROXY_RESPONSE', 'SSH proxy returned an invalid response.');
  }
  return Number(match[1]);
}

/** Opaque TCP transport only: HTTP 200 does not prove an SSH handshake or login.
 * The destination name is sent to the proxy unchanged, never resolved locally. */
export async function runSshProxy({ host, port, proxyUrl, allowedTargets, input = process.stdin, output = process.stdout,
  signal, connectTimeoutMs = 10_000, maxHeaderBytes = 16 * 1024 } = {}) {
  const target = validateSshTarget(host, port);
  const targets = validateTargets(allowedTargets);
  if (!targets.some(allowed => allowed.host === target.host && allowed.port === target.port)) {
    throw failure('SSH_PROXY_TARGET_DENIED', 'This SSH destination is not authorized for this session.');
  }
  const proxy = validateSshProxyUrl(proxyUrl);
  if (!Number.isInteger(connectTimeoutMs) || connectTimeoutMs < 10 || connectTimeoutMs > 120_000
    || !Number.isInteger(maxHeaderBytes) || maxHeaderBytes < 256 || maxHeaderBytes > 64 * 1024
    || !input?.pipe || !input?.pause || !output?.write || !output?.end || output.destroyed || input.destroyed && !input.readableEnded) throw invalid();
  if (signal?.aborted) throw failure('SSH_PROXY_CANCELLED', 'SSH proxy connection was cancelled.');
  input.pause();
  return new Promise((resolve, reject) => {
    let socket;
    let buffer = Buffer.alloc(0);
    let connected = false;
    let settled = false;
    let timer;
    let ended = false;
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      input.off('error', onStreamError);
      output.off('error', onStreamError);
      output.off('close', onOutputClose);
      input.unpipe(socket);
      input.pause();
      socket?.unpipe(output);
      socket?.off('data', onData);
      socket?.destroy();
    };
    const finish = error => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else resolve();
    };
    const onAbort = () => finish(failure('SSH_PROXY_CANCELLED', 'SSH proxy connection was cancelled.'));
    const onStreamError = () => finish(failure('SSH_PROXY_IO', 'SSH proxy transport closed unexpectedly.'));
    const onOutputClose = () => { if (!ended) onStreamError(); };
    const onData = chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      const boundary = buffer.indexOf('\r\n\r\n');
      if (boundary < 0) {
        if (buffer.length > maxHeaderBytes) finish(failure('SSH_PROXY_RESPONSE', 'SSH proxy response exceeded its limit.'));
        return;
      }
      if (boundary + 4 > maxHeaderBytes) return finish(failure('SSH_PROXY_RESPONSE', 'SSH proxy response exceeded its limit.'));
      let status;
      try { status = responseStatus(buffer.subarray(0, boundary)); } catch (error) { finish(error); return; }
      if (status !== 200) {
        const message = status === 407 ? 'SSH proxy authentication was refused.'
          : status === 403 ? 'SSH proxy refused this destination.' : 'SSH proxy could not establish the tunnel.';
        return finish(failure(`SSH_PROXY_HTTP_${status}`, message));
      }
      connected = true;
      clearTimeout(timer);
      socket.pause();
      socket.off('data', onData);
      const head = buffer.subarray(boundary + 4);
      buffer = null;
      // unshift lets pipe enforce backpressure for bytes delivered in the same
      // packet as HTTP headers, preserving their order before subsequent data.
      if (head.length) socket.unshift(head);
      // pipe() deliberately does not end process.stdout. Close that direction
      // explicitly on remote FIN so OpenSSH observes EOF even while its input
      // side is still open; the independent input half may finish afterward.
      socket.pipe(output, { end: false });
      input.pipe(socket);
      if (input.readableEnded && !socket.writableEnded) socket.end();
    };
    const onConnect = () => {
      const authority = `${net.isIP(target.host) === 6 ? `[${target.host}]` : target.host}:${target.port}`;
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\nProxy-Authorization: ${proxy.authorization}\r\n\r\n`);
    };
    input.once('error', onStreamError);
    output.once('error', onStreamError);
    output.once('close', onOutputClose);
    signal?.addEventListener('abort', onAbort, { once: true });
    const options = { host: proxy.host, port: proxy.port, allowHalfOpen: true };
    // No custom resolver and no destination socket. HTTPS always verifies the
    // proxy certificate even if NODE_TLS_REJECT_UNAUTHORIZED was inherited.
    socket = proxy.secure ? tls.connect({ ...options, rejectUnauthorized: true }, onConnect) : net.connect(options, onConnect);
    socket.on('error', () => finish(failure('SSH_PROXY_CONNECT', 'SSH proxy connection failed.')));
    socket.on('data', onData);
    socket.once('end', () => {
      ended = true;
      if (!connected) return finish(failure('SSH_PROXY_RESPONSE', 'SSH proxy closed before establishing the tunnel.'));
      output.end();
    });
    socket.once('close', () => finish(connected && ended ? undefined : failure('SSH_PROXY_CONNECT', 'SSH proxy connection closed unexpectedly.')));
    timer = setTimeout(() => finish(failure('SSH_PROXY_TIMEOUT', 'SSH proxy connection timed out.')), connectTimeoutMs);
  });
}

export async function runSshProxyCli(argv = process.argv.slice(2), env = process.env) {
  let signalNumber = 0;
  const abort = new AbortController();
  const onTerm = () => { signalNumber = 143; abort.abort(); };
  const onInt = () => { signalNumber = 130; abort.abort(); };
  process.once('SIGTERM', onTerm);
  process.once('SIGINT', onInt);
  try {
    if (argv.length !== 4 || argv[0] !== '--host' || argv[2] !== '--port') throw invalid();
    const allowedTargets = await readSshTargets(env.ENVARA_SSH_TARGETS);
    await runSshProxy({ host: argv[1], port: argv[3], proxyUrl: env.ENVARA_SSH_PROXY_URL, allowedTargets, signal: abort.signal });
    return 0;
  } catch (error) {
    // Never include native socket errors, URLs, host names or credentials.
    const safe = /^SSH_PROXY_[A-Z_\d]+$/.test(error?.code ?? '') ? error.message : 'SSH proxy connection failed.';
    process.stderr.write(`Envara: ${safe.slice(0, 180)}\n`);
    return signalNumber || 1;
  } finally {
    process.off('SIGTERM', onTerm);
    process.off('SIGINT', onInt);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await runSshProxyCli();
}
