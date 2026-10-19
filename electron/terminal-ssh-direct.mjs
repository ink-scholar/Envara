// Session-scoped TCP capabilities for fixed, saved SSH endpoints. This is not
// a general proxy: the caller supplies an alias, never a destination or route.
import { createWriteStream } from 'node:fs';
import { chmod, lstat, realpath, unlink } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { validateSshTarget } from './terminal-ssh-proxy.mjs';

const MAX_HANDSHAKE_BYTES = 512, MAX_CLIENTS = 16, MAX_RUNS = 4;
const fail = (code = 'SSH_DIRECT_UNAVAILABLE') => Object.assign(new Error('The protected SSH direct transport is unavailable.'), { code });
const allowedCodes = new Set(['SSH_DIRECT_CONFIGURATION', 'SSH_DIRECT_UNAVAILABLE', 'SSH_DIRECT_AUTHORIZATION',
  'SSH_DIRECT_TIMEOUT', 'SSH_DIRECT_BUSY', 'SSH_DIRECT_CANCELLED', 'SSH_DIRECT_IO', 'SSH_DIRECT_CLEANUP_FAILED']);
const aliasValid = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(value);
const tokenValid = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const deadlineValid = value => Number.isInteger(value) && value >= 10 && value <= 120000;
const checkedPath = value => {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.normalize(value) !== value || /[\x00-\x1f\x7f]/.test(value))
    throw fail('SSH_DIRECT_CONFIGURATION');
  return value;
};
const sameFile = (first, second) => first.dev === second.dev && first.ino === second.ino;
async function checkedDirectory(directory) {
  checkedPath(directory);
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o077 ||
      process.getuid && info.uid !== process.getuid() || await realpath(directory) !== directory) throw fail('SSH_DIRECT_CONFIGURATION');
  return info;
}
async function checkedSocket(socket) {
  checkedPath(socket);
  if (path.basename(socket) !== 'transport.sock' || Buffer.byteLength(socket) > 100) throw fail('SSH_DIRECT_CONFIGURATION');
  await checkedDirectory(path.dirname(socket));
  const info = await lstat(socket);
  if (!info.isSocket() || info.isSymbolicLink() || info.mode & 0o077 || process.getuid && info.uid !== process.getuid())
    throw fail('SSH_DIRECT_CONFIGURATION');
  return info;
}
function bounded(promise, milliseconds) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(fail('SSH_DIRECT_CLEANUP_FAILED')), Math.max(1, milliseconds));
    Promise.resolve(promise).then(value => { clearTimeout(timer); resolve(value); }, error => { clearTimeout(timer); reject(error); });
  });
}

export async function createSshDirectTransport({ directory, connections, isActive, connect = net.connect,
  connectTimeoutMs = 10000, handshakeTimeoutMs = 10000, cleanupTimeoutMs = 2000 } = {}) {
  const targets = new Map();
  let directoryIdentity;
  try {
    if (!Array.isArray(connections) || connections.length > 20 || typeof isActive !== 'function' || typeof connect !== 'function' ||
        ![connectTimeoutMs, handshakeTimeoutMs, cleanupTimeoutMs].every(deadlineValid)) throw fail('SSH_DIRECT_CONFIGURATION');
    directoryIdentity = await checkedDirectory(directory);
    for (const record of connections) {
      if (!exact(record, ['alias', 'host', 'port']) || !aliasValid(record.alias) || targets.has(record.alias)) throw fail('SSH_DIRECT_CONFIGURATION');
      targets.set(record.alias, validateSshTarget(record.host, record.port));
    }
  } catch { throw fail('SSH_DIRECT_CONFIGURATION'); }
  const socket = path.join(directory, 'transport.sock');
  if (Buffer.byteLength(socket) > 100) throw fail('SSH_DIRECT_CONFIGURATION');
  try { await lstat(socket); throw fail('SSH_DIRECT_CONFIGURATION'); }
  catch (error) { if (error.code !== 'ENOENT') throw fail('SSH_DIRECT_CONFIGURATION'); }
  const token = randomBytes(32).toString('hex'), tokenBytes = Buffer.from(token, 'hex');
  const states = new Set(), owned = new Map(), openings = new Set();
  let server, socketIdentity, closed = false, cleanup = null, sweep;
  const active = alias => { try { return !closed && targets.has(alias) && isActive(alias) === true; } catch { return false; } };
  const track = stream => {
    if (!stream || typeof stream.destroy !== 'function' || typeof stream.once !== 'function' || typeof stream.pipe !== 'function' ||
        typeof stream.pause !== 'function' || typeof stream.write !== 'function' || typeof stream.end !== 'function') throw fail();
    if (owned.has(stream) || stream.closed === true) return stream;
    owned.set(stream, new Promise(resolve => stream.once('close', () => { owned.delete(stream); resolve(); })));
    stream.on('error', () => {});
    if (closed) stream.destroy();
    return stream;
  };
  const stop = state => {
    clearTimeout(state.handshakeTimer); clearTimeout(state.connectTimer);
    state.stopped = true; state.client.destroy(); state.upstream?.destroy();
    if (!state.opening && (!state.upstream || state.upstream.closed === true)) states.delete(state);
  };
  const refuse = state => {
    clearTimeout(state.handshakeTimer); clearTimeout(state.connectTimer); state.stopped = true;
    state.upstream?.destroy();
    if (!state.client.destroyed) state.client.end('{"ok":false}\n', () => state.client.destroy());
  };
  const checkOwnedPath = async () => {
    if (!sameFile(directoryIdentity, await checkedDirectory(directory))) throw fail('SSH_DIRECT_CLEANUP_FAILED');
    let info;
    try { info = await lstat(socket); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    if (!socketIdentity || !info.isSocket() || info.isSymbolicLink() || !sameFile(info, socketIdentity)) throw fail('SSH_DIRECT_CLEANUP_FAILED');
    return info;
  };
  const dispose = () => {
    closed = true; clearInterval(sweep); tokenBytes.fill(0);
    for (const state of states) stop(state);
    for (const stream of owned.keys()) stream.destroy();
    if (cleanup) return cleanup;
    cleanup = (async () => {
      const deadline = Date.now() + cleanupTimeoutMs;
      // A delayed injected connector can return a socket after cancellation.
      // Its continuation retains and destroys it before cleanup can succeed.
      while (openings.size) await bounded(Promise.allSettled([...openings]), deadline - Date.now());
      while (owned.size) await bounded(Promise.allSettled([...owned.values()]), deadline - Date.now());
      // Node removes its Unix socket during server.close. Refuse that call if
      // someone replaced the path, rather than unlink an unrelated file.
      await checkOwnedPath();
      if (server?.listening) await bounded(new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())), deadline - Date.now());
      const remaining = await checkOwnedPath();
      if (remaining) await unlink(socket);
    })().catch(() => { cleanup = null; throw fail('SSH_DIRECT_CLEANUP_FAILED'); });
    return cleanup;
  };
  try {
    server = net.createServer({ allowHalfOpen: true }, client => {
      client.on('error', () => {});
      if (closed || states.size >= MAX_CLIENTS) { client.destroy(); return; }
      const state = { client: track(client), upstream: null, opening: null, alias: null, stopped: false,
        clientEnded: false, upstreamEnded: false, clientClosed: false, upstreamClosed: false, buffer: Buffer.alloc(0) };
      states.add(state);
      client.once('end', () => { state.clientEnded = true; });
      client.once('close', () => {
        state.clientClosed = true; clearTimeout(state.handshakeTimer);
        if (!state.clientEnded || !state.upstreamEnded) { state.stopped = true; state.upstream?.destroy(); }
        if (!state.opening && (!state.upstream || state.upstreamClosed)) states.delete(state);
      });
      state.handshakeTimer = setTimeout(() => stop(state), handshakeTimeoutMs);
      client.on('data', function handshake(chunk) {
        state.buffer = Buffer.concat([state.buffer, chunk]);
        const boundary = state.buffer.indexOf(10);
        if (boundary < 0) { if (state.buffer.length > MAX_HANDSHAKE_BYTES) stop(state); return; }
        client.pause(); client.off('data', handshake); clearTimeout(state.handshakeTimer);
        if (boundary > MAX_HANDSHAKE_BYTES) { stop(state); return; }
        let frame;
        try { frame = JSON.parse(state.buffer.subarray(0, boundary).toString('utf8')); } catch { refuse(state); return; }
        const head = state.buffer.subarray(boundary + 1); state.buffer = null;
        if (!exact(frame, ['version', 'token', 'alias']) || frame.version !== 1 || !tokenValid(frame.token) || !aliasValid(frame.alias) ||
            !timingSafeEqual(Buffer.from(frame.token, 'hex'), tokenBytes) || !active(frame.alias) ||
            [...states].filter(other => other.alias && !other.stopped).length >= MAX_RUNS) { refuse(state); return; }
        state.alias = frame.alias;
        state.connectTimer = setTimeout(() => stop(state), connectTimeoutMs);
        const opening = Promise.resolve().then(() => {
          if (state.stopped || !active(state.alias)) throw fail('SSH_DIRECT_AUTHORIZATION');
          const target = targets.get(state.alias);
          return connect({ host: target.host, port: target.port, allowHalfOpen: true });
        }).then(upstream => {
          state.upstream = track(upstream);
          const onConnected = () => {
            clearTimeout(state.connectTimer);
            if (state.stopped || client.destroyed || !active(state.alias)) { stop(state); return; }
            client.write('{"ok":true}\n');
            if (head.length) client.unshift(head);
            // Independent FINs and native pipe backpressure preserve both
            // directions, including bytes sent after the other peer's EOF.
            client.pipe(upstream); upstream.pipe(client);
          };
          upstream.once('end', () => { state.upstreamEnded = true; });
          upstream.once('error', () => stop(state));
          upstream.once('close', () => {
            state.upstreamClosed = true;
            if (!state.upstreamEnded || !state.clientEnded) client.destroy();
            if (state.clientClosed && !state.opening) states.delete(state);
          });
          if (state.stopped || closed || client.destroyed) { upstream.destroy(); return; }
          if (upstream.connecting === false && upstream.remoteAddress) onConnected();
          else upstream.once('connect', onConnected);
        }).catch(() => stop(state)).finally(() => {
          openings.delete(opening); state.opening = null;
          if (state.clientClosed && (!state.upstream || state.upstreamClosed || state.upstream.closed === true)) states.delete(state);
        });
        state.opening = opening; openings.add(opening);
      });
    });
    await new Promise((resolve, reject) => {
      const failed = () => { server.off('listening', ready); reject(fail()); };
      const ready = () => { server.off('error', failed); resolve(); };
      server.once('error', failed); server.once('listening', ready); server.listen(socket);
    });
    socketIdentity = await lstat(socket);
    if (!socketIdentity.isSocket() || socketIdentity.isSymbolicLink() || process.getuid && socketIdentity.uid !== process.getuid()) throw fail();
    await chmod(socket, 0o600);
    if (!sameFile(socketIdentity, await checkedSocket(socket))) throw fail();
    server.on('error', () => { void dispose().catch(() => {}); });
    sweep = setInterval(() => {
      for (const state of states) if (state.alias ? !active(state.alias) : ![...targets.keys()].some(active)) stop(state);
    }, 100); sweep.unref();
    return { socket, token, dispose };
  } catch {
    const error = fail();
    // A failed bind never owns another process's existing path.
    if (!socketIdentity && !server?.listening) throw error;
    try { await dispose(); } catch { error.sshCleanup = dispose; }
    throw error;
  }
}

export async function runSshDirect({ alias, socket, token, input = process.stdin, output = process.stdout,
  signal, connectTimeoutMs = 10000 } = {}) {
  try {
    if (!aliasValid(alias) || !tokenValid(token) || !deadlineValid(connectTimeoutMs) || !input?.pipe || !input?.pause ||
        !output?.write || !output?.end || output.destroyed || input.destroyed && !input.readableEnded) throw fail('SSH_DIRECT_CONFIGURATION');
    if (signal?.aborted) throw fail('SSH_DIRECT_CANCELLED');
    await checkedSocket(socket);
  } catch (error) { throw fail(allowedCodes.has(error.code) ? error.code : 'SSH_DIRECT_CONFIGURATION'); }
  input.pause();
  return new Promise((resolve, reject) => {
    let channel, buffer = Buffer.alloc(0), connected = false, settled = false, ended = false, transportClosed = false;
    const cleanup = () => {
      clearTimeout(timer); signal?.removeEventListener('abort', onAbort);
      input.off('error', onStreamError); input.off('end', onInputEnd); input.unpipe(channel); input.pause();
      output.off('error', onStreamError); output.off('close', onOutputClose); output.off('finish', onOutputFinish);
      channel?.unpipe(output); channel?.destroy();
    };
    const finish = error => { if (settled) return; settled = true; cleanup(); error ? reject(error) : resolve(); };
    const onAbort = () => finish(fail('SSH_DIRECT_CANCELLED'));
    const onStreamError = () => finish(fail('SSH_DIRECT_IO'));
    const onInputEnd = () => { if (connected && !channel.writableEnded) channel.end(); };
    const onOutputClose = () => { if (!ended || !output.writableFinished) onStreamError(); };
    const onOutputFinish = () => { if (transportClosed) finish(); };
    const onData = chunk => {
      buffer = Buffer.concat([buffer, chunk]); const boundary = buffer.indexOf(10);
      if (boundary < 0) { if (buffer.length > MAX_HANDSHAKE_BYTES) finish(fail('SSH_DIRECT_AUTHORIZATION')); return; }
      if (boundary > MAX_HANDSHAKE_BYTES) { finish(fail('SSH_DIRECT_AUTHORIZATION')); return; }
      let reply;
      try { reply = JSON.parse(buffer.subarray(0, boundary).toString('utf8')); } catch { finish(fail('SSH_DIRECT_AUTHORIZATION')); return; }
      if (!exact(reply, ['ok']) || reply.ok !== true) { finish(fail('SSH_DIRECT_AUTHORIZATION')); return; }
      connected = true; clearTimeout(timer); channel.pause(); channel.off('data', onData);
      const head = buffer.subarray(boundary + 1); buffer = null;
      if (head.length) channel.unshift(head);
      channel.pipe(output, { end: false }); input.pipe(channel, { end: false });
      if (input.readableEnded) onInputEnd();
    };
    const timer = setTimeout(() => finish(fail('SSH_DIRECT_TIMEOUT')), connectTimeoutMs);
    input.once('error', onStreamError); input.once('end', onInputEnd);
    output.once('error', onStreamError); output.once('close', onOutputClose); output.once('finish', onOutputFinish);
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) { onAbort(); return; }
    try {
      channel = net.connect({ path: socket, allowHalfOpen: true });
      channel.once('connect', () => channel.write(JSON.stringify({ version: 1, token, alias }) + '\n'));
      channel.on('error', onStreamError); channel.on('data', onData);
      channel.once('end', () => { ended = true; if (!connected) finish(fail('SSH_DIRECT_AUTHORIZATION')); else output.end(); });
      channel.once('close', () => {
        if (!connected || !ended) { finish(fail('SSH_DIRECT_IO')); return; }
        transportClosed = true; if (output.writableFinished) finish();
      });
    } catch { finish(fail()); }
  });
}

export async function runSshDirectCli(argv = process.argv.slice(2), environment = process.env,
  { input = process.stdin, output = process.stdout, errorOutput = process.stderr } = {}) {
  let signalNumber = 0;
  const controller = new AbortController();
  const term = () => { signalNumber = 143; controller.abort(); }, interrupt = () => { signalNumber = 130; controller.abort(); };
  process.once('SIGTERM', term); process.once('SIGINT', interrupt);
  try {
    if (argv.length !== 2 || argv[0] !== '--alias') throw fail('SSH_DIRECT_CONFIGURATION');
    await runSshDirect({ alias: argv[1], socket: environment.ENVARA_SSH_DIRECT_SOCKET,
      token: environment.ENVARA_SSH_DIRECT_TOKEN, input, output, signal: controller.signal });
    return 0;
  } catch (error) {
    const code = allowedCodes.has(error?.code) ? error.code : 'SSH_DIRECT_UNAVAILABLE';
    errorOutput.write(`Envara SSH [${code}]: The protected SSH direct transport is unavailable.\n`);
    return signalNumber || 1;
  } finally { process.off('SIGTERM', term); process.off('SIGINT', interrupt); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  void process.stderr;
  const output = createWriteStream(null, { fd: 1, autoClose: true }); output.on('error', () => {});
  let exitCode = 1;
  try { process.exitCode = exitCode = await runSshDirectCli(undefined, undefined, { output }); }
  finally { output.destroy(); if (exitCode !== 0) setTimeout(() => process.kill(process.pid, 'SIGTERM'), 1000).unref(); }
}
