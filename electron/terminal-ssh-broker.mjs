import net from 'node:net';
import path from 'node:path';
import { spawn as spawnChild } from 'node:child_process';
import { createRequire } from 'node:module';
import { StringDecoder } from 'node:string_decoder';
import { randomBytes } from 'node:crypto';
import { write as writeDescriptor } from 'node:fs';
import { chmod, lstat, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { TerminalNetworkFence } from './terminal-network-fence.mjs';
import { captureTerminalProcess, closeTerminalProcess } from './terminal-process.mjs';
import { describeSshSession, parseSshInvocation } from './terminal-ssh-command.mjs';
import { validateSshProxyUrl } from './terminal-ssh-proxy.mjs';

const require = createRequire(import.meta.url);
const defaultPtyFactory = (file, args, options) => require('node-pty').spawn(file, args, options);
// Capture the authored helper while the application loads, before terminals
// receive filesystem access. Runtime instances never reread mutable source.
const askpassSource = readFile(new URL('./terminal-ssh-askpass.mjs', import.meta.url), 'utf8');
const nativePtyWrite = (fd, buffer, offset) => new Promise((resolve, reject) =>
  writeDescriptor(fd, buffer, offset, buffer.length - offset, null, (error, written) => error ? reject(error) : resolve(written)));
const MAX_LINE = 128 * 1024, MAX_CHUNK = 48 * 1024, MAX_BUFFER = 1024 * 1024, MAX_RUNS = 4, MAX_CLIENTS = 16;
const fail = (code = 'SSH_BROKER_UNAVAILABLE') => Object.assign(new Error('The protected SSH password connection is unavailable.'), { code });
const allowedErrors = new Set(['SSH_BROKER_INVALID', 'SSH_BROKER_UNAVAILABLE', 'SSH_BROKER_BUSY', 'SSH_AUTHORIZATION_EXPIRED',
  'SSH_TARGET_NOT_AUTHORIZED', 'SSH_OPTIONS_UNSUPPORTED', 'SSH_ARGUMENT_INVALID', 'SSH_TARGET_AMBIGUOUS', 'SSH_BROKER_CLEANUP_FAILED']);
const checkedPath = value => {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.normalize(value) !== value || /[\x00-\x1f\x7f]/.test(value)) throw fail('SSH_BROKER_INVALID');
  return value;
};
const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
const fields = (value, names) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).every(key => names.includes(key));
const size = value => Number.isSafeInteger(value) && value >= 1 && value <= 1000;
const base64 = value => {
  if (typeof value !== 'string' || value.length > MAX_CHUNK * 4 / 3 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw fail('SSH_BROKER_INVALID');
  const result = Buffer.from(value, 'base64');
  if (result.length > MAX_CHUNK || result.toString('base64') !== value) throw fail('SSH_BROKER_INVALID');
  return result;
};
async function safePath(filename, directory = false, executable = false) {
  const info = await lstat(filename);
  if (info.isSymbolicLink() || await realpath(filename) !== filename || (directory ? !info.isDirectory() : !info.isFile())
    || process.getuid && info.uid !== process.getuid() && !(executable && info.uid === 0)
    || info.mode & 0o022 || executable && !(info.mode & 0o111) || !directory && !executable && info.nlink !== 1) throw fail('SSH_BROKER_INVALID');
  return info;
}
function closeServer(server) {
  if (!server?.listening) return Promise.resolve();
  return new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
async function listen(server, socket) {
  await new Promise((resolve, reject) => {
    const error = value => { server.off('listening', ready); reject(value); };
    const ready = () => { server.off('error', error); resolve(); };
    server.once('error', error); server.once('listening', ready); server.listen(socket);
  });
  await chmod(socket, 0o600);
}

/** Public IPC grants use of one fixed session, never retrieval of credentials.
 * The separate askpass socket is denied to every terminal process tree. Only
 * the main-owned SSH tree receives a fence exception and a one-use capability.
 * Like the terminal key guard, this is not isolation from unrelated same-UID
 * host processes outside Envara's sandbox. */
export async function createPasswordSshBroker({ directory, publicDirectory, nodeExecutable, configPath, proxyUrl, targetsPath,
  manifest, passwords, now = Date.now, expiresAt, isActive, fence = new TerminalNetworkFence(), spawn = spawnChild,
  runtimeReadOnlyPaths = [], ptyFactory = defaultPtyFactory, writePty = nativePtyWrite, monotonicNow = () => performance.now(),
  processControl = { capture: captureTerminalProcess, close: closeTerminalProcess } } = {}) {
  [directory, publicDirectory, nodeExecutable, configPath, targetsPath].forEach(checkedPath);
  if (!Array.isArray(runtimeReadOnlyPaths) || runtimeReadOnlyPaths.length > 64) throw fail('SSH_BROKER_INVALID');
  runtimeReadOnlyPaths.forEach(checkedPath);
  if (publicDirectory !== path.join(directory, 'public') || !configPath.startsWith(`${publicDirectory}/`)
    || !targetsPath.startsWith(`${publicDirectory}/`) || typeof now !== 'function' || typeof monotonicNow !== 'function' || typeof isActive !== 'function'
    || !(passwords instanceof Map) || !passwords.size || passwords.size > 20) throw fail('SSH_BROKER_INVALID');
  const createdAt = now(), monotonicStart = monotonicNow();
  if (!Number.isFinite(monotonicStart)) throw fail('SSH_BROKER_INVALID');
  const description = describeSshSession(structuredClone(manifest), createdAt);
  if (description.status !== 'ready') throw fail('SSH_AUTHORIZATION_EXPIRED');
  const fixedManifest = { schema: description.schema, version: description.version,
    expiresAt: description.expiresAt, connections: description.connections };
  const authorizations = new Map();
  for (const alias of passwords.keys()) {
    const record = description.connections.find(value => value.alias === alias);
    if (!record || description.version !== 1 && record.authType !== 'password') throw fail('SSH_BROKER_INVALID');
    const deadline = description.version === 1 ? description.expiresAt : record.expiresAt;
    const remaining = deadline === null ? null : deadline - createdAt;
    const hardDeadline = remaining === null ? null : monotonicStart + Math.max(0, remaining);
    if (remaining !== null && (remaining > 86400000 || !Number.isFinite(hardDeadline))) throw fail('SSH_BROKER_INVALID');
    authorizations.set(alias, { expiresAt: deadline, hardDeadline, expired: false });
  }
  // Public-key leases never shorten or extend password authorization. Within
  // this broker each password retains its own deadline even if another is
  // authorized for the application's lifetime.
  const deadlines = [...authorizations.values()].map(value => value.expiresAt);
  const passwordExpiry = deadlines.includes(null) ? null : Math.max(...deadlines);
  if (expiresAt !== passwordExpiry) throw fail('SSH_AUTHORIZATION_EXPIRED');
  const route = validateSshProxyUrl(proxyUrl), agentRoot = path.dirname(directory);
  const applicationRoot = filename => /^(.+?\.app)(?:\/|$)/.exec(filename)?.[1] ?? filename;
  const executionReadOnlyPaths = [...new Set([directory, path.dirname(nodeExecutable), path.dirname(fileURLToPath(import.meta.url)),
    ...runtimeReadOnlyPaths].map(applicationRoot))];
  const socket = path.join(directory, 'command.sock'), authSocket = path.join(directory, 'auth.sock');
  if ([socket, authSocket].some(value => Buffer.byteLength(value) > 100)) throw fail('SSH_BROKER_INVALID');
  await safePath(directory, true); await safePath(publicDirectory, true);
  await safePath(nodeExecutable, false, true);
  await Promise.all([configPath, targetsPath].map(value => safePath(value)));
  const secrets = new Map();
  try {
    for (const [alias, password] of passwords) {
      if (!Buffer.isBuffer(password)
        || password.length < 1 || password.length > 4096 || password.includes(0) || password.includes(10) || password.includes(13)) throw fail('SSH_BROKER_INVALID');
      secrets.set(alias, Buffer.from(password));
    }
  } catch (error) { for (const value of secrets.values()) value.fill(0); throw error; }
  const clients = new Set(), authClients = new Set(), runs = new Set(), grants = new Map(), ownedFiles = [];
  let closed = false, commandServer, authServer, sweep, cleanup = null;
  const live = () => {
    if (closed) return false;
    try { return isActive() === true; } catch { return false; }
  };
  const assertLive = () => { if (!live()) throw fail(); };
  const expireAuthorization = alias => {
    authorizations.get(alias).expired = true;
    secrets.get(alias)?.fill(0); secrets.delete(alias);
    for (const [token, grant] of grants) if (grant.alias === alias) grants.delete(token);
    for (const client of authClients) if (!client.sshGrant || client.sshGrant.alias === alias) client.destroy();
  };
  const authorizationAvailable = alias => {
    const authorization = authorizations.get(alias);
    if (!authorization || authorization.expired) return false;
    if (authorization.expiresAt !== null) {
      const wall = now(), monotonic = monotonicNow();
      if (!Number.isFinite(wall) || !Number.isFinite(monotonic)
        || wall >= authorization.expiresAt || monotonic >= authorization.hardDeadline) {
        expireAuthorization(alias); return false;
      }
    }
    return true;
  };
  const assertAuthorization = alias => {
    assertLive(); if (!authorizationAvailable(alias)) throw fail('SSH_AUTHORIZATION_EXPIRED');
  };
  const grantAvailable = grant => {
    const wall = now(), monotonic = monotonicNow();
    if (!Number.isFinite(wall) || !Number.isFinite(monotonic)
      || wall >= grant.expiresAt || monotonic >= grant.hardDeadline) grant.expired = true;
    return !grant.expired;
  };
  const send = (client, frame) => {
    if (client.destroyed) return false;
    const line = `${JSON.stringify(frame)}\n`;
    if (Buffer.byteLength(line) > MAX_LINE || client.writableLength + Buffer.byteLength(line) > MAX_BUFFER) throw fail('SSH_BROKER_INVALID');
    return client.write(line);
  };
  const errorFrame = (client, error) => {
    try { send(client, { type: 'error', code: allowedErrors.has(error?.code) ? error.code : 'SSH_BROKER_UNAVAILABLE' }); client.end(); }
    catch { client.destroy(); }
  };
  const pauseOutput = run => {
    run.process?.stdout?.pause(); run.process?.stderr?.pause(); if (run.tty) run.process?.pause?.();
  };
  const resumeOutput = run => {
    run.process?.stdout?.resume(); run.process?.stderr?.resume(); if (run.tty) run.process?.resume?.();
  };
  const ptyInput = async (run, buffer) => {
    // node-pty's write() queues without a drain or size bound. Its macOS fd
    // getter lets this broker serialize native writes under the IPC queue cap.
    // No input is submitted to that unbounded node-pty queue.
    const fd = run.process?.fd;
    if (!Number.isInteger(fd) || fd < 3) throw fail();
    for (let offset = 0; offset < buffer.length;) {
      assertLive(); if (run.cancelled || run.exited) throw fail();
      try {
        const written = await writePty(fd, buffer, offset);
        if (!Number.isInteger(written) || written < 1 || written > buffer.length - offset) throw fail();
        offset += written;
      } catch (error) {
        if (error.code !== 'EAGAIN' && error.code !== 'EINTR') throw fail();
        await delay(5);
      }
    }
  };
  async function stopRun(run) {
    run.cancelled = true; grants.delete(run.token);
    if (run.stopping) return run.stopping;
    run.stopping = (async () => {
      await run.starting?.catch(() => {});
      if (!run.process) { runs.delete(run); return; }
      if (run.capture) await run.capture.catch(() => {});
      if (run.identity) {
        const result = await processControl.close({ pty: run.process, identity: run.identity });
        if (result?.ok !== true) throw fail('SSH_BROKER_CLEANUP_FAILED');
      } else if (!run.exited) {
        // Password delivery waits for identity capture. Without that capture,
        // only the direct child handle remains safe to signal.
        try { run.process.kill('SIGKILL'); } catch {}
        let timeout;
        await Promise.race([run.exitPromise, new Promise(resolve => { timeout = setTimeout(resolve, 1000); })]);
        clearTimeout(timeout);
        if (!run.exited) throw fail('SSH_BROKER_CLEANUP_FAILED');
      }
      runs.delete(run);
    })();
    try { await run.stopping; } catch (error) { run.stopping = null; throw error; }
  }
  const abandon = (run, error = fail()) => {
    run.cancelled = true; errorFrame(run.client, error);
    void stopRun(run).catch(() => {});
  };
  async function start(client, frame) {
    assertLive();
    if (!fields(frame, ['type', 'version', 'argv', 'tty', 'cols', 'rows']) || frame.version !== 1 || typeof frame.tty !== 'boolean'
      || !size(frame.cols) || !size(frame.rows)) throw fail('SSH_BROKER_INVALID');
    const invocation = parseSshInvocation(frame.argv, { connections: fixedManifest.connections, entry: 'ssh' });
    if (invocation.kind !== 'connect' || !authorizations.has(invocation.alias)) throw fail('SSH_TARGET_NOT_AUTHORIZED');
    assertAuthorization(invocation.alias);
    if (runs.size >= MAX_RUNS) throw fail('SSH_BROKER_BUSY');
    const tty = !invocation.flags.includes('-T') && (invocation.flags.includes('-t') || frame.tty && !invocation.command.length);
    let exitResolve;
    const run = { client, invocation, tty, process: null, identity: null, capture: null, starting: null,
      cancelled: false, exited: false, completed: false, stopping: null, token: randomBytes(32).toString('hex'),
      exitPromise: new Promise(resolve => { exitResolve = resolve; }) };
    runs.add(run); client.run = run;
    const output = (type, value) => {
      if (run.cancelled || client.destroyed) return;
      const data = Buffer.isBuffer(value) ? value : Buffer.from(value);
      try {
        for (let offset = 0; offset < data.length; offset += MAX_CHUNK) {
          if (!send(client, { type, data: data.subarray(offset, offset + MAX_CHUNK).toString('base64') })) pauseOutput(run);
        }
      } catch (error) { abandon(run, error); }
    };
    const exit = (code, signal) => {
      if (run.exited) return;
      run.exited = true; grants.delete(run.token); exitResolve();
      // Waiting for startup preserves ready-before-output/exit ordering.
      void Promise.resolve().then(async () => {
        await run.starting?.catch(() => {});
        try { await stopRun(run); }
        catch (error) { errorFrame(client, error); return; }
        if (!run.cancelledByClient && !client.destroyed) {
          run.completed = true;
          try { send(client, { type: 'exit', code: Number.isInteger(code) && code >= 0 && code <= 255 ? code : 255,
            ...(typeof signal === 'string' ? { signal } : {}) }); client.end(); } catch { client.destroy(); }
        }
      });
    };
    run.starting = (async () => {
      const args = ['-F', configPath, ...[
        'PreferredAuthentications=password', 'PasswordAuthentication=yes', 'KbdInteractiveAuthentication=no',
        'PubkeyAuthentication=no', 'IdentityAgent=none', 'IdentityFile=none', 'HostbasedAuthentication=no', 'GSSAPIAuthentication=no',
        'BatchMode=no', 'NumberOfPasswordPrompts=1', 'StrictHostKeyChecking=yes', 'UpdateHostKeys=no', 'VerifyHostKeyDNS=no',
        'PermitLocalCommand=no', 'EnableEscapeCommandline=no', 'EscapeChar=none', 'ForwardAgent=no', 'ForwardX11=no',
        'ClearAllForwardings=yes', 'ControlMaster=no', 'ControlPath=none', 'ControlPersist=no',
      ].flatMap(value => ['-o', value]), ...invocation.flags.filter(value => value !== '-T' && value !== '-t'),
      tty ? '-tt' : '-T', '--', invocation.alias, ...invocation.command];
      const environment = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: publicDirectory, LANG: 'C', LC_ALL: 'C', TERM: 'xterm-256color',
        SSH_ASKPASS_REQUIRE: 'force', SSH_ASKPASS: path.join(directory, 'askpass'),
        ENVARA_SSH_ASKPASS_SOCKET: authSocket, ENVARA_SSH_ASKPASS_TOKEN: run.token,
        ENVARA_SSH_PROXY_URL: proxyUrl, ENVARA_SSH_TARGETS: targetsPath };
      const wrapped = await fence.wrap({ executable: '/usr/bin/ssh', args, environment }, { routePort: route.port,
        restrictDeviceIdentifiers: true, sshProtection: { protectedPaths: [agentRoot], readablePaths: [directory],
          readOnlyPaths: executionReadOnlyPaths, agentRoot, agentSocket: null, allowedSockets: [authSocket] } });
      assertAuthorization(invocation.alias); if (run.cancelled) throw fail();
      if (wrapped.sshPrivateKeyProtection !== true || wrapped.deviceIdentifierRestrictions !== true) throw fail();
      const grant = { run, alias: invocation.alias, expiresAt: now() + 30000, hardDeadline: monotonicNow() + 30000,
        expired: false, used: false };
      if (!Number.isFinite(grant.expiresAt) || !Number.isFinite(grant.hardDeadline)) throw fail();
      grants.set(run.token, grant);
      if (tty) {
        run.process = await ptyFactory(wrapped.executable, wrapped.args, { name: 'xterm-256color', cols: frame.cols, rows: frame.rows,
          cwd: publicDirectory, env: wrapped.environment, encoding: null, handleFlowControl: false });
        run.process.onData(value => output('stdout', value));
        run.process.onExit(event => exit(event.exitCode, event.signal ? String(event.signal) : undefined));
      } else {
        run.process = spawn(wrapped.executable, wrapped.args, { cwd: publicDirectory, env: wrapped.environment,
          stdio: ['pipe', 'pipe', 'pipe'], detached: true, windowsHide: true });
        run.process.stdout.on('data', value => output('stdout', value));
        run.process.stderr.on('data', value => output('stderr', value));
        run.process.stdin.on('error', () => {});
        run.process.once('error', () => abandon(run));
        run.process.once('close', exit);
      }
      pauseOutput(run);
      run.capture = Promise.resolve().then(() => processControl.capture(run.process.pid)).then(identity => { run.identity = identity; });
      await run.capture;
      assertAuthorization(invocation.alias); if (run.cancelled || client.destroyed) throw fail();
      run.ready = true; send(client, { type: 'ready' }); resumeOutput(run);
    })();
    try { await run.starting; } catch (error) { abandon(run, error); }
    return run;
  }
  const dispose = async () => {
    closed = true; clearInterval(sweep); grants.clear(); for (const secret of secrets.values()) secret.fill(0); secrets.clear();
    if (cleanup) return cleanup;
    cleanup = (async () => {
      for (const client of [...clients, ...authClients]) client.destroy();
      const results = await Promise.allSettled([...runs].map(stopRun));
      await Promise.all([closeServer(commandServer), closeServer(authServer)]);
      if (results.some(result => result.status === 'rejected')) throw fail('SSH_BROKER_CLEANUP_FAILED');
      for (const file of ownedFiles) await rm(file, { force: true });
    })();
    try { await cleanup; } catch (error) { cleanup = null; throw error; }
  };
  try {
    const helper = path.join(directory, 'terminal-ssh-askpass.mjs'), launcher = path.join(directory, 'askpass');
    await writeFile(helper, await askpassSource, { mode: 0o400, flag: 'wx' }); ownedFiles.push(helper);
    await writeFile(launcher, `#!/bin/sh\nexec ${quote(nodeExecutable)} ${quote(helper)} "$@"\n`, { mode: 0o500, flag: 'wx' }); ownedFiles.push(launcher);
    authServer = net.createServer(client => {
      if (!live() || authClients.size >= MAX_RUNS) { client.destroy(); return; }
      authClients.add(client); let buffer = '', consumed = false;
      client.setTimeout(5000, () => client.destroy()); client.on('error', () => {});
      client.once('close', () => authClients.delete(client));
      client.on('data', chunk => {
        if (consumed) { client.destroy(); return; }
        buffer += chunk.toString('utf8');
        if (Buffer.byteLength(buffer) > 256) { client.destroy(); return; }
        if (!buffer.includes('\n')) return;
        consumed = true;
        void (async () => {
          let request;
          try { request = JSON.parse(buffer.trim()); } catch { client.destroy(); return; }
          if (!fields(request, ['version', 'token']) || request.version !== 1 || typeof request.token !== 'string' || !/^[a-f0-9]{64}$/.test(request.token)) { client.destroy(); return; }
          const grant = grants.get(request.token);
          if (!grant || grant.used || !grantAvailable(grant)) { client.destroy(); return; }
          assertAuthorization(grant.alias); client.sshGrant = grant;
          grant.used = true; grants.delete(request.token);
          await grant.run.capture?.catch(() => {});
          assertAuthorization(grant.alias);
          if (!grantAvailable(grant) || !grant.run.identity || grant.run.cancelled || grant.run.exited || client.destroyed) { client.destroy(); return; }
          const secret = secrets.get(grant.alias);
          if (!secret) { client.destroy(); return; }
          const response = Buffer.concat([secret, Buffer.from('\n')]);
          client.end(response, () => response.fill(0));
        })().catch(() => client.destroy());
      });
    });
    await listen(authServer, authSocket); ownedFiles.push(authSocket);
    commandServer = net.createServer(client => {
      if (!live() || clients.size >= MAX_CLIENTS) { client.destroy(); return; }
      clients.add(client); const decoder = new StringDecoder('utf8');
      let buffer = '', started = false, chain = Promise.resolve(), queued = 0, queuedFrames = 0;
      const timer = setTimeout(() => { if (!started) client.destroy(); }, 10000);
      client.on('error', () => {}); client.on('drain', () => { if (client.run?.ready) resumeOutput(client.run); });
      client.once('close', () => {
        clearTimeout(timer); clients.delete(client);
        if (client.run && !client.run.completed) { client.run.cancelledByClient = true; void stopRun(client.run).catch(() => {}); }
      });
      const cancel = async run => {
        if (run.cancelledByClient) return;
        run.cancelledByClient = true;
        try {
          await stopRun(run);
          if (!client.destroyed) { send(client, { type: 'exit', code: 255 }); client.end(); }
        } catch (error) { abandon(run, error); }
      };
      client.on('data', chunk => {
        buffer += decoder.write(chunk);
        if (Buffer.byteLength(buffer) > MAX_BUFFER) { if (client.run) abandon(client.run, fail('SSH_BROKER_INVALID')); else client.destroy(); return; }
        while (buffer.includes('\n')) {
          const index = buffer.indexOf('\n'), line = buffer.slice(0, index); buffer = buffer.slice(index + 1);
          if (Buffer.byteLength(line) > MAX_LINE || queued + Buffer.byteLength(line) > MAX_BUFFER || queuedFrames >= 128) { client.destroy(); return; }
          let frame; try { frame = JSON.parse(line); } catch {}
          const immediateRun = client.run;
          // A stalled native input must not queue termination behind itself.
          // Only validated stop controls bypass the ordered input stream.
          if (immediateRun?.ready && (frame?.type === 'cancel' || frame?.type === 'signal'
            && (['SIGTERM', 'SIGHUP'].includes(frame.signal) || frame.signal === 'SIGINT' && !immediateRun.tty))) {
            try {
              assertLive();
              if (!fields(frame, frame.type === 'cancel' ? ['type'] : ['type', 'signal'])) throw fail('SSH_BROKER_INVALID');
              if (immediateRun.cancelled || immediateRun.exited) throw fail('SSH_BROKER_UNAVAILABLE');
              void cancel(immediateRun).catch(error => abandon(immediateRun, error));
            } catch (error) { if (!immediateRun.cancelledByClient) abandon(immediateRun, error); }
            continue;
          }
          queued += Buffer.byteLength(line); queuedFrames++;
          chain = chain.then(async () => {
            if (client.destroyed) return;
            if (!frame || typeof frame !== 'object' || Array.isArray(frame)) throw fail('SSH_BROKER_INVALID');
            assertLive();
            if (!started) {
              started = true; clearTimeout(timer);
              if (frame?.type !== 'start') throw fail('SSH_BROKER_INVALID');
              await start(client, frame); return;
            }
            const run = client.run;
            if (!run?.ready || run.cancelled || run.exited) throw fail('SSH_BROKER_UNAVAILABLE');
            if (frame.type === 'stdin' && fields(frame, ['type', 'data'])) {
              if (run.inputEnded) throw fail('SSH_BROKER_INVALID');
              const data = base64(frame.data);
              if (run.tty) await ptyInput(run, data);
              else await new Promise((resolve, reject) => run.process.stdin.write(data, error => error ? reject(fail()) : resolve()));
            } else if (frame.type === 'eof' && fields(frame, ['type'])) {
              if (run.inputEnded) throw fail('SSH_BROKER_INVALID');
              run.inputEnded = true;
              if (run.tty) await ptyInput(run, Buffer.from('\x04')); else run.process.stdin.end();
            } else if (frame.type === 'resize' && fields(frame, ['type', 'cols', 'rows']) && size(frame.cols) && size(frame.rows)) {
              if (run.tty) run.process.resize(frame.cols, frame.rows);
            } else if (frame.type === 'signal' && fields(frame, ['type', 'signal']) && ['SIGINT', 'SIGTERM', 'SIGHUP'].includes(frame.signal)) {
              if (frame.signal === 'SIGINT' && run.tty) await ptyInput(run, Buffer.from('\x03'));
              else await cancel(run);
            } else if (frame.type === 'cancel' && fields(frame, ['type'])) {
              await cancel(run);
            } else throw fail('SSH_BROKER_INVALID');
          }).catch(error => { if (client.run?.cancelledByClient) return; if (client.run) abandon(client.run, error); else errorFrame(client, error); })
            .finally(() => { queued -= Buffer.byteLength(line); queuedFrames--; });
        }
        if (Buffer.byteLength(buffer) > MAX_LINE) client.destroy();
      });
    });
    await listen(commandServer, socket); ownedFiles.push(socket);
    commandServer.on('error', () => { void dispose().catch(() => {}); }); authServer.on('error', () => { void dispose().catch(() => {}); });
    sweep = setInterval(() => {
      if (!live()) { void dispose().catch(() => {}); return; }
      for (const alias of authorizations.keys()) authorizationAvailable(alias);
      for (const [token, grant] of grants) if (!grantAvailable(grant)) grants.delete(token);
      for (const client of authClients) if (client.sshGrant && !grantAvailable(client.sshGrant)) client.destroy();
    }, 250); sweep.unref();
    assertLive();
    if (![...authorizations.keys()].map(authorizationAvailable).some(Boolean)) throw fail('SSH_AUTHORIZATION_EXPIRED');
    return { socket, dispose };
  } catch (error) {
    const failure = fail(allowedErrors.has(error?.code) ? error.code : undefined);
    try { await dispose(); } catch { failure.sshCleanup = dispose; }
    throw failure;
  }
}
