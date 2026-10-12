// Source-only shared channel multiplexer for the macOS PF authorized session.
// Import and construction are inert: nothing is spawned until a caller acquires
// a virtual process, and only the verified main-process candidate may do that.
//
// One authorized root session per Envara launch. The carrier is password-gated,
// so the real channel is spawned at most once and is shared by every attached
// application until Envara quits. Each application gets its own virtual process
// (stdin/stdout/close/kill) so per-run bookkeeping stays exactly per-run. The
// helper answers one request at a time, each under its own id, so responses are
// routed by id and a frame is never replayed to another run.
const FAILURE = 'PF_HELPER_UNAVAILABLE';
const CLOSED_CODE = 0;
const TERMINAL_BYTES = 131072;
const failed = reason => Object.assign(new Error('Shared authorized channel refused'), { code: FAILURE, reason });

/**
 * @param spawnRootControlledLifecycle Called once, on the first acquired
 *   virtual process; only then does the system authorization dialog appear.
 * @returns `{ acquire, release, dispose, snapshot }`. `release(target)` ends one
 *   virtual process; the real child stays open for later attachments and is
 *   only torn down by `dispose()`, which is what "quit Envara" means.
 */
export function createPFAuthorizedChannelMux({ spawnRootControlledLifecycle, maximumBytes = 65536 } = {}) {
  if (typeof spawnRootControlledLifecycle !== 'function' || !Number.isInteger(maximumBytes) || maximumBytes < 1024 || maximumBytes > TERMINAL_BYTES)
    throw failed('mux-request-invalid');
  const targets = new Map(), owners = new Map(), pending = new Map();
  let child = null, starting = null, buffer = Buffer.alloc(0), spawned = false, disposed = false, terminal = null;

  const start = () => starting ??= Promise.resolve().then(spawnRootControlledLifecycle).then(process => {
    if (!process?.stdin || !process?.stdout || typeof process.on !== 'function' || typeof process.kill !== 'function')
      throw failed('mux-process-unavailable');
    child = process; spawned = true;
    child.stdin.on('error', () => fail('mux-input-failed'));
    child.stderr?.on?.('error', () => {});
    child.stderr?.on?.('data', () => {});
    child.stdout.on('data', onData);
    child.stdout.once('end', () => { buffer = Buffer.alloc(0); });
    child.once('error', () => fail('mux-process-unavailable'));
    child.once('close', (exitCode, exitSignal) => {
      terminal = { exitCode, exitSignal };
      const remaining = [...pending.values()]; pending.clear(); owners.clear();
      for (const record of remaining) record.emit('end');
      for (const target of [...targets.values()]) target.emit('close', exitCode, exitSignal);
      targets.clear();
    });
    return child;
  }).catch(error => { starting = null; fail('mux-process-unavailable'); throw error; });

  function fail(reason) {
    const remaining = [...pending.values()]; pending.clear();
    for (const record of remaining) record.emit('end');
    for (const target of [...targets.values()]) target.emit('error', failed(reason));
    try { child?.kill?.('SIGTERM'); } catch { /* already gone */ }
  }
  const onData = bytes => {
    buffer = Buffer.concat([buffer, bytes]);
    if (buffer.length > maximumBytes * 2) return fail('mux-response-too-large');
    let newline;
    while ((newline = buffer.indexOf(10)) >= 0) {
      const line = buffer.subarray(0, newline); buffer = buffer.subarray(newline + 1);
      if (!line.length || line.length > maximumBytes) return fail('mux-response-invalid');
      let id = null;
      try { id = JSON.parse(line.toString('utf8'))?.id ?? null; } catch { return fail('mux-response-invalid'); }
      // A frame whose id belongs to no live request is still delivered to its
      // owning run, so that run's own late-response evidence is preserved.
      const owner = typeof id === 'string' ? owners.get(id) : null;
      const record = typeof id === 'string' ? pending.get(id) : null;
      if (record) pending.delete(id);
      if (!owner) { if (id === null) return fail('mux-unaddressed-response'); continue; }
      owner.emit('data', line);
    }
    if (buffer.length > maximumBytes) fail('mux-response-too-large');
  };
  const parseId = input => {
    const text = Buffer.isBuffer(input) ? input.toString('utf8') : String(input);
    const line = text.split('\n', 1)[0];
    if (!line) return null;
    try { const value = JSON.parse(line); return typeof value?.id === 'string' ? value.id : null; } catch { return null; }
  };

  function acquire({ key } = {}) {
    if (disposed) throw failed('mux-disposed');
    if (key && targets.has(key)) throw failed('mux-key-in-use');
    const handlers = new Set();
    const target = {
      key: key ?? null,
      on: (type, handler) => { handlers.add({ type, handler }); },
      once: (type, handler) => { handlers.add({ type, handler, once: true }); },
      removeListener: (type, handler) => { for (const entry of [...handlers]) if (entry.type === type && entry.handler === handler) handlers.delete(entry); },
      emit: (type, ...values) => { for (const entry of [...handlers]) { if (entry.type !== type) continue; if (entry.once) handlers.delete(entry); try { entry.handler(...values); } catch { /* a consumer fault cannot stop routing */ } } },
      kill: () => { /* A virtual process never signals the shared root child. */ },
    };
    let ended = false;
    // Ending one virtual process detaches it from the shared root session. The
    // run reports its own verified cleanup receipts before it does; the shared
    // session itself belongs to Envara and is only torn down by dispose().
    const end = () => {
      if (ended) return; ended = true;
      for (const [id, owner] of [...owners]) if (owner === target) { owners.delete(id); pending.delete(id); }
      if (target.key) targets.delete(target.key);
      target.emit('close', CLOSED_CODE, null);
    };
    target.end = end;
    target.stdin = {
      write: (input, callback) => {
        if (disposed || terminal || ended || !child) { callback?.(); return false; }
        const id = parseId(input);
        if (id) {
          if (pending.has(id)) { callback?.(); throw failed('mux-duplicate-request'); }
          pending.set(id, { id, emit: target.emit }); owners.set(id, target);
        }
        try { return child.stdin.write(input, callback); } catch { callback?.(); return false; }
      },
      end,
      on: () => {}, once: () => {}, removeListener: () => {},
    };
    target.stdout = {
      on: (type, handler) => target.on(type, handler), once: (type, handler) => target.once(type, handler),
      removeListener: (type, handler) => target.removeListener(type, handler), setEncoding: () => {},
    };
    target.stderr = { on: () => {}, once: () => {}, removeListener: () => {} };
    targets.set(key ?? Symbol('channel'), target);
    return target;
  }
  const release = target => {
    if (!target || !target.key) return;
    targets.delete(target.key);
    for (const [id, owner] of [...owners]) if (owner === target) { owners.delete(id); pending.delete(id); }
  };
  const dispose = async () => {
    if (disposed) return; disposed = true;
    pending.clear(); owners.clear();
    for (const target of [...targets.values()]) target.emit('close', null, null);
    targets.clear();
    try { await start().catch(() => {}); } catch { /* never spawned */ }
    try { child?.stdin?.end?.(); } catch { /* already closed */ }
  };
  return Object.freeze({
    acquire, release, dispose, start,
    snapshot: () => ({ spawned, connected: child != null, disposed, terminal: terminal ? { ...terminal } : null,
      targets: targets.size, pending: pending.size, bufferedBytes: buffer.length }),
    child: () => child,
  });
}
