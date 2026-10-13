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
  let child = null, starting = null, buffer = Buffer.alloc(0), spawned = false, disposed = false, terminal = null, sessionFailed = false;

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
      /* The shared root session ending is never a clean end for an attached
       * application unless it exited zero: a run whose cleanup was never
       * confirmed must be told the session is gone rather than look finished. */
      const abrupt = exitCode !== 0 || exitSignal != null;
      for (const target of [...targets.values()]) {
        target.emit('close', abrupt ? null : CLOSED_CODE, exitSignal ?? null);
        if (abrupt) target.emit('error', failed('mux-session-ended'));
      }
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
      /* Each run's client frames its own input by newline, exactly as it does
       * for a dedicated carrier, so the frame is delivered with its newline. */
      const frame = buffer.subarray(0, newline + 1), line = frame.subarray(0, newline); buffer = buffer.subarray(newline + 1);
      if (!line.length || line.length > maximumBytes) return fail('mux-response-invalid');
      let id = null;
      try { id = JSON.parse(line.toString('utf8'))?.id ?? null; } catch { return fail('mux-response-invalid'); }
      /* The carrier itself writes the only frames without an id: an
       * authorization refusal, or the root wrapper's cleanup-unconfirmed
       * terminal frame. Both describe the whole session, so every attached run
       * receives them and applies its own fixed checks. Dropping them lost the
       * refusal reason and the cleanup uncertainty. The session is over. */
      if (id === null) {
        sessionFailed = true;
        for (const target of [...targets.values()]) target.emit('data', frame);
        continue;
      }
      // A frame whose id belongs to no live request is still delivered to its
      // owning run, so that run's own late-response evidence is preserved.
      const owner = typeof id === 'string' ? owners.get(id) : null;
      const record = typeof id === 'string' ? pending.get(id) : null;
      if (record) pending.delete(id);
      if (!owner) continue;
      owner.emit('data', frame);
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
    if (terminal || sessionFailed) throw failed('mux-session-ended');
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
    // Requests written before the shared carrier is ready are held, not dropped:
    // the first request is what starts that carrier, and a caller must never
    // lose a request just because the authorization dialog is still on screen.
    const backlog = [];
    /* A write callback means "the stream is done with these bytes": the run's
     * client scrubs its request buffer in it, and a request can carry the
     * proxy password. So the callback goes to the real stream, which calls it
     * once it has taken the bytes. Calling it here first zeroed every request
     * still in flight, and the root helper received NUL bytes and never
     * answered. A false return from write is backpressure, not a failure. */
    const forward = (input, callback) => {
      if (disposed || terminal || sessionFailed || ended || !child) return false;
      try { child.stdin.write(input, callback); return true; } catch { return false; }
    };
    const scrub = () => { for (const held of backlog.splice(0)) held.fill(0); };
    const flush = () => {
      while (backlog.length) {
        const held = backlog.shift();
        if (!forward(held, () => held.fill(0))) { held.fill(0); scrub(); return false; }
      }
      return true;
    };
    target.stdin = {
      write: (input, callback) => {
        if (disposed || terminal || sessionFailed || ended) { callback?.(); return false; }
        const id = parseId(input);
        if (id) {
          if (pending.has(id)) { callback?.(); throw failed('mux-duplicate-request'); }
          pending.set(id, { id, emit: target.emit }); owners.set(id, target);
        }
        if (child) { if (forward(input, callback)) return true; callback?.(); return false; }
        /* The first request is what opens the shared authorized session; this
         * is the only place the carrier is ever spawned. Until it is ready the
         * request is held as a private copy, so the caller may scrub its own
         * buffer now, and the copy is scrubbed once the carrier takes it. */
        backlog.push(Buffer.from(input));
        void start().then(() => { if (!flush()) fail('mux-input-failed'); }).catch(() => { scrub(); fail('mux-process-unavailable'); });
        callback?.();
        return true;
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
    /* Quitting must never be what opens the session: a channel that was
     * acquired but never sent a request has no carrier, and starting one here
     * put an administrator password dialog in front of the user on quit. */
    if (starting) await starting.catch(() => {});
    try { child?.stdin?.end?.(); } catch { /* already closed */ }
  };
  return Object.freeze({
    acquire, release, dispose, start,
    snapshot: () => ({ spawned, connected: child != null, disposed, ended: disposed || terminal != null || sessionFailed,
      terminal: terminal ? { ...terminal } : null,
      targets: targets.size, pending: pending.size, bufferedBytes: buffer.length }),
    child: () => child,
  });
}
