/** Backend startup is independent from window loading and renderer requests.
 * Only read-only bootstrap requests should wait for ready; actions must call
 * assertReady so a click made during startup cannot execute later unnoticed.
 * settled is the cleanup barrier, including after failure or cancellation.
 */
export function createDesktopStartup({ initialize, onState = () => {} }) {
  if (typeof initialize !== 'function' || typeof onState !== 'function') throw new TypeError('Invalid desktop startup callbacks.');
  let phase = 'idle', started = false, failure;
  let resolveReady, rejectReady, resolveSettled;
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  const settled = new Promise(resolve => { resolveSettled = resolve; });
  // Startup can fail before any renderer has requested its initial snapshot.
  // Observe rejection without replacing the original promise/error for readers.
  void ready.catch(() => {});
  const startingError = Object.assign(new Error('应用正在启动，请稍后重试。'), { code: 'APP_STARTING' });
  const closingError = Object.assign(new Error('应用正在退出。'), { code: 'APP_CLOSING' });
  const change = value => {
    phase = value;
    try { void Promise.resolve(onState(value)).catch(() => {}); } catch {}
  };
  const checkOpen = () => { if (phase === 'closing') throw closingError; };
  const assertReady = () => {
    checkOpen();
    if (phase === 'failed') throw failure;
    if (phase !== 'ready') throw startingError;
  };
  const start = () => {
    if (started || phase === 'closing') return ready;
    started = true;
    change('starting');
    void Promise.resolve().then(() => {
      checkOpen();
      return initialize({ checkOpen });
    }).then(value => {
      checkOpen();
      change('ready');
      // A state listener may synchronously request shutdown.
      checkOpen();
      resolveReady(value);
    }).catch(error => {
      if (phase === 'closing') rejectReady(closingError);
      else { failure = error; change('failed'); rejectReady(error); }
    }).then(() => resolveSettled());
    return ready;
  };
  const close = () => {
    if (phase !== 'closing') change('closing');
    rejectReady(closingError);
    // In-flight initialization must finish before cleanup. With no start,
    // close permanently prevents initialize from allocating anything at all.
    if (!started) resolveSettled();
    return settled;
  };
  const read = async operation => {
    if (typeof operation !== 'function') throw new TypeError('Invalid startup read operation.');
    try { await ready; }
    catch (error) { checkOpen(); throw error; }
    assertReady();
    const result = await operation();
    assertReady();
    return result;
  };
  return { start, ready, settled, close, checkOpen, assertReady, read, get phase() { return phase; } };
}
