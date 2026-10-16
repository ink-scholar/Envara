/** One workspace window, opened only after trusted IPC has been registered.
 * Service initialization may continue behind its loading state. Early macOS
 * activate and second-instance events coalesce with the initial window request.
 */
export function createWorkspaceWindowController({ current, create, canOpen = () => true }) {
  let ready = false;
  let opening = null;
  return {
    markReady() { ready = true; },
    async open() {
      if (!ready || !canOpen()) return null;
      if (opening) return opening;
      const existing = current();
      if (existing && !existing.isDestroyed()) {
        if (existing.isMinimized()) existing.restore();
        existing.show(); existing.focus();
        return existing;
      }
      opening = Promise.resolve().then(() => canOpen() ? create() : null);
      try { return await opening; }
      finally { opening = null; }
    },
  };
}

/** Repeated quit requests remain blocked until the same cleanup succeeds.
 * Waiting for startup prevents its final awaited steps from creating resources
 * after shutdown has already inspected and closed a partial set of services.
 */
export function createOwnedQuitController({ hasResources, startup, shutdown, quit, onStateChange, onFailure }) {
  let authorized = false;
  let pending = null;
  return {
    async handle(event) {
      if (authorized) return;
      if (pending) { event.preventDefault(); return pending; }
      if (!hasResources()) return;
      event.preventDefault();
      onStateChange(true);
      pending = Promise.resolve().then(startup).then(shutdown).then(() => {
        authorized = true;
        quit();
      }).catch(error => {
        onStateChange(false);
        onFailure(error);
      }).finally(() => { pending = null; });
      return pending;
    },
  };
}
