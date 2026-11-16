/** Preserve application routes if native cleanup remains uncertain. A rejected
 * initial store load admitted no consumers, so it must not strand earlier
 * startup resources by repeating the same configuration error during shutdown.
 */
export async function shutdownDesktopServices({ applications, diagnostics, terminal, terminalBrowserBroker,
  linkChannel, routerChannel, service, sidecar, proxyCore, networkRecovery = null, runtimeDiagnostics = null, strict = false }) {
  const trace = (stage, operation) => runtimeDiagnostics ? runtimeDiagnostics.step(stage, operation) : operation();
  const optional = async (stage, operation) => {
    try { return await trace(stage, operation); } catch (error) { if (strict) throw error; }
  };
  try {
    if (applications) await trace('shutdown.applications', async () => {
      if (await applications.ready.then(() => true, () => false)) await applications.shutdown();
    });
  } finally { await trace('shutdown.diagnostics', async () => diagnostics?.pending).catch(() => {}); }
  await trace('shutdown.network-recovery', async () => networkRecovery?.close());
  await optional('shutdown.terminal', async () => terminal?.shutdown());
  await optional('shutdown.broker', async () => terminalBrowserBroker?.shutdown({ strict }));
  await optional('shutdown.links', async () => linkChannel?.close());
  await optional('shutdown.router', async () => routerChannel?.close());
  const closeBackend = () => trace('shutdown.backend', async () => {
    const serviceReady = service && await service.ready.then(() => true, () => false);
    if (serviceReady) await service.shutdown({ strict });
    else { service?.networkProbe?.close?.(); await sidecar?.shutdown(); }
  });
  if (strict) {
    await closeBackend();
    await trace('shutdown.proxy', () => proxyCore?.close());
  } else {
    try { await closeBackend(); }
    finally { await trace('shutdown.proxy', () => proxyCore?.close()); }
  }
}
