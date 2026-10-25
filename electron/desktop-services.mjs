/** Preserve application routes if native cleanup remains uncertain. A rejected
 * initial store load admitted no consumers, so it must not strand earlier
 * startup resources by repeating the same configuration error during shutdown.
 */
export async function shutdownDesktopServices({ applications, diagnostics, terminal, terminalBrowserBroker,
  linkChannel, routerChannel, service, sidecar, proxyCore, runtimeDiagnostics = null }) {
  const trace = (stage, operation) => runtimeDiagnostics ? runtimeDiagnostics.step(stage, operation) : operation();
  try {
    if (applications) await trace('shutdown.applications', async () => {
      if (await applications.ready.then(() => true, () => false)) await applications.shutdown();
    });
  } finally { await trace('shutdown.diagnostics', async () => diagnostics?.pending).catch(() => {}); }
  await trace('shutdown.terminal', async () => terminal?.shutdown()).catch(() => {});
  await trace('shutdown.broker', async () => terminalBrowserBroker?.shutdown()).catch(() => {});
  await trace('shutdown.links', async () => linkChannel?.close()).catch(() => {});
  await trace('shutdown.router', async () => routerChannel?.close()).catch(() => {});
  try {
    await trace('shutdown.backend', async () => {
      const serviceReady = service && await service.ready.then(() => true, () => false);
      if (serviceReady) await service.shutdown();
      else { service?.networkProbe?.close?.(); await sidecar?.shutdown(); }
    });
  } finally { await trace('shutdown.proxy', () => proxyCore?.close()); }
}
