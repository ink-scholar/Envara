/** Preserve application routes if native cleanup remains uncertain. A rejected
 * initial store load admitted no consumers, so it must not strand earlier
 * startup resources by repeating the same configuration error during shutdown.
 */
export async function shutdownDesktopServices({ applications, diagnostics, terminal, terminalBrowserBroker,
  linkChannel, routerChannel, service, sidecar, proxyCore }) {
  try {
    if (applications && await applications.ready.then(() => true, () => false)) await applications.shutdown();
  } finally { await diagnostics?.pending.catch(() => {}); }
  await terminal?.shutdown().catch(() => {});
  await terminalBrowserBroker?.shutdown().catch(() => {});
  await linkChannel?.close().catch(() => {});
  await routerChannel?.close().catch(() => {});
  try {
    const serviceReady = service && await service.ready.then(() => true, () => false);
    if (serviceReady) await service.shutdown();
    else { service?.networkProbe?.close?.(); await sidecar?.shutdown(); }
  } finally { await proxyCore?.close(); }
}
