/** Environment links and system browser registration are separate user actions. */
export function createLinkRoutingControls({ preferences, status, requestSystem, restoreSystem }) {
  let pending = Promise.resolve();
  const serialize = operation => {
    const next = pending.then(operation);
    pending = next.catch(() => {});
    return next;
  };
  const restore = async () => {
    const current = await status();
    if (!current.enabled) return current;
    await restoreSystem();
    return status();
  };
  return {
    setPreference(enabled) {
      return serialize(async () => {
        if (typeof enabled !== 'boolean') throw Object.assign(new Error('链接设置参数无效。'), { code: 'LINK_ROUTER_REQUEST_INVALID' });
        await preferences.patch({ openInEnvironment: enabled });
        // Keep the existing opt-out behavior, including restoring the previous
        // system browser. Enabling internal links never registers a handler.
        return enabled ? status() : restore();
      });
    },
    requestSystem() {
      return serialize(async () => {
        const saved = await preferences.load();
        if (!saved.openInEnvironment) throw Object.assign(new Error('请先开启境舱内链接。'), { code: 'LINK_ROUTER_PREFERENCE_DISABLED' });
        const outcome = await requestSystem();
        return { ...(await status()), granted: outcome.granted };
      });
    },
    disableSystem() { return serialize(restore); },
  };
}
