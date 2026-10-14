/* Where links from an environment open, as the interface shows it. The rule is
 * decided in electron/link-router.mjs; this mirrors it so the page names the
 * same browser the router will use. */
export const SYSTEM_BROWSER = 'system';

/** The browsers a link from this environment may use: its own first, then the
 *  other browsers of its group on the same node. */
export function linkBrowsersFor(profiles = [], owner) {
  if (!owner) return [];
  const others = profiles.filter(item => item.id !== owner.id && (item.proxyId ?? null) === (owner.proxyId ?? null) && (item.group || '') === (owner.group || ''))
    .sort((a, b) => String(a.name).localeCompare(String(b.name)));
  return [owner, ...others];
}

/** What a saved choice stands for: a browser of the network, the system
 *  browser when chosen on purpose, or (unset or stale) the environment's own. */
export function linkBrowserChoice(candidates = [], chosenId = null) {
  if (chosenId === SYSTEM_BROWSER) return SYSTEM_BROWSER;
  return candidates.find(item => item.id === chosenId)?.id ?? candidates[0]?.id ?? null;
}

/** The networks a terminal can leave through: one per node an environment
 *  uses, with those environments as the browsers on it. */
export function terminalNetworks(profiles = []) {
  const networks = new Map();
  for (const profile of profiles) {
    const id = profile.proxyId || 'direct';
    if (!networks.has(id)) networks.set(id, { id, name: profile.networkName || null, egress: null, profiles: [] });
    const entry = networks.get(id);
    entry.egress ??= profile.networkEgress || null;
    entry.profiles.push(profile);
  }
  for (const entry of networks.values()) entry.profiles.sort((a, b) => String(a.name).localeCompare(String(b.name)));
  return [...networks.values()];
}
