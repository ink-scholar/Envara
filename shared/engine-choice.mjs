/* Which browser engine a new environment uses, and the proxy region presets the
 * BrowseForge Chromium engine accepts. Shared by the page and the main process
 * so both name the same engine and the same region. */

/** The proxy regions BrowseForge Chromium can serve. It refuses any other label. */
export const BROWSEFORGE_CHROMIUM_REGIONS = Object.freeze({
  US: Object.freeze({ 'new york': 'us-ny', california: 'us-ca', texas: 'us-tx' }),
  CA: Object.freeze({ ontario: 'ca-on', 'british columbia': 'ca-bc' }),
});

/** The region label BrowseForge Chromium needs for this network: the saved one,
 *  or the preset that matches the network's confirmed location. Null when the
 *  location is outside every preset, because no label can make it work. */
export function browseForgeRegionFor(proxy) {
  if (typeof proxy?.region === 'string' && proxy.region.trim()) return proxy.region.trim();
  const location = proxy?.location?.confirmed === true ? proxy.location : null;
  const network = proxy?.network?.ok ? proxy.network : null;
  const country = String(location?.countryCode || network?.countryCode || '').toUpperCase();
  const table = BROWSEFORGE_CHROMIUM_REGIONS[country];
  if (!table) return null;
  const names = [location?.region, location?.label, network?.region].filter(Boolean).map(value => String(value).toLowerCase());
  for (const [name, preset] of Object.entries(table)) if (names.some(value => value.includes(name))) return preset;
  return null;
}

/** The engine a new environment starts with: the saved default, else CloakBrowser,
 *  which follows the network's confirmed location and needs no region preset,
 *  else the first engine that can run here. */
export function preferredEngine(engines = [], configured = null) {
  const runs = item => item.supported !== false;
  return engines.find(item => item.id === configured && runs(item) && item.installed)?.id
    || engines.find(item => item.id === 'cloakbrowser' && runs(item))?.id
    || engines.find(item => runs(item) && item.installed && !item.experimental)?.id
    || engines.find(item => runs(item) && !item.experimental)?.id
    || engines.find(runs)?.id
    || engines[0]?.id
    || 'cloakbrowser';
}
