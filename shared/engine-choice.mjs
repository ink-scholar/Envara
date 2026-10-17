/* Which browser engine a new environment uses, and the proxy region presets the
 * BrowseForge Chromium engine accepts. Shared by the page and the main process
 * so both name the same engine and the same region. */
import { BROWSEFORGE_CHROMIUM_REGION_PRESETS } from './browseforge-regions.mjs';

const supportedRegions = new Set(BROWSEFORGE_CHROMIUM_REGION_PRESETS.map(({ value }) => value));
const countryPresets = new Map(BROWSEFORGE_CHROMIUM_REGION_PRESETS.filter(({ value }) => !value.includes('-')).map(({ value }) => [value.toUpperCase(), value]));
const placeName = value => typeof value === 'string' ? value.trim().normalize('NFKD').replace(/\p{M}/gu, '').toLowerCase().replace(/[\s_-]+/g, ' ') : '';
const countryCode = value => typeof value === 'string' ? value.trim().toUpperCase() : '';

/** Exact region/city names and canonical code suffixes, taken from the engine's
 * supported presets. Country-only fallbacks are kept separate from place names. */
export const BROWSEFORGE_CHROMIUM_REGIONS = Object.freeze(Object.fromEntries([...countryPresets.keys()].map(country => {
  const names = BROWSEFORGE_CHROMIUM_REGION_PRESETS.filter(({ value }) => value.startsWith(`${country.toLowerCase()}-`)).flatMap(({ value, label }) => [
    [placeName(label.split(' — ')[1]), value],
    [placeName(value.slice(3)), value],
  ]);
  return [country, Object.freeze(Object.fromEntries(names))];
})));

function regionAt(location, country) {
  const names = BROWSEFORGE_CHROMIUM_REGIONS[country];
  if (!names) return null;
  // Structured region wins over city (for example a city named New York in
  // Texas). Saved locations normally carry a comma-separated display label.
  for (const value of [location?.region, location?.city]) {
    const match = Object.hasOwn(names, placeName(value)) ? names[placeName(value)] : null;
    if (match) return match;
  }
  const components = typeof location?.label === 'string' ? location.label.split(/[,，;；|—]/) : [];
  const matches = new Set(components.map(placeName).filter(name => Object.hasOwn(names, name)).map(name => names[name]));
  // Ambiguous labels and street text never invent a city or use preset order
  // to break a tie. A supported country value needs no guessed local detail.
  return matches.size === 1 ? [...matches][0] : countryPresets.get(country) ?? null;
}

/** Resolve only supported labels, without changing saved identity or location.
 * Explicit choices win; an invalid explicit choice must be fixed deliberately.
 * Confirmed location is one source, never blended with another measured city. */
export function browseForgeRegionFor(proxy) {
  if (proxy?.region != null && proxy.region !== '') {
    if (typeof proxy.region !== 'string') return null;
    const explicit = proxy.region.trim().toLowerCase();
    if (explicit) return supportedRegions.has(explicit) ? explicit : null;
  }
  const location = proxy?.location?.confirmed === true ? proxy.location : null;
  const network = proxy?.network?.ok === true && proxy.network.scope === 'egress' && proxy.network.ip && proxy.network.timezone ? proxy.network : null;
  if (location) return regionAt(location, countryCode(location.countryCode) || countryCode(network?.countryCode));
  return network ? regionAt(network, countryCode(network.countryCode)) : null;
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
