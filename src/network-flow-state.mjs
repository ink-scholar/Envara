import { normalizeNetworkLocation } from '../shared/network-location.mjs';

// Route fields invalidate the verified preview. Renaming a node does not change
// its route; no credentials or preview tokens leave this in-memory form state.
export const proxyRouteFields = new Set(['protocol', 'host', 'port', 'username', 'password', 'region', 'serverName', 'skipCertVerify', 'clientFingerprint', 'alpn', 'udp']);

export function locationFormState(location) {
  return { mode: location?.mode === 'manual' ? 'manual' : 'ip', label: location?.mode === 'manual' ? location.label || '' : '', mapsUrl: location?.mode === 'manual' ? location.mapsUrl || '' : '',
    latitude: location?.mode === 'manual' && location.latitude != null ? String(location.latitude) : '', longitude: location?.mode === 'manual' && location.longitude != null ? String(location.longitude) : '', confirmed: false };
}

export function verifiedLocationPreview(preview) {
  return preview?.network?.ok === true && preview.network.scope === 'egress' && typeof preview.network.ip === 'string' && !!preview.network.ip &&
    typeof preview.network.timezone === 'string' && !!preview.network.timezone && preview.locationRecommendation?.source === 'ip-estimate' &&
    typeof preview.locationPreviewToken === 'string' && !!preview.locationPreviewToken;
}

export function locationConfirmation(location, preview) {
  if (!verifiedLocationPreview(preview)) throw new Error('请先检测当前代理，再确认位置与时区。');
  if (location?.confirmed !== true) throw new Error('请确认这个网络环境的位置与时区。');
  if (location.mode === 'ip') return { mode: 'ip', confirmed: true };
  const input = { mode: 'manual', confirmed: true, label: location.label, mapsUrl: location.mapsUrl,
    latitude: location.latitude, longitude: location.longitude };
  // Validate locally without claiming that an address label was geocoded.
  normalizeNetworkLocation(input);
  return input;
}

export function networkApplicationChoices(proxies = [], groups = [], profiles = []) {
  const proxyById = new Map(proxies.map(proxy => [proxy.id, proxy]));
  const choices = groups.filter(group => group && typeof group === 'object' && group.name && proxyById.has(group.proxyId)).map(group => ({
    id: `group:${group.name}`, name: group.name, group: group.name, proxyId: group.proxyId, proxy: proxyById.get(group.proxyId),
    profileIds: profiles.filter(profile => profile.group === group.name && profile.proxyId === group.proxyId).map(profile => profile.id),
  }));
  const groupedNodeIds = new Set(choices.map(choice => choice.proxyId));
  for (const proxy of proxies.filter(proxy => !groupedNodeIds.has(proxy.id))) choices.push({ id: `node:${proxy.id}`, name: proxy.name, group: '', proxyId: proxy.id, proxy,
    profileIds: profiles.filter(profile => profile.proxyId === proxy.id).map(profile => profile.id) });
  return choices;
}

export function chooseApplicationProfile(choice, profiles, selectedId, active = () => false) {
  if (!choice || !Array.isArray(choice.profileIds)) return null;
  const matching = profiles.filter(profile => choice.profileIds.includes(profile.id) && profile.proxyId === choice.proxyId && (!choice.group || profile.group === choice.group));
  return matching.find(profile => profile.id === selectedId) ?? matching.find(profile => !active(profile)) ?? matching.slice().sort((a, b) => a.id.localeCompare(b.id))[0] ?? null;
}

export function isApplicationAlreadyAttached(application, bindings = []) {
  return bindings.some(binding => application?.identity && binding.identity === application.identity || application?.path && binding.path === application.path);
}

export function createdProfileFromSnapshot(beforeIds, snapshot, expected) {
  const created = (snapshot?.profiles || []).filter(profile => !beforeIds.has(profile.id));
  return created.length === 1 && created[0].proxyId === expected.proxyId && (created[0].group || '') === (expected.group || '') ? created[0] : null;
}

export function networkContextFailed(profile, proxy) {
  return profile?.networkContextUnavailable === true || profile?.network?.ok === false || !!profile?.networkLastError || (profile?.network == null && proxy?.network?.ok === false);
}

// Saved selections are configuration. Only a current successful environment
// probe can describe them as the current resolved network context.
export function savedNetworkPresentation(profile, proxy) {
  const failed = networkContextFailed(profile, proxy);
  const network = failed ? null : profile?.network?.ok ? profile.network : proxy?.network?.ok ? proxy.network : null;
  const location = proxy?.location?.confirmed ? proxy.location : profile?.savedNetworkLocation;
  const savedTimezone = location?.timezone || profile?.savedNetworkTimezone || null;
  const current = !failed && profile?.network?.ok === true && profile.network.scope === 'egress';
  const timezone = current && profile?.resolvedTimezone ? profile.resolvedTimezone : savedTimezone || (!failed ? profile?.resolvedTimezone || profile?.timezone : profile?.timezone) || null;
  return { failed, network, savedTimezone, timezone, savedOnly: !!timezone && (failed || !!savedTimezone && !current), location: location || null };
}

export function terminalTimezonePresentation({ profile, metadata, session, hasLiveSession }) {
  const failed = networkContextFailed(profile) || metadata?.network?.ok === false || metadata?.network?.egress?.ok === false || session?.network?.egress?.ok === false;
  const savedTimezone = profile?.savedNetworkTimezone || profile?.savedNetworkLocation?.timezone;
  const successfulEgress = network => network?.ok === true && network.scope === 'egress';
  const verified = !failed && (successfulEgress(profile?.network) || successfulEgress(metadata?.network?.egress) || successfulEgress(session?.network?.egress));
  const timezone = !hasLiveSession && savedTimezone ? savedTimezone : metadata?.timezone || profile?.resolvedTimezone || savedTimezone || null;
  const originalSource = metadata?.timezoneSource && metadata.timezoneSource !== 'unknown' ? metadata.timezoneSource : profile?.timezoneSource || 'unknown';
  const source = failed || savedTimezone && (!hasLiveSession || !verified) ? 'saved-configuration' : originalSource;
  return { timezone, source, failed };
}
