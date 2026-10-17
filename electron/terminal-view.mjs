import { isAppearancePreference } from '../shared/appearance.mjs';

const fail = (message, code) => Object.assign(new Error(message), { code });
const networkLabel = value => typeof value === 'string' && value.trim() && value.length <= 200 && !/[\0\r\n]/.test(value) ? value : null;

export function resolveTerminalView(args, workspace, terminalState) {
  if (!args || typeof args !== 'object' || Array.isArray(args) || typeof args.id !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(args.id)) throw fail('无效的环境标识。', 'VALIDATION_ERROR');
  const profile = workspace.profiles.find(row => row.id === args.id);
  if (!profile) throw fail('环境不存在。', 'PROFILE_NOT_FOUND');
  const sessions = terminalState.profiles?.find(row => row.profileId === args.id)?.sessions ?? [];
  let session;
  if (args.sessionId != null) {
    session = sessions.find(row => row.sessionId === args.sessionId);
    if (!session) throw fail('该终端会话已不可用，请重新选择。', 'TERMINAL_SESSION_NOT_FOUND');
  } else session = sessions.find(row => row.status === 'running');
  return { profileId: profile.id, name: profile.name, sessionId: session?.sessionId };
}

// Independent terminal views need environment labels, not proxy credentials.
export function terminalViewSnapshot(value) {
  if (!Array.isArray(value?.profiles) || !value.system) return value;
  const fields = ['id', 'name', 'group', 'engine', 'status', 'timezone', 'resolvedTimezone', 'timezoneSource', 'timezoneOrigin'];
  return { profiles: value.profiles.map(row => {
    const profile = Object.fromEntries(fields.filter(key => Object.hasOwn(row, key)).map(key => [key, row[key]]));
    if (row.proxyId === null || typeof row.proxyId === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(row.proxyId)) profile.proxyId = row.proxyId;
    if (['off', 'standard', 'strict'].includes(row.privacy?.mode)) profile.privacy = { mode: row.privacy.mode };
    const node = profile.proxyId && Array.isArray(value.proxies) ? value.proxies.find(item => item?.id === profile.proxyId) : null;
    const name = networkLabel(row.networkName) || networkLabel(node?.name);
    if (name) profile.networkName = name;
    const savedTimezone = row.selectedLocation?.timezone;
    if (row.selectedLocation?.confirmed === true && typeof savedTimezone === 'string' && savedTimezone.length <= 128) profile.savedNetworkTimezone = savedTimezone;
    if (row.network?.ok === false || row.networkLastError) profile.networkContextUnavailable = true;
    return profile;
  }), proxies: [], engines: [], settings: { ...(value.settings?.language ? { language: value.settings.language } : {}), ...(isAppearancePreference(value.settings?.appearance) ? { appearance: value.settings.appearance } : {}) }, events: [], system: { appVersion: value.system.appVersion, platform: value.system.platform, terminal: value.system.terminal } };
}
