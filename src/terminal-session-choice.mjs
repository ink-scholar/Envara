import { SYSTEM_BROWSER } from './link-browser.mjs';

export const CLAUDE_SESSION = 'claude-code';

export function sessionNetworks(networks, kind = 'shell') {
  return kind === CLAUDE_SESSION ? networks.filter(network => network.id !== 'direct' && network.profiles.some(profile => profile.proxyId)) : networks;
}

export function sessionChoiceHost(networks, choice, preferredId) {
  const network = sessionNetworks(networks, choice?.kind).find(item => item.id === choice?.networkId);
  if (!network) return null;
  if (choice.kind === CLAUDE_SESSION) return network.profiles.find(profile => profile.id === choice.browserId && profile.proxyId) ?? null;
  const browserId = choice.browserId === SYSTEM_BROWSER ? preferredId : choice.browserId;
  return network.profiles.find(profile => profile.id === browserId) ?? network.profiles[0] ?? null;
}

export function changeSessionKind(networks, choice, kind, preferredId) {
  const available = sessionNetworks(networks, kind);
  const network = available.find(item => item.id === choice.networkId) ?? available[0];
  const browserId = kind !== CLAUDE_SESSION && choice.browserId === SYSTEM_BROWSER ? SYSTEM_BROWSER
    : network?.profiles.find(profile => profile.id === choice.browserId)?.id
      ?? network?.profiles.find(profile => profile.id === preferredId)?.id ?? network?.profiles[0]?.id ?? null;
  return { ...choice, kind, networkId: network?.id ?? null, browserId, error: '' };
}

/** Only a selected environment browser may enter a dedicated Claude request.
 *  The desktop verifies the binding again against the live network context. */
export function terminalSessionOptions(kind = 'shell', browserProfileId = null, claudeAccountId) {
  if (kind === 'shell') return {};
  if (kind !== CLAUDE_SESSION || typeof browserProfileId !== 'string' || browserProfileId === SYSTEM_BROWSER || !/^[A-Za-z0-9_-]{1,96}$/.test(browserProfileId)) throw new Error('请选择此网络的境舱浏览器。');
  if (claudeAccountId != null && (typeof claudeAccountId !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(claudeAccountId))) throw new Error('请选择登录档案。');
  return { kind: CLAUDE_SESSION, browserProfileId, ...(claudeAccountId != null ? { claudeAccountId } : {}) };
}
