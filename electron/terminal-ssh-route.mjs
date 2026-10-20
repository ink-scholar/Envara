const invalid = () => Object.assign(new Error('SSH 网络路线无效，请重新选择。'), { code: 'SSH_ROUTE_INVALID' });

/** Stored references never contain listeners, credentials or mutable labels. */
export function normalizeSshRoute(value, { legacy = false } = {}) {
  if (value === undefined && legacy) return { kind: 'host' };
  if (!value || typeof value !== 'object' || Array.isArray(value) || !Object.hasOwn(value, 'kind')) throw invalid();
  if (value.kind === 'host' && Object.keys(value).length === 1) return { kind: 'host' };
  if (value.kind === 'environment' && Object.keys(value).length === 2 && Object.hasOwn(value, 'profileId')
    && typeof value.profileId === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(value.profileId))
    return { kind: 'environment', profileId: value.profileId };
  throw invalid();
}

export function sameSshRoute(first, second) {
  const a = normalizeSshRoute(first), b = normalizeSshRoute(second);
  return a.kind === b.kind && (a.kind === 'host' || a.profileId === b.profileId);
}
