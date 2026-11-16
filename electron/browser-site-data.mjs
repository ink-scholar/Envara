const fail = code => Object.assign(new Error('网站 Cookie 操作未完成，请刷新后重试。'), { code });
const engines = new Set(['cloakbrowser', 'browseforge-chromium', 'camoufox']);
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(value);
const text = (value, max) => typeof value === 'string' && value.length <= max && !/[\x00-\x1f\x7f]/.test(value);
const domain = value => text(value, 253) && value.length > 0 && !/[\\/ @?#]/.test(value);
const instance = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
function request(args, clear = false) {
  const keys = clear ? ['profileId', 'instanceId', 'domain'] : ['profileId'];
  if (!args || Array.isArray(args) || typeof args !== 'object' || Object.keys(args).some(key => !keys.includes(key)) || !identifier(args.profileId)
    || clear && (!instance(args.instanceId) || !domain(args.domain))) throw fail('SITE_DATA_INVALID');
}
function project(value, expectedInstance, expectedRuntime) {
  if (!value || value.instanceId !== expectedInstance || value.runtime !== expectedRuntime || !engines.has(value.runtime) || !Array.isArray(value.cookies) || value.cookies.length > 10000
    || typeof value.canClear !== 'boolean' || !Number.isFinite(Date.parse(value.checkedAt))) throw fail('SITE_DATA_UNAVAILABLE');
  const cookies = value.cookies.map(cookie => {
    if (!cookie || !text(cookie.name, 4096) || !domain(cookie.domain) || !text(cookie.path, 4096) || !Number.isFinite(cookie.expires)
      || typeof cookie.httpOnly !== 'boolean' || typeof cookie.secure !== 'boolean'
      || !['', 'Strict', 'Lax', 'None'].includes(cookie.sameSite)
      || !['partitioned', 'unpartitioned', 'opaque', 'unavailable'].includes(cookie.partitionState)
      || cookie.partitionKey != null && !text(cookie.partitionKey, 2048)) throw fail('SITE_DATA_UNAVAILABLE');
    return { name: cookie.name, domain: cookie.domain, path: cookie.path, expires: cookie.expires, httpOnly: cookie.httpOnly,
      secure: cookie.secure, sameSite: cookie.sameSite, partitionState: cookie.partitionState,
      ...(cookie.partitionKey ? { partitionKey: cookie.partitionKey } : {}) };
  });
  return { instanceId: expectedInstance, runtime: value.runtime, canClear: value.canClear && value.runtime !== 'camoufox',
    checkedAt: new Date(value.checkedAt).toISOString(), cookies };
}

/** A main-window-only adapter. Never starts browsers or reads on-disk cookies. */
export class BrowserSiteData {
  constructor({ getService }) { this.getService = getService; }
  async session(profileId, expectedInstance = null) {
    const service = this.getService();
    if (!service || typeof service.remote !== 'function' || typeof service.request !== 'function') throw fail('SITE_DATA_UNSUPPORTED');
    await service.ready;
    if (service.closed) throw fail('APP_CLOSING');
    const remote = await service.remote();
    if (!remote.profiles.some(profile => profile.id === profileId)) throw fail('SITE_DATA_INVALID');
    const session = remote.sessions.find(row => row.profile_id === profileId);
    if (!session) throw fail('SITE_DATA_NOT_RUNNING');
    if (!identifier(session.session_id) || !instance(session.instance_id) || expectedInstance && session.instance_id !== expectedInstance) throw fail('SITE_DATA_STALE');
    if (!engines.has(session.runtime_id)) throw fail('SITE_DATA_UNSUPPORTED');
    return { service, session, endpoint: `/api/sessions/${encodeURIComponent(session.session_id)}/site-cookies` };
  }
  async list(args) {
    request(args);
    const { service, session, endpoint } = await this.session(args.profileId);
    const result = await service.request('POST', endpoint, { instance_id: session.instance_id });
    return project(result?.data, session.instance_id, session.runtime_id);
  }
  async clear(args) {
    request(args, true);
    const { service, session, endpoint } = await this.session(args.profileId, args.instanceId);
    if (session.runtime_id === 'camoufox') throw fail('SITE_DATA_UNSUPPORTED');
    const result = (await service.request('POST', `${endpoint}/clear`, { instance_id: args.instanceId, domain: args.domain }))?.data;
    if (result?.instanceId !== args.instanceId || result?.domain !== args.domain || !Number.isSafeInteger(result?.removed) || result.removed < 0 || result.removed > 10000) throw fail('SITE_DATA_CLEAR_INCOMPLETE');
    return { removed: result.removed, domain: args.domain, instanceId: args.instanceId };
  }
}
