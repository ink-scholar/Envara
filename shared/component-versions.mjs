const activeStates = new Set(['starting', 'running', 'closing', 'stopping']);
const engineNames = { camoufox: 'Camoufox', cloakbrowser: 'CloakBrowser', 'browseforge-chromium': 'BrowseForge Chromium' };
const safeId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(value) ? value : null;
const safeName = value => typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 160) : '';
export const componentVersion = value => typeof value === 'string' && /^v?\d[0-9A-Za-z.+_-]{0,95}$/.test(value) ? value : null;

// Only explicitly selected public fields leave this projection. Terminal output,
// credentials, executable paths and backend error messages are never included.
export function componentVersionSnapshot({ snapshot = {}, terminals = null, claude = [], checkedAt = null } = {}) {
  const profiles = (Array.isArray(snapshot.profiles) ? snapshot.profiles : []).filter(item => safeId(item?.id));
  const profileNames = new Map(profiles.map(item => [item.id, safeName(item.name) || item.id]));
  const terminalKnown = Array.isArray(terminals?.profiles);
  const browserSessions = profiles.filter(item => activeStates.has(item.status)).map(item => ({
    id: item.id, kind: 'browser', profileId: item.id, name: profileNames.get(item.id), status: item.status,
  }));
  const terminalSessions = (terminalKnown ? terminals.profiles : []).flatMap(profile =>
    (Array.isArray(profile?.sessions) ? profile.sessions : []).filter(item => safeId(item?.sessionId) && activeStates.has(item.status)).map(item => ({
      id: item.sessionId, kind: 'terminal', profileId: safeId(profile.profileId), name: safeName(item.savedTerminalName),
      claude: item.kind === 'claude-code', status: item.status,
    })));
  const applicationSessions = (Array.isArray(snapshot.applications) ? snapshot.applications : []).filter(item => safeId(item?.id) &&
    (activeStates.has(item.status) || item.sessionId || item.notionTrial?.active === true || item.notionTrial?.cleanupUncertain === true)).map(item => ({
      id: item.id, kind: 'application', profileId: safeId(item.profileId), name: safeName(item.name), status: activeStates.has(item.status) ? item.status : 'stopping',
    }));
  const allSessions = [...browserSessions, ...terminalSessions, ...applicationSessions].map(item => ({ ...item, profileName: profileNames.get(item.profileId) || '' }));
  const system = snapshot.system ?? {};
  const appVersion = componentVersion(system.appVersion);
  const rows = [{ id: 'application', kind: 'application', name: 'Envara', version: appVersion,
    versionSource: appVersion ? 'running-app' : 'unknown', runningVersion: appVersion, status: 'running', support: 'unknown',
    impact: 'application', sessions: allSessions, sessionsKnown: terminalKnown, action: 'application-update', blocked: false }];
  for (const [id, name] of Object.entries(engineNames)) {
    const engine = (Array.isArray(snapshot.engines) ? snapshot.engines : []).find(item => item?.id === id);
    const version = engine?.installed === true ? componentVersion(engine.version) : null;
    const sessions = allSessions.filter(item => item.kind === 'browser' || item.kind === 'terminal' && item.claude);
    rows.push({ id, kind: 'browser', name, version, versionSource: version ? 'installation-record' : 'unknown', runningVersion: null,
      status: !engine ? 'unknown' : engine.installing ? 'updating' : engine.installed ? 'installed' : 'missing',
      support: typeof engine?.supported === 'boolean' ? engine.supported ? 'supported' : 'unsupported' : 'unknown',
      impact: 'browser', sessions,
      sessionsKnown: terminalKnown, action: 'install-engine',
      // Installation restarts the common browser service, not just this engine.
      blocked: engine?.supported !== true || engine.installing === true || !terminalKnown || sessions.length > 0 });
  }
  const core = system.proxyCore;
  const coreVersion = componentVersion(core?.version);
  rows.push({ id: 'proxy-core', kind: 'proxy', name: 'Mihomo', version: coreVersion, versionSource: coreVersion ? 'bundled-package' : 'unknown',
    runningVersion: null, status: !core ? 'unknown' : core.supported ? 'ready' : 'unavailable', support: 'unknown',
    impact: 'bundled', sessions: allSessions, sessionsKnown: terminalKnown, action: 'project', blocked: false });
  const routing = snapshot.applicationRouting;
  const routingVersion = routing?.installed === true ? componentVersion(routing.verification?.version) : null;
  rows.push({ id: 'application-routing', kind: 'routing', name: safeName(routing?.component?.name), version: routingVersion,
    bundledVersion: componentVersion(routing?.component?.version), versionSource: routingVersion ? 'installation-report' : 'unknown',
    runningVersion: null, status: !routing ? 'unknown' : routing.ready ? 'ready' : routing.installed ? 'needs-attention' : 'missing', support: 'unknown',
    impact: 'routing', sessions: allSessions.filter(item => item.kind === 'application'), sessionsKnown: Array.isArray(snapshot.applications),
    action: 'routing', blocked: !routing || routing.ready === true || routing.component?.available !== true || routing.component?.verified !== true || allSessions.some(item => item.kind === 'application') });
  for (const profile of profiles) {
    const installation = claude.find(item => item.profileId === profile.id);
    const version = installation?.installed === true ? componentVersion(installation.version) : null;
    rows.push({ id: `claude-${profile.id}`, kind: 'claude', name: 'Claude Code', profileId: profile.id, profileName: profileNames.get(profile.id),
      version, versionSource: version ? 'validated-installation-entry' : 'unknown', runningVersion: null,
      status: !installation || installation.status === 'unknown' ? 'unknown' : installation.errorCode ? 'needs-attention' : installation.installed ? 'installed' : 'missing',
      support: typeof installation?.supported === 'boolean' ? installation.supported ? 'supported' : 'unsupported' : 'unknown',
      impact: 'claude', sessions: allSessions.filter(item => item.kind === 'terminal' && item.claude && item.profileId === profile.id),
      sessionsKnown: terminalKnown, action: 'terminal', blocked: installation?.supported !== true });
  }
  return { schema: 'envara.component-versions', version: 1,
    checkedAt: typeof checkedAt === 'string' && Number.isFinite(Date.parse(checkedAt)) ? new Date(checkedAt).toISOString() : null, rows };
}
