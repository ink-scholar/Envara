import path from 'node:path';
import { execFile, spawn as spawnChild } from 'node:child_process';
import { constants } from 'node:fs';
import { access, lstat, realpath, stat } from 'node:fs/promises';
import { NativeApplicationRouting, applicationRoutingError, applicationRoutingReady, APPLICATION_ROUTING_CHECKS } from './application-routing.mjs';
import { inspectLocalApplication } from './application-service.mjs';
import { verifyPFInstallation } from '../native/macos-pf-routing/controller.mjs';
import { MacOSPFNotionTrial } from './macos-pf-notion-trial.mjs';
import { isIP } from 'node:net';

export const MACOS_PF_ROUTING_BACKEND = 'pf-utun';
export const MACOS_PF_INSTALLED_HELPER = '/Library/PrivilegedHelperTools/io.envara.pf-routing/EnvaraPFHelper';
export const MACOS_PF_ROUTING_CHECKS = Object.freeze([...APPLICATION_ROUTING_CHECKS, 'guard', 'unrelatedApps', 'nativeAcceptance']);
const safeId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,160}$/.test(value);
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
const checks = value => Object.fromEntries(MACOS_PF_ROUTING_CHECKS.map(key => [key, value?.[key] === true]));
const reject = code => { throw applicationRoutingError({ code }); };
const privateString = value => typeof value === 'string' && Buffer.byteLength(value) > 0 && Buffer.byteLength(value) <= 255 && !/[\0\r\n]/.test(value);
/* A locally added application bundle. Bounded and absolute only; the fixed
 * native registry independently inspects and seals the real signed bundle, so
 * this is a candidate path rather than an identity claim. */
const controlledTrialBundle = value => typeof value === 'string' && path.isAbsolute(value) && value.endsWith('.app') &&
  value.length > 5 && value.length <= 4096 && !/[\0\r\n]/.test(value) &&
  value.split('/').every(segment => segment !== '.' && segment !== '..') ? value : null;
const args = value => {
  if (!Array.isArray(value) || value.length > 128 || value.some(item => typeof item !== 'string' || item.length > 8192 || /[\0\r\n]/.test(item))) reject('APPLICATION_ROUTING_PROTOCOL_ERROR');
  return [...value];
};
const environmentKeys = new Set(['PATH', 'HOME', 'USERPROFILE', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'CLAUDE_CONFIG_DIR', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL', 'NPM_CONFIG_USERCONFIG', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM', 'DO_NOT_TRACK', 'DISABLE_TELEMETRY', 'DISABLE_ERROR_REPORTING', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'TZ', 'ENVARA_PROFILE_ID', 'ENVARA_ROUTE_ID']);
function environment(value = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject('APPLICATION_ROUTING_PROTOCOL_ERROR');
  const result = {};
  for (const [key, item] of Object.entries(value)) {
    if (!environmentKeys.has(key) || typeof item !== 'string' || item.length > 32768 || item.includes('\0')) reject('APPLICATION_ROUTING_PROTOCOL_ERROR');
    result[key] = item;
  }
  return result;
}
function verification(value) {
  return { backend: value?.backend === MACOS_PF_ROUTING_BACKEND ? MACOS_PF_ROUTING_BACKEND : null,
    native: value?.native === true, passed: value?.passed === true,
    version: typeof value?.version === 'string' && /^[A-Za-z0-9._/+:-]{1,128}$/.test(value.version) ? value.version : null,
    checks: checks(value?.checks) };
}
export function macOSPFApplicationRoutingReady(value) {
  return value?.backend === MACOS_PF_ROUTING_BACKEND && applicationRoutingReady(value) &&
    value.processScopeVerified === true && value.authorization?.kind === 'privileged-helper' && value.authorization.verified === true &&
    value.verification?.backend === MACOS_PF_ROUTING_BACKEND && value.verification.native === true &&
    typeof value.verification.version === 'string' && /^[A-Za-z0-9._/+:-]{1,128}$/.test(value.verification.version) &&
    MACOS_PF_ROUTING_CHECKS.every(key => value.capabilities?.[key] === true && value.verification.checks?.[key] === true);
}
function sessions(value) {
  if (!Array.isArray(value) || value.length > 4096) return [];
  return value.filter(item => safeId(item?.sessionId) && safeId(item.routeId)).map(item => ({
    sessionId: item.sessionId, routeId: item.routeId,
    status: ['running', 'stopped', 'exited', 'error'].includes(item.status) ? item.status : 'error',
    pid: Number.isSafeInteger(item.pid) && item.pid > 0 ? item.pid : null,
    ...(Number.isSafeInteger(item.exitCode) ? { exitCode: item.exitCode } : {}),
  }));
}
function installationReceipt(value) {
  if (value?.schema !== 'envara.macos-pf-install/v1' || value.action !== 'installedResourcesOnly' ||
      value.installed !== true || typeof value.changed !== 'boolean' || value.ready !== false || value.productionReady !== false ||
      value.reason !== 'installed-resources-only' || typeof value.manifestSHA256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.manifestSHA256) ||
      value.authorized === true || value.protected === true || value.activation === true ||
      Object.entries(value.operations ?? {}).some(([key, enabled]) => key !== 'copyFixedResources' && enabled !== false))
    reject('APPLICATION_ROUTING_PROTOCOL_ERROR');
  return { schema: value.schema, action: 'installedResourcesOnly', installed: true, changed: value.changed,
    manifestSHA256: value.manifestSHA256, ready: false, productionReady: false };
}
// Only the authorizer's fixed result reasons are recognised; any other output,
// including stderr or free text, keeps the generic authorization code.
const INSTALLER_FAILURES = Object.freeze({
  'administrator-authorization-canceled': 'APPLICATION_ROUTING_AUTHORIZATION_CANCELED',
  'administrator-authorization-denied': 'APPLICATION_ROUTING_AUTHORIZATION_DENIED',
  'controlled-runtime-still-present': 'APPLICATION_ROUTING_RUNTIME_PRESENT',
  'existing-installation-conflict': 'APPLICATION_ROUTING_INSTALL_CONFLICT',
  'owned-staging-review-required': 'APPLICATION_ROUTING_INSTALL_REVIEW',
  'installation-maintenance-busy': 'APPLICATION_ROUTING_INSTALL_BUSY',
  'installation-completion-unconfirmed': 'APPLICATION_ROUTING_INSTALL_INCOMPLETE',
});
const INSTALLER_FAILURE_CODES = Object.freeze(['APPLICATION_ROUTING_AUTHORIZATION_REQUIRED', ...Object.values(INSTALLER_FAILURES)]);
function installerFailure(output) {
  try {
    const value = JSON.parse(output);
    if (value?.schema === 'envara.macos-pf-install/v1' && value.installed === false && Object.hasOwn(INSTALLER_FAILURES, value.reason)) return INSTALLER_FAILURES[value.reason];
  } catch {}
  return 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED';
}
function executeInstallation(installerPath, { spawn, timeoutMs, maxBytes = 65536 }) {
  return new Promise((resolve, rejectPromise) => {
    let child, settled = false, output = '', bytes = 0;
    const finish = (code, value) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (code) { try { child?.kill(); } catch {} rejectPromise(applicationRoutingError({ code })); }
      else resolve(value);
    };
    const timer = setTimeout(() => finish('APPLICATION_ROUTING_TIMEOUT'), timeoutMs);
    try {
      child = spawn(installerPath, ['--request-install'], { shell: false, windowsHide: true,
        env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' }, stdio: ['pipe', 'pipe', 'pipe'] });
      child.stdout.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > maxBytes) finish('APPLICATION_ROUTING_PROTOCOL_ERROR'); else output += chunk.toString('utf8');
      });
      // Drain without exposing administrator diagnostics or the private pipe.
      child.stderr.on('data', () => {});
      child.stdin.on('error', () => finish('APPLICATION_ROUTING_UNAVAILABLE'));
      child.once('error', () => finish('APPLICATION_ROUTING_UNAVAILABLE'));
      child.once('close', (exitCode, signal) => {
        if (settled) return;
        if (exitCode !== 0 || signal != null) { finish(signal == null ? installerFailure(output) : 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED'); return; }
        try { finish(null, JSON.parse(output)); } catch { finish('APPLICATION_ROUTING_PROTOCOL_ERROR'); }
      });
      child.stdin.end();
    } catch { finish('APPLICATION_ROUTING_UNAVAILABLE'); }
  });
}

/** PF requires a privileged guard, not an Apple NE identity. Plans grant no routing protection. */
/* The root processes a trial session can leave behind. Matched by exact
 * installed path (or the fixed authorizer arguments), never by name alone. */
const OWNED_ROOT_PREFIXES = Object.freeze(['/Library/PrivilegedHelperTools/io.envara.pf-routing/envara-pf-native ',
  '/Library/PrivilegedHelperTools/io.envara.pf-routing/node ', '/Library/PrivilegedHelperTools/io.envara.pf-routing/mihomo ']);
export function ownedRootSessionInProcessList(commands) {
  return commands.split('\n').some(line => { const command = line.trim();
    return OWNED_ROOT_PREFIXES.some(prefix => command.startsWith(prefix)) ||
      /\/EnvaraPFInstall --(run|request)-controlled-experiment(\s|$)/.test(command); });
}
/* An unreadable process list is treated as a live session: the only outcome of
 * a wrong "absent" here would be quitting while a keeper still depends on the
 * managed route. */
async function ownedRootSessionAlive() {
  try {
    const { stdout } = await new Promise((resolve, reject) => execFile('/bin/ps', ['-axo', 'command='],
      { timeout: 5000, maxBuffer: 4 * 1024 * 1024, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL: 'C' } },
      (error, out) => error ? reject(error) : resolve({ stdout: String(out) })));
    return ownedRootSessionInProcessList(stdout);
  } catch { return true; }
}

export class MacOSPFApplicationRouting {
  constructor({ helperPath, installerPath, native, spawn = spawnChild, executeInstaller,
    installationTimeoutMs = 130000, inspectApplication = inspectLocalApplication, notionTrial, notionAuthorizerPath, onNotionTrialEvent, onNotionTrialDiagnostics,
    rootSessionAlive = ownedRootSessionAlive } = {}) {
    if (typeof rootSessionAlive !== 'function') reject('APPLICATION_ROUTING_PROTOCOL_ERROR');
    this.rootSessionAlive = rootSessionAlive;
    if (installerPath != null && (typeof installerPath !== 'string' || !path.isAbsolute(installerPath) ||
        path.basename(installerPath) !== 'EnvaraPFInstall' || /[\0\r\n]/.test(installerPath))) reject('APPLICATION_ROUTING_UNAVAILABLE');
    if (!Number.isSafeInteger(installationTimeoutMs) || installationTimeoutMs < 1 || installationTimeoutMs > 180000 ||
        (executeInstaller != null && typeof executeInstaller !== 'function')) reject('APPLICATION_ROUTING_PROTOCOL_ERROR');
    this.native = native ?? new NativeApplicationRouting({ helperPath, platform: 'darwin' });
    this.nativeInjected = native != null; this.installerPath = installerPath;
    this.executeInstaller = executeInstaller ?? (file => executeInstallation(file, { spawn, timeoutMs: installationTimeoutMs }));
    this.installationPending = false;
    this.inspectApplication = inspectApplication; this.closed = false; this.routes = new Map();
    this.notionTrial = notionTrial ?? new MacOSPFNotionTrial({ authorizerPath: notionAuthorizerPath, ...(onNotionTrialEvent ? { onEvent: onNotionTrialEvent } : {}),
      ...(onNotionTrialDiagnostics ? { persistDiagnostics: onNotionTrialDiagnostics } : {}) });
  }
  assertOpen() { if (this.closed) reject('APPLICATION_ROUTING_CLOSED'); }
  async nativeStatus() {
    this.assertOpen();
    try { return await this.native.status(); }
    catch { return { installed: false, authorized: false, ready: false }; }
  }
  async status() {
    const value = await this.nativeStatus();
    const pf = value?.backend === MACOS_PF_ROUTING_BACKEND;
    const receipt = verification(pf ? value.verification : null);
    const authorized = pf && value.authorized === true && value.authorization?.kind === 'privileged-helper' && value.authorization.verified === true;
    const capabilities = checks(pf ? value.capabilities : null);
    const ready = macOSPFApplicationRoutingReady(value);
    const reason = ready ? 'ready' : !pf || value.installed !== true ? 'pf-privileged-helper-required' : !authorized ? 'administrator-authorization-required' : 'pf-native-acceptance-required';
    return { platform: 'darwin', backend: MACOS_PF_ROUTING_BACKEND, requiresAppleNetworkExtension: false,
      installed: pf && value.installed === true, authorized, ready, productionReady: ready, protected: ready,
      authorization: { kind: 'privileged-helper', verified: authorized },
      processScopeVerified: pf && value.processScopeVerified === true, capabilities, verification: receipt,
      component: { name: 'envara-pf-routing', version: '1', available: pf && value.component?.available === true,
        installed: pf && value.installed === true, verified: pf && value.component?.verified === true },
      sessions: pf ? sessions(value.sessions) : [], reason };
  }
  async requireReady() {
    const state = await this.status();
    if (!macOSPFApplicationRoutingReady(state)) reject(state.installed !== true ? 'APPLICATION_ROUTING_UNAVAILABLE' : state.authorized !== true ? 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED' : 'APPLICATION_ROUTING_NOT_READY');
    return state;
  }
  async validate(params) {
    this.assertOpen();
    const application = params?.application, workspace = params?.workspace, route = params?.route, managed = params?.managedRoute;
    if (!application || !safeId(application.id) || !safeId(application.profileId) || !workspace || !route || !managed ||
        managed.profileId !== application.profileId || !safeId(managed.proxyId) || !uuid(managed.routeIdentity) || !uuid(managed.coreGeneration) ||
        !Number.isSafeInteger(managed.corePid) || managed.corePid < 1 || managed.coreVersion !== 'v1.19.32' ||
        typeof managed.nodeType !== 'string' || !/^[a-z][a-z0-9-]{0,31}$/.test(managed.nodeType)) reject('APPLICATION_ROUTING_NOT_READY');
    if (route.protocol !== 'socks5' || !['127.0.0.1', '::1'].includes(route.host) || !Number.isSafeInteger(route.port) || route.port < 1 || route.port > 65535 ||
        !privateString(route.username) || !privateString(route.password)) reject('APPLICATION_ROUTING_NOT_READY');
    const udpPolicy = route.udpPolicy ?? (route.udp === true ? 'proxy' : 'block');
    if (!['block', 'proxy'].includes(udpPolicy) || (udpPolicy === 'proxy' && route.udp !== true)) reject('APPLICATION_ROUTING_NOT_READY');
    if (typeof workspace.cwd !== 'string' || !path.isAbsolute(workspace.cwd) || /[\0\r\n]/.test(workspace.cwd) ||
        typeof workspace.timezone !== 'string' || workspace.timezone === 'Local') reject('APPLICATION_ROUTING_NOT_READY');
    try { new Intl.DateTimeFormat('en', { timeZone: workspace.timezone }); }
    catch { reject('APPLICATION_ROUTING_NOT_READY'); }
    let local, cwd;
    try {
      local = await this.inspectApplication(application.path, { platform: 'darwin' });
      cwd = await realpath(workspace.cwd);
      if (cwd !== workspace.cwd || !(await stat(cwd)).isDirectory()) throw new Error();
      await access(cwd, constants.R_OK | constants.X_OK);
    } catch { reject('APPLICATION_ROUTING_NOT_READY'); }
    if (local.identity !== application.identity || local.executablePath !== application.executablePath || local.path !== application.path) reject('APPLICATION_ROUTING_NOT_READY');
    const geolocation = workspace.geolocation == null ? null : workspace.geolocation;
    if (geolocation != null && (!Number.isFinite(geolocation.latitude) || Math.abs(geolocation.latitude) > 90 ||
        !Number.isFinite(geolocation.longitude) || Math.abs(geolocation.longitude) > 180 || !Number.isFinite(geolocation.accuracy) || geolocation.accuracy < 1000)) reject('APPLICATION_ROUTING_NOT_READY');
    if (workspace.locale != null && (typeof workspace.locale !== 'string' || !/^[A-Za-z0-9_.@-]{1,64}$/.test(workspace.locale))) reject('APPLICATION_ROUTING_NOT_READY');
    if (!['off', 'standard', 'strict'].includes(workspace.privacy?.mode ?? 'standard')) reject('APPLICATION_ROUTING_NOT_READY');
    return { application: { id: application.id, profileId: application.profileId, path: local.path, executablePath: local.executablePath,
      identity: local.identity, name: local.name, args: args(application.args ?? []) },
      workspace: { cwd, timezone: workspace.timezone, timezoneSource: ['proxy', 'proxy-egress', 'fixed'].includes(workspace.timezoneSource) ? workspace.timezoneSource : 'unknown',
        locale: workspace.locale ?? null, geolocation: geolocation && { latitude: geolocation.latitude, longitude: geolocation.longitude, accuracy: geolocation.accuracy },
        privacy: { mode: workspace.privacy?.mode ?? 'standard' } },
      route: { protocol: 'socks5', host: route.host, port: route.port, username: route.username, password: route.password, udp: route.udp === true, udpPolicy },
      managedRoute: { profileId: managed.profileId, proxyId: managed.proxyId, nodeType: managed.nodeType, routeIdentity: managed.routeIdentity,
        coreGeneration: managed.coreGeneration, corePid: managed.corePid, coreVersion: managed.coreVersion } };
  }
  async plan(params) {
    const validated = await this.validate(params);
    return { version: 1, backend: MACOS_PF_ROUTING_BACKEND, readOnly: true, protected: false, ready: false, productionReady: false,
      requiresAppleNetworkExtension: false, requiresAdministrator: true, scope: 'owned-process-family',
      environmentId: validated.application.profileId, applicationId: validated.application.id,
      network: { source: 'managed-node', nodeType: validated.managedRoute.nodeType, requiresAuthentication: true, verified: false, udpPolicy: validated.route.udpPolicy },
      workspace: { timezone: validated.workspace.timezone, locale: validated.workspace.locale, geolocation: validated.workspace.geolocation },
      requiredChecks: [...MACOS_PF_ROUTING_CHECKS], reason: 'pf-native-acceptance-required' };
  }
  async setup(params = {}) {
    this.assertOpen();
    if (params.activate !== true) return { ...(await this.status()), readOnly: true, requiresAdministrator: true };
    if (this.installerPath) {
      if (this.installationPending || this.routes.size || this.notionTrial.pending) reject('APPLICATION_ROUTING_NOT_READY');
      this.installationPending = true;
      try {
        try {
          const canonical = await realpath(this.installerPath), info = await lstat(canonical);
          if (canonical !== this.installerPath || !info.isFile() || info.nlink !== 1) throw new Error();
          await access(canonical, constants.R_OK | constants.X_OK);
        } catch { reject('APPLICATION_ROUTING_UNAVAILABLE'); }
        let raw;
        try { raw = await this.executeInstaller(this.installerPath); }
        catch (error) {
          const code = ['APPLICATION_ROUTING_TIMEOUT', 'APPLICATION_ROUTING_PROTOCOL_ERROR', ...INSTALLER_FAILURE_CODES].includes(error?.code)
            ? error.code : 'APPLICATION_ROUTING_UNAVAILABLE';
          reject(code);
        }
        const receipt = installationReceipt(raw);
        this.assertOpen();
        if (!this.nativeInjected) {
          const installed = await verifyPFInstallation();
          if (installed.verified !== true || installed.manifestVerified !== true) reject('APPLICATION_ROUTING_UNAVAILABLE');
        }
        this.native.helperPath = MACOS_PF_INSTALLED_HELPER;
        const status = await this.status();
        // Installing bytes is distinct from a verified guard/authorization.
        return { ...status, authorized: false, ready: false, productionReady: false, protected: false,
          authorization: { kind: 'privileged-helper', verified: false }, installation: receipt };
      } finally { this.installationPending = false; }
    }
    // Injection exists only for native unit-test fixtures. A desktop adapter
    // without its fixed installer must not pretend a read-only setup installs.
    if (!this.nativeInjected) reject('APPLICATION_ROUTING_UNAVAILABLE');
    // A NE helper or a low-level utun primitive cannot become a PF supervisor.
    const value = await this.nativeStatus();
    if (value?.backend !== MACOS_PF_ROUTING_BACKEND) reject('APPLICATION_ROUTING_UNAVAILABLE');
    try { await this.native.setup({ activate: true, backend: MACOS_PF_ROUTING_BACKEND }); }
    catch (error) { throw applicationRoutingError(error); }
    return this.status();
  }
  async reclaim(routeId) {
    const stopped = await this.native.stop({ routeId });
    if (stopped?.stopped !== true) reject('APPLICATION_ROUTING_NOT_READY');
    const revoked = await this.native.revoke({ routeId });
    if (revoked?.revoked !== true) reject('APPLICATION_ROUTING_NOT_READY');
    this.routes.delete(routeId);
  }
  async prepareRoute(params) {
    await this.requireReady();
    const validated = await this.validate(params);
    let result;
    try { result = await this.native.prepareRoute({ ...validated, backend: MACOS_PF_ROUTING_BACKEND }); }
    catch (error) { throw applicationRoutingError(error); }
    if (!safeId(result?.routeId) || this.routes.has(result.routeId)) reject('APPLICATION_ROUTING_PROTOCOL_ERROR');
    this.routes.set(result.routeId, { application: validated.application, workspace: validated.workspace, managedRoute: validated.managedRoute,
      ready: false, gid: Number.isSafeInteger(result.gid) && result.gid >= 7100 && result.gid <= 7999 ? result.gid : null });
    const conflict = [...this.routes].some(([id, prior]) => id !== result.routeId && prior.gid === result.gid && prior.application.profileId !== validated.application.profileId);
    if (result.ready !== true || result.failClosed !== true || result.guardArmed !== true || result.managedRouteVerified !== true ||
        result.profileId !== validated.application.profileId || result.applicationIdentity !== validated.application.identity ||
        result.routeIdentity !== validated.managedRoute.routeIdentity || result.coreGeneration !== validated.managedRoute.coreGeneration ||
        !Number.isSafeInteger(result.consoleUID) || result.consoleUID < 1 || !Number.isSafeInteger(result.gid) || result.gid < 7100 || result.gid > 7999 || conflict ||
        result.verification?.backend !== MACOS_PF_ROUTING_BACKEND || result.verification?.native !== true || result.verification?.passed !== true || verification(result.verification).version == null ||
        MACOS_PF_ROUTING_CHECKS.some(key => result.capabilities?.[key] !== true || result.verification.checks?.[key] !== true)) {
      try { await this.reclaim(result.routeId); } catch { /* Preserve the owned deny route until cleanup can be confirmed. */ }
      reject('APPLICATION_ROUTING_NOT_READY');
    }
    this.routes.get(result.routeId).ready = true;
    return { routeId: result.routeId, ready: true, failClosed: true, guardArmed: true,
      capabilities: checks(result.capabilities), verification: verification(result.verification) };
  }
  async launch(params) {
    await this.requireReady();
    const prepared = this.routes.get(params?.routeId);
    if (!prepared || prepared.ready !== true || prepared.launchAttempted === true || !Number.isSafeInteger(prepared.gid)) reject('APPLICATION_ROUTING_NOT_READY');
    const application = params?.application;
    if (!application || application.id !== prepared.application.id || application.profileId !== prepared.application.profileId ||
        application.path !== prepared.application.path || application.executablePath !== prepared.application.executablePath ||
        application.identity !== prepared.application.identity || params.cwd !== prepared.workspace.cwd) reject('APPLICATION_ROUTING_NOT_READY');
    try {
      const local = await this.inspectApplication(application.path, { platform: 'darwin' });
      const cwd = await realpath(params.cwd);
      if (local.path !== application.path || local.executablePath !== application.executablePath || local.identity !== application.identity ||
          cwd !== prepared.workspace.cwd || !(await stat(cwd)).isDirectory()) throw new Error();
      await access(cwd, constants.R_OK | constants.X_OK);
    } catch { reject('APPLICATION_ROUTING_NOT_READY'); }
    const launchArgs = args(params.args ?? []), env = environment(params.env);
    if ((env.TZ != null && env.TZ !== prepared.workspace.timezone) || (env.ENVARA_PROFILE_ID != null && env.ENVARA_PROFILE_ID !== prepared.application.profileId) ||
        (env.ENVARA_ROUTE_ID != null && env.ENVARA_ROUTE_ID !== params.routeId)) reject('APPLICATION_ROUTING_NOT_READY');
    let result;
    // A timed-out request may already have spawned. Retrying requires confirmed
    // cleanup and a fresh prepare, never reusing this uncertain process family.
    prepared.launchAttempted = true;
    try { result = await this.native.launch({ routeId: params.routeId, backend: MACOS_PF_ROUTING_BACKEND,
      application: { ...prepared.application, args: [...prepared.application.args] }, args: launchArgs, cwd: prepared.workspace.cwd, env }); }
    catch (error) { throw applicationRoutingError(error); }
    if (!safeId(result?.sessionId) || !Number.isSafeInteger(result.pid) || result.pid < 1 || result.routeId !== params.routeId || result.protected !== true || result.guardArmed !== true || result.failClosed !== true) {
      try { await this.reclaim(params.routeId); } catch { /* Keep deny rules on uncertain process exit. */ }
      reject('APPLICATION_ROUTING_PROTOCOL_ERROR');
    }
    return { sessionId: result.sessionId, pid: result.pid, ...(typeof result.startedAt === 'string' && !/[\0\r\n]/.test(result.startedAt) && result.startedAt.length <= 64 ? { startedAt: result.startedAt } : {}) };
  }
  async stop(params) {
    this.assertOpen();
    if (params?.sessionId != null ? !safeId(params.sessionId) || params.routeId != null : !safeId(params?.routeId)) reject('APPLICATION_ROUTING_PROTOCOL_ERROR');
    try { const result = await this.native.stop(params.sessionId ? { sessionId: params.sessionId } : { routeId: params.routeId }); return { stopped: result?.stopped === true }; }
    catch (error) { throw applicationRoutingError(error); }
  }
  async controlledNotionTrialAvailability() {
    this.assertOpen(); return this.notionTrial.available();
  }
  controlledNotionTrialSnapshot({ applicationId } = {}) {
    return this.notionTrial.snapshot(applicationId);
  }
  stopControlledNotionTrial({ applicationId } = {}) {
    this.assertOpen(); return this.notionTrial.stop(applicationId);
  }
  async controlledNotionTrial({ application, context, activationAuthorized } = {}) {
    this.assertOpen();
    /* Any locally added application whose bundle this process can inspect and
     * seal may be attached. The request still carries a real bundle path; the
     * renderer never supplies a route, credential or activation intent. */
    const requestedBundle = controlledTrialBundle(application?.path);
    if (activationAuthorized !== true || !requestedBundle || !safeId(application?.id) || !safeId(application?.profileId) || (application.args?.length ?? 0) !== 0)
      reject('PF_NOTION_TRIAL_REQUEST_INVALID');
    // Recheck before using a private route. Main also checks before resolving it.
    const availability = await this.notionTrial.available();
    if (!availability.controlledNotionTrialAvailable) reject(availability.errorCode);
    if (context?.profileId !== application.profileId || context.network?.ok !== true || !isIP(context.network.ip ?? '') || !context.managedRoute)
      reject('PF_NOTION_TRIAL_CONTEXT_REQUIRED');
    const validated = await this.validate({ application, workspace: context,
      route: { ...context.proxyEndpoint, udpPolicy: 'block' }, managedRoute: context.managedRoute });
    return this.notionTrial.run({ applicationId: application.id, activationAuthorized: true, request: {
      application: { id: application.id, profileId: application.profileId, executablePath: validated.application.executablePath },
      workspace: { cwd: validated.workspace.cwd, timezone: validated.workspace.timezone, locale: validated.workspace.locale,
        timezoneSource: ['proxy', 'proxy-egress'].includes(context.timezoneSource) ? context.timezoneSource : 'fixed' },
      route: { protocol: 'socks5', host: validated.route.host, port: validated.route.port,
        username: validated.route.username, password: validated.route.password, udpPolicy: 'block' },
      managedRoute: validated.managedRoute,
    } });
  }
  async revoke(params) {
    this.assertOpen();
    if (!safeId(params?.routeId)) reject('APPLICATION_ROUTING_PROTOCOL_ERROR');
    try { const result = await this.native.revoke({ routeId: params.routeId }); if (result?.revoked === true) this.routes.delete(params.routeId); return { revoked: result?.revoked === true }; }
    catch (error) { throw applicationRoutingError(error); }
  }
  async shutdown() {
    this.assertOpen();
    if (this.notionTrial.pending) {
      this.notionTrial.stop(this.notionTrial.state.applicationId);
      await this.notionTrial.pending;
    }
    /* Quitting Envara ends every attached application and the one shared
     * authorized root session the launch opened. The session is closed here so
     * the root controller cleans up and exits; no privileged daemon is left
     * behind. A recycled Electron process must not inherit a finished session. */
    if (typeof this.notionTrial.disposeShared === 'function') await this.notionTrial.disposeShared().catch(() => {});
    /* An unconfirmed cleanup used to make the app impossible to quit, even after
     * the system was verified clean and no Envara root process remained, which
     * forced a kill. Quitting changes no root state; what must not happen is
     * withdrawing the managed route while a root keeper may still depend on it.
     * So refuse only while such a process is actually alive. */
    if (this.notionTrial.state?.cleanupUncertain === true && await this.rootSessionAlive()) reject('APPLICATION_ROUTING_CLEANUP_UNCONFIRMED');
    for (const routeId of this.routes.keys()) await this.reclaim(routeId);
    await this.native.shutdown(); this.closed = true;
  }
}
