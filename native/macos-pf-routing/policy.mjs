import { createHash, randomUUID } from 'node:crypto';
import { isIP } from 'node:net';

// Historical frozen namespace only; never use it for a new routing run.
export const PF_ROUTING_ANCHOR = 'io.envara.pf.root.v1';
export const PF_ROUTING_NAMESPACE = 'io.envara.pf.run.';
export const isPFRoutingRunId = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
/* A stable identity in the canonical lowercase UUID v4 shape the native side
 * accepts, derived from fixed parts. The same environment and the same
 * application therefore always reach the same registration and data directory,
 * instead of a fresh random one on every attach. */
export function stableEnvaraUUID(namespace, ...parts) {
  if (typeof namespace !== 'string' || !/^envara\.[a-z0-9.-]+\/v[0-9]+$/.test(namespace) || !parts.length ||
      parts.some(part => typeof part !== 'string' || !part || part.length > 4096 || part.includes('\0'))) throw new TypeError('stable identity input invalid');
  const bytes = createHash('sha256').update([namespace, ...parts].join('\0')).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40; bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
export const pfApplicationRegistrationId = bundlePath => stableEnvaraUUID('envara.application-registration/v1', bundlePath);
export const pfAttachEnvironmentId = profileId =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(profileId ?? '') ? profileId : stableEnvaraUUID('envara.attach-environment/v1', profileId);
export function pfRoutingAnchor(runId) {
  if (!isPFRoutingRunId(runId)) throw fail('PF_ROUTING_INVALID_RUN');
  return `${PF_ROUTING_NAMESPACE}${runId}`;
}
export const PF_ROUTING_VERSION = '1';
export const PF_ROUTING_GID_MIN = 7100;
export const PF_ROUTING_GID_MAX = 7999;
export const PF_ROUTING_CHECKS = Object.freeze(['tcp', 'udp', 'dns', 'childProcesses', 'failClosed']);
export const PF_ROUTING_GATES = Object.freeze([
  'nativeAcceptance', 'freshGroup', 'processCredentials', 'inheritedDescriptors',
  'externalHelpers', 'dnsRealm', 'ipv6', 'nonTcpUdp', 'exactStateCleanup',
  'utunIdentityReuse', 'wholeGuardCrash', 'unrelatedApplications', 'halfClose',
]);
const fail = code => Object.assign(new Error('macOS PF routing policy is not ready'), { code });
const object = value => value != null && typeof value === 'object' && !Array.isArray(value);
const clone = value => structuredClone(value);
const digest = value => createHash('sha256').update(value).digest('hex').slice(0, 24);
function identifier(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(value)) throw fail('PF_ROUTING_INVALID_ID');
  return value;
}
function gid(value) {
  // Allocation and conflict checks belong to the privileged registry, never the UI.
  if (!Number.isSafeInteger(value) || value < PF_ROUTING_GID_MIN || value > PF_ROUTING_GID_MAX) throw fail('PF_ROUTING_INVALID_GID');
  return value;
}
function ipv4(value) {
  if (typeof value !== 'string' || isIP(value) !== 4 || value.split('.').some(part => String(Number(part)) !== part)) throw fail('PF_ROUTING_INVALID_TUNNEL');
  const bytes = value.split('.').map(Number);
  if (bytes[0] === 0 || bytes[0] === 127 || bytes[0] >= 224 || (bytes[0] === 169 && bytes[1] === 254)) throw fail('PF_ROUTING_INVALID_TUNNEL');
  return value;
}
function tunnel(value, required = false) {
  if (value == null && !required) return null;
  if (!object(value) || typeof value.interfaceName !== 'string' || !/^utun(?:0|[1-9][0-9]{0,5})$/.test(value.interfaceName) ||
      !Number.isSafeInteger(value.pid) || value.pid < 2 || value.pid > 0x7fffffff) throw fail('PF_ROUTING_INVALID_TUNNEL');
  return { interfaceName: value.interfaceName, pid: value.pid,
    instanceId: identifier(value.instanceId), ipv4Address: ipv4(value.ipv4Address) };
}
function mode(value) {
  if (value == null) return 'blocked';
  if (!['blocked', 'routed'].includes(value)) throw fail('PF_ROUTING_INVALID_MODE');
  return value;
}
function udp(value) {
  if (value == null) return 'block';
  if (!['block', 'proxy'].includes(value)) throw fail('PF_ROUTING_INVALID_UDP_POLICY');
  return value;
}
function route(value) {
  if (!object(value)) throw fail('PF_ROUTING_INVALID_ROUTE');
  const selectedMode = mode(value.mode);
  return { environmentId: identifier(value.environmentId), gid: gid(value.gid),
    mode: selectedMode, udpPolicy: udp(value.udpPolicy),
    tunnel: tunnel(value.tunnel, selectedMode === 'routed') };
}
function routes(values) {
  if (!Array.isArray(values) || values.length > 256) throw fail('PF_ROUTING_INVALID_ROUTE');
  const selected = values.map(route).sort((a, b) => a.environmentId < b.environmentId ? -1 : a.environmentId > b.environmentId ? 1 : 0);
  const ids = new Set(), gids = new Set(), interfaces = new Set(), instances = new Set(), addresses = new Set();
  for (const item of selected) {
    if (ids.has(item.environmentId) || gids.has(item.gid) || (item.tunnel &&
        (interfaces.has(item.tunnel.interfaceName) || instances.has(item.tunnel.instanceId) || addresses.has(item.tunnel.ipv4Address)))) throw fail('PF_ROUTING_IDENTITY_CONFLICT');
    ids.add(item.environmentId); gids.add(item.gid);
    if (item.tunnel) { interfaces.add(item.tunnel.interfaceName); instances.add(item.tunnel.instanceId); addresses.add(item.tunnel.ipv4Address); }
  }
  return selected;
}
function label(item, suffix, runId) { return `envara_${digest(`${runId}|${item.environmentId}`)}_${suffix}`; }
function managedProxy(value) {
  if (!object(value) || value.protocol !== 'socks5' || !['127.0.0.1', '::1'].includes(value.host) ||
      !Number.isSafeInteger(value.port) || value.port < 1 || value.port > 65535 ||
      ['username', 'password'].some(key => typeof value[key] !== 'string' || Buffer.byteLength(value[key]) < 1 || Buffer.byteLength(value[key]) > 255 || /[\0\r\n]/.test(value[key]))) throw fail('PF_ROUTING_MANAGED_PROXY_REQUIRED');
  return { protocol: 'socks5', host: value.host, port: value.port, username: value.username, password: value.password };
}

/**
 * Desired rules only. No system I/O, global PF flush, route, DNS, or installation.
 * Darwin group attribution covers TCP/UDP sockets, not all IP protocols or
 * requests delegated to mDNSResponder. Even blocked rules do not prove a kill
 * switch: existing floating states can bypass them, and a kif can follow a
 * replacement interface with the same utun name. Native acceptance is separate.
 */
export function createPFRoutingPolicy(input = [], { runId } = {}) {
  const anchor = pfRoutingAnchor(runId);
  const selected = routes(input), lines = [];
  for (const item of selected) {
    // No general loopback exception: an application must not escape through an
    // unrelated local proxy. Unix-domain IPC is unaffected by these IP rules.
    lines.push(`block return out quick on lo0 proto { tcp udp } from any to any group ${item.gid} label "${label(item, 'loopback', runId)}"`);
    lines.push(`block return out quick inet6 proto { tcp udp } from any to any group ${item.gid} label "${label(item, 'ipv6', runId)}"`);
    if (item.udpPolicy === 'block') lines.push(`block return out quick inet proto udp from any to any group ${item.gid} label "${label(item, 'udp', runId)}"`);
    if (item.mode === 'routed') {
      const proto = item.udpPolicy === 'proxy' ? '{ tcp udp }' : 'tcp';
      lines.push(`pass out quick on ! lo0 route-to (${item.tunnel.interfaceName} ${item.tunnel.ipv4Address}) inet proto ${proto} from any to any group ${item.gid} keep state label "${label(item, 'route', runId)}"`);
    }
    lines.push(`block return out quick proto { tcp udp } from any to any group ${item.gid} label "${label(item, 'blocked', runId)}"`);
  }
  return { schema: 'envara.macos-pf-policy', version: 1, runId, anchor,
    rules: lines.length ? `${lines.join('\n')}\n` : '', routes: selected,
    ready: false, failClosed: false, nativeAcceptanceRequired: true,
    gates: Object.fromEntries(PF_ROUTING_GATES.map(key => [key, false])) };
}

function fixtureDestinations(values) {
  if (!Array.isArray(values) || !values.length || values.length > 16) throw fail('PF_ROUTING_INVALID_FIXTURE');
  const seen = new Set();
  return values.map(value => {
    if (!object(value) || !Array.isArray(value.ports) || !value.ports.length || value.ports.length > 8) throw fail('PF_ROUTING_INVALID_FIXTURE');
    const host = ipv4(value.host), ports = [...new Set(value.ports)].sort((a, b) => a - b);
    // Documentation-only destination ranges are mapped by the owned local
    // fixture SOCKS server. 1.1.1.1:53 is only its synthetic DNS endpoint.
    const documentationHost = /^(?:192\.0\.2|198\.51\.100|203\.0\.113)\./.test(host);
    if (ports.length !== value.ports.length || ports.some(port => !Number.isSafeInteger(port) ||
        !(documentationHost && port >= 44441 && port <= 44444 || host === '1.1.1.1' && port === 53))) throw fail('PF_ROUTING_INVALID_FIXTURE');
    if (seen.has(host)) throw fail('PF_ROUTING_INVALID_FIXTURE'); seen.add(host);
    return { host, ports };
  }).sort((a, b) => a.host < b.host ? -1 : a.host > b.host ? 1 : 0);
}
function portsExpression(ports) { return ports.length === 1 ? String(ports[0]) : `{ ${ports.join(', ')} }`; }

/**
 * Cold-fixture candidate, not a production lifecycle or kill-switch proof.
 * XNU pf.c:9307-9314 supports route-to with s == NULL. Both directions need
 * no state; otherwise unrelated baseline inbound pass rules may create state.
 * Existing state still wins before rules, so the executor must reserve fresh
 * socket tuples and prove absence before and after the experiment. A fresh GID
 * alone is not sufficient. No state is killed or flushed by this plan.
 */
export function createStatelessFixturePFRoutingPolicy(input = [], { fixtureDestinations: destinations, runId } = {}) {
  const anchor = pfRoutingAnchor(runId);
  const selected = routes(input), targets = fixtureDestinations(destinations), lines = [];
  for (const item of selected) {
    lines.push(`block return out quick on lo0 proto { tcp udp } from any to any group ${item.gid} label "${label(item, 'loopback', runId)}"`);
    lines.push(`block return out quick inet6 proto { tcp udp } from any to any group ${item.gid} label "${label(item, 'ipv6', runId)}"`);
    if (item.udpPolicy === 'block') lines.push(`block return out quick inet proto udp from any to any group ${item.gid} label "${label(item, 'udp', runId)}"`);
    if (item.mode === 'routed') {
      for (const target of targets) {
        for (const protocol of item.udpPolicy === 'proxy' ? ['tcp', 'udp'] : ['tcp']) {
          const ports = portsExpression(target.ports), suffix = digest(`${item.environmentId}:${target.host}:${ports}:${protocol}`).slice(0, 12);
          // Only this owned tunnel's reserved fixture replies can match. This
          // cannot change inbound behavior on an unrelated VPN/interface.
          lines.push(`pass in quick on ${item.tunnel.interfaceName} inet proto ${protocol} from ${target.host} port ${ports} to any flags any no state label "${label(item, `in_${suffix}`, runId)}"`);
          lines.push(`pass out quick on ! lo0 route-to (${item.tunnel.interfaceName} ${item.tunnel.ipv4Address}) inet proto ${protocol} from any to ${target.host} port ${ports} group ${item.gid} flags any no state label "${label(item, `out_${suffix}`, runId)}"`);
        }
      }
      // Reject every other injected TCP/UDP reply on the owned fixture utun;
      // do not let baseline default pass create state behind this anchor.
      lines.push(`block return in quick on ${item.tunnel.interfaceName} proto { tcp udp } from any to any label "${label(item, 'fixture_in_block', runId)}"`);
    }
    lines.push(`block return out quick proto { tcp udp } from any to any group ${item.gid} label "${label(item, 'blocked', runId)}"`);
  }
  return { schema: 'envara.macos-pf-stateless-fixture', version: 1, runId, anchor,
    rules: lines.length ? `${lines.join('\n')}\n` : '', routes: selected, fixtureDestinations: targets,
    statePolicy: 'stateless-fixture', fixtureOnly: true, executable: false,
    ready: false, failClosed: false, productionReady: false, nativeAcceptanceRequired: true,
    gates: Object.fromEntries(PF_ROUTING_GATES.map(key => [key, false])),
    experiment: {
      requires: ['runBoundOwnedRootHook', 'noEarlierMatchingQuickRule', 'freshPrivateGroup', 'ownedTunnelIdentity',
        'coldSpawnClosedDescriptors', 'boundFreshSourceTuples', 'preflightMatchingStatesAbsent',
        'inboundAndOutboundNoState', 'postflightMatchingStatesAbsent'],
      cleanup: ['stop-and-confirm-owned-fixture-processes', 'confirm-matching-states-absent',
        'retain-group-deny-until-processes-stopped', 'remove-only-owned-fixture-rules', 'stop-only-owned-transport'],
      onUnexpectedState: 'retain-owned-guardian-and-deny-policy; refuse-automatic-cleanup',
      createsStateByDesign: false, statesAbsenceVerified: false,
    } };
}

function sameTunnel(a, b) {
  return a === null && b === null || object(a) && object(b) &&
    ['interfaceName', 'pid', 'instanceId', 'ipv4Address'].every(key => a[key] === b[key]);
}
function affectedRoute(a, b) {
  return !a || !b || a.gid !== b.gid || a.mode !== b.mode || a.udpPolicy !== b.udpPolicy || !sameTunnel(a.tunnel, b.tunnel);
}
function stateScope(item, runId) {
  return { environmentId: item.environmentId, gid: item.gid,
    labels: ['loopback', 'ipv6', 'udp', 'route', 'blocked'].map(suffix => label(item, suffix, runId)) };
}

/** An executor must satisfy every precondition before committing this plan. */
export function planPFTransition({ current = [], next = [], runId } = {}) {
  const anchor = pfRoutingAnchor(runId);
  const before = routes(current), after = routes(next), oldById = new Map(before.map(item => [item.environmentId, item]));
  const nextById = new Map(after.map(item => [item.environmentId, item]));
  const changedOld = before.filter(item => affectedRoute(item, nextById.get(item.environmentId)));
  const changedNew = after.filter(item => affectedRoute(oldById.get(item.environmentId), item));
  const changed = [...new Set([...changedOld, ...changedNew].map(item => item.environmentId))].sort();
  const policy = createPFRoutingPolicy(after, { runId });
  if (!changed.length) return { schema: 'envara.macos-pf-transition', version: 1, executable: false, ready: false, failClosed: false, changed, steps: [], policy };
  const preconditions = [...PF_ROUTING_GATES, 'runBoundOwnedRootHook', 'exclusiveRegistryLock', 'ownedTransportIdentity'];
  const steps = [];
  if (changedOld.length) {
    steps.push({ kind: 'stop-owned-processes', environments: changedOld.map(item => item.environmentId), requireConfirmedStopped: true });
    // Do not invent a safe pfctl invocation: -i utun -F states misses floating
    // routed states, and -k address can terminate unrelated applications.
    steps.push({ kind: 'purge-exact-owned-states', scopes: changedOld.map(item => stateScope(item, runId)),
      requireVerifiedStateAttribution: true, requireConfirmedEmpty: true, command: null });
  }
  if (changedNew.length) steps.push({ kind: 'verify-fresh-groups-and-owned-transports', routes: changedNew, requireNoInheritedNetworkDescriptors: true });
  steps.push({ kind: 'validate-owned-anchor', executable: '/sbin/pfctl', argv: ['-n', '-a', anchor, '-f', '-'], stdin: policy.rules });
  steps.push({ kind: 'replace-owned-anchor', executable: '/sbin/pfctl', argv: ['-a', anchor, '-f', '-'], stdin: policy.rules,
    requireConfirmedStateCleanup: changedOld.length > 0, requireNativeAcceptance: true });
  const removedTransports = changedOld.filter(item => item.tunnel && !sameTunnel(item.tunnel, nextById.get(item.environmentId)?.tunnel ?? null));
  if (removedTransports.length) steps.push({ kind: 'teardown-owned-transports', transports: removedTransports.map(item => ({ environmentId: item.environmentId, ...item.tunnel })),
    requireProcessesStopped: true, requireStatesEmpty: true });
  return { schema: 'envara.macos-pf-transition', version: 1, executable: false, ready: false, failClosed: false,
    changed, preconditions, steps, policy };
}

/** In-memory planning lifecycle. Desired modes are never installation evidence. */
export class MacOSPFPolicyPlanner {
  #routes = new Map();
  #proxies = new Map();
  #closed = false;
  #runId;
  constructor({ runId = randomUUID() } = {}) { pfRoutingAnchor(runId); this.#runId = runId; }
  #assertOpen() { if (this.#closed) throw fail('PF_ROUTING_CLOSED'); }
  #find(environmentId) {
    this.#assertOpen(); const item = this.#routes.get(identifier(environmentId));
    if (!item) throw fail('PF_ROUTING_ROUTE_NOT_FOUND'); return item;
  }
  #values() { return [...this.#routes.values()]; }
  prepareRoute(input) {
    this.#assertOpen();
    const item = route({ ...input, mode: 'blocked' }), proxy = managedProxy(input?.proxy);
    if (this.#routes.has(item.environmentId)) throw fail('PF_ROUTING_ROUTE_EXISTS');
    const before = this.#values(), next = [...before, item]; routes(next);
    const plan = planPFTransition({ runId: this.#runId, current: before, next });
    this.#routes.set(item.environmentId, item); this.#proxies.set(item.environmentId, proxy);
    return { routeId: item.environmentId, ...plan };
  }
  planActivation(environmentId) {
    const item = this.#find(environmentId), before = this.#values();
    const next = route({ ...item, mode: 'routed' });
    const plan = planPFTransition({ runId: this.#runId, current: before, next: before.map(value => value.environmentId === environmentId ? next : value) });
    this.#routes.set(environmentId, next);
    return { routeId: environmentId, ...plan };
  }
  observeRuntime(environmentId, witness) {
    const item = this.#find(environmentId);
    let observed = null;
    try { observed = tunnel(witness, true); } catch {}
    if (sameTunnel(item.tunnel, observed) && observed !== null) return { changed: false, ready: false, failClosed: false };
    const before = this.#values(), blocked = { ...item, mode: 'blocked' };
    const plan = planPFTransition({ runId: this.#runId, current: before, next: before.map(value => value.environmentId === environmentId ? blocked : value) });
    this.#routes.set(environmentId, blocked);
    return { ...plan, runtimeIdentityLost: true, retainBlockingPolicy: true,
      reason: 'PF_ROUTING_TRANSPORT_IDENTITY_LOST' };
  }
  planRevoke(environmentId) {
    this.#find(environmentId);
    return planPFTransition({ runId: this.#runId, current: this.#values(), next: this.#values().filter(item => item.environmentId !== environmentId) });
  }
  release(environmentId, { ownedProcessesStopped = false, ownedStatesEmpty = false } = {}) {
    this.#find(environmentId);
    if (ownedProcessesStopped !== true || ownedStatesEmpty !== true) throw fail('PF_ROUTING_CLEANUP_REQUIRED');
    // These are executor observations, not permission to install/remove rules.
    this.#routes.delete(environmentId); this.#proxies.delete(environmentId);
    return { released: true, ready: false };
  }
  privateTransportConfig(environmentId) {
    const item = this.#find(environmentId);
    return { environmentId, tunnel: clone(item.tunnel), proxy: clone(this.#proxies.get(environmentId)),
      udpPolicy: item.udpPolicy, directFallback: false, dns: { systemConfiguration: 'unchanged', realmIsolationVerified: false } };
  }
  snapshot() {
    return { schema: 'envara.macos-pf-status', version: 1, platform: 'darwin', runId: this.#runId, anchor: pfRoutingAnchor(this.#runId),
      installed: false, authorized: false, ready: false, failClosed: false, processScopeVerified: false,
      status: this.#closed ? 'closed' : 'incomplete',
      capabilities: Object.fromEntries(PF_ROUTING_CHECKS.map(key => [key, false])),
      verification: { passed: false, version: PF_ROUTING_VERSION, checks: Object.fromEntries(PF_ROUTING_CHECKS.map(key => [key, false])) },
      gates: Object.fromEntries(PF_ROUTING_GATES.map(key => [key, false])),
      routes: clone(this.#values()),
      limits: { scope: 'new-group-owned-tcp-udp-sockets', inheritedDescriptors: 'unverified',
        systemDns: 'unverified', externalHelpers: 'unverified', ipv6: 'blocked-tcp-udp-only',
        otherProtocols: 'unverified', interfaceNameReuse: 'unverified', globalNetworkChanges: false } };
  }
  close() {
    // Closing the planner cannot revoke real PF rules. An executor must stop
    // children and clear exact owned states first; its kernel blocks must stay.
    const before = this.#values(), next = before.map(item => ({ ...item, mode: 'blocked' }));
    const plan = planPFTransition({ runId: this.#runId, current: before, next });
    for (const item of next) this.#routes.set(item.environmentId, item);
    this.#closed = true; this.#proxies.clear();
    return { ...plan, closed: true, retainBlockingPolicy: true, requiredCleanup: clone(before) };
  }
}
