import fs from 'node:fs/promises';
import net from 'node:net';
import dgram from 'node:dgram';
import { execFile } from 'node:child_process';
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { SocketReader } from '../macos-local-routing/socks-stream.mjs';
import { validateDnsQuery } from '../macos-local-routing/dns-wire.mjs';
import { makeCachedFixtureDnsResponse, createUnboundLoopbackControl } from '../../scripts/macos-app-proxy-fixture-matrix.mjs';
import { PF_ROUTING_NAMESPACE, isPFRoutingRunId, pfRoutingAnchor } from './policy.mjs';

export const PF_ACCEPTANCE_PROTOCOL = 'envara-pf-acceptance/v1';
// A plan describes the namespace prefix; each actual run binds a complete UUID.
export const PF_ACCEPTANCE_ANCHOR = PF_ROUTING_NAMESPACE;
export const PF_ACCEPTANCE_HELPER_ROOT = '/Library/PrivilegedHelperTools/io.envara.pf-routing';
export const PF_ACCEPTANCE_HELPER = `${PF_ACCEPTANCE_HELPER_ROOT}/EnvaraPFHelper`;
export const PF_FIXTURE_TARGET = '198.51.100.42';
export const PF_FIXTURE_UDP_COUNTS = Object.freeze(['udpAssociations', 'udpPacketsReceived', 'udpPeerRejected', 'udpHeaderRejected', 'udpDestinationRejected', 'udpChallengeRejected', 'udpDNSRejected', 'udpRepliesQueued', 'udpReplySendFailed', 'udpSocketErrors']);
export function snapshotPFFixtureUDP(value) {
  if (!value || PF_FIXTURE_UDP_COUNTS.some(key => !Number.isSafeInteger(value[key]) || value[key] < 0 || value[key] > 1048576)) return null;
  return Object.fromEntries(PF_FIXTURE_UDP_COUNTS.map(key => [key, value[key]]));
}
export const PF_FIXTURE_PORTS = Object.freeze({ echo: 44441, halfClose: 44442, hold: 44443, udp: 44444 });
export const PF_ACCEPTANCE_CASES = Object.freeze([
  ['realm-identities', 'Two distinct groups and tunnel instances; exact parent, child and detached process births.'],
  ['tcp-concurrent', 'Six concurrent TCP probes to one reserved destination reach only their authenticated route.'],
  ['tcp-half-close', 'All upload bytes reach the upstream before FIN; the complete response arrives after FIN.'],
  ['udp-concurrent', 'Six UDP probes to the same reserved destination receive their own route response.'],
  ['udp-block', 'A blocked UDP policy has native zero-egress evidence while the other realm remains usable.'],
  ['dns-same-hostname-cold', 'Concurrent system resolution of one fresh synthetic hostname returns different realm answers.'],
  ['dns-same-hostname-warm', 'Repeated and child system resolution preserves those realm answers without cache crossover.'],
  ['unbound-dns', 'The unbound resolver never receives either synthetic realm answer; host DNS configuration is unchanged.'],
  ['first-packet', 'Before policy acknowledgement no selected first packet reaches a physical interface.'],
  ['core-crash', 'An owned core is terminated; existing and new selected flows stop while the other realm continues.'],
  ['helper-crash', 'The whole owned supervisor is terminated; an independent native observer proves both realms remain blocked.'],
  ['utun-reuse', 'An unrelated replacement reuses the old interface name and receives zero selected packets.'],
  ['ipv6-icmp-raw', 'IPv6, ICMP and raw sockets have native group attribution and the configured deny policy.'],
  ['precreated-fd', 'Cold exec closes a real inherited connected socket before any selected fixture resumes.'],
  ['exact-state-purge', 'Only exact owned state IDs are removed; unrelated rules, states, routes and DNS remain intact.'],
  ['cleanup', 'All owned processes, tunnel instances, states and anchor are gone; unrelated configuration is unchanged.'],
].map(([id, purpose]) => Object.freeze({ id, purpose })));
export const PF_CONTROLLED_EXTRA_CASES = Object.freeze([
  Object.freeze({ id: 'dns-tcp53', purpose: 'A real fixture TCP/53 query is answered only by its own authenticated SOCKS node.' }),
  Object.freeze({ id: 'dns-block', purpose: 'Fixture UDP/TCP DNS deny attempts have native zero-egress evidence without modifying host DNS.' }),
]);
export const PF_CONTROLLED_CASE_IDS = Object.freeze([...PF_ACCEPTANCE_CASES, ...PF_CONTROLLED_EXTRA_CASES].map(c => c.id));
const roles = Object.freeze(['parent', 'child', 'detached']);
const slots = Object.freeze(['one', 'two']);
const codePattern = /^[A-Z][A-Z0-9_]{0,63}$/;
const ownHostname = /^[a-z0-9-]{1,63}\.envara-fixture\.test$/;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const birth = /^\d{1,20}:\d{1,9}$/;
const fixedFlags = Object.freeze({ acceptanceOnly: true, productionReady: false, ready: false,
  productionReceiptAllowed: false, userApplicationsTested: false, automaticChildren: false,
  entireGuardCrashTested: false });
function failed(code) { return Object.assign(new Error('Owned PF acceptance operation refused'), { code }); }
function safeCode(error) { return codePattern.test(error?.code ?? '') ? error.code : 'PF_ACCEPTANCE_OPERATION_FAILED'; }
function nativeResult(value, runId) {
  if (!value || value.acceptanceProtocol !== PF_ACCEPTANCE_PROTOCOL || value.acceptanceOnly !== true ||
      value.ready !== false || value.productionReceiptAllowed !== false || (runId && value.runId !== runId)) throw failed('PF_ACCEPTANCE_RESPONSE_INVALID');
  return value;
}
function identity(value) {
  return Number.isInteger(value?.pid) && value.pid > 1 && birth.test(value.birth ?? '') &&
    Number.isInteger(value.gid) && value.gid >= 7100 && value.gid <= 7999;
}
function observer(evidence, { zero = false } = {}) {
  const o = evidence?.packetObserver;
  return o?.native === true && o.independent === true && Number.isInteger(o.pid) && o.pid > 1 && birth.test(o.birth ?? '') &&
    o.complete === true && Number.isInteger(o.selectedAttempts) && o.selectedAttempts > 0 &&
    Number.isInteger(o.physicalSelectedPackets) && o.physicalSelectedPackets >= 0 && (!zero || o.physicalSelectedPackets === 0);
}
function sameIdentity(a, b) { return a?.pid === b?.pid && a?.birth === b?.birth && a?.gid === b?.gid; }
export function validatePFProbeBinding(result, request) {
  return uuid.test(result?.reservationId ?? '') && result.consumed === true && result.usedReservedSocket === true &&
    result.protocol === request.op && result.remoteHost === request.host && result.remotePort === request.port &&
    result.sourceAddressResolved === true && result.sourceWildcard === false && net.isIP(result.localHost) === 4 && result.localHost !== '0.0.0.0' &&
    Number.isInteger(result.localPort) && result.localPort >= 1024 && result.localPort <= 65535;
}
export function validatePFControlledCleanupEvidence(evidence) {
  return evidence?.source === 'native-pf' && evidence.platform === 'darwin' && evidence.complete === true &&
    ['ownedProcessesExited', 'ownedTunnelsRemoved', 'ownedAnchorRemoved', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged',
      'hostDNSUnchanged', 'noOwnedStatesCreatedVerified', 'noOwnedStatesRemainVerified', 'ownedRootHookRemoved',
      'originalRootRestored', 'ownedPFReferenceReleased'].every(key => evidence[key] === true) && evidence.cleanupUncertain === false;
}
export function validatePFPreparedRootHook(value, runId) {
  return isPFRoutingRunId(runId) && value?.source === 'native-pf-root-hook' && value.anchor === pfRoutingAnchor(runId) &&
    value.runId === runId && value.verified === true && value.ticketSource === 'this-INSERT-return-only';
}
function exactRealms(realms, { requireDetached = true } = {}) {
  if (!Array.isArray(realms) || realms.length !== 2) return false;
  const found = slots.map(slot => realms.find(r => r.slot === slot));
  if (found.some(r => !r || !uuid.test(r.realmId ?? '') || !Number.isInteger(r.gid) || r.gid < 7100 || r.gid > 7999 ||
      !/^utun\d{1,5}$/.test(r.tunnel?.interfaceName ?? '') || !Number.isInteger(r.tunnel.pid) || r.tunnel.pid <= 1 ||
      typeof r.tunnel.instanceId !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/.test(r.tunnel.instanceId) ||
      !Array.isArray(r.fixtures) || (requireDetached ? r.fixtures.length !== 3 : ![2, 3].includes(r.fixtures.length)) ||
      new Set(r.fixtures.map(f => f.role)).size !== r.fixtures.length || r.fixtures.some(f => !roles.includes(f.role) || !identity(f) || f.gid !== r.gid) ||
      (requireDetached ? roles : ['parent', 'child']).some(role => !r.fixtures.some(f => f.role === role)))) return false;
  return found[0].gid !== found[1].gid && found[0].realmId !== found[1].realmId &&
    found[0].tunnel.interfaceName !== found[1].tunnel.interfaceName && found[0].tunnel.instanceId !== found[1].tunnel.instanceId &&
    new Set(found.flatMap(r => r.fixtures.map(f => f.pid))).size === found.reduce((count, r) => count + r.fixtures.length, 0);
}

/** Read-only system metadata; never reads VPN configuration or starts a helper. */
export async function inspectPFAcceptanceFoundation({ platform = process.platform, run = execFile } = {}) {
  const result = { platform, uid: process.getuid?.() ?? null, administrator: process.getuid?.() === 0,
    pfDevicePresent: false, pfDeviceReadable: false, pfDeviceWritable: false, pfReadStatus: 'UNAVAILABLE',
    defaultInterface: null, interfaces: [], helperPresent: false, rootOwnedHelper: false };
  if (platform !== 'darwin') return result;
  try { const s = await fs.lstat('/dev/pf'); result.pfDevicePresent = s.isCharacterDevice();
    try { await fs.access('/dev/pf', 4); result.pfDeviceReadable = true; } catch {}
    try { await fs.access('/dev/pf', 2); result.pfDeviceWritable = true; } catch {}
  } catch {}
  const command = (file, args) => new Promise(resolve => run(file, args, { timeout: 1500, maxBuffer: 32768, encoding: 'utf8' },
    (error, stdout, stderr) => resolve({ error, stdout: stdout ?? '', stderr: stderr ?? '' })));
  const [pf, route, list] = await Promise.all([command('/sbin/pfctl', ['-s', 'info']), command('/sbin/route', ['-n', 'get', 'default']), command('/sbin/ifconfig', ['-l'])]);
  result.pfReadStatus = !pf.error ? 'READABLE' : /Permission denied/i.test(pf.stderr) ? 'PERMISSION_DENIED' : 'UNAVAILABLE';
  result.defaultInterface = /interface:\s*([a-z][a-z0-9]{0,15})/i.exec(route.stdout)?.[1] ?? null;
  result.interfaces = list.stdout.split(/\s+/).filter(v => /^[a-z][a-z0-9]{0,15}$/.test(v)).slice(0, 64);
  try { const s = await fs.lstat(PF_ACCEPTANCE_HELPER); result.helperPresent = s.isFile() && !s.isSymbolicLink();
    result.rootOwnedHelper = result.helperPresent && s.uid === 0 && (s.mode & 0o022) === 0; } catch {}
  return result;
}

export function createPFAcceptancePlan(foundation = {}, status = null) {
  const supported = Array.isArray(status?.fixtureOperations) ? status.fixtureOperations.filter(id => PF_ACCEPTANCE_CASES.some(c => c.id === id)) : [];
  return { schema: PF_ACCEPTANCE_PROTOCOL, operation: 'plan', ...fixedFlags, activatesSystem: false,
    anchor: PF_ACCEPTANCE_ANCHOR, foundation, fixedHelper: PF_ACCEPTANCE_HELPER,
    fixtures: slots.map(slot => ({ slot, rootOwnedExecutable: `${PF_ACCEPTANCE_HELPER_ROOT}/fixtures/EnvaraRoutingAcceptanceFixture`,
      roles: [...roles], destination: PF_FIXTURE_TARGET, transports: ['tcp', 'udp', 'system-dns'] })),
    cases: PF_ACCEPTANCE_CASES.map(c => ({ ...c, implementedByHelper: supported.includes(c.id), nativeVerified: false })),
    requiredPreconditions: ['rootOwnedInstallationVerified', 'callerConsoleUIDVerified', 'privilegedOperationsAuthorized',
      'ownedRootHookCanCreate', 'exactStateCleanupVerified', 'independentPacketObserverVerified'],
    controlledPreconditions: { status: ['rootOwnedInstallationVerified', 'callerConsoleUIDVerified', 'privilegedOperationsAuthorized',
      'ownedRootHookCanCreate', 'statelessControlledFixtures', 'noStateNativeAvailable'],
      preparedRootHook: ['native-pf-root-hook', 'exact-run-binding', 'this-INSERT-return-only'],
      nativePrepareBeforeResume: ['freshTuplesVerified', 'noExistingOwnedStatesVerified', 'noStateRulesVerified', 'denyBeforeResumeVerified',
        'existingForeignPFStatesAbsentBeforeEnable'] },
    supportedCaseCount: supported.length, nativeRoutingAcceptance: false,
    controlledExperiments: PF_CONTROLLED_EXTRA_CASES.map(c => ({ ...c, nativeVerified: false })),
    reason: status ? 'NATIVE_CONTROLLED_ACCEPTANCE_REQUIRED' : 'PF_HELPER_AND_NATIVE_CONTROLLED_ACCEPTANCE_REQUIRED' };
}

/** Two private SOCKS nodes emulate reserved destinations; no destination is connected. */
export async function createPFFixtureSocksServer({ slot, lifetimeMs = 240000 } = {}) {
  if (!slots.includes(slot) || !Number.isInteger(lifetimeMs) || lifetimeMs < 1000 || lifetimeMs > 300000) throw failed('PF_FIXTURE_OPTIONS_INVALID');
  const credentials = { username: randomBytes(12).toString('hex'), password: randomBytes(24).toString('hex') };
  const address4 = slot === 'one' ? '203.0.113.42' : '203.0.113.43';
  const address6 = slot === 'one' ? '2001:db8::42' : '2001:db8::43';
  const sockets = new Set(), relays = new Set(), names = new Set(), challenges = new Map(), receipts = new Map();
  const counts = { connections: 0, authenticated: 0, rejected: 0, crossRouteRejected: 0, tcpReceipts: 0,
    halfCloseReceipts: 0, udpReceipts: 0, dnsAReplies: 0, dnsAAAAReplies: 0, holdBytes: 0, closed: false,
    ...Object.fromEntries(PF_FIXTURE_UDP_COUNTS.map(key => [key, 0])) };
  const server = net.createServer({ allowHalfOpen: true }, socket => {
    counts.connections++;
    if (counts.closed || counts.connections > 128 || sockets.size >= 24) { counts.rejected++; socket.destroy(); return; }
    sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket));
    socket.setTimeout(12000, () => socket.destroy());
    void handle(socket).catch(() => { counts.rejected++; socket.destroy(); });
  });
  function consumePayload(bytes, kind) {
    if (bytes.length > 4096) return false;
    const key = bytes.toString('hex'), registered = challenges.get(key);
    if (!registered || registered.kind !== kind) { counts.crossRouteRejected++; return false; }
    receipts.set(registered.id, (receipts.get(registered.id) ?? 0) + 1); return true;
  }
  function responseDns(query) {
    const d = validateDnsQuery(query); let p = 12; const labels = [];
    while (p < d.questionEnd - 4) { const n = query[p++]; if (!n) break; labels.push(query.subarray(p, p + n).toString('ascii').toLowerCase()); p += n; }
    if (!names.has(labels.join('.'))) throw failed('PF_FIXTURE_DNS_REJECTED');
    const type = query.readUInt16BE(d.questionEnd - 4);
    if (![1, 28].includes(type)) throw failed('PF_FIXTURE_DNS_REJECTED');
    const result = makeCachedFixtureDnsResponse(query, { address4, address6 });
    if (challenges.get(query.toString('hex'))?.kind === 'dns') consumePayload(query, 'dns');
    if (type === 1) counts.dnsAReplies++; else counts.dnsAAAAReplies++;
    return result;
  }
  async function udpRelay(control, requestedPort) {
    const udp = dgram.createSocket('udp4'); relays.add(udp); let peerPort = requestedPort || null;
    udp.on('error', () => { counts.udpSocketErrors++; });
    udp.on('message', (bytes, peer) => {
      counts.udpPacketsReceived++;
      if (counts.closed || peer.address !== '127.0.0.1' || (peerPort && peer.port !== peerPort)) { counts.udpPeerRejected++; counts.rejected++; return; }
      if (bytes.length < 10 || bytes.length > 8192 || bytes[0] || bytes[1] || bytes[2] || bytes[3] !== 1) { counts.udpHeaderRejected++; counts.rejected++; return; }
      const host = [...bytes.subarray(4, 8)].join('.'), port = bytes.readUInt16BE(8), payload = bytes.subarray(10);
      let reply;
      try {
        if (host === PF_FIXTURE_TARGET && port === PF_FIXTURE_PORTS.udp) {
          if (!consumePayload(payload, 'udp')) { counts.udpChallengeRejected++; return; } counts.udpReceipts++; reply = payload;
        } else if (['1.1.1.1', '1.0.0.1'].includes(host) && port === 53) reply = responseDns(payload);
        else { counts.udpDestinationRejected++; counts.rejected++; return; }
      } catch { counts.udpDNSRejected++; counts.rejected++; return; }
      peerPort ??= peer.port;
      try { udp.send(Buffer.concat([bytes.subarray(0, 10), reply]), peer.port, peer.address, error => {
        if (error) counts.udpReplySendFailed++; else counts.udpRepliesQueued++;
      }); } catch { counts.udpReplySendFailed++; }
    });
    await new Promise((resolve, reject) => { udp.once('error', reject); udp.bind(0, '127.0.0.1', () => { udp.removeListener('error', reject); resolve(); }); });
    const response = Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]); response.writeUInt16BE(udp.address().port, 8); control.write(response); counts.udpAssociations++;
    control.once('close', () => { try { udp.close(); } catch {} relays.delete(udp); });
  }
  async function handle(socket) {
    const reader = new SocketReader(socket, 16384); let released = false;
    try {
      const hello = await reader.read(2); if (hello[0] !== 5 || hello[1] < 1 || hello[1] > 8 || !(await reader.read(hello[1])).includes(2)) throw failed('PF_FIXTURE_AUTH_REQUIRED');
      socket.write(Buffer.from([5, 2]));
      const auth = await reader.read(2), username = await reader.read(auth[1]), password = await reader.read((await reader.read(1))[0]);
      const expectedUser = Buffer.from(credentials.username), expectedPassword = Buffer.from(credentials.password);
      if (auth[0] !== 1 || username.length !== expectedUser.length || password.length !== expectedPassword.length ||
          !timingSafeEqual(username, expectedUser) || !timingSafeEqual(password, expectedPassword)) { counts.rejected++; socket.end(Buffer.from([1, 1])); return; }
      counts.authenticated++; socket.write(Buffer.from([1, 0]));
      const header = await reader.read(4); if (header[0] !== 5 || header[2] || header[3] !== 1) throw failed('PF_FIXTURE_TARGET_REJECTED');
      const destination = await reader.read(6), host = [...destination.subarray(0, 4)].join('.'), port = destination.readUInt16BE(4);
      if (header[1] === 3) {
        if (!['0.0.0.0', '127.0.0.1'].includes(host)) throw failed('PF_FIXTURE_UDP_PEER_REJECTED');
        await udpRelay(socket, port); const buffered = reader.release(); released = true;
        if (buffered.length) throw failed('PF_FIXTURE_UDP_CONTROL_REJECTED'); socket.once('end', () => socket.end()); socket.resume(); return;
      }
      const dns = ['1.1.1.1', '1.0.0.1'].includes(host) && port === 53;
      if (header[1] !== 1 || (!dns && (host !== PF_FIXTURE_TARGET || ![44441, 44442, 44443].includes(port)))) throw failed('PF_FIXTURE_TARGET_REJECTED');
      socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
      if (dns) {
        for (let n = 0; n < 8 && !socket.destroyed; n++) {
          let prefix;
          try { prefix = await reader.read(2); }
          catch (error) { if (reader.ended && reader.length === 0) { socket.end(); return; } throw error; }
          const length = prefix.readUInt16BE(0); if (length < 12 || length > 4096) throw failed('PF_FIXTURE_DNS_REJECTED');
          const reply = responseDns(await reader.read(length)), responsePrefix = Buffer.alloc(2); responsePrefix.writeUInt16BE(reply.length);
          socket.write(Buffer.concat([responsePrefix, reply]));
        }
        return;
      }
      const buffered = reader.release(); released = true; const parts = []; let length = 0, replied = false;
      const consume = bytes => {
        length += bytes.length; if (length > 4096) { counts.rejected++; socket.destroy(); return; } parts.push(bytes);
        if (port === PF_FIXTURE_PORTS.hold) { counts.holdBytes += bytes.length; return; }
        const body = Buffer.concat(parts, length);
        if (port === PF_FIXTURE_PORTS.echo && !replied) {
          const key = body.toString('hex');
          if (challenges.get(key)?.kind === 'tcp') { consumePayload(body, 'tcp'); replied = true; counts.tcpReceipts++; socket.write(body); }
          else if (![...challenges].some(([candidate, entry]) => entry.kind === 'tcp' && candidate.startsWith(key))) {
            counts.crossRouteRejected++; socket.destroy();
          }
        } else if (port === PF_FIXTURE_PORTS.echo && replied) { counts.rejected++; socket.destroy(); }
      };
      const ended = () => {
        if (port === PF_FIXTURE_PORTS.halfClose) {
          const body = Buffer.concat(parts, length); if (consumePayload(body, 'fin')) { counts.halfCloseReceipts++; socket.end(body); } else socket.destroy();
        } else socket.end();
      };
      socket.on('data', consume); socket.once('end', ended); if (buffered.length) consume(buffered); if (reader.ended) ended(); socket.resume();
    } finally { if (reader.pending) reader.fail(failed('PF_FIXTURE_SOCKET_CLOSED')); if (!released) { try { reader.release(); } catch {} } }
  }
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); }); });
  let closePromise;
  const close = () => closePromise ??= (async () => {
    clearTimeout(timer); counts.closed = true; for (const socket of sockets) socket.destroy();
    for (const relay of relays) { try { relay.close(); } catch {} } relays.clear();
    if (!server.listening) return true;
    return await new Promise(resolve => { const deadline = setTimeout(() => resolve(false), 1500);
      server.close(error => { clearTimeout(deadline); resolve(!error); }); });
  })();
  const timer = setTimeout(() => void close(), lifetimeMs);
  return { route: { protocol: 'socks5', host: '127.0.0.1', port: server.address().port, ...credentials, udp: true, udpPolicy: 'proxy' },
    answers: [address4, address6], register(id, payload, kind) {
      if (!/^[A-Za-z0-9_-]{1,80}$/.test(id) || !Buffer.isBuffer(payload) || payload.length < 1 || payload.length > 4096 ||
          !['tcp', 'fin', 'udp', 'dns'].includes(kind) || challenges.size >= 128) throw failed('PF_FIXTURE_CHALLENGE_INVALID');
      challenges.set(payload.toString('hex'), { id, kind });
    }, allowHostname(name) { if (!ownHostname.test(name) || names.size >= 16) throw failed('PF_FIXTURE_DNS_NAME_INVALID'); names.add(name); },
    received: id => (receipts.get(id) ?? 0) > 0, receiptCount: id => receipts.get(id) ?? 0, snapshot: () => ({ ...counts }), close };
}

export function validatePFCaseEvidence(caseId, evidence, { realms = [], controlledExperiment = false } = {}) {
  if (!evidence || evidence.source !== 'native-pf' || evidence.platform !== 'darwin' || evidence.complete !== true) return false;
  if (controlledExperiment && ['tcp-concurrent', 'tcp-half-close', 'udp-concurrent', 'dns-tcp53'].includes(caseId) &&
      ['freshTuplesVerified', 'noExistingMatchingStatesVerified', 'noStateRulesVerified'].some(key => evidence[key] !== true)) return false;
  switch (caseId) {
    case 'realm-identities': return exactRealms(realms, { requireDetached: !controlledExperiment }) && evidence.threeGIDsVerified === true && evidence.coldExecVerified === true;
    case 'tcp-concurrent': case 'udp-concurrent': return evidence.overlapVerified === true && evidence.exactProcessAttribution === true;
    case 'dns-tcp53': return evidence.realTCP53Observed === true && evidence.exactProcessAttribution === true && evidence.ownAuthenticatedRouteObserved === true;
    case 'dns-block': return observer(evidence, { zero: true }) && evidence.fixtureDNSDenied === true && evidence.udp53Attempted === true && evidence.tcp53Attempted === true && evidence.hostDNSUnchanged === true;
    case 'tcp-half-close': return evidence.upstreamFINObserved === true && evidence.readDirectionPreserved === true;
    case 'udp-block': return observer(evidence, { zero: true }) && evidence.otherRealmUsable === true && evidence.blockedPolicyAcknowledged === true;
    case 'dns-same-hostname-cold': return evidence.systemResolver === true && evidence.concurrentSameHostname === true && evidence.exactProcessAttribution === true;
    case 'dns-same-hostname-warm': return evidence.systemResolver === true && evidence.repeatedSameHostname === true && evidence.childSameHostname === true && evidence.cacheCrossover === false;
    case 'unbound-dns': return evidence.unboundResolverTested === true && evidence.syntheticAnswersReceived === false && evidence.hostDNSUnchanged === true;
    case 'first-packet': return observer(evidence, { zero: true }) && evidence.beforePolicyACK === true && evidence.coldExecSuspended === true;
    case 'core-crash': return observer(evidence, { zero: true }) && evidence.coreExitConfirmed === true && evidence.existingSelectedBlocked === true && evidence.newSelectedBlocked === true && evidence.otherRealmUsable === true;
    case 'helper-crash': return observer(evidence, { zero: true }) && evidence.supervisorExitConfirmed === true && evidence.observerSurvivedSupervisor === true && evidence.bothRealmsBlocked === true && evidence.existingSelectedBlocked === true && evidence.newSelectedBlocked === true;
    case 'utun-reuse': return observer(evidence, { zero: true }) && evidence.originalInstanceRemoved === true && evidence.sameNameRecreated === true && evidence.replacementUnrelated === true && evidence.replacementInstanceDifferent === true && evidence.selectedPacketsOnReplacement === 0;
    case 'ipv6-icmp-raw': return observer(evidence, { zero: true }) && ['ipv6', 'icmp', 'raw'].every(key => evidence[key]?.attempted === true && evidence[key]?.gidAttributed === true && evidence[key]?.blocked === true);
    case 'precreated-fd': return evidence.liveConnectedFDInheritedIntoLauncher === true && evidence.closedBeforeFixtureExec === true && evidence.firstWriteDenied === true && evidence.coldExecVerified === true;
    case 'exact-state-purge': return evidence.exactOwnedStateIDsObserved === true && evidence.exactOwnedStateIDsRemoved === true && evidence.unrelatedStateIDsPreserved === true && evidence.globalFlushUsed === false && evidence.addressWideKillUsed === false;
    case 'cleanup': return ['ownedProcessesExited', 'ownedTunnelsRemoved', 'ownedAnchorStatesPurged', 'ownedAnchorRemoved', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged'].every(key => evidence[key] === true) && evidence.cleanupUncertain === false;
    default: return false;
  }
}

/** Native helper is injected. Simulation can exercise contracts but never native gates. */
export async function runPFAcceptanceMatrix({ call, evidenceMode = 'native', controlledCaseIds = null, workTimeoutMs = 110000,
  cleanupTimeoutMs = 20000, createProxy = createPFFixtureSocksServer, createControl = createUnboundLoopbackControl, runId = randomUUID(), controlledUDPSizeDiagnostic = false } = {}) {
  if (typeof call !== 'function' || !['native', 'simulation'].includes(evidenceMode) || !Number.isInteger(workTimeoutMs) ||
      workTimeoutMs < 1000 || workTimeoutMs > 115000 || !Number.isInteger(cleanupTimeoutMs) || cleanupTimeoutMs < 1000 || cleanupTimeoutMs > 25000 ||
      !isPFRoutingRunId(runId)) throw failed('PF_ACCEPTANCE_OPTIONS_INVALID');
  const controlledExperiment = controlledCaseIds !== null;
  if (typeof controlledUDPSizeDiagnostic !== 'boolean' || controlledUDPSizeDiagnostic && (!controlledExperiment || !Array.isArray(controlledCaseIds) || !controlledCaseIds.includes('udp-concurrent'))) throw failed('PF_ACCEPTANCE_OPTIONS_INVALID');
  if (controlledExperiment && (!Array.isArray(controlledCaseIds) || controlledCaseIds.length < 1 || controlledCaseIds.length > 17 ||
      new Set(controlledCaseIds).size !== controlledCaseIds.length || controlledCaseIds.some(id => !PF_CONTROLLED_CASE_IDS.includes(id) || id === 'cleanup'))) throw failed('PF_ACCEPTANCE_OPTIONS_INVALID');
  const selectedCases = controlledExperiment ? [...new Set(['realm-identities', ...controlledCaseIds])] : PF_ACCEPTANCE_CASES.map(c => c.id);
  const startedAt = new Date().toISOString(), anchor = pfRoutingAnchor(runId), report = { schema: PF_ACCEPTANCE_PROTOCOL, operation: 'runOwnedPFFixtures',
    ...fixedFlags, startedAt, evidenceMode, anchor, nativeRoutingAttempted: false,
    controlledExperiment, controlledUDPSizeDiagnostic, fullMatrix: !controlledExperiment, selectedCases, nativeRoutingAcceptance: false,
    fixtureMatrixPassed: false, checks: {}, cleanup: null, reason: null };
  const proxies = new Map(), udpChallenges = []; let control, prepared = false, realms = []; const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), workTimeoutMs), expires = Date.now() + workTimeoutMs;
  const boundedCall = (method, params, timeoutMs, signal) => new Promise((resolve, reject) => {
    let finished = false;
    const finish = (error, value) => { if (finished) return; finished = true; clearTimeout(deadline); signal?.removeEventListener('abort', cancelled); error ? reject(error) : resolve(value); };
    const cancelled = () => finish(failed('PF_ACCEPTANCE_ABORTED'));
    const deadline = setTimeout(() => finish(failed('PF_ACCEPTANCE_DEADLINE')), timeoutMs);
    signal?.addEventListener('abort', cancelled, { once: true });
    Promise.resolve().then(() => call(method, params, { signal, timeoutMs })).then(value => finish(null, value), error => finish(error));
    if (signal?.aborted) cancelled();
  });
  const rpc = async (method, params, timeoutMs = 15000) => {
    if (abort.signal.aborted || Date.now() >= expires) throw failed('PF_ACCEPTANCE_DEADLINE');
    return await boundedCall(method, params, Math.min(timeoutMs, Math.max(1, expires - Date.now())), abort.signal);
  };
  const record = (id, passed, code = null) => { report.checks[id] = { passed: Boolean(passed), nativeVerified: passed && evidenceMode === 'native', ...(code ? { code } : {}) }; };
  const verifyProbes = (value, challenges) => {
    if (!Array.isArray(value.probes) || value.probes.length !== challenges.length) return false;
    return challenges.every(challenge => {
      const p = value.probes.find(probe => probe.slot === challenge.slot && probe.role === challenge.role), realm = realms.find(r => r.slot === challenge.slot);
      if (!p || !sameIdentity(p.fixture, realm?.fixtures.find(f => f.role === challenge.role))) return false;
      if (controlledExperiment && challenge.request.op !== 'resolve' && !validatePFProbeBinding(p.result, challenge.request)) return false;
      if (challenge.request.op === 'resolve') return p.result?.ok === true && Array.isArray(p.result.addresses) &&
        p.result.addresses.length > 0 && p.result.addresses.every(address => proxies.get(challenge.slot).answers.includes(address));
      if (challenge.expectedResponseBase64) return p.result?.ok === true && p.result.payloadBase64 === challenge.expectedResponseBase64 &&
        p.result.receivedBytes === Buffer.from(challenge.expectedResponseBase64, 'base64').length && p.result.eof === true && proxies.get(challenge.slot).received(challenge.id);
      const expected = challenge.request.payloadBase64;
      return p.result?.ok === true && p.result.matches === true && p.result.payloadBase64 === expected &&
        p.result.receivedBytes === Buffer.from(expected, 'base64').length && proxies.get(challenge.slot).received(challenge.id) &&
        (!challenge.request.halfClose || (p.result.eof === true && p.result.halfClose === true));
    });
  };
  try {
    const status = nativeResult(await rpc('status', { runId }, 5000));
    for (const key of ['rootOwnedInstallationVerified', 'callerConsoleUIDVerified', 'privilegedOperationsAuthorized',
      'ownedRootHookCanCreate']) if (status[key] !== true) throw failed('PF_ACCEPTANCE_PREFLIGHT_REQUIRED');
    if (controlledExperiment) {
      for (const key of ['statelessControlledFixtures', 'noStateNativeAvailable']) if (status[key] !== true) throw failed('PF_STATELESS_CONTROLLED_PREFLIGHT_REQUIRED');
    } else for (const key of ['exactStateCleanupVerified', 'independentPacketObserverVerified']) if (status[key] !== true) throw failed('PF_ACCEPTANCE_PREFLIGHT_REQUIRED');
    if (status.anchor !== anchor || !Array.isArray(status.fixtureOperations) ||
        selectedCases.some(id => !status.fixtureOperations.includes(id)) || !status.fixtureOperations.includes('cleanup')) throw failed('PF_ACCEPTANCE_CASES_UNAVAILABLE');
    control = await createControl();
    record('unbound-loopback-before', await control.existing() && await control.fresh());
    for (const slot of slots) proxies.set(slot, await createProxy({ slot, lifetimeMs: Math.min(workTimeoutMs + cleanupTimeoutMs, 300000) }));
    prepared = true; report.nativeRoutingAttempted = evidenceMode === 'native';
    const preparation = nativeResult(await rpc('prepareOwnedFixtures', { acceptanceProtocol: PF_ACCEPTANCE_PROTOCOL,
      activationAuthorized: true, runId, controlledExperiment, caseIds: selectedCases, lifetimeSeconds: Math.ceil(workTimeoutMs / 1000),
      slots: slots.map(slot => ({ slot, environmentId: randomUUID(), proxy: proxies.get(slot).route, udpPolicy: 'proxy' })) }), runId);
    if (!validatePFPreparedRootHook(preparation.ownedRootHook, runId)) throw failed('PF_OWNED_ROOT_HOOK_EVIDENCE_REQUIRED');
    record('owned-root-hook-prepare', true);
    if (controlledExperiment && preparation.existingForeignPFStatesAbsentBeforeEnable !== true) throw failed('PF_FOREIGN_STATE_PREFLIGHT_EVIDENCE_REQUIRED');
    realms = preparation.realms;
    if (!exactRealms(realms, { requireDetached: !controlledExperiment })) throw failed('PF_ACCEPTANCE_REALM_IDENTITY_INVALID');
    if (controlledUDPSizeDiagnostic && realms.some(realm => realm.fixtures.length !== 2 || !['parent', 'child'].every(role => realm.fixtures.some(fixture => fixture.role === role)))) throw failed('PF_UDP_SIZE_DIAGNOSTIC_SCOPE_INVALID');
    report.fixtureScope = realms.map(r => ({ slot: r.slot, realmId: r.realmId, gid: r.gid,
      tunnel: { interfaceName: r.tunnel.interfaceName, pid: r.tunnel.pid, instanceId: r.tunnel.instanceId },
      fixtures: r.fixtures.map(f => ({ role: f.role, pid: f.pid, birth: f.birth, gid: f.gid })) }));
    if (controlledExperiment && (preparation.statelessEvidence?.source !== 'native-pf' ||
        ['freshTuplesVerified', 'noExistingOwnedStatesVerified', 'noStateRulesVerified', 'denyBeforeResumeVerified'].some(key => preparation.statelessEvidence[key] !== true))) throw failed('PF_STATELESS_NATIVE_EVIDENCE_REQUIRED');
    for (const id of selectedCases.filter(id => id !== 'cleanup')) {
      const challenges = [];
      if (['tcp-concurrent', 'tcp-half-close', 'udp-concurrent'].includes(id)) {
        const kind = id === 'udp-concurrent' ? 'udp' : id === 'tcp-half-close' ? 'fin' : 'tcp';
        for (const slot of slots) for (const { role } of realms.find(r => r.slot === slot).fixtures) {
          const challengeId = randomUUID(), payloadBytes = kind === 'udp' && controlledUDPSizeDiagnostic && role === 'parent' ? 1200 : 2048, payload = randomBytes(payloadBytes);
          proxies.get(slot).register(challengeId, payload, kind);
          if (kind === 'udp') udpChallenges.push({ id: challengeId, slot, role, payloadBytes });
          challenges.push({ id: challengeId, slot, role, request: { id: challengeId, op: kind === 'udp' ? 'udp' : 'tcp',
            host: PF_FIXTURE_TARGET, port: kind === 'udp' ? 44444 : kind === 'fin' ? 44442 : 44441,
            payloadBase64: payload.toString('base64'), halfClose: kind === 'fin', timeoutMs: 5000 } });
        }
      } else if (id === 'dns-tcp53') {
        const hostname = `pf-${randomBytes(12).toString('hex')}.envara-fixture.test`;
        for (const slot of slots) {
          const proxy = proxies.get(slot); proxy.allowHostname(hostname);
          for (const { role } of realms.find(r => r.slot === slot).fixtures) {
            const header = Buffer.alloc(12); header.writeUInt16BE(randomBytes(2).readUInt16BE(), 0); header.writeUInt16BE(0x0100, 2); header.writeUInt16BE(1, 4);
            const question = Buffer.concat([...hostname.split('.').map(label => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])), Buffer.from([0, 0, 1, 0, 1])]);
            const query = Buffer.concat([header, question]), prefix = Buffer.alloc(2); prefix.writeUInt16BE(query.length);
            const response = makeCachedFixtureDnsResponse(query, { address4: proxy.answers[0], address6: proxy.answers[1] }), responsePrefix = Buffer.alloc(2); responsePrefix.writeUInt16BE(response.length);
            const challengeId = randomUUID(); proxy.register(challengeId, query, 'dns'); challenges.push({ id: challengeId, slot, role, expectedResponseBase64: Buffer.concat([responsePrefix, response]).toString('base64'),
              request: { id: challengeId, op: 'tcp', host: '1.1.1.1', port: 53, payloadBase64: Buffer.concat([prefix, query]).toString('base64'), halfClose: true, timeoutMs: 5000 } });
          }
        }
      } else if (['dns-same-hostname-cold', 'dns-same-hostname-warm'].includes(id)) {
        // Retain one name across the cold and warm cases, independently of system cache state.
        report.syntheticHostname ??= `pf-${randomBytes(12).toString('hex')}.envara-fixture.test`;
        for (const slot of slots) { proxies.get(slot).allowHostname(report.syntheticHostname);
          for (const { role } of realms.find(r => r.slot === slot).fixtures) { const challengeId = randomUUID(); challenges.push({ id: challengeId, slot, role,
            request: { id: challengeId, op: 'resolve', host: report.syntheticHostname, timeoutMs: 5000 } }); } }
      }
      const before = new Map(slots.map(slot => [slot, proxies.get(slot).snapshot()]));
      try {
        const result = nativeResult(await rpc('runOwnedFixtureCase', { acceptanceProtocol: PF_ACCEPTANCE_PROTOCOL,
          runId, caseId: id, challenges, timeoutMs: 15000 }), runId);
        if (result.caseId !== id) throw failed('PF_ACCEPTANCE_CASE_ID_MISMATCH');
        let passed = validatePFCaseEvidence(id, result.evidence, { realms, controlledExperiment }) && (!challenges.length || verifyProbes(result, challenges));
        if (['dns-same-hostname-cold', 'dns-tcp53'].includes(id)) passed &&= slots.every(slot => {
          const after = proxies.get(slot).snapshot(), prior = before.get(slot); return after.dnsAReplies + after.dnsAAAAReplies > prior.dnsAReplies + prior.dnsAAAAReplies; });
        if (['tcp-concurrent', 'tcp-half-close', 'udp-concurrent'].includes(id)) passed &&= slots.every(slot => proxies.get(slot).snapshot().crossRouteRejected === before.get(slot).crossRouteRejected);
        record(id, passed, passed ? null : 'PF_NATIVE_EVIDENCE_INCOMPLETE');
        record(`unbound-loopback-after-${id}`, await control.existing() && await control.fresh());
        if (!passed) break;
      } catch (error) { record(id, false, safeCode(error)); break; }
    }
  } catch (error) { report.reason = safeCode(error); }
  finally {
    clearTimeout(timer); abort.abort(); delete report.syntheticHostname;
    if (prepared) {
      try {
        const cleaned = nativeResult(await boundedCall('cleanupOwnedFixtures', { acceptanceProtocol: PF_ACCEPTANCE_PROTOCOL, runId }, cleanupTimeoutMs), runId);
        const evidence = cleaned.evidence;
        const statelessClean = validatePFControlledCleanupEvidence(evidence);
        const uncertain = evidence?.cleanupUncertain !== false || cleaned.cleanupUncertain === true;
        record('cleanup', !uncertain && (controlledExperiment ? statelessClean : validatePFCaseEvidence('cleanup', evidence)));
        report.cleanup = { confirmed: report.checks.cleanup.passed, uncertain };
      } catch (error) { record('cleanup', false, safeCode(error)); report.cleanup = { confirmed: false, uncertain: true }; }
    }
    report.udpSizeDiagnostics = udpChallenges.map(({ id, slot, role, payloadBytes }) => {
      let authenticatedFixtureReceipts = null;
      try { const proxy = proxies.get(slot), count = typeof proxy?.receiptCount === 'function' ? proxy.receiptCount(id) : null;
        if (Number.isSafeInteger(count) && count >= 0 && count <= 128) authenticatedFixtureReceipts = count; } catch {}
      return { slot, role, payloadBytes, authenticatedFixtureReceipts };
    });
    report.fixtureUDPDiagnostics = [...proxies].map(([slot, proxy]) => {
      let counts = null;
      try { counts = snapshotPFFixtureUDP(typeof proxy.snapshot === 'function' ? proxy.snapshot() : null); } catch {}
      // Diagnostics are optional: an unavailable observer must never replace
      // the authoritative failure or prevent owned fixture/control cleanup.
      return { slot, source: 'owned-loopback-socks', routingEvidence: false, counts };
    });
    const closed = await Promise.allSettled([...proxies.values()].map(proxy => proxy.close()));
    report.localFixturesClosed = closed.every(value => value.status === 'fulfilled' && value.value === true);
    if (control) { try { record('unbound-loopback-final', await control.existing() && await control.fresh()); }
      catch { record('unbound-loopback-final', false, 'PF_UNBOUND_CONTROL_FAILED'); }
      report.localFixturesClosed &&= await control.close(); }
    report.completedAt = new Date().toISOString();
    report.selectedCasesPassed = [...new Set([...selectedCases, 'cleanup'])].every(id => report.checks[id]?.passed) &&
      Object.values(report.checks).every(c => c.passed) && report.localFixturesClosed;
    report.fixtureMatrixPassed = !controlledExperiment && report.selectedCasesPassed;
    report.nativeRoutingAcceptance = evidenceMode === 'native' && report.fixtureMatrixPassed;
    if (!report.reason && !report.selectedCasesPassed) report.reason = 'PF_NATIVE_ACCEPTANCE_INCOMPLETE';
  }
  return report;
}
