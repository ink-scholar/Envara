import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import net from 'node:net';
import dgram from 'node:dgram';
import path from 'node:path';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { MacOSPFExecutor } from './controller.mjs';
import { isPFRoutingRunId } from './policy.mjs';

assert.notEqual(process.getuid?.(), 0, 'Socket fixture tests must remain unprivileged');
assert.ok(process.argv.length <= 3);
const suppliedBinary = process.argv[2];
assert.ok(suppliedBinary === undefined || path.isAbsolute(suppliedBinary) && path.basename(suppliedBinary) === 'EnvaraRoutingAcceptanceFixture');
const binary = suppliedBinary ?? fileURLToPath(new URL('./build/EnvaraRoutingAcceptanceFixture', import.meta.url));
const child = spawn(binary, [], { stdio: ['pipe', 'pipe', 'pipe'] });
const pending = new Map(); let buffer = '', diagnostics = '';
child.stderr.on('data', chunk => { diagnostics += chunk; });
child.stdout.on('data', chunk => {
  buffer += chunk;
  while (buffer.includes('\n')) {
    const index = buffer.indexOf('\n'), line = buffer.slice(0, index); buffer = buffer.slice(index + 1);
    const response = JSON.parse(line), request = pending.get(response.id);
    assert(request, 'Response must match a pending request'); pending.delete(response.id); clearTimeout(request.timer); request.resolve(response);
  }
});
function rpc(request) {
  const id = request.id ?? randomUUID();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('Owned fixture RPC timed out')); }, 8000);
    pending.set(id, { resolve, reject, timer }); child.stdin.write(JSON.stringify({ id, ...request }) + '\n');
  });
}
const connections = [], servers = [], sockets = [];
async function tcpServer({ fin = false, silent = false } = {}) {
  const server = net.createServer({ allowHalfOpen: true }, socket => {
    connections.push({ port: socket.remotePort, bytes: 0 }); const record = connections.at(-1); sockets.push(socket);
    let data = Buffer.alloc(0);
    socket.on('error', () => {});
    socket.on('data', chunk => { record.bytes += chunk.length; data = Buffer.concat([data, chunk]); if (!fin && !silent) socket.write(chunk); });
    socket.on('end', () => { if (fin) socket.end(data); else socket.end(); });
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); servers.push(server); return server.address().port;
}
async function reserve(protocol, port, host = '127.0.0.1', owner) {
  const request = { op: 'reserve', protocol, host, port, timeoutMs: 3000 };
  const result = owner ? (await rpc({ op: 'child_probe', pid: owner, request })).childResult : await rpc(request);
  assert.equal(result.ok, true); assert.equal(result.bound, true); assert.equal(result.connected, false);
  assert.equal(result.packetsSent, 0); assert.equal(result.localHost, '0.0.0.0'); assert.equal(result.sourceWildcard, true);
  assert.equal(result.sourceAddressResolved, false); assert.equal(result.protocol, protocol);
  assert(Number.isInteger(result.localPort) && result.localPort >= 1024);
  assert.equal(isPFRoutingRunId(result.reservationId), true, 'Native reservation must use canonical lowercase UUIDv4'); return result;
}
async function probe(reservation, payload, halfClose = false, owner, timeoutMs = 3000) {
  const request = { op: 'probe_reserved', reservationId: reservation.reservationId,
    payloadBase64: Buffer.from(payload).toString('base64'), halfClose, timeoutMs };
  const result = owner ? (await rpc({ op: 'child_probe', pid: owner, request })).childResult : await rpc(request);
  assert.equal(result.ok, true); assert.equal(result.reservationId, reservation.reservationId);
  assert.equal(result.consumed, true); assert.equal(result.usedReservedSocket, true);
  assert.equal(result.localPort, reservation.localPort); assert.equal(result.localHost, '127.0.0.1');
  assert.equal(result.sourceAddressResolved, true); assert.equal(result.matches, true);
  assert.equal(Buffer.from(result.payloadBase64, 'base64').toString(), payload);
  assert(BigInt(result.finishedAtNanoseconds) >= BigInt(result.startedAtNanoseconds)); return result;
}
async function release(reservation, owner) {
  const request = { op: 'release_reservation', reservationId: reservation.reservationId };
  const result = owner ? (await rpc({ op: 'child_probe', pid: owner, request })).childResult : await rpc(request);
  assert.equal(result.ok, true); assert.equal(result.released, true);
}
async function portAvailable(port) {
  const temporary = net.createServer(); temporary.listen(port, '0.0.0.0');
  await once(temporary, 'listening'); await new Promise(resolve => temporary.close(resolve));
}
async function portReserved(port) {
  const temporary = net.createServer(); temporary.listen(port, '0.0.0.0');
  const [error] = await once(temporary, 'error'); assert.equal(error.code, 'EADDRINUSE');
}
let udp;
try {
  const status = await rpc({ op: 'status' }); assert.equal(status.twoPhaseSocketReservations, true);
  assert.equal(status.socketReservationProtocol, 'envara-pf-socket-reservation/v1');
  // Execute the production controller's reply validation against the freshly
  // compiled, unprivileged fixture. Only bind/reserve happens: no synthetic
  // destination receives a connection or packet and no PF command is run.
  const executor = new MacOSPFExecutor(), nativeRun = { caseIds: ['tcp-concurrent'], realms: [{ realmId: randomUUID(), fixtures: [{ role: 'parent' }] }] };
  let nativeReply, absenceReads = 0;
  const nativeTransact = async (_realm, _fixture, request) => { nativeReply = await rpc(request); return nativeReply; };
  executor.transactFixture = nativeTransact;
  executor.confirmReservedStatesAbsent = async () => { absenceReads++; return true; };
  const accepted = await executor.reserveFixtureTuples(nativeRun);
  assert.equal(accepted.freshTuplesVerified, true); assert.equal(nativeRun.reservations.length, 1);
  assert.equal(nativeRun.reservations[0].reservationId, nativeReply.reservationId); assert.equal(absenceReads, 1);
  // The parser must look up the same lowercase identity even when an existing
  // caller uses the previously accepted uppercase spelling.
  await release({ ...nativeReply, reservationId: nativeReply.reservationId.toUpperCase() });
  for (const token of ['12345678-ABCD-4ABC-8DEF-123456789ABC', '12345678-abcd-5abc-8def-123456789abc', 'not-a-token', null]) {
    executor.transactFixture = async (...args) => ({ ...await nativeTransact(...args), reservationId: token });
    await assert.rejects(executor.reserveFixtureTuples(nativeRun), { code: 'APPLICATION_ROUTING_NOT_READY' });
    assert.equal(absenceReads, 1, 'Rejected tokens cannot reach any PF state inspection');
    await release(nativeReply);
  }
  const echoPort = await tcpServer(), finPort = await tcpServer({ fin: true }), silentPort = await tcpServer({ silent: true });
  const refusal = await rpc({ op: 'tcp', host: '127.0.0.1', port: echoPort });
  assert.equal(refusal.code, 'RESERVATION_REQUIRED'); assert.equal(connections.length, 0);
  const tcp = await reserve('tcp', echoPort); await portReserved(tcp.localPort);
  assert.equal(connections.length, 0, 'reserve must not connect');
  await probe(tcp, 'actual-reserved-tcp'); assert.equal(connections.at(-1).port, tcp.localPort);
  assert.equal((await rpc({ op: 'probe_reserved', reservationId: tcp.reservationId })).code, 'RESERVATION_UNAVAILABLE');
  const fin = await reserve('tcp', finPort); const finResult = await probe(fin, 'actual-reserved-fin', true);
  assert.equal(finResult.eof, true); assert.equal(connections.at(-1).port, fin.localPort);
  udp = dgram.createSocket('udp4'); let udpRemote;
  udp.on('message', (data, remote) => { udpRemote = remote; udp.send(data, remote.port, remote.address); });
  udp.bind(0, '127.0.0.1'); await once(udp, 'listening');
  const datagram = await reserve('udp', udp.address().port); await probe(datagram, 'actual-reserved-udp');
  assert.equal(udpRemote.port, datagram.localPort);
  const dns = await reserve('tcp', 53, '1.1.1.1'); await release(dns); await portAvailable(dns.localPort);
  assert.equal((await rpc({ op: 'reserve', protocol: 'tcp', host: '1.1.1.1', port: 443 })).code, 'FORBIDDEN_ENDPOINT');
  const failed = await reserve('tcp', silentPort);
  assert.equal((await rpc({ op: 'probe_reserved', reservationId: failed.reservationId, timeoutMs: 200 })).code, 'PROBE_TIMEOUT');
  assert.equal((await rpc({ op: 'probe_reserved', reservationId: failed.reservationId })).code, 'RESERVATION_UNAVAILABLE');
  const parentHeld = await reserve('tcp', echoPort);
  const spawned = await rpc({ op: 'spawn_child' }); assert.equal(spawned.ok, true); const owner = spawned.childPID;
  // A live exec'd child must not retain its parent's reserved FD.
  await release(parentHeld); await portAvailable(parentHeld.localPort);
  const childReserved = await reserve('tcp', echoPort, '127.0.0.1', owner);
  await probe(childReserved, 'actual-reserved-child', false, owner); assert.equal(connections.at(-1).port, childReserved.localPort);
  const childHeld = await reserve('tcp', echoPort, '127.0.0.1', owner);
  const closed = await rpc({ op: 'close_child', pid: owner }); assert.equal(closed.exitConfirmed, true);
  await portAvailable(childHeld.localPort);
  const held = [];
  for (let index = 0; index < 16; index++) held.push(await reserve('tcp', echoPort));
  assert.equal((await rpc({ op: 'reserve', protocol: 'tcp', host: '127.0.0.1', port: echoPort })).code, 'RESERVATION_LIMIT');
  assert.equal((await rpc({ op: 'status' })).activeReservations, 16);
  // EOF must close every exclusive binding, rather than leave orphan sockets.
  child.stdin.end(); await once(child, 'exit');
  for (const item of held) await portAvailable(item.localPort);
  assert.equal(child.exitCode, 0, diagnostics);
  console.log('PF fixture: actual TCP/UDP/FIN source-port preservation, no connect during reserve, TCP53 reserve, child FD cleanup, consume-once, timeout, limit and EOF cleanup passed.');
} finally {
  for (const socket of sockets) socket.destroy();
  for (const server of servers) server.close();
  udp?.close(); if (child.exitCode === null) child.kill('SIGKILL');
}
