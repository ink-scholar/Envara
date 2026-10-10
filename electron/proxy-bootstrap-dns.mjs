import https from 'node:https';
import net from 'node:net';
import { domainToASCII } from 'node:url';
import { randomBytes } from 'node:crypto';
import { isPublicIP } from './proxy-network.mjs';

export const PROXY_BOOTSTRAP_DOH_ENDPOINTS = Object.freeze(['https://223.5.5.5/dns-query', 'https://223.6.6.6/dns-query']);
const MAX_DNS_BYTES = 16384;
const unavailable = () => Object.assign(new Error('无法安全解析节点入口；未切换为系统 DNS 或直接连接。'), { code: 'PROXY_CORE_BOOTSTRAP_UNAVAILABLE' });
const refused = () => Object.assign(new Error('节点解析响应无效。'), { code: 'PROXY_BOOTSTRAP_RESPONSE_INVALID' });

export function bootstrapDNSQuestion(host) {
  if (typeof host !== 'string' || host.length > 253 || /[\x00-\x20\x7f/@?#\\:]/.test(host) || net.isIP(host)) throw unavailable();
  const name = domainToASCII(host).toLowerCase().replace(/\.$/, '');
  if (!name || name.length > 253 || name.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw unavailable();
  const header = Buffer.alloc(12); randomBytes(2).copy(header); header.writeUInt16BE(0x0100, 2); header.writeUInt16BE(1, 4);
  const labels = name.split('.').flatMap(label => [Buffer.from([label.length]), Buffer.from(label, 'ascii')]);
  return { name, bytes: Buffer.concat([header, ...labels, Buffer.from([0, 0, 1, 0, 1])]) };
}

function readName(bytes, start) {
  let cursor = start, end = null, jumps = 0, totalLength = 0; const visited = new Set(), labels = [];
  while (cursor < bytes.length && labels.length < 128) {
    if (visited.has(cursor)) throw refused(); visited.add(cursor);
    const size = bytes[cursor++];
    if (size === 0) return { name: labels.join('.').toLowerCase(), end: end ?? cursor };
    if ((size & 0xc0) === 0xc0) {
      if (cursor >= bytes.length || ++jumps > 32) throw refused();
      const destination = ((size & 0x3f) << 8) | bytes[cursor++];
      if (destination >= bytes.length) throw refused(); end ??= cursor; cursor = destination;
    } else {
      if (size > 63 || cursor + size > bytes.length || (totalLength += size + 1) > 254) throw refused();
      const rawLabel = bytes.subarray(cursor, cursor + size);
      if (rawLabel.some(value => value < 0x21 || value > 0x7e)) throw refused();
      const label = rawLabel.toString('ascii');
      if (!/^[a-z0-9_*-]{1,63}$/i.test(label)) throw refused();
      labels.push(label); cursor += size;
    }
  }
  throw refused();
}

/** Strict A question binding; only public answer-section A records on its CNAME chain count. */
export function parseBootstrapDNSAnswer(bytes, question) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 12 || bytes.length > MAX_DNS_BYTES || !question || !Buffer.isBuffer(question.bytes) ||
      bytes.readUInt16BE(0) !== question.bytes.readUInt16BE(0)) throw refused();
  const flags = bytes.readUInt16BE(2), qd = bytes.readUInt16BE(4), an = bytes.readUInt16BE(6), ns = bytes.readUInt16BE(8), ar = bytes.readUInt16BE(10);
  if (!(flags & 0x8000) || flags & 0x7800 || flags & 0x0200 || flags & 0x0040 || qd !== 1 || an + ns + ar > 128) throw refused();
  const q = readName(bytes, 12);
  if (q.name !== question.name || q.end + 4 > bytes.length || bytes.readUInt16BE(q.end) !== 1 || bytes.readUInt16BE(q.end + 2) !== 1) throw refused();
  let offset = q.end + 4, extendedRcode = 0, optSeen = false; const records = [];
  for (let index = 0; index < an + ns + ar; index++) {
    const ownerStart = offset, owner = readName(bytes, offset); offset = owner.end;
    if (offset + 10 > bytes.length) throw refused();
    const type = bytes.readUInt16BE(offset), klass = bytes.readUInt16BE(offset + 2), ttl = bytes.readUInt32BE(offset + 4), size = bytes.readUInt16BE(offset + 8); offset += 10;
    if (offset + size > bytes.length) throw refused();
    let address = null, alias = null;
    if (type === 41) {
      if (index < an + ns || optSeen || owner.name !== '' || bytes[ownerStart] !== 0 || owner.end !== ownerStart + 1 || ((ttl >>> 16) & 255) !== 0) throw refused();
      optSeen = true; extendedRcode = ttl >>> 24;
      let option = offset;
      while (option < offset + size) {
        if (option + 4 > offset + size) throw refused();
        const optionLength = bytes.readUInt16BE(option + 2); option += 4;
        if (option + optionLength > offset + size) throw refused(); option += optionLength;
      }
    } else if (klass === 1 && type === 1) {
      if (size !== 4) throw refused();
      address = [...bytes.subarray(offset, offset + 4)].join('.');
    } else if (klass === 1 && type === 5) {
      const target = readName(bytes, offset); if (target.end !== offset + size) throw refused(); alias = target.name;
    }
    if (index < an) records.push({ owner: owner.name, address, alias }); offset += size;
  }
  if (offset !== bytes.length) throw refused();
  const rcode = (extendedRcode << 4) | (flags & 15); if (rcode !== 0) return { rcode, addresses: [] };
  const aliases = new Set([question.name]);
  for (let pass = 0; pass < 128; pass++) {
    let changed = false;
    for (const record of records) if (record.alias && aliases.has(record.owner) && !aliases.has(record.alias)) { aliases.add(record.alias); changed = true; }
    if (!changed) break;
  }
  const addresses = [...new Set(records.filter(record => aliases.has(record.owner) && record.address && isPublicIP(record.address)).map(record => record.address))];
  return { rcode, addresses };
}

/** Owned TLS socket only: no DNS listener, redirects, proxy environment, or insecure TLS fallback. */
export function requestBootstrapDNS({ url, question, timeoutMs, maxBodyBytes = MAX_DNS_BYTES, localAddress, signal }) {
  return new Promise((resolve, reject) => {
    let request, done = false, length = 0; const chunks = [];
    const finish = (error, value) => {
      if (done) return; done = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
      if (error) { request?.destroy(); reject(unavailable()); } else resolve(value);
    };
    const abort = () => finish(unavailable());
    const timer = setTimeout(abort, timeoutMs);
    try {
      const endpoint = new URL(url);
      if (!PROXY_BOOTSTRAP_DOH_ENDPOINTS.includes(endpoint.href) || !Buffer.isBuffer(question) || question.length < 17 || question.length > 512 ||
          !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000 || !Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 12 || maxBodyBytes > MAX_DNS_BYTES ||
          localAddress != null && net.isIP(localAddress) !== 4 || signal?.aborted) return finish(unavailable());
      request = https.request(endpoint, { method: 'POST', agent: false, rejectUnauthorized: true, localAddress, signal,
        headers: { Accept: 'application/dns-message', 'Content-Type': 'application/dns-message', 'Content-Length': question.length } }, response => {
        if (response.statusCode !== 200 || Number(response.headers['content-length']) > maxBodyBytes ||
            !/^application\/dns-message(?:\s*;|$)/i.test(response.headers['content-type'] ?? '')) { response.destroy(); finish(unavailable()); return; }
        response.on('data', chunk => { length += chunk.length; if (length > maxBodyBytes) { response.destroy(); finish(unavailable()); } else chunks.push(chunk); });
        response.once('error', abort); response.once('aborted', abort);
        response.once('end', () => finish(null, Buffer.concat(chunks)));
      });
      request.once('error', abort); request.end(question);
      signal?.addEventListener('abort', abort, { once: true });
    } catch { finish(unavailable()); }
  });
}

/** Negative or failed replies never preempt another pending valid public A answer. */
export async function resolveProxyBootstrapHost(host, { localAddress, timeoutMs = 4000, transport = requestBootstrapDNS, signal } = {}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000 || typeof transport !== 'function' ||
      localAddress != null && net.isIP(localAddress) !== 4 || signal?.aborted) throw unavailable();
  const question = bootstrapDNSQuestion(host), controllers = PROXY_BOOTSTRAP_DOH_ENDPOINTS.map(() => new AbortController());
  return new Promise((resolve, reject) => {
    let settled = false, pending = controllers.length;
    const finish = address => {
      if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
      controllers.forEach(controller => controller.abort());
      address ? resolve(address) : reject(unavailable());
    };
    const abort = () => finish(null), timer = setTimeout(abort, timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    for (let index = 0; index < controllers.length; index++) {
      Promise.resolve().then(() => transport({ url: PROXY_BOOTSTRAP_DOH_ENDPOINTS[index], question: Buffer.from(question.bytes),
        timeoutMs, maxBodyBytes: MAX_DNS_BYTES, localAddress, signal: controllers[index].signal }))
        .then(bytes => {
          if (settled) return;
          const answer = parseBootstrapDNSAnswer(bytes, question);
          if (answer.addresses.length) finish(answer.addresses[0]);
        }).catch(() => {})
        .finally(() => { if (!settled && --pending === 0) finish(null); });
    }
  });
}
