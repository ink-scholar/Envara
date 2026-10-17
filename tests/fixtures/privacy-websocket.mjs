// Loopback-only WS/WSS fixture. The HTTP proxy has no public forwarding path.
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

// Runs in the real document (including Camoufox's main world), not through
// Playwright evaluate, so isolated automation worlds cannot fake the result.
function nativeSocketProbe(target) {
  const socket = new WebSocket(target, ['fixture-echo']); socket.binaryType = 'arraybuffer';
  const result = { instance: socket instanceof WebSocket, prototype: Object.getPrototypeOf(socket) === WebSocket.prototype, constructor: socket.constructor === WebSocket,
    constants: [WebSocket.CONNECTING, WebSocket.OPEN, WebSocket.CLOSING, WebSocket.CLOSED], binaryType: socket.binaryType, events: [] };
  const finish = value => { document.documentElement.dataset.wsResult = JSON.stringify(value); };
  socket.addEventListener('open', () => { result.events.push('open'); result.protocol = socket.protocol; socket.send('ping'); });
  socket.addEventListener('message', event => { result.events.push(event.data); if (event.data === 'ping') socket.close(1000, 'done'); });
  socket.addEventListener('close', event => { result.events.push('close'); result.code = event.code; finish(result); });
  socket.addEventListener('error', () => finish({ error: true }));
  setTimeout(() => { if (!document.documentElement.dataset.wsResult) finish({ timeout: true }); }, 3000);
}

export async function createPrivacyWebSocketFixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-ws-fixture-'));
  const sockets = new Set(), received = [];
  const hosts = new Set(['example.test', 'chat.example.test', 'api.segment.io', 'app.segment.com', 'api.mixpanel.com']);
  const track = socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.on('error', () => {}); };
  let secure, proxy, closing;
  const close = () => closing ??= (async () => {
    for (const socket of sockets) socket.destroy();
    await Promise.all([secure, proxy].filter(Boolean).map(server => new Promise(resolve => server.close(resolve))));
    await rm(root, { recursive: true, force: true });
  })();
  try {
    await promisify(execFile)('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(root, 'key.pem'), '-out', path.join(root, 'cert.pem'), '-days', '1', '-subj', '/CN=Envara disposable fixture'], { timeout: 15000 });
    const serve = (request, response) => {
      const target = new URL(request.url, `http://${request.headers.host}`);
      if (!hosts.has(target.hostname)) { response.writeHead(403); response.end(); return; }
      response.writeHead(200, { 'content-type': 'text/html' });
      const socketURL = target.searchParams.get('socket'), nativeURL = target.searchParams.get('native');
      const escapeHTML = value => value.replaceAll('&', '&amp;').replaceAll('\"', '&quot;').replaceAll('<', '&lt;');
      const base = target.searchParams.get('base'), frame = target.searchParams.get('frame'), popup = target.searchParams.get('popup');
      response.end(`<!doctype html><title>Envara WebSocket fixture</title>${base ? `<base href="${escapeHTML(base)}">` : ''}${frame ? `<iframe src="${escapeHTML(frame)}"></iframe>` : ''}${popup ? `<a id="popup" target="_blank" href="${escapeHTML(popup)}">Popup</a>` : ''}${nativeURL ? `<script>(${nativeSocketProbe.toString()})(${JSON.stringify(nativeURL).replaceAll('<', '\\u003c')});</script>` : ''}${socketURL ? `<script>window.wsResult = new Promise(resolve => { let s; try { s = new WebSocket(${JSON.stringify(socketURL).replaceAll('<', '\\u003c')}); } catch (error) { resolve(error.name); return; } s.onmessage = event => { resolve(event.data); s.close(); }; s.onclose = () => resolve('closed'); s.onerror = () => resolve('error'); setTimeout(() => { s.close(); resolve('timeout'); }, 3000); }); window.wsResult.then(result => { document.documentElement.dataset.wsResult = result; });</script>` : ''}`);
    };
    const upgrade = (request, socket) => {
      track(socket);
      const target = new URL(request.url, `http://${request.headers.host}`);
      if (!hosts.has(target.hostname) || !request.headers['sec-websocket-key']) { socket.destroy(); return; }
      received.push({ host: target.hostname, path: target.pathname, secure: Boolean(socket.encrypted) });
      const accept = createHash('sha1').update(request.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
      const protocol = request.headers['sec-websocket-protocol']?.split(',')[0].trim();
      socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n${protocol ? `Sec-WebSocket-Protocol: ${protocol}\r\n` : ''}\r\n`);
      socket.write(Buffer.from([0x81, 5, ...Buffer.from('hello')]));
      let buffered = Buffer.alloc(0);
      socket.on('data', data => {
        buffered = Buffer.concat([buffered, data]);
        while (buffered.length >= 6) {
          const length = buffered[1] & 127;
          if (!(buffered[1] & 128) || length > 125) { socket.destroy(); return; }
          if (buffered.length < length + 6) return;
          const mask = buffered.subarray(2, 6), payload = Buffer.from(buffered.subarray(6, 6 + length)), opcode = buffered[0] & 15;
          for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
          buffered = buffered.subarray(6 + length);
          if (opcode === 8) { socket.end(Buffer.concat([Buffer.from([0x88, length]), payload])); return; }
          if (opcode === 1) socket.write(Buffer.concat([Buffer.from([0x81, length]), payload]));
        }
      });
    };
    secure = https.createServer({ key: await readFile(path.join(root, 'key.pem')), cert: await readFile(path.join(root, 'cert.pem')) }, serve);
    secure.on('upgrade', upgrade); secure.on('connection', track);
    await new Promise(resolve => secure.listen(0, '127.0.0.1', resolve));
    proxy = http.createServer(serve); proxy.on('upgrade', upgrade); proxy.on('connection', track);
    proxy.on('connect', (request, socket, head) => {
      const target = new URL(`https://${request.url}`);
      if (!hosts.has(target.hostname) || ![80, secure.address().port, proxy.address().port].includes(Number(target.port))) { socket.destroy(); return; }
      // Native Firefox resolves relative WS URLs against the document URL,
      // including its default port. Keep that synthetic destination local too.
      const port = Number(target.port) === 80 ? proxy.address().port : Number(target.port);
      const upstream = net.connect(port, '127.0.0.1'); track(upstream);
      upstream.on('connect', () => { socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); if (head.length) upstream.write(head); upstream.pipe(socket); socket.pipe(upstream); });
    });
    await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
    return { root, received, proxy: `http://127.0.0.1:${proxy.address().port}`, socketURL: (scheme, host, name) => `${scheme}://${host}:${scheme === 'wss' ? secure.address().port : proxy.address().port}/${name}`, close };
  } catch (error) { await close(); throw error; }
}
