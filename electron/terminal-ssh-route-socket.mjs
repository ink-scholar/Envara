// Main-process connector for a fixed saved SSH target and its resolved route.
// No listener credentials or destination selection are accepted from a terminal.
import net from 'node:net';
import tls from 'node:tls';
import { normalizeSshRoute } from './terminal-ssh-route.mjs';
import { validateSshProxyUrl, validateSshTarget } from './terminal-ssh-proxy.mjs';

const fail = (code = 'SSH_ROUTE_UNAVAILABLE') => Object.assign(new Error('SSH 所选网络不可用，未切换其他路线。'), { code });

export async function openSshRouteSocket({ target, routeContext, signal, timeoutMs = 10000,
  connect = net.connect, secureConnect = tls.connect } = {}) {
  let checked, route, proxy;
  try {
    checked = validateSshTarget(target?.host, target?.port);
    route = normalizeSshRoute(routeContext?.route);
    if (typeof routeContext.isActive !== 'function' || typeof connect !== 'function' || typeof secureConnect !== 'function'
      || !Number.isInteger(timeoutMs) || timeoutMs < 10 || timeoutMs > 120000) throw fail('SSH_ROUTE_INVALID');
    if (route.kind === 'environment') proxy = validateSshProxyUrl(routeContext.proxyUrl);
    else if (routeContext.proxyUrl != null) throw fail('SSH_ROUTE_INVALID');
  } catch { throw fail('SSH_ROUTE_INVALID'); }
  const active = () => { try { return routeContext.isActive() === true; } catch { return false; } };
  if (!active()) throw fail('SSH_ROUTE_CHANGED');
  if (signal?.aborted) throw fail('SSH_ROUTE_CANCELLED');
  return new Promise((resolve, reject) => {
    let socket, settled = false, buffer = Buffer.alloc(0);
    const cleanup = () => {
      clearTimeout(timer); signal?.removeEventListener('abort', aborted);
      socket?.off('data', response); socket?.off('error', errored); socket?.off('close', closed);
      socket?.off('connect', connected); socket?.off('secureConnect', connected);
    };
    const finish = error => {
      if (settled) return;
      settled = true; cleanup();
      if (error) { socket?.destroy(); reject(error); }
      else { socket.pause(); resolve(socket); }
    };
    const aborted = () => finish(fail('SSH_ROUTE_CANCELLED'));
    const errored = () => finish(fail());
    const closed = () => finish(fail());
    const timer = setTimeout(() => finish(fail()), timeoutMs);
    const response = chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      const end = buffer.indexOf('\r\n\r\n');
      if (end < 0) { if (buffer.length > 16384) finish(fail()); return; }
      if (end + 4 > 16384) { finish(fail()); return; }
      const lines = buffer.subarray(0, end).toString('latin1').split('\r\n');
      if (!/^HTTP\/1\.[01] 200(?: [\x20-\x7e]*)?$/.test(lines.shift())
        || lines.some(line => !/^[!#$%&'*+.^_`|~\da-z-]+:[\t\x20-\x7e\x80-\xff]*$/i.test(line))) {
        finish(fail()); return;
      }
      if (!active()) { finish(fail('SSH_ROUTE_CHANGED')); return; }
      socket.pause();
      const head = buffer.subarray(end + 4); buffer = null;
      socket.off('data', response);
      if (head.length) socket.unshift(head);
      finish();
    };
    const connected = () => {
      if (!active()) { finish(fail('SSH_ROUTE_CHANGED')); return; }
      if (!proxy) { finish(); return; }
      if (proxy.secure && socket.authorized === false) { finish(fail()); return; }
      const authority = `${net.isIP(checked.host) === 6 ? `[${checked.host}]` : checked.host}:${checked.port}`;
      socket.on('data', response);
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\nProxy-Authorization: ${proxy.authorization}\r\n\r\n`);
    };
    try {
      socket = proxy ? (proxy.secure ? secureConnect : connect)({ host: proxy.host, port: proxy.port,
        allowHalfOpen: true, ...(proxy.secure ? { rejectUnauthorized: true } : {}) })
        : connect({ host: checked.host, port: checked.port, allowHalfOpen: true });
      if (!socket?.once || !socket?.pause || !socket?.destroy || !socket?.write || !socket?.unshift) throw fail();
      // The receiving transport attaches its own listeners in the next microtask.
      socket.on('error', () => {});
      socket.once('error', errored); socket.once('close', closed);
      socket.once(proxy?.secure ? 'secureConnect' : 'connect', connected);
      signal?.addEventListener('abort', aborted, { once: true });
      if (signal?.aborted) aborted();
    } catch { finish(fail()); }
  });
}
