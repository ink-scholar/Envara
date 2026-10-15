import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

// Test-only localhost certificate. Never disable TLS verification in production.
export const key = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/rZHvXB3H0y+I
nPzMUftkDYwD2FIPYMRSb0Di+O1B+KXdQgLEO81bAunox769dqqb2L8sCH/qsrMe
pg3eVrKQ7p7NQNn9f8L65CPt6ZAd5eNXcBMSh8IjnB0BWUkP5V5z+/0wgtOe3dzC
Qb+E7CsJMylENoCLLmvRknAOhU1lmEAbm5uJ4+HcHfvTXp+sThqCtkeQbFU66aPm
OsdxNQkKnr08tK8zsgr50s/SrA7SUZlbd5Psn+alRqsXdc0o9ZBHUQzt4QaXATgC
HMJ5S616tTn8Tzj0ycmxXYGH+lcJENc+hqQLbNeWoG2dxlBnDdYptzP3QMXCKzNN
lFuDOWsdAgMBAAECggEAGQJloyyKujLk5ddN6L7dpS1bUnkcI+OFWhgoCDVgh5YQ
1jCxubbv0Wss5/GAAqqEEjeSogUt44qTcnFKJ/N58w0fbTqD9t5/q0qvIXCzHCON
qS/3XRiXjRvmcPGcZdWQoGOFopm/UOAz2KjJe2dxKg8h2EOgPAi/iqWnt01PTuz3
xx+LbXZqSwBczojh3JosbMdB0RJXm8wjrxsMaZ4eUgnzVBcvWKiMsb6+oXTEuGgR
zWrtaRjlL2BvDc93I0YGtVkuvv5dwbweQgczF6jJmODcm/0ys2IhkLTTaBXryCs7
cs8rrawVJ7QHvVhJ7DdJB1Xkj/RF/d9RznePbsJKgQKBgQDh9dEZzmVmjmffk0VU
/LiUKDnbl9m/3GV/ZrU4E15P9izXmZP+xh6DWb6TzEpoKxgZpfzBTjw6GjePgIuT
17BjYxwCIgr255fU0/CLNNBoovX8Ir04/xyOylSnJ/jNMTNBM7PnVR+5FKTT34pu
cu3fUmbKobO3twMPE9yhPFe9/QKBgQDZKQPC/z+ef4neIc+SjXQkoyALj4uWabDL
sdNaed/yG2mQMWC2qOqjjHTc9ziKckVCHJ/Uza6pCEVusK0P5Bx9eS6aSKyicDdc
eEkaO1qg+NhBU8DNYIAlHMqjcQBBTPuQxZ4ua+Hqklp1/GJnpEYgvFehLFTNjX9j
+ErJRCpboQKBgG2JlrYl4e4Xdq9hWyjZ4jigT3vuXvatRt690Xe/m+azdgWGQ8Is
FLqkFMjdLezVhzdXyfGDlZqs/uYn8IHY+38Smo9GJX6PwoC/xUoWbjlrVkfGJ2ir
8xIdb3Ag5nHCOhCPmdS45Un5gfXb1eW4/StXbNEqFk8m/uqePERFVluZAoGBALIm
V5Os2oAomO3GRwcvTEySFkPlqtnmMseoRn8+5F0159AG8hRnVrZ9D5IGrjfFrtOh
r+1gHx1ET9GS1ybmOAknVPf1DsrjzEbr1uzSLHNKMf7FurHBrN7FU+fpWBA6G1aV
CEOE9Xz+O3/3YLMtrOpGGI18VMWcgxl8I74hUa6BAoGARfonFd0vAGe2sOTOInTp
47g1ODHANnage1zvkfWVR3twxhLs/2va5MzpG0n2qyyzcGhbEbH2EnN3ujyUi3lC
dx8TommWxOt7pfTluvMMNj6d07Rc+RjLRG01YKNAYy5oZwu/YNhDVfs5zmSJlbWD
5UJbZFS79d+KUL080i4Dnyk=
-----END PRIVATE KEY-----`;
export const cert = `-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIURhKlSBjUu0ta9GwZplvfMKMxOmcwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAwNzEwMjYxMVoXDTM2MTAw
NDEwMjYxMVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAv62R71wdx9MviJz8zFH7ZA2MA9hSD2DEUm9A4vjtQfil
3UICxDvNWwLp6Me+vXaqm9i/LAh/6rKzHqYN3laykO6ezUDZ/X/C+uQj7emQHeXj
V3ATEofCI5wdAVlJD+Vec/v9MILTnt3cwkG/hOwrCTMpRDaAiy5r0ZJwDoVNZZhA
G5ubiePh3B37016frE4agrZHkGxVOumj5jrHcTUJCp69PLSvM7IK+dLP0qwO0lGZ
W3eT7J/mpUarF3XNKPWQR1EM7eEGlwE4AhzCeUuterU5/E849MnJsV2Bh/pXCRDX
PoakC2zXlqBtncZQZw3WKbcz90DFwiszTZRbgzlrHQIDAQABo28wbTAdBgNVHQ4E
FgQUkOFwk/CUJSTjxGD8/a/egeTsINIwHwYDVR0jBBgwFoAUkOFwk/CUJSTjxGD8
/a/egeTsINIwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH
BH8AAAEwDQYJKoZIhvcNAQELBQADggEBAFJnImSTRDGZxQ//KSL+WngHOrN/IEN2
0YU+Ds/DjlIV1S9xHDeOT1xEHlaOFuvbefHt7ffwspa+/bzfv7/hoJ5cURPkAyhE
GLUDzXDq8MlVmEgVWh8HWuJzSGH9lhs9ds+ybUKkcKVg3jwMyH7+KwSXxARXr76i
1snM5VszjMD8uevYSLuZh1t+zCFCrdohC7ZrcfjcdvABzHDTuan/BSOsDJANy4a+
bfJieeBz/COWxE4UOh8DJrpqJ1g8WwOTztdDhcrE51ZqdDuK5vhJZICrxae+++53
usL0De8navbofMctVAg7QWaXQNBPEecQgU4Y5XgvMxkl1e9gn4QqW14=
-----END CERTIFICATE-----`;

export const proxyUsername = 'download-fixture-user';
export const proxyPassword = 'download-fixture-password';
export const proxyAuth = `Basic ${Buffer.from(`${proxyUsername}:${proxyPassword}`).toString('base64')}`;

export async function listen(t, server) {
  const sockets = new Set();
  server.on('connection', socket => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  });
  return server.address().port;
}

/** All traffic stays on localhost. The certificate and proxy credentials are synthetic. */
export async function downloadFixture(t, { latest = '2.1.300', mutateManifest, respond, proxyMode = 'tunnel' } = {}) {
  const binary = await readFile(process.platform === 'win32' ? process.execPath : '/usr/bin/true');
  const checksum = createHash('sha256').update(binary).digest('hex');
  const manifest = { version: '2.1.300', platforms: {
    'darwin-arm64': { binary: 'claude', checksum, size: binary.length },
    'darwin-x64': { binary: 'claude', checksum, size: binary.length },
  } };
  mutateManifest?.(manifest);
  const requests = [], connects = [];
  const defaults = (request, response) => {
    if (request.url === '/releases/latest') response.end(latest);
    else if (request.url === '/releases/2.1.300/manifest.json') response.end(JSON.stringify(manifest));
    else if (/^\/releases\/2\.1\.300\/darwin-(arm64|x64)\/claude$/.test(request.url)) {
      response.setHeader('Content-Length', binary.length); response.end(binary);
    } else { response.writeHead(404); response.end(); }
  };
  const target = https.createServer({ key, cert }, (request, response) => {
    requests.push({ url: request.url, headers: request.headers });
    if (respond) respond(request, response, { defaults, binary, manifest });
    else defaults(request, response);
  });
  target.on('tlsClientError', () => {});
  const targetPort = await listen(t, target);
  const proxy = http.createServer();
  proxy.on('connect', (request, socket, head) => {
    connects.push({ target: request.url, auth: request.headers['proxy-authorization'] });
    if (proxyMode === 'silent') return;
    if (proxyMode === 'deny' || request.headers['proxy-authorization'] !== proxyAuth) {
      socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n'); return;
    }
    const upstream = net.connect(targetPort, '127.0.0.1', () => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      socket.pipe(upstream); upstream.pipe(socket);
    });
    socket.once('close', () => upstream.destroy());
    upstream.on('error', () => socket.destroy());
  });
  const proxyPort = await listen(t, proxy);
  return { binary, checksum, manifest, requests, connects, targetPort,
    baseURL: `https://localhost:${targetPort}/releases/`,
    proxyUrl: `http://${proxyUsername}:${proxyPassword}@127.0.0.1:${proxyPort}` };
}
