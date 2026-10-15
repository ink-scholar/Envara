/* How a fenced terminal hands a link back to Envara.
 *
 * A shell inside the environment's network fence cannot reach the host's
 * browser, and `open` would otherwise hand the URL to LaunchServices, which
 * starts a browser outside the environment on the host network. Instead the
 * environment's own private PATH gets a small `open` replacement that reports
 * the link to this app over a loopback unix socket, keyed by the environment's
 * session token; Envara then opens it in that environment's designated
 * fingerprint browser. The socket accepts a link and nothing else, and its
 * token identifies the environment without trusting anything in the request.
 */
import net from 'node:net';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { chmod, lstat, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';

const MAX_REQUEST_BYTES = 8192;
const LINK_TOKEN = /^[A-Za-z0-9_-]{32,128}$/;
const fail = message => Object.assign(new Error(message), { code: 'LINK_CHANNEL_UNAVAILABLE' });

export const TERMINAL_LINK_SOCKET = 'link.sock';
export const TERMINAL_LINK_BIN = 'bin';

/** The scripts an environment's PATH carries. `open` is replaced; a real
 * executable is never shadowed for anything that is not a web link, and a
 * failed report is never silent: the real browser is not started instead. */
export function linkShimScripts() {
  const opener = `#!/bin/sh
# Envara: open a web link in this environment's browser.
# Every expansion is braced: macOS /bin/sh (bash 3.2) in a UTF-8 locale would
# otherwise read a Chinese character after $name as part of the name.
# Anything that is not a web link keeps the system behaviour; every outcome
# for a link is said on the terminal, and a refusal never opens a host browser.
say() { printf 'envara: %s\n' "$1" >&2; }
links=""
passthrough=""
for arg in "$@"; do
  case "$arg" in
    -*) passthrough=1 ;;
    http://*|https://*) links=1 ;;
    *) passthrough=1 ;;
  esac
done
[ -n "$links" ] || exec /usr/bin/open "$@"
if [ -n "$passthrough" ]; then say "链接不能和其他参数一起打开；链接没有打开。"; exit 1; fi
if [ -z "\${ENVARA_LINK_TOKEN:-}" ] || [ -z "\${ENVARA_LINK_SOCKET:-}" ]; then
  say "这个终端没有连上 Envara 的链接通道，链接没有打开。请新建一个终端再试。"; exit 1
fi
body="\${TMPDIR:-/tmp}/envara-link.$$"
trap 'rm -f "$body"' EXIT INT TERM
status=0
for arg in "$@"; do
  escaped=$(printf '%s' "$arg" | /usr/bin/sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g')
  printf '{"url":"%s"}\n' "$escaped" > "$body" || exit 1
  reply=$(/usr/bin/curl --noproxy "*" --silent --max-time 30 \
    --unix-socket "$ENVARA_LINK_SOCKET" -H "Authorization: Bearer $ENVARA_LINK_TOKEN" \
    -w '\n%{http_code}' --data-binary @"$body" "http://localhost/link" 2>/dev/null)
  code=$(printf '%s\n' "$reply" | /usr/bin/tail -n 1)
  browser=$(printf '%s\n' "$reply" | /usr/bin/sed '$d' | /usr/bin/sed -n 's/.*"browser":"\\([^"]*\\)".*/\\1/p')
  case "$code" in
    200) if [ -n "\${browser}" ]; then say "正在「\${browser}」中打开 \${arg}"; else say "已交给系统默认浏览器打开，不经过境舱网络：\${arg}"; fi ;;
    403) say "链接通道已更换（Envara 重启过）；请新建一个终端再打开链接。"; status=1 ;;
    400) say "这个链接无法打开：\${arg}"; status=1 ;;
    000) say "Envara 没有响应，链接没有打开。"; status=1 ;;
    *) say "Envara 没有打开这个链接（\${code:-无响应}）。"; status=1 ;;
  esac
done
exit $status
`;
  /* BROWSER callers (python -m webbrowser, gh, gcloud) reach the same channel. */
  const browser = `#!/bin/sh
# Envara: the environment's browser for tools that honour $BROWSER.
exec "$(dirname "$0")/open" "$@"
`;
  return { open: opener, browser, 'envara-open': browser };
}

export class LinkSocketServer {
  /* Two kinds of caller. A terminal's shim presents its environment's token and
   * sends a lone url. The system link helper has no token: it is trusted by the
   * socket itself (this user's alone, 0600) and says which process sent the link. */
  constructor({ root, onLink, log = () => {}, socketDirectory = null, socketPath = null, socketOwner = process.getuid?.() ?? null, sender = 'token' }) {
    if (!['token', 'owner'].includes(sender)) throw fail('终端链接通道无效。');
    this.sender = sender;
    if (typeof root !== 'string' || !path.isAbsolute(root) || typeof onLink !== 'function') throw fail('终端链接通道无效。');
    for (const value of [socketDirectory, socketPath])
      if (value != null && (typeof value !== 'string' || !path.isAbsolute(value))) throw fail('终端链接通道无效。');
    this.root = root; this.onLink = onLink; this.log = log; this.socketDirectory = socketDirectory;
    /* macOS refuses a unix socket path longer than 104 bytes, and a silently
     * unreachable socket is the difference between a link that opens in the
     * environment and one that opens on the host, so it is refused here. */
    if (socketPath != null && Buffer.byteLength(socketPath, 'utf8') > 100) throw fail('终端链接通道路径过长。');
    this.flatSocketPath = socketPath; this.socketOwner = socketOwner;
    this.server = null; this.socketPath = null; this.directory = null; this.tokens = new Map();
  }
  /* One directory and one socket for the whole app; each environment gets a
   * token, so nothing about a session is guessable from the URL. */
  async listen({ directory: chosen = null, socketName = TERMINAL_LINK_SOCKET } = {}) {
    /* A flat path is what a native helper needs: a unix socket path is limited
     * to 104 bytes, so the shared temporary directory is the only place short
     * enough. The socket is user-only and a stale one from an earlier run is
     * replaced, which is safe because the name carries the user's id. */
    const flat = Boolean(this.flatSocketPath);
    const directory = chosen ?? (flat ? path.dirname(this.flatSocketPath) : this.socketDirectory ?? path.join(this.root, 'link'));
    await mkdir(directory, { recursive: true, mode: flat ? 0o755 : 0o700 }).catch(error => { throw fail(`终端链接通道无法创建：${error.message}`); });
    if (flat) {
      /* The shared temporary directory is the only place short enough for the
       * native router's socket path. It is sticky and world-writable by design,
       * and the socket inside it is user-only, so only the directory's type and
       * its identity as a temporary directory are checked here. */
      const resolved = await realpath(directory).catch(() => null);
      const temporary = await Promise.all([realpath('/tmp').catch(() => '/private/tmp'), realpath(os.tmpdir()).catch(() => null)]);
      const info = resolved ? await lstat(resolved).catch(() => null) : null;
      const inside = temporary.some(place => place && (resolved === place || resolved?.startsWith(`${place}${path.sep}`)));
      if (!info?.isDirectory() || !inside) throw fail('终端链接通道目录不安全。');
    } else {
      const info = await lstat(directory);
      if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid?.() || (info.mode & 0o077)) throw fail('终端链接通道目录不安全。');
      await chmod(directory, 0o700);
    }
    this.directory = directory;
    this.socketPath = this.flatSocketPath ?? path.join(directory, socketName);
    try { await rm(this.socketPath, { force: true }); } catch {}
    this.server = net.createServer(socket => { socket.setTimeout(10000, () => socket.destroy()); void this.handle(socket); });
    await new Promise((resolve, reject) => { this.server.once('error', reject); this.server.listen(this.socketPath, resolve); }).catch(error => { throw fail(`终端链接通道无法监听：${error.message}`); });
    await chmod(this.socketPath, 0o600);
    return this.socketPath;
  }
  token(profileId) {
    const existing = [...this.tokens.entries()].find(([, value]) => value.profileId === profileId);
    if (existing) return existing[0];
    const token = randomUUID().replaceAll('-', '') + randomUUID().replaceAll('-', '');
    this.tokens.set(token, { profileId });
    return token;
  }
  release(profileId) { for (const [token, value] of this.tokens) if (value.profileId === profileId) this.tokens.delete(token); }
  async handle(socket) {
    /* The request is answered as soon as its declared body has arrived: curl
     * keeps the connection open, so waiting for the stream to end would leave
     * the caller without an answer. */
    const chunks = []; let size = 0, settled = false;
    const reply = async (status, body) => { try { socket.end(`HTTP/1.1 ${status}\r\ncontent-length: ${Buffer.byteLength(body)}\r\nconnection: close\r\n\r\n${body}`); } catch {} };
    const settle = async () => {
      if (settled) return; settled = true;
      socket.setTimeout(0); // the request is complete; answering may take a moment
      try {
        const request = Buffer.concat(chunks).toString('utf8');
        const split = request.indexOf('\r\n\r\n');
        if (split < 0 || !request.startsWith('POST /link ')) return await reply('404 Not Found', '{"error":"not-found"}');
        const header = request.slice(0, split), body = request.slice(split + 4);
        let payload;
        try { payload = JSON.parse(body); } catch { payload = null; }
        let link;
        if (this.sender === 'owner') {
          // The link helper: a url and the pid that sent it, nothing else.
          const fields = payload && typeof payload === 'object' && !Array.isArray(payload) ? Object.keys(payload) : null;
          if (!fields || typeof payload.url !== 'string' || !Number.isSafeInteger(payload.senderPid) || payload.senderPid < 0 || fields.some(key => !['url', 'senderPid'].includes(key)))
            return await reply('400 Bad Request', '{"error":"invalid-body"}');
          link = { url: payload.url, pid: payload.senderPid };
        } else {
          const presented = /^authorization:[ \t]*bearer[ \t]+(\S+)[ \t]*$/im.exec(header)?.[1] ?? '';
          // A token that is well formed but unknown is refused the same way as a missing one.
          const found = LINK_TOKEN.test(presented) ? this.tokens.get(presented) : null;
          if (!found) return await reply('403 Forbidden', '{"error":"not-authorized"}');
          if (!payload || typeof payload.url !== 'string' || Object.keys(payload).length !== 1) return await reply('400 Bad Request', '{"error":"invalid-body"}');
          link = { profileId: found.profileId, url: payload.url };
        }
        const result = await this.onLink(link);
        return await reply('200 OK', JSON.stringify({ opened: result?.opened ?? 'unknown', browser: result?.browser ?? null }));
      } catch (error) {
        this.log(`link request failed: ${error?.message ?? 'unknown'}`);
        return await reply('502 Bad Gateway', '{"error":"failed"}');
      }
    };
    socket.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_REQUEST_BYTES) { socket.destroy(); return; }
      chunks.push(chunk);
      const request = Buffer.concat(chunks);
      const split = request.indexOf('\r\n\r\n');
      if (split < 0) return;
      const declared = Number(/^content-length:[ \t]*(\d+)[ \t]*$/im.exec(request.slice(0, split).toString('utf8'))?.[1] ?? 0);
      if (request.length - (split + 4) >= declared) void settle();
    });
    socket.on('error', () => {});
    socket.on('end', () => { void settle(); });
  }
  async close() {
    this.tokens.clear(); this.directory = null;
    const server = this.server; this.server = null;
    if (server) await new Promise(resolve => server.close(() => resolve())).catch(() => {});
    if (this.socketPath) await rm(this.socketPath, { force: true }).catch(() => {});
  }
  /* The environment's own executable directory, with the shim in place. */
  async executableDirectory(profileId) {
    if (!this.directory) throw fail('终端链接通道尚未就绪。');
    const directory = path.join(this.directory, 'bin');
    const perProfile = path.join(this.directory, 'bin', profileId);
    await mkdir(perProfile, { recursive: true, mode: 0o700 });
    await chmod(directory, 0o700).catch(() => {}); await chmod(perProfile, 0o700);
    for (const [name, source] of Object.entries(linkShimScripts())) {
      const target = path.join(perProfile, name);
      try { const info = await lstat(target); if (info.isFile() && !info.isSymbolicLink() && info.size === Buffer.byteLength(source)) continue; } catch {}
      await writeFile(target, source, { mode: 0o700 });
      await chmod(target, 0o700);
    }
    return perProfile;
  }
  environment(profileId) {
    if (!this.socketPath) throw fail('终端链接通道尚未就绪。');
    return { ENVARA_LINK_SOCKET: this.socketPath, ENVARA_LINK_TOKEN: this.token(profileId) };
  }
}

export class TerminalLinkChannel extends LinkSocketServer {
  async listen() { return super.listen({ socketName: TERMINAL_LINK_SOCKET }); }
}
