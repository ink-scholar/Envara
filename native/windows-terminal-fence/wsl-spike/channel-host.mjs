// Windows-host end of the Envara <-> WSL channel (spike). Spawns wsl.exe with
// plain pipes and multiplexes streams over its stdio; "route" connects to the
// environment's route (here yyb's Clash), "bench" streams 200 MB of zeros.
import { spawn } from 'node:child_process';
import net from 'node:net';

const DISTRO = 'EnvaraSpike2', ROUTE = { host: '127.0.0.1', port: 7897 };
const OPEN = 1, DATA = 2, CLOSE = 3;
const wsl = 'C:\\Windows\\System32\\wsl.exe';
const child = spawn(wsl, ['-d', DISTRO, '-u', 'root', '--', 'env', `CH_DEBUG=${process.argv[3] === 'debug' ? 1 : 0}`, 'python3', '/opt/spike/channel-agent.py', process.argv[2] || '/opt/spike/channel-spike.sh'],
  { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
child.stderr.pipe(process.stdout);
const streams = new Map();
const stats = { opened: {}, up: 0, down: 0 };

function send(kind, id, payload = Buffer.alloc(0)) {
  const h = Buffer.alloc(9);
  h.writeUInt8(kind, 0); h.writeUInt32BE(id, 1); h.writeUInt32BE(payload.length, 5);
  return child.stdin.write(Buffer.concat([h, payload]));
}
function close(id) { if (streams.delete(id)) send(CLOSE, id); }

function open(id, name) {
  stats.opened[name] = (stats.opened[name] || 0) + 1;
  if (name === 'route') {
    const sock = net.connect(ROUTE);
    streams.set(id, sock);
    sock.on('data', d => {
      stats.down += d.length;
      if (!send(DATA, id, d)) { sock.pause(); child.stdin.once('drain', () => sock.resume()); }
    });
    sock.on('close', () => close(id));
    sock.on('error', () => {});
  } else if (name === 'bench') {
    streams.set(id, null);
    const chunk = Buffer.alloc(64 * 1024); let sent = 0; const total = 200 * 1024 * 1024;
    const pump = () => {
      while (sent < total) {
        const ok = send(DATA, id, chunk); sent += chunk.length;
        if (!ok) return child.stdin.once('drain', pump);
      }
      close(id);
    };
    pump();
  } else send(CLOSE, id); // unknown names get nothing
}

let buf = Buffer.alloc(0);
child.stdout.on('data', chunk => {
  buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
  while (buf.length >= 9) {
    const n = buf.readUInt32BE(5);
    if (buf.length < 9 + n) break;
    const kind = buf[0], id = buf.readUInt32BE(1), p = buf.subarray(9, 9 + n);
    buf = buf.subarray(9 + n);
    if (kind === OPEN) open(id, p.toString());
    else if (kind === DATA) { const s = streams.get(id); if (s) { stats.up += p.length; s.write(p); } }
    else if (kind === CLOSE) { const s = streams.get(id); streams.delete(id); s?.end(); }
  }
});
child.stdin.on('error', () => {});

child.on('exit', async code => {
  console.log(`\n== host: agent exit ${code}; streams ${JSON.stringify(stats.opened)}; up ${stats.up} B; down ${stats.down} B`);
  // Lifecycle: does killing wsl.exe (as when Envara crashes) kill the Linux side?
  const run = args => new Promise(r => { const p = spawn(wsl, ['-d', DISTRO, '-u', 'root', '--', ...args], { windowsHide: true }); let o = ''; p.stdout.on('data', d => o += d); p.on('exit', () => r(o.trim())); });
  const victim = spawn(wsl, ['-d', DISTRO, '-u', 'root', '--', 'sh', '-c', 'echo $$ > /tmp/life.pid; exec sleep 600'], { windowsHide: true });
  await new Promise(r => setTimeout(r, 3000));
  victim.kill();
  await new Promise(r => setTimeout(r, 2000));
  console.log('== host: Linux process after its wsl.exe was terminated:', await run(['sh', '-c', 'kill -0 $(cat /tmp/life.pid) 2>/dev/null && echo still-alive || echo gone']));
  process.exit(code ?? 1);
});
