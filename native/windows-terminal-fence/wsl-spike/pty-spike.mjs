// node-pty (ConPTY) -> wsl.exe -> environment namespace -> unprivileged bash,
// rendered by @xterm/headless. The route reaches Windows over wsl.exe stdio.
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import net from 'node:net';
import fs from 'node:fs';

const require = createRequire('C:\\Users\\Admin\\envara-test\\Envara\\package.json');
const pty = require('node-pty');
const { Terminal } = require('@xterm/headless');

const DISTRO = 'EnvaraSpike3', WSL = 'C:\\Windows\\System32\\wsl.exe';
const step = process.argv[2] || 'all';
const log = (...a) => console.log(...a);
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---- channel (route only), same framing as channel-host.mjs
const agent = spawn(WSL, ['-d', DISTRO, '-u', 'root', '--', 'env', `CONTAINERENV=${process.argv[3] === 'containerenv' ? 1 : 0}`, 'python3', '/opt/spike/channel-agent.py', '/opt/spike/ns-up.sh'],
  { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
const streams = new Map();
const send = (k, id, p = Buffer.alloc(0)) => { const h = Buffer.alloc(9); h[0] = k; h.writeUInt32BE(id, 1); h.writeUInt32BE(p.length, 5); return agent.stdin.write(Buffer.concat([h, p])); };
let abuf = Buffer.alloc(0);
agent.stdout.on('data', c => {
  abuf = abuf.length ? Buffer.concat([abuf, c]) : c;
  while (abuf.length >= 9) {
    const n = abuf.readUInt32BE(5); if (abuf.length < 9 + n) break;
    const k = abuf[0], id = abuf.readUInt32BE(1), p = abuf.subarray(9, 9 + n); abuf = abuf.subarray(9 + n);
    if (k === 1) {
      const s = net.connect(7897, '127.0.0.1'); streams.set(id, s);
      s.on('data', d => { if (!send(2, id, d)) { s.pause(); agent.stdin.once('drain', () => s.resume()); } });
      s.on('close', () => { if (streams.delete(id)) send(3, id); }); s.on('error', () => {});
    } else if (k === 2) streams.get(id)?.write(p);
    else if (k === 3) { const s = streams.get(id); streams.delete(id); s?.end(); }
  }
});
agent.stdin.on('error', () => {});
await new Promise((res, rej) => {
  let e = ''; agent.stderr.on('data', d => { e += d; if (e.includes('NS-READY')) res(); });
  setTimeout(() => rej(new Error('namespace not ready: ' + e)), 30000);
});
log('namespace ready');

// ---- terminal
const term = new Terminal({ cols: 100, rows: 30, scrollback: 5000, allowProposedApi: true });
const p = pty.spawn(WSL, ['-d', DISTRO, '-u', 'root', '--', 'sh', '/opt/spike/enter.sh'], { name: 'xterm-256color', cols: 100, rows: 30, useConpty: true });
let raw = '';
p.onData(d => { raw += d; term.write(d); });
const text = () => { const b = term.buffer.active, out = []; for (let i = 0; i < b.length; i++) out.push(b.getLine(i).translateToString(true)); return out.join('\n'); };
const screen = () => { const b = term.buffer.active, out = []; for (let i = b.viewportY; i < b.viewportY + term.rows; i++) out.push(b.getLine(i)?.translateToString(true) ?? ''); return out.join('\n').replace(/\n+$/, ''); };
async function waitFor(re, ms = 20000) {
  const t = Date.now();
  while (Date.now() - t < ms) { await sleep(150); if (re.test(text())) return Date.now() - t; }
  throw new Error(`timeout waiting for ${re}\n--- screen ---\n${screen()}`);
}
let n = 0;
async function run(cmd, ms) {
  const tag = ++n;
  p.write(`${cmd}; echo __D""ONE_${tag}\r`);
  await waitFor(new RegExp(`^__DONE_${tag}$`, 'm'), ms);
  const all = text(), start = all.lastIndexOf(cmd.slice(0, 30)), end = all.indexOf(`\n__DONE_${tag}`, start);
  return all.slice(all.indexOf('\n', start) + 1, end).trim();
}
const out = (label, v) => log(`\n== ${label}\n${v}`);

try {
  await waitFor(/\$ $/m, 20000).catch(() => {});
  p.write("export PS1='ENV\\$ ' PATH=/opt/spike/bin:$HOME/.local/bin:$PATH" + (process.argv[5] === 'display' ? ' DISPLAY=:0' : '') + "\r"); await sleep(500);
  out('identity, home, size, TERM, namespace interfaces', await run('id; echo $HOME; stty size; echo $TERM; ip -br link'));
  p.resize(120, 40); term.resize(120, 40); await sleep(500);
  out('after resize to 120x40', await run('stty size; tput cols; tput lines'));
  p.write('sleep 30\r'); await sleep(1000); const t0 = Date.now(); p.write('\x03');
  await waitFor(/ENV\$ $/m, 5000); out('Ctrl-C interrupts sleep', `prompt back after ${Date.now() - t0} ms`);
  await run("printf '\\033[31mRED\\033[0m \\033[38;2;0;200;100mTRUE\\033[0m\\n'");
  { const b = term.buffer.active; let found = 'not found';
    for (let i = b.length - 1; i >= 0; i--) { const l = b.getLine(i); if (l.translateToString(true).startsWith('RED TRUE')) { const r = l.getCell(0), g = l.getCell(4); found = `RED fg palette=${r.getFgColor()} (isPalette ${r.isFgPalette()}); TRUE fg rgb=${g.getFgColor().toString(16)} (isRGB ${g.isFgRGB()})`; break; } }
    out('colors', found); }
  out('wide characters', await run('echo 中文宽字符OK'));
  out('exit IP inside', await run('curl -s -m 15 https://api.ipify.org; echo', 30000));
  out('can env read other users / escape', await run('ls /root 2>&1; cat /etc/shadow 2>&1 | head -1; ls /mnt 2>&1'));
  if (!fs.existsSync('C:\\Users\\Admin\\envara-test\\wsl-spike2\\.skip-install')) {
    out('install Claude Code as env', await run('curl -fsSL https://claude.ai/install.sh | bash 2>&1 | tail -4; claude --version', 300000));
  }
  out('claude --version', await run('claude --version', 60000));

  // ---- Claude first run and login
  p.write(process.argv[4] === 'strace' ? 'strace -f -qq -e trace=execve,connect -s 400 -o /home/env/st.txt claude\r' : 'claude\r');
  const snaps = [];
  const snap = async (label, wait = 4000) => { await sleep(wait); snaps.push(`---- ${label}\n${screen()}`); };
  await snap('start', 8000);
  for (let i = 0; i < 6 && !/paste code|Paste code|Browser didn|oauth|authorize/i.test(text()); i++) {
    p.write('\r'); await snap(`after Enter #${i + 1}`, 5000);
  }
  await snap('login screen', 3000);
  log('\n' + snaps.slice(-1).join('\n'));
  const urls = (text().replace(/\n/g, '').match(/https:\/\/[^\s]+/g) || []).filter(u => /oauth|authorize/.test(u));
  out('OAuth URL(s) on screen', urls.join('\n') || 'none');
  for (const u of urls) { try { const q = new URL(u).searchParams; out('redirect_uri on screen', q.get('redirect_uri')); } catch {} }
  // Terminal hyperlinks (OSC 8) carry the full URL behind the short label.
  const links = [...new Set([...raw.matchAll(/\x1b\]8;[^;]*;([^\x07\x1b]+)(?:\x07|\x1b\\)/g)].map(m => m[1]))].filter(u => /oauth/.test(u));
  for (const u of links) { try { const x = new URL(u); out('OSC 8 link', `${x.origin}${x.pathname} redirect_uri=${x.searchParams.get('redirect_uri')} code=${x.searchParams.get('code')}`); } catch { out('OSC 8 link (unparsed)', u.slice(0, 200)); } }

  const probe = spawn(WSL, ['-d', DISTRO, '-u', 'root', '--', 'sh', '-c', 'ip netns exec envpty ss -ltnp; echo ---; cat /home/env/opened-urls.txt 2>/dev/null; echo --- execve; grep execve /home/env/st.txt 2>/dev/null | grep -v "versions/2.1" | cut -c1-300 | head -40; echo --- connect; grep connect /home/env/st.txt 2>/dev/null | grep -o "sun_path=[^}]*\\|sin_port=[^,]*, sin_addr=[^)]*)" | sort | uniq -c | head'], { windowsHide: true });
  let po = ''; probe.stdout.on('data', d => po += d); await new Promise(r => probe.on('exit', r));
  out('listeners in the namespace while login waits; URLs handed to the browser channel', po.trim());
  for (const m of po.matchAll(/redirect_uri=([^&\s]+)/g)) out('redirect_uri sent to browser', decodeURIComponent(m[1]));
  const cb = /127\.0\.0\.1:(\d+)\s.*"claude"/.exec(po);
  if (cb) {
    const r = await new Promise(res => { const s = net.connect(Number(cb[1]), '127.0.0.1'); s.on('connect', () => { s.destroy(); res('connected (reachable from Windows)'); }); s.on('error', e => res(`not reachable from Windows: ${e.code}`)); });
    out(`Windows host -> claude callback 127.0.0.1:${cb[1]}`, r);
  }
  p.write('\x03'); await sleep(800); p.write('\x03'); await sleep(1500);
  out('after Ctrl-C x2', screen().split('\n').slice(-5).join('\n'));
} catch (e) { log('FAILED:', e.message); }
finally {
  p.kill(); agent.stdin.end();
  const down = spawn(WSL, ['-d', DISTRO, '-u', 'root', '--', 'sh', '-c', 'pkill -f "mihomo -d /etc/envara/envpty"; pkill -f "sleep 3600"; pkill -f TCP-LISTEN:1080; ip netns del envpty; echo cleaned'], { windowsHide: true });
  down.stdout.pipe(process.stdout); await new Promise(r => down.on('exit', r));
  process.exit(0);
}
