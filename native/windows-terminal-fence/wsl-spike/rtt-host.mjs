// Round trips over wsl.exe's piped stdio: small messages, then bulk echo.
import { spawn } from 'node:child_process';
const child = spawn('C:\\Windows\\System32\\wsl.exe', ['-d', 'EnvaraSpike2', '-u', 'root', '--', 'python3', '/opt/spike/rtt-agent.py'],
  { stdio: ['pipe', 'pipe', 'inherit'], windowsHide: true });
let want = 0, got = 0, done = null;
child.stdout.on('data', d => { got += d.length; if (got >= want && done) { const f = done; done = null; f(); } });
const echo = size => new Promise(r => { want = got + size; done = r; child.stdin.write(Buffer.alloc(size, 7)); });
const ms = async fn => { const t = process.hrtime.bigint(); await fn(); return Number(process.hrtime.bigint() - t) / 1e6; };
for (const size of [1, 100, 1000, 16384, 65536]) {
  const times = [];
  for (let i = 0; i < 10; i++) times.push(await ms(() => echo(size)));
  times.sort((a, b) => a - b);
  console.log(`echo ${size} B: min ${times[0].toFixed(1)} ms, median ${times[5].toFixed(1)} ms, max ${times[9].toFixed(1)} ms`);
}
const big = 100 * 1024 * 1024;
const t = await ms(() => new Promise(r => {
  want = got + big; done = r;
  const chunk = Buffer.alloc(1 << 16); let sent = 0;
  const pump = () => { while (sent < big) { sent += chunk.length; if (!child.stdin.write(chunk)) return child.stdin.once('drain', pump); } };
  pump();
}));
console.log(`bulk echo 100 MB both ways: ${(t / 1000).toFixed(2)} s = ${(big / t / 1e3).toFixed(0)} MB/s`);
child.stdin.end();
