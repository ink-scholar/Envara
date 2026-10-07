import { spawn } from 'node:child_process';
import { setTimeout } from 'node:timers/promises';
import electron from 'electron';

const vite = spawn(process.execPath, ['node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', '5173', '--strictPort'], { stdio: 'inherit' });
let desktop;
let exiting = false;
function cleanup(code = 0) {
  if (exiting) return;
  exiting = true;
  desktop?.kill('SIGTERM');
  vite.kill('SIGTERM');
  process.exitCode = code;
}
process.on('SIGINT', () => cleanup());
process.on('SIGTERM', () => cleanup());
vite.on('exit', code => { if (!exiting) cleanup(code ?? 1); });
for (let attempt = 0; attempt < 100; attempt++) {
  try {
    const response = await fetch('http://127.0.0.1:5173');
    if (response.ok) {
      const env = { ...process.env, ENVARA_DEV_URL: 'http://127.0.0.1:5173' };
      delete env.ELECTRON_RUN_AS_NODE;
      desktop = spawn(electron, ['.'], { stdio: 'inherit', env });
      desktop.on('exit', code => cleanup(code ?? 0));
      break;
    }
  } catch {}
  await setTimeout(200);
}
if (!desktop) { console.error('Vite did not become ready.'); cleanup(1); }
