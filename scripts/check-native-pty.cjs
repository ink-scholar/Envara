// Run this file with Electron's Node runtime, never in the ordinary Node test suite.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createRequire } = require('node:module');

const root = path.resolve(__dirname, '..');
const requireApp = createRequire(path.join(root, 'package.json'));
const pty = requireApp('node-pty');
if (!process.versions.electron) throw new Error('PTY check requires the Electron runtime.');
const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'envara-pty-check-'));
const ready = '__ENVARA_PTY_READY__';
const input = '__ENVARA_PTY_INPUT__envara-pty-input';
const isWindows = process.platform === 'win32';
const shell = isWindows
  ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'cmd.exe')
  : '/bin/sh';
const args = isWindows
  ? ['/d', '/q', '/v:on', '/c', `echo ${ready} & set /p envara_line= & echo __ENVARA_PTY_INPUT__!envara_line! & exit /b 0`]
  : ['-c', `printf '${ready}\\n'; IFS= read -r envara_line; printf '\\n__ENVARA_PTY_INPUT__%s\\n' "$envara_line"`];
// A noninteractive shell and temporary HOME avoid reading personal shell settings.
const env = { HOME: cwd, TMPDIR: cwd, TMP: cwd, TEMP: cwd, TERM: 'xterm-256color', LANG: 'C.UTF-8' };
if (isWindows) env.SystemRoot = process.env.SystemRoot || 'C:\\Windows';
let terminal;
let output = '';
let wrote = false;
let finished = false;
let dataListener;
let exitListener;
function finish(error, event) {
  if (finished) return;
  finished = true;
  clearTimeout(timeout);
  dataListener?.dispose();
  exitListener?.dispose();
  if (error) {
    try { terminal?.kill(); } catch {}
    console.error(error.message);
    process.exitCode = 1;
  } else {
    console.log(JSON.stringify({
      ok: true, electron: process.versions.electron, node: process.versions.node,
      modules: process.versions.modules, napi: process.versions.napi,
      platform: process.platform, arch: process.arch, resize: true, write: true,
      exitCode: event.exitCode,
    }));
  }
  fs.rmSync(cwd, { recursive: true, force: true });
}
const timeout = setTimeout(() => finish(new Error('Electron PTY check timed out.')), 10000);
try {
  terminal = pty.spawn(shell, args, { cwd, env, cols: 80, rows: 24, name: 'xterm-256color', encoding: 'utf8' });
  terminal.resize(100, 30);
  dataListener = terminal.onData(data => {
    output = (output + data).slice(-4096);
    if (!wrote && output.includes(ready)) {
      wrote = true;
      terminal.write('envara-pty-input\r');
    }
  });
  exitListener = terminal.onExit(event => {
    if (event.exitCode !== 0 || !output.includes(input)) {
      finish(new Error('Electron PTY check did not complete its input/output handshake.'));
    } else finish(null, event);
  });
} catch (error) { finish(error); }
