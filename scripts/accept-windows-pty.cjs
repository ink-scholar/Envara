// Explicit Windows acceptance fixture. Run with the packaged Electron executable
// and ELECTRON_RUN_AS_NODE=1, never from the renderer or production startup.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash, randomBytes } = require('node:crypto');

const [applicationDirectory, reportPath] = process.argv.slice(2);
if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('Windows x64 native execution required');
if (!applicationDirectory || !reportPath || process.argv.length !== 4 || !path.isAbsolute(applicationDirectory) || !path.isAbsolute(reportPath)) {
  throw new Error('Expected absolute unpacked/installed application directory and new report path');
}
if (fs.existsSync(reportPath)) throw new Error('Refuse to overwrite acceptance evidence');
const ptyDirectory = path.join(applicationDirectory, 'resources', 'app.asar.unpacked', 'node_modules', 'node-pty');
const nativeDirectory = path.join(ptyDirectory, 'prebuilds', 'win32-x64');
const report = { schema: 'envara.windows-pty-acceptance', schemaVersion: 1, startedAt: new Date().toISOString(),
  platform: process.platform, arch: process.arch, versions: process.versions, passed: false,
  source: 'Packaged Electron Node runtime and packaged node-pty', checks: {}, files: [],
  GUIAcceptance: false, browserAcceptance: false, driverAcceptance: false };
const owned = new Set();
let pty, failure;
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const deadline = (promise, timeoutMs, code) => {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error(code), { code })), timeoutMs);
  })]).finally(() => clearTimeout(timer));
};

async function terminalLifecycle({ useConptyDll, kill }) {
  const marker = `ENVARA_PTY_${randomBytes(12).toString('hex')}`;
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  const command = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'cmd.exe');
  const terminal = pty.spawn(command, ['/d', '/q'], { name: 'xterm-color', cols: 80, rows: 24,
    cwd: path.dirname(reportPath), env, useConpty: true, useConptyDll });
  owned.add(terminal);
  let output = '', outputOverflow = false, resolveMarker, rejectMarker;
  const markerSeen = new Promise((resolve, reject) => { resolveMarker = resolve; rejectMarker = reject; });
  let exited = false;
  const exit = new Promise(resolve => terminal.onExit(value => { exited = true; owned.delete(terminal); resolve(value); }));
  const listener = terminal.onData(data => {
    output += data;
    if (output.length > 65536) { outputOverflow = true; rejectMarker(Object.assign(new Error('PTY_OUTPUT_LIMIT'), { code: 'PTY_OUTPUT_LIMIT' })); return; }
    // Exact output line, not the echoed command line or a cached fixture value.
    const clean = output.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '').replace(/\r/g, '');
    if (clean.split('\n').some(line => line.trim() === marker)) resolveMarker();
  });
  try {
    assert.ok(Number.isSafeInteger(terminal.pid) && terminal.pid > 0);
    terminal.write(`echo ${marker}\r`);
    await deadline(markerSeen, 15000, 'PTY_ECHO_TIMEOUT');
    assert.equal(outputOverflow, false);
    // Windows node-pty queues resize until the data pipe is ready. Real output
    // proves readiness before checking the updated dimensions.
    terminal.resize(132, 40);
    assert.equal(terminal.cols, 132);
    assert.equal(terminal.rows, 40);
    if (kill) terminal.kill();
    else terminal.write('exit 0\r');
    const result = await deadline(exit, 15000, 'PTY_EXIT_TIMEOUT');
    if (!kill) assert.equal(result.exitCode, 0);
    return { passed: true, spawned: true, wroteAndReceivedOutput: true, resized: true,
      closed: exited, closeMethod: kill ? 'kill' : 'shell exit', exitCode: result.exitCode,
      useConptyDll, outputStored: false };
  } finally {
    listener.dispose();
    if (!exited) {
      try { terminal.kill(); } catch {}
      try { await deadline(exit, 5000, 'PTY_CLEANUP_TIMEOUT'); } catch {}
    }
    if (!exited) throw Object.assign(new Error('PTY_CLEANUP_TIMEOUT'), { code: 'PTY_CLEANUP_TIMEOUT' });
  }
}

(async () => {
  try {
    assert.ok(process.versions.electron, 'Use the actual packaged Electron executable');
    assert.ok(Number(process.versions.napi) >= 8);
    assert.equal(path.resolve(process.execPath).toLowerCase(), path.join(applicationDirectory, 'Envara.exe').toLowerCase());
    report.files.push({ name: 'Envara.exe', sha256: hash(process.execPath) });
    for (const name of ['conpty.node', 'conpty_console_list.node', 'pty.node']) {
      const filename = path.join(nativeDirectory, name);
      const module = require(filename);
      assert.ok(module && typeof module === 'object');
      report.files.push({ name, sha256: hash(filename) });
    }
    report.checks.nativeModulesLoaded = { passed: true, modules: 3, napi: process.versions.napi };
    pty = require(ptyDirectory);
    report.checks.systemConpty = await terminalLifecycle({ useConptyDll: false, kill: false });
    report.checks.bundledConpty = await terminalLifecycle({ useConptyDll: true, kill: true });
    report.passed = Object.values(report.checks).every(check => check.passed === true);
  } catch (error) { failure = error; report.error = error.code || 'WINDOWS_PTY_ACCEPTANCE_FAILED'; }
  finally {
    for (const terminal of owned) { try { terminal.kill(); } catch {} }
    report.cleanupComplete = owned.size === 0;
    report.passed &&= report.cleanupComplete;
    report.finishedAt = new Date().toISOString();
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify(report));
    if (failure || !report.passed) process.exitCode = 1;
  }
})();
