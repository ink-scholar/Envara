import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { captureTerminalProcess, closeTerminalProcess, terminalProcessMatches } from '../electron/terminal-process.mjs';

const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const isAlive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const posixOnly = { skip: process.platform === 'win32' };

async function startShell(t, body) {
  const shell = spawn('/bin/sh', ['-c', body], { stdio: ['pipe', 'pipe', 'ignore'] });
  t.after(() => { try { shell.kill('SIGKILL'); } catch {} });
  let output = '';
  const childPid = await new Promise((resolve, reject) => {
    shell.once('error', reject);
    shell.stdout.on('data', chunk => { output += chunk; if (output.includes('\n')) resolve(Number(output.split('\n')[0])); });
  });
  t.after(() => { try { process.kill(childPid, 'SIGKILL'); } catch {} });
  return { shell, childPid, pty: { pid: shell.pid, kill: signal => shell.kill(signal) } };
}

test('birth comparison rejects reused PIDs, zombies and mismatched kernel birth ticks', () => {
  const captured = { pid: 9123, birth: 'Mon Oct 5 12:00:00 2026', kernelBirth: '123456' };
  assert.equal(terminalProcessMatches({ ...captured, state: 'S' }, captured), true);
  assert.equal(terminalProcessMatches({ ...captured, birth: 'Mon Oct 5 12:00:01 2026' }, captured), false);
  assert.equal(terminalProcessMatches({ ...captured, kernelBirth: '123457' }, captured), false);
  assert.equal(terminalProcessMatches({ ...captured, state: 'Z' }, captured), false);
  assert.equal(terminalProcessMatches(undefined, captured), false);
});

test('invalid, app and uncaptured terminal PIDs cannot be signaled', async () => {
  for (const pid of [0, 1, -2, NaN, 1.5, '123', process.pid]) await assert.rejects(captureTerminalProcess(pid), TypeError);
  let kills = 0;
  await assert.rejects(closeTerminalProcess({ pty: { pid: 123, kill() { kills++; } }, identity: { pid: 123 } }), TypeError);
  assert.equal(kills, 0);
});

test('closing a real shell cleans its background child and leaves an unrelated child alive', posixOnly, async t => {
  const { shell, childPid, pty } = await startShell(t, 'sleep 300 & printf "%s\\n" "$!"; wait');
  const unrelated = spawn('/bin/sleep', ['300'], { stdio: 'ignore' });
  t.after(() => unrelated.kill('SIGKILL'));
  const identity = await captureTerminalProcess(shell.pid);
  const [first, second] = await Promise.all([closeTerminalProcess({ pty, identity }), closeTerminalProcess({ pty, identity })]);
  assert.deepEqual(second, first);
  assert.equal(first.ok, true);
  assert.equal(first.rootExited, true);
  assert.ok(first.signaledPids.includes(childPid));
  assert.equal(isAlive(unrelated.pid), true);
  assert.deepEqual(first.remainingPids, []);
});

test('a previously captured background child is cleaned after its shell has exited, without calling stale PTY kill', posixOnly, async t => {
  const { shell, childPid } = await startShell(t, 'sleep 300 </dev/null >/dev/null 2>&1 & printf "%s\\n" "$!"; read marker; exit 0');
  const identity = await captureTerminalProcess(shell.pid);
  const exited = once(shell, 'exit');
  shell.stdin.end('exit\n');
  await exited;
  await wait(50);
  assert.equal(isAlive(childPid), true);
  let staleKills = 0;
  const result = await closeTerminalProcess({ pty: { pid: shell.pid, kill() { staleKills++; } }, identity });
  assert.equal(staleKills, 0);
  assert.ok(result.signaledPids.includes(childPid));
  assert.equal(result.ok, true);
  assert.deepEqual(result.remainingPids, []);
});

test('a PTY with a different PID cannot use another captured context', posixOnly, async t => {
  const { shell, pty } = await startShell(t, 'sleep 300 & printf "%s\\n" "$!"; wait');
  const identity = await captureTerminalProcess(shell.pid);
  await assert.rejects(closeTerminalProcess({ pty: { ...pty, pid: shell.pid + 1 }, identity }), TypeError);
  const result = await closeTerminalProcess({ pty, identity });
  assert.equal(result.ok, true);
});

test('a process and child ignoring graceful signals are killed within the bounded close budget', posixOnly, async t => {
  const childProgram = 'process.on("SIGHUP",()=>{}); process.on("SIGTERM",()=>{}); process.stdout.write("ready\\n"); setInterval(()=>{},1000);';
  const program = `const {spawn}=require('node:child_process'); process.on('SIGHUP',()=>{}); process.on('SIGTERM',()=>{}); const child=spawn(process.execPath,['-e',${JSON.stringify(childProgram)}],{stdio:['ignore','pipe','ignore']}); child.stdout.once('data',()=>process.stdout.write(child.pid+'\\n')); setInterval(()=>{},1000);`;
  const shell = spawn(process.execPath, ['-e', program], { stdio: ['ignore', 'pipe', 'ignore'] });
  t.after(() => shell.kill('SIGKILL'));
  const [output] = await once(shell.stdout, 'data');
  const childPid = Number(output.toString().trim());
  t.after(() => { try { process.kill(childPid, 'SIGKILL'); } catch {} });
  const pty = { pid: shell.pid, kill: signal => shell.kill(signal) };
  const identity = await captureTerminalProcess(shell.pid);
  const signals = [];
  const trackedPty = { ...pty, kill(signal) { signals.push(signal); return pty.kill(signal); } };
  const started = Date.now();
  const result = await closeTerminalProcess({ pty: trackedPty, identity, timeoutMs: 1000 });
  assert.ok(signals.includes('SIGKILL'));
  assert.equal(result.ok, true);
  assert.deepEqual(result.remainingPids, []);
  assert.ok(Date.now() - started < 1400, 'Close should not wait indefinitely for ignored signals');
});
