import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { quietConsoleListAgent } from '../electron/terminal-process.mjs';

function fakePty(shellPid = 4321) {
  const agent = { _innerPid: shellPid, _getConsoleProcessList: () => Promise.reject(new Error('original agent must not run')) };
  return { pty: { _agent: agent }, agent };
}
function fakeFork(behaviour) {
  const calls = [];
  const fork = (script, args, options) => {
    const child = Object.assign(new EventEmitter(), { stdout: new PassThrough(), stderr: new PassThrough(), killed: false, kill() { this.killed = true; } });
    calls.push({ script, args, options, child });
    queueMicrotask(() => behaviour(child));
    return child;
  };
  return { fork, calls };
}

test('the console list agent runs silently and returns the processes it reports', async () => {
  const { pty, agent } = fakePty();
  const { fork, calls } = fakeFork(child => child.emit('message', { consoleProcessList: [4321, 99] }));
  assert.equal(quietConsoleListAgent(pty, 'C:\\pty\\lib\\conpty_console_list_agent.js', fork), true);
  assert.deepEqual(await agent._getConsoleProcessList(), [4321, 99]);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].args, ['4321']);
  assert.equal(calls[0].options.silent, true, 'its stack traces must not reach the app log');
  assert.equal(calls[0].script, 'C:\\pty\\lib\\conpty_console_list_agent.js');
});

test('an agent that exits without a list (the shell already gone) settles at once with the shell PID', async () => {
  const { pty, agent } = fakePty(777);
  const { fork } = fakeFork(child => { child.stderr.write('Error: AttachConsole failed\n'); child.emit('exit', 1); });
  quietConsoleListAgent(pty, 'agent.js', fork);
  const started = Date.now();
  assert.deepEqual(await agent._getConsoleProcessList(), [777]);
  assert.ok(Date.now() - started < 1000, 'node-pty would otherwise wait five seconds');
});

test('a failed fork or a malformed reply still falls back to the shell PID', async () => {
  const throwing = fakePty(5);
  quietConsoleListAgent(throwing.pty, 'agent.js', () => { throw new Error('spawn failed'); });
  assert.deepEqual(await throwing.agent._getConsoleProcessList(), [5]);
  const malformed = fakePty(6);
  quietConsoleListAgent(malformed.pty, 'agent.js', fakeFork(child => child.emit('message', { consoleProcessList: 'all' })).fork);
  assert.deepEqual(await malformed.agent._getConsoleProcessList(), [6]);
});

test('PTYs without a Windows agent are left untouched', () => {
  assert.equal(quietConsoleListAgent({}, 'agent.js'), false);
  assert.equal(quietConsoleListAgent(null, 'agent.js'), false);
  assert.equal(quietConsoleListAgent({ _agent: {} }, 'agent.js'), false);
});
