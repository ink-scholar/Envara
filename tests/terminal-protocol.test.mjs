import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { TerminalProtocol } from '../electron/terminal-protocol.mjs';
import { TerminalService } from '../electron/terminal-service.mjs';
import { getTerminalTheme } from '../shared/terminal-theme.mjs';

const ESC = '\x1b';
const osc = (code, data = '') => `${ESC}]${code}${data ? `;${data}` : ''}${ESC}\\`;

function protocol(t, options = {}) {
  const replies = [], pressure = [];
  const instance = new TerminalProtocol({ columns: 80, rows: 24, write: data => replies.push(data), onPressure: value => pressure.push(value), ...options });
  t.after(() => instance.dispose());
  return { instance, replies, pressure };
}

test('one PTY protocol answers fragmented live queries without a renderer', async t => {
  const { instance, replies } = protocol(t);
  for (const chunk of ['hello', `${ESC}[`, '6n', `${ESC}]11;`, '?', ESC, '\\']) await instance.write(chunk);
  await instance.write(`${ESC}[5n${ESC}[c${ESC}[>c${ESC}[?6n${ESC}[?25$p${ESC}P$q q${ESC}\\`);
  assert.deepEqual(replies.slice(0, 4), [`${ESC}[1;6R`, osc(11, 'rgb:1919/1919/1c1c'), `${ESC}[0n`, `${ESC}[?1;2c`]);
  assert.ok(replies.includes(`${ESC}[>0;276;0c`));
  assert.ok(replies.includes(`${ESC}[?1;6R`));
  assert.ok(replies.includes(`${ESC}[?25;1$y`));
  assert.ok(replies.includes(`${ESC}P1$r1 q${ESC}\\`), 'cursor blink/style matches the browser terminal');
});

test('color queries preserve indexed/special set and reset operations and follow theme changes', async t => {
  let theme = 'dark';
  const { instance, replies } = protocol(t, { getTheme: () => getTerminalTheme(theme) });
  await instance.write(osc(4, '1;#123456;1;?;255;?') + osc(10, '#abcdef;?;?'));
  assert.deepEqual(replies, [osc('4;1', 'rgb:1212/3434/5656'), osc('4;255', 'rgb:eeee/eeee/eeee'),
    osc(11, 'rgb:1919/1919/1c1c'), osc(12, 'rgb:e2e2/e2e2/e8e8')]);
  replies.length = 0;
  await instance.write(osc(10, '?') + osc(104, '1') + osc(110) + osc(4, '1;?') + osc(10, '?'));
  assert.deepEqual(replies, [osc(10, 'rgb:abab/cdcd/efef'), osc('4;1', 'rgb:eded/7474/7c7c'), osc(10, 'rgb:d8d8/d8d8/dfdf')]);
  await instance.write(osc(11, '#123'));
  replies.length = 0;
  await instance.write(osc(11, '?'));
  assert.deepEqual(replies, [osc(11, 'rgb:1010/2020/3030')], 'XParseColor short hex uses its high nibble');
  theme = 'light'; replies.length = 0;
  await instance.write(osc(11, '?') + osc(4, '1;?'));
  assert.deepEqual(replies, [osc(11, 'rgb:ffff/ffff/ffff'), osc('4;1', 'rgb:a3a3/3232/3e3e')]);
});

test('PTYs keep independent protocol state and colors', async t => {
  const first = protocol(t), second = protocol(t, { getTheme: () => getTerminalTheme('light') });
  await Promise.all([first.instance.write(`first${ESC}[6n${osc(11, '?')}`), second.instance.write(`b${ESC}[6n${osc(11, '?')}`)]);
  assert.deepEqual(first.replies, [`${ESC}[1;6R`, osc(11, 'rgb:1919/1919/1c1c')]);
  assert.deepEqual(second.replies, [`${ESC}[1;2R`, osc(11, 'rgb:ffff/ffff/ffff')]);
});

test('DEC 2026 reports the browser safety timeout without extending it on repeated set operations', async t => {
  let now = 0;
  t.mock.method(performance, 'now', () => now);
  const { instance, replies } = protocol(t);
  const query = `${ESC}[?2026$p`, set = `${ESC}[?2026h`;
  await instance.write(query + set + 'data' + query);
  now = 600;
  await instance.write(set + query);
  now = 1000;
  await instance.write(query);
  now = 1100;
  await instance.write(set + query + `${ESC}[?2026l` + query);
  await instance.write(set + `${ESC}[!p` + query);
  await instance.write(set + `${ESC}c` + query);
  await instance.write(`${ESC}[?25h${ESC}[?25$p`);
  assert.deepEqual(replies, [2, 1, 1, 2, 1, 2, 2, 2].map(value => `${ESC}[?2026;${value}$y`).concat(`${ESC}[?25;1$y`));
});

test('DEC 2026 keeps the browser deadline through a same-write soft reset and re-enable', async t => {
  let now = 0;
  t.mock.method(performance, 'now', () => now);
  const { instance, replies } = protocol(t);
  const query = `${ESC}[?2026$p`, set = `${ESC}[?2026h`, softReset = `${ESC}[!p`;
  await instance.write(set);
  now = 500;
  await instance.write(softReset + set + query);
  now = 1000;
  await instance.write(query);
  now = 1100;
  await instance.write(set);
  now = 1600;
  await instance.write(softReset);
  await instance.write(set + query);
  now = 2100;
  await instance.write(query);
  now = 2600;
  await instance.write(query);
  now = 2700;
  await instance.write(set + `${ESC}[?2026l` + set + query);
  now = 3700;
  await instance.write(query);
  assert.deepEqual(replies, [1, 2, 1, 1, 2, 1, 2].map(value => `${ESC}[?2026;${value}$y`));
});

test('resize waits for earlier output and updates the PTY before subsequent queries', async t => {
  const { instance, replies } = protocol(t);
  const ordering = [];
  const before = instance.write(`${ESC}[24;80H${ESC}[6n`);
  const resizing = instance.resize(100, 30, () => ordering.push([...replies]));
  const after = instance.write(`${ESC}[999;999H${ESC}[6n${ESC}[18t`);
  await Promise.all([before, resizing, after]);
  assert.deepEqual(ordering, [[`${ESC}[24;80R`]]);
  assert.deepEqual(replies, [`${ESC}[24;80R`, `${ESC}[30;100R`, `${ESC}[8;30;100t`]);
  assert.equal(instance.terminal.options.scrollback, 3000);
  await instance.write(`${ESC}[14t${ESC}[16t`);
  assert.equal(replies.length, 3, 'no pixel dimensions are invented for a headless terminal');
});

test('protocol parsing applies independent backpressure and resumes after draining', async t => {
  const { instance, pressure } = protocol(t);
  const writing = instance.write('x'.repeat(160 * 1024));
  assert.equal(pressure[0], true);
  await writing;
  assert.deepEqual(pressure, [true, false]);
  assert.equal(instance.queuedBytes, 0);
});

test('disposal settles queued parser and resize work without writing replies or changing the PTY', async t => {
  const { instance, replies } = protocol(t);
  let resized = false;
  const writing = instance.write(`${ESC}[6n`), resizing = instance.resize(100, 30, () => { resized = true; });
  instance.dispose();
  assert.deepEqual(await Promise.all([writing, resizing]), [false, false]);
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.deepEqual(replies, []); assert.equal(resized, false);
  assert.equal(await instance.write(`${ESC}[6n`), false);
});

test('a native reply-write failure rejects its parse operation instead of escaping an xterm timer', async t => {
  const failure = Object.assign(new Error('owned fixture channel closed'), { code: 'EIO' });
  const { instance } = protocol(t, { write: () => { throw failure; } });
  await assert.rejects(instance.write(`${ESC}[6n`), error => error === failure);
  assert.equal(await instance.flush(), true);
});

class FakePty extends EventEmitter {
  constructor() { super(); this.pid = 123456; this.written = []; this.pauses = 0; this.resumes = 0; }
  onData(listener) { this.on('data', listener); return { dispose: () => this.off('data', listener) }; }
  onExit(listener) { this.on('exit', listener); return { dispose: () => this.off('exit', listener) }; }
  write(data) { this.written.push(data); }
  resize(columns, rows) { this.size = [columns, rows]; }
  pause() { this.pauses++; } resume() { this.resumes++; }
}

async function serviceFixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-protocol-'));
  const cwd = path.join(root, 'project'); await mkdir(cwd);
  const pty = new FakePty(), events = [], diagnostics = [];
  const service = new TerminalService({ dataDir: path.join(root, 'data'), networkFence: null, availableLocales: ['C'],
    resolveContext: async id => ({ id, timezone: 'UTC', proxy: null }), ptyFactory: () => pty,
    processControl: { capture: async pid => ({ pid }), close: async () => { pty.emit('exit', { exitCode: 0 }); return { ok: true }; } },
    onEvent: event => events.push(event), diagnostics: {
      step: async (stage, operation, details) => { diagnostics.push({ stage, ...details }); return operation(); },
      mark: stage => diagnostics.push({ stage }), flush: async () => true,
    } });
  t.after(async () => { await service.shutdown().catch(() => {}); await rm(root, { recursive: true, force: true }); });
  await service.ready; await service.setDirectory({ id: 'profile_fixture', path: cwd });
  const opened = await service.create({ id: 'profile_fixture' });
  return { service, pty, events, diagnostics, session: service.sessions.get(opened.sessionId) };
}

test('service feeds redacted live bytes exactly once; snapshots/replay never respond again', async t => {
  const { service, pty, session } = await serviceFixture(t);
  session.secrets = ['synthetic-password'];
  pty.emit('data', 'synthetic-pa');
  pty.emit('data', `ssword${ESC}[6n${ESC}]11;`);
  pty.emit('data', `?${ESC}`); pty.emit('data', '\\');
  await session.protocol.flush();
  assert.deepEqual(pty.written, [`${ESC}[1;11R`, osc(11, 'rgb:1919/1919/1c1c')]);
  assert.equal(session.protocol.terminal.buffer.active.getLine(0).translateToString(true), '[redacted]');
  const first = await service.snapshot(), second = await service.snapshot({ id: 'profile_fixture' });
  assert.equal(first.profiles[0].sessions[0].replay, second.profiles[0].sessions[0].replay);
  assert.equal(first.profiles[0].sessions[0].replay.includes('synthetic-password'), false);
  assert.equal(pty.written.length, 2);
  await service.resize({ sessionId: session.sessionId, columns: 100, rows: 30 });
  assert.deepEqual(pty.size, [100, 30]);
});

test('the PTY resumes only after both renderer delivery and protocol parsing drain', async t => {
  for (const first of ['renderer', 'protocol']) await t.test(`${first} drains first`, async t => {
    const { service, pty, session } = await serviceFixture(t);
    const callbacks = [];
    session.protocol.terminal.write = (_data, callback) => callbacks.push(callback);
    let releaseOutput;
    const outputGate = new Promise(resolve => { releaseOutput = resolve; });
    service.onEvent = event => event.type === 'data' ? outputGate : undefined;
    try {
      pty.emit('data', 'x'.repeat(160 * 1024));
      assert.equal(session.paused, true); assert.equal(session.protocolPaused, true);
      assert.equal(pty.pauses, 1); assert.equal(pty.resumes, 0);
      if (first === 'renderer') {
        releaseOutput(); await new Promise(resolve => setImmediate(resolve));
        assert.equal(session.paused, false); assert.equal(session.protocolPaused, true);
        assert.equal(pty.resumes, 0, 'protocol backlog must keep the PTY paused');
        callbacks.shift()(); await session.protocol.flush();
      } else {
        callbacks.shift()(); await session.protocol.flush();
        assert.equal(session.paused, true); assert.equal(session.protocolPaused, false);
        assert.equal(pty.resumes, 0, 'renderer backlog must keep the PTY paused');
        releaseOutput(); await new Promise(resolve => setImmediate(resolve));
      }
      assert.equal(session.paused, false); assert.equal(session.protocolPaused, false);
      assert.equal(pty.resumes, 1);
    } finally {
      releaseOutput(); for (const callback of callbacks.splice(0)) callback();
    }
  });
});

test('native close observation records no content and neither changes lifecycle nor installs error listeners', async t => {
  const { service, pty, session, diagnostics } = await serviceFixture(t);
  pty.emit('close');
  assert.equal(session.status, 'running');
  assert.equal(pty.listenerCount('error'), 0);
  assert.ok(diagnostics.some(item => item.stage === 'terminal.pty-close'));
  await service.write({ sessionId: session.sessionId, data: 'owned-input' });
  assert.deepEqual(diagnostics.find(item => item.stage === 'terminal.write'), { stage: 'terminal.write', bytes: 11 });
  const parser = session.protocol;
  await service.close({ sessionId: session.sessionId });
  assert.equal(parser.disposed, true); assert.equal(pty.listenerCount('close'), 0);
  assert.ok(diagnostics.some(item => item.stage === 'terminal.pty-exit'));
  assert.equal(JSON.stringify(diagnostics).includes('owned-input'), false);
});
