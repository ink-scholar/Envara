import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { PassThrough, Readable, Writable } from 'node:stream';
import test from 'node:test';
import { runPasswordSshClient } from '../electron/terminal-ssh-client.mjs';

const encode = frame => `${JSON.stringify(frame)}\n`;
const dataFrame = (type, data) => ({ type, data: Buffer.from(data).toString('base64') });
const failure = 'Envara: SSH connection failed.\n';

function collector({ delay = 0, highWaterMark = 16 * 1024 } = {}) {
  const chunks = [];
  const stream = new Writable({ highWaterMark, write(chunk, encoding, done) {
    chunks.push(Buffer.from(chunk));
    if (delay) setTimeout(done, delay);
    else done();
  } });
  return { stream, bytes: () => Buffer.concat(chunks) };
}

async function broker(t, onFrame) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'es-client-'));
  const socket = path.join(root, 's');
  const frames = [], clients = new Set();
  const server = net.createServer(client => {
    clients.add(client);
    client.on('error', () => {});
    client.once('close', () => clients.delete(client));
    let pending = '';
    client.on('data', chunk => {
      pending += chunk.toString();
      let newline;
      while ((newline = pending.indexOf('\n')) >= 0) {
        const frame = JSON.parse(pending.slice(0, newline));
        pending = pending.slice(newline + 1);
        frames.push(frame);
        onFrame(client, frame);
      }
    });
  });
  server.listen(socket);
  await once(server, 'listening');
  t.after(async () => {
    const closed = new Promise(resolve => server.close(resolve));
    for (const client of clients) client.destroy();
    await closed;
    await rm(root, { recursive: true, force: true });
  });
  return { socket, frames };
}

function options(socket, extra = {}) {
  const out = collector(), err = collector(), signals = new EventEmitter();
  return { out, err, signals, args: { socket, argv: ['envara-123456abcdef', 'printf', 'fixture'],
    input: Readable.from([]), output: out.stream, errorOutput: err.stream, signals, ...extra } };
}

test('forwards exact arguments, binary streams and exit status, and keeps EOF half open', async t => {
  const bytes = Buffer.from([0, 255, 128, 13, 10, 65]);
  const received = [];
  const fixture = await broker(t, (client, frame) => {
    if (frame.type === 'start') {
      assert.equal(fixture.frames.length, 1);
      client.write(encode({ type: 'ready' }));
    }
    if (frame.type === 'stdin') received.push(Buffer.from(frame.data, 'base64'));
    if (frame.type === 'eof') client.end(encode(dataFrame('stdout', bytes))
      + encode(dataFrame('stderr', 'remote diagnostic')) + encode({ type: 'exit', code: 23 }));
  });
  const args = ['envara-123456abcdef', 'printf', 'one two', '中文', '; $()'];
  const state = options(fixture.socket, { argv: args, input: Readable.from([bytes]) });
  assert.equal(await runPasswordSshClient(state.args), 23);
  assert.deepEqual(fixture.frames[0], { type: 'start', version: 1, argv: args, tty: false, cols: 80, rows: 24 });
  assert.deepEqual(Buffer.concat(received), bytes);
  assert.deepEqual(state.out.bytes(), bytes);
  assert.equal(state.err.bytes().toString(), 'remote diagnostic');
  assert.equal(fixture.frames.filter(frame => frame.type === 'eof').length, 1);
  assert.equal(fixture.frames.some(frame => frame.type === 'cancel'), false);
  assert.equal(state.args.output.writableEnded, false);
  assert.equal(state.args.errorOutput.writableEnded, false);
  for (const event of ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGWINCH']) assert.equal(state.signals.listenerCount(event), 0);
});

test('waits for ready before stdin and reconstructs fragmented response frames', async t => {
  let ready = false;
  const fixture = await broker(t, (client, frame) => {
    if (frame.type === 'start') setTimeout(() => {
      ready = true;
      client.write('{"type":"rea');
      setTimeout(() => client.write('dy"}\n'), 5);
    }, 10);
    if (frame.type === 'stdin') assert.equal(ready, true);
    if (frame.type === 'eof') {
      client.write(encode(dataFrame('stdout', 'fragmented response')).slice(0, 15));
      setTimeout(() => client.end(encode(dataFrame('stdout', 'fragmented response')).slice(15)
        + encode({ type: 'exit', code: 0 })), 5);
    }
  });
  const state = options(fixture.socket, { input: Readable.from(['input']) });
  assert.equal(await runPasswordSshClient(state.args), 0);
  assert.equal(state.out.bytes().toString(), 'fragmented response');
});

test('bounds stdin frames and preserves bytes with socket and output backpressure', async t => {
  const chunk = Buffer.alloc(64 * 1024, 0xa5);
  const payload = Buffer.concat(Array.from({ length: 40 }, () => chunk));
  const received = [];
  let drainCount = 0, pauseCount = 0;
  const fixture = await broker(t, (client, frame) => {
    if (frame.type === 'start') {
      client.write(encode({ type: 'ready' }));
      client.pause();
      setTimeout(() => client.resume(), 25);
    }
    if (frame.type === 'stdin') {
      const bytes = Buffer.from(frame.data, 'base64');
      assert.ok(bytes.length <= 48 * 1024);
      assert.equal(bytes.toString('base64'), frame.data);
      received.push(bytes);
    }
    if (frame.type === 'eof') {
      for (let i = 0; i < 40; i++) client.write(encode(dataFrame(i % 2 ? 'stderr' : 'stdout', chunk.subarray(0, 32 * 1024))));
      client.end(encode({ type: 'exit', code: 0 }));
    }
  });
  const out = collector({ delay: 1, highWaterMark: 64 });
  const err = collector({ delay: 1, highWaterMark: 64 });
  const state = options(fixture.socket, { input: Readable.from(Array.from({ length: 40 }, () => chunk)),
    output: out.stream, errorOutput: err.stream, connect: settings => {
      const wire = net.createConnection({ ...settings, writableHighWaterMark: 64 });
      wire.on('drain', () => drainCount++);
      const pause = wire.pause.bind(wire);
      wire.pause = () => { pauseCount++; return pause(); };
      return wire;
    } });
  assert.equal(await runPasswordSshClient(state.args), 0);
  assert.deepEqual(Buffer.concat(received), payload);
  assert.deepEqual(out.bytes(), Buffer.alloc(20 * 32 * 1024, 0xa5));
  assert.deepEqual(err.bytes(), Buffer.alloc(20 * 32 * 1024, 0xa5));
  assert.ok(drainCount > 0);
  assert.ok(pauseCount > 0);
});

test('waits for pending output callbacks before returning a remote exit', async t => {
  let flushed = false;
  const fixture = await broker(t, (client, frame) => {
    if (frame.type === 'start') client.end(encode({ type: 'ready' }) + encode(dataFrame('stdout', 'pending')) + encode({ type: 'exit', code: 7 }));
  });
  const output = new Writable({ write(chunk, encoding, done) {
    setTimeout(() => { flushed = true; done(); }, 20);
  } });
  const state = options(fixture.socket, { output });
  assert.equal(await runPasswordSshClient(state.args), 7);
  assert.equal(flushed, true);
});

test('empty output frames never create unaccounted writable queue entries', async t => {
  let writes = 0;
  const fixture = await broker(t, (client, frame) => {
    if (frame.type === 'start') client.end(encode({ type: 'ready' })
      + encode(dataFrame('stdout', '')).repeat(1000) + encode({ type: 'exit', code: 0 }));
  });
  const output = new Writable({ write() { writes++; } });
  const state = options(fixture.socket, { output });
  assert.equal(await runPasswordSshClient(state.args), 0);
  assert.equal(writes, 0);
});

function terminalInput(raw = false) {
  const input = new PassThrough();
  input.isTTY = true;
  input.isRaw = raw;
  input.rawModes = [];
  input.setRawMode = value => { input.isRaw = value; input.rawModes.push(value); return input; };
  return input;
}

for (const originalRaw of [false, true]) {
  test(`restores original raw mode ${originalRaw} and forwards resize and signals`, async t => {
    const input = terminalInput(originalRaw);
    const state = options(null, { tty: true, input, cols: 90, rows: 30 });
    state.out.stream.columns = 132;
    state.out.stream.rows = 45;
    const fixture = await broker(t, (client, frame) => {
      if (frame.type === 'start') {
        assert.equal(frame.tty, true);
        client.write(encode({ type: 'ready' }));
        setTimeout(() => {
          assert.equal(input.isRaw, true);
          state.signals.emit('SIGWINCH');
          state.signals.emit('SIGINT');
          state.signals.emit('SIGHUP');
          state.signals.emit('SIGTERM');
        }, 10);
      }
      if (frame.type === 'signal' && frame.signal === 'SIGTERM') client.end(encode({ type: 'exit', code: 143, signal: 'SIGTERM' }));
    });
    state.args.socket = fixture.socket;
    assert.equal(await runPasswordSshClient(state.args), 143);
    assert.deepEqual(input.rawModes, [true, originalRaw]);
    assert.equal(input.isRaw, originalRaw);
    assert.deepEqual(fixture.frames.find(frame => frame.type === 'resize'), { type: 'resize', cols: 132, rows: 45 });
    assert.deepEqual(fixture.frames.filter(frame => frame.type === 'signal').map(frame => frame.signal), ['SIGINT', 'SIGHUP', 'SIGTERM']);
    assert.equal(input.listenerCount('data'), 0);
    assert.equal(input.listenerCount('error'), 0);
  });
}

test('does not change raw mode for a non-TTY invocation', async t => {
  const input = terminalInput();
  const fixture = await broker(t, (client, frame) => {
    if (frame.type === 'start') client.end(encode({ type: 'ready' }) + encode({ type: 'exit', code: 0 }));
  });
  const state = options(fixture.socket, { input, tty: false });
  assert.equal(await runPasswordSshClient(state.args), 0);
  assert.deepEqual(input.rawModes, []);
});

const invalidFrames = [
  ['output before ready', encode(dataFrame('stdout', 'forbidden'))],
  ['exit before ready', encode({ type: 'exit', code: 0 })],
  ['unknown frame', encode({ type: 'ready' }) + encode({ type: 'password', value: 'private' })],
  ['duplicate ready', encode({ type: 'ready' }) + encode({ type: 'ready' })],
  ['unknown property', encode({ type: 'ready', password: 'private' })],
  ['noncanonical base64 bits', encode({ type: 'ready' }) + encode({ type: 'stdout', data: 'Zh==' })],
  ['unpadded base64', encode({ type: 'ready' }) + encode({ type: 'stdout', data: 'Zg' })],
  ['base64 whitespace', encode({ type: 'ready' }) + encode({ type: 'stdout', data: 'Zg==\n' })],
  ['oversized data', encode({ type: 'ready' }) + encode(dataFrame('stdout', Buffer.alloc(48 * 1024 + 1)))],
  ['invalid exit', encode({ type: 'ready' }) + encode({ type: 'exit', code: 256 })],
  ['invalid exit signal', encode({ type: 'ready' }) + encode({ type: 'exit', code: 0, signal: 'private detail' })],
  ['trailing frame', encode({ type: 'ready' }) + encode({ type: 'exit', code: 0 }) + encode({ type: 'ready' })],
  ['partial EOF', '{"type":"ready"'],
  ['empty line', '\n'],
  ['invalid JSON', 'private internal error\n'],
  ['oversized line', ' '.repeat(128 * 1024) + '\n'],
  ['server error', encode({ type: 'error', code: 'SSH_AUTHORIZATION_EXPIRED' })],
  ['unsafe server error', encode({ type: 'error', code: 'private /path password' })],
];
for (const [name, payload] of invalidFrames) {
  test(`fails closed on ${name} without displaying protocol content`, async t => {
    const fixture = await broker(t, (client, frame) => {
      if (frame.type === 'start') client.end(payload);
    });
    const state = options(fixture.socket);
    assert.equal(await runPasswordSshClient(state.args), 255);
    assert.equal(state.out.bytes().length, 0);
    assert.equal(state.err.bytes().toString(), failure);
  });
}

test('input failure cancels the owned socket and restores raw mode', async t => {
  const input = terminalInput();
  let closed = false;
  const fixture = await broker(t, (client, frame) => {
    if (frame.type === 'start') {
      client.once('close', () => { closed = true; });
      client.write(encode({ type: 'ready' }));
      setTimeout(() => input.emit('error', new Error('private input detail')), 10);
    }
  });
  const state = options(fixture.socket, { input, tty: true });
  assert.equal(await runPasswordSshClient(state.args), 255);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(input.isRaw, false);
  assert.equal(state.err.bytes().toString(), failure);
  assert.ok(closed || fixture.frames.some(frame => frame.type === 'cancel'));
});

test('output write failure closes the socket and restores raw mode without leaking stream errors', async t => {
  const input = terminalInput();
  const fixture = await broker(t, (client, frame) => {
    if (frame.type === 'start') client.write(encode({ type: 'ready' }) + encode(dataFrame('stdout', 'fixture')));
  });
  const output = new Writable({ write(chunk, encoding, done) {
    setImmediate(() => done(new Error('private output error')));
  }, destroy(error, done) { setTimeout(() => done(error), 15); } });
  const state = options(fixture.socket, { input, output, tty: true });
  assert.equal(await runPasswordSshClient(state.args), 255);
  await new Promise(resolve => output.once('close', resolve));
  assert.equal(input.isRaw, false);
  assert.equal(state.err.bytes().toString(), failure);
  assert.equal(output.listenerCount('error'), 0);
});

test('retains error protection for pending writes after a peer error', async t => {
  const fixture = await broker(t, (client, frame) => {
    if (frame.type === 'start') client.write(encode({ type: 'ready' })
      + encode(dataFrame('stdout', 'fixture')) + encode({ type: 'error', code: 'SSH_BROKER_UNAVAILABLE' }));
  });
  let writeCompleted;
  const completed = new Promise(resolve => { writeCompleted = resolve; });
  const output = new Writable({ write(chunk, encoding, done) {
    setTimeout(() => { done(new Error('private pending error')); writeCompleted(); }, 10);
  }, destroy(error, done) { setTimeout(() => done(error), 15); } });
  const state = options(fixture.socket, { output });
  assert.equal(await runPasswordSshClient(state.args), 255);
  await completed;
  await new Promise(resolve => output.once('close', resolve));
  assert.equal(state.err.bytes().toString(), failure);
  assert.equal(output.listenerCount('error'), 0);
});

test('a failed diagnostic write does not cause an uncaught stderr error', async t => {
  const fixture = await broker(t, (client, frame) => {
    if (frame.type === 'start') client.end(encode({ type: 'error', code: 'SSH_BROKER_UNAVAILABLE' }));
  });
  const errorOutput = new Writable({ write(chunk, encoding, done) {
    setImmediate(() => done(new Error('private stderr error')));
  }, destroy(error, done) { setTimeout(() => done(error), 15); } });
  const state = options(fixture.socket, { errorOutput });
  assert.equal(await runPasswordSshClient(state.args), 255);
  await new Promise(resolve => errorOutput.once('close', resolve));
  assert.equal(errorOutput.listenerCount('error'), 0);
});

test('rejects an excessive buffered input chunk and closes instead of sending unbounded frames', async t => {
  const fixture = await broker(t, (client, frame) => {
    if (frame.type === 'start') client.write(encode({ type: 'ready' }));
  });
  const state = options(fixture.socket, { input: Readable.from([Buffer.alloc(1024 * 1024 + 1)]) });
  assert.equal(await runPasswordSshClient(state.args), 255);
  assert.equal(state.err.bytes().toString(), failure);
  assert.equal(fixture.frames.some(frame => frame.type === 'stdin'), false);
});

test('sanitizes connection failures and rejects malformed invocation before connecting', async () => {
  for (const extra of [{ socket: 'relative' }, { socket: 'http://fixture.invalid' }, { argv: [null] },
    { argv: ['a\0b'] }, { argv: [] }, { cols: 0 }, { rows: 1001 }, { tty: 'yes' }]) {
    let contacted = false;
    const state = options('/tmp/owned-fixture.sock', { ...extra, connect: () => { contacted = true; throw new Error('private error'); } });
    assert.equal(await runPasswordSshClient(state.args), 255);
    assert.equal(contacted, false);
    assert.equal(state.err.bytes().toString(), failure);
  }
  const state = options('/tmp/owned-fixture.sock', { connect: () => { throw new Error('private error /path'); } });
  assert.equal(await runPasswordSshClient(state.args), 255);
  assert.equal(state.err.bytes().toString(), failure);
});

test('setup deadline is 15 seconds and does not remain active after ready', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const makeWire = () => {
    const wire = new PassThrough();
    wire.write = () => true;
    return wire;
  };
  const waitingWire = makeWire();
  const waiting = options('/tmp/owned-fixture.sock', { connect: () => waitingWire });
  const timeout = runPasswordSshClient(waiting.args);
  waitingWire.emit('connect');
  t.mock.timers.tick(14_999);
  assert.equal(waitingWire.destroyed, false);
  t.mock.timers.tick(1);
  assert.equal(await timeout, 255);
  assert.equal(waitingWire.destroyed, true);

  const activeWire = makeWire();
  const active = options('/tmp/owned-fixture.sock', { input: new PassThrough(), connect: () => activeWire });
  const running = runPasswordSshClient(active.args);
  activeWire.emit('connect');
  activeWire.emit('data', Buffer.from(encode({ type: 'ready' })));
  t.mock.timers.tick(24 * 60 * 60 * 1000);
  assert.equal(activeWire.destroyed, false);
  activeWire.emit('data', Buffer.from(encode({ type: 'exit', code: 0 })));
  assert.equal(await running, 0);
});
