import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { TerminalLinkChannel } from '../electron/terminal-link-channel.mjs';

async function bounded(operation, message) {
  let timer;
  try {
    return await Promise.race([operation, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), 1000);
    })]);
  } finally { clearTimeout(timer); }
}

test('closing a link channel revokes it and closes a connection whose opener is still pending', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-link-close-'));
  let entered;
  const handling = new Promise(resolve => { entered = resolve; });
  const channel = new TerminalLinkChannel({ root, onLink: () => {
    entered();
    return new Promise(() => {});
  } });
  await channel.listen();
  const socketPath = channel.socketPath;
  const token = channel.token('prof_owned');
  const client = net.createConnection(socketPath);
  client.on('error', () => {});
  let closing;
  t.after(async () => { client.destroy(); await (closing ?? channel.close()); await rm(root, { recursive: true, force: true }); });
  await new Promise(resolve => client.once('connect', resolve));
  const body = JSON.stringify({ url: 'https://example.test/owned-fixture' });
  client.write(`POST /link HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ${token}\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
  await bounded(handling, 'the owned fixture request did not reach its opener');

  closing = Promise.all([channel.close(), channel.close()]);
  try { await bounded(closing, 'channel close waited for an opener that never completed'); }
  finally { client.destroy(); await closing; }
  assert.equal(channel.tokens.size, 0);
  await assert.rejects(stat(socketPath), { code: 'ENOENT' });
});

test('a closed link channel cannot issue new credentials or be reopened', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-link-ended-'));
  const channel = new TerminalLinkChannel({ root, onLink: async () => ({ opened: 'environment' }) });
  t.after(async () => { await channel.close(); await rm(root, { recursive: true, force: true }); });
  await channel.listen();
  channel.environment('prof_owned');
  await channel.close();
  assert.equal(channel.socketPath, null);
  assert.throws(() => channel.environment('prof_owned'), { code: 'LINK_CHANNEL_UNAVAILABLE' });
  assert.throws(() => channel.token('prof_owned'), { code: 'LINK_CHANNEL_UNAVAILABLE' });
  await assert.rejects(channel.executableDirectory('prof_owned'), { code: 'LINK_CHANNEL_UNAVAILABLE' });
  await assert.rejects(channel.listen(), { code: 'LINK_CHANNEL_UNAVAILABLE' });
  assert.equal(channel.tokens.size, 0);
});

test('closing during socket setup cannot leave a late listener behind', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-link-setup-'));
  const channel = new TerminalLinkChannel({ root, onLink: async () => ({ opened: 'environment' }) });
  t.after(async () => { await channel.close(); await rm(root, { recursive: true, force: true }); });
  const listening = channel.listen();
  await channel.close();
  await assert.rejects(listening, { code: 'LINK_CHANNEL_UNAVAILABLE' });
  assert.equal(channel.server, null);
  assert.equal(channel.socketPath, null);
  await assert.rejects(stat(path.join(root, 'link', 'link.sock')), { code: 'ENOENT' });
});
