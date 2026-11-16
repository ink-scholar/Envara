import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { EventEmitter } from 'node:events';
import { mkdtemp, mkdir, readFile, readdir, realpath, rm, writeFile, symlink, stat } from 'node:fs/promises';
import { TerminalAttachments, quoteTerminalAttachmentPath } from '../electron/terminal-attachments.mjs';

const transferId = 'a'.repeat(32), sessionId = `term_${'b'.repeat(32)}`;
async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-attachments-test-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const profilesDir = path.join(root, 'profiles');
  await mkdir(profilesDir); await mkdir(path.join(profilesDir, 'owned'));
  const session = { sessionId, profileId: 'owned', kind: 'shell', status: 'running', pty: { process: 'zsh' }, abortController: new AbortController() };
  const owner = Object.assign(new EventEmitter(), { isDestroyed: () => false });
  const writes = [];
  const terminal = { profilesDir, ready: Promise.resolve(), write: async value => { writes.push(value); return { accepted: true }; }, session: id => { assert.equal(id, sessionId); return session; } };
  return { root, profilesDir, session, terminal, writes, owner, context: { window: owner }, manager: new TerminalAttachments({ terminal }),
    request: { sessionId, transferId, files: [{ name: 'shot.png', bytes: new Uint8Array([1, 2, 3]) }] } };
}
async function savedFiles(f) {
  const root = path.join(f.profilesDir, 'owned', 'attachments');
  return await readdir(root).catch(() => []);
}

test('attachments are private owned copies in the actual session environment and never write input', async t => {
  const f = await fixture(t);
  const result = await f.manager.stage(f.request, f.context);
  assert.equal(result.count, 1); assert.equal(result.transferId, transferId);
  assert.match(result.quotedPaths, /\/owned\/attachments\/batch-.*\/1-shot\.png' $/);
  assert.equal(/[\r\n]/.test(result.quotedPaths), false);
  const target = result.quotedPaths.slice(1, -2);
  assert.deepEqual([...await readFile(target)], [1, 2, 3]);
  if (process.platform !== 'win32') assert.equal((await stat(target)).mode & 0o777, 0o600);
  assert.deepEqual(f.writes, []);
  await f.manager.finish({ sessionId, transferId, accepted: true }, f.context);
  assert.deepEqual(f.writes, [{ sessionId, data: result.quotedPaths }]);
  assert.equal(f.manager.transfers.size, 0); assert.equal((await savedFiles(f)).length, 1);
});

test('real selected files are copied and names cannot escape the environment or inject shell input', async t => {
  const f = await fixture(t);
  const source = path.join(f.root, 'selected.txt'); await writeFile(source, 'owned source');
  const result = await f.manager.stage({ ...f.request, files: [{ name: "odd ' $(command).txt", path: source }] }, f.context);
  const files = await savedFiles(f); const names = await readdir(path.join(f.profilesDir, 'owned', 'attachments', files[0]));
  assert.deepEqual(names, ['1-odd _ _(command).txt']);
  assert.match(result.quotedPaths, /^'/); assert.equal(result.quotedPaths.includes('$('), false);
  await f.manager.finish({ sessionId, transferId, accepted: false }, f.context);
  assert.deepEqual(await savedFiles(f), []); assert.equal(await readFile(source, 'utf8'), 'owned source');
});

test('source symlinks, linked ancestors, folders and unsafe names are rejected with owned rollback', async t => {
  const f = await fixture(t); const source = path.join(f.root, 'source'); await writeFile(source, 'safe');
  await symlink(source, path.join(f.root, 'link'));
  await mkdir(path.join(f.root, 'real')); await writeFile(path.join(f.root, 'real', 'file'), 'safe');
  await symlink(path.join(f.root, 'real'), path.join(f.root, 'linked-parent'));
  for (const files of [[{ name: 'file', path: path.join(f.root, 'link') }], [{ name: 'file', path: path.join(f.root, 'linked-parent', 'file') }], [{ name: 'file', path: f.root }], [{ name: '../escape', bytes: new Uint8Array() }], [{ name: 'line\nfeed', bytes: new Uint8Array() }]]) {
    await assert.rejects(f.manager.stage({ ...f.request, files }, f.context), error => ['TERMINAL_ATTACHMENT_UNSAFE', 'TERMINAL_ATTACHMENT_INVALID'].includes(error.code));
    assert.deepEqual(await savedFiles(f), []);
  }
});

test('a linked destination is refused without touching its external target', async t => {
  const f = await fixture(t); const external = path.join(f.root, 'external'); await mkdir(external);
  await symlink(external, path.join(f.profilesDir, 'owned', 'attachments'));
  await assert.rejects(f.manager.stage(f.request, f.context), { code: 'TERMINAL_ATTACHMENT_UNSAFE' });
  assert.deepEqual(await readdir(external), []);
});

test('count, individual bytes, accumulated bytes and duplicate transfers are bounded', async t => {
  const f = await fixture(t);
  await assert.rejects(f.manager.stage({ ...f.request, files: Array(9).fill(f.request.files[0]) }, f.context), { code: 'TERMINAL_ATTACHMENT_LIMIT' });
  await assert.rejects(f.manager.stage({ ...f.request, files: [{ name: 'large', bytes: new Uint8Array(20 * 1024 * 1024 + 1) }] }, f.context), { code: 'TERMINAL_ATTACHMENT_LIMIT' });
  await assert.rejects(f.manager.stage({ ...f.request, files: Array.from({ length: 3 }, (_, i) => ({ name: String(i), bytes: new Uint8Array(18 * 1024 * 1024) })) }, f.context), { code: 'TERMINAL_ATTACHMENT_LIMIT' });
  assert.deepEqual(await savedFiles(f), []);
  await f.manager.stage(f.request, f.context);
  await assert.rejects(f.manager.stage(f.request, f.context), { code: 'TERMINAL_ATTACHMENT_BUSY' });
});

test('cancellation before delayed IPC arrival prevents all staging and window/session ownership is enforced', async t => {
  const f = await fixture(t);
  await f.manager.finish({ sessionId, transferId }, f.context);
  await assert.rejects(f.manager.finish({ sessionId, transferId, accepted: true }, f.context), { code: 'TERMINAL_ATTACHMENT_CANCELLED' });
  await assert.rejects(f.manager.stage(f.request, f.context), { code: 'TERMINAL_ATTACHMENT_CANCELLED' });
  assert.deepEqual(await savedFiles(f), []);
  const another = 'c'.repeat(32); await f.manager.stage({ ...f.request, transferId: another }, f.context);
  await assert.rejects(f.manager.finish({ sessionId, transferId: another, accepted: true }, { window: {} }), { code: 'TERMINAL_ATTACHMENT_INVALID' });
  await assert.rejects(f.manager.finish({ sessionId: 'wrong', transferId: another }, f.context), { code: 'TERMINAL_ATTACHMENT_INVALID' });
});

test('closing the owner or stopping its session removes only its unaccepted batch', async t => {
  for (const close of ['window', 'session']) {
    const f = await fixture(t); await f.manager.stage(f.request, f.context);
    if (close === 'window') f.owner.emit('closed'); else f.session.abortController.abort();
    for (let i = 0; i < 50 && f.manager.transfers.size; i++) await new Promise(resolve => setTimeout(resolve, 2));
    assert.equal(f.manager.transfers.size, 0); assert.deepEqual(await savedFiles(f), []);
  }
});

test('SSH and unknown foreground programs never receive a misleading local file reference', async t => {
  const f = await fixture(t);
  for (const foreground of ['ssh', 'mosh-client', 'scp', 'node', '']) {
    f.session.pty.process = foreground;
    await assert.rejects(f.manager.stage(f.request, f.context), { code: ['ssh', 'mosh-client', 'scp'].includes(foreground) ? 'TERMINAL_ATTACHMENT_REMOTE' : 'TERMINAL_ATTACHMENT_UNSUPPORTED' });
  }
  assert.deepEqual(await savedFiles(f), []);
});

test('shell path quoting protects spaces and metacharacters without adding a command terminator', () => {
  assert.equal(quoteTerminalAttachmentPath("/owned/a'b $HOME `x`"), "'/owned/a'\\''b $HOME `x`'");
  assert.equal(quoteTerminalAttachmentPath("C:\\owned\\a'b", 'powershell'), "'C:\\owned\\a''b'");
  assert.throws(() => quoteTerminalAttachmentPath('/owned/a\nb'), { code: 'TERMINAL_ATTACHMENT_UNSAFE' });
});

test('commit rechecks foreground before input and preserves files once a write may have occurred', async t => {
  const f = await fixture(t);
  await f.manager.stage(f.request, f.context); f.session.pty.process = 'ssh';
  await assert.rejects(f.manager.finish({ sessionId, transferId, accepted: true }, f.context), { code: 'TERMINAL_ATTACHMENT_REMOTE' });
  assert.deepEqual(f.writes, []); f.session.pty.process = 'zsh';
  let release;
  f.terminal.write = value => { f.writes.push(value); return new Promise(resolve => { release = resolve; }); };
  const pending = f.manager.finish({ sessionId, transferId, accepted: true, bracketedPaste: true }, f.context);
  assert.equal(f.writes.length, 1); assert.match(f.writes[0].data, /^\x1b\[200~'.*' \x1b\[201~$/);
  await f.manager.finish({ sessionId, transferId }, f.context); f.owner.emit('closed');
  assert.equal((await savedFiles(f)).length, 1);
  release({ accepted: true }); await pending;
  assert.equal((await savedFiles(f)).length, 1);
});

test('a failed write acknowledgement retains the referenced file and reports an input failure', async t => {
  const f = await fixture(t); await f.manager.stage(f.request, f.context);
  f.terminal.write = async () => { throw new Error('private PTY details'); };
  await assert.rejects(f.manager.finish({ sessionId, transferId, accepted: true }, f.context), { code: 'TERMINAL_ATTACHMENT_INPUT', message: '附件已保存，但无法确认路径是否已插入终端。' });
  await f.manager.finish({ sessionId, transferId }, f.context);
  assert.equal((await savedFiles(f)).length, 1);
});
