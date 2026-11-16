import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { chmod, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { TerminalEntryStore } from '../electron/terminal-entry-store.mjs';
import { WorkCombinations, workCombinationEntryHash } from '../electron/work-combinations.mjs';

const secret = 'SYNTHETIC_SECRET_DO_NOT_RETURN';
async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-work-combinations-')));
  await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  const entries = new TerminalEntryStore({ root }); await entries.ready;
  const profiles = new Map([['environment_a', { id: 'environment_a', engine: 'cloakbrowser', proxyId: 'proxy_a' }],
    ['environment_b', { id: 'environment_b', engine: 'camoufox', proxyId: 'proxy_b' }]]);
  const records = [], checks = [], accounts = new Set(['default']), reservations = new Set();
  let nextSession = 0;
  const terminal = { ready: Promise.resolve(), savedTerminal: (id, entryId) => entries.get(id, entryId),
    claudeAccounts: { get: async (id, accountId) => { if (!accounts.has(accountId)) throw new Error(secret); return { id: accountId }; } },
    resolveContext: async id => ({ id, proxyId: profiles.get(id)?.proxyId }),
    validateSavedTerminalContext: async (entry, context) => {
      checks.push(entry.id); if (entry.networkRef.proxyId !== context.proxyId) throw new Error(secret);
    },
    reserveSavedTerminalStart: async ({ id, entryId }) => { const key = `${id}:${entryId}`; reservations.add(key); return () => reservations.delete(key); },
    openSavedTerminalFresh: async args => { records.push({ kind: 'terminal', args }); return { profileId: args.id, sessionId: `session_${++nextSession}` }; },
  };
  const options = { root, terminal, getProfile: async id => profiles.get(id), ensureBrowser: async id => { records.push({ kind: 'browser', id }); } };
  const create = async () => { const combinations = new WorkCombinations(options); await combinations.ready; return combinations; };
  const combinations = await create();
  const add = async (name, patch = {}) => {
    const cwd = path.join(root, name); await mkdir(cwd);
    return entries.upsert({ profileId: 'environment_a', name, kind: 'shell', cwd, browserProfileId: 'environment_a', claudeAccountId: null,
      networkRef: { kind: 'managed', proxyId: 'proxy_a' }, ...patch });
  };
  return { root, entries, profiles, records, checks, accounts, reservations, terminal, combinations, create, add,
    save: async (selected, includeBrowser = false) => (await combinations.save({ id: 'environment_a', name: 'Synthetic work', entryIds: selected.map(entry => entry.id), includeBrowser })).combination,
    open: (combination, requestId = 'request_one') => combinations.open({ id: 'environment_a', combinationId: combination.id, requestId }),
  };
}
const code = value => error => { assert.equal(error.code, value); assert.equal(error.message.includes(secret), false); return true; };

test('work combinations persist only saved references and context hashes and retain names through terminal pinning and renaming', async t => {
  const f = await fixture(t), first = await f.add('first'), second = await f.add('second');
  const combo = await f.save([second, first], true);
  assert.deepEqual(combo.entryIds, [second.id, first.id]); assert.equal(combo.includeBrowser, true);
  const bytes = await readFile(path.join(f.root, 'work-combinations.json'), 'utf8');
  for (const value of [f.root, 'cwd', 'password', 'command', 'pid', 'proxy_a', 'sessionId']) assert.equal(bytes.includes(value), false, value);
  assert.deepEqual(await (await f.create()).list({ id: 'environment_a' }), { combinations: [combo] });
  assert.deepEqual(await f.combinations.list({ id: 'environment_b' }), { combinations: [] });
  await f.entries.rename('environment_a', first.id, 'Renamed terminal'); await f.entries.setPinned('environment_a', first.id, true);
  assert.equal(workCombinationEntryHash(await f.entries.get('environment_a', first.id)), workCombinationEntryHash(first));
  const opened = await f.open(combo);
  assert.equal(opened.status, 'opened'); assert.equal(opened.browserOpened, true); assert.equal(opened.sessions.length, 2);
  assert.deepEqual(f.checks, [second.id, first.id], 'all entries are checked before the first launch');
  assert.deepEqual(f.records.map(record => record.kind), ['browser', 'terminal', 'terminal']);
  assert.deepEqual(f.records.filter(record => record.kind === 'terminal').map(record => Object.keys(record.args).sort()),
    [['entryId', 'id', 'requestId'], ['entryId', 'id', 'requestId']], 'no path, command or prior session is sent to fresh launch');
  assert.equal(f.reservations.size, 0);
});

test('work combination validation rejects renderer paths, duplicate IDs and cross-environment references', async t => {
  const f = await fixture(t), entry = await f.add('selected'), combo = await f.save([entry]);
  const base = { id: 'environment_a', name: 'New work', entryIds: [entry.id], includeBrowser: false };
  for (const patch of [{ cwd: f.root }, { entryIds: [entry.id, entry.id] }, { entryIds: [] }, { entryIds: ['../outside'] },
    { name: '' }, { name: `${secret}\n` }, { includeBrowser: 'true' }, { browserProfileId: 'environment_b' }, { id: '../outside' }])
    await assert.rejects(async () => f.combinations.save({ ...base, ...patch }), error => { assert.ok(['WORK_COMBINATION_INVALID', 'TERMINAL_ENTRY_INVALID'].includes(error.code)); return true; });
  await assert.rejects(f.combinations.save({ ...base, id: 'environment_b' }), code('WORK_COMBINATION_ENTRY_UNAVAILABLE'));
  await assert.rejects(f.combinations.remove({ id: 'environment_b', combinationId: combo.id }), code('WORK_COMBINATION_NOT_FOUND'));
  const rejected = await f.combinations.open({ id: 'environment_b', combinationId: combo.id, requestId: 'foreign' });
  assert.equal(rejected.error.code, 'WORK_COMBINATION_NOT_FOUND'); assert.deepEqual(f.records, []);
  assert.deepEqual(await f.combinations.list({ id: 'environment_a' }), { combinations: [combo] });
});

test('every saved entry is preflighted before any browser or terminal starts', async t => {
  for (const mode of ['missing', 'directory', 'account', 'route', 'entry-context', 'browser-context']) await t.test(mode, async t => {
    const f = await fixture(t), first = await f.add('first'), second = await f.add('second', mode === 'account'
      ? { kind: 'claude-code', claudeAccountId: 'default' } : {});
    const combo = await f.save([first, second], true);
    if (mode === 'missing') await f.entries.remove('environment_a', second.id);
    if (mode === 'directory') await rm(second.cwd, { recursive: true });
    if (mode === 'account') f.accounts.clear();
    if (mode === 'route') f.terminal.validateSavedTerminalContext = async entry => { if (entry.id === second.id) throw new Error(secret); };
    if (mode === 'entry-context') f.entries.entries.get(second.id).browserProfileId = 'system';
    if (mode === 'browser-context') f.profiles.get('environment_a').engine = 'camoufox';
    const result = await f.open(combo);
    assert.equal(result.status, 'failed'); assert.deepEqual(result.sessions, []); assert.equal(result.browserOpened, false);
    assert.equal(JSON.stringify(result).includes(secret), false); assert.deepEqual(f.records, []); assert.equal(f.reservations.size, 0);
  });
});

test('partial failures preserve opened sessions and repeated or concurrent requests cannot duplicate a launch', async t => {
  const f = await fixture(t), a = await f.add('a'), b = await f.add('b'), c = await f.add('c'), combo = await f.save([a, b, c]);
  let attempts = 0;
  f.terminal.openSavedTerminalFresh = async args => {
    attempts++; if (attempts === 2) throw new Error(secret);
    f.records.push({ kind: 'terminal', args }); return { profileId: args.id, sessionId: `session_${attempts}` };
  };
  const [first, duplicate] = await Promise.all([f.open(combo), f.open(combo)]);
  assert.deepEqual(first, duplicate); assert.equal(first.status, 'partial'); assert.equal(first.sessions.length, 1); assert.equal(attempts, 2);
  assert.equal(first.error.code, 'WORK_COMBINATION_OPEN_FAILED'); assert.equal(JSON.stringify(first).includes(secret), false);
  first.sessions.length = 0;
  assert.equal((await f.open(combo)).sessions.length, 1); assert.equal(attempts, 2); assert.equal(f.reservations.size, 0);
  await assert.rejects(async () => f.combinations.open({ id: 'environment_b', combinationId: combo.id, requestId: 'request_one' }), code('WORK_COMBINATION_INVALID'));
});

test('a changed later entry is refused even when it changes after the complete preflight', async t => {
  const f = await fixture(t), a = await f.add('a'), b = await f.add('b'), combo = await f.save([a, b]);
  const launch = f.terminal.openSavedTerminalFresh;
  f.terminal.openSavedTerminalFresh = async args => {
    const result = await launch(args); f.entries.entries.get(b.id).networkRef.proxyId = 'changed_proxy'; return result;
  };
  const result = await f.open(combo);
  assert.equal(result.status, 'partial'); assert.equal(result.sessions.length, 1); assert.equal(result.error.code, 'WORK_COMBINATION_CONTEXT_CHANGED');
  assert.equal(f.records.length, 1);
});

test('deleting a combination preserves terminal definitions and files; failed writes keep committed state', async t => {
  const f = await fixture(t), entry = await f.add('account-data'), combo = await f.save([entry]);
  const marker = path.join(entry.cwd, 'sign-in'); await writeFile(marker, secret);
  const filename = path.join(f.root, 'work-combinations.json'), before = await readFile(filename, 'utf8'), persist = f.combinations.persist;
  f.combinations.persist = async () => { throw Object.assign(new Error('fixture failure'), { code: 'EIO' }); };
  await assert.rejects(f.combinations.remove({ id: 'environment_a', combinationId: combo.id }), { code: 'EIO' });
  await assert.rejects(f.save([entry]), { code: 'EIO' });
  assert.equal(await readFile(filename, 'utf8'), before); assert.deepEqual(await f.combinations.list({ id: 'environment_a' }), { combinations: [combo] });
  f.combinations.persist = persist;
  assert.deepEqual(await f.combinations.remove({ id: 'environment_a', combinationId: combo.id }), { removed: true });
  assert.equal(await readFile(marker, 'utf8'), secret); assert.deepEqual(await f.entries.get('environment_a', entry.id), entry);
  assert.deepEqual(await (await f.create()).list({ id: 'environment_a' }), { combinations: [] });
  assert.equal((await readdir(f.root)).some(name => name.endsWith('.tmp')), false);
});

test('deleted-environment cleanup removes only its combination metadata and persists without looking up the profile', async t => {
  const f = await fixture(t), a = await f.add('a'), b = await f.add('b', { profileId: 'environment_b',
    browserProfileId: 'environment_b', networkRef: { kind: 'managed', proxyId: 'proxy_b' } });
  await f.save([a]); await f.save([a], true);
  const other = (await f.combinations.save({ id: 'environment_b', name: 'Keep B', entryIds: [b.id], includeBrowser: true })).combination;
  const accountDir = path.join(f.root, 'accounts', 'environment_a', 'default'); await mkdir(accountDir, { recursive: true });
  const accountMarker = path.join(accountDir, 'sign-in'), terminalMarker = path.join(a.cwd, 'history');
  await writeFile(accountMarker, secret); await writeFile(terminalMarker, 'synthetic shell history');
  const entriesBefore = await f.entries.list('environment_a');
  f.profiles.delete('environment_a');
  f.combinations.getProfile = async () => assert.fail('cleanup must not query an already deleted profile');
  assert.deepEqual(await f.combinations.removeProfile('environment_a'), { removed: 2 });
  assert.deepEqual(await f.combinations.list({ id: 'environment_a' }), { combinations: [] });
  const reloaded = await f.create();
  assert.deepEqual(await reloaded.list({ id: 'environment_a' }), { combinations: [] });
  assert.deepEqual(await reloaded.list({ id: 'environment_b' }), { combinations: [other] });
  assert.deepEqual(await f.entries.list('environment_a'), entriesBefore);
  assert.deepEqual(await f.entries.get('environment_b', b.id), b);
  assert.equal(await readFile(accountMarker, 'utf8'), secret);
  assert.equal(await readFile(terminalMarker, 'utf8'), 'synthetic shell history');
  f.combinations.persist = async () => assert.fail('absent metadata needs no write');
  assert.deepEqual(await f.combinations.removeProfile('environment_a'), { removed: 0 });
  assert.deepEqual(f.records, []);
});

test('environment combination cleanup validates IDs and retains committed state after write or initialization failure', async t => {
  const f = await fixture(t), entry = await f.add('entry'), combination = await f.save([entry]);
  const filename = path.join(f.root, 'work-combinations.json'), before = await readFile(filename, 'utf8');
  for (const invalidId of [null, {}, '', '../outside', 'a'.repeat(97)])
    assert.throws(() => f.combinations.removeProfile(invalidId), code('WORK_COMBINATION_INVALID'));
  const persist = f.combinations.persist;
  f.combinations.persist = async () => { throw Object.assign(new Error('synthetic write failure'), { code: 'EIO' }); };
  await assert.rejects(f.combinations.removeProfile('environment_a'), { code: 'EIO' });
  assert.equal(await readFile(filename, 'utf8'), before);
  assert.deepEqual(await f.combinations.list({ id: 'environment_a' }), { combinations: [combination] });
  f.combinations.persist = persist;
  await writeFile(filename, '{', { mode: 0o600 });
  const broken = new WorkCombinations({ root: f.root, terminal: f.terminal,
    getProfile: async () => assert.fail('cleanup must not query a profile'), ensureBrowser: async () => assert.fail('cleanup must not launch') });
  await assert.rejects(broken.removeProfile('environment_a'), code('WORK_COMBINATION_STORAGE_INVALID'));
  assert.equal(await readFile(filename, 'utf8'), '{');
  assert.deepEqual(await f.entries.get('environment_a', entry.id), entry);
});

test('unsafe and malformed combination stores fail without rewriting or following links', async t => {
  const f = await fixture(t), entry = await f.add('entry'); await f.save([entry]);
  const filename = path.join(f.root, 'work-combinations.json'), bytes = await readFile(filename, 'utf8'), document = JSON.parse(bytes), item = document.combinations[0];
  for (const bad of ['{', JSON.stringify({ ...document, password: secret }), JSON.stringify({ ...document, combinations: [item, item] }),
    JSON.stringify({ ...document, combinations: [{ ...item, entries: [...item.entries, ...item.entries] }] }),
    JSON.stringify({ ...document, combinations: [{ ...item, browser: { profileId: 'environment_b', contextHash: 'a'.repeat(64) } }] }),
    JSON.stringify({ ...document, combinations: [{ ...item, entries: [{ ...item.entries[0], cwd: f.root }] }] })]) {
    await writeFile(filename, bad, { mode: 0o600 }); await assert.rejects(f.create(), code('WORK_COMBINATION_STORAGE_INVALID'));
    assert.equal(await readFile(filename, 'utf8'), bad);
  }
  const target = path.join(f.root, 'outside'); await writeFile(target, secret); await unlink(filename); await symlink(target, filename);
  await assert.rejects(f.create(), code('WORK_COMBINATION_UNSAFE_PATH'));
  await assert.rejects(f.save([entry]), code('WORK_COMBINATION_UNSAFE_PATH')); assert.equal(await readFile(target, 'utf8'), secret);
  await unlink(filename); await writeFile(filename, 'x'.repeat(256 * 1024 + 1));
  await assert.rejects(f.create(), code('WORK_COMBINATION_UNSAFE_PATH'));
});

test('completed request cache stays bounded while retaining recent request results', async t => {
  const f = await fixture(t), entry = await f.add('entry'), combo = await f.save([entry]);
  for (let index = 0; index < 130; index++) await f.open(combo, `request_${index}`);
  assert.equal(f.combinations.requests.size, 128); const count = f.records.length;
  await f.open(combo, 'request_129'); assert.equal(f.records.length, count);
});
