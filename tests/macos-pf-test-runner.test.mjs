import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { chmod, mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { createMacOSPFTestCommands, parseMacOSPFTestArguments, runMacOSPFTests } from '../scripts/test-macos-pf-routing.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const UNPRIVILEGED_MAC = { platform: 'darwin', uid: 501, euid: 501, gid: 20, egid: 20 };

async function fixture(t, { external = false } = {}) {
  const temporary = await mkdtemp(path.join(tmpdir(), 'envara-pf-runner-'));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const root = path.join(temporary, 'source with spaces');
  const source = path.join(root, 'native/macos-pf-routing');
  const resources = external ? path.join(temporary, 'independent payload') : path.join(root, 'build/app-routing/macos-pf');
  const names = (await readdir(path.join(ROOT, 'native/macos-pf-routing'), { withFileTypes: true }))
    .filter(entry => entry.isFile() && entry.name.endsWith('.test.mjs')).map(entry => entry.name).sort();
  await mkdir(source, { recursive: true });
  await mkdir(path.join(resources, 'fixtures'), { recursive: true });
  for (const name of [...names, 'test.mjs', 'future-fixture.test.mjs', 'not-a-test.mjs']) {
    await writeFile(path.join(source, name), '// Inert runner test input; must never execute.\n');
  }
  await mkdir(path.join(source, 'directory.test.mjs'));
  const binaries = [path.join(resources, 'envara-pf-native'), path.join(resources, 'fixtures/EnvaraRoutingAcceptanceFixture')];
  for (const filename of binaries) await writeFile(filename, 'Inert, non-program fixture bytes.\n', { mode: 0o755 });
  return { root, source, resources, names, binaries };
}

test('runner enumerates the complete native test inventory and separates the two payload entry points', async t => {
  const f = await fixture(t);
  const inherited = { PATH: '/fixture/path', ENVARA_PF_NATIVE_TEST_BINARY: '/stale/native' };
  const commands = await createMacOSPFTestCommands({ root: f.root, env: inherited });
  assert.equal(commands.length, 3);
  const names = [...f.names.filter(name => name !== 'fixture-reservation.test.mjs'), 'future-fixture.test.mjs'].sort();
  assert.deepEqual(commands[0].args, ['--test', '--test-concurrency=2', ...names.map(name => path.join(f.source, name))]);
  assert.deepEqual(commands[1].args, [path.join(f.source, 'test.mjs')]);
  assert.equal(commands[1].options.env.ENVARA_PF_NATIVE_TEST_BINARY, f.binaries[0]);
  assert.deepEqual(commands[2].args, [path.join(f.source, 'fixture-reservation.test.mjs'), f.binaries[1]]);
  assert.deepEqual(inherited, { PATH: '/fixture/path', ENVARA_PF_NATIVE_TEST_BINARY: '/stale/native' });
  for (const command of commands) {
    assert.equal(command.executable, process.execPath);
    assert.equal(command.options.cwd, f.root);
    assert.equal(command.options.stdio, 'inherit');
    assert.equal(command.options.shell, false);
    assert.equal(command.options.env.PATH, inherited.PATH);
  }
});

test('explicit payload path remains a single argument and all three phases execute in order', async t => {
  const f = await fixture(t, { external: true });
  const calls = [];
  let active = false;
  const commands = await runMacOSPFTests({ ...UNPRIVILEGED_MAC, root: f.root, resources: f.resources, env: {},
    exec: async (executable, args, options) => {
      assert.equal(active, false, 'phases must not overlap');
      active = true;
      await new Promise(resolve => setImmediate(resolve));
      calls.push({ executable, args, options });
      active = false;
    } });
  assert.deepEqual(calls, commands.map(({ name, ...command }) => command));
  assert.equal(calls[1].options.env.ENVARA_PF_NATIVE_TEST_BINARY, f.binaries[0]);
  assert.equal(calls[2].args[1], f.binaries[1]);
});

test('each failed phase preserves the original error and prevents all later phases', async t => {
  const f = await fixture(t);
  for (let failedPhase = 0; failedPhase < 3; failedPhase++) {
    const failure = Object.assign(new Error(`phase ${failedPhase} failed`), { exitCode: 17 + failedPhase });
    let calls = 0;
    await assert.rejects(runMacOSPFTests({ ...UNPRIVILEGED_MAC, root: f.root,
      exec: async () => { if (calls++ === failedPhase) throw failure; } }), error => error === failure);
    assert.equal(calls, failedPhase + 1);
  }
});

test('unsupported or privileged identities are refused before reading inputs or executing', async () => {
  const rejected = [
    { platform: 'linux' }, { platform: 'win32' },
    { uid: 0 }, { euid: 0 }, { gid: 0 }, { egid: 0 },
    { uid: 502 }, { egid: 21 }, { uid: null }, { euid: '501' }, { gid: -1 }, { egid: 1.5 },
  ];
  for (const override of rejected) {
    let calls = 0;
    const identity = { ...UNPRIVILEGED_MAC, ...override };
    await assert.rejects(runMacOSPFTests({ ...identity, root: '/missing-inert-test-root',
      exec: async () => { calls++; } }), /require macOS|unprivileged user/);
    assert.equal(calls, 0);
  }
});

test('arguments accept only one absolute payload and reject unknown, duplicate or relative inputs', () => {
  const resources = path.resolve('fixture payload');
  assert.deepEqual(parseMacOSPFTestArguments([]), {});
  assert.deepEqual(parseMacOSPFTestArguments(['--resources', resources]), { resources });
  for (const args of [
    ['--resources'], ['--resources', 'relative/path'], ['--resources', ''],
    ['--install'], ['--resources=' + resources], ['--resources', resources, '--activate'],
    ['--resources', resources, '--resources', resources], [resources], ['--resources', null],
  ]) assert.throws(() => parseMacOSPFTestArguments(args), /Usage:/);
});

test('preflight rejects missing payload files before any phase starts', async t => {
  for (const missing of [0, 1]) {
    const f = await fixture(t);
    await rm(f.binaries[missing]);
    let calls = 0;
    await assert.rejects(runMacOSPFTests({ ...UNPRIVILEGED_MAC, root: f.root,
      exec: async () => { calls++; } }), { code: 'ENOENT' });
    assert.equal(calls, 0);
  }
});

test('preflight refuses directory payloads and non-executable files', async t => {
  const f = await fixture(t);
  await rm(f.binaries[0]);
  await mkdir(f.binaries[0]);
  await assert.rejects(createMacOSPFTestCommands({ root: f.root }), /not a file/);
  await rm(f.binaries[0], { recursive: true });
  await writeFile(f.binaries[0], 'inert', { mode: 0o755 });
  if (process.platform !== 'win32') {
    await chmod(f.binaries[1], 0o600);
    await assert.rejects(createMacOSPFTestCommands({ root: f.root }), { code: 'EACCES' });
  }
});

test('command construction rejects relative paths and an empty test inventory', async t => {
  for (const options of [{ root: '.' }, { resources: 'payload' }, { node: 'node' }]) {
    await assert.rejects(createMacOSPFTestCommands(options), /must be absolute/);
  }
  const f = await fixture(t);
  for (const name of [...f.names.filter(name => name !== 'fixture-reservation.test.mjs'), 'future-fixture.test.mjs']) {
    await rm(path.join(f.source, name));
  }
  await assert.rejects(createMacOSPFTestCommands({ root: f.root }), /No macOS PF native fixture tests found/);
});
