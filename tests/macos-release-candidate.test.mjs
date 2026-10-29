import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { candidateBootstrapExpression, candidateEnvironment, candidateFailure, clearCandidateRuntime, observeCandidateProcesses,
  parseCandidateArguments, parseCandidateProcesses, prepareCandidateRuntime, requiredChecks,
  readCandidateProcessSnapshot, validateCandidateInputs, verifyMacosReleaseCandidate, waitForCandidateBrowserEndpoint,
  writeCandidateReceipt } from '../scripts/verify-macos-release-candidate.mjs';

function input(root = '/fixture/release') {
  const nonce = randomUUID(), evidence = path.join(root, 'evidence', nonce);
  return { app: path.join(root, 'candidate/mac-arm64/Envara.app'), runtime: path.join(root, 'runtime'), evidence,
    receipt: path.join(evidence, 'candidate-acceptance.json'), sourceCommit: 'a'.repeat(40), nonce, candidateManifestSHA256: 'b'.repeat(64) };
}

async function filesystem(t) {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'envara-candidate-test-'))), request = input(root);
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  for (const directory of [request.app, request.evidence, request.runtime, ...['home', 'userData', 'work'].map(name => path.join(request.runtime, name))]) {
    await fs.mkdir(directory, { recursive: true, mode: 0o700 }); await fs.chmod(directory, 0o700);
  }
  return { root, request };
}

test('candidate CLI binds all fixed paths, nonce, source and manifest without accepting options twice', () => {
  const request = input(), args = Object.entries({ '--app': request.app, '--runtime': request.runtime,
    '--evidence': request.evidence, '--receipt': request.receipt, '--source-commit': request.sourceCommit,
    '--nonce': request.nonce, '--candidate-manifest-sha256': request.candidateManifestSHA256 }).flat();
  assert.deepEqual(parseCandidateArguments(args), request);
  for (const altered of [args.slice(0, -1), [...args, '--app', request.app], [...args, '--unknown', 'value']])
    assert.throws(() => parseCandidateArguments(altered), { code: 'CANDIDATE_INPUT_INVALID' });
  for (const patch of [{ app: '/Applications/Envara.app' }, { runtime: '/fixture/elsewhere' },
    { receipt: path.join(request.evidence, 'old.json') }, { evidence: path.join(request.evidence, '..') },
    { sourceCommit: 'HEAD' }, { candidateManifestSHA256: '' }])
    assert.throws(() => validateCandidateInputs({ ...request, ...patch }), { code: 'CANDIDATE_INPUT_INVALID' });
});

test('runtime preparation requires empty owned fixed roots and clears only its roots', async t => {
  const { root, request } = await filesystem(t), sentinel = path.join(root, 'unrelated');
  await fs.writeFile(sentinel, 'preserved');
  const state = await prepareCandidateRuntime(request);
  for (const directory of Object.values(state.directories)) assert(directory.startsWith(request.runtime + path.sep));
  await fs.writeFile(path.join(state.roots.userData, 'synthetic-config.json'), '{}');
  await clearCandidateRuntime(state);
  for (const directory of Object.values(state.roots)) assert.deepEqual(await fs.readdir(directory), []);
  assert.equal(await fs.readFile(sentinel, 'utf8'), 'preserved');
});

test('an existing configuration blocks preparation without deletion', async t => {
  const { request } = await filesystem(t), file = path.join(request.runtime, 'userData/workspace.json');
  await fs.writeFile(file, 'existing synthetic configuration');
  await assert.rejects(prepareCandidateRuntime(request), { code: 'CANDIDATE_RUNTIME_NOT_EMPTY' });
  assert.equal(await fs.readFile(file, 'utf8'), 'existing synthetic configuration');
  assert.deepEqual(await fs.readdir(path.join(request.runtime, 'work')), []);
});

test('runtime symlinks and a replaced runtime root are refused rather than adopted', async t => {
  const { root, request } = await filesystem(t), home = path.join(request.runtime, 'home');
  await fs.rmdir(home); await fs.symlink(root, home);
  await assert.rejects(prepareCandidateRuntime(request), { code: 'CANDIDATE_RUNTIME_UNSAFE' });
  await fs.unlink(home); await fs.mkdir(home, { mode: 0o700 });
  const state = await prepareCandidateRuntime(request), old = path.join(root, 'saved-home');
  await fs.rename(home, old); await fs.mkdir(home, { mode: 0o700 });
  await fs.writeFile(path.join(home, 'foreign'), 'do not delete');
  await assert.rejects(clearCandidateRuntime(state), { code: 'CANDIDATE_CLEANUP_FAILED' });
  assert.equal(await fs.readFile(path.join(home, 'foreign'), 'utf8'), 'do not delete');
});

test('receipt creation is exclusive and never follows an existing symlink', async t => {
  const { request } = await filesystem(t);
  await writeCandidateReceipt(request.receipt, { passed: false });
  assert.equal((await fs.stat(request.receipt)).mode & 0o777, 0o600);
  await assert.rejects(writeCandidateReceipt(request.receipt, { passed: true }), { code: 'EEXIST' });
  assert.equal(JSON.parse(await fs.readFile(request.receipt)).passed, false);
  await fs.unlink(request.receipt);
  const target = path.join(request.evidence, 'original'); await fs.writeFile(target, 'unchanged');
  await fs.symlink(target, request.receipt);
  await assert.rejects(writeCandidateReceipt(request.receipt, {}));
  assert.equal(await fs.readFile(target, 'utf8'), 'unchanged');
});

test('child environment is allowlisted and pre-main bootstrap refuses a ready or different process before changing paths', () => {
  const directories = Object.fromEntries(['home', 'appData', 'userData', 'sessionData', 'temp', 'logs', 'crashDumps', 'documents',
    'desktop', 'downloads', 'music', 'pictures', 'videos', 'cache', 'config', 'data', 'engines'].map(name => [name, `/fixture/runtime/${name}`]));
  const env = candidateEnvironment(directories);
  assert.equal(env.HOME, directories.home); assert.equal(env.USERPROFILE, directories.home);
  for (const key of ['ANTHROPIC_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN', 'NODE_OPTIONS', 'ENVARA_DEV_DATA', 'ENVARA_BACKEND', 'HTTP_PROXY'])
    assert.equal(Object.hasOwn(env, key), false);
  const expression = candidateBootstrapExpression({ executable: '/fixture/Envara', directories, runtime: '/fixture/runtime', pid: 123 });
  const evaluate = ({ ready = false, packaged = true, pid = 123 } = {}) => {
    const changes = [], values = {};
    const electron = { app: { isReady: () => ready, isPackaged: packaged, setPath: (name, value) => { changes.push(name); values[name] = value; },
      getPath: name => values[name], on: () => {} }, BrowserWindow: { getAllWindows: () => [] } };
    const context = { process: { pid, execPath: '/fixture/Envara' }, require: name => ({ electron, 'node:fs': { realpathSync: value => value },
      'node:path': path, 'node:assert/strict': assert })[name] };
    let error; try { runInNewContext(expression, context); } catch (caught) { error = caught; }
    return { changes, error };
  };
  assert.equal(evaluate().changes.length, 13);
  for (const options of [{ ready: true }, { packaged: false }, { pid: 456 }]) {
    const result = evaluate(options); assert(result.error); assert.deepEqual(result.changes, []);
  }
});

test('read-only process parser rejects incomplete identities and never needs arguments or environments', () => {
  const rows = parseCandidateProcesses('123 1 123 Ss Wed Oct 28 10:00:00 2026 /fixture/Envara\n124 123 123 Z+ Wed Oct 28 10:00:01 2026 (zsh)\n');
  assert.equal(rows.length, 2); assert.equal(rows[0].command, '/fixture/Envara'); assert.equal(rows[1].state, 'Z+');
  for (const text of ['', '123 /fixture/Envara', '123 1 123 Wed Oct 28 10:00:00 2026 /fixture/Envara',
    '123 1 123 Ss Wed Oct 28 10:00:00 2026 /fixture/Envara\nmalformed'])
    assert.throws(() => parseCandidateProcesses(text), { code: 'CANDIDATE_PROCESS_SNAPSHOT_FAILED' });
});

test('process snapshots retry only incomplete reads, and repeated failure remains closed with categorical evidence', async () => {
  let reads = 0;
  const valid = '123 1 123 Ss Wed Oct 28 10:00:00 2026 Envara\n';
  const result = await readCandidateProcessSnapshot({ read: async () => ++reads === 1 ? 'incomplete private row' : valid, delay: async () => {} });
  assert.equal(reads, 2); assert.equal(result[0].pid, 123);
  reads = 0;
  await assert.rejects(readCandidateProcessSnapshot({ read: async () => { reads += 1; return 'incomplete private row'; }, delay: async () => {} }),
    error => { assert.deepEqual(candidateFailure(error, 'process-cleanup'), {
      code: 'CANDIDATE_PROCESS_SNAPSHOT_FAILED', phase: 'process-cleanup', reason: 'SNAPSHOT_ROW_SHAPE', attempts: 3 }); return true; });
  assert.equal(reads, 3);
  reads = 0;
  await assert.rejects(readCandidateProcessSnapshot({ read: async () => { reads += 1; throw Object.assign(new Error('cannot inspect'), { code: 'EACCES' }); },
    delay: async () => { throw new Error('must not retry command failures'); } }), { code: 'EACCES' });
  assert.equal(reads, 1);
});

test('only descendants of the captured process identity are owned, and PID reuse is refused', () => {
  const root = { pid: 10, ppid: 1, pgid: 10, birth: 'fixture birth', command: '/fixture/Envara' };
  const child = { pid: 11, ppid: 10, pgid: 10, birth: 'child birth', command: '/bin/zsh' };
  const unrelated = { pid: 12, ppid: 1, pgid: 12, birth: 'other birth', command: '/Applications/Envara.app/Contents/MacOS/Envara' };
  assert.deepEqual(observeCandidateProcesses([root, child, unrelated], root), [root, child]);
  assert.throws(() => observeCandidateProcesses([{ ...root, birth: 'new birth' }], root), { code: 'CANDIDATE_PROCESS_IDENTITY_CHANGED' });
  assert.deepEqual(observeCandidateProcesses([unrelated], root, [root, child]), [root, child]);
  const grandchild = { pid: 13, ppid: 11, pgid: 13, birth: 'grandchild birth', command: '/bin/sh' };
  const afterRootExit = observeCandidateProcesses([child, grandchild, unrelated], root, [root, child]);
  assert.deepEqual(afterRootExit, [root, child, grandchild]);
  assert.deepEqual(observeCandidateProcesses([grandchild, unrelated], root, afterRootExit), afterRootExit);
  assert.deepEqual(observeCandidateProcesses([{ ...child, birth: 'replacement' }, grandchild], root, [root, child]), [root, child]);
});

test('Darwin exiting and zombie command changes complete observation without trusting live changes or PID reuse', () => {
  const root = { pid: 10, ppid: 1, pgid: 10, state: 'Ss', birth: 'fixture birth', command: '/fixture/Envara' };
  const child = { pid: 11, ppid: 10, pgid: 10, state: 'S', birth: 'child birth', command: '/bin/zsh' };
  for (const [state, command] of [['UEs', '(Envara)'], ['Z+', '(Envara)'], ['Z', '<defunct>']]) {
    const dead = { ...root, state, command };
    assert.deepEqual(observeCandidateProcesses([dead, child], root, [root]), [root, child]);
    assert.throws(() => observeCandidateProcesses([{ ...dead, birth: 'another birth' }], root), { code: 'CANDIDATE_PROCESS_IDENTITY_CHANGED' });
    assert.throws(() => observeCandidateProcesses([{ ...dead, state: 'S' }], root), { code: 'CANDIDATE_PROCESS_IDENTITY_CHANGED' });
  }
});

test('browser endpoint waits through startup responses before returning a same-port loopback websocket', async t => {
  let requests = 0;
  const server = http.createServer((request, response) => {
    assert.equal(request.url, '/json/version/'); requests += 1;
    if (requests < 3) { response.writeHead(503); response.end(); return; }
    response.setHeader('Content-Type', 'application/json');
    response.end(JSON.stringify({ webSocketDebuggerUrl: `ws://127.0.0.1:${server.address().port}/devtools/browser/fixture` }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  assert.equal(await waitForCandidateBrowserEndpoint(server.address().port, { timeout: 1000 }),
    `ws://127.0.0.1:${server.address().port}/devtools/browser/fixture`);
  assert.equal(requests, 3);
});

test('browser endpoint rejects foreign addresses and reports bounded startup failure categorically', async () => {
  for (const address of ['ws://example.invalid:1234/devtools/browser/fixture', 'ws://127.0.0.1:5678/devtools/browser/fixture',
    'ws://name:secret@127.0.0.1:1234/devtools/browser/fixture', 'ws://127.0.0.1:1234/other', 'not-a-url']) {
    await assert.rejects(waitForCandidateBrowserEndpoint(1234, { read: async () => ({ webSocketDebuggerUrl: address }) }),
      { code: 'CANDIDATE_BOOTSTRAP_FAILED' });
  }
  await assert.rejects(waitForCandidateBrowserEndpoint(1234, { timeout: 20,
    read: async () => { throw Object.assign(new Error('private endpoint details'), { code: 'ECONNREFUSED' }); } }),
  error => {
    assert.deepEqual(candidateFailure(error, 'browser-endpoint'),
      { code: 'CANDIDATE_CHECK_TIMEOUT', phase: 'browser-endpoint', reason: 'ECONNREFUSED' });
    return true;
  });
});

test('failure evidence preserves fixed inspector detail and excludes raw diagnostic contents', () => {
  const error = Object.assign(new Error('sensitive endpoint, path and expression'), {
    code: 'CANDIDATE_BOOTSTRAP_FAILED', operation: 'Runtime.evaluate', reason: 'INSPECTOR_EXCEPTION' });
  assert.deepEqual(candidateFailure(error, 'pre-main-isolation'), {
    code: 'CANDIDATE_BOOTSTRAP_FAILED', phase: 'pre-main-isolation', operation: 'Runtime.evaluate', reason: 'INSPECTOR_EXCEPTION' });
  assert.deepEqual(candidateFailure(new Error('CANDIDATE_BOOTSTRAP_FAILED'), 'main-inspector'),
    { code: 'CANDIDATE_BOOTSTRAP_FAILED', phase: 'main-inspector' });
  assert.deepEqual(candidateFailure({ message: 'private', code: 'private', reason: 'private', operation: 'private' }, '/private/path'),
    { code: 'CANDIDATE_CHECK_FAILED', phase: 'unknown' });
});

function orchestration(overrides = {}) {
  const events = [], stored = [];
  const methods = { platform: 'darwin', prepare: async () => { events.push('prepare'); return {}; },
    desktop: async () => { events.push('desktop'); return { appLaunched: true, cleanupComplete: true, remainingOwnedProcesses: 0,
      checks: requiredChecks.slice(0, 3).map(id => ({ id, passed: true })) }; },
    keychain: async () => { events.push('keychain'); return { passed: true, cleanupComplete: true, hostSelectionUnchanged: true }; },
    cleanup: async () => { events.push('cleanup'); }, writeReceipt: async (file, value) => { events.push('receipt'); stored.push({ file, value }); }, ...overrides };
  return { events, stored, methods };
}

test('passing receipt requires actual desktop and synthetic persistence checks followed by cleanup', async () => {
  const f = orchestration(), request = input(), receipt = await verifyMacosReleaseCandidate(request, f.methods);
  assert.deepEqual(f.events, ['prepare', 'desktop', 'keychain', 'cleanup', 'receipt']);
  assert(receipt.passed && receipt.appLaunched && receipt.cleanup.complete);
  assert.deepEqual(receipt.checks.map(item => item.id).sort(), [...requiredChecks].sort());
  assert.equal(receipt.candidateManifestSHA256, request.candidateManifestSHA256);
  assert.equal(receipt.checks.find(item => item.id === 'claude-keychain-persistence').details.actualOAuthLogin, false);
});

test('failed GUI cannot be upgraded to a pass by successful cleanup and does not start keychain test', async () => {
  const f = orchestration({ desktop: async () => { throw Object.assign(new Error('sensitive path must be omitted'), {
    code: 'CANDIDATE_GUI_FAILED', observation: { appLaunched: true, checks: [], remainingOwnedProcesses: 0, cleanupComplete: true } }); } });
  await assert.rejects(verifyMacosReleaseCandidate(input(), f.methods), error => error.receipt.passed === false);
  assert(!f.events.includes('keychain')); assert(f.events.includes('cleanup'));
  assert.deepEqual(f.stored[0].value.error, { code: 'CANDIDATE_GUI_FAILED', phase: 'launch' });
  assert(!JSON.stringify(f.stored).includes('sensitive path'));
});

test('a cleanup failure does not overwrite the phase and reason of the first desktop failure', async () => {
  const f = orchestration({ desktop: async () => { throw Object.assign(new Error('private'), {
    observation: { appLaunched: false, checks: [], remainingOwnedProcesses: 0, cleanupComplete: true,
      failure: { code: 'CANDIDATE_CHECK_FAILED', phase: 'first-launch-ui', reason: 'TimeoutError' } } }); },
  cleanup: async () => { throw new Error('cleanup path'); } });
  await assert.rejects(verifyMacosReleaseCandidate(input(), f.methods));
  assert.deepEqual(f.stored[0].value.error, { code: 'CANDIDATE_CHECK_FAILED', phase: 'first-launch-ui', reason: 'TimeoutError' });
  assert.deepEqual(f.stored[0].value.cleanup.error, { code: 'CANDIDATE_CLEANUP_FAILED', phase: 'runtime-cleanup' });
  assert(!JSON.stringify(f.stored).includes('cleanup path'));
});

test('uncertain native cleanup preserves temporary data and refuses publication', async () => {
  for (const native of [async () => ({ passed: false, cleanupComplete: false, hostSelectionUnchanged: true }),
    async () => { throw Object.assign(new Error('native failure'), { proof: { cleanupComplete: false } }); }]) {
    const f = orchestration({ keychain: native });
    await assert.rejects(verifyMacosReleaseCandidate(input(), f.methods));
    assert(!f.events.includes('cleanup'));
    assert.equal(f.stored[0].value.cleanup.complete, false); assert.equal(f.stored[0].value.passed, false);
  }
});

test('cleanup failure, missing check, skipped GUI or duplicate check never yield passed true', async () => {
  for (const override of [
    { cleanup: async () => { throw new Error('failure'); } },
    { desktop: async () => ({ appLaunched: false, cleanupComplete: true, remainingOwnedProcesses: 0, checks: [] }) },
    { desktop: async () => ({ appLaunched: true, cleanupComplete: true, remainingOwnedProcesses: 0, checks: [{ id: 'clean-first-launch', passed: true }] }) },
    { desktop: async () => ({ appLaunched: true, cleanupComplete: true, remainingOwnedProcesses: 0,
      checks: [...requiredChecks.slice(0, 3), 'terminal-pty'].map(id => ({ id, passed: true })) }) },
  ]) {
    const f = orchestration(override); await assert.rejects(verifyMacosReleaseCandidate(input(), f.methods));
    assert.equal(f.stored[0].value.passed, false);
  }
});
