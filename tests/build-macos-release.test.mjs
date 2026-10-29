import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { buildMacRelease, signingGate, signingRequest, selectSigningIdentity, beforePack, command,
  signingTargets, validateDesignatedRequirement, validateSigningChanges, inventory, inspectCandidateAcceptanceScript,
  candidateSigningOptions, validateSignedIdentity, validateAdhocRequirement, verifySignedBundle, zipArchiveArguments,
  CANDIDATE_ACCEPTANCE_SCRIPT, CANDIDATE_ACCEPTANCE_SCHEMA, CANDIDATE_ACCEPTANCE_CHECKS,
  validateCandidateAcceptance, readCandidateAcceptanceReceipt, runCandidateAcceptance } from '../scripts/build-macos-release.mjs';

const identity = 'A'.repeat(40), team = 'EXAMPLE123';
const env = { ENVARA_MAC_SIGNING_IDENTITY: identity, ENVARA_MAC_SIGNING_TEAM_ID: team };
const adhocEnv = { ENVARA_MAC_SIGNING_MODE: 'adhoc' };
const listing = `  1) ${identity} "Developer ID Application: Example Maintainer (${team})"\n     1 valid identities found\n`;
const requirement = `designated => identifier "io.envara.desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "${team}"`;

test('macOS release entry is a single gate before preparation', async () => {
  const pkg = JSON.parse(await fs.readFile(new URL('../package.json', import.meta.url)));
  assert.equal(pkg.scripts['dist:mac'], 'node scripts/build-macos-release.mjs');
  assert.equal(pkg.build.mac.identity, null);
  assert.equal(pkg.build.beforePack, './scripts/build-macos-release.mjs');
  const called = [];
  await assert.rejects(buildMacRelease({ env: {}, platform: 'darwin', arch: 'arm64',
    run: async () => called.push('command'), openWorkspace: async () => called.push('workspace') }), /existing Developer ID/);
  assert.deepEqual(called, []);
});

test('an explicit valid Developer ID passes a read-only identity check', async () => {
  const called = [];
  const result = await buildMacRelease({ env, platform: 'darwin', arch: 'arm64', checkOnly: true,
    run: async (cmd, args) => { called.push([cmd, args]); return { code: 0, stdout: listing }; },
    openWorkspace: async () => assert.fail('check-only must not create a workspace') });
  assert.equal(result.ready, true);
  assert.equal(result.workspaceCreated, false);
  assert.equal(result.identity.identity, identity);
  assert.equal(result.identity.mode, 'developer-id');
  assert.deepEqual(called, [['/usr/bin/security', ['find-identity', '-v', '-p', 'codesigning']]]);
});

test('explicit ad-hoc mode passes a read-only check without certificate discovery or a workspace', async () => {
  const result = await buildMacRelease({ env: adhocEnv, platform: 'darwin', arch: 'arm64', checkOnly: true,
    run: async () => assert.fail('ad-hoc must not discover or import certificates'),
    openWorkspace: async () => assert.fail('check-only must not create a workspace') });
  assert.deepEqual(result, { ready: true, identity: { mode: 'adhoc', identity: '-', team: null }, workspaceCreated: false });
  await assert.rejects(signingGate({ env: adhocEnv, platform: 'linux', arch: 'arm64',
    run: async () => assert.fail('unsupported platform must not run commands') }), /Apple Silicon/);
});

test('signing mode never downgrades implicitly or accepts conflicting certificate selection', async () => {
  for (const mode of ['', 'auto', 'ad-hoc', 'ADHOC', 'none']) {
    assert.throws(() => signingRequest({ ...env, ENVARA_MAC_SIGNING_MODE: mode }), /must be developer-id or adhoc/);
  }
  for (const extras of [{ ENVARA_MAC_SIGNING_IDENTITY: identity }, { ENVARA_MAC_SIGNING_IDENTITY: '-' },
    { ENVARA_MAC_SIGNING_TEAM_ID: team }]) {
    assert.throws(() => signingRequest({ ...adhocEnv, ...extras }), /cannot include/);
  }
  for (const extras of [{}, { ENVARA_MAC_SIGNING_MODE: 'developer-id' }]) {
    await assert.rejects(signingGate({ env: { ...env, ...extras }, platform: 'darwin', arch: 'arm64',
      run: async () => ({ code: 0, stdout: '0 valid identities found\n' }) }), /exactly once/);
  }
  assert.throws(() => selectSigningIdentity(listing, signingRequest(adhocEnv)), /requires developer-id/);
});

for (const invalid of ['', '-', 'Developer ID Application: Example', 'A'.repeat(39), 'Z'.repeat(40)]) {
  test(`reject non-fingerprint signing selection ${invalid || '(empty)'}`, () => {
    assert.throws(() => signingRequest({ ...env, ENVARA_MAC_SIGNING_IDENTITY: invalid }), /existing Developer ID/);
  });
}

for (const key of ['CSC_LINK', 'CSC_KEY_PASSWORD', 'CSC_KEYCHAIN', 'CSC_NAME', 'CSC_INSTALLER_LINK', 'CSC_INSTALLER_KEY_PASSWORD']) {
  test(`reject certificate import or alternate selection through ${key}`, async () => {
    let calls = 0;
    await assert.rejects(signingGate({ env: { ...env, [key]: 'example' }, platform: 'darwin', arch: 'arm64',
      run: async () => { calls++; } }), new RegExp(key));
    assert.equal(calls, 0);
    assert.throws(() => signingRequest({ ...adhocEnv, [key]: 'example' }), new RegExp(key));
  });
}

test('refuse gdb, ad-hoc, duplicate, invalid, and other-team identities', () => {
  const request = signingRequest(env);
  for (const text of [listing.replace('Developer ID Application: Example Maintainer', 'gdb-cert'),
    listing.replace(team, 'OTHERTEAM1'), '', `${listing}${listing}`, listing.replace(identity, 'B'.repeat(40)),
    listing.replace('"\n', '" (CSSMERR_TP_CERT_REVOKED)\n')]) {
    assert.throws(() => selectSigningIdentity(text, request));
  }
});

test('ad-hoc signature arguments disable timestamps and preserve the prior runtime policy', () => {
  const selected = signingRequest(adhocEnv);
  const options = candidateSigningOptions(selected, 0x20002, 'io.envara.desktop');
  assert.deepEqual(options.args, ['--force', '--sign', '-', '--timestamp=none', '--options', '0x0', '--identifier', 'io.envara.desktop']);
  assert.equal(options.expectedFlags, 0x2);
  // Changing signing mode does not add or remove an existing runtime policy.
  assert.equal(candidateSigningOptions(selected, 0x30002, 'io.envara.desktop').expectedFlags, 0x10002);
  const developer = candidateSigningOptions(signingRequest(env), 0x30002, 'io.envara.desktop');
  assert.equal(developer.expectedFlags, 0x10000);
  assert.equal(developer.args[2], identity);
  assert.equal(developer.args[3], '--timestamp');
  for (const invalid of [{ mode: 'adhoc', identity, team }, { mode: 'developer-id', identity: '-', team: null },
    { mode: 'auto', identity: '-', team: null }]) {
    assert.throws(() => candidateSigningOptions(invalid, 0x20002, 'io.envara.desktop'), /Invalid signing/);
  }
});

test('final ad-hoc identity is unique, certificate-free and bound to the exact code hash', async () => {
  const cdhash = 'c'.repeat(40), selected = signingRequest(adhocEnv);
  const text = `Identifier=io.envara.desktop\nSignature=adhoc\nTeamIdentifier=not set\nCDHash=${cdhash}\n`;
  assert.deepEqual(validateSignedIdentity(text, 'io.envara.desktop', selected), {
    mode: 'adhoc', identifier: 'io.envara.desktop', team: null, certificateSHA1: null, cdhash,
  });
  for (const altered of [text.replace('adhoc', 'invalid'), text.replace('not set', team),
    text.replace('io.envara.desktop', 'io.envara.other'), text + 'Authority=Unexpected certificate\n',
    text + 'Signature=adhoc\n', text + 'TeamIdentifier=not set\n', text + 'Identifier=io.envara.desktop\n',
    text.replace(cdhash, 'not-a-hash'), text + `CDHash=${cdhash}\n`]) {
    assert.throws(() => validateSignedIdentity(altered, 'io.envara.desktop', selected));
  }
  assert.throws(() => validateSignedIdentity(text, 'io.envara.desktop', signingRequest(env)), /identity differs/);
  for (const prefix of ['designated => ', '# designated => ']) {
    assert.equal(validateAdhocRequirement(`${prefix}cdhash H"${cdhash}"\n`, cdhash), `cdhash H"${cdhash}"`);
  }
  for (const altered of ['designated => identifier "io.envara.desktop"',
    `# designated => cdhash H"${'d'.repeat(40)}"`, `# designated => cdhash H"${cdhash}" or identifier "io.envara.desktop"`,
    `# designated => cdhash H"${cdhash}"\n# designated => cdhash H"${cdhash}"`]) {
    assert.throws(() => validateAdhocRequirement(altered, cdhash));
  }
  const calls = [];
  const verified = await verifySignedBundle('/owned/synthetic-app', 'io.envara.desktop', selected, async (cmd, args) => {
    calls.push([cmd, args]);
    if (args[0] === '--verify') return { code: 0, stdout: '', stderr: '' };
    if (args[1] === '--verbose=4') return { code: 0, stdout: '', stderr: text };
    assert.deepEqual(args, ['--display', '--requirements', '-', '/owned/synthetic-app']);
    return { code: 0, stdout: `# designated => cdhash H"${cdhash}"\n`, stderr: '' };
  });
  assert.equal(verified.cdhash, cdhash);
  assert.deepEqual(calls[0], ['/usr/bin/codesign', ['--verify', '--strict', '/owned/synthetic-app']]);
  assert.equal(calls.length, 3, 'ad-hoc verification never extracts certificates');
});

test('native codesign verifies the explicit ad-hoc mode on a disposable executable', { skip: process.platform !== 'darwin' }, async t => {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'envara-release-sign-test-')));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const source = path.join(root, 'fixture.c'), executable = path.join(root, 'fixture');
  await fs.writeFile(source, 'int main(void) { return 0; }\n');
  const checked = async (...args) => { const result = await command(...args); assert.equal(result.code, 0, result.stderr); return result; };
  await checked('/usr/bin/xcrun', ['clang', source, '-o', executable]);
  const before = await checked('/usr/bin/codesign', ['--display', '--verbose=4', executable]);
  const originalFlags = /CodeDirectory.*flags=(0x[A-Fa-f0-9]+)/.exec(before.stderr + before.stdout);
  assert.ok(originalFlags);
  const selected = signingRequest(adhocEnv), identifier = 'io.envara.synthetic-signing';
  const options = candidateSigningOptions(selected, Number(originalFlags[1]), identifier);
  await checked('/usr/bin/codesign', [...options.args, executable]);
  const verified = await verifySignedBundle(executable, identifier, selected, checked);
  assert.equal(verified.mode, 'adhoc');
  assert.equal(verified.certificateSHA1, null);
  const after = await checked('/usr/bin/codesign', ['--display', '--verbose=4', executable]);
  assert.equal(Number(/CodeDirectory.*flags=(0x[A-Fa-f0-9]+)/.exec(after.stderr + after.stdout)[1]), options.expectedFlags);
});

test('native zip archive excludes resource metadata while preserving the exact fixture tree', { skip: process.platform !== 'darwin' }, async t => {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'envara-release-zip-test-')));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const fixture = path.join(root, 'archive-fixture'), extracted = path.join(root, 'extracted'), archive = path.join(root, 'fixture.zip');
  await fs.mkdir(path.join(fixture, 'bin'), { recursive: true, mode: 0o700 });
  await fs.chmod(fixture, 0o750); await fs.chmod(path.join(fixture, 'bin'), 0o755);
  const program = path.join(fixture, 'bin', 'program');
  await fs.writeFile(program, 'synthetic executable bytes; never launched\n', { mode: 0o751 });
  await fs.chmod(program, 0o751);
  await fs.symlink('bin/program', path.join(fixture, 'program-link'));
  await fs.mkdir(extracted, { mode: 0o700 });
  const checked = async (cmd, args) => {
    const result = await command(cmd, args, { cwd: root, timeout: 45000,
      env: { ...process.env, COPYFILE_DISABLE: '1', DITTONORSRC: '1' } });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.closeConfirmed, true); assert.equal(result.cleanupUncertain, false);
    return result;
  };
  for (const target of [fixture, program]) {
    await checked('/usr/bin/xattr', ['-w', 'com.envara.release-test', 'synthetic metadata', target]);
    assert.equal((await checked('/usr/bin/xattr', ['-p', 'com.envara.release-test', target])).stdout.trim(), 'synthetic metadata');
  }
  const before = await inventory(fixture);
  await checked('/usr/bin/ditto', zipArchiveArguments(fixture, archive));
  const members = (await checked('/usr/bin/unzip', ['-Z', '-1', archive])).stdout.trim().split('\n');
  assert.deepEqual(members.sort(), ['archive-fixture/', 'archive-fixture/bin/', 'archive-fixture/bin/program', 'archive-fixture/program-link'].sort());
  assert.equal(members.some(name => name.split('/').some(part => part === '__MACOSX' || part.startsWith('._'))), false);
  await checked('/usr/bin/ditto', ['-x', '-k', '--noqtn', '--norsrc', '--noextattr', archive, extracted]);
  assert.deepEqual(await fs.readdir(extracted), ['archive-fixture']);
  const restored = path.join(extracted, 'archive-fixture');
  assert.deepEqual(await inventory(restored), before);
  assert.equal((await fs.stat(path.join(restored, 'bin/program'))).mode & 0o7777, 0o751);
  assert.equal(await fs.readlink(path.join(restored, 'program-link')), 'bin/program');
  assert.equal((await checked('/usr/bin/xattr', [path.join(restored, 'bin/program')])).stdout.includes('com.envara.release-test'), false);
});

test('platform and identity discovery failures occur before workspace creation', async () => {
  await assert.rejects(signingGate({ env, platform: 'linux', arch: 'arm64', run: async () => assert.fail('must not discover') }), /Apple Silicon/);
  await assert.rejects(signingGate({ env, platform: 'darwin', arch: 'arm64', run: async () => ({ code: 1, stdout: listing }) }), /Unable to inspect/);
});

test('accept only the full default Developer ID requirement with the selected team', () => {
  assert.equal(validateDesignatedRequirement(requirement, 'io.envara.desktop', team), requirement.slice('designated => '.length));
  assert.doesNotThrow(() => validateDesignatedRequirement(requirement.replace(`"${team}"`, team), 'io.envara.desktop', team));
  for (const altered of [
    'designated => identifier "io.envara.desktop"',
    'designated => cdhash H"0123456789"',
    `${requirement} or identifier "io.envara.desktop"`,
    requirement.replace('anchor apple generic', 'anchor trusted'),
    requirement.replace('100.6.1.13', '100.6.1.2'),
    requirement.replace(team, 'OTHERTEAM1'),
    `${requirement}\n${requirement}`,
  ]) assert.throws(() => validateDesignatedRequirement(altered, 'io.envara.desktop', team));
});

test('bounded signing never includes pinned carriers or third-party resource programs', () => {
  assert.equal(signingTargets.length, 9);
  assert.equal(signingTargets.at(-1), '.');
  assert.ok(signingTargets.every(item => item === '.' || item.startsWith('Contents/Frameworks/')));
  const metadata = [{ executable: 'Contents/MacOS/Envara', seal: 'Contents/_CodeSignature' }];
  const before = { 'Contents/MacOS/Envara': { hash: 'old' }, 'Contents/Resources/pinned': { hash: 'original' } };
  const after = { ...before, 'Contents/MacOS/Envara': { hash: 'signed' }, 'Contents/_CodeSignature/CodeResources': { hash: 'seal' } };
  assert.equal(validateSigningChanges(before, after, metadata).length, 2);
  for (const name of ['Contents/Resources/pinned', 'Contents/Resources/app.asar', 'Contents/Info.plist', 'Contents/Frameworks/unknown']) {
    assert.throws(() => validateSigningChanges(before, { ...after, [name]: { hash: 'changed' } }, metadata), /outside the nine/);
  }
});

test('a preparation failure retains its first error even when cleanup also fails', async () => {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'envara-release-gate-test-')));
  const calls = [], evidenceDir = path.join(root, 'evidence');
  try {
    await fs.mkdir(evidenceDir);
    await fs.writeFile(path.join(root, 'package.json'), JSON.stringify({ version: '1.2.3', build: { appId: 'io.envara.desktop' } }));
    await fs.mkdir(path.join(root, 'scripts'));
    await fs.writeFile(path.join(root, CANDIDATE_ACCEPTANCE_SCRIPT), '// fixture only\n');
    await assert.rejects(buildMacRelease({ env, platform: 'darwin', arch: 'arm64', root,
      run: async (cmd, args) => {
        calls.push([cmd, args]);
        if (cmd === '/usr/bin/security') return { code: 0, stdout: listing };
        if (cmd === 'git') return { code: 0, stdout: args[0] === 'rev-parse' ? `${'b'.repeat(40)}\n`
          : args[0] === 'ls-files' ? `${CANDIDATE_ACCEPTANCE_SCRIPT}\n` : '' };
        if (cmd === 'npm') return { code: 7, stdout: '', stderr: 'synthetic preparation failure' };
        assert.fail('unexpected mutation');
      },
      openWorkspace: async () => {
        await fs.writeFile(path.join(root, 'lock.json'), JSON.stringify({ nonce: 'synthetic', pid: process.pid }));
        return { root, evidenceDir, cleanup: async ({ operationError }) => {
        assert.match(operationError, /npm failed \(7\)/);
        return { complete: false, cleanupErrors: ['synthetic cleanup failure'] };
        } };
      },
    }), error => {
      assert.match(error.message, /npm failed \(7\)/);
      assert.equal(error.operationError, error.message);
      assert.deepEqual(error.cleanupErrors, ['synthetic cleanup failure']);
      return true;
    });
    assert.equal(calls.filter(([cmd]) => cmd === 'npm').length, 1);
    assert.match(await fs.readFile(path.join(evidenceDir, 'commands.jsonl'), 'utf8'), /synthetic preparation failure/);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test('the builder hook refuses legacy or random macOS output before any command', async () => {
  let commands = 0;
  await assert.rejects(beforePack({ electronPlatformName: 'darwin', arch: 3, appOutDir: '/tmp/example/Envara.app' },
    { env, run: async () => { commands++; } }), /fixed owned workspace/);
  assert.equal(commands, 0);
  await assert.rejects(beforePack({ electronPlatformName: 'mas' }, { env, run: async () => assert.fail('MAS must fail before commands') }), /Unsupported macOS/);
  await assert.doesNotReject(beforePack({ electronPlatformName: 'win32' }, { env: {}, run: async () => assert.fail('non-macOS hook must be inert') }));
});

test('the builder hook binds the live locked workspace and rechecks the identity', async () => {
  const home = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'envara-builder-hook-test-')));
  try {
    const root = path.join(home, 'Library/Caches/io.envara.release/mac-arm64');
    await fs.mkdir(root, { recursive: true, mode: 0o700 });
    const nonce = '00000000-0000-4000-8000-000000000001';
    for (const [name, record] of Object.entries({ 'owner.json': { repository: home },
      'lock.json': { repository: home, nonce, pid: process.pid }, 'state.json': { nonce, complete: false } })) {
      await fs.writeFile(path.join(root, name), JSON.stringify(record), { mode: 0o600 });
    }
    const hookEnv = { ...env, CSC_IDENTITY_AUTO_DISCOVERY: 'false', ENVARA_MAC_RELEASE_NONCE: nonce, ENVARA_MAC_RELEASE_PARENT_PID: String(process.pid) };
    const context = { electronPlatformName: 'darwin', arch: 3, appOutDir: path.join(root, 'candidate/mac-arm64'),
      outDir: path.join(root, 'candidate'), targets: [], packager: { projectDir: home, config: { mac: { identity: null } } } };
    let checks = 0;
    const run = async () => { checks++; return { code: 0, stdout: listing }; };
    await beforePack(context, { env: hookEnv, home, run });
    assert.equal(checks, 1);
    const adhocHookEnv = { ...hookEnv, ...adhocEnv, ENVARA_MAC_SIGNING_IDENTITY: '', ENVARA_MAC_SIGNING_TEAM_ID: '' };
    await beforePack(context, { env: adhocHookEnv, home,
      run: async () => assert.fail('explicit ad-hoc builder authorization must not select a certificate') });
    await assert.rejects(beforePack(context, { env: { ...hookEnv, ...adhocEnv }, home, run }), /cannot include/);
    await assert.rejects(beforePack({ ...context, targets: [{ name: 'dmg' }] }, { env: hookEnv, home, run }), /fixed owned workspace/);
    await assert.rejects(beforePack(context, { env: { ...hookEnv, ENVARA_MAC_RELEASE_NONCE: '00000000-0000-4000-8000-000000000002' }, home, run }), /authorization differs/);
  } finally { await fs.rm(home, { recursive: true, force: true }); }
});

test('the pinned macOS builder maps --dir to an empty beforePack target array', () => {
  const require = createRequire(import.meta.url);
  require('app-builder-lib');
  const { MacPackager } = require('app-builder-lib/out/macPackager.js');
  const mapped = [];
  MacPackager.prototype.createTargets.call({}, ['dir'], (...args) => mapped.push(args));
  assert.deepEqual(mapped, []);
});

test('a command that ignores TERM and never closes has a bounded owned-group deadline', async () => {
  const signals = [], child = new EventEmitter();
  Object.assign(child, { pid: 424242, stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), unref() {} });
  const result = await command('synthetic', [], { timeout: 5, terminateGrace: 5,
    spawnProcess: (cmd, args, options) => { assert.equal(options.detached, true); return child; },
    signalProcess: (pid, signal) => signals.push([pid, signal]),
  });
  assert.equal(result.code, 124);
  assert.equal(result.closeConfirmed, false);
  assert.equal(result.cleanupUncertain, true);
  assert.deepEqual(signals, [[-424242, 'SIGTERM'], [-424242, 'SIGKILL']]);
});

test('a normal command clears its deadline without signalling another process', async () => {
  const child = new EventEmitter();
  Object.assign(child, { pid: 424243, stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), unref() {} });
  const result = await command('synthetic', [], { timeout: 50, terminateGrace: 5,
    spawnProcess: () => { queueMicrotask(() => child.emit('close', 0, null)); return child; },
    signalProcess: () => assert.fail('normal command must never signal'),
  });
  assert.equal(result.code, 0);
  assert.equal(result.cleanupUncertain, false);
  assert.equal(result.closeConfirmed, true);
});

test('an exited leader with inherited pipes is never signalled by its stale PID', async () => {
  const child = new EventEmitter();
  Object.assign(child, { pid: 424244, stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), unref() {} });
  const result = await command('synthetic', [], { timeout: 5, terminateGrace: 5,
    spawnProcess: () => { queueMicrotask(() => child.emit('exit', 0, null)); return child; },
    signalProcess: () => assert.fail('an exited leader no longer authorizes any group signal'),
  });
  assert.equal(result.code, 124);
  assert.equal(result.cleanupUncertain, true);
  assert.equal(result.closeConfirmed, false);
});

async function acceptanceFixture(t) {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'envara-release-acceptance-test-')));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = path.join(root, 'candidate', 'Envara.app'), runtime = path.join(root, 'runtime'), evidence = path.join(root, 'evidence');
  for (const directory of [app, path.join(runtime, 'home'), path.join(runtime, 'work'), evidence, path.join(root, 'scripts')])
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await fs.writeFile(path.join(app, 'fixture'), 'synthetic candidate bytes', { mode: 0o600 });
  await fs.writeFile(path.join(root, CANDIDATE_ACCEPTANCE_SCRIPT), '// synthetic runner; never executed\n', { mode: 0o600 });
  const expected = { app, runtime, sourceCommit: 'b'.repeat(40), nonce: '00000000-0000-4000-8000-000000000001',
    candidateManifestSHA256: createHash('sha256').update(JSON.stringify(await inventory(app))).digest('hex') };
  const receipt = { schema: CANDIDATE_ACCEPTANCE_SCHEMA, ...expected, passed: true, appLaunched: true,
    cleanup: { complete: true, remainingOwnedProcesses: 0 }, checks: CANDIDATE_ACCEPTANCE_CHECKS.map(id => ({ id, passed: true })) };
  const receiptPath = path.join(evidence, 'candidate-acceptance.json'), calls = [];
  let runnerCalls = 0;
  const run = async (cmd, args, options) => {
    calls.push({ cmd, args, options });
    if (cmd === 'git') return { code: 0, stdout: `${CANDIDATE_ACCEPTANCE_SCRIPT}\n`, stderr: '' };
    if (cmd === '/bin/ps') return { code: 0, stdout: '1 0 1 Wed Oct 28 01:02:03 2026 /sbin/launchd\n', stderr: '' };
    if (cmd === '/usr/sbin/lsof') return { code: 1, stdout: '', stderr: '' };
    assert.equal(cmd, process.execPath); assert.equal(args[0], path.join(root, CANDIDATE_ACCEPTANCE_SCRIPT));
    runnerCalls++;
    await fs.writeFile(receiptPath, JSON.stringify(receipt), { flag: 'wx', mode: 0o600 });
    return { code: 0, stdout: '', stderr: '', closeConfirmed: true, cleanupUncertain: false };
  };
  return { root, app, runtime, evidence, expected, receipt, receiptPath, calls, run,
    options: { root, evidence, ...expected, run }, runnerCalls: () => runnerCalls };
}

test('candidate runner belongs to the reviewed commit and cannot be a symlink', async t => {
  const f = await acceptanceFixture(t);
  assert.equal(await inspectCandidateAcceptanceScript(f.root, f.run), path.join(f.root, CANDIDATE_ACCEPTANCE_SCRIPT));
  await assert.rejects(inspectCandidateAcceptanceScript(f.root, async () => ({ code: 1, stdout: '', stderr: '' })), /reviewed source/);
  const script = path.join(f.root, CANDIDATE_ACCEPTANCE_SCRIPT);
  await fs.rename(script, script + '.saved'); await fs.symlink(script + '.saved', script);
  await assert.rejects(inspectCandidateAcceptanceScript(f.root, f.run), /Unsafe candidate acceptance script/);
});

test('a missing candidate runner stops release before acquiring a workspace or preparing resources', async t => {
  const f = await acceptanceFixture(t);
  await fs.unlink(path.join(f.root, CANDIDATE_ACCEPTANCE_SCRIPT));
  await assert.rejects(buildMacRelease({ env, platform: 'darwin', arch: 'arm64', root: f.root,
    run: async (cmd, args) => {
      if (cmd === '/usr/bin/security') return { code: 0, stdout: listing };
      if (cmd === 'git') return { code: 0, stdout: args[0] === 'rev-parse' ? `${'b'.repeat(40)}\n` : '' };
      assert.fail('must not prepare or package without the runner');
    }, openWorkspace: async () => assert.fail('must not acquire a workspace without the runner'),
  }), { code: 'ENOENT' });
});

test('candidate acceptance binds the run, commit, exact bundle and required real checks', async t => {
  const f = await acceptanceFixture(t);
  assert.equal(validateCandidateAcceptance(f.receipt, f.expected), f.receipt);
  for (const field of ['schema', 'sourceCommit', 'app', 'runtime', 'nonce', 'candidateManifestSHA256']) {
    assert.throws(() => validateCandidateAcceptance({ ...f.receipt, [field]: 'stale-or-different' }, f.expected));
  }
  for (const altered of [
    { passed: false }, { appLaunched: false }, { checks: f.receipt.checks.slice(1) },
    { checks: [...f.receipt.checks, f.receipt.checks[0]] },
    { checks: f.receipt.checks.map((check, index) => index ? check : { ...check, passed: false }) },
    { cleanup: { complete: false, remainingOwnedProcesses: 0 } },
    { cleanup: { complete: true, remainingOwnedProcesses: 1 } },
  ]) assert.throws(() => validateCandidateAcceptance({ ...f.receipt, ...altered }, f.expected));
});

test('candidate receipt must be private, ordinary, single-link and bounded', async t => {
  const f = await acceptanceFixture(t);
  const write = bytes => fs.writeFile(f.receiptPath, bytes, { flag: 'wx', mode: 0o600 });
  await write(JSON.stringify(f.receipt));
  assert.deepEqual(await readCandidateAcceptanceReceipt(f.receiptPath, f.expected), f.receipt);
  await fs.chmod(f.receiptPath, 0o644);
  await assert.rejects(readCandidateAcceptanceReceipt(f.receiptPath, f.expected), /Unsafe/);
  await fs.chmod(f.receiptPath, 0o600);
  const alias = f.receiptPath + '.alias'; await fs.link(f.receiptPath, alias);
  await assert.rejects(readCandidateAcceptanceReceipt(f.receiptPath, f.expected), /Unsafe/);
  await fs.unlink(alias); await fs.rename(f.receiptPath, alias); await fs.symlink(alias, f.receiptPath);
  await assert.rejects(readCandidateAcceptanceReceipt(f.receiptPath, f.expected), /Unsafe/);
  await fs.unlink(f.receiptPath); await fs.unlink(alias);
  await write(' '.repeat(64 * 1024 + 1));
  await assert.rejects(readCandidateAcceptanceReceipt(f.receiptPath, f.expected), /Unsafe/);
});

test('exact candidate runs with argv and private runtime, followed by independent idle checks', async t => {
  const f = await acceptanceFixture(t);
  assert.deepEqual(await runCandidateAcceptance(f.options), f.receipt);
  const call = f.calls.find(item => item.cmd === process.execPath);
  assert.deepEqual(call.args, [path.join(f.root, CANDIDATE_ACCEPTANCE_SCRIPT), '--app', f.app, '--runtime', f.runtime,
    '--evidence', f.evidence, '--receipt', f.receiptPath, '--source-commit', f.expected.sourceCommit,
    '--nonce', f.expected.nonce, '--candidate-manifest-sha256', f.expected.candidateManifestSHA256]);
  assert.equal(call.options.env.HOME, path.join(f.runtime, 'home'));
  assert.equal(call.options.env.TMPDIR, path.join(f.runtime, 'work') + path.sep);
  assert.deepEqual(Object.keys(call.options.env).sort(), ['HOME', 'LANG', 'LC_ALL', 'PATH', 'TEMP', 'TMP', 'TMPDIR', 'TZ', 'USERPROFILE']);
  assert.equal(call.options.shell, undefined);
  assert.equal(f.calls.filter(item => item.cmd === '/bin/ps').length, 2);
  assert.equal(f.calls.filter(item => item.cmd === '/usr/sbin/lsof').length, 4);
});

test('a stale receipt or changed signed candidate is refused before starting the runner', async t => {
  const f = await acceptanceFixture(t);
  await fs.writeFile(f.receiptPath, JSON.stringify(f.receipt), { mode: 0o600 });
  await assert.rejects(runCandidateAcceptance(f.options), /already exists/);
  await fs.unlink(f.receiptPath);
  await fs.writeFile(path.join(f.app, 'fixture'), 'changed');
  await assert.rejects(runCandidateAcceptance(f.options), /changed before/);
  assert.equal(f.runnerCalls(), 0);
});

test('candidate changes during an otherwise passing acceptance prevent archival', async t => {
  const f = await acceptanceFixture(t);
  await assert.rejects(runCandidateAcceptance({ ...f.options, run: async (cmd, ...args) => {
    const result = await f.run(cmd, ...args);
    if (cmd === process.execPath) await fs.writeFile(path.join(f.app, 'fixture'), 'changed by test');
    return result;
  } }), /changed during/);
});

test('a runner failure is retained when its owned-process inspection also fails', async t => {
  const f = await acceptanceFixture(t); let launched = false;
  await assert.rejects(runCandidateAcceptance({ ...f.options, run: async (cmd, args, options) => {
    if (cmd === process.execPath) { launched = true; return { code: 7, stdout: '', stderr: 'synthetic failure' }; }
    if (launched && cmd === '/usr/sbin/lsof') return { code: 0, stdout: 'p424242\nf1\n', stderr: '' };
    return f.run(cmd, args, options);
  } }), error => {
    assert.match(error.message, /runner did not complete/);
    assert.equal(error.candidateAcceptanceCleanupUncertain, true);
    assert.match(error.acceptanceCleanupErrors.join('\n'), /cleanup receipt could not be confirmed/);
    assert.match(error.acceptanceCleanupErrors.join('\n'), /still in use/);
    return true;
  });
});

test('a zero runner exit cannot replace a receipt or confirm uncertain termination', async t => {
  const f = await acceptanceFixture(t);
  const withoutReceipt = (cmd, args, options) => cmd === process.execPath
    ? { code: 0, stdout: '', stderr: '', closeConfirmed: true } : f.run(cmd, args, options);
  await assert.rejects(runCandidateAcceptance({ ...f.options, run: withoutReceipt }),
    error => error.code === 'ENOENT' && error.candidateAcceptanceCleanupUncertain === true);
  await assert.rejects(runCandidateAcceptance({ ...f.options, run: (cmd, args, options) => cmd === process.execPath
    ? { code: 0, stdout: '', stderr: '', closeConfirmed: false } : f.run(cmd, args, options) }),
  error => error.candidateAcceptanceCleanupUncertain === true);
});

test('a nonzero runner exit preserves incomplete resource cleanup even when all processes exited', async t => {
  const f = await acceptanceFixture(t);
  f.receipt.passed = false; f.receipt.cleanup.complete = false;
  await assert.rejects(runCandidateAcceptance({ ...f.options, run: async (cmd, ...args) => {
    const result = await f.run(cmd, ...args);
    return cmd === process.execPath ? { ...result, code: 1 } : result;
  } }), error => {
    assert.match(error.message, /runner did not complete/);
    assert.equal(error.candidateAcceptanceCleanupUncertain, true);
    assert.match(error.acceptanceCleanupErrors.join('\n'), /cleanup was not confirmed/);
    return true;
  });
  assert.equal(f.calls.filter(item => item.cmd === '/bin/ps').length, 2);
  assert.equal(f.calls.filter(item => item.cmd === '/usr/sbin/lsof').length, 4);
});

test('a failed acceptance check can confirm cleanup without granting publication', async t => {
  const f = await acceptanceFixture(t); f.receipt.passed = false;
  await assert.rejects(runCandidateAcceptance({ ...f.options, run: async (cmd, ...args) => {
    const result = await f.run(cmd, ...args);
    return cmd === process.execPath ? { ...result, code: 1 } : result;
  } }), error => {
    assert.match(error.message, /runner did not complete/);
    assert.equal(error.candidateAcceptanceCleanupUncertain, false);
    return true;
  });
});

test('reported incomplete cleanup and lingering runtime processes prevent acceptance', async t => {
  const f = await acceptanceFixture(t);
  f.receipt.cleanup.complete = false;
  await assert.rejects(runCandidateAcceptance(f.options), error => error.candidateAcceptanceCleanupUncertain === true);
  await fs.unlink(f.receiptPath); f.receipt.cleanup.complete = true;
  await assert.rejects(runCandidateAcceptance({ ...f.options, run: async (cmd, args, options) => {
    if (cmd === '/bin/ps') return { code: 0, stdout: `424242 1 424242 Wed Oct 28 01:02:03 2026 ${f.runtime}/owned-child\n`, stderr: '' };
    return f.run(cmd, args, options);
  } }), /still running/);
  assert.equal(f.runnerCalls(), 1);
});
