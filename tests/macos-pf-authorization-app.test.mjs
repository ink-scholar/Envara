import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { appendFile, chmod, mkdir, mkdtemp, readFile, realpath, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { buildPFLocalAuthorizationApp, inspectAuthorizationPayload, PF_AUTHORIZATION_INFO, validateAuthorizationPlan } from '../scripts/build-macos-pf-authorization-app.mjs';
import { PF_INSTALLATION_SCHEMA, PF_MANIFEST_FILES } from '../native/macos-pf-routing/controller.mjs';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const prior = 'f8fce1d14566fdf822d220ef1a3469cbb815a37924c7ed709a1098729b8bed8b';
const execute = promisify(execFile);
async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-local-auth-test-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const payload = path.join(root, 'payload'); await mkdir(payload);
  const files = {};
  for (const [name, executable] of Object.entries(PF_MANIFEST_FILES)) {
    const bytes = Buffer.from(`inert file fixture ${name}\n`), filename = path.join(payload, name);
    await mkdir(path.dirname(filename), { recursive: true }); await writeFile(filename, bytes, { mode: executable ? 0o755 : 0o644 });
    files[name] = digest(bytes);
  }
  const manifest = { schema: PF_INSTALLATION_SCHEMA, component: 'envara-pf-routing', platform: 'darwin', arch: 'arm64',
    ready: false, nativeAcceptance: false, files };
  const bytes = JSON.stringify(manifest) + '\n'; await writeFile(path.join(payload, 'manifest.json'), bytes, { mode: 0o644 });
  const installer = Buffer.from('inert authorization fixture; not executable code\n');
  await writeFile(path.join(payload, 'EnvaraPFInstall'), installer, { mode: 0o755 });
  const options = { resourceRoot: payload, expectedManifestSHA256: digest(bytes), originalInstallerSHA256: digest(installer) };
  const plan = source => ({ schema: 'envara.macos-pf-install/v1', action: 'installedResourcesOnly', readOnly: true, sourceVerified: true,
    ready: false, productionReady: false, systemInstallation: false, activation: false, requiresAppleDeveloperIdentity: false,
    bootstrapIdentityBound: false, manifestSHA256: digest(bytes), source, existingInstallation: 'known-prior',
    priorManifestSHA256: prior, requiresUpgradeApproval: true,
    operations: { copyFixedResources: true, changePF: false, createGroups: false, createTunnel: false, startDaemon: false, launchApplication: false } });
  return { root, payload, options, plan };
}

test('local carrier Info.plist fixes the authorization main executable and background App role', () => {
  assert.match(PF_AUTHORIZATION_INFO, /<key>CFBundleExecutable<\/key><string>EnvaraPFAuthorization<\/string>/);
  assert.match(PF_AUTHORIZATION_INFO, /<key>LSUIElement<\/key><true\/>/);
  assert.match(PF_AUTHORIZATION_INFO, /io\.envara\.pf-authorization\.local/);
});

test('payload verification detects runtime changes, mode changes and unlisted or symlink leaves', async t => {
  for (const variant of ['exact', 'runtime', 'mode', 'extra', 'empty-directory', 'symlink']) {
    const value = await fixture(t), file = path.join(value.payload, 'node');
    if (variant === 'runtime') await appendFile(file, 'changed');
    if (variant === 'mode') await chmod(file, 0o644);
    if (variant === 'extra') await writeFile(path.join(value.payload, 'unlisted'), 'unknown');
    if (variant === 'empty-directory') await mkdir(path.join(value.payload, 'unknown-empty'));
    if (variant === 'symlink') { await rm(file); await symlink('mihomo', file); }
    if (variant === 'exact') assert.equal((await inspectAuthorizationPayload(value.options)).verified, true);
    else await assert.rejects(inspectAuthorizationPayload(value.options));
  }
});

test('installer and official runtime bytes remain fixed despite carrier signing', async t => {
  const value = await fixture(t); await appendFile(path.join(value.payload, 'EnvaraPFInstall'), 'owned mock signature');
  await assert.rejects(inspectAuthorizationPayload(value.options), /Original installer bytes differ/);
  const second = await fixture(t); await appendFile(path.join(second.payload, 'mihomo'), 'invalid runtime signature change');
  await assert.rejects(inspectAuthorizationPayload(second.options), /mihomo differs from fixed runtime bytes/);
});

test('read-only authorizer plan rejects readiness, network operations or a different prior snapshot', async t => {
  const value = await fixture(t), original = value.plan(value.payload);
  assert.equal(validateAuthorizationPlan(original, value.options.expectedManifestSHA256).requiresUpgradeApproval, true);
  for (const altered of [{ ...original, ready: true }, { ...original, systemInstallation: true },
    { ...original, bootstrapIdentityBound: true }, { ...original, priorManifestSHA256: '0'.repeat(64) },
    { ...original, requiresUpgradeApproval: false }, { ...original, operations: { ...original.operations, changePF: true } }])
    assert.throws(() => validateAuthorizationPlan(altered, value.options.expectedManifestSHA256));
});

test('later updates accept only fixed reviewed priors and report private runtime inspection honestly', async t => {
  const value = await fixture(t), original = value.plan(value.payload);
  for (const priorManifestSHA256 of [
    'e940e171ac39624cd3cfeaea09234f4e8e035bfba141a843950cb0209e00db04',
    '518a75d94bac4f17d9e1ce60e842648ba6ff657a68cc62e95ce13718abda6d5a',
    '2a7f4ad635041c434b511034e9535b688cee8eeaebce97617586ad142db5f02d',
    '83256899dc6db90bb6a21dcd18d17cb08a46d3ba4e79177098629475cc107f78',
    'ff9f6a77bb8eeb105e35ce9b9bdd55f69d2995ab63d8f64f42b7004d7899951b',
  '6f8386e1586af12775c9aadd1de339568d29cf93dc4135d8de00b8661407026f',
  '199ff3f1e9b5c36a41f27903db0c592471516d35c44147803b3e09fc6bb29053',
  '46ae6acddd4f7b0a941bfbf6d6cc12aaedf59dd0c681b9aa440e72c38536d56b',
  'c37c49f9ca94b285d7b362ee4a42a01203d3632874d803e90ff38e48dd66c5e0',
  'f99aac934122ac3cafe992ac6fbf232ff917c1b8632034d19491b3dca7ab0d51',
  '05d6eb6ab3d63870d37825b47e2847789a6b5b8c3cf93c434636e0b8aad4f061',
  '14b87d3452af4acaf67709c2494d637163d108a101f6d07fb27ce8e61c2d1d50',
  'dbcf5262ae01da769a85d1f4c104b9f3402d3b54b69e7c6ff862ea871e85c56d',
  '43b392665e496cba2bc2675284fd2d03390ea92db85496d07e49ba696cd7c2a7',
  'acfc112b497c680001c7ce37dcdc99021b51de615072b15c096895900ecfa0c6',
  'c34cba313dad0712fc53eaea514d8466c6710eb70cc7840a1ca4238eea3817e4',
  ]) {
  const inspected = { ...original, priorManifestSHA256,
    privateRuntimeInspectionRequired: true, controlledRuntimeAbsent: false, canRequestAuthorizationForInspection: true,
    reason: 'privileged-runtime-inspection-required' };
  assert.equal(validateAuthorizationPlan(inspected, value.options.expectedManifestSHA256).controlledRuntimeAbsent, false);
  assert.throws(() => validateAuthorizationPlan({ ...inspected, controlledRuntimeAbsent: true }, value.options.expectedManifestSHA256),
    /Private content not observed/);
  assert.throws(() => validateAuthorizationPlan({ ...inspected, priorManifestSHA256: '1'.repeat(64) }, value.options.expectedManifestSHA256),
    /fixed reviewed prior/);
  assert.throws(() => validateAuthorizationPlan({ ...inspected, canRequestAuthorizationForInspection: false }, value.options.expectedManifestSHA256),
    /administrator inspection/);
  assert.throws(() => validateAuthorizationPlan({ ...inspected, priorManifestSHA256: `${priorManifestSHA256.slice(0, 63)}${priorManifestSHA256.endsWith('0') ? '1' : '0'}` }, value.options.expectedManifestSHA256),
    /fixed reviewed prior/);
  }
});

// The following construction fixtures are inert bytes. Only system command
// boundaries are stubbed: no binary, codesign, authorization or runtime starts.
function builderDependencies(value, calls, mutateRuntime = false) {
  return {
    inspectResources: async ({ resourceRoot }) => { assert.equal(resourceRoot, value.payload); return { verified: true }; },
    exec: async (command, args, options) => {
      calls.push({ command, args }); assert.deepEqual(options.env, { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' });
      if (command === '/usr/bin/clang') {
        assert.deepEqual(args.slice(0, 5), ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror']);
        await writeFile(args.at(-1), 'inert launcher fixture', { mode: 0o755 }); return { stdout: '' };
      }
      if (command === '/usr/bin/plutil') { assert.equal(args[0], '-lint'); return { stdout: '' }; }
      if (command === '/usr/bin/codesign') {
        assert.equal(args.includes('--deep'), false); const target = args.at(-1);
        if (args[0] === '--force') {
          assert.deepEqual(args.slice(0, -1), ['--force', '--sign', '-', '--timestamp=none']);
          assert.ok(target.endsWith('.app') || target.endsWith('/EnvaraPFAuthorization'));
          if (target.endsWith('/EnvaraPFAuthorization')) await appendFile(target, '\nowned mock signature');
          if (mutateRuntime && target.endsWith('.app')) await appendFile(path.join(target, 'Contents/Resources/app-routing/macos-pf/node'), 'bad resign');
        } else assert.deepEqual(args.slice(0, -1), ['--verify', '--strict', '--verbose=4']);
        return { stdout: '' };
      }
      assert.ok(command.endsWith('/EnvaraPFInstall')); assert.deepEqual(args, ['--plan']);
      return { stdout: JSON.stringify(value.plan(path.dirname(command))) };
    },
  };
}

test('builder copies the exact payload, signs only main and outer App, and runs only read-only plan', async t => {
  const value = await fixture(t), calls = [], output = path.join(value.root, 'local/Reviewed.app');
  const report = await buildPFLocalAuthorizationApp({ root: value.root, payload: value.payload, output, platform: 'darwin', ...builderDependencies(value, calls) });
  assert.equal(report.authorizerPath, path.join(output, 'Contents/Resources/app-routing/macos-pf/EnvaraPFInstall'));
  assert.equal(report.resourceContract.verified, true); assert.equal(report.ready, false); assert.equal(report.authorized, false);
  assert.equal(report.readOnlyPlan.requiresUpgradeApproval, true); assert.equal(report.manifestSHA256, value.options.expectedManifestSHA256);
  assert.equal(report.postSignAuthorizerSHA256, report.originalInstallerSHA256);
  assert.equal(report.installerResigned, false);
  assert.equal((await inspectAuthorizationPayload(value.options)).verified, true, 'source payload remains untouched');
  const signTargets = calls.filter(call => call.command === '/usr/bin/codesign' && call.args[0] === '--force').map(call => call.args.at(-1));
  assert.equal(signTargets.length, 2); assert.ok(signTargets[0].endsWith('/EnvaraPFAuthorization')); assert.ok(signTargets[1].endsWith('.app'));
  assert.equal(calls.some(call => call.args.some(arg => arg.startsWith('--request'))), false);
  assert.equal(await readFile(path.join(output, 'Contents/Info.plist'), 'utf8'), PF_AUTHORIZATION_INFO);
});

test('builder refuses to overwrite an existing App and removes only its own failed new stage', async t => {
  const value = await fixture(t), output = path.join(value.root, 'PreviousFull.app'); await mkdir(output);
  await writeFile(path.join(output, 'preserve'), 'old full App'); const calls = [];
  await assert.rejects(buildPFLocalAuthorizationApp({ root: value.root, payload: value.payload, output, platform: 'darwin', ...builderDependencies(value, calls) }), /existing App must be preserved/);
  assert.equal(await readFile(path.join(output, 'preserve'), 'utf8'), 'old full App'); assert.deepEqual(calls, []);
  const fresh = path.join(value.root, 'New.app');
  await assert.rejects(buildPFLocalAuthorizationApp({ root: value.root, payload: value.payload, output: fresh, platform: 'darwin', ...builderDependencies(value, calls, true) }), /node differs from fixed runtime bytes/);
  await assert.rejects(readFile(path.join(fresh, 'Contents/Info.plist')), { code: 'ENOENT' });
  assert.equal((await readdir(value.root)).some(name => name.startsWith('.EnvaraPFAuthorization-')), false);
  assert.equal((await inspectAuthorizationPayload(value.options)).verified, true);
});

test('real native carrier resolves only its own fixed resource installer and refuses extra arguments and symlinks', { skip: process.platform !== 'darwin' }, async t => {
  const value = await fixture(t), app = path.join(value.root, 'NativeFixture.app');
  const main = path.join(app, 'Contents/MacOS/EnvaraPFAuthorization');
  const installer = path.join(app, 'Contents/Resources/app-routing/macos-pf/EnvaraPFInstall');
  await mkdir(path.dirname(main), { recursive: true }); await mkdir(path.dirname(installer), { recursive: true });
  const stub = path.join(value.root, 'inert-installer.c');
  await writeFile(stub, '#include <stdio.h>\n#include <string.h>\nint main(int argc,char **argv){if(argc!=2||strcmp(argv[1],"--plan"))return 90;puts("owned-plan-only-fixture");return 0;}\n');
  for (const [source, target] of [[fileURLToPath(new URL('../native/macos-pf-authorization/launcher.c', import.meta.url)), main], [stub, installer]]) {
    const result = await execute('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', source, '-o', target], { timeout: 30000 });
    assert.equal(result.stderr, '', 'native carrier and inert stub must compile without warnings');
  }
  for (const args of [[], ['--plan']]) assert.equal((await execute(main, args, { timeout: 5000 })).stdout, 'owned-plan-only-fixture\n');
  for (const args of [['--exec'], ['--plan', '/untrusted']]) {
    await assert.rejects(execute(main, args, { timeout: 5000 }), error => error.code === 1 && error.signal == null && /fixed-operation-or-resource-unavailable/.test(error.stderr));
  }
  await rm(installer); await symlink(path.join(value.payload, 'EnvaraPFInstall'), installer);
  await assert.rejects(execute(main, ['--plan'], { timeout: 5000 }), error => error.code === 1 && error.signal == null);
});
