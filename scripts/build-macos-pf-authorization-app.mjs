// Local reviewed authorization carrier only. Never requests rights or activates
// the component; official runtime binaries are copied without re-signing.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, open, readFile, readdir, realpath, rename, rm, rmdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { PF_INSTALLATION_SCHEMA, PF_MANIFEST_FILES } from '../native/macos-pf-routing/controller.mjs';
import { inspectPFRoutingResources } from './verify-package-resources.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const execute = promisify(execFile);
const KNOWN_PRIORS = new Set([
  'f8fce1d14566fdf822d220ef1a3469cbb815a37924c7ed709a1098729b8bed8b',
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
  '4b9f859585a10e31eb98d43682595a9e152b3f93439ebea6ef1de0a4659ba557',
  '43392e3095a921e1531d459a93d5d7329bfc5a28bab5192179eb1fc4fadd0fce',
  'f0b99f600185ecadd9c862fe826193a52e348cde3fb77d353ab5bd7471ab1bfc',
  'f39101dd94c622c886ca6709f2f13f8c826cdd1f3fe609112d5445ad2fd6f305',
  'a8bd008ae1b54f656e52ecba509e706811df386ac7a2b12bb269cd095fc74575',
  'da6e7c9714ec57781f68d875d131e9ee178adbaab401793a153ac7b216ceef05',
  '03245359a948d31c9f4b87fe88dd1b3cb6a270228fbfc13fe873de50cdcce7da',
  '2059a0870f88f6fa6caa89c9dbd751e41ee3b2cbf4101933c8519efa32f08b68',
  '127e8354fbc420e8c12e32a439129a517d2bad0e2950347fc18efaa6c24e9377',
  '010117dbf9fb8bf28ebc5ef92de19235d34774ef114c8c86b4ee3feda48c2374',
  '9b51cf9b161d1add0ea86049adc535ea298b6bb6e44ff7496989cd0662fa4743',
  '91b62aeeb17c2f38339f5e749b996e30537cbf9d36434acd830ec496882d38a8',
  '7c91a10d3935887a082f8602d74c1d5d188b5870ebba452d429953f17c704ed2',
  'af79b180ede3776f94ac057c8558f8eb8629fcdc7d690be7c91543bd40e7a63e',
  'dceba9d272ef7cb74fbfb09cc2e15eb0108a838183ba8841da734c5409babbe4',
  'fa70a2ff212cf478f2165e086288815c9bd87c8c9538b40c5d75186a4398a7d4',
  '32811e9718b4c803c23b79f90828131709f6d0e139bc6713fd3482b0122214bb',
  '22a6f3ea8e9354c3b32b488c50e8ae6ab0d9c5aa565a80911b1848f40aea87de',
  '78c3fcff00b6d66273290fb38e1bbfd14811b3ca6af81fe92baa87bd72e091e4',
  'fb74d63e38710d8129e409cc72840b6a8bfc0ac3917de4905d7d5357e61c66f2',
  '554c5ac706c108b7530842a4a5e156e095004ad0fb11e3fe821b255ac2ab6f2e',
  '2af8c63918675c5ccca1d46fd763e462ea8cefabd6cc41ebdcefa85bc45049b6',
  '005f91acca0cecfc7ef7c2f731e9a7e178a6a8268e88a048caf54ac762047dcc',
  '88f8c7363d7b689829e712b39f26c09ca9856685cc71fd8b1e05cbeb43027715',
  '0b6d9bffd6629d4855bf44b5d7f2e99b88e9732020cd84f72919dcae35020a13',
  '03596ac0849e4e91a39367934e7555ab166eb9084a5ca2bb15a3a0230b9d0539',
]);
const LEAVES = [...Object.keys(PF_MANIFEST_FILES), 'manifest.json', 'EnvaraPFInstall'].sort();
const within = (base, target) => target === base || (!path.relative(base, target).startsWith('../') && !path.isAbsolute(path.relative(base, target)));
export const PF_AUTHORIZATION_INFO = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>io.envara.pf-authorization.local</string>
<key>CFBundleName</key><string>Envara PF Authorization</string>
<key>CFBundleExecutable</key><string>EnvaraPFAuthorization</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>LSUIElement</key><true/>
</dict></plist>
`;

async function fileHash(filename) {
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    assert.ok(before.isFile() && before.nlink === 1, 'Authorization resources must be ordinary single-link files');
    const hash = createHash('sha256');
    for await (const chunk of handle.createReadStream({ autoClose: false })) hash.update(chunk);
    const after = await handle.stat();
    assert.ok(['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs', 'nlink'].every(key => before[key] === after[key]),
      'Authorization resource changed while hashing');
    return { sha256: hash.digest('hex'), mode: before.mode & 0o7777, bytes: before.size };
  } finally { await handle.close(); }
}

async function leaves(root, prefix = '') {
  assert.ok(prefix.split('/').length <= 64, 'Authorization resource nesting is excessive');
  const result = [];
  for (const name of (await readdir(path.join(root, prefix))).sort()) {
    const relative = prefix ? `${prefix}/${name}` : name, info = await lstat(path.join(root, relative));
    assert.ok(!info.isSymbolicLink(), 'Authorization resources must not contain symlinks');
    if (info.isDirectory()) {
      assert.ok(LEAVES.some(leaf => leaf.startsWith(`${relative}/`)), 'Authorization payload directory inventory differs');
      result.push(...await leaves(root, relative));
    }
    else { assert.ok(info.isFile() && info.nlink === 1, 'Authorization resource type or link count differs'); result.push(relative); }
  }
  return result.sort();
}

/** Compares all permitted payload leaves, including the untouched original
 * installer. Only the separate native carrier main is ad-hoc signed. */
export async function inspectAuthorizationPayload({ resourceRoot, expectedManifestSHA256, originalInstallerSHA256 } = {}) {
  assert.ok(path.isAbsolute(resourceRoot ?? ''), 'Authorization payload root must be absolute');
  assert.deepEqual(await leaves(resourceRoot), LEAVES, 'Authorization payload leaf inventory differs');
  const manifestRecord = await fileHash(path.join(resourceRoot, 'manifest.json'));
  assert.equal(manifestRecord.sha256, expectedManifestSHA256, 'Authorization manifest differs');
  const manifest = JSON.parse(await readFile(path.join(resourceRoot, 'manifest.json'), 'utf8'));
  assert.equal(manifest.schema, PF_INSTALLATION_SCHEMA); assert.equal(manifest.component, 'envara-pf-routing');
  assert.equal(manifest.platform, 'darwin'); assert.ok(['arm64', 'x64'].includes(manifest.arch));
  assert.equal(manifest.ready, false); assert.equal(manifest.nativeAcceptance, false);
  assert.deepEqual(Object.keys(manifest.files).sort(), Object.keys(PF_MANIFEST_FILES).sort(), 'Authorization manifest inventory differs');
  const records = {};
  for (const name of LEAVES) {
    const record = await fileHash(path.join(resourceRoot, name));
    assert.equal(record.mode, (PF_MANIFEST_FILES[name] || name === 'EnvaraPFInstall') ? 0o755 : 0o644, `${name} mode differs`);
    if (name !== 'manifest.json' && name !== 'EnvaraPFInstall') assert.equal(record.sha256, manifest.files[name], `${name} differs from fixed runtime bytes`);
    if (name === 'EnvaraPFInstall') assert.equal(record.sha256, originalInstallerSHA256, 'Original installer bytes differ');
    records[name] = record;
  }
  return { verified: true, leafInventoryExact: true, manifestSHA256: manifestRecord.sha256, arch: manifest.arch,
    installerSHA256: records.EnvaraPFInstall.sha256, runtimeFilesUnchanged: true, officialRuntimesResigned: false,
    files: records, ready: false, productionReady: false };
}

export function validateAuthorizationPlan(plan, manifestSHA256) {
  assert.equal(plan?.schema, 'envara.macos-pf-install/v1'); assert.equal(plan.action, 'installedResourcesOnly');
  for (const key of ['readOnly', 'sourceVerified']) assert.equal(plan[key], true, `Authorization plan ${key} differs`);
  for (const key of ['ready', 'productionReady', 'systemInstallation', 'activation', 'requiresAppleDeveloperIdentity', 'bootstrapIdentityBound'])
    assert.equal(plan[key], false, `Authorization plan ${key} must remain false`);
  assert.equal(plan.manifestSHA256, manifestSHA256);
  if (plan.existingInstallation === 'known-prior') {
    assert.ok(KNOWN_PRIORS.has(plan.priorManifestSHA256), 'Only a fixed reviewed prior snapshot is accepted');
    assert.equal(plan.requiresUpgradeApproval, true);
  }
  if (plan.privateRuntimeInspectionRequired === true) {
    assert.equal(plan.controlledRuntimeAbsent, false, 'Private content not observed must not be claimed absent');
    assert.equal(plan.canRequestAuthorizationForInspection, true, 'Private runtime needs a permitted administrator inspection');
    assert.equal(plan.reason, 'privileged-runtime-inspection-required');
  }
  assert.deepEqual(plan.operations, { copyFixedResources: true, changePF: false, createGroups: false,
    createTunnel: false, startDaemon: false, launchApplication: false });
  return plan;
}

export async function buildPFLocalAuthorizationApp({ root = ROOT, payload = path.join(root, 'build/app-routing/macos-pf'), output,
  platform = process.platform, exec = execute, inspectResources = inspectPFRoutingResources } = {}) {
  assert.equal(platform, 'darwin', 'The local authorization carrier is macOS only');
  assert.ok(path.isAbsolute(root) && path.isAbsolute(payload), 'Build inputs must be absolute paths');
  assert.equal(await realpath(payload), payload, 'Payload directory must be canonical');
  assert.ok((await lstat(payload)).isDirectory(), 'Payload must be a directory');
  const source = await inspectResources({ resourceRoot: payload, arch: process.arch, sourceRoot: root });
  assert.equal(source.verified, true, 'Source build must be verified before copying');
  const manifestSHA256 = (await fileHash(path.join(payload, 'manifest.json'))).sha256;
  const originalInstallerSHA256 = (await fileHash(path.join(payload, 'EnvaraPFInstall'))).sha256;
  output ??= path.join(root, 'build/local-authorization', `EnvaraPFAuthorization-${manifestSHA256.slice(0, 12)}.app`);
  assert.ok(path.isAbsolute(output) && output.endsWith('.app'), 'Output must be an absolute local App path');
  assert.ok(!within(payload, output) && !within(output, payload), 'App and payload must not overlap');
  await mkdir(path.dirname(output), { recursive: true });
  assert.equal(await realpath(path.dirname(output)), path.dirname(output), 'Output parent must be canonical');
  await assert.rejects(lstat(output), { code: 'ENOENT' }, 'An existing App must be preserved; choose a fresh output path');
  const stage = path.join(path.dirname(output), `.EnvaraPFAuthorization-${randomUUID()}.app`);
  let committed = false;
  try {
    const macOS = path.join(stage, 'Contents/MacOS'), resources = path.join(stage, 'Contents/Resources/app-routing/macos-pf');
    await mkdir(macOS, { recursive: true }); await mkdir(resources, { recursive: true });
    await writeFile(path.join(stage, 'Contents/Info.plist'), PF_AUTHORIZATION_INFO, { mode: 0o644 });
    for (const name of LEAVES) {
      const destination = path.join(resources, name); await mkdir(path.dirname(destination), { recursive: true });
      await copyFile(path.join(payload, name), destination, constants.COPYFILE_FICLONE);
      await chmod(destination, (PF_MANIFEST_FILES[name] || name === 'EnvaraPFInstall') ? 0o755 : 0o644);
    }
    await inspectAuthorizationPayload({ resourceRoot: resources, expectedManifestSHA256: manifestSHA256, originalInstallerSHA256 });
    const options = { timeout: 30000, maxBuffer: 1024 * 1024, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' } };
    const launcherSource = path.join(ROOT, 'native/macos-pf-authorization/launcher.c');
    const launcherSourceSHA256 = (await fileHash(launcherSource)).sha256, launcher = path.join(macOS, 'EnvaraPFAuthorization');
    await exec('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', launcherSource, '-o', launcher], options);
    assert.equal((await fileHash(launcherSource)).sha256, launcherSourceSHA256, 'Carrier source changed during compilation');
    await exec('/usr/bin/plutil', ['-lint', path.join(stage, 'Contents/Info.plist')], options);
    await exec('/usr/bin/codesign', ['--force', '--sign', '-', '--timestamp=none', launcher], options);
    await exec('/usr/bin/codesign', ['--force', '--sign', '-', '--timestamp=none', stage], options);
    const contract = await inspectAuthorizationPayload({ resourceRoot: resources, expectedManifestSHA256: manifestSHA256,
      originalInstallerSHA256 });
    assert.deepEqual(await readdir(macOS), ['EnvaraPFAuthorization'], 'Only the fixed launcher belongs in MacOS');
    await exec('/usr/bin/codesign', ['--verify', '--strict', '--verbose=4', stage], options);
    await exec('/usr/bin/codesign', ['--verify', '--strict', '--verbose=4', launcher], options);
    await exec('/usr/bin/codesign', ['--verify', '--strict', '--verbose=4', path.join(resources, 'EnvaraPFInstall')], options);
    const postSignLauncherSHA256 = (await fileHash(launcher)).sha256;
    const untouchedSource = await inspectResources({ resourceRoot: payload, arch: process.arch, sourceRoot: root });
    assert.equal(untouchedSource.verified, true);
    assert.equal((await fileHash(path.join(payload, 'EnvaraPFInstall'))).sha256, originalInstallerSHA256, 'Source installer must remain unchanged');
    // Claim the final App with exclusive mkdir. A concurrent pre-existing
    // directory must never be replaced by ordinary POSIX rename semantics.
    await mkdir(output);
    await rename(path.join(stage, 'Contents'), path.join(output, 'Contents'));
    await rmdir(stage); committed = true;
    const authorizerPath = path.join(output, 'Contents/Resources/app-routing/macos-pf/EnvaraPFInstall');
    await exec('/usr/bin/codesign', ['--verify', '--strict', '--verbose=4', output], options);
    const result = await exec(authorizerPath, ['--plan'], options);
    const plan = validateAuthorizationPlan(JSON.parse(result.stdout), manifestSHA256);
    assert.equal(plan.source, path.dirname(authorizerPath), 'Authorizer must inspect its own executable directory');
    const report = { schema: 'envara.local-pf-authorization-app/v1', generatedAt: new Date().toISOString(), appPath: output,
      authorizerPath, manifestSHA256, originalInstallerSHA256, postSignAuthorizerSHA256: contract.installerSHA256,
      launcherSource, launcherSourceSHA256, postSignLauncherSHA256, sourceBuildVerified: true,
      adHocOuterAndMainOnly: true, installerResigned: false, signaturesStrictVerified: true, resourceContract: contract,
      readOnlyPlan: plan, localDevelopmentOnly: true, published: false, installed: false, authorized: false,
      reviewableForInstallation: plan.canRequestInstall === true && plan.needsManualReview === false,
      bootstrapIdentityBound: false, ready: false, productionReady: false };
    const evidence = path.join(root, 'test-artifacts/mac-pf-routing', `authorization-bundle-${manifestSHA256.slice(0, 12)}.json`);
    await mkdir(path.dirname(evidence), { recursive: true }); await writeFile(evidence, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
    return { ...report, evidence };
  } finally {
    if (!committed) await rm(stage, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    assert.ok(process.argv.length === 2 || (process.argv.length === 4 && process.argv[2] === '--output'),
      'Only --output /absolute/fresh/App.app is accepted; no installation or activation options exist');
    const report = await buildPFLocalAuthorizationApp({ output: process.argv[3] });
    console.log(JSON.stringify({ appPath: report.appPath, authorizerPath: report.authorizerPath, manifestSHA256: report.manifestSHA256,
      postSignAuthorizerSHA256: report.postSignAuthorizerSHA256, resourceContractVerified: report.resourceContract.verified,
      requiresUpgradeApproval: report.readOnlyPlan.requiresUpgradeApproval, canRequestInstall: report.readOnlyPlan.canRequestInstall,
      reviewableForInstallation: report.reviewableForInstallation, ready: false, evidence: report.evidence }, null, 2));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
