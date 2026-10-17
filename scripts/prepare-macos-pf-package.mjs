// Prepares only the reviewed carrier for packaging. Never installs or activates.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { cp, lstat, mkdir, readFile, readdir, realpath, rename, rm, rmdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { buildPFLocalAuthorizationApp, inspectAuthorizationPayload, PF_AUTHORIZATION_INFO } from './build-macos-pf-authorization-app.mjs';
import { inspectPFRoutingResources } from './verify-package-resources.mjs';
import { parsePFPackageCandidate, PF_AUTHORIZATION_PACKAGE_DIRECTORY } from './macos-pf-package-contract.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const execute = promisify(execFile);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const exists = async filename => { try { await lstat(filename); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } };
const within = (base, target) => target === base || (!path.relative(base, target).startsWith(`..${path.sep}`) && !path.isAbsolute(path.relative(base, target)));

async function inventory(directory, prefix = '') {
  const rows = [];
  for (const name of (await readdir(path.join(directory, prefix))).sort()) {
    const relative = prefix ? `${prefix}/${name}` : name, filename = path.join(directory, relative), stat = await lstat(filename);
    assert.ok(!stat.isSymbolicLink(), `Package carrier must not contain symlinks: ${relative}`);
    if (stat.isDirectory()) rows.push({ path: relative, type: 'directory', mode: stat.mode & 0o7777 }, ...await inventory(directory, relative));
    else {
      assert.ok(stat.isFile() && stat.nlink === 1, `Package carrier must contain ordinary single-link files: ${relative}`);
      rows.push({ path: relative, type: 'file', mode: stat.mode & 0o7777, sha256: digest(await readFile(filename)) });
    }
  }
  return rows;
}

/** Verify an existing carrier against its original build receipt as well as the
 * reviewed payload. A newly signed replacement main cannot silently be reused. */
export async function inspectPFPackageCarrier({ app, candidate, root = ROOT, evidence, exec = execute } = {}) {
  assert.equal(await realpath(app), app, 'Carrier path must be canonical');
  assert.ok((await lstat(app)).isDirectory(), 'Carrier must be an ordinary directory');
  const payload = path.join(app, 'Contents/Resources/app-routing/macos-pf');
  const contract = await inspectAuthorizationPayload({ resourceRoot: payload,
    expectedManifestSHA256: candidate.manifestSHA256, originalInstallerSHA256: candidate.authorizerSHA256 });
  assert.equal(await readFile(path.join(app, 'Contents/Info.plist'), 'utf8'), PF_AUTHORIZATION_INFO, 'Carrier Info.plist differs');
  const rows = await inventory(app), prefix = 'Contents/Resources/app-routing/macos-pf/';
  const leaves = rows.filter(row => row.type === 'file').map(row => row.path);
  assert.deepEqual(leaves.filter(name => !name.startsWith(prefix)), [
    'Contents/Info.plist', 'Contents/MacOS/EnvaraPFAuthorization', 'Contents/_CodeSignature/CodeResources']);
  const allowedDirs = new Set(['Contents', 'Contents/MacOS', 'Contents/_CodeSignature', 'Contents/Resources',
    'Contents/Resources/app-routing', 'Contents/Resources/app-routing/macos-pf']);
  for (const name of leaves) for (let parent = path.posix.dirname(name); parent !== '.'; parent = path.posix.dirname(parent)) allowedDirs.add(parent);
  assert.ok(rows.filter(row => row.type === 'directory').every(row => allowedDirs.has(row.path)), 'Unlisted carrier directory');
  evidence ??= path.join(root, 'test-artifacts/mac-pf-routing', `authorization-bundle-${candidate.manifestSHA256.slice(0, 12)}.json`);
  const receipt = JSON.parse(await readFile(evidence, 'utf8'));
  assert.equal(receipt.schema, 'envara.local-pf-authorization-app/v1');
  assert.equal(receipt.manifestSHA256, candidate.manifestSHA256);
  assert.equal(receipt.originalInstallerSHA256, candidate.authorizerSHA256);
  assert.equal(receipt.postSignAuthorizerSHA256, candidate.authorizerSHA256);
  for (const key of ['sourceBuildVerified', 'adHocOuterAndMainOnly', 'signaturesStrictVerified']) assert.equal(receipt[key], true);
  assert.equal(receipt.installerResigned, false);
  const launcher = path.join(app, 'Contents/MacOS/EnvaraPFAuthorization');
  assert.equal(digest(await readFile(launcher)), receipt.postSignLauncherSHA256, 'Carrier main differs from its build receipt');
  assert.equal(digest(await readFile(path.join(root, 'native/macos-pf-authorization/launcher.c'))), receipt.launcherSourceSHA256,
    'Carrier launcher source differs from its build receipt');
  const options = { timeout: 30000, maxBuffer: 1024 * 1024, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' } };
  for (const filename of [app, launcher, path.join(payload, 'EnvaraPFInstall')])
    await exec('/usr/bin/codesign', ['--verify', '--strict', '--verbose=4', filename], options);
  return { verified: true, rows, resourceContract: contract };
}

export async function prepareMacOSPFPackage({ root = ROOT, payload = path.join(root, 'build/app-routing/macos-pf'),
  carrierRoot = path.join(root, 'build/local-authorization'), output = path.join(root, PF_AUTHORIZATION_PACKAGE_DIRECTORY),
  evidence, platform = process.platform, exec = execute, inspectResources = inspectPFRoutingResources,
  buildCarrier = buildPFLocalAuthorizationApp } = {}) {
  assert.equal(platform, 'darwin', 'PF package preparation is macOS only');
  for (const filename of [root, payload, carrierRoot, output]) assert.ok(path.isAbsolute(filename), 'Package inputs must be absolute paths');
  assert.equal(await realpath(root), root, 'Source root must be canonical');
  assert.equal(await realpath(payload), payload, 'Payload path must be canonical');
  for (const input of [payload, carrierRoot]) assert.ok(!within(input, output) && !within(output, input), 'Package stage must not overlap source inputs');
  const candidate = parsePFPackageCandidate(await readFile(path.join(root, 'electron/macos-pf-notion-trial.mjs'), 'utf8'));
  await inspectAuthorizationPayload({ resourceRoot: payload, expectedManifestSHA256: candidate.manifestSHA256,
    originalInstallerSHA256: candidate.authorizerSHA256 });
  assert.equal((await inspectResources({ resourceRoot: payload, arch: process.arch, sourceRoot: root })).verified, true,
    'Prepared PF source build must be verified');
  await mkdir(carrierRoot, { recursive: true });
  assert.equal(await realpath(carrierRoot), carrierRoot, 'Carrier root must be canonical');
  const app = path.join(carrierRoot, candidate.carrierName);
  let built = false;
  if (!await exists(app)) {
    const report = await buildCarrier({ root, payload, output: app, platform, exec, inspectResources });
    evidence ??= report.evidence; built = true;
  }
  const source = await inspectPFPackageCarrier({ app, candidate, root, evidence, exec });
  await mkdir(path.dirname(output), { recursive: true });
  assert.equal(await realpath(path.dirname(output)), path.dirname(output), 'Package parent must be canonical');
  const lock = `${output}.lock`;
  await mkdir(lock); // Exclusive; never replace another preparation in progress.
  let stage;
  try {
    if (await exists(output)) {
      assert.equal(await realpath(output), output, 'Existing stage must be canonical');
      assert.deepEqual(await readdir(output), [candidate.carrierName],
        'Existing package stage differs; preserve it in an archive before preparing the new reviewed candidate');
      const current = await inspectPFPackageCarrier({ app: path.join(output, candidate.carrierName), candidate, root, evidence, exec });
      assert.deepEqual(current.rows, source.rows, 'Existing package stage differs from the selected carrier');
    } else {
      stage = `${output}.stage-${randomUUID()}`;
      await mkdir(stage);
      await cp(app, path.join(stage, candidate.carrierName), { recursive: true, preserveTimestamps: true, verbatimSymlinks: true,
        mode: constants.COPYFILE_FICLONE, errorOnExist: true, force: false });
      const copied = await inspectPFPackageCarrier({ app: path.join(stage, candidate.carrierName), candidate, root, evidence, exec });
      assert.deepEqual(copied.rows, source.rows, 'Staged carrier differs from selected source bytes');
      // Claim the destination without overwriting anything that appeared during copying.
      await mkdir(output);
      await rename(path.join(stage, candidate.carrierName), path.join(output, candidate.carrierName));
      await rmdir(stage); stage = undefined;
    }
    assert.deepEqual((await inspectPFPackageCarrier({ app, candidate, root, evidence, exec })).rows, source.rows,
      'Source carrier changed while preparing package');
    return { schema: 'envara.pf-package-preparation/v1', verified: true, output,
      carrier: path.join(output, candidate.carrierName), candidate, builtCarrier: built,
      preservedOtherCarriers: true, installed: false, activated: false };
  } finally {
    if (stage) await rm(stage, { recursive: true, force: true });
    await rmdir(lock);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const options = {};
    for (let index = 2; index < process.argv.length; index += 2) {
      const names = { '--payload': 'payload', '--carrier-root': 'carrierRoot', '--output': 'output', '--evidence': 'evidence' };
      const key = names[process.argv[index]], value = process.argv[index + 1];
      assert.ok(key && value && path.isAbsolute(value) && !Object.hasOwn(options, key), 'Use unique --payload, --carrier-root, --output or --evidence absolute paths only');
      options[key] = value;
    }
    console.log(JSON.stringify(await prepareMacOSPFPackage(options), null, 2));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
