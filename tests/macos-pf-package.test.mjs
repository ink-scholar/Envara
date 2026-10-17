import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { appendFile, cp, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PF_MANIFEST_FILES, PF_INSTALLATION_SCHEMA } from '../native/macos-pf-routing/controller.mjs';
import { PF_AUTHORIZATION_INFO } from '../scripts/build-macos-pf-authorization-app.mjs';
import { prepareMacOSPFPackage } from '../scripts/prepare-macos-pf-package.mjs';
import { parsePFPackageCandidate, PF_AUTHORIZATION_PACKAGE_DIRECTORY } from '../scripts/macos-pf-package-contract.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
async function fixture(t, existing = true) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-pf-package-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const payload = path.join(root, 'build/app-routing/macos-pf'), carrierRoot = path.join(root, 'build/local-authorization');
  await mkdir(payload, { recursive: true }); await mkdir(carrierRoot, { recursive: true });
  const files = {};
  for (const [name, executable] of Object.entries(PF_MANIFEST_FILES)) {
    const bytes = `inert ${name}\n`, filename = path.join(payload, name);
    await mkdir(path.dirname(filename), { recursive: true }); await writeFile(filename, bytes, { mode: executable ? 0o755 : 0o644 }); files[name] = hash(bytes);
  }
  const manifest = JSON.stringify({ schema: PF_INSTALLATION_SCHEMA, component: 'envara-pf-routing', platform: 'darwin', arch: 'arm64', ready: false, nativeAcceptance: false, files });
  const installer = 'inert original installer';
  await writeFile(path.join(payload, 'manifest.json'), manifest, { mode: 0o644 });
  await writeFile(path.join(payload, 'EnvaraPFInstall'), installer, { mode: 0o755 });
  const pin = `export const PF_NOTION_TRIAL_CANDIDATE = Object.freeze({\n  authorizerSHA256: '${hash(installer)}',\n  manifestSHA256: '${hash(manifest)}',\n});`;
  await mkdir(path.join(root, 'electron')); await writeFile(path.join(root, 'electron/macos-pf-notion-trial.mjs'), pin);
  await mkdir(path.join(root, 'native/macos-pf-authorization'), { recursive: true });
  await writeFile(path.join(root, 'native/macos-pf-authorization/launcher.c'), 'inert launcher source');
  const candidate = parsePFPackageCandidate(pin), app = path.join(carrierRoot, candidate.carrierName);
  const evidence = path.join(root, 'test-artifacts/mac-pf-routing', `authorization-bundle-${candidate.manifestSHA256.slice(0, 12)}.json`);
  const calls = [], buildCalls = [];
  async function buildCarrier(options) {
    buildCalls.push(options);
    await mkdir(path.join(app, 'Contents/MacOS'), { recursive: true });
    await mkdir(path.join(app, 'Contents/Resources/app-routing'), { recursive: true });
    await cp(payload, path.join(app, 'Contents/Resources/app-routing/macos-pf'), { recursive: true });
    await mkdir(path.join(app, 'Contents/_CodeSignature'));
    await writeFile(path.join(app, 'Contents/Info.plist'), PF_AUTHORIZATION_INFO);
    await writeFile(path.join(app, 'Contents/MacOS/EnvaraPFAuthorization'), 'inert carrier main', { mode: 0o755 });
    await writeFile(path.join(app, 'Contents/_CodeSignature/CodeResources'), 'inert signature');
    await mkdir(path.dirname(evidence), { recursive: true });
    await writeFile(evidence, JSON.stringify({ schema: 'envara.local-pf-authorization-app/v1', manifestSHA256: candidate.manifestSHA256,
      originalInstallerSHA256: candidate.authorizerSHA256, postSignAuthorizerSHA256: candidate.authorizerSHA256,
      sourceBuildVerified: true, adHocOuterAndMainOnly: true, signaturesStrictVerified: true, installerResigned: false,
      postSignLauncherSHA256: hash('inert carrier main'), launcherSourceSHA256: hash('inert launcher source') }));
    return { evidence };
  }
  if (existing) { await buildCarrier({}); buildCalls.length = 0; }
  const options = { root, platform: 'darwin', buildCarrier, inspectResources: async () => ({ verified: true }),
    exec: async (program, args) => { calls.push([program, args]); return { stdout: '' }; } };
  return { root, payload, carrierRoot, app, candidate, options, buildCalls, calls, output: path.join(root, PF_AUTHORIZATION_PACKAGE_DIRECTORY) };
}

test('package stage reuses only the pinned complete carrier and preserves unrelated old carriers', async t => {
  const value = await fixture(t), old = path.join(value.carrierRoot, 'EnvaraPFAuthorization-000000000000.app');
  await mkdir(old); await writeFile(path.join(old, 'keep'), 'untouched');
  const result = await prepareMacOSPFPackage(value.options);
  assert.equal(result.verified, true); assert.equal(result.builtCarrier, false);
  assert.deepEqual(await readdir(value.output), [value.candidate.carrierName]);
  assert.equal(await readFile(path.join(old, 'keep'), 'utf8'), 'untouched');
  assert.equal(value.buildCalls.length, 0);
  assert.ok(value.calls.every(([program, args]) => program === '/usr/bin/codesign' && args[0] === '--verify'));
  assert.equal((await prepareMacOSPFPackage(value.options)).builtCarrier, false);
});

test('a missing selected carrier uses the existing reviewed builder with exact source and output', async t => {
  const value = await fixture(t, false), result = await prepareMacOSPFPackage(value.options);
  assert.equal(result.builtCarrier, true); assert.equal(value.buildCalls.length, 1);
  assert.equal(value.buildCalls[0].output, value.app); assert.equal(value.buildCalls[0].payload, value.payload);
  assert.equal(result.installed, false); assert.equal(result.activated, false);
});

test('pin mismatch and failed source verification refuse before carrier creation or staging', async t => {
  for (const fault of ['manifest', 'installer', 'source']) {
    const value = await fixture(t, false);
    if (fault === 'source') value.options.inspectResources = async () => ({ verified: false });
    else await appendFile(path.join(value.payload, fault === 'manifest' ? 'manifest.json' : 'EnvaraPFInstall'), 'changed');
    await assert.rejects(prepareMacOSPFPackage(value.options));
    assert.equal(value.buildCalls.length, 0); assert.equal(value.calls.length, 0);
    await assert.rejects(readdir(value.output), { code: 'ENOENT' });
  }
});

test('changed mains, stale receipts, extra files, symlinks and failed signatures cannot be reused', async t => {
  for (const fault of ['main', 'source', 'extra', 'symlink', 'signature']) {
    const value = await fixture(t), main = path.join(value.app, 'Contents/MacOS/EnvaraPFAuthorization');
    if (fault === 'main') await appendFile(main, 'changed');
    if (fault === 'source') await appendFile(path.join(value.root, 'native/macos-pf-authorization/launcher.c'), 'changed');
    if (fault === 'extra') await writeFile(path.join(value.app, 'unexpected'), 'unknown');
    if (fault === 'symlink') { await rm(main); await symlink('../Info.plist', main); }
    if (fault === 'signature') value.options.exec = async () => { throw new Error('signature refused'); };
    await assert.rejects(prepareMacOSPFPackage(value.options));
    await assert.rejects(readdir(value.output), { code: 'ENOENT' });
  }
});

test('unknown or stale staging and concurrent preparation are preserved and refused', async t => {
  for (const fault of ['unknown', 'stale', 'lock', 'symlink']) {
    const value = await fixture(t);
    await mkdir(path.dirname(value.output), { recursive: true });
    if (fault === 'lock') await mkdir(`${value.output}.lock`);
    else if (fault === 'symlink') await symlink(value.carrierRoot, value.output);
    else { await mkdir(value.output); await writeFile(path.join(value.output, fault === 'stale' ? 'EnvaraPFAuthorization-000000000000.app' : 'keep'), 'untouched'); }
    await assert.rejects(prepareMacOSPFPackage(value.options));
    if (['unknown', 'stale'].includes(fault)) assert.equal(await readFile(path.join(value.output, fault === 'stale' ? 'EnvaraPFAuthorization-000000000000.app' : 'keep'), 'utf8'), 'untouched');
  }
});

test('candidate parsing requires one fixed literal and package preparation rejects non-macOS', async t => {
  const value = await fixture(t), source = await readFile(path.join(value.root, 'electron/macos-pf-notion-trial.mjs'), 'utf8');
  assert.throws(() => parsePFPackageCandidate(source + source));
  assert.throws(() => parsePFPackageCandidate(source.replace(value.candidate.manifestSHA256, 'dynamic')));
  await assert.rejects(prepareMacOSPFPackage({ ...value.options, platform: 'linux' }), /macOS only/);
});
