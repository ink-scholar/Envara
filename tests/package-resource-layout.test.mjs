import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { minimatch } from 'minimatch';
import { getFileMatchers } from 'app-builder-lib/out/fileMatcher.js';
import { bundledPFRoutingPaths } from '../electron/macos-pf-resources.mjs';
import { PF_NOTION_TRIAL_CARRIER } from '../electron/macos-pf-notion-trial.mjs';
import { packagedResourceEntries } from '../scripts/verify-package-resources.mjs';

const root = path.resolve(import.meta.dirname, '..');
const config = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8')).build;
const includes = (entry, name) => entry.filter.some(pattern => !pattern.startsWith('!') && minimatch(name, pattern)) &&
  !entry.filter.some(pattern => pattern.startsWith('!') && minimatch(name, pattern.slice(1)));

test('release routing and authorization use the same pinned complete payload; development retains its build path', () => {
  const resources = path.join(root, 'owned-fixture/Contents/Resources');
  const release = bundledPFRoutingPaths(resources);
  assert.equal(release.authorizerPath, path.join(resources, PF_NOTION_TRIAL_CARRIER));
  assert.equal(release.installerPath, release.authorizerPath);
  assert.equal(release.helperPath, path.join(path.dirname(release.authorizerPath), 'EnvaraPFHelper'));
  const development = bundledPFRoutingPaths(path.join(root, 'build'), { packaged: false });
  assert.equal(development.directory, path.join(root, 'build/app-routing/macos-pf'));
  assert.equal(development.authorizerPath, path.join(root, 'build', PF_NOTION_TRIAL_CARRIER));
});

test('macOS ships NE/link alternatives and one authorization payload, excluding duplicate PF and Windows artifacts', () => {
  const entries = packagedResourceEntries(config, 'darwin', 'arm64');
  const routing = entries.filter(entry => entry.to === 'app-routing'); assert.equal(routing.length, 1);
  for (const name of ['macos/EnvaraAppRouting.app/Contents/MacOS/EnvaraAppRoutingHelper',
    'macos-local/Resources/Mitmproxy Redirector.app/Contents/MacOS/Mitmproxy Redirector', 'macos-link-router/Contents/MacOS/EnvaraLinkRouter']) assert.equal(includes(routing[0], name), true, name);
  for (const name of ['macos-pf/node', 'macos-pf-before-performance-91b62a/node', 'win32/x64/EnvaraAppRouting.exe', 'win32/arm64/EnvaraAppRouting.exe', 'macos/.swift-build/debug/tool']) assert.equal(includes(routing[0], name), false, name);
  assert.equal(entries.filter(entry => entry.to === 'local-authorization').length, 1);
});

test('Windows selects its own routing architecture, while Linux carries neither platform-specific payload', () => {
  for (const arch of ['x64', 'arm64']) {
    const entries = packagedResourceEntries(config, 'win32', arch);
    const routing = entries.find(entry => entry.to === 'app-routing');
    assert.equal(includes(routing, `win32/${arch}/EnvaraAppRouting.exe`), true);
    assert.equal(includes(routing, `win32/${arch === 'x64' ? 'arm64' : 'x64'}/EnvaraAppRouting.exe`), false);
    assert.equal(includes(routing, 'macos-pf/node'), false);
    assert.equal(entries.some(entry => entry.to === 'local-authorization'), false);
  }
  assert.equal(packagedResourceEntries(config, 'linux', 'x64').some(entry => ['app-routing', 'local-authorization'].includes(entry.to)), false);
});

test('resource verification follows electron-builder common plus platform entry merging and architecture expansion', () => {
  for (const [platform, key, arch] of [['darwin', 'mac', 'arm64'], ['win32', 'win', 'x64'], ['linux', 'linux', 'x64']]) {
    const destination = path.join(root, 'owned-output/resources');
    const actual = getFileMatchers(config, 'extraResources', destination, { defaultSrc: root, globalOutDir: path.join(root, 'release'),
      macroExpander: value => value.replaceAll('${arch}', arch), customBuildOptions: config[key] });
    const expected = packagedResourceEntries(config, platform, arch);
    assert.deepEqual(actual.map(entry => [entry.from, entry.to, entry.patterns]), expected.map(entry => [path.join(root, entry.from), path.join(destination, entry.to), entry.filter ?? []]));
  }
});
