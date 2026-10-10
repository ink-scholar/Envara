import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, chmodSync, rmSync, realpathSync, symlinkSync, unlinkSync, existsSync, lstatSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// A separate test entry keeps production build/installation/resource maps intact.
// This creates only a caller-owned temporary bundle, never PF, routes, or utun.
assert.equal(process.platform, 'darwin');
assert.notEqual(process.getuid(), 0);
const directory = path.dirname(fileURLToPath(import.meta.url));
const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'envara-gui-launch-fixture-')));
function binaryStringDictionary(values) {
  const keys = Object.keys(values), strings = [...keys, ...Object.values(values)];
  const objects = strings.map(value => {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([bytes.length < 15 ? Buffer.from([0x50 | bytes.length]) : Buffer.from([0x5f, 0x10, bytes.length]), bytes]);
  });
  objects.push(Buffer.from([0xd0 | keys.length, ...keys.map((_, index) => index), ...keys.map((_, index) => keys.length + index)]));
  let offset = 8; const offsets = objects.map(object => { const current = offset; offset += object.length; return current; });
  assert.ok(offset < 256 && objects.length < 256);
  const trailer = Buffer.alloc(32); trailer[6] = 1; trailer[7] = 1;
  trailer.writeBigUInt64BE(BigInt(objects.length), 8); trailer.writeBigUInt64BE(BigInt(objects.length - 1), 16);
  trailer.writeBigUInt64BE(BigInt(offset), 24);
  return Buffer.concat([Buffer.from('bplist00'), ...objects, Buffer.from(offsets), trailer]);
}
try {
  const executable = path.join(temporary, 'gui-fixture');
  const compile = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
    '-Wno-deprecated-declarations', '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`,
    path.join(directory, 'gui-launch.m'), path.join(directory, 'gui-fixture.m'), path.join(directory, 'launcher.c'),
    '-framework', 'Foundation', '-framework', 'AppKit', '-framework', 'Security', '-lbsm', '-o', executable],
    { encoding: 'utf8', timeout: 60000 });
  assert.equal(compile.status, 0, compile.stderr);
  const bundle = path.join(temporary, 'Own GUI Fixture.app');
  const cwd = path.join(temporary, 'selected workspace 空间');
  mkdirSync(path.join(bundle, 'Contents', 'MacOS'), { recursive: true, mode: 0o755 });
  mkdirSync(path.join(bundle, 'Contents', 'Resources'), { recursive: true, mode: 0o755 });
  mkdirSync(cwd, { mode: 0o700 });
  copyFileSync(executable, path.join(bundle, 'Contents', 'MacOS', 'OwnGUIFixture'));
  chmodSync(path.join(bundle, 'Contents', 'MacOS', 'OwnGUIFixture'), 0o755);
  writeFileSync(path.join(bundle, 'Contents', 'Resources', 'marker'), 'original', { mode: 0o644 });
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleIdentifier</key><string>io.envara.selfowned-gui-fixture</string>
<key>CFBundleExecutable</key><string>OwnGUIFixture</string>
</dict></plist>`;
  writeFileSync(path.join(bundle, 'Contents', 'Info.plist'), plist, { mode: 0o644 });
  const fixture = spawnSync(executable, [bundle, cwd], { encoding: 'utf8', timeout: 30000 });
  assert.equal(fixture.status, 0, fixture.stderr);
  const report = JSON.parse(fixture.stdout.trim());
  assert.equal(report.ready, false); assert.equal(report.protected, false); assert.equal(report.activatesSystem, false);
  assert.ok(Object.values(report.fixtures).every(value => value === true));
  const inspect = (target, expected, mode = 'inspect-fixture', timeoutMs = 10000) => {
    const result = spawnSync(executable, [mode, target], { encoding: 'utf8', timeout: timeoutMs });
    assert.equal(result.status, expected ? 0 : 1, `${mode}: ${result.stderr}\n${result.stdout}`);
    const inspected = JSON.parse(result.stdout);
    assert.equal(inspected.ok, expected); assert.equal(inspected.ready, false); assert.equal(inspected.activatesSystem, false);
    if (mode === 'acl-inspect') assert.equal(inspected.protected, false);
  };
  inspect(bundle, true);
  const internalLink = path.join(bundle, 'Contents', 'Resources', 'internal-link');
  const marker = path.join(bundle, 'Contents', 'Resources', 'marker');
  const resources = path.dirname(marker);
  inspect(marker, true, 'acl-inspect'); inspect(resources, true, 'acl-inspect');
  symlinkSync('marker', internalLink); inspect(bundle, true); inspect(internalLink, true, 'acl-inspect');
  const ownedACL = (target, install) => {
    const args = install ? ['+a', 'everyone deny write', target] : ['-N', target];
    const result = spawnSync('/bin/chmod', args, { encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 0, result.stderr);
    if (install) {
      const listed = spawnSync('/bin/ls', ['-lde', target], { encoding: 'utf8', timeout: 5000 });
      assert.equal(listed.status, 0, listed.stderr); assert.match(listed.stdout, /everyone deny (?:write|add_file)/);
    }
  };
  ownedACL(marker, true); inspect(marker, false, 'acl-inspect');
  // Inspect the link's own ACL; an ACL on its target must not be followed.
  inspect(internalLink, true, 'acl-inspect');
  ownedACL(marker, false); inspect(marker, true, 'acl-inspect');
  ownedACL(resources, true); inspect(resources, false, 'acl-inspect');
  ownedACL(resources, false); inspect(resources, true, 'acl-inspect');
  unlinkSync(internalLink);
  const alias = path.join(temporary, 'Alias.app'); symlinkSync(bundle, alias); inspect(alias, false); unlinkSync(alias);
  const outsideLink = path.join(bundle, 'Contents', 'Resources', 'outside-link');
  symlinkSync('/etc/hosts', outsideLink); inspect(bundle, false); unlinkSync(outsideLink);
  writeFileSync(path.join(bundle, 'Contents', 'Info.plist'), plist.replace('OwnGUIFixture', '../OwnGUIFixture')); inspect(bundle, false);
  for (const field of ['CFBundleExecutable', 'CFBundleIdentifier']) {
    const values = { CFBundlePackageType: 'APPL', CFBundleIdentifier: 'io.envara.selfowned-gui-fixture', CFBundleExecutable: 'OwnGUIFixture' };
    values[field] += '\0suffix';
    writeFileSync(path.join(bundle, 'Contents', 'Info.plist'), binaryStringDictionary(values)); inspect(bundle, false);
  }
  const infoPlist = path.join(bundle, 'Contents', 'Info.plist');
  unlinkSync(infoPlist);
  const fifoPlist = spawnSync('/usr/bin/mkfifo', ['-m', '600', infoPlist], { encoding: 'utf8', timeout: 5000 });
  assert.equal(fifoPlist.status, 0, fifoPlist.stderr); assert.equal(lstatSync(infoPlist).isFIFO(), true);
  // No writer exists: a blocking read-only open would stall until this timeout.
  inspect(bundle, false, 'inspect-fixture', 1000); unlinkSync(infoPlist);
  writeFileSync(path.join(bundle, 'Contents', 'Info.plist'), plist);
  const appExecutable = path.join(bundle, 'Contents', 'MacOS', 'OwnGUIFixture');
  writeFileSync(appExecutable, '#!/bin/sh\nexit 0\n'); chmodSync(appExecutable, 0o755); inspect(bundle, false);
  const calculator = '/System/Applications/Calculator.app';
  if (existsSync(calculator)) inspect(realpathSync(calculator), true, 'inspect-production');
  console.log('macOS GUI launch preparation: lifecycle, malformed-manifest, bounded FIFO refusal, file/directory ACL refusal, nofollow link ACL inspection, bundle/script/link rejection and signed system-bundle inspection passed; production ready=false.');
} finally { rmSync(temporary, { recursive: true, force: true }); }
