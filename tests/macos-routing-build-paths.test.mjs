import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { swiftBuildPathOptions } from '../scripts/macos-swift-build-paths.mjs';

const run = promisify(execFile);

test('SwiftPM receives separate Swift, Clang and linker path maps without shell interpolation', () => {
  const root = '/temporary/checkouts/space and unicode-境舱';
  const args = swiftBuildPathOptions(root);
  const pairs = [];
  for (let index = 0; index < args.length; index += 2) pairs.push([args[index], args[index + 1]]);
  assert(pairs.every(([key, value]) => ['-debug-info-format', '-Xswiftc', '-Xcc', '-Xlinker'].includes(key) && typeof value === 'string'));
  for (const pair of [
    ['-debug-info-format', 'none'],
    ['-Xswiftc', '-file-prefix-map'], ['-Xswiftc', '-debug-prefix-map'],
    ['-Xswiftc', `${root}=/envara/src`], ['-Xswiftc', '-prefix-serialized-debugging-options'],
    ['-Xswiftc', '/envara/src/native/macos-app-routing'],
    ['-Xcc', `-ffile-prefix-map=${root}=/envara/src`], ['-Xcc', `-fdebug-prefix-map=${root}=/envara/src`],
    ['-Xcc', '-fdebug-compilation-dir=/envara/src/native/macos-app-routing'],
    ['-Xlinker', '-oso_prefix'], ['-Xlinker', `${root}/`],
  ]) assert(pairs.some(value => value[0] === pair[0] && value[1] === pair[1]), pair[1]);
});

test('real Swift and C release output has mapped source identities without its checkout or home path', {
  skip: process.platform !== 'darwin', timeout: 60000,
}, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-path-map-'));
  try {
    const source = path.join(root, 'native/macos-app-routing');
    const scratch = path.join(root, 'build/fixture');
    await Promise.all(['Sources/Probe', 'Sources/CProbe/include'].map(name => mkdir(path.join(source, name), { recursive: true })));
    await writeFile(path.join(source, 'Package.swift'), '// swift-tools-version: 5.9\nimport PackageDescription\nlet package = Package(name: "PathProbe", products: [.executable(name: "PathProbe", targets: ["Probe"])], targets: [.target(name: "CProbe"), .executableTarget(name: "Probe", dependencies: ["CProbe"])])\n');
    await writeFile(path.join(source, 'Sources/CProbe/include/CProbe.h'), 'const char *probe_file(void);\n');
    await writeFile(path.join(source, 'Sources/CProbe/probe.c'), '#include "CProbe.h"\nconst char *probe_file(void) { return __FILE__; }\n');
    await writeFile(path.join(source, 'Sources/Probe/main.swift'), 'import CProbe\nprint(#fileID)\nprint(String(cString: probe_file()))\n');
    const result = await run('swift', ['build', '--package-path', source, '-c', 'release', '--jobs', '2', '--scratch-path', scratch,
      ...swiftBuildPathOptions(root)], { cwd: source, timeout: 55000, maxBuffer: 1024 * 1024 });
    assert.equal(typeof result.stdout, 'string');
    assert.doesNotMatch(result.stderr, /unable to open object file|no debug symbols in executable/);
    const binary = path.join(scratch, 'release/PathProbe');
    const bytes = await readFile(binary);
    for (const [label, privatePrefix] of [['fixture root', root], ['canonical fixture root', await realpath(root)], ['home', os.homedir()]]) {
      assert.equal(bytes.includes(Buffer.from(privatePrefix)), false, `binary contains ${label}`);
    }
    const probe = await run(binary, [], { timeout: 5000 });
    assert.deepEqual(probe.stdout.trim().split('\n'), [
      'Probe/main.swift',
      '/envara/src/native/macos-app-routing/Sources/CProbe/probe.c',
    ]);
  } finally { await rm(root, { recursive: true, force: true }); }
});
