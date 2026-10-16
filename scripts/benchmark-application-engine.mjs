// Explicit app path, own compiler output, read-only native calls; no privileged helper.
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execute=promisify(execFile), root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
assert.equal(process.platform,'darwin'); assert.notEqual(process.getuid(),0); assert.equal(process.argv.length,3);
const temporary=await mkdtemp(path.join(tmpdir(),'envara-engine-benchmark-'));
try {
 const binary=path.join(temporary,'benchmark');
 await execute('/usr/bin/xcrun',['clang','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations',
  path.join(root,'scripts/fixtures/application-engine-benchmark.m'),path.join(root,'scripts/fixtures/application-manifest-benchmark.m'),
  path.join(root,'native/macos-pf-routing/launcher.c'),'-framework','Foundation','-framework','AppKit','-framework','Security','-lbsm','-o',binary],
  {timeout:30000,maxBuffer:65536});
 const result=await execute(binary,[path.resolve(process.argv[2])],{timeout:90000,maxBuffer:65536});
 process.stdout.write(`${JSON.stringify(JSON.parse(result.stdout),null,2)}\n`);
} finally { await rm(temporary,{recursive:true,force:true}); }
