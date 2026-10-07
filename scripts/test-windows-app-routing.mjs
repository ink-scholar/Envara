import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const source = path.join(root, 'native/windows-app-routing');
const temporary = mkdtempSync(path.join(tmpdir(), 'envara-windows-routing-test-'));

function run(args, { env = process.env, input, encoding = 'utf8' } = {}) {
  const result = spawnSync('go', args, { cwd: source, env, input, encoding, timeout: 120_000, maxBuffer: 2_000_000 });
  if (result.error || result.status !== 0) {
    throw new Error(`Go source verification failed: ${result.stderr ?? ''}`, { cause: result.error });
  }
  return result.stdout;
}

try {
  console.log(run(['test', '-race', './...']).trim());
  run(['vet', './...']);
  const lifecycle = path.join(temporary, 'lifecycle-test');
  const compiler = process.env.CC || (process.platform === 'win32' ? 'clang' : 'cc');
  const compile = spawnSync(compiler, ['-std=c11', '-Wall', '-Wextra', '-Werror', 'tests/lifecycle.c', '-o', lifecycle], { cwd: source, encoding: 'utf8' });
  assert.equal(compile.status, 0, `Portable driver lifecycle/ABI compile failed: ${compile.stderr || compile.error || ''}`);
  const transitions = spawnSync(lifecycle, [], { encoding: 'utf8' });
  assert.equal(transitions.status, 0, `Lifecycle transition tests failed: ${transitions.stderr || ''}`);
  console.log('Portable C: production lifecycle transitions and ABI sizes passed; no WDK/runtime claim.');
  for (const arch of ['amd64', 'arm64']) {
    const env = { ...process.env, GOOS: 'windows', GOARCH: arch, CGO_ENABLED: '0' };
    run(['vet', './...'], { env });
    const executable = path.join(temporary, `${arch}.exe`);
    run(['build', '-trimpath', '-o', executable, './cmd/envara-app-routing'], { env });
    const binary = readFileSync(executable);
    assert.equal(binary.subarray(0, 2).toString(), 'MZ');
    const peOffset = binary.readUInt32LE(0x3c);
    assert.equal(binary.readUInt32LE(peOffset), 0x00004550);
    assert.equal(binary.readUInt16LE(peOffset + 4), arch === 'amd64' ? 0x8664 : 0xaa64);
    console.log(`Windows ${arch}: helper cross-compiled and vetted.`);
  }
  if (process.platform !== 'win32') {
    const envelope = { protocol: 'envara.application-routing', version: 1, id: 'fixture', method: 'status', params: {} };
    const status = JSON.parse(run(['run', './cmd/envara-app-routing', '--rpc'], { input: JSON.stringify(envelope) })).result;
    assert.equal(status.ready, false);
    assert.equal(status.verification.passed, false);
    envelope.method = 'launch';
    envelope.params = { application: { path: '/bin/echo' }, args: ['MUST-NOT-SPAWN'] };
    const result = JSON.parse(run(['run', './cmd/envara-app-routing', '--rpc'], { input: JSON.stringify(envelope) }));
    assert.equal(result.error.code, 'PLATFORM_UNSUPPORTED');
  }
  const wire = readFileSync(path.join(source, 'driver/envara_wire.h'), 'utf8');
  const kernel = readFileSync(path.join(source, 'driver/envara_driver.c'), 'utf8');
  const engine = readFileSync(path.join(source, 'internal/host/engine_windows.go'), 'utf8');
  assert.match(wire, /ENVARA_ABI_VERSION 2u/);
  assert.match(kernel, /CreatingThreadId\.UniqueProcess/);
  assert.match(kernel, /rootCreationTime/);
  assert.match(kernel, /info->CreationStatus=STATUS_INSUFFICIENT_RESOURCES/);
  assert.match(kernel, /protocol!=IPPROTO_TCP/);
  assert.match(engine, /status\.Ready\s*=\s*false/);
  assert.match(engine, /CREATE_SUSPENDED/);
  assert.match(engine, /JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE/);
  console.log('Source tests passed. Windows WFP runtime, driver build/signing and DNS isolation remain unverified.');
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
