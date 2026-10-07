// Exercise the packaged TerminalService and native PTY in disposable app data.
// Run: node scripts/verify-terminal-package.mjs /absolute/path/Envara.app
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { access, chmod, mkdir, mkdtemp, readFile, realpath, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const filename = fileURLToPath(import.meta.url);
const projectRoot = path.resolve(path.dirname(filename), '..');
const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const isAlive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const sha256 = async filename => createHash('sha256').update(await readFile(filename)).digest('hex');
const quote = value => process.platform === 'win32'
  ? `"${value.replaceAll('"', '""')}"` : `'${value.replaceAll("'", "'\\''")}'`;

async function waitUntil(predicate, description, milliseconds = 10000) {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) {
    const result = await predicate();
    if (result) return result;
    await sleep(25);
  }
  throw new Error(description);
}

async function verifyInside(resources, runDir) {
  assert(process.versions.electron && process.env.ELECTRON_RUN_AS_NODE === '1', 'Use the packaged Electron runtime.');
  assert.equal(await realpath(process.resourcesPath), await realpath(resources));
  const archive = path.join(resources, 'app.asar');
  const servicePath = path.join(archive, 'electron/terminal-service.mjs');
  const nativeRoot = path.join(resources, 'app.asar.unpacked/node_modules/node-pty');
  const driverDirectory = path.join(resources, 'backend/playwright-driver');
  const bundledNode = path.join(driverDirectory, process.platform === 'win32' ? 'node.exe' : 'node');
  const packageInfo = JSON.parse(await readFile(path.join(archive, 'package.json'), 'utf8'));
  const nativeInfo = JSON.parse(await readFile(path.join(nativeRoot, 'package.json'), 'utf8'));
  await access(bundledNode);
  const moduleURL = pathToFileURL(servicePath).href;
  const { TerminalService } = await import(moduleURL);
  const requirePackaged = createRequire(moduleURL);
  const result = {
    passed: false, candidate: packageInfo.version, electron: process.versions.electron,
    node: process.versions.node, modulesAbi: process.versions.modules, napi: process.versions.napi,
    platform: process.platform, arch: process.arch, resources, runDir,
    importedService: servicePath, serviceSha256: await sha256(servicePath),
    nativePackage: { name: nativeInfo.name, version: nativeInfo.version, root: nativeRoot },
    checks: [],
    limitations: ['This verifies packaged terminal loading and lifecycle. It does not exercise UI, external CLI accounts or proxy routing.'],
  };
  const data = new Map();
  const ownedPids = new Set();
  let service;
  const terminate = () => {
    void Promise.resolve().then(() => service?.shutdown()).finally(() => process.exit(1));
  };
  process.once('SIGTERM', terminate);
  const check = description => { result.checks.push(description); console.log(`PASS ${description}`); };
  try {
    const workspace = path.join(runDir, 'working-directory');
    await mkdir(workspace, { mode: 0o700 });
    const dataDir = path.join(runDir, 'private-app-data');
    const fixture = path.join(runDir, 'fixture.mjs');
    const marker = '__ENVARA_PACKAGED_TERMINAL__';
    await writeFile(fixture, `
      import fs from 'node:fs';
      import path from 'node:path';
      const document = {
        nonce: process.argv[2], executable: process.execPath, node: process.versions.node,
        cwd: process.cwd(), home: process.env.HOME, config: process.env.XDG_CONFIG_HOME,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        electronFlagPresent: 'ELECTRON_RUN_AS_NODE' in process.env,
      };
      fs.writeFileSync(path.join(process.env.XDG_CONFIG_HOME, 'packaged-check-marker'), process.argv[2]);
      process.stdout.write(${JSON.stringify(marker)} + JSON.stringify(document) + '\\n');
    `, { mode: 0o600 });
    service = new TerminalService({
      dataDir, additionalExecutablePaths: [driverDirectory],
      resolveContext: async id => ({ id, name: 'Packaged terminal fixture', timezone: 'Asia/Shanghai', timezoneSource: 'manual', proxy: null }),
      onEvent: event => {
        if (event.type === 'data') data.set(event.sessionId, (data.get(event.sessionId) || '') + event.data);
      },
    });
    await service.setDirectory({ id: 'packaged_fixture', path: workspace });
    const session = await service.create({ id: 'packaged_fixture', columns: 80, rows: 24 });
    assert.equal(session.status, 'running');
    ownedPids.add(service.sessions.get(session.sessionId).pty.pid);
    const loaded = Object.keys(requirePackaged.cache).filter(file => file.includes(`${path.sep}node-pty${path.sep}`));
    assert(loaded.some(file => file.endsWith('.node')), 'The packaged native PTY binding must be loaded.');
    const virtualRoot = path.join(archive, 'node_modules/node-pty');
    assert(loaded.every(file => file.startsWith(`${nativeRoot}${path.sep}`) || file.startsWith(`${virtualRoot}${path.sep}`)), 'node-pty must load from the packaged archive or its complete unpacked directory.');
    result.loadedNativeBindings = loaded.filter(file => file.endsWith('.node'));
    const physicalBindings = result.loadedNativeBindings.map(binding => binding.startsWith(`${virtualRoot}${path.sep}`)
      ? path.join(nativeRoot, path.relative(virtualRoot, binding)) : binding);
    for (const binding of physicalBindings) assert((await realpath(binding)).startsWith(`${await realpath(nativeRoot)}${path.sep}`));
    result.physicalNativeBindings = physicalBindings;
    const sharedObjects = (process.report?.getReport?.().sharedObjects || []).filter(file => file.includes(`${path.sep}node-pty${path.sep}`) && file.endsWith('.node'));
    if (sharedObjects.length) {
      for (const binding of sharedObjects) assert((await realpath(binding)).startsWith(`${await realpath(nativeRoot)}${path.sep}`), 'The loaded native library must use the physical unpacked directory.');
      result.loadedNativeSharedObjects = sharedObjects;
    }
    if (process.platform !== 'win32') {
      for (const binding of physicalBindings) {
        const helper = path.join(path.dirname(binding), 'spawn-helper');
        assert((await stat(helper)).mode & 0o111, 'The unpacked PTY helper must remain executable.');
      }
    }
    check('The archived TerminalService starts a real PTY using the complete unpacked node-pty package.');
    const dimensions = await service.resize({ sessionId: session.sessionId, columns: 120, rows: 40 });
    assert.equal(dimensions.columns, 120); assert.equal(dimensions.rows, 40);
    const nonce = randomUUID();
    // Deliberately resolve "node" through the same trusted bundled-driver PATH as the app.
    await service.write({ sessionId: session.sessionId, data: `node ${quote(fixture)} ${quote(nonce)}\r` });
    const observed = await waitUntil(() => {
      for (const match of (data.get(session.sessionId) || '').matchAll(/__ENVARA_PACKAGED_TERMINAL__(\{[^\r\n]*\})/g)) {
        try { const candidate = JSON.parse(match[1]); if (candidate.nonce === nonce) return candidate; } catch {}
      }
    }, 'The packaged PTY did not return its fixture output.');
    assert.equal(await realpath(observed.executable), await realpath(bundledNode));
    assert.equal(await realpath(observed.cwd), await realpath(workspace));
    assert.equal(observed.timezone, 'Asia/Shanghai');
    assert(observed.home.startsWith(`${dataDir}${path.sep}`));
    assert(observed.config.startsWith(`${dataDir}${path.sep}`));
    assert.equal(observed.electronFlagPresent, false);
    assert.equal(await readFile(path.join(observed.config, 'packaged-check-marker'), 'utf8'), nonce);
    result.observed = observed;
    check('PTY input/output and resize work; its CLI resolves bundled Node and uses the private working/configuration paths and timezone.');
    await service.write({ sessionId: session.sessionId, data: 'exit\r' });
    await waitUntil(async () => (await service.snapshot({ id: 'packaged_fixture' })).profiles[0].sessions.find(row => row.sessionId === session.sessionId)?.status === 'exited', 'The packaged shell exit did not update service state.');
    const reopened = await service.create({ id: 'packaged_fixture' });
    assert.equal(reopened.status, 'running');
    ownedPids.add(service.sessions.get(reopened.sessionId).pty.pid);
    const closed = await service.close({ sessionId: reopened.sessionId });
    assert(['closed', 'exited'].includes(closed.status));
    await service.shutdown();
    await waitUntil(() => [...ownedPids].every(pid => !isAlive(pid)), 'A packaged verification PTY remained alive.');
    result.remainingOwnedProcesses = [...ownedPids].filter(isAlive).length;
    check('Natural shell exit, reopen, explicit close and shutdown leave no owned PTY process running.');
    result.passed = true;
  } catch (error) {
    result.error = { message: error.message, code: error.code || 'PACKAGED_TERMINAL_CHECK_FAILED' };
    process.exitCode = 1;
  } finally {
    try { await service?.shutdown(); }
    catch { result.shutdownFailed = true; result.passed = false; process.exitCode = 1; }
    result.remainingOwnedProcesses = [...ownedPids].filter(isAlive).length;
    if (result.remainingOwnedProcesses) { result.passed = false; process.exitCode = 1; }
    await writeFile(path.join(runDir, 'proof.json'), `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
    console.log(`Packaged terminal proof: ${path.join(runDir, 'proof.json')}`);
    process.removeListener('SIGTERM', terminate);
  }
}

async function launchVerification(application) {
  if (!application) throw new Error('Usage: node scripts/verify-terminal-package.mjs /absolute/path/Envara.app (or Envara executable)');
  let executable = path.resolve(application);
  let resources;
  if (process.platform === 'darwin') {
    if (executable.endsWith('.app')) executable = path.join(executable, 'Contents/MacOS/Envara');
    resources = path.resolve(path.dirname(executable), '../Resources');
  } else {
    if ((await stat(executable)).isDirectory()) executable = path.join(executable, process.platform === 'win32' ? 'Envara.exe' : 'envara');
    resources = path.join(path.dirname(executable), 'resources');
  }
  await access(executable);
  await access(path.join(resources, 'app.asar'));
  const artifactDirectory = path.join(projectRoot, 'test-artifacts/packaged-terminal');
  await mkdir(artifactDirectory, { recursive: true, mode: 0o700 });
  const runDir = await mkdtemp(path.join(artifactDirectory, 'run-'));
  await chmod(runDir, 0o700);
  const temporaryHome = path.join(runDir, 'verification-runtime-home');
  await mkdir(temporaryHome, { mode: 0o700 });
  const env = { HOME: temporaryHome, USERPROFILE: temporaryHome, TMPDIR: runDir, TMP: runDir, TEMP: runDir, ELECTRON_RUN_AS_NODE: '1' };
  if (process.platform === 'win32') {
    env.SystemRoot = process.env.SystemRoot || 'C:\\Windows';
    env.PATH = `${env.SystemRoot}\\System32`;
  } else env.PATH = '/usr/bin:/bin:/usr/sbin:/sbin';
  const child = spawn(executable, [filename, '--inside', resources, runDir], { env, cwd: runDir, stdio: 'inherit' });
  const timeout = setTimeout(() => { child.kill('SIGTERM'); }, 45000);
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); }).finally(() => clearTimeout(timeout));
  if (code !== 0) throw new Error(`Packaged terminal verification failed; inspect ${path.join(runDir, 'proof.json')}.`);
  const proof = JSON.parse(await readFile(path.join(runDir, 'proof.json'), 'utf8'));
  assert(proof.passed && proof.remainingOwnedProcesses === 0);
  await writeFile(path.join(artifactDirectory, 'latest-proof.json'), `${JSON.stringify(proof, null, 2)}\n`, { mode: 0o600 });
  return proof;
}

try {
  if (process.argv[2] === '--inside') await verifyInside(process.argv[3], process.argv[4]);
  else await launchVerification(process.argv[2]);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
