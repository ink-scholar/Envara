// Standalone candidate only. Never changes 832 resources or invokes a root,
// authorization, native hook, ledger or PF operation. The only run is --plan.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { constants } from 'node:fs';
import { mkdtemp, realpath, mkdir, writeFile, readFile, open } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MANIFEST_SHA = '83256899dc6db90bb6a21dcd18d17cb08a46d3ba4e79177098629475cc107f78';
const NATIVE_SHA = '8259641a73e96a28a8d1ca373b2d51c066bb74fafd91450e3f59279a477844b8';
const RUN_ID = 'a85314b8-5b24-4784-95ec-47b739c2e841';
const executableLeaves = new Set(['node', 'mihomo', 'envara-pf-native', 'EnvaraPFHelper', 'fixtures/EnvaraRoutingAcceptanceFixture']);
export async function hashPFCanaryInput(file) {
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size > 1024n * 1024n * 1024n) throw new Error('Candidate input is not a bounded regular file.');
    const sha = createHash('sha256'), buffer = Buffer.alloc(65536); let total = 0n;
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (!bytesRead) break;
      total += BigInt(bytesRead); if (total > before.size) throw new Error('Candidate input changed while hashing.');
      sha.update(buffer.subarray(0, bytesRead));
    }
    const after = await handle.stat({ bigint: true });
    if (total !== before.size || ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].some(key => before[key] !== after[key]))
      throw new Error('Candidate input changed while hashing.');
    return { sha256: sha.digest('hex'), mode: Number(before.mode & 0o7777n), bytes: Number(total) };
  } finally { await handle.close(); }
}
export async function buildPFSingleFilterCanary832({ output, exec = execute } = {}) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('This independent candidate targets the reviewed Darwin arm64 host.');
  const staged = path.join(root, 'build/app-routing/macos-pf'), manifestFile = path.join(staged, 'manifest.json');
  if ((await hashPFCanaryInput(manifestFile)).sha256 !== MANIFEST_SHA) throw new Error('The staged manifest is not the fixed 832 snapshot.');
  const manifest = JSON.parse(await readFile(manifestFile, 'utf8'));
  if (manifest.schema !== 'envara.macos-pf-installation/v1' || manifest.backend !== 'pf-utun' || Object.keys(manifest.files ?? {}).length !== 14 ||
    manifest.files['envara-pf-native'] !== NATIVE_SHA) throw new Error('The fixed 832 runtime inventory was not found.');
  const runtimeInputs = { 'manifest.json': { sha256: MANIFEST_SHA, mode: 0o644 } };
  // Hash large runtime inputs sequentially with one 64 KiB buffer.
  for (const [name, expected] of Object.entries(manifest.files)) {
    if (!/^[a-zA-Z0-9_.-]+$/.test(name) && name !== 'fixtures/EnvaraRoutingAcceptanceFixture') throw new Error('Unexpected fixed inventory name.');
    const input = await hashPFCanaryInput(path.join(staged, name)), mode = executableLeaves.has(name) ? 0o755 : 0o644;
    if (input.sha256 !== expected || input.mode !== mode) throw new Error(`Staged fixed snapshot leaf differs: ${name}`);
    runtimeInputs[name] = { sha256: expected, mode };
  }
  const nativeSourceSnapshot = manifest.nativeSourceFiles;
  if (!nativeSourceSnapshot || Object.keys(nativeSourceSnapshot).length !== 26) throw new Error('Fixed corresponding source snapshot is missing.');
  const sourcesUnchanged = async () => {
    for (const [name, expected] of Object.entries(nativeSourceSnapshot)) {
      if ((!name.startsWith('native/macos-pf-routing/') && name !== 'scripts/build-macos-pf-routing.mjs') ||
        name.split('/').some(part => !/^[a-zA-Z0-9_.-]+$/.test(part) || part === '..' || part === '.')) return false;
      if ((await hashPFCanaryInput(path.join(root, name))).sha256 !== expected) return false;
    }
    return true;
  };
  if (!await sourcesUnchanged()) throw new Error('Pinned corresponding native source differs from the frozen 832 snapshot.');
  const source = path.join(root, 'native/macos-pf-routing/pf-single-filter-canary-832.m');
  const inventory = path.join(root, 'native/macos-pf-routing/pf-single-filter-canary-inventory-832.h');
  const transaction = path.join(root,'native/macos-pf-routing/pf-single-filter-transaction.c');
  const transactionHeader = path.join(root,'native/macos-pf-routing/pf-single-filter-transaction.h');
  const transactionSHA256=(await hashPFCanaryInput(transaction)).sha256, transactionHeaderSHA256=(await hashPFCanaryInput(transactionHeader)).sha256;
  const sourceSHA256 = (await hashPFCanaryInput(source)).sha256, inventorySHA256 = (await hashPFCanaryInput(inventory)).sha256;
  const inventoryText = await readFile(inventory, 'utf8');
  if (!inventoryText.includes(MANIFEST_SHA) || !inventoryText.includes(NATIVE_SHA) || !inventoryText.includes(RUN_ID)) throw new Error('Canary constants do not bind the fixed 832 snapshot.');
  for (const [name, { sha256, mode }] of Object.entries(runtimeInputs)) {
    const line = name === 'manifest.json' ? `{"manifest.json", CANARY_MANIFEST_SHA, 0644}` : `{"${name}", "${sha256}", 0${mode.toString(8)}}`;
    if (!inventoryText.includes(line)) throw new Error(`Canary fixed leaf table differs: ${name}`);
  }
  const directory = output ? path.resolve(output) : await realpath(await mkdtemp(path.join(tmpdir(), 'envara-pf-run-canary-832-')));
  const app = path.join(directory, 'Envara PF Single Filter Canary 832.app');
  const contents = path.join(app, 'Contents'), binaries = path.join(contents, 'MacOS');
  await mkdir(binaries, { recursive: true, mode: 0o700 });
  const binary = path.join(binaries, 'EnvaraPFSingleFilterCanary832');
  await exec('/usr/bin/clang', ['-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror', source, transaction,
    '-framework', 'Foundation', '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
  const sourceUnchanged = async () => (await hashPFCanaryInput(transaction)).sha256 === transactionSHA256 && (await hashPFCanaryInput(transactionHeader)).sha256 === transactionHeaderSHA256 && (await hashPFCanaryInput(source)).sha256 === sourceSHA256 && (await hashPFCanaryInput(inventory)).sha256 === inventorySHA256;
  if (!await sourceUnchanged()) throw new Error('Review source changed while compiling; discard this independent candidate.');
  const metadata = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n' +
    '<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.envara.pf-single-filter-canary-832</string><key>CFBundleName</key><string>Envara PF Single Filter Canary 832</string>' +
    '<key>CFBundleExecutable</key><string>EnvaraPFSingleFilterCanary832</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>2</string><key>LSUIElement</key><true/></dict></plist>\n';
  await writeFile(path.join(contents, 'Info.plist'), metadata, { flag: 'wx', mode: 0o600 });
  await exec('/usr/bin/codesign', ['--force', '--sign', '-', app], { timeout: 15000, maxBuffer: 1024 * 1024 });
  await exec('/usr/bin/codesign', ['--verify', '--strict', app], { timeout: 15000, maxBuffer: 1024 * 1024 });
  const plan = JSON.parse((await exec(binary, ['--plan'], { timeout: 15000, maxBuffer: 1024 * 1024 })).stdout);
  if (plan.runId !== RUN_ID || plan.manifestSHA256 !== MANIFEST_SHA || plan.nativeSHA256 !== NATIVE_SHA || plan.readOnly !== true ||
    plan.authorizationRequested !== false || plan.insertAttempted !== false || plan.deleteAttempted !== false) throw new Error('The built candidate plan is not inert or does not match the reviewed snapshot.');
  if (!await sourceUnchanged() || !await sourcesUnchanged() || (await hashPFCanaryInput(manifestFile)).sha256 !== MANIFEST_SHA) throw new Error('Review inputs changed before bundle completion.');
  const result = { schema: 'envara.macos-pf-single-filter-canary-build/v1', directory, app, binary, fixedRunId: RUN_ID,
    sourceSHA256, inventorySHA256, transactionSHA256, transactionHeaderSHA256, binarySHA256: (await hashPFCanaryInput(binary)).sha256,
    pinnedManifestSHA256: MANIFEST_SHA, pinnedNativeSHA256: NATIVE_SHA, runtimeInputs, nativeSourceSnapshot, plan, strictABIBoundToInstalledSource:true,
    authorizationRequested: false, systemOperationExecuted: false, ledgerWriteExecuted: false, PFWriteExecuted: false,
    activation: false, installed: false, productionReady: false, requiresSeparateApproval: true };
  await writeFile(path.join(directory, 'canary-build.json'), JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return result;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) { console.error('Build accepts no operation, UUID, path, manifest or authorization arguments.'); process.exitCode = 1; }
  else { try { console.log(JSON.stringify(await buildPFSingleFilterCanary832(), null, 2)); }
    catch (error) { console.error(error.message); process.exitCode = 1; } }
}
