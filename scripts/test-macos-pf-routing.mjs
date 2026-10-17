import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { constants } from 'node:fs';
import { access, readdir, stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RESERVATION_TEST = 'fixture-reservation.test.mjs';

export function parseMacOSPFTestArguments(args) {
  if (args.length === 0) return {};
  if (args.length !== 2 || args[0] !== '--resources' || typeof args[1] !== 'string' || !path.isAbsolute(args[1])) {
    throw new Error('Usage: node scripts/test-macos-pf-routing.mjs [--resources /absolute/payload]');
  }
  return { resources: path.resolve(args[1]) };
}

async function requireFile(filename, executable = false) {
  if (!(await stat(filename)).isFile()) throw new Error(`Required test input is not a file: ${filename}`);
  await access(filename, executable ? constants.R_OK | constants.X_OK : constants.R_OK);
}

/** Construct the complete suite without executing, building or installing resources. */
export async function createMacOSPFTestCommands({ root = ROOT,
  resources = path.join(root, 'build/app-routing/macos-pf'), node = process.execPath, env = process.env } = {}) {
  if (![root, resources, node].every(value => typeof value === 'string' && path.isAbsolute(value))) {
    throw new Error('Repository, resources and Node executable paths must be absolute.');
  }
  const source = path.join(root, 'native/macos-pf-routing');
  const names = (await readdir(source, { withFileTypes: true }))
    .filter(entry => entry.isFile() && entry.name.endsWith('.test.mjs') && entry.name !== RESERVATION_TEST)
    .map(entry => entry.name).sort();
  if (names.length === 0) throw new Error('No macOS PF native fixture tests found.');
  const nativeTest = path.join(source, 'test.mjs');
  const reservationTest = path.join(source, RESERVATION_TEST);
  const nativeBinary = path.join(resources, 'envara-pf-native');
  const reservationBinary = path.join(resources, 'fixtures/EnvaraRoutingAcceptanceFixture');
  await Promise.all([
    ...names.map(name => requireFile(path.join(source, name))),
    requireFile(nativeTest), requireFile(reservationTest),
    requireFile(nativeBinary, true), requireFile(reservationBinary, true),
  ]);
  const command = (name, args, environment = env) => ({ name, executable: node, args,
    options: { cwd: root, env: { ...environment }, stdio: 'inherit', shell: false } });
  return [
    command('native fixture suites', ['--test', '--test-concurrency=2', ...names.map(name => path.join(source, name))]),
    command('native CLI fixtures', [nativeTest], { ...env, ENVARA_PF_NATIVE_TEST_BINARY: nativeBinary }),
    command('socket reservation fixtures', [reservationTest, reservationBinary]),
  ];
}

function execute(executable, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, options);
    child.once('error', reject);
    child.once('close', (code, signal) => {
      if (code === 0) return resolve();
      const error = new Error(`macOS PF test process failed (${signal ?? `exit ${code}`}).`);
      error.exitCode = Number.isInteger(code) && code > 0 ? code : 1;
      error.signal = signal;
      reject(error);
    });
  });
}

/** Existing suites may compile disposable fixtures; no resource build or activation is added here. */
export async function runMacOSPFTests({ platform = process.platform, uid = process.getuid?.(),
  euid = process.geteuid?.(), gid = process.getgid?.(), egid = process.getegid?.(), exec = execute, ...options } = {}) {
  if (platform !== 'darwin') throw new Error('macOS PF native fixture tests require macOS.');
  if (![uid, euid, gid, egid].every(value => Number.isInteger(value) && value > 0) || uid !== euid || gid !== egid) {
    throw new Error('Run macOS PF native fixture tests as an unprivileged user with matching real/effective IDs.');
  }
  const commands = await createMacOSPFTestCommands(options);
  // Do not wrap failures: retain the first error and never start later phases.
  for (const command of commands) await exec(command.executable, command.args, command.options);
  return commands;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    await runMacOSPFTests(parseMacOSPFTestArguments(process.argv.slice(2)));
  } catch (error) {
    console.error(error.message);
    process.exitCode = Number.isInteger(error.exitCode) && error.exitCode > 0 ? error.exitCode : 1;
  }
}
