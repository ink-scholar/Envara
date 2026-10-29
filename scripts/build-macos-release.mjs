// The only macOS release entry point. Runs the reviewed candidate acceptance
// with private test data; never installs the application or publishes remotely.
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash, X509Certificate } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { openReleaseWorkspace, releaseWorkspacePaths } from './macos-release-workspace.mjs';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const requireValue = (condition, message) => { if (!condition) throw new Error(message); };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const within = (base, item) => { const rel = path.relative(base, item); return !rel || rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel); };

export const CANDIDATE_ACCEPTANCE_SCRIPT = 'scripts/verify-macos-release-candidate.mjs';
export const CANDIDATE_ACCEPTANCE_SCHEMA = 'envara.macos-release-acceptance/v1';
export const CANDIDATE_ACCEPTANCE_CHECKS = Object.freeze([
  'clean-first-launch', 'desktop-service-ready', 'terminal-pty', 'claude-keychain-persistence', 'owned-process-cleanup',
]);
const receiptLimit = 64 * 1024;

export const signingTargets = Object.freeze([
  'Contents/Frameworks/Mantle.framework',
  'Contents/Frameworks/ReactiveObjC.framework',
  'Contents/Frameworks/Squirrel.framework',
  'Contents/Frameworks/Electron Framework.framework',
  'Contents/Frameworks/Envara Helper.app',
  'Contents/Frameworks/Envara Helper (GPU).app',
  'Contents/Frameworks/Envara Helper (Plugin).app',
  'Contents/Frameworks/Envara Helper (Renderer).app',
  '.',
]);

// Developer ID remains the default. Ad-hoc signing requires an explicit mode
// before preparation; the wrapper never creates/imports certificates or silently
// downgrades when a requested Developer ID identity is unavailable.
export function signingRequest(env) {
  for (const key of Object.keys(env)) {
    requireValue(!key.startsWith('CSC_') || !env[key] || key === 'CSC_IDENTITY_AUTO_DISCOVERY' && env[key] === 'false',
      `Remove ${key}; release signing only uses the explicitly selected mode and identity.`);
  }
  const mode = env.ENVARA_MAC_SIGNING_MODE ?? 'developer-id';
  requireValue(['developer-id', 'adhoc'].includes(mode), 'ENVARA_MAC_SIGNING_MODE must be developer-id or adhoc.');
  const identity = env.ENVARA_MAC_SIGNING_IDENTITY ?? '';
  const team = env.ENVARA_MAC_SIGNING_TEAM_ID ?? '';
  if (mode === 'adhoc') {
    requireValue(!identity && !team, 'Ad-hoc mode cannot include ENVARA_MAC_SIGNING_IDENTITY or ENVARA_MAC_SIGNING_TEAM_ID.');
    return { mode, identity: '-', team: null };
  }
  requireValue(/^[A-Fa-f0-9]{40}$/.test(identity),
    'Set ENVARA_MAC_SIGNING_IDENTITY to the SHA-1 of an existing Developer ID Application identity, or explicitly select ENVARA_MAC_SIGNING_MODE=adhoc.');
  requireValue(/^[A-Z0-9]{10}$/.test(team), 'Set ENVARA_MAC_SIGNING_TEAM_ID to the matching Apple team identifier.');
  return { mode, identity: identity.toUpperCase(), team };
}

export function selectSigningIdentity(text, request) {
  requireValue(request.mode === 'developer-id', 'Certificate selection requires developer-id mode.');
  const records = [...text.matchAll(/^\s*\d+\)\s+([A-Fa-f0-9]{40})\s+"([^"\r\n]+)"\s*$/gm)]
    .map(([, identity, name]) => ({ identity: identity.toUpperCase(), name }));
  const matches = records.filter(item => item.identity === request.identity);
  requireValue(matches.length === 1, 'The selected signing identity must occur exactly once among valid code-signing identities.');
  const selected = matches[0];
  requireValue(selected.name.startsWith('Developer ID Application: ') && selected.name.endsWith(` (${request.team})`),
    'The selected identity is not a Developer ID Application identity for the requested team.');
  return { ...request, name: selected.name };
}

// Accept the generated Developer ID requirement, never an identifier-only or
// cdhash requirement. A fixed grammar intentionally refuses unknown weakenings.
export function validateDesignatedRequirement(text, identifier, team) {
  const lines = text.split(/\r?\n/).map(line => line.trim()).filter(line => line.startsWith('designated => '));
  requireValue(lines.length === 1, 'Missing or ambiguous designated requirement.');
  const actual = lines[0].slice('designated => '.length).replace(/\s+/g, ' ');
  const clauses = actual.split(' and ');
  const expected = [
    `identifier ${JSON.stringify(identifier)}`,
    'anchor apple generic',
    'certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */',
    'certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */',
    `certificate leaf[subject.OU] = ${JSON.stringify(team)}`,
  ];
  // codesign may omit quotes around a simple team value.
  const normalize = value => value.replace(`= ${team}`, `= ${JSON.stringify(team)}`);
  requireValue(clauses.length === expected.length && new Set(clauses.map(normalize)).size === expected.length
    && expected.every(value => clauses.map(normalize).includes(value)), 'Unrecognized or unstable Developer ID designated requirement.');
  return actual;
}

export async function command(commandPath, args, { cwd = repository, env = process.env, timeout = 900_000, input,
  terminateGrace = 2000, spawnProcess = spawn, signalProcess = process.kill.bind(process) } = {}) {
  return await new Promise((resolve, reject) => {
    const child = spawnProcess(commandPath, args, { cwd, env, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
    child.stdin.on('error', () => {});
    child.stdin.end(input ?? '');
    const output = [[], []]; let bytes = 0, stopped = false, settled = false, leaderExited = false, escalation, deadline;
    const signalOwnedGroup = signal => {
      // An exited leader's numeric PID is no longer authority: descendants can
      // keep pipes open after exit while that PID becomes available for reuse.
      if (!settled && !leaderExited && child.exitCode == null && child.signalCode == null
        && Number.isSafeInteger(child.pid) && child.pid > 1) try { signalProcess(-child.pid, signal); }
      catch (error) { if (error.code !== 'ESRCH') stopped = true; }
    };
    const finish = (code, signal, closeConfirmed) => {
      if (settled) return; settled = true;
      clearTimeout(timer); clearTimeout(escalation); clearTimeout(deadline);
      if (!closeConfirmed) { child.stdout.destroy(); child.stderr.destroy(); child.stdin.destroy(); child.unref(); }
      resolve({ code: stopped ? 124 : code ?? 128, signal, closeConfirmed, cleanupUncertain: stopped,
        stdout: Buffer.concat(output[0]).toString(), stderr: Buffer.concat(output[1]).toString() });
    };
    const stop = () => {
      if (stopped || settled) return; stopped = true; signalOwnedGroup('SIGTERM');
      if (settled) return;
      escalation = setTimeout(() => signalOwnedGroup('SIGKILL'), terminateGrace);
      deadline = setTimeout(() => finish(124, 'deadline', false), terminateGrace * 2);
    };
    const timer = setTimeout(stop, timeout);
    for (const [index, stream] of [child.stdout, child.stderr].entries()) stream.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > 40 * 1024 * 1024) stop(); else output[index].push(chunk);
    });
    child.once('error', error => { if (!settled) { settled = true; clearTimeout(timer); clearTimeout(escalation); clearTimeout(deadline); reject(error); } });
    child.once('exit', () => { leaderExited = true; });
    child.once('close', (code, signal) => finish(code, signal, true));
  });
}

export async function signingGate({ env = process.env, platform = process.platform, arch = process.arch, run = command } = {}) {
  const request = signingRequest(env);
  requireValue(platform === 'darwin' && arch === 'arm64', 'This release workflow currently supports macOS Apple Silicon only.');
  if (request.mode === 'adhoc') return request;
  const result = await run('/usr/bin/security', ['find-identity', '-v', '-p', 'codesigning']);
  requireValue(result.code === 0, 'Unable to inspect existing signing identities.');
  return selectSigningIdentity(result.stdout, request);
}

// electron-builder invokes this hook before extracting Electron or preparing
// the application directory, including when an old helper invokes it directly.
export async function beforePack(context, { env = process.env, home = os.homedir(), run = command } = {}) {
  if (['win32', 'linux'].includes(context.electronPlatformName)) return;
  requireValue(context.electronPlatformName === 'darwin', 'Unsupported macOS packaging target; use npm run dist:mac.');
  const paths = releaseWorkspacePaths(home), nonce = env.ENVARA_MAC_RELEASE_NONCE;
  requireValue(/^[0-9a-f-]{36}$/.test(nonce ?? '') && context.arch === 3
    && context.appOutDir === path.dirname(paths.candidateApp) && context.outDir === paths.candidateOutput
    // In the pinned MacPackager, --dir deliberately creates no archive target.
    && Array.isArray(context.targets) && context.targets.length === 0,
  'macOS packaging must use npm run dist:mac and its fixed owned workspace.');
  const project = context.packager?.projectDir;
  requireValue(typeof project === 'string' && await fs.realpath(project) === project
    && context.packager.config?.mac?.identity === null && env.CSC_IDENTITY_AUTO_DISCOVERY === 'false', 'Unexpected macOS builder configuration.');
  for (const name of ['owner.json', 'lock.json', 'state.json']) {
    const filename = path.join(paths.root, name), stat = await fs.lstat(filename);
    requireValue(stat.isFile() && !stat.isSymbolicLink() && stat.uid === process.getuid() && (stat.mode & 0o077) === 0
      && stat.nlink === 1 && await fs.realpath(filename) === filename, 'Unsafe release workspace authorization.');
  }
  const owner = JSON.parse(await fs.readFile(path.join(paths.root, 'owner.json'), 'utf8'));
  const lock = JSON.parse(await fs.readFile(path.join(paths.root, 'lock.json'), 'utf8'));
  const state = JSON.parse(await fs.readFile(path.join(paths.root, 'state.json'), 'utf8'));
  requireValue(owner.repository === project && lock.repository === project && lock.nonce === nonce && state.nonce === nonce
    && state.complete === false && lock.pid === Number(env.ENVARA_MAC_RELEASE_PARENT_PID), 'Release workspace authorization differs.');
  await signingGate({ env, platform: 'darwin', arch: 'arm64', run });
}

async function retainBuilderMetadata(workspace) {
  const allowed = new Set(['mac-arm64', 'builder-effective-config.yaml', 'builder-debug.yml', '.icon-icns']);
  const names = await fs.readdir(workspace.candidateOutput);
  requireValue(names.every(name => allowed.has(name)), 'Unknown file in builder output.');
  const retained = path.join(workspace.evidenceDir, 'builder-output');
  await fs.mkdir(retained, { mode: 0o700 });
  async function safeMetadata(filename, icons = false) {
    const stat = await fs.lstat(filename);
    requireValue(!stat.isSymbolicLink() && stat.uid === process.getuid() && await fs.realpath(filename) === filename,
      'Unsafe builder metadata.');
    if (stat.isDirectory()) {
      requireValue(icons && !filename.endsWith('.app'), 'Unknown builder metadata directory.');
      for (const name of await fs.readdir(filename)) await safeMetadata(path.join(filename, name), true);
    } else requireValue(stat.isFile() && (!icons || /\.(?:icns|png)$/.test(filename)), 'Unknown builder metadata file.');
  }
  for (const name of names.filter(name => name !== 'mac-arm64')) {
    const filename = path.join(workspace.candidateOutput, name);
    await safeMetadata(filename, name === '.icon-icns');
    await fs.rename(filename, path.join(retained, name));
  }
}

export async function inventory(root) {
  requireValue(await fs.realpath(root) === root && !(await fs.lstat(root)).isSymbolicLink(), 'Noncanonical app bundle.');
  const rows = {};
  async function visit(item) {
    const stat = await fs.lstat(item), relative = path.relative(root, item) || '.';
    const row = { mode: stat.mode & 0o7777 };
    if (stat.isSymbolicLink()) {
      requireValue(within(root, await fs.realpath(item)), 'Escaping app symlink.');
      Object.assign(row, { kind: 'symlink', target: await fs.readlink(item) });
    } else if (stat.isDirectory()) {
      row.kind = 'directory';
      for (const name of (await fs.readdir(item)).sort()) await visit(path.join(item, name));
    } else {
      requireValue(stat.isFile(), 'Special file in app bundle.');
      Object.assign(row, { kind: 'file', bytes: stat.size, sha256: hash(await fs.readFile(item)) });
    }
    rows[relative] = row;
  }
  await visit(root);
  return Object.fromEntries(Object.entries(rows).sort(([a], [b]) => a.localeCompare(b)));
}

export async function inspectCandidateAcceptanceScript(root, run = command) {
  const filename = path.join(root, CANDIDATE_ACCEPTANCE_SCRIPT), info = await fs.lstat(filename);
  requireValue(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && info.uid === process.getuid()
    && !(info.mode & 0o022) && await fs.realpath(filename) === filename, 'Unsafe candidate acceptance script.');
  const tracked = await run('git', ['ls-files', '--error-unmatch', '--', CANDIDATE_ACCEPTANCE_SCRIPT], { cwd: root });
  requireValue(tracked.code === 0 && tracked.stdout.trim() === CANDIDATE_ACCEPTANCE_SCRIPT,
    'Candidate acceptance script must belong to the reviewed source commit.');
  return filename;
}

export function validateCandidateAcceptance(receipt, expected) {
  requireValue(receipt && typeof receipt === 'object' && !Array.isArray(receipt)
    && receipt.schema === CANDIDATE_ACCEPTANCE_SCHEMA, 'Invalid candidate acceptance receipt.');
  for (const key of ['sourceCommit', 'app', 'runtime', 'nonce', 'candidateManifestSHA256'])
    requireValue(receipt[key] === expected[key], `Candidate acceptance ${key} binding differs.`);
  if (receipt.cleanup?.complete !== true || receipt.cleanup.remainingOwnedProcesses !== 0)
    throw Object.assign(new Error('Candidate acceptance cleanup was not confirmed.'), { candidateAcceptanceCleanupUncertain: true });
  try {
    requireValue(receipt.passed === true && receipt.appLaunched === true, 'Candidate application acceptance did not pass.');
    requireValue(Array.isArray(receipt.checks) && receipt.checks.length >= CANDIDATE_ACCEPTANCE_CHECKS.length
      && receipt.checks.length <= 64, 'Candidate acceptance checks are missing or invalid.');
    const ids = new Set();
    for (const check of receipt.checks) {
      requireValue(check && typeof check === 'object' && !Array.isArray(check) && /^[a-z][a-z0-9-]{0,79}$/.test(check.id)
        && !ids.has(check.id) && check.passed === true, 'Candidate acceptance contains duplicate, invalid or failed checks.');
      ids.add(check.id);
    }
    requireValue(CANDIDATE_ACCEPTANCE_CHECKS.every(id => ids.has(id)), 'Candidate acceptance required checks are missing.');
  } catch (error) {
    // A failed acceptance check and an uncertain cleanup are different states.
    // Only a correctly bound receipt may positively confirm this cleanup.
    error.candidateAcceptanceCleanupConfirmed = true;
    throw error;
  }
  return receipt;
}

export async function readCandidateAcceptanceReceipt(filename, expected) {
  const before = await fs.lstat(filename, { bigint: true });
  const valid = info => info.isFile() && !info.isSymbolicLink() && info.uid === BigInt(process.getuid())
    && info.nlink === 1n && (info.mode & 0o7777n) === 0o600n && info.size > 0n && info.size <= BigInt(receiptLimit);
  const identity = info => [info.dev, info.ino, info.uid, info.nlink, info.mode, info.size, info.mtimeNs, info.ctimeNs].map(String).join(':');
  requireValue(valid(before) && await fs.realpath(filename) === filename, 'Unsafe candidate acceptance receipt file.');
  const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    requireValue(identity(await handle.stat({ bigint: true })) === identity(before), 'Candidate receipt changed while opening.');
    // Bound the read independently of the earlier stat in case a writer grows it.
    const buffer = Buffer.alloc(receiptLimit + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, length);
      if (!bytesRead) break;
      length += bytesRead;
    }
    requireValue(length <= receiptLimit && BigInt(length) === before.size
      && identity(await handle.stat({ bigint: true })) === identity(before)
      && identity(await fs.lstat(filename, { bigint: true })) === identity(before), 'Candidate receipt changed during reading.');
    return validateCandidateAcceptance(JSON.parse(buffer.subarray(0, length).toString('utf8')), expected);
  } finally { await handle.close(); }
}

export async function assertCandidateIdle({ app, runtime, run = command }) {
  const inspect = async (cmd, args) => {
    const result = await run(cmd, args, { timeout: 45000, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' } });
    requireValue(result.cleanupUncertain !== true && result.closeConfirmed !== false, 'Candidate process inspection did not complete.');
    return result;
  };
  try {
    const ps = await inspect('/bin/ps', ['-axo', 'pid=,ppid=,pgid=,lstart=,comm=']);
    requireValue(ps.code === 0 && !ps.stderr.trim() && ps.stdout.trim(), 'Candidate process inspection failed.');
    const seen = new Set();
    for (const line of ps.stdout.split('\n').filter(line => line.trim())) {
      const row = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+(.+?)\s*$/.exec(line);
      requireValue(row && !seen.has(row[1]), 'Invalid candidate process inventory.');
      seen.add(row[1]);
      requireValue(row[4] !== 'Envara' && !within(app, row[4]) && !within(runtime, row[4]), 'Candidate acceptance process is still running.');
    }
    for (const directory of [app, runtime]) {
      const open = await inspect('/usr/sbin/lsof', ['-nP', '-Fpf', '+D', directory]);
      requireValue(open.code === 1 && !open.stdout.trim() && !open.stderr.trim(), 'Candidate or acceptance runtime is still in use, or inspection failed.');
    }
  } catch (error) {
    error.candidateAcceptanceCleanupUncertain = true;
    throw error;
  }
}

/** Runs only the reviewed repository runner; a receipt alone cannot publish. */
export async function runCandidateAcceptance({ root, app, runtime, evidence, sourceCommit, nonce, candidateManifestSHA256,
  script = path.join(root, CANDIDATE_ACCEPTANCE_SCRIPT), run = command }) {
  requireValue(script === path.join(root, CANDIDATE_ACCEPTANCE_SCRIPT) && /^[0-9a-f]{40}$/.test(sourceCommit)
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(nonce)
    && /^[0-9a-f]{64}$/.test(candidateManifestSHA256), 'Invalid candidate acceptance binding.');
  for (const directory of [runtime, path.join(runtime, 'home'), path.join(runtime, 'work'), evidence]) {
    const info = await fs.lstat(directory);
    requireValue(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid()
      && (info.mode & 0o7777) === 0o700 && await fs.realpath(directory) === directory, 'Unsafe candidate acceptance directory.');
  }
  const filename = path.join(evidence, 'candidate-acceptance.json');
  try { await fs.lstat(filename); throw new Error('Candidate acceptance receipt already exists.'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const before = await inventory(app);
  requireValue(hash(JSON.stringify(before)) === candidateManifestSHA256, 'Signed candidate changed before acceptance.');
  await assertCandidateIdle({ app, runtime, run });
  let result, operationError;
  try {
    const launched = await run(process.execPath, [script, '--app', app, '--runtime', runtime, '--evidence', evidence,
      '--receipt', filename, '--source-commit', sourceCommit, '--nonce', nonce, '--candidate-manifest-sha256', candidateManifestSHA256],
    { cwd: root, timeout: 600_000, env: { PATH: `${path.dirname(process.execPath)}:/usr/bin:/bin:/usr/sbin:/sbin`,
      HOME: path.join(runtime, 'home'), USERPROFILE: path.join(runtime, 'home'), TMPDIR: path.join(runtime, 'work') + path.sep,
      TMP: path.join(runtime, 'work'), TEMP: path.join(runtime, 'work'), LANG: 'en_US.UTF-8', LC_ALL: 'en_US.UTF-8', TZ: 'UTC' } });
    const runnerError = launched.code !== 0 || launched.cleanupUncertain === true || launched.closeConfirmed === false
      ? Object.assign(new Error('Candidate acceptance runner did not complete successfully.'),
        { candidateAcceptanceCleanupUncertain: launched.cleanupUncertain === true || launched.closeConfirmed === false }) : null;
    // A failed runner can still report incomplete Keychain or other non-process
    // cleanup. A clean ps/lsof snapshot cannot replace that bound receipt.
    try { result = await readCandidateAcceptanceReceipt(filename, { sourceCommit, app, runtime, nonce, candidateManifestSHA256 }); }
    catch (error) {
      const uncertain = error.candidateAcceptanceCleanupConfirmed !== true;
      if (runnerError) {
        runnerError.candidateAcceptanceCleanupUncertain ||= uncertain;
        if (uncertain) runnerError.acceptanceCleanupErrors = [`Candidate cleanup receipt could not be confirmed: ${error.message}`];
        throw runnerError;
      }
      error.candidateAcceptanceCleanupUncertain ||= uncertain;
      throw error;
    }
    if (runnerError) throw runnerError;
    requireValue(JSON.stringify(await inventory(app)) === JSON.stringify(before), 'Signed candidate changed during acceptance.');
  } catch (error) { operationError = error; }
  try { await assertCandidateIdle({ app, runtime, run }); }
  catch (error) {
    if (!operationError) operationError = error;
    else {
      operationError.candidateAcceptanceCleanupUncertain = true;
      operationError.acceptanceCleanupErrors = [...(operationError.acceptanceCleanupErrors ?? []), error.message];
    }
  }
  if (operationError) throw operationError;
  return result;
}

function field(text, name) {
  const lines = text.split(/\r?\n/).filter(line => line.startsWith(`${name}=`));
  requireValue(lines.length === 1, `Missing or ambiguous signing field: ${name}`);
  return lines[0].slice(name.length + 1);
}

export function candidateSigningOptions(identity, flags, identifier) {
  const adhoc = identity?.mode === 'adhoc';
  requireValue(adhoc ? identity.identity === '-' && identity.team === null
    : identity?.mode === 'developer-id' && /^[A-F0-9]{40}$/.test(identity.identity) && /^[A-Z0-9]{10}$/.test(identity.team),
  'Invalid signing mode or identity.');
  requireValue(Number.isSafeInteger(flags) && flags >= 0 && flags <= 0xffffffff, 'Invalid original signature flags.');
  // Remove the linker signature and let codesign set CS_ADHOC for the explicit
  // ad-hoc mode. Preserve all other flags, including the existing runtime policy.
  const optionsFlags = (flags & ~0x20002) >>> 0;
  return {
    args: ['--force', '--sign', identity.identity, adhoc ? '--timestamp=none' : '--timestamp',
      '--options', `0x${optionsFlags.toString(16)}`, '--identifier', identifier],
    expectedFlags: (optionsFlags | (adhoc ? 0x2 : 0)) >>> 0,
  };
}

export function validateSignedIdentity(text, identifier, identity) {
  requireValue(field(text, 'Identifier') === identifier, 'Final bundle signing identifier differs.');
  if (identity.mode === 'adhoc') {
    requireValue(identity.identity === '-' && identity.team === null && field(text, 'Signature') === 'adhoc'
      && field(text, 'TeamIdentifier') === 'not set' && !/^Authority=/m.test(text), 'Final ad-hoc signing identity differs.');
    const cdhash = field(text, 'CDHash');
    requireValue(/^[A-Fa-f0-9]{40}$/.test(cdhash), 'Missing or invalid ad-hoc code hash.');
    return { mode: 'adhoc', identifier, team: null, certificateSHA1: null, cdhash: cdhash.toLowerCase() };
  }
  requireValue(identity.mode === 'developer-id' && !/^Signature=adhoc$/m.test(text)
    && field(text, 'TeamIdentifier') === identity.team, 'Final bundle signing identity differs.');
  return { mode: 'developer-id', identifier, team: identity.team, certificateSHA1: identity.identity };
}

export function validateAdhocRequirement(text, cdhash) {
  const lines = text.split(/\r?\n/).map(line => line.trim()).filter(line => /^(?:#\s*)?designated => /.test(line));
  requireValue(lines.length === 1, 'Missing or ambiguous ad-hoc designated requirement.');
  const match = /^(?:#\s*)?designated => (cdhash H"([A-Fa-f0-9]{40})")$/.exec(lines[0]);
  requireValue(match && match[2].toLowerCase() === cdhash, 'Ad-hoc designated requirement differs from its code hash.');
  return match[1];
}

async function signatureMetadata(app, relative, run) {
  const bundle = path.resolve(app, relative), info = await fs.lstat(bundle);
  requireValue(info.isDirectory() && !info.isSymbolicLink() && within(app, await fs.realpath(bundle)), 'Signing target escaped app.');
  const display = await run('/usr/bin/codesign', ['--display', '--verbose=4', bundle]);
  const text = display.stdout + display.stderr;
  const executable = await fs.realpath(field(text, 'Executable'));
  requireValue(within(app, executable), 'Signing executable escaped app.');
  const flags = text.match(/^CodeDirectory.*flags=(0x[A-Fa-f0-9]+)/m);
  requireValue(flags, 'Missing signing flags.');
  const entitlements = await run('/usr/bin/codesign', ['--display', '--entitlements', '-', '--xml', bundle]);
  const sealParent = relative.endsWith('.framework') ? path.dirname(executable) : path.dirname(path.dirname(executable));
  return { relative, bundle, identifier: field(text, 'Identifier'), executable: path.relative(app, executable),
    adhoc: /^Signature=adhoc$/m.test(text), team: field(text, 'TeamIdentifier'), flags: Number(flags[1]),
    entitlements: entitlements.stdout.trim(), seal: path.relative(app, path.join(sealParent, '_CodeSignature')), text };
}

export function validateSigningChanges(before, after, metadata) {
  const allowed = new Set(metadata.flatMap(item => [item.executable, item.seal, `${item.seal}/CodeResources`]));
  const changed = [...new Set([...Object.keys(before), ...Object.keys(after)])]
    .filter(key => JSON.stringify(before[key]) !== JSON.stringify(after[key]));
  requireValue(changed.every(key => allowed.has(key) && !key.startsWith('Contents/Resources/')),
    'Signing modified files outside the nine owned executable/signature targets.');
  return changed;
}

export async function verifySignedBundle(bundle, identifier, identity, run, evidence, index) {
  await run('/usr/bin/codesign', ['--verify', '--strict', bundle]);
  const display = await run('/usr/bin/codesign', ['--display', '--verbose=4', bundle]);
  const text = display.stdout + display.stderr;
  const verified = validateSignedIdentity(text, identifier, identity);
  const requirements = await run('/usr/bin/codesign', ['--display', '--requirements', '-', bundle]);
  if (identity.mode === 'adhoc') return { ...verified,
    requirement: validateAdhocRequirement(requirements.stdout + requirements.stderr, verified.cdhash) };
  const requirement = validateDesignatedRequirement(requirements.stdout + requirements.stderr, identifier, identity.team);
  const prefix = path.join(evidence, `certificate-${index}-`);
  await run('/usr/bin/codesign', ['--display', '--extract-certificates', prefix, bundle]);
  const cert = new X509Certificate(await fs.readFile(`${prefix}0`));
  requireValue(cert.fingerprint.replaceAll(':', '').toUpperCase() === identity.identity, 'Final leaf certificate differs from the selected identity.');
  return { ...verified, requirement };
}

async function signCandidate(app, identity, run, evidence) {
  const before = await inventory(app), metadata = [];
  for (const relative of signingTargets) metadata.push(await signatureMetadata(app, relative, run));
  for (const item of metadata) requireValue(item.adhoc && item.team === 'not set', 'Refusing to replace an existing vendor or unknown signature.');
  const verified = [];
  for (const [index, item] of metadata.entries()) {
    const identifier = item.relative === '.' ? 'io.envara.desktop' : item.identifier;
    // Preserve the existing runtime policy. Enabling hardened runtime here
    // would also require reviewed Electron JIT/native-module entitlements and
    // real launch acceptance; stable Developer ID identity alone does not.
    const { args, expectedFlags } = candidateSigningOptions(identity, item.flags, identifier);
    if (item.entitlements) {
      const entitlementsPath = path.join(evidence, `entitlements-${index}.plist`);
      await fs.writeFile(entitlementsPath, `${item.entitlements}\n`, { flag: 'wx', mode: 0o600 });
      args.push('--entitlements', entitlementsPath);
    }
    // Regenerate the selected mode's designated requirement. Never recursively
    // re-sign pinned routing carriers, vendor programs, drivers, or app resources.
    await run('/usr/bin/codesign', [...args, item.bundle]);
    verified.push(await verifySignedBundle(item.bundle, identifier, identity, run, evidence, index));
    const current = await signatureMetadata(app, item.relative, run);
    requireValue(current.entitlements === item.entitlements && current.flags === expectedFlags, 'Entitlements or signature flags differ after signing.');
  }
  await run('/usr/bin/codesign', ['--verify', '--deep', '--strict', app]);
  const after = await inventory(app);
  const changed = validateSigningChanges(before, after, metadata);
  await fs.writeFile(path.join(evidence, 'signing.json'), JSON.stringify({ verified, changed, resourcesUnchanged: true, before, after }, null, 2), { flag: 'wx', mode: 0o600 });
  return after;
}

const preparation = ['native:prepare', 'claude:keychain:prepare', 'backend:prepare', 'proxy:prepare', 'routing:build:mac',
  'routing:build:mac:local', 'routing:build:mac:acceptance', 'routing:build:mac:pf',
  'routing:prepare:mac:package', 'routing:build:mac:link-router', 'build'];

export async function buildMacRelease({ env = process.env, platform = process.platform, arch = process.arch,
  home = os.homedir(), root = repository, run = command, openWorkspace = openReleaseWorkspace, checkOnly = false } = {}) {
  // Keep this ahead of all mutable operations, including opening the workspace.
  const identity = await signingGate({ env, platform, arch, run });
  if (checkOnly) return { ready: true, identity, workspaceCreated: false };
  const buildEnv = { ...env, ENVARA_MAC_SIGNING_MODE: identity.mode, CSC_IDENTITY_AUTO_DISCOVERY: 'false', COPYFILE_DISABLE: '1', DITTONORSRC: '1' };
  let evidenceDirectory, uncertainCommand = false;
  const recorded = async (cmd, args, options = {}) => {
    const result = await run(cmd, args, { cwd: root, env: buildEnv, ...options });
    uncertainCommand ||= result.cleanupUncertain === true || result.closeConfirmed === false;
    if (evidenceDirectory) await fs.appendFile(path.join(evidenceDirectory, 'commands.jsonl'),
      `${JSON.stringify({ command: cmd, args, code: result.code, stdout: result.stdout, stderr: result.stderr })}\n`, { mode: 0o600 });
    return result;
  };
  const checked = async (...args) => {
    const result = await recorded(...args);
    requireValue(result.code === 0, `${path.basename(args[0])} failed (${result.code}); retained local release evidence requires review.`);
    return result;
  };
  const commit = (await checked('git', ['rev-parse', 'HEAD'])).stdout.trim();
  const frozen = async () => requireValue((await checked('git', ['rev-parse', 'HEAD'])).stdout.trim() === commit
    && !(await checked('git', ['status', '--porcelain'])).stdout.trim(), 'Release source must remain a clean, reviewed commit.');
  await frozen();
  const acceptanceScript = await inspectCandidateAcceptanceScript(root, checked);
  const pkg = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8'));
  requireValue(/^\d+\.\d+\.\d+$/.test(pkg.version) && pkg.build?.appId === 'io.envara.desktop', 'Unexpected release version or bundle identifier.');
  const workspace = await openWorkspace({ home, repository: root });
  evidenceDirectory = workspace.evidenceDir;
  const authorization = JSON.parse(await fs.readFile(path.join(workspace.root, 'lock.json'), 'utf8'));
  buildEnv.ENVARA_MAC_RELEASE_NONCE = authorization.nonce;
  buildEnv.ENVARA_MAC_RELEASE_PARENT_PID = String(process.pid);
  let operationError, cleanup, receipt;
  try {
    for (const script of preparation) await checked('npm', ['run', script]);
    await frozen();
    await checked(process.execPath, ['scripts/verify-public-release.mjs']);
    await workspace.claim('candidate');
    const builderConfig = path.join(workspace.evidenceDir, 'builder.json');
    await fs.writeFile(builderConfig, JSON.stringify({ ...pkg.build, directories: { ...pkg.build.directories, output: workspace.candidateOutput },
      mac: { ...pkg.build.mac, identity: null, notarize: false } }), { flag: 'wx', mode: 0o600 });
    await checked(path.join(root, 'node_modules/.bin/electron-builder'), ['--mac', '--arm64', '--dir',
      '--config', builderConfig]);
    await retainBuilderMetadata(workspace);
    const plist = JSON.parse((await checked('/usr/bin/plutil', ['-convert', 'json', '-o', '-', path.join(workspace.candidateApp, 'Contents/Info.plist')])).stdout);
    requireValue(plist.CFBundleIdentifier === 'io.envara.desktop' && plist.CFBundleShortVersionString === pkg.version, 'Packaged bundle identity/version differs.');
    const manifest = await signCandidate(workspace.candidateApp, identity, checked, workspace.evidenceDir);
    await workspace.seal('candidate');
    for (const script of ['verify-package-resources.mjs', 'verify-public-release.mjs']) {
      await checked(process.execPath, [`scripts/${script}`, ...(script === 'verify-public-release.mjs' ? ['--app'] : []), workspace.candidateApp]);
    }
    await frozen();
    const acceptance = await runCandidateAcceptance({ root, app: workspace.candidateApp, runtime: workspace.runtimeDir,
      evidence: workspace.evidenceDir, sourceCommit: commit, nonce: authorization.nonce,
      candidateManifestSHA256: hash(JSON.stringify(manifest)), script: acceptanceScript, run: recorded });
    await frozen();
    const release = path.join(root, 'release');
    await fs.mkdir(release, { recursive: true });
    requireValue(await fs.realpath(release) === release && !(await fs.lstat(release)).isSymbolicLink(), 'Noncanonical release output.');
    const stem = `Envara-${pkg.version}-mac-arm64`, outputs = {};
    for (const name of [`${stem}.zip`, `${stem}.dmg`, 'SHA256SUMS.txt']) {
      try { await fs.lstat(path.join(release, name)); throw new Error(`Refuse overwriting release/${name}.`); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    const archiveFile = suffix => path.join(workspace.evidenceDir, `${stem}.${suffix}`);
    await workspace.claim('payload');
    await checked('/usr/bin/ditto', ['--noqtn', '--norsrc', '--noextattr', workspace.candidateApp, workspace.payloadApp]);
    await workspace.seal('payload');
    await checked('/usr/bin/ditto', ['-c', '-k', '--sequesterRsrc', '--keepParent', '--noqtn', '--norsrc', '--noextattr', workspace.candidateApp, archiveFile('zip')]);
    await workspace.claim('zip');
    await checked('/usr/bin/ditto', ['-x', '-k', '--noqtn', '--norsrc', '--noextattr', archiveFile('zip'), workspace.zipDir]);
    await workspace.seal('zip');
    requireValue(JSON.stringify((await fs.readdir(workspace.payloadDir)).sort()) === JSON.stringify(['Envara.app']), 'Unknown file in archive payload.');
    await checked('/usr/bin/hdiutil', ['create', '-volname', `Envara ${pkg.version}`, '-srcfolder', workspace.payloadDir, '-format', 'UDZO', archiveFile('dmg')]);
    await workspace.claim('mounted');
    const mount = await checked('/usr/bin/hdiutil', ['attach', '-readonly', '-nobrowse', '-noautoopen', '-plist', '-mountpoint', workspace.mountDir, archiveFile('dmg')]);
    const mountPlist = path.join(workspace.evidenceDir, 'mount.plist');
    await fs.writeFile(mountPlist, mount.stdout, { flag: 'wx', mode: 0o600 });
    const mounted = JSON.parse((await checked('/usr/bin/plutil', ['-convert', 'json', '-o', '-', mountPlist])).stdout);
    const volumes = mounted['system-entities']?.filter(item => item['mount-point'] === workspace.mountDir) ?? [];
    requireValue(volumes.length === 1 && /^\/dev\/disk\d+s?\d*$/.test(volumes[0]['dev-entry']), 'Unable to bind the owned read-only mount.');
    await workspace.seal('mounted', { device: volumes[0]['dev-entry'], imagePath: archiveFile('dmg') });
    for (const directory of [workspace.payloadDir, workspace.zipDir, workspace.mountDir]) {
      requireValue(JSON.stringify((await fs.readdir(directory)).sort()) === JSON.stringify(['Envara.app']), 'Unknown file outside archived application.');
    }
    for (const app of [workspace.payloadApp, workspace.zipApp, workspace.mountedApp]) {
      requireValue(JSON.stringify(await inventory(app)) === JSON.stringify(manifest), 'Archived application differs from the signed candidate.');
      await checked('/usr/bin/codesign', ['--verify', '--deep', '--strict', app]);
    }
    await frozen();
    for (const suffix of ['dmg', 'zip']) outputs[`${stem}.${suffix}`] = hash(await fs.readFile(archiveFile(suffix)));
    receipt = { sourceCommit: commit, version: pkg.version, identity, outputs, signedManifestSHA256: hash(JSON.stringify(manifest)),
      exactArchivesVerified: true, published: false, installed: false, appLaunched: acceptance.appLaunched, notarized: false,
      acceptance: { schema: acceptance.schema, nonce: acceptance.nonce, checks: acceptance.checks, cleanup: acceptance.cleanup,
        receipt: path.join(workspace.evidenceDir, 'candidate-acceptance.json') } };
    await fs.writeFile(path.join(workspace.evidenceDir, 'archive.json'), JSON.stringify(receipt, null, 2), { flag: 'wx', mode: 0o600 });
  } catch (error) { operationError = error; uncertainCommand ||= error.candidateAcceptanceCleanupUncertain === true; }
  // A failed LS unregister/detach is a release failure. Keep the journal and
  // fixed slots for inspection instead of making a new bundle path on retry.
  try { cleanup = uncertainCommand ? { complete: false, cleanupErrors: [
      ...(operationError?.acceptanceCleanupErrors ?? []),
      'Command or candidate acceptance cleanup was uncertain; fixed staging and journal retained.',
    ] }
    : await workspace.cleanup({ run, operationError: operationError?.message }); }
  catch (error) { cleanup = { complete: false, cleanupErrors: [error.message] }; }
  if (operationError || !cleanup.complete) {
    const error = new Error(operationError?.message ?? 'Release staging cleanup was not confirmed.');
    error.operationError = operationError?.message ?? null; error.cleanupErrors = cleanup.cleanupErrors;
    throw error;
  }
  // Publishable files appear only after signatures, archive equality and owned
  // LaunchServices cleanup all pass. Copies never overwrite a prior artifact.
  for (const name of Object.keys(receipt.outputs)) await fs.copyFile(path.join(workspace.evidenceDir, name), path.join(root, 'release', name), fs.constants.COPYFILE_EXCL);
  await fs.writeFile(path.join(root, 'release/SHA256SUMS.txt'), Object.entries(receipt.outputs).map(([name, digest]) => `${digest}  ${name}\n`).join(''), { flag: 'wx', mode: 0o644 });
  return { ...receipt, cleanup, evidence: workspace.evidenceDir };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    requireValue(process.argv.slice(2).every(arg => arg === '--check') && process.argv.length <= 3, 'Usage: node scripts/build-macos-release.mjs [--check]');
    console.log(JSON.stringify(await buildMacRelease({ checkOnly: process.argv.includes('--check') }), null, 2));
  } catch (error) {
    console.error(JSON.stringify({ passed: false, error: error.message, operationError: error.operationError,
      cleanupErrors: error.cleanupErrors ?? [] }));
    process.exitCode = 1;
  }
}
