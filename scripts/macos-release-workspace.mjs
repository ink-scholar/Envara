import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';

export const LSREGISTER = '/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister';
export const RELEASE_SLOT_KINDS = Object.freeze(['candidate', 'payload', 'zip', 'mounted']);
const schema = 'envara.macos-release-workspace/v1';
const fail = (code, message = code) => { throw Object.assign(new Error(message), { code }); };
const requireThat = (value, code) => { if (!value) fail(code); };
const within = (root, value) => value === root || value.startsWith(root + path.sep);
const digest = value => createHash('sha256').update(value).digest('hex');
const exists = async filename => { try { await fs.lstat(filename); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } };
const identity = info => ({ dev: String(info.dev), ino: String(info.ino), uid: Number(info.uid), mode: Number(info.mode) & 0o7777,
  kind: info.isDirectory() ? 'directory' : info.isFile() ? 'file' : info.isSymbolicLink() ? 'symlink' : 'special' });
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const describe = async filename => identity(await fs.lstat(filename, { bigint: true }));

export function releaseWorkspacePaths(home) {
  const root = path.join(home, 'Library/Caches/io.envara.release/mac-arm64');
  const candidateOutput = path.join(root, 'candidate');
  const payloadDir = path.join(root, 'archive/payload'), zipDir = path.join(root, 'archive/zip-extracted'), mountDir = path.join(root, 'archive/mount');
  return { root, candidateOutput, candidateApp: path.join(candidateOutput, 'mac-arm64/Envara.app'), payloadDir,
    payloadApp: path.join(payloadDir, 'Envara.app'), zipDir, zipApp: path.join(zipDir, 'Envara.app'), mountDir,
    mountedApp: path.join(mountDir, 'Envara.app'), fixtureDir: path.join(root, 'fixtures'), runtimeDir: path.join(root, 'runtime') };
}

/** A complete dump is required. Never accept a substring match or an empty/error response. */
export function parseLaunchServicesDump(text) {
  requireThat(typeof text === 'string' && text.length > 0 && !text.includes('\0'), 'LS_DUMP_INVALID');
  const records = [];
  for (const block of text.split(/^\s*-{3,}\s*$/m)) {
    const paths = [...block.matchAll(/^\s*path:\s*(.*?)\s*$/gm)];
    const ids = [...block.matchAll(/^\s*identifier:\s*(.*?)\s*$/gm)];
    if (!paths.length && !ids.length) continue;
    requireThat(paths.length <= 1 && ids.length <= 1, 'LS_DUMP_DUPLICATE_FIELD');
    const identifier = ids.length ? ids[0][1].replace(/\s+\(0x[0-9a-f]+\)$/i, '') : null;
    if (identifier !== null) requireThat(identifier.length > 0 && !/[\r\n\0]/.test(identifier), 'LS_DUMP_INVALID_IDENTIFIER');
    const codeInfo = [...block.matchAll(/^\s*codeInfoID:\s*(.*?)\s*$/gm)];
    requireThat(codeInfo.length <= 1, 'LS_DUMP_DUPLICATE_FIELD');
    if (!paths.length) {
      requireThat(!/^io\.envara(?:\.|$)/i.test(identifier), 'LS_DUMP_INCOMPLETE_RECORD');
      continue;
    }
    const filename = paths[0][1].replace(/\s+\(0x[0-9a-f]+\)$/i, '');
    requireThat(path.isAbsolute(filename) && path.normalize(filename) === filename && !/[\r\n\0]/.test(filename), 'LS_DUMP_INVALID_PATH');
    records.push({ path: filename, identifier, ...(codeInfo.length ? { codeInfoID: codeInfo[0][1] } : {}) });
  }
  requireThat(records.length > 0, 'LS_DUMP_EMPTY_OR_UNRECOGNIZED');
  return records;
}
export const parseLS = parseLaunchServicesDump;

function protectedRegistrations(records) {
  return records.filter(item => item.path === '/Applications/Envara.app' || item.identifier === 'io.envara.link-router')
    .map(item => JSON.stringify(item)).sort();
}

export function planReleaseCleanup(paths, claims) {
  const slots = { candidate: paths.candidateApp, payload: paths.payloadApp, zip: paths.zipApp, mounted: paths.mountedApp };
  return ['mounted', 'zip', 'payload', 'candidate'].filter(kind => claims.some(item => item.kind === kind)).map(kind => {
    const matching = claims.filter(item => item.kind === kind);
    requireThat(matching.length === 1 && matching[0].path === slots[kind], 'CLEANUP_SLOT_INVALID');
    return { kind, path: slots[kind] };
  });
}

async function regularBytes(filename, uid) {
  const before = await fs.lstat(filename, { bigint: true });
  requireThat(before.isFile() && Number(before.uid) === uid && before.nlink === 1n
    && (Number(before.mode) & 0o7777) === 0o600, 'UNSAFE_REGULAR_FILE');
  const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    requireThat(same(identity(await handle.stat({ bigint: true })), identity(before)), 'FILE_IDENTITY_CHANGED');
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    requireThat(same(identity(after), identity(before)) && after.size === before.size && after.mtimeNs === before.mtimeNs, 'FILE_CHANGED_DURING_READ');
    return bytes;
  } finally { await handle.close(); }
}

async function fileHash(filename, uid) {
  const before = await fs.lstat(filename, { bigint: true });
  requireThat(before.isFile() && Number(before.uid) === uid && before.nlink === 1n, 'UNSAFE_BUNDLE_FILE');
  const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    requireThat(same(identity(await handle.stat({ bigint: true })), identity(before)), 'FILE_IDENTITY_CHANGED');
    const hash = createHash('sha256');
    for await (const chunk of handle.createReadStream({ autoClose: false })) hash.update(chunk);
    const after = await handle.stat({ bigint: true });
    requireThat(same(identity(after), identity(before)) && after.size === before.size && after.mtimeNs === before.mtimeNs, 'FILE_CHANGED_DURING_READ');
    return hash.digest('hex');
  } finally { await handle.close(); }
}

async function bundleTree(app, uid) {
  requireThat(await fs.realpath(app) === app, 'APP_NOT_CANONICAL');
  const rows = [];
  async function visit(filename, relative) {
    const before = await fs.lstat(filename, { bigint: true }), info = identity(before);
    requireThat(info.uid === uid && info.kind !== 'special', 'BUNDLE_OWNER_OR_TYPE_INVALID');
    const row = { relative, ...info };
    if (info.kind === 'file') { row.size = String(before.size); row.sha256 = await fileHash(filename, uid); }
    else if (info.kind === 'symlink') {
      row.target = await fs.readlink(filename);
      requireThat(within(app, await fs.realpath(filename)), 'BUNDLE_SYMLINK_ESCAPES');
    }
    rows.push(row);
    if (info.kind === 'directory') for (const name of (await fs.readdir(filename)).sort()) {
      requireThat(!/[\r\n\0]/.test(name), 'BUNDLE_NAME_INVALID');
      await visit(path.join(filename, name), relative === '.' ? name : relative + '/' + name);
    }
    requireThat(same(info, await describe(filename)), 'BUNDLE_CHANGED_DURING_INSPECTION');
  }
  await visit(app, '.');
  requireThat(rows[0].kind === 'directory', 'APP_NOT_DIRECTORY');
  for (const relative of ['Contents/Info.plist', 'Contents/Resources/app.asar'])
    requireThat(rows.some(row => row.relative === relative && row.kind === 'file'), 'APP_REQUIRED_FILE_MISSING');
  return rows;
}

function contentInventory(tree) {
  return Object.fromEntries(tree.map(item => {
    const value = { mode: item.mode, kind: item.kind };
    if (item.kind === 'file') Object.assign(value, { bytes: Number(item.size), sha256: item.sha256 });
    if (item.kind === 'symlink') value.target = item.target;
    return [item.relative, value];
  }).sort(([a], [b]) => a.localeCompare(b)));
}

async function privateDirectory(filename, uid, create = false) {
  if (create) try { await fs.mkdir(filename, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const info = await describe(filename);
  requireThat(info.kind === 'directory' && info.uid === uid && info.mode === 0o700 && await fs.realpath(filename) === filename, 'WORKSPACE_DIRECTORY_UNSAFE');
  return info;
}

async function directoryEntries(filename, allowed, uid, code) {
  await privateDirectory(filename, uid);
  const names = await fs.readdir(filename);
  requireThat(names.every(name => allowed.includes(name)), code);
  return names;
}

async function fixedStructure(paths, uid) {
  const entries = [
    [paths.root, ['owner.json', 'state.json', 'lock.json', 'candidate', 'archive', 'fixtures', 'runtime', 'evidence']],
    [paths.candidateOutput, ['mac-arm64']],
    [path.join(paths.root, 'archive'), ['payload', 'zip-extracted', 'mount']],
    [paths.runtimeDir, ['home', 'userData', 'work']],
  ];
  for (const [directory, names] of entries) if (await exists(directory))
    await directoryEntries(directory, names, uid, 'WORKSPACE_UNEXPECTED_ENTRY');
}

/** No app, process, registration or signing command runs while opening/claiming/sealing. */
export async function openReleaseWorkspace({ home = os.homedir(), repository, uid = process.getuid() } = {}) {
  requireThat(Number.isSafeInteger(uid) && uid === process.getuid(), 'WORKSPACE_UID_INVALID');
  for (const filename of [home, repository]) requireThat(typeof filename === 'string' && path.isAbsolute(filename)
    && path.resolve(filename) === filename && await fs.realpath(filename) === filename, 'WORKSPACE_INPUT_NOT_CANONICAL');
  requireThat((await describe(home)).kind === 'directory' && (await describe(repository)).kind === 'directory', 'WORKSPACE_INPUT_NOT_DIRECTORY');
  const paths = releaseWorkspacePaths(home), { root } = paths;
  let parent = home;
  for (const name of ['Library', 'Caches']) {
    parent = path.join(parent, name);
    try { await fs.mkdir(parent, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    const info = await describe(parent);
    requireThat(info.kind === 'directory' && info.uid === uid && !(info.mode & 0o022) && await fs.realpath(parent) === parent, 'WORKSPACE_PARENT_UNSAFE');
  }
  const namespace = path.join(parent, 'io.envara.release');
  await privateDirectory(namespace, uid, true);
  let fresh = false;
  try { await fs.mkdir(root, { mode: 0o700 }); fresh = true; } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const rootIdentity = await privateDirectory(root, uid), parentIdentity = await describe(namespace);
  const ownerPath = path.join(root, 'owner.json'), statePath = path.join(root, 'state.json'), lockPath = path.join(root, 'lock.json');
  if (fresh) await fs.writeFile(ownerPath, JSON.stringify({ schema, repository, uid, rootIdentity }) + '\n', { flag: 'wx', mode: 0o600 });
  const ownerBytes = await regularBytes(ownerPath, uid), owner = JSON.parse(ownerBytes);
  requireThat(owner.schema === schema && owner.repository === repository && owner.uid === uid && same(owner.rootIdentity, rootIdentity), 'WORKSPACE_OWNER_MISMATCH');
  requireThat(!await exists(lockPath), 'WORKSPACE_LOCKED');
  if (!fresh) {
    const previous = JSON.parse(await regularBytes(statePath, uid));
    requireThat(previous.complete === true && /^[0-9a-f-]{36}$/.test(previous.nonce ?? '')
      && previous.journal === path.join(root, 'evidence', previous.nonce, 'journal.jsonl')
      && await fs.realpath(previous.journal) === previous.journal, 'WORKSPACE_RECOVERY_REQUIRED');
    const journal = (await regularBytes(previous.journal, uid)).toString();
    requireThat(journal.endsWith('\n'), 'WORKSPACE_JOURNAL_INVALID');
    const entries = journal.trim().split('\n').map(line => JSON.parse(line));
    requireThat(entries.every((entry, index) => entry.sequence === index + 1 && entry.nonce === previous.nonce)
      && entries.at(-1)?.event === 'complete', 'WORKSPACE_JOURNAL_INVALID');
  }
  const slots = { candidate: paths.candidateApp, payload: paths.payloadApp, zip: paths.zipApp, mounted: paths.mountedApp };
  await fixedStructure(paths, uid);
  for (const app of Object.values(slots)) requireThat(!await exists(app), 'WORKSPACE_SLOT_OCCUPIED');
  // Refuse foreign siblings before acquiring a lock or creating any new run
  // evidence. A sibling in payload would otherwise be included by hdiutil.
  for (const directory of new Set(Object.values(slots).map(app => path.dirname(app))))
    if (await exists(directory)) await directoryEntries(directory, [], uid, 'WORKSPACE_SLOT_NOT_EMPTY');
  const nonce = randomUUID();
  const lock = await fs.open(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  await lock.writeFile(JSON.stringify({ schema, nonce, pid: process.pid, repository, uid }) + '\n'); await lock.sync(); await lock.close();
  const lockIdentity = await describe(lockPath);
  for (const relative of ['candidate', 'candidate/mac-arm64', 'archive', 'archive/payload', 'archive/zip-extracted', 'archive/mount',
    'fixtures', 'runtime', 'runtime/home', 'runtime/userData', 'runtime/work', 'evidence'])
    await privateDirectory(path.join(root, relative), uid, true);
  const evidenceParent = path.join(root, 'evidence'), evidenceParentIdentity = await describe(evidenceParent);
  const evidenceDir = path.join(evidenceParent, nonce), evidenceIdentity = await privateDirectory(evidenceDir, uid, true);
  const journalPath = path.join(evidenceDir, 'journal.jsonl');
  const journal = await fs.open(journalPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  const journalIdentity = await describe(journalPath), claims = new Map(); let sequence = 0, closed = false, cleanupStarted = false;
  async function evidenceGuard() {
    requireThat(same(await describe(root), rootIdentity) && same(await describe(namespace), parentIdentity)
      && await fs.realpath(root) === root, 'WORKSPACE_IDENTITY_CHANGED');
    requireThat(same(await describe(evidenceParent), evidenceParentIdentity) && same(await describe(evidenceDir), evidenceIdentity)
      && await fs.realpath(evidenceDir) === evidenceDir, 'WORKSPACE_EVIDENCE_CHANGED');
  }
  async function guard() {
    requireThat(!closed, 'WORKSPACE_CLOSED'); await evidenceGuard();
    requireThat(same(await describe(lockPath), lockIdentity) && same(await describe(journalPath), journalIdentity), 'WORKSPACE_CONTROL_CHANGED');
    requireThat((await regularBytes(ownerPath, uid)).equals(ownerBytes), 'WORKSPACE_OWNER_CHANGED');
    requireThat(JSON.parse(await regularBytes(lockPath, uid)).nonce === nonce, 'WORKSPACE_LOCK_CHANGED');
  }
  async function record(event, fields = {}) {
    await guard(); await journal.writeFile(JSON.stringify({ sequence: ++sequence, nonce, event, ...fields }) + '\n'); await journal.sync();
  }
  async function state(complete) {
    const temporary = path.join(root, `state-${nonce}.tmp`);
    const handle = await fs.open(temporary, 'wx', 0o600);
    try { await handle.writeFile(JSON.stringify({ schema, complete, nonce, journal: journalPath }) + '\n'); await handle.sync(); }
    finally { await handle.close(); }
    await fs.rename(temporary, statePath);
  }
  await record('opened', { root, repository }); await state(false);
  async function claim(kind) {
    await guard(); requireThat(!cleanupStarted && RELEASE_SLOT_KINDS.includes(kind) && !claims.has(kind), 'CLAIM_INVALID');
    await fixedStructure(paths, uid);
    const app = slots[kind]; requireThat(!await exists(app), 'CLAIM_PATH_OCCUPIED');
    const entry = { kind, path: app, parent: await privateDirectory(path.dirname(app), uid), sealed: false,
      ...(kind === 'candidate' ? { outputParent: await privateDirectory(paths.candidateOutput, uid) } : {}) };
    await directoryEntries(path.dirname(app), [], uid, 'CLAIM_PARENT_NOT_EMPTY');
    await record('claim-intent', { kind, path: app, parent: entry.parent, ...(entry.outputParent ? { outputParent: entry.outputParent } : {}) }); claims.set(kind, entry);
    return app;
  }
  async function adoptCandidateOutput({ builderResult, signedManifest } = {}) {
    await guard(); const entry = claims.get('candidate');
    requireThat(entry && !entry.sealed && !entry.builderOutputAdopted && !cleanupStarted, 'BUILDER_ADOPTION_INVALID');
    requireThat(builderResult?.code === 0 && builderResult.closeConfirmed === true
      && builderResult.cleanupUncertain !== true, 'BUILDER_COMPLETION_UNCONFIRMED');
    requireThat(signedManifest && typeof signedManifest === 'object' && !Array.isArray(signedManifest), 'BUILDER_SIGNED_MANIFEST_INVALID');
    const parent = path.dirname(entry.path), before = await describe(parent);
    const guardOutput = async () => {
      await guard();
      requireThat(same(await privateDirectory(paths.candidateOutput, uid), entry.outputParent), 'BUILDER_OUTPUT_PARENT_CHANGED');
      await fixedStructure(paths, uid);
      const current = await describe(parent);
      requireThat(current.kind === 'directory' && current.uid === uid && current.dev === entry.parent.dev
        && [0o700, 0o755].includes(current.mode) && await fs.realpath(parent) === parent, 'BUILDER_OUTPUT_PARENT_UNSAFE');
      requireThat(same((await fs.readdir(parent)).sort(), ['Envara.app']), 'BUILDER_OUTPUT_NOT_EXCLUSIVE');
    };
    await guardOutput();
    // electron-builder replaces only appOutDir while extracting Electron. The
    // controlled candidate output directory above it must retain its identity.
    requireThat(before.kind === 'directory' && before.uid === uid && before.dev === entry.parent.dev
      && [0o700, 0o755].includes(before.mode) && await fs.realpath(parent) === parent, 'BUILDER_OUTPUT_PARENT_UNSAFE');
    const tree = await bundleTree(entry.path, uid);
    requireThat(same(contentInventory(tree), signedManifest), 'BUILDER_SIGNED_MANIFEST_CHANGED');
    await guardOutput();
    requireThat(same(await describe(parent), before), 'BUILDER_OUTPUT_PARENT_CHANGED');
    const handle = await fs.open(parent, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
    try {
      requireThat(same(identity(await handle.stat({ bigint: true })), before), 'BUILDER_OUTPUT_PARENT_CHANGED');
      const manifestSHA256 = digest(JSON.stringify(signedManifest));
      await record('builder-output-adoption-intent', { kind: 'candidate', path: entry.path,
        previousParent: entry.parent, replacementParent: before, outputParent: entry.outputParent, signedManifestSHA256: manifestSHA256 });
      // Change the verified directory descriptor, never a recursively selected
      // path. Unrelated archive parents continue to use the original seal rule.
      await handle.chmod(0o700);
      const adopted = { ...before, mode: 0o700 };
      requireThat(same(identity(await handle.stat({ bigint: true })), adopted)
        && same(await privateDirectory(parent, uid), adopted), 'BUILDER_OUTPUT_PARENT_CHANGED');
      await guardOutput();
      requireThat(same(await bundleTree(entry.path, uid), tree), 'BUILDER_SIGNED_MANIFEST_CHANGED');
      await record('builder-output-adopted', { kind: 'candidate', path: entry.path, parent: adopted,
        outputParent: entry.outputParent, signedManifestSHA256: manifestSHA256 });
      entry.parent = adopted; entry.builderOutputAdopted = true;
    } finally { await handle.close(); }
    return entry.path;
  }
  async function seal(kind, options = {}) {
    await guard(); const entry = claims.get(kind); requireThat(entry && !entry.sealed && !cleanupStarted, 'SEAL_INVALID');
    if (kind === 'mounted') {
      requireThat(/^\/dev\/disk\d+(?:s\d+)?$/.test(options.device ?? '') && typeof options.imagePath === 'string'
        && within(evidenceDir, options.imagePath) && options.imagePath.endsWith('.dmg')
        && await fs.realpath(options.imagePath) === options.imagePath, 'MOUNT_BINDING_INVALID');
      entry.mount = { device: options.device, imagePath: options.imagePath, imageIdentity: await describe(options.imagePath), imageHash: await fileHash(options.imagePath, uid) };
      entry.parent = await describe(paths.mountDir);
      requireThat(entry.parent.kind === 'directory' && await fs.realpath(paths.mountDir) === paths.mountDir, 'MOUNT_DIRECTORY_INVALID');
    } else requireThat(same(await describe(path.dirname(entry.path)), entry.parent), 'SEAL_PARENT_CHANGED');
    requireThat(same((await fs.readdir(path.dirname(entry.path))).sort(), [path.basename(entry.path)]), 'SEAL_PARENT_NOT_EXCLUSIVE');
    entry.tree = await bundleTree(entry.path, uid); entry.sealed = true;
    await record('sealed', { kind, path: entry.path, parent: entry.parent, treeSHA256: digest(JSON.stringify(entry.tree)), mount: entry.mount ?? null });
    await fs.writeFile(path.join(evidenceDir, `${kind}-manifest.json`), JSON.stringify(entry.tree) + '\n', { flag: 'wx', mode: 0o600 });
    return { path: entry.path, manifestSHA256: digest(JSON.stringify(entry.tree)) };
  }
  async function cleanup({ run, operationError = null } = {}) {
    requireThat(typeof run === 'function' && !cleanupStarted, 'CLEANUP_INVALID'); cleanupStarted = true;
    const report = { complete: false, operationError, cleanupErrors: [], results: [] };
    const execute = async (command, args, options = {}) => {
      const value = await run(command, args, { cwd: root, timeout: 45000, maxBuffer: 32 * 1024 * 1024,
        env: { ...process.env, LC_ALL: 'C', LANG: 'C' }, ...options });
      requireThat(value?.cleanupUncertain !== true && value?.closeConfirmed !== false, 'INSPECTION_TERMINATION_UNCERTAIN');
      return { code: value?.code ?? value?.exitCode ?? value?.status, stdout: String(value?.stdout ?? ''), stderr: String(value?.stderr ?? '') };
    };
    const checked = async (...args) => { const value = await execute(...args); requireThat(value.code === 0, 'INSPECTION_COMMAND_FAILED'); return value; };
    const registrations = async () => { const result = await checked(LSREGISTER, ['-dump']); requireThat(!result.stderr.trim(), 'LS_DUMP_DIAGNOSTIC'); return parseLaunchServicesDump(result.stdout); };
    let protectedBefore;
    const stableRegistrations = async () => {
      const records = await registrations(), projection = protectedRegistrations(records);
      if (protectedBefore === undefined) protectedBefore = projection;
      else requireThat(same(projection, protectedBefore), 'PROTECTED_REGISTRATION_CHANGED');
      return records;
    };
    const absent = async app => requireThat(!(await stableRegistrations()).some(item => item.path === app), 'REGISTRATION_REMAINS');
    async function verifyEntry(entry) {
      await guard(); requireThat(entry.sealed, 'UNSEALED_APP_RETAINED');
      requireThat(same(await describe(path.dirname(entry.path)), entry.parent) && same(await bundleTree(entry.path, uid), entry.tree), 'SEALED_APP_CHANGED');
    }
    async function noProcesses(app) {
      const ps = await checked('/bin/ps', ['-axo', 'pid=,ppid=,pgid=,lstart=,comm=']);
      requireThat(!ps.stderr.trim() && ps.stdout.trim(), 'PROCESS_INSPECTION_INVALID');
      const seen = new Set();
      for (const line of ps.stdout.split('\n').filter(line => line.trim())) {
        const row = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+(.+?)\s*$/.exec(line);
        requireThat(row && !seen.has(row[1]), 'PROCESS_INSPECTION_INVALID'); seen.add(row[1]);
        requireThat(row[4] !== 'Envara' && !within(app, row[4]), 'APP_STILL_RUNNING');
      }
      const open = await execute('/usr/sbin/lsof', ['-nP', '-Fpf', '+D', app]);
      requireThat(open.code === 1 && !open.stdout.trim() && !open.stderr.trim(), 'APP_IN_USE_OR_INSPECTION_FAILED');
    }
    async function mounts() {
      const raw = await checked('/usr/bin/hdiutil', ['info', '-plist']);
      const converted = await checked('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '-'], { input: raw.stdout });
      const parsed = JSON.parse(converted.stdout); requireThat(Array.isArray(parsed.images), 'MOUNT_INSPECTION_INVALID'); return parsed.images;
    }
    async function ownedMount(entry) {
      const binding = entry.mount;
      requireThat(binding && same(await describe(binding.imagePath), binding.imageIdentity) && await fileHash(binding.imagePath, uid) === binding.imageHash, 'MOUNT_IMAGE_CHANGED');
      const matches = (await mounts()).filter(item => item['image-path'] === binding.imagePath);
      requireThat(matches.length === 1, 'MOUNT_IMAGE_AMBIGUOUS');
      const entities = matches[0]['system-entities']; requireThat(Array.isArray(entities), 'MOUNT_ENTITIES_INVALID');
      const mounted = entities.filter(item => item['mount-point']);
      requireThat(mounted.length === 1 && mounted[0]['mount-point'] === paths.mountDir && mounted[0]['dev-entry'] === binding.device, 'MOUNT_IDENTITY_CHANGED');
    }
    for (const item of planReleaseCleanup(paths, [...claims.values()])) {
      const entry = claims.get(item.kind), result = { ...item, unregistered: false, removed: false, detached: false };
      report.results.push(result);
      try {
        await verifyEntry(entry); await noProcesses(entry.path);
        await checked('/usr/bin/codesign', ['--verify', '--deep', '--strict', entry.path]);
        if (entry.mount) await ownedMount(entry);
        const registered = (await stableRegistrations()).some(record => record.path === entry.path);
        await verifyEntry(entry); await noProcesses(entry.path);
        if (registered) {
          await record('unregister-intent', item);
          const unregister = await execute(LSREGISTER, ['-u', entry.path]);
          await record('unregister-result', { ...item, code: unregister.code });
          requireThat(unregister.code === 0 && !unregister.stderr.trim(), 'UNREGISTER_FAILED');
        } else {
          await record('unregister-already-absent', item); result.alreadyAbsent = true;
        }
        await absent(entry.path); if (registered) result.unregistered = true;
        await verifyEntry(entry); await noProcesses(entry.path);
        if (entry.mount) {
          await ownedMount(entry); await absent(entry.path); await record('detach-intent', { ...item, device: entry.mount.device });
          await checked('/usr/bin/hdiutil', ['detach', entry.mount.device]);
          requireThat(!(await mounts()).some(image => image['image-path'] === entry.mount.imagePath), 'MOUNT_REMAINS');
          requireThat(!await exists(entry.path), 'MOUNT_PATH_REMAINS'); result.detached = true;
          await record('detached', item);
        } else {
          await record('remove-intent', item); await verifyEntry(entry); await absent(entry.path);
          // Only the private, sealed slot can reach this removal. No glob, lookup
          // by identifier, unrelated app, or recursive workspace deletion exists.
          await fs.rm(entry.path, { recursive: true, force: false });
          requireThat(!await exists(entry.path), 'APP_PATH_REMAINS'); result.removed = true;
          await record('removed', item);
        }
        await absent(entry.path);
      } catch (error) {
        const failure = { kind: item.kind, code: error.code ?? 'CLEANUP_FAILED', message: error.message };
        report.cleanupErrors.push(failure);
        try { await record('cleanup-failed', failure); } catch { /* Preserve the original cleanup failure. */ }
        break;
      }
    }
    if (!report.cleanupErrors.length) {
      try {
        await record('complete'); await state(true); await guard(); await fs.unlink(lockPath); report.complete = true;
      } catch (error) { report.cleanupErrors.push({ code: error.code ?? 'COMPLETION_FAILED', message: error.message }); }
    }
    await journal.close(); closed = true;
    try {
      await evidenceGuard();
      await fs.writeFile(path.join(evidenceDir, 'cleanup.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    } catch (error) {
      report.complete = false;
      report.cleanupErrors.push({ code: error.code ?? 'CLEANUP_REPORT_FAILED', message: error.message });
    }
    return report;
  }
  return { ...paths, evidenceDir, journalPath, claim, adoptCandidateOutput, seal, cleanup };
}
