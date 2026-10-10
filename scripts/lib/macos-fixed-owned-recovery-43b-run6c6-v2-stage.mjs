// Generates one closed program for the reviewed interactive native wrapper.
// It reads no source path, environment setting, caller argument or user file.
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';

export const FIXED_OWNED_RECOVERY_STAGE_SCHEMA = 'envara.macos-fixed-owned-recovery-stage/v1';
const PARENT = '/Library/PrivilegedHelperTools';
const MAX_BYTES = 32 * 1024 * 1024;

// Serialized into --eval; all capabilities in production are Node builtins.
// Tests run the identical program with capabilities confined to owned temp.
function closedStage(config) {
  'use strict';
  const fs = require('node:fs'), zlib = require('node:zlib'), crypto = require('node:crypto');
  let file = -1, parent = -1;
  const emit = value => process.stdout.write(JSON.stringify(value) + '\n');
  const refused = () => {
    if (file >= 0) { try { fs.closeSync(file); } catch {} file = -1; }
    if (parent >= 0) { try { fs.closeSync(parent); } catch {} parent = -1; }
    // Never remove, reopen or adopt a partial/existing destination.
    emit({ schema: config.schema, ok: false, reason: 'FIXED_STAGE_REFUSED' });
    process.exitCode = 1;
  };
  const directory = stat => stat.isDirectory() && stat.uid === 0n && stat.gid === 0n && (stat.mode & 0o22n) === 0n;
  const same = (a, b) => ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink'].every(key => a[key] === b[key]);
  // APFS changes a directory's link count when this new child is created.
  const sameDirectory = (a, b) => ['dev', 'ino', 'mode', 'uid', 'gid'].every(key => a[key] === b[key]);
  try {
    // Security may retain the caller's RUID while providing genuine EUID 0.
    if (process.geteuid() !== 0) throw new Error();
    process.setgroups([0]); process.setgid(0); process.setuid(0);
    process.umask(0o077);
    if (process.getuid() !== 0 || process.geteuid() !== 0 || process.getgid() !== 0 || process.getegid() !== 0 ||
      process.getgroups().length !== 1 || process.getgroups()[0] !== 0) throw new Error();
    if (config.schema !== 'envara.macos-fixed-owned-recovery-stage/v1' || config.parent !== '/Library/PrivilegedHelperTools' ||
      config.target !== config.parent + '/io.envara.pf-owned-recovery-43b-' + config.sha || !/^[0-9a-f]{64}$/.test(config.sha) ||
      !Number.isSafeInteger(config.size) || config.size < 1 || config.size > 33554432) throw new Error();
    const binary = zlib.gunzipSync(Buffer.from(config.gzip, 'base64'), { maxOutputLength: config.size });
    if (binary.length !== config.size || crypto.createHash('sha256').update(binary).digest('hex') !== config.sha) throw new Error();
    for (const name of ['/', '/Library', config.parent]) {
      if (fs.realpathSync(name) !== name || !directory(fs.lstatSync(name, { bigint: true }))) throw new Error();
    }
    parent = fs.openSync(config.parent, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(parent, { bigint: true });
    if (!directory(before) || !sameDirectory(before, fs.lstatSync(config.parent, { bigint: true }))) throw new Error();
    file = fs.openSync(config.target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    let stat = fs.fstatSync(file, { bigint: true });
    if (!stat.isFile() || stat.uid !== 0n || stat.gid !== 0n || stat.nlink !== 1n || (stat.mode & 0o7777n) !== 0o600n || stat.size !== 0n) throw new Error();
    let at = 0;
    while (at < binary.length) {
      const count = fs.writeSync(file, binary, at, binary.length - at, null);
      if (!Number.isSafeInteger(count) || count < 1 || count > binary.length - at) throw new Error();
      at += count;
    }
    stat = fs.fstatSync(file, { bigint: true });
    if (!stat.isFile() || stat.size !== BigInt(config.size) || stat.nlink !== 1n || stat.uid !== 0n || stat.gid !== 0n ||
      !same(stat, fs.lstatSync(config.target, { bigint: true })) || !sameDirectory(before, fs.fstatSync(parent, { bigint: true })) ||
      !sameDirectory(before, fs.lstatSync(config.parent, { bigint: true }))) throw new Error();
    fs.fsyncSync(file); fs.fchmodSync(file, 0o755); fs.fsyncSync(file); fs.fsyncSync(parent);
    const final = fs.fstatSync(file, { bigint: true });
    if (final.dev !== stat.dev || final.ino !== stat.ino || final.uid !== 0n || final.gid !== 0n || final.nlink !== 1n ||
      final.size !== BigInt(config.size) || (final.mode & 0o7777n) !== 0o755n || !same(final, fs.lstatSync(config.target, { bigint: true }))) throw new Error();
    fs.closeSync(file); file = -1; fs.closeSync(parent); parent = -1;
    emit({ schema: config.schema, ok: true, binarySHA256: config.sha, binaryBytes: config.size,
      device: final.dev.toString(), inode: final.ino.toString(), closed: true });
  } catch { refused(); }
}

export function createFixedOwnedRecoveryStage({ binary, binarySHA256, rootTarget } = {}) {
  if (!Buffer.isBuffer(binary) || binary.length < 1 || binary.length > MAX_BYTES ||
    typeof binarySHA256 !== 'string' || !/^[0-9a-f]{64}$/.test(binarySHA256) ||
    createHash('sha256').update(binary).digest('hex') !== binarySHA256 ||
    rootTarget !== `${PARENT}/io.envara.pf-owned-recovery-43b-${binarySHA256}`) {
    throw new Error('Fixed owned recovery stage input refused.');
  }
  const config = { schema: FIXED_OWNED_RECOVERY_STAGE_SCHEMA, parent: PARENT, target: rootTarget,
    sha: binarySHA256, size: binary.length, gzip: gzipSync(binary, { level: 9 }).toString('base64') };
  const program = `(${closedStage.toString()})(${JSON.stringify(config)});`;
  if (Buffer.byteLength(program, 'utf8') > 196608) throw new Error('Fixed owned recovery stage exceeds the bounded argument size.');
  return Object.freeze({ schema: FIXED_OWNED_RECOVERY_STAGE_SCHEMA, program, binarySHA256, binaryBytes: binary.length, rootTarget });
}
