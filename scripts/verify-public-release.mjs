// Read-only release guard. Reports filenames and rule counts, never matched values.
import { execFile } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { lstat, readdir, readlink, realpath } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import * as asar from '@electron/asar';
import { inspectSourceArchive, SOURCE_ARCHIVE_LIMITS } from './source-archive.mjs';

const execute = promisify(execFile);
const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const overlapBytes = 32768;
// Existing self-issued localhost TLS fixtures only. A new key, another path or
// any packaged copy still fails; tests are never excluded from secret scanning.
const localhostTLSFixtures = new Set(['tests/claude-download-fixture.mjs', 'tests/proxy-network.test.mjs']);
const localhostTLSKeySha256 = 'e15e1d35ce40272bdcaddc93ae92a29c09cbc9476f8181f24fc631571c475df4';
const coverage = ['Current home/repository paths in UTF-8, UTF-16 and common escapes',
  'Complete PEM private keys and selected service-token formats',
  'Credential-bearing URLs and proxy configuration', 'Local runtime, signing and evidence filenames',
  'Bounded tar/PAX metadata in known corresponding-source archives; no recursive content classification'];
const exampleValue = value => /fixture|example|sample|placeholder|redacted|dummy|replace.?me|your[-_ ]|^\$\{|^<|^test[-_]/i.test(value)
  || /^(?:user(?:name)?|pw|pass(?:word)?|token|secret|changeme|user:pass(?:word)?)$/i.test(value)
  || /^(?:(?:stored|group|profile|session|proxy|node|test|fixture|dummy)[-_])+(?:password|secret|token|key|credential)$/i.test(value);
const reservedHost = host => /^(?:localhost|127\.|0\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|::1$)/i.test(host)
  || /(?:^|\.)(?:example\.(?:com|net|org)|invalid|test|example|localhost)$/i.test(host);
const within = (root, target) => { const relative = path.relative(root, target); return !relative || !relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative); };
const posix = value => value.split(path.sep).join('/');
const knownSourceArchive = label => /(?:^|[/:])mihomo-corresponding-source\.tar\.gz$/.test(label);

function forbiddenFile(filename, mode) {
  filename = filename.replace(/^.*?\.asar:/, '');
  const name = path.posix.basename(filename).toLowerCase();
  if (/^(?:\.env(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519))$/.test(name) && !/^\.env\.(?:example|sample|template)$/.test(name)
      || /\.(?:p12|pfx|keychain(?:-db)?)$/.test(name)) return 'PRIVATE_CREDENTIAL_FILE';
  if (/(?:^|\/)(?:local-verification|local-carrier-verification|test-artifacts|playwright-report|local-authorization-archive|release-verified-[^/]+|notion-trial-diagnostics|startup-diagnostics|runtime-diagnostics)(?:\/|$)/i.test(filename)
      || name === '.ds_store' || /\.(?:dmp|log)$/.test(name)) return 'LOCAL_EVIDENCE_FILE';
  if (mode === 'app' && /^(?:tests|scripts)\//.test(filename)) return 'LOCAL_EVIDENCE_FILE';
  const fixture = /(?:^|\/)(?:fixtures?|testdata)(?:\/|$)/i.test(filename);
  const vendor = /(?:^|\/)(?:node_modules|third_party)(?:\/|$)/.test(filename);
  if (!vendor && !(mode === 'source' && fixture) && new Set(['workspace.json', 'profiles.json', 'proxies.json',
    'claude-accounts.json', '.claude.json', '.credentials.json', '.envara-token', 'link-preferences.json',
    'last-startup.json', 'previous-startup.json', 'last-runtime.json', 'previous-runtime.json', 'cookies', 'login data', 'local state']).has(name)) return 'LOCAL_RUNTIME_FILE';
  return null;
}

function pathNeedles(home, repoRoot) {
  const needles = [];
  for (const [rule, value] of [['LOCAL_HOME_PATH', home], ['LOCAL_REPOSITORY_PATH', repoRoot]]) {
    if (!path.isAbsolute(value ?? '') || path.parse(value).root === value) throw Object.assign(new Error(), { code: 'INVALID_SCAN_ROOT' });
    const variants = new Set([value, value.replaceAll('/', '\\/'), value.replaceAll('\\', '\\\\'), encodeURI(value), encodeURIComponent(value)]);
    for (const variant of variants) {
      needles.push({ rule, bytes: Buffer.from(variant), unit: 1 });
      const wide = Buffer.from(variant, 'utf16le');
      needles.push({ rule, bytes: wide, unit: 2 }, { rule, bytes: Buffer.from(wide).swap16(), unit: 2, bigEndian: true });
    }
  }
  return needles;
}

function scanWindow(bytes, { needles, file, mode, offset = 0, final = true, emit }) {
  for (const { rule, bytes: needle, unit, bigEndian } of needles) {
    for (let at = bytes.indexOf(needle); at !== -1; at = bytes.indexOf(needle, at + needle.length)) {
      const end = at + needle.length;
      if (!final && end + unit > bytes.length) continue;
      const next = unit === 1 ? bytes[end] : end + 1 < bytes.length ? bigEndian ? bytes.readUInt16BE(end) : bytes.readUInt16LE(end) : undefined;
      if (next !== undefined && /[A-Za-z0-9_.-]/.test(String.fromCharCode(next))) continue;
      emit(rule, offset + at);
    }
  }
  // Latin-1 preserves byte offsets for streaming overlap de-duplication.
  const text = bytes.toString('latin1');
  const matches = (expression, check, rule) => {
    for (const match of text.matchAll(expression)) {
      if ((!final && match.index + match[0].length === bytes.length) || !check(match)) continue;
      emit(rule, offset + match.index);
    }
  };
  matches(/-----BEGIN ((?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----([\s\S]{64,20000}?)-----END \1-----/g,
    match => /^[A-Za-z0-9+/=]{64,}$/.test(match[2].replace(/\\[rn]/g, '').replace(/\s/g, ''))
      && !(mode === 'source' && localhostTLSFixtures.has(file) && createHash('sha256').update(match[0].replaceAll('\r\n', '\n')).digest('hex') === localhostTLSKeySha256), 'PRIVATE_KEY');
  matches(/\b(?:gh[pousr]_[A-Za-z0-9_]{30,255}|github_pat_[A-Za-z0-9_]{50,255}|sk-(?:ant-api\d+-[A-Za-z0-9_-]{32,255}|(?:proj|svcacct)-[A-Za-z0-9_-]{32,255}|[A-Za-z0-9]{32,255})|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{24,255})\b/g,
    match => !exampleValue(match[0]) && new Set(match[0]).size >= 8, 'SERVICE_TOKEN');
  matches(/\b(?:https?|socks5h?|anytls|trojan|vless|ss):\\?\/\\?\/(?:\\\/|[^\x00-\x20\x7f<>"'\\]){4,2048}/g, match => {
    try {
      const url = new URL(match[0].replaceAll('\\/', '/'));
      if (reservedHost(url.hostname)) return false;
      const password = decodeURIComponent(url.password), username = decodeURIComponent(url.username);
      if (password && !exampleValue(password)) return true;
      // Node and Chromium ship username-only URL parser examples. A username
      // is a secret only for node protocols that carry their credential there.
      if (['anytls:', 'trojan:', 'vless:', 'ss:'].includes(url.protocol) && username.length >= 8 && !exampleValue(username)) return true;
      return [...url.searchParams].some(([key, value]) => /^(?:token|api[_-]?key|access[_-]?token|secret|password)$/i.test(key)
        && value.length >= 8 && !exampleValue(value));
    } catch { return false; }
  }, 'CREDENTIAL_URL');
  matches(/["']?(?:password|passwd|proxy[_-]?password)["']?\s*[:=]\s*(?:"([^"\r\n]{8,512})"|'([^'\r\n]{8,512})'|([A-Za-z0-9+/_=:-]{8,512})(?=\s*[,}\r\n]|$))/gi, match => {
    const value = match[1] ?? match[2] ?? match[3];
    if (exampleValue(value)) return false;
    const objectStart = text.lastIndexOf('{', match.index), objectEnd = text.indexOf('}', match.index + match[0].length);
    const context = objectStart >= 0 && objectEnd >= 0 && objectEnd - objectStart <= 2048
      ? text.slice(objectStart, objectEnd + 1)
      : text.slice(Math.max(0, match.index - 512), match.index + match[0].length + 512);
    return [...context.matchAll(/["']?(?:server|host)["']?\s*[:=]\s*["']?([A-Za-z0-9][A-Za-z0-9.-]{0,252})(?=["'\s,}])/gi)]
      .some(host => host[1].includes('.') && !reservedHost(host[1]));
  }, 'PROXY_CREDENTIAL');
}

function collector({ home, repoRoot, mode }) {
  const needles = pathNeedles(home, repoRoot), findings = new Map();
  let scannedFiles = 0, skippedDeleted = 0;
  const add = (file, rule, count = 1) => {
    const key = `${file}\0${rule}`, old = findings.get(key);
    findings.set(key, { file, rule, count: (old?.count ?? 0) + count });
  };
  const scanner = file => {
    scannedFiles++;
    const rule = forbiddenFile(file, mode); if (rule) add(file, rule);
    const seen = new Set();
    return (bytes, options) => scanWindow(bytes, { needles, file, mode, ...options, emit(rule, at) {
      const key = `${rule}:${at}`;
      if (!seen.has(key)) { seen.add(key); add(file, rule); }
    } });
  };
  return { add, scanner, deleted: () => { skippedDeleted++; }, report: () => ({
    ok: findings.size === 0, scannedFiles, skippedDeleted, coverage,
    findings: [...findings.values()].sort((a, b) => a.file.localeCompare(b.file) || a.rule.localeCompare(b.rule)),
  }) };
}

async function scanFile(filename, label, scan) {
  if (knownSourceArchive(label)) return scanCorrespondingSource(filename, label, scan);
  const inspect = scan.scanner(label);
  let tail = Buffer.alloc(0), read = 0;
  try {
    for await (const chunk of createReadStream(filename, { highWaterMark: 256 * 1024 })) {
      const bytes = Buffer.concat([tail, chunk]);
      inspect(bytes, { offset: read - tail.length, final: false });
      read += chunk.length; tail = bytes.subarray(Math.max(0, bytes.length - overlapBytes));
    }
    inspect(tail, { offset: read - tail.length, final: true });
  } catch { scan.add(label, 'SCAN_READ_FAILED'); }
}

async function scanCorrespondingSource(input, label, scan) {
  scan.scanner(label);
  try {
    const report = await inspectSourceArchive(input, { requireClean: false });
    for (const finding of report.findings) scan.add(label, finding.rule, finding.count);
  } catch (error) {
    scan.add(label, ['SOURCE_ARCHIVE_INVALID', 'SOURCE_ARCHIVE_LIMIT_EXCEEDED'].includes(error.code) ? error.code : 'SCAN_SOURCE_ARCHIVE_FAILED');
  }
}

/** The packaged source archive's metadata can be checked without rescanning an app. */
export async function scanPublicSourceArchive({ archive, repoRoot = projectRoot, home = os.homedir() }) {
  const scan = collector({ home, repoRoot: path.resolve(repoRoot), mode: 'source' });
  await scanCorrespondingSource(archive, path.basename(archive), scan);
  return scan.report();
}

async function scanLink(filename, label, root, scan) {
  const target = await readlink(filename);
  scan.scanner(label)(Buffer.from(target));
  try { if (!within(root, await realpath(filename))) scan.add(label, 'EXTERNAL_SYMLINK'); }
  catch { scan.add(label, 'UNRESOLVED_SYMLINK'); }
}

export async function scanPublicSource({ repoRoot = projectRoot, home = os.homedir() } = {}) {
  repoRoot = path.resolve(repoRoot);
  const scan = collector({ home, repoRoot, mode: 'source' });
  const { stdout } = await execute('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { cwd: repoRoot, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  for (const relative of [...new Set(stdout.split('\0').filter(Boolean))].sort()) {
    const filename = path.resolve(repoRoot, relative), label = posix(relative);
    if (!within(repoRoot, filename)) { scan.add(label, 'INVALID_SOURCE_PATH'); continue; }
    let info;
    try { info = await lstat(filename); }
    catch (error) { if (error.code === 'ENOENT') { scan.deleted(); continue; } scan.add(label, 'SCAN_READ_FAILED'); continue; }
    if (info.isSymbolicLink()) await scanLink(filename, label, repoRoot, scan);
    else if (info.isFile()) await scanFile(filename, label, scan);
    else scan.add(label, 'UNSUPPORTED_SOURCE_ENTRY');
  }
  return scan.report();
}

async function scanArchive(filename, label, scan) {
  try {
    asar.uncache(filename);
    scan.scanner(`${label}:header`)(Buffer.from(asar.getRawHeader(filename).headerString));
    for (const entry of asar.listPackage(filename).sort()) {
      const relative = entry.replace(/^\//, ''), name = `${label}:${relative}`;
      if (!relative || relative.includes('\\') || path.posix.normalize(relative) !== relative || relative.startsWith('../')) { scan.add(name, 'INVALID_ARCHIVE_PATH'); continue; }
      const info = asar.statFile(filename, relative, false);
      if (info.files) continue;
      if (info.link) {
        scan.scanner(name)(Buffer.from(info.link));
        if (path.posix.isAbsolute(info.link) || path.posix.normalize(info.link).startsWith('../')) scan.add(name, 'EXTERNAL_SYMLINK');
      } else if (knownSourceArchive(name)) {
        if (info.size > SOURCE_ARCHIVE_LIMITS.compressedBytes) scan.add(name, 'SOURCE_ARCHIVE_LIMIT_EXCEEDED');
        else await scanCorrespondingSource(asar.extractFile(filename, relative), name, scan);
      } else scan.scanner(name)(asar.extractFile(filename, relative));
    }
  } catch { scan.add(label, 'SCAN_ARCHIVE_FAILED'); }
  finally { asar.uncache(filename); }
}

export async function scanPublicApp({ app, repoRoot = projectRoot, home = os.homedir() }) {
  const root = path.resolve(app);
  if (!root.toLowerCase().endsWith('.app') || !(await lstat(root)).isDirectory()) throw Object.assign(new Error(), { code: 'INVALID_APPLICATION' });
  const scan = collector({ home, repoRoot: path.resolve(repoRoot), mode: 'app' });
  let foundArchive = false;
  const visit = async (filename, label) => {
    const info = await lstat(filename);
    if (info.isSymbolicLink()) return scanLink(filename, label, root, scan);
    if (info.isDirectory()) { for (const entry of (await readdir(filename)).sort()) await visit(path.join(filename, entry), label ? `${label}/${entry}` : entry); }
    else if (info.isFile()) {
      if (filename === path.join(root, 'Contents/Resources/app.asar')) foundArchive = true;
      if (filename.endsWith('.asar')) await scanArchive(filename, label, scan);
      else await scanFile(filename, label, scan);
    } else scan.add(label, 'UNSUPPORTED_APPLICATION_ENTRY');
  };
  await visit(root, '');
  if (!foundArchive) scan.add('Contents/Resources/app.asar', 'APPLICATION_ARCHIVE_MISSING');
  return scan.report();
}

async function main(values) {
  let app, repoRoot = projectRoot;
  for (let index = 0; index < values.length; index++) {
    const flag = values[index];
    if (flag === '--help' || flag === '-h') { console.log('Usage: node scripts/verify-public-release.mjs [--repo directory] [--app Envara.app]\nScans current public-source candidates and optionally the complete macOS app. Findings show file/rule/count only. This is a scoped release guard, not proof that arbitrary unknown secrets are absent.'); return; }
    if (!['--repo', '--app'].includes(flag) || !values[index + 1] || values[index + 1].startsWith('--')) throw Object.assign(new Error(), { code: 'INVALID_ARGUMENTS' });
    if (flag === '--repo') repoRoot = path.resolve(values[++index]); else app = path.resolve(values[++index]);
  }
  const source = await scanPublicSource({ repoRoot });
  const artifact = app ? await scanPublicApp({ app, repoRoot }) : null;
  console.log(JSON.stringify({ ok: source.ok && (!artifact || artifact.ok), source, ...(artifact ? { app: artifact } : {}) }, null, 2));
  if (!source.ok || artifact && !artifact.ok) process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => {
    console.log(JSON.stringify({ ok: false, error: /^[A-Z_]{1,64}$/.test(error.code ?? '') ? error.code : 'SCAN_FAILED' }));
    process.exitCode = 1;
  });
}
