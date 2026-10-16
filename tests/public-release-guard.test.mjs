import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import * as asar from '@electron/asar';
import { scanPublicSource, scanPublicApp } from '../scripts/verify-public-release.mjs';

const execute = promisify(execFile);
const scannerPath = new URL('../scripts/verify-public-release.mjs', import.meta.url);
const count = (report, file, rule) => report.findings.find(item => item.file === file && item.rule === rule)?.count ?? 0;
const privateKey = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1', privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } }).privateKey;

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-release-guard-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const repoRoot = path.join(root, 'repository'), home = path.join(root, 'home');
  await mkdir(repoRoot); await mkdir(home);
  await execute('git', ['init', '-q'], { cwd: repoRoot });
  const put = async (relative, bytes) => { const filename = path.join(repoRoot, relative); await mkdir(path.dirname(filename), { recursive: true }); await writeFile(filename, bytes); return filename; };
  return { root, repoRoot, home, put, source: () => scanPublicSource({ repoRoot, home }) };
}

async function application(f, files) {
  const input = path.join(f.root, 'asar-input'), app = path.join(f.root, 'Envara.app');
  await mkdir(input); await mkdir(path.join(app, 'Contents/Resources'), { recursive: true });
  for (const [relative, bytes] of Object.entries(files)) { const filename = path.join(input, relative); await mkdir(path.dirname(filename), { recursive: true }); await writeFile(filename, bytes); }
  const archive = path.join(app, 'Contents/Resources/app.asar');
  await asar.createPackage(input, archive);
  return { app, archive, scan: () => scanPublicApp({ app, repoRoot: f.repoRoot, home: f.home }) };
}

test('source inventory scans tracked and unignored files, includes ignored tracked files and skips deletions', async t => {
  const f = await fixture(t);
  await f.put('tracked.txt', `${f.home}/profile`); await f.put('deleted.txt', 'old');
  await execute('git', ['add', 'tracked.txt', 'deleted.txt'], { cwd: f.repoRoot });
  await f.put('.gitignore', 'tracked.txt\nignored-private.txt\n');
  await f.put('ignored-private.txt', privateKey()); await f.put('new.bin', Buffer.from(`${f.repoRoot}/src`, 'utf16le'));
  await rm(path.join(f.repoRoot, 'deleted.txt'));
  const report = await f.source();
  assert.equal(report.scannedFiles, 3); assert.equal(report.skippedDeleted, 1);
  assert.equal(count(report, 'tracked.txt', 'LOCAL_HOME_PATH'), 1);
  assert.equal(count(report, 'new.bin', 'LOCAL_REPOSITORY_PATH'), 1);
  assert.ok(!report.findings.some(item => item.file === 'ignored-private.txt'));
});

test('streamed binary paths crossing a chunk boundary are found once and other usernames are not matched', async t => {
  const f = await fixture(t), data = Buffer.concat([Buffer.alloc(256 * 1024 - 8), Buffer.from(`${f.home}/one`), Buffer.alloc(20), Buffer.from(`${f.home}/two`)]);
  await f.put('binary.dat', data);
  await f.put('different.txt', `${f.home}-different/profile\n${path.join(path.dirname(f.home), 'vendor-builder', 'build', 'ws')}`);
  await f.put('escaped.txt', JSON.stringify(`${f.home}/three`).replaceAll('/', '\\/'));
  const report = await f.source();
  assert.equal(count(report, 'binary.dat', 'LOCAL_HOME_PATH'), 2);
  assert.equal(count(report, 'escaped.txt', 'LOCAL_HOME_PATH'), 1);
  assert.ok(!report.findings.some(item => item.file === 'different.txt'));
});

test('new keys, service tokens, proxy credentials and subscription credentials are refused even in fixtures', async t => {
  const f = await fixture(t), key = privateKey(), secret = randomBytes(24).toString('hex');
  const token = `gh${'p_'}${randomBytes(24).toString('hex')}`;
  await f.put('tests/fixtures/private.txt', key);
  await f.put('tests/fixtures/token.txt', token);
  await f.put('tests/fixtures/node.txt', `{type: anytls, server: node.production-simulated.net, password: ${secret}, port: 35165}`);
  await f.put('tests/fixtures/subscription.txt', `https://provider.production-simulated.net/download?token=${secret}`);
  await f.put('tests/fixtures/subscription.json', JSON.stringify({ data: `https://provider.production-simulated.net/download?token=${secret}` }).replaceAll('/', '\\/'));
  await f.put('tests/fixtures/node-uri.txt', `anytls://${secret}@node.production-simulated.net:35165`);
  const report = await f.source(), output = JSON.stringify(report);
  for (const rule of ['PRIVATE_KEY', 'SERVICE_TOKEN', 'PROXY_CREDENTIAL', 'CREDENTIAL_URL']) assert.ok(report.findings.some(item => item.rule === rule), rule);
  assert.equal(count(report, 'tests/fixtures/subscription.json', 'CREDENTIAL_URL'), 1);
  assert.ok(!output.includes(secret)); assert.ok(!output.includes(token)); assert.ok(!output.includes(key));
  assert.ok(!output.includes('production-simulated.net'));
});

test('expressions, reserved examples and incomplete PEM documentation are not treated as credentials', async t => {
  const f = await fixture(t);
  await f.put('example.js', `const proxy = {server: 'real-provider.net', password: validated.route.password};\nconst docs = {server: 'proxy.example.com', password: 'replace-me-password'};\nconst local = 'https://user:secret@dns.google';\n// -----BEGIN PRIVATE KEY-----\n`);
  await f.put('upstream-url.dat', Buffer.from('http://a@b?@c\0http://a%40b@c\0'));
  const report = await f.source();
  assert.equal(report.ok, true);
});

test('the audited localhost TLS fixture exception is bound to its exact key and source path', async t => {
  const f = await fixture(t), relative = 'tests/claude-download-fixture.mjs';
  await f.put(relative, await readFile(new URL('../tests/claude-download-fixture.mjs', import.meta.url)));
  assert.equal((await f.source()).ok, true);
  await f.put(relative, privateKey());
  assert.equal(count(await f.source(), relative, 'PRIVATE_KEY'), 1);
});

test('runtime, signing and evidence files are refused while an empty environment example remains public', async t => {
  const f = await fixture(t);
  for (const relative of ['.env.local', 'credentials/release.p12', 'runtime/workspace.json', 'build/local-verification/report.json']) await f.put(relative, '{}');
  await f.put('.env.example', 'API_KEY=replace-me\n');
  const report = await f.source();
  assert.equal(report.findings.length, 4);
  assert.equal(count(report, '.env.local', 'PRIVATE_CREDENTIAL_FILE'), 1);
  assert.equal(count(report, 'runtime/workspace.json', 'LOCAL_RUNTIME_FILE'), 1);
  assert.equal(count(report, 'build/local-verification/report.json', 'LOCAL_EVIDENCE_FILE'), 1);
});

test('app scanning reads nested asar entries and external binary resources without modifying upstream content', async t => {
  const f = await fixture(t), upstream = path.join(path.dirname(f.home), 'vendor-builder', 'build', 'ws');
  const a = await application(f, { 'main.js': 'export {};', 'nested/profile.dat': Buffer.from(`${f.home}/session`, 'utf16le') });
  const binary = path.join(a.app, 'Contents/Resources/node');
  const original = Buffer.from(`\0${upstream}\0${f.repoRoot}/native\0`);
  await writeFile(binary, original);
  const report = await a.scan();
  assert.equal(count(report, 'Contents/Resources/app.asar:nested/profile.dat', 'LOCAL_HOME_PATH'), 1);
  assert.equal(count(report, 'Contents/Resources/node', 'LOCAL_REPOSITORY_PATH'), 1);
  assert.equal(count(report, 'Contents/Resources/node', 'LOCAL_HOME_PATH'), 0);
  assert.deepEqual(await readFile(binary), original);
});

test('a complete app with only upstream paths passes, but packaged runtime configuration is blocked', async t => {
  const f = await fixture(t), a = await application(f, { 'main.js': 'export {};', 'assets/about.txt': 'Public application' });
  await writeFile(path.join(a.app, 'Contents/Resources/node'), `${path.join(path.dirname(f.home), 'vendor-builder', 'build', 'ws')}`);
  assert.equal((await a.scan()).ok, true);
  await writeFile(path.join(a.app, 'Contents/Resources/workspace.json'), '{}');
  assert.equal(count(await a.scan(), 'Contents/Resources/workspace.json', 'LOCAL_RUNTIME_FILE'), 1);
});

test('missing or unreadable asar does not become a successful app scan and external symlinks are not followed', async t => {
  const f = await fixture(t), a = await application(f, { 'main.js': 'export {};' });
  await symlink(f.home, path.join(a.app, 'Contents/Resources/host-home'));
  assert.equal(count(await a.scan(), 'Contents/Resources/host-home', 'EXTERNAL_SYMLINK'), 1);
  await writeFile(a.archive, 'invalid archive');
  assert.equal(count(await a.scan(), 'Contents/Resources/app.asar', 'SCAN_ARCHIVE_FAILED'), 1);
  await rm(a.archive);
  assert.equal(count(await a.scan(), 'Contents/Resources/app.asar', 'APPLICATION_ARCHIVE_MISSING'), 1);
});

test('CLI findings fail the command and never print the private value', async t => {
  const f = await fixture(t), key = privateKey();
  await f.put('leak.txt', key);
  await assert.rejects(execute(process.execPath, [scannerPath.pathname, '--repo', f.repoRoot]), error => {
    assert.equal(error.code, 1);
    const report = JSON.parse(error.stdout);
    assert.equal(report.ok, false); assert.equal(report.source.findings[0].rule, 'PRIVATE_KEY');
    assert.ok(!error.stdout.includes(key)); assert.equal(error.stderr, '');
    return true;
  });
});
