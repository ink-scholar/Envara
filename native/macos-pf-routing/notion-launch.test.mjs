import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer } from 'node:net';
import { createSocket } from 'node:dgram';
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, chmodSync, rmSync,
  realpathSync, readFileSync, lstatSync, readdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Standalone nonroot fixture only: no PF, root helper, DNS query, or Notion
// execution/copy/mutation. A local socket rule supplements (never changes) the
// production profile so Seatbelt inheritance can be exercised without a broker.
const directory = path.dirname(fileURLToPath(import.meta.url));
const profile = '(version 1)(allow default)'
  + '(deny mach-lookup (global-name "com.apple.dnssd.service"))'
  + '(deny file-read* file-write* (literal "/private/var/run/mDNSResponder")'
  + ' (literal "/var/run/mDNSResponder") (literal "/private/var/tmp/mDNSResponder") (literal "/var/tmp/mDNSResponder"))'
  + '(deny network-outbound (remote unix-socket (literal "/private/var/run/mDNSResponder"))'
  + ' (remote unix-socket (literal "/var/run/mDNSResponder")) (remote unix-socket (literal "/private/var/tmp/mDNSResponder"))'
  + ' (remote unix-socket (literal "/var/tmp/mDNSResponder")))'
  + '(deny network-outbound (remote tcp "*:53") (remote udp "*:53")'
  + ' (remote tcp "*:853") (remote udp "*:853") (remote udp "*:5353"))';

function tree(root) {
  const entries = [];
  function visit(target) {
    const stat = lstatSync(target);
    assert.ok(stat.isFile() || stat.isDirectory(), 'owned fixture tree contains only files/directories');
    entries.push({ path: path.relative(root, target), mode: stat.mode & 0o7777,
      uid: stat.uid, gid: stat.gid, inode: stat.ino, size: stat.size,
      mtime: stat.mtimeMs, ctime: stat.ctimeMs,
      sha256: stat.isFile() ? createHash('sha256').update(readFileSync(target)).digest('hex') : null });
    if (stat.isDirectory()) for (const name of readdirSync(target).sort()) visit(path.join(target, name));
  }
  visit(root);
  return entries;
}

function run(executable, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timeout = setTimeout(() => { child.kill('SIGKILL'); }, 15_000);
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', text => { stdout += text; });
    child.stderr.on('data', text => { stderr += text; });
    child.once('error', error => { clearTimeout(timeout); reject(error); });
    child.once('close', (status, signal) => {
      clearTimeout(timeout);
      try {
        assert.equal(signal, null, `${executable}: ${stderr}`);
        assert.equal(status, 0, `${executable}: ${stderr}\n${stdout}`);
        resolve(stdout.trim());
      } catch (error) { reject(error); }
    });
  });
}

function inactive(report) {
  assert.equal(report.ready, false);
  assert.equal(report.protected, false);
  if ('activatesSystem' in report) assert.equal(report.activatesSystem, false);
}

function plistValue(filename, key) {
  if (!existsSync(filename)) return null;
  const result = spawnSync('/usr/libexec/PlistBuddy', ['-c', `Print :${key}`, filename],
    { encoding: 'utf8', timeout: 5000 });
  return result.status === 0 ? result.stdout.trim() : null;
}

test('Notion launch preparation refuses fixtures and preserves process-local Seatbelt denial',
  { skip: process.platform !== 'darwin' }, async t => {
    assert.notEqual(process.getuid(), 0, 'this test must remain unprivileged');
    assert.equal(process.getuid(), process.geteuid());
    assert.equal(process.getgid(), process.getegid());
    const temporary = realpathSync(mkdtempSync('/private/tmp/envara-notion-fixture-'));
    chmodSync(temporary, 0o700);
    let server; const networkServers = []; let udp;
    try {
      const executable = path.join(temporary, 'fixture');
      const compile = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-Wno-deprecated-declarations', '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`,
        path.join(directory, 'gui-launch.m'), path.join(directory, 'launcher.c'),
        path.join(directory, 'notion-launch-fixture.m'),
        '-framework', 'Foundation', '-framework', 'AppKit', '-framework', 'Security', '-lbsm', '-o', executable],
      { encoding: 'utf8', timeout: 60_000 });
      assert.equal(compile.status, 0, compile.stderr);

      await t.test('the actual native version predicate accepts only the two exact Electron-compatible versions', async () => {
        const report = JSON.parse(await run(executable, ['versions']));
        for (const key of ['ok', 'bothExactVersionsAccepted', 'otherVersionsRefused', 'electronPairRequired']) assert.equal(report[key], true, key);
        inactive(report);
      });

      await t.test('fixed production profile includes explicit resolver IPC and DNS port exclusions', async () => {
        assert.equal(await run(executable, ['profile']), profile);
      });
      await t.test('exact held TCP front is allowed; other TCP, IPv6 and UDP are blocked in child and descendants', async () => {
        let allowedConnections = 0, deniedConnections = 0, ipv6Connections = 0, packets = 0;
        const ownedTCP = async (host, counter, port = 0) => {
          const s = createServer(client => { counter(); client.destroy(); }); networkServers.push(s);
          await new Promise((resolve, reject) => { s.once('error', reject); s.listen(port, host, resolve); }); return s.address().port;
        };
        const frontPort = await ownedTCP('127.0.0.1', () => allowedConnections++);
        const deniedPort = await ownedTCP('127.0.0.1', () => deniedConnections++);
        const ipv6Port = await ownedTCP('::1', () => ipv6Connections++, frontPort);
        udp = createSocket('udp4'); udp.on('message', () => packets++);
        await new Promise((resolve, reject) => { udp.once('error', reject); udp.bind(0, '127.0.0.1', resolve); });
        const scoped = await run(executable, ['scoped-profile', String(frontPort)]);
        assert.ok(scoped.endsWith(`(deny network-outbound)(allow network-outbound (remote tcp4 "localhost:${frontPort}"))`));
        for (const mode of ['direct','inherit']) {
          const before = { allowedConnections, deniedConnections, ipv6Connections, packets };
          const probe = async (host, port, protocol, sandboxed) => JSON.parse(await run(sandboxed ? '/usr/bin/sandbox-exec' : executable,
            [...(sandboxed ? ['-p', scoped, executable] : []), 'inet-probe', host, String(port), protocol, mode]));
          const allowed = await probe('127.0.0.1', frontPort, 'tcp', true); assert.equal(allowed.connected, true); inactive(allowed);
          for (const [host,port,protocol] of [['127.0.0.1',deniedPort,'tcp'],['::1',ipv6Port,'tcp'],['127.0.0.1',udp.address().port,'udp']]) {
            assert.equal((await probe(host,port,protocol,false)).connected, true, 'own unsandboxed control must reach each server');
            const blocked = await probe(host,port,protocol,true);
            assert.equal(blocked.connected, false); assert.ok([1,13].includes(blocked.error)); inactive(blocked);
            assert.equal(blocked.childObserved, mode === 'inherit');
          }
          await new Promise(resolve => setTimeout(resolve, 30));
          assert.equal(allowedConnections, before.allowedConnections + 1);
          assert.equal(deniedConnections, before.deniedConnections + 1);
          assert.equal(ipv6Connections, before.ipv6Connections + 1);
          assert.equal(packets, before.packets + 1);
        }
      });

      await t.test('unsigned self-owned notion.id bundle cannot plan or stage a protected launch', async () => {
        const bundle = path.join(temporary, 'Own Fixture.app');
        const workspace = path.join(temporary, 'selected workspace 空间');
        mkdirSync(path.join(bundle, 'Contents', 'MacOS'), { recursive: true, mode: 0o755 });
        mkdirSync(path.join(bundle, 'Contents', 'Frameworks', 'Electron Framework.framework', 'Resources'),
          { recursive: true, mode: 0o755 });
        mkdirSync(workspace, { mode: 0o700 });
        // These are solely the compiled fixture's bytes, never Notion's bytes.
        copyFileSync(executable, path.join(bundle, 'Contents', 'MacOS', 'Notion'));
        chmodSync(path.join(bundle, 'Contents', 'MacOS', 'Notion'), 0o755);
        writeFileSync(path.join(bundle, 'Contents', 'Info.plist'), `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleIdentifier</key><string>notion.id</string><key>CFBundleExecutable</key><string>Notion</string><key>CFBundleShortVersionString</key><string>7.34.0</string></dict></plist>`, { mode: 0o644 });
        writeFileSync(path.join(bundle, 'Contents', 'Frameworks', 'Electron Framework.framework', 'Resources', 'Info.plist'),
          '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleVersion</key><string>43.6.0</string></dict></plist>',
          { mode: 0o644 });
        writeFileSync(path.join(workspace, 'marker'), 'selected workspace preserved\n', { mode: 0o600 });
        const before = tree(temporary);
        const report = JSON.parse(await run(executable, ['refusal', bundle, workspace]));
        assert.equal(report.ok, true);
        for (const key of ['fixtureManifestRefused', 'unsealedRefused', 'planRefused', 'stageRefused']) {
          assert.equal(report[key], true, key);
        }
        assert.equal(report.childPID, 0); inactive(report);
        assert.deepEqual(tree(temporary), before, 'read-only refusal must preserve every owned input and create no state');
      });

      const socket = path.join(temporary, 's');
      assert.ok(Buffer.byteLength(socket) < 104, 'owned AF_UNIX path must fit sockaddr_un');
      let connections = 0;
      server = createServer(client => { connections++; client.destroy(); });
      await new Promise((resolve, reject) => {
        server.once('error', reject); server.listen(socket, resolve);
      });
      chmodSync(socket, 0o600);
      const localDeny = profile + `(deny network-outbound (remote unix-socket (literal "${socket}")))`;
      for (const mode of ['direct', 'inherit']) {
        await t.test(`self-owned Unix socket allows ${mode} control and Seatbelt denies ${mode} probe`, async () => {
          const before = connections;
          const control = JSON.parse(await run(executable, ['socket-probe', socket, mode]));
          await new Promise(resolve => setImmediate(resolve));
          assert.equal(control.connected, true); assert.equal(control.error, 0);
          assert.equal(control.childObserved, mode === 'inherit'); inactive(control);
          assert.equal(connections, before + 1, 'own server must independently observe the unsandboxed control');
          const denied = JSON.parse(await run('/usr/bin/sandbox-exec', ['-p', localDeny, executable, 'socket-probe', socket, mode]));
          await new Promise(resolve => setImmediate(resolve));
          assert.equal(denied.connected, false);
          assert.ok([1, 13].includes(denied.error), `expected EPERM/EACCES, got ${denied.error}`);
          assert.equal(denied.childObserved, mode === 'inherit'); inactive(denied);
          assert.equal(connections, before + 1, 'denied probe must never reach the owned server');
        });
      }

      const notion = '/Applications/Notion.app';
      const notionVersion = plistValue(path.join(notion, 'Contents', 'Info.plist'), 'CFBundleShortVersionString');
      const electronVersion = plistValue(path.join(notion, 'Contents', 'Frameworks', 'Electron Framework.framework', 'Resources', 'Info.plist'), 'CFBundleVersion');
      const exactVersions = ['7.34.0', '7.37.1'].includes(notionVersion) && electronVersion === '43.6.0';
      await t.test('exact installed Notion version passes read-only strict identity inspection',
        { skip: exactVersions ? false : 'installed metadata differs from exact Notion 7.34.0 or 7.37.1 / Electron 43.6.0' }, async () => {
          const report = JSON.parse(await run(executable, ['supported', notion]));
          assert.equal(report.ok, true); assert.equal(report.supported, true); assert.equal(report.error, 0);
          assert.equal(report.requiredTeam, 'LBQJ96FQ8D');
          assert.equal(report.supportedVersion, notionVersion); assert.equal(report.electronVersion, '43.6.0');
          inactive(report);
        });
    } finally {
      for (const s of networkServers) if (s.listening) await new Promise(resolve => s.close(resolve));
      if (udp) await new Promise(resolve => udp.close(resolve));
      if (server?.listening) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
      rmSync(temporary, { recursive: true, force: true });
    }
  });
