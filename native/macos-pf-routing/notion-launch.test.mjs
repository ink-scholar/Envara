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
  + '(deny mach-lookup (global-name "com.apple.dnssd.service")'
  + ' (global-name "com.apple.nsurlsessiond") (global-name "com.apple.nsurlsessiond-launchondemand"))'
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

      await t.test('scoped paths, launch flags and UTF-8 environment preserve UserData and isolate every environment', async () => {
        const environment = '00000000-0000-4000-8000-000000000204', registration = '00000000-0000-4000-8000-000000000201';
        const context = JSON.parse(await run(executable, ['context', environment, registration, 'zh-CN']));
        inactive(context); assert.equal(context.allocationVerified, false);
        const root = `/Library/PrivilegedHelperTools/io.envara.pf-app-data/${environment}/${registration}`;
        for (const name of ['UserData', 'Home', 'Cache', 'Temp', 'Extensions']) assert.equal(context[name], `${root}/${name}`);
        assert.equal(context.SharedData, `${root}/Home/.vscode-shared`);
        // VS Code binds its main socket inside --user-data-dir and IPC pipes in TMPDIR; macOS limits socket paths to
        // 103 characters, which the scoped paths exceed. Both use short root-owned aliases of the same directories.
        assert.match(context.UserDataAlias, /^\/Library\/PrivilegedHelperTools\/io\.envara\.pf-s\/[0-9a-f]{16}u$/);
        assert.equal(context.TempAlias, context.UserDataAlias.slice(0, -1) + 't');
        assert.ok(`${context.UserData}/1.14-main.sock`.length > 103, 'the scoped path alone is too long for a socket');
        assert.ok(`${context.UserDataAlias}/1.14-main.sock`.length < 103);
        assert.ok(103 - 1 - `${context.TempAlias}/vscode-ipc-.sock`.length >= 16, 'VS Code keeps at least 16 random pipe characters');
        assert.ok(`${context.TempAlias}/scoped_dirXXXXXX/SingletonSocket`.length < 104, 'Chromium singleton socket fits');
        for (const flag of [`--user-data-dir=${context.UserDataAlias}`, `--extensions-dir=${context.Extensions}`,
          `--shared-data-dir=${context.SharedData}`, `--disk-cache-dir=${context.Cache}`, '--no-sandbox',
          '--proxy-bypass-list=<-loopback>', '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1']) assert.ok(context.arguments.includes(flag), flag);
        assert.ok(context.posixLocale.endsWith('.UTF-8'));
        assert.ok(context.environment.includes(`HOME=${context.Home}`));
        assert.ok(context.environment.includes(`TMPDIR=${context.TempAlias}/`));
        assert.ok(!context.arguments.includes(`--user-data-dir=${context.UserData}`));
        for (const key of ['LANG', 'LC_CTYPE', 'LC_ALL']) assert.ok(context.environment.includes(`${key}=${context.posixLocale}`));
        assert.ok(!context.environment.some(item => /^(VSCODE_|HTTP_PROXY=|HTTPS_PROXY=|ALL_PROXY=|DYLD_)/.test(item)));
        const second = JSON.parse(await run(executable, ['context', '00000000-0000-4000-8000-000000000205', registration, 'unknown-ZZ']));
        for (const name of ['UserData', 'Home', 'Cache', 'Temp', 'Extensions', 'UserDataAlias', 'TempAlias']) assert.notEqual(second[name], context[name]);
        const again = JSON.parse(await run(executable, ['context', environment, registration, 'zh-CN']));
        assert.equal(again.UserDataAlias, context.UserDataAlias, 'an alias name is stable for one environment and application');
        assert.equal(second.posixLocale, 'en_US.UTF-8'); assert.equal(second.localeFallback, true);
      });

      await t.test('engine capability follows framework metadata and defined Mach-O entry points, not application names', async () => {
        let sequence = 0;
        const build = async ({ chromium = false, product = false, version, principal, frameworkId, symbol, extraFramework = false } = {}) => {
          const bundle = path.join(temporary, `Engine ${++sequence}.app`);
          const identifier = product ? 'com.microsoft.VSCode' : `org.envara.fixture.engine${sequence}`;
          const framework = chromium ? 'Owned Chromium Framework' : 'Electron Framework';
          const frameworkRoot = path.join(bundle, 'Contents', 'Frameworks', `${framework}.framework`);
          mkdirSync(path.join(bundle, 'Contents', 'MacOS'), { recursive: true });
          mkdirSync(path.join(frameworkRoot, 'Resources'), { recursive: true });
          copyFileSync(executable, path.join(bundle, 'Contents', 'MacOS', 'Completely Unrelated Name'));
          const plist = fields => '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
            + Object.entries(fields).map(([key,value]) => `<key>${key}</key><string>${value}</string>`).join('') + '</dict></plist>';
          writeFileSync(path.join(bundle, 'Contents', 'Info.plist'), plist({ CFBundlePackageType: 'APPL', CFBundleIdentifier: identifier,
            CFBundleExecutable: 'Completely Unrelated Name', NSPrincipalClass: principal ?? (chromium ? 'BrowserCrApplication' : 'AtomApplication'), CFBundleShortVersionString: '99.99.99' }));
          writeFileSync(path.join(frameworkRoot, 'Resources', 'Info.plist'), plist({ CFBundlePackageType: 'FMWK',
            CFBundleIdentifier: frameworkId ?? (chromium ? `${identifier}.framework` : 'com.github.Electron.framework'),
            CFBundleExecutable: framework, CFBundleVersion: version ?? (chromium ? '155.0.1.2' : '44.1.2') }));
          const compile = spawnSync('xcrun', ['clang', '-dynamiclib', '-x', 'c', '-', '-o', path.join(frameworkRoot, framework)],
            { input: `__attribute__((visibility("default"))) int ${symbol ?? (chromium ? 'ChromeMain' : 'ElectronMain')}(void) { return 0; }`, encoding: 'utf8', timeout: 15_000 });
          assert.equal(compile.status, 0, compile.stderr);
          if (product) {
            mkdirSync(path.join(bundle, 'Contents', 'Resources', 'app'), { recursive: true });
            writeFileSync(path.join(bundle, 'Contents', 'Resources', 'app', 'product.json'), JSON.stringify({
              darwinBundleIdentifier: identifier, applicationName: 'code', quality: 'stable' }));
          }
          if (extraFramework) {
            const other = path.join(bundle, 'Contents', 'Frameworks', 'Other Framework.framework');
            mkdirSync(path.join(other, 'Resources'), { recursive: true });
            copyFileSync(path.join(frameworkRoot, framework), path.join(other, 'Other Framework'));
            writeFileSync(path.join(other, 'Resources', 'Info.plist'), plist({ CFBundlePackageType: 'FMWK', CFBundleIdentifier: `${identifier}.framework`, CFBundleExecutable: 'Other Framework', CFBundleVersion: '155.0.1.2' }));
          }
          return bundle;
        };
        for (const [options, expected] of [[{},1], [{ chromium: true },2], [{ product: true },3],
          [{ principal: 'NSApplication' },0], [{ frameworkId: 'org.fake.framework' },0], [{ version: '43.6.0-suffix' },0],
          [{ version: '43' },0], [{ symbol: 'PretendMain' },0], [{ chromium: true, extraFramework: true },0]]) {
          const bundle = await build(options), before = tree(bundle);
          const report = JSON.parse(await run(executable, ['metadata', bundle]));
          assert.equal(report.engine, expected, JSON.stringify(options)); assert.equal(report.fixtureManifestRefused, true);
          assert.equal(report.metadataOnly, true); assert.equal(report.signedCapabilityVerified, false); inactive(report);
          assert.deepEqual(tree(bundle), before);
        }
        for (const corruption of ['fat-count', 'load-count', 'truncated']) {
          const bundle = await build(); const library = path.join(bundle, 'Contents/Frameworks/Electron Framework.framework/Electron Framework');
          let bytes = readFileSync(library);
          if (corruption === 'fat-count') { bytes.writeUInt32BE(0xcafebabe, 0); bytes.writeUInt32BE(0xffffffff, 4); }
          else if (corruption === 'load-count') bytes.writeUInt32LE(0xffffffff, 16);
          else bytes = bytes.subarray(0, 5);
          writeFileSync(library, bytes);
          assert.equal(JSON.parse(await run(executable, ['metadata', bundle])).engine, 0, corruption);
        }
      });

      await t.test('native validation scope re-proves identity, refuses mutations including restored times, and does not cross end, thread or fork boundaries', async () => {
        const bundle = path.join(temporary, 'Scope Fixture.app');
        mkdirSync(path.join(bundle, 'Contents', 'MacOS'), { recursive: true });
        mkdirSync(path.join(bundle, 'Contents', 'Resources'), { recursive: true });
        copyFileSync(executable, path.join(bundle, 'Contents', 'MacOS', 'Fixture'));
        writeFileSync(path.join(bundle, 'Contents', 'Resources', 'scope-marker'), 'original', { mode: 0o600 });
        writeFileSync(path.join(bundle, 'Contents', 'Info.plist'), '<plist version="1.0"><dict>'
          + '<key>CFBundlePackageType</key><string>APPL</string><key>CFBundleIdentifier</key><string>org.envara.scope-fixture</string>'
          + '<key>CFBundleExecutable</key><string>Fixture</string></dict></plist>');
        const report = JSON.parse(await run(executable, ['validation-scope', bundle]));
        for (const name of ['ok', 'nestedScopesVerified', 'forgedManifestRefused', 'threadIsolationVerified', 'forkIsolationVerified', 'mutationRefused', 'scopeCleared',
          'identityReproofCounted', 'restoredTimesMutationRefused', 'witnessEndsWithScope']) assert.equal(report[name], true, name);
        inactive(report);
      });

      await t.test('diagnostic step frames are fixed, bounded, whole lines from the beginning process only, and never block', async () => {
        const lines = (await run(executable, ['step-frames'])).split('\n');
        assert.equal(lines.length, 16);
        const keys = ['schema', 'event', 'runId', 'environmentId', 'step', 'stepMs', 'totalMs', 'fullChecks', 'identityChecks', 'ready', 'protected'];
        lines.forEach((line, index) => {
          const frame = JSON.parse(line);
          assert.equal(line, JSON.stringify(frame));
          assert.deepEqual(Object.keys(frame), keys);
          assert.equal(frame.schema, 'envara.macos-pf-app-transport/v1'); assert.equal(frame.event, 'stage-progress');
          assert.equal(frame.runId, '11111111-2222-4333-8444-555555555555'); assert.equal(frame.environmentId, '66666666-7777-4888-9999-aaaaaaaaaaaa');
          assert.equal(frame.step, index === 0 ? 'front-commit' : 'ticket-prepare');
          assert.ok(Number.isSafeInteger(frame.stepMs) && Number.isSafeInteger(frame.totalMs) && frame.stepMs <= frame.totalMs);
          assert.equal(frame.fullChecks, 0); assert.equal(frame.identityChecks, 0);
          assert.equal(frame.ready, false); assert.equal(frame.protected, false);
        });
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
        // Only the application's own scoped directory admits local socket connects.
        const socketRoot = '/Library/PrivilegedHelperTools/io.envara.pf-app-data/c18de15a-7946-423e-9fee-7ec215e188e5/cbf1365d-358c-4081-a6a3-3053cfdebd7f';
        const local = await run(executable, ['scoped-profile', String(frontPort), socketRoot]);
        assert.ok(local.endsWith(`(allow network-outbound (remote tcp4 "localhost:${frontPort}"))` +
          `(allow network-outbound (remote unix-socket (subpath "${socketRoot}")))`));
        for (const bad of [socketRoot + '/UserData', socketRoot.replace('pf-app-data', 'pf-apps'), socketRoot.replace('c18de15a', 'c18de15"'), '/tmp'])
          await assert.rejects(run(executable, ['scoped-profile', String(frontPort), bad]), undefined, bad);
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

      const vscode = '/Applications/Visual Studio Code.app';
      await t.test('installed VS Code passes actual read-only engine and Microsoft signature checks',
        { skip: existsSync(path.join(vscode, 'Contents', 'Info.plist')) ? false : 'VS Code is not installed' }, async () => {
          const report = JSON.parse(await run(executable, ['supported', vscode]));
          assert.equal(report.supported, true); assert.equal(report.error, 0); assert.equal(report.engine, 3);
          assert.equal(report.requiredTeam, 'UBF8T346G9'); inactive(report);
        });

      const notion = '/Applications/Notion.app';
      const notionVersion = plistValue(path.join(notion, 'Contents', 'Info.plist'), 'CFBundleShortVersionString');
      const electronVersion = plistValue(path.join(notion, 'Contents', 'Frameworks', 'Electron Framework.framework', 'Resources', 'Info.plist'), 'CFBundleVersion');
      const exactVersions = Boolean(notionVersion && electronVersion);
      await t.test('installed Notion passes read-only signed engine inspection without a version allowlist',
        { skip: exactVersions ? false : 'Notion is not installed' }, async () => {
          const report = JSON.parse(await run(executable, ['supported', notion]));
          assert.equal(report.ok, true); assert.equal(report.supported, true); assert.equal(report.error, 0);
          assert.equal(report.requiredTeam, 'LBQJ96FQ8D');
          assert.equal(report.supportedVersion, notionVersion); assert.equal(report.electronVersion, electronVersion);
          inactive(report);
        });
    } finally {
      for (const s of networkServers) if (s.listening) await new Promise(resolve => s.close(resolve));
      if (udp) await new Promise(resolve => udp.close(resolve));
      if (server?.listening) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
      rmSync(temporary, { recursive: true, force: true });
    }
  });
