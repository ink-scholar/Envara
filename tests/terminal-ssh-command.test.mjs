import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import path from 'node:path';
import test from 'node:test';
import { createSshChildEnvironment, describeSshSession, parseSshInvocation, runSshCommand, SSH_SESSION_SCHEMA, SSH_SESSION_VERSION } from '../electron/terminal-ssh-command.mjs';

const now = 1_800_000_000_000;
const baseConnection = { id: 'ssh_fixture_a', name: 'Fixture server', alias: 'envara-123456789abc', host: 'ssh-fixture.invalid', port: 2222, user: 'fixture' };
const connection = { ...baseConnection, authType: 'publickey', expiresAt: now + 3_600_000 };
const passwordConnection = { ...connection, authType: 'password', expiresAt: null };
const described = (record, status = 'ready') => ({ ...record, status, available: status === 'ready' });
const manifest = (connections = [connection], expiresAt = connections.length && !connections.some(record => record.expiresAt === null)
  ? Math.max(...connections.map(record => record.expiresAt)) : null) => ({
  schema: SSH_SESSION_SCHEMA, version: SSH_SESSION_VERSION, connections, expiresAt,
});
const parse = (argv, connections = [connection], entry = 'ssh') => parseSshInvocation(argv, { connections, entry });
const fail = code => ({ code });
const recorder = () => { let text = ''; return { write(value) { text += value; }, value: () => text }; };
const adHocConfigPath = path.resolve('owned-fixture-proxy-config');
const childContext = { home: '/private/tmp/owned-ssh-runtime', proxyUrl: 'http://fixture:synthetic-secret@127.0.0.1:48123',
  targetsPath: '/private/tmp/owned-ssh-runtime/targets.json', directSocket: '/private/tmp/owned-ssh-runtime/direct.sock', directToken: 'a'.repeat(64) };
async function invoke({ argv = [], entry = 'ssh', selected = manifest(), currentTime = now, spawn, signals = new EventEmitter(), ...extra } = {}) {
  const output = recorder(), errorOutput = recorder(), calls = [];
  const code = await runSshCommand({ argv, entry, manifest: selected, now: currentTime,
    configPath: path.resolve('owned-fixture-config'), output, errorOutput, signals,
    spawn: spawn ?? ((...args) => { calls.push(args); const child = new EventEmitter(); queueMicrotask(() => child.emit('exit', 0, null)); return child; }),
    ...extra,
  });
  return { code, stdout: output.value(), stderr: errorOutput.value(), calls, signals };
}

test('discovery projects only public session records and has explicit empty, expired and unavailable states', () => {
  const selected = { ...manifest([{ ...connection, keyPath: '/private-fixture/key', password: 'synthetic-secret', keyFingerprint: 'secret-fingerprint' }]),
    usage: 'caller-injected-instructions', credential: 'synthetic-secret' };
  const ready = describeSshSession(selected, now);
  assert.deepEqual(ready.connections, [described(connection)]);
  assert.equal(ready.schema, SSH_SESSION_SCHEMA); assert.equal(ready.version, SSH_SESSION_VERSION);
  assert.equal(ready.status, 'ready'); assert.equal(ready.available, true);
  assert.equal(ready.usage.list, 'envara-ssh list [--json]');
  assert.doesNotMatch(JSON.stringify(ready), /private-fixture|synthetic-secret|fingerprint|caller-injected/);
  const expired = describeSshSession(selected, selected.expiresAt);
  assert.equal(expired.status, 'expired'); assert.equal(expired.available, false); assert.deepEqual(expired.connections, [described(connection, 'expired')]);
  const empty = describeSshSession(manifest([]), now);
  assert.equal(empty.status, 'empty'); assert.equal(empty.available, false); assert.equal(empty.expiresAt, null);
  for (const option of ['closed', 'unavailable']) {
    const hidden = describeSshSession(selected, now, { [option]: true });
    assert.equal(hidden.status, option); assert.equal(hidden.available, false); assert.equal(hidden.expiresAt, null); assert.deepEqual(hidden.connections, []);
  }
  ready.connections[0].host = 'modified.invalid';
  assert.equal(describeSshSession(selected, now).connections[0].host, connection.host);
});

test('explicit saved routes are public references and must match the immutable configured route before native launch', async () => {
  const route = { kind: 'environment', profileId: 'route-b' }, selected = { ...connection, route };
  assert.deepEqual(describeSshSession(manifest([selected]), now).connections[0].route, route);
  assert.equal(Object.hasOwn(describeSshSession(manifest([connection]), now).connections[0], 'route'), false,
    'legacy manifests retain their original public shape');
  const configured = [{ ...connection, route: { kind: 'host' } }];
  const mismatch = await invoke({ argv: [connection.alias], selected: manifest([selected]), configuredConnections: configured });
  assert.equal(mismatch.code, 2); assert.equal(mismatch.calls.length, 0); assert.match(mismatch.stderr, /SSH_SESSION_INVALID/);
  for (const invalidRoute of [{ kind: 'environment', profileId: 'route-b', proxyUrl: 'http://user:secret@127.0.0.1:1234' },
    { kind: 'host', profileId: 'route-b' }, { kind: 'environment' }, null])
    assert.throws(() => describeSshSession(manifest([{ ...connection, route: invalidRoute }]), now), fail('SSH_SESSION_INVALID'));
});

test('discovery refuses malformed schemas, records, expiration and duplicate identities', () => {
  for (const selected of [null, {}, { ...manifest(), schema: 'untrusted' }, { ...manifest(), version: 3 },
    manifest([], now + 1), manifest([connection], null), manifest([connection], NaN),
    manifest([{ ...connection, port: '2222' }]), manifest([{ ...connection, user: 'bad user' }]),
    manifest([{ ...connection, host: 'target\r\ninvalid' }]), manifest([{ ...connection, alias: 'arbitrary' }]),
    manifest([{ ...connection, name: '\x1b[2J' }]), manifest([connection, { ...connection, id: 'other' }]),
    manifest([connection, { ...connection, alias: 'envara-abcdef123456' }]), manifest(Array(21).fill(connection))]) {
    assert.throws(() => describeSshSession(selected, now), fail('SSH_SESSION_INVALID'));
  }
});

test('v2 permits app-lifetime authorization for either authentication type and validates aggregate expiration exactly', () => {
  for (const authType of ['password', 'publickey']) {
    for (const expiresAt of [null, now + 1, Number.MAX_SAFE_INTEGER]) {
      const record = { ...connection, authType, expiresAt };
      const description = describeSshSession(manifest([record]), now);
      assert.equal(description.status, 'ready');
      assert.equal(description.expiresAt, expiresAt);
      assert.deepEqual(description.connections, [described(record)]);
    }
  }
  const second = { ...connection, id: 'ssh_fixture_b', alias: 'envara-abcdef123456', expiresAt: now + 1 };
  const finite = manifest([connection, second]);
  assert.equal(describeSshSession(finite, now).expiresAt, connection.expiresAt);
  for (const expiresAt of [null, second.expiresAt, connection.expiresAt - 1, connection.expiresAt + 1, NaN, Infinity]) {
    assert.throws(() => describeSshSession({ ...finite, expiresAt }, now), fail('SSH_SESSION_INVALID'));
  }
  for (const authType of ['password', 'publickey']) {
    const mixed = manifest([connection, { ...second, authType, expiresAt: null }]);
    assert.equal(describeSshSession(mixed, now).expiresAt, null);
    assert.throws(() => describeSshSession({ ...mixed, expiresAt: connection.expiresAt }, now), fail('SSH_SESSION_INVALID'));
  }
});

test('v2 rejects missing authentication, invalid deadlines and sparse inputs', () => {
  for (const authType of [undefined, null, '', 'key', 'password ']) {
    assert.throws(() => describeSshSession(manifest([{ ...connection, authType }]), now), fail('SSH_SESSION_INVALID'));
  }
  for (const authType of ['password', 'publickey']) {
    for (const expiresAt of [undefined, 0, -1, 1.5, '1800000000001', NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      assert.throws(() => describeSshSession(manifest([{ ...connection, authType, expiresAt }]), now), fail('SSH_SESSION_INVALID'));
    }
  }
  assert.throws(() => describeSshSession(manifest([baseConnection]), now), fail('SSH_SESSION_INVALID'));
  const sparse = Array(2); sparse[1] = passwordConnection;
  assert.throws(() => describeSshSession(manifest(sparse), now), fail('SSH_SESSION_INVALID'));
  assert.throws(() => parse([connection.alias], sparse), fail('SSH_SESSION_INVALID'));
});

test('v1 finite manifests preserve their original public shape while null nonempty expiration remains invalid', async () => {
  const legacy = { schema: SSH_SESSION_SCHEMA, version: 1, expiresAt: now + 1,
    connections: [{ ...baseConnection, authType: 'password', expiresAt: null, status: 'ready', available: true, password: 'synthetic-secret' }] };
  const ready = describeSshSession(legacy, now);
  assert.equal(ready.version, 1);
  assert.deepEqual(ready.connections, [baseConnection]);
  assert.equal(ready.status, 'ready');
  const expired = describeSshSession(legacy, now + 1);
  assert.equal(expired.status, 'expired');
  assert.deepEqual(expired.connections, [baseConnection]);
  assert.throws(() => describeSshSession({ ...legacy, expiresAt: null }, now), fail('SSH_SESSION_INVALID'));
  assert.equal(describeSshSession({ ...legacy, connections: [], expiresAt: null }, now).status, 'empty');
  const result = await invoke({ argv: [connection.alias], selected: legacy });
  assert.equal(result.code, 0); assert.equal(result.calls.length, 1);
  let dispatched = 0;
  const password = await invoke({ argv: [connection.alias], selected: legacy,
    passwordBroker: { socket: '/private/tmp/legacy-fixture.sock', aliases: [connection.alias] },
    passwordClient: async () => { dispatched++; return 23; } });
  assert.equal(password.code, 23); assert.equal(password.calls.length, 0); assert.equal(dispatched, 1);
});

test('statuses are recomputed per record and unavailable aliases take priority over expiration', () => {
  const expired = { ...connection, expiresAt: now, status: 'ready', available: true };
  const password = { ...passwordConnection, id: 'password', alias: 'envara-abcdef123456', status: 'expired', available: false };
  const selected = { ...manifest([expired, password]), status: 'expired', available: false };
  const description = describeSshSession(selected, now);
  assert.equal(description.status, 'ready'); assert.equal(description.available, true); assert.equal(description.expiresAt, null);
  assert.deepEqual(description.connections, [described({ ...connection, expiresAt: now }, 'expired'),
    described({ ...passwordConnection, id: 'password', alias: password.alias })]);
  const unavailable = describeSshSession(selected, now, { unavailableAliases: [expired.alias] });
  assert.equal(unavailable.status, 'ready');
  assert.equal(unavailable.connections[0].status, 'unavailable');
  assert.equal(unavailable.connections[0].available, false);
  assert.equal(unavailable.connections[1].status, 'ready');
  const concealed = describeSshSession(selected, now, { unavailableAliases: [password.alias] });
  assert.equal(concealed.status, 'unavailable'); assert.equal(concealed.expiresAt, null); assert.deepEqual(concealed.connections, []);
  for (const options of [{ closed: true }, { unavailable: true }, { unavailableAliases: [expired.alias, password.alias] }]) {
    const hidden = describeSshSession(selected, now, options);
    assert.equal(hidden.available, false); assert.deepEqual(hidden.connections, []); assert.equal(hidden.expiresAt, null);
  }
});

test('unavailable alias observations require a unique known alias array', () => {
  for (const unavailableAliases of [null, false, 'alias', {}, [connection.alias, connection.alias],
    ['arbitrary'], ['envara-abcdef123456'], [null], Array(1)]) {
    assert.throws(() => describeSshSession(manifest(), now, { unavailableAliases }), fail('SSH_SESSION_INVALID'));
  }
});

test('alias, user@host and explicit -l requests map to the same saved configuration', () => {
  for (const argv of [
    [connection.alias], ['-p', '2222', '-l', 'fixture', connection.alias],
    ['-p', '2222', 'fixture@ssh-fixture.invalid'], ['fixture@ssh-fixture.invalid', '-p', '2222'],
    ['-p2222', 'fixture@SSH-Fixture.INVALID'], ['fixture@ssh-fixture.invalid', '-p2222'],
    ['-l', 'fixture', '-p', '2222', 'ssh-fixture.invalid'], ['ssh-fixture.invalid', '-p2222', '-lfixture'],
    ['-lfixture', '-p2222', 'fixture@ssh-fixture.invalid'],
  ]) assert.deepEqual(parse(argv), { kind: 'connect', alias: connection.alias, flags: [], command: [] }, JSON.stringify(argv));
  const defaultPort = { ...connection, port: 22 };
  assert.equal(parse(['fixture@ssh-fixture.invalid'], [defaultPort]).alias, connection.alias);
  assert.throws(() => parse(['fixture@ssh-fixture.invalid']), fail('SSH_TARGET_NOT_AUTHORIZED'));
});

test('explicit environment capability permits new destinations without changing saved target selection', () => {
  const options = { connections: [connection], allowAdHoc: true };
  assert.deepEqual(parseSshInvocation(['-p2200', 'other@new.invalid', '-T', 'printf', '-oProxyCommand=remote-data'], options), {
    kind: 'connect', alias: null, target: { host: 'new.invalid', port: 2200, user: 'other' }, flags: ['-T'], command: ['printf', '-oProxyCommand=remote-data'],
  });
  assert.deepEqual(parseSshInvocation(['-lfixture', 'NEW.invalid'], { connections: [], allowAdHoc: true }).target,
    { host: 'new.invalid', port: 22, user: 'fixture' });
  assert.deepEqual(parseSshInvocation(['envara-user@envara-server.invalid'], { connections: [], allowAdHoc: true }).target,
    { host: 'envara-server.invalid', port: 22, user: 'envara-user' });
  assert.deepEqual(parseSshInvocation(['fixture@[2001:db8::12]'], options).target,
    { host: '2001:db8::12', port: 22, user: 'fixture' });
  assert.equal(parseSshInvocation(['-p2222', 'fixture@ssh-fixture.invalid'], options).alias, connection.alias);
  assert.equal(parseSshInvocation(['-p2223', 'fixture@ssh-fixture.invalid'], options).alias, null);
  for (const argv of [['-p2222', 'other@ssh-fixture.invalid'], [connection.alias, '-lother'], ['envara-deadbeefdead'], ['fixture@envara-deadbeefdead']]) {
    assert.throws(() => parseSshInvocation(argv, options), fail('SSH_TARGET_NOT_AUTHORIZED'));
  }
  assert.throws(() => parseSshInvocation(['new.invalid'], options), fail('SSH_ARGUMENT_INVALID'));
  assert.throws(() => parseSshInvocation(['fixture@new.invalid']), fail('SSH_CONNECTIONS_EMPTY'));
  assert.throws(() => parseSshInvocation(['fixture@new.invalid'], { ...options, allowAdHoc: 'yes' }), fail('SSH_SESSION_INVALID'));
});

test('environment destinations keep the connection-option whitelist and opaque remote command boundary', () => {
  for (const flag of ['-i/private/key', '-oProxyCommand=direct', '-F/custom', '-Jjump', '-A', '-L1234:x:22', '-s', '-tt']) {
    for (const argv of [[flag, 'fixture@new.invalid'], ['fixture@new.invalid', flag]]) {
      assert.throws(() => parseSshInvocation(argv, { allowAdHoc: true }), fail('SSH_OPTIONS_UNSUPPORTED'));
    }
  }
  assert.deepEqual(parseSshInvocation(['fixture@new.invalid', '--', '-i', '/remote/path'], { allowAdHoc: true }).command,
    ['-i', '/remote/path']);
});

test('an empty saved manifest can start only the fixed proxy configuration with explicit target arguments', async () => {
  const result = await invoke({ argv: ['-v', '-p2200', 'fixture@new.invalid', '-T', 'printf', '%s', 'remote data'],
    selected: manifest([]), configuredConnections: [], adHocConfigPath, childEnvironment: childContext });
  assert.equal(result.code, 0); assert.equal(result.calls.length, 1);
  assert.deepEqual(result.calls[0][1], ['-F', adHocConfigPath, '-v', '-T', '-oBatchMode=yes', '-p', '2200', '-l', 'fixture', '--', 'new.invalid', 'printf', '%s', 'remote data']);
  assert.deepEqual(result.calls[0][2].env, createSshChildEnvironment(childContext));
  const refused = await invoke({ argv: ['fixture@new.invalid'], selected: manifest([]) });
  assert.equal(refused.calls.length, 0); assert.match(refused.stderr, /SSH_CONNECTIONS_EMPTY/);
});

test('new destinations require a local input and output TTY for manual authentication', async () => {
  for (const [inputTty, outputTty] of [[true, true], [true, false], [false, true], [false, false]]) {
    const result = await invoke({ argv: ['-T', 'fixture@new.invalid', 'true'], selected: manifest([]), adHocConfigPath,
      input: { isTTY: inputTty }, output: { isTTY: outputTty, write() {} } });
    assert.equal(result.code, 0);
    assert.equal(result.calls[0][1].includes('-oBatchMode=yes'), !(inputTty && outputTty));
    assert.ok(result.calls[0][1].includes('-T'));
  }
  const saved = await invoke({ argv: [connection.alias], adHocConfigPath,
    input: { isTTY: false }, output: { isTTY: false, write() {} } });
  assert.equal(saved.calls[0][1].includes('-oBatchMode=yes'), false);
});

test('configured but locked targets never become environment destinations or borrow another identity', async () => {
  const locked = { ...passwordConnection, id: 'locked-password', alias: 'envara-abcdef123456', host: 'locked.invalid', port: 22 };
  for (const argv of [[locked.alias], [`${locked.user}@${locked.host}`]]) {
    const result = await invoke({ argv, selected: manifest([]), configuredConnections: [locked], adHocConfigPath,
      passwordClient: async () => { throw new Error('No unavailable credential may be requested'); } });
    assert.equal(result.code, 2); assert.equal(result.calls.length, 0); assert.match(result.stderr, /SSH_SAVED_CONNECTION_UNAVAILABLE/);
  }
  const mismatch = await invoke({ argv: ['other@locked.invalid'], selected: manifest([]), configuredConnections: [locked], adHocConfigPath });
  assert.equal(mismatch.calls.length, 0); assert.match(mismatch.stderr, /SSH_TARGET_NOT_AUTHORIZED/);
  const unknown = await invoke({ argv: ['fixture@new.invalid'], selected: manifest([]), configuredConnections: [locked], adHocConfigPath });
  assert.equal(unknown.code, 0); assert.equal(unknown.calls[0][1][1], adHocConfigPath);
});

test('equivalent numeric saved and locked endpoints cannot escape to the environment proxy', async () => {
  for (const hosts of [
    ['2001:db8::1', '2001:0db8:0000:0000:0000:0000:0000:0001', '[2001:DB8:0:0::1]'],
    ['192.0.2.1', '::ffff:192.0.2.1', '::ffff:c000:201', '[0:0:0:0:0:FFFF:C000:0201]'],
  ]) for (const stored of hosts) for (const requested of hosts) {
    const saved = { ...connection, host: stored }, argv = ['-p2222', `fixture@${requested}`];
    assert.equal(parseSshInvocation(argv, { connections: [saved], allowAdHoc: true }).alias, saved.alias, `${stored} / ${requested}`);
    const active = await invoke({ argv, selected: manifest([saved]), configuredConnections: [{ ...saved, host: requested }], adHocConfigPath });
    assert.equal(active.code, 0); assert.equal(active.calls[0][1][1], path.resolve('owned-fixture-config'));
    assert.ok(active.calls[0][1].includes(saved.alias));
    const locked = { ...saved, authType: 'password', expiresAt: null };
    const refused = await invoke({ argv, selected: manifest([]), configuredConnections: [locked], adHocConfigPath });
    assert.equal(refused.calls.length, 0); assert.match(refused.stderr, /SSH_SAVED_CONNECTION_UNAVAILABLE/);
    const otherUser = await invoke({ argv: ['-p2222', `other@${requested}`], selected: manifest([]), configuredConnections: [locked], adHocConfigPath });
    assert.equal(otherUser.calls.length, 0); assert.match(otherUser.stderr, /SSH_TARGET_NOT_AUTHORIZED/);
  }
  const duplicate = { ...connection, id: 'another', alias: 'envara-abcdef123456', host: '0:0:0:0:0:ffff:c000:201' };
  assert.throws(() => parseSshInvocation(['-p2222', 'fixture@192.0.2.1'], {
    connections: [{ ...connection, host: '::ffff:192.0.2.1' }, duplicate], allowAdHoc: true }), fail('SSH_TARGET_AMBIGUOUS'));
});

test('proxy capability cannot reroute saved expiration, ambiguity or a mismatched configured snapshot', async () => {
  const expired = { ...connection, expiresAt: now };
  const result = await invoke({ argv: [expired.alias], selected: manifest([expired]), configuredConnections: [expired], adHocConfigPath });
  assert.equal(result.calls.length, 0); assert.match(result.stderr, /SSH_AUTHORIZATION_EXPIRED/);
  for (const configuredConnections of [[], [{ ...connection, host: 'changed.invalid' }], [{ ...connection, id: 'changed' }]]) {
    const value = await invoke({ argv: ['fixture@new.invalid'], configuredConnections, adHocConfigPath });
    assert.equal(value.calls.length, 0); assert.match(value.stderr, /SSH_SESSION_INVALID/);
  }
  const second = { ...connection, id: 'second', alias: 'envara-abcdef123456' };
  const ambiguous = await invoke({ argv: ['-p2222', 'fixture@ssh-fixture.invalid'], selected: manifest([connection, second]), adHocConfigPath });
  assert.equal(ambiguous.calls.length, 0); assert.match(ambiguous.stderr, /SSH_TARGET_AMBIGUOUS/);
  const selected = await invoke({ argv: [connection.alias], adHocConfigPath, childEnvironment: childContext });
  assert.equal(selected.code, 0); assert.equal(selected.calls[0][1][1], path.resolve('owned-fixture-config'));
});

test('native child environment has only fixed runtime fields and explicitly issued capabilities', () => {
  const value = createSshChildEnvironment({ ...childContext, USER: 'host-user', LOGNAME: 'host-user', HOSTNAME: 'host-name',
    PWD: '/private/host', TZ: 'Private/Zone', DISPLAY: ':42', ANTHROPIC_API_KEY: 'host-secret', SSH_AUTH_SOCK: '/host-agent',
    NODE_OPTIONS: '--require=host-code', LANG: 'host-locale', environment: process.env });
  assert.deepEqual(value, { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: childContext.home, LANG: 'C', LC_ALL: 'C', TERM: 'xterm-256color',
    SSH_ASKPASS_REQUIRE: 'never', SSH_ASKPASS: '/usr/bin/false', ENVARA_SSH_PROXY_URL: childContext.proxyUrl,
    ENVARA_SSH_TARGETS: childContext.targetsPath, ENVARA_SSH_DIRECT_SOCKET: childContext.directSocket, ENVARA_SSH_DIRECT_TOKEN: childContext.directToken });
  const askpass = createSshChildEnvironment({ ...childContext, askpassPath: '/private/tmp/owned/askpass',
    askpassSocket: '/private/tmp/owned/auth.sock', askpassToken: 'b'.repeat(64) });
  assert.equal(askpass.SSH_ASKPASS_REQUIRE, 'force'); assert.equal(askpass.SSH_ASKPASS, '/private/tmp/owned/askpass');
  assert.equal(askpass.ENVARA_SSH_ASKPASS_SOCKET, '/private/tmp/owned/auth.sock'); assert.equal(askpass.ENVARA_SSH_ASKPASS_TOKEN, 'b'.repeat(64));
});

test('invalid native capabilities and ad-hoc config paths fail before spawning or echoing values', async () => {
  for (const value of [{ home: 'relative' }, { home: '/private/tmp/owned', proxyUrl: 'http://private-secret@remote.invalid' },
    { home: '/private/tmp/owned', targetsPath: '../private-secret' }, { home: '/private/tmp/owned', directSocket: '/private/tmp/direct.sock' },
    { home: '/private/tmp/owned', directToken: 'a'.repeat(64) }, { home: '/private/tmp/owned', askpassPath: '/private/tmp/askpass' },
    { home: '/private/tmp/owned', askpassSocket: '/private/tmp/auth.sock', askpassToken: 'private-secret' }]) {
    assert.throws(() => createSshChildEnvironment(value), fail('SSH_SESSION_INVALID'));
    const result = await invoke({ argv: [connection.alias], childEnvironment: value });
    assert.equal(result.calls.length, 0); assert.match(result.stderr, /SSH_SESSION_INVALID/); assert.doesNotMatch(result.stderr, /private-secret/);
  }
  for (const config of [null, '', 'relative', '/private/../tmp/config', '/private/tmp/bad\nconfig']) {
    const result = await invoke({ argv: ['fixture@new.invalid'], adHocConfigPath: config });
    assert.equal(result.calls.length, 0); assert.match(result.stderr, /SSH_SESSION_INVALID/);
  }
});

test('the first remote command token or explicit delimiter permanently ends connection options', () => {
  const command = ['printf', '--', '-p', '9999', '-oProxyCommand=synthetic', 'one argument with spaces', 'line one\nline two'];
  assert.deepEqual(parse(['fixture@ssh-fixture.invalid', '-p2222', ...command]).command, command);
  assert.deepEqual(parse(['-p2222', 'fixture@ssh-fixture.invalid', ...command]).command, command);
  assert.deepEqual(parse([connection.alias, '--', '-p', '9999']).command, ['-p', '9999']);
  assert.deepEqual(parse(['--', connection.alias, '-p', '9999']).command, ['-p', '9999']);
  assert.deepEqual(parse(['-T', connection.alias, '-vv', 'printf', '-t']).flags, ['-T', '-vv']);
  assert.deepEqual(parse(['-T', connection.alias, '-vv', 'printf', '-t']).command, ['printf', '-t']);
  assert.throws(() => parse([connection.alias, '-oProxyCommand=synthetic']), fail('SSH_OPTIONS_UNSUPPORTED'));
});

test('no unmatched target, conflicting option or ambiguous record can create native arguments', () => {
  for (const argv of [
    ['-p22', 'fixture@ssh-fixture.invalid'], ['-p2222', 'other@ssh-fixture.invalid'],
    ['-p2222', 'fixture@other.invalid'], [connection.alias, '-p22'], [connection.alias, '-lother'],
  ]) assert.throws(() => parse(argv), fail('SSH_TARGET_NOT_AUTHORIZED'));
  for (const argv of [[], ['-p'], ['-p0', connection.alias], ['-p65536', connection.alias], ['-p22x', connection.alias],
    ['-p2222', connection.alias, '-p2222'], ['-lfixture', connection.alias, '-lfixture'],
    ['-lother', '-p2222', 'fixture@ssh-fixture.invalid'], ['-T', '-t', connection.alias],
    ['ssh-fixture.invalid'], ['fixture@ssh-fixture.invalid:2222'], ['fixture@@ssh-fixture.invalid'], ['--']]) {
    assert.throws(() => parse(argv), fail('SSH_ARGUMENT_INVALID'), JSON.stringify(argv));
  }
  const second = { ...connection, id: 'ssh_fixture_b', name: 'Second identity', alias: 'envara-abcdef123456' };
  assert.throws(() => parse(['-p2222', 'fixture@ssh-fixture.invalid'], [connection, second]), fail('SSH_TARGET_AMBIGUOUS'));
  assert.equal(parse([second.alias], [connection, second]).alias, second.alias);
});

test('custom SSH connection and forwarding options are refused before and immediately after the destination', () => {
  for (const argument of ['-i', '-i/private-fixture/key', '-o', '-oProxyCommand=synthetic', '-F', '-Jjump.invalid',
    '-L8080:target.invalid:80', '-R8080:target.invalid:80', '-D8080', '-A', '-X', '-Y', '-Wtarget.invalid:22', '-N', '-S', '-G']) {
    for (const argv of [[argument, connection.alias], [connection.alias, argument]]) {
      assert.throws(() => parse(argv), fail('SSH_OPTIONS_UNSUPPORTED'), JSON.stringify(argv));
    }
  }
  for (const argv of [[null], ['bad\0value'], Array(513).fill('-v'), ['x'.repeat(64 * 1024 + 1)]]) {
    assert.throws(() => parse(argv), fail('SSH_ARGUMENT_INVALID'));
  }
});

test('IPv6 destinations use validated host identity and a separately matched port', () => {
  const ipv6 = { ...connection, host: '2001:db8::12' };
  for (const host of ['2001:db8::12', '[2001:db8::12]']) assert.equal(parse(['-p2222', `fixture@${host}`], [ipv6]).alias, connection.alias);
  for (const host of ['[2001:db8::12]:2222', '[2001:db8::12', 'fe80::1%en0']) {
    assert.throws(() => parse(['-p2222', `fixture@${host}`], [ipv6]), fail('SSH_ARGUMENT_INVALID'));
  }
});

test('empty sessions expose read-only discovery and a precise refusal without starting native SSH', async () => {
  for (const argv of [[], ['fixture@ssh-fixture.invalid'], ['-i', '/private-fixture/key', 'fixture@ssh-fixture.invalid']]) {
    const result = await invoke({ argv, selected: manifest([]) });
    assert.equal(result.code, 2); assert.equal(result.stdout, ''); assert.equal(result.calls.length, 0);
    assert.match(result.stderr, /SSH_CONNECTIONS_EMPTY.*Terminal > SSH connections.*new terminal session/);
    assert.doesNotMatch(result.stderr, /private-fixture/);
  }
  for (const argv of [['list'], ['list', '--json'], ['help'], ['--help']]) {
    const result = await invoke({ argv, entry: 'envara-ssh', selected: manifest([]) });
    assert.equal(result.code, 0); assert.equal(result.calls.length, 0); assert.equal(result.stderr, '');
    if (argv.includes('--json')) assert.equal(JSON.parse(result.stdout).status, 'empty');
    else assert.match(result.stdout, /No saved SSH connections are loaded/);
  }
});

test('expiration blocks execution but keeps the fixed session discovery readable', async () => {
  const expired = manifest([{ ...connection, expiresAt: now }]);
  const result = await invoke({ argv: [connection.alias], selected: expired });
  assert.equal(result.code, 2); assert.equal(result.calls.length, 0); assert.match(result.stderr, /SSH_AUTHORIZATION_EXPIRED.*No authorization was renewed/);
  const discovery = await invoke({ argv: ['list', '--json'], entry: 'envara-ssh', selected: expired });
  assert.equal(discovery.code, 0); assert.equal(discovery.calls.length, 0);
  const value = JSON.parse(discovery.stdout);
  assert.equal(value.status, 'expired'); assert.equal(value.available, false);
  assert.deepEqual(value.connections, [described(expired.connections[0], 'expired')]);
});

test('an expired key blocks only its selected alias while an app-lifetime password still dispatches', async () => {
  const expiredKey = { ...connection, expiresAt: now };
  const password = { ...passwordConnection, id: 'password', alias: 'envara-abcdef123456' };
  const selected = manifest([expiredKey, password]);
  let requests = 0;
  const extra = { selected, passwordBroker: { socket: '/private/tmp/mixed-fixture.sock', aliases: [password.alias] },
    passwordClient: async () => { requests++; return 23; } };
  const expired = await invoke({ ...extra, argv: [expiredKey.alias] });
  assert.equal(expired.code, 2); assert.equal(expired.calls.length, 0); assert.equal(requests, 0);
  assert.match(expired.stderr, /SSH_AUTHORIZATION_EXPIRED/);
  const passwordRun = await invoke({ ...extra, argv: [password.alias] });
  assert.equal(passwordRun.code, 23); assert.equal(passwordRun.calls.length, 0); assert.equal(requests, 1);
  const unavailable = await invoke({ ...extra, argv: [expiredKey.alias], unavailableAliases: [expiredKey.alias] });
  assert.equal(unavailable.code, 2); assert.match(unavailable.stderr, /SSH_SESSION_INVALID/);
  assert.equal(unavailable.calls.length, 0); assert.equal(requests, 1);
  const ambiguous = await invoke({ ...extra, argv: ['-p2222', 'fixture@ssh-fixture.invalid'] });
  assert.equal(ambiguous.code, 2); assert.match(ambiguous.stderr, /SSH_TARGET_AMBIGUOUS/);
  assert.equal(ambiguous.calls.length, 0); assert.equal(requests, 1);
});

test('finite password expiration blocks only that alias and an app-lifetime key retains its native path', async () => {
  const key = { ...connection, expiresAt: null };
  const password = { ...passwordConnection, id: 'password', alias: 'envara-abcdef123456', expiresAt: now };
  const selected = manifest([key, password]);
  let requests = 0;
  const extra = { selected, passwordBroker: { socket: '/private/tmp/mixed-fixture.sock', aliases: [password.alias] },
    passwordClient: async () => { requests++; return 0; } };
  const expired = await invoke({ ...extra, argv: [password.alias] });
  assert.equal(expired.code, 2); assert.match(expired.stderr, /SSH_AUTHORIZATION_EXPIRED/);
  assert.equal(expired.calls.length, 0); assert.equal(requests, 0);
  const native = await invoke({ ...extra, argv: [key.alias], currentTime: Number.MAX_SAFE_INTEGER });
  assert.equal(native.code, 0); assert.equal(native.calls.length, 1); assert.equal(requests, 0);
  const unavailable = await invoke({ ...extra, argv: [key.alias], unavailableAliases: [key.alias] });
  assert.equal(unavailable.code, 2); assert.match(unavailable.stderr, /SSH_SESSION_INVALID/);
  assert.equal(unavailable.calls.length, 0);
});

test('text discovery marks individual expired and unavailable records while the session remains ready', async () => {
  const expired = { ...connection, name: 'Expired key', expiresAt: now };
  const unavailable = { ...connection, name: 'Unavailable key', id: 'unavailable', alias: 'envara-abcdef123456' };
  const ready = { ...passwordConnection, name: 'Ready password', id: 'ready', alias: 'envara-abcdef123457' };
  const selected = manifest([expired, unavailable, ready]);
  const result = await invoke({ argv: ['list'], entry: 'envara-ssh', selected, unavailableAliases: [unavailable.alias] });
  assert.equal(result.code, 0); assert.equal(result.calls.length, 0);
  assert.match(result.stdout, /Expired key:.*\[expired\]/);
  assert.match(result.stdout, /Unavailable key:.*\[unavailable\]/);
  assert.match(result.stdout, /Ready password:.*\n/);
  assert.doesNotMatch(result.stdout, /Ready password:.*\[(?:expired|unavailable)\]/);
});

test('text discovery handles every positive safe integer deadline without a Date conversion failure', async () => {
  const selected = manifest([{ ...connection, expiresAt: Number.MAX_SAFE_INTEGER }]);
  for (const argv of [['list'], ['help']]) {
    const result = await invoke({ argv, entry: 'envara-ssh', selected });
    assert.equal(result.code, 0); assert.equal(result.stderr, ''); assert.equal(result.calls.length, 0);
    assert.match(result.stdout, /Unix timestamp 9007199254740991 ms/);
  }
});

test('native invocation receives only the fixed config, allowed flags, matched alias and opaque command', async () => {
  const command = ['printf', '%s', '-oProxyCommand=remote-data'];
  const result = await invoke({ argv: ['-v', 'fixture@ssh-fixture.invalid', '-p2222', '-T', ...command] });
  assert.equal(result.code, 0); assert.equal(result.calls.length, 1); assert.equal(result.stderr, '');
  const [executable, argv, options] = result.calls[0];
  assert.equal(executable, '/usr/bin/ssh');
  assert.deepEqual(argv, ['-F', path.resolve('owned-fixture-config'), '-v', '-T', '--', connection.alias, ...command]);
  assert.equal(options.stdio, 'inherit'); assert.equal(options.env.SSH_ASKPASS_REQUIRE, 'never');
  for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) assert.equal(result.signals.listenerCount(signal), 0);
});

test('native signals and failures are cleaned up without exposing underlying exception text', async () => {
  const signals = new EventEmitter(), killed = [];
  const terminated = await invoke({ argv: [connection.alias], signals, spawn: () => {
    const child = new EventEmitter(); child.kill = signal => { killed.push(signal); child.emit('exit', null, signal); };
    queueMicrotask(() => signals.emit('SIGTERM')); return child;
  } });
  assert.equal(terminated.code, 1); assert.deepEqual(killed, ['SIGTERM']); assert.equal(signals.listenerCount('SIGTERM'), 0);
  const result = await invoke({ argv: [connection.alias], spawn: () => {
    const child = new EventEmitter(); queueMicrotask(() => child.emit('error', new Error('sensitive-private-fixture-detail'))); return child;
  } });
  assert.equal(result.code, 1); assert.match(result.stderr, /SSH_CLIENT_UNAVAILABLE/); assert.doesNotMatch(result.stderr, /sensitive-private/);
});

test('password dispatch keeps its fixed broker capability and chooses raw mode only for a remote PTY', async () => {
  const socket = '/private/tmp/envara-test-command.sock';
  for (const [argv, localTty, expectedTty] of [
    [[connection.alias], true, true], [[connection.alias, 'sleep', '10'], true, false],
    [['-T', connection.alias], true, false], [['-t', connection.alias, 'id'], false, true],
    [[connection.alias], false, false],
  ]) {
    const calls = [], output = { ...recorder(), isTTY: localTty, columns: 100, rows: 40 }, errorOutput = recorder();
    const code = await runSshCommand({ argv, manifest: manifest([passwordConnection]), now, configPath: path.resolve('fixture-config'),
      passwordBroker: { socket, aliases: [connection.alias] }, input: { isTTY: localTty }, output, errorOutput,
      passwordClient: async options => { calls.push(options); return 23; }, spawn: () => { throw new Error('Password dispatch cannot spawn in the terminal'); } });
    assert.equal(code, 23); assert.equal(calls.length, 1); assert.equal(calls[0].socket, socket);
    assert.equal(calls[0].tty, expectedTty); assert.deepEqual(calls[0].argv, argv); assert.equal(errorOutput.value(), '');
  }
});

test('invalid or mismatched password capability cannot open a broker and keyed connections retain their native path', async () => {
  const keyed = { ...connection, id: 'keyed', alias: 'envara-0123456789ab' };
  let requests = 0;
  const options = { argv: [connection.alias], manifest: manifest([passwordConnection]), now, configPath: path.resolve('fixture-config'),
    output: recorder(), errorOutput: recorder(), passwordClient: async () => { requests++; return 0; } };
  for (const passwordBroker of [{ socket: 'relative', aliases: [connection.alias] },
    { socket: '/private/tmp/fixed.sock', aliases: [keyed.alias] },
    { socket: '/private/tmp/fixed.sock', aliases: [connection.alias, connection.alias] }]) {
    assert.equal(await runSshCommand({ ...options, passwordBroker }), 2);
  }
  assert.equal(requests, 0);
  let native = 0;
  const code = await runSshCommand({ ...options, argv: [keyed.alias], manifest: manifest([passwordConnection, keyed]),
    passwordBroker: { socket: '/private/tmp/fixed.sock', aliases: [connection.alias] },
    spawn: () => { native++; const child = new EventEmitter(); queueMicrotask(() => child.emit('exit', 0)); return child; } });
  assert.equal(code, 0); assert.equal(native, 1); assert.equal(requests, 0);
});

test('v2 authentication type cannot fall back to an unrelated transport', async () => {
  const password = { ...passwordConnection, id: 'second_password', alias: 'envara-abcdef123456' };
  let requests = 0;
  const extra = { argv: [passwordConnection.alias], selected: manifest([passwordConnection, password]),
    passwordClient: async () => { requests++; return 0; } };
  for (const passwordBroker of [null, { socket: '/private/tmp/fixture.sock', aliases: [password.alias] }]) {
    const result = await invoke({ ...extra, passwordBroker });
    assert.equal(result.code, 2); assert.match(result.stderr, /SSH_SESSION_INVALID/);
    assert.equal(result.calls.length, 0);
  }
  const result = await invoke({ argv: [connection.alias], selected: manifest(),
    passwordBroker: { socket: '/private/tmp/fixture.sock', aliases: [connection.alias] },
    passwordClient: extra.passwordClient });
  assert.equal(result.code, 2); assert.match(result.stderr, /SSH_SESSION_INVALID/);
  assert.equal(result.calls.length, 0); assert.equal(requests, 0);
});
