// Shared by the main-process discovery tool and the protected terminal shim.
// This module and terminal-ssh-proxy.mjs are copied together into each owned,
// read-only runtime. Keep their dependencies limited to Node builtins.
import { spawn as spawnChild } from 'node:child_process';
import path from 'node:path';
import { validateSshTarget } from './terminal-ssh-proxy.mjs';
import { runPasswordSshClient } from './terminal-ssh-client.mjs';

export const SSH_SESSION_SCHEMA = 'envara.ssh-session';
export const SSH_SESSION_VERSION = 2;
const MAX_CONNECTIONS = 20;
const USER = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const ALIAS = /^envara-[a-f0-9]{12}$/;
const MESSAGES = Object.freeze({
  SSH_SESSION_INVALID: 'The protected SSH session is unavailable. Start a new terminal session.',
  SSH_CONNECTIONS_EMPTY: 'No SSH connections are loaded in this terminal. Open Terminal > SSH connections, save a connection, then start a new terminal session.',
  SSH_AUTHORIZATION_EXPIRED: 'SSH authorization has expired. Start a new terminal session to load the saved connections again. No authorization was renewed.',
  SSH_TARGET_NOT_AUTHORIZED: 'This host, port and user do not match a saved connection. Run envara-ssh list to see this session\'s authorized connections.',
  SSH_TARGET_AMBIGUOUS: 'More than one saved connection matches this host, port and user. Run envara-ssh list and use the intended saved alias.',
  SSH_OPTIONS_UNSUPPORTED: 'Custom connection options are not allowed. Use only -p PORT, -l USER, -T, -t, -v, -vv or -vvv. Run envara-ssh help for examples.',
  SSH_ARGUMENT_INVALID: 'SSH arguments are invalid or conflicting. Use a saved alias or an explicit user@host, and run envara-ssh help for syntax.',
  SSH_CLIENT_UNAVAILABLE: 'The protected SSH client could not start. Start a new terminal session.',
});
const failure = code => Object.assign(new Error(MESSAGES[code] ?? MESSAGES.SSH_SESSION_INVALID), { code });

const usage = () => ({
  list: 'envara-ssh list [--json]',
  alias: 'ssh [-T|-t] [-v|-vv|-vvv] SAVED_ALIAS [COMMAND ...]',
  target: 'ssh [-p PORT] [-l USER] USER@HOST [COMMAND ...]',
  options: 'Connection options may also follow the destination until the first command argument. Use -- to end connection options explicitly. Later command arguments are preserved unchanged.',
  setup: 'Open Terminal > SSH connections, save a connection, then start a new terminal session. Only connections loaded in this session are available.',
});

function publicConnections(value) {
  if (!Array.isArray(value) || value.length > MAX_CONNECTIONS) throw failure('SSH_SESSION_INVALID');
  const aliases = new Set(), ids = new Set();
  return Array.from(value).map(record => {
    if (!record || typeof record !== 'object' || Array.isArray(record)
      || typeof record.id !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(record.id)
      || typeof record.name !== 'string' || !record.name.trim() || record.name.length > 80 || /[\x00-\x1f\x7f]/.test(record.name)
      || typeof record.alias !== 'string' || !ALIAS.test(record.alias)
      || typeof record.user !== 'string' || !USER.test(record.user) || !Number.isInteger(record.port)
      || ids.has(record.id) || aliases.has(record.alias)) throw failure('SSH_SESSION_INVALID');
    let target;
    try { target = validateSshTarget(record.host, record.port); } catch { throw failure('SSH_SESSION_INVALID'); }
    ids.add(record.id); aliases.add(record.alias);
    // Explicit projection: callers may hold private metadata, but discovery
    // never forwards paths, credentials, arbitrary usage strings or key bytes.
    return { id: record.id, name: record.name, alias: record.alias, ...target, user: record.user };
  });
}

/** Describe a fixed session manifest, never the mutable global connection store.
 * The caller supplies lifecycle observations; ready is not reachability proof. */
export function describeSshSession(manifest, now = Date.now(), { closed = false, unavailable = false, unavailableAliases = [] } = {}) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)
    || manifest.schema !== SSH_SESSION_SCHEMA || ![1, SSH_SESSION_VERSION].includes(manifest.version)
    || !Number.isFinite(now) || typeof closed !== 'boolean' || typeof unavailable !== 'boolean') throw failure('SSH_SESSION_INVALID');
  const records = publicConnections(manifest.connections);
  if (!Array.isArray(unavailableAliases) || unavailableAliases.length > records.length || new Set(unavailableAliases).size !== unavailableAliases.length
    || Array.from(unavailableAliases).some(alias => typeof alias !== 'string' || !ALIAS.test(alias) || !records.some(record => record.alias === alias))) {
    throw failure('SSH_SESSION_INVALID');
  }
  const expiresAt = manifest.expiresAt;
  const deadline = value => Number.isSafeInteger(value) && value > 0;
  let connections;
  const states = records.map((record, index) => {
    const source = manifest.connections[index];
    const recordExpiry = manifest.version === 1 ? expiresAt : source.expiresAt;
    if (manifest.version === SSH_SESSION_VERSION && (!['password', 'publickey'].includes(source.authType)
      || !deadline(recordExpiry) && recordExpiry !== null)) throw failure('SSH_SESSION_INVALID');
    return unavailableAliases.includes(record.alias) ? 'unavailable'
      : recordExpiry !== null && now >= recordExpiry ? 'expired' : 'ready';
  });
  if (manifest.version === 1) {
    if (records.length ? !deadline(expiresAt) : expiresAt !== null) throw failure('SSH_SESSION_INVALID');
    connections = records;
  } else {
    const aggregate = records.length && !manifest.connections.some(record => record.expiresAt === null)
      ? Math.max(...manifest.connections.map(record => record.expiresAt)) : null;
    if (expiresAt !== aggregate) throw failure('SSH_SESSION_INVALID');
    connections = records.map((record, index) => ({ ...record, authType: manifest.connections[index].authType,
      expiresAt: manifest.connections[index].expiresAt, status: states[index], available: states[index] === 'ready' }));
  }
  const status = closed ? 'closed' : unavailable ? 'unavailable' : !records.length ? 'empty'
    : states.includes('ready') ? 'ready' : states.includes('unavailable') ? 'unavailable' : 'expired';
  const concealed = status === 'closed' || status === 'unavailable';
  return { schema: SSH_SESSION_SCHEMA, version: manifest.version, status, available: status === 'ready',
    expiresAt: concealed ? null : expiresAt, connections: concealed ? [] : connections, usage: usage() };
}

function checkedArguments(argv, entry) {
  if (!['ssh', 'envara-ssh'].includes(entry) || !Array.isArray(argv) || argv.length > 512
    || argv.some(value => typeof value !== 'string' || value.includes('\0'))
    || argv.reduce((total, value) => total + Buffer.byteLength(value), 0) > 64 * 1024) throw failure('SSH_ARGUMENT_INVALID');
}

function discoveryInvocation(argv, entry) {
  checkedArguments(argv, entry);
  if (argv.length === 1 && ['help', '--help', '-h'].includes(argv[0]) || !argv.length && entry === 'envara-ssh') return { kind: 'help' };
  if (entry === 'envara-ssh' && argv[0] === 'list') {
    if (argv.length !== 1 && (argv.length !== 2 || argv[1] !== '--json')) throw failure('SSH_ARGUMENT_INVALID');
    return { kind: 'list', json: argv.length === 2 };
  }
  return null;
}

/** No caller-supplied option reaches native SSH except the small flags below.
 * Once a remote command begins, its remaining arguments are opaque data. */
export function parseSshInvocation(argv, { connections = [], entry = 'ssh' } = {}) {
  const discovery = discoveryInvocation(argv, entry);
  if (discovery) return discovery;
  const records = publicConnections(connections);
  if (!records.length) throw failure('SSH_CONNECTIONS_EMPTY');
  let targetToken = null, selectedPort = null, selectedUser = null, terminalFlag = null;
  let index = 0, command = [];
  const flags = [];
  while (index < argv.length) {
    const argument = argv[index++];
    if (argument === '--') {
      if (targetToken === null) targetToken = argv[index++] ?? null;
      command = argv.slice(index);
      break;
    }
    if (argument.startsWith('-')) {
      if (argument === '-T' || argument === '-t') {
        if (terminalFlag && terminalFlag !== argument) throw failure('SSH_ARGUMENT_INVALID');
        terminalFlag = argument; flags.push(argument); continue;
      }
      if (['-v', '-vv', '-vvv'].includes(argument)) { flags.push(argument); continue; }
      if (argument === '-p' || argument.startsWith('-p')) {
        if (selectedPort !== null) throw failure('SSH_ARGUMENT_INVALID');
        const value = argument === '-p' ? argv[index++] : argument.slice(2);
        if (typeof value !== 'string' || !/^\d{1,5}$/.test(value) || Number(value) < 1 || Number(value) > 65535) throw failure('SSH_ARGUMENT_INVALID');
        selectedPort = Number(value); continue;
      }
      if (argument === '-l' || argument.startsWith('-l')) {
        if (selectedUser !== null) throw failure('SSH_ARGUMENT_INVALID');
        const value = argument === '-l' ? argv[index++] : argument.slice(2);
        if (typeof value !== 'string' || !USER.test(value)) throw failure('SSH_ARGUMENT_INVALID');
        selectedUser = value; continue;
      }
      throw failure('SSH_OPTIONS_UNSUPPORTED');
    }
    if (targetToken === null) { targetToken = argument; continue; }
    command = argv.slice(index - 1);
    break;
  }
  if (!targetToken || targetToken.startsWith('-')) throw failure('SSH_ARGUMENT_INVALID');
  let selected = records.find(record => record.alias === targetToken);
  if (selected) {
    if (selectedPort !== null && selectedPort !== selected.port || selectedUser !== null && selectedUser !== selected.user) throw failure('SSH_TARGET_NOT_AUTHORIZED');
  } else {
    const parts = targetToken.split('@');
    if (parts.length > 2) throw failure('SSH_ARGUMENT_INVALID');
    const user = parts.length === 2 ? parts[0] : selectedUser;
    const host = parts.at(-1);
    if (typeof user !== 'string' || !USER.test(user) || selectedUser !== null && selectedUser !== user) throw failure('SSH_ARGUMENT_INVALID');
    let target;
    try { target = validateSshTarget(host, selectedPort ?? 22); } catch { throw failure('SSH_ARGUMENT_INVALID'); }
    const matches = records.filter(record => record.host === target.host && record.port === target.port && record.user === user);
    if (!matches.length) throw failure('SSH_TARGET_NOT_AUTHORIZED');
    if (matches.length > 1) throw failure('SSH_TARGET_AMBIGUOUS');
    [selected] = matches;
  }
  return { kind: 'connect', alias: selected.alias, flags, command };
}

function describeText(description) {
  const lines = ['Envara SSH connections loaded in this terminal:'];
  if (description.status === 'empty') lines.push(MESSAGES.SSH_CONNECTIONS_EMPTY);
  else if (description.status === 'expired') lines.push(MESSAGES.SSH_AUTHORIZATION_EXPIRED);
  else if (!description.available) lines.push(MESSAGES.SSH_SESSION_INVALID);
  for (const connection of description.connections) {
    const status = ['expired', 'unavailable'].includes(connection.status) ? ` [${connection.status}]` : '';
    lines.push(`${connection.name}: ${connection.user}@${connection.host}:${connection.port}${status}`, `  ssh ${connection.alias}`);
  }
  if (description.expiresAt !== null) {
    const date = new Date(description.expiresAt);
    const formatted = Number.isNaN(date.getTime()) ? `Unix timestamp ${description.expiresAt} ms` : date.toISOString();
    lines.push(`Authorization expires at ${formatted}.`);
  }
  return `${lines.join('\n')}\n`;
}

function helpText(description) {
  return `${describeText(description)}\nUsage:\n  ${description.usage.list}\n  ${description.usage.alias}\n  ${description.usage.target}\n${description.usage.options}\n` +
    'Host, port and user must uniquely match a connection already loaded in this session. Without -p, a host target uses port 22; aliases keep their saved port and user. IPv6 hosts may use brackets; inline host:port is not supported.\n' +
    'Custom key/configuration/proxy options, jump hosts, forwarding, scp and sftp are not supported. No direct-network fallback is used.\n';
}

export async function runSshCommand({ argv = [], entry = 'ssh', manifest, configPath,
  passwordBroker = null, passwordClient = runPasswordSshClient, input = process.stdin,
  unavailableAliases = [], now = Date.now, spawn = spawnChild, output = process.stdout, errorOutput = process.stderr, signals = process } = {}) {
  const writeError = code => errorOutput.write(`Envara SSH [${code}]: ${MESSAGES[code] ?? MESSAGES.SSH_SESSION_INVALID}\n`);
  try {
    const description = describeSshSession(manifest, typeof now === 'function' ? now() : now, { unavailableAliases });
    const discovery = discoveryInvocation(argv, entry);
    if (discovery) {
      output.write(discovery.kind === 'help' ? helpText(description)
        : discovery.json ? `${JSON.stringify(description)}\n` : describeText(description));
      return 0;
    }
    if (description.status === 'empty') throw failure('SSH_CONNECTIONS_EMPTY');
    if (description.status === 'unavailable' || description.status === 'closed') throw failure('SSH_SESSION_INVALID');
    const invocation = parseSshInvocation(argv, { connections: description.connections, entry });
    const selected = description.connections.find(record => record.alias === invocation.alias);
    const selectedStatus = description.version === 1
      ? unavailableAliases.includes(invocation.alias) ? 'unavailable' : description.status : selected.status;
    if (selectedStatus === 'expired') throw failure('SSH_AUTHORIZATION_EXPIRED');
    if (selectedStatus === 'unavailable') throw failure('SSH_SESSION_INVALID');
    if (typeof configPath !== 'string' || !path.isAbsolute(configPath) || path.normalize(configPath) !== configPath
      || /[\x00-\x1f\x7f]/.test(configPath)) throw failure('SSH_SESSION_INVALID');
    if (passwordBroker !== null) {
      if (!passwordBroker || typeof passwordBroker !== 'object' || Array.isArray(passwordBroker)
        || typeof passwordBroker.socket !== 'string' || !path.isAbsolute(passwordBroker.socket)
        || path.normalize(passwordBroker.socket) !== passwordBroker.socket || /[\x00-\x1f\x7f]/.test(passwordBroker.socket)
        || Buffer.byteLength(passwordBroker.socket) > 100 || !Array.isArray(passwordBroker.aliases)
        || !passwordBroker.aliases.length || passwordBroker.aliases.length > MAX_CONNECTIONS
        || new Set(passwordBroker.aliases).size !== passwordBroker.aliases.length
        || passwordBroker.aliases.some(alias => !description.connections.some(record => record.alias === alias
          && (description.version === 1 || record.authType === 'password')))) throw failure('SSH_SESSION_INVALID');
      if (passwordBroker.aliases.includes(invocation.alias)) {
        return await passwordClient({ socket: passwordBroker.socket, argv: [...argv], input, output, errorOutput, signals,
          tty: !invocation.flags.includes('-T') && (invocation.flags.includes('-t')
            || !invocation.command.length && input.isTTY === true && output.isTTY === true),
          cols: Number.isInteger(output.columns) && output.columns >= 1 && output.columns <= 1000 ? output.columns : 80,
          rows: Number.isInteger(output.rows) && output.rows >= 1 && output.rows <= 1000 ? output.rows : 24 });
      }
    }
    if (selected.authType === 'password') throw failure('SSH_SESSION_INVALID');
    return await new Promise(resolve => {
      let child, settled = false;
      const listeners = new Map();
      const finish = code => {
        if (settled) return;
        settled = true;
        for (const [signal, handler] of listeners) signals.off(signal, handler);
        resolve(code);
      };
      try {
        child = spawn('/usr/bin/ssh', ['-F', configPath, ...invocation.flags, '--', invocation.alias, ...invocation.command], {
          stdio: 'inherit', env: { ...process.env, SSH_ASKPASS_REQUIRE: 'never', SSH_ASKPASS: '/usr/bin/false' },
        });
        for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
          const handler = () => { try { child.kill(signal); } catch {} };
          listeners.set(signal, handler); signals.on(signal, handler);
        }
        child.once('error', () => { writeError('SSH_CLIENT_UNAVAILABLE'); finish(1); });
        child.once('exit', (code, signal) => finish(!signal && Number.isInteger(code) ? code : 1));
      } catch { writeError('SSH_CLIENT_UNAVAILABLE'); finish(1); }
    });
  } catch (error) {
    const code = Object.hasOwn(MESSAGES, error?.code ?? '') ? error.code : 'SSH_SESSION_INVALID';
    writeError(code);
    return 2;
  }
}
