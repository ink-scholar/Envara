import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const contexts = new WeakMap();
const WINDOWS_SNAPSHOT = "Get-CimInstance -ClassName Win32_Process | Where-Object { $_.CreationDate } | Select-Object @{Name='pid';Expression={[int]$_.ProcessId}},@{Name='ppid';Expression={[int]$_.ParentProcessId}},@{Name='birth';Expression={$_.CreationDate.ToUniversalTime().Ticks.ToString()}} | ConvertTo-Json -Compress";
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function metadataEnvironment(platform) {
  if (platform !== 'win32') return { LC_ALL: 'C', PATH: '/usr/bin:/bin' };
  const systemRoot = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows';
  return { SystemRoot: systemRoot, WINDIR: systemRoot, PATH: `${systemRoot}\\System32;${systemRoot}\\System32\\WindowsPowerShell\\v1.0` };
}

function validPid(pid) {
  return Number.isSafeInteger(pid) && pid > 1 && pid !== process.pid && pid <= 2147483647;
}

// Only process metadata is requested. Arguments, commands and environment are never read.
async function processSnapshot(platform, pid, deadline) {
  try {
    const timeout = deadline === undefined ? (platform === 'win32' ? 5000 : 2000) : Math.max(1, Math.min(platform === 'win32' ? 5000 : 2000, deadline - Date.now()));
    if (platform === 'win32') {
      const { stdout } = await execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_SNAPSHOT], { timeout, maxBuffer: 4 * 1024 * 1024, windowsHide: true, env: metadataEnvironment(platform) });
      const parsed = JSON.parse(stdout || '[]');
      return new Map((Array.isArray(parsed) ? parsed : [parsed]).filter(row => row && Number.isSafeInteger(row.pid) && row.birth).map(row => [row.pid, { ...row, state: '' }]));
    }
    const args = pid === undefined ? ['-axo', 'pid=,ppid=,lstart=,stat='] : ['-p', String(pid), '-o', 'pid=,ppid=,lstart=,stat='];
    const { stdout } = await execFileAsync('/bin/ps', args, { timeout, maxBuffer: 4 * 1024 * 1024, env: metadataEnvironment(platform) });
    const rows = new Map();
    for (const line of stdout.split('\n')) {
      const match = line.trim().match(/^(\d+)\s+(\d+)\s+(.+?)\s+(\S+)$/);
      if (match) rows.set(Number(match[1]), { pid: Number(match[1]), ppid: Number(match[2]), birth: match[3].trim().replace(/\s+/g, ' '), state: match[4] });
    }
    return rows;
  } catch (error) {
    // ps exits 1 when a selected PID has gone away. Never include its stderr in a log.
    if (pid !== undefined && error.code === 1) return new Map();
    const failure = new Error('Could not read terminal process metadata');
    failure.code = 'TERMINAL_PROCESS_METADATA_UNAVAILABLE';
    throw failure;
  }
}

async function strongIdentity(row, platform) {
  if (!row || platform !== 'linux') return row;
  try {
    const raw = await readFile(`/proc/${row.pid}/stat`, 'utf8');
    const fields = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/);
    return { ...row, state: fields[0], kernelBirth: fields[19] };
  } catch {
    return undefined;
  }
}

export function terminalProcessMatches(current, captured) {
  if (!current || !captured || current.pid !== captured.pid || current.birth !== captured.birth || current.state?.startsWith('Z')) return false;
  return captured.kernelBirth === undefined || current.kernelBirth === captured.kernelBirth;
}

function descendsFromApp(row, snapshot) {
  const visited = new Set();
  while (row && !visited.has(row.pid)) {
    if (row.ppid === process.pid) return true;
    visited.add(row.pid);
    row = snapshot.get(row.ppid);
  }
  return false;
}

async function refresh(state, deadline) {
  const snapshot = await processSnapshot(state.platform, undefined, deadline);
  const roots = [state.root, ...state.children.values()];
  const reachable = new Set();
  for (const captured of roots) {
    const current = await strongIdentity(snapshot.get(captured.pid), state.platform);
    if (terminalProcessMatches(current, captured)) reachable.add(captured.pid);
    else if (captured.pid !== state.root.pid) state.children.delete(captured.pid);
  }
  const childrenByParent = new Map();
  for (const row of snapshot.values()) {
    if (!validPid(row.pid) || row.state.startsWith('Z')) continue;
    const siblings = childrenByParent.get(row.ppid) || [];
    siblings.push(row);
    childrenByParent.set(row.ppid, siblings);
  }
  const queue = [...reachable];
  for (let index = 0; index < queue.length; index++) {
    for (const row of childrenByParent.get(queue[index]) || []) {
      if (reachable.has(row.pid)) continue;
      const identity = await strongIdentity(row, state.platform);
      if (!identity) continue;
      reachable.add(row.pid);
      queue.push(row.pid);
      if (row.pid !== state.root.pid) state.children.set(row.pid, identity);
    }
  }
  return reachable;
}

/** Capture an app-owned PTY shell and keep metadata-only snapshots of its children. */
export async function captureTerminalProcess(pid) {
  if (!validPid(pid)) throw new TypeError('Terminal PID must identify a child process');
  const platform = process.platform;
  const snapshot = await processSnapshot(platform);
  const root = await strongIdentity(snapshot.get(pid), platform);
  if (!root || root.state.startsWith('Z')) {
    const error = new Error('Terminal process has already exited');
    error.code = 'TERMINAL_PROCESS_EXITED';
    throw error;
  }
  if (!descendsFromApp(root, snapshot)) {
    const error = new Error('Terminal process is not owned by this app');
    error.code = 'TERMINAL_PROCESS_NOT_OWNED';
    throw error;
  }
  const state = { root, platform, children: new Map(), pending: null, closing: null, timer: null };
  await refresh(state);
  const identity = Object.freeze({ pid, platform, root: Object.freeze({ ...root }) });
  contexts.set(identity, state);
  state.timer = setInterval(() => {
    if (state.pending || state.closing) return;
    state.pending = refresh(state).catch(() => {}).finally(() => { state.pending = null; });
  }, platform === 'win32' ? 750 : 150);
  state.timer.unref();
  return identity;
}

async function currentIdentity(state, pid, deadline) {
  const snapshot = await processSnapshot(state.platform, pid, deadline);
  return strongIdentity(snapshot.get(pid), state.platform);
}

async function cleanProcessTree(state, pty, timeoutMs) {
  clearInterval(state.timer);
  const deadline = Date.now() + timeoutMs;
  const signaled = new Set();
  const skipped = new Set();
  const failures = new Set();
  let metadataAvailable = true;
  if (state.pending) {
    // A stuck metadata subprocess cannot make terminal shutdown wait forever.
    let timeout;
    const completed = await Promise.race([state.pending.then(() => true), new Promise(resolve => { timeout = setTimeout(() => resolve(false), timeoutMs); })]).finally(() => clearTimeout(timeout));
    if (!completed) metadataAvailable = false;
  }
  const refreshSafely = async () => {
    if (Date.now() >= deadline) return new Set();
    try { return await refresh(state, deadline); } catch { metadataAvailable = false; return new Set(); }
  };
  await refreshSafely();
  const targets = () => [...state.children.values(), state.root]; // Children first; PTY shell last.
  const alive = async () => {
    const result = [];
    let snapshot;
    // One metadata snapshot verifies the whole known tree; signals still get a
    // separate immediately-before-signal check for each exact PID.
    try { snapshot = await processSnapshot(state.platform, undefined, Math.max(deadline, Date.now() + 100)); }
    catch { metadataAvailable = false; return targets(); }
    for (const target of targets()) {
      const current = await strongIdentity(snapshot.get(target.pid), state.platform);
      if (terminalProcessMatches(current, target)) result.push(target);
      else if (current && !current.state.startsWith('Z')) skipped.add(target.pid);
    }
    return result;
  };
  const signal = async (target, phase) => {
    if (Date.now() >= deadline) return;
    let current;
    try { current = await currentIdentity(state, target.pid, deadline); } catch { metadataAvailable = false; return; }
    if (!terminalProcessMatches(current, target)) {
      if (current && !current.state.startsWith('Z')) skipped.add(target.pid);
      return;
    }
    try {
      if (state.platform === 'win32' && target.pid === state.root.pid && phase !== 'SIGKILL' && typeof pty.kill === 'function') {
        // ConPTY first gets its normal shutdown path while its shell is still verified.
        pty.kill();
      } else if (state.platform === 'win32') {
        // taskkill receives only a verified numeric PID. /T targets that owned tree.
        await execFileAsync('taskkill.exe', ['/PID', String(target.pid), '/T', ...(phase === 'SIGKILL' ? ['/F'] : [])], { timeout: Math.min(2000, Math.max(1, deadline - Date.now())), windowsHide: true, maxBuffer: 64 * 1024, env: metadataEnvironment(state.platform) });
      } else if (target.pid === state.root.pid && typeof pty.kill === 'function') {
        // Never call node-pty.kill after the root birth identity no longer matches.
        pty.kill(phase);
      } else {
        process.kill(target.pid, phase);
      }
      signaled.add(target.pid);
    } catch (error) {
      if (error.code !== 'ESRCH') failures.add(target.pid);
    }
  };
  for (const phase of state.platform === 'win32' ? ['SIGTERM', 'SIGKILL'] : ['SIGHUP', 'SIGTERM', 'SIGKILL']) {
    if (Date.now() >= deadline) break;
    if (phase !== 'SIGKILL' && Date.now() + 150 >= deadline) continue;
    await refreshSafely();
    const living = await alive();
    if (!living.length) break;
    for (const target of living) await signal(target, phase);
    const pause = phase === 'SIGKILL' ? 0 : Math.min(150, Math.max(0, deadline - Date.now()));
    if (pause) await delay(pause);
  }
  let remaining = await alive();
  while (remaining.length && Date.now() < deadline) {
    await delay(Math.min(50, deadline - Date.now()));
    remaining = await alive();
  }
  return {
    ok: metadataAvailable && remaining.length === 0 && skipped.size === 0,
    rootExited: metadataAvailable && !remaining.some(row => row.pid === state.root.pid),
    remainingPids: remaining.map(row => row.pid),
    signaledPids: [...signaled],
    skippedPids: [...skipped],
    failedPids: [...failures],
    metadataAvailable,
    limitations: ['Processes that detach before a metadata snapshot cannot be reliably attributed.', ...(state.platform === 'darwin' ? ['macOS ps birth markers have one-second resolution; this is process cleanup, not OS isolation.'] : [])],
  };
}

/** Idempotently close only the captured shell and children whose birth identities still match. */
export async function closeTerminalProcess({ pty, identity, timeoutMs = 1500 } = {}) {
  const state = contexts.get(identity);
  if (!state || !pty || pty.pid !== state.root.pid) throw new TypeError('PTY and captured terminal identity must match');
  if (!state.closing) {
    const boundedTimeout = Number.isFinite(timeoutMs) ? Math.max(250, Math.min(5000, timeoutMs)) : 1500;
    const attempt = cleanProcessTree(state, pty, boundedTimeout);
    state.closing = attempt;
    // Concurrent callers share this attempt. An uncertain result must allow a
    // later explicit close to inspect the same captured identities again.
    void attempt.then(result => {
      if (result?.ok !== true && state.closing === attempt) state.closing = null;
    }, () => { if (state.closing === attempt) state.closing = null; });
  }
  return state.closing;
}
