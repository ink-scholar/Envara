const validSequence = value => Number.isSafeInteger(value) && value >= 0;
const MAX_REPLAY_CHARACTERS = 256 * 1024;
const MAX_RETIRED_SESSIONS = 256;
const endedStatuses = new Set(['closed', 'exited', 'error']);
const metadata = value => {
  const { replay, ...result } = value;
  return result;
};
const tail = value => {
  let start = Math.max(0, value.length - MAX_REPLAY_CHARACTERS);
  if (start && value.charCodeAt(start) >= 0xdc00 && value.charCodeAt(start) <= 0xdfff && value.charCodeAt(start - 1) >= 0xd800 && value.charCodeAt(start - 1) <= 0xdbff) start++;
  return value.slice(start);
};

// Return the portion of a rolling replay not already delivered to xterm.
// A lost sequence can require a reset, but a stale snapshot never does.
function replayDelta(previous, replay) {
  if (!previous) return { data: replay, reset: false };
  if (replay === previous || previous.endsWith(replay)) return { data: '', reset: false };
  if (replay.startsWith(previous)) return { data: replay.slice(previous.length), reset: false };
  // KMP finds the longest suffix of previous that is a prefix of replay.
  const prefix = new Uint32Array(replay.length);
  for (let index = 1, length = 0; index < replay.length; index++) {
    while (length && replay[index] !== replay[length]) length = prefix[length - 1];
    if (replay[index] === replay[length]) length++;
    prefix[index] = length;
  }
  let overlap = 0;
  for (let index = 0; index < previous.length; index++) {
    const character = previous[index];
    while (overlap && (overlap === replay.length || character !== replay[overlap])) overlap = prefix[overlap - 1];
    if (character === replay[overlap]) overlap++;
  }
  return overlap ? { data: replay.slice(overlap), reset: false } : { data: replay, reset: true };
}

/** Sequence-aware state for the desktop event stream and rolling snapshots. */
export class TerminalStreamStore {
  constructor() {
    this.profiles = new Map();
    this.sessions = new Map();
    this.unknown = new Map();
    this.retired = new Set();
  }
  snapshot() {
    return { profiles: [...this.profiles.values()].map(profile => ({ ...profile, sessions: [...this.sessions.values()].filter(entry => entry.meta.profileId === profile.profileId).map(entry => ({ ...entry.meta, sequence: entry.sequence })) })) };
  }
  getSession(sessionId) {
    const entry = this.sessions.get(sessionId);
    return entry ? { ...entry.meta, sequence: entry.sequence } : null;
  }
  replayFor(sessionId) {
    return this.sessions.get(sessionId)?.text ?? '';
  }
  deliver(entry, event, writes) {
    entry.sequence = event.sequence;
    if (event.type === 'data' && typeof event.data === 'string') {
      entry.text = tail(entry.text + event.data);
      if (event.data) writes.push({ sessionId: event.sessionId, data: event.data });
    } else if (event.type === 'exit') {
      entry.meta.status = event.status || 'exited';
      entry.meta.exitCode = event.exitCode ?? null;
    } else if (event.type === 'status') {
      if (typeof event.status === 'string') entry.meta.status = event.status;
      if (typeof event.error === 'string') entry.meta.error = event.error;
      if (typeof event.message === 'string') entry.meta.message = event.message;
      if (event.claudeInstall && typeof event.claudeInstall === 'object') entry.meta.claudeInstall = { ...event.claudeInstall };
      else if (event.claudeInstall === null) entry.meta.claudeInstall = null;
    }
  }
  drain(entry, writes) {
    for (const sequence of entry.pending.keys()) if (sequence <= entry.sequence) entry.pending.delete(sequence);
    while (entry.pending.has(entry.sequence + 1)) {
      const event = entry.pending.get(entry.sequence + 1);
      entry.pending.delete(event.sequence);
      this.deliver(entry, event, writes);
    }
  }
  applyEvent(event) {
    const writes = [];
    if (!event || typeof event.sessionId !== 'string' || typeof event.profileId !== 'string' || !validSequence(event.sequence) || !['data', 'exit', 'status'].includes(event.type)) return { writes, refreshNeeded: false };
    if (this.retired.has(event.sessionId)) return { writes, refreshNeeded: false };
    const entry = this.sessions.get(event.sessionId);
    if (!entry) {
      const pending = this.unknown.get(event.sessionId) ?? new Map();
      pending.set(event.sequence, { ...event });
      this.unknown.set(event.sessionId, pending);
      return { writes, refreshNeeded: true };
    }
    if (event.profileId !== entry.meta.profileId || event.sequence <= entry.sequence) return { writes, refreshNeeded: false };
    entry.pending.set(event.sequence, { ...event });
    this.drain(entry, writes);
    return { writes, refreshNeeded: entry.pending.size > 0 };
  }
  applySnapshot(snapshot, { complete = false } = {}) {
    const writes = [];
    const profileIds = new Set(), sessionIds = new Set();
    for (const profile of snapshot?.profiles ?? []) {
      if (!profile || typeof profile.profileId !== 'string') continue;
      profileIds.add(profile.profileId);
      const { sessions = [], ...profileMetadata } = profile;
      this.profiles.set(profile.profileId, { ...(this.profiles.get(profile.profileId) ?? {}), ...profileMetadata });
      for (const session of sessions) {
        if (!session || typeof session.sessionId !== 'string' || !validSequence(session.sequence)) continue;
        sessionIds.add(session.sessionId);
        if (this.retired.has(session.sessionId)) continue;
        const replay = typeof session.replay === 'string' ? session.replay : '';
        let entry = this.sessions.get(session.sessionId);
        if (!entry) {
          entry = { meta: { ...metadata(session), profileId: profile.profileId }, sequence: session.sequence, text: tail(replay), pending: this.unknown.get(session.sessionId) ?? new Map() };
          this.sessions.set(session.sessionId, entry);
          this.unknown.delete(session.sessionId);
          if (replay) writes.push({ sessionId: session.sessionId, data: replay });
        } else if (session.sequence >= entry.sequence) {
          if (session.sequence > entry.sequence) {
            const delta = replayDelta(entry.text, replay);
            if (delta.data || delta.reset) writes.push({ sessionId: session.sessionId, ...delta });
            entry.text = tail(replay);
            entry.sequence = session.sequence;
          }
          entry.meta = { ...entry.meta, ...metadata(session), profileId: profile.profileId };
        }
        this.drain(entry, writes);
      }
    }
    // Open/duplicate replies are partial. Only a complete backend snapshot can
    // retire history it no longer keeps, and missing live sessions may still
    // be waiting for their first snapshot or an in-flight exit event.
    if (complete && Array.isArray(snapshot?.profiles)) {
      for (const [sessionId, entry] of this.sessions) {
        if (sessionIds.has(sessionId) || !endedStatuses.has(entry.meta.status)) continue;
        this.sessions.delete(sessionId);
        this.unknown.delete(sessionId);
        this.retired.add(sessionId);
        while (this.retired.size > MAX_RETIRED_SESSIONS) this.retired.delete(this.retired.values().next().value);
      }
      const retainedProfileIds = new Set([...this.sessions.values()].map(entry => entry.meta.profileId));
      for (const profileId of this.profiles.keys()) {
        if (!profileIds.has(profileId) && !retainedProfileIds.has(profileId)) this.profiles.delete(profileId);
      }
    }
    return { writes, refreshNeeded: this.unknown.size > 0 || [...this.sessions.values()].some(entry => entry.pending.size > 0) };
  }
}

/** Keep each input IPC call below the PTY byte limit without breaking emoji. */
export function splitTerminalInput(data, maximumBytes = 32 * 1024) {
  if (typeof data !== 'string' || !Number.isInteger(maximumBytes) || maximumBytes < 4) throw new TypeError('Invalid terminal input chunk.');
  const chunks = [];
  let chunk = '', bytes = 0;
  for (const character of data) {
    const point = character.codePointAt(0);
    const size = point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4;
    if (bytes + size > maximumBytes) { chunks.push(chunk); chunk = ''; bytes = 0; }
    chunk += character; bytes += size;
  }
  if (chunk) chunks.push(chunk);
  return chunks;
}

export function clampTerminalHeight(height, minimum = 320, maximum = 1200) {
  if (![height, minimum, maximum].every(Number.isFinite) || minimum < 0 || maximum < minimum) throw new RangeError('Invalid terminal height.');
  return Math.round(Math.max(minimum, Math.min(maximum, height)));
}

export function terminalHeightForPointer(startHeight, startY, pointerY, minimum, maximum) {
  return clampTerminalHeight(startHeight + startY - pointerY, minimum, maximum);
}

export function terminalHeightForKey(height, key, minimum, maximum, step = 32) {
  if (key === 'Home') return minimum;
  if (key === 'End') return maximum;
  if (key === 'ArrowUp') return clampTerminalHeight(height + step, minimum, maximum);
  if (key === 'ArrowDown') return clampTerminalHeight(height - step, minimum, maximum);
  return null;
}
