/** Failure events and the following snapshot describe the same incident.
 * Keep it visible after its live tab ends, without announcing it repeatedly. */
export class TerminalErrorNotices {
  constructor() { this.seen = new Map(); }
  take(value) {
    if (!value || typeof value.sessionId !== 'string' || typeof value.error !== 'string' || !value.error.trim()) return null;
    const key = JSON.stringify([value.sessionId, value.error]);
    const previous = this.seen.get(key);
    const sequence = Number.isSafeInteger(value.sequence) && value.sequence >= 0 ? value.sequence : null;
    if (sequence != null && previous?.sequence != null && sequence < previous.sequence) return null;
    const code = typeof value.errorCode === 'string' && /^[A-Z0-9_]{1,96}$/.test(value.errorCode) ? value.errorCode : previous?.code ?? '';
    const incomingCleanup = typeof value.cleanupError === 'string' ? value.cleanupError.slice(0, 512) : '';
    const cleanupResolved = Boolean(previous?.cleanupError) && !incomingCleanup && (value.cleanupError === null || ['closed', 'exited', 'error'].includes(value.status));
    const cleanupError = incomingCleanup || (cleanupResolved ? '' : previous?.cleanupError ?? '');
    const signature = JSON.stringify([code, cleanupError]);
    const record = previous ?? { signatures: new Set() };
    if (sequence != null) record.sequence = sequence;
    if (record.signature === signature || (!cleanupResolved && record.signatures.has(signature))) return null;
    record.code = code; record.cleanupError = cleanupError; record.signature = signature; record.signatures.add(signature);
    while (record.signatures.size > 16) record.signatures.delete(record.signatures.values().next().value);
    this.seen.set(key, record);
    while (this.seen.size > 128) this.seen.delete(this.seen.keys().next().value);
    return { sessionId: value.sessionId, message: value.error, code, cleanupError, ...(cleanupResolved ? { updateOnly: true } : {}) };
  }
}
