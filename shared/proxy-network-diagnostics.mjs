// Public diagnostics carry only fixed labels and bounded observations. Never
// serialize transport objects, provider payloads, URLs, or exception messages.
export const NETWORK_DIAGNOSTIC_STAGES = Object.freeze(['configuration', 'https', 'response', 'validation']);
export const NETWORK_DIAGNOSTIC_ERROR_CODES = Object.freeze([
  'NETWORK_TIMEOUT', 'PROXY_AUTH_FAILED', 'GEO_BODY_TOO_LARGE', 'INVALID_GEO_RESPONSE',
  'GEO_PROVIDER_REJECTED', 'GEO_HTTP_ERROR', 'NETWORK_FAILED', 'NETWORK_CHANGED', 'APP_CLOSING',
]);
const sources = new Set(['ipwho.is', 'ipapi.co', 'custom']);
const outcomes = new Set(['success', 'failure', 'cancelled']);
const statuses = new Set(['passed', 'failed', 'unobserved']);
const errorCodes = new Set(NETWORK_DIAGNOSTIC_ERROR_CODES);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

export function networkDiagnosticSource(value) { return sources.has(value) ? value : 'custom'; }
export function networkDiagnosticElapsed(value) { return Number.isFinite(value) ? Math.min(120000, Math.max(0, Math.round(value))) : 0; }

/** Rebuild the complete projection; unknown values never become display text. */
export function sanitizeNetworkDiagnostics(value) {
  if (!object(value) || value.version !== 1 || !Array.isArray(value.attempts) || value.attempts.length > 3) return null;
  const attempts = [];
  for (const attempt of value.attempts) {
    if (!object(attempt) || !outcomes.has(attempt.outcome) || !Number.isFinite(attempt.elapsedMs) ||
        !Array.isArray(attempt.stages) || attempt.stages.length > NETWORK_DIAGNOSTIC_STAGES.length) return null;
    const observed = new Map();
    for (const entry of attempt.stages) {
      if (!object(entry) || !NETWORK_DIAGNOSTIC_STAGES.includes(entry.stage) || !statuses.has(entry.status) || observed.has(entry.stage)) return null;
      observed.set(entry.stage, entry.status);
    }
    attempts.push({ source: networkDiagnosticSource(attempt.source), elapsedMs: networkDiagnosticElapsed(attempt.elapsedMs), outcome: attempt.outcome,
      ...(attempt.outcome !== 'success' ? { errorCode: errorCodes.has(attempt.errorCode) ? attempt.errorCode : 'NETWORK_FAILED' } : {}),
      stages: NETWORK_DIAGNOSTIC_STAGES.map(stage => ({ stage, status: observed.get(stage) ?? 'unobserved' })) });
  }
  return { version: 1, attempts };
}
