const stages = new Set(['arguments', 'lock', 'scoped-query', 'host-query', 'stage', 'select', 'publish', 'verify', 'host-verify', 'cleanup']);

export function sanitizeClaudeKeychainDiagnostic(value) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== 2 || !keys.includes('stage') || !keys.includes('osStatus')) return null;
    // Read only data properties; diagnostics never evaluate supplied accessors.
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const stage = descriptors.stage.value, osStatus = descriptors.osStatus.value;
    if (!stages.has(stage) || !(osStatus === null || Number.isSafeInteger(osStatus) && osStatus >= -2147483648 && osStatus <= 2147483647)) return null;
    return { stage, osStatus };
  } catch { return null; }
}
