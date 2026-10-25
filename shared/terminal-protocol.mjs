// Query families implemented by the pinned xterm 6 parser. The process owns
// their replies; renderers still parse every sequence for display/state changes.
export const TERMINAL_PROTOCOL_CSI = Object.freeze([
  { final: 'c' }, { prefix: '>', final: 'c' },
  { final: 'n' }, { prefix: '?', final: 'n' },
  { intermediates: '$', final: 'p' }, { prefix: '?', intermediates: '$', final: 'p' },
  { final: 't' },
].map(Object.freeze));
export const TERMINAL_PROTOCOL_DCS = Object.freeze([{ intermediates: '$', final: 'q' }].map(Object.freeze));
export const TERMINAL_PROTOCOL_OSC = Object.freeze([4, 10, 11, 12]);

export function isTerminalProtocolCsi(id, params) {
  // Window operations also push/pop titles. Those are not reply operations.
  return id.final !== 't' || [14, 16, 18].includes(params?.[0]);
}

export function isTerminalProtocolOsc(id, data) {
  if (typeof data !== 'string') return false;
  const parts = data.split(';');
  if (id === 4) return parts.some((part, index) => index % 2 === 1 && part === '?' &&
    /^\d+$/.test(parts[index - 1]) && Number(parts[index - 1]) <= 255);
  return id >= 10 && id <= 12 && parts.slice(0, 13 - id).includes('?');
}
