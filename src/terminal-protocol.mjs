import { TERMINAL_PROTOCOL_CSI, TERMINAL_PROTOCOL_DCS, TERMINAL_PROTOCOL_OSC,
  isTerminalProtocolCsi, isTerminalProtocolOsc } from '../shared/terminal-protocol.mjs';

/** The session's main-process terminal answers queries, even with no views.
 * Keep renderer parsing intact (notably mixed OSC colour set/query commands),
 * but do not send its duplicate or replay-generated answers back to the PTY.
 *
 * xterm 6's built-in parser handlers and their replies are synchronous. Native
 * keyboard, paste and IME events run in a later task; the microtask clears this
 * guard before those events. Do not add asynchronous query handlers or inject
 * user input from a terminal.write callback without revisiting this boundary.
 */
export function attachTerminalProtocol(terminal) {
  let responding = false, disposed = false;
  const suppress = () => {
    if (!responding) {
      responding = true;
      queueMicrotask(() => { responding = false; });
    }
    // The native handler still updates colours, modes and other parser state.
    return false;
  };
  const subscriptions = [
    ...TERMINAL_PROTOCOL_CSI.map(id => terminal.parser.registerCsiHandler(id,
      params => isTerminalProtocolCsi(id, params) ? suppress() : false)),
    ...TERMINAL_PROTOCOL_DCS.map(id => terminal.parser.registerDcsHandler(id, suppress)),
    ...TERMINAL_PROTOCOL_OSC.map(id => terminal.parser.registerOscHandler(id,
      data => isTerminalProtocolOsc(id, data) ? suppress() : false)),
  ];
  return {
    // A query and DECSET 1004 can share a parse batch. Focus reports still
    // belong to the real view; the headless terminal cannot supply them.
    isResponse: data => !disposed && responding && data !== '\x1b[I' && data !== '\x1b[O',
    dispose() {
      disposed = true;
      for (const subscription of subscriptions) subscription.dispose();
    },
  };
}
