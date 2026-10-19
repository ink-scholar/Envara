/** Keep modified Enter distinct from submit without changing the shell or CLI. */
export function attachTerminalKeyboard(terminal) {
  const textarea = terminal.textarea;
  const inputContainer = textarea.parentElement;
  const isMac = /^Mac/.test(globalThis.navigator?.platform ?? '');
  let composing = false, suppressEnterKeyPress = false, pendingText = null;
  const compositionStart = () => { composing = true; pendingText = null; };
  const compositionEnd = () => { composing = false; };
  const blur = () => { composing = false; suppressEnterKeyPress = false; pendingText = null; };
  const input = event => {
    if (event.target !== textarea || !pendingText || pendingText.sent || composing || event.isComposing
      || event.inputType !== 'insertText' || !event.data) return;
    // Some IMEs omit keypress. Use their committed text, never a replacement
    // guessed from a physical key. Capture before xterm to avoid double input.
    pendingText.sent = true;
    event.stopPropagation();
    terminal.input(event.data);
  };
  textarea.addEventListener('compositionstart', compositionStart);
  textarea.addEventListener('compositionend', compositionEnd);
  textarea.addEventListener('blur', blur);
  inputContainer.addEventListener('input', input, true);

  terminal.attachCustomKeyEventHandler(event => {
    const enter = event.key === 'Enter' || event.code === 'Enter' || event.code === 'NumpadEnter' || event.keyCode === 13;
    if (event.type === 'keyup') {
      if (enter || event.keyCode === 229) suppressEnterKeyPress = false;
      if (event.code === pendingText?.code) pendingText = null;
      return true;
    }
    // Some IMEs send a trailing keypress after compositionend. It belongs to
    // the candidate confirmation, not a second command-submission action.
    if (event.type === 'keypress') {
      if (enter && suppressEnterKeyPress) return false;
      if (pendingText) {
        if (pendingText.sent) return false;
        // xterm's native keypress path uses charCode (the IME result), and
        // retains its normal accessibility and dead-key handling.
        if ((event.charCode || event.which || event.keyCode) && !event.ctrlKey && !event.altKey && !event.metaKey) pendingText.sent = true;
      }
      return true;
    }
    if (event.type !== 'keydown') return true;
    suppressEnterKeyPress = false;
    pendingText = null;
    // macOS Chinese input reports "\\" at keydown, then "、" at keypress/input.
    // Let the OS finish this printable key; shortcuts still belong to xterm.
    if (isMac && ['Backslash', 'IntlBackslash'].includes(event.code) && event.key?.length === 1
      && !event.ctrlKey && !event.altKey && !event.metaKey && !composing && !event.isComposing && event.keyCode !== 229) {
      pendingText = { code: event.code, sent: false };
      return false;
    }
    if (!enter) return true;
    // Let the browser commit its IME candidate. Returning false here only skips
    // xterm's key handling; preventDefault would also cancel the native commit.
    if (composing || event.isComposing || event.keyCode === 229) {
      suppressEnterKeyPress = true;
      return false;
    }
    if (!event.shiftKey || event.altKey || event.ctrlKey || event.metaKey || terminal.options.disableStdin) return true;
    event.preventDefault();
    suppressEnterKeyPress = true;
    // Match xterm's existing Alt/Option+Enter encoding, recognized by Claude
    // for multiline input. A bare LF would also execute a waiting shell line.
    terminal.input('\x1b\r');
    return false;
  });

  return () => {
    textarea.removeEventListener('compositionstart', compositionStart);
    textarea.removeEventListener('compositionend', compositionEnd);
    textarea.removeEventListener('blur', blur);
    inputContainer.removeEventListener('input', input, true);
    terminal.attachCustomKeyEventHandler(() => true);
  };
}
