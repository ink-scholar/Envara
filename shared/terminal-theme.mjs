// Fixed ANSI palettes. This module has no session, storage or process authority.
export const terminalFontFamily = '"SFMono-Regular", Menlo, Monaco, Consolas, "Liberation Mono", monospace';

const dark = Object.freeze({
  background: '#19191c', foreground: '#d8d8df',
  cursor: '#e2e2e8', selectionBackground: '#334c68',
  black: '#25252b', brightBlack: '#737382',
  red: '#ed747c', green: '#8bcd9b', yellow: '#d9c58b',
  blue: '#71aaf5', magenta: '#be9add', cyan: '#83c9d1', white: '#d8d8df',
});

const light = Object.freeze({
  background: '#ffffff', foreground: '#252b36',
  cursor: '#0969da', cursorAccent: '#ffffff',
  selectionBackground: '#cfe1fb', selectionForeground: '#252b36',
  black: '#2f3540', brightBlack: '#626976',
  red: '#a3323e', brightRed: '#b53d49',
  green: '#147d44', brightGreen: '#176b3e',
  yellow: '#8a5c00', brightYellow: '#805300',
  blue: '#145fb7', brightBlue: '#0969da',
  magenta: '#7d4097', brightMagenta: '#9045a5',
  cyan: '#176f82', brightCyan: '#0b6a80',
  white: '#626976', brightWhite: '#252b36',
});

export function getTerminalTheme(effective) {
  // xterm owns the returned object; a renderer cannot mutate another's palette.
  return { ...(effective === 'light' ? light : dark) };
}
