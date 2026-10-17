/** A failed launch spends the main-process picker token. Keep retry from
 * silently substituting the environment's saved directory for that choice. */
export function invalidatePickedTerminalDirectory(choice) {
  return choice?.directory ? { ...choice, directory: null, directoryNeedsSelection: true } : choice;
}

export function terminalDirectoryChoice(choice, savedDirectory = null) {
  const needsSelection = choice?.directoryNeedsSelection === true;
  return { path: choice?.directory?.path ?? (needsSelection ? null : savedDirectory),
    ready: !needsSelection || typeof choice?.directory?.token === 'string' && !!choice.directory.token };
}
