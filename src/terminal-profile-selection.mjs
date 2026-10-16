/** Follow an explicit outer selection, not every snapshot or local tab click. */
export function reconcileTerminalProfile({ activeProfileId, selectedProfileId, previousSelectedProfileId, profileIds }) {
  const valid = new Set(profileIds);
  if (selectedProfileId !== previousSelectedProfileId && valid.has(selectedProfileId)) return selectedProfileId;
  if (valid.has(activeProfileId)) return activeProfileId;
  return valid.has(selectedProfileId) ? selectedProfileId : profileIds[0] ?? null;
}
