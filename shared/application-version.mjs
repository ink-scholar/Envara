// Stable application releases use exactly three bounded numeric components.
// Keep release selection and recovery ordering on the same rules; browser/CLI
// component versions and macOS minimum-version strings have different formats.
export const applicationVersionParts = value => typeof value === 'string'
  && /^(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})$/.test(value)
  ? value.split('.').map(Number) : null;

/** Callers validate both inputs before comparing release or receipt versions. */
export function compareApplicationVersions(left, right) {
  const a = applicationVersionParts(left), b = applicationVersionParts(right);
  for (let index = 0; index < 3; index++) if (a[index] !== b[index]) return a[index] > b[index] ? 1 : -1;
  return 0;
}
