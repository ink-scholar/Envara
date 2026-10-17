export const appearancePreferences = Object.freeze(['system', 'light', 'dark']);
export const isAppearancePreference = value => typeof value === 'string' && appearancePreferences.includes(value);
// Missing choices belong to an existing workspace, whose appearance was dark.
export const workspaceAppearance = settings => isAppearancePreference(settings?.appearance) ? settings.appearance : 'dark';
export const effectiveAppearance = (preference, systemDark) => preference === 'system' ? (systemDark ? 'dark' : 'light') : preference === 'light' ? 'light' : 'dark';
export const appearanceBackground = effective => effective === 'light' ? '#f6f7f9' : '#1c1c1e';
