import { readFileSync } from 'node:fs';
import { effectiveAppearance, appearanceBackground, isAppearancePreference, workspaceAppearance } from '../shared/appearance.mjs';

// A local read before the first window: never wait for the browser backend,
// network, application routing or the full workspace snapshot to paint the UI.
export function readInitialAppearance(file) {
  try { return workspaceAppearance(JSON.parse(readFileSync(file, 'utf8')).settings); }
  catch (error) { return error.code === 'ENOENT' ? 'system' : 'dark'; }
}

export function createAppearanceManager({ nativeTheme, views, preference }) {
  let saved = isAppearancePreference(preference) ? preference : 'dark';
  const snapshot = () => ({ preference: saved, effective: effectiveAppearance(saved, nativeTheme.shouldUseDarkColors) });
  const updateWindow = view => {
    if (view.isDestroyed()) return;
    const value = snapshot();
    view.setBackgroundColor(appearanceBackground(value.effective));
    view.webContents.send('envara:appearance', value);
  };
  const publish = () => { for (const { window } of views.values()) updateWindow(window); };
  // Electron's themeSource is scoped to this application; it does not change
  // macOS/Windows appearance or any managed browser/terminal process settings.
  nativeTheme.themeSource = saved;
  nativeTheme.on('updated', publish);
  return {
    snapshot, updateWindow,
    setPreference(next) {
      if (!isAppearancePreference(next) || saved === next) return;
      saved = next;
      nativeTheme.themeSource = next;
      publish();
    },
    dispose() { nativeTheme.removeListener('updated', publish); },
  };
}
