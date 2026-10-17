import { effectiveAppearance, isAppearancePreference, workspaceAppearance } from '../shared/appearance.mjs';
import { isSettingsSnapshot } from './interface-language-state.mjs';

export function createAppearanceController({ api, initial, mediaQuery } = {}) {
  let systemDark = mediaQuery?.matches === true;
  let state = { preference: isAppearancePreference(initial?.preference) ? initial.preference : 'system', saving: false };
  state.effective = ['light', 'dark'].includes(initial?.effective) ? initial.effective : effectiveAppearance(state.preference, systemDark);
  let generation = 0, revision = 0, latestPreference = state.preference, latestCloseOnExit = true, stopListening = null;
  const listeners = new Set();
  const publish = patch => {
    state = Object.freeze({ ...state, ...patch, effective: patch?.effective ?? effectiveAppearance(patch?.preference ?? state.preference, systemDark) });
    listeners.forEach(listener => listener(state));
  };
  const applyPreference = (preference, effective) => {
    if (!isAppearancePreference(preference)) return;
    effective = ['light', 'dark'].includes(effective) ? effective : undefined;
    revision++;
    latestPreference = preference;
    if (preference === 'system' && ['light', 'dark'].includes(effective)) systemDark = effective === 'dark';
    if (!state.saving) publish({ preference, ...(effective ? { effective } : {}) });
  };
  const start = () => {
    if (stopListening) return;
    const currentGeneration = ++generation;
    const onSystemChange = event => { systemDark = event.matches; if (state.preference === 'system') publish({}); };
    mediaQuery?.addEventListener?.('change', onSystemChange);
    const offSnapshot = api?.subscribe?.(value => {
      if (!isSettingsSnapshot(value)) return;
      latestCloseOnExit = value.settings.closeBrowsersOnExit !== false;
      applyPreference(workspaceAppearance(value.settings));
    });
    const offAppearance = api?.onAppearance?.(value => applyPreference(value?.preference, value?.effective));
    stopListening = () => { offSnapshot?.(); offAppearance?.(); mediaQuery?.removeEventListener?.('change', onSystemChange); };
    const beforeRead = revision;
    if (api) void api.call('snapshot').then(value => {
      if (generation === currentGeneration && revision === beforeRead && isSettingsSnapshot(value)) {
        latestCloseOnExit = value.settings.closeBrowsersOnExit !== false;
        applyPreference(workspaceAppearance(value.settings));
      }
    }).catch(() => {}); // Keep the already painted appearance when startup fails.
  };
  const stop = () => { generation++; stopListening?.(); stopListening = null; };
  const setPreference = async next => {
    if (!isAppearancePreference(next) || state.saving || state.preference === next) return false;
    const previous = state.preference, beforeSave = revision, currentGeneration = generation;
    publish({ preference: next, saving: true });
    try {
      const result = await api?.call('saveSettings', { settings: { closeBrowsersOnExit: latestCloseOnExit, appearance: next } });
      if (generation !== currentGeneration) return true;
      if (revision === beforeSave && isSettingsSnapshot(result)) {
        latestPreference = workspaceAppearance(result.settings);
        latestCloseOnExit = result.settings.closeBrowsersOnExit !== false;
      }
      publish({ preference: revision !== beforeSave || isSettingsSnapshot(result) ? latestPreference : next, saving: false });
      return true;
    } catch (error) {
      if (generation === currentGeneration) publish({ preference: revision !== beforeSave ? latestPreference : previous, saving: false });
      throw error;
    }
  };
  return { getState: () => state, subscribe(listener) { listeners.add(listener); listener(state); return () => listeners.delete(listener); }, start, stop, setPreference };
}
