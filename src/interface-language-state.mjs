import { isInterfaceLanguage, recommendInterfaceLanguage } from '../shared/interface-languages.mjs';

// A settings notification can arrive before the initial snapshot request finishes.
// Only a complete snapshot is evidence about whether first-run setup is needed.
export function isSettingsSnapshot(value) {
  return !!value && Array.isArray(value.profiles) && Array.isArray(value.proxies)
    && !!value.system && typeof value.system === 'object' && !Array.isArray(value.system)
    && typeof value.system.platform === 'string' && !!value.system.platform
    && typeof value.system.appVersion === 'string' && !!value.system.appVersion
    && !!value.settings && typeof value.settings === 'object' && !Array.isArray(value.settings);
}

export function createInterfaceLanguageController({ api, preferences, preferredLanguage, onLanguageChange } = {}) {
  const recommendedLanguage = recommendInterfaceLanguage(preferences);
  let state = Object.freeze({
    language: isInterfaceLanguage(preferredLanguage) ? preferredLanguage : recommendedLanguage,
    recommendedLanguage,
    phase: api ? 'loading' : 'ready',
    saving: false,
    error: null,
  });
  let latestSnapshot = null;
  let revision = 0;
  let generation = 0;
  let request = 0;
  let unsubscribe = null;
  const listeners = new Set();
  const publish = patch => {
    state = Object.freeze({ ...state, ...patch });
    listeners.forEach(listener => listener(state));
  };
  const apply = (value, authoritative = false) => {
    if (!isSettingsSnapshot(value)) return false;
    latestSnapshot = value;
    const next = value.settings.language;
    if (state.saving) return true;
    if (isInterfaceLanguage(next)) publish({ language: next, phase: 'ready', error: null });
    else if (authoritative && state.phase !== 'ready') publish({ phase: 'required', error: null });
    return true;
  };
  const reload = async () => {
    if (!api) return;
    const currentGeneration = generation;
    const currentRequest = ++request;
    const initialRevision = revision;
    if (state.phase !== 'ready') publish({ phase: 'loading', error: null });
    try {
      const value = await api.call('snapshot');
      if (currentGeneration !== generation || currentRequest !== request) return;
      // A newer subscription wins over the older response captured by this request.
      const current = revision !== initialRevision && isInterfaceLanguage(latestSnapshot?.settings?.language) ? latestSnapshot : value;
      if (!apply(current, true)) throw new Error('Invalid settings snapshot');
    } catch {
      if (currentGeneration === generation && currentRequest === request && state.phase !== 'ready') {
        publish({ phase: 'error', error: '无法读取设置，请重试。' });
      }
    }
  };
  const start = () => {
    if (!api || unsubscribe) return;
    generation += 1;
    unsubscribe = api.subscribe(value => {
      if (!isSettingsSnapshot(value)) return;
      revision += 1;
      apply(value);
    }) || (() => {});
    void reload();
  };
  const stop = () => {
    generation += 1;
    request += 1;
    unsubscribe?.();
    unsubscribe = null;
  };
  const previewLanguage = next => {
    if (state.phase === 'required' && !state.saving && isInterfaceLanguage(next)) publish({ language: next, error: null });
  };
  const setLanguage = async next => {
    if (!isInterfaceLanguage(next) || state.saving) return false;
    const previous = state.language;
    const initialPhase = state.phase;
    const currentGeneration = generation;
    const initialRevision = revision;
    publish({ language: next, saving: true, error: null });
    try {
      let result;
      if (onLanguageChange) result = await onLanguageChange(next);
      else if (api) result = await api.call('saveSettings', { settings: {
        closeBrowsersOnExit: latestSnapshot?.settings?.closeBrowsersOnExit !== false,
        language: next,
      } });
      if (currentGeneration !== generation) return true;
      if (revision === initialRevision && isSettingsSnapshot(result)) latestSnapshot = result;
      const persisted = revision !== initialRevision || isSettingsSnapshot(result) ? latestSnapshot?.settings?.language : next;
      publish({ language: isInterfaceLanguage(persisted) ? persisted : next, phase: 'ready', saving: false, error: null });
      return true;
    } catch (error) {
      if (currentGeneration === generation) publish({
        language: initialPhase === 'required' ? next : previous,
        phase: initialPhase,
        saving: false,
        error: '无法保存语言，请重试。',
      });
      throw error;
    }
  };
  return {
    getState: () => state,
    subscribe(listener) { listeners.add(listener); listener(state); return () => listeners.delete(listener); },
    start,
    stop,
    reload,
    setLanguage,
    previewLanguage,
  };
}
