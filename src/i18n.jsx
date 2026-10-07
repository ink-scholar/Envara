import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { translate, languages } from './i18n.mjs';

const I18nContext = createContext({ language: 'zh-CN', t: (value, vars) => translate(value, 'zh-CN', vars), setLanguage: () => {} });

export function I18nProvider({ children, language: preferredLanguage, onLanguageChange, api }) {
  const [language, updateLanguage] = useState(() => languages.includes(preferredLanguage) ? preferredLanguage : 'zh-CN');
  useEffect(() => { if (languages.includes(preferredLanguage)) updateLanguage(preferredLanguage); }, [preferredLanguage]);
  useEffect(() => {
    if (!api) return;
    let mounted = true;
    const apply = (snapshot) => { if (mounted && languages.includes(snapshot?.settings?.language)) updateLanguage(snapshot.settings.language); };
    api.call('snapshot').then(apply).catch(() => {});
    const unsubscribe = api.subscribe(apply);
    return () => { mounted = false; unsubscribe?.(); };
  }, [api]);
  useEffect(() => { document.documentElement.lang = language === 'en' ? 'en' : 'zh-CN'; }, [language]);
  const setLanguage = useCallback(async (next) => {
    if (!languages.includes(next)) return;
    const previous = language;
    updateLanguage(next);
    try {
      if (onLanguageChange) await onLanguageChange(next);
      else if (api) await api.call('saveSettings', { settings: { closeBrowsersOnExit: true, language: next } });
    } catch (error) { updateLanguage(previous); throw error; }
  }, [language, api, onLanguageChange]);
  const value = useMemo(() => ({ language, setLanguage, t: (text, vars) => translate(text, language, vars) }), [language, setLanguage]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export const useI18n = () => useContext(I18nContext);
