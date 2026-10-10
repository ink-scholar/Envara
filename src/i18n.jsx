import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { translate } from './i18n.mjs';
import { createInterfaceLanguageController } from './interface-language-state.mjs';

const I18nContext = createContext({ language: 'zh-CN', t: (value, vars) => translate(value, 'zh-CN', vars), setLanguage: () => {} });

export function I18nProvider({ children, language: preferredLanguage, onLanguageChange, api }) {
  const controller = useMemo(() => createInterfaceLanguageController({
    api, preferredLanguage, onLanguageChange,
    preferences: typeof navigator === 'undefined' ? [] : navigator.languages,
  }), [api, preferredLanguage, onLanguageChange]);
  const [state, setState] = useState(() => controller.getState());
  useEffect(() => {
    const unsubscribe = controller.subscribe(setState);
    controller.start();
    return () => { unsubscribe(); controller.stop(); };
  }, [controller]);
  const { language } = state;
  useEffect(() => { document.documentElement.lang = language; }, [language]);
  const value = useMemo(() => ({
    ...state,
    setLanguage: controller.setLanguage,
    previewLanguage: controller.previewLanguage,
    reloadLanguage: controller.reload,
    t: (text, vars) => translate(text, language, vars),
  }), [state, language, controller]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export const useI18n = () => useContext(I18nContext);
