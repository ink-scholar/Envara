import React, { createContext, useContext, useEffect, useLayoutEffect, useMemo, useState } from 'react';
import { appearanceBackground } from '../shared/appearance.mjs';
import { createAppearanceController } from './appearance-state.mjs';

const AppearanceContext = createContext({ preference: 'system', effective: 'dark', setPreference: async () => false, saving: false });

export function AppearanceProvider({ api, children }) {
  const controller = useMemo(() => createAppearanceController({ api,
    initial: api?.getAppearance?.() ?? { preference: document.documentElement.dataset.appearance, effective: document.documentElement.dataset.theme },
    mediaQuery: window.matchMedia('(prefers-color-scheme: dark)'),
  }), [api]);
  const [state, setState] = useState(() => controller.getState());
  useEffect(() => {
    const unsubscribe = controller.subscribe(setState);
    controller.start();
    return () => { unsubscribe(); controller.stop(); };
  }, [controller]);
  useLayoutEffect(() => {
    const root = document.documentElement;
    root.dataset.appearance = state.preference;
    root.dataset.theme = state.effective;
    root.style.colorScheme = state.effective;
    root.style.backgroundColor = appearanceBackground(state.effective);
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', appearanceBackground(state.effective));
  }, [state.preference, state.effective]);
  const value = useMemo(() => ({ ...state, setPreference: controller.setPreference }), [state, controller]);
  return <AppearanceContext.Provider value={value}>{children}</AppearanceContext.Provider>;
}

export const useAppearance = () => useContext(AppearanceContext);
