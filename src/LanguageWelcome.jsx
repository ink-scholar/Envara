import React, { useEffect, useRef } from 'react';
import { ArrowRight, ArrowsClockwise, Check, WarningCircle } from '@phosphor-icons/react';
import { languageOptions } from '../shared/interface-languages.mjs';
import { useI18n } from './i18n.jsx';

export function LanguageWelcome() {
  const { language, recommendedLanguage, phase, saving, error, t, previewLanguage, setLanguage, reloadLanguage } = useI18n();
  const panelRef = useRef(null);
  const visible = phase !== 'ready';
  useEffect(() => {
    if (!visible) return;
    document.body.classList.add('language-onboarding');
    return () => document.body.classList.remove('language-onboarding');
  }, [visible]);
  useEffect(() => {
    if (!visible || phase === 'loading') return;
    const panel = panelRef.current;
    const previous = document.activeElement;
    const focusable = () => [...panel.querySelectorAll('input:not(:disabled), button:not(:disabled)')];
    const frame = requestAnimationFrame(() => {
      (panel.querySelector('input:checked:not(:disabled)') || focusable()[0] || panel).focus({ preventScroll: true });
    });
    const onKey = event => {
      if (event.key !== 'Tab') return;
      // Native radio groups form one tab stop; arrow keys change their selection.
      const controls = focusable().filter(element => element.type !== 'radio' || element.checked);
      const first = controls[0] || panel;
      const last = controls.at(-1) || panel;
      if (!panel.contains(document.activeElement) || !controls.length) {
        event.preventDefault(); first.focus();
      } else if (event.shiftKey && document.activeElement === first) {
        event.preventDefault(); last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault(); first.focus();
      }
    };
    panel.addEventListener('keydown', onKey);
    return () => {
      cancelAnimationFrame(frame);
      panel.removeEventListener('keydown', onKey);
      requestAnimationFrame(() => {
        if (document.querySelector('.language-welcome-layer')) return;
        if (previous?.isConnected && !previous.closest('[inert]')) previous.focus?.();
        else document.querySelector('.navigation button')?.focus();
      });
    };
  }, [visible, phase, saving]);
  if (!visible) return null;
  if (phase === 'loading') return <div className="language-welcome-layer language-bootstrap" role="status" aria-label={t('正在读取环境…')}>
    <img src={`${import.meta.env.BASE_URL}assets/envara-icon.png`} alt="" /><ArrowsClockwise className="spin" size={19} />
  </div>;
  const confirm = event => { event.preventDefault(); void setLanguage(language).catch(() => {}); };
  return <div className="language-welcome-layer">
    <section className="language-welcome-card" role="dialog" aria-modal="true" aria-labelledby="language-welcome-title" aria-describedby={phase === 'error' ? undefined : 'language-welcome-description'} aria-busy={saving} ref={panelRef} tabIndex={-1}>
      <div className="language-welcome-brand"><img src={`${import.meta.env.BASE_URL}assets/envara-icon.png`} alt="" /><strong>Envara{language.startsWith('zh') && <span>境舱</span>}</strong><span className="language-setup-label">{t('首次设置')}</span></div>
      <h1 id="language-welcome-title">{t(phase === 'error' ? '无法读取设置，请重试。' : '欢迎使用 Envara')}</h1>
      {phase !== 'error' && <p id="language-welcome-description">{t('选择界面语言')}</p>}
      {phase === 'error' ? <button className="button primary language-start-button" onClick={() => void reloadLanguage()}><ArrowsClockwise size={18} />{t('重新加载')}</button> : <form onSubmit={confirm}>
        <fieldset className="language-choice-grid" disabled={saving}><legend className="sr-only">{t('选择语言')}</legend>
          {languageOptions.map(option => <label className={`language-choice ${language === option.code ? 'selected' : ''}`} key={option.code}>
            <input className="language-choice-input" type="radio" name="interface-language" value={option.code} checked={language === option.code} onChange={() => previewLanguage(option.code)} />
            <span className="language-choice-copy"><strong lang={option.code}>{option.nativeName}</strong>{option.code === recommendedLanguage && <small>{t('系统推荐')}</small>}</span>
            <span className="language-choice-check" aria-hidden="true">{language === option.code && <Check size={17} weight="bold" />}</span>
          </label>)}
        </fieldset>
        {error && <p className="language-welcome-error" role="alert"><WarningCircle size={17} />{t(error)}</p>}
        <button className="button primary language-start-button" type="submit" disabled={saving}>{saving ? <ArrowsClockwise size={18} className="spin" /> : null}{t(saving ? '正在保存…' : '开始使用')}{!saving && <ArrowRight size={18} />}</button>
        <p className="language-welcome-hint">{t('可在设置中更改。')}</p>
        <p className="language-welcome-scope">{t('不影响浏览器语言和网络。')}</p>
      </form>}
    </section>
  </div>;
}
