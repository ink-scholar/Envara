// Runs before styles and the React bundle, including under the desktop CSP.
(() => {
  const valid = value => ['system', 'light', 'dark'].includes(value);
  let preference = 'system';
  const native = window.envara?.getAppearance?.();
  if (valid(native?.preference)) preference = native.preference;
  else if (!window.envara) {
    try {
      const saved = localStorage.getItem('envara.preview.v1');
      if (saved) { const value = JSON.parse(saved)?.settings?.appearance; preference = valid(value) ? value : 'dark'; }
    } catch { preference = 'dark'; }
  }
  const effective = ['light', 'dark'].includes(native?.effective) ? native.effective : preference === 'system' ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : preference;
  const root = document.documentElement;
  root.dataset.appearance = preference;
  root.dataset.theme = effective;
  root.style.colorScheme = effective;
  root.style.backgroundColor = effective === 'light' ? '#f6f7f9' : '#1c1c1e';
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', root.style.backgroundColor);
})();
