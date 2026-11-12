// Shared light/dark toggle for every page in the lab (homepage + tools,
// except AI-SHIELD - its dark theme is a fixed brand identity, not a
// togglable preference, so it doesn't render this button at all).
//
// The actual theme (light vs dark, resolved from an explicit choice or
// the OS preference) is applied by a tiny inline script in each page's
// <head>, before this file loads, so there's no flash of the wrong
// theme while this file is still being fetched. This file only wires
// up the button: showing the right icon and handling clicks.
(function () {
  function currentTheme() {
    var attr = document.documentElement.getAttribute('data-theme');
    if (attr === 'light' || attr === 'dark') return attr;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function updateButton(btn, theme) {
    btn.setAttribute('data-theme', theme);
    btn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
    btn.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
  }

  function applyTheme(btn, theme) {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('lab-theme', theme); } catch (e) {}
    updateButton(btn, theme);
  }

  function init() {
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    updateButton(btn, currentTheme());
    btn.addEventListener('click', function () {
      applyTheme(btn, currentTheme() === 'dark' ? 'light' : 'dark');
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
