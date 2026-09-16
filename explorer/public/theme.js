/*
 * The stored theme, applied before the first paint.
 *
 * The palette is decided in CSS and the control is in the nav row. This file
 * exists so a reader who chose a theme does not watch the other one paint
 * first: it runs synchronously in the head, before the bundle and before the
 * static shell in index.html is drawn. A reader who stored nothing keeps the
 * system setting, which the stylesheet already follows.
 *
 * It is a file rather than an inline script because the policy this site ships
 * under is `script-src 'self' 'wasm-unsafe-eval'`, with no `'unsafe-inline'`.
 */
(function () {
  'use strict';
  try {
    var theme = localStorage.getItem('qnero-explorer-theme');
    if (theme === 'light' || theme === 'dark') {
      document.documentElement.setAttribute('data-theme', theme);
    }
  } catch {
    /* Site data blocked. The system setting stands. */
  }
})();
